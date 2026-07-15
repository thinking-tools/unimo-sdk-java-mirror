package com.unimo.sdk.client;

import com.unimo.sdk.crypto.CodedException;
import com.unimo.sdk.shared.Json;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;

/**
 * Port of {@code sdk/ts/src_ts/client/Connection.ts} — a long-lived authenticated WebSocket per
 * vault, over OkHttp. The gateway pushes {@code vault:event} frames (blob put / trash / restore /
 * head change / presence / member revoked / invite claimed / subscription changed). Credentials
 * ride the URL query (the upgrade can't set headers): {@code wss://host/api/ws?token=&vid=&mid=}.
 *
 * <p>Reconnect uses exponential backoff (250ms → 30s) with jitter, and the attempt counter resets
 * only when the just-closed socket had been open ≥30s — so a rejected upgrade or rapid-die cycle
 * keeps backing off instead of hot-spinning at the floor. Auth failures take two forms: the gateway
 * rejects an expired-token upgrade with HTTP 401 (delivered to {@link Listener#onFailure}), and a
 * {@code 1008} wiring-fault close. Both trigger a single-flight reauth via {@link
 * VaultController#reauth()}; on success the next reconnect uses the fresh token, on a transient
 * failure backoff continues, and only a definitive rejection (404/401/403) halts the chain.
 */
public final class Connection {
  public interface Handler {
    void onMessage(Map<String, Object> msg);
  }

  private static final long RECONNECT_INITIAL_MS = 250;
  private static final long RECONNECT_CAP_MS = 30_000;
  /** A socket open at least this long counts as "stable" — its close resets the backoff counter. */
  private static final long RECONNECT_STABLE_MS = 30_000;
  private static final ScheduledExecutorService SCHED =
      Executors.newScheduledThreadPool(
          1,
          r -> {
            Thread t = new Thread(r, "unimo-ws-reconnect");
            t.setDaemon(true);
            return t;
          });
  private static final OkHttpClient CLIENT =
      new OkHttpClient.Builder().pingInterval(20, TimeUnit.SECONDS).readTimeout(0, TimeUnit.SECONDS).build();

  private final String wsBase;
  private final String path;
  private final VaultController vault;
  private final Map<String, Set<Handler>> handlers = new ConcurrentHashMap<>();
  private final Set<CompletableFuture<Map<String, Object>>> pending = ConcurrentHashMap.newKeySet();

  private volatile WebSocket ws;
  private volatile boolean connected;
  private volatile boolean stopped;
  private volatile int generation;
  private int reconnectAttempt;
  private ScheduledFuture<?> reconnectTask;

  public Connection(String serviceUrl, VaultController vault) {
    this.wsBase = httpToWs(serviceUrl.replaceAll("/+$", ""));
    this.path = "/api/ws";
    this.vault = vault;
  }

  public void start() {
    stopped = false;
    generation++; // invalidate any in-flight reauth from a prior connection
    // Fresh start = fresh intent: clear any stale elevated counter. Under the same lock as
    // scheduleReconnect so the write is visible to the reconnect thread (reconnectAttempt isn't volatile).
    synchronized (this) {
      reconnectAttempt = 0;
    }
    open();
  }

  public void stop() {
    stopped = true;
    generation++; // any in-flight reauth must not scheduleReconnect on the restarted connection
    if (reconnectTask != null) reconnectTask.cancel(false);
    WebSocket w = this.ws;
    if (w != null) {
      try {
        w.close(1000, "client stop");
      } catch (RuntimeException ignored) {
      }
      this.ws = null;
    }
    connected = false;
    failPending("client stop");
  }

  /** Register a handler for a server message {@code type}; returns an unsubscribe handle. */
  public ReactiveValue.Subscription on(String type, Handler handler) {
    handlers.computeIfAbsent(type, k -> ConcurrentHashMap.newKeySet()).add(handler);
    return () -> {
      Set<Handler> set = handlers.get(type);
      if (set != null) set.remove(handler);
    };
  }

  public boolean send(Map<String, Object> msg) {
    WebSocket w = this.ws;
    if (w == null || !connected) return false;
    try {
      return w.send(Json.canonical(msg));
    } catch (RuntimeException e) {
      return false;
    }
  }

  public boolean isOpen() {
    return connected;
  }

  /**
   * Starts an id-correlated request/response exchange (the gateway echoes the client-generated
   * {@code id} on every reply frame). {@code msg} is sent with a fresh id; the returned builder's
   * {@link WsRequest#send()} future completes with the first {@code terminalType} frame carrying
   * that id. A gateway {@code error} frame rejects with a {@link CodedException} (the frame's
   * {@code code}, or {@code WS_ERROR}); no reply within the timeout rejects with
   * {@code WS_TIMEOUT}; a closed socket rejects immediately — and a socket close or failure
   * mid-exchange rejects the in-flight future — with {@code CONNECTION_CLOSED}. An exception
   * thrown by an {@link WsRequest#onFrame} handler rejects with {@code HANDLER_ERROR}, the
   * throw as cause.
   */
  public WsRequest request(String terminalType, Map<String, Object> msg) {
    return new WsRequest(terminalType, msg);
  }

  /** One request/response exchange over the socket — see {@link #request(String, Map)}. */
  public final class WsRequest {
    private final String terminalType;
    private final Map<String, Object> msg;
    private String intermediateType;
    private Handler intermediateHandler;
    private long timeoutMs = 20_000;

    private WsRequest(String terminalType, Map<String, Object> msg) {
      this.terminalType = terminalType;
      this.msg = msg;
    }

    /** Also deliver non-terminal {@code type} frames carrying this request's id (e.g. the early
     *  {@code search:suggestions} frame the gateway emits before {@code search:results}) — a
     *  throw from {@code handler} rejects the {@link #send()} future with {@code HANDLER_ERROR}. */
    public WsRequest onFrame(String type, Handler handler) {
      this.intermediateType = type;
      this.intermediateHandler = handler;
      return this;
    }

    public WsRequest timeoutMs(long ms) {
      this.timeoutMs = ms;
      return this;
    }

    public CompletableFuture<Map<String, Object>> send() {
      String id = UUID.randomUUID().toString();
      CompletableFuture<Map<String, Object>> future = new CompletableFuture<>();
      pending.add(future);

      // Register before sending so a fast reply can't slip past the handlers.
      ReactiveValue.Subscription terminal =
          on(terminalType, m -> {
            if (id.equals(m.get("id"))) future.complete(m);
          });
      ReactiveValue.Subscription error =
          on("error", m -> {
            if (!id.equals(m.get("id"))) return;
            Object code = m.get("code");
            future.completeExceptionally(
                new CodedException(String.valueOf(m.get("error")), code != null ? String.valueOf(code) : "WS_ERROR"));
          });
      ReactiveValue.Subscription intermediate =
          intermediateHandler == null
              ? null
              : on(intermediateType, m -> {
                if (!id.equals(m.get("id"))) return;
                try {
                  intermediateHandler.onMessage(m);
                } catch (RuntimeException e) {
                  future.completeExceptionally(
                      new CodedException("onFrame handler threw: " + e, "HANDLER_ERROR", e));
                }
              });
      ScheduledFuture<?> timer =
          SCHED.schedule(
              () -> future.completeExceptionally(
                  new CodedException("no " + terminalType + " within " + timeoutMs + "ms", "WS_TIMEOUT")),
              timeoutMs,
              TimeUnit.MILLISECONDS);

      future.whenComplete(
          (r, e) -> {
            pending.remove(future);
            timer.cancel(false);
            terminal.close();
            error.close();
            if (intermediate != null) intermediate.close();
          });

      Map<String, Object> withId = new LinkedHashMap<>(msg);
      withId.put("id", id);
      if (!Connection.this.send(withId)) {
        future.completeExceptionally(new CodedException("WebSocket not connected", "CONNECTION_CLOSED"));
      }
      return future;
    }
  }

  private void open() {
    if (stopped) return;
    if (this.ws != null) return; // already connecting/connected; generation guard covers reauth races
    String token = vault.getAuthToken();
    if (token == null) {
      scheduleReconnect();
      return;
    }
    // token (130-hex), vid/mid (64-hex) are all URL-safe — no percent-encoding needed.
    String url = wsBase + path + "?token=" + token + "&vid=" + vault.getId() + "&mid=" + vault.getMemberId();
    this.ws = CLIENT.newWebSocket(new Request.Builder().url(url).build(), new Listener());
  }

  private void dispatch(String text) {
    Map<String, Object> msg;
    try {
      Object o = Json.parse(text);
      if (!(o instanceof Map)) return;
      @SuppressWarnings("unchecked")
      Map<String, Object> m = (Map<String, Object>) o;
      msg = m;
    } catch (RuntimeException e) {
      return;
    }
    Object type = msg.get("type");
    if (!(type instanceof String)) return;
    Set<Handler> set = handlers.get(type);
    if (set == null) return;
    for (Handler h : set) {
      try {
        h.onMessage(msg);
      } catch (RuntimeException e) {
        System.err.println("[Connection] handler error for " + type + " id=" + msg.get("id") + ": " + e);
      }
    }
  }

  private void scheduleReconnect() {
    scheduleReconnect(false);
  }

  /**
   * Schedules the next {@link #open()}; {@code resetBackoff=true} zeroes the attempt counter (after
   * a fresh token, or a stable connection's close) so reconnect is fast. The counter is what backs
   * off — a {@code false} call keeps climbing toward {@link #RECONNECT_CAP_MS}, which is what stops
   * a rejected-upgrade / rapid-die loop from hot-spinning at {@link #RECONNECT_INITIAL_MS}.
   */
  private synchronized void scheduleReconnect(boolean resetBackoff) {
    if (stopped) return;
    if (resetBackoff) reconnectAttempt = 0;
    if (reconnectTask != null && !reconnectTask.isDone()) return;
    int attempt = reconnectAttempt++;
    double exp = Math.min(RECONNECT_INITIAL_MS * Math.pow(2, attempt), RECONNECT_CAP_MS);
    double jitter = exp * 0.5 * ThreadLocalRandom.current().nextDouble();
    long delay = (long) Math.floor(exp - exp * 0.25 + jitter);
    reconnectTask = SCHED.schedule(this::open, delay, TimeUnit.MILLISECONDS);
  }

  /** A socket open at least {@link #RECONNECT_STABLE_MS} resets backoff on close. 0 (never opened,
   *  i.e. a rejected upgrade) does not — that is the guard against hot-looping. Static for testing. */
  static boolean shouldResetBackoff(long uptimeMs) {
    return uptimeMs >= RECONNECT_STABLE_MS;
  }

  /** Whether a failed WS upgrade with this HTTP status should trigger a reauth before reconnecting.
   *  401 = expired/invalid token; 410 = manifest missing (a false 410 self-heals via reauth; a true
   *  one yields 404 → REJECTED → halt). 0/transport-error/5xx/403… just reconnect. Static for testing. */
  static boolean shouldReauthAfterUpgradeFailure(int status) {
    return status == 401 || status == 410;
  }

  /**
   * Reauths (single-flight via {@link VaultController#reauth()}) then reconnects on the outcome.
   * Called from {@link Listener#onFailure} on an HTTP 401/410 upgrade rejection (the expired-token
   * case) and from {@link Listener#onClosed} on a {@code 1008} close. A {@code generation} snapshot
   * drops the completion if a {@link #stop()}/{@link #start()} cycle happened in the meantime, so a
   * late reauth can't double-open a socket on a restarted connection.
   */
  private void runReauthThenReconnect(long closedUptimeMs) {
    final int gen = generation;
    vault
        .reauth()
        .whenComplete(
            (outcome, err) -> {
              if (stopped || gen != generation) return;
              // reauth() always completes normally (TRANSIENT on any failure, incl. a sync throw),
              // so outcome is non-null and err is null — switch directly on it.
              switch (outcome) {
                case REFRESHED:
                  scheduleReconnect(true); // fresh token — reconnect promptly
                  break;
                case TRANSIENT:
                  scheduleReconnect(shouldResetBackoff(closedUptimeMs));
                  break;
                case REJECTED:
                default:
                  System.err.println(
                      "[Connection] reauth rejected (404/401/403 — account/member problem)"
                          + " — connection halted");
                  break;
              }
            });
  }

  /** Rejects all in-flight request futures: the gateway replies on the connection a request
   *  arrived on, so once that socket is gone no reply is coming. Completed futures no-op. */
  private void failPending(String message) {
    for (CompletableFuture<Map<String, Object>> f : pending) {
      f.completeExceptionally(new CodedException(message, "CONNECTION_CLOSED"));
    }
  }

  private final class Listener extends WebSocketListener {
    /** Wall-clock ms when onOpen fired; 0 until then. Per-instance so a rejected upgrade (which
     *  never opens) can't borrow a prior connection's uptime to reset backoff — the hot-loop bug. */
    private long openedAtMs;

    private long uptimeMs() {
      return openedAtMs == 0 ? 0 : System.currentTimeMillis() - openedAtMs;
    }

    @Override
    public void onOpen(WebSocket webSocket, Response response) {
      connected = true;
      openedAtMs = System.currentTimeMillis();
      // Backoff is reset on close (stability-gated in scheduleReconnect), NOT here — resetting
      // here would let an accept-then-immediately-die cycle hot-loop at the 250ms floor.
    }

    @Override
    public void onMessage(WebSocket webSocket, String text) {
      dispatch(text);
    }

    @Override
    public void onClosing(WebSocket webSocket, int code, String reason) {
      try {
        webSocket.close(1000, null); // complete the close handshake
      } catch (RuntimeException ignored) {
      }
    }

    @Override
    public void onClosed(WebSocket webSocket, int code, String reason) {
      connected = false;
      Connection.this.ws = null;
      long uptime = uptimeMs();
      // After connected=false: a send() racing this close either sees the flag (fails fast) or
      // its already-registered future is failed here — no request can slip through unrejected.
      failPending("WebSocket closed: " + code + " " + reason);
      if (stopped) return;
      if (code == 1008) {
        // 1008 is a policy/wiring-fault close (the gateway rejects expired auth at the HTTP
        // upgrade as 401, not via 1008); refresh the token, then reconnect on the outcome.
        runReauthThenReconnect(uptime);
        return;
      }
      scheduleReconnect(shouldResetBackoff(uptime));
    }

    @Override
    public void onFailure(WebSocket webSocket, Throwable t, Response response) {
      connected = false;
      Connection.this.ws = null;
      long uptime = uptimeMs();
      failPending("WebSocket failure: " + t);
      if (stopped) return;
      int status = response != null ? response.code() : 0;
      if (shouldReauthAfterUpgradeFailure(status)) {
        // Upgrade rejected: 401 = expired/invalid token; 410 = manifest missing (also revokes the
        // token). Reauth instead of looping on the stale token — this is the expired-token path.
        runReauthThenReconnect(uptime);
        return;
      }
      scheduleReconnect(shouldResetBackoff(uptime));
    }
  }

  private static String httpToWs(String url) {
    if (url.startsWith("https://")) return "wss://" + url.substring("https://".length());
    if (url.startsWith("http://")) return "ws://" + url.substring("http://".length());
    return url;
  }
}
