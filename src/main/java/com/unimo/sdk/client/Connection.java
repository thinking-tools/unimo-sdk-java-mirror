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
 * <p>Recovery is layered. A dropped or dead connection retries on exponential backoff (250ms →
 * 30s cap, with jitter — matching the TS original), and client pings make silent network loss
 * detectable: OkHttp's {@code pingInterval} fails the socket when pongs stop arriving, so a
 * half-open connection (gateway restart, NAT timeout, Doze suspension) can't linger as
 * {@code connected=true}. The app can accelerate recovery with OS events via {@link
 * #networkLost()} (kill the transport now instead of waiting for the pong timeout) and {@link
 * #networkAvailable()} (reconnect now) — both idempotent. Each connect attempt is bounded by a
 * call timeout (covers DNS, which {@code connectTimeout} does not), so a hung attempt can never
 * pin the connection. Auth failures recover on their own: the gateway rejects an expired-token
 * upgrade with HTTP 401 (delivered to {@link Listener#onFailure}), a close before open of any
 * code, or a {@code 1008} wiring-fault close; all trigger a single-flight reauth via {@link
 * VaultController#reauth()}. On success the connection reopens with the fresh token
 * (streak-capped so a token the gateway keeps rejecting can't loop unthrottled), a transient
 * failure keeps backing off, and a definitive rejection (404/401/403) halts the chain.
 */
public final class Connection {
  public interface Handler {
    void onMessage(Map<String, Object> msg);
  }

  /** Consecutive reauth→reopen cycles without a successful open before halting — the guard
   *  against a fresh token the gateway keeps rejecting (clock skew) looping unthrottled. */
  private static final int REAUTH_STREAK_CAP = 5;
  private static final long RECONNECT_INITIAL_MS = 250;
  private static final long RECONNECT_CAP_MS = 30_000;
  /** A socket open at least this long counts as "stable" — its close resets the backoff counter. */
  private static final long RECONNECT_STABLE_MS = 30_000;
  /** Backs the {@link WsRequest} per-request timeouts and the reconnect schedule. */
  private static final ScheduledExecutorService SCHED =
      Executors.newScheduledThreadPool(
          1,
          r -> {
            Thread t = new Thread(r, "unimo-ws-reconnect");
            t.setDaemon(true);
            return t;
          });
  /** callTimeout bounds each upgrade attempt end-to-end — including DNS, which connectTimeout
   *  does not cover — and stops applying once the socket is established. pingInterval detects
   *  silent network loss: OkHttp fails the socket when pongs stop arriving, which is the only
   *  way to notice a half-open connection (gateway restart, NAT timeout) without an OS event.
   *  The gateway (Bun, {@code sendPings} on) also pings; both directions coexist per RFC 6455. */
  private static final OkHttpClient CLIENT =
      new OkHttpClient.Builder()
          .callTimeout(15, TimeUnit.SECONDS)
          .pingInterval(20, TimeUnit.SECONDS)
          .readTimeout(0, TimeUnit.SECONDS)
          .build();

  private final String wsBase;
  private final String path;
  private final VaultController vault;
  private final Map<String, Set<Handler>> handlers = new ConcurrentHashMap<>();
  private final Set<Runnable> openListeners = ConcurrentHashMap.newKeySet();
  private final Set<CompletableFuture<Map<String, Object>>> pending = ConcurrentHashMap.newKeySet();

  private volatile WebSocket ws;
  private volatile boolean connected;
  private volatile boolean stopped;
  private volatile int generation;
  /** One-shot, armed by {@link #networkAvailable()} before it cancels a half-dead socket: that
   *  socket's terminal callback reopens once. Consumed unconditionally, so a failed reopen cannot
   *  loop without a fresh external event. */
  private volatile boolean reopenOnFailure;
  /** Consecutive REFRESHED-reauth reopens with no intervening onOpen; see {@link #REAUTH_STREAK_CAP}. */
  private volatile int reauthStreak;
  /** Backoff attempt counter — guarded by {@code this} (scheduleReconnect's lock). */
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
    reauthStreak = 0; // fresh start = fresh intent
    open();
  }

  public void stop() {
    stopped = true;
    generation++; // any in-flight reauth must not reopen on the restarted connection
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

  /**
   * OS-event entry point: the network just died (Android {@code NetworkCallback.onLost}). Cancels
   * the socket immediately — without pings, OkHttp never notices a silent network loss on its own,
   * so this is what turns an OS signal into the normal failure path (pending requests rejected,
   * state cleared). The connection then stays down until {@link #networkAvailable()}.
   */
  public void networkLost() {
    WebSocket w = this.ws;
    if (w != null) w.cancel();
  }

  /**
   * OS-event entry point: connectivity is back (Android {@code onAvailable} /
   * {@code onCapabilitiesChanged(VALIDATED)} / app resume). Reconnects now: opens directly when
   * nothing is live, or cancels a connecting/half-dead socket and arms a one-shot reopen from its
   * failure callback. Idempotent — a healthy connection is left alone, so calling it eagerly and
   * repeatedly is safe (and covers drops that happen with no network change, e.g. a gateway
   * restart, when wired to app resume).
   */
  public synchronized void networkAvailable() {
    if (stopped) return;
    reauthStreak = 0; // fresh external event = fresh intent
    if (reconnectTask != null) { // pending reconnect is superseded by an immediate open
      reconnectTask.cancel(false);
      reconnectTask = null;
    }
    WebSocket w = this.ws;
    if (w == null) {
      open();
    } else if (!connected) {
      reopenOnFailure = true; // consumed (once) by the cancelled socket's terminal callback
      w.cancel();
    }
  }

  /** Register a handler for a server message {@code type}; returns an unsubscribe handle. */
  public ReactiveValue.Subscription on(String type, Handler handler) {
    handlers.computeIfAbsent(type, k -> ConcurrentHashMap.newKeySet()).add(handler);
    return () -> {
      Set<Handler> set = handlers.get(type);
      if (set != null) set.remove(handler);
    };
  }

  /**
   * Run {@code listener} on every successful open — the first and each reconnect — on an OkHttp
   * thread. {@code vault:event} frames are live-only, so anything that happened while the socket
   * was down is only recoverable here (see {@link Tasker#hookVault}). Returns an unsubscribe handle.
   */
  public ReactiveValue.Subscription onOpen(Runnable listener) {
    openListeners.add(listener);
    return () -> openListeners.remove(listener);
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

  /** Synchronized: with no scheduler funnel, this races start(), networkAvailable(), the OkHttp
   *  terminal callbacks, and the reauth completion — the ws null-check must be atomic with the
   *  assignment. newWebSocket never invokes callbacks synchronously, so no deadlock risk. */
  private synchronized void open() {
    if (stopped) return;
    if (this.ws != null) return; // already connecting/connected; generation guard covers reauth races
    String token = vault.getAuthToken();
    if (token == null) { // pre-login; retry on backoff rather than waiting for an external event
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

  private synchronized void scheduleReconnect(boolean resetBackoff) {
    if (stopped) return;
    if (resetBackoff) reconnectAttempt = 0;
    if (reconnectTask != null && !reconnectTask.isDone()) return;
    int attempt = reconnectAttempt++;
    double exp = Math.min(RECONNECT_INITIAL_MS * Math.pow(2, attempt), RECONNECT_CAP_MS);
    // Uniform jitter over [0.75·exp, 1.25·exp)
    long delay = (long) (exp * (0.75 + 0.5 * ThreadLocalRandom.current().nextDouble()));
    reconnectTask = SCHED.schedule(this::open, delay, TimeUnit.MILLISECONDS);
  }

  /** Whether a failed WS upgrade with this HTTP status should trigger a reauth before reconnecting.
   *  401 = expired/invalid token; 410 = manifest missing (a false 410 self-heals via reauth; a true
   *  one yields 404 → REJECTED → halt). 0/transport-error/5xx/403… don't reauth — backoff retries
   *  them. Static for testing. */
  static boolean shouldReauthAfterUpgradeFailure(int status) {
    return status == 401 || status == 410;
  }

  /**
   * Reauths (single-flight via {@link VaultController#reauth()}) then acts on the outcome. Called
   * from {@link Listener#onFailure} on an HTTP 401/410 upgrade rejection (the expired-token case),
   * from {@link Listener#onClosed} on a {@code 1008} close, and from any close-before-open.
   * REFRESHED reconnects promptly (backoff reset), streak-capped by {@link #REAUTH_STREAK_CAP} so
   * a fresh token the gateway keeps rejecting (clock skew) can't loop unthrottled; TRANSIENT keeps
   * backing off; a definitive rejection (404/401/403) halts the chain. A {@code generation}
   * snapshot drops the completion if a {@link #stop()}/{@link #start()} cycle happened in the
   * meantime, so a late reauth can't double-open a socket on a restarted connection.
   */
  private void runReauthThenReconnect() {
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
                  if (++reauthStreak > REAUTH_STREAK_CAP) {
                    System.err.println(
                        "[Connection] reauth keeps succeeding but the upgrade keeps failing ("
                            + reauthStreak + "x) — reconnects throttled to backoff");
                    scheduleReconnect();
                    break;
                  }
                  scheduleReconnect(true); // fresh token — reconnect promptly
                  break;
                case TRANSIENT:
                  scheduleReconnect(); // transient failure — retry on backoff
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
    /** Wall-clock ms when onOpen fired. Per-instance so a rejected upgrade (which never opens)
     *  can't borrow a prior connection's uptime to reset backoff — the hot-loop bug. */
    private long openedAtMs;
    /** True once onOpen fired — a terminal callback before it is an upgrade that never opened. */
    private boolean opened;

    @Override
    public void onOpen(WebSocket webSocket, Response response) {
      connected = true;
      reauthStreak = 0; // a real open clears the reauth-loop streak
      opened = true;
      openedAtMs = System.currentTimeMillis();
      // Backoff is reset on close (stability-gated at the close site), NOT here — resetting
      // here would let an accept-then-immediately-die cycle hot-loop at the 250ms floor.
      for (Runnable l : openListeners) {
        try {
          l.run();
        } catch (RuntimeException e) {
          System.err.println("[Connection] open listener error: " + e);
        }
      }
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
      if (webSocket != Connection.this.ws) return; // stale socket (replaced or stop()ed) — no-op
      reopenOnFailure = false; // a clean close disarms a pending reopen
      connected = false;
      Connection.this.ws = null;
      // After connected=false: a send() racing this close either sees the flag (fails fast) or
      // its already-registered future is failed here — no request can slip through unrejected.
      failPending("WebSocket closed: " + code + " " + reason);
      if (stopped) return;
      if (code == 1008 || code == 4001) {
        // 1008 is a policy/wiring-fault close (the gateway rejects expired auth at the HTTP
        // upgrade as 401, not via 1008); 4001 is the gateway closing the socket because a manager
        // removed this member — the reauth then answers NOT_A_MEMBER → REVOKED → halt.
        runReauthThenReconnect();
        return;
      }
      if (!opened) {
        // Close-before-open (port of the TS 78ccfa1 fix): an upgrade the server accepted then
        // dropped without any auth signal. Refresh the token first — expiry is the common cause —
        // then reconnect regardless of the refresh outcome.
        runReauthThenReconnect();
        return;
      }
      scheduleReconnect(System.currentTimeMillis() - openedAtMs >= RECONNECT_STABLE_MS);
    }

    @Override
    public void onFailure(WebSocket webSocket, Throwable t, Response response) {
      if (webSocket != Connection.this.ws) return; // stale socket — no-op
      boolean reopen = reopenOnFailure;
      reopenOnFailure = false; // consume unconditionally: a failed reopen must not loop
      connected = false;
      Connection.this.ws = null;
      failPending("WebSocket failure: " + t);
      if (stopped) return;
      int status = response != null ? response.code() : 0;
      if (shouldReauthAfterUpgradeFailure(status)) {
        // Upgrade rejected: 401 = expired/invalid token; 410 = manifest missing (also revokes the
        // token). Reauth instead of looping on the stale token — this is the expired-token path.
        runReauthThenReconnect();
        return;
      }
      if (!opened) {
        // Failure-before-open without an auth status (transport error during upgrade): the TS
        // original reauths here too — a token rejected in a way that surfaces as a plain
        // transport failure otherwise needs a full backoff cycle before the 401 path is hit.
        runReauthThenReconnect();
        return;
      }
      if (reopen) {
        // networkAvailable() cancelled a half-dead socket — its terminal callback reopens now.
        open();
        return;
      }
      scheduleReconnect(System.currentTimeMillis() - openedAtMs >= RECONNECT_STABLE_MS);
    }
  }

  private static String httpToWs(String url) {
    if (url.startsWith("https://")) return "wss://" + url.substring("https://".length());
    if (url.startsWith("http://")) return "ws://" + url.substring("http://".length());
    return url;
  }
}
