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
 * <p>Reconnect uses exponential backoff (250ms → 30s) with jitter. A {@code 1008} close (the
 * gateway's auth-failure code) triggers a reauth via {@link VaultController#handleAuthError}; if
 * that succeeds the next reconnect uses the refreshed token, otherwise the chain halts.
 */
public final class Connection {
  public interface Handler {
    void onMessage(Map<String, Object> msg);
  }

  private static final long RECONNECT_INITIAL_MS = 250;
  private static final long RECONNECT_CAP_MS = 30_000;
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
  private int reconnectAttempt;
  private ScheduledFuture<?> reconnectTask;

  public Connection(String serviceUrl, VaultController vault) {
    this.wsBase = httpToWs(serviceUrl.replaceAll("/+$", ""));
    this.path = "/api/ws";
    this.vault = vault;
  }

  public void start() {
    stopped = false;
    open();
  }

  public void stop() {
    stopped = true;
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

  private synchronized void scheduleReconnect() {
    if (stopped) return;
    if (reconnectTask != null && !reconnectTask.isDone()) return;
    int attempt = reconnectAttempt++;
    double exp = Math.min(RECONNECT_INITIAL_MS * Math.pow(2, attempt), RECONNECT_CAP_MS);
    double jitter = exp * 0.5 * ThreadLocalRandom.current().nextDouble();
    long delay = (long) Math.floor(exp - exp * 0.25 + jitter);
    reconnectTask = SCHED.schedule(this::open, delay, TimeUnit.MILLISECONDS);
  }

  /** Rejects all in-flight request futures: the gateway replies on the connection a request
   *  arrived on, so once that socket is gone no reply is coming. Completed futures no-op. */
  private void failPending(String message) {
    for (CompletableFuture<Map<String, Object>> f : pending) {
      f.completeExceptionally(new CodedException(message, "CONNECTION_CLOSED"));
    }
  }

  private final class Listener extends WebSocketListener {
    @Override
    public void onOpen(WebSocket webSocket, Response response) {
      connected = true;
      reconnectAttempt = 0;
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
      // After connected=false: a send() racing this close either sees the flag (fails fast) or
      // its already-registered future is failed here — no request can slip through unrejected.
      failPending("WebSocket closed: " + code + " " + reason);
      if (stopped) return;
      if (code == 1008) {
        // gateway auth-failure code — try a token refresh before reconnecting.
        vault
            .handleAuthError()
            .whenComplete(
                (ok, err) -> {
                  if (Boolean.TRUE.equals(ok)) scheduleReconnect();
                  else System.err.println("[Connection] auth refresh failed — connection halted");
                });
        return;
      }
      scheduleReconnect();
    }

    @Override
    public void onFailure(WebSocket webSocket, Throwable t, Response response) {
      connected = false;
      Connection.this.ws = null;
      failPending("WebSocket failure: " + t);
      if (!stopped) scheduleReconnect();
    }
  }

  private static String httpToWs(String url) {
    if (url.startsWith("https://")) return "wss://" + url.substring("https://".length());
    if (url.startsWith("http://")) return "ws://" + url.substring("http://".length());
    return url;
  }
}
