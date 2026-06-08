package com.unimo.sdk.client;

import com.unimo.sdk.shared.Json;
import java.util.Map;
import java.util.Set;
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
        System.err.println("[Connection] handler error: " + e);
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
      if (!stopped) scheduleReconnect();
    }
  }

  private static String httpToWs(String url) {
    if (url.startsWith("https://")) return "wss://" + url.substring("https://".length());
    if (url.startsWith("http://")) return "ws://" + url.substring("http://".length());
    return url;
  }
}
