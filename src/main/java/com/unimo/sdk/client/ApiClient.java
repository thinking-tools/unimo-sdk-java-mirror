package com.unimo.sdk.client;

import com.unimo.sdk.crypto.CodedException;
import com.unimo.sdk.shared.Consts;
import com.unimo.sdk.shared.Helpers;
import com.unimo.sdk.shared.Json;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.ConnectionPool;
import okhttp3.Dispatcher;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * HTTP surface, port of {@code sdk/ts/src_ts/client/ApiClient.ts}. OkHttp under the hood; every
 * call returns a {@link CompletableFuture} (the TS SDK's only true async boundary — crypto is
 * synchronous in this port). {@link #makeRequest} throws on non-2xx (register/login/reauth);
 * {@link #authRequest} is non-throwing so callers can branch on 401 for token refresh.
 */
public final class ApiClient {
  /** True once the gateway has refused this build's API version: nothing will work until the app
   *  is updated, so the app shows its "update required" notice. It stays true, as the build cannot
   *  change while it runs. */
  public static final ReactiveValue<Boolean> UPGRADE_REQUIRED = new ReactiveValue<>(false);

  /** Every gateway answer passes through here, the WebSocket upgrade's included. The gateway names
   *  its minimum version only when refusing, so another 426 on the path is not taken for one.
   *  Synchronized to set once: {@code set} notifies every time, and from here on every request is
   *  refused. */
  static synchronized void noteRefusal(Response response) {
    if (response.header(Consts.HEADER_MIN_API_VERSION) != null && !UPGRADE_REQUIRED.get()) {
      UPGRADE_REQUIRED.set(true);
    }
  }

  private static final OkHttpClient CLIENT =
      new OkHttpClient.Builder()
          .connectTimeout(15, TimeUnit.SECONDS)
          .readTimeout(30, TimeUnit.SECONDS)
          .writeTimeout(30, TimeUnit.SECONDS)
          // Pooled sockets die silently while the app is backgrounded and OkHttp never retries a
          // sent POST on HTTP/2: drop idle connections early. The pool closes them on its own
          // thread; closing a TLS socket on Android's main thread throws NetworkOnMainThreadException.
          .connectionPool(new ConnectionPool(5, 10, TimeUnit.SECONDS))
          .build();

  /**
   * The owners {@link #cancelCalls} has ended: nothing of theirs is sent any more. Held weakly, so
   * a vault nobody uses any longer is forgotten, its keys with it. Guarded by itself.
   */
  private static final Set<Object> CANCELLED = Collections.newSetFromMap(new WeakHashMap<>());

  private ApiClient() {}

  /** A consumed HTTP response: status, body bytes, and lower-cased single-value headers. */
  public static final class ApiResponse {
    public final int status;
    public final byte[] body;
    public final Map<String, String> headers;

    ApiResponse(int status, byte[] body, Map<String, String> headers) {
      this.status = status;
      this.body = body;
      this.headers = headers;
    }

    public boolean ok() {
      return status >= 200 && status < 300;
    }

    public String text() {
      return Helpers.fromUtf8(body);
    }

    public Map<String, Object> jsonObject() {
      return Json.parseObject(text());
    }

    public String header(String name) {
      return headers.get(name.toLowerCase());
    }
  }

  /** JSON-body send. */
  public static CompletableFuture<ApiResponse> send(
      String method, String url, byte[] body, Map<String, String> headers, Object owner) {
    return send(method, url, body, "application/json", headers, owner);
  }

  /**
   * Core non-throwing send. Completes exceptionally only when no answer came (a transport failure,
   * or {@link #cancelCalls} ended the owner's requests), not on HTTP status. {@code owner} is the
   * vault whose request this is: null for a request of no vault, such as a login.
   */
  public static CompletableFuture<ApiResponse> send(
      String method, String url, byte[] body, String contentType, Map<String, String> headers, Object owner) {
    Request.Builder rb = new Request.Builder().url(url);
    for (Map.Entry<String, String> h : headers.entrySet()) rb.header(h.getKey(), h.getValue());
    rb.header(Consts.HEADER_API_VERSION, String.valueOf(Consts.API_VERSION));
    RequestBody reqBody = body == null ? null : RequestBody.create(body, MediaType.get(contentType));
    switch (method) {
      case "GET":
        rb.get();
        break;
      case "HEAD":
        rb.head();
        break;
      case "DELETE":
        if (reqBody == null) rb.delete();
        else rb.delete(reqBody);
        break;
      case "POST":
        rb.post(reqBody == null ? RequestBody.create(new byte[0], null) : reqBody);
        break;
      case "PUT":
        rb.put(reqBody == null ? RequestBody.create(new byte[0], null) : reqBody);
        break;
      default:
        throw new IllegalArgumentException("Unsupported method: " + method);
    }

    CompletableFuture<ApiResponse> future = new CompletableFuture<>();
    Callback whenAnswered =
        new Callback() {
          @Override
          public void onFailure(Call call, IOException e) {
            future.completeExceptionally(e);
          }

          @Override
          public void onResponse(Call call, Response response) {
            try (Response r = response) {
              noteRefusal(r);
              byte[] b = r.body() != null ? r.body().bytes() : new byte[0];
              Map<String, String> hs = new HashMap<>();
              for (Map.Entry<String, List<String>> e : r.headers().toMultimap().entrySet()) {
                if (!e.getValue().isEmpty()) hs.put(e.getKey(), e.getValue().get(0));
              }
              future.complete(new ApiResponse(r.code(), b, hs));
            } catch (Exception e) {
              future.completeExceptionally(e);
            }
          }
        };
    // One step with cancelCalls: a request is refused here or found there, never neither.
    synchronized (CANCELLED) {
      if (CANCELLED.contains(owner)) {
        future.completeExceptionally(canceled());
      } else {
        // Tagged for cancelCalls: whose request this is, and who waits for it.
        CLIENT.newCall(rb.tag(owner).tag(CompletableFuture.class, future).build()).enqueue(whenAnswered);
      }
    }
    return future;
  }

  /**
   * End the requests of {@code owner}, for good: each one it is still waiting for fails at once, as
   * on a lost connection, and one it sends later comes back failed the same way, unsent. Only that
   * owner's: {@link #CLIENT} serves every account in the process, and the login of the next one may
   * be on its way. Whoever waits is told here, not by OkHttp: it reports a cancel only when the call
   * next looks, which is not while a name is being resolved or while the call waits its turn behind
   * others. Told on OkHttp's threads, where the answer would have arrived: the caller may be
   * Android's main thread.
   */
  static void cancelCalls(Object owner) {
    Dispatcher dispatcher = CLIENT.dispatcher();
    List<Call> owned = new ArrayList<>();
    synchronized (CANCELLED) {
      CANCELLED.add(owner);
      // Queued before running: a call that starts in between is still in one of the two lists.
      owned.addAll(dispatcher.queuedCalls());
      owned.addAll(dispatcher.runningCalls());
    }
    owned.removeIf(call -> call.request().tag() != owner);
    if (owned.isEmpty()) return;
    dispatcher
        .executorService()
        .execute(
            () -> {
              for (Call call : owned) {
                call.cancel();
                CompletableFuture<?> waiting = call.request().tag(CompletableFuture.class);
                waiting.completeExceptionally(canceled());
              }
            });
  }

  /** What a cancelled request fails with, worded as OkHttp words its own. */
  private static IOException canceled() {
    return new IOException("Canceled");
  }

  /** Unauthenticated JSON request that throws on non-2xx (register / login / reauth flows); the
   *  thrown code is {@link #errorCode}. */
  public static CompletableFuture<Map<String, Object>> makeRequest(String method, String url, Map<String, Object> body) {
    byte[] payload = body == null ? null : Helpers.utf8(Json.canonical(body));
    return send(method, url, payload, Collections.emptyMap(), null)
        .thenApply(
            resp -> {
              if (!resp.ok()) {
                throw new CodedException("HTTP " + resp.status + ": " + resp.text(), errorCode(resp));
              }
              return resp.jsonObject();
            });
  }

  /** The gateway's JSON {@code code} for a non-2xx response (e.g. {@code NOT_A_MEMBER}), else
   *  {@code HTTP_<status>}. */
  static String errorCode(ApiResponse resp) {
    try {
      Object code = resp.jsonObject().get("code");
      if (code instanceof String) return (String) code;
    } catch (RuntimeException ignored) {
    }
    return "HTTP_" + resp.status;
  }

  /** Bearer-authenticated request; non-throwing (caller inspects status, e.g. 401 → reauth).
   *  {@code owner}: see {@link #send}. */
  public static CompletableFuture<ApiResponse> authRequest(
      String method, String url, String authToken, Map<String, Object> body, Map<String, String> extraHeaders, Object owner) {
    Map<String, String> headers = new HashMap<>();
    if (extraHeaders != null) headers.putAll(extraHeaders);
    headers.put("Authorization", "Bearer " + authToken);
    byte[] payload = body == null ? null : Helpers.utf8(Json.canonical(body));
    return send(method, url, payload, headers, owner);
  }
}
