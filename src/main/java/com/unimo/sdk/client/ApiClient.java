package com.unimo.sdk.client;

import com.unimo.sdk.crypto.CodedException;
import com.unimo.sdk.shared.Helpers;
import com.unimo.sdk.shared.Json;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import okhttp3.Call;
import okhttp3.Callback;
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
  private static final OkHttpClient CLIENT =
      new OkHttpClient.Builder()
          .connectTimeout(15, TimeUnit.SECONDS)
          .readTimeout(30, TimeUnit.SECONDS)
          .writeTimeout(30, TimeUnit.SECONDS)
          .build();

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
  public static CompletableFuture<ApiResponse> send(String method, String url, byte[] body, Map<String, String> headers) {
    return send(method, url, body, "application/json", headers);
  }

  /** Core non-throwing send. Completes exceptionally only on transport failure, not on HTTP status. */
  public static CompletableFuture<ApiResponse> send(
      String method, String url, byte[] body, String contentType, Map<String, String> headers) {
    Request.Builder rb = new Request.Builder().url(url);
    for (Map.Entry<String, String> h : headers.entrySet()) rb.header(h.getKey(), h.getValue());
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
    CLIENT.newCall(rb.build())
        .enqueue(
            new Callback() {
              @Override
              public void onFailure(Call call, IOException e) {
                future.completeExceptionally(e);
              }

              @Override
              public void onResponse(Call call, Response response) {
                try (Response r = response) {
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
            });
    return future;
  }

  /** Unauthenticated JSON request that throws on non-2xx (register / login / reauth flows); the
   *  thrown code is {@link #errorCode}. */
  public static CompletableFuture<Map<String, Object>> makeRequest(String method, String url, Map<String, Object> body) {
    byte[] payload = body == null ? null : Helpers.utf8(Json.canonical(body));
    return send(method, url, payload, Collections.emptyMap())
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

  /** Bearer-authenticated request; non-throwing (caller inspects status, e.g. 401 → reauth). */
  public static CompletableFuture<ApiResponse> authRequest(
      String method, String url, String authToken, Map<String, Object> body, Map<String, String> extraHeaders) {
    Map<String, String> headers = new HashMap<>();
    if (extraHeaders != null) headers.putAll(extraHeaders);
    headers.put("Authorization", "Bearer " + authToken);
    byte[] payload = body == null ? null : Helpers.utf8(Json.canonical(body));
    return send(method, url, payload, headers);
  }
}
