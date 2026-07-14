package com.unimo.sdk.client;

import com.unimo.sdk.crypto.CodedException;
import com.unimo.sdk.shared.Json;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * Typed client for the gateway's WebSocket {@code search} domain (protocol in
 * {@code secure.gateway.unimo/src/protocol/messages.ts}, engine in {@code src/search-engine.ts}).
 * Java-first addition: there is no {@code sdk/ts/src_ts} original yet — when the TS SDK gains
 * one, re-align this class with it (the port direction is normally TS → Java).
 *
 * <p>{@link #suggest} sends {@code search:typing} and resolves the {@code search:suggestions}
 * reply (cache/Google-Suggest backed; free, not quota-counted). {@link #search} sends
 * {@code search:query} and resolves the {@code search:results} reply (provider-backed, counted
 * against the vault's search quota); the early {@code search:suggestions} frame the gateway emits
 * before results is surfaced via the optional callback (a throwing callback rejects the future).
 * Both need an open {@link Connection} and
 * reject with {@code CONNECTION_CLOSED} / {@code WS_TIMEOUT} / the gateway's error code otherwise.
 */
public final class Search {
  /** One organic result from the gateway's sanitized provider response. */
  public static final class Result {
    public final String title;
    public final String url;
    public final String description;
    /** Provider age string (e.g. "2 days ago"), or null. */
    public final String age;
    /** Favicon URL, or null. */
    public final String favicon;

    Result(String title, String url, String description, String age, String favicon) {
      this.title = title;
      this.url = url;
      this.description = description;
      this.age = age;
      this.favicon = favicon;
    }
  }

  /** A full {@code search:results} payload. */
  public static final class Response {
    public final String query;
    public final List<Result> results;
    /** True when served from the gateway's semantic/exact cache instead of a live provider. */
    public final boolean cached;

    Response(String query, List<Result> results, boolean cached) {
      this.query = query;
      this.results = results;
      this.cached = cached;
    }
  }

  private final Connection connection;

  public Search(Connection connection) {
    this.connection = connection;
  }

  /** Typing-time suggestions ({@code search:typing} → {@code search:suggestions}). */
  public CompletableFuture<List<String>> suggest(String query) {
    String q = requireQuery(query);
    return connection
        .request("search:suggestions", Json.obj("type", "search:typing", "query", q))
        .send()
        .thenApply(Search::parseSuggestions);
  }

  /** Full search ({@code search:query} → {@code search:results}); the suggestions frame is dropped. */
  public CompletableFuture<Response> search(String query) {
    return search(query, null);
  }

  /** Full search; the gateway's early {@code search:suggestions} frame feeds {@code onSuggestions} —
   *  a throw from that callback rejects the returned future ({@code HANDLER_ERROR}). */
  public CompletableFuture<Response> search(String query, Consumer<List<String>> onSuggestions) {
    String q = requireQuery(query);
    Connection.WsRequest req = connection.request("search:results", Json.obj("type", "search:query", "query", q));
    if (onSuggestions != null) {
      req.onFrame("search:suggestions", m -> onSuggestions.accept(parseSuggestions(m)));
    }
    return req.send().thenApply(Search::parseResponse);
  }

  /** Fail fast on blank queries — the gateway would only echo an error frame back. */
  private static String requireQuery(String query) {
    String q = query == null ? "" : query.trim();
    if (q.isEmpty()) throw new CodedException("Empty query", "EMPTY_QUERY");
    return q;
  }

  @SuppressWarnings("unchecked")
  private static List<String> parseSuggestions(Map<String, Object> frame) {
    List<Object> raw = (List<Object>) frame.get("suggestions");
    List<String> out = new ArrayList<>();
    if (raw != null) for (Object s : raw) out.add(String.valueOf(s));
    return out;
  }

  @SuppressWarnings("unchecked")
  private static Response parseResponse(Map<String, Object> frame) {
    Map<String, Object> data = (Map<String, Object>) frame.get("data");
    if (data == null) throw new CodedException("search:results frame missing data", "BAD_FRAME");
    List<Object> raw = (List<Object>) data.get("results");
    List<Result> results = new ArrayList<>();
    if (raw != null) {
      for (Object o : raw) {
        if (!(o instanceof Map)) continue;
        Map<String, Object> r = (Map<String, Object>) o;
        results.add(
            new Result(str(r.get("title")), str(r.get("url")), str(r.get("description")), str(r.get("age")), str(r.get("favicon"))));
      }
    }
    return new Response(str(data.get("query")), results, Boolean.TRUE.equals(frame.get("cached")));
  }

  private static String str(Object v) {
    return v == null ? null : String.valueOf(v);
  }
}
