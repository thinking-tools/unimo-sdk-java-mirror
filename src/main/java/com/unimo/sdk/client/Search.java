package com.unimo.sdk.client;

import com.unimo.sdk.crypto.CodedException;
import com.unimo.sdk.shared.Json;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * Typed client for the gateway's WebSocket {@code search} domain (protocol in
 * {@code secure.gateway.unimo/src/ws/messages.ts}, engine in {@code src/search-engine.ts}).
 * Port of {@code sdk-ts/src_ts/client/Search.ts}; keep the two aligned.
 *
 * <p>{@link #suggest} sends {@code search:typing} and resolves the {@code search:suggestions}
 * reply (cache/Google-Suggest backed; free, not quota-counted). {@link #search} sends
 * {@code search:query} and resolves the {@code search:results} reply (provider-backed, counted
 * against the vault's search quota); the early {@code search:suggestions} frame the gateway emits
 * before results is surfaced via the optional callback (a throwing callback rejects the future).
 * {@link #searchImages} is the same exchange with {@code vertical: "images"}; it resolves image
 * rows and is never cached by the gateway. Every call takes optional {@link Options}.
 * All need an open {@link Connection} and
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

  /** One image row of an {@code images}-vertical reply; {@code src} is the provider thumbnail. */
  public static final class ImageResult {
    public final String title;
    public final String url;
    public final String src;
    /** Full image pixel size, or null when the provider omitted it. */
    public final Integer width;
    public final Integer height;

    ImageResult(String title, String url, String src, Integer width, Integer height) {
      this.title = title;
      this.url = url;
      this.src = src;
      this.width = width;
      this.height = height;
    }
  }

  /** A full {@code search:results} payload for the images vertical. */
  public static final class ImageResponse {
    public final String query;
    public final List<ImageResult> results;
    public final boolean cached;

    ImageResponse(String query, List<ImageResult> results, boolean cached) {
      this.query = query;
      this.results = results;
      this.cached = cached;
    }
  }

  /**
   * Provider-neutral search options, forwarded to the gateway unvalidated; a bad value rejects
   * with {@code INVALID_OPTIONS}. An axis a provider lacks is silently ignored. Unset (null or
   * empty) fields are omitted from the frame.
   */
  public static final class Options {
    /** ISO 3166-1 alpha-2, e.g. {@code "DE"}. */
    public String country;
    /** ISO 639-1, e.g. {@code "de"}. */
    public String lang;
    /** Free-text locality ≤ 64 chars; requires {@link #country}. */
    public String city;
    /** {@code off} / {@code moderate} / {@code strict}; images honour only {@code off}. */
    public String safesearch;
    /** {@code day} / {@code week} / {@code month} / {@code year}; results are never cached when set. */
    public String freshness;

    /** The {@code options} object for a frame; null when nothing is set. */
    Map<String, Object> toJson() {
      Map<String, Object> m = new LinkedHashMap<>();
      put(m, "country", country);
      put(m, "lang", lang);
      put(m, "city", city);
      put(m, "safesearch", safesearch);
      put(m, "freshness", freshness);
      return m.isEmpty() ? null : m;
    }

    private static void put(Map<String, Object> m, String key, String value) {
      if (value != null && !value.isEmpty()) m.put(key, value);
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
    return suggest(query, null);
  }

  /** Typing-time suggestions, localised by {@code options} (country / lang only). */
  public CompletableFuture<List<String>> suggest(String query, Options options) {
    String q = requireQuery(query);
    return connection
        .request("search:suggestions", frame("search:typing", q, null, options))
        .send()
        .thenApply(Search::parseSuggestions);
  }

  /** Full search ({@code search:query} → {@code search:results}); the suggestions frame is dropped. */
  public CompletableFuture<Response> search(String query) {
    return search(query, null, null);
  }

  /** Full search; the gateway's early {@code search:suggestions} frame feeds {@code onSuggestions} —
   *  a throw from that callback rejects the returned future ({@code HANDLER_ERROR}). */
  public CompletableFuture<Response> search(String query, Consumer<List<String>> onSuggestions) {
    return search(query, null, onSuggestions);
  }

  /** Full search with {@code options}; see {@link #search(String, Consumer)}. */
  public CompletableFuture<Response> search(String query, Options options, Consumer<List<String>> onSuggestions) {
    String q = requireQuery(query);
    Connection.WsRequest req = connection.request("search:results", frame("search:query", q, null, options));
    if (onSuggestions != null) {
      req.onFrame("search:suggestions", m -> onSuggestions.accept(parseSuggestions(m)));
    }
    return req.send().thenApply(Search::parseResponse);
  }

  /** Image search ({@code search:query} with {@code vertical: "images"}). Quota-counted, never cached. */
  public CompletableFuture<ImageResponse> searchImages(String query, Options options) {
    String q = requireQuery(query);
    return connection
        .request("search:results", frame("search:query", q, "images", options))
        .send()
        .thenApply(Search::parseImageResponse);
  }

  private static Map<String, Object> frame(String type, String query, String vertical, Options options) {
    Map<String, Object> m = Json.obj("type", type, "query", query);
    if (vertical != null) m.put("vertical", vertical);
    Map<String, Object> opts = options == null ? null : options.toJson();
    if (opts != null) m.put("options", opts);
    return m;
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

  @SuppressWarnings("unchecked")
  static ImageResponse parseImageResponse(Map<String, Object> frame) {
    Map<String, Object> data = (Map<String, Object>) frame.get("data");
    if (data == null) throw new CodedException("search:results frame missing data", "BAD_FRAME");
    List<Object> raw = (List<Object>) data.get("results");
    List<ImageResult> results = new ArrayList<>();
    if (raw != null) {
      for (Object o : raw) {
        if (!(o instanceof Map)) continue;
        Map<String, Object> r = (Map<String, Object>) o;
        results.add(new ImageResult(str(r.get("title")), str(r.get("url")), str(r.get("src")),
            num(r.get("width")), num(r.get("height"))));
      }
    }
    return new ImageResponse(str(data.get("query")), results, Boolean.TRUE.equals(frame.get("cached")));
  }

  private static String str(Object v) {
    return v == null ? null : String.valueOf(v);
  }

  private static Integer num(Object v) {
    return v instanceof Number ? ((Number) v).intValue() : null;
  }
}
