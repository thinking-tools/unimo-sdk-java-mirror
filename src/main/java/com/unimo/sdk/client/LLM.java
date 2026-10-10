package com.unimo.sdk.client;

import com.unimo.sdk.crypto.CodedException;
import com.unimo.sdk.shared.Json;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * Typed client for the gateway's WebSocket {@code llm} domain: one streamed text turn per call
 * (protocol in {@code secure.gateway.unimo/src/ws/messages.ts}). Port of
 * {@code sdk-ts/src_ts/client/LLM.ts}; keep the two aligned. Text only — no tools are declared,
 * so the gateway never relays a tool call back here.
 *
 * <p>{@link #complete} sends {@code llm:request}, hands every {@code llm:delta} to the optional
 * callback and resolves on {@code llm:end} with the joined text. Quota-counted. A gateway fault
 * rejects with a {@link CodedException} carrying its code ({@code LLM_DISABLED}, {@code UPSTREAM},
 * {@code RATE_LIMITED}, …); {@code CONNECTION_CLOSED} / {@code WS_TIMEOUT} as for every request.
 * Cancelling the returned future tells the gateway with {@code llm:cancel} — the Java stand-in
 * for the TS {@code AbortSignal} option.
 */
public final class LLM {
  /** A model turn can run for minutes; the request builder's 20s default is for lookups. A dead
   *  socket is caught by the connection heartbeat and a stalled upstream by the gateway's own
   *  timeouts, so this is only a backstop. */
  static final long TURN_TIMEOUT_MS = 5 * 60_000L;

  /** OpenAI-style chat message, forwarded to the gateway as is. */
  public static final class Message {
    /** {@code system} / {@code user} / {@code assistant}. */
    public final String role;
    public final String content;

    public Message(String role, String content) {
      this.role = role;
      this.content = content;
    }
  }

  public static final class Usage {
    public final int promptTokens;
    public final int completionTokens;
    public final int totalTokens;

    Usage(int promptTokens, int completionTokens, int totalTokens) {
      this.promptTokens = promptTokens;
      this.completionTokens = completionTokens;
      this.totalTokens = totalTokens;
    }
  }

  public static final class Turn {
    /** Every streamed delta, joined. */
    public final String text;
    /** Why the turn ended: {@code stop}, {@code length} (cut at the token cap),
     *  {@code content_filter}, or the gateway-injected {@code max_iterations}. */
    public final String finishReason;
    /** Summed over the turn, or null when the gateway omitted it. */
    public final Usage usage;

    Turn(String text, String finishReason, Usage usage) {
      this.text = text;
      this.finishReason = finishReason;
      this.usage = usage;
    }
  }

  /** Unset (null) fields are omitted from the frame. */
  public static final class Options {
    /** Route to the expert tier; rejects with {@code TIER_UNAVAILABLE} when the deployment has none. */
    public Boolean expert;
    /** Output cap; the gateway clamps it to its own maximum. */
    public Integer maxTokens;
    /** Each streamed text piece, in order, on the socket's reader thread, before the future resolves. */
    public Consumer<String> onDelta;
    public long timeoutMs = TURN_TIMEOUT_MS;
  }

  private final Connection connection;

  public LLM(Connection connection) {
    this.connection = connection;
  }

  /** One complete turn ({@code llm:request} → {@code llm:delta}… → {@code llm:end}) with default options. */
  public CompletableFuture<Turn> complete(List<Message> messages) {
    return complete(messages, null);
  }

  /** One complete turn; see the class doc. Throws {@code EMPTY_MESSAGES} synchronously on an empty list. */
  public CompletableFuture<Turn> complete(List<Message> messages, Options options) {
    if (messages == null || messages.isEmpty()) throw new CodedException("No messages", "EMPTY_MESSAGES");
    final Options o = options == null ? new Options() : options;
    // Deltas and the terminal frame arrive on the socket's reader thread, so no locking.
    final StringBuilder text = new StringBuilder();
    final CompletableFuture<Map<String, Object>> end =
        connection
            .request("llm:end", frame(messages, o))
            .onFrame("llm:delta", m -> {
              Object delta = m.get("delta");
              if (!(delta instanceof String)) return;
              text.append((String) delta);
              if (o.onDelta != null) o.onDelta.accept((String) delta);
            })
            .timeoutMs(o.timeoutMs)
            .cancelWith("llm:cancel")
            .send();
    final CompletableFuture<Turn> turn = end.thenApply(m -> parseTurn(m, text.toString()));
    turn.whenComplete((t, e) -> { if (turn.isCancelled()) end.cancel(false); });
    return turn;
  }

  static Map<String, Object> frame(List<Message> messages, Options o) {
    List<Object> msgs = new ArrayList<>(messages.size());
    for (Message m : messages) msgs.add(Json.obj("role", m.role, "content", m.content));
    Map<String, Object> f = Json.obj("type", "llm:request", "messages", msgs);
    if (o.expert != null) f.put("expert", o.expert);
    if (o.maxTokens != null) f.put("params", Json.obj("max_tokens", o.maxTokens));
    return f;
  }

  @SuppressWarnings("unchecked")
  static Turn parseTurn(Map<String, Object> end, String text) {
    Object u = end.get("usage");
    Usage usage = null;
    if (u instanceof Map) {
      Map<String, Object> m = (Map<String, Object>) u;
      usage = new Usage(num(m.get("prompt_tokens")), num(m.get("completion_tokens")), num(m.get("total_tokens")));
    }
    Object reason = end.get("finishReason");
    return new Turn(text, reason == null ? null : String.valueOf(reason), usage);
  }

  private static int num(Object v) {
    return v instanceof Number ? ((Number) v).intValue() : 0;
  }
}
