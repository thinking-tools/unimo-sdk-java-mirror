package com.unimo.sdk.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.unimo.sdk.crypto.CodedException;
import com.unimo.sdk.shared.Json;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The request frame matches what the TS SDK sends (llm.test.ts) and llm:end parses; an empty turn never hits the wire. */
class LLMTest {
  @Test
  void frameOmitsUnsetOptionsAndKeepsMessageOrder() {
    LLM.Options o = new LLM.Options();
    assertEquals(
        Json.obj("type", "llm:request", "messages", Json.arr(Json.obj("role", "user", "content", "hi"))),
        LLM.frame(Collections.singletonList(new LLM.Message("user", "hi")), o));
    o.expert = true;
    o.maxTokens = 50;
    Map<String, Object> f = LLM.frame(
        Arrays.asList(new LLM.Message("system", "s"), new LLM.Message("user", "u")), o);
    assertEquals(true, f.get("expert"));
    assertEquals(Json.obj("max_tokens", 50), f.get("params"));
    assertEquals(Json.arr(Json.obj("role", "system", "content", "s"), Json.obj("role", "user", "content", "u")), f.get("messages"));
  }

  @Test
  void endFrameParsesWithAndWithoutUsage() {
    LLM.Turn t = LLM.parseTurn(Json.parseObject(
        "{\"type\":\"llm:end\",\"id\":\"1\",\"finishReason\":\"stop\",\"usage\":{\"prompt_tokens\":1,\"completion_tokens\":2,\"total_tokens\":3}}"),
        "Hello");
    assertEquals("Hello", t.text);
    assertEquals("stop", t.finishReason);
    assertEquals(3, t.usage.totalTokens);
    assertNull(LLM.parseTurn(Json.obj("type", "llm:end", "finishReason", "length"), "").usage);
  }

  @Test
  void emptyTurnRejectedLocally() {
    LLM llm = new LLM(new Connection("http://localhost", null));
    CodedException e = assertThrows(CodedException.class, () -> llm.complete(Collections.emptyList()));
    assertEquals("EMPTY_MESSAGES", e.getCode());
  }
}
