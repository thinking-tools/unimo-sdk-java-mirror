package com.unimo.sdk.client.collections;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.Map;
import org.junit.jupiter.api.Test;

/** Same cases as sdk-ts {@code tests/kv.test.ts}: the remote snapshot is the base, not a union. */
class KVContentMergeTest {

  @Test
  void dropsKeysTheRemoteNoLongerHas() {
    // A delete on another device must land here, or this device's next save re-uploads the key.
    KVContent local = new KVContent(Map.of("a", 1L, "b", 2L));
    local.merge(new KVContent(Map.of("b", 2L)));
    assertEquals(Map.of("b", 2L), local.data.get());
  }

  @Test
  void reappliesPendingLocalOpsOnTopOfTheRemoteState() {
    KVContent local = new KVContent(Map.of("a", 1L, "stale", 1L));
    local.set("c", 3L);
    local.delete("a");
    local.merge(new KVContent(Map.of("a", 1L, "d", 4L)));
    assertEquals(Map.of("c", 3L, "d", 4L), local.data.get());
  }
}
