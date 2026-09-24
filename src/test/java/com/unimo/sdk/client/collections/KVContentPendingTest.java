package com.unimo.sdk.client.collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Same contract as sdk-ts {@code clearPending(uploaded)}: a save forgets only the ops it uploaded. */
class KVContentPendingTest {

  @Test
  void keepsOpsMadeWhileTheUploadWasInFlight() {
    // Clearing them would leave writes that were never uploaded looking saved.
    KVContent kv = new KVContent();
    kv.set("a", 1L);
    Map<String, Object> uploaded = kv.pendingSnapshot();
    kv.set("a", 2L);
    kv.delete("a");
    kv.set("b", 3L);
    kv.clearPending(uploaded);
    assertEquals(Set.of("a", "b"), kv.getPendingChanges().keySet());
  }

  @Test
  void forgetsTheUploadedOps() {
    KVContent kv = new KVContent();
    kv.set("a", 1L);
    kv.clearPending(kv.pendingSnapshot());
    assertNull(kv.getPendingChanges());
  }
}
