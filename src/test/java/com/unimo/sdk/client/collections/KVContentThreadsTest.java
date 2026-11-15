package com.unimo.sdk.client.collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.unimo.sdk.shared.Helpers;
import com.unimo.sdk.shared.Json;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/**
 * Java only: the app's thread, the save timer and the network threads all reach one {@link
 * KVContent}. Unlocked, these runs end in a ConcurrentModificationException or a map that lost
 * entries.
 */
@Timeout(60) // a deadlock hangs: fail instead
class KVContentThreadsTest {
  private static final int WRITERS = 4;
  private static final int KEYS = 40;
  private static final int ROUNDS = 150;

  private final List<Throwable> failures = Collections.synchronizedList(new ArrayList<>());

  private Thread start(CountDownLatch go, Runnable body) {
    Thread t =
        new Thread(
            () -> {
              try {
                go.await();
                body.run();
              } catch (Throwable e) {
                failures.add(e);
              }
            });
    t.start();
    return t;
  }

  private static void joinAll(List<Thread> threads) throws InterruptedException {
    for (Thread t : threads) t.join();
  }

  private List<Thread> writers(KVContent kv, CountDownLatch go) {
    List<Thread> out = new ArrayList<>();
    for (int w = 0; w < WRITERS; w++) {
      final int writer = w;
      out.add(
          start(
              go,
              () -> {
                for (long round = 0; round < ROUNDS; round++) {
                  for (int k = 0; k < KEYS; k++) kv.set("w" + writer + "-" + k, round);
                }
              }));
    }
    return out;
  }

  private static void assertWritersLanded(KVContent kv) {
    for (int w = 0; w < WRITERS; w++) {
      for (int k = 0; k < KEYS; k++) assertEquals((long) (ROUNDS - 1), kv.get("w" + w + "-" + k), "w" + w + "-" + k);
    }
  }

  @Test
  void editsSurviveMergesAndSerializingFromOtherThreads() throws InterruptedException {
    KVContent kv = new KVContent();
    CountDownLatch go = new CountDownLatch(1);
    AtomicBoolean writing = new AtomicBoolean(true);
    List<Thread> writers = writers(kv, go);
    writers.add(
        start(
            go,
            () -> {
              for (int round = 0; round < ROUNDS; round++) {
                for (int k = 0; k < KEYS; k++) {
                  kv.set("gone-" + k, 1L);
                  kv.delete("gone-" + k);
                }
              }
            }));
    List<Thread> others = new ArrayList<>();
    // The network thread: a pull replaces the map with the remote one, pending edits laid back over it.
    others.add(
        start(
            go,
            () -> {
              for (long version = 1; writing.get(); version++) {
                Map<String, Object> remote = new LinkedHashMap<>();
                remote.put("remote", version);
                kv.merge(new KVContent(remote));
              }
            }));
    // The save timer: reads the pending list and walks the whole map.
    others.add(
        start(
            go,
            () -> {
              while (writing.get()) {
                kv.pendingSnapshot();
                kv.getPendingChanges();
                kv.keys();
                Json.parse(Helpers.fromUtf8(kv.serialize()));
              }
            }));
    go.countDown();
    joinAll(writers);
    writing.set(false);
    joinAll(others);

    assertEquals(Collections.emptyList(), failures);
    assertWritersLanded(kv);
    for (int k = 0; k < KEYS; k++) assertFalse(kv.has("gone-" + k), "gone-" + k);
    assertEquals(WRITERS * KEYS + KEYS, kv.getPendingChanges().size(), "every edit is still waiting for its save");
  }

  @Test
  void aSaveForgetsOnlyWhatItUploadedWhileOthersKeepWriting() throws InterruptedException {
    KVContent kv = new KVContent();
    CountDownLatch go = new CountDownLatch(1);
    AtomicBoolean writing = new AtomicBoolean(true);
    List<Thread> writers = writers(kv, go);
    Thread saver =
        start(
            go,
            () -> {
              while (writing.get()) kv.clearPending(kv.pendingSnapshot());
            });
    go.countDown();
    joinAll(writers);
    writing.set(false);
    saver.join();

    assertEquals(Collections.emptyList(), failures);
    assertWritersLanded(kv);
    kv.clearPending(kv.pendingSnapshot());
    assertNull(kv.getPendingChanges());
    assertTrue(kv.keys().size() == WRITERS * KEYS);
  }
}
