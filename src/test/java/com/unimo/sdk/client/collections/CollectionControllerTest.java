package com.unimo.sdk.client.collections;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.unimo.sdk.client.Tasker;
import com.unimo.sdk.crypto.CodedException;
import com.unimo.sdk.shared.Helpers;
import com.unimo.sdk.shared.Json;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

/** One collection reached by several threads, with its transfers faked (the real ones need a server and a logged-in vault). */
@Timeout(60) // a lock taken in the wrong order hangs: fail instead
class CollectionControllerTest {
  private static final Tasker NO_SOCKET = new Tasker("http://localhost");

  /** Storage as a collection sees it: scripted downloads, recorded uploads. */
  private static final class FakeRemote implements CollectionController.Remote {
    final AtomicInteger downloads = new AtomicInteger();
    final List<Object[]> uploads = Collections.synchronizedList(new ArrayList<>());
    volatile Supplier<CompletableFuture<Tasker.DownloadResult>> onDownload;
    volatile Supplier<CompletableFuture<Tasker.UploadResult>> onUpload = () -> stored(2);

    @Override
    public CompletableFuture<Tasker.DownloadResult> download() {
      downloads.incrementAndGet();
      return onDownload.get();
    }

    @Override
    public CompletableFuture<Tasker.UploadResult> upload(byte[] blob, int expectedVersion) {
      uploads.add(new Object[] {blob, expectedVersion});
      return onUpload.get();
    }

    @Override
    public CompletableFuture<Integer> probeVersion() {
      return CompletableFuture.completedFuture(0);
    }

    List<Object[]> uploaded() {
      synchronized (uploads) {
        return new ArrayList<>(uploads);
      }
    }
  }

  private static CompletableFuture<Tasker.UploadResult> stored(int version) {
    return CompletableFuture.completedFuture(new Tasker.UploadResult(version, "e", 0, 0));
  }

  private static <T> CompletableFuture<T> refused(String message, String code) {
    CompletableFuture<T> refused = new CompletableFuture<>();
    refused.completeExceptionally(new CodedException(message, code));
    return refused;
  }

  private static CollectionController collection(FakeRemote remote) {
    CollectionController c = new CollectionController("id", "KV", "c", new byte[32], null, null);
    c.remote = remote;
    return c;
  }

  /** A stored blob holding {@code key → value}, as the server would hand it out at {@code version}. */
  private static Tasker.DownloadResult blob(String key, Object value, int version) {
    CollectionController scratch = CollectionController.createNew("c", "KV", null, "member");
    if (key != null) scratch.content().set(key, value);
    return new Tasker.DownloadResult("e", scratch.serialize(), version);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> contentOf(Object blob) {
    byte[] b = (byte[]) blob;
    int metaLen = (b[0] & 0xff) | (b[1] & 0xff) << 8 | (b[2] & 0xff) << 16 | (b[3] & 0xff) << 24;
    return (Map<String, Object>) Json.parse(Helpers.fromUtf8(Arrays.copyOfRange(b, 4 + metaLen, b.length)));
  }

  private static String codeOf(Throwable thrown) {
    Throwable cause = thrown instanceof CompletionException ? thrown.getCause() : thrown;
    return cause instanceof CodedException ? ((CodedException) cause).getCode() : String.valueOf(cause);
  }

  @Test
  void twoLoadsAtOnceShareOneDownloadAndOneContent() throws Exception {
    // Two contents would leave every edit made to the one the controller did not keep unsaved.
    for (int round = 0; round < 200; round++) {
      FakeRemote remote = new FakeRemote();
      CompletableFuture<Tasker.DownloadResult> download = new CompletableFuture<>();
      remote.onDownload = () -> download;
      CollectionController c = collection(remote);
      CyclicBarrier together = new CyclicBarrier(2);
      List<CompletableFuture<KVContent>> loads = Collections.synchronizedList(new ArrayList<>());
      Runnable load = () -> {
        try {
          together.await();
          loads.add(c.load(NO_SOCKET, false));
        } catch (Exception e) {
          throw new IllegalStateException(e);
        }
      };
      Thread one = new Thread(load), other = new Thread(load);
      one.start();
      other.start();
      one.join();
      other.join();
      download.complete(blob("k", "v", 3));

      assertEquals(1, remote.downloads.get());
      assertSame(loads.get(0).join(), loads.get(1).join());
      assertEquals("v", loads.get(0).join().get("k"));
      assertEquals(3, c.getVersion());
    }
  }

  @Test
  void aFailedFirstLoadIsTriedAgain() {
    FakeRemote remote = new FakeRemote();
    remote.onDownload = () -> refused("offline", "NETWORK");
    CollectionController c = collection(remote);
    assertThrows(CompletionException.class, () -> c.load(NO_SOCKET, false).join());

    remote.onDownload = () -> CompletableFuture.completedFuture(blob("k", "v", 1));
    assertEquals("v", c.load(NO_SOCKET, false).join().get("k"));
    assertEquals(2, remote.downloads.get());
  }

  @Test
  void aLoadFillsTheContentThatIsAlreadyThere() {
    // serialize() on a collection whose load is still on its way makes an empty content; the load
    // must fill that one, not swap it for another that the first holder never sees.
    FakeRemote remote = new FakeRemote();
    CompletableFuture<Tasker.DownloadResult> download = new CompletableFuture<>();
    remote.onDownload = () -> download;
    CollectionController c = collection(remote);
    CompletableFuture<KVContent> loading = c.load(NO_SOCKET, false);
    c.serialize();
    KVContent early = c.content();

    download.complete(blob("k", "v", 4));

    assertSame(early, loading.join());
    assertEquals("v", early.get("k"));
    assertEquals(4, c.getVersion());
  }

  @Test
  void aSaveUploadsOnceAndForgetsWhatItUploaded() {
    FakeRemote remote = new FakeRemote();
    remote.onDownload = () -> CompletableFuture.completedFuture(blob(null, null, 1));
    CollectionController c = collection(remote);
    KVContent kv = c.load(NO_SOCKET, false).join();
    kv.set("a", 1L);

    c.flush().join();
    c.flush().join();

    assertEquals(1, remote.uploaded().size());
    assertEquals(1, remote.uploaded().get(0)[1], "pinned to the version it was loaded at");
    assertNull(kv.getPendingChanges());
    assertEquals(2, c.getVersion());
  }

  @Test
  void aFlushThatMeetsANewerVersionMergesAndUploadsAgainBeforeItCompletes() {
    // Whoever flushes and then logs out must be able to rely on it: completed means stored.
    FakeRemote remote = new FakeRemote();
    AtomicReference<Tasker.DownloadResult> server = new AtomicReference<>(blob(null, null, 1));
    remote.onDownload = () -> CompletableFuture.completedFuture(server.get());
    CollectionController c = collection(remote);
    KVContent kv = c.load(NO_SOCKET, false).join();
    kv.set("a", 1L);
    server.set(blob("other", "device", 2)); // another device stored version 2 first
    AtomicInteger asked = new AtomicInteger();
    remote.onUpload = () -> asked.incrementAndGet() == 1 ? refused("CAS VERSION_MISMATCH: expected 1", "VERSION_MISMATCH") : stored(3);

    c.flush().join();

    List<Object[]> uploads = remote.uploaded();
    assertEquals(2, uploads.size());
    assertEquals(2, uploads.get(1)[1], "the second one is pinned to what the pull brought");
    assertEquals("device", contentOf(uploads.get(1)[0]).get("other"));
    assertEquals(1L, contentOf(uploads.get(1)[0]).get("a"));
    assertNull(kv.getPendingChanges());
    assertEquals(3, c.getVersion());
    c.dispose();
  }

  @Test
  void aSaveThatNeverWinsFailsAndKeepsItsEdits() {
    FakeRemote remote = new FakeRemote();
    AtomicInteger version = new AtomicInteger(1);
    remote.onDownload = () -> CompletableFuture.completedFuture(blob("v", (long) version.incrementAndGet(), version.get()));
    remote.onUpload = () -> refused("CAS VERSION_MISMATCH", "VERSION_MISMATCH");
    CollectionController c = collection(remote);
    KVContent kv = c.load(NO_SOCKET, false).join();
    kv.set("a", 1L);

    assertEquals("VERSION_MISMATCH", codeOf(assertThrows(CompletionException.class, () -> c.flush().join())));
    assertEquals(3, remote.uploaded().size(), "a few tries, not for ever");
    assertEquals(4, remote.downloads.get(), "the load, and a pull after every lost try: the last one too, which queues the later save");
    assertEquals(Collections.singleton("a"), kv.getPendingChanges().keySet());
    c.dispose();
  }

  @Test
  void anUploadOvertakenByAPullGivesWayToWhatThePullBrought() {
    // Ours is stored as 6; another device then stores 7 over it; the pull of 7 lands before our upload reports back.
    FakeRemote remote = new FakeRemote();
    AtomicReference<Tasker.DownloadResult> server = new AtomicReference<>(blob("k", "a", 5));
    remote.onDownload = () -> CompletableFuture.completedFuture(server.get());
    CompletableFuture<Tasker.UploadResult> upload = new CompletableFuture<>();
    remote.onUpload = () -> upload;
    CollectionController c = collection(remote);
    KVContent kv = c.load(NO_SOCKET, false).join();
    kv.set("k", "b");
    CompletableFuture<Void> saving = c.save();
    server.set(blob("k", "c", 7));
    c.pullIfNewer(7).join(); // merged with our edit still pending: b laid over c
    assertEquals("b", kv.get("k"));

    upload.complete(new Tasker.UploadResult(6, "e", 0, 0));
    saving.join();

    assertEquals("c", kv.get("k"), "the later version wins the key both changed");
    assertEquals(7, c.getVersion());
    assertNull(kv.getPendingChanges());
    c.dispose();
  }

  @Test
  void nothingIsSavedLoadedOrScheduledAfterDispose() throws InterruptedException {
    // Logout disposes every collection: an edit still waiting for its save must not leave the device,
    // and nobody may be told it was saved.
    FakeRemote remote = new FakeRemote();
    remote.onDownload = () -> CompletableFuture.completedFuture(blob(null, null, 1));
    CollectionController c = collection(remote);
    KVContent kv = c.load(NO_SOCKET, true).join(); // auto-sync on: an edit queues a save
    kv.set("a", 1L);

    c.dispose();
    kv.set("b", 2L);
    Thread.sleep(1_100); // past the debounce: the save queued for "a" would have fired by now

    assertTrue(remote.uploaded().isEmpty());
    assertEquals("DISPOSED", codeOf(assertThrows(CompletionException.class, () -> c.flush().join())));
    assertEquals("DISPOSED", codeOf(assertThrows(CompletionException.class, () -> c.load(NO_SOCKET, true).join())));
    assertEquals(false, c.pullIfNewer(9).join());
    assertTrue(remote.uploaded().isEmpty());
    assertEquals(1, remote.downloads.get());
  }

  @Test
  void aBlobIsNeverPinnedToAVersionItDoesNotHold() throws InterruptedException {
    // A save reading the data before a pull and the version after it would upload the old data over the new.
    // Every stored version n holds v = n, so an upload pinned to n must carry v = n too.
    FakeRemote remote = new FakeRemote();
    AtomicInteger serverVersion = new AtomicInteger(1);
    remote.onDownload = () -> {
      int v = serverVersion.get();
      return CompletableFuture.completedFuture(blob("v", (long) v, v));
    };
    remote.onUpload = () -> refused("down", "NETWORK"); // nothing is ever stored: only pulls move the version
    CollectionController c = collection(remote);
    KVContent kv = c.load(NO_SOCKET, false).join();

    int pulls = 4_000;
    Thread puller =
        new Thread(
            () -> {
              for (int v = 2; v <= pulls; v++) {
                serverVersion.set(v);
                c.pullIfNewer(v).join();
              }
            });
    Thread saver =
        new Thread(
            () -> {
              for (long i = 0; c.getVersion() < pulls; i++) {
                kv.set("local", i);
                c.save().exceptionally(e -> null).join();
              }
            });
    puller.start();
    saver.start();
    puller.join();
    saver.join();
    c.dispose(); // a pull queued a later save: it must not fire into the checks below or the next test

    List<Object[]> uploads = remote.uploaded();
    assertTrue(uploads.size() > 0);
    for (Object[] upload : uploads) {
      assertEquals(((Integer) upload[1]).longValue(), contentOf(upload[0]).get("v"), "pinned to " + upload[1]);
    }
  }
}
