package com.unimo.sdk.client.collections;

import com.unimo.sdk.client.ReactiveValue;
import com.unimo.sdk.client.Tasker;
import com.unimo.sdk.client.VaultController;
import com.unimo.sdk.crypto.CodedException;
import com.unimo.sdk.crypto.CryptoUtils;
import com.unimo.sdk.shared.Consts;
import com.unimo.sdk.shared.Helpers;
import com.unimo.sdk.shared.Json;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

/**
 * Port of {@code sdk/ts/src_ts/client/collections/Collection.ts}. One synced collection. The
 * on-disk blob is {@code [LE-uint32 metaLen][meta JSON][content bytes]}, AEAD-encrypted with the
 * collection's own key and stored at {@code fileId = colId} via {@link Tasker}. Only the KV type
 * is implemented (matching the TS, where VFS/LIST/CRDTLIST are stubs).
 *
 * <p>Threads (Java only; the TS original has one): the app's thread, the save timer and the network
 * threads all come here. Two locks keep them apart, always taken in the same order:
 *
 * <ol>
 *   <li>the content's own lock ({@link KVContent} is synchronized). It also ties the data to its
 *       version: a save reads both, and a pull replaces both, as one step under it.
 *   <li>{@link #lock}, for this object's fields. Never held across a network call, nor while
 *       calling into the content.
 * </ol>
 */
public final class CollectionController {
  private static final long SYNC_DEBOUNCE_MS = 810; // Consts.SYNC_DEBOUNCE_MS
  /** How often one save uploads before it gives up on a collection another device keeps changing. */
  private static final int SAVE_ATTEMPTS = 3;
  /** The debounce doubles with every save that failed in a row, this many times at most (about 50 s). */
  private static final int MAX_BACKOFF_DOUBLINGS = 6;
  private static final ScheduledExecutorService SCHED =
      Executors.newScheduledThreadPool(
          1,
          r -> {
            Thread t = new Thread(r, "unimo-collection-sync");
            t.setDaemon(true);
            return t;
          });

  /** This collection's transfers. A seam for tests: the real ones need a server and a logged-in vault. */
  interface Remote {
    CompletableFuture<Tasker.DownloadResult> download();

    CompletableFuture<Tasker.UploadResult> upload(byte[] blob, int expectedVersion);

    CompletableFuture<Integer> probeVersion();
  }

  private final String colId;
  private final String colType;
  private final byte[] colEncKey;
  private final VaultController vault;

  private final Object lock = new Object();
  private String colName;
  private Map<String, Object> meta;
  /** Set once, by {@link #createNew}, the first load or {@link #serialize}; never replaced, so everyone holds the same one. */
  private KVContent content;
  private Tasker tasker;
  /** The first download, shared by everyone who asks while it runs. */
  private CompletableFuture<KVContent> loading;
  private ReactiveValue.Subscription contentSub;
  private ScheduledFuture<?> syncTask;
  /** The tasker that routes change frames here, to take the watch back from that one. */
  private Tasker watchedBy;
  private boolean disposed;
  /** Saves that failed in a row: a conflict that will not resolve, or a server that is down, is not hammered. */
  private int failedSaves;

  Remote remote =
      new Remote() {
        @Override
        public CompletableFuture<Tasker.DownloadResult> download() {
          return tasker().download(vault, colId, colEncKey);
        }

        @Override
        public CompletableFuture<Tasker.UploadResult> upload(byte[] blob, int expectedVersion) {
          return tasker().upload(vault, colId, blob, colEncKey, expectedVersion);
        }

        @Override
        public CompletableFuture<Integer> probeVersion() {
          return tasker().probeVersion(vault, colId);
        }
      };

  public CollectionController(String colId, String colType, String colName, byte[] colEncKey, VaultController vault, Map<String, Object> meta) {
    this.colId = colId;
    this.colType = colType;
    this.colName = colName;
    this.colEncKey = colEncKey;
    this.vault = vault;
    this.meta = meta;
  }

  public static CollectionController createNew(String name, String type, VaultController vault, String memberId) {
    String id = Helpers.hex(CryptoUtils.generateRandomBytes(32));
    CollectionController c =
        new CollectionController(id, type, name, CryptoUtils.generateRandomBytes(32), vault, defaultMeta(memberId));
    c.content = create(type);
    return c;
  }

  private static Map<String, Object> defaultMeta(String memberId) {
    long now = System.currentTimeMillis();
    return Json.obj(
        "epoch", 0, "version", 0, "createdAt", now, "createdById", memberId, "modifiedAt", now,
        "modifiedById", memberId, "archived", false, "archivedAt", null, "toDelete", false);
  }

  private static KVContent create(String type) {
    if (!Consts.COLLECTION_TYPE_KV.equals(type)) {
      throw new CodedException("Unsupported collection type: " + type, "UNSUPPORTED_COLLECTION_TYPE");
    }
    return new KVContent();
  }

  // ── blob (de)serialization: [LE-uint32 metaLen][meta JSON][content] ──

  /** Serialize meta + content into the storage blob (the plaintext that gets AEAD-encrypted). */
  public byte[] serialize() {
    KVContent kv;
    byte[] metaBytes;
    synchronized (lock) {
      if (content == null) content = create(colType);
      kv = content;
      metaBytes = Helpers.utf8(Json.canonical(meta));
    }
    byte[] contentBytes = kv.serialize();
    int len = metaBytes.length;
    byte[] header = {(byte) len, (byte) (len >> 8), (byte) (len >> 16), (byte) (len >> 24)};
    return Helpers.concat(header, metaBytes, contentBytes);
  }

  private static byte[][] parsePayload(byte[] buffer) {
    int metaLen =
        (buffer[0] & 0xff) | (buffer[1] & 0xff) << 8 | (buffer[2] & 0xff) << 16 | (buffer[3] & 0xff) << 24;
    byte[] meta = Arrays.copyOfRange(buffer, 4, 4 + metaLen);
    byte[] content = Arrays.copyOfRange(buffer, 4 + metaLen, buffer.length);
    return new byte[][] {meta, content};
  }

  /** The blob's meta, carrying the version the server stored it under. */
  private static Map<String, Object> metaOf(byte[] metaBytes, int version) {
    Map<String, Object> m = Json.parseObject(Helpers.fromUtf8(metaBytes));
    m.put("version", (long) version);
    return m;
  }

  // ── load / save ──

  /**
   * First call downloads; later calls only refresh, and only when a body-less HEAD shows the
   * server holding a newer version — so reloading an unchanged collection costs one header
   * round-trip, not a download.
   */
  public CompletableFuture<KVContent> load(Tasker tasker, boolean autoSync) {
    CompletableFuture<KVContent> first;
    synchronized (lock) {
      if (disposed) return failed(disposed("Collection disposed"));
      this.tasker = tasker;
      if (content != null) {
        first = null;
      } else {
        // One download for every caller: two would hand out two contents, and edits made to the
        // one this controller did not keep would never be saved. A failed one is tried again.
        if (loading == null || loading.isDone()) loading = download();
        first = loading;
      }
    }
    CompletableFuture<?> ready = first != null ? first : pullIfNewer(null);
    return ready.thenApply(
        x -> {
          if (autoSync) enableAutoSync();
          return content();
        });
  }

  /** The first download. Called with {@link #lock} held. */
  private CompletableFuture<KVContent> download() {
    return remote
        .download()
        .thenApply(
            dl -> {
              if (!Consts.COLLECTION_TYPE_KV.equals(colType)) {
                throw new CodedException("Unsupported collection type: " + colType, "UNSUPPORTED_COLLECTION_TYPE");
              }
              byte[][] parts = parsePayload(dl.data);
              Map<String, Object> loaded = metaOf(parts[0], dl.version);
              KVContent kv = KVContent.deserialize(parts[1]);
              KVContent existing;
              synchronized (lock) {
                meta = loaded;
                if (content == null) content = kv;
                existing = content;
              }
              // serialize() may have made an empty one meanwhile: what was loaded goes into that one.
              if (existing != kv) existing.merge(kv);
              return existing;
            });
  }

  /**
   * Persist pending changes via a CAS-pinned upload. Completes once they are stored: when another
   * device stored a version first, it pulls, merges and uploads again, a few times at most, and
   * fails if the edits are still unsaved then (they stay pending for the next save). A disposed
   * collection with unsaved edits fails as {@code DISPOSED}.
   */
  public CompletableFuture<Void> save() {
    return save(SAVE_ATTEMPTS)
        .whenComplete(
            (saved, err) -> {
              synchronized (lock) {
                failedSaves = err == null ? 0 : failedSaves + 1;
              }
            });
  }

  private CompletableFuture<Void> save(int attemptsLeft) {
    KVContent kv;
    synchronized (lock) {
      if (tasker == null || content == null) return CompletableFuture.completedFuture(null);
      kv = content;
    }
    Map<String, Object> uploaded;
    CompletableFuture<Tasker.UploadResult> upload;
    // One step against a pull: a blob serialized before a merge but pinned to the version after
    // it would overwrite what the merge brought.
    synchronized (kv) {
      if (kv.getPendingChanges() == null) return CompletableFuture.completedFuture(null);
      uploaded = kv.pendingSnapshot();
      byte[] blob = serialize();
      int expected = getVersion();
      synchronized (lock) { // started under the lock dispose() takes: once dispose() has returned, no upload begins
        if (disposed) return failed(disposed("Collection disposed with unsaved edits"));
        upload = remote.upload(blob, expected);
      }
    }
    return upload
        .handle((result, err) -> new Object[] {result, err})
        .thenCompose(
            ra -> {
              Throwable err = (Throwable) ra[1];
              if (err == null) {
                int stored = ((Tasker.UploadResult) ra[0]).version;
                boolean overtaken;
                // A pull that ran meanwhile merged a later version with these edits still pending,
                // laying them over what that version holds. Step back to what was stored and pull
                // again, now without them, so the later version wins where it changed the same keys.
                synchronized (kv) {
                  overtaken = getVersion() > stored;
                  setVersion(stored);
                  kv.clearPending(uploaded);
                }
                return overtaken ? pullAndMerge().thenApply(merged -> (Void) null) : CompletableFuture.<Void>completedFuture(null);
              }
              Throwable cause = err instanceof CompletionException && err.getCause() != null ? err.getCause() : err;
              if (!isCasError(err)) return failed(cause);
              // Another device stored a version first. The pull also queues a later save for what is
              // still pending, so edits this call gives up on are not left waiting for the next edit.
              return pullAndMerge().thenCompose(merged -> attemptsLeft > 1 ? save(attemptsLeft - 1) : failed(cause));
            });
  }

  /**
   * Watch refresh (see {@link Tasker.Watch}): pull + merge when the server holds a version newer
   * than this copy. {@code knownVersion} comes from a change frame; null probes with a HEAD first.
   * Completes true when newer remote content was merged.
   */
  public CompletableFuture<Boolean> pullIfNewer(Integer knownVersion) {
    synchronized (lock) {
      if (disposed || tasker == null || content == null) return CompletableFuture.completedFuture(false);
    }
    CompletableFuture<Integer> remoteVersion =
        knownVersion != null ? CompletableFuture.completedFuture(knownVersion) : remote.probeVersion();
    return remoteVersion.thenCompose(v -> v > getVersion() ? pullAndMerge() : CompletableFuture.completedFuture(false));
  }

  /** Download + merge; a download no newer than this copy (a concurrent pull won) is dropped. */
  private CompletableFuture<Boolean> pullAndMerge() {
    KVContent kv;
    synchronized (lock) {
      if (disposed || tasker == null || content == null) return CompletableFuture.completedFuture(false);
      kv = content;
    }
    return remote
        .download()
        .thenApply(
            dl -> {
              boolean newer;
              synchronized (kv) { // the version and the data move together: see save()
                synchronized (lock) {
                  if (disposed) return false; // disposed while this was on its way: nothing is merged any more
                }
                newer = dl.version > getVersion();
                if (newer) {
                  byte[][] parts = parsePayload(dl.data);
                  Map<String, Object> pulled = metaOf(parts[0], dl.version);
                  synchronized (lock) {
                    meta = pulled;
                  }
                  if (Consts.COLLECTION_TYPE_KV.equals(colType)) kv.merge(KVContent.deserialize(parts[1]));
                }
              }
              if (kv.getPendingChanges() != null) scheduleSave();
              return newer;
            });
  }

  /** Cancel any pending debounce and persist now. */
  public CompletableFuture<Void> flush() {
    synchronized (lock) {
      if (syncTask != null) syncTask.cancel(false);
    }
    return save();
  }

  /** Push local edits (debounced save) and pull remote ones (WS watch, when the tasker has a live
   *  connection). */
  public void enableAutoSync() {
    Tasker t;
    synchronized (lock) {
      if (disposed || contentSub != null || content == null) return;
      KVContent kv = content;
      // Runs under the content's lock, on the thread that changed it.
      contentSub =
          kv.data.onChange(
              m -> {
                if (kv.getPendingChanges() != null) scheduleSave();
              });
      t = tasker;
    }
    if (t == null || !t.isLive()) return;
    t.watchCollection(vault, colId, this::pullIfNewer);
    boolean disposedMeanwhile;
    synchronized (lock) {
      disposedMeanwhile = disposed;
      if (!disposed) watchedBy = t;
    }
    if (disposedMeanwhile) t.unwatchCollection(vault.getId(), colId);
  }

  private void scheduleSave() {
    synchronized (lock) {
      if (disposed) return;
      if (syncTask != null) syncTask.cancel(false);
      syncTask =
          SCHED.schedule(
              () -> save().exceptionally(e -> { System.err.println("collection auto-save error: " + e); return null; }),
              SYNC_DEBOUNCE_MS << Math.min(failedSaves, MAX_BACKOFF_DOUBLINGS),
              TimeUnit.MILLISECONDS);
    }
  }

  /**
   * The end of this object: from here on nothing is scheduled, no upload or load begins, and nothing
   * pulled is merged. Edits still pending are not saved, and a save asked for them fails as
   * {@code DISPOSED}: flush first what must be kept.
   */
  public void dispose() {
    ReactiveValue.Subscription sub;
    Tasker watcher;
    synchronized (lock) {
      disposed = true;
      sub = contentSub;
      contentSub = null;
      if (syncTask != null) syncTask.cancel(false);
      syncTask = null;
      watcher = watchedBy;
      watchedBy = null;
    }
    if (sub != null) sub.close();
    if (watcher != null) watcher.unwatchCollection(vault.getId(), colId);
  }

  private static CodedException disposed(String message) {
    return new CodedException(message, "DISPOSED");
  }

  private static <T> CompletableFuture<T> failed(Throwable cause) {
    CompletableFuture<T> future = new CompletableFuture<>();
    future.completeExceptionally(cause);
    return future;
  }

  // ── accessors / wiring ──

  public String getId() {
    return colId;
  }

  public String getName() {
    synchronized (lock) {
      return colName;
    }
  }

  public String getType() {
    return colType;
  }

  public byte[] getEncKey() {
    return colEncKey;
  }

  public int getVersion() {
    synchronized (lock) {
      Object v = meta == null ? null : meta.get("version");
      return v instanceof Number ? ((Number) v).intValue() : 0;
    }
  }

  private void setVersion(int version) {
    synchronized (lock) {
      if (meta != null) meta.put("version", (long) version);
    }
  }

  public KVContent content() {
    synchronized (lock) {
      if (content == null) throw new CodedException("Not loaded", "NOT_LOADED");
      return content;
    }
  }

  private Tasker tasker() {
    synchronized (lock) {
      return tasker;
    }
  }

  public void setInitialVersion(int version) {
    setVersion(version);
  }

  public void attachTasker(Tasker tasker, boolean autoSync) {
    synchronized (lock) {
      this.tasker = tasker;
    }
    if (autoSync) enableAutoSync();
  }

  public void setName(String newName, String memberId) {
    synchronized (lock) {
      this.colName = newName;
      if (meta != null) {
        meta.put("modifiedAt", System.currentTimeMillis());
        meta.put("modifiedById", memberId);
      }
    }
  }

  /** Minimal descriptor stored (encrypted) in the manifest's collections list. */
  public Map<String, Object> minimalMap() {
    return Json.obj("colId", colId, "colType", colType, "colName", getName(), "colEncKey", Helpers.base64(colEncKey));
  }

  private static boolean isCasError(Throwable err) {
    Throwable t = err instanceof CompletionException && err.getCause() != null ? err.getCause() : err;
    if (t instanceof CodedException) {
      String code = ((CodedException) t).getCode();
      if ("CAS_FAILED".equals(code)) return true;
    }
    String m = t.getMessage();
    return m != null && (m.contains("CAS") || m.contains("VERSION_MISMATCH"));
  }
}
