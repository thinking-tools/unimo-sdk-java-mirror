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
 */
public final class CollectionController {
  private static final long SYNC_DEBOUNCE_MS = 810; // Consts.SYNC_DEBOUNCE_MS
  private static final ScheduledExecutorService SCHED =
      Executors.newScheduledThreadPool(
          1,
          r -> {
            Thread t = new Thread(r, "unimo-collection-sync");
            t.setDaemon(true);
            return t;
          });

  private final String colId;
  private final String colType;
  private String colName;
  private final byte[] colEncKey;
  private final VaultController vault;

  private Map<String, Object> meta;
  private KVContent content;
  private Tasker tasker;
  private ReactiveValue.Subscription contentSub;
  private ScheduledFuture<?> syncTask;

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
    c.content = c.create(type);
    return c;
  }

  private static Map<String, Object> defaultMeta(String memberId) {
    long now = Helpers.now();
    return Json.obj(
        "epoch", 0, "version", 0, "createdAt", now, "createdById", memberId, "modifiedAt", now,
        "modifiedById", memberId, "archived", false, "archivedAt", null, "toDelete", false);
  }

  private KVContent create(String type) {
    if (!Consts.COLLECTION_TYPE_KV.equals(type)) {
      throw new CodedException("Unsupported collection type: " + type, "UNSUPPORTED_COLLECTION_TYPE");
    }
    this.content = new KVContent();
    return this.content;
  }

  // ── blob (de)serialization: [LE-uint32 metaLen][meta JSON][content] ──

  /** Serialize meta + content into the storage blob (the plaintext that gets AEAD-encrypted). */
  public byte[] serialize() {
    if (content == null) content = create(colType);
    byte[] metaBytes = Helpers.utf8(Json.canonical(meta));
    byte[] contentBytes = content.serialize();
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

  // ── load / save ──

  /**
   * First call downloads; later calls only refresh, and only when a body-less HEAD shows the
   * server holding a newer version — so reloading an unchanged collection costs one header
   * round-trip, not a download.
   */
  public CompletableFuture<KVContent> load(Tasker tasker, boolean autoSync) {
    this.tasker = tasker;
    if (content != null) {
      return pullIfNewer(null)
          .thenApply(
              merged -> {
                if (autoSync) enableAutoSync();
                return this.content;
              });
    }
    return tasker
        .download(vault, colId, colEncKey)
        .thenApply(
            dl -> {
              if (!Consts.COLLECTION_TYPE_KV.equals(colType)) {
                throw new CodedException("Unsupported collection type: " + colType, "UNSUPPORTED_COLLECTION_TYPE");
              }
              byte[][] parts = parsePayload(dl.data);
              this.meta = Json.parseObject(Helpers.fromUtf8(parts[0]));
              this.meta.put("version", (long) dl.version);
              this.content = KVContent.deserialize(parts[1]);
              if (autoSync) enableAutoSync();
              return this.content;
            });
  }

  /** Persist pending changes via a CAS-pinned upload; on CAS exhaustion, pull + merge. */
  public CompletableFuture<Void> save() {
    if (tasker == null || content == null || content.getPendingChanges() == null) {
      return CompletableFuture.completedFuture(null);
    }
    Map<String, Object> uploaded = content.pendingSnapshot();
    byte[] blob = serialize();
    int expected = getVersion();
    return tasker
        .upload(vault, colId, blob, colEncKey, expected)
        .handle((result, err) -> new Object[] {result, err})
        .thenCompose(
            ra -> {
              Throwable err = (Throwable) ra[1];
              if (err == null) {
                meta.put("version", (long) ((Tasker.UploadResult) ra[0]).version);
                content.clearPending(uploaded);
                return CompletableFuture.<Void>completedFuture(null);
              }
              if (isCasError(err)) return pullAndMerge().thenApply(merged -> (Void) null);
              CompletableFuture<Void> failed = new CompletableFuture<>();
              failed.completeExceptionally(err instanceof CompletionException ? err.getCause() : err);
              return failed;
            });
  }

  /**
   * Watch refresh (see {@link Tasker.Watch}): pull + merge when the server holds a version newer
   * than this copy. {@code knownVersion} comes from a change frame; null probes with a HEAD first.
   * Completes true when newer remote content was merged.
   */
  public CompletableFuture<Boolean> pullIfNewer(Integer knownVersion) {
    if (tasker == null || content == null) return CompletableFuture.completedFuture(false);
    CompletableFuture<Integer> remote =
        knownVersion != null ? CompletableFuture.completedFuture(knownVersion) : tasker.probeVersion(vault, colId);
    return remote.thenCompose(v -> v > getVersion() ? pullAndMerge() : CompletableFuture.completedFuture(false));
  }

  /** Download + merge; a download no newer than this copy (a concurrent pull won) is dropped. */
  private CompletableFuture<Boolean> pullAndMerge() {
    if (tasker == null) return CompletableFuture.completedFuture(false);
    return tasker
        .download(vault, colId, colEncKey)
        .thenApply(
            dl -> {
              boolean newer = dl.version > getVersion();
              if (newer) {
                byte[][] parts = parsePayload(dl.data);
                this.meta = Json.parseObject(Helpers.fromUtf8(parts[0]));
                this.meta.put("version", (long) dl.version);
                if (Consts.COLLECTION_TYPE_KV.equals(colType) && content != null) {
                  content.merge(KVContent.deserialize(parts[1]));
                }
              }
              if (content != null && content.getPendingChanges() != null) scheduleSave();
              return newer;
            });
  }

  /** Cancel any pending debounce and persist now. */
  public CompletableFuture<Void> flush() {
    if (syncTask != null) syncTask.cancel(false);
    return save();
  }

  /** Push local edits (debounced save) and pull remote ones (WS watch, when the tasker has a live
   *  connection). */
  public void enableAutoSync() {
    if (contentSub != null) return;
    contentSub =
        content.data.onChange(
            m -> {
              if (content.getPendingChanges() != null) scheduleSave();
            });
    if (tasker != null) tasker.watchCollection(vault, colId, this::pullIfNewer);
  }

  private void scheduleSave() {
    if (syncTask != null) syncTask.cancel(false);
    syncTask =
        SCHED.schedule(
            () -> save().exceptionally(e -> { System.err.println("collection auto-save error: " + e); return null; }),
            SYNC_DEBOUNCE_MS,
            TimeUnit.MILLISECONDS);
  }

  public void dispose() {
    if (contentSub != null) contentSub.close();
    if (syncTask != null) syncTask.cancel(false);
    if (tasker != null) tasker.unwatchCollection(vault.getId(), colId);
  }

  // ── accessors / wiring ──

  public String getId() {
    return colId;
  }

  public String getName() {
    return colName;
  }

  public String getType() {
    return colType;
  }

  public byte[] getEncKey() {
    return colEncKey;
  }

  public int getVersion() {
    Object v = meta == null ? null : meta.get("version");
    return v instanceof Number ? ((Number) v).intValue() : 0;
  }

  public KVContent content() {
    if (content == null) throw new CodedException("Not loaded", "NOT_LOADED");
    return content;
  }

  public void setInitialVersion(int version) {
    if (meta != null) meta.put("version", (long) version);
  }

  public void attachTasker(Tasker tasker, boolean autoSync) {
    this.tasker = tasker;
    if (autoSync) enableAutoSync();
  }

  public void setName(String newName, String memberId) {
    this.colName = newName;
    if (meta != null) {
      meta.put("modifiedAt", Helpers.now());
      meta.put("modifiedById", memberId);
    }
  }

  /** Minimal descriptor stored (encrypted) in the manifest's collections list. */
  public Map<String, Object> minimalMap() {
    return Json.obj("colId", colId, "colType", colType, "colName", colName, "colEncKey", Helpers.base64(colEncKey));
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
