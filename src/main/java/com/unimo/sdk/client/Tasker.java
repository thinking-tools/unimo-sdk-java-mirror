package com.unimo.sdk.client;

import com.unimo.sdk.crypto.AEAD;
import com.unimo.sdk.crypto.CodedException;
import com.unimo.sdk.crypto.CryptoUtils;
import com.unimo.sdk.shared.Consts;
import com.unimo.sdk.shared.Helpers;
import com.unimo.sdk.shared.Json;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Supplier;

/**
 * Port of the upload/download core of {@code sdk/ts/src_ts/client/Tasker.ts} (storage-v2).
 * The task-queue / reactive-progress control plane is deferred to later phases — this is the
 * encrypted blob transfer plus the WS watch plane ({@link #hookVault}, {@link #watchCollection}):
 *
 * <ul>
 *   <li>Single-chunk (≤ {@link Consts#CHUNK_SIZE}): AEAD-encrypt → CAS head PUT.
 *   <li>Multi-chunk: HEAD probe → parallel chunk PUTs → encrypted head-blob commit.
 *   <li>Download: GET head; if {@code chunkCount>0}, decrypt the head-blob JSON, parallel chunk
 *       GETs, concat.
 * </ul>
 *
 * Orchestration runs on a small daemon pool and blocks on the per-call {@link CompletableFuture}s
 * (OkHttp provides the actual concurrency); each public method returns a {@link CompletableFuture}.
 */
public final class Tasker {
  private static final int MAX_CAS_RETRIES = 5;
  private static final String OCTET = "application/octet-stream";
  private static final ExecutorService POOL =
      Executors.newCachedThreadPool(
          r -> {
            Thread t = new Thread(r, "unimo-tasker");
            t.setDaemon(true);
            return t;
          });

  private final String endpoint;
  private final Connection connection; // null = no live watch (keepAlive=false)
  private final Map<String, VaultWatch> watches = new ConcurrentHashMap<>();
  private final Set<Consumer<String>> remoteChangeListeners = ConcurrentHashMap.newKeySet();

  public Tasker(String serviceUrl) {
    this(serviceUrl, null);
  }

  /** With a live {@code connection}, {@code vault:event} frames drive the watches and every
   *  (re)open catches them up (see {@link #hookVault}). */
  public Tasker(String serviceUrl, Connection connection) {
    this.endpoint = serviceUrl.replaceAll("/+$", "");
    this.connection = connection;
    if (connection != null) {
      connection.on("vault:event", this::route);
      connection.onOpen(this::catchUp);
    }
  }

  /**
   * Refresh of one watched file: pull when the server holds a newer version than the local copy.
   * {@code knownVersion} is the version a frame announced, or null when unknown (reconnect
   * catch-up) — probe first. Completes true when remote state was merged locally.
   */
  public interface Watch {
    CompletableFuture<Boolean> refresh(Integer knownVersion);
  }

  static final class VaultWatch {
    final Watch manifest;
    final Map<String, Watch> files = new ConcurrentHashMap<>();

    VaultWatch(Watch manifest) {
      this.manifest = manifest;
    }
  }

  public static final class UploadResult {
    public final int version;
    public final String etag;
    public final long totalBytes;
    public final int chunkCount;

    UploadResult(int version, String etag, long totalBytes, int chunkCount) {
      this.version = version;
      this.etag = etag;
      this.totalBytes = totalBytes;
      this.chunkCount = chunkCount;
    }
  }

  public static final class DownloadResult {
    public final String etag;
    public final byte[] data;
    public final int version;

    DownloadResult(String etag, byte[] data, int version) {
      this.etag = etag;
      this.data = data;
      this.version = version;
    }
  }

  public static final class DeleteResult {
    /** Epoch ms the file entered trash; restorable until {@link #expiresAt}. */
    public final long trashedAt;
    public final long expiresAt;
    public final int retentionDays;
    /** True while the server is still moving objects to trash; restore refuses until it clears. */
    public final boolean inflight;
    public final int blobsAffected;
    public final long bytesAffected;

    DeleteResult(Map<String, Object> j) {
      this.trashedAt = ((Number) j.get("trashedAt")).longValue();
      this.expiresAt = ((Number) j.get("expiresAt")).longValue();
      this.retentionDays = ((Number) j.get("retentionDays")).intValue();
      this.inflight = Boolean.TRUE.equals(j.get("inflight"));
      this.blobsAffected = ((Number) j.get("blobsAffected")).intValue();
      this.bytesAffected = ((Number) j.get("bytesAffected")).longValue();
    }
  }

  /** Upload encrypted bytes under {@code fileId}. {@code expectedVersion} CAS-pins the current
   *  head (use {@code 0} to assert first-write); {@code null} HEAD-probes for multi-chunk. */
  public CompletableFuture<UploadResult> upload(
      VaultController v, String fileId, byte[] data, byte[] encKey, Integer expectedVersion) {
    return CompletableFuture.supplyAsync(
        () ->
            data.length <= Consts.CHUNK_SIZE
                ? singleChunkUpload(v, fileId, data, encKey, expectedVersion)
                : multiChunkUpload(v, fileId, data, encKey, expectedVersion),
        POOL);
  }

  public CompletableFuture<UploadResult> upload(VaultController v, String fileId, byte[] data, byte[] encKey) {
    return upload(v, fileId, data, encKey, null);
  }

  public CompletableFuture<DownloadResult> download(VaultController v, String fileId, byte[] encKey) {
    return CompletableFuture.supplyAsync(() -> doDownload(v, fileId, encKey), POOL);
  }

  /** Current server version of {@code fileId} via a body-less HEAD ({@code 0} when it has none). */
  public CompletableFuture<Integer> probeVersion(VaultController v, String fileId) {
    return CompletableFuture.supplyAsync(() -> headProbe(v, fileId), POOL);
  }

  // ── WS watch plane (port of the TS Tasker hookVault / watchCollection) ──

  /**
   * Keep {@code v}'s manifest current: refetch on {@code manifest_updated} frames newer than the
   * held version, and on every (re)open. Frames are live-only, so the open-time pass — which also
   * probes every {@link #watchCollection watched collection} — is what recovers changes made
   * while the socket was down. No-op without a live connection. Idempotent.
   */
  public void hookVault(VaultController v) {
    if (connection == null) return;
    hook(
        v.getId(),
        known -> {
          int before = v.getManifestVersion();
          if (known != null && known <= before) return CompletableFuture.completedFuture(false);
          return v.timeToFetchUpdate().thenApply(x -> v.getManifestVersion() != before);
        });
  }

  /** Package-private seam for tests (a VaultController needs a live login). */
  VaultWatch hook(String vaultId, Watch manifest) {
    return watches.computeIfAbsent(vaultId, id -> new VaultWatch(manifest));
  }

  /** Route {@code colId}'s change frames (and the reconnect catch-up) to {@code watch}, replacing
   *  any earlier watch for it. No-op without a live connection. */
  public void watchCollection(VaultController v, String colId, Watch watch) {
    if (connection == null) return;
    hookVault(v);
    watches.get(v.getId()).files.put(colId, watch);
  }

  public void unwatchCollection(String vaultId, String colId) {
    VaultWatch w = watches.get(vaultId);
    if (w != null) w.files.remove(colId);
  }

  /** Run {@code listener} (on an SDK thread) whenever a watch merged newer remote state: with the
   *  collection's id for a watched collection's content, with null for the manifest (members, the
   *  collections list). */
  public ReactiveValue.Subscription onRemoteChange(Consumer<String> listener) {
    remoteChangeListeners.add(listener);
    return () -> remoteChangeListeners.remove(listener);
  }

  /**
   * {@code vault:event} router. The frame's {@code version} ({@code head} on head_changed /
   * blob_restored) lets a watch skip a change it already holds — e.g. this device's own upload —
   * without a request. Frames without a {@code fileId} (presence, invite_claimed, …) are ignored:
   * none of them changes the manifest, and the TS original's manifest refetch on them would fire
   * on every member connect. Package-private for tests.
   */
  void route(Map<String, Object> msg) {
    VaultWatch w = watches.get(String.valueOf(msg.get("vaultId")));
    if (w == null) return;
    Object v = msg.containsKey("version") ? msg.get("version") : msg.get("head");
    Integer known = v instanceof Number ? ((Number) v).intValue() : null;
    if ("manifest_updated".equals(msg.get("kind"))) {
      run(w.manifest, known, null);
      return;
    }
    String fileId = String.valueOf(msg.get("fileId"));
    Watch f = w.files.get(fileId);
    if (f != null) run(f, known, fileId);
  }

  /** Every (re)open: whatever changed while the socket was down produced frames nobody received. */
  void catchUp() {
    for (VaultWatch w : watches.values()) {
      run(w.manifest, null, null);
      for (Map.Entry<String, Watch> f : w.files.entrySet()) run(f.getValue(), null, f.getKey());
    }
  }

  private void run(Watch watch, Integer known, String fileId) {
    CompletableFuture<Boolean> refresh;
    try {
      refresh = watch.refresh(known);
    } catch (RuntimeException e) {
      refresh = new CompletableFuture<>();
      refresh.completeExceptionally(e);
    }
    refresh.whenComplete(
        (changed, err) -> {
          if (err != null) {
            System.err.println("[Tasker] watch refresh failed: " + err);
            return;
          }
          if (!Boolean.TRUE.equals(changed)) return;
          for (Consumer<String> l : remoteChangeListeners) {
            try {
              l.accept(fileId);
            } catch (RuntimeException e) {
              System.err.println("[Tasker] remote-change listener error: " + e);
            }
          }
        });
  }

  /** Soft-delete {@code fileId}: every version moves to trash and stays restorable until
   *  {@link DeleteResult#expiresAt}. 404 → {@code NOT_FOUND}; 409 (already trashed) → {@code TRASHED}. */
  public CompletableFuture<DeleteResult> delete(VaultController v, String fileId) {
    return authedSend(v, "DELETE", fileUrl(v, fileId), null, Collections.emptyMap())
        .thenApply(
            r -> {
              if (r.status == 404) throw new CodedException("Not found", "NOT_FOUND");
              if (r.status == 409) throw new CodedException("File is trashed", "TRASHED");
              if (r.status == 401) throw new CodedException("Unauthorized", "UNAUTHORIZED");
              if (!r.ok()) throw new CodedException("DELETE failed: " + r.status, "DELETE_FAILED");
              return new DeleteResult(r.jsonObject());
            });
  }

  // ── upload paths ──

  private UploadResult singleChunkUpload(
      VaultController v, String fileId, byte[] data, byte[] encKey, Integer expectedVersion) {
    byte[] ciphertext = AEAD.encrypt(encKey, data);
    ApiClient.ApiResponse r = commitHead(v, fileId, ciphertext, 0, expectedVersion);
    if (r.status == 201) {
      Map<String, Object> j = r.jsonObject();
      return new UploadResult(((Number) j.get("version")).intValue(), (String) j.get("etag"), data.length, 0);
    }
    if (r.status == 412) {
      // 412 VERSION_MISMATCH: the remote head moved since the caller pinned expectedVersion (or
      // expectedVersion=0 asserted first-write but an object already exists). Re-committing the
      // same ciphertext over the new head would silently clobber the concurrent writer, so
      // surface the conflict for the caller to pull + merge + retry (CollectionController.save
      // branches on a "CAS"/"VERSION_MISMATCH" message). A commit with no expectedVersion can
      // never 412 — the server skips CAS — so this only ever fires on a real pinned conflict.
      Object cur;
      try {
        cur = r.jsonObject().get("currentHead");
      } catch (RuntimeException e) {
        cur = null;
      }
      throw new CodedException(
          "CAS VERSION_MISMATCH: expected version " + expectedVersion + ", remote head "
              + (cur instanceof Number ? cur : "unknown"),
          "VERSION_MISMATCH");
    }
    if (r.status == 401) throw new CodedException("Unauthorized", "UNAUTHORIZED");
    if (r.status == 409) throw new CodedException("File is trashed", "TRASHED");
    throw new CodedException("head PUT failed: " + r.status, "HEAD_PUT_FAILED");
  }

  private UploadResult multiChunkUpload(
      VaultController v, String fileId, byte[] data, byte[] encKey, Integer expectedVersion) {
    int totalChunks = (int) ((data.length + (long) Consts.CHUNK_SIZE - 1) / Consts.CHUNK_SIZE);
    if (totalChunks > Consts.STORAGE_MAX_CHUNKS_PER_FILE) {
      throw new CodedException(
          "File exceeds " + Consts.STORAGE_MAX_CHUNKS_PER_FILE + " chunks", "TOO_MANY_CHUNKS");
    }
    for (int attempt = 0; attempt < MAX_CAS_RETRIES; attempt++) {
      int currentHead = (attempt == 0 && expectedVersion != null) ? expectedVersion : headProbe(v, fileId);
      int predictedVersion = currentHead + 1;
      byte[] uploadNonce = CryptoUtils.generateRandomBytes(Consts.UPLOAD_NONCE_BYTES);

      AtomicBoolean stale = new AtomicBoolean(false);
      List<CompletableFuture<Void>> puts = new ArrayList<>();
      for (int i = 0; i < totalChunks; i++) {
        int start = i * Consts.CHUNK_SIZE;
        int end = Math.min(start + Consts.CHUNK_SIZE, data.length);
        byte[] ct = AEAD.encrypt(encKey, Arrays.copyOfRange(data, start, end));
        String chunkId = Helpers.deriveChunkId(fileId, uploadNonce, i);
        String url = chunkUrl(v, fileId, predictedVersion, chunkId);
        puts.add(
            authedSend(v, "PUT", url, ct, Collections.emptyMap())
                .thenAccept(
                    r -> {
                      if (r.status == 201) return;
                      if (r.status == 409) {
                        stale.set(true);
                        return;
                      }
                      if (r.status == 410) throw new CodedException("File is trashed", "TRASHED");
                      throw new CodedException("chunk PUT failed: " + r.status, "CHUNK_PUT_FAILED");
                    }));
      }
      CompletableFuture.allOf(puts.toArray(new CompletableFuture[0])).join();
      if (stale.get()) continue; // some chunk saw a stale head — retry with a fresh probe

      Map<String, Object> headBlob =
          Json.obj("v", Consts.HEAD_BLOB_SCHEMA_VERSION, "nonce", Helpers.hex(uploadNonce), "count", totalChunks, "size", data.length);
      byte[] headCiphertext = AEAD.encrypt(encKey, Helpers.utf8(Json.canonical(headBlob)));
      ApiClient.ApiResponse commit = commitHead(v, fileId, headCiphertext, totalChunks, currentHead);
      if (commit.status == 201) {
        Map<String, Object> j = commit.jsonObject();
        return new UploadResult(((Number) j.get("version")).intValue(), (String) j.get("etag"), data.length, totalChunks);
      }
      if (commit.status != 412) throw new CodedException("head commit failed: " + commit.status, "HEAD_PUT_FAILED");
      // 412 → loop and retry with a fresh head
    }
    throw new CodedException("Multi-chunk upload CAS failed after retries", "CAS_FAILED");
  }

  // ── download ──

  private DownloadResult doDownload(VaultController v, String fileId, byte[] encKey) {
    ApiClient.ApiResponse head = authedSend(v, "GET", fileUrl(v, fileId), null, Collections.emptyMap()).join();
    if (head.status == 404) throw new CodedException("Not found", "NOT_FOUND");
    if (head.status == 410) throw new CodedException("File is trashed", "TRASHED");
    if (!head.ok()) throw new CodedException("GET failed: " + head.status, "GET_FAILED");

    int chunkCount = headerInt(head, Consts.HEADER_CHUNK_COUNT, 0);
    int version = headerInt(head, Consts.HEADER_STORAGE_VERSION, 0);
    String etag = head.header("etag");

    if (chunkCount == 0) {
      return new DownloadResult(etag, AEAD.decrypt(encKey, head.body), version);
    }

    Map<String, Object> manifest = Json.parseObject(Helpers.fromUtf8(AEAD.decrypt(encKey, head.body)));
    byte[] uploadNonce = Helpers.fromHex((String) manifest.get("nonce"));
    int count = ((Number) manifest.get("count")).intValue();

    List<CompletableFuture<byte[]>> gets = new ArrayList<>();
    for (int i = 0; i < count; i++) {
      String chunkId = Helpers.deriveChunkId(fileId, uploadNonce, i);
      gets.add(
          authedSend(v, "GET", chunkUrl(v, fileId, version, chunkId), null, Collections.emptyMap())
              .thenApply(
                  r -> {
                    if (!r.ok()) throw new CodedException("chunk GET failed: " + r.status, "CHUNK_GET_FAILED");
                    return AEAD.decrypt(encKey, r.body);
                  }));
    }
    CompletableFuture.allOf(gets.toArray(new CompletableFuture[0])).join();
    byte[][] chunks = new byte[count][];
    for (int i = 0; i < count; i++) chunks[i] = gets.get(i).join();
    return new DownloadResult(etag, Helpers.concat(chunks), version);
  }

  // ── HTTP helpers (blocking on the orchestration worker) ──

  /**
   * Storage twin of {@link VaultController#invokeAuthed}: single 401→reauth→retry. Tokens expire
   * after 2h while the WebSocket stays open, so without this every storage call 401s until
   * re-unlock. {@code extra} is merged over fresh auth headers per attempt.
   */
  private CompletableFuture<ApiClient.ApiResponse> authedSend(
      VaultController v, String method, String url, byte[] body, Map<String, String> extra) {
    return withReauth(
        () -> {
          Map<String, String> h = authHeaders(v);
          h.putAll(extra);
          return ApiClient.send(method, url, body, OCTET, h);
        },
        v::handleAuthError);
  }

  /** Pure retry policy: send; on 401 ask {@code reauth}; if it refreshed the token, send once more. */
  static CompletableFuture<ApiClient.ApiResponse> withReauth(
      Supplier<CompletableFuture<ApiClient.ApiResponse>> send, Supplier<CompletableFuture<Boolean>> reauth) {
    return send.get()
        .thenCompose(
            r -> {
              if (r.status != 401) return CompletableFuture.completedFuture(r);
              return reauth.get().thenCompose(ok -> ok ? send.get() : CompletableFuture.completedFuture(r));
            });
  }

  private ApiClient.ApiResponse commitHead(
      VaultController v, String fileId, byte[] body, int chunkCount, Integer expectedVersion) {
    Map<String, String> h = new java.util.HashMap<>();
    h.put(Consts.HEADER_CHUNK_COUNT, String.valueOf(chunkCount));
    if (expectedVersion != null) h.put(Consts.HEADER_EXPECTED_VERSION, String.valueOf(expectedVersion));
    return authedSend(v, "PUT", fileUrl(v, fileId), body, h).join();
  }

  private int headProbe(VaultController v, String fileId) {
    ApiClient.ApiResponse r = authedSend(v, "HEAD", fileUrl(v, fileId), null, Collections.emptyMap()).join();
    if (r.status == 404) return 0;
    if (r.status == 410) throw new CodedException("File is trashed", "TRASHED");
    if (!r.ok()) throw new CodedException("HEAD failed: " + r.status, "HEAD_FAILED");
    return headerInt(r, Consts.HEADER_STORAGE_VERSION, 0);
  }

  private Map<String, String> authHeaders(VaultController v) {
    Map<String, String> h = v.authedHeaders();
    h.put("Authorization", "Bearer " + v.getAuthToken());
    return h;
  }

  private String fileUrl(VaultController v, String fileId) {
    return endpoint + "/api/storage/" + v.getId() + "/" + fileId;
  }

  private String chunkUrl(VaultController v, String fileId, int version, String chunkId) {
    return fileUrl(v, fileId) + "/v" + version + "/chunks/" + chunkId;
  }

  private static int headerInt(ApiClient.ApiResponse r, String name, int dflt) {
    String s = r.header(name);
    return s != null ? Integer.parseInt(s) : dflt;
  }
}
