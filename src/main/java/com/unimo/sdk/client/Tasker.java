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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * Port of the upload/download core of {@code sdk/ts/src_ts/client/Tasker.ts} (storage-v2).
 * The task-queue / reactive-progress / WS-watch control plane is deferred to later phases —
 * this is the encrypted blob transfer:
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

  public Tasker(String serviceUrl) {
    this.endpoint = serviceUrl.replaceAll("/+$", "");
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
