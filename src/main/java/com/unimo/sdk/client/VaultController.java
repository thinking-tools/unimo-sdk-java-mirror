package com.unimo.sdk.client;

import com.unimo.sdk.client.Members.MemberInfoBasics;
import com.unimo.sdk.client.collections.CollectionController;
import com.unimo.sdk.client.collections.KVContent;
import com.unimo.sdk.crypto.AEAD;
import com.unimo.sdk.crypto.CodedException;
import com.unimo.sdk.crypto.CryptoPQ;
import com.unimo.sdk.crypto.CryptoUtils;
import com.unimo.sdk.shared.Consts;
import com.unimo.sdk.shared.Helpers;
import com.unimo.sdk.shared.Json;
import com.unimo.sdk.shared.Validators;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;

/**
 * Port of {@code sdk/ts/src_ts/client/Vault.ts} — Phase 2 subset: login + manifest validation +
 * {@code deriveKeys} (unlock the vault key from this member's KEM-wrapped slot). Manifest
 * mutation (CAS PUT), member add/remove + key rotation, and reauth land in Phase 3.
 */
public final class VaultController {
  private final String serviceUrl;
  private final MemberInfoBasics activeMember;
  private Map<String, Object> vaultManifest;
  private String etag;
  private volatile String authToken;
  private int manifestVersion;

  private byte[] aeadVaultKey;
  private boolean isManagerMember;
  private byte[] managersKey;
  private byte[] collectionsKey;
  private List<Map<String, Object>> memberList;
  /** Serializes {@link #reauth()} dispatch so concurrent 401s share one POST and one token. */
  private final Object reauthLock = new Object();
  /** Non-null while a reauth is in flight; {@link #reauth()} joins it instead of re-dispatching. */
  private CompletableFuture<ReauthOutcome> inFlightReauth;
  /** Fired once when a reauth comes back {@link ReauthOutcome#REVOKED}: a manager removed this
   *  device. Wired by {@link Account}. */
  volatile Runnable onRevoked;

  /** Observable list of this vault's collections (decrypted from the manifest at unlock). */
  public final ReactiveValue<List<CollectionController>> collections = new ReactiveValue<>(new ArrayList<>());

  private VaultController(
      String serviceUrl,
      Map<String, Object> vaultManifest,
      String etag,
      String authToken,
      MemberInfoBasics activeMember,
      int manifestVersion) {
    this.serviceUrl = serviceUrl;
    this.vaultManifest = vaultManifest;
    this.etag = etag;
    this.authToken = authToken;
    this.activeMember = activeMember;
    this.manifestVersion = manifestVersion;
  }

  /** Sign a login request, POST it, validate the returned manifest, and unlock the vault key. */
  public static CompletableFuture<VaultController> init(String serviceUrl, String accountName, MemberInfoBasics member) {
    String name = accountName.trim();
    Map<String, Object> loginPayload =
        Json.obj("accountName", name, "memberId", member.memberId, "timestamp", System.currentTimeMillis());
    byte[] hash = CryptoUtils.sha256(Helpers.utf8(Json.canonical(loginPayload)));
    Map<String, Object> loginBody =
        Json.obj(
            "payload", loginPayload,
            "payloadHash", Helpers.base64(hash),
            "signerId", member.memberId,
            "signature", Helpers.base64(CryptoPQ.sign(member.dsaKeys.secretKey, hash)));

    return ApiClient.makeRequest("POST", serviceUrl + "/api/auth/login", loginBody)
        .thenApply(
            resp -> {
              if (!Boolean.TRUE.equals(resp.get("ok"))) {
                throw new CodedException(String.valueOf(resp.getOrDefault("message", "Login failed")), "LOGIN_FAILED");
              }
              @SuppressWarnings("unchecked")
              Map<String, Object> manifest = (Map<String, Object>) resp.get("accountVault");
              @SuppressWarnings("unchecked")
              Map<String, Object> payload = manifest == null ? null : (Map<String, Object>) manifest.get("payload");
              if (manifest == null
                  || !Validators.isValidVaultManifest(manifest, Consts.VAULT_TYPE_ACCOUNT)
                  || !name.equals(payload.get("name"))) {
                throw new CodedException("Invalid vault manifest received from server", "INVALID_MANIFEST");
              }
              VaultController vc =
                  new VaultController(
                      serviceUrl,
                      manifest,
                      (String) resp.get("vaultEtag"),
                      (String) resp.get("authToken"),
                      member,
                      intOr(resp.get("manifestVersion"), 1));
              vc.deriveKeys();
              return vc;
            });
  }

  /** Decapsulate this member's KEM ciphertext, unwrap the role key, and derive sub-keys. */
  @SuppressWarnings("unchecked")
  private void deriveKeys() {
    Map<String, Object> payload = (Map<String, Object>) vaultManifest.get("payload");
    List<Object> slots = (List<Object>) payload.get("memberSlots");
    Map<String, Object> slot = Validators.getMemberFromMemberSlots(slots, activeMember.memberId);
    if (slot == null) throw new CodedException("Active member slot not found in manifest", "NO_MEMBER_SLOT");

    byte[] shared =
        CryptoPQ.decapsulate(activeMember.kemKeys, Helpers.fromBase64((String) slot.get("memberKemCiphertext")));
    byte[] roleKey = AEAD.decrypt(shared, Helpers.fromBase64((String) slot.get("memberVaultKeyWrapped")));
    this.aeadVaultKey = roleKey;

    if (Consts.isManagerRole((String) slot.get("memberRole"))) {
      this.managersKey = Members.getManagerKey(roleKey);
      this.memberList = Members.decryptMemberList((String) payload.get("managerOnlyMemberList"), managersKey);
      this.isManagerMember = true;
      this.collectionsKey = Members.getCollectionsKey(roleKey);
    } else {
      this.isManagerMember = false;
      this.collectionsKey = this.aeadVaultKey;
    }
    this.collections.set(decryptCollectionsList());
  }

  // ── manifest CAS update (PUT /api/auth/manifest) ──

  private CompletableFuture<Map<String, Object>> trySignAndPut(int basedOnVersion) {
    Map<String, Object> payload = payload();
    payload.put("updatedAt", Helpers.isoNow());
    byte[] hash = CryptoUtils.sha256(Helpers.utf8(Json.canonical(payload)));
    Map<String, Object> body =
        Json.obj(
            "prevVersion", basedOnVersion,
            "payload", payload,
            "payloadHash", Helpers.base64(hash),
            "signerId", activeMember.memberId,
            "signature", Helpers.base64(CryptoPQ.sign(activeMember.dsaKeys.secretKey, hash)));
    return ApiClient.authRequest("PUT", serviceUrl + "/api/auth/manifest", authToken, body, authedHeaders())
        .thenApply(ApiClient.ApiResponse::jsonObject);
  }

  /** Sign + PUT the current payload, CAS-pinned to {@code manifestVersion}; on 412 refresh the
   *  version from the response and retry once (mirrors TS {@code #saveUpdate}). */
  private CompletableFuture<Void> saveUpdate() {
    return trySignAndPut(manifestVersion)
        .thenCompose(
            result -> {
              if (!Boolean.TRUE.equals(result.get("ok"))
                  && "VERSION_MISMATCH".equals(result.get("code"))
                  && result.get("currentVersion") instanceof Number) {
                manifestVersion = ((Number) result.get("currentVersion")).intValue();
                return trySignAndPut(manifestVersion);
              }
              return CompletableFuture.completedFuture(result);
            })
        .thenAccept(
            result -> {
              if (!Boolean.TRUE.equals(result.get("ok"))) {
                throw new CodedException(
                    "Manifest update failed: " + result.get("statusCode") + " " + result.get("message"),
                    "MANIFEST_UPDATE_FAILED");
              }
              manifestVersion = ((Number) result.get("version")).intValue();
              etag = (String) result.get("etag");
            });
  }

  // ── manifest refresh (GET /api/auth/manifest) + reauth ──

  private static final class ManifestResult {
    final Map<String, Object> vault;
    final int version;

    ManifestResult(Map<String, Object> vault, int version) {
      this.vault = vault;
      this.version = version;
    }
  }

  @SuppressWarnings("unchecked")
  private CompletableFuture<ManifestResult> fetchLatestManifest() {
    String url = serviceUrl + "/api/auth/manifest";
    return ApiClient.authRequest("GET", url, authToken, null, authedHeaders())
        .thenCompose(
            resp -> {
              if (resp.status == 401) {
                return handleAuthError()
                    .thenCompose(
                        ok ->
                            ok
                                ? ApiClient.authRequest("GET", url, authToken, null, authedHeaders())
                                : CompletableFuture.completedFuture(null));
              }
              return CompletableFuture.completedFuture(resp);
            })
        .thenApply(
            resp -> {
              if (resp == null || !resp.ok()) return null;
              Map<String, Object> body = resp.jsonObject();
              if (!Boolean.TRUE.equals(body.get("ok"))) return null;
              return new ManifestResult((Map<String, Object>) body.get("accountVault"), intOr(body.get("version"), 1));
            });
  }

  /** Refresh local state from the server (re-deriving keys if the epoch rotated). */
  public CompletableFuture<Void> timeToFetchUpdate() {
    return fetchLatestManifest()
        .thenAccept(
            result -> {
              if (result == null || !Validators.isValidVaultManifest(result.vault, Consts.VAULT_TYPE_ACCOUNT)) return;
              long oldEpoch = ((Number) payload().get("keyEpoch")).longValue();
              @SuppressWarnings("unchecked")
              Map<String, Object> newPayload = (Map<String, Object>) result.vault.get("payload");
              long newEpoch = rollbackCheckedEpoch(oldEpoch, newPayload);
              this.vaultManifest = result.vault;
              this.manifestVersion = result.version;
              if (newEpoch != oldEpoch) {
                deriveKeys(); // re-derives keys + re-sets the collections list
              } else {
                if (isManagerMember && managersKey != null) {
                  this.memberList =
                      Members.decryptMemberList((String) newPayload.get("managerOnlyMemberList"), managersKey);
                }
                mergeCollections(decryptCollectionsList()); // pick up collection-list changes at the same epoch
              }
            });
  }

  /**
   * Rollback floor for a fetched manifest. {@code keyEpoch} only ever increases (rotation bumps it
   * in {@link #rotateAndRewrapForMembers}), so a fetched manifest whose epoch is below the one held
   * is a replayed/rolled-back manifest from the untrusted server — reject it rather than adopt
   * (which would undo a member removal or re-derive down to retired keys). Fails closed when the
   * fetched epoch is missing or non-integer.
   *
   * <p>In-session mitigation only: with no persisted floor, the first manifest of a session and any
   * rollback across a restart remain undefended. Package-private for unit testing.
   */
  static long rollbackCheckedEpoch(long oldEpoch, Map<String, Object> newPayload) {
    Object raw = newPayload == null ? null : newPayload.get("keyEpoch");
    if (raw instanceof Double || raw instanceof Float || !(raw instanceof Number)) {
      throw new CodedException("fetched manifest has a missing or non-integer keyEpoch", "INVALID_MANIFEST");
    }
    long newEpoch = ((Number) raw).longValue();
    if (newEpoch < oldEpoch) {
      throw new CodedException(
          "manifest rollback rejected: fetched keyEpoch " + newEpoch + " < current " + oldEpoch,
          "MANIFEST_ROLLBACK");
    }
    return newEpoch;
  }

  /** Outcome of a reauth attempt, classifying the gateway response by retryability. */
  enum ReauthOutcome {
    /** 2xx with a fresh authToken — reconnect/retry with it. */
    REFRESHED,
    /** 404/401/403, or a 2xx with no usable token — genuine rejection; halting the chain is correct. */
    REJECTED,
    /** A rejection carrying the gateway's {@code NOT_A_MEMBER} code: a manager removed this
     *  member. Halts like REJECTED and fires {@link #onRevoked} so the app can wipe the account. */
    REVOKED,
    /** 400 catch-all / 409 replay / 429 / 5xx / transport failure — momentary; retry on backoff. */
    TRANSIENT
  }

  /**
   * Pure classification of a {@code POST /api/auth/reauth} response (route in
   * {@code secure.gateway.unimo/src/users/routes.ts}). Package-private + static so the
   * retryability rules are unit-testable in isolation, mirroring {@link #rollbackCheckedEpoch}.
   * {@code body} is the parsed JSON when the response parses, else null.
   */
  static ReauthOutcome classifyReauth(int status, Map<String, Object> body) {
    if (status >= 200 && status < 300) {
      // TS does `if (response.ok && response.authToken)` — JS truthiness, so "" is rejected. Match
      // that with a non-empty String, and require String so the (String) cast in doReauth can't throw
      // (a non-String would otherwise ClassCastException into a swallowed TRANSIENT = infinite retry).
      if (body != null && Boolean.TRUE.equals(body.get("ok"))) {
        Object tok = body.get("authToken");
        if (tok instanceof String && !((String) tok).isEmpty()) return ReauthOutcome.REFRESHED;
      }
      // 2xx without a usable non-empty String authToken: gateway/version skew — treat as not-refreshed.
      return ReauthOutcome.REJECTED;
    }
    // The gateway's NOT_A_MEMBER (a 401 for a member it no longer lists): the one rejection with a
    // known cause. Apps wipe the account on it, so a bare 401 (bad signature, clock skew) must not
    // be promoted.
    if (body != null && "NOT_A_MEMBER".equals(body.get("code"))) return ReauthOutcome.REVOKED;
    // 404 account gone, 401 bad signature/clock skew, 403 role unknown: definitive, don't spin.
    if (status == 404 || status == 401 || status == 403) return ReauthOutcome.REJECTED;
    // 400 (catch-all incl. infra), 409 (replay — a duplicated POST can trip this), 429, 5xx: retry.
    return ReauthOutcome.TRANSIENT;
  }

  /**
   * Single-flight reauth: concurrent callers (a Connection upgrade-401, {@link #invokeAuthed}'s
   * 401, {@link #fetchLatestManifest}'s 401) share one {@code POST /api/auth/reauth} and adopt one
   * refreshed token, instead of racing N signed reauths whose token regenerations invalidate each
   * other. The per-vault gateway rate limit (429) and this single-flight together replace the old
   * 3-in-5s client-side throttle, which folded transient failures into a permanent halt.
   */
  CompletableFuture<ReauthOutcome> reauth() {
    synchronized (reauthLock) {
      if (inFlightReauth != null) return inFlightReauth;
      CompletableFuture<ReauthOutcome> f = doReauth();
      inFlightReauth = f;
      f.whenComplete(
          (r, e) -> {
            synchronized (reauthLock) {
              if (inFlightReauth == f) inFlightReauth = null;
            }
          });
      return f;
    }
  }

  /**
   * Guards {@link #dispatchReauth()} so a synchronous throw (from the sign/sha256/getId preamble,
   * or send()'s sync portion) never escapes: doReauth always returns a normally-completing future,
   * so reauth() — and Connection's .whenComplete — always attach. A sync throw otherwise leaves
   * reauth() with no future and stalls the WebSocket reconnect silently.
   */
  private CompletableFuture<ReauthOutcome> doReauth() {
    try {
      return dispatchReauth();
    } catch (RuntimeException ignored) {
      return CompletableFuture.completedFuture(ReauthOutcome.TRANSIENT);
    }
  }

  private CompletableFuture<ReauthOutcome> dispatchReauth() {
    long nowTime = System.currentTimeMillis();
    Map<String, Object> payload =
        Json.obj(
            "memberId", activeMember.memberId,
            "vaultId", getId(),
            "timestamp", nowTime,
            "reqId", CryptoUtils.generateRandomUUID());
    byte[] hash = CryptoUtils.sha256(Helpers.utf8(Json.canonical(payload)));
    Map<String, Object> body =
        Json.obj(
            "payload", payload,
            "payloadHash", Helpers.base64(hash),
            "signature", Helpers.base64(CryptoPQ.sign(activeMember.dsaKeys.secretKey, hash)));
    // send() (not makeRequest) so the HTTP status survives for classification.
    return ApiClient.send("POST", serviceUrl + "/api/auth/reauth", Helpers.utf8(Json.canonical(body)), Collections.emptyMap())
        .<ReauthOutcome>thenApply(
            resp -> {
              Map<String, Object> parsed;
              try {
                parsed = resp.jsonObject();
              } catch (RuntimeException parseError) {
                // 2xx with an unparseable body is a gateway/version bug — retry, don't halt.
                if (resp.ok()) return ReauthOutcome.TRANSIENT;
                parsed = null;
              }
              ReauthOutcome outcome = classifyReauth(resp.status, parsed);
              if (outcome == ReauthOutcome.REFRESHED) {
                // Safe: classifyReauth returns REFRESHED only when authToken is a non-empty String.
                this.authToken = (String) parsed.get("authToken");
              }
              if (outcome == ReauthOutcome.REVOKED) {
                Runnable r = onRevoked;
                onRevoked = null; // fire once
                if (r != null) r.run();
              }
              return outcome;
            })
        .exceptionally(e -> ReauthOutcome.TRANSIENT);
  }

  /**
   * Boolean view of {@link #reauth()} for the two HTTP callers ({@link #fetchLatestManifest},
   * {@link #invokeAuthed}) that only need "did the token refresh, should I retry once". This is the
   * public surface; {@link #reauth()} is package-private and exposes the full tri-state to in-package
   * callers (e.g. {@link Connection}).
   */
  public CompletableFuture<Boolean> handleAuthError() {
    return reauth().thenApply(o -> o == ReauthOutcome.REFRESHED);
  }

  // ── members (add / remove → key rotation + signed manifest PUT) ──

  /** Generate a fresh vault key, rewrap the manager area, and re-encapsulate the vault key for
   *  every member slot under its KEM public key. Mutates the manifest payload in place. */
  private void rotateAndRewrapForMembers(List<Object> newSlots, List<Map<String, Object>> newDetails) {
    if (!isManagerMember || managersKey == null) {
      throw new CodedException("Only manager members can rotate vault keys", "NOT_MANAGER");
    }
    byte[] oldManagerKey = this.managersKey;
    byte[] newVaultKey = AEAD.generateRawAEADKeyData();
    byte[] newManagerKey = Members.getManagerKey(newVaultKey);
    byte[] newCollectionsKey = Members.getCollectionsKey(newVaultKey);
    Map<String, Object> payload = payload();

    Object areaB64 = payload.get("managerOnlyArea");
    if (areaB64 instanceof String && !((String) areaB64).isEmpty()) {
      byte[] areaPlain = AEAD.decrypt(oldManagerKey, Helpers.fromBase64((String) areaB64));
      payload.put("managerOnlyArea", Helpers.base64(AEAD.encrypt(newManagerKey, areaPlain)));
    }

    for (Object so : newSlots) {
      @SuppressWarnings("unchecked")
      Map<String, Object> slot = (Map<String, Object>) so;
      Map<String, Object> detail = findById(newDetails, slot.get("memberId"));
      if (detail == null) throw new CodedException("Missing detail for " + slot.get("memberId"), "MISSING_DETAIL");
      CryptoPQ.Encapsulated enc = CryptoPQ.encapsulate(Helpers.fromBase64((String) detail.get("memberKemPubkey")));
      byte[] roleKey = CryptoUtils.deriveKeyForRole((String) slot.get("memberRole"), newVaultKey);
      byte[] wrapped = AEAD.encrypt(enc.sharedSecret, roleKey);
      if (roleKey != newVaultKey) Arrays.fill(roleKey, (byte) 0); // never zero the shared master-key reference
      Arrays.fill(enc.sharedSecret, (byte) 0);
      slot.put("memberKemCiphertext", Helpers.base64(enc.cipherText));
      slot.put("memberVaultKeyWrapped", Helpers.base64(wrapped));
      slot.put("updatedAt", System.currentTimeMillis());
    }

    payload.put("managerOnlyMemberList", Members.encryptMemberList(newDetails, newManagerKey));
    payload.put("collectionsEncrypted", encryptCollectionsList(newCollectionsKey)); // re-key the real list
    // newVaultKey is retained as aeadVaultKey (not zeroed): unlike the TS WebCrypto path that
    // imports a copy then wipes the raw, this port uses the raw bytes directly as the key.
    this.aeadVaultKey = newVaultKey;
    this.managersKey = newManagerKey;
    this.collectionsKey = newCollectionsKey;
    this.memberList = newDetails;
    payload.put("keyEpoch", ((Number) payload.get("keyEpoch")).longValue() + 1);
    payload.put("memberSlots", newSlots);
  }

  /** Add a member by its KEM+DSA public keys (rotates keys, re-wraps for all, PUTs the manifest). */
  public CompletableFuture<Map<String, Object>> addMemberByPublicKeys(
      String kemPubkeyB64, String dsaPubkeyB64, String memberName, String memberRole, String privateNote) {
    if (!isManagerMember || managersKey == null) {
      throw new CodedException("Only manager members can add members", "NOT_MANAGER");
    }
    if (!Validators.validateAccountName(memberName)) {
      throw new CodedException("Invalid member name", "INVALID_MEMBER_NAME");
    }
    String memberId = CryptoUtils.getMemberIdFromPubkey(Helpers.fromBase64(dsaPubkeyB64));
    long ts = System.currentTimeMillis();
    Map<String, Object> newSlot =
        Json.obj(
            "memberId", memberId,
            "memberRole", memberRole,
            "memberStatus", Consts.STATUS_ACTIVE,
            "memberKemCiphertext", "",
            "memberVaultKeyWrapped", "",
            "memberDsaPubkey", dsaPubkeyB64,
            "createdAt", ts,
            "updatedAt", ts);
    Map<String, Object> newDetail =
        Json.obj(
            "memberId", memberId,
            "memberName", memberName,
            "memberKemPubkey", kemPubkeyB64,
            "memberAddedBy", activeMember.memberId,
            "memberAddedAt", ts);
    if (privateNote != null) newDetail.put("memberPrivateNote", privateNote);

    List<Object> newSlots = new ArrayList<>(slots());
    newSlots.add(newSlot);
    List<Map<String, Object>> newDetails = new ArrayList<>(memberList);
    newDetails.add(newDetail);
    rotateAndRewrapForMembers(newSlots, newDetails);
    return saveUpdate().thenApply(x -> findById(slots(), memberId));
  }

  /** Add a member from a seed (derives its keypair, then {@link #addMemberByPublicKeys}). */
  public CompletableFuture<Map<String, Object>> addMemberWithSeed(
      byte[] memberSeed, String memberName, String memberRole, String privateNote) {
    MemberInfoBasics m = Members.buildMember(memberSeed);
    return addMemberByPublicKeys(
        Helpers.base64(m.kemKeys.publicKey), Helpers.base64(m.dsaKeys.publicKey), memberName, memberRole, privateNote);
  }

  public CompletableFuture<Boolean> removeMember(String memberId) {
    if (!isManagerMember || managersKey == null) {
      throw new CodedException("Only manager members can remove members", "NOT_MANAGER");
    }
    if (memberId.equals(activeMember.memberId)) {
      throw new CodedException("Cannot remove yourself", "REMOVE_SELF");
    }
    if (findById(slots(), memberId) == null) throw new CodedException("Member not found", "MEMBER_NOT_FOUND");
    List<Object> newSlots = new ArrayList<>();
    for (Object s : slots()) if (!memberId.equals(((Map<?, ?>) s).get("memberId"))) newSlots.add(s);
    List<Map<String, Object>> newDetails = new ArrayList<>();
    for (Map<String, Object> d : memberList) if (!memberId.equals(d.get("memberId"))) newDetails.add(d);
    rotateAndRewrapForMembers(newSlots, newDetails);
    return saveUpdate().thenApply(x -> true);
  }

  // ── collections ──

  @SuppressWarnings("unchecked")
  private List<CollectionController> decryptCollectionsList() {
    Object enc = payload().get("collectionsEncrypted");
    if (!(enc instanceof String) || ((String) enc).isEmpty() || collectionsKey == null) return new ArrayList<>();
    byte[] plain = AEAD.decrypt(collectionsKey, Helpers.fromBase64((String) enc));
    List<CollectionController> out = new ArrayList<>();
    for (Object o : (List<Object>) Json.parse(Helpers.fromUtf8(plain))) {
      Map<String, Object> c = (Map<String, Object>) o;
      out.add(
          new CollectionController(
              (String) c.get("colId"),
              (String) c.get("colType"),
              (String) c.get("colName"),
              Helpers.fromBase64((String) c.get("colEncKey")),
              this,
              null));
    }
    return out;
  }

  private String encryptCollectionsList(byte[] key) {
    List<Object> minimal = new ArrayList<>();
    for (CollectionController c : collections.get()) minimal.add(c.minimalMap());
    return Helpers.base64(AEAD.encrypt(key, Helpers.utf8(Json.canonical(minimal))));
  }

  private void encryptAndUpdateCollectionsList() {
    if (collectionsKey == null) throw new CodedException("Collections key not available", "NO_COLLECTIONS_KEY");
    payload().put("collectionsEncrypted", encryptCollectionsList(collectionsKey));
  }

  private void mergeCollections(List<CollectionController> incoming) {
    Map<String, CollectionController> current = new HashMap<>();
    for (CollectionController c : collections.get()) current.put(c.getId(), c);
    List<CollectionController> merged = new ArrayList<>();
    for (CollectionController inc : incoming) {
      CollectionController existing = current.get(inc.getId());
      merged.add(existing != null ? existing : inc);
    }
    collections.set(merged);
  }

  public List<CollectionController> listCollections() {
    return collections.get();
  }

  /** Create a KV collection: upload its initial blob (CAS first-write), then sign the manifest with
   *  the updated collections list. Manager-only. */
  public CompletableFuture<KVContent> createCollection(String name, String type, Tasker tasker) {
    if (!Validators.isValidCollectionName(name)) throw new CodedException("Invalid collection name", "INVALID_COLLECTION_NAME");
    if (!Validators.isValidCollectionType(type)) throw new CodedException("Invalid collection type", "INVALID_COLLECTION_TYPE");
    for (CollectionController c : collections.get()) {
      if (name.trim().equals(c.getName())) throw new CodedException("Collection name must be unique", "DUPLICATE_COLLECTION");
    }
    if (!isManagerMember || collectionsKey == null) {
      throw new CodedException("Only manager members can create collections", "NOT_MANAGER");
    }
    CollectionController col = CollectionController.createNew(name, type, this, activeMember.memberId);
    collections.update(list -> list.add(col));
    return tasker
        .upload(this, col.getId(), col.serialize(), col.getEncKey(), 0)
        .thenCompose(
            up -> {
              col.setInitialVersion(up.version);
              col.attachTasker(tasker, true);
              encryptAndUpdateCollectionsList();
              return saveUpdate();
            })
        .thenApply(x -> col.content());
  }

  public CompletableFuture<KVContent> getCollectionByName(Tasker tasker, String name) {
    for (CollectionController c : collections.get()) if (name.equals(c.getName())) return c.load(tasker, true);
    return CompletableFuture.completedFuture(null);
  }

  public CompletableFuture<KVContent> getCollectionById(Tasker tasker, String colId) {
    for (CollectionController c : collections.get()) if (colId.equals(c.getId())) return c.load(tasker, true);
    return CompletableFuture.completedFuture(null);
  }

  public CompletableFuture<Boolean> renameCollectionById(String colId, String newName) {
    CollectionController col = findCollection(colId);
    if (col == null) throw new CodedException("Collection not found", "COLLECTION_NOT_FOUND");
    col.setName(newName, activeMember.memberId);
    encryptAndUpdateCollectionsList();
    return saveUpdate().thenApply(x -> true);
  }

  public CompletableFuture<Boolean> removeCollectionById(Tasker tasker, String colId) {
    if (!isManagerMember || collectionsKey == null) {
      throw new CodedException("Only manager members can remove collections", "NOT_MANAGER");
    }
    CollectionController col = findCollection(colId);
    if (col != null) col.dispose();
    // Soft-delete via Tasker (reauth-on-401). A blob already gone (NOT_FOUND) or already trashed
    // (TRASHED) still gets pruned from the manifest.
    return tasker
        .delete(this, colId)
        .exceptionally(
            err -> {
              if (isAlreadyGone(err)) return null;
              throw err instanceof RuntimeException ? (RuntimeException) err : new CompletionException(err);
            })
        .thenCompose(
            x -> {
              List<CollectionController> kept = new ArrayList<>();
              for (CollectionController c : collections.get()) if (!colId.equals(c.getId())) kept.add(c);
              collections.set(kept);
              encryptAndUpdateCollectionsList();
              return saveUpdate();
            })
        .thenApply(x -> true);
  }

  private static boolean isAlreadyGone(Throwable err) {
    Throwable t = err instanceof CompletionException && err.getCause() != null ? err.getCause() : err;
    if (!(t instanceof CodedException)) return false;
    String code = ((CodedException) t).getCode();
    return "NOT_FOUND".equals(code) || "TRASHED".equals(code);
  }

  private CollectionController findCollection(String colId) {
    for (CollectionController c : collections.get()) if (colId.equals(c.getId())) return c;
    return null;
  }

  @SuppressWarnings("unchecked")
  private Map<String, Object> payload() {
    return (Map<String, Object>) vaultManifest.get("payload");
  }

  @SuppressWarnings("unchecked")
  private List<Object> slots() {
    return (List<Object>) payload().get("memberSlots");
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> findById(List<?> items, Object memberId) {
    for (Object o : items) {
      Map<String, Object> m = (Map<String, Object>) o;
      if (memberId.equals(m.get("memberId"))) return m;
    }
    return null;
  }

  // ── manager-only area + invites ──

  /** Bearer-authed request with a single 401→reauth→retry (shared by invites + billing). */
  public CompletableFuture<ApiClient.ApiResponse> invokeAuthed(String method, String path, Map<String, Object> body) {
    if (authToken == null) throw new CodedException("Not authenticated", "NOT_AUTHENTICATED");
    String url = serviceUrl + path;
    return ApiClient.authRequest(method, url, authToken, body, authedHeaders())
        .thenCompose(
            resp -> {
              if (resp.status != 401) return CompletableFuture.completedFuture(resp);
              return handleAuthError()
                  .thenCompose(
                      ok ->
                          ok
                              ? ApiClient.authRequest(method, url, authToken, body, authedHeaders())
                              : CompletableFuture.completedFuture(resp));
            });
  }

  private Map<String, Object> readManagerArea() {
    if (managersKey == null) throw new CodedException("Only manager members can access the manager area", "NOT_MANAGER");
    byte[] plain = AEAD.decrypt(managersKey, Helpers.fromBase64((String) payload().get("managerOnlyArea")));
    Map<String, Object> area = Json.parseObject(Helpers.fromUtf8(plain));
    if (!(area.get("v") instanceof Number) || ((Number) area.get("v")).intValue() != Consts.MANAGER_AREA_VERSION) {
      throw new CodedException("Unsupported managerOnlyArea version", "BAD_AREA_VERSION");
    }
    return area;
  }

  private CompletableFuture<Void> writeManagerArea(Map<String, Object> area) {
    if (managersKey == null) throw new CodedException("Only manager members can access the manager area", "NOT_MANAGER");
    payload().put("managerOnlyArea", Helpers.base64(AEAD.encrypt(managersKey, Helpers.utf8(Json.canonical(area)))));
    return saveUpdate();
  }

  @SuppressWarnings("unchecked")
  private static List<Object> invitesOf(Map<String, Object> area) {
    return area.get("invites") instanceof List ? (List<Object>) area.get("invites") : new ArrayList<>();
  }

  @SuppressWarnings("unchecked")
  public CompletableFuture<Void> addPendingInvite(Map<String, Object> entry) {
    Map<String, Object> area = readManagerArea();
    long cutoff = Helpers.now() - Consts.INVITE_MAX_TTL_SECONDS * 1000;
    List<Object> next = new ArrayList<>();
    for (Object o : invitesOf(area)) {
      Map<String, Object> i = (Map<String, Object>) o;
      if (((Number) i.get("createdAt")).longValue() > cutoff) next.add(i);
    }
    next.add(entry);
    area.put("invites", next);
    return writeManagerArea(area);
  }

  @SuppressWarnings("unchecked")
  public Map<String, Object> getPendingInvite(String inviteId) {
    for (Object o : invitesOf(readManagerArea())) {
      Map<String, Object> i = (Map<String, Object>) o;
      if (inviteId.equals(i.get("inviteId"))) return i;
    }
    return null;
  }

  @SuppressWarnings("unchecked")
  public CompletableFuture<Void> removePendingInvite(String inviteId) {
    Map<String, Object> area = readManagerArea();
    List<Object> invites = invitesOf(area);
    List<Object> next = new ArrayList<>();
    for (Object o : invites) {
      Map<String, Object> i = (Map<String, Object>) o;
      if (!inviteId.equals(i.get("inviteId"))) next.add(i);
    }
    if (next.size() == invites.size()) return CompletableFuture.completedFuture(null);
    area.put("invites", next);
    return writeManagerArea(area);
  }

  public static final class InviteCreated {
    public final String inviteId;
    public final String code;
    public final long expiresAt;

    InviteCreated(String inviteId, String code, long expiresAt) {
      this.inviteId = inviteId;
      this.code = code;
      this.expiresAt = expiresAt;
    }
  }

  /** Create a pending invite: persist the secret into the manager area, register the server
   *  record, and return the shareable code (hand to the invitee in person). Manager-only. */
  public CompletableFuture<InviteCreated> createInvite(String role, Integer ttlSeconds) {
    if (!isManagerMember) throw new CodedException("Only managers can create invites", "NOT_MANAGER");
    byte[] secret = CryptoUtils.generateRandomBytes(Consts.INVITE_SECRET_LENGTH_BYTES);
    String inviteId = Invites.deriveInviteId(secret);
    Map<String, Object> entry =
        Json.obj("inviteId", inviteId, "inviteSecret", Helpers.base64(secret), "role", role, "createdAt", Helpers.now());
    Map<String, Object> body =
        ttlSeconds != null
            ? Json.obj("inviteId", inviteId, "role", role, "ttlSeconds", ttlSeconds)
            : Json.obj("inviteId", inviteId, "role", role);
    return addPendingInvite(entry)
        .thenCompose(x -> invokeAuthed("POST", "/api/auth/invite", body))
        .thenApply(
            resp -> {
              Map<String, Object> b = resp.ok() ? resp.jsonObject() : null;
              if (b == null || !Boolean.TRUE.equals(b.get("ok"))) {
                throw new CodedException("createInvite failed: " + resp.status, "INVITE_CREATE_FAILED");
              }
              long expiresAt = b.get("expiresAt") instanceof Number ? ((Number) b.get("expiresAt")).longValue() : 0;
              return new InviteCreated(inviteId, Invites.encodeInviteCode(secret), expiresAt);
            });
  }

  /** Fetch the sealed claim, verify proof-of-possession, enrol the member (rotates keys), prune
   *  the invite, and delete the server record. Returns the new member slot. */
  public CompletableFuture<Map<String, Object>> finalizeInvite(String inviteId) {
    Map<String, Object> pending = getPendingInvite(inviteId);
    if (pending == null) throw new CodedException("No pending invite for this inviteId", "NO_PENDING_INVITE");
    byte[] inviteSecret = Helpers.fromBase64((String) pending.get("inviteSecret"));
    String role = (String) pending.get("role");
    return invokeAuthed("GET", "/api/auth/invite/" + inviteId, null)
        .thenCompose(
            resp -> {
              Map<String, Object> got = resp.ok() ? resp.jsonObject() : null;
              if (got == null || !Boolean.TRUE.equals(got.get("ok"))) {
                throw new CodedException("invite fetch failed: " + resp.status, "INVITE_FETCH_FAILED");
              }
              if (!"claimed".equals(got.get("status")) || got.get("sealed") == null) {
                throw new CodedException("Invite not yet claimed", "INVITE_NOT_CLAIMED");
              }
              Invites.OpenedClaim opened =
                  Invites.openClaim(Invites.deriveChannelKey(inviteSecret), (String) got.get("sealed"));
              if (!opened.verified) throw new CodedException("Invite proof-of-possession failed", "INVITE_POP_FAILED");
              if (!inviteId.equals(opened.payload.get("inviteId"))) {
                throw new CodedException("Invite id mismatch in claim", "INVITE_ID_MISMATCH");
              }
              return addMemberByPublicKeys(
                  (String) opened.payload.get("kemPub"),
                  (String) opened.payload.get("dsaPub"),
                  (String) opened.payload.get("requestedName"),
                  role,
                  null);
            })
        .thenCompose(slot -> removePendingInvite(inviteId).thenApply(x -> slot))
        .thenCompose(
            slot ->
                invokeAuthed("DELETE", "/api/auth/invite/" + inviteId, null).exceptionally(e -> null).thenApply(x -> slot));
  }

  /** Cancel a pending invite: prune it from the manager area and delete the server record. */
  public CompletableFuture<Void> cancelInvite(String inviteId) {
    return removePendingInvite(inviteId)
        .thenCompose(x -> invokeAuthed("DELETE", "/api/auth/invite/" + inviteId, null))
        .thenAccept(
            resp -> {
              if (!resp.ok()) throw new CodedException("cancelInvite failed: " + resp.status, "INVITE_CANCEL_FAILED");
            });
  }

  // ── accessors ──
  public String getId() {
    return (String) ((Map<?, ?>) vaultManifest.get("payload")).get("id");
  }

  public String getAuthToken() {
    return authToken;
  }

  public String getEtag() {
    return etag;
  }

  public int getManifestVersion() {
    return manifestVersion;
  }

  public boolean isManagerMember() {
    return isManagerMember;
  }

  public Map<String, Object> getManifest() {
    return vaultManifest;
  }

  public byte[] getVaultKey() {
    return aeadVaultKey;
  }

  public byte[] getCollectionsKey() {
    return collectionsKey;
  }

  public List<Map<String, Object>> getMemberList() {
    return memberList;
  }

  /** Headers required by the authenticated routes ({@code x-vault-id} / {@code x-member-id}). */
  public Map<String, String> authedHeaders() {
    Map<String, String> h = new java.util.HashMap<>();
    h.put("x-vault-id", getId());
    h.put("x-member-id", activeMember.memberId);
    return h;
  }

  public String getMemberId() {
    return activeMember.memberId;
  }

  private static int intOr(Object v, int dflt) {
    return v instanceof Number ? ((Number) v).intValue() : dflt;
  }
}
