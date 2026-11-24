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
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.Predicate;
import java.util.function.Supplier;

/**
 * Port of {@code sdk/ts/src_ts/client/Vault.ts}: login, the held manifest and what this member's
 * keys open in it, manifest updates (members, collections, invites) and reauth.
 *
 * <p>Threads (Java only; the TS original has one). Two things keep the held manifest whole:
 *
 * <ol>
 *   <li>turns ({@link #exclusive}): updates and refreshes of the manifest run one at a time.
 *   <li>{@link #lock}: a turn moves the manifest, the keys and the collections list under it, and a
 *       reader outside a turn (a pending invite looked up, logout) takes it, so it never sees a
 *       manifest next to keys that do not open it. Never held across a network call.
 * </ol>
 */
public final class VaultController {
  /** How often an update is applied again on top of a manifest another device committed first. */
  private static final int MANIFEST_CAS_RETRIES = 3;

  private final String serviceUrl;
  private final String vaultId;
  private final MemberInfoBasics activeMember;
  private volatile String authToken;

  private final Object lock = new Object();
  private volatile Map<String, Object> vaultManifest;
  private volatile int manifestVersion;
  private volatile String etag;
  private volatile byte[] aeadVaultKey;
  private volatile boolean isManagerMember;
  private volatile byte[] managersKey;
  private volatile byte[] collectionsKey;
  private volatile List<Map<String, Object>> memberList;
  /** The last turn: the next one starts when it has ended. */
  private final AtomicReference<CompletableFuture<Void>> manifestTurn =
      new AtomicReference<>(CompletableFuture.completedFuture(null));
  /** Collections being created: their first blob is on its way and no manifest lists them yet, but
   *  their names are taken. Logout empties it, which abandons them. */
  private final Set<CollectionController> pendingCollections = ConcurrentHashMap.newKeySet();
  /** Serializes {@link #reauth()} dispatch so concurrent 401s share one POST and one token. */
  private final Object reauthLock = new Object();
  /** Non-null while a reauth is in flight; {@link #reauth()} joins it instead of re-dispatching. */
  private CompletableFuture<ReauthOutcome> inFlightReauth;
  /** Fired once when a reauth comes back {@link ReauthOutcome#REVOKED}: a manager removed this
   *  device. Wired by {@link Account}. */
  volatile Runnable onRevoked;
  /** Run when an update here had to take in a manifest another device committed first. Nothing else
   *  announces that one: its frame finds the version already held. Wired by {@link Tasker#hookVault}. */
  volatile Runnable onAdopted;

  /** Observable list of this vault's collections (decrypted from the manifest at unlock). Listeners
   *  run inside the update that changed the list: they must not wait for another update of this vault. */
  public final ReactiveValue<List<CollectionController>> collections = new ReactiveValue<>(new ArrayList<>());

  private VaultController(
      String serviceUrl, String vaultId, String etag, String authToken, MemberInfoBasics activeMember) {
    this.serviceUrl = serviceUrl;
    this.vaultId = vaultId;
    this.etag = etag;
    this.authToken = authToken;
    this.activeMember = activeMember;
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
                      (String) payload.get("id"),
                      (String) resp.get("vaultEtag"),
                      (String) resp.get("authToken"),
                      member);
              vc.hold(new ManifestResult(manifest, intOr(resp.get("manifestVersion"), 1)));
              return vc;
            });
  }

  /** A manifest and the version the server has it under. */
  private static final class ManifestResult {
    final Map<String, Object> vault;
    final int version;

    ManifestResult(Map<String, Object> vault, int version) {
      this.vault = vault;
      this.version = version;
    }
  }

  /**
   * Make {@code confirmed} the manifest held: this member's keys are unwrapped from its slot, and the
   * member and collections lists are read with them. Everything is derived first and the vault moves
   * in the block at the end, which cannot fail part-way: a manifest this device cannot open leaves
   * the vault as it was.
   */
  @SuppressWarnings("unchecked")
  private void hold(ManifestResult confirmed) {
    Map<String, Object> payload = payloadOf(confirmed.vault);
    Map<String, Object> slot =
        Validators.getMemberFromMemberSlots((List<Object>) payload.get("memberSlots"), activeMember.memberId);
    if (slot == null) throw new CodedException("Active member slot not found in manifest", "NO_MEMBER_SLOT");

    byte[] shared =
        CryptoPQ.decapsulate(activeMember.kemKeys, Helpers.fromBase64((String) slot.get("memberKemCiphertext")));
    byte[] roleKey = AEAD.decrypt(shared, Helpers.fromBase64((String) slot.get("memberVaultKeyWrapped")));
    boolean isManager = Consts.isManagerRole((String) slot.get("memberRole"));
    byte[] managerKey = isManager ? Members.getManagerKey(roleKey) : null;
    List<Map<String, Object>> members =
        isManager
            ? Members.decryptMemberList((String) payload.get("managerOnlyMemberList"), managerKey)
            : Collections.emptyList();
    byte[] listKey = isManager ? Members.getCollectionsKey(roleKey) : roleKey;
    List<CollectionController> listed = decryptCollectionsList(payload, listKey);

    synchronized (lock) {
      this.vaultManifest = confirmed.vault;
      this.manifestVersion = confirmed.version;
      this.aeadVaultKey = roleKey;
      this.isManagerMember = isManager;
      this.managersKey = managerKey;
      this.memberList = members;
      this.collectionsKey = listKey;
      mergeCollections(listed);
    }
  }

  // ── manifest updates (PUT /api/auth/manifest), one at a time ──

  /**
   * Everything that changes or replaces the held manifest takes its turn here. An update reads the
   * manifest, changes it and puts it, and on failure goes back to the one it started from: that only
   * holds while nothing else moves the manifest in between.
   *
   * <p>The returned future completes inside the turn, before the next one starts, so what a caller
   * chains on it sees the vault as its own update left it. That code must not wait for another turn
   * of this vault. Cancelling the future does not end the turn.
   */
  private <T> CompletableFuture<T> exclusive(Supplier<CompletableFuture<T>> task) {
    CompletableFuture<T> result = new CompletableFuture<>();
    CompletableFuture<Void> ended = new CompletableFuture<>();
    manifestTurn
        .getAndSet(ended)
        .thenCompose(free -> task.get())
        .whenComplete(
            (value, failure) -> {
              if (failure == null) result.complete(value);
              else result.completeExceptionally(failure);
              ended.complete(null);
            });
    return result;
  }

  /** Apply {@code change} to the held manifest and put it: see {@link #applyAndPut}. */
  private CompletableFuture<Void> saveUpdate(BooleanSupplier change) {
    return exclusive(() -> applyAndPut(change, 0));
  }

  /**
   * Apply a change to the held manifest and put it. A change that finds the manifest already says
   * what it wants returns false, and nothing is sent. When the server's manifest turns out to be
   * ahead of the one changed, the change is applied again on top of that one, so it must be written
   * to run more than once. Whatever fails (the change itself, the request, a refusal that stands),
   * the vault is left on the manifest the server last confirmed: a failed update neither blocks the
   * next one nor rides along with it.
   */
  private CompletableFuture<Void> applyAndPut(BooleanSupplier change, int attempt) {
    ManifestResult confirmed = heldCopy();
    return CompletableFuture.completedFuture(null) // a change that throws fails the future like anything after it
        .thenCompose(start -> applied(change) ? put(confirmed, attempt) : CompletableFuture.completedFuture(true))
        .whenComplete(
            (taken, failure) -> {
              if (failure != null) hold(confirmed);
            })
        .thenCompose(
            taken -> taken ? CompletableFuture.<Void>completedFuture(null) : applyAndPut(change, attempt + 1));
  }

  /** What is held, out of reach of a change. */
  private ManifestResult heldCopy() {
    Map<String, Object> copy = new HashMap<>(vaultManifest);
    copy.put("payload", Json.parseObject(Json.canonical(payload())));
    return new ManifestResult(copy, manifestVersion);
  }

  private boolean applied(BooleanSupplier change) {
    synchronized (lock) {
      return change.getAsBoolean();
    }
  }

  /**
   * Sign and put the held manifest, which was changed from {@code base}. True when the server took
   * it. False when the server's manifest was ahead of {@code base}: that one is held now, for the
   * change to be applied again. Every refusal is checked for that, not only a version mismatch: a
   * gateway that was busy with another update answers 503, and one from before it compared versions
   * first tells a device one key rotation behind that its key epoch is too low. A refusal from a
   * server that is not ahead stands.
   */
  private CompletableFuture<Boolean> put(ManifestResult base, int attempt) {
    return signAndPut()
        .thenCompose(
            answer -> {
              if (Boolean.TRUE.equals(answer.get("ok"))) {
                synchronized (lock) {
                  manifestVersion = ((Number) answer.get("version")).intValue();
                  etag = (String) answer.get("etag");
                }
                return CompletableFuture.completedFuture(true);
              }
              CodedException refused =
                  new CodedException(
                      "Manifest update failed: " + answer.get("statusCode") + " " + answer.get("message"),
                      "MANIFEST_UPDATE_FAILED");
              if (attempt >= MANIFEST_CAS_RETRIES) throw refused;
              return fetchLatestManifest(keyEpoch(payloadOf(base.vault)))
                  .handle(
                      (latest, unreachable) -> {
                        if (unreachable != null || latest.version <= base.version) throw refused;
                        hold(latest);
                        Runnable announce = onAdopted;
                        if (announce != null) announce.run();
                        return false;
                      });
            });
  }

  private CompletableFuture<Map<String, Object>> signAndPut() {
    Map<String, Object> payload = payload();
    synchronized (lock) {
      payload.put("updatedAt", Helpers.isoNow());
    }
    byte[] hash = CryptoUtils.sha256(Helpers.utf8(Json.canonical(payload)));
    Map<String, Object> body =
        Json.obj(
            "prevVersion", manifestVersion,
            "payload", payload,
            "payloadHash", Helpers.base64(hash),
            "signerId", activeMember.memberId,
            "signature", Helpers.base64(CryptoPQ.sign(activeMember.dsaKeys.secretKey, hash)));
    // Tokens expire while the app stays open: on 401 the token is refreshed and the same signed manifest sent once more.
    String url = serviceUrl + "/api/auth/manifest";
    return Tasker.withReauth(
            () -> ApiClient.authRequest("PUT", url, authToken, body, authedHeaders()), this::handleAuthError)
        .thenApply(ApiClient.ApiResponse::jsonObject);
  }

  // ── manifest refresh (GET /api/auth/manifest) + reauth ──

  /** The server's manifest. Fails unless it is valid, of this vault, and not below {@code floorEpoch}
   *  (see {@link #rollbackCheckedEpoch}). */
  @SuppressWarnings("unchecked")
  private CompletableFuture<ManifestResult> fetchLatestManifest(long floorEpoch) {
    String url = serviceUrl + "/api/auth/manifest";
    return Tasker.withReauth(
            () -> ApiClient.authRequest("GET", url, authToken, null, authedHeaders()), this::handleAuthError)
        .thenApply(
            resp -> {
              Map<String, Object> body = resp.ok() ? resp.jsonObject() : null;
              if (body == null || !Boolean.TRUE.equals(body.get("ok"))) {
                throw new CodedException("Manifest fetch failed: " + resp.status, "MANIFEST_FETCH_FAILED");
              }
              Map<String, Object> vault = (Map<String, Object>) body.get("accountVault");
              if (!Validators.isValidVaultManifest(vault, Consts.VAULT_TYPE_ACCOUNT)
                  || !vaultId.equals(payloadOf(vault).get("id"))) {
                throw new CodedException("Invalid vault manifest received from server", "INVALID_MANIFEST");
              }
              rollbackCheckedEpoch(floorEpoch, payloadOf(vault));
              return new ManifestResult(vault, intOr(body.get("version"), 1));
            });
  }

  /**
   * Refresh local state from the server. True when the server's manifest was newer than the one held
   * when this refresh got its turn: an update of this device that was on its way when the refresh was
   * asked for is not reported as a change from elsewhere. Fails when no manifest this device can hold
   * came back.
   */
  public CompletableFuture<Boolean> timeToFetchUpdate() {
    return exclusive(
        () ->
            fetchLatestManifest(keyEpoch(payload()))
                .thenApply(
                    latest -> {
                      boolean newer = latest.version != manifestVersion;
                      hold(latest);
                      return newer;
                    }));
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
      // that with a non-empty String, and require String so the (String) cast in dispatchReauth can't throw
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
      CompletableFuture<ReauthOutcome> started;
      try {
        started = dispatchReauth();
      } catch (RuntimeException e) {
        // a sync throw (sign/sha256 preamble, send()'s sync part) must still yield a future, or
        // Connection's reconnect .whenComplete never attaches and the WebSocket stalls silently
        started = CompletableFuture.completedFuture(ReauthOutcome.TRANSIENT);
      }
      final CompletableFuture<ReauthOutcome> f = started;
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

  private CompletableFuture<ReauthOutcome> dispatchReauth() {
    long nowTime = System.currentTimeMillis();
    Map<String, Object> payload =
        Json.obj(
            "memberId", activeMember.memberId,
            "vaultId", getId(),
            "timestamp", nowTime,
            "reqId", UUID.randomUUID().toString());
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
   *  every member slot under its KEM public key. Everything is computed first, and the vault moves to
   *  the new key in the block at the end, which cannot fail part-way: a failure before it (a member
   *  whose KEM key cannot be used) leaves the vault exactly as it was. */
  private void rotateAndRewrapForMembers(List<Object> newSlots, List<Map<String, Object>> newDetails) {
    if (!isManagerMember || managersKey == null) {
      throw new CodedException("Only manager members can rotate vault keys", "NOT_MANAGER");
    }
    byte[] newVaultKey = AEAD.generateRawAEADKeyData();
    byte[] newManagerKey = Members.getManagerKey(newVaultKey);
    byte[] newCollectionsKey = Members.getCollectionsKey(newVaultKey);
    Map<String, Object> payload = payload();
    long newEpoch = keyEpoch(payload) + 1;

    // The manager-only area moves under the new managersKey: the rotation would otherwise orphan it
    // under the discarded one.
    Object managerOnlyArea = payload.get("managerOnlyArea");
    if (managerOnlyArea instanceof String && !((String) managerOnlyArea).isEmpty()) {
      byte[] areaPlain = AEAD.decrypt(managersKey, Helpers.fromBase64((String) managerOnlyArea));
      managerOnlyArea = Helpers.base64(AEAD.encrypt(newManagerKey, areaPlain));
    }

    List<Object> rewrappedSlots = new ArrayList<>();
    for (Object so : newSlots) {
      @SuppressWarnings("unchecked")
      Map<String, Object> slot = new HashMap<>((Map<String, Object>) so); // a copy: the held slot stays as it is
      Map<String, Object> detail = Validators.getMemberFromMemberSlots(newDetails, slot.get("memberId"));
      if (detail == null) throw new CodedException("Missing detail for " + slot.get("memberId"), "MISSING_DETAIL");
      CryptoPQ.Encapsulated enc = CryptoPQ.encapsulate(Helpers.fromBase64((String) detail.get("memberKemPubkey")));
      byte[] roleKey = CryptoUtils.deriveKeyForRole((String) slot.get("memberRole"), newVaultKey);
      byte[] wrapped = AEAD.encrypt(enc.sharedSecret, roleKey);
      if (roleKey != newVaultKey) Arrays.fill(roleKey, (byte) 0); // never zero the shared master-key reference
      Arrays.fill(enc.sharedSecret, (byte) 0);
      slot.put("memberKemCiphertext", Helpers.base64(enc.cipherText));
      slot.put("memberVaultKeyWrapped", Helpers.base64(wrapped));
      slot.put("updatedAt", System.currentTimeMillis());
      rewrappedSlots.add(slot);
    }
    String managerOnlyMemberList = Members.encryptMemberList(newDetails, newManagerKey);
    String collectionsEncrypted = encryptCollectionsList(newCollectionsKey); // re-key the real list

    // The move to the new key: nothing from here on can fail.
    if (managerOnlyArea != null) payload.put("managerOnlyArea", managerOnlyArea);
    payload.put("managerOnlyMemberList", managerOnlyMemberList);
    payload.put("collectionsEncrypted", collectionsEncrypted);
    payload.put("memberSlots", rewrappedSlots);
    payload.put("keyEpoch", newEpoch);
    // newVaultKey is retained as aeadVaultKey (not zeroed): unlike the TS WebCrypto path that
    // imports a copy then wipes the raw, this port uses the raw bytes directly as the key.
    this.aeadVaultKey = newVaultKey;
    this.managersKey = newManagerKey;
    this.collectionsKey = newCollectionsKey;
    this.memberList = newDetails;
  }

  /** Add a member by its KEM+DSA public keys (rotates keys, re-wraps for all, PUTs the manifest).
   *  A member the manifest already lists is left as it is and its slot returned: adding it again,
   *  after a retry or because another manager was first, would list it twice. */
  public CompletableFuture<Map<String, Object>> addMemberByPublicKeys(
      String kemPubkeyB64, String dsaPubkeyB64, String memberName, String memberRole, String privateNote) {
    if (!isManagerMember || managersKey == null) {
      throw new CodedException("Only manager members can add members", "NOT_MANAGER");
    }
    if (!Validators.validateDeviceName(memberName)) {
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

    return saveUpdate(
            () -> {
              if (Validators.getMemberFromMemberSlots(slots(), memberId) != null) return false;
              List<Object> newSlots = new ArrayList<>(slots());
              newSlots.add(newSlot);
              List<Map<String, Object>> newDetails = new ArrayList<>(memberList);
              newDetails.add(newDetail);
              rotateAndRewrapForMembers(newSlots, newDetails);
              return true;
            })
        .thenApply(x -> Validators.getMemberFromMemberSlots(slots(), memberId));
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
    return saveUpdate(
            () -> {
              if (Validators.getMemberFromMemberSlots(slots(), memberId) == null) {
                throw new CodedException("Member not found", "MEMBER_NOT_FOUND");
              }
              List<Object> newSlots = new ArrayList<>();
              for (Object s : slots()) if (!memberId.equals(((Map<?, ?>) s).get("memberId"))) newSlots.add(s);
              List<Map<String, Object>> newDetails = new ArrayList<>();
              for (Map<String, Object> d : memberList) if (!memberId.equals(d.get("memberId"))) newDetails.add(d);
              rotateAndRewrapForMembers(newSlots, newDetails);
              return true;
            })
        .thenApply(x -> true);
  }

  // ── collections ──

  /** The collections {@code payload} lists, read with {@code key}. */
  @SuppressWarnings("unchecked")
  private List<CollectionController> decryptCollectionsList(Map<String, Object> payload, byte[] key) {
    Object enc = payload.get("collectionsEncrypted");
    if (!(enc instanceof String) || ((String) enc).isEmpty() || key == null) return new ArrayList<>();
    byte[] plain = AEAD.decrypt(key, Helpers.fromBase64((String) enc));
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

  /**
   * The collections the held manifest lists. A controller already handed out is kept, its tasker and
   * loaded content with it, under the name the manifest gives it. One the manifest no longer lists is
   * disposed, unless it is still being created. Called with {@link #lock} held.
   */
  private void mergeCollections(List<CollectionController> listed) {
    Map<String, CollectionController> unlisted = new HashMap<>();
    for (CollectionController c : collections.get()) unlisted.put(c.getId(), c);
    List<CollectionController> merged = new ArrayList<>();
    for (CollectionController fresh : listed) {
      CollectionController existing = unlisted.remove(fresh.getId());
      if (existing != null) existing.adoptName(fresh.getName());
      merged.add(existing != null ? existing : fresh);
    }
    collections.set(merged);
    for (CollectionController c : unlisted.values()) if (!pendingCollections.contains(c)) c.dispose();
  }

  public List<CollectionController> listCollections() {
    return collections.get();
  }

  /**
   * Create a KV collection: upload its initial blob (CAS first-write), then sign the manifest with
   * the updated collections list. Manager-only. Until the manifest lists it the collection is in
   * no list: a create that fails leaves nothing behind for a later update to commit.
   */
  public CompletableFuture<KVContent> createCollection(String name, String type, Tasker tasker) {
    if (!Validators.isValidCollectionName(name)) throw new CodedException("Invalid collection name", "INVALID_COLLECTION_NAME");
    if (!Validators.isValidCollectionType(type)) throw new CodedException("Invalid collection type", "INVALID_COLLECTION_TYPE");
    requireUnusedName(name, collections.get());
    requireUnusedName(name, pendingCollections);
    if (!isManagerMember || collectionsKey == null) {
      throw new CodedException("Only manager members can create collections", "NOT_MANAGER");
    }
    CollectionController col = CollectionController.createNew(name, type, this, activeMember.memberId);
    byte[] blob = col.serialize();
    pendingCollections.add(col);
    return tasker
        .upload(this, col.getId(), blob, col.getEncKey(), 0)
        .thenCompose(
            up -> {
              col.setInitialVersion(up.version);
              return saveUpdate(() -> list(col));
            })
        .whenComplete(
            (listed, failure) -> {
              pendingCollections.remove(col);
              // It was in the list while its manifest was on its way: whoever loaded it then must not keep saving it.
              if (failure != null) col.dispose();
            })
        .thenApply(
            listed -> {
              col.attachTasker(tasker, true);
              return col.content();
            });
  }

  /** The change that lists a created collection. The name is checked again: another device may have
   *  listed one of that name since the create began. */
  private boolean list(CollectionController col) {
    if (!pendingCollections.contains(col)) {
      throw new CodedException("Logged out while the collection was created", "CREATE_ABANDONED");
    }
    requireUnusedName(col.getName(), collections.get());
    // A new list, never an edit in place: other threads iterate the one they hold.
    List<CollectionController> grown = new ArrayList<>(collections.get());
    grown.add(col);
    collections.set(grown);
    encryptAndUpdateCollectionsList();
    return true;
  }

  private static void requireUnusedName(String name, Iterable<CollectionController> among) {
    for (CollectionController c : among) {
      if (name.trim().equals(c.getName())) throw new CodedException("Collection name must be unique", "DUPLICATE_COLLECTION");
    }
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
    return saveUpdate(
            () -> {
              CollectionController col = findCollection(colId);
              if (col == null) throw new CodedException("Collection not found", "COLLECTION_NOT_FOUND");
              col.setName(newName, activeMember.memberId);
              encryptAndUpdateCollectionsList();
              return true;
            })
        .thenApply(x -> true);
  }

  public CompletableFuture<Boolean> removeCollectionById(Tasker tasker, String colId) {
    if (!isManagerMember || collectionsKey == null) {
      throw new CodedException("Only manager members can remove collections", "NOT_MANAGER");
    }
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
            x ->
                saveUpdate(
                    () -> {
                      // Disposed only now that it is gone: a collection whose delete failed stays in the list and must still save.
                      List<CollectionController> kept = new ArrayList<>();
                      for (CollectionController c : collections.get()) {
                        if (colId.equals(c.getId())) c.dispose();
                        else kept.add(c);
                      }
                      if (kept.size() == collections.get().size()) return false; // not listed (any more)
                      collections.set(kept);
                      encryptAndUpdateCollectionsList();
                      return true;
                    }))
        .thenApply(x -> true);
  }

  private static boolean isAlreadyGone(Throwable err) {
    Throwable t = err instanceof CompletionException && err.getCause() != null ? err.getCause() : err;
    if (!(t instanceof CodedException)) return false;
    String code = ((CodedException) t).getCode();
    return "NOT_FOUND".equals(code) || "TRASHED".equals(code);
  }

  /**
   * The end of the collections this vault has handed out (see {@link CollectionController#dispose}):
   * none of them saves or pulls again. The vault itself stays usable: whoever asks next gets
   * collections loaded afresh.
   */
  public void disposeCollections() {
    List<CollectionController> ended;
    synchronized (lock) {
      pendingCollections.clear();
      ended = collections.get();
      collections.set(decryptCollectionsList(payload(), collectionsKey));
    }
    for (CollectionController c : ended) c.dispose();
  }

  private CollectionController findCollection(String colId) {
    for (CollectionController c : collections.get()) if (colId.equals(c.getId())) return c;
    return null;
  }

  private Map<String, Object> payload() {
    return payloadOf(vaultManifest);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> payloadOf(Map<String, Object> manifest) {
    return (Map<String, Object>) manifest.get("payload");
  }

  private static long keyEpoch(Map<String, Object> payload) {
    return ((Number) payload.get("keyEpoch")).longValue();
  }

  @SuppressWarnings("unchecked")
  private List<Object> slots() {
    return (List<Object>) payload().get("memberSlots");
  }

  // ── manager-only area + invites ──

  /** Bearer-authed request with a single 401→reauth→retry (shared by invites + billing). */
  public CompletableFuture<ApiClient.ApiResponse> invokeAuthed(String method, String path, Map<String, Object> body) {
    if (authToken == null) throw new CodedException("Not authenticated", "NOT_AUTHENTICATED");
    String url = serviceUrl + path;
    return Tasker.withReauth(
        () -> ApiClient.authRequest(method, url, authToken, body, authedHeaders()), this::handleAuthError);
  }

  private Map<String, Object> readManagerArea() {
    byte[] plain;
    synchronized (lock) {
      if (managersKey == null) throw new CodedException("Only manager members can access the manager area", "NOT_MANAGER");
      plain = AEAD.decrypt(managersKey, Helpers.fromBase64((String) payload().get("managerOnlyArea")));
    }
    Map<String, Object> area = Json.parseObject(Helpers.fromUtf8(plain));
    if (!(area.get("v") instanceof Number) || ((Number) area.get("v")).intValue() != Consts.MANAGER_AREA_VERSION) {
      throw new CodedException("Unsupported managerOnlyArea version", "BAD_AREA_VERSION");
    }
    return area;
  }

  /** Read the manager-only area, change it and put it. A change that leaves it as it was returns
   *  false, and nothing is sent. */
  private CompletableFuture<Void> updateManagerArea(Predicate<Map<String, Object>> change) {
    return saveUpdate(
        () -> {
          Map<String, Object> area = readManagerArea();
          if (!change.test(area)) return false;
          payload().put("managerOnlyArea", Helpers.base64(AEAD.encrypt(managersKey, Helpers.utf8(Json.canonical(area)))));
          return true;
        });
  }

  @SuppressWarnings("unchecked")
  private static List<Object> invitesOf(Map<String, Object> area) {
    return area.get("invites") instanceof List ? (List<Object>) area.get("invites") : new ArrayList<>();
  }

  @SuppressWarnings("unchecked")
  public CompletableFuture<Void> addPendingInvite(Map<String, Object> entry) {
    return updateManagerArea(
        area -> {
          long cutoff = System.currentTimeMillis() - Consts.INVITE_MAX_TTL_SECONDS * 1000;
          List<Object> next = new ArrayList<>();
          for (Object o : invitesOf(area)) {
            Map<String, Object> i = (Map<String, Object>) o;
            if (((Number) i.get("createdAt")).longValue() > cutoff) next.add(i);
          }
          next.add(entry);
          area.put("invites", next);
          return true;
        });
  }

  @SuppressWarnings("unchecked")
  public Map<String, Object> getPendingInvite(String inviteId) {
    for (Object o : invitesOf(readManagerArea())) {
      Map<String, Object> i = (Map<String, Object>) o;
      if (inviteId.equals(i.get("inviteId"))) return i;
    }
    return null;
  }

  /** Remove a consumed or cancelled invite. An invite that is not there: nothing is sent. */
  @SuppressWarnings("unchecked")
  public CompletableFuture<Void> removePendingInvite(String inviteId) {
    return updateManagerArea(
        area -> {
          List<Object> invites = invitesOf(area);
          List<Object> next = new ArrayList<>();
          for (Object o : invites) {
            Map<String, Object> i = (Map<String, Object>) o;
            if (!inviteId.equals(i.get("inviteId"))) next.add(i);
          }
          area.put("invites", next);
          return next.size() != invites.size();
        });
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
        Json.obj("inviteId", inviteId, "inviteSecret", Helpers.base64(secret), "role", role, "createdAt", System.currentTimeMillis());
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
    return vaultId;
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

  /** Headers required by the authenticated routes ({@code x-vault-id} / {@code x-member-id}), and
   *  the API version every gateway request states: the app sends these on requests it makes itself. */
  public Map<String, String> authedHeaders() {
    Map<String, String> h = new java.util.HashMap<>();
    h.put("x-vault-id", getId());
    h.put("x-member-id", activeMember.memberId);
    h.put(Consts.HEADER_API_VERSION, String.valueOf(Consts.API_VERSION));
    return h;
  }

  public String getMemberId() {
    return activeMember.memberId;
  }

  private static int intOr(Object v, int dflt) {
    return v instanceof Number ? ((Number) v).intValue() : dflt;
  }
}
