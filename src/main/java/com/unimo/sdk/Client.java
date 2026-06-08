package com.unimo.sdk;

import com.unimo.sdk.client.Account;
import com.unimo.sdk.client.ApiClient;
import com.unimo.sdk.client.Invites;
import com.unimo.sdk.client.Members;
import com.unimo.sdk.client.Members.MemberCredentials;
import com.unimo.sdk.client.Members.MemberInfoBasics;
import com.unimo.sdk.client.VaultController;
import com.unimo.sdk.crypto.AEAD;
import com.unimo.sdk.crypto.CodedException;
import com.unimo.sdk.crypto.CryptoPQ;
import com.unimo.sdk.crypto.CryptoUtils;
import com.unimo.sdk.shared.Consts;
import com.unimo.sdk.shared.Helpers;
import com.unimo.sdk.shared.Json;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Port of {@code sdk/ts/src_ts/Client.ts} (the {@code LatticeStoreClient} entry point) — Phase 2
 * surface: {@code register} and {@code login}. The browser security-context probe is dropped
 * (Android N/A). {@code login} returns a {@link VaultController}; the full {@code Account}
 * wrapper (Tasker / Connection / Billing) arrives in later phases.
 */
public final class Client {
  private final String serviceUrl;

  public Client(String serviceUrl) {
    this.serviceUrl = serviceUrl;
  }

  /** Outcome of {@link #register}: the two provisioned devices + their recoverable seeds. */
  public static final class RegisterResult {
    public final boolean ok;
    public final MemberCredentials deviceCredentials;
    public final MemberCredentials recoveryDeviceCredentials;
    public final byte[] recoverySeed;
    public final byte[] thisDeviceSeed;

    RegisterResult(
        boolean ok,
        MemberCredentials deviceCredentials,
        MemberCredentials recoveryDeviceCredentials,
        byte[] recoverySeed,
        byte[] thisDeviceSeed) {
      this.ok = ok;
      this.deviceCredentials = deviceCredentials;
      this.recoveryDeviceCredentials = recoveryDeviceCredentials;
      this.recoverySeed = recoverySeed;
      this.thisDeviceSeed = thisDeviceSeed;
    }
  }

  /**
   * Provision a new account: an active ADMIN device + an OWNER recovery device (both wrapping the
   * same fresh master key), an account identity keypair (the vaultId), and a manager-only area
   * holding the account seed. The manifest is signed by the recovery (OWNER) device.
   */
  public CompletableFuture<RegisterResult> register(String accountName, String deviceName, byte[] deviceSeed) {
    byte[] thisDeviceSeed = deviceSeed != null ? deviceSeed : CryptoUtils.generateRandomBytes(Consts.DEFAULT_SEED_LENGTH_BYTES);
    byte[] recoverySeed = CryptoUtils.generateRandomBytes(Consts.DEFAULT_SEED_LENGTH_BYTES);
    byte[] masterKey = AEAD.generateRawAEADKeyData();

    MemberCredentials thisDevice = Members.createNewCredentials(deviceName.trim(), Consts.ROLE_ADMIN, masterKey, thisDeviceSeed);
    MemberCredentials recovery = Members.createNewCredentials(Consts.RECOVERY_DEVICE_NAME, Consts.ROLE_OWNER, masterKey, recoverySeed);

    byte[] accountSeed = CryptoUtils.generateRandomBytes(Consts.DEFAULT_SEED_LENGTH_BYTES);
    MemberInfoBasics accountMember = Members.buildMember(accountSeed);

    byte[] managersKey = Members.getManagerKey(masterKey);
    Arrays.fill(masterKey, (byte) 0);

    Map<String, Object> managerArea =
        Json.obj(
            "v", Consts.MANAGER_AREA_VERSION,
            "accountSeed", Helpers.base64(accountMember.memberSeed),
            "invites", Json.arr());
    String encryptedManagerArea = Helpers.base64(AEAD.encrypt(managersKey, Helpers.utf8(Json.canonical(managerArea))));
    String encryptedMemberList =
        Members.encryptMemberList(
            Json.arr(thisDevice.memberEncryptedDetail, recovery.memberEncryptedDetail), managersKey);

    String timestamp = Helpers.isoNow();
    Map<String, Object> payload =
        Json.obj(
            "version", 1,
            "name", accountName.trim(),
            "type", Consts.VAULT_TYPE_ACCOUNT,
            "id", accountMember.memberId,
            "dsaPubkey", Helpers.base64(accountMember.dsaKeys.publicKey),
            "kemPubkey", Helpers.base64(accountMember.kemKeys.publicKey),
            "memberSlots", Json.arr(thisDevice.memberSlot, recovery.memberSlot),
            "managerOnlyMemberList", encryptedMemberList,
            "managerOnlyArea", encryptedManagerArea,
            "keyEpoch", 0,
            "createdAt", timestamp,
            "updatedAt", timestamp);

    byte[] payloadSha = CryptoUtils.sha256(Helpers.utf8(Json.canonical(payload)));
    Map<String, Object> body =
        Json.obj(
            "payload", payload,
            "payloadHash", Helpers.base64(payloadSha),
            "signerId", recovery.secrets.memberId,
            "signature", Helpers.base64(CryptoPQ.sign(recovery.secrets.dsaKeys.secretKey, payloadSha)));

    return ApiClient.makeRequest("POST", serviceUrl + "/api/auth/register", body)
        .thenApply(
            resp -> {
              if (!Boolean.TRUE.equals(resp.get("ok"))) {
                throw new CodedException(String.valueOf(resp.getOrDefault("message", "Registration failed")), "REGISTER_FAILED");
              }
              return new RegisterResult(true, thisDevice, recovery, recoverySeed, thisDeviceSeed);
            });
  }

  /** Authenticate with a device seed; returns an unlocked {@link VaultController}. */
  public CompletableFuture<VaultController> login(String accountName, byte[] deviceSeed) {
    return VaultController.init(serviceUrl, accountName, Members.buildMember(deviceSeed));
  }

  /** Like {@link #login} but returns an {@link Account} (Tasker + Billing + optional live WS). */
  public CompletableFuture<Account> loginAccount(String accountName, byte[] deviceSeed, boolean keepAlive) {
    return login(accountName, deviceSeed).thenApply(vc -> new Account(serviceUrl, vc, keepAlive));
  }

  /** Outcome of {@link #claimInvite}: the granted account/role + the device seed to log in with
   *  once a manager finalizes. */
  public static final class InviteClaim {
    public final String accountName;
    public final String role;
    public final byte[] deviceSeed;

    InviteClaim(String accountName, String role, byte[] deviceSeed) {
      this.accountName = accountName;
      this.role = role;
      this.deviceSeed = deviceSeed;
    }
  }

  /** Claim an invite as a new device (pre-auth): derive the channel from the in-person code, seal
   *  a proof-of-possession claim for a manager to finalize, and return the granted account/role. */
  public CompletableFuture<InviteClaim> claimInvite(String code, String requestedName, byte[] deviceSeed) {
    byte[] secret = Invites.decodeInviteCode(code);
    String inviteId = Invites.deriveInviteId(secret);
    byte[] channelKey = Invites.deriveChannelKey(secret);
    byte[] seed = deviceSeed != null ? deviceSeed : CryptoUtils.generateRandomBytes(Consts.DEFAULT_SEED_LENGTH_BYTES);
    MemberInfoBasics member = Members.buildMember(seed);
    Map<String, Object> payload =
        Json.obj(
            "inviteId", inviteId,
            "kemPub", Helpers.base64(member.kemKeys.publicKey),
            "dsaPub", Helpers.base64(member.dsaKeys.publicKey),
            "requestedName", requestedName.trim(),
            "timestamp", Helpers.now());
    String sealed = Invites.sealClaim(channelKey, payload, member.dsaKeys);
    return ApiClient.makeRequest(
            "POST", serviceUrl + "/api/auth/invite/" + inviteId + "/claim", Json.obj("sealed", sealed))
        .thenApply(
            res -> {
              if (!Boolean.TRUE.equals(res.get("ok"))) {
                throw new CodedException(String.valueOf(res.getOrDefault("message", "claimInvite failed")), "INVITE_CLAIM_FAILED");
              }
              if (res.get("accountName") == null || res.get("role") == null) {
                throw new CodedException("claimInvite: malformed server response", "INVITE_CLAIM_FAILED");
              }
              return new InviteClaim((String) res.get("accountName"), (String) res.get("role"), seed);
            });
  }
}
