package com.unimo.sdk.client;

import com.unimo.sdk.crypto.AEAD;
import com.unimo.sdk.crypto.CryptoPQ;
import com.unimo.sdk.crypto.CryptoUtils;
import com.unimo.sdk.shared.Consts;
import com.unimo.sdk.shared.Helpers;
import com.unimo.sdk.shared.Json;
import java.util.List;
import java.util.Map;

/**
 * Port of {@code sdk/ts/src_ts/client/Members.ts}. Builds a member's identity (KEM+DSA from a
 * seed), the public {@code memberSlot} + manager-only {@code memberEncryptedDetail}, and the
 * manager-only blob crypto. Member slots/details are modeled as ordered JSON maps (faithful to
 * the TS plain objects and friendly to canonical signing).
 *
 * <p>Note on key handling: where the TS returns WebCrypto {@code AEADCryptoKey} handles, this
 * port uses raw 32-byte AES keys directly with {@link AEAD} — semantically identical.
 */
public final class Members {
  private Members() {}

  /** Deterministic identity derived from a 32-byte device/account seed. */
  public static final class MemberInfoBasics {
    public final String memberId;
    public final byte[] memberSeed;
    public final CryptoPQ.DsaKeyPair dsaKeys;
    public final CryptoPQ.KemKeyPair kemKeys;

    MemberInfoBasics(String memberId, byte[] memberSeed, CryptoPQ.DsaKeyPair dsaKeys, CryptoPQ.KemKeyPair kemKeys) {
      this.memberId = memberId;
      this.memberSeed = memberSeed;
      this.dsaKeys = dsaKeys;
      this.kemKeys = kemKeys;
    }
  }

  /** Private key material for a freshly provisioned member (never leaves the client). */
  public static final class MemberSecrets {
    public final String memberId;
    public final CryptoPQ.KemKeyPair kemKeys;
    public final CryptoPQ.DsaKeyPair dsaKeys;

    MemberSecrets(String memberId, CryptoPQ.KemKeyPair kemKeys, CryptoPQ.DsaKeyPair dsaKeys) {
      this.memberId = memberId;
      this.kemKeys = kemKeys;
      this.dsaKeys = dsaKeys;
    }
  }

  /** Public slot (goes in the manifest) + manager-only detail + secrets, for one new member. */
  public static final class MemberCredentials {
    public final Map<String, Object> memberSlot;
    public final Map<String, Object> memberEncryptedDetail;
    public final MemberSecrets secrets;

    MemberCredentials(Map<String, Object> memberSlot, Map<String, Object> memberEncryptedDetail, MemberSecrets secrets) {
      this.memberSlot = memberSlot;
      this.memberEncryptedDetail = memberEncryptedDetail;
      this.secrets = secrets;
    }
  }

  public static MemberInfoBasics buildMember(byte[] seed) {
    CryptoUtils.Seeds s = CryptoUtils.deriveSeeds(seed);
    CryptoPQ.KemKeyPair kem = CryptoPQ.generateKemKeys(s.kemSeed);
    CryptoPQ.DsaKeyPair dsa = CryptoPQ.generateDsaKeys(s.dsaSeed);
    return new MemberInfoBasics(CryptoUtils.getMemberIdFromPubkey(dsa.publicKey), seed, dsa, kem);
  }

  /**
   * Provision a new member: encapsulate to its own fresh KEM key, wrap the role-appropriate
   * vault key under the KEM shared secret, and derive its memberId from the DSA public key.
   */
  public static MemberCredentials createNewCredentials(String name, String role, byte[] rootKey, byte[] initSeed) {
    CryptoUtils.Seeds s = CryptoUtils.deriveSeeds(initSeed);
    CryptoPQ.KemKeyPair kem = CryptoPQ.generateKemKeys(s.kemSeed);
    CryptoPQ.Encapsulated enc = CryptoPQ.encapsulate(kem.publicKey);
    byte[] wrapped = AEAD.encrypt(enc.sharedSecret, CryptoUtils.deriveKeyForRole(role, rootKey));
    CryptoPQ.DsaKeyPair dsa = CryptoPQ.generateDsaKeys(s.dsaSeed);
    String memberId = CryptoUtils.getMemberIdFromPubkey(dsa.publicKey);
    long ts = System.currentTimeMillis();

    Map<String, Object> slot =
        Json.obj(
            "memberId", memberId,
            "memberRole", role,
            "memberStatus", Consts.STATUS_ACTIVE,
            "memberKemCiphertext", Helpers.base64(enc.cipherText),
            "memberVaultKeyWrapped", Helpers.base64(wrapped),
            "memberDsaPubkey", Helpers.base64(dsa.publicKey),
            "createdAt", ts,
            "updatedAt", ts);
    Map<String, Object> detail =
        Json.obj(
            "memberId", memberId,
            "memberName", name,
            "memberKemPubkey", Helpers.base64(kem.publicKey),
            "memberAddedBy", memberId,
            "memberAddedAt", ts);
    return new MemberCredentials(slot, detail, new MemberSecrets(memberId, kem, dsa));
  }

  /** Manager root key for the manager-only area + member list (cSHAKE of the master key). */
  public static byte[] getManagerKey(byte[] masterKeyRaw) {
    return CryptoUtils.cShake256(masterKeyRaw, Consts.CUSTOM_MANAGER_KEY_STRING, Consts.DEFAULT_AEAD_KEY_LENGTH_BYTES);
  }

  /** Collections-list key (cSHAKE of the master key). */
  public static byte[] getCollectionsKey(byte[] masterKeyRaw) {
    return CryptoUtils.cShake256(
        masterKeyRaw, Consts.CUSTOM_COLLECTION_LIST_STRING, Consts.DEFAULT_AEAD_KEY_LENGTH_BYTES);
  }

  /** Encrypt the manager-only member-detail list under the manager key → base64.
   *  Serialization order is irrelevant: the blob is opaque and parsed (not hashed) on decrypt. */
  public static String encryptMemberList(List<?> memberDetails, byte[] managersKey) {
    return Helpers.base64(AEAD.encrypt(managersKey, Helpers.utf8(Json.canonical(memberDetails))));
  }

  @SuppressWarnings("unchecked")
  public static List<Map<String, Object>> decryptMemberList(String encryptedB64, byte[] managersKey) {
    byte[] plain = AEAD.decrypt(managersKey, Helpers.fromBase64(encryptedB64));
    return (List<Map<String, Object>>) (Object) Json.parse(Helpers.fromUtf8(plain));
  }
}
