package com.unimo.sdk.crypto;

import com.unimo.sdk.shared.Consts;
import com.unimo.sdk.shared.Helpers;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;
import org.bouncycastle.crypto.digests.CSHAKEDigest;

/**
 * Port of {@code sdk/ts/src_ts/crypto/CryptoUtils.ts}. SHA-256 via the JDK; cSHAKE256 and the
 * seed/key/memberId derivations via BouncyCastle (no native cSHAKE exists in the JDK or
 * Android). All outputs must match the noble/WebCrypto originals byte-for-byte.
 */
public final class CryptoUtils {
  private CryptoUtils() {}

  private static final SecureRandom RNG = new SecureRandom();
  private static final byte[] EMPTY = new byte[0];

  public static byte[] generateRandomBytes(int length) {
    if (length <= 0) throw new CodedException("Length must be a positive integer", "INVALID_LENGTH");
    byte[] b = new byte[length];
    RNG.nextBytes(b);
    return b;
  }

  public static byte[] generateRandomBytes() {
    return generateRandomBytes(32);
  }

  public static String generateRandomUUID() {
    return UUID.randomUUID().toString();
  }

  public static byte[] sha256(byte[] data) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(data);
    } catch (NoSuchAlgorithmException e) {
      throw new CodedException("SHA-256 unavailable", "NO_SHA256", e);
    }
  }

  public static byte[] sha256(String data) {
    return sha256(Helpers.utf8(data));
  }

  /**
   * cSHAKE256 with empty function-name N and customization S = {@code personalization}
   * (NIST SP 800-185). Mirrors {@code letscShake256}.
   */
  public static byte[] cShake256(byte[] data, byte[] personalization, int outputLength) {
    if (outputLength <= 0) throw new CodedException("Output length must be positive", "INVALID_OUTPUT_LENGTH");
    CSHAKEDigest d = new CSHAKEDigest(256, EMPTY, personalization);
    d.update(data, 0, data.length);
    byte[] out = new byte[outputLength];
    d.doFinal(out, 0, outputLength);
    return out;
  }

  public static byte[] cShake256(byte[] data, String personalization, int outputLength) {
    return cShake256(data, Helpers.utf8(personalization), outputLength);
  }

  public static final class Seeds {
    public final byte[] kemSeed;
    public final byte[] dsaSeed;

    Seeds(byte[] kemSeed, byte[] dsaSeed) {
      this.kemSeed = kemSeed;
      this.dsaSeed = dsaSeed;
    }
  }

  public static Seeds deriveSeeds(byte[] masterSeed) {
    return new Seeds(
        cShake256(masterSeed, Consts.CUSTOM_KEM_STRING, Consts.KEM_KEY_LENGTH_BYTES),
        cShake256(masterSeed, Consts.CUSTOM_DSA_STRING, Consts.DSA_KEY_LENGTH_BYTES));
  }

  public static byte[] deriveKeyForRole(String role, byte[] rootKey) {
    return Consts.isManagerRole(role)
        ? rootKey
        : cShake256(rootKey, Consts.CUSTOM_COLLECTION_LIST_STRING, Consts.DEFAULT_AEAD_KEY_LENGTH_BYTES);
  }

  public static String getMemberIdFromPubkey(byte[] dsaPublicKey) {
    return Helpers.hex(cShake256(dsaPublicKey, Consts.MEMBER_ID_STRING, 32));
  }
}
