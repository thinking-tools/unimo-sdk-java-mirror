package com.unimo.sdk.crypto;

import com.unimo.sdk.shared.Consts;
import com.unimo.sdk.shared.Helpers;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Port of {@code sdk/ts/src_ts/crypto/CryptoAEAD.ts}. AES-256-GCM with the WebCrypto wire
 * layout: {@code [12-byte IV] [ciphertext] [16-byte tag]} (the GCM tag is appended by both
 * WebCrypto and the JCA, so the formats are identical). Uses only {@code javax.crypto} — no
 * external dependency.
 */
public final class AEAD {
  private AEAD() {}

  private static final int KEY_LENGTH = Consts.DEFAULT_AEAD_KEY_LENGTH_BYTES; // 32
  private static final int IV_LENGTH = 12;
  private static final int TAG_BITS = 128;
  private static final SecureRandom RNG = new SecureRandom();

  public static byte[] generateRawAEADKeyData() {
    byte[] k = new byte[KEY_LENGTH];
    RNG.nextBytes(k);
    return k;
  }

  public static byte[] encrypt(byte[] key, byte[] plaintext) {
    byte[] iv = new byte[IV_LENGTH];
    RNG.nextBytes(iv);
    return encrypt(key, plaintext, iv);
  }

  /** Encrypt with a caller-supplied IV. Exposed for deterministic test vectors. */
  public static byte[] encrypt(byte[] key, byte[] plaintext, byte[] iv) {
    requireKey(key);
    try {
      Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
      c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
      byte[] sealed = c.doFinal(plaintext);
      return Helpers.concat(iv, sealed);
    } catch (Exception e) {
      throw new CodedException("Encryption failed: " + e.getMessage(), "ENCRYPTION_FAILED", e);
    }
  }

  public static byte[] decrypt(byte[] key, byte[] ciphertext) {
    requireKey(key);
    if (ciphertext.length < IV_LENGTH) {
      throw new CodedException(
          "Ciphertext too short: expected at least " + IV_LENGTH + " bytes, got " + ciphertext.length,
          "INVALID_CIPHERTEXT_LENGTH");
    }
    try {
      byte[] iv = Arrays.copyOfRange(ciphertext, 0, IV_LENGTH);
      Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
      c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
      return c.doFinal(ciphertext, IV_LENGTH, ciphertext.length - IV_LENGTH);
    } catch (CodedException e) {
      throw e;
    } catch (Exception e) {
      throw new CodedException(
          "Decryption failed: authentication tag mismatch or corrupted data", "DECRYPTION_FAILED", e);
    }
  }

  private static void requireKey(byte[] key) {
    if (key.length != KEY_LENGTH) {
      throw new CodedException(
          "Invalid key length: expected " + KEY_LENGTH + " bytes, got " + key.length, "INVALID_KEY_LENGTH");
    }
  }
}
