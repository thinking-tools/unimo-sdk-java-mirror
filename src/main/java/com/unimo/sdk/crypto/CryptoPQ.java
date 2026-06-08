package com.unimo.sdk.crypto;

import com.unimo.sdk.shared.Consts;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSASigner;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMExtractor;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;

import java.security.SecureRandom;

/**
 * Port of {@code sdk/ts/src_ts/crypto/CryptoPQ.ts}. ML-KEM-1024 (FIPS-203) + ML-DSA-87
 * (FIPS-204 pure, empty context) via BouncyCastle low-level APIs — no JCA provider is
 * registered, sidestepping the Android-bundled-BouncyCastle clash.
 *
 * <p>Interop with the TS/noble side:
 * <ul>
 *   <li>Keygen is deterministic from the same seed via {@link SeedRandom} (ML-DSA reads ξ=32B;
 *       ML-KEM reads d=32B then z=32B), so public keys / memberIds match byte-for-byte.
 *   <li>ML-DSA signing is hedged (randomized) like noble's default; verification accepts both
 *       hedged and deterministic signatures, so signatures interoperate across languages.
 *   <li>BouncyCastle applies the FIPS-204 {@code 0x00 || ctxLen || ctx || M} prefix with an
 *       empty context — identical to noble's {@code getMessage(msg)}.
 * </ul>
 */
public final class CryptoPQ {
  private CryptoPQ() {}

  private static final SecureRandom RNG = new SecureRandom();
  private static final MLDSAParameters DSA = MLDSAParameters.ml_dsa_87;
  private static final MLKEMParameters KEM = MLKEMParameters.ml_kem_1024;

  /** ML-DSA-87 key pair: raw public key bytes + BouncyCastle private key handle. */
  public static final class DsaKeyPair {
    public final byte[] publicKey;
    public final MLDSAPrivateKeyParameters secretKey;

    DsaKeyPair(byte[] publicKey, MLDSAPrivateKeyParameters secretKey) {
      this.publicKey = publicKey;
      this.secretKey = secretKey;
    }
  }

  /** ML-KEM-1024 key pair: raw public key bytes + BouncyCastle private key handle. */
  public static final class KemKeyPair {
    public final byte[] publicKey;
    public final MLKEMPrivateKeyParameters secretKey;

    KemKeyPair(byte[] publicKey, MLKEMPrivateKeyParameters secretKey) {
      this.publicKey = publicKey;
      this.secretKey = secretKey;
    }
  }

  /** Result of {@link #encapsulate}: ciphertext + 32-byte shared secret. */
  public static final class Encapsulated {
    public final byte[] cipherText;
    public final byte[] sharedSecret;

    Encapsulated(byte[] cipherText, byte[] sharedSecret) {
      this.cipherText = cipherText;
      this.sharedSecret = sharedSecret;
    }
  }

  // ── ML-KEM-1024 ──

  public static KemKeyPair generateKemKeys(byte[] seed) {
    if (seed.length != Consts.KEM_KEY_LENGTH_BYTES) {
      throw new CodedException("Seed must be 64 bytes", "INVALID_SEED_LENGTH");
    }
    MLKEMKeyPairGenerator g = new MLKEMKeyPairGenerator();
    g.init(new MLKEMKeyGenerationParameters(new SeedRandom(seed), KEM));
    AsymmetricCipherKeyPair kp = g.generateKeyPair();
    return new KemKeyPair(
        ((MLKEMPublicKeyParameters) kp.getPublic()).getEncoded(), (MLKEMPrivateKeyParameters) kp.getPrivate());
  }

  public static Encapsulated encapsulate(byte[] publicKey) {
    SecretWithEncapsulation swe =
        new MLKEMGenerator(RNG).generateEncapsulated(new MLKEMPublicKeyParameters(KEM, publicKey));
    return new Encapsulated(swe.getEncapsulation(), swe.getSecret());
  }

  public static byte[] decapsulate(MLKEMPrivateKeyParameters secretKey, byte[] ciphertext) {
    return new MLKEMExtractor(secretKey).extractSecret(ciphertext);
  }

  public static byte[] decapsulate(KemKeyPair keyPair, byte[] ciphertext) {
    return decapsulate(keyPair.secretKey, ciphertext);
  }

  // ── ML-DSA-87 ──

  public static DsaKeyPair generateDsaKeys(byte[] seed) {
    MLDSAKeyPairGenerator g = new MLDSAKeyPairGenerator();
    g.init(new MLDSAKeyGenerationParameters(new SeedRandom(seed), DSA));
    AsymmetricCipherKeyPair kp = g.generateKeyPair();
    return new DsaKeyPair(
        ((MLDSAPublicKeyParameters) kp.getPublic()).getEncoded(), (MLDSAPrivateKeyParameters) kp.getPrivate());
  }

  public static byte[] sign(MLDSAPrivateKeyParameters secretKey, byte[] message) {
    if (message == null || message.length == 0) throw new CodedException("Message cannot be empty", "EMPTY_MESSAGE");
    MLDSASigner s = new MLDSASigner();
    s.init(true, new ParametersWithRandom(secretKey, RNG));
    s.update(message, 0, message.length);
    try {
      return s.generateSignature();
    } catch (Exception e) {
      throw new CodedException("ML-DSA signing failed", "SIGN_FAILED", e);
    }
  }

  public static boolean verifySignature(byte[] publicKey, byte[] message, byte[] signature) {
    if (signature.length != Consts.ML_DSA_SIGNATURE_SIZE) {
      throw new CodedException("Invalid signature length", "INVALID_SIGNATURE_LENGTH");
    }
    if (publicKey.length != Consts.ML_DSA_PUBLIC_KEY_SIZE) {
      throw new CodedException("Invalid public key length", "INVALID_PUBLIC_KEY_LENGTH");
    }
    if (message == null || message.length == 0) throw new CodedException("Message cannot be empty", "EMPTY_MESSAGE");
    MLDSASigner s = new MLDSASigner();
    s.init(false, new MLDSAPublicKeyParameters(DSA, publicKey));
    s.update(message, 0, message.length);
    return s.verifySignature(signature);
  }
}
