package com.unimo.sdk.crypto;

import java.security.SecureRandom;

/**
 * A {@link SecureRandom} that dispenses a fixed seed buffer sequentially across
 * {@code nextBytes} calls. Used to drive BouncyCastle's ML-DSA / ML-KEM key generators
 * deterministically from a caller-supplied seed, matching noble's {@code keygen(seed)}:
 *
 * <ul>
 *   <li>ML-DSA-87 keygen reads one 32-byte seed (ξ).
 *   <li>ML-KEM-1024 keygen reads d (32) then z (32) — verified against bc-java's
 *       {@code MLKEMEngine.generateKemKeyPair}.
 * </ul>
 *
 * Strict by design: over-reading the buffer throws, so a future BouncyCastle change in how
 * many bytes keygen consumes surfaces as a loud failure (and a failed conformance vector)
 * rather than silently wrong keys.
 */
final class SeedRandom extends SecureRandom {
  private static final long serialVersionUID = 1L;
  private final byte[] seed;
  private int pos;

  SeedRandom(byte[] seed) {
    this.seed = seed.clone();
  }

  @Override
  public synchronized void nextBytes(byte[] bytes) {
    if (pos + bytes.length > seed.length) {
      throw new CodedException(
          "SeedRandom exhausted: requested " + bytes.length + " at offset " + pos + " of " + seed.length,
          "SEED_EXHAUSTED");
    }
    System.arraycopy(seed, pos, bytes, 0, bytes.length);
    pos += bytes.length;
  }
}
