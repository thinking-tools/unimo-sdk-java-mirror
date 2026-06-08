package com.unimo.sdk.shared;

import com.unimo.sdk.crypto.CryptoUtils;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

/**
 * Port of {@code sdk/ts/src_ts/shared/Helpers.ts} — byte/encoding utilities + canonical JSON.
 * Hex is lowercase; Base64 is standard (with padding, no line wrapping) to match the TS SDK's
 * {@code btoa}/Buffer output. BouncyCastle encoders are reused (already a dependency).
 */
public final class Helpers {
  private Helpers() {}

  public static byte[] utf8(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  public static String fromUtf8(byte[] b) {
    return new String(b, StandardCharsets.UTF_8);
  }

  public static String hex(byte[] b) {
    return Hex.toHexString(b);
  }

  public static byte[] fromHex(String h) {
    if (h.length() % 2 != 0) throw new IllegalArgumentException("Invalid hex string");
    return Hex.decode(h);
  }

  public static String base64(byte[] b) {
    return Base64.toBase64String(b);
  }

  public static byte[] fromBase64(String s) {
    return Base64.decode(s);
  }

  public static byte[] concat(byte[]... parts) {
    int total = 0;
    for (byte[] p : parts) total += p.length;
    byte[] out = new byte[total];
    int off = 0;
    for (byte[] p : parts) {
      System.arraycopy(p, 0, out, off, p.length);
      off += p.length;
    }
    return out;
  }

  /** Encode a non-negative integer as a 4-byte big-endian array. */
  public static byte[] u32be(long n) {
    if (n < 0 || n > 0xffffffffL) throw new IllegalArgumentException("u32be: value out of range: " + n);
    return new byte[] {
      (byte) ((n >>> 24) & 0xff), (byte) ((n >>> 16) & 0xff), (byte) ((n >>> 8) & 0xff), (byte) (n & 0xff)
    };
  }

  /** Mirror of {@code generateCanonicalJSON}. */
  public static String generateCanonicalJSON(Object payload) {
    return Json.canonical(payload);
  }

  /** Current epoch milliseconds (mirror of {@code now()} / {@code Date.now()}). */
  public static long now() {
    return System.currentTimeMillis();
  }

  /** ISO-8601 UTC timestamp with millisecond precision, e.g. {@code 2026-06-05T07:43:25.123Z}.
   *  Uses {@link SimpleDateFormat} (available on every Android API level, unlike java.time).
   *  The exact format is not interop-critical — the client signs the same string it sends. */
  public static String isoNow() {
    SimpleDateFormat f = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
    f.setTimeZone(TimeZone.getTimeZone("UTC"));
    return f.format(new Date());
  }

  /**
   * Derive a chunkId for storage-v2 multi-chunk uploads:
   * {@code chunkId = sha256( hexToBytes(fileId) || uploadNonce || u32be(chunkIndex) )}.
   */
  public static String deriveChunkId(String fileId, byte[] uploadNonce, int chunkIndex) {
    return hex(CryptoUtils.sha256(concat(fromHex(fileId), uploadNonce, u32be(chunkIndex))));
  }
}
