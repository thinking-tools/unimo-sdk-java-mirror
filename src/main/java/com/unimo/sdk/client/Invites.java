package com.unimo.sdk.client;

import com.unimo.sdk.crypto.AEAD;
import com.unimo.sdk.crypto.CryptoPQ;
import com.unimo.sdk.crypto.CryptoUtils;
import com.unimo.sdk.shared.Consts;
import com.unimo.sdk.shared.Helpers;
import com.unimo.sdk.shared.Json;
import java.util.Map;

/**
 * Port of {@code sdk/ts/src_ts/client/Invites.ts}. Client-only invite crypto — the server is a
 * blind drop-box that only sees the derived {@code inviteId} and the AEAD-sealed claim:
 *
 * <pre>
 *   inviteId   = cSHAKE256(secret, "unimo-invite-id",   16) hex   — server lookup handle
 *   channelKey = cSHAKE256(secret, "unimo-invite-chan", 32)       — AEAD key for the drop-box
 *   SAS        = cSHAKE256(kemPub‖dsaPub, "unimo-invite-sas", 4)  — 6-digit human confirm
 * </pre>
 *
 * The claim is sign-then-seal: the invitee signs the canonical claim with its DSA key (proof of
 * possession), then AEAD-seals {@code {payload, signature}} under {@code channelKey}. The manager
 * verifies the signature against the presented {@code dsaPub} before enrolling the member.
 */
public final class Invites {
  private Invites() {}

  public static final class OpenedClaim {
    public final Map<String, Object> payload;
    public final boolean verified;

    OpenedClaim(Map<String, Object> payload, boolean verified) {
      this.payload = payload;
      this.verified = verified;
    }
  }

  /** Server lookup handle — cSHAKE of the secret (16 bytes → 32 hex), never the secret. */
  public static String deriveInviteId(byte[] secret) {
    return Helpers.hex(CryptoUtils.cShake256(secret, Consts.INVITE_ID_PERSONALIZATION, Consts.INVITE_ID_LENGTH_BYTES));
  }

  public static byte[] deriveChannelKey(byte[] secret) {
    return CryptoUtils.cShake256(secret, Consts.INVITE_CHANNEL_PERSONALIZATION, Consts.DEFAULT_AEAD_KEY_LENGTH_BYTES);
  }

  /** 6-digit short authentication string both sides compare out-of-band (optional UX check). */
  public static String deriveSAS(byte[] kemPub, byte[] dsaPub) {
    byte[] d = CryptoUtils.cShake256(Helpers.concat(kemPub, dsaPub), Consts.INVITE_SAS_PERSONALIZATION, 4);
    long n =
        ((long) (d[0] & 0xff) << 24 | (long) (d[1] & 0xff) << 16 | (long) (d[2] & 0xff) << 8 | (d[3] & 0xff))
            & 0xffffffffL;
    return String.format("%06d", n % 1_000_000);
  }

  public static String encodeInviteCode(byte[] secret) {
    return Helpers.base64(secret);
  }

  public static byte[] decodeInviteCode(String code) {
    return Helpers.fromBase64(code.trim());
  }

  /** Sign the canonical payload with the invitee's DSA key, then AEAD-seal under channelKey. */
  public static String sealClaim(byte[] channelKey, Map<String, Object> payload, CryptoPQ.DsaKeyPair dsaKeys) {
    byte[] hash = CryptoUtils.sha256(Helpers.utf8(Json.canonical(payload)));
    byte[] signature = CryptoPQ.sign(dsaKeys.secretKey, hash);
    byte[] blob = Helpers.utf8(Json.canonical(Json.obj("payload", payload, "signature", Helpers.base64(signature))));
    return Helpers.base64(AEAD.encrypt(channelKey, blob));
  }

  /** Decrypt + verify proof-of-possession. {@code verified=false} on any signature/parse failure. */
  @SuppressWarnings("unchecked")
  public static OpenedClaim openClaim(byte[] channelKey, String sealedB64) {
    byte[] plain = AEAD.decrypt(channelKey, Helpers.fromBase64(sealedB64));
    Map<String, Object> parsed = Json.parseObject(Helpers.fromUtf8(plain));
    Map<String, Object> payload = (Map<String, Object>) parsed.get("payload");
    byte[] hash = CryptoUtils.sha256(Helpers.utf8(Json.canonical(payload)));
    boolean verified;
    try {
      verified =
          CryptoPQ.verifySignature(
              Helpers.fromBase64((String) payload.get("dsaPub")),
              hash,
              Helpers.fromBase64((String) parsed.get("signature")));
    } catch (RuntimeException e) {
      verified = false;
    }
    return new OpenedClaim(payload, verified);
  }
}
