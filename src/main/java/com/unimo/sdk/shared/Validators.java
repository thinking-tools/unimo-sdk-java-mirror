package com.unimo.sdk.shared;

import com.unimo.sdk.crypto.CryptoPQ;
import com.unimo.sdk.crypto.CryptoUtils;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Port of the client-relevant validators in {@code sdk/ts/src_ts/shared/Validators.ts}. The
 * security-critical path is {@link #isValidVaultManifest}: re-canonicalize the manifest payload,
 * SHA-256 it, compare to {@code payloadHash}, and ML-DSA-verify the signature against a manager
 * signer slot — exactly the gate the TS SDK runs on the manifest the server returns at login.
 */
public final class Validators {
  private Validators() {}

  private static final Pattern ACCOUNT_NAME = Pattern.compile("^[a-zA-Z0-9_-]+$");
  private static final Pattern ACCOUNT_ID = Pattern.compile("^[a-f0-9]{64}$");
  private static final Pattern VAULT_NAME = Pattern.compile("^[\\x20-\\x7E]+$");
  private static final Pattern RESERVED_SUBSTR = Pattern.compile("(official|verified|staff|support|admin)", Pattern.CASE_INSENSITIVE);
  private static final String[] RESERVED_PREFIXES = {"admin", "mod", "support", "staff", "system", "official"};

  private static final Set<String> RESERVED_USERNAMES =
      Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
          Consts.RECOVERY_DEVICE_NAME,
          "admin", "administrator", "root", "system", "sysadmin", "moderator", "mod", "superuser",
          "operator", "webmaster", "host", "owner", "founder", "creator",
          "support", "help", "helpdesk", "service", "customer-service", "staff", "team", "official",
          "verified", "info", "contact",
          "security", "abuse", "noreply", "no-reply", "postmaster", "hostmaster", "privacy", "legal",
          "dmca", "copyright",
          "api", "www", "mail", "ftp", "smtp", "pop", "imap", "login", "logout", "register", "signup",
          "signin", "auth", "oauth", "settings", "account", "profile", "dashboard", "home", "search",
          "discover",
          "everyone", "all", "none", "null", "undefined", "anonymous", "guest", "user", "test", "demo",
          "example", "sample",
          "latticestore", "lattice-store", "lattice", "latticeapp",
          "notification", "notifications", "alert", "alerts", "message", "messages", "payment",
          "billing", "invoice", "receipt")));

  private static boolean isAccountNameReserved(String accountName) {
    String n = accountName.toLowerCase().trim();
    if (RESERVED_USERNAMES.contains(n)) return true;
    for (String p : RESERVED_PREFIXES) if (n.startsWith(p)) return true;
    return RESERVED_SUBSTR.matcher(n).find();
  }

  public static boolean validateAccountName(String accountName) {
    if (accountName == null || isAccountNameReserved(accountName)) return false;
    return accountName.length() >= 5 && accountName.length() <= 256 && ACCOUNT_NAME.matcher(accountName).matches();
  }

  private static boolean validateVaultName(String vaultName) {
    if (vaultName == null) return false;
    String t = vaultName.trim();
    return t.length() >= 3 && t.length() <= 128 && VAULT_NAME.matcher(t).matches();
  }

  public static boolean isValidCollectionName(String name) {
    if (name == null) return false;
    String t = name.trim();
    return t.length() >= 1 && t.length() <= 64 && ACCOUNT_NAME.matcher(t).matches();
  }

  public static boolean isValidCollectionType(String type) {
    return Consts.COLLECTION_TYPE_VFS.equals(type)
        || Consts.COLLECTION_TYPE_KV.equals(type)
        || Consts.COLLECTION_TYPE_LIST.equals(type)
        || Consts.COLLECTION_TYPE_CRDTLIST.equals(type);
  }

  @SuppressWarnings("unchecked")
  public static Map<String, Object> getMemberFromMemberSlots(List<Object> memberSlots, String memberId) {
    if (memberSlots == null) return null;
    for (Object o : memberSlots) {
      Map<String, Object> m = (Map<String, Object>) o;
      if (memberId.equals(m.get("memberId"))) return m;
    }
    return null;
  }

  /**
   * Verify an ML-DSA signature over a base64 message (the {@code payloadHash} = base64 of the
   * 32-byte SHA-256 digest). Mirrors TS {@code isValidSignature}: decode the base64 to the raw
   * digest bytes and verify against the slot's DSA public key. Throws on malformed inputs.
   */
  public static boolean isValidSignature(String messageB64, String signatureB64, Map<String, Object> memberSlot) {
    if (isBlank(messageB64) || isBlank(signatureB64) || memberSlot == null) {
      throw new IllegalArgumentException("Missing or malformed signature components");
    }
    byte[] sig = Helpers.fromBase64(signatureB64);
    if (sig.length != Consts.ML_DSA_SIGNATURE_SIZE) throw new IllegalArgumentException("Invalid signature length");
    byte[] pub = Helpers.fromBase64((String) memberSlot.get("memberDsaPubkey"));
    if (pub.length != Consts.ML_DSA_PUBLIC_KEY_SIZE) throw new IllegalArgumentException("Invalid member public key length");
    byte[] digest = Helpers.fromBase64(messageB64);
    return CryptoPQ.verifySignature(pub, digest, sig);
  }

  /**
   * Full manifest validation: structure → manager signer → expected type → hash match →
   * signature. Returns false on any failure.
   */
  @SuppressWarnings("unchecked")
  public static boolean isValidVaultManifest(Map<String, Object> manifest, String expectedType) {
    if (manifest == null) return false;
    if (!hasKeys(manifest, "payload", "payloadHash", "signerId", "signature")) return false;
    Map<String, Object> payload = (Map<String, Object>) manifest.get("payload");
    if (payload == null
        || !hasKeys(payload, "version", "name", "type", "id", "dsaPubkey", "kemPubkey", "memberSlots",
            "managerOnlyMemberList", "managerOnlyArea", "keyEpoch", "createdAt", "updatedAt")) {
      return false;
    }
    String type = (String) payload.get("type");
    String name = (String) payload.get("name");
    String id = (String) payload.get("id");
    if (!(id instanceof String) || !ACCOUNT_ID.matcher(id).matches()) return false;
    boolean nameOk = Consts.VAULT_TYPE_ACCOUNT.equals(type) ? validateAccountName(name) : validateVaultName(name);
    if (!nameOk) return false;

    List<Object> slots = (List<Object>) payload.get("memberSlots");
    if (!validMemberSlots(slots)) return false;
    if (!expectedType.equals(type)) return false;

    String signerId = (String) manifest.get("signerId");
    Map<String, Object> signer = getMemberFromMemberSlots(slots, signerId);
    if (signer == null) return false;
    String signerRole = (String) signer.get("memberRole");
    if (!Consts.ROLE_OWNER.equals(signerRole) && !Consts.ROLE_ADMIN.equals(signerRole)) return false;

    String calculatedHash = Helpers.base64(CryptoUtils.sha256(Helpers.utf8(Json.canonical(payload))));
    if (!calculatedHash.equals(manifest.get("payloadHash"))) return false;
    return isValidSignature((String) manifest.get("payloadHash"), (String) manifest.get("signature"), signer);
  }

  private static final String[] SLOT_REQUIRED = {
    "memberId", "memberRole", "memberStatus", "memberKemCiphertext", "memberVaultKeyWrapped",
    "memberDsaPubkey", "createdAt", "updatedAt"
  };

  @SuppressWarnings("unchecked")
  private static boolean validMemberSlots(List<Object> slots) {
    if (slots == null || slots.isEmpty()) return false;
    for (Object o : slots) {
      if (!(o instanceof Map)) return false;
      if (!hasKeys((Map<String, Object>) o, SLOT_REQUIRED)) return false;
    }
    return true;
  }

  private static boolean hasKeys(Map<String, Object> m, String... keys) {
    for (String k : keys) if (!m.containsKey(k)) return false;
    return true;
  }

  private static boolean isBlank(String s) {
    return s == null || s.trim().isEmpty();
  }
}
