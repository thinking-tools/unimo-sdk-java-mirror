package conformance;

import com.unimo.sdk.client.Members;
import com.unimo.sdk.client.collections.KVContent;
import com.unimo.sdk.crypto.AEAD;
import com.unimo.sdk.crypto.CryptoPQ;
import com.unimo.sdk.crypto.CryptoUtils;
import com.unimo.sdk.shared.Helpers;
import com.unimo.sdk.shared.Json;
import com.unimo.sdk.shared.Validators;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

/**
 * Cross-language conformance gate: loads the golden vectors emitted by
 * {@code sdk/ts/tools/gen-conformance.ts} (the real noble/WebCrypto SDK) and asserts the Java
 * port reproduces every one. Run after {@code bun run sdk/ts/tools/gen-conformance.ts}:
 *
 *   javac -cp libs/bcprov-jdk18on-1.81.jar -d out $(find src/main/java -name '*.java') conformance/ConformanceRunner.java
 *   java  -cp out:libs/bcprov-jdk18on-1.81.jar conformance.ConformanceRunner conformance/vectors.json
 */
public final class ConformanceRunner {
  private static int pass = 0;
  private static int fail = 0;

  public static void main(String[] args) throws Exception {
    if (run(args.length > 0 ? args[0] : "conformance/vectors.json") > 0) System.exit(1);
  }

  /** Runs all checks; returns the failure count (0 = all green). Reused by the JUnit test. */
  public static int run(String path) throws Exception {
    pass = 0;
    fail = 0;
    Map<String, Object> v = Json.parseObject(new String(Files.readAllBytes(Paths.get(path)), "UTF-8"));

    // SHA-256
    for (Object o : list(v, "sha256")) {
      Map<String, Object> c = cast(o);
      eq("sha256(" + c.get("in") + ")", str(c, "outHex"), Helpers.hex(CryptoUtils.sha256(str(c, "in"))));
    }

    // cSHAKE256
    for (Object o : list(v, "cshake256")) {
      Map<String, Object> c = cast(o);
      byte[] out =
          CryptoUtils.cShake256(Helpers.fromHex(str(c, "dataHex")), Helpers.utf8(str(c, "pers")), i(c, "dkLen"));
      eq("cshake256[" + c.get("label") + "]", str(c, "outHex"), Helpers.hex(out));
    }

    // deriveSeeds
    Map<String, Object> ds = map(v, "deriveSeeds");
    CryptoUtils.Seeds seeds = CryptoUtils.deriveSeeds(Helpers.fromHex(str(ds, "masterSeedHex")));
    eq("deriveSeeds.kem", str(ds, "kemSeedHex"), Helpers.hex(seeds.kemSeed));
    eq("deriveSeeds.dsa", str(ds, "dsaSeedHex"), Helpers.hex(seeds.dsaSeed));

    // deriveKeyForRole
    Map<String, Object> dk = map(v, "deriveKeyForRole");
    byte[] root = Helpers.fromHex(str(dk, "rootKeyHex"));
    eq("deriveKeyForRole.ADMIN", str(dk, "managerHex"), Helpers.hex(CryptoUtils.deriveKeyForRole("ADMIN", root)));
    eq("deriveKeyForRole.MEMBER", str(dk, "memberHex"), Helpers.hex(CryptoUtils.deriveKeyForRole("MEMBER", root)));

    // ML-DSA keygen (public key byte-equality with noble)
    Map<String, Object> dg = map(v, "mldsaKeygen");
    CryptoPQ.DsaKeyPair dkp = CryptoPQ.generateDsaKeys(Helpers.fromHex(str(dg, "seedHex")));
    eq("mldsaKeygen.pub", str(dg, "publicKeyHex"), Helpers.hex(dkp.publicKey));

    // ML-KEM keygen (public key byte-equality with noble)
    Map<String, Object> kg = map(v, "mlkemKeygen");
    CryptoPQ.KemKeyPair kkp = CryptoPQ.generateKemKeys(Helpers.fromHex(str(kg, "seedHex")));
    eq("mlkemKeygen.pub", str(kg, "publicKeyHex"), Helpers.hex(kkp.publicKey));

    // buildMember (deriveSeeds → keygen → memberId)
    Map<String, Object> bm = map(v, "buildMember");
    CryptoUtils.Seeds ms = CryptoUtils.deriveSeeds(Helpers.fromHex(str(bm, "seedHex")));
    CryptoPQ.DsaKeyPair mDsa = CryptoPQ.generateDsaKeys(ms.dsaSeed);
    CryptoPQ.KemKeyPair mKem = CryptoPQ.generateKemKeys(ms.kemSeed);
    eq("buildMember.dsaPub", str(bm, "dsaPublicKeyHex"), Helpers.hex(mDsa.publicKey));
    eq("buildMember.kemPub", str(bm, "kemPublicKeyHex"), Helpers.hex(mKem.publicKey));
    eq("buildMember.memberId", str(bm, "memberId"), CryptoUtils.getMemberIdFromPubkey(mDsa.publicKey));

    // ML-DSA verify a TS-produced (hedged) signature, plus a Java→Java round-trip
    Map<String, Object> sg = map(v, "mldsaSign");
    byte[] sigPub = Helpers.fromHex(str(sg, "publicKeyHex"));
    byte[] sigMsg = Helpers.fromHex(str(sg, "msgHex"));
    bool("mldsaSign.verifyTsSig", CryptoPQ.verifySignature(sigPub, sigMsg, Helpers.fromBase64(str(sg, "signatureB64"))));
    byte[] jSig = CryptoPQ.sign(dkp.secretKey, sigMsg);
    bool("mldsaSign.roundTrip", CryptoPQ.verifySignature(dkp.publicKey, sigMsg, jSig));

    // ML-KEM decapsulate a TS-produced ciphertext to the same shared secret
    Map<String, Object> kd = map(v, "mlkemDecap");
    CryptoPQ.KemKeyPair dkk = CryptoPQ.generateKemKeys(Helpers.fromHex(str(kd, "seedHex")));
    byte[] ss = CryptoPQ.decapsulate(dkk, Helpers.fromBase64(str(kd, "ciphertextB64")));
    eq("mlkemDecap.sharedSecret", str(kd, "sharedSecretHex"), Helpers.hex(ss));

    // ML-KEM encapsulate→decapsulate Java-internal round-trip (covers encapsulate(), untested above)
    CryptoPQ.Encapsulated jEnc = CryptoPQ.encapsulate(kkp.publicKey);
    eq("mlkem.encapRoundTrip", Helpers.hex(jEnc.sharedSecret), Helpers.hex(CryptoPQ.decapsulate(kkp, jEnc.cipherText)));

    // AEAD random-IV round-trip (non-ASCII plaintext)
    byte[] rk = AEAD.generateRawAEADKeyData();
    String rt = "round-trip ✓ üñ";
    eq("aead.randomIvRoundTrip", rt, Helpers.fromUtf8(AEAD.decrypt(rk, AEAD.encrypt(rk, Helpers.utf8(rt)))));

    // Canonical JSON byte-equality + hash
    for (Object o : list(v, "canonicalJson")) {
      Map<String, Object> c = cast(o);
      String canon = Helpers.generateCanonicalJSON(c.get("value"));
      eq("canonicalJson[" + c.get("name") + "]", str(c, "canonical"), canon);
      if (c.containsKey("sha256Hex")) {
        eq("canonicalJson[" + c.get("name") + "].sha256", str(c, "sha256Hex"), Helpers.hex(CryptoUtils.sha256(canon)));
        eq(
            "canonicalJson[" + c.get("name") + "].payloadHash",
            str(c, "payloadHashB64"),
            Helpers.base64(CryptoUtils.sha256(canon)));
      }
    }

    // AEAD: decrypt a TS ciphertext + reproduce a fixed-IV ciphertext byte-for-byte
    Map<String, Object> ae = map(v, "aead");
    byte[] aeKey = Helpers.fromHex(str(ae, "keyHex"));
    eq(
        "aead.decryptTsCipher",
        str(ae, "plaintextUtf8"),
        Helpers.fromUtf8(AEAD.decrypt(aeKey, Helpers.fromBase64(str(ae, "tsCipherB64")))));
    byte[] fixed = AEAD.encrypt(aeKey, Helpers.utf8(str(ae, "plaintextUtf8")), Helpers.fromHex(str(ae, "fixedIvHex")));
    eq("aead.fixedIvEncrypt", str(ae, "fixedRefB64"), Helpers.base64(fixed));

    // deriveChunkId
    Map<String, Object> dc = map(v, "deriveChunkId");
    eq(
        "deriveChunkId",
        str(dc, "chunkId"),
        Helpers.deriveChunkId(str(dc, "fileId"), Helpers.fromHex(str(dc, "uploadNonceHex")), i(dc, "chunkIndex")));

    // ── Phase 2: identity ──

    // createNewCredentials (TS) → deriveKeys unlock (Java): recover the role key byte-for-byte
    for (Object o : list(v, "credentials")) {
      Map<String, Object> c = cast(o);
      CryptoUtils.Seeds s = CryptoUtils.deriveSeeds(Helpers.fromHex(str(c, "initSeedHex")));
      CryptoPQ.KemKeyPair kem = CryptoPQ.generateKemKeys(s.kemSeed);
      byte[] shared = CryptoPQ.decapsulate(kem, Helpers.fromBase64(str(c, "memberKemCiphertextB64")));
      byte[] roleKey = AEAD.decrypt(shared, Helpers.fromBase64(str(c, "memberVaultKeyWrappedB64")));
      eq("credentials[" + c.get("role") + "].roleKey", str(c, "expectedRoleKeyHex"), Helpers.hex(roleKey));
    }

    // encryptMemberList (TS) → decryptMemberList (Java)
    Map<String, Object> ml = map(v, "memberList");
    List<Map<String, Object>> members =
        Members.decryptMemberList(str(ml, "encryptedB64"), Members.getManagerKey(Helpers.fromHex(str(ml, "masterKeyHex"))));
    eq("memberList.firstId", str(ml, "firstMemberId"), (String) members.get(0).get("memberId"));
    eq("memberList.firstName", str(ml, "firstMemberName"), (String) members.get(0).get("memberName"));

    // managerOnlyArea decrypt
    Map<String, Object> ma = map(v, "managerArea");
    byte[] areaPlain =
        AEAD.decrypt(Members.getManagerKey(Helpers.fromHex(str(ma, "masterKeyHex"))), Helpers.fromBase64(str(ma, "encryptedB64")));
    Map<String, Object> area = Json.parseObject(Helpers.fromUtf8(areaPlain));
    eq("managerArea.v", "1", String.valueOf(((Number) area.get("v")).intValue()));
    eq("managerArea.accountSeed", str(ma, "accountSeedB64"), (String) area.get("accountSeed"));

    // Full manifest validation (hash + manager-signer ML-DSA signature) + tamper rejection
    bool("manifest.valid", Validators.isValidVaultManifest(map(v, "manifestValid"), "a"));
    bool("manifest.tamperRejected", !Validators.isValidVaultManifest(map(v, "manifestTampered"), "a"));

    // ── Phase 5: collections (KV serialize + collection blob LE-uint32 header) ──
    Map<String, Object> kvv = map(v, "kv");
    KVContent kvc = KVContent.deserialize(Helpers.fromBase64(str(kvv, "serializedB64")));
    eq("kv.greeting", str(kvv, "greeting"), (String) kvc.get("greeting"));
    eq("kv.count", "42", String.valueOf(((Number) kvc.get("count")).intValue()));
    eq("kv.roundTrip", "hello", (String) KVContent.deserialize(kvc.serialize()).get("greeting"));

    Map<String, Object> cb = map(v, "collectionBlob");
    byte[] blob = Helpers.fromBase64(str(cb, "blobB64"));
    int metaLen = (blob[0] & 0xff) | (blob[1] & 0xff) << 8 | (blob[2] & 0xff) << 16 | (blob[3] & 0xff) << 24;
    Map<String, Object> cmeta = Json.parseObject(Helpers.fromUtf8(java.util.Arrays.copyOfRange(blob, 4, 4 + metaLen)));
    eq("collectionBlob.metaVersion", "3", String.valueOf(((Number) cmeta.get("version")).intValue()));
    KVContent cbkv = KVContent.deserialize(java.util.Arrays.copyOfRange(blob, 4 + metaLen, blob.length));
    eq("collectionBlob.content", str(cb, "greeting"), (String) cbkv.get("greeting"));

    System.out.println();
    System.out.println("conformance: " + pass + " passed, " + fail + " failed");
    return fail;
  }

  // ── assertions + map helpers ──
  private static void eq(String name, String expected, String actual) {
    if (expected.equals(actual)) {
      pass++;
    } else {
      fail++;
      System.out.println("FAIL " + name);
      System.out.println("  expected: " + trunc(expected));
      System.out.println("  actual:   " + trunc(actual));
    }
  }

  private static void bool(String name, boolean ok) {
    if (ok) {
      pass++;
    } else {
      fail++;
      System.out.println("FAIL " + name + " (expected true)");
    }
  }

  private static String trunc(String s) {
    return s.length() > 96 ? s.substring(0, 96) + "…(" + s.length() + ")" : s;
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> cast(Object o) {
    return (Map<String, Object>) o;
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> map(Map<String, Object> m, String k) {
    return (Map<String, Object>) m.get(k);
  }

  @SuppressWarnings("unchecked")
  private static List<Object> list(Map<String, Object> m, String k) {
    return (List<Object>) m.get(k);
  }

  private static String str(Map<String, Object> m, String k) {
    return (String) m.get(k);
  }

  private static int i(Map<String, Object> m, String k) {
    return ((Number) m.get(k)).intValue();
  }
}
