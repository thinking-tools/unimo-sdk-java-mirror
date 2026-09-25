package conformance;

import com.unimo.sdk.Client;
import com.unimo.sdk.client.Account;
import com.unimo.sdk.client.Billing;
import com.unimo.sdk.client.Connection;
import com.unimo.sdk.client.Members;
import com.unimo.sdk.client.Search;
import com.unimo.sdk.client.Tasker;
import com.unimo.sdk.client.VaultController;
import com.unimo.sdk.client.collections.CollectionController;
import com.unimo.sdk.client.collections.KVContent;
import com.unimo.sdk.crypto.CodedException;
import com.unimo.sdk.crypto.CryptoUtils;
import com.unimo.sdk.shared.Consts;
import com.unimo.sdk.shared.Helpers;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Live end-to-end test against a running gateway (default {@code http://localhost:3000}, or arg
 * / {@code UNIMO_SERVICE_URL}). Exercises Phase 2 (register → login → unlock) and Phase 3
 * (addMember + key rotation → new-member login → reauth → removeMember → post-removal rejection)
 * over real HTTP. Run with the {@code bun run dev:local} stack up.
 */
public final class IntegrationRunner {
  private static int pass = 0;
  private static int fail = 0;

  public static void main(String[] args) throws Exception {
    String url = args.length > 0 ? args[0] : System.getenv().getOrDefault("UNIMO_SERVICE_URL", "http://localhost:3000");
    System.out.println("gateway: " + url);
    Client client = new Client(url);

    String account = "itest_" + Helpers.hex(CryptoUtils.generateRandomBytes(6));
    byte[] seed1 = CryptoUtils.generateRandomBytes(32);

    // Phase 2: email OTP → register → login → unlock
    String email = account + "@unimo.test";
    await(client.requestEmailCode(email));
    await(client.verifyEmailCode(email, otpCode(email)));
    Client.RegisterResult reg = await(client.register(account, email, "device1", seed1));
    check("register.ok", reg.ok);

    VaultController vc1 = await(client.login(account, seed1));
    check("login.isManager", vc1.isManagerMember());
    check("login.vaultId is 64-hex", vc1.getId() != null && vc1.getId().matches("^[a-f0-9]{64}$"));
    check("login.hasToken", vc1.getAuthToken() != null && !vc1.getAuthToken().isEmpty());

    // Phase 3: add a MEMBER device (rotates keys + signed manifest PUT)
    byte[] seed2 = CryptoUtils.generateRandomBytes(32);
    Members.MemberInfoBasics m2 = Members.buildMember(seed2);
    Map<String, Object> slot2 = await(vc1.addMemberWithSeed(seed2, "device2", "MEMBER", null));
    check("addMember.returnedSlotId", m2.memberId.equals(slot2.get("memberId")));

    // New member can log in and unlock the rotated vault key
    VaultController vc2 = await(client.login(account, seed2));
    check("member2.login.notManager", !vc2.isManagerMember());
    check("member2.sameVault", vc1.getId().equals(vc2.getId()));

    // Reauth issues a fresh token
    String oldToken = vc1.getAuthToken();
    boolean reauthed = await(vc1.handleAuthError());
    check("reauth.ok", reauthed);
    check("reauth.tokenChanged", !oldToken.equals(vc1.getAuthToken()));

    // Remove the member (rotates again); they can no longer log in
    boolean removed = await(vc1.removeMember(m2.memberId));
    check("removeMember.ok", removed);

    boolean rejected = false;
    try {
      await(client.login(account, seed2));
    } catch (Exception e) {
      rejected = true;
    }
    check("member2.loginRejectedAfterRemoval", rejected);

    // Phase 4: encrypted storage (single-chunk, CAS bump, multi-chunk)
    Tasker tasker = new Tasker(url);
    byte[] encKey = CryptoUtils.generateRandomBytes(32);
    String fileId = Helpers.hex(CryptoUtils.generateRandomBytes(32));

    byte[] payload = Helpers.utf8("hello unimo storage — single chunk ✓ üñ");
    Tasker.UploadResult up1 = await(tasker.upload(vc1, fileId, payload, encKey, 0));
    check("storage.single.firstVersion", up1.version == 1 && up1.chunkCount == 0);
    Tasker.DownloadResult down1 = await(tasker.download(vc1, fileId, encKey));
    check("storage.single.roundTrip", Arrays.equals(payload, down1.data) && down1.version == 1);

    byte[] payload2 = Helpers.utf8("second version of the same file");
    Tasker.UploadResult up2 = await(tasker.upload(vc1, fileId, payload2, encKey, 1)); // CAS pin to v1
    check("storage.single.casBumpToV2", up2.version == 2);
    Tasker.DownloadResult down2 = await(tasker.download(vc1, fileId, encKey));
    check("storage.single.headIsLatest", Arrays.equals(payload2, down2.data) && down2.version == 2);

    int bigLen = Consts.CHUNK_SIZE + 50_000; // > CHUNK_SIZE → 2 chunks
    byte[] big = new byte[bigLen];
    for (int i = 0; i < bigLen; i++) big[i] = (byte) ((i * 31 + 7) & 0xff);
    String fileId2 = Helpers.hex(CryptoUtils.generateRandomBytes(32));
    Tasker.UploadResult upBig = await(tasker.upload(vc1, fileId2, big, encKey, 0));
    check("storage.multi.twoChunks", upBig.chunkCount == 2 && upBig.version == 1);
    Tasker.DownloadResult downBig = await(tasker.download(vc1, fileId2, encKey));
    check("storage.multi.roundTrip", Arrays.equals(big, downBig.data) && downBig.version == 1);

    Tasker.DeleteResult del = await(tasker.delete(vc1, fileId2));
    check("storage.delete.trashed", del.trashedAt > 0 && del.expiresAt > del.trashedAt && del.blobsAffected >= 1);
    String afterDelete = null;
    try {
      await(tasker.download(vc1, fileId2, encKey));
    } catch (CodedException e) {
      afterDelete = e.getCode();
    }
    check("storage.delete.downloadIsTrashed", "TRASHED".equals(afterDelete));

    // Phase 5: collections (KV) — create, persist, reload, survive key rotation
    KVContent notes = await(vc1.createCollection("notes", "KV", tasker));
    notes.set("title", "first note");
    notes.set("body", "hello collections");
    CollectionController notesCol = null;
    for (CollectionController c : vc1.listCollections()) if ("notes".equals(c.getName())) notesCol = c;
    check("collection.controllerPresent", notesCol != null);
    if (notesCol != null) await(notesCol.flush());

    VaultController c2c = await(client.login(account, seed1));
    KVContent notes2 = await(c2c.getCollectionByName(tasker, "notes"));
    check("collection.reloadedAfterRelogin", notes2 != null);
    check(
        "collection.kvPersisted",
        notes2 != null && "first note".equals(notes2.get("title")) && "hello collections".equals(notes2.get("body")));

    byte[] seed3 = CryptoUtils.generateRandomBytes(32);
    await(c2c.addMemberWithSeed(seed3, "device3", "MEMBER", null)); // rotation must preserve collections
    VaultController c3c = await(client.login(account, seed1));
    KVContent notes3 = await(c3c.getCollectionByName(tasker, "notes"));
    check("collection.survivesKeyRotation", notes3 != null && "hello collections".equals(notes3.get("body")));

    // Phase 6a: billing (public catalog reachable; state uninitialized — no Stripe needed)
    Billing billing = new Billing(url, c3c);
    List<Object> plans = await(billing.listPlans());
    check("billing.catalogReachable", plans != null);
    Map<String, Object> billingState = await(billing.getState());
    check("billing.stateUninitialized", billingState == null);

    // Phase 6a: invites — manager creates → invitee claims → manager finalizes → new member logs in
    VaultController.InviteCreated inv = await(c3c.createInvite("MEMBER", null));
    check("invite.created", inv.inviteId != null && inv.code != null && inv.inviteId.matches("^[a-f0-9]{32}$"));
    byte[] seed5 = CryptoUtils.generateRandomBytes(32);
    Client.InviteClaim claim = await(client.claimInvite(inv.code, "invitee5", seed5));
    check("invite.claimedAccountMatches", account.equals(claim.accountName) && "MEMBER".equals(claim.role));
    Map<String, Object> invSlot = await(c3c.finalizeInvite(inv.inviteId));
    check("invite.finalizedSlot", invSlot != null && invSlot.get("memberId") != null);
    VaultController inviteVc = await(client.login(account, seed5));
    check("invite.newMemberCanLogIn", inviteVc != null && !inviteVc.isManagerMember());

    // Phase 6b: WebSocket — connect, then a blob PUT should push a vault:event (blob_put)
    CountDownLatch eventLatch = new CountDownLatch(1);
    AtomicReference<Object> gotKind = new AtomicReference<>();
    String wsFileId = Helpers.hex(CryptoUtils.generateRandomBytes(32));
    Connection conn = new Connection(url, c3c);
    conn.on(
        "vault:event",
        msg -> {
          if ("blob_put".equals(msg.get("kind")) && wsFileId.equals(msg.get("fileId"))) {
            gotKind.set(msg.get("kind"));
            eventLatch.countDown();
          }
        });
    conn.start();
    Thread.sleep(1500); // allow the upgrade + server-side vault subscription to settle
    check("ws.connected", conn.isOpen());
    await(tasker.upload(c3c, wsFileId, Helpers.utf8("ws-triggered blob"), encKey, 0));
    boolean gotEvent = eventLatch.await(15, TimeUnit.SECONDS);
    check("ws.receivedBlobPutEvent", gotEvent && "blob_put".equals(gotKind.get()));

    // Phase 7: WebSocket search. suggest is provider-key-free (Google Suggest) — any failure
    // there is a real regression, FAIL. Full search needs a Brave/Serper key, and the gateway
    // strips error codes for the search domain (any engine throw → uncoded "Internal error" →
    // WS_ERROR), so provider-missing is indistinguishable from a genuine gateway-side bug:
    // with UNIMO_SEARCH_LIVE=1 (keyed/CI envs) any error FAILs; otherwise only WS_ERROR SKIPs
    // loudly and SDK-side codes (WS_TIMEOUT/CONNECTION_CLOSED/BAD_FRAME/HANDLER_ERROR) still FAIL.
    Search search = new Search(conn);
    boolean emptyRejected = false;
    try {
      search.suggest("   ");
    } catch (CodedException e) {
      emptyRejected = "EMPTY_QUERY".equals(e.getCode());
    }
    check("search.emptyQueryRejectedLocally", emptyRejected);
    boolean searchLive = "1".equals(System.getenv("UNIMO_SEARCH_LIVE"));
    List<String> sugg = null;
    try {
      sugg = await(search.suggest("open source"));
    } catch (CodedException e) {
      System.out.println("  (suggest failed: " + e.getMessage() + " [" + e.getCode() + "])");
    }
    check("search.suggest.roundTrip", sugg != null);
    // The gateway degrades suggest to [] when Google Suggest (unofficial endpoint) and the paid
    // fallbacks are all unreachable — only a declared-live env can honestly demand content.
    if (searchLive && sugg != null) check("search.suggest.nonEmpty", !sugg.isEmpty());
    try {
      AtomicReference<List<String>> early = new AtomicReference<>();
      Search.Response res = await(search.search("post-quantum cryptography", early::set));
      check("search.query.hasResults", res != null && !res.results.isEmpty() && res.results.get(0).url != null);
      check("search.query.earlySuggestionsFrame", early.get() != null);
    } catch (CodedException e) {
      if (searchLive || !"WS_ERROR".equals(e.getCode())) {
        check("search.roundTrip (" + e.getCode() + ")", false);
      } else {
        System.out.println("  SKIP search round-trip — no provider configured? set UNIMO_SEARCH_LIVE=1 to enforce: "
            + e.getMessage() + " [" + e.getCode() + "]");
      }
    }
    conn.stop();

    // Phase 6b: minimal Account wrapper (reuses the existing vault — no extra login)
    Account acct = new Account(url, c3c, false);
    check("account.wrapsManagerVault", acct.isManagerMember());
    String acctFile = Helpers.hex(CryptoUtils.generateRandomBytes(32));
    await(acct.upload(acctFile, Helpers.utf8("via account"), encKey, 0));
    Tasker.DownloadResult acctDl = await(acct.download(acctFile, encKey));
    check("account.uploadDownloadRoundTrip", Arrays.equals(Helpers.utf8("via account"), acctDl.data));

    System.out.println();
    System.out.println("integration: " + pass + " passed, " + fail + " failed");
    System.exit(fail > 0 ? 1 : 0);
  }

  /**
   * The gateway never mails in dev, so read the code it stored ({@code HGET auth:otp:{email} code})
   * straight off Valkey over RESP. {@code UNIMO_VALKEY} defaults to the {@code dev:local} bundled
   * instance; point it at {@code redis://127.0.0.1:6390} for a host-run {@code bun run dev}.
   */
  private static String otpCode(String email) throws IOException {
    URI u = URI.create(System.getenv().getOrDefault("UNIMO_VALKEY", "redis://:devpass@127.0.0.1:6379"));
    try (Socket s = new Socket(u.getHost(), u.getPort())) {
      OutputStream out = s.getOutputStream();
      BufferedReader in = new BufferedReader(new InputStreamReader(s.getInputStream(), StandardCharsets.UTF_8));
      String userInfo = u.getUserInfo();
      if (userInfo != null && !userInfo.isEmpty()) {
        resp(out, "AUTH", userInfo.substring(userInfo.indexOf(':') + 1));
        String reply = in.readLine();
        if (reply == null || !reply.startsWith("+")) throw new IOException("valkey AUTH failed: " + reply);
      }
      resp(out, "HGET", "auth:otp:" + email, "code");
      String len = in.readLine();
      if (len == null || !len.startsWith("$") || len.equals("$-1")) {
        throw new IOException("no OTP for " + email + " in valkey at " + u.getHost() + ":" + u.getPort()
            + " (" + len + ") — set UNIMO_VALKEY to the gateway's Valkey");
      }
      return in.readLine();
    }
  }

  private static void resp(OutputStream out, String... args) throws IOException {
    StringBuilder sb = new StringBuilder("*").append(args.length).append("\r\n");
    for (String a : args) {
      sb.append('$').append(a.getBytes(StandardCharsets.UTF_8).length).append("\r\n").append(a).append("\r\n");
    }
    out.write(sb.toString().getBytes(StandardCharsets.UTF_8));
    out.flush();
  }

  private static <T> T await(CompletableFuture<T> f) throws Exception {
    try {
      return f.get(60, TimeUnit.SECONDS);
    } catch (java.util.concurrent.ExecutionException e) {
      Throwable cause = e.getCause();
      throw cause instanceof Exception ? (Exception) cause : e;
    }
  }

  private static void check(String name, boolean ok) {
    if (ok) {
      pass++;
      System.out.println("  ok   " + name);
    } else {
      fail++;
      System.out.println("  FAIL " + name);
    }
  }
}
