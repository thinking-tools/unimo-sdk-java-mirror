package com.unimo.sdk.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import com.unimo.sdk.Client;
import com.unimo.sdk.client.Members.MemberInfoBasics;
import com.unimo.sdk.client.collections.CollectionController;
import com.unimo.sdk.crypto.CryptoUtils;
import com.unimo.sdk.shared.Consts;
import com.unimo.sdk.shared.Helpers;
import com.unimo.sdk.shared.Json;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * A manifest update that fails leaves the vault on the manifest the server last confirmed, and one
 * that meets another device's update is applied on top of it. A failed update used to stay in
 * memory and go out with the next unrelated one (after a key rotation applied in part: as a manifest
 * no device could open), and a conflicting one used to overwrite what the other device committed.
 */
class VaultFailedUpdateTest {
  private static final String ACCOUNT = "failedupdate";
  private static final String INVITE = "abababab";

  private StandInGateway gateway;
  private Client client;
  private byte[] deviceSeed;
  private byte[] recoverySeed;

  @BeforeEach
  void register() throws Exception {
    gateway = new StandInGateway();
    client = new Client(gateway.url());
    deviceSeed = seed();
    recoverySeed = await(client.register(ACCOUNT, "a@example.com", "laptop", deviceSeed)).recoverySeed;
  }

  @AfterEach
  void stopGateway() {
    gateway.stop();
  }

  @Test
  void aMemberWhoseKemKeyCannotBeUsedIsRefusedAndTheVaultIsAsItWas() throws Exception {
    VaultController vault = login();
    String dsaKey = Helpers.base64(Members.buildMember(seed()).dsaKeys.publicKey);
    String unusableKemKey = Helpers.base64(new byte[16]);

    assertThrows(
        ExecutionException.class,
        () -> await(vault.addMemberByPublicKeys(unusableKemKey, dsaKey, "phone", Consts.ROLE_MEMBER, null)));

    await(invite(vault));
    await(addMember(vault, "tablet"));
    assertEquals(1L, keyEpoch(gateway.committed()));
    assertEquals(3, memberSlots(gateway.committed()).size());
    // The manifest on the server opens for every device, the recovery one included.
    login();
    await(client.login(ACCOUNT, recoverySeed));
  }

  @Test
  void anUpdateTheServerDoesNotTakeIsNotCarriedIntoTheNextOne() throws Exception {
    VaultController vault = login();

    gateway.refuseNextPut(503);
    ExecutionException refused = assertThrows(ExecutionException.class, () -> await(addMember(vault, "phone")));
    assertTrue(refused.getCause().getMessage().contains("503"), refused.getCause().getMessage());

    await(vault.timeToFetchUpdate()); // the server's manifest is not behind the one held
    await(invite(vault));
    assertEquals(0L, keyEpoch(gateway.committed()));
    assertEquals(2, memberSlots(gateway.committed()).size());
    login();
  }

  @Test
  void anUpdateSentWithAnExpiredTokenSignsInAgainAndGoesThrough() throws Exception {
    VaultController vault = login();

    gateway.refuseNextPut(401);
    await(invite(vault));

    assertEquals(1, gateway.reauths.get());
    assertEquals(2, gateway.manifests.size());
  }

  @Test
  void anUpdateThatMeetsAnotherDevicesIsAppliedOnTopOfIt() throws Exception {
    VaultController here = login();
    VaultController elsewhere = login();
    AtomicBoolean announced = new AtomicBoolean();
    here.onAdopted = () -> announced.set(true);

    await(invite(elsewhere));
    await(addMember(here, "tablet"));

    assertEquals(3, memberSlots(gateway.committed()).size());
    assertNotNull(login().getPendingInvite(INVITE));
    assertTrue(announced.get(), "the other device's manifest was taken in without a word");
    // Announced once: a refresh asked for meanwhile finds nothing newer here, and the update there.
    assertFalse(await(here.timeToFetchUpdate()));
    assertTrue(await(elsewhere.timeToFetchUpdate()));
  }

  @Test
  void aDeviceBehindByAKeyRotationCatchesUp() throws Exception {
    VaultController here = login();
    VaultController elsewhere = login();

    await(addMember(elsewhere, "tablet"));
    await(invite(here));

    assertEquals(3, memberSlots(gateway.committed()).size());
    assertNotNull(login().getPendingInvite(INVITE));
  }

  @Test
  void aCollectionWhoseManifestIsRefusedIsNotLeftBehind() throws Exception {
    VaultController vault = login();
    Tasker tasker = new Tasker(gateway.url());
    await(vault.createCollection("notes", Consts.COLLECTION_TYPE_KV, tasker));
    CollectionController notes = vault.listCollections().get(0);

    gateway.refuseNextPut(503);
    assertThrows(
        ExecutionException.class, () -> await(vault.createCollection("drafts", Consts.COLLECTION_TYPE_KV, tasker)));

    assertEquals(1, vault.listCollections().size());
    assertSame(notes, vault.listCollections().get(0)); // the one handed out keeps its tasker and content
    await(invite(vault));
    assertEquals(1, login().listCollections().size());
  }

  @Test
  void aRenameTheServerDoesNotTakeGoesBack() throws Exception {
    VaultController vault = login();
    await(vault.createCollection("notes", Consts.COLLECTION_TYPE_KV, new Tasker(gateway.url())));
    CollectionController notes = vault.listCollections().get(0);

    gateway.refuseNextPut(503);
    assertThrows(ExecutionException.class, () -> await(vault.renameCollectionById(notes.getId(), "drafts")));

    assertEquals("notes", notes.getName());
  }

  @Test
  void aMemberAlreadyListedIsNotListedAgain() throws Exception {
    VaultController vault = login();
    MemberInfoBasics phone = Members.buildMember(seed());
    String kemKey = Helpers.base64(phone.kemKeys.publicKey);
    String dsaKey = Helpers.base64(phone.dsaKeys.publicKey);

    Map<String, Object> slot = await(vault.addMemberByPublicKeys(kemKey, dsaKey, "phone", Consts.ROLE_MEMBER, null));
    int committedBefore = gateway.manifests.size();

    assertEquals(slot, await(vault.addMemberByPublicKeys(kemKey, dsaKey, "phone", Consts.ROLE_MEMBER, null)));
    assertEquals(committedBefore, gateway.manifests.size());
    assertEquals(3, memberSlots(gateway.committed()).size());
  }

  private VaultController login() throws Exception {
    return await(client.login(ACCOUNT, deviceSeed));
  }

  private static CompletableFuture<Void> invite(VaultController vault) {
    return vault.addPendingInvite(
        Json.obj(
            "inviteId", INVITE,
            "inviteSecret", "c2VjcmV0",
            "role", Consts.ROLE_MEMBER,
            "createdAt", System.currentTimeMillis()));
  }

  private static CompletableFuture<Map<String, Object>> addMember(VaultController vault, String name) {
    return vault.addMemberWithSeed(seed(), name, Consts.ROLE_MEMBER, null);
  }

  private static byte[] seed() {
    return CryptoUtils.generateRandomBytes(Consts.DEFAULT_SEED_LENGTH_BYTES);
  }

  private static <T> T await(CompletableFuture<T> pending) throws Exception {
    return pending.get(20, TimeUnit.SECONDS);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> payload(Map<String, Object> manifest) {
    return (Map<String, Object>) manifest.get("payload");
  }

  private static long keyEpoch(Map<String, Object> manifest) {
    return ((Number) payload(manifest).get("keyEpoch")).longValue();
  }

  private static List<?> memberSlots(Map<String, Object> manifest) {
    return (List<?>) payload(manifest).get("memberSlots");
  }

  /**
   * One account, no signature checks. Keeps every manifest it is sent, and answers an update that is
   * behind as a gateway from before it compared versions first: a lower key epoch is refused before
   * the version is looked at.
   */
  private static final class StandInGateway {
    final List<Map<String, Object>> manifests = new CopyOnWriteArrayList<>();
    final AtomicInteger reauths = new AtomicInteger();
    private final HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    /** The status the next manifest PUT is refused with; 0 when it is taken. */
    private int nextPutRefusal;

    StandInGateway() throws IOException {
      server.createContext(
          "/",
          exchange -> {
            String body = new String(readAll(exchange.getRequestBody()), "UTF-8");
            Map<String, Object> answer = answer(exchange.getRequestMethod(), exchange.getRequestURI().getPath(), body);
            byte[] reply = Helpers.utf8(Json.canonical(answer));
            exchange.sendResponseHeaders(((Number) answer.get("statusCode")).intValue(), reply.length);
            exchange.getResponseBody().write(reply);
            exchange.close();
          });
      server.start();
    }

    String url() {
      return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    void stop() {
      server.stop(0);
    }

    synchronized void refuseNextPut(int status) {
      nextPutRefusal = status;
    }

    Map<String, Object> committed() {
      return manifests.get(manifests.size() - 1);
    }

    private synchronized Map<String, Object> answer(String method, String path, String body) {
      int version = manifests.size();
      if (path.equals("/api/auth/register")) {
        manifests.add(Json.parseObject(body));
        return answer(200, true);
      }
      if (path.equals("/api/auth/login")) {
        Map<String, Object> login = answer(200, true);
        login.put("accountVault", committed());
        login.put("vaultEtag", "e");
        login.put("manifestVersion", version);
        login.put("authToken", "t");
        return login;
      }
      if (path.equals("/api/auth/reauth")) {
        reauths.incrementAndGet();
        Map<String, Object> refreshed = answer(200, true);
        refreshed.put("authToken", "t2");
        return refreshed;
      }
      if (path.startsWith("/api/storage/")) return stored(201, 1);
      if (method.equals("GET")) {
        Map<String, Object> held = answer(200, true);
        held.put("accountVault", committed());
        held.put("version", version);
        return held;
      }
      if (nextPutRefusal != 0) {
        Map<String, Object> refused = answer(nextPutRefusal, false);
        nextPutRefusal = 0;
        return refused;
      }
      Map<String, Object> update = Json.parseObject(body);
      if (keyEpoch(update) < keyEpoch(committed())) return answer(400, false);
      if (((Number) update.remove("prevVersion")).intValue() != version) {
        Map<String, Object> behind = answer(412, false);
        behind.put("code", "VERSION_MISMATCH");
        behind.put("currentVersion", version);
        return behind;
      }
      manifests.add(update);
      return stored(200, version + 1);
    }

    private static Map<String, Object> stored(int status, int version) {
      Map<String, Object> stored = answer(status, true);
      stored.put("version", version);
      stored.put("etag", "e");
      return stored;
    }

    private static Map<String, Object> answer(int status, boolean ok) {
      return Json.obj("ok", ok, "statusCode", status, "message", "stand-in " + status);
    }

    private static byte[] readAll(InputStream in) throws IOException {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] chunk = new byte[8192];
      for (int read; (read = in.read(chunk)) != -1; ) out.write(chunk, 0, read);
      return out.toByteArray();
    }
  }
}
