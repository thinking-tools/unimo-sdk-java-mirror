package com.unimo.sdk.client;

import com.sun.net.httpserver.HttpServer;
import com.unimo.sdk.shared.Helpers;
import com.unimo.sdk.shared.Json;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * One account, no signature checks. Keeps every manifest it is sent, and answers an update that is
 * behind as a gateway from before it compared versions first: a lower key epoch is refused before
 * the version is looked at.
 */
final class StandInGateway {
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

  /** From now on a request under {@code path} is taken in and never answered, as on a network
   *  that has gone dead. The latch opens when {@code awaited} of them have arrived. */
  CountDownLatch leaveUnanswered(String path, int awaited) {
    CountDownLatch arrived = new CountDownLatch(awaited);
    server.createContext(path, exchange -> arrived.countDown());
    return arrived;
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

  @SuppressWarnings("unchecked")
  static Map<String, Object> payload(Map<String, Object> manifest) {
    return (Map<String, Object>) manifest.get("payload");
  }

  static long keyEpoch(Map<String, Object> manifest) {
    return ((Number) payload(manifest).get("keyEpoch")).longValue();
  }

  private static byte[] readAll(InputStream in) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] chunk = new byte[8192];
    for (int read; (read = in.read(chunk)) != -1; ) out.write(chunk, 0, read);
    return out.toByteArray();
  }
}
