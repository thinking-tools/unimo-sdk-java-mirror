package com.unimo.sdk.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import com.unimo.sdk.shared.Consts;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/** Every gateway request states the API version this SDK speaks. The gateway names the oldest
 *  version it serves only when it refuses one: {@code UPGRADE_REQUIRED} then flips, once, and the
 *  app shows its "update required" notice. */
class ApiVersionTest {
  @Test
  void requestStatesTheApiVersionAndOnlyANamedRefusalIsFlaggedOnce() throws Exception {
    AtomicReference<String> stated = new AtomicReference<>();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/",
        ex -> {
          stated.set(ex.getRequestHeaders().getFirst(Consts.HEADER_API_VERSION));
          if (ex.getRequestURI().getPath().equals("/gateway")) {
            ex.getResponseHeaders().set(Consts.HEADER_MIN_API_VERSION, "2");
          }
          ex.sendResponseHeaders(426, -1);
          ex.close();
        });
    server.start();
    AtomicInteger notified = new AtomicInteger();
    try (ReactiveValue.Subscription ignored =
        ApiClient.UPGRADE_REQUIRED.onChange(v -> notified.incrementAndGet())) {
      String base = "http://127.0.0.1:" + server.getAddress().getPort();

      send(base + "/proxy"); // a 426 from something else on the path
      assertEquals(String.valueOf(Consts.API_VERSION), stated.get());
      assertFalse(ApiClient.UPGRADE_REQUIRED.get());

      send(base + "/gateway");
      send(base + "/gateway");
      assertTrue(ApiClient.UPGRADE_REQUIRED.get());
      assertEquals(1, notified.get());
    } finally {
      server.stop(0);
      ApiClient.UPGRADE_REQUIRED.set(false);
    }
  }

  private static void send(String url) throws Exception {
    ApiClient.send("GET", url, null, Collections.emptyMap(), null).get(5, TimeUnit.SECONDS);
  }
}
