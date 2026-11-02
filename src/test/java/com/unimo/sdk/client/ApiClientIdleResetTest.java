package com.unimo.sdk.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/** Different client ports = different connections; a request after an idle pause must not reuse
 *  the pooled one. */
class ApiClientIdleResetTest {
  @Test
  void requestAfterIdlePauseOpensFreshConnection() throws Exception {
    List<Integer> ports = new CopyOnWriteArrayList<>();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext(
        "/",
        ex -> {
          ports.add(ex.getRemoteAddress().getPort());
          ex.sendResponseHeaders(200, 2);
          try (OutputStream out = ex.getResponseBody()) {
            out.write("{}".getBytes());
          }
        });
    server.start();
    try {
      String url = "http://127.0.0.1:" + server.getAddress().getPort() + "/";
      ApiClient.send("GET", url, null, Collections.emptyMap()).get(5, TimeUnit.SECONDS);
      Thread.sleep(11_000); // > the pool's 10 s keep-alive
      ApiClient.send("GET", url, null, Collections.emptyMap()).get(5, TimeUnit.SECONDS);
      assertEquals(2, ports.size());
      assertNotEquals(ports.get(0), ports.get(1), "second request reused the idle connection");
    } finally {
      server.stop(0);
    }
  }
}
