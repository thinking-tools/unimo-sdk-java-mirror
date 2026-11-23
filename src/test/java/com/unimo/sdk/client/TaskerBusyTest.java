package com.unimo.sdk.client;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.unimo.sdk.shared.Helpers;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * Retry policy of the head commit ({@link Tasker#retryWhileBusy}). Writes that move a file's head
 * run one at a time on the gateway. One that outwaits another gets 503 {@code BUSY} with a {@code
 * Retry-After}: nothing was done, so the commit is sent again instead of failing the upload (and,
 * for a multi-chunk file, throwing away every chunk already uploaded).
 */
class TaskerBusyTest {

  private static ApiClient.ApiResponse resp(int status, String json, Map<String, String> headers) {
    return new ApiClient.ApiResponse(status, Helpers.utf8(json), headers);
  }

  private static final ApiClient.ApiResponse BUSY =
      resp(503, "{\"code\":\"BUSY\"}", Collections.singletonMap("retry-after", "1"));
  private static final ApiClient.ApiResponse COMMITTED = resp(201, "{\"version\":2}", new HashMap<>());

  private static final class Rig {
    final ApiClient.ApiResponse[] answers;
    final AtomicInteger sends = new AtomicInteger();
    final List<Long> waits = new ArrayList<>();

    Rig(ApiClient.ApiResponse... answers) {
      this.answers = answers;
    }

    ApiClient.ApiResponse run() {
      return Tasker.retryWhileBusy(() -> answers[sends.getAndIncrement()], waits::add);
    }
  }

  @Test
  void busyCommitIsSentAgainAfterTheWaitTheGatewayNames() {
    Rig rig = new Rig(BUSY, COMMITTED);
    assertEquals(201, rig.run().status);
    assertEquals(2, rig.sends.get());
    assertEquals(Collections.singletonList(1000L), rig.waits);
  }

  @Test
  void givesUpAfterThreeMoreBusyAnswers() {
    Rig rig = new Rig(BUSY, BUSY, BUSY, BUSY);
    assertEquals(503, rig.run().status);
    assertEquals(4, rig.sends.get());
  }

  @Test
  void a503ThatIsNotBusyIsNotRepeated() {
    Rig rig = new Rig(resp(503, "{\"error\":\"storage unavailable\"}", new HashMap<>()));
    assertEquals(503, rig.run().status);
    assertEquals(1, rig.sends.get(), "no retry");
  }

  @Test
  void a503WithoutAJsonBodyIsNotRepeated() {
    Rig rig = new Rig(resp(503, "<html>bad gateway</html>", new HashMap<>()));
    assertEquals(503, rig.run().status);
    assertEquals(1, rig.sends.get(), "no retry");
  }
}
