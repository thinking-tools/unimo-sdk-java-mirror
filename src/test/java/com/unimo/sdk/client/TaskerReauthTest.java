package com.unimo.sdk.client;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HashMap;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * Retry policy of the storage path ({@link Tasker#withReauth}). Gateway tokens expire after 2h
 * while the WebSocket (validated only at upgrade) stays open, so an unlocked-overnight phone keeps
 * its socket but every storage GET/PUT starts 401ing. Before this policy existed the Tasker threw
 * on the first 401 and nothing ever reauthed — notes/contacts/notification sync stayed dead until
 * the next manual unlock.
 */
class TaskerReauthTest {

  private static ApiClient.ApiResponse resp(int status) {
    return new ApiClient.ApiResponse(status, new byte[0], new HashMap<>());
  }

  private static final class Rig {
    final int[] statuses;
    final boolean reauthOk;
    final AtomicInteger sends = new AtomicInteger();
    final AtomicInteger reauths = new AtomicInteger();

    Rig(boolean reauthOk, int... statuses) {
      this.reauthOk = reauthOk;
      this.statuses = statuses;
    }

    ApiClient.ApiResponse run() {
      return Tasker.withReauth(
              () -> CompletableFuture.completedFuture(resp(statuses[sends.getAndIncrement()])),
              () -> {
                reauths.incrementAndGet();
                return CompletableFuture.completedFuture(reauthOk);
              })
          .join();
    }
  }

  @Test
  void expiredTokenReauthsAndRetriesOnce() {
    Rig rig = new Rig(true, 401, 201);
    assertEquals(201, rig.run().status);
    assertEquals(2, rig.sends.get(), "one retry after the refresh");
    assertEquals(1, rig.reauths.get());
  }

  @Test
  void rejectedReauthSurfacesTheOriginal401() {
    // REJECTED/TRANSIENT reauth → false: don't spin, hand the 401 back so the caller throws as before.
    Rig rig = new Rig(false, 401, 201);
    assertEquals(401, rig.run().status);
    assertEquals(1, rig.sends.get(), "no retry without a fresh token");
    assertEquals(1, rig.reauths.get());
  }

  @Test
  void non401FailuresNeverReauth() {
    Rig rig = new Rig(true, 500);
    assertEquals(500, rig.run().status);
    assertEquals(1, rig.sends.get());
    assertEquals(0, rig.reauths.get());
  }
}
