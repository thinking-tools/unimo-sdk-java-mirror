package com.unimo.sdk.client;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.unimo.sdk.Client;
import com.unimo.sdk.crypto.CryptoUtils;
import com.unimo.sdk.shared.Consts;
import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import okhttp3.Dispatcher;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * {@link Account#destroy} ends the requests of its account: those it still waits for, and any made
 * later. On a network that is connected but dead they used to run into their timeout, one after
 * the other, and whoever waited for them (an app's logout clean-up, behind a save on the same
 * thread) waited that long too.
 */
class AccountDestroyTest {
  private static final String ACCOUNT = "twologins";
  private static final String UNANSWERED = "/api/storage/";
  private static final byte[] FILE_KEY = new byte[32];
  /** OkHttp sends this many requests to one host at a time: a further one waits its turn. */
  private static final int SENT_AT_ONCE = new Dispatcher().getMaxRequestsPerHost();

  private StandInGateway gateway;
  private Account leaving;
  private Account staying;

  @BeforeEach
  void logInTwice() throws Exception {
    gateway = new StandInGateway();
    Client client = new Client(gateway.url());
    byte[] seed = CryptoUtils.generateRandomBytes(Consts.DEFAULT_SEED_LENGTH_BYTES);
    await(client.register(ACCOUNT, "a@example.com", "laptop", seed));
    // The same device logged in twice: the two differ in nothing but being two accounts.
    leaving = await(client.loginAccount(ACCOUNT, seed, false));
    staying = await(client.loginAccount(ACCOUNT, seed, false));
  }

  @AfterEach
  void stopGateway() {
    gateway.stop();
  }

  @Test
  void aRequestTheGatewayNeverAnswersFailsAtOnceAndAnotherAccountsGoesOn() throws Exception {
    CountDownLatch arrived = gateway.leaveUnanswered(UNANSWERED, 2);
    CompletableFuture<Tasker.DownloadResult> cut = leaving.download("left", FILE_KEY);
    CompletableFuture<Tasker.DownloadResult> kept = staying.download("stayed", FILE_KEY);
    assertTrue(arrived.await(5, TimeUnit.SECONDS), "the requests never reached the gateway");

    leaving.destroy();

    assertFailsAtOnce(cut);
    assertThrows(TimeoutException.class, () -> kept.get(200, TimeUnit.MILLISECONDS));
  }

  @Test
  void aRequestStillWaitingItsTurnFailsAtOnceToo() throws Exception {
    CountDownLatch arrived = gateway.leaveUnanswered(UNANSWERED, SENT_AT_ONCE);
    for (int i = 0; i < SENT_AT_ONCE; i++) staying.download("stayed" + i, FILE_KEY);
    assertTrue(arrived.await(5, TimeUnit.SECONDS), "the requests never reached the gateway");
    // Behind those this one is not sent, and OkHttp has no word of its cancel before it would be.
    CompletableFuture<ApiClient.ApiResponse> unsent = leaving.vault().invokeAuthed("GET", UNANSWERED + "unsent", null);

    leaving.destroy();

    assertFailsAtOnce(unsent);
  }

  @Test
  void aRequestMadeAfterwardsFailsAtOnceUnsentAndAnotherAccountsIsAnswered() throws Exception {
    CountDownLatch arrived = gateway.leaveUnanswered(UNANSWERED, 1);

    leaving.destroy();

    assertFailsAtOnce(leaving.vault().invokeAuthed("GET", UNANSWERED + "late", null));
    assertFalse(arrived.await(200, TimeUnit.MILLISECONDS), "the request was sent");
    await(staying.vault().timeToFetchUpdate());
  }

  /** As a lost connection fails it, and well within a second. */
  private static void assertFailsAtOnce(CompletableFuture<?> request) {
    ExecutionException failed = assertThrows(ExecutionException.class, () -> request.get(1, TimeUnit.SECONDS));
    assertInstanceOf(IOException.class, failed.getCause());
  }

  private static <T> T await(CompletableFuture<T> pending) throws Exception {
    return pending.get(20, TimeUnit.SECONDS);
  }
}
