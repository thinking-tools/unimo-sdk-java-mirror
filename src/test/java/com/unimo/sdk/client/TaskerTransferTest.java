package com.unimo.sdk.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.unimo.sdk.shared.Consts;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;

/**
 * {@link Tasker#inTurns}: a large file goes a few chunks at a time, so its size does not decide how
 * much of it is held in memory at once.
 */
class TaskerTransferTest {
  private static final int JOBS = Consts.TRANSFER_CONCURRENCY + 2;
  private static final ScheduledExecutorService LATER =
      Executors.newSingleThreadScheduledExecutor(
          r -> {
            Thread t = new Thread(r, "transfer-test");
            t.setDaemon(true);
            return t;
          });

  /** Jobs that each take a moment. Counts how many were started and how many ran at once. */
  private static final class Jobs {
    final AtomicInteger started = new AtomicInteger();
    final AtomicInteger mostInFlight = new AtomicInteger();
    private final AtomicInteger inFlight = new AtomicInteger();
    private final int failing;

    /** {@code failing}: the index of the job that fails, sooner than the others finish; -1 for none. */
    Jobs(int failing) {
      this.failing = failing;
    }

    CompletableFuture<Integer> run(int index) {
      started.incrementAndGet();
      mostInFlight.accumulateAndGet(inFlight.incrementAndGet(), Math::max);
      CompletableFuture<Integer> done = new CompletableFuture<>();
      LATER.schedule(
          () -> {
            inFlight.decrementAndGet();
            if (index == failing) done.completeExceptionally(new IllegalStateException("chunk " + index + " failed"));
            else done.complete(index);
          },
          index == failing ? 10 : 60,
          TimeUnit.MILLISECONDS);
      return done;
    }
  }

  @Test
  void aFewJobsRunAtATimeAndTheResultsComeBackInOrder() {
    Jobs jobs = new Jobs(-1);
    List<Integer> everyIndex = IntStream.range(0, JOBS).boxed().collect(Collectors.toList());

    assertEquals(everyIndex, Tasker.inTurns(JOBS, jobs::run, () -> false));
    assertEquals(Consts.TRANSFER_CONCURRENCY, jobs.mostInFlight.get());
  }

  @Test
  void noFurtherJobStartsOnceOneHasFailed() {
    Jobs jobs = new Jobs(0);

    assertThrows(CompletionException.class, () -> Tasker.inTurns(JOBS, jobs::run, () -> false));
    assertEquals(Consts.TRANSFER_CONCURRENCY, jobs.started.get());
  }

  @Test
  void noFurtherJobStartsOnceToldToStop() {
    Jobs jobs = new Jobs(-1);

    assertEquals(Arrays.asList(0, 1), Tasker.inTurns(JOBS, jobs::run, () -> jobs.started.get() == 2));
  }
}
