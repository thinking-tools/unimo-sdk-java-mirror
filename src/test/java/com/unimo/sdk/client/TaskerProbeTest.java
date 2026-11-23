package com.unimo.sdk.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.unimo.sdk.crypto.CodedException;
import com.unimo.sdk.shared.Consts;
import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * What the upload reads from the HEAD probe ({@link Tasker.Probe}) and sends with the commit. A head
 * commit the gateway could not store keeps its version number, so the next commit is not issued
 * {@code head + 1}; a multi-chunk upload that put its chunks there anyway committed a head pointing
 * at nothing. The chunks go under the version the gateway names, and the commit names it.
 */
class TaskerProbeTest {

  private static Tasker.Probe probe(int status, String head, String nextVersion) {
    Map<String, String> headers = new HashMap<>();
    if (head != null) headers.put(Consts.HEADER_STORAGE_VERSION, head);
    if (nextVersion != null) headers.put(Consts.HEADER_STORAGE_NEXT_VERSION, nextVersion);
    return Tasker.Probe.of(new ApiClient.ApiResponse(status, new byte[0], headers));
  }

  private static void assertProbe(int head, int nextVersion, Tasker.Probe probe) {
    assertEquals(head, probe.head);
    assertEquals(nextVersion, probe.nextVersion);
  }

  @Test
  void nextVersionIsTheOneTheGatewayNames() {
    assertProbe(1, 3, probe(200, "1", "3"));
  }

  @Test
  void fileWithoutAHeadCanStillHaveUsedVersions() {
    assertProbe(0, 2, probe(404, null, "2"));
  }

  @Test
  void gatewayThatNamesNoNextVersionIssuesHeadPlusOne() {
    assertProbe(1, 2, probe(200, "1", null));
    assertProbe(0, 1, probe(404, null, null));
  }

  @Test
  void multiChunkCommitPinsTheProbedHeadAndNamesTheVersionOfItsChunks() {
    Map<String, String> headers = Tasker.multiChunkCommitHeaders(2, probe(200, "1", "3"));
    assertEquals("2", headers.get(Consts.HEADER_CHUNK_COUNT));
    assertEquals("1", headers.get(Consts.HEADER_EXPECTED_VERSION));
    assertEquals("3", headers.get(Consts.HEADER_CHUNK_VERSION));
  }

  @Test
  void trashedFileIsRefused() {
    assertEquals("TRASHED", assertThrows(CodedException.class, () -> probe(410, null, null)).getCode());
  }
}
