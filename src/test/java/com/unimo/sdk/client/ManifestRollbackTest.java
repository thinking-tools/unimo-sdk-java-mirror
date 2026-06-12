package com.unimo.sdk.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.unimo.sdk.crypto.CodedException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Tier-1 manifest-rollback floor: {@link VaultController#rollbackCheckedEpoch} refuses to adopt a
 * fetched manifest whose {@code keyEpoch} is below the one already held (a replayed manifest from
 * the untrusted gateway), and fails closed on a missing/non-integer epoch.
 */
class ManifestRollbackTest {

  private static Map<String, Object> payloadWithEpoch(Object epoch) {
    Map<String, Object> p = new HashMap<>();
    p.put("keyEpoch", epoch);
    return p;
  }

  @Test
  void higherOrEqualEpochIsAdopted() {
    // Same epoch (ordinary refresh) and a forward rotation both pass, returning the fetched epoch.
    assertEquals(5L, VaultController.rollbackCheckedEpoch(5, payloadWithEpoch(5L)), "equal epoch");
    assertEquals(6L, VaultController.rollbackCheckedEpoch(5, payloadWithEpoch(6L)), "forward epoch");
    assertEquals(0L, VaultController.rollbackCheckedEpoch(0, payloadWithEpoch(0L)), "genesis epoch");
  }

  @Test
  void lowerEpochIsRejectedAsRollback() {
    CodedException ex =
        assertThrows(
            CodedException.class,
            () -> VaultController.rollbackCheckedEpoch(6, payloadWithEpoch(5L)),
            "a lower epoch is a replayed manifest and must be refused");
    assertEquals("MANIFEST_ROLLBACK", ex.getCode());
  }

  @Test
  void nonIntegerEpochFailsClosed() {
    // A structurally valid manifest always carries an integral keyEpoch; a Double, a String, an
    // explicit null, or an absent field from the untrusted server is rejected, not coerced.
    Map<String, Object> absent = new HashMap<>(); // no keyEpoch key at all
    List<Map<String, Object>> badPayloads =
        List.of(payloadWithEpoch(5.5d), payloadWithEpoch("5"), payloadWithEpoch(null), absent);
    for (Map<String, Object> payload : badPayloads) {
      CodedException ex =
          assertThrows(
              CodedException.class,
              () -> VaultController.rollbackCheckedEpoch(1, payload),
              "non-integer keyEpoch must be rejected");
      assertEquals("INVALID_MANIFEST", ex.getCode());
    }
  }
}
