package com.unimo.sdk.client;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Reauth-classification predicate extracted from {@link Connection}'s OkHttp callbacks, tested in
 * isolation: which WS-upgrade failure statuses mean the token is bad (reauth, then reopen) versus
 * infra trouble (stay down until the next network event).
 */
class ConnectionRecoveryTest {

  @Test
  void authRejectionsOnUpgradeTriggerReauth() {
    // 401 = expired/invalid token (the overnight cause); 410 = manifest missing. Both mean the
    // token is bad and reconnecting with it loops forever — reauth instead.
    assertTrue(Connection.shouldReauthAfterUpgradeFailure(401), "401 expired token");
    assertTrue(Connection.shouldReauthAfterUpgradeFailure(410), "410 manifest missing");
  }

  @Test
  void nonAuthUpgradeFailuresDoNotReauth() {
    // Transport errors surface as a null Response (status 0 here); 5xx/403/… are infra/policy —
    // the token is fine, so no reauth: recovery waits for the next network event.
    assertFalse(Connection.shouldReauthAfterUpgradeFailure(0), "transport error (no response)");
    assertFalse(Connection.shouldReauthAfterUpgradeFailure(500), "500");
    assertFalse(Connection.shouldReauthAfterUpgradeFailure(503), "503");
    assertFalse(Connection.shouldReauthAfterUpgradeFailure(403), "403");
  }
}
