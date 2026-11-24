package com.unimo.sdk.client;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.concurrent.TimeUnit;
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

  @Test
  void anOpenSocketsTokenIsRefreshedBeforeTheGatewayLetsItExpire() {
    // The gateway's tokens last 2 hours whether used or not, and an open socket is never asked for
    // its token again: refreshed at 90 minutes, no request meets an expired one.
    assertFalse(Connection.isTokenDue(true, TimeUnit.MINUTES.toMillis(89)), "still fresh");
    assertTrue(Connection.isTokenDue(true, TimeUnit.MINUTES.toMillis(90)), "due");
    // A socket that is down has its token refreshed by the rejected upgrade instead.
    assertFalse(Connection.isTokenDue(false, TimeUnit.HOURS.toMillis(3)), "socket down");
  }
}
