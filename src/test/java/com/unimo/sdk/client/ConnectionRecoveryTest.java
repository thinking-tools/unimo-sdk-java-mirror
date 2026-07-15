package com.unimo.sdk.client;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Reconnect-recovery predicates extracted from {@link Connection}'s OkHttp callbacks, tested in
 * isolation. Both guard against the same failure class: a rejected or short-lived WebSocket upgrade
 * hot-spinning the reconnect chain at the 250ms floor instead of backing off.
 */
class ConnectionRecoveryTest {

  @Test
  void stableConnectionResetsBackoff() {
    // A socket open >= 30s was healthy; its close should reconnect fast (attempt counter reset).
    assertTrue(Connection.shouldResetBackoff(30_000L), "exactly 30s is stable");
    assertTrue(Connection.shouldResetBackoff(60_000L), "a minute is stable");
  }

  @Test
  void shortLivedSocketKeepsBackingOff() {
    // Below the floor the counter keeps climbing — this is what stops a rapid-die cycle from
    // hot-spinning at RECONNECT_INITIAL_MS.
    assertFalse(Connection.shouldResetBackoff(29_999L), "just under floor is not stable");
    assertFalse(Connection.shouldResetBackoff(1_000L), "1s is not stable");
  }

  @Test
  void neverOpenedNeverResets() {
    // A rejected upgrade (401 on the HTTP handshake) never calls onOpen, so its uptime is 0. This
    // MUST return false — otherwise a rejected upgrade borrows a stale prior timestamp and the chain
    // hot-loops against the 401-ing gateway. This is the overnight outage, precisely.
    assertFalse(Connection.shouldResetBackoff(0L), "never-opened socket must not reset backoff");
  }

  @Test
  void authRejectionsOnUpgradeTriggerReauth() {
    // 401 = expired/invalid token (the overnight cause); 410 = manifest missing. Both mean the
    // token is bad and reconnecting with it loops forever — reauth instead.
    assertTrue(Connection.shouldReauthAfterUpgradeFailure(401), "401 expired token");
    assertTrue(Connection.shouldReauthAfterUpgradeFailure(410), "410 manifest missing");
  }

  @Test
  void nonAuthUpgradeFailuresJustReconnect() {
    // Transport errors surface as a null Response (status 0 here); 5xx/403/… are infra/policy — the
    // token is fine, so a plain reconnect (not a reauth) is the right response.
    assertFalse(Connection.shouldReauthAfterUpgradeFailure(0), "transport error (no response)");
    assertFalse(Connection.shouldReauthAfterUpgradeFailure(500), "500");
    assertFalse(Connection.shouldReauthAfterUpgradeFailure(503), "503");
    assertFalse(Connection.shouldReauthAfterUpgradeFailure(403), "403");
  }
}
