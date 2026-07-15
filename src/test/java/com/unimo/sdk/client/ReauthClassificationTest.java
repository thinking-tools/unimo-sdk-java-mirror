package com.unimo.sdk.client;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Retryability of {@code POST /api/auth/reauth} responses, as decided by {@link
 * VaultController#classifyReauth}. The gateway's statuses (route in {@code
 * secure.gateway.unimo/src/users/routes.ts}) split into three outcomes — and the split is
 * load-bearing: a misclassified transient response used to fold into {@code false} and halt the
 * WebSocket reconnect chain permanently (the overnight search outage of 2026-07-15).
 */
class ReauthClassificationTest {

  private static Map<String, Object> body(Object ok, Object authToken) {
    Map<String, Object> b = new HashMap<>();
    if (ok != null) b.put("ok", ok);
    if (authToken != null) b.put("authToken", authToken);
    return b;
  }

  @Test
  void refreshTokenIsRefreshed() {
    // 2xx + ok:true + non-null authToken is the only success — adopt the token, reconnect fast.
    assertEquals(
        VaultController.ReauthOutcome.REFRESHED,
        VaultController.classifyReauth(200, body(true, "tok")),
        "200 ok+token refreshes");
    assertEquals(
        VaultController.ReauthOutcome.REFRESHED,
        VaultController.classifyReauth(204, body(true, "tok")),
        "any 2xx with ok+token refreshes");
    assertEquals(
        VaultController.ReauthOutcome.REFRESHED,
        VaultController.classifyReauth(200, body(true, " ")),
        "whitespace authToken refreshes — TS does no trim, so match its truthiness");
  }

  @Test
  void definitiveRejectionsAreRejected() {
    // 404 account gone, 401 bad signature/revoked, 403 member removed — the server is saying this
    // member/account is done. Retrying forever would spin; halting the chain is correct.
    assertEquals(VaultController.ReauthOutcome.REJECTED, VaultController.classifyReauth(404, null), "404 vault gone");
    assertEquals(VaultController.ReauthOutcome.REJECTED, VaultController.classifyReauth(401, null), "401 invalid reauth");
    assertEquals(VaultController.ReauthOutcome.REJECTED, VaultController.classifyReauth(403, null), "403 member removed");
  }

  @Test
  void malformedSuccessIsRejected() {
    // 2xx without ok+authToken is a gateway/version skew: not a usable refresh, don't adopt garbage.
    assertEquals(VaultController.ReauthOutcome.REJECTED, VaultController.classifyReauth(200, body(false, "tok")), "ok:false");
    assertEquals(VaultController.ReauthOutcome.REJECTED, VaultController.classifyReauth(200, body(true, null)), "missing authToken");
    assertEquals(VaultController.ReauthOutcome.REJECTED, VaultController.classifyReauth(200, null), "null body");
    // Empty-string authToken: TS `if (response.authToken)` is falsy for "" — a broken refresh; reject
    // rather than adopt an empty Bearer (which would 401-loop the reconnect at the 250ms floor).
    assertEquals(VaultController.ReauthOutcome.REJECTED, VaultController.classifyReauth(200, body(true, "")), "empty-string authToken");
    // Non-String authToken: the (String) cast in doReauth would ClassCastException here (swallowed into
    // TRANSIENT = infinite retry). classifyReauth must reject before the cast ever runs.
    assertEquals(VaultController.ReauthOutcome.REJECTED, VaultController.classifyReauth(200, body(true, 123L)), "Number authToken");
    assertEquals(VaultController.ReauthOutcome.REJECTED, VaultController.classifyReauth(200, body(true, Boolean.TRUE)), "Boolean authToken");
  }

  @Test
  void transientFailuresAreTransient() {
    // 400 is the route's catch-all — it wraps infra throws (Valkey/S3), not just bad bodies, so a
    // 400 during a gateway blip must not brick the session. 409 is the replay guard: OkHttp can
    // silently duplicate the POST into it, and a fresh reqId succeeds next time. 429 is the per-vault
    // rate limit; 5xx is a proxy/LB/infra failure. All retryable.
    assertEquals(VaultController.ReauthOutcome.TRANSIENT, VaultController.classifyReauth(400, null), "400 catch-all (infra)");
    assertEquals(VaultController.ReauthOutcome.TRANSIENT, VaultController.classifyReauth(409, null), "409 replay (duplicated POST)");
    assertEquals(VaultController.ReauthOutcome.TRANSIENT, VaultController.classifyReauth(429, null), "429 rate limited");
    assertEquals(VaultController.ReauthOutcome.TRANSIENT, VaultController.classifyReauth(500, null), "500 server error");
    assertEquals(VaultController.ReauthOutcome.TRANSIENT, VaultController.classifyReauth(503, null), "503 unavailable");
  }
}
