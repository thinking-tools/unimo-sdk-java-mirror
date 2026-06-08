package com.unimo.sdk.client;

import com.unimo.sdk.crypto.CodedException;
import com.unimo.sdk.shared.Json;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

/**
 * Port of {@code sdk/ts/src_ts/client/Billing.ts} — the Stripe-backed subscription surface.
 * {@code listPlans} is the public catalog; the rest are bearer-authed and inherit the vault's
 * single-attempt 401→reauth retry (via {@link VaultController#invokeAuthed}). Subscription change
 * notifications arrive as {@code vault:event} frames (kind {@code subscription_changed}) once the
 * WebSocket {@code Connection} lands.
 */
public final class Billing {
  private final String serviceUrl;
  private final VaultController vault;

  public Billing(String serviceUrl, VaultController vault) {
    this.serviceUrl = serviceUrl.replaceAll("/+$", "");
    this.vault = vault;
  }

  /** Public plan catalog. */
  @SuppressWarnings("unchecked")
  public CompletableFuture<List<Object>> listPlans() {
    return ApiClient.makeRequest("GET", serviceUrl + "/api/billing/plans", null)
        .thenApply(
            b -> {
              if (!Boolean.TRUE.equals(b.get("ok"))) throw new CodedException("listPlans failed", "BILLING_FAILED");
              return (List<Object>) b.get("plans");
            });
  }

  /** Current subscription state, or null when the vault has never subscribed. */
  @SuppressWarnings("unchecked")
  public CompletableFuture<Map<String, Object>> getState() {
    return vault
        .invokeAuthed("GET", "/api/billing/state", null)
        .thenApply(
            resp -> {
              if (!resp.ok()) throw new CodedException("getState HTTP " + resp.status, "BILLING_FAILED");
              Map<String, Object> b = resp.jsonObject();
              if (!Boolean.TRUE.equals(b.get("ok"))) throw new CodedException("getState failed", "BILLING_FAILED");
              return Boolean.TRUE.equals(b.get("initialized")) ? (Map<String, Object>) b.get("state") : null;
            });
  }

  /** Start a Checkout session → Stripe-hosted URL (open via the platform browser). */
  public CompletableFuture<String> createCheckout(String planId) {
    return vault
        .invokeAuthed("POST", "/api/billing/checkout", Json.obj("planId", planId))
        .thenApply(resp -> requireUrl(resp, "createCheckout"));
  }

  /** Open the Stripe Billing Portal (cancel / change plan / update card). */
  public CompletableFuture<String> createPortal() {
    return vault.invokeAuthed("POST", "/api/billing/portal", Json.obj()).thenApply(resp -> requireUrl(resp, "createPortal"));
  }

  private static String requireUrl(ApiClient.ApiResponse resp, String op) {
    Map<String, Object> b = resp.jsonObject();
    if (!resp.ok() || !Boolean.TRUE.equals(b.get("ok")) || b.get("url") == null) {
      throw new CodedException(op + " failed: " + resp.status + " " + b.get("error"), "BILLING_FAILED");
    }
    return (String) b.get("url");
  }
}
