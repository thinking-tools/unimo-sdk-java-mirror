package com.unimo.sdk.client;

import com.unimo.sdk.client.collections.CollectionController;
import com.unimo.sdk.client.collections.KVContent;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.function.Consumer;

/**
 * Minimal port of {@code sdk/ts/src_ts/client/Account.ts}: wraps a {@link VaultController} with a
 * {@link Tasker}, {@link Billing}, and (when {@code keepAlive}) a live {@link Connection}, exposing
 * the common surface so callers don't thread a Tasker through every call; with a live connection,
 * loaded collections stay current on their own (see {@link #onRemoteChange}). The TS reactive
 * task-list is deferred. Network awareness is the app's job: wire OS connectivity events into
 * {@link Connection#networkLost()} / {@link Connection#networkAvailable()} via {@link
 * #connection()} — see the README; that wiring is what recovers a dropped socket. {@link
 * #onRevoked} tells the app when the gateway no longer accepts this device.
 */
public final class Account {
  private final String serviceUrl;
  private final VaultController vault;
  private final Tasker tasker;
  private final Billing billing;
  private final Connection connection; // null when keepAlive=false
  private final Search search; // null when keepAlive=false

  public Account(String serviceUrl, VaultController vault, boolean keepAlive) {
    this.serviceUrl = serviceUrl;
    this.vault = vault;
    this.billing = new Billing(serviceUrl, vault);
    if (keepAlive) {
      this.connection = new Connection(serviceUrl, vault);
      this.tasker = new Tasker(serviceUrl, connection);
      this.tasker.hookVault(vault); // before start(): the first open's catch-up must see the hook
      this.connection.start();
      this.search = new Search(this.connection);
    } else {
      this.connection = null;
      this.tasker = new Tasker(serviceUrl);
      this.search = null;
    }
  }

  /** Called once, from an SDK thread, when the gateway no longer accepts this device because a
   *  manager removed it (a reauth answered {@code NOT_A_MEMBER}); the live connection is stopped
   *  first. The host should drop the session and wipe the account's local data. */
  public void onRevoked(Runnable callback) {
    vault.onRevoked = () -> {
      if (connection != null) connection.stop();
      callback.run();
    };
  }

  public VaultController vault() {
    return vault;
  }

  public Tasker tasker() {
    return tasker;
  }

  public Billing billing() {
    return billing;
  }

  /** Live WebSocket (or null when keepAlive=false). */
  public Connection connection() {
    return connection;
  }

  /** WebSocket search over the live connection (or null when keepAlive=false). */
  public Search search() {
    return search;
  }

  public boolean isManagerMember() {
    return vault.isManagerMember();
  }

  public String getServiceUrl() {
    return serviceUrl;
  }

  // ── storage ──
  public CompletableFuture<Tasker.UploadResult> upload(String fileId, byte[] data, byte[] encKey, Integer expectedVersion) {
    return tasker.upload(vault, fileId, data, encKey, expectedVersion);
  }

  public CompletableFuture<Tasker.DownloadResult> download(String fileId, byte[] encKey) {
    return tasker.download(vault, fileId, encKey);
  }

  /** Soft-delete a file; see {@link Tasker#delete}. */
  public CompletableFuture<Tasker.DeleteResult> delete(String fileId) {
    return tasker.delete(vault, fileId);
  }

  // ── collections ──
  public List<CollectionController> listCollections() {
    return vault.listCollections();
  }

  public CompletableFuture<KVContent> createNewCollection(String name, String type) {
    return vault.createCollection(name, type, tasker);
  }

  public CompletableFuture<KVContent> getCollection(String name) {
    return vault.getCollectionByName(tasker, name);
  }

  // ── members + invites ──
  public CompletableFuture<Map<String, Object>> addMemberWithSeed(byte[] seed, String name, String role, String note) {
    return vault.addMemberWithSeed(seed, name, role, note);
  }

  public CompletableFuture<Boolean> removeMember(String memberId) {
    return vault.removeMember(memberId);
  }

  public CompletableFuture<VaultController.InviteCreated> createInvite(String role, Integer ttlSeconds) {
    return vault.createInvite(role, ttlSeconds);
  }

  public CompletableFuture<Map<String, Object>> finalizeInvite(String inviteId) {
    return vault.finalizeInvite(inviteId);
  }

  /**
   * Run {@code listener} (on an SDK thread) after remote changes were merged locally — from a live
   * {@code vault:event} push or the catch-up after every WebSocket reconnect. It receives the
   * collection's name for a loaded collection's content (collections are watched once loaded via
   * {@link #getCollection}), or null for the manifest (members, collections list — a collection
   * another device just created shows up here). Never fires when keepAlive=false.
   */
  public ReactiveValue.Subscription onRemoteChange(Consumer<String> listener) {
    return tasker.onRemoteChange(
        colId -> {
          if (colId == null) {
            listener.accept(null);
            return;
          }
          for (CollectionController c : vault.listCollections()) {
            if (colId.equals(c.getId())) {
              listener.accept(c.getName());
              return;
            }
          }
        });
  }

  /** Subscribe to live {@code vault:event} frames (no-op when keepAlive=false). */
  public ReactiveValue.Subscription onVaultEvent(Connection.Handler handler) {
    return connection != null ? connection.on("vault:event", handler) : () -> {};
  }

  public void destroy() {
    if (connection != null) connection.stop();
  }
}
