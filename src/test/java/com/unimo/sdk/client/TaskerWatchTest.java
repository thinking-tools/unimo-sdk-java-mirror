package com.unimo.sdk.client;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.unimo.sdk.shared.Json;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;

/**
 * The WS watch plane ({@link Tasker#route}, {@link Tasker#catchUp}). {@code vault:event} frames are
 * live-only: a phone that dozed through another device's edit never receives that frame, so
 * without the open-time catch-up its collections stay stale until something reloads them — which
 * is exactly what the launcher used to paper over by re-downloading every collection on resume.
 */
class TaskerWatchTest {

  /** Records the version each refresh was asked for (null = "unknown, probe"). */
  private static final class Rec implements Tasker.Watch {
    final List<Integer> calls = new ArrayList<>();
    final boolean changed;

    Rec(boolean changed) {
      this.changed = changed;
    }

    @Override
    public CompletableFuture<Boolean> refresh(Integer knownVersion) {
      calls.add(knownVersion);
      return CompletableFuture.completedFuture(changed);
    }
  }

  private static Tasker live() {
    return new Tasker("http://localhost", new Connection("http://localhost", null));
  }

  @Test
  void framesReachOnlyTheirWatchWithTheAnnouncedVersion() {
    Tasker t = live();
    Rec manifest = new Rec(false);
    Rec notes = new Rec(false);
    t.hook("v1", manifest).files.put("notes", notes);

    t.route(Json.obj("vaultId", "v1", "kind", "blob_put", "fileId", "notes", "version", 7L));
    t.route(Json.obj("vaultId", "v1", "kind", "head_changed", "fileId", "notes", "head", 8L));
    t.route(Json.obj("vaultId", "v1", "kind", "manifest_updated", "version", 3L));
    // Other vault, unwatched file, fileless presence: no request may follow.
    t.route(Json.obj("vaultId", "v2", "kind", "blob_put", "fileId", "notes", "version", 9L));
    t.route(Json.obj("vaultId", "v1", "kind", "blob_put", "fileId", "other", "version", 1L));
    t.route(Json.obj("vaultId", "v1", "kind", "presence", "members", new ArrayList<>()));

    // The version rides along so a watch can skip a change it already holds (its own upload).
    assertEquals(Arrays.asList(7, 8), notes.calls);
    assertEquals(Arrays.asList(3), manifest.calls);
  }

  @Test
  void reopenProbesEverythingWatched() {
    Tasker t = live();
    Rec manifest = new Rec(false);
    Rec notes = new Rec(false);
    Rec history = new Rec(false);
    Tasker.VaultWatch w = t.hook("v1", manifest);
    w.files.put("notes", notes);
    w.files.put("history", history);

    t.catchUp();

    // null = no frame to trust: each watch must probe the server itself.
    List<Integer> probe = new ArrayList<>();
    probe.add(null);
    assertEquals(probe, manifest.calls);
    assertEquals(probe, notes.calls);
    assertEquals(probe, history.calls);
  }

  @Test
  void onlyMergedRemoteStateNotifiesTheApp() {
    Tasker t = live();
    List<String> notified = new ArrayList<>();
    t.onRemoteChange(notified::add);
    Tasker.VaultWatch w = t.hook("v1", new Rec(true));
    w.files.put("unchanged", new Rec(false));
    w.files.put("changed", new Rec(true));

    t.catchUp();

    // An up-to-date probe must stay silent, or every reconnect would trigger an app-side sync;
    // the id tells each consumer whether the change is theirs (null = the manifest).
    assertEquals(Arrays.asList(null, "changed"), notified);
  }
}
