package com.unimo.sdk.client.collections;

import com.unimo.sdk.client.ReactiveValue;
import com.unimo.sdk.crypto.CodedException;
import com.unimo.sdk.shared.Consts;
import com.unimo.sdk.shared.Helpers;
import com.unimo.sdk.shared.Json;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Port of {@code sdk/ts/src_ts/client/collections/KV.ts}. A key→value map collection whose values
 * are JSON-compatible ({@code String}, {@code Long}, {@code Double}, {@code Boolean}, nested
 * {@code Map}/{@code List}, or null). Local edits accumulate in {@code pending} until the owning
 * {@link CollectionController} persists them. The reactive {@link #data} drives UI bindings.
 */
public final class KVContent {
  public final ReactiveValue<Map<String, Object>> data = new ReactiveValue<>(new LinkedHashMap<>());

  private static final class Pending {
    final boolean delete;
    final Object value;

    Pending(boolean delete, Object value) {
      this.delete = delete;
      this.value = value;
    }
  }

  private final Map<String, Pending> pending = new LinkedHashMap<>();

  public KVContent() {}

  public KVContent(Map<String, Object> initial) {
    if (initial != null) data.set(new LinkedHashMap<>(initial));
  }

  @SuppressWarnings("unchecked")
  public static KVContent deserialize(byte[] bytes) {
    if (bytes.length == 0) return new KVContent();
    return new KVContent((Map<String, Object>) Json.parse(Helpers.fromUtf8(bytes)));
  }

  /** Serialize the map to a JSON object (UTF-8). Order-free: the blob is parsed, never hashed. */
  public byte[] serialize() {
    return Helpers.utf8(Json.canonical(data.get()));
  }

  public Object get(String key) {
    return data.get().get(key);
  }

  public void set(String key, Object value) {
    validateKey(key);
    pending.put(key, new Pending(false, value));
    data.update(m -> m.put(key, value));
  }

  public boolean delete(String key) {
    boolean had = data.get().containsKey(key);
    if (had) {
      pending.put(key, new Pending(true, null));
      data.update(m -> m.remove(key));
    }
    return had;
  }

  public boolean has(String key) {
    return data.get().containsKey(key);
  }

  public Set<String> keys() {
    return new LinkedHashMap<>(data.get()).keySet();
  }

  /**
   * Replace the local map with a remote snapshot, then re-apply local pending edits. The remote is
   * the base, not a union with the local map: a key another device deleted must not survive here,
   * or this device's next save re-uploads it.
   */
  public void merge(KVContent remote) {
    Map<String, Object> merged = new LinkedHashMap<>(remote.data.get());
    for (Map.Entry<String, Pending> e : pending.entrySet()) {
      if (e.getValue().delete) merged.remove(e.getKey());
      else merged.put(e.getKey(), e.getValue().value);
    }
    data.set(merged);
  }

  /** Non-null (a snapshot of pending edits) when there are unsaved changes, else null. */
  public Map<String, Object> getPendingChanges() {
    if (pending.isEmpty()) return null;
    Map<String, Object> out = new LinkedHashMap<>();
    for (Map.Entry<String, Pending> e : pending.entrySet()) out.put(e.getKey(), e.getValue().value);
    return out;
  }

  public void clearPending() {
    pending.clear();
  }

  private void validateKey(String key) {
    if (Helpers.utf8(key).length > Consts.KV_KEY_SIZE_LIMIT_BYTES) {
      throw new CodedException("Key exceeds " + Consts.KV_KEY_SIZE_LIMIT_BYTES + " bytes", "KEY_TOO_LARGE");
    }
  }
}
