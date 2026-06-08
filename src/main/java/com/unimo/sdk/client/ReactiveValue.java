package com.unimo.sdk.client;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;

/**
 * Dependency-free observable state holder (port of {@code sdk/ts/src_ts/client/ReactiveValue.ts},
 * refined for Java/Android DX). Deliberately neutral — no Android, coroutines, or reactive-streams
 * dependency — so the SDK stays pure-JVM and unit-testable. Adapt to the UI layer at the edge:
 *
 * <pre>{@code
 * // LiveData (Views / Java):
 * MutableLiveData<T> ld = new MutableLiveData<>(rv.get());
 * rv.subscribe(ld::postValue);
 *
 * // StateFlow (Compose / Kotlin):
 * val flow = MutableStateFlow(rv.get())
 * rv.subscribe { flow.value = it }   // collectAsState() in the composable
 * }</pre>
 *
 * Notifications fire synchronously on the mutating thread; UI adapters marshal to the main thread
 * ({@code postValue} / a main dispatcher). Listener storage is thread-safe.
 */
public final class ReactiveValue<T> {
  /** Unsubscribe handle; {@link AutoCloseable} so it works with try-with-resources. */
  public interface Subscription extends AutoCloseable {
    @Override
    void close();
  }

  private volatile T value;
  private final Set<Consumer<T>> listeners = ConcurrentHashMap.newKeySet();

  public ReactiveValue(T initial) {
    this.value = initial;
  }

  public T get() {
    return value;
  }

  public void set(T next) {
    this.value = next;
    notifyListeners(next);
  }

  /** Mutate the current value in place, then notify (mirror of the TS {@code update}). */
  public void update(Consumer<T> mutator) {
    mutator.accept(value);
    notifyListeners(value);
  }

  /** Subscribe and receive the current value immediately, then on every change (LiveData/StateFlow
   *  semantics — new observers get initial state). Returns an unsubscribe handle. */
  public Subscription subscribe(Consumer<T> listener) {
    listeners.add(listener);
    safe(listener, value);
    return () -> listeners.remove(listener);
  }

  /** Subscribe to future changes only (no immediate delivery) — matches the TS {@code subscribe}. */
  public Subscription onChange(Consumer<T> listener) {
    listeners.add(listener);
    return () -> listeners.remove(listener);
  }

  private void notifyListeners(T v) {
    for (Consumer<T> l : listeners) safe(l, v);
  }

  private void safe(Consumer<T> l, T v) {
    try {
      l.accept(v);
    } catch (RuntimeException e) {
      System.err.println("ReactiveValue listener error: " + e);
    }
  }
}
