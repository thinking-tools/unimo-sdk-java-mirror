# unimo-sdk-java

[![Release](https://jitpack.io/v/org.codeberg.thinking_tools/unimo-sdk-java.svg)](https://jitpack.io/#org.codeberg.thinking_tools/unimo-sdk-java)

Java/Android port of the TypeScript E2EE client SDK (`sdk/ts`). Post-quantum (ML-DSA-87 +
ML-KEM-1024), cSHAKE256-derived identities, AES-256-GCM content encryption — wire-compatible
with the gateway and the TS SDK.

## Status

| Phase | Scope | State |
|---|---|---|
| 0 | Scaffold + cross-language conformance harness | ✅ done |
| 1 | `crypto` + `shared` (byte-exact interop foundation) | ✅ done |
| 2 | Identity: `Members`, `Validators`, register/login, `deriveKeys` unlock, `ApiClient` (OkHttp) | ✅ done — **live-verified** vs gateway (register→login→unlock) |
| 3 | `VaultController`: manifest CAS PUT/GET, member add/remove + key rotation, reauth | ✅ done — **live-verified** (addMember+rotation, new-member login, reauth, removeMember) |
| 4 | `Tasker`: chunked storage upload/download/delete + CAS | ✅ done — **live-verified** (single + multi-chunk 8.4 MiB round-trips, CAS bump) |
| 5 | Collections/KV + `ReactiveValue` observable (dependency-free) | ✅ done — **live-verified** (create/persist/reload + survives key rotation) |
| 6a | Billing + Invites (manager-area read/write) | ✅ done — **live-verified** (create→claim→finalize→login; billing catalog/state) |
| 6b | WebSocket `Connection` (`vault:event` push) + minimal `Account` + collection watch | ✅ done — **live-verified** (real blob_put push received; Account upload/download; another device's edit merged live and after a reconnect) |
| 7 | WebSocket `Search` (typing suggestions + full web search) + `Connection` request/response | ✅ done — **live-verified** (suggest round-trip + error-frame path; full results need gateway search providers) |

**Feature-complete** vs the TypeScript SDK (the only TS gaps are also stubs there: `VFS`/`LIST`/`CRDTLIST` collection types, and the Tasker reactive task-queue/progress UI convenience). `Search` is a **Java-first** addition — the TS SDK has no search client yet; it speaks the gateway's WS `search` domain directly.

Live coverage: **43/43** in `IntegrationRunner` (email OTP → register/login/unlock · member add/remove + key rotation · reauth · single + multi-chunk encrypted storage + CAS · KV collection create/reload/rotate · billing catalog/state · full invite create→claim→finalize→login · WebSocket `vault:event` push · search suggest round-trip · Account wrapper · collection watch: live edit, reconnect catch-up, manifest update; the full search-results checks self-skip loudly when the gateway lacks working search providers; set `UNIMO_SEARCH_LIVE=1` to FAIL instead). Offline cross-language conformance: **45/45**.

**UI binding:** `ReactiveValue<T>` is a neutral, dependency-free observable (`get`/`set`/`update`/`subscribe`/`onChange`). Adapt at the UI edge — `MutableLiveData` (`rv.subscribe(ld::postValue)`) for Views/Java, or `MutableStateFlow` (`rv.subscribe { flow.value = it }`, read via `collectAsState()`) for Compose. The core stays Android-free and pure-JVM-testable.

## Dependencies (two)

- **`org.bouncycastle:bcprov-jdk18on:1.81`** — ML-DSA-87, ML-KEM-1024, cSHAKE256. Used via
  **low-level APIs** (no JCA provider registration) to avoid clashing with Android's bundled
  `com.android.org.bouncycastle`.
- **`com.squareup.okhttp3:okhttp:4.12.0`** — HTTP + WebSocket (Phase 2+).

Everything else is core JVM: AES-GCM/SHA-256 (`javax.crypto`/`java.security`), Base64/Hex
(BouncyCastle encoders), JSON (hand-rolled `shared/Json` — canonical writer + parser),
`CompletableFuture` for the async network surface.

### Why not native PQC?

`javax.crypto.KEM` (JDK 21) is only a generic API; ML-KEM/ML-DSA *implementations* are
JDK 24+ (SunJCE) and Android 17 (Keystore) only. Neither works here: **cSHAKE256 has no
native implementation in any JDK/Android provider**, and the SDK requires **seed-derived,
exportable** keypairs (recovery devices re-derive keys from a seed) — the opposite of
Android Keystore's non-exportable, hardware-bound keys. BouncyCastle is the only fit.

## Layout (mirrors `sdk/ts/src_ts`)

```
src/main/java/com/unimo/sdk/
├── crypto/   CryptoPQ (ML-DSA/ML-KEM), AEAD (AES-GCM), CryptoUtils (sha256, cSHAKE256,
│             derivations), SeedRandom (deterministic keygen), CodedException
├── shared/   Consts, Helpers (hex/base64/concat/u32be/chunkId), Json (canonical + parse)
└── client/   (Phase 2+)
conformance/  ConformanceRunner + vectors.json (golden oracle from the TS SDK)
```

## Install (JitPack)

Published from this Codeberg repo via [JitPack](https://jitpack.io/#org.codeberg.thinking_tools/unimo-sdk-java).
Add the JitPack repository, then the dependency — BouncyCastle and OkHttp come in transitively.

**Gradle**

```gradle
repositories {
    mavenCentral()
    maven { url 'https://jitpack.io' }
}

dependencies {
    implementation 'org.codeberg.thinking_tools:unimo-sdk-java:v0.0.1'
}
```

**Maven**

```xml
<repositories>
  <repository>
    <id>jitpack.io</id>
    <url>https://jitpack.io</url>
  </repository>
</repositories>

<dependency>
  <groupId>org.codeberg.thinking_tools</groupId>
  <artifactId>unimo-sdk-java</artifactId>
  <version>v0.0.1</version>
</dependency>
```

Any pushed tag, `main-SNAPSHOT` (latest commit), or a commit hash works as the version.

## Web search

Search rides the same authenticated WebSocket as `vault:event` push (there is no HTTP search
route). `search:typing` → suggestions (free); `search:query` → full results (counted against
the vault's search quota).

```java
Account account = new Account(serviceUrl, vault, true); // keepAlive=true opens the WS
Search search = account.search();

List<String> suggestions = search.suggest("post-quantum").get();

Search.Response res = search.search("post-quantum cryptography",
    early -> System.out.println("suggestions: " + early)).get();
for (Search.Result r : res.results) {
  System.out.println(r.title + " — " + r.url);
}
```

Failures reject the future with a `CodedException`: the gateway's error code (or `WS_ERROR`)
for server-side errors, `WS_TIMEOUT` after 20s without a reply, `CONNECTION_CLOSED` when the
socket is down or drops mid-request, `BAD_FRAME` when a `search:results` reply is malformed
(missing `data`), `EMPTY_QUERY` (thrown synchronously) for blank queries.
A throwing `onSuggestions` callback rejects the future with a `HANDLER_ERROR` `CodedException`
wrapping it — keep the early-frame handler cheap and non-throwing.

## Connection recovery (Android wiring — required)

A dropped socket reconnects on its own (exponential backoff, 250 ms → 30 s), and client pings
detect a half-open one within 20–40 s. OS events make recovery immediate instead of waiting on
backoff or ping timeouts — feed them into the connection:

```java
ConnectivityManager cm =
    (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
Connection conn = account.connection();
cm.registerDefaultNetworkCallback(new ConnectivityManager.NetworkCallback() {
  @Override public void onAvailable(Network network) { conn.networkAvailable(); }
  @Override public void onCapabilitiesChanged(Network network, NetworkCapabilities caps) {
    // onAvailable can fire before the network is validated (DNS not yet working) — this
    // second trigger retries once validation lands. networkAvailable() is idempotent.
    if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) conn.networkAvailable();
  }
  @Override public void onLost(Network network) { conn.networkLost(); }
});
```

Requires `ACCESS_NETWORK_STATE`. Also call `conn.networkAvailable()` from `onResume()` — it
covers drops that happen with no network change (e.g. a gateway restart while the app sits in
the background). `networkLost()` kills the transport at once instead of waiting minutes for TCP
timeouts; `networkAvailable()` reconnects immediately, or cancels a half-dead attempt and
retries once. Auth-expiry recovery (401 upgrade rejection / `1008` close → reauth → reopen)
stays automatic and needs no wiring.

## Staying current (collection watch)

With `keepAlive`, a collection loaded through `Account.getCollection` stays current by itself —
no polling, no reload on resume:

```java
KVContent notes = account.getCollection("notes").join(); // first load downloads, then watches
account.onRemoteChange(name -> {                           // SDK thread — marshal to main
  if ("notes".equals(name)) runOnUiThread(this::render);   // null = manifest changed
});
```

- **Live:** a `vault:event` frame for the collection carries its new version; the SDK downloads
  and merges only when that version is newer than the local copy (its own uploads cost nothing).
- **Reconnect:** frames are live-only, so on every (re)open the SDK refetches the manifest and
  sends one body-less `HEAD` per loaded collection, downloading only what moved while the socket
  was down.
- **Reload:** calling `getCollection` again on a loaded collection is a `HEAD`, not a download.

`onRemoteChange` fires only when newer remote state was merged: with the collection's name for
its content, or with null for the manifest (members, collections list — re-call `getCollection`
to pick up a collection another device just created). Pending local edits survive every merge.

## Build & test

```bash
# Gradle (consumer path)
gradle test

# No-Gradle path (what CI/dev can run with just a JDK): fetch the 4 compile jars into libs/
M=https://repo1.maven.org/maven2
curl -sLo libs/bcprov-jdk18on-1.81.jar  $M/org/bouncycastle/bcprov-jdk18on/1.81/bcprov-jdk18on-1.81.jar
curl -sLo libs/okhttp-4.12.0.jar        $M/com/squareup/okhttp3/okhttp/4.12.0/okhttp-4.12.0.jar
curl -sLo libs/okio-jvm-3.6.0.jar       $M/com/squareup/okio/okio-jvm/3.6.0/okio-jvm-3.6.0.jar
curl -sLo libs/kotlin-stdlib-1.9.10.jar $M/org/jetbrains/kotlin/kotlin-stdlib/1.9.10/kotlin-stdlib-1.9.10.jar
CP=$(printf 'libs/%s:' bcprov-jdk18on-1.81.jar okhttp-4.12.0.jar okio-jvm-3.6.0.jar kotlin-stdlib-1.9.10.jar)
javac -cp "$CP" -d out $(find src/main/java -name '*.java') conformance/ConformanceRunner.java conformance/IntegrationRunner.java
java -cp "out:$CP" conformance.ConformanceRunner conformance/vectors.json

# Live end-to-end test (needs the `bun run dev:local` gateway up on :3000):
java -cp "out:$CP" conformance.IntegrationRunner http://localhost:3000
# Registration is email-OTP gated and dev gateways never mail: the runner reads the code off Valkey
# (UNIMO_VALKEY, default redis://:devpass@127.0.0.1:6379 = the dev:local bundled instance).
```

## Conformance workflow

`conformance/vectors.json` is generated from the **real** noble/WebCrypto crypto:

```bash
bun run sdk/ts/tools/gen-conformance.ts   # regenerate after any TS crypto change
```

The Java port must reproduce every vector byte-for-byte (keygen-from-seed public keys,
cSHAKE outputs, canonical JSON, AEAD wire bytes, cross-language sign/verify + decapsulate).

## Interop contract (verified)

- **ML-DSA-87**: FIPS-204 pure, empty context (`0x00‖0x00‖M`), hedged signing. Sign the raw
  32-byte SHA-256 digest of the canonical JSON; `payloadHash = base64(digest)`.
- **ML-KEM-1024**: FIPS-203; 64-byte seed = `d‖z`.
- **cSHAKE256**: `N=""`, `S=personalization` (SP 800-185).
- **AEAD**: AES-256-GCM, `[12B IV][ciphertext][16B tag]`.
- **Canonical JSON**: recursive key sort + compact `JSON.stringify`.
