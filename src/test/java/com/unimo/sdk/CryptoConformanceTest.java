package com.unimo.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;

import conformance.ConformanceRunner;
import org.junit.jupiter.api.Test;

/**
 * Gate: the Java crypto must reproduce every golden vector emitted by the real TypeScript SDK
 * ({@code sdk/ts/tools/gen-conformance.ts}). Regenerate vectors after touching the TS crypto;
 * a single byte of drift fails the build.
 */
class CryptoConformanceTest {

  @Test
  void reproducesTypeScriptSdkVectors() throws Exception {
    assertEquals(0, ConformanceRunner.run("conformance/vectors.json"), "cross-language conformance vectors must all pass");
  }
}
