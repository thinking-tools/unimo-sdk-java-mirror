package com.unimo.sdk.shared;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * {@link Validators#validateEmail} must accept exactly what the TS {@code VALIDATION_RULES.email}
 * regex accepts: the gateway runs the same pattern, so a looser Java check would let a user
 * request a code for an address that {@code /email/start} then rejects with 400.
 */
class ValidatorsEmailTest {

  @Test
  void acceptsStandardAddresses() {
    for (String s : new String[] {"a@b.co", "itest_1a2b3c@unimo.test", "first.last+tag@sub.example.org", "x'y@ex-ample.com"}) {
      assertTrue(Validators.validateEmail(s), s);
    }
  }

  @Test
  void rejectsMalformedAddresses() {
    for (String s : new String[] {null, "", "a@b", "a b@c.com", "@x.com", "a@.com", "a@b.c", "a@-b.com", "a@b.co."}) {
      assertFalse(Validators.validateEmail(s), String.valueOf(s));
    }
  }
}
