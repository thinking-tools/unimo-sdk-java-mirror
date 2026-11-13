package com.unimo.sdk.shared;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * Name rules must match the TS {@code VALIDATION_RULES} and {@code RESERVED_USERNAMES}: an account
 * name let through here is answered with 400 by the gateway's {@code /register}, and a device name
 * refused here stops a manager from enabling a device that another client let join.
 */
class ValidatorsNameTest {

  private static String ofLength(int length) {
    char[] chars = new char[length];
    Arrays.fill(chars, 'a');
    return new String(chars);
  }

  @Test
  void accountNameKeepsToItsLengths() {
    assertFalse(Validators.validateAccountName(ofLength(Consts.ACCOUNT_NAME_MIN_LENGTH - 1)));
    assertTrue(Validators.validateAccountName(ofLength(Consts.ACCOUNT_NAME_MIN_LENGTH)));
    assertTrue(Validators.validateAccountName(ofLength(Consts.ACCOUNT_NAME_MAX_LENGTH)));
    assertFalse(Validators.validateAccountName(ofLength(Consts.ACCOUNT_NAME_MAX_LENGTH + 1)));
  }

  @Test
  void accountNameRefusesReservedNames() {
    for (String s : new String[] {"unimo", "UNIMO", "unimo-app", "moderator", "admin_jane", "jane-support"}) {
      assertFalse(Validators.validateAccountName(s), s);
    }
    assertTrue(Validators.validateAccountName("unimo_jane"), "only the bare app name is reserved");
  }

  @Test
  void deviceNameAllowsWordsReservedForAccounts() {
    for (String s : new String[] {"admin-laptop", "support_pc", "modern-phone", "unimo", "android_SM-A546B"}) {
      assertTrue(Validators.validateDeviceName(s), s);
    }
  }

  @Test
  void deviceNameKeepsToItsLengthsAndCharacters() {
    assertFalse(Validators.validateDeviceName(ofLength(Consts.DEVICE_NAME_MIN_LENGTH - 1)));
    assertTrue(Validators.validateDeviceName(ofLength(Consts.DEVICE_NAME_MIN_LENGTH)));
    assertTrue(Validators.validateDeviceName(ofLength(Consts.DEVICE_NAME_MAX_LENGTH)));
    assertFalse(Validators.validateDeviceName(ofLength(Consts.DEVICE_NAME_MAX_LENGTH + 1)));
    for (String s : new String[] {null, "", "my phone", "pixel.8", "telef\u00f3n"}) {
      assertFalse(Validators.validateDeviceName(s), String.valueOf(s));
    }
  }

  @Test
  void deviceNameRefusesTheRecoveryMembersName() {
    assertFalse(Validators.validateDeviceName(Consts.RECOVERY_DEVICE_NAME));
  }
}
