package com.unimo.sdk.shared;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Port of {@code sdk/ts/src_ts/shared/Consts.ts}. Wire-contract constants shared with the
 * gateway and the TypeScript SDK — values here are load-bearing for cross-language interop
 * and MUST match the TS source exactly.
 */
public final class Consts {
  private Consts() {}

  // ── Roles ──
  public static final String ROLE_OWNER = "OWNER";
  public static final String ROLE_ADMIN = "ADMIN";
  public static final String ROLE_MEMBER = "MEMBER";
  public static final String ROLE_VIEWER = "VIEWER";
  public static final String ROLE_TEMP = "TEMP";

  // ── Member status ──
  public static final String STATUS_ACTIVE = "ACTIVE";
  public static final String STATUS_INVITED = "INVITED";
  public static final String STATUS_REMOVED = "REMOVED";

  // ── Vault types ──
  public static final String VAULT_TYPE_ACCOUNT = "a";
  public static final String VAULT_TYPE_TEAM = "t";

  public static final String RECOVERY_DEVICE_NAME = "__RECOVERY__";

  private static final Set<String> MANAGER_ROLES =
      Collections.unmodifiableSet(new HashSet<>(Arrays.asList(ROLE_OWNER, ROLE_ADMIN)));

  /** Mirrors {@code IS_MANAGER_ROLE} — a role holding the {@code manage} permission. */
  public static boolean isManagerRole(String role) {
    if (role == null
        || !(role.equals(ROLE_OWNER)
            || role.equals(ROLE_ADMIN)
            || role.equals(ROLE_MEMBER)
            || role.equals(ROLE_VIEWER)
            || role.equals(ROLE_TEMP))) {
      throw new IllegalArgumentException("Invalid member role: " + role);
    }
    return MANAGER_ROLES.contains(role);
  }

  // ── Key / token lengths ──
  public static final int KEM_KEY_LENGTH_BYTES = 64;
  public static final int DSA_KEY_LENGTH_BYTES = 32;
  public static final int TOKEN_LENGTH_BYTES = 64;
  public static final int DEFAULT_AEAD_KEY_LENGTH_BYTES = 32;
  public static final int DEFAULT_SEED_LENGTH_BYTES = 32;

  // ── ML-DSA-87 fixed sizes (FIPS-204) ──
  public static final int ML_DSA_SIGNATURE_SIZE = 4627;
  public static final int ML_DSA_SECRET_KEY_SIZE = 4896;
  public static final int ML_DSA_PUBLIC_KEY_SIZE = 2592;

  // ── cSHAKE256 personalization strings (domain separation) ──
  public static final String CUSTOM_KEM_STRING = "*incredibly_unique-custom_string_for_KEM&LatticeStore*";
  public static final String CUSTOM_DSA_STRING = "*incredibly_unique-custom_string_for_ML-DSA&LatticeStore*";
  public static final String MEMBER_ID_STRING = "*incredibly_unique-custom_string_for_MEMBER_ID&LatticeStore*";
  public static final String CUSTOM_MANAGER_KEY_STRING = "*incredibly_unique-custom_string_for_MANAGER_KEY&LatticeStore*";
  public static final String CUSTOM_COLLECTION_LIST_STRING =
      "*incredibly_unique-custom_string_for_COLLECTIONS_LISTcrypt0&LatticeStore*";

  // ── Invites ──
  public static final String INVITE_ID_PERSONALIZATION = "unimo-invite-id";
  public static final String INVITE_CHANNEL_PERSONALIZATION = "unimo-invite-chan";
  public static final String INVITE_SAS_PERSONALIZATION = "unimo-invite-sas";
  public static final int INVITE_ID_LENGTH_BYTES = 16;
  public static final int INVITE_SECRET_LENGTH_BYTES = 32;
  public static final long INVITE_MAX_TTL_SECONDS = 7L * 24 * 60 * 60;
  public static final int MANAGER_AREA_VERSION = 1;

  // ── Storage v2 ──
  public static final int STORAGE_MAX_BLOB_BYTES = 8 * 1024 * 1024;
  public static final int AEAD_OVERHEAD_BYTES = 28;
  public static final int CHUNK_SIZE = STORAGE_MAX_BLOB_BYTES - 1024;
  public static final int STORAGE_MAX_CHUNKS_PER_FILE = 8192;
  public static final int UPLOAD_NONCE_BYTES = 16;
  public static final int HEAD_BLOB_SCHEMA_VERSION = 1;

  public static final String HEADER_EXPECTED_VERSION = "x-expected-version";
  public static final String HEADER_CHUNK_COUNT = "x-chunk-count";
  public static final String HEADER_STORAGE_VERSION = "x-storage-version";
  public static final String HEADER_STORAGE_ENDPOINT = "x-storage-endpoint";

  public static final int KV_KEY_SIZE_LIMIT_BYTES = 64;
  public static final long TOKEN_EXPIRATION_MS = 1000L * 60 * 60 * 2;
  public static final long TIMESTAMP_TOLERANCE_MS = 60 * 1000;

  // ── Collections ──
  public static final String COLLECTION_TYPE_VFS = "VFS";
  public static final String COLLECTION_TYPE_KV = "KV";
  public static final String COLLECTION_TYPE_LIST = "LIST";
  public static final String COLLECTION_TYPE_CRDTLIST = "CRDTLIST";
  public static final long SYNC_DEBOUNCE_MS = 810;
}
