package com.unimo.sdk.crypto;

/**
 * Base for the SDK's crypto errors, mirroring the TS {@code *Error} classes that carry a
 * string {@code code} (e.g. {@code INVALID_SEED_LENGTH}). Unchecked so call sites read like
 * the async TS originals without checked-exception noise.
 */
public class CodedException extends RuntimeException {
  private static final long serialVersionUID = 1L;
  private final String code;

  public CodedException(String message, String code) {
    super(message);
    this.code = code;
  }

  public CodedException(String message, String code, Throwable cause) {
    super(message, cause);
    this.code = code;
  }

  public String getCode() {
    return code;
  }
}
