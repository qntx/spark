/** Base class of every error raised by this package. */
export class SparkError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SparkError";
  }
}

/**
 * A failure reported by a {@link SparkCrypto} backend. `code` is the C ABI error code (see
 * `qntx_spark.h`); the message never carries input bytes.
 */
export class SparkCryptoError extends SparkError {
  readonly code: number;

  constructor(code: number, options?: ErrorOptions) {
    super(`spark crypto backend failed (code ${code})`, options);
    this.name = "SparkCryptoError";
    this.code = code;
  }
}

/**
 * Malformed caller- or peer-supplied data: a Spark address, a BOLT-11 invoice, an encoding. The
 * message names the offending field and rule; it never echoes the input, so no secret or invoice
 * content leaks into logs through error messages.
 */
export class SparkInputError extends SparkError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SparkInputError";
  }
}
