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

/**
 * A request to a signing operator or the SSP failed. `code` uses one vocabulary: the gRPC canonical
 * snake_case names for operator errors ("unauthenticated", "unavailable", "invalid_argument",
 * "deadline_exceeded", … — Connect's PascalCase enum names are mapped down), `http_<status>` for
 * SSP HTTP failures, `unexpected_response` for malformed SSP responses, and the SSP's GraphQL
 * `extensions.code` lowercased. `operator` is the FROST identifier of the operator that failed,
 * when the failure came from an operator. The message carries the server's own message — never
 * request bodies.
 */
export class SparkRequestError extends SparkError {
  readonly code?: string | undefined;
  readonly operator?: string | undefined;

  constructor(
    message: string,
    options?: ErrorOptions & { readonly code?: string; readonly operator?: string },
  ) {
    super(message, options);
    this.name = "SparkRequestError";
    this.code = options?.code;
    this.operator = options?.operator;
  }
}
