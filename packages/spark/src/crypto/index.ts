export { SparkCryptoError } from "../errors/index.ts";

/**
 * C ABI version implemented by a {@link SparkCrypto} backend. Bumped only when `qntx_spark.h`
 * changes incompatibly; the signer verifies it at construction.
 */
export const SPARK_ABI_VERSION = 1;

/**
 * Curve-intensive Spark cryptography behind a bytes-only boundary. A backend maps 1:1 onto the C
 * ABI in `qntx_spark.h` (`@qntx/spark-wasm` wraps the wasm32 build, `@qntx/spark-native` the native
 * HybridObject); every method returns raw bytes and reports failure as a `SparkCryptoError` whose
 * `code` is the ABI error code.
 *
 * Error codes: `0` success; `1` length error; `2` invalid scalar; `3` invalid point; `4` protobuf
 * decode failure; `5` argument out of range (threshold, share count, job count cap 256); `6` FROST
 * failure (invalid share, missing commitment); `7` decryption authentication failure; `8` internal
 * error.
 */
export type SparkCrypto = {
  readonly abiVersion: number;

  /**
   * FROST signing nonces and commitments.
   *
   * `hedge` is a 32-byte signer-private hedge secret; `random` is `n`×32 bytes. Returns `n`×130
   * bytes: per item `hiding‖binding` nonces (64) followed by the compressed `hiding‖binding`
   * commitments (66). Each item runs frost `SigningNonces::new(hedge,
   * ChaCha20Rng::from_seed(random_i))`; nonces stay unique even if the random source fails.
   */
  frostCommit: (hedge: Uint8Array, random: Uint8Array) => Uint8Array;

  /**
   * User-side FROST signature shares.
   *
   * `request` is a protobuf `ffi.FrostSignRequest`; returns `ffi.FrostSignResponse` — one 32-byte
   * signature share per job, in job order. The backend signs the user role under the `SingleUser`
   * scheme with `Identifier::derive("user")`; the user verifying share is computed from the secret
   * key inside the backend and never accepted as input.
   */
  frostSign: (request: Uint8Array) => Uint8Array;

  /**
   * FROST aggregate signatures.
   *
   * `request` is a protobuf `ffi.FrostAggregateRequest`; returns `ffi.FrostAggregateResponse` — one
   * 64-byte signature per job, in job order. When an adaptor public key is present the final
   * verification is skipped per branch, matching upstream.
   */
  frostAggregate: (request: Uint8Array) => Uint8Array;

  /**
   * ECIES encryption, byte-compatible with `ecies` 0.2 defaults.
   *
   * `publicKey` is a 33- or 65-byte secp256k1 public key; `random` is 32 bytes. Returns
   * `ephemeralPk(65)‖nonce(16)‖tag(16)‖ciphertext`: HKDF-SHA256 over `ephemeralPk‖sharedPoint`
   * (both uncompressed) with AES-256-GCM and a 16-byte nonce; the ephemeral key and nonce are
   * derived from `random`.
   */
  eciesEncrypt: (publicKey: Uint8Array, plaintext: Uint8Array, random: Uint8Array) => Uint8Array;

  /** Inverse of {@link eciesEncrypt}: 32-byte private key and ciphertext yield the plaintext. */
  eciesDecrypt: (privateKey: Uint8Array, ciphertext: Uint8Array) => Uint8Array;

  /**
   * Feldman VSS secret splitting, matching upstream `vss.rs` (`vsss-rs`) with seeded ChaCha20
   * replacing its randomness source.
   *
   * `secret` is 32 bytes, `threshold` t ≥ 2, `shares` n ≥ t and `random` is 32 bytes. Returns
   * `t`×33 proof bytes followed by `n`×32 share bytes; share indexes run 1..n.
   */
  splitSecretWithProofs: (
    secret: Uint8Array,
    threshold: number,
    shares: number,
    random: Uint8Array,
  ) => Uint8Array;
};
