import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils.js";

import { requireLength } from "../core/assert.ts";
import { SparkCryptoError, SparkError, SparkInputError } from "../errors/index.ts";
import type { SigningCommitment, SparkOperator } from "./types.ts";

export const MAX_JOBS = 256;
export const PUBLIC_KEY_LENGTH = 33;
export const SECRET_KEY_LENGTH = 32;
const VSS_PROOF_LENGTH = 33;
const VSS_SHARE_LENGTH = 32;
const IDENTIFIER_PATTERN = /^[0-9a-f]{64}$/;

/**
 * The local backend is synchronous; awaiting a resolved promise keeps every method async so callers
 * always observe rejections, never synchronous throws.
 */
export const ready: Promise<void> = Promise.resolve();

export function unreachable(message: string): never {
  throw new SparkError(message);
}

export function checkBatch(count: number, name: string): void {
  if (count > MAX_JOBS) {
    throw new SparkInputError(`${name}: at most ${MAX_JOBS} items per call`);
  }
}

/** Backend failures keep their ABI code; anything else becomes SparkCryptoError(8). */
export function backendCall(call: () => Uint8Array): Uint8Array {
  try {
    return call();
  } catch (error) {
    if (error instanceof SparkCryptoError) {
      throw error;
    }
    const code =
      typeof error === "object" &&
      error !== null &&
      "code" in error &&
      typeof error.code === "number"
        ? error.code
        : 8;
    throw new SparkCryptoError(code, { cause: error });
  }
}

export function randomBytes(random: (length: number) => Uint8Array, length: number): Uint8Array {
  const bytes = random(length);
  if (bytes.length !== length) {
    throw new SparkError(`random: expected ${length} bytes, got ${bytes.length}`);
  }
  return bytes;
}

/**
 * Draws `length` bytes of caller-supplied randomness for a single backend call, then wipes the
 * seed. The seed is secret-equivalent material: it determines FROST nonces, the VSS polynomial, and
 * the ECIES ephemeral key — knowing it undoes the secret the call protects.
 */
export function withRandom<T>(
  random: (length: number) => Uint8Array,
  length: number,
  use: (seed: Uint8Array) => T,
): T {
  const seed = randomBytes(random, length);
  try {
    return use(seed);
  } finally {
    seed.fill(0);
  }
}

/** A fresh 32-byte scalar, retrying on the (negligible) chance the RNG output is invalid. */
export function randomScalar(random: (length: number) => Uint8Array): Uint8Array {
  for (;;) {
    const scalar = randomBytes(random, SECRET_KEY_LENGTH);
    if (secp256k1.utils.isValidSecretKey(scalar)) {
      return scalar;
    }
    scalar.fill(0);
  }
}

export function identifierBytes(identifier: string): Uint8Array {
  if (!IDENTIFIER_PATTERN.test(identifier)) {
    throw new SparkInputError("identifier: must be 64 lowercase hex characters");
  }
  return hexToBytes(identifier);
}

export function commitmentKey(commitment: SigningCommitment): string {
  requireLength(commitment.hiding, PUBLIC_KEY_LENGTH, "commitment.hiding");
  requireLength(commitment.binding, PUBLIC_KEY_LENGTH, "commitment.binding");
  return bytesToHex(concatBytes(commitment.hiding, commitment.binding));
}

export function checkOperators(operators: ReadonlyArray<SparkOperator>): void {
  if (operators.length === 0) {
    throw new SparkInputError("operators: must not be empty");
  }
  for (const operator of operators) {
    if (!Number.isSafeInteger(operator.id) || operator.id < 0) {
      throw new SparkInputError("operator.id: must be a non-negative safe integer");
    }
    identifierBytes(operator.identifier);
    requireLength(operator.identityPublicKey, PUBLIC_KEY_LENGTH, "operator.identityPublicKey");
  }
}

/** Splits the flat `t×33 ‖ n×32` backend output into per-share proofs and share bytes. */
export function parseSplit(
  output: Uint8Array,
  threshold: number,
  count: number,
): { proofs: Uint8Array[]; shares: Uint8Array[] } {
  const proofsLength = threshold * VSS_PROOF_LENGTH;
  if (output.length !== proofsLength + count * VSS_SHARE_LENGTH) {
    throw new SparkCryptoError(8);
  }
  const proofs: Uint8Array[] = [];
  for (let i = 0; i < threshold; i++) {
    proofs.push(output.slice(i * VSS_PROOF_LENGTH, (i + 1) * VSS_PROOF_LENGTH));
  }
  const shares: Uint8Array[] = [];
  for (let i = 0; i < count; i++) {
    shares.push(
      output.slice(proofsLength + i * VSS_SHARE_LENGTH, proofsLength + (i + 1) * VSS_SHARE_LENGTH),
    );
  }
  return { proofs, shares };
}

/** The share for `operator` — share indexes run 1..n and operator id + 1 selects the share. */
export function operatorShare(
  shares: ReadonlyArray<Uint8Array>,
  operator: SparkOperator,
  context: string,
): Uint8Array {
  const share = shares[operator.id];
  if (share === undefined) {
    throw new SparkError(`${context}: no share for operator id ${operator.id}`);
  }
  return share;
}
