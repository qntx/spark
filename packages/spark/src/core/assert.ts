import { secp256k1 } from "@noble/curves/secp256k1.js";

import { SparkInputError } from "../errors/index.ts";

/** Maximum satoshi amount accepted anywhere in the protocol (21e6 BTC). */
export const MAX_SATS = 2_100_000_000_000_000;

export function assertU32(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xff_ff_ff_ff) {
    throw new SparkInputError(`${field}: must be a uint32`);
  }
}

export function assertSats(value: number, field: string): void {
  if (!Number.isSafeInteger(value) || value < 0 || value > MAX_SATS) {
    throw new SparkInputError(`${field}: must be a non-negative satoshi amount (<= ${MAX_SATS})`);
  }
}

export function requireLength(value: Uint8Array, length: number, field: string): void {
  if (value.length !== length) {
    throw new SparkInputError(`${field}: must be exactly ${length} bytes`);
  }
}

/** Narrows a protobuf `uint64`/`int64` satoshi value; rejects anything outside 0..MAX_SATS. */
export function u64ToSats(value: bigint, field: string): number {
  if (value < 0n || value > BigInt(MAX_SATS)) {
    throw new SparkInputError(`${field}: must be a non-negative satoshi amount (<= ${MAX_SATS})`);
  }
  return Number(value);
}

export const COMPRESSED_PUBLIC_KEY_LENGTH = 33;

/** Length-checks plus a real point-on-curve check for a compressed secp256k1 key. */
export function assertCompressedKey(key: Uint8Array, field: string): void {
  if (key.length !== COMPRESSED_PUBLIC_KEY_LENGTH) {
    throw new SparkInputError(`${field}: must be a 33-byte compressed public key`);
  }
  try {
    secp256k1.Point.fromBytes(key);
  } catch (error) {
    throw new SparkInputError(`${field}: not a valid secp256k1 point`, { cause: error });
  }
}
