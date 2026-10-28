import { fromBinary } from "@bufbuild/protobuf";
import { BinaryWriter } from "@bufbuild/protobuf/wire";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { bech32m } from "@scure/base";

import { SparkInputError } from "../errors/index.ts";
import { SparkAddressSchema } from "../proto/gen/spark_pb.ts";
import { assertCompressedKey } from "./assert.ts";
import { hashSparkInvoice } from "./hashing/invoice.ts";
import { encodeInvoiceFields, protoInvoiceToPlain, validateInvoiceFields } from "./invoice.ts";
import type { SparkInvoiceFields } from "./invoice.ts";
import type { SparkNetwork } from "./network.ts";

// Upstream reference: sdks/js/packages/spark-sdk/src/utils/address.ts
// (buildonspark/spark@0b3a32a). Addresses are bech32m over a SparkAddress
// protobuf with a 1024-character limit; legacy two-letter prefixes decode to
// the same networks.

const BECH32M_LIMIT = 1024;
const SIGNATURE_LENGTH = 64;

const ADDRESS_PREFIX: Record<SparkNetwork, string> = {
  mainnet: "spark",
  regtest: "sparkrt",
};

const PREFIX_TO_NETWORK: Record<string, SparkNetwork> = {
  spark: "mainnet",
  sparkrt: "regtest",
  sp: "mainnet",
  sprt: "regtest",
};

export type { SparkInvoiceFields, SparkInvoicePayment } from "./invoice.ts";

/**
 * Plain-TypeScript mirror of `spark.SparkAddress`. `signature` is the 64-byte schnorr signature
 * over the invoice fields; signing and verification are handled by the signer.
 */
export type SparkAddress = {
  readonly network: SparkNetwork;
  readonly identityPublicKey: Uint8Array;
  readonly invoice?: SparkInvoiceFields | undefined;
  readonly signature?: Uint8Array | undefined;
};

/** Encodes a Spark address as `hrp1…` bech32m (the network's current prefix). */
export function encodeSparkAddress(address: SparkAddress): string {
  assertCompressedKey(address.identityPublicKey, "identityPublicKey");
  if (address.invoice !== undefined) {
    validateInvoiceFields(address.invoice, { requireCurrentVersion: true });
  }
  if (address.signature !== undefined && address.signature.length !== SIGNATURE_LENGTH) {
    throw new SparkInputError(`signature: must be ${SIGNATURE_LENGTH} bytes`);
  }
  return encodeSparkAddressBytes(
    address.identityPublicKey,
    address.network,
    address.invoice === undefined ? undefined : encodeInvoiceFields(address.invoice),
    address.signature,
  );
}

/**
 * Encodes an address from pre-serialized invoice fields bytes, embedding them verbatim. Used by
 * invoice finalization, where the signed bytes must not be re-encoded. Internal to `core`.
 */
export function encodeSparkAddressBytes(
  identityPublicKey: Uint8Array,
  network: SparkNetwork,
  sparkInvoiceFieldsBytes: Uint8Array | undefined,
  signature: Uint8Array | undefined,
): string {
  assertCompressedKey(identityPublicKey, "identityPublicKey");
  const prefix = ADDRESS_PREFIX[network];
  if (prefix === undefined) {
    throw new SparkInputError("network: must be 'mainnet' or 'regtest'");
  }

  const w = new BinaryWriter();
  w.uint32(10).bytes(identityPublicKey);
  if (sparkInvoiceFieldsBytes !== undefined) {
    w.uint32(18).bytes(sparkInvoiceFieldsBytes);
  }
  if (signature !== undefined && signature.length > 0) {
    w.uint32(26).bytes(signature);
  }
  return bech32m.encode(prefix, bech32m.toWords(w.finish()), BECH32M_LIMIT);
}

function bech32mDecode(address: string): { prefix: string; words: number[] } {
  try {
    return bech32m.decode(address, BECH32M_LIMIT);
  } catch (error) {
    throw new SparkInputError("address: invalid bech32m encoding", { cause: error });
  }
}

/**
 * Decodes a bech32m Spark address. Current (`spark`, `sparkrt`) and legacy (`sp`, `sprt`) prefixes
 * are accepted; the prefix selects the network. Throws {@link SparkInputError} on malformed input.
 */
export function decodeSparkAddress(address: string): SparkAddress {
  const { prefix, words } = bech32mDecode(address);
  const network = PREFIX_TO_NETWORK[prefix];
  if (network === undefined) {
    throw new SparkInputError(
      "address: unsupported network prefix (expected spark, sparkrt, sp or sprt)",
    );
  }
  let payload;
  try {
    payload = fromBinary(SparkAddressSchema, bech32m.fromWords(words));
  } catch (error) {
    throw new SparkInputError("address: invalid SparkAddress payload", { cause: error });
  }

  assertCompressedKey(payload.identityPublicKey, "identityPublicKey");
  const { signature } = payload;
  if (signature !== undefined && signature.length > 0 && signature.length !== SIGNATURE_LENGTH) {
    throw new SparkInputError(`signature: must be ${SIGNATURE_LENGTH} bytes`);
  }
  let invoice: SparkInvoiceFields | undefined;
  if (payload.sparkInvoiceFields !== undefined) {
    invoice = protoInvoiceToPlain(payload.sparkInvoiceFields);
    // Decoded peer data gets the same field validation as local input, except the
    // version check — unknown future versions may still parse.
    validateInvoiceFields(invoice, { requireCurrentVersion: false });
  }
  return {
    network,
    identityPublicKey: payload.identityPublicKey,
    invoice,
    signature: signature !== undefined && signature.length > 0 ? signature : undefined,
  };
}

/**
 * Verifies the BIP-340 schnorr signature a Spark invoice carries: the signature covers
 * `hashSparkInvoice(invoice, identityPublicKey, network)` under the x-only identity public key.
 * Returns false for a missing invoice/signature or an invalid signature, matching upstream
 * `validateSparkInvoiceSignature`'s verification step.
 */
export function verifySparkAddressSignature(address: SparkAddress): boolean {
  if (address.invoice === undefined || address.signature === undefined) {
    return false;
  }
  try {
    const hash = hashSparkInvoice(address.invoice, address.identityPublicKey, address.network);
    const xOnly = secp256k1.Point.fromBytes(address.identityPublicKey).toBytes(true).slice(1);
    return schnorr.verify(address.signature, hash, xOnly);
  } catch {
    return false;
  }
}
