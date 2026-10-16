import { fromBinary, toBinary } from "@bufbuild/protobuf";
import { BinaryWriter } from "@bufbuild/protobuf/wire";
import { TimestampSchema } from "@bufbuild/protobuf/wkt";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { bech32m } from "@scure/base";

import { SparkInputError } from "../errors/index.ts";
import {
  SatsPaymentSchema,
  SparkAddressSchema,
  TokensPaymentSchema,
} from "../proto/gen/spark_pb.ts";
import type { SparkInvoiceFields as SparkInvoiceFieldsProto } from "../proto/gen/spark_pb.ts";
import type { SparkNetwork } from "./network.ts";
import { uuidFromBytes, uuidToBytes } from "./uuid.ts";

// Upstream reference: sdks/js/packages/spark-sdk/src/utils/address.ts
// (buildonspark/spark@0b3a32a). Addresses are bech32m over a SparkAddress
// protobuf with a 1024-character limit; legacy two-letter prefixes decode to
// the same networks.

const BECH32M_LIMIT = 1024;
const MEMO_MAX_BYTES = 120;
const SIGNATURE_LENGTH = 64;
const IDENTITY_KEY_LENGTH = 33;
const TOKEN_IDENTIFIER_LENGTH = 32;
const MAX_SATS_AMOUNT = 2_100_000_000_000_000; // 21_000_000 BTC in sats
const MAX_TOKEN_AMOUNT_BYTES = 16; // uint128, big-endian
const INVOICE_VERSION = 1;

const ADDRESS_PREFIX: Record<SparkNetwork, string> = {
  mainnet: "spark",
  regtest: "sparkrt",
};

const LEGACY_PREFIX: Record<SparkNetwork, string> = {
  mainnet: "sp",
  regtest: "sprt",
};

const PREFIX_TO_NETWORK: Record<string, SparkNetwork> = {};
for (const network of ["mainnet", "regtest"] as const) {
  PREFIX_TO_NETWORK[ADDRESS_PREFIX[network]] = network;
  PREFIX_TO_NETWORK[LEGACY_PREFIX[network]] = network;
}

/** Payment carried by a Spark invoice: satoshis or BTKN tokens. */
export type SparkPayment =
  | { readonly type: "sats"; readonly amount?: number | undefined }
  | {
      readonly type: "tokens";
      /** 32-byte token identifier. */
      readonly tokenIdentifier?: Uint8Array | undefined;
      /** Big-endian uint128, at most 16 bytes. */
      readonly amount?: Uint8Array | undefined;
    };

/** Plain-TypeScript mirror of `spark.SparkInvoiceFields`; version is currently always 1. */
export type SparkInvoiceFields = {
  readonly version: number;
  /** UUID identifying the invoice (canonical lowercase form). */
  readonly id: string;
  readonly payment?: SparkPayment | undefined;
  /** At most 120 UTF-8 bytes. */
  readonly memo?: string | undefined;
  /** 33-byte compressed secp256k1 public key. */
  readonly senderPublicKey?: Uint8Array | undefined;
  /** Unix milliseconds. */
  readonly expiresAt?: number | undefined;
};

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

function assertCompressedKey(key: Uint8Array, field: string): void {
  if (key.length !== IDENTITY_KEY_LENGTH) {
    throw new SparkInputError(`${field}: must be a 33-byte compressed public key`);
  }
  try {
    secp256k1.Point.fromBytes(key);
  } catch (error) {
    throw new SparkInputError(`${field}: not a valid secp256k1 point`, { cause: error });
  }
}

function validateInvoice(invoice: SparkInvoiceFields): void {
  if (invoice.version !== INVOICE_VERSION) {
    throw new SparkInputError(`invoice.version: must be ${INVOICE_VERSION}`);
  }
  validateInvoiceFields(invoice);
}

function validateInvoiceFields(invoice: SparkInvoiceFields): void {
  uuidToBytes(invoice.id);
  if (invoice.memo !== undefined && utf8ToBytes(invoice.memo).length > MEMO_MAX_BYTES) {
    throw new SparkInputError(`invoice.memo: exceeds ${MEMO_MAX_BYTES} UTF-8 bytes`);
  }
  if (invoice.senderPublicKey !== undefined) {
    assertCompressedKey(invoice.senderPublicKey, "invoice.senderPublicKey");
  }
  if (invoice.expiresAt !== undefined && !Number.isSafeInteger(invoice.expiresAt)) {
    throw new SparkInputError("invoice.expiresAt: must be a safe-integer unix-ms timestamp");
  }
  const { payment } = invoice;
  if (payment === undefined) {
    return;
  }
  switch (payment.type) {
    case "sats":
      if (payment.amount !== undefined) {
        if (!Number.isSafeInteger(payment.amount) || payment.amount < 0) {
          throw new SparkInputError("invoice.payment.amount: must be a non-negative safe integer");
        }
        if (payment.amount > MAX_SATS_AMOUNT) {
          throw new SparkInputError(`invoice.payment.amount: exceeds ${MAX_SATS_AMOUNT} sats`);
        }
      }
      return;
    case "tokens":
      if (
        payment.tokenIdentifier !== undefined &&
        payment.tokenIdentifier.length !== TOKEN_IDENTIFIER_LENGTH
      ) {
        throw new SparkInputError(
          `invoice.payment.tokenIdentifier: must be ${TOKEN_IDENTIFIER_LENGTH} bytes`,
        );
      }
      if (payment.amount !== undefined && payment.amount.length > MAX_TOKEN_AMOUNT_BYTES) {
        throw new SparkInputError(
          `invoice.payment.amount: exceeds ${MAX_TOKEN_AMOUNT_BYTES} bytes (uint128)`,
        );
      }
  }
}

// The inner SparkInvoiceFields message is written in the upstream canonical order —
// scalar fields first, the payment oneof last — so that re-encoding a decoded address
// reproduces the exact same protobuf bytes (the signature covers these bytes).
function encodeInvoiceInner(invoice: SparkInvoiceFields): Uint8Array {
  const w = new BinaryWriter();
  if (invoice.version !== 0) {
    w.uint32(8).uint32(invoice.version);
  }
  const id = uuidToBytes(invoice.id);
  w.uint32(18).bytes(id);
  if (invoice.memo !== undefined) {
    w.uint32(42).string(invoice.memo);
  }
  if (invoice.senderPublicKey !== undefined) {
    w.uint32(50).bytes(invoice.senderPublicKey);
  }
  if (invoice.expiresAt !== undefined) {
    const seconds = Math.floor(invoice.expiresAt / 1000);
    const timestamp = toBinary(TimestampSchema, {
      $typeName: "google.protobuf.Timestamp",
      seconds: BigInt(seconds),
      nanos: (invoice.expiresAt - seconds * 1000) * 1_000_000,
    });
    w.uint32(58).bytes(timestamp);
  }
  const { payment } = invoice;
  if (payment?.type === "tokens") {
    const tokens = toBinary(TokensPaymentSchema, {
      $typeName: "spark.TokensPayment",
      tokenIdentifier: payment.tokenIdentifier,
      amount: payment.amount,
    });
    w.uint32(26).bytes(tokens);
  } else if (payment?.type === "sats") {
    const sats = toBinary(SatsPaymentSchema, {
      $typeName: "spark.SatsPayment",
      amount: payment.amount === undefined ? undefined : BigInt(payment.amount),
    });
    w.uint32(34).bytes(sats);
  }
  return w.finish();
}

/** Encodes a Spark address as `hrp1…` bech32m (the network's current prefix). */
export function encodeSparkAddress(address: SparkAddress): string {
  assertCompressedKey(address.identityPublicKey, "identityPublicKey");
  if (address.invoice !== undefined) {
    validateInvoice(address.invoice);
  }
  if (address.signature !== undefined && address.signature.length !== SIGNATURE_LENGTH) {
    throw new SparkInputError(`signature: must be ${SIGNATURE_LENGTH} bytes`);
  }
  const prefix = ADDRESS_PREFIX[address.network];
  if (prefix === undefined) {
    throw new SparkInputError("network: must be 'mainnet' or 'regtest'");
  }

  const w = new BinaryWriter();
  w.uint32(10).bytes(address.identityPublicKey);
  if (address.invoice !== undefined) {
    w.uint32(18).bytes(encodeInvoiceInner(address.invoice));
  }
  if (address.signature !== undefined && address.signature.length > 0) {
    w.uint32(26).bytes(address.signature);
  }
  return bech32m.encode(prefix, bech32m.toWords(w.finish()), BECH32M_LIMIT);
}

function bech32mDecode(address: string): { prefix: string; words: number[] } {
  const separator = address.lastIndexOf("1");
  if (separator <= 0 || separator >= address.length - 1) {
    throw new SparkInputError("address: malformed bech32 separator");
  }
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
  return {
    network,
    identityPublicKey: payload.identityPublicKey,
    invoice: payload.sparkInvoiceFields ? decodeInvoice(payload.sparkInvoiceFields) : undefined,
    signature: signature !== undefined && signature.length > 0 ? signature : undefined,
  };
}

function decodeInvoice(fields: SparkInvoiceFieldsProto): SparkInvoiceFields {
  let payment: SparkPayment | undefined;
  if (fields.paymentType.case === "tokensPayment") {
    const { tokenIdentifier, amount } = fields.paymentType.value;
    payment = {
      type: "tokens",
      tokenIdentifier,
      amount: amount !== undefined && amount.length > 0 ? amount : undefined,
    };
  } else if (fields.paymentType.case === "satsPayment") {
    const { amount } = fields.paymentType.value;
    payment = {
      type: "sats",
      amount: amount === undefined ? undefined : bigintToSafeInt(amount),
    };
  }
  const invoice: SparkInvoiceFields = {
    version: fields.version,
    id: uuidFromBytes(fields.id),
    payment,
    memo: fields.memo,
    senderPublicKey: fields.senderPublicKey,
    expiresAt: fields.expiryTime
      ? Number(fields.expiryTime.seconds) * 1000 + Math.floor(fields.expiryTime.nanos / 1_000_000)
      : undefined,
  };
  // Decoded peer data gets the same field validation as local input, except the
  // version check — unknown future versions may still parse.
  validateInvoiceFields(invoice);
  return invoice;
}

function bigintToSafeInt(amount: bigint): number {
  if (amount < 0n || amount > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new SparkInputError("invoice.payment.amount: does not fit a safe integer");
  }
  return Number(amount);
}
