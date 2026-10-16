import { fromBinary, toBinary } from "@bufbuild/protobuf";
import { BinaryWriter } from "@bufbuild/protobuf/wire";
import { TimestampSchema } from "@bufbuild/protobuf/wkt";
import { schnorr, secp256k1 } from "@noble/curves/secp256k1.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";
import { bech32m } from "@scure/base";

import { SparkInputError } from "../errors/index.ts";
import {
  SatsPaymentSchema,
  SparkAddressSchema,
  TokensPaymentSchema,
  SparkInvoiceFieldsSchema,
} from "../proto/gen/spark_pb.ts";
import { hashSparkInvoice } from "./hashing/invoice.ts";
import { INVOICE_VERSION, protoInvoiceToPlain } from "./invoice.ts";
import type { SparkInvoiceFields } from "./invoice.ts";
import type { SparkNetwork } from "./network.ts";
import { uuidFromBytes, uuidToBytes, uuidv7 } from "./uuid.ts";

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
const ID_LENGTH = 16;
const PUBLIC_KEY_LENGTH = 33;

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

export type { SparkInvoiceFields, SparkPayment } from "./invoice.ts";

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
export function encodeSparkInvoiceFieldsV1Canonical(invoice: SparkInvoiceFields): Uint8Array {
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
  return encodeSparkAddressBytes(
    address.identityPublicKey,
    address.network,
    address.invoice === undefined
      ? undefined
      : encodeSparkInvoiceFieldsV1Canonical(address.invoice),
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
  let invoice: SparkInvoiceFields | undefined;
  if (payload.sparkInvoiceFields !== undefined) {
    invoice = protoInvoiceToPlain(payload.sparkInvoiceFields);
    // Decoded peer data gets the same field validation as local input, except the
    // version check — unknown future versions may still parse.
    validateInvoiceFields(invoice);
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

export type PrepareTokenInvoiceRequest = {
  readonly receiverIdentityPublicKey: Uint8Array;
  readonly network: SparkNetwork;
  readonly tokenIdentifier?: Uint8Array | undefined;
  readonly tokenAmount?: Uint8Array | undefined;
  readonly memo?: string | undefined;
  /** Spark address of the sender; only its identity public key is bound. */
  readonly senderAddress?: string | undefined;
  /** Unix milliseconds. */
  readonly expiresAtMs?: number | undefined;
  /** 16-byte invoice id (uuid_v7 bytes). Generated from `random`/`now` when omitted. */
  readonly invoiceId?: Uint8Array | undefined;
  readonly random?: ((length: number) => Uint8Array) | undefined;
  readonly now?: (() => number) | undefined;
};

export type PreparedTokenInvoice = {
  readonly invoice: SparkInvoiceFields;
  /** Canonical SparkInvoiceFields protobuf bytes, embedded verbatim in the address. */
  readonly invoiceFieldsBytes: Uint8Array;
  readonly invoiceHash: Uint8Array;
  readonly unsignedAddress: string;
};

function requireLength(value: Uint8Array, length: number, field: string): void {
  if (value.length !== length) {
    throw new SparkInputError(`${field} must be exactly ${length} bytes`);
  }
}

function validateTokenInvoiceFields(invoice: SparkInvoiceFields): void {
  if (invoice.version !== INVOICE_VERSION) {
    throw new SparkInputError("invoice.version: must be 1");
  }
  uuidToBytes(invoice.id);
  if (invoice.memo !== undefined && utf8ToBytes(invoice.memo).length > MEMO_MAX_BYTES) {
    throw new SparkInputError("invoice.memo: exceeds 120 UTF-8 bytes");
  }
  if (invoice.senderPublicKey !== undefined) {
    requireLength(invoice.senderPublicKey, PUBLIC_KEY_LENGTH, "invoice.senderPublicKey");
  }
  if (invoice.payment === undefined || invoice.payment.type !== "tokens") {
    throw new SparkInputError("expected token invoice, got sats invoice or no payment");
  }
  const { tokenIdentifier, amount } = invoice.payment;
  if (tokenIdentifier !== undefined && tokenIdentifier.length !== TOKEN_IDENTIFIER_LENGTH) {
    throw new SparkInputError("invoice token identifier must be 32 bytes");
  }
  if (amount !== undefined && amount.length > MAX_TOKEN_AMOUNT_BYTES) {
    throw new SparkInputError("invoice token amount must be at most 16 bytes");
  }
}

/**
 * Builds a token invoice: the canonical `SparkInvoiceFields` encoding, the invoice signing hash,
 * and the unsigned bech32m Spark address. Mirrors the upstream Rust `prepare_token_invoice`; the
 * caller signs `invoiceHash` with BIP-340 schnorr and passes the signature to
 * {@link finalizeTokenInvoice}.
 */
export function prepareTokenInvoice(request: PrepareTokenInvoiceRequest): PreparedTokenInvoice {
  requireLength(
    request.receiverIdentityPublicKey,
    PUBLIC_KEY_LENGTH,
    "receiver identity public key",
  );
  if (request.tokenIdentifier !== undefined) {
    requireLength(request.tokenIdentifier, TOKEN_IDENTIFIER_LENGTH, "token identifier");
  }
  if (request.tokenAmount !== undefined && request.tokenAmount.length > MAX_TOKEN_AMOUNT_BYTES) {
    throw new SparkInputError("token amount must be at most 16 bytes");
  }
  if (request.memo !== undefined && utf8ToBytes(request.memo).length > MEMO_MAX_BYTES) {
    throw new SparkInputError("memo must be at most 120 UTF-8 bytes");
  }

  let { invoiceId } = request;
  if (invoiceId === undefined) {
    if (request.random === undefined || request.now === undefined) {
      throw new SparkInputError(
        "invoice id: pass invoiceId or inject random/now for uuid v7 generation",
      );
    }
    invoiceId = uuidToBytes(uuidv7(request.random, request.now));
  }
  requireLength(invoiceId, ID_LENGTH, "invoice id");

  let senderPublicKey: Uint8Array | undefined;
  if (request.senderAddress !== undefined) {
    const sender = decodeSparkAddress(request.senderAddress);
    if (sender.network !== request.network) {
      throw new SparkInputError("sender address network mismatch");
    }
    senderPublicKey = sender.identityPublicKey;
  }

  const invoice: SparkInvoiceFields = {
    version: INVOICE_VERSION,
    id: uuidFromBytes(invoiceId),
    payment: {
      type: "tokens",
      tokenIdentifier: request.tokenIdentifier,
      amount: request.tokenAmount,
    },
    memo: request.memo,
    senderPublicKey,
    expiresAt: request.expiresAtMs,
  };
  validateTokenInvoiceFields(invoice);

  const invoiceHash = hashSparkInvoice(invoice, request.receiverIdentityPublicKey, request.network);
  const invoiceFieldsBytes = encodeSparkInvoiceFieldsV1Canonical(invoice);
  const unsignedAddress = encodeSparkAddressBytes(
    request.receiverIdentityPublicKey,
    request.network,
    invoiceFieldsBytes,
    undefined,
  );
  return { invoice, invoiceFieldsBytes, invoiceHash, unsignedAddress };
}

/**
 * Produces the final bech32m Spark address from canonical invoice fields bytes plus an optional
 * signature — the fields bytes are embedded verbatim, exactly like the upstream Rust
 * `finalize_token_invoice`.
 */
export function finalizeTokenInvoice(request: {
  readonly receiverIdentityPublicKey: Uint8Array;
  readonly network: SparkNetwork;
  readonly invoiceFieldsBytes: Uint8Array;
  readonly signature?: Uint8Array | undefined;
}): string {
  requireLength(
    request.receiverIdentityPublicKey,
    PUBLIC_KEY_LENGTH,
    "receiver identity public key",
  );
  if (request.invoiceFieldsBytes.length === 0) {
    throw new SparkInputError("invoice fields bytes must not be empty");
  }
  if (request.signature !== undefined) {
    requireLength(request.signature, SIGNATURE_LENGTH, "signature");
  }
  let fields;
  try {
    fields = fromBinary(SparkInvoiceFieldsSchema, request.invoiceFieldsBytes);
  } catch (error) {
    throw new SparkInputError("failed to decode invoice fields", { cause: error });
  }
  // The signing hash applies to the decoded fields; validate with the same rules.
  validateTokenInvoiceFields(protoInvoiceToPlain(fields));
  return encodeSparkAddressBytes(
    request.receiverIdentityPublicKey,
    request.network,
    request.invoiceFieldsBytes,
    request.signature,
  );
}
