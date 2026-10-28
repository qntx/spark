import { toBinary } from "@bufbuild/protobuf";
import { BinaryWriter } from "@bufbuild/protobuf/wire";
import { TimestampSchema } from "@bufbuild/protobuf/wkt";
import { utf8ToBytes } from "@noble/hashes/utils.js";

import { SparkInputError } from "../errors/index.ts";
import { SatsPaymentSchema, TokensPaymentSchema } from "../proto/gen/spark_pb.ts";
import type { SparkInvoiceFields as SparkInvoiceFieldsProto } from "../proto/gen/spark_pb.ts";
import { assertCompressedKey, assertSats, requireLength } from "./assert.ts";
import { uuidFromBytes, uuidToBytes } from "./uuid.ts";

// Upstream reference: sdks/js/packages/spark-sdk/src/utils/address.ts and
// signer/spark-token-primitives/src/invoice.rs (buildonspark/spark@0b3a32a).
// This module owns the plain-TypeScript invoice model shared by the address
// codec and the invoice hasher, so neither of those depends on the other.

export const INVOICE_VERSION = 1;

const MEMO_MAX_BYTES = 120;
const TOKEN_IDENTIFIER_LENGTH = 32;
const MAX_TOKEN_AMOUNT_BYTES = 16; // uint128, big-endian

/** Payment carried by a Spark invoice: satoshis or BTKN tokens. */
export type SparkInvoicePayment =
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
  readonly payment?: SparkInvoicePayment | undefined;
  /** At most 120 UTF-8 bytes. */
  readonly memo?: string | undefined;
  /** 33-byte compressed secp256k1 public key. */
  readonly senderPublicKey?: Uint8Array | undefined;
  /** Unix milliseconds. */
  readonly expiresAt?: number | undefined;
};

/**
 * Validates every field of an invoice: `id` must be a UUID, `memo` at most 120 UTF-8 bytes,
 * `senderPublicKey` a valid compressed secp256k1 point, `expiresAt` a non-negative safe integer,
 * sats amounts bounded by {@link MAX_SATS} and token fields uint128-sized. With
 * `requireCurrentVersion` the version must equal {@link INVOICE_VERSION} — used for locally built
 * invoices; decoded peer invoices may carry newer versions and still parse.
 */
export function validateInvoiceFields(
  invoice: SparkInvoiceFields,
  options: { readonly requireCurrentVersion: boolean },
): void {
  if (options.requireCurrentVersion && invoice.version !== INVOICE_VERSION) {
    throw new SparkInputError(`invoice.version: must be ${INVOICE_VERSION}`);
  }
  uuidToBytes(invoice.id);
  if (invoice.memo !== undefined && utf8ToBytes(invoice.memo).length > MEMO_MAX_BYTES) {
    throw new SparkInputError(`invoice.memo: exceeds ${MEMO_MAX_BYTES} UTF-8 bytes`);
  }
  if (invoice.senderPublicKey !== undefined) {
    assertCompressedKey(invoice.senderPublicKey, "invoice.senderPublicKey");
  }
  if (
    invoice.expiresAt !== undefined &&
    (!Number.isSafeInteger(invoice.expiresAt) || invoice.expiresAt < 0)
  ) {
    throw new SparkInputError(
      "invoice.expiresAt: must be a non-negative safe-integer unix-ms timestamp",
    );
  }
  const { payment } = invoice;
  if (payment === undefined) {
    return;
  }
  switch (payment.type) {
    case "sats":
      if (payment.amount !== undefined) {
        assertSats(payment.amount, "invoice.payment.amount");
      }
      return;
    case "tokens":
      if (payment.tokenIdentifier !== undefined) {
        requireLength(
          payment.tokenIdentifier,
          TOKEN_IDENTIFIER_LENGTH,
          "invoice.payment.tokenIdentifier",
        );
      }
      if (payment.amount !== undefined && payment.amount.length > MAX_TOKEN_AMOUNT_BYTES) {
        throw new SparkInputError(
          `invoice.payment.amount: exceeds ${MAX_TOKEN_AMOUNT_BYTES} bytes (uint128)`,
        );
      }
  }
}

/**
 * Converts a decoded `SparkInvoiceFields` message into the plain model, normalizing empty fields
 * (zero-length bytes, absent scalars) to `undefined`.
 */
export function protoInvoiceToPlain(fields: SparkInvoiceFieldsProto): SparkInvoiceFields {
  const { paymentType } = fields;
  let payment: SparkInvoiceFields["payment"];
  if (paymentType.case === "tokensPayment") {
    payment = {
      type: "tokens",
      tokenIdentifier:
        paymentType.value.tokenIdentifier !== undefined &&
        paymentType.value.tokenIdentifier.length > 0
          ? paymentType.value.tokenIdentifier
          : undefined,
      amount:
        paymentType.value.amount !== undefined && paymentType.value.amount.length > 0
          ? paymentType.value.amount
          : undefined,
    };
  } else if (paymentType.case === "satsPayment") {
    const { amount } = paymentType.value;
    payment = {
      type: "sats",
      amount: amount === undefined ? undefined : bigintToSafeInt(amount),
    };
  }
  return {
    version: fields.version,
    id: uuidFromBytes(fields.id),
    payment,
    memo: fields.memo,
    senderPublicKey:
      fields.senderPublicKey !== undefined && fields.senderPublicKey.length > 0
        ? fields.senderPublicKey
        : undefined,
    expiresAt:
      fields.expiryTime === undefined
        ? undefined
        : Number(fields.expiryTime.seconds) * 1000 +
          Math.floor(fields.expiryTime.nanos / 1_000_000),
  };
}

// The inner SparkInvoiceFields message is written in a canonical order — scalar fields first, the
// payment oneof last — so our encoding is byte-identical to the invoice bytes upstream embeds in
// address strings. The invoice signature covers `hashSparkInvoice`, not these bytes; the order
// matters only for address-encoding parity.
export function encodeInvoiceFields(invoice: SparkInvoiceFields): Uint8Array {
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

function bigintToSafeInt(amount: bigint): number {
  if (amount < 0n || amount > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new SparkInputError("invoice.payment.amount: does not fit a safe integer");
  }
  return Number(amount);
}
