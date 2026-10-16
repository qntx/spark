import { SparkInputError } from "../errors/index.ts";
import type { SparkInvoiceFields as SparkInvoiceFieldsProto } from "../proto/gen/spark_pb.ts";
import { uuidFromBytes } from "./uuid.ts";

// Upstream reference: sdks/js/packages/spark-sdk/src/utils/address.ts and
// signer/spark-token-primitives/src/invoice.rs (buildonspark/spark@0b3a32a).
// This module owns the plain-TypeScript invoice model shared by the address
// codec and the invoice hasher, so neither of those depends on the other.

export const INVOICE_VERSION = 1;

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

function bigintToSafeInt(amount: bigint): number {
  if (amount < 0n || amount > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new SparkInputError("invoice.payment.amount: does not fit a safe integer");
  }
  return Number(amount);
}
