import { fromBinary } from "@bufbuild/protobuf";
import { utf8ToBytes } from "@noble/hashes/utils.js";

import { SparkInputError } from "../errors/index.ts";
import { SparkInvoiceFieldsSchema } from "../proto/gen/spark_pb.ts";
import { decodeSparkAddress, encodeSparkAddressBytes } from "./address.ts";
import { COMPRESSED_PUBLIC_KEY_LENGTH, requireLength } from "./assert.ts";
import { hashSparkInvoice } from "./hashing/invoice.ts";
import {
  encodeInvoiceFields,
  INVOICE_VERSION,
  protoInvoiceToPlain,
  validateInvoiceFields,
} from "./invoice.ts";
import type { SparkInvoiceFields } from "./invoice.ts";
import type { SparkNetwork } from "./network.ts";
import { uuidFromBytes, uuidToBytes, uuidv7 } from "./uuid.ts";

// Upstream reference: signer/spark-token-primitives/src/invoice.rs
// (buildonspark/spark@0b3a32a). Token invoice preparation and finalization:
// the unsigned invoice is hashed once for the sender's BIP-340 signature and
// the canonical fields bytes are embedded in the address verbatim.

const MEMO_MAX_BYTES = 120;
const TOKEN_IDENTIFIER_LENGTH = 32;
const MAX_TOKEN_AMOUNT_BYTES = 16;
const ID_LENGTH = 16;
const SIGNATURE_LENGTH = 64;

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

function validateTokenInvoiceFields(invoice: SparkInvoiceFields): void {
  validateInvoiceFields(invoice, { requireCurrentVersion: true });
  if (invoice.payment === undefined || invoice.payment.type !== "tokens") {
    throw new SparkInputError("expected token invoice, got sats invoice or no payment");
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
    COMPRESSED_PUBLIC_KEY_LENGTH,
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
  const invoiceFieldsBytes = encodeInvoiceFields(invoice);
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
    COMPRESSED_PUBLIC_KEY_LENGTH,
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
