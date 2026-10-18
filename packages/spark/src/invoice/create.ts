import { numberToVarBytesBE } from "@noble/curves/utils.js";

import { encodeSparkAddress } from "../core/address.ts";
import { encodeInvoiceFields, INVOICE_VERSION, validateInvoiceFields } from "../core/invoice.ts";
import type { SparkInvoiceFields } from "../core/invoice.ts";
import type { SparkNetwork } from "../core/network.ts";
import { finalizeTokenInvoice, prepareTokenInvoice } from "../core/token-invoice.ts";
import { uuidv7 } from "../core/uuid.ts";
import { SparkInputError } from "../errors/index.ts";
import type { SparkSigner } from "../signer/types.ts";

// Upstream reference: spark-wallet/spark-wallet.ts createSatsInvoice /
// createTokensInvoice (buildonspark/spark@0b3a32a). Invoices are signed by the
// receiver's own identity key; this module only creates invoices for the
// caller's own identity.

const MAX_UINT128 = (1n << 128n) - 1n;

type InvoiceOptions = {
  readonly signer: SparkSigner;
  readonly network: SparkNetwork;
  readonly random: (length: number) => Uint8Array;
  readonly now: () => number;
  readonly memo?: string;
  /** Restricts payment to this sender identity public key. */
  readonly senderPublicKey?: Uint8Array;
  /** Unix milliseconds; the invoice is rejected once expired. */
  readonly expiresAtMs?: number;
};

/**
 * Builds a signed sats invoice address for this identity. `amountSats` may be omitted for an
 * open-amount invoice the payer fills in.
 */
export async function createSatsInvoice(
  options: InvoiceOptions & { readonly amountSats?: number },
): Promise<string> {
  const identityPublicKey = await options.signer.identityPublicKey();
  const fields: SparkInvoiceFields = {
    version: INVOICE_VERSION,
    id: uuidv7(options.random, options.now),
    payment: { type: "sats", amount: options.amountSats },
    ...(options.memo === undefined ? {} : { memo: options.memo }),
    ...(options.senderPublicKey === undefined ? {} : { senderPublicKey: options.senderPublicKey }),
    ...(options.expiresAtMs === undefined ? {} : { expiresAt: options.expiresAtMs }),
  };
  validateInvoiceFields(fields, { requireCurrentVersion: true });
  const signature = await options.signer.signIdentity({
    kind: "spark-invoice",
    invoice: encodeInvoiceFields(fields),
  });
  // encodeSparkAddress embeds encodeInvoiceFields(fields) — the canonical bytes the signature
  // was produced over.
  return encodeSparkAddress({
    network: options.network,
    identityPublicKey,
    invoice: fields,
    signature,
  });
}

/**
 * Builds a signed tokens invoice address for this identity. `tokenIdentifier` (32 bytes raw) and
 * `amount` may be omitted; payers then pick the token and amount.
 */
export async function createTokensInvoice(
  options: InvoiceOptions & {
    readonly tokenIdentifier?: Uint8Array;
    readonly amount?: bigint;
  },
): Promise<string> {
  const identityPublicKey = await options.signer.identityPublicKey();
  if (options.amount !== undefined && (options.amount <= 0n || options.amount > MAX_UINT128)) {
    throw new SparkInputError("token invoice amount must be a positive uint128");
  }
  const prepared = prepareTokenInvoice({
    receiverIdentityPublicKey: identityPublicKey,
    network: options.network,
    ...(options.tokenIdentifier === undefined ? {} : { tokenIdentifier: options.tokenIdentifier }),
    ...(options.amount === undefined ? {} : { tokenAmount: numberToVarBytesBE(options.amount) }),
    ...(options.memo === undefined ? {} : { memo: options.memo }),
    ...(options.senderPublicKey === undefined
      ? {}
      : {
          senderAddress: encodeSparkAddress({
            network: options.network,
            identityPublicKey: options.senderPublicKey,
          }),
        }),
    ...(options.expiresAtMs === undefined ? {} : { expiresAtMs: options.expiresAtMs }),
    random: options.random,
    now: options.now,
  });
  // The signer computes hashSparkInvoice over the canonical fields bytes — the same digest as
  // prepared.invoiceHash — and the final address embeds those bytes verbatim.
  const signature = await options.signer.signIdentity({
    kind: "spark-invoice",
    invoice: prepared.invoiceFieldsBytes,
  });
  return finalizeTokenInvoice({
    receiverIdentityPublicKey: identityPublicKey,
    network: options.network,
    invoiceFieldsBytes: prepared.invoiceFieldsBytes,
    signature,
  });
}
