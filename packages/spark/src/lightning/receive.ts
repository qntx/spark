import { equalBytes, hexToBytes } from "@noble/curves/utils.js";

import { decodeBolt11 } from "../core/bolt11.ts";
import type { Bolt11Invoice } from "../core/bolt11.ts";
import { SparkInputError, SparkRequestError } from "../errors/index.ts";
import type { LightningDeps } from "./types.ts";

// Lightning receive via the SSP: upstream services/lightning.ts createLightningInvoice
// (buildonspark/spark@0b3a32a) and Breez crates/spark/src/services/lightning.rs.

/** Default receive-invoice validity — 30 days, matching upstream and Breez. */
export const LIGHTNING_INVOICE_EXPIRY_SECS: number = 30 * 24 * 60 * 60;

/**
 * Route-hint short channel id under which the SSP embeds the receiver's Spark address (decimal
 * 17592187092992000001).
 */
export const SPARK_ROUTE_SHORT_CHANNEL_ID: Uint8Array = hexToBytes("f42400f424000001");

export type LightningInvoice = {
  /** The SSP lightning receive request id — pass to `lightningReceiveStatus`. */
  readonly id: string;
  /** The encoded BOLT-11 invoice to hand to the payer. */
  readonly invoice: string;
  readonly paymentHash: Uint8Array;
  readonly amountSats: number;
  readonly expiresAtMs: number;
};

/**
 * The invoice the SSP returns must pay exactly what we asked for — anything else makes the payer
 * settle terms we never agreed to (Breez `validate_received_invoice`). `memo` and `expiry` are
 * advisory: the SSP may shorten or normalize them, so they are not compared.
 */
function validateReceivedInvoice(
  invoice: Bolt11Invoice,
  request: {
    readonly paymentHash: Uint8Array;
    readonly amountSats: number;
    readonly descriptionHash?: Uint8Array | undefined;
  },
  network: string,
): void {
  if (!equalBytes(invoice.paymentHash, request.paymentHash)) {
    throw new SparkRequestError("ssp invoice payment hash does not match the requested hash");
  }
  if (invoice.network !== network) {
    throw new SparkRequestError("ssp invoice network does not match the requested network");
  }
  // A zero request asks for an amountless invoice; a fixed amount is as much a mismatch as the
  // wrong one — it pins the payer to an amount we never asked for.
  const expectedMsat = request.amountSats > 0 ? BigInt(request.amountSats) * 1000n : undefined;
  if (invoice.amountMsat !== expectedMsat) {
    throw new SparkRequestError("ssp invoice amount does not match the requested amount");
  }
  if (
    request.descriptionHash !== undefined &&
    (invoice.descriptionHash === undefined ||
      !equalBytes(invoice.descriptionHash, request.descriptionHash))
  ) {
    throw new SparkRequestError("ssp invoice description hash does not match the requested hash");
  }
}

/**
 * The Spark address embedded in an SSP-returned receive invoice's route hints must be the payee's,
 * and present only if we asked for one — a payer that finds an address transfers to it directly, so
 * an injected address is paid instead of the payee (Breez `validate_received_spark_address`). EVERY
 * hop under the Spark short channel id is checked: one foreign hop among several would pass a
 * first-match scan just the same.
 */
function validateReceivedSparkAddress(
  invoice: Bolt11Invoice,
  includeSparkAddress: boolean,
  payeeIdentityPublicKey: Uint8Array,
): void {
  const sparkHops = invoice.routeHints
    .flat()
    .filter((hop) => equalBytes(hop.shortChannelId, SPARK_ROUTE_SHORT_CHANNEL_ID));
  if (!includeSparkAddress) {
    if (sparkHops.length > 0) {
      throw new SparkRequestError("ssp invoice carries a spark address that was not requested");
    }
    return;
  }
  if (sparkHops.length === 0) {
    throw new SparkRequestError("ssp invoice is missing the requested spark address");
  }
  for (const hop of sparkHops) {
    if (!equalBytes(hop.publicKey, payeeIdentityPublicKey)) {
      throw new SparkRequestError("ssp invoice spark address does not match the payee identity");
    }
  }
}

/**
 * Requests a BOLT-11 receive invoice from the SSP: the signer generates the preimage (it never
 * leaves) and the per-operator ECIES shares; the returned invoice is validated field by field
 * before the preimage shares are stored with the coordinator — a bad invoice must not bind our
 * preimage to it.
 */
export async function createLightningInvoice(
  deps: LightningDeps,
  options: {
    readonly amountSats: number;
    readonly memo?: string;
    readonly descriptionHash?: Uint8Array;
    readonly expirySecs?: number;
    readonly includeSparkAddress?: boolean;
    /**
     * Payee's identity public key. When set, the invoice is created for that identity: the SSP
     * routes the incoming payment to it, the preimage share is stored under it, and an embedded
     * Spark address must be its (upstream `createLightningInvoiceWithPreImage`). Omitted, the
     * invoice pays this wallet's own identity.
     */
    readonly receiverIdentityPublicKey?: Uint8Array;
  },
): Promise<LightningInvoice> {
  // Reject malformed options before any signer work — an invalid request must not sign.
  const expirySecs = options.expirySecs ?? LIGHTNING_INVOICE_EXPIRY_SECS;
  if (!Number.isSafeInteger(options.amountSats) || options.amountSats < 0) {
    throw new SparkInputError("lightning receive: amountSats must be a non-negative integer");
  }
  if (!Number.isSafeInteger(expirySecs) || expirySecs <= 0) {
    throw new SparkInputError("lightning receive: expirySecs must be a positive integer");
  }
  if (options.descriptionHash !== undefined && options.descriptionHash.length !== 32) {
    throw new SparkInputError("lightning receive: descriptionHash must be 32 bytes");
  }
  if (
    options.receiverIdentityPublicKey !== undefined &&
    options.receiverIdentityPublicKey.length !== 33
  ) {
    throw new SparkInputError("lightning receive: receiver identity public key must be 33 bytes");
  }

  const identityPublicKey = await deps.signer.identityPublicKey();
  const payeeIdentityPublicKey = options.receiverIdentityPublicKey ?? identityPublicKey;
  const prepared = await deps.signer.prepareLightningReceive();

  const request = await deps.ssp.requestLightningReceive({
    network: deps.network,
    amountSats: options.amountSats,
    paymentHash: prepared.paymentHash,
    expirySecs,
    receiverIdentityPublicKey: payeeIdentityPublicKey,
    ...(options.memo === undefined ? {} : { memo: options.memo }),
    ...(options.descriptionHash === undefined ? {} : { descriptionHash: options.descriptionHash }),
    ...(options.includeSparkAddress === undefined
      ? {}
      : { includeSparkAddress: options.includeSparkAddress }),
  });

  const invoice = decodeBolt11(request.invoice);
  // Both validations must precede the share store and the return: a mismatch has to abort the
  // receive before the invoice can reach a payer.
  validateReceivedInvoice(
    invoice,
    {
      paymentHash: prepared.paymentHash,
      amountSats: options.amountSats,
      descriptionHash: options.descriptionHash,
    },
    deps.network,
  );
  validateReceivedSparkAddress(
    invoice,
    options.includeSparkAddress === true,
    payeeIdentityPublicKey,
  );

  await deps.spark.store_preimage_share_v2({
    paymentHash: prepared.paymentHash,
    encryptedPreimageShares: prepared.operatorPackages,
    threshold: deps.threshold,
    invoiceString: request.invoice,
    userIdentityPublicKey: payeeIdentityPublicKey,
  });

  return {
    id: request.id,
    invoice: request.invoice,
    paymentHash: prepared.paymentHash,
    amountSats: options.amountSats,
    expiresAtMs: (invoice.timestamp + invoice.expirySeconds) * 1000,
  };
}
