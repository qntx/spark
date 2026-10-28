import { bytesToHex, equalBytes } from "@noble/curves/utils.js";

import { decodeBolt11 } from "../core/bolt11.ts";
import type { SspUserRequest } from "../ssp/types.ts";
import type { SparkTransfer } from "./model.ts";

/**
 * One entry of `client.transfers.history`: a transfer folded with its SSP `user_request` into the
 * wallet-facing payment shape. Mapping follows the Breez adaptor semantics; every field a consumer
 * displays comes from authenticated SO data or the SSP record — never from host input.
 */
export type SparkPayment = {
  readonly id: string;
  readonly direction: "send" | "receive";
  readonly status: "pending" | "completed" | "failed";
  readonly method: "spark" | "lightning" | "deposit" | "withdraw";
  /** Sats excluding fees — the total minus the fee for outbound sends and exits. */
  readonly amountSats: number;
  readonly feeSats: number;
  /** Milliseconds since the epoch; absent when the SO reports none. */
  readonly createdAt: number | undefined;
  readonly details:
    | { readonly kind: "spark"; readonly invoice?: string }
    | {
        readonly kind: "lightning";
        readonly invoice: string;
        /** Payment hash, hex. */
        readonly paymentHash: string;
        /** Payment preimage, hex. */
        readonly preimage?: string;
        readonly description?: string;
      }
    | { readonly kind: "withdraw"; readonly txid?: string }
    | { readonly kind: "deposit"; readonly txid: string; readonly vout: number }
    | undefined;
};

/**
 * CoopExitRequest statuses, bucketed per Breez's `SparkCoopExitRequestStatus::acceptance`: accepted
 * means the SSP took the exit over — the SO-side transfer status keeps telling completion; terminal
 * failures are failed; anything else (incl. unknown values) is pending.
 */
const COOP_EXIT_ACCEPTED = new Set([
  "INBOUND_TRANSFER_CHECKED",
  "TX_SIGNED",
  "TX_BROADCASTED",
  "WAITING_ON_TX_CONFIRMATIONS",
  "COMPLETE_REQUEST_RECEIVED",
  "ON_CHAIN_TX_CONFIRMED",
  "SUCCEEDED",
]);
const COOP_EXIT_FAILED = new Set([
  "EXPIRED",
  "FAILED",
  "INBOUND_TRANSFER_CLAIMING_FAILED",
  "EXPIRING_FAILED",
  "FAILING_FAILED",
]);

/**
 * Whether the transfer's counterparty is the SSP: the receiver on sends (any edge of a
 * multi-receiver), the sender on receives. Shared by the history batch-fetch and the mapper.
 */
export function sspCounterparty(
  transfer: SparkTransfer,
  identityPublicKey: Uint8Array,
  sspIdentityPublicKey: Uint8Array,
): boolean {
  return equalBytes(transfer.senderIdentityPublicKey, identityPublicKey)
    ? equalBytes(transfer.receiverIdentityPublicKey, sspIdentityPublicKey) ||
        transfer.receivers.some((receiver) =>
          equalBytes(receiver.identityPublicKey, sspIdentityPublicKey),
        )
    : equalBytes(transfer.senderIdentityPublicKey, sspIdentityPublicKey);
}

export function toSparkPayment(options: {
  readonly transfer: SparkTransfer;
  readonly request: SspUserRequest | undefined;
  readonly identityPublicKey: Uint8Array;
  readonly sspIdentityPublicKey: Uint8Array;
}): SparkPayment {
  const { transfer, request } = options;
  const direction = equalBytes(transfer.senderIdentityPublicKey, options.identityPublicKey)
    ? "send"
    : "receive";
  const isSsp = sspCounterparty(transfer, options.identityPublicKey, options.sspIdentityPublicKey);

  const method =
    transfer.type === "COOPERATIVE_EXIT"
      ? "withdraw"
      : transfer.type === "UTXO_SWAP"
        ? "deposit"
        : transfer.type === "PREIMAGE_SWAP"
          ? isSsp
            ? "lightning"
            : "spark"
          : "spark";

  let status: SparkPayment["status"];
  if (transfer.status === "COMPLETED") {
    status = "completed";
  } else if (direction === "send" && transfer.status === "SENDER_KEY_TWEAKED") {
    // Committed and claimable: the outbound leg is final for the payer even before the
    // receiver claims.
    status = "completed";
  } else if (transfer.status === "EXPIRED" || transfer.status === "RETURNED") {
    status = "failed";
  } else {
    status = "pending";
  }

  let feeSats = 0;
  // A multi-receiver transfer's total is the sum across edges — fee-less spark sends expose it
  // whole.
  let amountSats = transfer.totalValueSats;
  let details: SparkPayment["details"];

  switch (method) {
    case "lightning":
      if (request?.kind === "lightning-send") {
        if (request.preimage !== undefined) {
          // A known preimage settles the send even while the SO status still moves.
          status = "completed";
        }
        ({ feeSats } = request);
        amountSats = Math.max(0, transfer.totalValueSats - feeSats);
        details = lightningDetails(request.invoice, request.preimage);
      } else if (request?.kind === "lightning-receive") {
        details = lightningDetails(request.invoice, request.preimage);
      }
      break;
    case "withdraw":
      if (request?.kind === "coop-exit") {
        ({ feeSats } = request);
        amountSats = Math.max(0, transfer.totalValueSats - feeSats);
        if (COOP_EXIT_FAILED.has(request.status)) {
          status = "failed";
        } else if (!COOP_EXIT_ACCEPTED.has(request.status)) {
          status = "pending";
        }
        details = {
          kind: "withdraw",
          ...(request.txid === undefined ? {} : { txid: request.txid }),
        };
      }
      break;
    case "deposit":
      if (request?.kind === "static-deposit") {
        // The deposit is the on-chain UTXO value; the transfer total is the credited amount —
        // the fee is their difference.
        feeSats = Math.max(0, request.depositAmountSats - request.creditAmountSats);
        details = { kind: "deposit", txid: request.txid, vout: request.vout };
      }
      break;
    case "spark":
      details = {
        kind: "spark",
        ...(transfer.sparkInvoice === undefined ? {} : { invoice: transfer.sparkInvoice }),
      };
      break;
  }

  // An SSP-method transfer can only be called completed from the SSP record itself — a missing
  // request or a failed detail parse leaves it pending rather than guessing.
  if (method !== "spark" && details === undefined) {
    status = "pending";
  }

  return {
    id: transfer.id,
    direction,
    status,
    method,
    amountSats,
    feeSats,
    createdAt: transfer.createdTimeMs,
    details,
  };
}

function lightningDetails(
  invoice: string,
  preimage: Uint8Array | undefined,
): SparkPayment["details"] | undefined {
  try {
    const decoded = decodeBolt11(invoice);
    return {
      kind: "lightning",
      invoice,
      paymentHash: bytesToHex(decoded.paymentHash),
      ...(decoded.description === undefined ? {} : { description: decoded.description }),
      ...(preimage === undefined ? {} : { preimage: bytesToHex(preimage) }),
    };
  } catch {
    return undefined;
  }
}
