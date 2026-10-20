import { equalBytes } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { decodeBolt11 } from "../core/bolt11.ts";
import { SparkError } from "../errors/index.ts";
import type { SspClient } from "../ssp/index.ts";

/** Coarse outcome of a lightning send, derived from the SSP status and the verified preimage. */
export type LightningSendOutcome = "pending" | "succeeded" | "failed" | "returned";

/**
 * SSP send statuses where the payment will not settle. `PENDING_USER_SWAP_RETURN` and
 * `USER_SWAP_RETURN_FAILED` are transient stages of the SSP's swap-return flow — the return retries
 * until `USER_SWAP_RETURNED` (≈5 min observed on hosted). `USER_TRANSFER_VALIDATION_FAILED` has no
 * return flow: the funds come back only when the committed transfer expires.
 */
const LIGHTNING_SEND_FAILED = new Set([
  "LIGHTNING_PAYMENT_FAILED",
  "TRANSFER_FAILED",
  "PREIMAGE_PROVIDING_FAILED",
  "USER_TRANSFER_VALIDATION_FAILED",
  "PENDING_USER_SWAP_RETURN",
  "USER_SWAP_RETURN_FAILED",
]);

export type LightningSendStatus = {
  readonly status: string;
  /**
   * "succeeded" once a verified preimage is present; "returned" once the SSP reports
   * `USER_SWAP_RETURNED` — the leaves reappear in `leaves()` on the next sync. "failed" means the
   * payment will not settle but the swap return has not finished — keep polling until "returned".
   * Everything else is "pending".
   */
  readonly outcome: LightningSendOutcome;
  /** The settled payment preimage — present once the SSP reports the send paid. */
  readonly preimage?: Uint8Array;
};

export type LightningReceiveStatus = {
  readonly status: string;
  /** The inbound transfer's spark id, once the SSP reports the payment arrived. */
  readonly transferId?: string;
  /** The settled payment preimage — verified against the request invoice's payment hash. */
  readonly preimage?: Uint8Array;
};

/** A `LightningPayment` satisfies this shape — pass the pay() result straight in. */
export type LightningSendStatusRequest = {
  readonly requestId: string;
  /** The payment hash of the invoice we paid — the proof target, not SSP-supplied data. */
  readonly paymentHash: Uint8Array;
};

/**
 * `user_request` status of a lightning send. Both the request's invoice and a returned preimage are
 * checked against the payment hash of the invoice we actually paid — an SSP answering with a
 * self-consistent status for a different payment must not look like proof of ours.
 */
export async function lightningSendStatus(
  ssp: SspClient,
  request: LightningSendStatusRequest,
): Promise<LightningSendStatus> {
  const status = await ssp.lightningSendRequest(request.requestId);
  const invoice = decodeBolt11(status.encodedInvoice);
  if (!equalBytes(invoice.paymentHash, request.paymentHash)) {
    throw new SparkError("lightning send status: request invoice is not the invoice we paid");
  }
  if (
    status.paymentPreimage !== undefined &&
    !equalBytes(sha256(status.paymentPreimage), request.paymentHash)
  ) {
    throw new SparkError("lightning send status: preimage does not match the paid payment hash");
  }
  const outcome: LightningSendOutcome =
    status.paymentPreimage === undefined
      ? status.status === "USER_SWAP_RETURNED"
        ? "returned"
        : LIGHTNING_SEND_FAILED.has(status.status)
          ? "failed"
          : "pending"
      : "succeeded";
  return {
    status: status.status,
    outcome,
    ...(status.paymentPreimage === undefined ? {} : { preimage: status.paymentPreimage }),
  };
}

/**
 * `user_request` status of a lightning receive, with the inbound transfer id once present. A
 * reported preimage is returned only after `sha256(preimage)` is checked against the request
 * invoice's own payment hash — a mismatched preimage must not look like settlement proof.
 */
export async function lightningReceiveStatus(
  ssp: SspClient,
  requestId: string,
): Promise<LightningReceiveStatus> {
  const request = await ssp.lightningReceiveRequest(requestId);
  if (request.paymentPreimage !== undefined) {
    const invoice = decodeBolt11(request.invoice);
    if (!equalBytes(sha256(request.paymentPreimage), invoice.paymentHash)) {
      throw new SparkError(
        "lightning receive status: preimage does not match the invoice payment hash",
      );
    }
  }
  return {
    status: request.status,
    ...(request.transferId === undefined ? {} : { transferId: request.transferId }),
    ...(request.paymentPreimage === undefined ? {} : { preimage: request.paymentPreimage }),
  };
}
