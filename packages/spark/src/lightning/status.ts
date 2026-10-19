import { equalBytes } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { decodeBolt11 } from "../core/bolt11.ts";
import { SparkError } from "../errors/index.ts";
import type { SspClient } from "../ssp/index.ts";

export type LightningSendStatus = {
  readonly status: string;
  /** The settled payment preimage — present once the SSP reports the send paid. */
  readonly preimage?: Uint8Array;
};

export type LightningReceiveStatus = {
  readonly status: string;
  /** The inbound transfer's spark id, once the SSP reports the payment arrived. */
  readonly transferId?: string;
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
  return {
    status: status.status,
    ...(status.paymentPreimage === undefined ? {} : { preimage: status.paymentPreimage }),
  };
}

/** `user_request` status of a lightning receive, with the inbound transfer id once present. */
export async function lightningReceiveStatus(
  ssp: SspClient,
  requestId: string,
): Promise<LightningReceiveStatus> {
  const request = await ssp.lightningReceiveRequest(requestId);
  return {
    status: request.status,
    ...(request.transferId === undefined ? {} : { transferId: request.transferId }),
  };
}
