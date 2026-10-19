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

/**
 * `user_request` status of a lightning send. A returned preimage is checked against the request's
 * invoice payment hash before it is handed back — a wrong preimage must never look like proof of
 * payment.
 */
export async function lightningSendStatus(
  ssp: SspClient,
  requestId: string,
): Promise<LightningSendStatus> {
  const request = await ssp.lightningSendRequest(requestId);
  if (request.paymentPreimage === undefined) {
    return { status: request.status };
  }
  const invoice = decodeBolt11(request.encodedInvoice);
  if (!equalBytes(sha256(request.paymentPreimage), invoice.paymentHash)) {
    throw new SparkError("lightning send status: preimage does not match the invoice payment hash");
  }
  return { status: request.status, preimage: request.paymentPreimage };
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
