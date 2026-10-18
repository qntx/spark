import { decodeSparkAddress, verifySparkAddressSignature } from "../core/address.ts";
import type { SparkInvoiceFields } from "../core/invoice.ts";
import type { SparkNetwork } from "../core/network.ts";
import { SparkInputError } from "../errors/index.ts";

export type ParsedSparkInvoice = {
  readonly receiverIdentityPublicKey: Uint8Array;
  readonly fields: SparkInvoiceFields;
  /** True when the invoice carries a signature that verifies under the receiver's key. */
  readonly signed: boolean;
};

/**
 * Decodes and validates a signed invoice address: must be an invoice-carrying Spark address for
 * `network`, any signature must verify, and the invoice must not be expired at `now`.
 */
export function parseSparkInvoice(
  text: string,
  options: { readonly network: SparkNetwork; readonly now: number },
): ParsedSparkInvoice {
  const address = decodeSparkAddress(text);
  if (address.invoice === undefined) {
    throw new SparkInputError("invoice: address carries no invoice fields");
  }
  if (address.network !== options.network) {
    throw new SparkInputError(`invoice: address is for ${address.network}`);
  }
  const signed = address.signature !== undefined;
  if (signed && !verifySparkAddressSignature(address)) {
    throw new SparkInputError("invoice: signature is invalid");
  }
  if (address.invoice.expiresAt !== undefined && address.invoice.expiresAt <= options.now) {
    throw new SparkInputError("invoice: expired");
  }
  return {
    receiverIdentityPublicKey: address.identityPublicKey,
    fields: address.invoice,
    signed,
  };
}
