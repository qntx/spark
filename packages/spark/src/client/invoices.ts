import { bytesToNumberBE, equalBytes } from "@noble/curves/utils.js";
import { bytesToHex } from "@noble/hashes/utils.js";

import { protoEnumName } from "../core/proto-enum.ts";
import { SparkInputError } from "../errors/index.ts";
import { createSatsInvoice, createTokensInvoice, parseSparkInvoice } from "../invoice/index.ts";
import { InvoiceStatus } from "../proto/gen/spark_pb.ts";
import type { ClientContext } from "./context.ts";
import type { SparkClient, SparkInvoiceStatus } from "./index.ts";
import { sendTokens } from "./tokens.ts";
import { sendSats } from "./transfers.ts";

/** Normalizes a caller-provided amount to bigint; undefined when not a whole number. */
function requestedAmount(requested: number | bigint): bigint | undefined {
  if (typeof requested === "bigint") {
    return requested;
  }
  return Number.isSafeInteger(requested) ? BigInt(requested) : undefined;
}

const MAX_UINT128 = (1n << 128n) - 1n;

function satsAmount(
  invoiceAmount: number | undefined,
  requested: number | bigint | undefined,
): number {
  if (invoiceAmount !== undefined) {
    if (requested !== undefined && requestedAmount(requested) !== BigInt(invoiceAmount)) {
      throw new SparkInputError("invoice: amount does not match the invoice amount");
    }
    return invoiceAmount;
  }
  if (requested === undefined) {
    throw new SparkInputError("invoice: open invoice, pass options.amount");
  }
  const amount = requestedAmount(requested);
  if (amount === undefined || amount <= 0n || amount > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new SparkInputError("invoice: amount must be a positive safe-integer sats amount");
  }
  return Number(amount);
}

function tokenAmount(
  invoiceAmount: Uint8Array | undefined,
  requested: number | bigint | undefined,
): bigint {
  const fixed = invoiceAmount === undefined ? undefined : bytesToNumberBE(invoiceAmount);
  if (fixed !== undefined) {
    if (requested !== undefined && requestedAmount(requested) !== fixed) {
      throw new SparkInputError("invoice: amount does not match the invoice amount");
    }
    return fixed;
  }
  if (requested === undefined) {
    throw new SparkInputError("invoice: open invoice, pass options.amount");
  }
  const amount = requestedAmount(requested);
  if (amount === undefined || amount <= 0n || amount > MAX_UINT128) {
    throw new SparkInputError("invoice: amount must be a positive uint128 token amount");
  }
  return amount;
}

export function createInvoices(context: ClientContext): SparkClient["invoices"] {
  const { coordinatorConnection, signer, network, random, now } = context;
  const clock = now;
  return {
    createSats: async (createOptions) =>
      createSatsInvoice({
        signer,
        network,
        random,
        now: clock,
        ...(createOptions?.amountSats === undefined
          ? {}
          : { amountSats: createOptions.amountSats }),
        ...(createOptions?.memo === undefined ? {} : { memo: createOptions.memo }),
        ...(createOptions?.senderPublicKey === undefined
          ? {}
          : { senderPublicKey: createOptions.senderPublicKey }),
        ...(createOptions?.expiresAtMs === undefined
          ? {}
          : { expiresAtMs: createOptions.expiresAtMs }),
      }),
    createTokens: async (createOptions) =>
      createTokensInvoice({
        signer,
        network,
        random,
        now: clock,
        ...(createOptions?.tokenIdentifier === undefined
          ? {}
          : { tokenIdentifier: context.tokenIdentifierForNetwork(createOptions.tokenIdentifier) }),
        ...(createOptions?.amount === undefined ? {} : { amount: createOptions.amount }),
        ...(createOptions?.memo === undefined ? {} : { memo: createOptions.memo }),
        ...(createOptions?.senderPublicKey === undefined
          ? {}
          : { senderPublicKey: createOptions.senderPublicKey }),
        ...(createOptions?.expiresAtMs === undefined
          ? {}
          : { expiresAtMs: createOptions.expiresAtMs }),
      }),
    pay: async (invoice, payOptions) => {
      const parsed = parseSparkInvoice(invoice, { network, now: clock() });
      if (
        parsed.fields.senderPublicKey !== undefined &&
        !equalBytes(parsed.fields.senderPublicKey, await signer.identityPublicKey())
      ) {
        throw new SparkInputError("invoice: payment is restricted to a different sender");
      }
      const { payment } = parsed.fields;
      if (payment?.type === "sats") {
        return sendSats(context, {
          receivers: [
            {
              receiverIdentityPublicKey: parsed.receiverIdentityPublicKey,
              amountSats: satsAmount(payment.amount, payOptions?.amount),
            },
          ],
          sparkInvoice: invoice,
          ...(payOptions?.transferId === undefined ? {} : { transferId: payOptions.transferId }),
        });
      }
      if (payment?.type === "tokens") {
        if (payment.tokenIdentifier === undefined) {
          throw new SparkInputError("invoice: token payment carries no token identifier");
        }
        const { transactionHash } = await sendTokens(context, {
          tokenIdentifier: payment.tokenIdentifier,
          amount: tokenAmount(payment.amount, payOptions?.amount),
          receiver: parsed.receiverIdentityPublicKey,
          invoiceAttachments: [invoice],
          ...(payOptions?.inputOutputIds === undefined
            ? {}
            : { inputOutputIds: payOptions.inputOutputIds }),
        });
        return transactionHash;
      }
      throw new SparkInputError("invoice: unsupported payment type");
    },
    status: async (invoices) => {
      const response = await coordinatorConnection.spark.query_spark_invoices({
        invoice: [...invoices],
      });
      const statuses: SparkInvoiceStatus[] = [];
      for (const entry of response.invoiceStatuses) {
        statuses.push({
          invoice: entry.invoice,
          status: protoEnumName(InvoiceStatus, entry.status),
          ...(entry.transferType.case === "satsTransfer"
            ? { satsTransferId: bytesToHex(entry.transferType.value.transferId) }
            : {}),
          ...(entry.transferType.case === "tokenTransfer"
            ? {
                tokenTransactionHash: bytesToHex(
                  entry.transferType.value.finalTokenTransactionHash,
                ),
              }
            : {}),
        });
      }
      return statuses;
    },
  };
}
