import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import { equalBytes } from "@noble/curves/utils.js";

import {
  createRefundTxsForLightning,
  getNextHTLCTransactionSequence,
  lightningHtlcOutputScript,
  parseTransaction,
} from "../core/bitcoin/index.ts";
import { decodeBolt11, isExpired } from "../core/bolt11.ts";
import type { Bolt11Invoice } from "../core/bolt11.ts";
import { uuidv7 } from "../core/uuid.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import {
  InitiatePreimageSwapRequest_Reason,
  StartTransferRequestSchema,
  TransferType,
} from "../proto/gen/spark_pb.ts";
import { mapTransfer } from "../transfer/model.ts";
import type { SparkTransfer } from "../transfer/model.ts";
import {
  assertCommittedTransfer,
  assertLiveTransfer,
  queryCommittedTransfer,
  queryTransferById,
  verifyTransferAcrossOperators,
} from "../transfer/query.ts";
import { prepareTransferPackage } from "../transfer/send.ts";
import type { SparkLeaf } from "../tree/index.ts";
import type { LightningDeps } from "./types.ts";

// Lightning send via the SSP: upstream spark-wallet.ts payLightningInvoice +
// services/lightning.ts swapNodesForPreimage, and Breez services/lightning.rs send flow.

/** The preimage-swap transfer's expiry — ~16 days, both reference implementations agree. */
export const LIGHTNING_TRANSFER_EXPIRY_MS: number = 16 * 24 * 60 * 60 * 1000;

export type LightningPayment = {
  /** The preimage-swap transfer id — the idempotency handle for retries. */
  readonly transferId: string;
  /** The SSP lightning send request id — pass to `lightningSendStatus`. */
  readonly requestId: string;
  readonly status: string;
  readonly paymentHash: Uint8Array;
  readonly amountSats: number;
  readonly feeSats: number;
};

/**
 * The sats to pay: fixed invoices carry their own amount and reject `amountSats`; amountless
 * invoices require it. Millisatoshis round up to sats (upstream behaviour).
 */
export function lightningInvoiceAmount(
  invoice: Bolt11Invoice,
  amountSats: number | undefined,
): number {
  const invoiceMsat = invoice.amountMsat;
  if (invoiceMsat === undefined) {
    if (amountSats === undefined) {
      throw new SparkInputError("lightning pay: amountSats is required for a zero-amount invoice");
    }
    if (!Number.isSafeInteger(amountSats) || amountSats <= 0) {
      throw new SparkInputError("lightning pay: amountSats must be a positive integer");
    }
    return amountSats;
  }
  if (amountSats !== undefined) {
    throw new SparkInputError("lightning pay: amountSats is only valid for a zero-amount invoice");
  }
  const amount = Math.ceil(Number(invoiceMsat) / 1000);
  if (!Number.isSafeInteger(amount) || amount <= 0) {
    throw new SparkInputError("lightning pay: invoice amount must be a positive integer");
  }
  return amount;
}

/**
 * Pays a BOLT-11 invoice over Lightning: selects `amount + fee` of leaves, wraps their refunds in
 * HTLCs (hash-lock → SSP, sequence-lock → us), commits them in a preimage-swap transfer and asks
 * the SSP to settle the invoice. On a lost `initiate_preimage_swap_v3` response the transfer id
 * doubles as the idempotency key, so a committed swap is picked up instead of retried blind.
 *
 * `spendLeaves` hands `use` AVAILABLE leaves summing exactly to the requested amount and keeps the
 * client's leaf lock held until `use` resolves — package build, commit and chain cleanup inside
 * `use` cannot interleave with another spend; the client injects the shared select/swap/renew path
 * it uses for ordinary sends.
 */
export async function payLightningInvoice(
  deps: LightningDeps & {
    readonly spendLeaves: <T>(
      amountSats: number,
      use: (leaves: ReadonlyArray<SparkLeaf>) => Promise<T>,
    ) => Promise<T>;
    readonly deleteExitChains: (leafIds: ReadonlyArray<string>) => Promise<void>;
  },
  options: {
    readonly invoice: string;
    readonly maxFeeSats: number;
    /** Payer-chosen amount — only valid for a zero-amount invoice. */
    readonly amountSats?: number;
    /** UUID to reuse on retries so a repeat resolves to the same transfer. */
    readonly transferId?: string;
  },
): Promise<LightningPayment> {
  const { spark, ssp, sspIdentityPublicKey, signer, network } = deps;
  // The fee gate must hold a real number before any SSP call: NaN or a cast undefined otherwise
  // makes every `feeSats > maxFeeSats` comparison false and lifts the cap entirely.
  if (!Number.isSafeInteger(options.maxFeeSats) || options.maxFeeSats < 0) {
    throw new SparkInputError("lightning pay: maxFeeSats must be a non-negative integer");
  }
  const invoice = options.invoice.toLowerCase();
  const decoded = decodeBolt11(invoice);
  if (decoded.network !== network) {
    throw new SparkInputError(
      `lightning pay: invoice is for ${decoded.network}, wallet is on ${network}`,
    );
  }
  if (isExpired(decoded, deps.now())) {
    throw new SparkInputError("lightning pay: invoice is expired");
  }
  const amountSats = lightningInvoiceAmount(decoded, options.amountSats);
  const isZeroAmount = decoded.amountMsat === undefined;
  const transferId = options.transferId ?? uuidv7(deps.random, deps.now);

  const identityPublicKey = await signer.identityPublicKey();
  const expected = {
    transferId,
    type: TransferType.PREIMAGE_SWAP,
    senderIdentityPublicKey: identityPublicKey,
    receiverIdentityPublicKeys: [sspIdentityPublicKey],
  } as const;
  // The output-0 script the fresh path writes into every HTLC refund variant (hash-lock → SSP,
  // sequence-lock 2160 → our identity key). Used to bind a committed transfer to THIS invoice's
  // payment hash — see {@link assertCommittedPaymentHash}.
  const expectedHtlcScript = lightningHtlcOutputScript(
    decoded.paymentHash,
    sspIdentityPublicKey,
    identityPublicKey,
  );

  // A caller-supplied id is the idempotency handle: a committed swap under it means this call is
  // a retry — skip the fee estimate, leaf selection and package building, and continue with the
  // post-commit steps. A committed swap under different terms fails rather than riding along on
  // the reused id.
  let transfer: SparkTransfer | undefined;
  if (options.transferId !== undefined) {
    transfer = await queryTransferById({ spark, network, transferId });
    if (transfer !== undefined) {
      assertLiveTransfer(transfer);
    }
  }

  /**
   * The committed swap's HTLC refunds must lock to this invoice's payment hash — a retry naming a
   * different invoice must not ride a transfer built for another payment. The expected output
   * script is rebuilt exactly as the fresh path builds it (`constructHtlcTransaction`'s two-leaf
   * NUMS tree); the input sequence, prevout and fee never enter the script, so comparing output 0
   * of each intermediate refund variant is sufficient. A leaf with no intermediate refunds at all
   * fails closed — the fresh path always produces at least the cpfp variant.
   *
   * A zero-amount invoice adds one caveat: the `invoiceAmount` the first call committed is stored
   * server-side only, so the committed amount cannot be re-verified here beyond the `totalValueSats
   * − amountSats` fee bound below — retry a zero-amount invoice only with the same amountSats.
   */
  function assertCommittedPaymentHash(transfer: SparkTransfer): void {
    for (const transferLeaf of transfer.leaves) {
      const variants: ReadonlyArray<readonly [string, Uint8Array]> = [
        ["refund", transferLeaf.intermediateRefundTx],
        ["direct refund", transferLeaf.intermediateDirectRefundTx],
        ["direct-from-cpfp refund", transferLeaf.intermediateDirectFromCpfpRefundTx],
      ];
      let checked = 0;
      for (const [variant, txBytes] of variants) {
        if (txBytes.length === 0) {
          continue;
        }
        checked += 1;
        let output;
        try {
          output = parseTransaction(txBytes).getOutput(0);
        } catch (error) {
          throw new SparkError(
            `lightning pay: committed transfer ${transfer.id} leaf ` +
              `${transferLeaf.leaf.id} ${variant} tx does not parse`,
            { cause: error },
          );
        }
        if (output.script === undefined || !equalBytes(output.script, expectedHtlcScript)) {
          throw new SparkError(
            `lightning pay: committed transfer ${transfer.id} is locked to a ` +
              "different payment hash",
          );
        }
      }
      if (checked === 0) {
        throw new SparkError(
          `lightning pay: committed transfer ${transfer.id} leaf ` +
            `${transferLeaf.leaf.id} carries no intermediate refunds`,
        );
      }
    }
  }

  let feeSats: number;
  if (transfer === undefined) {
    // The SSP charges the fee separately; only amountless invoices take an amount for it.
    feeSats = await ssp.lightningSendFeeEstimate(invoice, isZeroAmount ? amountSats : undefined);
    if (feeSats > options.maxFeeSats) {
      throw new SparkInputError(
        `lightning pay: fee estimate ${feeSats} exceeds maxFeeSats ${options.maxFeeSats}`,
      );
    }
    // Selection through commit and the spent leaves' chain deletion runs under the client's leaf
    // lock: a concurrent spend sees the committed leaves gone from its own sync.
    transfer = await deps.spendLeaves(amountSats + feeSats, async (leaves) => {
      const committed = await initiatePreimageSwap(leaves);
      assertCommittedTransfer(committed, expected, "lightning pay");
      assertCommittedPaymentHash(committed);
      // No cross-operator gate on this call's own commit: the swap already committed server-side,
      // and an operator error or lag here would strand the payment we must now finish (a preimage
      // swap waits ~16 days for its refund path). The gate applies to probe hits — commits an
      // earlier call made — in the `transferId` resume below.
      // The leaves are committed under HTLC refunds now, so the old refund txs must not survive a
      // failure on the SSP call below. Only leaf ids this call both selected and the committed
      // transfer names are deleted — a reported list cannot strip other leaves' exit data (N-01);
      // the leftover ids' chains are reclaimed by the endorsed sync sweep.
      const selected = new Set(leaves.map((leaf) => leaf.id));
      const spent = [
        ...new Set(
          committed.leaves
            .map((transferLeaf) => transferLeaf.leaf.id)
            .filter((leafId) => selected.has(leafId)),
        ),
      ];
      if (spent.length > 0) {
        await deps.deleteExitChains(spent);
      }
      return committed;
    });
  } else {
    assertCommittedTransfer(transfer, expected, "lightning pay");
    await verifyTransferAcrossOperators({
      operators: deps.operatorSparks,
      network,
      transfer,
      compareIntermediateRefunds: true,
    });
    assertCommittedPaymentHash(transfer);
    // The swap commits amount + fee as the transfer total; the committed total is the fee source.
    feeSats = transfer.totalValueSats - amountSats;
    if (feeSats < 0 || feeSats > options.maxFeeSats) {
      throw new SparkInputError(
        `lightning pay: committed transfer fee ${feeSats} exceeds maxFeeSats ${options.maxFeeSats}`,
      );
    }
    // A probe hit deletes nothing: the leaves were committed in an earlier call, and the endorsed
    // sync sweep reclaims them — a reported leaf list never decides deletions on its own (N-01).
  }

  /** Wraps `leaves`' refunds in HTLCs and commits the preimage-swap transfer. */
  async function initiatePreimageSwap(leaves: ReadonlyArray<SparkLeaf>): Promise<SparkTransfer> {
    // Hash-locked to the SSP (preimage path) and sequence-locked back to us (refund path);
    // sequences decrement from each leaf's current refund sequence per the HTLC offsets.
    const transferPackage = await prepareTransferPackage({
      spark,
      signer,
      network,
      operators: deps.operators,
      threshold: deps.threshold,
      transferId,
      leaves: leaves.map((leaf) => ({
        leaf,
        receiverIdentityPublicKey: sspIdentityPublicKey,
      })),
      buildRefunds: (entry, sequence) => {
        const { nextSequence, nextDirectSequence } = getNextHTLCTransactionSequence(sequence);
        const refunds = createRefundTxsForLightning({
          nodeTx: entry.leaf.nodeTx,
          directNodeTx: entry.leaf.directTx,
          vout: 0,
          sequence: nextSequence,
          directSequence: nextDirectSequence,
          paymentHash: decoded.paymentHash,
          hashLockDestinationPublicKey: sspIdentityPublicKey,
          sequenceLockDestinationPublicKey: identityPublicKey,
        });
        return {
          refunds: {
            cpfpRefund: refunds.cpfpRefundTx,
            directRefund: refunds.directRefundTx,
            directFromCpfpRefund: refunds.directFromCpfpRefundTx,
          },
        };
      },
    });

    const transferRequest = create(StartTransferRequestSchema, {
      transferId,
      ownerIdentityPublicKey: identityPublicKey,
      receiverIdentityPublicKey: sspIdentityPublicKey,
      transferPackage,
      expiryTime: timestampFromDate(new Date(deps.now() + LIGHTNING_TRANSFER_EXPIRY_MS)),
    });

    try {
      const response = await spark.initiate_preimage_swap_v3(
        {
          paymentHash: decoded.paymentHash,
          invoiceAmount: {
            invoiceAmountProof: { bolt11Invoice: invoice },
            valueSats: BigInt(amountSats),
          },
          reason: InitiatePreimageSwapRequest_Reason.SEND,
          receiverIdentityPublicKey: sspIdentityPublicKey,
          feeSats: BigInt(feeSats),
          transferRequest,
        },
        { headers: { "x-idempotency-key": transferId } },
      );
      if (response.transfer === undefined) {
        throw new SparkError("lightning pay: preimage swap returned no transfer");
      }
      return mapTransfer(response.transfer);
    } catch (error) {
      // The swap can commit server-side and still lose its response. The committed transfer is
      // the only sound test — a retry must continue with it rather than fail or double-pay.
      const recovered = await queryCommittedTransfer({ spark, network, ...expected });
      if (recovered === undefined) {
        throw error;
      }
      return recovered;
    }
  }

  // The SSP refuses `idempotency_key` alongside the external id; the transfer id keys the request.
  const sendRequest = await ssp.requestLightningSend({
    encodedInvoice: invoice,
    ...(isZeroAmount ? { amountSats } : {}),
    userOutboundTransferExternalId: transfer.id,
  });
  if (sendRequest.encodedInvoice.toLowerCase() !== invoice) {
    throw new SparkError("lightning pay: ssp send request is for a different invoice");
  }
  if (sendRequest.transferId !== undefined && sendRequest.transferId !== transfer.id) {
    throw new SparkError(
      `lightning pay: ssp send request is bound to transfer ${sendRequest.transferId}, ` +
        `expected ${transfer.id}`,
    );
  }

  return {
    transferId: transfer.id,
    requestId: sendRequest.id,
    status: sendRequest.status,
    paymentHash: decoded.paymentHash,
    amountSats,
    feeSats,
  };
}
