import { create } from "@bufbuild/protobuf";
import { timestampFromDate } from "@bufbuild/protobuf/wkt";
import type { Client } from "@connectrpc/connect";
import { equalBytes } from "@noble/curves/utils.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { Address, OutScript } from "@scure/btc-signer";

import { u64ToSats } from "../core/assert.ts";
import {
  btcNetwork,
  createConnectorRefundTxs,
  parseTransaction,
  taprootKeySpendSighash,
  txId,
  validateConnectorTxBindsToCoopExitTxid,
  validateCoopExitPayoutTransaction,
} from "../core/bitcoin/index.ts";
import type { RefundTxTrio } from "../core/bitcoin/index.ts";
import type { SparkNetwork, SparkOperatorConfig } from "../core/network.ts";
import { defaultSleep } from "../core/time.ts";
import { uuidv7 } from "../core/uuid.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import { StartTransferRequestSchema, TransferType } from "../proto/gen/spark_pb.ts";
import type { SparkService } from "../proto/gen/spark_pb.ts";
import type { SparkSigner } from "../signer/types.ts";
import type {
  SspClient,
  SspCoopExitFeeQuote,
  SspCoopExitSpeed,
  SspCoopExitStatus,
} from "../ssp/index.ts";
import { mapTransfer } from "../transfer/model.ts";
import type { SparkTransfer } from "../transfer/model.ts";
import {
  assertCommittedTransfer,
  assertLiveTransfer,
  queryCommittedTransfer,
  queryTransferById,
} from "../transfer/query.ts";
import { prepareTransferPackage } from "../transfer/send.ts";
import type { SparkLeaf } from "../tree/index.ts";

// Cooperative exit via the SSP: upstream spark-wallet.ts withdraw/coopExit +
// services/coop-exit.ts, and Breez services/coop_exit.rs. Fee-deduction mode only
// (withdraw_all: true) — paying the fee from separate leaves is not supported yet.

/** `cooperative_exit_v2` transfer expiry: 7d+5m on mainnet, 35m elsewhere (Breez constants). */
export const COOP_EXIT_TRANSFER_EXPIRY_MS: Record<SparkNetwork, number> = {
  mainnet: 7 * 24 * 60 * 60 * 1000 + 5 * 60 * 1000,
  regtest: 35 * 60 * 1000,
};

/**
 * SSP `SparkCoopExitRequestStatus` values where the SSP accepted the payout request — the exit
 * proceeds without us (Breez `acceptance()` plus the enum's deprecated equivalents).
 */
const COOP_EXIT_ACCEPTED = new Set([
  "COMPLETE_REQUEST_RECEIVED",
  "INBOUND_TRANSFER_CHECKED",
  "TX_SIGNED",
  // Observed live on the hosted SSP right after complete_coop_exit; Breez's enum predates it.
  "TX_BROADCASTING_SCHEDULED",
  "TX_BROADCASTED",
  "WAITING_ON_TX_CONFIRMATIONS",
  "ON_CHAIN_TX_CONFIRMED",
  "SUCCEEDED",
]);

/** Terminal failure values of the same enum — no retry can change the outcome. */
const COOP_EXIT_FAILED = new Set([
  "INBOUND_TRANSFER_CLAIMING_FAILED",
  "EXPIRING_FAILED",
  "EXPIRED",
  "FAILING_FAILED",
  "FAILED",
]);

const COMPLETE_ATTEMPTS = 3;
const COMPLETE_RETRY_DELAY_MS = 2000;

export type CoopExitDeps = {
  /** Coordinator `spark` client. */
  readonly spark: Client<typeof SparkService>;
  readonly ssp: SspClient;
  readonly sspIdentityPublicKey: Uint8Array;
  readonly signer: SparkSigner;
  readonly network: SparkNetwork;
  readonly operators: ReadonlyArray<SparkOperatorConfig>;
  readonly threshold: number;
  readonly random: (length: number) => Uint8Array;
  readonly now: () => number;
  readonly sleep?: (ms: number) => Promise<void>;
};

export type CooperativeExitResult = {
  /** The cooperative-exit transfer id — the idempotency handle for retries. */
  readonly transferId: string;
  /** The SSP exit request id — pass to `cooperativeExitStatus`. */
  readonly requestId: string;
  readonly coopExitTxid: string;
  readonly payoutSats: number;
  readonly feeSats: number;
  readonly status: string;
};

/** `FAST` | `MEDIUM` | `SLOW` — the SSP's broadcast-speed tiers. */
export type CooperativeExitSpeed = SspCoopExitSpeed;
export type CooperativeExitQuote = SspCoopExitFeeQuote;
export type CooperativeExitStatus = SspCoopExitStatus;

/** `address` must decode under this client's network before any signer or SSP work runs. */
function checkWithdrawalAddress(address: string, network: SparkNetwork): void {
  try {
    Address(btcNetwork(network)).decode(address);
  } catch (error) {
    throw new SparkInputError(`coop exit: invalid withdrawal address for ${network}`, {
      cause: error,
    });
  }
}

function checkAmountSats(amountSats: number | undefined): void {
  if (amountSats !== undefined && (!Number.isSafeInteger(amountSats) || amountSats <= 0)) {
    throw new SparkInputError("coop exit: amountSats must be a positive integer");
  }
}

/** Output 0 of `txBytes` as a signing prevout — a refund's leaf-side first input commits to it. */
function prevout0(txBytes: Uint8Array, context: string): { script: Uint8Array; amount: number } {
  const output = parseTransaction(txBytes).getOutput(0);
  if (output.script === undefined || output.amount === undefined) {
    throw new SparkError(`coop exit: ${context} has no output 0`);
  }
  return { script: output.script, amount: u64ToSats(output.amount, context) };
}

/** The sats `rawCoopExitTransaction` pays to `address` — an exit not paying it is an error. */
function payoutSatsForAddress(
  rawCoopExitTransaction: Uint8Array,
  address: string,
  network: SparkNetwork,
): number {
  const expectedScript = OutScript.encode(Address(btcNetwork(network)).decode(address));
  const tx = parseTransaction(rawCoopExitTransaction);
  for (let i = 0; i < tx.outputsLength; i++) {
    const output = tx.getOutput(i);
    if (
      output.script !== undefined &&
      output.amount !== undefined &&
      equalBytes(output.script, expectedScript)
    ) {
      return u64ToSats(output.amount, "coop exit payout");
    }
  }
  throw new SparkInputError("coop exit: payout transaction does not pay the withdrawal address");
}

/**
 * `coop_exit_fee_quote` for the leaves an exit would use: every spendable leaf when `amountSats` is
 * omitted, otherwise the exact-amount selection (which may swap). `selectLeaves` is the client's
 * shared selection path under `leafLock`; an empty selection is rejected before the SSP call.
 */
export async function quoteCooperativeExit(
  deps: Pick<CoopExitDeps, "ssp" | "network"> & {
    readonly selectLeaves: (amountSats?: number) => Promise<ReadonlyArray<SparkLeaf>>;
  },
  options: { readonly address: string; readonly amountSats?: number },
): Promise<SspCoopExitFeeQuote> {
  checkWithdrawalAddress(options.address, deps.network);
  checkAmountSats(options.amountSats);
  const leaves = await deps.selectLeaves(options.amountSats);
  if (leaves.length === 0) {
    throw new SparkInputError("coop exit: no leaves to withdraw");
  }
  return deps.ssp.coopExitFeeQuote(
    leaves.map((leaf) => leaf.id),
    options.address,
  );
}

/**
 * `complete_coop_exit` with bounded retries: a lost completion response must not be retried blind,
 * so between attempts the request status decides — accepted means the SSP has the payout, failed is
 * terminal, anything else sleeps and retries (Breez request_payout).
 */
async function completeWithRetries(
  deps: Pick<CoopExitDeps, "ssp" | "sleep">,
  requestId: string,
  transferId: string,
): Promise<string> {
  const sleep = deps.sleep ?? defaultSleep;
  let lastError: unknown;
  for (let attempt = 0; attempt < COMPLETE_ATTEMPTS; attempt++) {
    if (attempt > 0) {
      // oxlint-disable-next-line no-await-in-loop -- retries must stay sequential
      await sleep(COMPLETE_RETRY_DELAY_MS);
      // oxlint-disable-next-line no-await-in-loop -- the status read gates the retry
      const status = await deps.ssp.coopExitRequest(requestId);
      if (COOP_EXIT_ACCEPTED.has(status.status)) {
        return status.status;
      }
      if (COOP_EXIT_FAILED.has(status.status)) {
        throw new SparkError(`coop exit: ssp reports ${status.status}`);
      }
    }
    try {
      // oxlint-disable-next-line no-await-in-loop -- bounded attempts must stay sequential
      const completed = await deps.ssp.completeCoopExit({
        coopExitRequestId: requestId,
        userOutboundTransferExternalId: transferId,
      });
      return completed.status;
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError;
}

/**
 * Resumes an exit whose transfer already committed under `options.transferId`: the SSP request is
 * re-created for the committed leaf ids — the SSP dedupes on `userOutboundTransferExternalId`, so a
 * live request resolves to itself and an expired one is re-created — then validated and completed.
 * `maxFeeSats` does not gate this path: the fee was already committed on the first call. A payout
 * that does not pay `options.address` means the id was reused with different terms — that fails
 * rather than riding along.
 */
async function resumeCommittedExit(
  deps: CoopExitDeps & {
    readonly deleteExitChains: (leafIds: ReadonlyArray<string>) => Promise<void>;
  },
  options: { readonly address: string; readonly speed: SspCoopExitSpeed },
  transfer: SparkTransfer,
): Promise<CooperativeExitResult> {
  const { ssp, sspIdentityPublicKey, signer, network } = deps;
  const identityPublicKey = await signer.identityPublicKey();
  assertCommittedTransfer(
    transfer,
    {
      type: TransferType.COOPERATIVE_EXIT,
      senderIdentityPublicKey: identityPublicKey,
      receiverIdentityPublicKeys: [sspIdentityPublicKey],
    },
    "coop exit",
  );

  // The transfer committed in an earlier call — deleting its old chains needs no lock: a
  // leaves() sync only re-stores chains for leaves it just queried, and these are gone.
  await deps.deleteExitChains(transfer.leaves.map((leaf) => leaf.leaf.id));

  const request = await ssp.requestCoopExit({
    leafIds: transfer.leaves.map((leaf) => leaf.leaf.id),
    withdrawalAddress: options.address,
    exitSpeed: options.speed,
    withdrawAll: true,
    userOutboundTransferExternalId: transfer.id,
  });
  if (COOP_EXIT_FAILED.has(request.status)) {
    throw new SparkError(`coop exit: ssp request for transfer ${transfer.id} is ${request.status}`);
  }
  // The SSP request record must be bound to the committed transfer we probed — dedupe on the
  // external id should guarantee it, but a record carrying a different transfer id would mean the
  // payout belongs to an exit we did not commit.
  const bound = await ssp.coopExitRequest(request.id);
  if (bound.transferId !== undefined && bound.transferId !== transfer.id) {
    throw new SparkError(
      `coop exit: ssp request ${request.id} is bound to transfer ${bound.transferId}, ` +
        `not the committed ${transfer.id}`,
    );
  }

  const payoutSats = payoutSatsForAddress(request.rawCoopExitTransaction, options.address, network);
  validateCoopExitPayoutTransaction({
    rawCoopExitTransaction: request.rawCoopExitTransaction,
    expectedCoopExitTxid: request.coopExitTxid,
    expectedPayoutAddress: options.address,
    expectedPayoutAmountSats: payoutSats,
    network,
  });
  const feeSats = transfer.totalValueSats - payoutSats;
  if (feeSats < 0) {
    throw new SparkError(
      `coop exit: payout ${payoutSats} exceeds the committed ${transfer.totalValueSats} sats`,
    );
  }

  const status = await completeWithRetries(deps, request.id, transfer.id);
  return {
    transferId: transfer.id,
    requestId: request.id,
    coopExitTxid: request.coopExitTxid,
    payoutSats,
    feeSats,
    status,
  };
}

/**
 * Withdraws `leaves` to an on-chain address: asks the SSP for the payout + connector transactions,
 * re-signs each leaf's three refunds with the connector output as second input, commits them in a
 * COOPERATIVE_EXIT transfer to the SSP and asks the SSP to complete the exit.
 *
 * The SSP's answers are validated before anything is signed: the payout tx must match the returned
 * txid and pay `total − fee` to the requested address, and the connector tx must spend it and carry
 * one output per leaf plus the trailing anchor — leaf i is bound to output i in the order the leaf
 * ids were sent. On a lost `cooperative_exit_v2` response the transfer id doubles as the recovery
 * key; once the transfer commits, the old refund txs are deleted before the completion request so
 * an SSP failure cannot leave them usable.
 *
 * Retry semantics: the SSP request expires ~2 minutes after creation unless the transfer commits,
 * so the request alone cannot be relied on across calls. A caller-supplied `transferId` probes the
 * committed transfer first — on a hit, the payout is re-requested for the committed leaf ids and
 * completed, skipping selection and signing. An uncommitted id whose request expired is burned:
 * retry with a fresh `transferId`.
 *
 * `spendLeaves` hands `use` the selected leaves (all spendable ones when `amountSats` is undefined)
 * and keeps the client's leaf lock held until `use` resolves — selection, SSP quote, commit and
 * chain cleanup inside `use` cannot interleave with another spend.
 */
export async function cooperativeExit(
  deps: CoopExitDeps & {
    readonly spendLeaves: <T>(
      amountSats: number | undefined,
      use: (leaves: ReadonlyArray<SparkLeaf>) => Promise<T>,
    ) => Promise<T>;
    readonly deleteExitChains: (leafIds: ReadonlyArray<string>) => Promise<void>;
  },
  options: {
    readonly address: string;
    readonly speed: SspCoopExitSpeed;
    readonly maxFeeSats: number;
    readonly amountSats?: number;
    /** Caller-supplied transfer id (uuidv7) to make a retry idempotent. */
    readonly transferId?: string;
  },
): Promise<CooperativeExitResult> {
  const { spark, ssp, sspIdentityPublicKey, signer, network } = deps;
  checkWithdrawalAddress(options.address, network);
  checkAmountSats(options.amountSats);
  if (!Number.isSafeInteger(options.maxFeeSats) || options.maxFeeSats < 0) {
    throw new SparkInputError("coop exit: maxFeeSats must be a non-negative integer");
  }

  // A caller-supplied id is the idempotency handle: a committed exit under it means this call is
  // a retry — probe before any leaf selection and resume with the committed leaves.
  if (options.transferId !== undefined) {
    const committed = await queryTransferById({
      spark,
      network,
      transferId: options.transferId,
    });
    if (committed !== undefined) {
      assertLiveTransfer(committed);
      return resumeCommittedExit(deps, options, committed);
    }
  }

  // Selection through the committed transfer's chain deletion is one critical section under the
  // client's leaf lock — the quote, payout request and commit cannot interleave with other spends.
  const completed = await deps.spendLeaves(options.amountSats, async (leaves) => {
    if (leaves.length === 0) {
      throw new SparkInputError("coop exit: no leaves to withdraw");
    }
    const leafIds = leaves.map((leaf) => leaf.id);
    const totalSats = leaves.reduce((sum, leaf) => sum + leaf.valueSats, 0);

    const quote = await ssp.coopExitFeeQuote(leafIds, options.address);
    const feeSats = {
      FAST: quote.fees.fast,
      MEDIUM: quote.fees.medium,
      SLOW: quote.fees.slow,
    }[options.speed];
    if (feeSats > options.maxFeeSats) {
      throw new SparkInputError(
        `coop exit: quoted fee ${feeSats} exceeds maxFeeSats ${options.maxFeeSats}`,
      );
    }
    if (feeSats >= totalSats) {
      throw new SparkInputError(`coop exit: quoted fee ${feeSats} leaves no payout`);
    }
    const payoutSats = totalSats - feeSats;

    const transferId = options.transferId ?? uuidv7(deps.random, deps.now);
    const request = await ssp.requestCoopExit({
      leafIds,
      withdrawalAddress: options.address,
      exitSpeed: options.speed,
      withdrawAll: true,
      userOutboundTransferExternalId: transferId,
    });
    // Never commit against a dead request — an expired external id is burned, not retried.
    if (COOP_EXIT_FAILED.has(request.status)) {
      throw new SparkError(
        `coop exit: ssp request for transfer ${transferId} is ${request.status}; retry with a new transferId`,
      );
    }

    // The payout tx must be the one the SSP claims it is and must pay out what the quote implied.
    validateCoopExitPayoutTransaction({
      rawCoopExitTransaction: request.rawCoopExitTransaction,
      expectedCoopExitTxid: request.coopExitTxid,
      expectedPayoutAddress: options.address,
      expectedPayoutAmountSats: payoutSats,
      network,
    });

    const exitTxidInternal = hexToBytes(request.coopExitTxid).reverse();
    validateConnectorTxBindsToCoopExitTxid(request.rawConnectorTransaction, exitTxidInternal);
    // btc-signer inputs carry display-order txid bytes (it reverses on serialize).
    const connectorTxidDisplay = txId(request.rawConnectorTransaction);

    const connectorTx = parseTransaction(request.rawConnectorTransaction);
    if (connectorTx.outputsLength !== leaves.length + 1) {
      throw new SparkError(
        `coop exit: connector tx has ${connectorTx.outputsLength} outputs, expected ${leaves.length} + anchor`,
      );
    }
    const connectorPrevouts = leaves.map((leaf, i) => {
      const output = connectorTx.getOutput(i);
      if (output.script === undefined || output.amount === undefined) {
        throw new SparkError(`coop exit: connector tx output ${i} for leaf ${leaf.id} is missing`);
      }
      return { script: output.script, amount: u64ToSats(output.amount, "coop exit connector") };
    });
    const indexByLeafId = new Map(leaves.map((leaf, i) => [leaf.id, i]));

    const identityPublicKey = await signer.identityPublicKey();
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
        const index = indexByLeafId.get(entry.leaf.id);
        const connectorPrevout = index === undefined ? undefined : connectorPrevouts[index];
        if (index === undefined || connectorPrevout === undefined) {
          throw new SparkError("coop exit: refund leaf is outside the connector mapping");
        }
        const txs = createConnectorRefundTxs({
          nodeTx: entry.leaf.nodeTx,
          directNodeTx: entry.leaf.directTx,
          sequence,
          receivingPublicKey: sspIdentityPublicKey,
          network,
          connectorInput: { txid: hexToBytes(connectorTxidDisplay), index },
        });
        const job = (
          txBytes: Uint8Array,
          firstPrevout: { readonly script: Uint8Array; readonly amount: number },
        ) => ({
          txBytes,
          sighash: taprootKeySpendSighash({
            transaction: txBytes,
            inputIndex: 0,
            prevouts: [firstPrevout, connectorPrevout],
          }),
        });
        const nodePrevout = prevout0(entry.leaf.nodeTx, `leaf ${entry.leaf.id} node tx`);
        const refunds: RefundTxTrio = {
          cpfpRefund: job(txs.cpfpRefundTx, nodePrevout),
          directFromCpfpRefund: job(txs.directFromCpfpRefundTx, nodePrevout),
          directRefund:
            txs.directRefundTx === undefined || entry.leaf.directTx === undefined
              ? undefined
              : job(
                  txs.directRefundTx,
                  prevout0(entry.leaf.directTx, `leaf ${entry.leaf.id} direct node tx`),
                ),
        };
        return { refunds, extraPrevout: connectorPrevout };
      },
    });

    const transferRequest = create(StartTransferRequestSchema, {
      transferId,
      ownerIdentityPublicKey: identityPublicKey,
      receiverIdentityPublicKey: sspIdentityPublicKey,
      transferPackage,
      expiryTime: timestampFromDate(new Date(deps.now() + COOP_EXIT_TRANSFER_EXPIRY_MS[network])),
    });

    let transfer: SparkTransfer;
    try {
      const response = await spark.cooperative_exit_v2({
        transfer: transferRequest,
        exitId: uuidv7(deps.random, deps.now),
        exitTxid: exitTxidInternal,
        connectorTx: request.rawConnectorTransaction,
      });
      if (response.transfer === undefined) {
        throw new SparkError("coop exit: cooperative_exit_v2 returned no transfer");
      }
      transfer = mapTransfer(response.transfer);
    } catch (error) {
      // The exit can commit server-side and still lose its response. The committed transfer is the
      // only sound test — a retry must continue with it rather than fail or commit the leaves twice.
      const recovered = await queryCommittedTransfer({
        spark,
        network,
        transferId,
        type: TransferType.COOPERATIVE_EXIT,
        senderIdentityPublicKey: identityPublicKey,
        receiverIdentityPublicKeys: [sspIdentityPublicKey],
      });
      if (recovered === undefined) {
        throw error;
      }
      transfer = recovered;
    }
    assertCommittedTransfer(
      transfer,
      {
        type: TransferType.COOPERATIVE_EXIT,
        senderIdentityPublicKey: identityPublicKey,
        receiverIdentityPublicKeys: [sspIdentityPublicKey],
      },
      "coop exit",
    );

    // The leaves are committed under connector refunds now, so the old refund txs must not survive
    // a failure on the completion call. The returned transfer — not the selected list — decides
    // which leaves left the wallet: on a retry the SO may report the first-attempt leaves.
    await deps.deleteExitChains(transfer.leaves.map((leaf) => leaf.leaf.id));

    return { transfer, request, payoutSats, feeSats };
  });

  const status = await completeWithRetries(deps, completed.request.id, completed.transfer.id);
  return {
    transferId: completed.transfer.id,
    requestId: completed.request.id,
    coopExitTxid: completed.request.coopExitTxid,
    payoutSats: completed.payoutSats,
    feeSats: completed.feeSats,
    status,
  };
}

/** `user_request` status of a cooperative-exit request — status plus the transfer id once set. */
export async function cooperativeExitStatus(
  deps: Pick<CoopExitDeps, "ssp">,
  requestId: string,
): Promise<SspCoopExitStatus> {
  return deps.ssp.coopExitRequest(requestId);
}
