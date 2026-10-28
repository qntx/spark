import { equalBytes } from "@noble/curves/utils.js";

import { defaultSleep } from "../core/time.ts";
import { uuidv7 } from "../core/uuid.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import { TransferType } from "../proto/gen/spark_pb.ts";
import type { SspUserRequest } from "../ssp/types.ts";
import {
  assertCommittedTransfer,
  assertLiveTransfer,
  claimByTransferId,
  claimTransfer,
  CLAIMABLE_TRANSFER_STATUSES,
  queryAllTransfers,
  queryCommittedTransfer,
  queryPendingTransfers,
  queryTransferById,
  sendTransfer,
  sspCounterparty,
  toSparkPayment,
  verifyTransferAcrossOperators,
} from "../transfer/index.ts";
import type {
  CommittedTransferExpectation,
  SparkPayment,
  SparkTransfer,
} from "../transfer/index.ts";
import type { SparkLeaf } from "../tree/index.ts";
import type { ClientContext } from "./context.ts";
import type { SparkClient } from "./index.ts";
import { selectSendLeaves } from "./leaves.ts";

/**
 * Sats send shared by `transfers.send`/`sendMany` and `invoices.pay`: pick an exact leaf
 * combination per receiver, or swap leaves with the SSP first when none exists, then
 * start_transfer_v2 (one receiver) or start_transfer_v3 (several), and drop the spent leaves' exit
 * chains.
 *
 * A caller-supplied `transferId` makes the send idempotent: the committed transfer is probed before
 * any leaf selection, and again after a lost `start_transfer` response — reusing an id over
 * different terms fails instead of paying twice.
 */
export async function sendSats(
  context: ClientContext,
  options: {
    readonly receivers: ReadonlyArray<{
      readonly receiverIdentityPublicKey: Uint8Array;
      readonly amountSats: number;
    }>;
    readonly sparkInvoice?: string;
    readonly transferId?: string;
  },
): Promise<SparkTransfer> {
  const { store, random, now } = context;
  const { spark } = context.transferCoordinator;
  const { signer, network } = context;
  if (options.receivers.length === 0) {
    throw new SparkInputError("send: receivers must not be empty");
  }
  let totalSats = 0;
  const receiverKeys: Uint8Array[] = [];
  for (const receiver of options.receivers) {
    if (!Number.isSafeInteger(receiver.amountSats) || receiver.amountSats <= 0) {
      throw new SparkInputError("send: amountSats must be a positive safe integer");
    }
    totalSats += receiver.amountSats;
    if (!Number.isSafeInteger(totalSats)) {
      throw new SparkInputError("send: amountSats sum exceeds the safe integer range");
    }
    if (receiverKeys.some((key) => equalBytes(key, receiver.receiverIdentityPublicKey))) {
      throw new SparkInputError("send: duplicate receiver");
    }
    receiverKeys.push(receiver.receiverIdentityPublicKey);
  }

  const senderIdentityPublicKey = await signer.identityPublicKey();
  const transferId = options.transferId ?? uuidv7(random, now);
  const expected: CommittedTransferExpectation = {
    transferId,
    type: TransferType.TRANSFER,
    senderIdentityPublicKey,
    receiverIdentityPublicKeys: receiverKeys,
    receiverAmountsSats: options.receivers.map((receiver) => ({
      receiverIdentityPublicKey: receiver.receiverIdentityPublicKey,
      amountSats: receiver.amountSats,
    })),
  };

  // Retry path: the id is already committed — resume on it. A present-but-mismatched transfer
  // means the id was reused with different terms and must not ride along. The probe stays outside
  // the leaf lock: it only reads. The coordinator's claim of a commit is not enough — every other
  // operator must serve the identical transfer (L-05). A probe hit deletes no chains: the leaves
  // were committed in an earlier call, and the endorsed sync sweep reclaims them — a reported leaf
  // list must never decide deletions on its own (N-01).
  if (options.transferId !== undefined) {
    const found = await queryTransferById({ spark, network, transferId });
    if (found !== undefined) {
      assertLiveTransfer(found);
      assertCommittedTransfer(found, expected, "send");
      await verifyTransferAcrossOperators({
        operators: context.otherConnections.map((connection) => connection.spark),
        network,
        transfer: found,
      });
      return found;
    }
  }

  // Selection (including any swap or renewal) through the committed transfer's chain cleanup is
  // one critical section: a concurrent spend sees the spent leaves gone from its own sync.
  return context.leafLock.run(async () => {
    const groups = await selectSendLeaves(
      context,
      options.receivers.map((receiver) => receiver.amountSats),
    );
    const allocations = options.receivers.map((receiver, index) => {
      const leaves = groups[index];
      if (leaves === undefined) {
        throw new SparkError("send: leaf selection returned fewer groups than requested");
      }
      return { receiverIdentityPublicKey: receiver.receiverIdentityPublicKey, leaves };
    });

    let sent: SparkTransfer;
    try {
      sent = await sendTransfer({
        ...context.transferCoordinator,
        transferId,
        allocations,
        ...(options.sparkInvoice === undefined ? {} : { sparkInvoice: options.sparkInvoice }),
      });
    } catch (error) {
      // The transfer can commit server-side and still lose its response — pick the committed one
      // up instead of failing or double-paying.
      const recovered = await queryCommittedTransfer({
        spark,
        network,
        ...expected,
      });
      if (recovered === undefined) {
        throw error;
      }
      sent = recovered;
    }
    // The returned transfer — fresh or recovered by this call — must be the one we signed for:
    // same id, type, sender and receiver set (the lightning-pay path asserts its fresh response
    // the same way). There is no cross-operator gate here: the commit already happened
    // server-side, so an operator error or lag must not strand a spend the caller cannot undo —
    // the gate applies only to probe hits, commits an earlier call made.
    assertCommittedTransfer(sent, expected, "send");
    // Only leaves this call both selected locally AND the returned transfer names may lose their
    // chains — the coordinator cannot strip the exit data of leaves it merely lists (N-01). On a
    // retry the SO may report the first-attempt leaves; responses echoing no leaves fall back to
    // the selection (the send path always commits the leaves it built the package over).
    const selectedLeafIds = new Set(
      allocations.flatMap((allocation) => allocation.leaves.map((leaf) => leaf.id)),
    );
    const spentLeafIds =
      sent.leaves.length > 0
        ? [
            ...new Set(
              sent.leaves
                .map((transferLeaf) => transferLeaf.leaf.id)
                .filter((leafId) => selectedLeafIds.has(leafId)),
            ),
          ]
        : [...selectedLeafIds];
    if (spentLeafIds.length > 0) {
      await store.deleteExitChains(spentLeafIds);
    }
    return sent;
  });
}

export function createTransfers(context: ClientContext): SparkClient["transfers"] {
  const { coordinatorConnection, signer, network } = context;
  const { spark } = coordinatorConnection;
  return {
    pending: async () => {
      const pending = await queryPendingTransfers({
        spark,
        identityPublicKey: await signer.identityPublicKey(),
        network,
      });
      return pending.transfers;
    },
    history: async (historyOptions) => {
      const limit = historyOptions?.limit ?? 20;
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
        throw new SparkInputError("history: limit must be an integer in 1–100");
      }
      const offset = historyOptions?.offset ?? 0;
      if (!Number.isSafeInteger(offset) || offset < 0) {
        throw new SparkInputError("history: offset must be a non-negative integer");
      }
      const identityPublicKey = await signer.identityPublicKey();
      const sspIdentityPublicKey = context.config.ssp.identityPublicKey;
      const { transfers, nextOffset } = await queryAllTransfers({
        spark,
        identityPublicKey,
        network,
        limit,
        offset,
        types: [
          TransferType.TRANSFER,
          TransferType.PREIMAGE_SWAP,
          TransferType.COOPERATIVE_EXIT,
          TransferType.UTXO_SWAP,
        ],
      });
      // One batched SSP call per page: only transfers whose counterparty is the SSP carry a
      // user_request worth fetching.
      const sspIds = transfers
        .filter((transfer) => sspCounterparty(transfer, identityPublicKey, sspIdentityPublicKey))
        .map((transfer) => transfer.id);
      const requests = new Map<string, SspUserRequest>();
      for (const result of await context.sspClient.transfers(sspIds)) {
        if (result.request !== undefined) {
          requests.set(result.transferId, result.request);
        }
      }
      const payments: SparkPayment[] = transfers.map((transfer) =>
        toSparkPayment({
          transfer,
          request: requests.get(transfer.id),
          identityPublicKey,
          sspIdentityPublicKey,
        }),
      );
      return { payments, nextOffset };
    },
    list: async (listOptions) => {
      const { transfers } = await queryAllTransfers({
        spark,
        identityPublicKey: await signer.identityPublicKey(),
        network,
        ...(listOptions?.limit === undefined ? {} : { limit: listOptions.limit }),
        ...(listOptions?.offset === undefined ? {} : { offset: listOptions.offset }),
      });
      return transfers;
    },
    send: async (sendOptions) =>
      sendSats(context, {
        receivers: [
          {
            receiverIdentityPublicKey: context.receiverIdentityKey(sendOptions.receiver),
            amountSats: sendOptions.amountSats,
          },
        ],
        ...(sendOptions.transferId === undefined ? {} : { transferId: sendOptions.transferId }),
      }),
    sendMany: async (sendOptions) =>
      sendSats(context, {
        receivers: sendOptions.receivers.map((receiver) => ({
          receiverIdentityPublicKey: context.receiverIdentityKey(receiver.receiver),
          amountSats: receiver.amountSats,
        })),
        ...(sendOptions.transferId === undefined ? {} : { transferId: sendOptions.transferId }),
      }),
    claim: async (transferId, claimOptions) =>
      claimByTransferId({
        ...context.transferCoordinator,
        transferId,
        sleep: context.sleep ?? defaultSleep,
        ...(claimOptions?.signal === undefined ? {} : { signal: claimOptions.signal }),
        claim: async (transfer) =>
          context.leafLock.run(async () => {
            const claimed = await claimTransfer({ ...context.transferCoordinator, transfer });
            await context.storeChainsFor(claimed);
            return claimed;
          }),
      }),
    claimPending: async () => {
      const pending = await queryPendingTransfers({
        spark,
        identityPublicKey: await signer.identityPublicKey(),
        network,
      });
      const leaves: SparkLeaf[] = [];
      // Rows the coordinator returned but mapping rejected are reported, not fatal.
      const failures: Array<{ transferId: string; error: unknown }> = [...pending.unmappable];
      for (const transfer of pending.transfers) {
        if (!CLAIMABLE_TRANSFER_STATUSES.includes(transfer.status)) {
          continue;
        }
        // Each claim plus its chain store is one critical section, so a concurrent leaves() sync
        // cannot observe and delete a half-stored claim. A claim that fails is reported, not
        // fatal: one poisoned transfer must not starve every transfer behind it.
        try {
          // oxlint-disable-next-line no-await-in-loop -- claims run strictly in order; each consumes signer nonces
          const claimed = await context.leafLock.run(async () => {
            const claimedLeaves = await claimTransfer({ ...context.transferCoordinator, transfer });
            await context.storeChainsFor(claimedLeaves);
            return claimedLeaves;
          });
          leaves.push(...claimed);
        } catch (error) {
          failures.push({ transferId: transfer.id, error });
        }
      }
      return { leaves, failures };
    },
  };
}
