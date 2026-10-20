import { equalBytes } from "@noble/curves/utils.js";

import { uuidv7 } from "../core/uuid.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import { TransferType } from "../proto/gen/spark_pb.ts";
import {
  assertCommittedTransfer,
  claimTransfer,
  CLAIMABLE_TRANSFER_STATUSES,
  queryAllTransfers,
  queryCommittedTransfer,
  queryPendingTransfers,
  queryTransferById,
  sendTransfer,
} from "../transfer/index.ts";
import type { CommittedTransferExpectation, SparkTransfer } from "../transfer/index.ts";
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
  const expected: CommittedTransferExpectation = {
    type: TransferType.TRANSFER,
    senderIdentityPublicKey,
    receiverIdentityPublicKeys: receiverKeys,
    receiverAmountsSats: options.receivers.map((receiver) => ({
      receiverIdentityPublicKey: receiver.receiverIdentityPublicKey,
      amountSats: receiver.amountSats,
    })),
  };
  const transferId = options.transferId ?? uuidv7(random, now);

  // Retry path: the id is already committed — resume on it. A present-but-mismatched transfer
  // means the id was reused with different terms and must not ride along. The probe stays outside
  // the leaf lock: it only reads. The committed transfer's chain deletion needs no lock either —
  // a leaves() sync only re-stores chains for leaves it just queried, and these are gone.
  if (options.transferId !== undefined) {
    const found = await queryTransferById({ spark, network, transferId });
    if (found !== undefined) {
      assertCommittedTransfer(found, expected, "send");
      await store.deleteExitChains(found.leaves.map((leaf) => leaf.leaf.id));
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
        transferId,
        ...expected,
      });
      if (recovered === undefined) {
        throw error;
      }
      sent = recovered;
    }
    // The returned transfer — not the locally selected list — decides which leaves left the wallet:
    // on a retry the SO may report the first-attempt leaves. Responses echoing no leaves fall back
    // to the selection (the send path always commits the leaves it built the package over).
    const spentLeafIds =
      sent.leaves.length > 0
        ? sent.leaves.map((transferLeaf) => transferLeaf.leaf.id)
        : allocations.flatMap((allocation) => allocation.leaves.map((leaf) => leaf.id));
    await store.deleteExitChains(spentLeafIds);
    return sent;
  });
}

export function createTransfers(context: ClientContext): SparkClient["transfers"] {
  const { coordinatorConnection, signer, network } = context;
  const { spark } = coordinatorConnection;
  return {
    pending: async () =>
      queryPendingTransfers({
        spark,
        identityPublicKey: await signer.identityPublicKey(),
        network,
      }),
    list: async (listOptions) =>
      queryAllTransfers({
        spark,
        identityPublicKey: await signer.identityPublicKey(),
        network,
        ...(listOptions?.limit === undefined ? {} : { limit: listOptions.limit }),
        ...(listOptions?.offset === undefined ? {} : { offset: listOptions.offset }),
      }),
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
    claim: async (transfer) =>
      context.leafLock.run(async () => {
        const claimed = await claimTransfer({ ...context.transferCoordinator, transfer });
        await context.storeChainsFor(claimed);
        return claimed;
      }),
    claimPending: async () => {
      const pending = await queryPendingTransfers({
        spark,
        identityPublicKey: await signer.identityPublicKey(),
        network,
      });
      const claimed: SparkLeaf[] = [];
      for (const transfer of pending) {
        if (!CLAIMABLE_TRANSFER_STATUSES.includes(transfer.status)) {
          continue;
        }
        // Each claim plus its chain store is one critical section, so a concurrent leaves() sync
        // cannot observe and delete a half-stored claim.
        // oxlint-disable-next-line no-await-in-loop -- claims run strictly in order; each consumes signer nonces
        const leaves = await context.leafLock.run(async () => {
          const claimedLeaves = await claimTransfer({ ...context.transferCoordinator, transfer });
          await context.storeChainsFor(claimedLeaves);
          return claimedLeaves;
        });
        claimed.push(...leaves);
      }
      return claimed;
    },
  };
}
