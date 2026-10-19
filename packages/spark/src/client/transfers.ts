import { uuidv7 } from "../core/uuid.ts";
import {
  claimTransfer,
  CLAIMABLE_TRANSFER_STATUSES,
  queryAllTransfers,
  queryPendingTransfers,
  sendTransfer,
} from "../transfer/index.ts";
import type { SparkTransfer } from "../transfer/index.ts";
import type { SparkLeaf } from "../tree/index.ts";
import type { ClientContext } from "./context.ts";
import type { SparkClient } from "./index.ts";
import { selectSendLeaves } from "./leaves.ts";

/**
 * Sats send shared by `transfers.send` and `invoices.pay`: pick an exact leaf combination, or swap
 * leaves with the SSP first when none exists, then renew stale inputs, start_transfer_v2, and drop
 * the spent leaves' exit chains.
 */
export async function sendSats(
  context: ClientContext,
  options: {
    readonly receiver: Uint8Array;
    readonly amountSats: number;
    readonly sparkInvoice?: string;
  },
): Promise<SparkTransfer> {
  const { store, random, now } = context;

  const sendLeaves = await selectSendLeaves(context, options.amountSats);
  const sent = await sendTransfer({
    ...context.transferCoordinator,
    transferId: uuidv7(random, now),
    leaves: sendLeaves,
    receiverIdentityPublicKey: options.receiver,
    ...(options.sparkInvoice === undefined ? {} : { sparkInvoice: options.sparkInvoice }),
  });
  await store.deleteExitChains(sendLeaves.map((leaf) => leaf.id));
  return sent;
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
        receiver: context.receiverIdentityKey(sendOptions.receiver),
        amountSats: sendOptions.amountSats,
      }),
    claim: async (transfer) => {
      const claimed = await claimTransfer({ ...context.transferCoordinator, transfer });
      await context.storeChainsFor(claimed);
      return claimed;
    },
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
        // oxlint-disable-next-line no-await-in-loop -- claims run strictly in order; each consumes signer nonces
        const leaves = await claimTransfer({ ...context.transferCoordinator, transfer });
        // Persist each claim's chains before the next, so a later failure loses nothing.
        // oxlint-disable-next-line no-await-in-loop
        await context.storeChainsFor(leaves);
        claimed.push(...leaves);
      }
      return claimed;
    },
  };
}
