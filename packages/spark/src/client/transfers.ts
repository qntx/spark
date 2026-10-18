import { uuidv7 } from "../core/uuid.ts";
import {
  claimTransfer,
  CLAIMABLE_TRANSFER_STATUSES,
  queryAllTransfers,
  queryPendingTransfers,
  selectLeavesExact,
  sendTransfer,
} from "../transfer/index.ts";
import type { SparkLeaf } from "../tree/index.ts";
import { renewLeaf, renewalKind } from "../tree/renew.ts";
import type { ClientContext } from "./context.ts";
import type { SparkClient } from "./index.ts";

export function createTransfers(context: ClientContext): SparkClient["transfers"] {
  const { coordinatorConnection, signer, network, store, random, now } = context;
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
    send: async (sendOptions) => {
      const receiver = context.receiverIdentityKey(sendOptions.receiver);
      const selected = selectLeavesExact(await context.leaves(), sendOptions.amountSats);
      // Renew any leaf whose refund timelock is spent before handing it to the receiver.
      const sendLeaves: SparkLeaf[] = [];
      for (const leaf of selected) {
        if (renewalKind(leaf) === undefined) {
          sendLeaves.push(leaf);
          continue;
        }
        // oxlint-disable-next-line no-await-in-loop -- renewals must complete in order before send
        const renewed = await renewLeaf({
          spark,
          signer,
          network,
          leaf,
        });
        sendLeaves.push(renewed);
      }
      const sent = await sendTransfer({
        ...context.transferCoordinator,
        transferId: uuidv7(random, now),
        leaves: sendLeaves,
        receiverIdentityPublicKey: receiver,
      });
      await store.deleteExitChains(sendLeaves.map((leaf) => leaf.id));
      return sent;
    },
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
