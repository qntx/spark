import { equalBytes } from "@noble/curves/utils.js";

import { defaultSleep } from "../core/time.ts";
import { uuidv7 } from "../core/uuid.ts";
import {
  claimDeposit,
  generateDepositAddress,
  queryUnusedDepositAddresses,
} from "../deposit/index.ts";
import {
  claimStaticDeposit,
  generateStaticDepositAddress,
  queryStaticDepositUtxos,
  refundStaticDeposit,
} from "../deposit/static.ts";
import type { StaticDepositClaim } from "../deposit/static.ts";
import { SparkError } from "../errors/index.ts";
import {
  claimTransfer,
  CLAIMABLE_TRANSFER_STATUSES,
  mapTransfer,
  queryPendingTransfers,
  queryTransfersByIds,
} from "../transfer/index.ts";
import type { SparkTransfer } from "../transfer/index.ts";
import type { SparkLeaf } from "../tree/index.ts";
import type { ClientContext } from "./context.ts";
import type { SparkClient } from "./index.ts";

/** `claim_static_deposit` plus the leaves its inbound transfer credited. */
export type StaticDepositClaimResult = StaticDepositClaim & {
  readonly leaves: ReadonlyArray<SparkLeaf>;
};

// The SSP creates the claim's inbound transfer before (or just after) the mutation returns;
// bound the wait so a transfer that never arrives leaves the deposit claimable on retry.
const CLAIM_TRANSFER_POLLS = 6;
const CLAIM_TRANSFER_DELAY_MS = 1000;

/**
 * Claims the transfer the SSP's `claim_static_deposit` credited: the reported transfer id when the
 * response carries one, otherwise the oldest claimable inbound transfer from the SSP whose total
 * equals `creditAmountSats`. Returns no leaves when nothing claimable shows up within the bound —
 * the caller can retry `transfers.claimPending` later.
 */
/** Exported for focused tests; the public entry point is `deposits.claimStatic`. */
export async function claimInboundTransfer(
  context: ClientContext,
  creditAmountSats: number,
  transferId?: string,
): Promise<ReadonlyArray<SparkLeaf>> {
  const { coordinatorConnection, signer, network } = context;
  const { spark } = coordinatorConnection;
  const sspIdentityPublicKey = context.config.ssp.identityPublicKey;
  const identityPublicKey = await signer.identityPublicKey();
  const sleep = context.sleep ?? defaultSleep;

  for (let attempt = 0; ; attempt++) {
    let transfer: SparkTransfer | undefined;
    if (transferId === undefined) {
      // oxlint-disable-next-line no-await-in-loop -- bounded sequential polling
      const { transfers: pending } = await queryPendingTransfers({
        spark,
        identityPublicKey,
        network,
      });
      // Without a reported id only the claim's credit amount binds the transfer: other SSP
      // transfers in flight must not be mistaken for this deposit's credit.
      const [oldest] = pending
        .filter(
          (candidate) =>
            equalBytes(candidate.senderIdentityPublicKey, sspIdentityPublicKey) &&
            CLAIMABLE_TRANSFER_STATUSES.includes(candidate.status) &&
            candidate.totalValueSats === creditAmountSats,
        )
        .sort((a, b) => (a.createdTimeMs ?? 0) - (b.createdTimeMs ?? 0));
      transfer = oldest;
    } else {
      // oxlint-disable-next-line no-await-in-loop -- bounded sequential polling
      const [found] = await queryTransfersByIds({ spark, transferIds: [transferId], network });
      if (found !== undefined) {
        const candidate = mapTransfer(found);
        if (
          !equalBytes(candidate.senderIdentityPublicKey, sspIdentityPublicKey) ||
          !equalBytes(candidate.receiverIdentityPublicKey, identityPublicKey)
        ) {
          throw new SparkError(
            "claimStatic: the SSP-reported transfer is not the SSP's payment to us",
          );
        }
        if (candidate.totalValueSats !== creditAmountSats) {
          throw new SparkError(
            `claimStatic: the SSP-reported transfer total ${candidate.totalValueSats} ` +
              `does not match the credited ${creditAmountSats} sats`,
          );
        }
        if (CLAIMABLE_TRANSFER_STATUSES.includes(candidate.status)) {
          transfer = candidate;
        }
      }
    }

    if (transfer !== undefined) {
      // Claim plus chain store under the leaf lock — a concurrent leaves() sync must not observe
      // and delete a half-stored claim. Polling and sleeps stay outside the lock.
      return context.leafLock.run(async () => {
        const leaves = await claimTransfer({ ...context.transferCoordinator, transfer });
        await context.storeChainsFor(leaves);
        return leaves;
      });
    }
    if (attempt >= CLAIM_TRANSFER_POLLS) {
      return [];
    }
    // oxlint-disable-next-line no-await-in-loop -- bounded sequential polling
    await sleep(CLAIM_TRANSFER_DELAY_MS);
  }
}

export function createDeposits(context: ClientContext): SparkClient["deposits"] {
  const { random, now } = context;
  return {
    newAddress: async () =>
      generateDepositAddress({
        ...context.depositCoordinator,
        leafId: uuidv7(random, now),
      }),
    unused: async () => queryUnusedDepositAddresses(context.depositCoordinator),
    claim: async (claimOptions) =>
      context.leafLock.run(async () => {
        const leaf = await claimDeposit({
          ...context.depositCoordinator,
          outputs: [
            {
              transaction: claimOptions.transaction,
              ...(claimOptions.vout === undefined ? {} : { vout: claimOptions.vout }),
            },
          ],
        });
        await context.storeChainsFor([leaf]);
        return leaf;
      }),
    claimMany: async (claimOptions) =>
      context.leafLock.run(async () => {
        const leaf = await claimDeposit({
          ...context.depositCoordinator,
          outputs: claimOptions.outputs,
        });
        await context.storeChainsFor([leaf]);
        return leaf;
      }),
    staticAddress: async () => generateStaticDepositAddress(context.depositCoordinator),
    staticUtxos: async () => queryStaticDepositUtxos(context.depositCoordinator),
    claimStatic: async (claimOptions) => {
      const claim = await claimStaticDeposit(
        {
          ...context.depositCoordinator,
          ssp: context.sspClient,
          sspIdentityPublicKey: context.config.ssp.identityPublicKey,
        },
        claimOptions,
      );
      const leaves = await claimInboundTransfer(context, claim.creditAmountSats, claim.transferId);
      return { ...claim, leaves };
    },
    refundStatic: async (refundOptions) =>
      refundStaticDeposit(context.depositCoordinator, refundOptions),
  };
}
