import { uuidv7 } from "../core/uuid.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";
import { swapLeaves } from "../transfer/index.ts";
import type { SparkLeaf } from "../tree/index.ts";
import { renewLeaf, renewalKind } from "../tree/renew.ts";
import { selectExactMany, selectLeaves } from "../tree/select.ts";
import type { ClientContext } from "./context.ts";

/**
 * Renews every leaf whose refund timelock is spent, in order, before the leaves leave the wallet —
 * used by sends, swaps, lightning payments and cooperative exits alike. Caller holds `leafLock`.
 */
export async function renewStaleLeaves(
  context: ClientContext,
  leaves: ReadonlyArray<SparkLeaf>,
): Promise<SparkLeaf[]> {
  const { spark } = context.coordinatorConnection;
  const { signer, network } = context;
  const out: SparkLeaf[] = [];
  for (const leaf of leaves) {
    if (renewalKind(leaf) === undefined) {
      out.push(leaf);
      continue;
    }
    // oxlint-disable-next-line no-await-in-loop -- renewals must complete in order before send
    out.push(await renewLeaf({ spark, signer, network, leaf }));
  }
  return out;
}

// The SO rejects a transfer package carrying more leaves than this (upstream MaxLeavesToSend).
const MAX_TRANSFER_LEAVES = 1000;

function assertTransferLeafLimit(group: ReadonlyArray<SparkLeaf>, context: string): void {
  if (group.length > MAX_TRANSFER_LEAVES) {
    throw new SparkInputError(
      `${context}: the transfer carries ${group.length} leaves, over the ${MAX_TRANSFER_LEAVES}-leaf limit`,
    );
  }
}

/**
 * One leaf group per amount, each summing exactly to its amount: disjoint exact combinations when
 * they all exist, otherwise an SSP leaves swap minted for all amounts at once — with stale-input
 * renewals on both paths and exit-chain bookkeeping (swap inputs dropped, swapped-in leaves
 * stored). Shared by `transfers.send`/`sendMany`, `invoices.pay`, `lightning.pay` and coop exits.
 * Caller holds `leafLock` — selection through swap-minted re-selection must not interleave with
 * another spend.
 */
export async function selectSendLeaves(
  context: ClientContext,
  amounts: ReadonlyArray<number>,
): Promise<SparkLeaf[][]> {
  const { store, random, now } = context;

  const selection = selectLeaves(await context.syncLeaves(), amounts);
  if (selection.kind === "exact") {
    const renewed: SparkLeaf[][] = [];
    for (const group of selection.groups) {
      assertTransferLeafLimit(group, "send");
      // oxlint-disable-next-line no-await-in-loop -- renewals must complete in order
      renewed.push(await renewStaleLeaves(context, group));
    }
    return renewed;
  }

  assertTransferLeafLimit(selection.leaves, "send swap");
  const swapInputs = await renewStaleLeaves(context, selection.leaves);
  const claimed = await swapLeaves({
    ...context.transferCoordinator,
    ssp: context.sspClient,
    sspIdentityPublicKey: context.config.ssp.identityPublicKey,
    transferId: uuidv7(random, now),
    leaves: swapInputs,
    targetAmountsSats: amounts,
    random,
  });
  await store.deleteExitChains(swapInputs.map((leaf) => leaf.id));
  await context.storeChainsFor(claimed);
  // swapLeaves already verified coverage with the same selection rule.
  const groups = selectExactMany(claimed, amounts);
  if (groups === undefined) {
    throw new SparkError("send: swapped leaves cannot cover the requested amounts exactly");
  }
  const renewed: SparkLeaf[][] = [];
  for (const group of groups) {
    assertTransferLeafLimit(group, "send");
    // oxlint-disable-next-line no-await-in-loop -- renewals must complete in order
    renewed.push(await renewStaleLeaves(context, group));
  }
  return renewed;
}
