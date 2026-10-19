import { uuidv7 } from "../core/uuid.ts";
import { SparkError } from "../errors/index.ts";
import { swapLeaves } from "../transfer/index.ts";
import type { SparkLeaf } from "../tree/index.ts";
import { renewLeaf, renewalKind } from "../tree/renew.ts";
import { selectExact, selectLeaves } from "../tree/select.ts";
import type { ClientContext } from "./context.ts";

/**
 * Renews every leaf whose refund timelock is spent, in order, before the leaves leave the wallet —
 * used by sends, swaps, lightning payments and cooperative exits alike.
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

/**
 * Leaves covering exactly `amountSats`: an exact combination when one exists, otherwise an SSP
 * leaves swap minted for the amount — with stale-input renewals on both paths and exit-chain
 * bookkeeping (swap inputs dropped, swapped-in leaves stored). Shared by `transfers.send`,
 * `invoices.pay` and `lightning.pay`.
 */
export async function selectSendLeaves(
  context: ClientContext,
  amountSats: number,
): Promise<SparkLeaf[]> {
  const { store, random, now } = context;

  const selection = selectLeaves(await context.leaves(), amountSats);
  if (selection.kind === "swap") {
    const swapInputs = await renewStaleLeaves(context, selection.leaves);
    const claimed = await swapLeaves({
      ...context.transferCoordinator,
      ssp: context.sspClient,
      sspIdentityPublicKey: context.config.ssp.identityPublicKey,
      transferId: uuidv7(random, now),
      leaves: swapInputs,
      targetAmountsSats: [amountSats],
      random,
    });
    await store.deleteExitChains(swapInputs.map((leaf) => leaf.id));
    await context.storeChainsFor(claimed);
    const exact = selectExact(claimed, amountSats);
    if (exact === undefined) {
      throw new SparkError(`send: swapped leaves cannot cover ${amountSats} sats exactly`);
    }
    return renewStaleLeaves(context, exact);
  }
  return renewStaleLeaves(context, selection.leaves);
}
