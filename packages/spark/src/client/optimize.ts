import { uuidv7 } from "../core/uuid.ts";
import { swapLeaves } from "../transfer/index.ts";
import {
  assertOptimizationOptions,
  DEFAULT_MAX_LEAVES_PER_SWAP,
  MAX_PLANNING_ITERATIONS,
  optimize,
  shouldOptimize,
} from "../tree/index.ts";
import type { OptimizationSwap, SparkLeaf } from "../tree/index.ts";
import type { ClientContext } from "./context.ts";
import { renewStaleLeaves } from "./leaves.ts";

export type OptimizeLeavesOptions = {
  /**
   * 0 consolidates dust into the fewest leaves (cheapest unilateral exit); 1–5 keeps every
   * power-of-two denomination that many times so sends can pay from exact leaves without a swap.
   */
  readonly multiplicity?: number;
  /** Soft bound on swap inputs per round — well under the SO's 1000-leaf transfer limit. */
  readonly maxLeavesPerSwap?: number;
  /** Checked between swaps; an in-flight swap completes first. */
  readonly signal?: AbortSignal;
};

export type OptimizeLeavesResult = {
  /** Swaps actually executed. */
  readonly swaps: number;
  readonly leavesBefore: number;
  readonly leavesAfter: number;
};

/**
 * Maps a planned swap's input values onto concrete leaves of the same values; `undefined` when the
 * live set no longer covers them (e.g. a concurrent claim or send changed the multiset).
 */
function leavesForValues(
  leaves: ReadonlyArray<SparkLeaf>,
  values: ReadonlyArray<number>,
): SparkLeaf[] | undefined {
  const buckets = new Map<number, SparkLeaf[]>();
  for (const leaf of leaves) {
    const bucket = buckets.get(leaf.valueSats);
    if (bucket === undefined) {
      buckets.set(leaf.valueSats, [leaf]);
    } else {
      bucket.push(leaf);
    }
  }
  const inputs: SparkLeaf[] = [];
  for (const value of values) {
    const leaf = buckets.get(value)?.shift();
    if (leaf === undefined) {
      return undefined;
    }
    inputs.push(leaf);
  }
  return inputs;
}

/**
 * Reshapes the wallet's leaf denominations through zero-fee SSP swaps. One planning round derives
 * the swap list under `leafLock`, then each swap runs in its own `leafLock` round — re-synced and
 * value-mapped onto the live leaf set, so a concurrent spend sees a consistent leaf set between
 * swaps and a changed set just replans. Stops when the plan is empty or after
 * `MAX_PLANNING_ITERATIONS` planning rounds (Breez's bound). The wallet decides when to call this
 * (e.g. after claims); nothing schedules it.
 */
export async function optimizeLeaves(
  context: ClientContext,
  options: OptimizeLeavesOptions = {},
): Promise<OptimizeLeavesResult> {
  const multiplicity = options.multiplicity ?? 1;
  const maxLeavesPerSwap = options.maxLeavesPerSwap ?? DEFAULT_MAX_LEAVES_PER_SWAP;
  assertOptimizationOptions(multiplicity, maxLeavesPerSwap);

  const { store, random, now } = context;
  const aborted = (): boolean => options.signal?.aborted === true;
  let swaps = 0;
  let leavesBefore = 0;
  let leavesAfter = 0;

  const planRound = async (first: boolean) =>
    context.leafLock.run(async () => {
      const leaves = await context.syncLeaves();
      const values = leaves.map((leaf) => leaf.valueSats);
      const plan =
        first && !shouldOptimize(values, multiplicity, maxLeavesPerSwap)
          ? []
          : optimize(values, multiplicity, maxLeavesPerSwap);
      return { leafCount: leaves.length, plan };
    });

  const executeSwap = async (swap: OptimizationSwap) =>
    context.leafLock.run(async () => {
      const leaves = await context.syncLeaves();
      const inputs = leavesForValues(leaves, swap.inLeaves);
      if (inputs === undefined) {
        return { done: false as const, leafCount: leaves.length };
      }
      const renewed = await renewStaleLeaves(context, inputs);
      const claimed = await swapLeaves({
        ...context.transferCoordinator,
        ssp: context.sspClient,
        sspIdentityPublicKey: context.config.ssp.identityPublicKey,
        transferId: uuidv7(random, now),
        leaves: renewed,
        targetAmountsSats: swap.outLeaves,
        random,
      });
      await store.deleteExitChains(renewed.map((leaf) => leaf.id));
      await context.storeChainsFor(claimed);
      return { done: true as const, leafCount: leaves.length - renewed.length + claimed.length };
    });

  for (let iteration = 0; iteration < MAX_PLANNING_ITERATIONS; iteration++) {
    if (aborted()) {
      break;
    }
    // oxlint-disable-next-line no-await-in-loop -- each lock round must see the last swap's effect
    const round = await planRound(iteration === 0);
    if (iteration === 0) {
      leavesBefore = round.leafCount;
    }
    leavesAfter = round.leafCount;
    if (round.plan.length === 0) {
      break;
    }
    for (const swap of round.plan) {
      if (aborted()) {
        break;
      }
      // oxlint-disable-next-line no-await-in-loop -- swaps must be strictly sequential
      const result = await executeSwap(swap);
      if (!result.done) {
        break;
      }
      swaps += 1;
      leavesAfter = result.leafCount;
    }
  }
  return { swaps, leavesBefore, leavesAfter };
}
