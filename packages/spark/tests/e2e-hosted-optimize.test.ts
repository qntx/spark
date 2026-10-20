import { describe, expect, test } from "vite-plus/test";

import { MAX_PLANNING_ITERATIONS, optimize, shouldOptimize } from "../src/tree/index.ts";
import type { OptimizationSwap, SparkLeaf } from "../src/tree/index.ts";
import { hostedSeed, hostedWallet, sendAndClaimIfPositive } from "./support/hosted.ts";

const CLAIM_DEADLINE_MS = 180_000;
/** Sats left on account 2 after the cleanup send — a float for future payer tests. */
const PAYER_FLOAT_SATS = 5000;

const denominations = (leaves: ReadonlyArray<SparkLeaf>): number[] =>
  leaves.map((leaf) => leaf.valueSats);

const sorted = (values: ReadonlyArray<number>): number[] => values.toSorted((a, b) => a - b);

/** Executes planned swaps on a leaf multiset: inputs removed, outputs appended. */
function applySwaps(
  leaves: ReadonlyArray<number>,
  swaps: ReadonlyArray<OptimizationSwap>,
): number[] {
  const residual = [...leaves];
  for (const swap of swaps) {
    for (const value of swap.inLeaves) {
      const index = residual.indexOf(value);
      if (index === -1) {
        throw new Error(`planned swap input ${value} not in the leaf set`);
      }
      residual.splice(index, 1);
    }
    residual.push(...swap.outLeaves);
  }
  return residual;
}

/**
 * Replays the client's optimize loop on a leaf multiset: the first round is gated by
 * `shouldOptimize`, then replans run until the plan is empty or the iteration bound hits.
 */
function settle(
  values: ReadonlyArray<number>,
  multiplicity: number,
): { leaves: number[]; swaps: number } {
  let current = [...values];
  let swaps = 0;
  for (let iteration = 0; iteration < MAX_PLANNING_ITERATIONS; iteration++) {
    if (iteration === 0 && !shouldOptimize(current, multiplicity)) {
      break;
    }
    const plan = optimize(current, multiplicity);
    if (plan.length === 0) {
      break;
    }
    current = applySwaps(current, plan);
    swaps += plan.length;
  }
  return { leaves: current, swaps };
}

describe.skipIf(process.env["SPARK_E2E_HOSTED"] !== "1")("hosted regtest leaf optimization", () => {
  test("account 2 optimizes its dust, then returns the excess to account 0", async (ctx) => {
    const seed = hostedSeed();
    const walletA = await hostedWallet(seed, 0);
    const walletC = await hostedWallet(seed, 2);
    const { client: clientA } = walletA;
    const { client: clientC } = walletC;

    const identityA = await clientA.identityPublicKey();
    await clientA.transfers.claimPending();
    await clientC.transfers.claimPending();
    const balanceA0 = await clientA.balance();
    const balanceC0 = await clientC.balance();
    const leavesC0 = await clientC.leaves();
    const valuesC0 = denominations(leavesC0);
    ctx.skip(balanceC0 === 0, "account 2 is empty — nothing to optimize");
    console.log(
      "account 2 start:",
      balanceC0,
      "sats in",
      leavesC0.length,
      "leaves",
      sorted(valuesC0),
    );

    // multiplicity 0: consolidate into the greedy decomposition (fewest leaves).
    const expected0 = settle(valuesC0, 0);
    const optimized0 = await clientC.optimizeLeaves({ multiplicity: 0 });
    const leavesC1 = await clientC.leaves();
    console.log(
      "after multiplicity 0:",
      optimized0,
      "-> denominations",
      sorted(denominations(leavesC1)),
    );
    expect(optimized0.leavesBefore).toBe(leavesC0.length);
    expect(optimized0.leavesAfter).toBe(leavesC1.length);
    expect(optimized0.swaps).toBe(expected0.swaps);
    expect(sorted(denominations(leavesC1))).toStrictEqual(sorted(expected0.leaves));
    await expect(clientC.balance()).resolves.toBe(balanceC0);

    // multiplicity 1: reshape toward the swap-minimizing denomination set.
    const expected1 = settle(denominations(leavesC1), 1);
    const optimized1 = await clientC.optimizeLeaves({ multiplicity: 1 });
    const leavesC2 = await clientC.leaves();
    console.log(
      "after multiplicity 1:",
      optimized1,
      "-> denominations",
      sorted(denominations(leavesC2)),
    );
    expect(optimized1.leavesAfter).toBe(leavesC2.length);
    expect(optimized1.swaps).toBe(expected1.swaps);
    expect(sorted(denominations(leavesC2))).toStrictEqual(sorted(expected1.leaves));
    await expect(clientC.balance()).resolves.toBe(balanceC0);

    // One-off + recurring cleanup: everything above the float returns to the funder.
    const returned = Math.max(0, balanceC0 - PAYER_FLOAT_SATS);
    await sendAndClaimIfPositive(
      clientC,
      clientA,
      identityA,
      returned,
      Date.now() + CLAIM_DEADLINE_MS,
    );
    await expect(clientC.balance()).resolves.toBe(Math.min(balanceC0, PAYER_FLOAT_SATS));
    await expect(clientA.balance()).resolves.toBe(balanceA0 + returned);
    console.log(
      "cleanup returned",
      returned,
      "sats; account 2 keeps",
      Math.min(balanceC0, PAYER_FLOAT_SATS),
    );

    clientA.close();
    clientC.close();
    walletA.signer.dispose();
    walletC.signer.dispose();
  }, 600_000);
});
