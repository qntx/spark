import { assertSats } from "../core/assert.ts";
import { SparkError, SparkInputError } from "../errors/index.ts";

/**
 * Leaf denomination planning, ported from the upstream JS SDK (lightspark-spark sdks/js
 * `utils/optimize.ts` @0b3a32a, with Breez `leaf_optimizer.rs` agreeing on every case in
 * `vectors/optimize.json`).
 *
 * Two strategies: `multiplicity === 0` consolidates dust into the greedy decomposition (minimizes
 * leaves — cheapest unilateral exit), while `multiplicity >= 1` reshapes the wallet toward
 * `swapMinimizingLeaves`, which keeps each power-of-two denomination present up to `multiplicity`
 * times so transfers can be paid from exact leaves without an SSP swap.
 */

const DENOMINATIONS: number[] = Array.from({ length: 28 }, (_, i) => 2 ** i);

/** Where upstream JS disagrees with Breez, upstream wins (see vectors). */
export type OptimizationSwap = {
  readonly inLeaves: number[];
  readonly outLeaves: number[];
};

export const MAX_MULTIPLICITY = 5;
export const DEFAULT_MAX_LEAVES_PER_SWAP = 64;
/** Breez's planning bound — replans are cheap, so the driver caps iterations at this. */
export const MAX_PLANNING_ITERATIONS = 8;

/** `multiplicity` is an integer in 0..5; `maxLeavesPerSwap` a positive integer. */
export function assertOptimizationOptions(multiplicity: number, maxLeavesPerSwap: number): void {
  if (!Number.isSafeInteger(multiplicity) || multiplicity < 0 || multiplicity > MAX_MULTIPLICITY) {
    throw new SparkInputError(`multiplicity: must be an integer between 0 and ${MAX_MULTIPLICITY}`);
  }
  if (!Number.isSafeInteger(maxLeavesPerSwap) || maxLeavesPerSwap < 1) {
    throw new SparkInputError("maxLeavesPerSwap: must be a positive integer");
  }
}

function sum(arr: ReadonlyArray<number>): number {
  let total = 0;
  for (const value of arr) {
    total += value;
  }
  return total;
}

function sorted(arr: ReadonlyArray<number>): number[] {
  return [...arr].sort((a, b) => a - b);
}

function equals(a: ReadonlyArray<number>, b: ReadonlyArray<number>): boolean {
  return a.length === b.length && a.every((val, index) => val === b[index]);
}

function countOccurrences(arr: ReadonlyArray<number>): Map<number, number> {
  const map = new Map<number, number>();
  for (const x of arr) {
    map.set(x, (map.get(x) ?? 0) + 1);
  }
  return map;
}

function subtractCounters(a: Map<number, number>, b: Map<number, number>): Map<number, number> {
  const result = new Map<number, number>();
  for (const [key, value] of a.entries()) {
    const diff = value - (b.get(key) ?? 0);
    if (diff > 0) {
      result.set(key, diff);
    }
  }
  return result;
}

function counterToFlatArray(counter: Map<number, number>): number[] {
  const arr: number[] = [];
  for (const [k, v] of [...counter.entries()].sort((a, b) => a[0] - b[0])) {
    for (let i = 0; i < v; i++) {
      arr.push(k);
    }
  }
  return arr;
}

/** The greedy decomposition of `amount` into power-of-two denominations, ascending. */
export function greedyLeaves(amount: number): number[] {
  const leaves: number[] = [];
  let remaining = amount;
  for (let i = DENOMINATIONS.length - 1; i >= 0; i--) {
    const leaf = DENOMINATIONS[i];
    if (leaf !== undefined && leaf > 0) {
      while (remaining >= leaf) {
        remaining -= leaf;
        leaves.push(leaf);
      }
    }
  }
  if (sum(leaves) !== amount) {
    throw new SparkError("greedyLeaves: decomposition does not sum to the amount");
  }
  return sorted(leaves);
}

/**
 * The denomination set that minimizes the chance a transfer needs an SSP swap: each power of two
 * appears up to `multiplicity` times, then the remainder decomposes greedily. Ascending.
 */
export function swapMinimizingLeaves(
  amount: number,
  // oxlint-disable-next-line no-inferrable-types -- isolatedDeclarations requires it
  multiplicity: number = 1,
): number[] {
  if (multiplicity <= 0) {
    throw new SparkInputError("multiplicity: must be > 0");
  }
  const leaves: number[] = [];
  let remaining = amount;
  for (const leaf of DENOMINATIONS) {
    if (leaf > 0) {
      for (let i = 0; i < multiplicity; i++) {
        if (remaining >= leaf) {
          remaining -= leaf;
          leaves.push(leaf);
        }
      }
    }
  }
  leaves.push(...greedyLeaves(remaining));
  if (sum(leaves) !== amount) {
    throw new SparkError("swapMinimizingLeaves: decomposition does not sum to the amount");
  }
  return sorted(leaves);
}

function makeSwap(
  inLeaves: ReadonlyArray<number>,
  outLeaves: ReadonlyArray<number>,
): OptimizationSwap {
  if (sum(inLeaves) !== sum(outLeaves)) {
    throw new SparkError(
      `optimize: swap in/out leaves must sum to the same value (in=${JSON.stringify(inLeaves)}, out=${JSON.stringify(outLeaves)})`,
    );
  }
  return { inLeaves: [...inLeaves], outLeaves: [...outLeaves] };
}

/**
 * Swaps that consolidate leaves into the greedy decomposition — the fewest leaves, which maximizes
 * the amount exitable per unit of unilateral-exit fee. Batches of roughly `maxLeavesPerSwap`;
 * multiple planning iterations may be needed to reach the optimum.
 */
export function maximizeUnilateralExit(
  inputLeaves: ReadonlyArray<number>,
  maxLeavesPerSwap: number = DEFAULT_MAX_LEAVES_PER_SWAP,
): OptimizationSwap[] {
  const swaps: OptimizationSwap[] = [];
  let batch: number[] = [];
  const leaves: number[] = sorted(inputLeaves);

  while (leaves.length > 0) {
    const leaf = leaves.shift();
    if (leaf === undefined) {
      break;
    }
    batch.push(leaf);
    const target = greedyLeaves(sum(batch));
    if (batch.length >= maxLeavesPerSwap || target.length >= maxLeavesPerSwap) {
      if (!equals(target, batch)) {
        swaps.push(makeSwap(batch, target));
      }
      batch = [];
    }
  }

  if (batch.length > 0) {
    const target = greedyLeaves(sum(batch));
    if (!equals(target, batch)) {
      swaps.push(makeSwap(batch, target));
    }
  }

  return swaps;
}

/**
 * Swaps that reshape the wallet toward `swapMinimizingLeaves(balance, multiplicity)` — the
 * denomination set least likely to need an SSP swap when paying. The give/receive batches are
 * balanced leaf-by-leaf; oversized batches are split around `maxLeavesPerSwap`.
 */
export function minimizeTransferSwap(
  inputLeaves: ReadonlyArray<number>,
  // oxlint-disable-next-line no-inferrable-types -- isolatedDeclarations requires it
  multiplicity: number = 1,
  maxLeavesPerSwap: number = DEFAULT_MAX_LEAVES_PER_SWAP,
): OptimizationSwap[] {
  const balance = sum(inputLeaves);
  const optimalLeaves = swapMinimizingLeaves(balance, multiplicity);
  const walletCounter = countOccurrences(inputLeaves);
  const optimalCounter = countOccurrences(optimalLeaves);

  const leavesToGive = subtractCounters(walletCounter, optimalCounter);
  const leavesToReceive = subtractCounters(optimalCounter, walletCounter);

  const give = counterToFlatArray(leavesToGive);
  const receive = counterToFlatArray(leavesToReceive);

  const swaps: OptimizationSwap[] = [];
  let toGiveBatch: number[] = [];
  let toReceiveBatch: number[] = [];

  while (give.length > 0 || receive.length > 0) {
    if (sum(toGiveBatch) > sum(toReceiveBatch)) {
      if (receive.length === 0) {
        break;
      }
      const leaf = receive.shift();
      if (leaf === undefined) {
        break;
      }
      toReceiveBatch.push(leaf);
    } else {
      if (give.length === 0) {
        break;
      }
      const leaf = give.shift();
      if (leaf === undefined) {
        break;
      }
      toGiveBatch.push(leaf);
    }

    if (
      toGiveBatch.length > 0 &&
      toReceiveBatch.length > 0 &&
      sum(toGiveBatch) === sum(toReceiveBatch)
    ) {
      if (toGiveBatch.length > maxLeavesPerSwap) {
        for (let i = 0; i < toGiveBatch.length; i += maxLeavesPerSwap) {
          const subset = toGiveBatch.slice(i, i + maxLeavesPerSwap);
          swaps.push(makeSwap(subset, greedyLeaves(sum(subset))));
        }
      } else if (toReceiveBatch.length > maxLeavesPerSwap) {
        for (let cutoff = maxLeavesPerSwap; cutoff > 0; cutoff--) {
          const sumCut = sum(toReceiveBatch.slice(0, cutoff));
          const remainder = sum(toGiveBatch) - sumCut;
          const alternateBatch = [...toReceiveBatch.slice(0, cutoff), ...greedyLeaves(remainder)];
          if (alternateBatch.length <= maxLeavesPerSwap) {
            swaps.push(makeSwap(toGiveBatch, alternateBatch));
            break;
          }
        }
      } else {
        swaps.push(makeSwap(toGiveBatch, toReceiveBatch));
      }
      toGiveBatch = [];
      toReceiveBatch = [];
    }
  }

  return swaps;
}

/**
 * Whether optimizing would change the wallet enough to be worth the swap rounds: for exit
 * maximization (multiplicity 0), only when the leaf count drops by more than 5x; otherwise, when
 * the active-denomination count changes by more than 2.
 */
export function shouldOptimize(
  inputLeaves: ReadonlyArray<number>,
  // oxlint-disable-next-line no-inferrable-types -- isolatedDeclarations requires it
  multiplicity: number = 1,
  maxLeavesPerSwap: number = DEFAULT_MAX_LEAVES_PER_SWAP,
): boolean {
  assertOptimizationOptions(multiplicity, maxLeavesPerSwap);
  for (const leaf of inputLeaves) {
    assertSats(leaf, "optimizeLeaves input");
  }
  if (multiplicity === 0) {
    const swaps = maximizeUnilateralExit(inputLeaves, maxLeavesPerSwap);
    const numInputs = sum(swaps.map((swap) => swap.inLeaves.length));
    const numOutputs = sum(swaps.map((swap) => swap.outLeaves.length));
    return numOutputs * 5 < numInputs;
  }
  const swaps = minimizeTransferSwap(inputLeaves, multiplicity, maxLeavesPerSwap);
  const inputCounter = countOccurrences(swaps.flatMap((swap) => swap.inLeaves));
  const outputCounter = countOccurrences(swaps.flatMap((swap) => swap.outLeaves));
  return Math.abs(inputCounter.size - outputCounter.size) > 2;
}

/** The planned swaps for `multiplicity === 0` (exit) or `>= 1` (swap-minimizing). */
export function optimize(
  inputLeaves: ReadonlyArray<number>,
  // oxlint-disable-next-line no-inferrable-types -- isolatedDeclarations requires it
  multiplicity: number = 1,
  maxLeavesPerSwap: number = DEFAULT_MAX_LEAVES_PER_SWAP,
): OptimizationSwap[] {
  assertOptimizationOptions(multiplicity, maxLeavesPerSwap);
  for (const leaf of inputLeaves) {
    assertSats(leaf, "optimizeLeaves input");
  }
  if (multiplicity === 0) {
    return maximizeUnilateralExit(inputLeaves, maxLeavesPerSwap);
  }
  return minimizeTransferSwap(inputLeaves, multiplicity, maxLeavesPerSwap);
}
