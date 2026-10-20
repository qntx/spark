import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import { SparkInputError } from "../src/errors/index.ts";
import type { OptimizationSwap } from "../src/tree/index.ts";
import {
  assertOptimizationOptions,
  DEFAULT_MAX_LEAVES_PER_SWAP,
  greedyLeaves,
  MAX_PLANNING_ITERATIONS,
  maximizeUnilateralExit,
  minimizeTransferSwap,
  optimize,
  shouldOptimize,
  swapMinimizingLeaves,
} from "../src/tree/optimize.ts";

type VectorCase = {
  readonly id: string;
  readonly fn: string;
  readonly amount?: number;
  readonly inputLeaves?: number[];
  readonly multiplicity?: number;
  readonly maxLeavesPerSwap?: number;
  readonly expected?: unknown;
  readonly expectError?: string;
};

const vectors = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "../../../vectors/optimize.json"), "utf8"),
) as { cases: VectorCase[] };

function runCase(c: VectorCase): { result?: unknown; error?: string } {
  try {
    switch (c.fn) {
      case "greedyLeaves":
        return { result: greedyLeaves(c.amount ?? 0) };
      case "swapMinimizingLeaves":
        return { result: swapMinimizingLeaves(c.amount ?? 0, c.multiplicity ?? 1) };
      case "maximizeUnilateralExit":
        return {
          result: maximizeUnilateralExit(
            c.inputLeaves ?? [],
            c.maxLeavesPerSwap ?? DEFAULT_MAX_LEAVES_PER_SWAP,
          ),
        };
      case "minimizeTransferSwap":
        return {
          result: minimizeTransferSwap(
            c.inputLeaves ?? [],
            c.multiplicity ?? 1,
            c.maxLeavesPerSwap ?? DEFAULT_MAX_LEAVES_PER_SWAP,
          ),
        };
      case "shouldOptimize":
        return {
          result: shouldOptimize(
            c.inputLeaves ?? [],
            c.multiplicity ?? 1,
            c.maxLeavesPerSwap ?? DEFAULT_MAX_LEAVES_PER_SWAP,
          ),
        };
      case "optimize":
        return {
          result: optimize(
            c.inputLeaves ?? [],
            c.multiplicity ?? 1,
            c.maxLeavesPerSwap ?? DEFAULT_MAX_LEAVES_PER_SWAP,
          ),
        };
      default:
        return { error: `unknown fn ${c.fn}` };
    }
  } catch (error) {
    return { error: (error as Error).constructor.name };
  }
}

/** Executes planned swaps on a leaf multiset: inputs removed, outputs appended. */
function applySwaps(leaves: number[], swaps: ReadonlyArray<OptimizationSwap>): number[] {
  const residual = [...leaves];
  for (const swap of swaps) {
    for (const value of swap.inLeaves) {
      const index = residual.indexOf(value);
      if (index === -1) {
        throw new Error(`swap input ${value} not in residual leaves`);
      }
      residual.splice(index, 1);
    }
    residual.push(...swap.outLeaves);
  }
  return residual;
}

const valueCases = vectors.cases.filter((c) => c.expectError === undefined);
const errorCases = vectors.cases.filter((c) => c.expectError !== undefined);

describe("optimize vectors", () => {
  test.each(valueCases)("$id", (c) => {
    expect(runCase(c).result).toStrictEqual(c.expected);
  });

  test.each(errorCases)("$id", (c) => {
    expect(runCase(c).error).toBe(c.expectError);
  });
});

describe("optimize planner edge cases", () => {
  test("empty wallet yields no swaps and never optimizes", () => {
    expect(optimize([], 0)).toStrictEqual([]);
    expect(optimize([], 1)).toStrictEqual([]);
    expect(shouldOptimize([], 0)).toBe(false);
    expect(shouldOptimize([], 1)).toBe(false);
  });

  test("an already swap-minimized wallet yields no swaps", () => {
    expect(optimize([1, 1, 2, 4], 1)).toStrictEqual([]);
    expect(shouldOptimize([1, 1, 2, 4], 1)).toBe(false);
  });

  test("a non-denomination leaf reshapes into denominations", () => {
    expect(optimize([7], 1)).toStrictEqual([{ inLeaves: [7], outLeaves: [1, 2, 4] }]);
  });

  test("every planned swap is value-conserving and bounded", () => {
    const input = [3, 5, 9, 17, 33, 100, 250, 700];
    for (const swap of optimize(input, 1)) {
      expect(swap.inLeaves.length).toBeGreaterThan(0);
      expect(swap.outLeaves.length).toBeGreaterThan(0);
      expect(swap.inLeaves.reduce((a, b) => a + b, 0)).toBe(
        swap.outLeaves.reduce((a, b) => a + b, 0),
      );
    }
    expect(applySwaps(input, optimize(input, 1)).reduce((a, b) => a + b, 0)).toBe(1117);
  });

  test("rejects non-integer and out-of-range options", () => {
    expect(() => assertOptimizationOptions(1.5, 64)).toThrow(SparkInputError);
    expect(() => assertOptimizationOptions(Number.NaN, 64)).toThrow(SparkInputError);
    expect(() => assertOptimizationOptions(6, 64)).toThrow(SparkInputError);
    expect(() => assertOptimizationOptions(1, 0)).toThrow(SparkInputError);
    expect(() => assertOptimizationOptions(1, 2.5)).toThrow(SparkInputError);
    expect(() => swapMinimizingLeaves(100, 0)).toThrow(SparkInputError);
  });

  // Breez's `does_not_converge_when_split` analogue: when the optimal receive side does not fit
  // one swap, the emitted swap only partially reaches the optimum, so replanning must continue.
  test("an oversized optimal set needs another planning round (non-converging)", () => {
    const firstRound = optimize([50_000], 5, 64);
    expect(firstRound.length).toBeGreaterThan(0);
    for (const swap of firstRound) {
      expect(swap.inLeaves.length).toBeLessThanOrEqual(64);
      expect(swap.outLeaves.length).toBeLessThanOrEqual(64);
    }
    const residual = applySwaps([50_000], firstRound);
    expect(residual.reduce((a, b) => a + b, 0)).toBe(50_000);
    expect(optimize(residual, 5, 64).length).toBeGreaterThan(0);
  });

  test("MAX_PLANNING_ITERATIONS bounds the driver, matching Breez", () => {
    expect(MAX_PLANNING_ITERATIONS).toBe(8);
  });
});
