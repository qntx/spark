import { SparkInputError } from "../errors/index.ts";
import type { SparkLeaf } from "./index.ts";

export type LeafSelection =
  | { readonly kind: "exact"; readonly leaves: SparkLeaf[] }
  | { readonly kind: "swap"; readonly leaves: SparkLeaf[] };

// 64-bit-safe power-of-two check (a JS `&` would truncate to 32 bits).
function isPowerOfTwo(value: number): boolean {
  let v = value;
  while (v > 0 && v % 2 === 0) {
    v /= 2;
  }
  return v === 1;
}

function available(leaves: ReadonlyArray<SparkLeaf>): SparkLeaf[] {
  return leaves.filter((leaf) => leaf.status === "AVAILABLE");
}

/**
 * Value-descending greedy subset-sum (Breez `greedy_exact_match`): take every leaf that fits the
 * remaining amount, in one pass.
 */
function greedyExact(
  leaves: ReadonlyArray<SparkLeaf>,
  amountSats: number,
): SparkLeaf[] | undefined {
  const sorted = [...leaves].sort((a, b) => b.valueSats - a.valueSats);
  const result: SparkLeaf[] = [];
  let remaining = amountSats;
  for (const leaf of sorted) {
    if (leaf.valueSats > remaining) {
      continue;
    }
    remaining -= leaf.valueSats;
    result.push(leaf);
    if (remaining === 0) {
      return result;
    }
  }
  return undefined;
}

/**
 * AVAILABLE leaves summing exactly to `amountSats`, or undefined (Breez `find_exact_multiple_match`
 * plus its single-match fast path): a single exact leaf first, then greedy over all leaves; when
 * that fails and some leaf is not a power of two, greedy again over power-of-two leaves only —
 * SSP-pooled denominations are powers of two, so a mixed wallet may only split evenly on them.
 */
export function selectExact(
  leaves: ReadonlyArray<SparkLeaf>,
  amountSats: number,
): SparkLeaf[] | undefined {
  if (!Number.isSafeInteger(amountSats) || amountSats <= 0) {
    return undefined;
  }
  const candidates = available(leaves);
  const single = candidates.find((leaf) => leaf.valueSats === amountSats);
  if (single !== undefined) {
    return [single];
  }
  if (candidates.length === 0) {
    return undefined;
  }
  const pass1 = greedyExact(candidates, amountSats);
  if (pass1 !== undefined) {
    return pass1;
  }
  const powersOfTwo = candidates.filter((leaf) => isPowerOfTwo(leaf.valueSats));
  if (powersOfTwo.length === candidates.length) {
    return undefined;
  }
  return greedyExact(powersOfTwo, amountSats);
}

/**
 * Picks the leaves a spend uses: an exact combination when one exists, otherwise the inputs to a
 * leaves swap — the smallest single leaf covering the amount, else value-descending accumulation
 * until the total covers it. Insufficient AVAILABLE balance throws.
 */
export function selectLeaves(leaves: ReadonlyArray<SparkLeaf>, amountSats: number): LeafSelection {
  if (!Number.isSafeInteger(amountSats) || amountSats <= 0) {
    throw new SparkInputError("send: amountSats must be a positive safe integer");
  }
  const exact = selectExact(leaves, amountSats);
  if (exact !== undefined) {
    return { kind: "exact", leaves: exact };
  }
  const candidates = available(leaves);
  let total = 0;
  let smallestCovering: SparkLeaf | undefined;
  for (const leaf of candidates) {
    total += leaf.valueSats;
    if (
      leaf.valueSats >= amountSats &&
      (smallestCovering === undefined || leaf.valueSats < smallestCovering.valueSats)
    ) {
      smallestCovering = leaf;
    }
  }
  if (total < amountSats) {
    throw new SparkInputError(
      `send: insufficient balance — need ${amountSats} sats, have ${total} sats`,
    );
  }
  if (smallestCovering !== undefined) {
    return { kind: "swap", leaves: [smallestCovering] };
  }
  const sorted = [...candidates].sort((a, b) => b.valueSats - a.valueSats);
  const swapInputs: SparkLeaf[] = [];
  let sum = 0;
  for (const leaf of sorted) {
    swapInputs.push(leaf);
    sum += leaf.valueSats;
    if (sum >= amountSats) {
      break;
    }
  }
  return { kind: "swap", leaves: swapInputs };
}
