import { SparkError, SparkInputError } from "../errors/index.ts";
import type { SparkLeaf } from "./index.ts";

export type LeafSelection =
  | { readonly kind: "exact"; readonly groups: SparkLeaf[][] }
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
 * Disjoint exact combinations, one per amount (upstream `selectLeaves` semantics): amounts are
 * matched smallest-first over the remaining AVAILABLE leaves, so a small target cannot be starved
 * by a large one taking its exact leaf first. Returns the groups in the order `amounts` listed
 * them, or undefined when any amount cannot be matched exactly.
 */
export function selectExactMany(
  leaves: ReadonlyArray<SparkLeaf>,
  amounts: ReadonlyArray<number>,
): SparkLeaf[][] | undefined {
  let remaining = available(leaves);
  const groups: Array<SparkLeaf[] | undefined> = Array.from({ length: amounts.length });
  const byAscending = amounts.map((amount, index) => ({ amount, index }));
  byAscending.sort((a, b) => a.amount - b.amount);
  for (const { amount, index } of byAscending) {
    const group = selectExact(remaining, amount);
    if (group === undefined) {
      return undefined;
    }
    groups[index] = group;
    const used = new Set(group.map((leaf) => leaf.id));
    remaining = remaining.filter((leaf) => !used.has(leaf.id));
  }
  return groups.map((group) => {
    if (group === undefined) {
      throw new SparkError("selectExactMany: internal grouping failure");
    }
    return group;
  });
}

/**
 * Picks the leaves a spend uses: one exact combination per amount when they all exist, otherwise
 * the inputs to a leaves swap covering their total — the smallest single leaf covering it, else
 * value-descending accumulation until the inputs do. Insufficient AVAILABLE balance throws.
 */
export function selectLeaves(
  leaves: ReadonlyArray<SparkLeaf>,
  amounts: ReadonlyArray<number>,
): LeafSelection {
  if (amounts.length === 0) {
    throw new SparkInputError("send: amounts must not be empty");
  }
  let amountSats = 0;
  for (const amount of amounts) {
    if (!Number.isSafeInteger(amount) || amount <= 0) {
      throw new SparkInputError("send: amountSats must be a positive safe integer");
    }
    amountSats += amount;
    if (!Number.isSafeInteger(amountSats)) {
      throw new SparkInputError("send: amountSats sum exceeds the safe integer range");
    }
  }
  const exact = selectExactMany(leaves, amounts);
  if (exact !== undefined) {
    return { kind: "exact", groups: exact };
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
