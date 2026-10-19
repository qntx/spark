import { equalBytes } from "@noble/curves/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { decodeSparkAddress } from "../src/core/address.ts";
import { selectLeaves } from "../src/tree/index.ts";
import type { SparkLeaf } from "../src/tree/index.ts";
import { hostedSeed, hostedWallet } from "./support/hosted.ts";
import { claimPendingUntil } from "./support/local.ts";

const CLAIM_DEADLINE_MS = 180_000;
const FUNDED_ADDRESS = "sparkrt1pgssy2j63j3kmdzg54wavqs2z7yljfmk7j5adt5p4046lk5dzp7qjn3mz0ecyh";

const denominations = (leaves: ReadonlyArray<SparkLeaf>): number[] =>
  leaves.map((leaf) => leaf.valueSats);
function totalSats(leaves: ReadonlyArray<SparkLeaf>): number {
  let sum = 0;
  for (const leaf of leaves) {
    sum += leaf.valueSats;
  }
  return sum;
}

/**
 * The largest amount at or under `capSats` that no exact combination covers and that a single
 * covering leaf supplies as swap input (searched downward from `capSats`).
 */
function pickSingleLeafSwap(leaves: ReadonlyArray<SparkLeaf>, capSats: number): number | undefined {
  for (let candidate = Math.min(capSats, totalSats(leaves)); candidate >= 1; candidate--) {
    const selection = selectLeaves(leaves, candidate);
    if (selection.kind === "swap" && selection.leaves.length === 1) {
      return candidate;
    }
  }
  return undefined;
}

/**
 * The smallest amount above the largest leaf that no exact combination covers, so the swap input
 * accumulates several leaves.
 */
function pickMultiLeafSwap(leaves: ReadonlyArray<SparkLeaf>): number | undefined {
  const total = totalSats(leaves);
  let largest = 0;
  for (const leaf of leaves) {
    largest = Math.max(largest, leaf.valueSats);
  }
  for (let candidate = largest + 1; candidate < total; candidate++) {
    if (selectLeaves(leaves, candidate).kind === "swap") {
      return candidate;
    }
  }
  return undefined;
}

function required<T>(value: T | undefined, name: string): T {
  if (value === undefined) {
    throw new Error(`${name} was not produced`);
  }
  return value;
}

describe.skipIf(process.env["SPARK_E2E_HOSTED"] !== "1")("hosted regtest leaves swap", () => {
  test("A pays B unselectable amounts via single-leaf and multi-leaf swaps; B returns the balance", async (ctx) => {
    const seed = hostedSeed();
    const walletA = await hostedWallet(seed, 0);
    const walletB = await hostedWallet(seed, 1);
    const { client: clientA } = walletA;
    const { client: clientB } = walletB;

    const identityA = await clientA.identityPublicKey();
    const identityB = await clientB.identityPublicKey();
    const funded = decodeSparkAddress(FUNDED_ADDRESS);
    expect(equalBytes(funded.identityPublicKey, identityA)).toBe(true);

    // Faucet funds arrive as incoming transfers; claim them before reading the balance.
    await clientA.transfers.claimPending();
    const balanceA0 = await clientA.balance();
    const balanceB0 = await clientB.balance();
    let leavesA = await clientA.leaves();
    console.log("A balance:", balanceA0, "denominations:", denominations(leavesA));
    ctx.skip(
      balanceA0 < 1000,
      `hosted account 0 holds ${balanceA0} sats (< 1000) — fund it via the web faucet`,
    );

    const amountSingle = pickSingleLeafSwap(leavesA, 777);
    ctx.skip(
      amountSingle === undefined,
      "every unselectable amount up to 777 sats lacks a single covering leaf",
    );
    const satsSingle = required(amountSingle, "single-leaf swap amount");
    console.log("sending", satsSingle, "sats (no exact combination, one covering leaf input)");

    const sentSingle = await clientA.transfers.send({
      receiver: identityB,
      amountSats: satsSingle,
    });
    console.log("swap+send transfer:", sentSingle.id, sentSingle.status);

    let claimed = await claimPendingUntil(clientB, Date.now() + CLAIM_DEADLINE_MS);
    expect(claimed.length).toBeGreaterThan(0);
    console.log("B claimed denominations:", denominations(claimed));
    await expect(clientA.balance()).resolves.toBe(balanceA0 - satsSingle);
    await expect(clientB.balance()).resolves.toBe(balanceB0 + satsSingle);

    leavesA = await clientA.leaves();
    const balanceA1 = await clientA.balance();
    console.log("A denominations now:", denominations(leavesA));
    const amountMulti = pickMultiLeafSwap(leavesA);
    ctx.skip(
      amountMulti === undefined,
      "every amount above the largest leaf has an exact combination",
    );
    const satsMulti = required(amountMulti, "multi-leaf swap amount");
    console.log("sending", satsMulti, "sats (above the largest leaf — inputs accumulate)");

    const sentMulti = await clientA.transfers.send({
      receiver: identityB,
      amountSats: satsMulti,
    });
    console.log("swap+send transfer:", sentMulti.id, sentMulti.status);

    claimed = await claimPendingUntil(clientB, Date.now() + CLAIM_DEADLINE_MS);
    expect(claimed.length).toBeGreaterThan(0);
    console.log("B claimed denominations:", denominations(claimed));
    const balanceB = await clientB.balance();
    await expect(clientA.balance()).resolves.toBe(balanceA1 - satsMulti);
    expect(balanceB).toBe(balanceB0 + satsSingle + satsMulti);

    const sentBack = await clientB.transfers.send({
      receiver: identityA,
      amountSats: balanceB,
    });
    console.log("B sent back:", sentBack.id, sentBack.status);
    const reclaimed = await claimPendingUntil(clientA, Date.now() + CLAIM_DEADLINE_MS);
    expect(reclaimed.length).toBeGreaterThan(0);
    console.log("A reclaimed denominations:", denominations(reclaimed));
    await expect(clientA.balance()).resolves.toBe(balanceA0 + balanceB0);
    console.log("A denominations final:", denominations(await clientA.leaves()));

    clientA.close();
    clientB.close();
    walletA.signer.dispose();
    walletB.signer.dispose();
  }, 600_000);
});
