import { equalBytes } from "@noble/curves/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { decodeSparkAddress } from "../src/core/address.ts";
import { selectLeaves } from "../src/tree/index.ts";
import type { SparkLeaf } from "../src/tree/index.ts";
import { required } from "./support/fakes.ts";
import type { HostedWallet } from "./support/hosted.ts";
import { hostedSeed, hostedWallet } from "./support/hosted.ts";
import { claimPendingUntil } from "./support/local.ts";

const CLAIM_DEADLINE_MS = 180_000;
const FUNDED_ADDRESS = "sparkrt1pgssy2j63j3kmdzg54wavqs2z7yljfmk7j5adt5p4046lk5dzp7qjn3mz0ecyh";

const denominations = (leaves: ReadonlyArray<SparkLeaf>): number[] =>
  leaves.map((leaf) => leaf.valueSats);

/**
 * Returns whichever wallet ended the test ahead to its starting balance: spark sends conserve sats,
 * so at most one side can be up — and a whole-balance send would also sweep every leaf the account
 * has ever accumulated into one transfer.
 */
async function returnNetGain(
  clientA: HostedWallet["client"],
  clientB: HostedWallet["client"],
  identityA: Uint8Array,
  identityB: Uint8Array,
  balanceA0: number,
  balanceB0: number,
): Promise<void> {
  const balanceA1 = await clientA.balance();
  const balanceB1 = await clientB.balance();
  if (balanceB1 > balanceB0) {
    const sentBack = await clientB.transfers.send({
      receiver: identityA,
      amountSats: balanceB1 - balanceB0,
    });
    console.log("B sent back:", sentBack.id, sentBack.status);
    const reclaimed = await claimPendingUntil(clientA, Date.now() + CLAIM_DEADLINE_MS);
    if (reclaimed.length === 0) {
      throw new Error("A never claimed the returned sats");
    }
    console.log("A reclaimed denominations:", denominations(reclaimed));
  } else if (balanceA1 > balanceA0) {
    const sentBack = await clientA.transfers.send({
      receiver: identityB,
      amountSats: balanceA1 - balanceA0,
    });
    console.log("A sent back:", sentBack.id, sentBack.status);
    const reclaimed = await claimPendingUntil(clientB, Date.now() + CLAIM_DEADLINE_MS);
    if (reclaimed.length === 0) {
      throw new Error("B never claimed the returned sats");
    }
    console.log("B reclaimed denominations:", denominations(reclaimed));
  }
}
function totalSats(leaves: ReadonlyArray<SparkLeaf>): number {
  let sum = 0;
  for (const leaf of leaves) {
    sum += leaf.valueSats;
  }
  return sum;
}

/**
 * The smallest unselectable amount a single covering leaf supplies as swap input. Amounts at or
 * under `preferredCapSats` are preferred so small denominations are exercised first; the search
 * continues upward because a contiguous small-leaf set leaves no gap below it.
 */
function pickSingleLeafSwap(
  leaves: ReadonlyArray<SparkLeaf>,
  preferredCapSats: number,
): number | undefined {
  const total = totalSats(leaves);
  for (let candidate = 1; candidate <= Math.min(preferredCapSats, total); candidate++) {
    const selection = selectLeaves(leaves, [candidate]);
    if (selection.kind === "swap" && selection.leaves.length === 1) {
      return candidate;
    }
  }
  for (let candidate = preferredCapSats + 1; candidate < total; candidate++) {
    const selection = selectLeaves(leaves, [candidate]);
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
    if (selectLeaves(leaves, [candidate]).kind === "swap") {
      return candidate;
    }
  }
  return undefined;
}

type MultiSwapSender = {
  readonly sender: HostedWallet["client"];
  readonly senderLabel: string;
  readonly receiver: HostedWallet["client"];
  readonly receiverLabel: string;
  readonly receiverIdentity: Uint8Array;
  readonly sats: number;
};

/** The first wallet holding an unselectable amount above its largest leaf — A preferred, then B. */
function pickMultiSwapSender(options: {
  clientA: HostedWallet["client"];
  clientB: HostedWallet["client"];
  identityB: Uint8Array;
  identityA: Uint8Array;
  leavesA: ReadonlyArray<SparkLeaf>;
  leavesB: ReadonlyArray<SparkLeaf>;
}): MultiSwapSender | undefined {
  const fromA = pickMultiLeafSwap(options.leavesA);
  if (fromA !== undefined) {
    return {
      sender: options.clientA,
      senderLabel: "A",
      receiver: options.clientB,
      receiverLabel: "B",
      receiverIdentity: options.identityB,
      sats: fromA,
    };
  }
  const fromB = pickMultiLeafSwap(options.leavesB);
  if (fromB === undefined) {
    return undefined;
  }
  return {
    sender: options.clientB,
    senderLabel: "B",
    receiver: options.clientA,
    receiverLabel: "A",
    receiverIdentity: options.identityA,
    sats: fromB,
  };
}

describe.skipIf(process.env["SPARK_E2E_HOSTED"] !== "1")("hosted regtest leaves swap", () => {
  test("A pays B unselectable amounts via single-leaf and multi-leaf swaps; the net gain returns", async (ctx) => {
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
    console.log("A denominations now:", denominations(leavesA));
    // Multi-leaf swap inputs need an unselectable amount above the sender's largest leaf; whether
    // either wallet holds one depends on its denominations. Try A first, then B.
    const multi = pickMultiSwapSender({
      clientA,
      clientB,
      identityA,
      identityB,
      leavesA,
      leavesB: await clientB.leaves(),
    });
    ctx.skip(
      multi === undefined,
      "neither wallet has an unselectable amount above its largest leaf",
    );
    const {
      sender,
      senderLabel,
      receiver,
      receiverLabel,
      receiverIdentity,
      sats: satsMulti,
    } = required(multi, "multi-leaf swap sender");
    const senderBefore = await sender.balance();
    const receiverBefore = await receiver.balance();
    console.log(
      `${senderLabel} sending`,
      satsMulti,
      "sats (above its largest leaf — inputs accumulate)",
    );
    const sentMulti = await sender.transfers.send({
      receiver: receiverIdentity,
      amountSats: satsMulti,
    });
    console.log("swap+send transfer:", sentMulti.id, sentMulti.status);
    claimed = await claimPendingUntil(receiver, Date.now() + CLAIM_DEADLINE_MS);
    expect(claimed.length).toBeGreaterThan(0);
    console.log(`${receiverLabel} claimed denominations:`, denominations(claimed));
    await expect(sender.balance()).resolves.toBe(senderBefore - satsMulti);
    await expect(receiver.balance()).resolves.toBe(receiverBefore + satsMulti);

    // Return this test's net gain so the accounts end where they started.
    await returnNetGain(clientA, clientB, identityA, identityB, balanceA0, balanceB0);
    await expect(clientA.balance()).resolves.toBe(balanceA0);
    await expect(clientB.balance()).resolves.toBe(balanceB0);
    console.log("A denominations final:", denominations(await clientA.leaves()));

    clientA.close();
    clientB.close();
    walletA.signer.dispose();
    walletB.signer.dispose();
  }, 600_000);
});
