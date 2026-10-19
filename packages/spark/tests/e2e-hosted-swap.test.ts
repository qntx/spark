import { equalBytes } from "@noble/curves/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { decodeSparkAddress } from "../src/core/address.ts";
import { selectExact } from "../src/tree/index.ts";
import type { SparkLeaf } from "../src/tree/index.ts";
import { hostedSeed, hostedWallet } from "./support/hosted.ts";
import { claimPendingUntil } from "./support/local.ts";

const CLAIM_DEADLINE_MS = 180_000;
const FUNDED_ADDRESS = "sparkrt1pgssy2j63j3kmdzg54wavqs2z7yljfmk7j5adt5p4046lk5dzp7qjn3mz0ecyh";

const denominations = (leaves: ReadonlyArray<SparkLeaf>): number[] =>
  leaves.map((leaf) => leaf.valueSats);

/** The smallest amount at or under `capSats` that no exact leaf combination covers. */
function pickSwapAmount(leaves: ReadonlyArray<SparkLeaf>, capSats: number): number | undefined {
  for (let candidate = 1; candidate <= capSats; candidate++) {
    if (selectExact(leaves, candidate) === undefined) {
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
  test("A swaps leaves with the SSP to pay B an unselectable amount; B sends its balance back", async (ctx) => {
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
    const balanceA = await clientA.balance();
    const leavesA = await clientA.leaves();
    console.log("A balance:", balanceA, "denominations:", denominations(leavesA));
    ctx.skip(
      balanceA < 1000,
      `hosted account 0 holds ${balanceA} sats (< 1000) — fund it via the web faucet`,
    );

    const cap = Math.min(balanceA, 1000);
    const amount = pickSwapAmount(leavesA, cap);
    ctx.skip(
      amount === undefined,
      `every amount up to ${cap} sats has an exact combination — nothing to swap`,
    );
    const sats = required(amount, "swap amount");
    console.log("sending", sats, "sats (no exact combination)");

    const sent = await clientA.transfers.send({ receiver: identityB, amountSats: sats });
    console.log("swap+send transfer:", sent.id, sent.status);

    const claimed = await claimPendingUntil(clientB, Date.now() + CLAIM_DEADLINE_MS);
    expect(claimed.length).toBeGreaterThan(0);
    console.log("B claimed denominations:", denominations(claimed));

    const balanceAAfter = await clientA.balance();
    const balanceB = await clientB.balance();
    console.log("balances after send — A:", balanceAAfter, "B:", balanceB);
    expect(balanceAAfter).toBe(balanceA - sats);
    expect(balanceB).toBe(sats);

    const sentBack = await clientB.transfers.send({
      receiver: identityA,
      amountSats: balanceB,
    });
    console.log("B sent back:", sentBack.id, sentBack.status);
    const reclaimed = await claimPendingUntil(clientA, Date.now() + CLAIM_DEADLINE_MS);
    expect(reclaimed.length).toBeGreaterThan(0);
    console.log("A reclaimed denominations:", denominations(reclaimed));
    await expect(clientA.balance()).resolves.toBe(balanceA);
    console.log("A denominations now:", denominations(await clientA.leaves()));

    clientA.close();
    clientB.close();
    walletA.signer.dispose();
    walletB.signer.dispose();
  }, 600_000);
});
