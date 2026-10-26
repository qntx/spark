import { randomUUID } from "node:crypto";

import { describe, expect, test } from "vite-plus/test";

import type { SparkLeaf, SparkTransfer } from "../src/index.ts";
import { hostedSeed, hostedWallet } from "./support/hosted.ts";
import type { HostedWallet } from "./support/hosted.ts";
import { claimPendingUntil, pendingUntil, requiredTransfer } from "./support/local.ts";

const CLAIM_DEADLINE_MS = 180_000;

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
 * Two amounts `selectLeaves` can only cover via a swap: the first is the smallest sum no subset of
 * the AVAILABLE leaves forms exactly (subset-sum DP over the denominations), so the pair can never
 * select exactly. The pair's total must still fit the wallet.
 */
function pickSwapForcingPair(
  leaves: ReadonlyArray<SparkLeaf>,
): { readonly first: number; readonly second: number } | undefined {
  const second = 777;
  const total = totalSats(leaves);
  let reachable = new Set<number>([0]);
  for (const leaf of leaves) {
    if (leaf.status !== "AVAILABLE") {
      continue;
    }
    const next = new Set(reachable);
    for (const sum of reachable) {
      const candidate = sum + leaf.valueSats;
      if (candidate <= total) {
        next.add(candidate);
      }
    }
    reachable = next;
  }
  for (let first = 1; first + second <= total; first++) {
    if (!reachable.has(first)) {
      return { first, second };
    }
  }
  return undefined;
}

/**
 * The pair the test sends: preferably one no exact combination covers (forcing the SSP swap path);
 * when the wallet's denominations cover every affordable amount, two single-leaf exact amounts —
 * the v3 multi-receiver and retry paths are exercised either way.
 */
function pickSendPair(
  leaves: ReadonlyArray<SparkLeaf>,
): { readonly first: number; readonly second: number; readonly description: string } | undefined {
  const swapPair = pickSwapForcingPair(leaves);
  if (swapPair !== undefined) {
    return { ...swapPair, description: "forces a swap" };
  }
  const available = leaves
    .filter((leaf) => leaf.status === "AVAILABLE")
    .toSorted((a, b) => b.valueSats - a.valueSats);
  const [big, small] = available;
  if (big === undefined || small === undefined) {
    return undefined;
  }
  return { first: big.valueSats, second: small.valueSats, description: "exact leaf match" };
}

/** Polls until the given transfer id is pending for `client`, then returns that transfer. */
async function pendingTransfer(
  client: HostedWallet["client"],
  transferId: string,
): Promise<SparkTransfer> {
  const pending = await pendingUntil(client, Date.now() + CLAIM_DEADLINE_MS);
  return requiredTransfer(pending.find((transfer) => transfer.id === transferId));
}

/**
 * SendMany to two receivers over amounts that force an SSP leaves swap, then both receivers pay
 * back; afterwards a `send` retried under the same transferId must resolve to the committed
 * transfer instead of paying twice.
 */
describe.skipIf(process.env["SPARK_E2E_HOSTED"] !== "1")(
  "hosted regtest multi-receiver send",
  () => {
    test("A sendMany to B and C via a swap, both claim and repay; a retried send id resolves once", async (ctx) => {
      const seed = hostedSeed();
      const walletA = await hostedWallet(seed, 0);
      const walletB = await hostedWallet(seed, 1);
      const walletC = await hostedWallet(seed, 2);
      const { client: clientA } = walletA;
      const { client: clientB } = walletB;
      const { client: clientC } = walletC;

      const identityA = await clientA.identityPublicKey();
      const identityB = await clientB.identityPublicKey();
      const identityC = await clientC.identityPublicKey();
      await clientA.transfers.claimPending();
      const balanceA0 = await clientA.balance();
      const leavesA = await clientA.leaves();
      console.log("A balance:", balanceA0, "denominations:", denominations(leavesA));

      const pair = pickSendPair(leavesA);
      ctx.skip(pair === undefined, "account 0 holds fewer than two usable leaves");
      const amounts = requiredTransfer(pair);
      console.log(
        "sendMany amounts:",
        amounts.first,
        "+",
        amounts.second,
        `(${amounts.description})`,
      );

      const multi = await clientA.transfers.sendMany({
        receivers: [
          { receiver: identityB, amountSats: amounts.first },
          { receiver: identityC, amountSats: amounts.second },
        ],
      });
      console.log(
        "multi-send transfer:",
        multi.id,
        multi.status,
        "edges:",
        multi.receivers.map((receiver) => receiver.amountSats).join("/"),
      );
      await expect(clientA.balance()).resolves.toBe(balanceA0 - amounts.first - amounts.second);

      // G-SV: the signer derived a transfer outflow with per-receiver totals.
      const sent = walletA.outflows.find((o) => o.kind === "transfer");
      expect(sent?.kind).toBe("transfer");
      // oxlint-disable-next-line vitest/no-conditional-in-test -- narrowing guard
      if (sent === undefined || sent.kind !== "transfer") {
        throw new Error(`expected transfer outflow`);
      }
      expect(sent.transferId).toBe(multi.id);
      expect(sent.totalSats).toBe(amounts.first + amounts.second);
      const perReceiver = new Map(
        sent.receivers.map((r) => [Buffer.from(r.identityPublicKey).toString("hex"), r.amountSats]),
      );
      expect(perReceiver.get(Buffer.from(identityB).toString("hex"))).toBe(amounts.first);
      expect(perReceiver.get(Buffer.from(identityC).toString("hex"))).toBe(amounts.second);

      const claimedB = await clientB.transfers.claim(await pendingTransfer(clientB, multi.id));
      console.log("B claimed:", denominations(claimedB));
      expect(totalSats(claimedB)).toBe(amounts.first);
      const claimedC = await clientC.transfers.claim(await pendingTransfer(clientC, multi.id));
      console.log("C claimed:", denominations(claimedC));
      expect(totalSats(claimedC)).toBe(amounts.second);

      const backB = await clientB.transfers.send({
        receiver: identityA,
        amountSats: amounts.first,
      });
      console.log("B sent back:", backB.id);
      const backC = await clientC.transfers.send({
        receiver: identityA,
        amountSats: amounts.second,
      });
      console.log("C sent back:", backC.id);
      const reclaimed = await claimPendingUntil(clientA, Date.now() + CLAIM_DEADLINE_MS);
      console.log("A reclaimed:", denominations(reclaimed));

      // Idempotent retry: the second call with the same transferId probes the committed transfer,
      // returns it and must not move any more sats.
      const retryId = randomUUID();
      const first = await clientA.transfers.send({
        receiver: identityB,
        amountSats: 555,
        transferId: retryId,
      });
      const balanceAfterFirst = await clientA.balance();
      const second = await clientA.transfers.send({
        receiver: identityB,
        amountSats: 555,
        transferId: retryId,
      });
      expect(second.id).toBe(first.id);
      expect(second.id).toBe(retryId);
      await expect(clientA.balance()).resolves.toBe(balanceAfterFirst);
      console.log("retried send:", first.id, "resolved once at", balanceAfterFirst, "sats");

      const returnedB = await clientB.transfers.claim(await pendingTransfer(clientB, first.id));
      expect(totalSats(returnedB)).toBe(555);
      const finalBack = await clientB.transfers.send({ receiver: identityA, amountSats: 555 });
      console.log("B returned retry amount:", finalBack.id);
      await claimPendingUntil(clientA, Date.now() + CLAIM_DEADLINE_MS);
      await expect(clientA.balance()).resolves.toBe(balanceA0);
      console.log("A final balance:", await clientA.balance());

      clientA.close();
      clientB.close();
      clientC.close();
      walletA.signer.dispose();
      walletB.signer.dispose();
      walletC.signer.dispose();
    }, 600_000);
  },
);
