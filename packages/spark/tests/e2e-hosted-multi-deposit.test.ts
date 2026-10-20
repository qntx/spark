import { describe, expect, test } from "vite-plus/test";

import type { SparkLeaf } from "../src/tree/index.ts";
import type { HostedWallet } from "./support/hosted.ts";
import { hostedSeed, hostedWallet } from "./support/hosted.ts";

// 2 × (amount − slow fee ≈ 1950) must clear the hosted 20000-sat deposit minimum.
const EXIT_AMOUNT_SATS = 15_000;
const MAX_FEE_SATS = 3000;
const STATUS_POLLS = 40;
const STATUS_POLL_DELAY_MS = 15_000;
const CLAIM_POLLS = 40;
const CLAIM_POLL_DELAY_MS = 15_000;
const FUNDED_ADDRESS = "sparkrt1pgssy2j63j3kmdzg54wavqs2z7yljfmk7j5adt5p4046lk5dzp7qjn3mz0ecyh";

const sleep = async (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

async function pollPayoutTx(
  client: HostedWallet["client"],
  requestId: string,
): Promise<Uint8Array> {
  for (let i = 0; i < STATUS_POLLS; i++) {
    // oxlint-disable-next-line no-await-in-loop -- sequential polls by design
    const status = await client.withdrawals.cooperativeExitStatus(requestId);
    console.log(
      `status poll ${i + 1}:`,
      status.status,
      "raw payout tx:",
      status.rawCoopExitTransaction !== undefined,
    );
    if (status.status === "FAILED" || status.status === "EXPIRED") {
      throw new Error(`coop exit ${requestId} ${status.status}`);
    }
    if (status.status === "SUCCEEDED" && status.rawCoopExitTransaction !== undefined) {
      return status.rawCoopExitTransaction;
    }
    // oxlint-disable-next-line no-await-in-loop -- sequential polls by design
    await sleep(STATUS_POLL_DELAY_MS);
  }
  throw new Error(`coop exit ${requestId} did not succeed in time`);
}

async function claimManyUntilAccepted(
  client: HostedWallet["client"],
  transactions: ReadonlyArray<Uint8Array>,
): Promise<SparkLeaf> {
  let lastError: Error | undefined;
  for (let i = 0; i < CLAIM_POLLS; i++) {
    try {
      // oxlint-disable-next-line no-await-in-loop -- sequential retries by design
      return await client.deposits.claimMany({
        outputs: transactions.map((transaction) => ({ transaction })),
      });
    } catch (error) {
      lastError = error as Error;
      console.log(`claim poll ${i + 1}:`, lastError.message.split("\n")[0]);
      // oxlint-disable-next-line no-await-in-loop -- sequential retries by design
      await sleep(CLAIM_POLL_DELAY_MS);
    }
  }
  throw lastError ?? new Error("claimMany was not accepted");
}

describe.skipIf(process.env["SPARK_E2E_HOSTED"] !== "1")(
  "hosted regtest multi-utxo deposit",
  () => {
    test("A exits twice to one single-use address and claims both UTXOs together", async (ctx) => {
      const seed = hostedSeed();
      const walletA = await hostedWallet(seed, 0);
      const { client: clientA } = walletA;

      await clientA.transfers.claimPending();
      const balanceA0 = await clientA.balance();
      console.log("A balance:", balanceA0);
      ctx.skip(
        balanceA0 < 2 * EXIT_AMOUNT_SATS,
        `hosted account 0 holds ${balanceA0} sats (< ${2 * EXIT_AMOUNT_SATS}) — ` +
          `fund ${FUNDED_ADDRESS} via the web faucet`,
      );

      const depositAddress = await clientA.deposits.newAddress();
      console.log("single-use deposit address:", depositAddress);

      const exitA = await clientA.withdrawals.cooperativeExit({
        address: depositAddress,
        speed: "SLOW",
        maxFeeSats: MAX_FEE_SATS,
        amountSats: EXIT_AMOUNT_SATS,
      });
      console.log(
        "exit A:",
        exitA.requestId,
        "txid:",
        exitA.coopExitTxid,
        "payout:",
        exitA.payoutSats,
        "fee:",
        exitA.feeSats,
        "status:",
        exitA.status,
      );
      const exitB = await clientA.withdrawals.cooperativeExit({
        address: depositAddress,
        speed: "SLOW",
        maxFeeSats: MAX_FEE_SATS,
        amountSats: EXIT_AMOUNT_SATS,
      });
      console.log(
        "exit B:",
        exitB.requestId,
        "txid:",
        exitB.coopExitTxid,
        "payout:",
        exitB.payoutSats,
        "fee:",
        exitB.feeSats,
        "status:",
        exitB.status,
      );
      expect(exitA.coopExitTxid).not.toBe(exitB.coopExitTxid);

      const rawTxA = await pollPayoutTx(clientA, exitA.requestId);
      console.log("payout tx A confirmed, raw bytes:", rawTxA.length);
      const rawTxB = await pollPayoutTx(clientA, exitB.requestId);
      console.log("payout tx B confirmed, raw bytes:", rawTxB.length);

      const payoutSum = exitA.payoutSats + exitB.payoutSats;
      const leaf = await claimManyUntilAccepted(clientA, [rawTxA, rawTxB]);
      console.log("claimed multi-utxo leaf:", leaf.id, leaf.status, leaf.valueSats, "sats");
      expect(leaf.valueSats).toBe(payoutSum);

      const balanceA1 = await clientA.balance();
      console.log("A balance after claim:", balanceA1);
      expect(balanceA1).toBe(balanceA0 - 2 * EXIT_AMOUNT_SATS + payoutSum);

      clientA.close();
      walletA.signer.dispose();
    }, 1_200_000);
  },
);
