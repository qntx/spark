import { bytesToHex } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { describe, expect, test } from "vite-plus/test";

import type { StaticDepositUtxo } from "../src/index.ts";
import type { SparkLeaf } from "../src/tree/index.ts";
import type { HostedWallet } from "./support/hosted.ts";
import {
  esploraBroadcast,
  esploraRawTx,
  esploraWaitConfirmed,
  hostedSeed,
  hostedWallet,
  sleep,
} from "./support/hosted.ts";

// The payout must clear the hosted 20000-sat deposit minimum after the slow fee lands.
const EXIT_AMOUNT_SATS = 25_000;
const MAX_FEE_SATS = 3000;
const CONFIRM_DEADLINE_MS = 900_000;
const UTXO_POLLS = 30;
const UTXO_POLL_DELAY_MS = 15_000;
const CLAIM_POLLS = 40;
const CLAIM_POLL_DELAY_MS = 15_000;
const FUNDED_ADDRESS = "sparkrt1pgssy2j63j3kmdzg54wavqs2z7yljfmk7j5adt5p4046lk5dzp7qjn3mz0ecyh";

const sats = (amount: bigint | undefined): number => {
  if (amount === undefined) {
    throw new Error("transaction output carries no amount");
  }
  return Number(amount);
};

function inputPrevout(tx: Transaction, index: number): { txid: string; vout: number } {
  const input = tx.getInput(index);
  if (input.txid === undefined || input.index === undefined) {
    throw new Error(`transaction input ${index} carries no outpoint`);
  }
  return { txid: bytesToHex(input.txid), vout: input.index };
}

async function staticUtxoUntil(
  client: HostedWallet["client"],
  txid: string,
): Promise<StaticDepositUtxo> {
  for (let i = 0; i < UTXO_POLLS; i++) {
    // oxlint-disable-next-line no-await-in-loop -- sequential polls by design
    const utxos = await client.deposits.staticUtxos();
    console.log("static utxos:", utxos.map((u) => `${u.txid.slice(0, 8)}:${u.vout}`).join(", "));
    const found = utxos.find((u) => u.txid === txid);
    if (found !== undefined) {
      return found;
    }
    // oxlint-disable-next-line no-await-in-loop -- sequential polls by design
    await sleep(UTXO_POLL_DELAY_MS);
  }
  throw new Error(`static deposit utxo ${txid} did not appear`);
}

async function claimUntilAccepted(
  client: HostedWallet["client"],
  transaction: Uint8Array,
): Promise<SparkLeaf> {
  let lastError: Error | undefined;
  for (let i = 0; i < CLAIM_POLLS; i++) {
    try {
      // oxlint-disable-next-line no-await-in-loop -- sequential retries by design
      return await client.deposits.claim({ transaction });
    } catch (error) {
      lastError = error as Error;
      console.log(`claim poll ${i + 1}:`, lastError.message.split("\n")[0]);
      // oxlint-disable-next-line no-await-in-loop -- sequential retries by design
      await sleep(CLAIM_POLL_DELAY_MS);
    }
  }
  throw lastError ?? new Error("claim was not accepted");
}

describe.skipIf(process.env["SPARK_E2E_HOSTED"] !== "1")("hosted regtest static refund", () => {
  test("coop exit to the static address, refund the utxo, claim it back", async (ctx) => {
    const seed = hostedSeed();
    const walletA = await hostedWallet(seed, 0);
    const { client: clientA } = walletA;

    await clientA.transfers.claimPending();
    const balanceA0 = await clientA.balance();
    console.log("A balance:", balanceA0);
    ctx.skip(
      balanceA0 < EXIT_AMOUNT_SATS,
      `hosted account 0 holds ${balanceA0} sats (< ${EXIT_AMOUNT_SATS}) — ` +
        `fund ${FUNDED_ADDRESS} via the web faucet`,
    );

    const staticAddress = await clientA.deposits.staticAddress();
    console.log("static deposit address:", staticAddress);
    const exit = await clientA.withdrawals.cooperativeExit({
      address: staticAddress,
      speed: "SLOW",
      amountSats: EXIT_AMOUNT_SATS,
      maxFeeSats: MAX_FEE_SATS,
    });
    console.log(
      "exit:",
      exit.requestId,
      "txid:",
      exit.coopExitTxid,
      "payout:",
      exit.payoutSats,
      "fee:",
      exit.feeSats,
      "status:",
      exit.status,
    );

    // The static utxo is spendable only once the payout confirms on chain.
    const height = await esploraWaitConfirmed(exit.coopExitTxid, Date.now() + CONFIRM_DEADLINE_MS);
    console.log("payout confirmed at height", height);

    const utxo = await staticUtxoUntil(clientA, exit.coopExitTxid);
    // The SO does not return raw_tx; Esplora is the raw-tx source of truth.
    const rawTx = await esploraRawTx(exit.coopExitTxid);
    const depositTx = Transaction.fromRaw(rawTx, { allowUnknownOutputs: true });
    const utxoSats = sats(depositTx.getOutput(utxo.vout).amount);
    console.log(`static utxo ${utxo.txid}:${utxo.vout} = ${utxoSats} sats`);
    expect(utxoSats).toBe(exit.payoutSats);

    // Refund the utxo back to a fresh single-use address instead of claiming it —
    // the refund output then comes home like an ordinary deposit.
    const destination = await clientA.deposits.newAddress();
    console.log("recycle destination:", destination);
    const refund = await clientA.deposits.refundStatic({
      txid: utxo.txid,
      vout: utxo.vout,
      destinationAddress: destination,
      feeRateSatPerVbyte: 1,
      rawTx,
    });
    const refundTx = Transaction.fromRaw(refund.transaction, { allowUnknownOutputs: true });
    const prevout = inputPrevout(refundTx, 0);
    const outSats = sats(refundTx.getOutput(0).amount);
    console.log("refund tx:", refund.txid, "pays", outSats, "sats (fee", utxoSats - outSats, ")");
    expect(prevout).toStrictEqual({ txid: utxo.txid, vout: utxo.vout });
    expect(outSats).toBeLessThan(utxoSats);

    const broadcastTxid = await esploraBroadcast(refund.transaction);
    expect(broadcastTxid).toBe(refund.txid);
    const refundHeight = await esploraWaitConfirmed(refund.txid, Date.now() + CONFIRM_DEADLINE_MS);
    console.log("refund confirmed at height", refundHeight);

    const leaf = await claimUntilAccepted(clientA, refund.transaction);
    console.log("claimed leaf:", leaf.id, leaf.status, leaf.valueSats, "sats");
    expect(leaf.valueSats).toBe(outSats);

    const balanceA1 = await clientA.balance();
    console.log("A balance:", balanceA0, "->", balanceA1);
    // balance − exit amount + (utxo − refund fee); the SSP exit fee is inside exit.feeSats.
    expect(balanceA1).toBe(balanceA0 - EXIT_AMOUNT_SATS + outSats);

    clientA.close();
    walletA.signer.dispose();
  }, 1_800_000);
});
