import { describe, expect, test } from "vite-plus/test";

import type { StaticDepositUtxo } from "../src/index.ts";
import type { HostedWallet } from "./support/hosted.ts";
import { esploraRawTx, hostedSeed, hostedWallet } from "./support/hosted.ts";

const UTXO_POLLS = 20;
const UTXO_POLL_DELAY_MS = 30_000;
const EXIT_AMOUNT_SATS = 4000;
const FUNDED_ADDRESS = "sparkrt1pgssy2j63j3kmdzg54wavqs2z7yljfmk7j5adt5p4046lk5dzp7qjn3mz0ecyh";

function describeUtxo(utxo: StaticDepositUtxo): string {
  return `${utxo.txid.slice(0, 8)}:${utxo.vout}`;
}

async function pollStaticUtxo(
  client: HostedWallet["client"],
  txid: string,
): Promise<{ vout: number }> {
  for (let i = 0; i < UTXO_POLLS; i++) {
    // oxlint-disable-next-line no-await-in-loop -- sequential polls by design
    const utxos = await client.deposits.staticUtxos();
    console.log("static utxos:", utxos.map(describeUtxo).join(", ") || "(none)");
    const found = utxos.find((u) => u.txid === txid);
    if (found !== undefined) {
      return { vout: found.vout };
    }
    // oxlint-disable-next-line no-await-in-loop -- sequential polls by design
    await new Promise((resolve) => setTimeout(resolve, UTXO_POLL_DELAY_MS));
  }
  throw new Error("static deposit utxo did not appear");
}

async function refundSecondUtxo(
  client: HostedWallet["client"],
  staticAddress: string,
  excludedTxid: string,
): Promise<string | undefined> {
  const remaining = await client.deposits.staticUtxos();
  const second = remaining.find((u) => u.txid !== excludedTxid);
  if (second === undefined) {
    console.log("no second static utxo — refund exercised in unit tests only");
    return undefined;
  }
  // The SO does not carry raw_tx — Esplora is the raw-tx source of truth.
  const refund = await client.deposits.refundStatic({
    txid: second.txid,
    vout: second.vout,
    destinationAddress: staticAddress,
    feeRateSatPerVbyte: 1,
    rawTx: await esploraRawTx(second.txid),
  });
  console.log("refund built (not broadcast):", refund.txid, refund.transaction.length, "bytes");
  expect(refund.txid).toMatch(/^[0-9a-f]{64}$/);
  return refund.txid;
}

async function claimStaticUtxo(
  client: HostedWallet["client"],
  txid: string,
  vout: number,
  rawTx: Uint8Array,
) {
  const claim = await client.deposits.claimStatic({
    txid,
    vout,
    maxFeeSats: 5000,
    rawTx,
  });
  console.log(
    "claimed:",
    claim.creditAmountSats,
    "fee:",
    claim.feeSats,
    "transfer:",
    claim.transferId,
    "leaves:",
    claim.leaves.length,
  );
  return claim;
}

describe.skipIf(process.env["SPARK_E2E_HOSTED"] !== "1")("hosted regtest static deposit", () => {
  test("A exits to its own static address, then claims the utxo back", async (ctx) => {
    const seed = hostedSeed();
    const walletA = await hostedWallet(seed, 0);
    const { client: clientA } = walletA;

    const staticAddress = await clientA.deposits.staticAddress();
    console.log("static address:", staticAddress);
    const balanceA0 = await clientA.balance();
    console.log("A balance:", balanceA0);
    ctx.skip(
      balanceA0 < EXIT_AMOUNT_SATS,
      `hosted account 0 holds ${balanceA0} sats — fund ${FUNDED_ADDRESS} via the web faucet`,
    );

    const exit = await clientA.withdrawals.cooperativeExit({
      address: staticAddress,
      speed: "SLOW",
      amountSats: EXIT_AMOUNT_SATS,
      maxFeeSats: 4000,
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

    const { vout } = await pollStaticUtxo(clientA, exit.coopExitTxid);
    const rawTx = await esploraRawTx(exit.coopExitTxid);

    const claim = await claimStaticUtxo(clientA, exit.coopExitTxid, vout, rawTx);
    expect(claim.creditAmountSats).toBeGreaterThan(0);

    // If the inbound transfer was not claimable inside claimStatic, this finishes it.
    const pending = await clientA.transfers.claimPending();
    console.log("claimPending recovered:", pending.leaves.length);
    const balanceA1 = await clientA.balance();
    console.log("A balance after claim:", balanceA1);
    expect(balanceA1).toBeGreaterThan(balanceA0 - EXIT_AMOUNT_SATS);

    await refundSecondUtxo(clientA, staticAddress, exit.coopExitTxid);

    clientA.close();
    walletA.signer.dispose();
  }, 900_000);
});
