import { randomBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { uuidv7 } from "../src/core/uuid.ts";
import type { LightningPayment } from "../src/index.ts";
import { encodeTestBolt11 } from "./support/bolt11.ts";
import type { HostedWallet } from "./support/hosted.ts";
import { hostedSeed, hostedWallet, sleep } from "./support/hosted.ts";

const INVOICE_SATS = 1000;
const MAX_FEE_SATS = 50;
const POLL_MS = 15_000;
const RETURN_DEADLINE_MS = 12 * 60_000;
const FUNDED_ADDRESS = "sparkrt1pgssy2j63j3kmdzg54wavqs2z7yljfmk7j5adt5p4046lk5dzp7qjn3mz0ecyh";

type SeenStatus = { ms: number; status: string; outcome: string };

const TERMINAL_TRANSFER_STATUSES = new Set(["COMPLETED", "EXPIRED", "RETURNED"]);

/**
 * Waits until no transfer on the account is still in flight. An SSP swap abandoned by a crashed run
 * (a PRIMARY_SWAP_V3 the counter-swap never answered) returns on its own minutes later and would
 * inflate a balance measured while it is in flight.
 */
async function settleTransfers(client: HostedWallet["client"]): Promise<void> {
  for (let i = 0; i < 10; i++) {
    // oxlint-disable-next-line no-await-in-loop -- sequential polls by design
    const list = await client.transfers.list({ limit: 30 });
    const inFlight = list.filter((transfer) => !TERMINAL_TRANSFER_STATUSES.has(transfer.status));
    if (inFlight.length === 0) {
      return;
    }
    console.log("in-flight:", inFlight.map((t) => `${t.id} ${t.status}`).join(", "));
    // oxlint-disable-next-line no-await-in-loop -- sequential polls by design
    await sleep(POLL_MS);
  }
  throw new Error("transfers still in flight after 150s");
}

/** Polls sendStatus until the outcome is "succeeded" or "returned"; returns every transition. */
async function pollSendUntilTerminal(
  client: HostedWallet["client"],
  payment: LightningPayment,
): Promise<SeenStatus[]> {
  const t0 = Date.now();
  const seen: SeenStatus[] = [];
  let last = "";
  for (;;) {
    // oxlint-disable-next-line no-await-in-loop -- sequential polls by design
    const s = await client.lightning.sendStatus(payment);
    const key = `${s.status}/${s.outcome}`;
    if (key !== last) {
      last = key;
      seen.push({ ms: Date.now() - t0, status: s.status, outcome: s.outcome });
      console.log(`[+${Date.now() - t0}ms] ${s.status} -> ${s.outcome}`);
    }
    if (s.outcome === "succeeded" || s.outcome === "returned") {
      return seen;
    }
    if (Date.now() - t0 > RETURN_DEADLINE_MS) {
      throw new Error(`send did not reach a terminal outcome in time (last: ${last})`);
    }
    // oxlint-disable-next-line no-await-in-loop -- sequential polls by design
    await sleep(POLL_MS);
  }
}

describe.skipIf(process.env["SPARK_E2E_HOSTED"] !== "1")("hosted regtest lightning failure", () => {
  test("an unroutable invoice is returned by the SSP and the balance is restored", async (ctx) => {
    const seed = hostedSeed();
    const walletA = await hostedWallet(seed, 0);
    const { client: clientA } = walletA;

    await clientA.transfers.claimPending();
    await settleTransfers(clientA);
    const balanceA0 = await clientA.balance();
    console.log("A balance:", balanceA0);
    ctx.skip(
      balanceA0 < INVOICE_SATS + MAX_FEE_SATS,
      `hosted account 0 holds ${balanceA0} sats — fund ${FUNDED_ADDRESS} via the web faucet`,
    );

    // Valid signature, but the node key and payment hash are random — no route exists.
    const invoice = encodeTestBolt11({
      network: "regtest",
      amountMsat: BigInt(INVOICE_SATS) * 1000n,
      paymentHash: randomBytes(32),
      secretKey: randomBytes(32),
      expirySeconds: 3600,
      minFinalCltvExpiry: 18,
      description: "hosted e2e unroutable probe",
    });
    console.log("invoice:", invoice.slice(0, 60), "...");

    const payment = await clientA.lightning.pay({
      invoice,
      maxFeeSats: MAX_FEE_SATS,
      transferId: uuidv7(randomBytes),
    });
    console.log(
      "pay:",
      payment.requestId,
      "transfer:",
      payment.transferId,
      "status:",
      payment.status,
      "amount:",
      payment.amountSats,
      "fee:",
      payment.feeSats,
    );
    const committedSats = payment.amountSats + payment.feeSats;
    const balanceAfterPay = await clientA.balance();
    console.log("balance after pay:", balanceAfterPay);
    expect(balanceAfterPay).toBe(balanceA0 - committedSats);

    const sequence = await pollSendUntilTerminal(clientA, payment);
    const last = sequence.at(-1);
    // An unroutable payment can only fail or return — never succeed.
    expect(sequence.every((entry) => entry.outcome !== "succeeded")).toBe(true);
    expect(last?.outcome).toBe("returned");

    // The swap return restores the committed leaves in place: the balance is whole again,
    // including the fee, and no reverse transfer needs claiming.
    const balanceA1 = await clientA.balance();
    console.log("A balance:", balanceA0, "->", balanceA1);
    expect(balanceA1).toBe(balanceA0);

    clientA.close();
    walletA.signer.dispose();
  }, 1_200_000);
});
