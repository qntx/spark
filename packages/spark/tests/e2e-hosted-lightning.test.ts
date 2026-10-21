import { equalBytes } from "@noble/curves/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { decodeSparkAddress } from "../src/core/address.ts";
import { decodeBolt11 } from "../src/core/bolt11.ts";
import { hostedSeed, hostedWallet, sendStatusUntil } from "./support/hosted.ts";
import { claimPendingUntil } from "./support/local.ts";

const CLAIM_DEADLINE_MS = 180_000;
const SEND_DEADLINE_MS = 180_000;
const FUNDED_ADDRESS = "sparkrt1pgssy2j63j3kmdzg54wavqs2z7yljfmk7j5adt5p4046lk5dzp7qjn3mz0ecyh";

describe.skipIf(process.env["SPARK_E2E_HOSTED"] !== "1")("hosted regtest lightning", () => {
  test("B invoices A twice over lightning; B returns the balance over spark", async (ctx) => {
    const seed = hostedSeed();
    const walletA = await hostedWallet(seed, 0);
    const walletB = await hostedWallet(seed, 1);
    const { client: clientA } = walletA;
    const { client: clientB } = walletB;

    const identityA = await clientA.identityPublicKey();
    const funded = decodeSparkAddress(FUNDED_ADDRESS);
    expect(equalBytes(funded.identityPublicKey, identityA)).toBe(true);

    await clientA.transfers.claimPending();
    await clientB.transfers.claimPending();
    const balanceA0 = await clientA.balance();
    const balanceB0 = await clientB.balance();
    console.log("A balance:", balanceA0, "B balance:", balanceB0);
    ctx.skip(
      balanceA0 < 3000,
      `hosted account 0 holds ${balanceA0} sats (< 3000) — fund it via the web faucet`,
    );

    // Fixed-amount invoice: B receives 1000 sats over lightning.
    const invoice1 = await clientB.lightning.createInvoice({
      amountSats: 1000,
      memo: "hosted e2e fixed",
    });
    console.log("B invoice:", invoice1.id, decodeBolt11(invoice1.invoice).network, "amount 1000");
    const paid1 = await clientA.lightning.pay({
      invoice: invoice1.invoice,
      maxFeeSats: 200,
    });
    console.log(
      "A paid:",
      paid1.requestId,
      "transfer:",
      paid1.transferId,
      "status:",
      paid1.status,
      "fee:",
      paid1.feeSats,
    );
    expect(paid1.feeSats).toBeLessThanOrEqual(200);

    const settled1 = await sendStatusUntil(clientA, paid1, Date.now() + SEND_DEADLINE_MS);
    console.log("send status:", settled1.status);
    // Internal (same-SSP) payments terminate at TRANSFER_COMPLETED; a real outbound
    // lightning payment would end at LIGHTNING_PAYMENT_SUCCEEDED. When the SSP surfaces a
    // preimage, sendStatus has already verified sha256(preimage) == the payment hash.
    expect(settled1.outcome).toBe("succeeded");
    console.log("preimage surfaced:", settled1.preimage !== undefined);

    const claimed1 = await claimPendingUntil(clientB, Date.now() + CLAIM_DEADLINE_MS);
    expect(claimed1.length).toBeGreaterThan(0);
    console.log("B claimed", claimed1.length, "leaves");
    await expect(clientB.balance()).resolves.toBeGreaterThanOrEqual(balanceB0 + 1000);

    // Amountless invoice: A picks 500 sats.
    const invoice2 = await clientB.lightning.createInvoice({
      amountSats: 0,
      memo: "hosted e2e amountless",
    });
    const paid2 = await clientA.lightning.pay({
      invoice: invoice2.invoice,
      amountSats: 500,
      maxFeeSats: 200,
    });
    console.log(
      "A paid amountless:",
      paid2.requestId,
      "transfer:",
      paid2.transferId,
      "status:",
      paid2.status,
      "fee:",
      paid2.feeSats,
    );
    const settled2 = await sendStatusUntil(clientA, paid2, Date.now() + SEND_DEADLINE_MS);
    console.log("send status:", settled2.status);
    expect(settled2.outcome).toBe("succeeded");
    console.log("preimage surfaced:", settled2.preimage !== undefined);
    await expect(
      clientB.lightning.receiveStatus({
        requestId: invoice2.id,
        paymentHash: invoice2.paymentHash,
      }),
    ).resolves.toMatchObject({
      status: expect.any(String),
    });

    const claimed2 = await claimPendingUntil(clientB, Date.now() + CLAIM_DEADLINE_MS);
    expect(claimed2.length).toBeGreaterThan(0);
    const balanceB = await clientB.balance();
    console.log("B balance:", balanceB);

    // B returns what it received to A so the account stays reusable. The send stays
    // bounded: a whole-balance send selects every leaf, and a long-lived account
    // accumulates more leaves than one signing round allows.
    const sentBack = await clientB.transfers.send({
      receiver: identityA,
      amountSats: balanceB - balanceB0,
    });
    console.log("B sent back:", sentBack.id, sentBack.status);
    const reclaimed = await claimPendingUntil(clientA, Date.now() + CLAIM_DEADLINE_MS);
    expect(reclaimed.length).toBeGreaterThan(0);
    const balanceAFinal = await clientA.balance();
    console.log("A balance final:", balanceAFinal);
    // A is out the two lightning fees; the invoiced amounts came back with B's return.
    expect(balanceAFinal).toBe(balanceA0 - paid1.feeSats - paid2.feeSats);

    clientA.close();
    clientB.close();
    walletA.signer.dispose();
    walletB.signer.dispose();
  }, 600_000);
});
