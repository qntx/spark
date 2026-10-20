import { equalBytes } from "@noble/curves/utils.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { decodeBolt11 } from "../src/core/bolt11.ts";
import {
  lightningAddressRegisterBody,
  lightningAddressUnregisterBody,
} from "../src/lnurl/index.ts";
import {
  createLightningAddressServer,
  createMemoryLightningAddressStore,
} from "../src/server/index.ts";
import type { LightningAddressInvoice, LightningAddressServer } from "../src/server/index.ts";
import { hostedSeed, hostedWallet, sendStatusUntil, sleep } from "./support/hosted.ts";
import { claimPendingUntil, required } from "./support/local.ts";

const CLAIM_DEADLINE_MS = 180_000;
const SETTLE_DEADLINE_MS = 180_000;
const FUNDED_ADDRESS = "sparkrt1pgssy2j63j3kmdzg54wavqs2z7yljfmk7j5adt5p4046lk5dzp7qjn3mz0ecyh";

/** Polls `server.settlePending` until an invoice settles or the deadline passes. */
async function settleUntil(
  server: LightningAddressServer,
  deadline: number,
): Promise<ReadonlyArray<LightningAddressInvoice>> {
  const settled = await server.settlePending();
  if (settled.length > 0 || Date.now() > deadline) {
    return settled;
  }
  await sleep(5000);
  return settleUntil(server, deadline);
}

describe.skipIf(process.env["SPARK_E2E_HOSTED"] !== "1")(
  "hosted regtest lightning address server",
  () => {
    test("register, invoice, settle, verify and unregister a lightning address", async (ctx) => {
      const seed = hostedSeed();
      const domain = "example.com";
      const username = `alice${Date.now().toString(36)}`;
      // The server wallet (account 3) only creates invoices — a zero balance is fine.
      const serverWallet = await hostedWallet(seed, 3);
      const registrant = await hostedWallet(seed, 1);
      const payer = await hostedWallet(seed, 2);
      const funder = await hostedWallet(seed, 0);

      const server = createLightningAddressServer({
        client: serverWallet.client,
        domain,
        store: createMemoryLightningAddressStore(),
        minSendableMsat: 1000,
        maxSendableMsat: 100_000_000,
        commentAllowed: 255,
      });

      const balanceF0 = await funder.client.balance();
      ctx.skip(
        balanceF0 < 20_000,
        `hosted account 0 holds ${balanceF0} sats (< 20000) — fund ${FUNDED_ADDRESS} via the web faucet`,
      );
      const balanceR0 = await registrant.client.balance();
      const balanceP0 = await payer.client.balance();
      console.log("balances: funder", balanceF0, "registrant", balanceR0, "payer", balanceP0);

      // Registrant (account 1) signs the register statement and claims the name.
      const { pubkeyHex, body } = await lightningAddressRegisterBody({
        domain,
        username,
        description: "Hosted e2e address",
        signer: registrant.signer,
      });
      const registered = await server.register(pubkeyHex, body);
      expect(registered.status).toBe(200);
      const registration = registered.body as { lnurl: string; lightning_address: string };
      console.log("registered:", registration.lightning_address);
      expect(registration.lightning_address).toBe(`${username}@${domain}`);

      // LUD-06 payRequest + invoice callback for 700 sats.
      const payResponse = await server.payRequest(username);
      expect(payResponse.status).toBe(200);
      const invoiceResponse = await server.invoice(username, { amount: 700_000 });
      expect(invoiceResponse.status).toBe(200);
      const offer = invoiceResponse.body as { pr: string; verify: string };
      const { paymentHash } = decodeBolt11(offer.pr);
      console.log("invoice:", offer.pr.slice(0, 60), "verify:", offer.verify);

      // Fund the payer with a fixed 5,000 sats from account 0, then pay.
      const payerIdentity = await payer.client.identityPublicKey();
      await funder.client.transfers.send({ receiver: payerIdentity, amountSats: 5000 });
      const funded = await claimPendingUntil(payer.client, Date.now() + CLAIM_DEADLINE_MS);
      expect(funded.length).toBeGreaterThan(0);
      const balanceP1 = await payer.client.balance();
      expect(balanceP1).toBe(balanceP0 + 5000);

      const payment = await payer.client.lightning.pay({ invoice: offer.pr, maxFeeSats: 50 });
      console.log("payment:", payment.requestId, payment.status, "fee:", payment.feeSats);

      // The server settles once the SSP reports the verified preimage.
      const settled = await settleUntil(server, Date.now() + SETTLE_DEADLINE_MS);
      expect(settled).toHaveLength(1);
      const preimageHex = required(settled[0]!.preimageHex, "settled preimage");
      expect(equalBytes(sha256(hexToBytes(preimageHex)), paymentHash)).toBe(true);

      const sendOutcome = await sendStatusUntil(
        payer.client,
        payment,
        Date.now() + CLAIM_DEADLINE_MS,
      );
      expect(sendOutcome.outcome).toBe("succeeded");

      // LUD-21 verify reports the settled invoice with its preimage.
      const verified = await server.verify(bytesToHex(paymentHash));
      const verifyBody = verified.body as Record<string, unknown>;
      expect(verifyBody["status"]).toBe("OK");
      expect(verifyBody["settled"]).toBe(true);
      expect(verifyBody["preimage"]).toBe(preimageHex);
      expect(verifyBody["pr"]).toBe(offer.pr);

      // The registrant claims the inbound SSP transfer: +700 sats.
      const claimed = await claimPendingUntil(registrant.client, Date.now() + CLAIM_DEADLINE_MS);
      expect(claimed.length).toBeGreaterThan(0);
      await expect(registrant.client.balance()).resolves.toBe(balanceR0 + 700);

      // Close the loop: the registrant returns the 700 sats to the payer, so the only loss is
      // the lightning fee the payer spent (and the 5,000 the funder put in).
      await registrant.client.transfers.send({ receiver: payerIdentity, amountSats: 700 });
      const returned = await claimPendingUntil(payer.client, Date.now() + CLAIM_DEADLINE_MS);
      expect(returned.length).toBeGreaterThan(0);
      await expect(registrant.client.balance()).resolves.toBe(balanceR0);
      await expect(payer.client.balance()).resolves.toBe(balanceP1 - payment.feeSats);

      // Give the name up.
      const unreg = await lightningAddressUnregisterBody({
        domain,
        username,
        signer: registrant.signer,
      });
      const unregistered = await server.unregister(unreg.pubkeyHex, unreg.body);
      expect(unregistered.status).toBe(200);
      const gone = await server.payRequest(username);
      expect(gone.status).toBe(404);
    }, 600_000);
  },
);
