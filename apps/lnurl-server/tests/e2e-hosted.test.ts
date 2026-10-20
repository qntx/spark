// Hosted e2e for the reference LNURL server: a real Hono listener on an ephemeral port, the
// sqlite store, the account-3 server wallet, and an in-process fake relay network standing in
// for the zap-request relays. The registrant signs over HTTP, a zapped invoice is paid on the
// hosted regtest deployment, the poll loop settles it and publishes the kind-9735 receipt.

import { randomBytes } from "node:crypto";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vite-plus/test";

import type { Event } from "@qntx/nostr";
import { Pool, Keys, bytesToHex, finalizeEvent } from "@qntx/nostr";
import { makeZapRequest, validateZapReceipt } from "@qntx/nostr/nips/nip57";
import type { FakeRelay } from "@qntx/nostr/testing";
import { createFakeRelayNetwork } from "@qntx/nostr/testing";
import { lightningAddressRegisterBody, lightningAddressUnregisterBody } from "@qntx/spark/lnurl";

import {
  hostedSeed,
  hostedWallet,
  sendStatusUntil,
  sleep,
} from "../../../packages/spark/tests/support/hosted.ts";
import { claimPendingUntil, required } from "../../../packages/spark/tests/support/local.ts";
import { startLnurlServer } from "../src/main.ts";
import { ZAP_RECEIPT_KIND } from "../src/zap.ts";

const CLAIM_DEADLINE_MS = 180_000;
const SETTLE_DEADLINE_MS = 180_000;
const RECEIPT_DEADLINE_MS = 90_000;
const AMOUNT_MSAT = 700_000;
const AMOUNT_SATS = 700;
const RELAY_URL = "wss://e2e.relay";
const FUNDED_ADDRESS = "sparkrt1pgssy2j63j3kmdzg54wavqs2z7yljfmk7j5adt5p4046lk5dzp7qjn3mz0ecyh";

/** Polls the HTTP verify endpoint until the invoice is reported settled or the deadline hits. */
async function verifyUntilSettled(
  base: string,
  hash: string,
  deadline: number,
): Promise<Record<string, unknown>> {
  const res = await fetch(`${base}/lnurlp/verify/${hash}`);
  const body = (await res.json()) as Record<string, unknown>;
  if (body["settled"] === true || Date.now() > deadline) {
    return body;
  }
  await sleep(3000);
  return verifyUntilSettled(base, hash, deadline);
}

/** Polls the fake relay until the kind-9735 receipt lands (or the deadline hits). */
async function receiptOn(relay: FakeRelay, deadline: number): Promise<Event | undefined> {
  const found = relay.events().find((event) => event.kind === ZAP_RECEIPT_KIND);
  if (found !== undefined || Date.now() > deadline) {
    return found;
  }
  await sleep(2000);
  return receiptOn(relay, deadline);
}

describe.skipIf(process.env["SPARK_E2E_HOSTED"] !== "1")("hosted regtest lnurl-server app", () => {
  test("registers over HTTP, settles a zapped invoice and publishes the receipt", async (ctx) => {
    const seed = hostedSeed();
    const domain = "example.com";
    const username = `carol${Date.now().toString(36)}`;
    const zapSecretHex = randomBytes(32).toString("hex");
    const zapPublicKey = Keys.fromSecretKey(zapSecretHex).publicKey;
    const zapper = Keys.generate();
    const zapTarget = Keys.generate().publicKey;

    // In-process relay network: the app's Pool connects to it through the injected
    // websocket implementation, so `relay.events()` observes the published receipt.
    const network = createFakeRelayNetwork();
    const relay = network.relay(RELAY_URL);
    const pool = new Pool({ websocketImplementation: network.websocketImplementation });

    const dbDir = mkdtempSync(join(tmpdir(), "lnurl-server-e2e-"));
    const served = await startLnurlServer(
      {
        LNURL_DOMAIN: domain,
        LNURL_NETWORK: "regtest",
        LNURL_SPARK_SEED: bytesToHex(seed),
        LNURL_SPARK_ACCOUNT: "3",
        LNURL_DB_PATH: join(dbDir, "lnurl.db"),
        LNURL_PORT: "0",
        LNURL_POLL_INTERVAL_MS: "2000",
        LNURL_ZAP_SECRET_KEY: zapSecretHex,
      },
      { pool },
    );
    const base = `http://127.0.0.1:${served.port}`;

    const registrant = await hostedWallet(seed, 1);
    const payer = await hostedWallet(seed, 2);
    const funder = await hostedWallet(seed, 0);

    try {
      const balanceF0 = await funder.client.balance();
      ctx.skip(
        balanceF0 < 20_000,
        `hosted account 0 holds ${balanceF0} sats (< 20000) — fund ${FUNDED_ADDRESS} via the web faucet`,
      );
      const balanceR0 = await registrant.client.balance();
      const balanceP0 = await payer.client.balance();
      console.log("balances: funder", balanceF0, "registrant", balanceR0, "payer", balanceP0);

      // Register over real HTTP.
      const { pubkeyHex, body } = await lightningAddressRegisterBody({
        domain,
        username,
        description: "Hosted e2e zap address",
        signer: registrant.signer,
      });
      const registered = await fetch(`${base}/lnurlpay/${pubkeyHex}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      expect(registered.status).toBe(200);
      const registration = (await registered.json()) as {
        lnurl: string;
        lightning_address: string;
      };
      expect(registration.lightning_address).toBe(`${username}@${domain}`);
      console.log("registered:", registration.lightning_address);

      // LUD-06 pay request advertises zaps with the configured receipt key.
      const payResponse = await fetch(`${base}/.well-known/lnurlp/${username}`);
      expect(payResponse.status).toBe(200);
      const payBody = (await payResponse.json()) as Record<string, unknown>;
      expect(payBody["tag"]).toBe("payRequest");
      expect(payBody["allowsNostr"]).toBe(true);
      expect(payBody["nostrPubkey"]).toBe(zapPublicKey);

      // A real signed 9734 zap request names the fake relay.
      const zapEvent = finalizeEvent(
        makeZapRequest({
          pubkey: zapTarget,
          amount: AMOUNT_MSAT,
          relays: [RELAY_URL],
        }),
        zapper,
      );
      const zapJson = JSON.stringify(zapEvent);

      const invoiceResponse = await fetch(
        `${base}/lnurlp/${username}/invoice?amount=${AMOUNT_MSAT}&nostr=${encodeURIComponent(zapJson)}`,
      );
      expect(invoiceResponse.status).toBe(200);
      const offer = (await invoiceResponse.json()) as { pr: string; verify: string };
      const hash = offer.verify.slice(offer.verify.lastIndexOf("/") + 1);
      console.log("invoice:", offer.pr.slice(0, 60), "hash:", hash);

      // Fund the payer with a fixed 5,000 sats from account 0, then pay.
      const payerIdentity = await payer.client.identityPublicKey();
      await funder.client.transfers.send({ receiver: payerIdentity, amountSats: 5000 });
      const funded = await claimPendingUntil(payer.client, Date.now() + CLAIM_DEADLINE_MS);
      expect(funded.length).toBeGreaterThan(0);
      const balanceP1 = await payer.client.balance();
      expect(balanceP1).toBe(balanceP0 + 5000);

      const payment = await payer.client.lightning.pay({ invoice: offer.pr, maxFeeSats: 50 });
      console.log("payment:", payment.requestId, payment.status, "fee:", payment.feeSats);

      // The app's own poll loop settles the invoice; the verify endpoint reports it.
      const verified = await verifyUntilSettled(base, hash, Date.now() + SETTLE_DEADLINE_MS);
      expect(verified["status"]).toBe("OK");
      expect(verified["settled"]).toBe(true);
      const preimageHex = required(verified["preimage"] as string | undefined, "settled preimage");
      expect(verified["pr"]).toBe(offer.pr);

      const sendOutcome = await sendStatusUntil(
        payer.client,
        payment,
        Date.now() + CLAIM_DEADLINE_MS,
      );
      expect(sendOutcome.outcome).toBe("succeeded");

      // The kind-9735 receipt is published to the zap request's relay and validates.
      const receipt = required(
        await receiptOn(relay, Date.now() + RECEIPT_DEADLINE_MS),
        "zap receipt on the relay",
      );
      expect(receipt.pubkey).toBe(zapPublicKey);
      const validation = validateZapReceipt(receipt, { nostrPubkey: zapPublicKey });
      expect(validation.valid).toBe(true);
      const tags = new Map(receipt.tags.map((tag) => [tag[0], tag[1]]));
      expect(tags.get("p")).toBe(zapTarget);
      expect(tags.get("P")).toBe(zapper.publicKey);
      expect(tags.get("bolt11")).toBe(offer.pr);
      expect(tags.get("description")).toBe(zapJson);
      expect(tags.get("preimage")).toBe(preimageHex);
      console.log("zap receipt:", receipt.id, "published to", RELAY_URL);

      // The registrant claims the inbound SSP transfer: +700 sats.
      const claimed = await claimPendingUntil(registrant.client, Date.now() + CLAIM_DEADLINE_MS);
      expect(claimed.length).toBeGreaterThan(0);
      await expect(registrant.client.balance()).resolves.toBe(balanceR0 + AMOUNT_SATS);

      // Close the loop: the registrant returns the 700 sats to the payer, so the only loss
      // is the lightning fee the payer spent (and the 5,000 the funder put in).
      await registrant.client.transfers.send({ receiver: payerIdentity, amountSats: AMOUNT_SATS });
      const returned = await claimPendingUntil(payer.client, Date.now() + CLAIM_DEADLINE_MS);
      expect(returned.length).toBeGreaterThan(0);
      await expect(registrant.client.balance()).resolves.toBe(balanceR0);
      await expect(payer.client.balance()).resolves.toBe(balanceP1 - payment.feeSats);

      // Give the name up over HTTP.
      const unreg = await lightningAddressUnregisterBody({
        domain,
        username,
        signer: registrant.signer,
      });
      const unregistered = await fetch(`${base}/lnurlpay/${unreg.pubkeyHex}`, {
        method: "DELETE",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(unreg.body),
      });
      expect(unregistered.status).toBe(200);
      const gone = await fetch(`${base}/.well-known/lnurlp/${username}`);
      expect(gone.status).toBe(404);
    } finally {
      await served.close();
      network.close();
    }
  }, 600_000);
});
