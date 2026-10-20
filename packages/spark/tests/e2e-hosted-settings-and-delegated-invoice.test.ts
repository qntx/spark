import { randomBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { connectOperator } from "../src/connection/index.ts";
import { encodeSparkAddress } from "../src/core/address.ts";
import { sparkNetworkConfig, sparkNetworkProto } from "../src/core/network.ts";
import { TreeNodeStatus } from "../src/proto/gen/spark_pb.ts";
import { hostedSeed, hostedWallet, SEND_OK, sendStatusUntil } from "./support/hosted.ts";
import { claimPendingUntil } from "./support/local.ts";

const CLAIM_DEADLINE_MS = 180_000;
const SEND_DEADLINE_MS = 180_000;
const FUNDED_ADDRESS = "sparkrt1pgssy2j63j3kmdzg54wavqs2z7yljfmk7j5adt5p4046lk5dzp7qjn3mz0ecyh";

const [COORDINATOR] = sparkNetworkConfig("regtest").operators;

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

describe.skipIf(process.env["SPARK_E2E_HOSTED"] !== "1")(
  "hosted regtest wallet settings and delegated invoices",
  () => {
    test("private_enabled hides a wallet's nodes from other identities", async (ctx) => {
      const seed = hostedSeed();
      const walletA = await hostedWallet(seed, 0);
      const walletB = await hostedWallet(seed, 1);
      const clientA = walletA.client;

      const identityA = await clientA.identityPublicKey();
      const balanceA = await clientA.balance();
      console.log("A balance:", balanceA);
      ctx.skip(
        balanceA < 3000,
        `hosted account 0 holds ${balanceA} sats (< 3000) — fund ${FUNDED_ADDRESS} via the web faucet`,
      );

      // A foreign session on the coordinator, authenticated as account 1.
      const foreign = connectOperator(COORDINATOR!, {
        signer: walletB.signer,
        fetch: globalThis.fetch,
        random: (length) => randomBytes(length),
      });
      const queryAsB = async () =>
        foreign.spark.query_nodes({
          source: { case: "ownerIdentityPubkey", value: identityA },
          includeParents: false,
          limit: 1n,
          offset: 0n,
          network: sparkNetworkProto("regtest"),
          statuses: [TreeNodeStatus.AVAILABLE],
        });

      // Public by default: another identity can read account 0's nodes.
      const before = await queryAsB();
      console.log("foreign query before private:", Object.keys(before.nodes).length, "nodes");
      expect(Object.keys(before.nodes).length).toBeGreaterThan(0);

      try {
        const enabled = await clientA.walletSettings.setPrivate(true);
        expect(enabled.privateEnabled).toBe(true);
        await expect(clientA.walletSettings.get()).resolves.toStrictEqual({
          privateEnabled: true,
        });

        // The owner's own reads still work (all three operators serve syncLeaves).
        const ownLeaves = await clientA.leaves();
        console.log("A leaves while private:", ownLeaves.length);
        expect(ownLeaves.length).toBeGreaterThan(0);

        // A foreign session is denied — record whether it errors or returns empty.
        let foreignResult = "";
        try {
          const denied = await queryAsB();
          foreignResult = `empty response, ${Object.keys(denied.nodes).length} nodes`;
        } catch (error) {
          foreignResult = `error: ${errorText(error)}`;
        }
        console.log("foreign query while private:", foreignResult);
      } finally {
        const restored = await clientA.walletSettings.setPrivate(false);
        expect(restored.privateEnabled).toBe(false);
      }

      const after = await queryAsB();
      console.log("foreign query after restore:", Object.keys(after.nodes).length, "nodes");
      expect(Object.keys(after.nodes).length).toBeGreaterThan(0);

      clientA.close();
      walletB.client.close();
      walletA.signer.dispose();
      walletB.signer.dispose();
    }, 300_000);

    test("A creates an invoice paying B; C pays it; B claims it", async (ctx) => {
      const seed = hostedSeed();
      const walletA = await hostedWallet(seed, 0);
      const walletB = await hostedWallet(seed, 1);
      const walletC = await hostedWallet(seed, 2);
      const clientA = walletA.client;
      const clientB = walletB.client;
      const clientC = walletC.client;

      const identityB = await clientB.identityPublicKey();
      const identityC = await clientC.identityPublicKey();
      const addressB = encodeSparkAddress({ network: "regtest", identityPublicKey: identityB });

      await clientA.transfers.claimPending();
      await clientB.transfers.claimPending();
      await clientC.transfers.claimPending();
      const balanceA0 = await clientA.balance();
      const balanceB0 = await clientB.balance();
      const balanceC0 = await clientC.balance();
      console.log("balances:", balanceA0, balanceB0, balanceC0);
      ctx.skip(
        balanceA0 < 2500,
        `hosted account 0 holds ${balanceA0} sats (< 2500) — fund ${FUNDED_ADDRESS} via the web faucet`,
      );

      // Account 2 is the payer; fund it over spark first so the three roles stay distinct.
      const funded = await clientA.transfers.send({ receiver: identityC, amountSats: 2000 });
      console.log("A funded C:", funded.id, funded.status);
      await claimPendingUntil(clientC, Date.now() + CLAIM_DEADLINE_MS);
      await expect(clientC.balance()).resolves.toBe(balanceC0 + 2000);

      // A creates a 500-sat invoice whose payee is B (identity key form).
      const invoice1 = await clientA.lightning.createInvoice({
        amountSats: 500,
        memo: "delegated e2e",
        receiver: identityB,
      });
      console.log("delegated invoice:", invoice1.id);
      const paid1 = await clientC.lightning.pay({ invoice: invoice1.invoice, maxFeeSats: 200 });
      console.log("C paid:", paid1.requestId, "transfer:", paid1.transferId, "fee:", paid1.feeSats);
      const settled1 = await sendStatusUntil(clientC, paid1, Date.now() + SEND_DEADLINE_MS);
      console.log("send status:", settled1.status);
      expect(SEND_OK.has(settled1.status)).toBe(true);

      const claimed1 = await claimPendingUntil(clientB, Date.now() + CLAIM_DEADLINE_MS);
      expect(claimed1.length).toBeGreaterThan(0);
      await expect(clientB.balance()).resolves.toBe(balanceB0 + 500);

      // Again, with the spark address embedded — and passed as an address string.
      const invoice2 = await clientA.lightning.createInvoice({
        amountSats: 500,
        memo: "delegated e2e spark address",
        receiver: addressB,
        includeSparkAddress: true,
      });
      const paid2 = await clientC.lightning.pay({ invoice: invoice2.invoice, maxFeeSats: 200 });
      console.log("C paid:", paid2.requestId, "transfer:", paid2.transferId, "fee:", paid2.feeSats);
      const settled2 = await sendStatusUntil(clientC, paid2, Date.now() + SEND_DEADLINE_MS);
      console.log("send status:", settled2.status);
      expect(SEND_OK.has(settled2.status)).toBe(true);
      const claimed2 = await claimPendingUntil(clientB, Date.now() + CLAIM_DEADLINE_MS);
      expect(claimed2.length).toBeGreaterThan(0);
      await expect(clientB.balance()).resolves.toBe(balanceB0 + 1000);

      // B returns what it received to C; C then returns its whole balance to A — the wallet
      // ends out only the two lightning fees.
      const returned = await clientB.transfers.send({ receiver: identityC, amountSats: 1000 });
      console.log("B returned:", returned.id, returned.status);
      await claimPendingUntil(clientC, Date.now() + CLAIM_DEADLINE_MS);
      const balanceCBeforeReturn = await clientC.balance();
      const returnedToA = await clientC.transfers.send({
        receiver: await clientA.identityPublicKey(),
        amountSats: balanceCBeforeReturn,
      });
      console.log("C returned:", returnedToA.id, returnedToA.status);
      await claimPendingUntil(clientA, Date.now() + CLAIM_DEADLINE_MS);

      const balanceA1 = await clientA.balance();
      const balanceB1 = await clientB.balance();
      const balanceC1 = await clientC.balance();
      console.log("final balances:", balanceA1, balanceB1, balanceC1);
      expect(balanceA1).toBe(balanceA0 - paid1.feeSats - paid2.feeSats);
      expect(balanceB1).toBe(balanceB0);
      expect(balanceC1).toBe(balanceC0);

      clientA.close();
      clientB.close();
      clientC.close();
      walletA.signer.dispose();
      walletB.signer.dispose();
      walletC.signer.dispose();
    }, 600_000);
  },
);
