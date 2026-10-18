import { hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import {
  bitcoinRpc,
  CLAIM_DEADLINE_MS,
  claimPendingUntil,
  claimUntilAccepted,
  exitChainDroppedUntil,
  leavesUntil,
  localWallet,
  mine,
  requiredTransfer,
} from "./support/local.ts";

describe.skipIf(process.env["SPARK_E2E_LOCAL"] !== "1")("local SO store reconcile", () => {
  test("exit chains reconcile across two devices sharing a seed", async () => {
    const walletA = await localWallet(randomBytes(32));
    const seedB = randomBytes(32);
    const walletB1 = await localWallet(seedB);
    const walletB2 = await localWallet(seedB);

    // A deposits and sends to B's identity; both B devices share the seed.
    const address = await walletA.client.deposits.newAddress();
    const txid = (await bitcoinRpc("sendtoaddress", [address, 0.001])) as string;
    await mine(1);
    const rawHex = (await bitcoinRpc("getrawtransaction", [txid])) as string;
    await claimUntilAccepted(walletA.client, hexToBytes(rawHex), Date.now() + CLAIM_DEADLINE_MS);
    await leavesUntil(walletA.client, Date.now() + CLAIM_DEADLINE_MS);
    await walletA.client.transfers.send({
      receiver: await walletB1.signer.identityPublicKey(),
      amountSats: 100_000,
    });

    // Device B1 claims and syncs: its store holds the exit chain.
    const claimedByB1 = await claimPendingUntil(walletB1.client, Date.now() + CLAIM_DEADLINE_MS);
    const leafId = requiredTransfer(claimedByB1[0]).id;
    await leavesUntil(walletB1.client, Date.now() + CLAIM_DEADLINE_MS);
    const b1Chains = await walletB1.store.exitChains();
    expect(b1Chains.map((chain) => chain.leafId)).toContain(leafId);
    console.log("B1 stored exit chain for", leafId);

    // Device B2 sees the same leaf (same identity) and sends it back to A.
    await leavesUntil(walletB2.client, Date.now() + CLAIM_DEADLINE_MS);
    await walletB2.client.transfers.send({
      receiver: await walletA.signer.identityPublicKey(),
      amountSats: 100_000,
    });
    console.log("B2 sent the leaf away");

    // B1 re-syncs against the owner query: the leaf is gone, so its chain is dropped.
    const dropped = await exitChainDroppedUntil(
      walletB1.client,
      walletB1.store,
      leafId,
      Date.now() + CLAIM_DEADLINE_MS,
    );
    expect(dropped).toBe(true);
    const b2Chains = await walletB2.store.exitChains();
    expect(b2Chains.map((chain) => chain.leafId)).not.toContain(leafId);
    console.log("B1 and B2 stores dropped the spent chain");

    walletA.client.close();
    walletB1.client.close();
    walletB2.client.close();
    walletA.signer.dispose();
    walletB1.signer.dispose();
    walletB2.signer.dispose();
  }, 300_000);
});
