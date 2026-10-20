import { hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { encodeSparkAddress } from "../src/core/address.ts";
import { exitTransactions } from "../src/index.ts";
import {
  bitcoinRpc,
  CLAIM_DEADLINE_MS,
  claimPendingUntil,
  claimUntilAccepted,
  leavesUntil,
  localWallet,
  pendingUntil,
  requiredTransfer,
} from "./support/local.ts";

describe.skipIf(process.env["SPARK_E2E_LOCAL"] !== "1")("local SO transfer flow", () => {
  test("newAddress → on-chain deposit → claim → leaf visible; second claim fails", async () => {
    const { signer, client } = await localWallet(randomBytes(32));

    const address = await client.deposits.newAddress();
    expect(address.startsWith("bcrt1")).toBe(true);
    console.log("deposit address:", address);

    const txid = (await bitcoinRpc("sendtoaddress", [address, 0.001])) as string;
    console.log("sent deposit tx:", txid);
    const minerAddress = (await bitcoinRpc("getnewaddress", [])) as string;
    await bitcoinRpc("generatetoaddress", [1, minerAddress]);
    const rawHex = (await bitcoinRpc("getrawtransaction", [txid])) as string;
    const transaction = hexToBytes(rawHex);

    const leaf = await claimUntilAccepted(client, transaction, Date.now() + CLAIM_DEADLINE_MS);
    expect(leaf.valueSats).toBe(100_000);
    console.log("claimed leaf:", leaf.id, leaf.status, leaf.valueSats, "sats");

    const leaves = await leavesUntil(client, Date.now() + CLAIM_DEADLINE_MS);
    expect(leaves.map((l) => l.id)).toContain(leaf.id);
    await expect(client.balance()).resolves.toBe(100_000);

    const unused = await client.deposits.unused();
    expect(unused.map((u) => u.address)).not.toContain(address);

    await expect(client.deposits.claim({ transaction })).rejects.toThrow(/./);
    client.close();
    signer.dispose();
  }, 180_000);

  test("A sends 100000 sats to B, B claims and sends it back", async () => {
    const { signer: signerA, store: storeA, client: clientA } = await localWallet(randomBytes(32));
    const { signer: signerB, store: storeB, client: clientB } = await localWallet(randomBytes(32));

    // Fund A via the S7a deposit flow.
    const address = await clientA.deposits.newAddress();
    const txid = (await bitcoinRpc("sendtoaddress", [address, 0.001])) as string;
    console.log("A deposit tx:", txid);
    const minerAddress = (await bitcoinRpc("getnewaddress", [])) as string;
    await bitcoinRpc("generatetoaddress", [1, minerAddress]);
    const rawHex = (await bitcoinRpc("getrawtransaction", [txid])) as string;
    const leafA = await claimUntilAccepted(
      clientA,
      hexToBytes(rawHex),
      Date.now() + CLAIM_DEADLINE_MS,
    );
    console.log("A claimed leaf:", leafA.id, leafA.valueSats, "sats");

    const receiverAddress = encodeSparkAddress({
      network: "regtest",
      identityPublicKey: await signerB.identityPublicKey(),
    });
    const leavesA = await leavesUntil(clientA, Date.now() + CLAIM_DEADLINE_MS);
    expect(leavesA.map((l) => l.id)).toContain(leafA.id);
    const transfer = await clientA.transfers.send({
      receiver: receiverAddress,
      amountSats: 100_000,
    });
    console.log("A sent transfer:", transfer.id, "status:", transfer.status);

    const [pendingTransfer] = await pendingUntil(clientB, Date.now() + CLAIM_DEADLINE_MS);
    const claimedByB = await clientB.transfers.claim(requiredTransfer(pendingTransfer));
    expect(claimedByB.length).toBeGreaterThan(0);
    console.log("B claimed leaves:", claimedByB.map((l) => `${l.id}=${l.valueSats}`).join(", "));
    await expect(clientB.balance()).resolves.toBe(100_000);
    await expect(clientA.balance()).resolves.toBe(0);

    // A second claim of the same transfer hits the SO's already_exists path and
    // recovers the same leaves instead of failing.
    const recovered = await clientB.transfers.claim(requiredTransfer(pendingTransfer));
    expect(recovered.map((l) => l.id).toSorted()).toStrictEqual(
      claimedByB.map((l) => l.id).toSorted(),
    );
    console.log("B recovered leaves on re-claim:", recovered.map((l) => l.id).join(", "));

    // B's store holds the claimed exit chain; replaying it yields the same
    // transactions the SO query path returns.
    const leafId = requiredTransfer(claimedByB[0]).id;
    const claimed = await storeB.exitChains();
    const storedChains = claimed.filter((chain) => chain.leafId === leafId);
    expect(storedChains).toHaveLength(1);
    const queried = await clientB.withdrawals.unilateralExit([leafId]);
    expect(exitTransactions(storedChains).map((tx) => tx.txid)).toStrictEqual(
      queried.map((tx) => tx.txid),
    );

    // Round trip: B sends the leaf back to A's identity key.
    const leavesB = await leavesUntil(clientB, Date.now() + CLAIM_DEADLINE_MS);
    expect(leavesB.map((l) => l.id)).toContain(claimedByB[0]?.id);
    const transferBack = await clientB.transfers.send({
      receiver: await signerA.identityPublicKey(),
      amountSats: 100_000,
    });
    console.log("B sent transfer back:", transferBack.id);

    const reclaimedByA = await claimPendingUntil(clientA, Date.now() + CLAIM_DEADLINE_MS);
    expect(reclaimedByA.length).toBeGreaterThan(0);
    console.log(
      "A reclaimed leaves:",
      reclaimedByA.map((l) => `${l.id}=${l.valueSats}`).join(", "),
    );
    await expect(clientA.balance()).resolves.toBe(100_000);
    await expect(clientB.balance()).resolves.toBe(0);

    // Send removed B's chain; A's claim stored A's leaf chain.
    const storeBChains = await storeB.exitChains();
    expect(storeBChains.map((chain) => chain.leafId)).not.toContain(leafId);
    const reclaimedId = requiredTransfer(reclaimedByA[0]).id;
    const storeAChains = await storeA.exitChains();
    expect(storeAChains.map((chain) => chain.leafId)).toContain(reclaimedId);

    clientA.close();
    clientB.close();
    signerA.dispose();
    signerB.dispose();
  }, 300_000);
});

/** Deposit `amountBtc` to a fresh single-use address and claim the leaf it produces. */
async function fundAndClaim(
  client: Awaited<ReturnType<typeof localWallet>>["client"],
  amountBtc: number,
  minerAddress: string,
) {
  const address = await client.deposits.newAddress();
  const txid = (await bitcoinRpc("sendtoaddress", [address, amountBtc])) as string;
  await bitcoinRpc("generatetoaddress", [1, minerAddress]);
  const rawHex = (await bitcoinRpc("getrawtransaction", [txid])) as string;
  return claimUntilAccepted(client, hexToBytes(rawHex), Date.now() + CLAIM_DEADLINE_MS);
}

describe.skipIf(process.env["SPARK_E2E_LOCAL"] !== "1")("local SO multi-receiver send", () => {
  test("A sends to B and C in one sendMany; both claim their edge", async () => {
    const { signer: signerA, client: clientA } = await localWallet(randomBytes(32));
    const { signer: signerB, client: clientB } = await localWallet(randomBytes(32));
    const { signer: signerC, client: clientC } = await localWallet(randomBytes(32));
    const minerAddress = (await bitcoinRpc("getnewaddress", [])) as string;

    // Two deposits → two leaves, so each receiver gets an exact leaf group (no SSP locally).
    const leaf100k = await fundAndClaim(clientA, 0.001, minerAddress);
    const leaf50k = await fundAndClaim(clientA, 0.0005, minerAddress);
    console.log("A claimed leaves:", leaf100k.id, leaf50k.id);

    const transfer = await clientA.transfers.sendMany({
      receivers: [
        { receiver: await signerB.identityPublicKey(), amountSats: 100_000 },
        { receiver: await signerC.identityPublicKey(), amountSats: 50_000 },
      ],
    });
    console.log("A sent multi-receiver transfer:", transfer.id, "status:", transfer.status);
    console.log(
      "receivers:",
      transfer.receivers.map((receiver) => `${receiver.id}=${receiver.amountSats}`).join(", "),
    );
    await expect(clientA.balance()).resolves.toBe(0);

    const [pendingB] = await pendingUntil(clientB, Date.now() + CLAIM_DEADLINE_MS);
    const claimedByB = await clientB.transfers.claim(requiredTransfer(pendingB));
    expect(claimedByB.map((leaf) => leaf.valueSats)).toStrictEqual([100_000]);
    const [pendingC] = await pendingUntil(clientC, Date.now() + CLAIM_DEADLINE_MS);
    const claimedByC = await clientC.transfers.claim(requiredTransfer(pendingC));
    expect(claimedByC.map((leaf) => leaf.valueSats)).toStrictEqual([50_000]);
    await expect(clientB.balance()).resolves.toBe(100_000);
    await expect(clientC.balance()).resolves.toBe(50_000);
    console.log(
      "B claimed:",
      claimedByB.map((leaf) => leaf.id).join(", "),
      "— C claimed:",
      claimedByC.map((leaf) => leaf.id).join(", "),
    );

    clientA.close();
    clientB.close();
    clientC.close();
    signerA.dispose();
    signerB.dispose();
    signerC.dispose();
  }, 300_000);
});
