import { hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { describe, expect, test } from "vite-plus/test";

import { encodeSparkAddress } from "../src/core/address.ts";
import { exitTransactions } from "../src/index.ts";
import {
  bitcoinRpc,
  CLAIM_DEADLINE_MS,
  claimManyUntilAccepted,
  claimPendingUntil,
  claimUntilAccepted,
  leavesUntil,
  leavesUntilCount,
  localWallet,
  pendingUntil,
  pendingUntilCount,
  requiredTransfer,
  sleep,
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

  test("two UTXOs to one single-use address claim as a single summed leaf", async () => {
    const { signer, client } = await localWallet(randomBytes(32));

    const address = await client.deposits.newAddress();
    console.log("multi-utxo deposit address:", address);
    const txidA = (await bitcoinRpc("sendtoaddress", [address, 0.0004])) as string;
    const txidB = (await bitcoinRpc("sendtoaddress", [address, 0.0006])) as string;
    console.log("deposit txs:", txidA, txidB);
    const minerAddress = (await bitcoinRpc("getnewaddress", [])) as string;
    await bitcoinRpc("generatetoaddress", [2, minerAddress]);
    const transactionA = hexToBytes((await bitcoinRpc("getrawtransaction", [txidA])) as string);
    const transactionB = hexToBytes((await bitcoinRpc("getrawtransaction", [txidB])) as string);

    const leaf = await claimManyUntilAccepted(
      client,
      [transactionA, transactionB],
      Date.now() + CLAIM_DEADLINE_MS,
    );
    expect(leaf.valueSats).toBe(100_000);
    console.log("claimed multi-utxo leaf:", leaf.id, leaf.status, leaf.valueSats, "sats");

    const leaves = await leavesUntil(client, Date.now() + CLAIM_DEADLINE_MS);
    expect(leaves.map((l) => l.id)).toContain(leaf.id);
    await expect(client.balance()).resolves.toBe(100_000);

    const unused = await client.deposits.unused();
    expect(unused.map((u) => u.address)).not.toContain(address);
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
    const claimedByB = await clientB.transfers.claim(requiredTransfer(pendingTransfer).id);
    expect(claimedByB.length).toBeGreaterThan(0);
    console.log("B claimed leaves:", claimedByB.map((l) => `${l.id}=${l.valueSats}`).join(", "));
    await expect(clientB.balance()).resolves.toBe(100_000);
    await expect(clientA.balance()).resolves.toBe(0);

    // A second claim of the same transfer hits the SO's already_exists path and
    // recovers the same leaves instead of failing.
    const recovered = await clientB.transfers.claim(requiredTransfer(pendingTransfer).id);
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

    // A leaf is spendable only once every operator reports it — wait for both.
    const spendable = await leavesUntilCount(clientA, 2, Date.now() + CLAIM_DEADLINE_MS);
    expect(spendable.map((leaf) => leaf.id).toSorted()).toStrictEqual(
      [leaf100k.id, leaf50k.id].toSorted(),
    );

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
    const claimedByB = await clientB.transfers.claim(requiredTransfer(pendingB).id);
    expect(claimedByB.map((leaf) => leaf.valueSats)).toStrictEqual([100_000]);
    const [pendingC] = await pendingUntil(clientC, Date.now() + CLAIM_DEADLINE_MS);
    const claimedByC = await clientC.transfers.claim(requiredTransfer(pendingC).id);
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

type DecodedVout = {
  n: number;
  scriptPubKey: { address?: string; addresses?: string[] };
};

/** The output index paying `address` in a decoded deposit transaction. */
function depositVout(vouts: ReadonlyArray<DecodedVout>, address: string): number {
  const output = vouts.find(
    (entry) =>
      entry.scriptPubKey.address === address ||
      entry.scriptPubKey.addresses?.includes(address) === true,
  );
  if (output === undefined) {
    throw new Error(`deposit tx has no output paying ${address}`);
  }
  return output.n;
}

/** Polls `deposits.claim` for one output of a multi-output deposit tx (bounded). */
async function claimVoutUntilAccepted(
  client: Awaited<ReturnType<typeof localWallet>>["client"],
  transaction: Uint8Array,
  vout: number,
  deadline: number,
): Promise<void> {
  try {
    await client.deposits.claim({ transaction, vout });
  } catch (error) {
    if (Date.now() > deadline) {
      throw error;
    }
    await sleep(3000);
    return claimVoutUntilAccepted(client, transaction, vout, deadline);
  }
}

/**
 * Generates `wave` single-use deposit addresses, pays them all in one sendmany, mines a block and
 * claims each output (which frees its unused-address slot for the next wave).
 */
async function fundWave(
  client: Awaited<ReturnType<typeof localWallet>>["client"],
  minerAddress: string,
  wave: number,
): Promise<void> {
  const addresses: string[] = [];
  for (let batch = 0; batch < wave; batch += 8) {
    // oxlint-disable-next-line no-await-in-loop -- bound the operators' DB connections
    const batchAddresses = await Promise.all(
      Array.from({ length: Math.min(8, wave - batch) }, async () => client.deposits.newAddress()),
    );
    addresses.push(...batchAddresses);
  }
  const txid = (await bitcoinRpc("sendmany", [
    "",
    Object.fromEntries(addresses.map((address) => [address, 0.00002])),
  ])) as string;
  await bitcoinRpc("generatetoaddress", [1, minerAddress]);
  const decoded = (await bitcoinRpc("getrawtransaction", [txid, true])) as {
    vout: ReadonlyArray<DecodedVout>;
  };
  const transaction = hexToBytes((await bitcoinRpc("getrawtransaction", [txid])) as string);
  for (const address of addresses) {
    // oxlint-disable-next-line no-await-in-loop -- claims are sequential under the leaf lock
    await claimVoutUntilAccepted(
      client,
      transaction,
      depositVout(decoded.vout, address),
      Date.now() + CLAIM_DEADLINE_MS,
    );
  }
}

describe.skipIf(process.env["SPARK_E2E_LOCAL"] !== "1")("local SO many-leaf send", () => {
  test("a wallet holding 140 leaves sends its whole balance in one transfer", async () => {
    const { signer: signerA, client: clientA } = await localWallet(randomBytes(32));
    const { signer: signerB, client: clientB } = await localWallet(randomBytes(32));
    const minerAddress = (await bitcoinRpc("getnewaddress", [])) as string;

    // 140 single-use deposits claim into 140 leaves — enough that a whole-balance send's
    // refund jobs (two per leaf) exceed the signer's 256-job per-call cap and must be split
    // into sequential batches. The SO caps unused deposit addresses at 64 per user, so the
    // leaves are funded in 48-leaf waves.
    const LEAF_COUNT = 140;
    for (let claimed = 0; claimed < LEAF_COUNT;) {
      const wave = Math.min(48, LEAF_COUNT - claimed);
      // oxlint-disable-next-line no-await-in-loop -- a wave's claims free the next wave's slots
      await fundWave(clientA, minerAddress, wave);
      claimed += wave;
      console.log("funded wave ending at leaf", claimed, "of", LEAF_COUNT);
    }
    const spendable = await leavesUntilCount(clientA, LEAF_COUNT, Date.now() + CLAIM_DEADLINE_MS);
    expect(spendable).toHaveLength(LEAF_COUNT);
    const balance = await clientA.balance();
    console.log("A holds", spendable.length, "leaves,", balance, "sats");

    const transfer = await clientA.transfers.send({
      receiver: await signerB.identityPublicKey(),
      amountSats: balance,
    });
    console.log("many-leaf send:", transfer.id, transfer.status);

    const claimed = await claimPendingUntil(clientB, Date.now() + CLAIM_DEADLINE_MS);
    expect(claimed).toHaveLength(LEAF_COUNT);
    await expect(clientB.balance()).resolves.toBe(balance);
    await expect(clientA.balance()).resolves.toBe(0);

    clientA.close();
    clientB.close();
    signerA.dispose();
    signerB.dispose();
  }, 900_000);
});

describe.skipIf(process.env["SPARK_E2E_LOCAL"] !== "1")("local SO concurrent sends", () => {
  test("two concurrent sends take disjoint leaves and B claims both", async () => {
    const { signer: signerA, client: clientA } = await localWallet(randomBytes(32));
    const { signer: signerB, client: clientB } = await localWallet(randomBytes(32));
    const minerAddress = (await bitcoinRpc("getnewaddress", [])) as string;

    // Two deposits → two exact leaves; no SSP locally, so each send must pick its own leaf.
    const leaf1 = await fundAndClaim(clientA, 0.0005, minerAddress);
    const leaf2 = await fundAndClaim(clientA, 0.0005, minerAddress);
    console.log("A funded leaves:", leaf1.id, leaf2.id);

    // A leaf is spendable only once every operator reports it — wait for both.
    const spendable = await leavesUntilCount(clientA, 2, Date.now() + CLAIM_DEADLINE_MS);
    expect(spendable.map((leaf) => leaf.id).toSorted()).toStrictEqual(
      [leaf1.id, leaf2.id].toSorted(),
    );

    const receiver = await signerB.identityPublicKey();
    const [first, second] = await Promise.all([
      clientA.transfers.send({ receiver, amountSats: 50_000 }),
      clientA.transfers.send({ receiver, amountSats: 50_000 }),
    ]);
    expect(first.id).not.toBe(second.id);
    const secondLeafIds = new Set(second.leaves.map((leaf) => leaf.leaf.id));
    expect(first.leaves.every((leaf) => !secondLeafIds.has(leaf.leaf.id))).toBe(true);
    console.log("concurrent sends committed:", first.id, second.id);
    await expect(clientA.balance()).resolves.toBe(0);

    const pending = await pendingUntilCount(clientB, 2, Date.now() + CLAIM_DEADLINE_MS);
    expect(pending).toHaveLength(2);
    const claimed = await clientB.transfers.claimPending();
    expect(claimed.leaves.reduce((sum, leaf) => sum + leaf.valueSats, 0)).toBe(100_000);
    await expect(clientB.balance()).resolves.toBe(100_000);
    console.log(
      "B claimed:",
      claimed.leaves.map((leaf) => `${leaf.id}=${leaf.valueSats}`).join(", "),
    );

    clientA.close();
    clientB.close();
    signerA.dispose();
    signerB.dispose();
  }, 300_000);
});
