import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { randomBytes, hexToBytes, bytesToHex } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { Agent, fetch as undiciFetch } from "undici";
import { describe, expect, test } from "vite-plus/test";

import { createSparkClient } from "../src/client/index.ts";
import { encodeSparkAddress } from "../src/core/address.ts";
import { getTimelockFromSequence } from "../src/core/bitcoin/index.ts";
import type { SparkOperatorConfig } from "../src/core/network.ts";
import { buildCpfpChild, createMemorySparkStore, exitTransactions } from "../src/index.ts";
import type { SparkStore } from "../src/index.ts";
import { createSparkSigner, sparkAccountKey } from "../src/signer/index.ts";
import { loadWasmBackend } from "./support/backend.ts";

// Local e2e against the upstream docker-compose stack (bun scripts/spark-local.ts up).
// Opt-in: SPARK_E2E_LOCAL=1. Operator identity keys derive from the committed
// docker/keys/operator_{0,1,2}.key files (they equal upstream LOCAL_OPERATOR_PUBLIC_KEYS).
const CERT_DIR = process.env["SPARK_LOCAL_CERT_DIR"] ?? join(tmpdir(), "spark-local-certs");
const BITCOIND_RPC =
  process.env["BITCOIND_RPC"] ?? "http://testutil:testutilpassword@localhost:8332";

const LOCAL_OPERATORS: SparkOperatorConfig[] = [
  {
    id: 0,
    identifier: "0000000000000000000000000000000000000000000000000000000000000001",
    address: "https://localhost:8535",
    identityPublicKey: hexToBytes(
      "0322ca18fc489ae25418a0e768273c2c61cabb823edfb14feb891e9bec62016510",
    ),
  },
  {
    id: 1,
    identifier: "0000000000000000000000000000000000000000000000000000000000000002",
    address: "https://localhost:8536",
    identityPublicKey: hexToBytes(
      "0341727a6c41b168f07eb50865ab8c397a53c7eef628ac1020956b705e43b6cb27",
    ),
  },
  {
    id: 2,
    identifier: "0000000000000000000000000000000000000000000000000000000000000003",
    address: "https://localhost:8537",
    identityPublicKey: hexToBytes(
      "0305ab8d485cc752394de4981f8a5ae004f2becfea6f432c9a59d5022d8764f0a6",
    ),
  },
];

// The SOs present self-signed per-operator certs exported from the tls-certs volume; trust
// exactly those certs for this test's fetch only. Built lazily so importing this file without
// SPARK_E2E_LOCAL never touches the cert dir.
function localFetch() {
  const agent = new Agent({
    connect: {
      ca: ["server_0.crt", "server_1.crt", "server_2.crt"].map((name) =>
        readFileSync(join(CERT_DIR, name), "utf8"),
      ),
    },
  });
  return async (input: string | URL | Request, init?: RequestInit): Promise<Response> =>
    undiciFetch(input, { ...init, dispatcher: agent });
}

async function bitcoinRpcRaw(
  method: string,
  params: ReadonlyArray<unknown>,
): Promise<{ result: unknown; error: { message: string } | null }> {
  const url = new URL(BITCOIND_RPC);
  const credentials = url.username === "" ? "" : `Basic ${btoa(`${url.username}:${url.password}`)}`;
  url.username = "";
  url.password = "";
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(credentials === "" ? {} : { authorization: credentials }),
    },
    body: JSON.stringify({ jsonrpc: "1.0", id: "e2e", method, params }),
  });
  return (await response.json()) as {
    result: unknown;
    error: { message: string } | null;
  };
}

async function bitcoinRpc(method: string, params: ReadonlyArray<unknown>): Promise<unknown> {
  const body = await bitcoinRpcRaw(method, params);
  if (body.error !== null) {
    throw new Error(`bitcoind ${method}: ${body.error.message}`);
  }
  return body.result;
}

const sleep = async (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

const CLAIM_DEADLINE_MS = 120_000;

/** Polls `claimPending` until at least one transfer is claimed (bounded). */
async function claimPendingUntil(client: ReturnType<typeof createSparkClient>, deadline: number) {
  const claimed = await client.transfers.claimPending();
  if (claimed.length > 0 || Date.now() > deadline) {
    return claimed;
  }
  await sleep(3000);
  return claimPendingUntil(client, deadline);
}

function requiredTransfer<T>(value: T | undefined): T {
  if (value === undefined) {
    throw new Error("expected a pending transfer");
  }
  return value;
}

/** Polls `transfers.pending` until at least one incoming transfer is visible (bounded). */
async function pendingUntil(client: ReturnType<typeof createSparkClient>, deadline: number) {
  const pending = await client.transfers.pending();
  if (pending.length > 0 || Date.now() > deadline) {
    return pending;
  }
  await sleep(3000);
  return pendingUntil(client, deadline);
}

/** Polls `leaves` until `leafId` is gone from both the owner query and the store (bounded). */
async function exitChainDroppedUntil(
  client: ReturnType<typeof createSparkClient>,
  store: SparkStore,
  leafId: string,
  deadline: number,
): Promise<boolean> {
  const leaves = await client.leaves();
  const chains = await store.exitChains();
  const dropped =
    !leaves.some((leaf) => leaf.id === leafId) && !chains.some((chain) => chain.leafId === leafId);
  if (dropped || Date.now() > deadline) {
    return dropped;
  }
  await sleep(3000);
  return exitChainDroppedUntil(client, store, leafId, deadline);
}

/** Polls `leaves` until at least one AVAILABLE leaf is visible (bounded). */
async function leavesUntil(client: ReturnType<typeof createSparkClient>, deadline: number) {
  const leaves = await client.leaves();
  if (leaves.length > 0 || Date.now() > deadline) {
    return leaves;
  }
  await sleep(3000);
  return leavesUntil(client, deadline);
}

/** Polls `claim` until the SO accepts the deposit (bounded). */
async function claimUntilAccepted(
  client: ReturnType<typeof createSparkClient>,
  transaction: Uint8Array,
  deadline: number,
) {
  try {
    return await client.deposits.claim({ transaction });
  } catch (error) {
    if (Date.now() > deadline) {
      throw error;
    }
    console.log("claim not accepted yet:", (error as Error).message.split("\n")[0]);
    await sleep(3000);
    return claimUntilAccepted(client, transaction, deadline);
  }
}

function refundTimelock(leaf: { refundTx: Uint8Array }): number {
  const { sequence } = Transaction.fromRaw(leaf.refundTx, {
    allowUnknownOutputs: true,
  }).getInput(0);
  if (sequence === undefined) {
    throw new Error("refund tx has no sequence");
  }
  return getTimelockFromSequence(sequence);
}

type PingPongState = {
  sender: ReturnType<typeof createSparkClient>;
  receiver: ReturnType<typeof createSparkClient>;
  senderIdentity: Uint8Array;
  receiverIdentity: Uint8Array;
  previousTimelock: number;
  previousNodeTx: Uint8Array;
  renewedRound: number;
  renewedTimelock: number;
};

// The refund timelock starts at 2000 and loses 100 per send; the send that would
// push it below 200 renews the leaf first. Recursion keeps the rounds sequential.
async function pingPongUntilRenewed(state: PingPongState, sendsLeft: number, round: number) {
  if (sendsLeft === 0) {
    return state;
  }
  await state.sender.transfers.send({
    receiver: state.receiverIdentity,
    amountSats: 100_000,
  });
  const claimed = await claimPendingUntil(state.receiver, Date.now() + CLAIM_DEADLINE_MS);
  const [claimedLeaf] = claimed;
  if (claimedLeaf === undefined) {
    throw new Error(`send ${round}: receiver claimed nothing`);
  }
  const timelock = refundTimelock(claimedLeaf);
  const renewedNow =
    timelock > state.previousTimelock ||
    bytesToHex(claimedLeaf.nodeTx) !== bytesToHex(state.previousNodeTx);
  console.log(
    renewedNow && state.renewedRound === 0
      ? `send ${round}: renewed, refund timelock ${state.previousTimelock} -> ${timelock}`
      : `send ${round}: refund timelock ${timelock}`,
  );
  await leavesUntil(state.receiver, Date.now() + CLAIM_DEADLINE_MS);
  return pingPongUntilRenewed(
    {
      sender: state.receiver,
      receiver: state.sender,
      senderIdentity: state.receiverIdentity,
      receiverIdentity: state.senderIdentity,
      previousTimelock: timelock,
      previousNodeTx: claimedLeaf.nodeTx,
      renewedRound: renewedNow && state.renewedRound === 0 ? round : state.renewedRound,
      renewedTimelock: renewedNow && state.renewedRound === 0 ? timelock : state.renewedTimelock,
    },
    sendsLeft - 1,
    round + 1,
  );
}

type FundedUtxo = {
  readonly txid: string;
  readonly vout: number;
  readonly script: Uint8Array;
  readonly amountSats: number;
};

/** Sends `amountBtc` to a fresh P2WPKH wallet address; caller must mine a block. */
async function fundP2wpkh(amountBtc: number): Promise<{ txid: string; address: string }> {
  const address = (await bitcoinRpc("getnewaddress", ["", "bech32"])) as string;
  const txid = (await bitcoinRpc("sendtoaddress", [address, amountBtc])) as string;
  return { txid, address };
}

async function utxoFor(txid: string, address: string): Promise<FundedUtxo> {
  const verbose = (await bitcoinRpc("getrawtransaction", [txid, true])) as {
    vout: ReadonlyArray<{
      n: number;
      value: number;
      scriptPubKey: { hex: string; address?: string };
    }>;
  };
  const out = verbose.vout.find((o) => o.scriptPubKey.address === address);
  if (out === undefined) {
    throw new Error(`no output to ${address} in ${txid}`);
  }
  return {
    txid,
    vout: out.n,
    script: hexToBytes(out.scriptPubKey.hex),
    amountSats: Math.round(out.value * 1e8),
  };
}

/** Change scriptPubKey of a fresh bech32 wallet address. */
async function changeScript(): Promise<Uint8Array> {
  const address = (await bitcoinRpc("getnewaddress", ["", "bech32"])) as string;
  const info = (await bitcoinRpc("getaddressinfo", [address])) as { scriptPubKey: string };
  return hexToBytes(info.scriptPubKey);
}

/**
 * Builds the CPFP child for one exit tx, lets the bitcoind wallet sign the funding input (it also
 * finalizes the P2A anchor with an empty witness), and submits [parent, child] as a package.
 * Returns the RPC result verbatim.
 */
async function broadcastExitPackage(
  exitTx: { transaction: Uint8Array; txid: string },
  funding: FundedUtxo,
) {
  const child = buildCpfpChild({
    parent: exitTx.transaction,
    funding: [
      {
        txid: funding.txid,
        vout: funding.vout,
        script: funding.script,
        amountSats: funding.amountSats,
        signedInputVbytes: 68,
      },
    ],
    changeScript: await changeScript(),
    feeRateSatPerVbyte: 2,
  });
  const psbtB64 = Buffer.from(child.psbt).toString("base64");
  const processed = (await bitcoinRpc("walletprocesspsbt", [psbtB64])) as {
    psbt: string;
    complete: boolean;
  };
  console.log(`walletprocesspsbt complete=${processed.complete}`);
  const finalized = (await bitcoinRpc("finalizepsbt", [processed.psbt])) as {
    complete: boolean;
    hex?: string;
    psbt?: string;
  };
  if (finalized.hex === undefined) {
    throw new Error(`finalizepsbt incomplete: ${JSON.stringify(finalized)}`);
  }
  const submission = await bitcoinRpcRaw("submitpackage", [
    [bytesToHex(exitTx.transaction), finalized.hex],
  ]);
  console.log(`submitpackage ${exitTx.txid}:`, JSON.stringify(submission));
  return submission;
}

// generatetoaddress in chunks: a multi-thousand-block call outlives the
// undici headers timeout.
async function mine(blocks: number): Promise<void> {
  const minerAddress = (await bitcoinRpc("getnewaddress", [])) as string;
  let left = blocks;
  while (left > 0) {
    const batch = Math.min(left, 200);
    // oxlint-disable-next-line no-await-in-loop -- block batches must be sequential
    await bitcoinRpc("generatetoaddress", [batch, minerAddress]);
    left -= batch;
  }
}

async function confirmations(txid: string): Promise<number> {
  const verbose = (await bitcoinRpc("getrawtransaction", [txid, true])) as {
    confirmations?: number;
  };
  return verbose.confirmations ?? 0;
}

/**
 * Mines until `txid` shows `target` confirmations. The background miner adds a block every ~30s, so
 * a fixed block count drifts — polling the confirmation count is the only way to land exactly on a
 * BIP68 boundary.
 */
async function mineUntilConfirmations(txid: string, target: number): Promise<void> {
  const confs = await confirmations(txid);
  if (confs >= target) {
    return;
  }
  await mine(Math.min(target - confs, 200));
  return mineUntilConfirmations(txid, target);
}

describe.skipIf(process.env["SPARK_E2E_LOCAL"] !== "1")("local SO deposit flow", () => {
  test("newAddress → on-chain deposit → claim → leaf visible; second claim fails", async () => {
    const crypto = await loadWasmBackend();
    const signer = createSparkSigner({
      crypto,
      accountKey: sparkAccountKey(randomBytes(32), "regtest"),
      network: "regtest",
      random: (length: number) => randomBytes(length),
    });
    const client = createSparkClient({
      network: "regtest",
      signer,
      fetch: localFetch(),
      operators: LOCAL_OPERATORS,
    });

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
    const crypto = await loadWasmBackend();
    const signerA = createSparkSigner({
      crypto,
      accountKey: sparkAccountKey(randomBytes(32), "regtest"),
      network: "regtest",
      random: (length: number) => randomBytes(length),
    });
    const signerB = createSparkSigner({
      crypto,
      accountKey: sparkAccountKey(randomBytes(32), "regtest"),
      network: "regtest",
      random: (length: number) => randomBytes(length),
    });
    const storeA = createMemorySparkStore();
    const storeB = createMemorySparkStore();
    const clientA = createSparkClient({
      network: "regtest",
      signer: signerA,
      fetch: localFetch(),
      operators: LOCAL_OPERATORS,
      store: storeA,
    });
    const clientB = createSparkClient({
      network: "regtest",
      signer: signerB,
      fetch: localFetch(),
      operators: LOCAL_OPERATORS,
      store: storeB,
    });

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

  test("ping-pong sends renew the leaf timelock once it drops below 200", async () => {
    const crypto = await loadWasmBackend();
    const signerA = createSparkSigner({
      crypto,
      accountKey: sparkAccountKey(randomBytes(32), "regtest"),
      network: "regtest",
      random: (length: number) => randomBytes(length),
    });
    const signerB = createSparkSigner({
      crypto,
      accountKey: sparkAccountKey(randomBytes(32), "regtest"),
      network: "regtest",
      random: (length: number) => randomBytes(length),
    });
    const clientA = createSparkClient({
      network: "regtest",
      signer: signerA,
      fetch: localFetch(),
      operators: LOCAL_OPERATORS,
    });
    const clientB = createSparkClient({
      network: "regtest",
      signer: signerB,
      fetch: localFetch(),
      operators: LOCAL_OPERATORS,
    });

    const address = await clientA.deposits.newAddress();
    const txid = (await bitcoinRpc("sendtoaddress", [address, 0.001])) as string;
    const minerAddress = (await bitcoinRpc("getnewaddress", [])) as string;
    await bitcoinRpc("generatetoaddress", [1, minerAddress]);
    const rawHex = (await bitcoinRpc("getrawtransaction", [txid])) as string;
    const leafA = await claimUntilAccepted(
      clientA,
      hexToBytes(rawHex),
      Date.now() + CLAIM_DEADLINE_MS,
    );
    await leavesUntil(clientA, Date.now() + CLAIM_DEADLINE_MS);

    // 22 sends cover the ~19 sends needed to exhaust a 2000-timelock refund.
    const state = await pingPongUntilRenewed(
      {
        sender: clientA,
        receiver: clientB,
        senderIdentity: await signerA.identityPublicKey(),
        receiverIdentity: await signerB.identityPublicKey(),
        previousTimelock: refundTimelock(leafA),
        previousNodeTx: leafA.nodeTx,
        renewedRound: 0,
        renewedTimelock: 0,
      },
      22,
      1,
    );

    // A 2000-timelock refund drops by 100 per send, so renewal must fire on
    // send 20 (timelock 100 -> renewed 2000 -> decremented to 1900 by the send).
    expect(state.renewedRound).toBe(20);
    expect(state.renewedTimelock).toBe(1900);
    const finalLeaves = await leavesUntil(state.sender, Date.now() + CLAIM_DEADLINE_MS);
    expect(finalLeaves.length).toBeGreaterThan(0);
    await expect(state.sender.balance()).resolves.toBe(100_000);
    await expect(state.receiver.balance()).resolves.toBe(0);
    console.log("final holder after 22 sends:", await state.sender.balance(), "sats");

    clientA.close();
    clientB.close();
    signerA.dispose();
    signerB.dispose();
  }, 600_000);

  test("exit chains reconcile across two devices sharing a seed", async () => {
    const crypto = await loadWasmBackend();
    const makeWallet = (seed: Uint8Array) => {
      const signer = createSparkSigner({
        crypto,
        accountKey: sparkAccountKey(seed, "regtest"),
        network: "regtest",
        random: (length: number) => randomBytes(length),
      });
      const store = createMemorySparkStore();
      const client = createSparkClient({
        network: "regtest",
        signer,
        fetch: localFetch(),
        operators: LOCAL_OPERATORS,
        store,
      });
      return { signer, store, client };
    };
    const walletA = makeWallet(randomBytes(32));
    const seedB = randomBytes(32);
    const walletB1 = makeWallet(seedB);
    const walletB2 = makeWallet(seedB);

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

  test("unilateral exit: node+refund packages confirm on-chain, refund sweeps to wallet", async () => {
    const crypto = await loadWasmBackend();
    const signerA = createSparkSigner({
      crypto,
      accountKey: sparkAccountKey(randomBytes(32), "regtest"),
      network: "regtest",
      random: (length: number) => randomBytes(length),
    });
    const signerB = createSparkSigner({
      crypto,
      accountKey: sparkAccountKey(randomBytes(32), "regtest"),
      network: "regtest",
      random: (length: number) => randomBytes(length),
    });
    const clientA = createSparkClient({
      network: "regtest",
      signer: signerA,
      fetch: localFetch(),
      operators: LOCAL_OPERATORS,
    });
    const storeB = createMemorySparkStore();
    const clientB = createSparkClient({
      network: "regtest",
      signer: signerB,
      fetch: localFetch(),
      operators: LOCAL_OPERATORS,
      store: storeB,
    });

    // A deposits, sends to B, B claims — B's leaf is the exit chain's tail.
    const address = await clientA.deposits.newAddress();
    const txid = (await bitcoinRpc("sendtoaddress", [address, 0.001])) as string;
    await mine(1);
    const rawHex = (await bitcoinRpc("getrawtransaction", [txid])) as string;
    await claimUntilAccepted(clientA, hexToBytes(rawHex), Date.now() + CLAIM_DEADLINE_MS);
    await leavesUntil(clientA, Date.now() + CLAIM_DEADLINE_MS);
    await clientA.transfers.send({
      receiver: await signerB.identityPublicKey(),
      amountSats: 100_000,
    });
    const claimedByB = await claimPendingUntil(clientB, Date.now() + CLAIM_DEADLINE_MS);
    const leafB = requiredTransfer(claimedByB[0]);
    await leavesUntil(clientB, Date.now() + CLAIM_DEADLINE_MS);
    console.log("exit leaf:", leafB.id);

    // The claim already stored B's exit chain; derive the broadcast set from it
    // instead of issuing a second SO query.
    const stored = await storeB.exitChains();
    const exits = exitTransactions(stored.filter((chain) => chain.leafId === leafB.id));
    expect(exits.map((e) => e.kind)).toStrictEqual(["node", "refund"]);
    const nodeExit = requiredTransfer(exits[0]);
    const refundExit = requiredTransfer(exits[1]);
    console.log(
      `exit txs: node ${nodeExit.txid} (timelock ${nodeExit.relativeTimelock}), refund ${refundExit.txid} (timelock ${refundExit.relativeTimelock})`,
    );

    // Two confirmed wallet UTXOs fund the two CPFP children.
    const fundingTx1 = await fundP2wpkh(0.0006);
    const fundingTx2 = await fundP2wpkh(0.0006);
    await mine(1);
    const utxo1 = await utxoFor(fundingTx1.txid, fundingTx1.address);
    const utxo2 = await utxoFor(fundingTx2.txid, fundingTx2.address);

    // Node tx package.
    const nodeSubmit = await broadcastExitPackage(nodeExit, utxo1);
    expect(JSON.stringify(nodeSubmit)).toContain('"package_msg":"success"');
    await mine(1);
    const nodeConfirmed = (await bitcoinRpc("getrawtransaction", [nodeExit.txid, true])) as {
      confirmations?: number;
    };
    expect(nodeConfirmed.confirmations).toBeGreaterThanOrEqual(1);
    console.log("node tx confirmed:", nodeExit.txid);

    // Watchtower observation: does an SO react to the on-chain node tx?
    const mempoolAfterNode = (await bitcoinRpc("getrawmempool", [])) as string[];
    console.log("mempool after node tx:", JSON.stringify(mempoolAfterNode));

    // The refund's BIP68 lock needs relativeTimelock confirmations on its
    // parent (the node tx); stop one block short and show the rejection.
    await mineUntilConfirmations(nodeExit.txid, refundExit.relativeTimelock - 1);
    const early = await broadcastExitPackage(refundExit, utxo2);
    expect(JSON.stringify(early)).toContain("non-BIP68-final");
    console.log("refund one block early rejected as expected");

    // utxo2 was not consumed by the rejected package; reuse it.
    await mine(1);
    const refundSubmit = await broadcastExitPackage(refundExit, utxo2);
    expect(JSON.stringify(refundSubmit)).toContain('"package_msg":"success"');
    await mine(1);
    const refundConfirmed = (await bitcoinRpc("getrawtransaction", [refundExit.txid, true])) as {
      confirmations?: number;
    };
    expect(refundConfirmed.confirmations).toBeGreaterThanOrEqual(1);
    console.log("refund tx confirmed:", refundExit.txid);
    console.log("mempool after refund:", JSON.stringify(await bitcoinRpc("getrawmempool", [])));

    // Sweep the confirmed refund output to a fresh wallet address.
    const sweepAddress = (await bitcoinRpc("getnewaddress", ["", "bech32"])) as string;
    const sweepInfo = (await bitcoinRpc("getaddressinfo", [sweepAddress])) as {
      scriptPubKey: string;
    };
    const sweepTx = await clientB.withdrawals.sweepRefund({
      leafId: leafB.id,
      refundTx: refundExit.transaction,
      destinationScript: hexToBytes(sweepInfo.scriptPubKey),
      feeRateSatPerVbyte: 2,
    });
    const sweepTxid = (await bitcoinRpc("sendrawtransaction", [bytesToHex(sweepTx)])) as string;
    await mine(1);
    const sweepConfirmed = (await bitcoinRpc("getrawtransaction", [sweepTxid, true])) as {
      confirmations?: number;
      vout: ReadonlyArray<{ value: number; scriptPubKey: { address?: string } }>;
    };
    expect(sweepConfirmed.confirmations).toBeGreaterThanOrEqual(1);
    const swept = requiredTransfer(
      sweepConfirmed.vout.find((o) => o.scriptPubKey.address === sweepAddress),
    );
    const sweptSats = Math.round(swept.value * 1e8);
    console.log(`swept ${sweptSats} sats to ${sweepAddress} (refund was ${leafB.valueSats})`);
    expect(sweptSats).toBeGreaterThan(leafB.valueSats - 1000);
    expect(sweptSats).toBeLessThan(leafB.valueSats);

    clientA.close();
    clientB.close();
    signerA.dispose();
    signerB.dispose();
  }, 600_000);
});
