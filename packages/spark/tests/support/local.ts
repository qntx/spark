import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils.js";
import { Transaction } from "@scure/btc-signer";
import { Agent, fetch as undiciFetch } from "undici";

import { createSparkClient } from "../../src/client/index.ts";
import { getTimelockFromSequence } from "../../src/core/bitcoin/index.ts";
import type { SparkOperatorConfig } from "../../src/core/network.ts";
import type { SparkExitChain } from "../../src/exit/store.ts";
import { buildCpfpChild, createMemorySparkStore } from "../../src/index.ts";
import { createSparkSigner, sparkAccountKey } from "../../src/signer/index.ts";
import type { SparkTransfer } from "../../src/transfer/index.ts";
import type { SparkLeaf } from "../../src/tree/index.ts";
import { loadWasmBackend } from "./backend.ts";

// Opt-in: SPARK_E2E_LOCAL=1. Operator identity keys derive from the committed
// docker/keys/operator_{0,1,2}.key files (they equal upstream LOCAL_OPERATOR_PUBLIC_KEYS).
const CERT_DIR = process.env["SPARK_LOCAL_CERT_DIR"] ?? join(tmpdir(), "spark-local-certs");
const BITCOIND_RPC =
  process.env["BITCOIND_RPC"] ?? "http://testutil:testutilpassword@localhost:8332";

export const LOCAL_OPERATORS: SparkOperatorConfig[] = [
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
export function localFetch() {
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

// generatetoaddress batches can stall past the default 300s undici header timeout while
// the operators' chain watchers hammer bitcoind on every fresh block.
const BITCOIND_AGENT = new Agent({ headersTimeout: 600_000, bodyTimeout: 600_000 });

async function bitcoinRpcRaw(
  method: string,
  params: ReadonlyArray<unknown>,
): Promise<{ result: unknown; error: { message: string } | null }> {
  const url = new URL(BITCOIND_RPC);
  const credentials = url.username === "" ? "" : `Basic ${btoa(`${url.username}:${url.password}`)}`;
  url.username = "";
  url.password = "";
  const response = await undiciFetch(url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(credentials === "" ? {} : { authorization: credentials }),
    },
    body: JSON.stringify({ jsonrpc: "1.0", id: "e2e", method, params }),
    dispatcher: BITCOIND_AGENT,
  });
  return (await response.json()) as {
    result: unknown;
    error: { message: string } | null;
  };
}

export async function bitcoinRpc(method: string, params: ReadonlyArray<unknown>): Promise<unknown> {
  const body = await bitcoinRpcRaw(method, params);
  if (body.error !== null) {
    throw new Error(`bitcoind ${method}: ${body.error.message}`);
  }
  return body.result;
}

export const sleep = async (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

export const CLAIM_DEADLINE_MS = 120_000;

export type LocalWallet = {
  readonly signer: ReturnType<typeof createSparkSigner>;
  readonly store: ReturnType<typeof createMemorySparkStore>;
  readonly client: ReturnType<typeof createSparkClient>;
};

/** Signer + client + memory store over one seed (two calls with the same seed = two devices). */
export async function localWallet(seed: Uint8Array): Promise<LocalWallet> {
  const crypto = await loadWasmBackend();
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
}

/** Polls `claimPending` until at least one transfer is claimed (bounded). */
export async function claimPendingUntil(
  client: ReturnType<typeof createSparkClient>,
  deadline: number,
): Promise<ReadonlyArray<SparkLeaf>> {
  const claimed = await client.transfers.claimPending();
  if (claimed.length > 0 || Date.now() > deadline) {
    return claimed;
  }
  await sleep(3000);
  return claimPendingUntil(client, deadline);
}

export function requiredTransfer<T>(value: T | undefined): T {
  if (value === undefined) {
    throw new Error("expected a pending transfer");
  }
  return value;
}

/** Polls `transfers.pending` until at least one incoming transfer is visible (bounded). */
export async function pendingUntil(
  client: ReturnType<typeof createSparkClient>,
  deadline: number,
): Promise<ReadonlyArray<SparkTransfer>> {
  const pending = await client.transfers.pending();
  if (pending.length > 0 || Date.now() > deadline) {
    return pending;
  }
  await sleep(3000);
  return pendingUntil(client, deadline);
}

/** Polls `leaves` until `leafId` is gone from both the owner query and the store (bounded). */
export async function exitChainDroppedUntil(
  client: ReturnType<typeof createSparkClient>,
  store: ReturnType<typeof createMemorySparkStore>,
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
export async function leavesUntil(
  client: ReturnType<typeof createSparkClient>,
  deadline: number,
): Promise<ReadonlyArray<SparkLeaf>> {
  const leaves = await client.leaves();
  if (leaves.length > 0 || Date.now() > deadline) {
    return leaves;
  }
  await sleep(3000);
  return leavesUntil(client, deadline);
}

/**
 * Polls `leaves` until at least `count` AVAILABLE leaves are spendable (bounded). A just-claimed
 * leaf is spendable only once every operator reports it, so sends must wait for the full count.
 */
export async function leavesUntilCount(
  client: ReturnType<typeof createSparkClient>,
  count: number,
  deadline: number,
): Promise<ReadonlyArray<SparkLeaf>> {
  const leaves = await client.leaves();
  if (leaves.length >= count || Date.now() > deadline) {
    return leaves;
  }
  await sleep(3000);
  return leavesUntilCount(client, count, deadline);
}

/** Polls `transfers.pending` until at least `count` incoming transfers are visible (bounded). */
export async function pendingUntilCount(
  client: ReturnType<typeof createSparkClient>,
  count: number,
  deadline: number,
): Promise<ReadonlyArray<SparkTransfer>> {
  const pending = await client.transfers.pending();
  if (pending.length >= count || Date.now() > deadline) {
    return pending;
  }
  await sleep(3000);
  return pendingUntilCount(client, count, deadline);
}

/** Polls `claim` until the SO accepts the deposit (bounded). */
export async function claimUntilAccepted(
  client: ReturnType<typeof createSparkClient>,
  transaction: Uint8Array,
  deadline: number,
): Promise<SparkLeaf> {
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

export async function claimManyUntilAccepted(
  client: ReturnType<typeof createSparkClient>,
  transactions: ReadonlyArray<Uint8Array>,
  deadline: number,
): Promise<SparkLeaf> {
  try {
    return await client.deposits.claimMany({
      outputs: transactions.map((transaction) => ({ transaction })),
    });
  } catch (error) {
    if (Date.now() > deadline) {
      throw error;
    }
    console.log("claimMany not accepted yet:", (error as Error).message.split("\n")[0]);
    await sleep(3000);
    return claimManyUntilAccepted(client, transactions, deadline);
  }
}

export type FundedUtxo = {
  readonly txid: string;
  readonly vout: number;
  readonly script: Uint8Array;
  readonly amountSats: number;
};

/** Sends `amountBtc` to a fresh P2WPKH wallet address; caller must mine a block. */
export async function fundP2wpkh(amountBtc: number): Promise<{ txid: string; address: string }> {
  const address = (await bitcoinRpc("getnewaddress", ["", "bech32"])) as string;
  const txid = (await bitcoinRpc("sendtoaddress", [address, amountBtc])) as string;
  return { txid, address };
}

export async function utxoFor(txid: string, address: string): Promise<FundedUtxo> {
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
export async function changeScript(): Promise<Uint8Array> {
  const address = (await bitcoinRpc("getnewaddress", ["", "bech32"])) as string;
  const info = (await bitcoinRpc("getaddressinfo", [address])) as { scriptPubKey: string };
  return hexToBytes(info.scriptPubKey);
}

/**
 * Builds the CPFP child for one exit tx, lets the bitcoind wallet sign the funding input (it also
 * finalizes the P2A anchor with an empty witness), and submits [parent, child] as a package.
 * Returns the RPC result verbatim.
 */
export async function broadcastExitPackage(
  exitTx: { transaction: Uint8Array; txid: string },
  funding: FundedUtxo,
): Promise<{ result: unknown; error: { message: string } | null }> {
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

/** Mines one block carrying `txsHex` directly — zero-fee node txs cannot relay, only mine. */
export async function generateBlockWith(txsHex: ReadonlyArray<string>): Promise<void> {
  const address = (await bitcoinRpc("getnewaddress", [])) as string;
  await bitcoinRpc("generateblock", [address, [...txsHex]]);
}

// generatetoaddress in chunks: a multi-thousand-block call outlives the
// undici headers timeout.
export async function mine(blocks: number): Promise<void> {
  const minerAddress = (await bitcoinRpc("getnewaddress", [])) as string;
  let left = blocks;
  while (left > 0) {
    const batch = Math.min(left, 200);
    // oxlint-disable-next-line no-await-in-loop -- block batches must be sequential
    await bitcoinRpc("generatetoaddress", [batch, minerAddress]);
    left -= batch;
  }
}

export async function confirmations(txid: string): Promise<number> {
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
export async function mineUntilConfirmations(txid: string, target: number): Promise<void> {
  const confs = await confirmations(txid);
  if (confs >= target) {
    return;
  }
  await mine(Math.min(target - confs, 200));
  return mineUntilConfirmations(txid, target);
}

/** Confirmations for `txid`, or -1 while bitcoind has never seen the transaction. */
export async function knownConfirmations(txid: string): Promise<number> {
  try {
    return await confirmations(txid);
  } catch {
    return -1;
  }
}

/**
 * Mines `batch` blocks per round until `txid` confirms — the SO's chain watcher only acts on a new
 * block, so waiting for a watchtower broadcast means mining. Throws after `rounds` rounds.
 */
export async function awaitWatchtowerBroadcast(
  txid: string,
  batch: number,
  rounds: number,
): Promise<void> {
  if ((await knownConfirmations(txid)) >= 1) {
    return;
  }
  if (rounds <= 0) {
    throw new Error(`${txid} was never broadcast`);
  }
  await mine(batch);
  return awaitWatchtowerBroadcast(txid, batch, rounds - 1);
}

export type LocalTestWallet = LocalWallet & { readonly identity: Uint8Array };

/** `localWallet` plus the identity public key, the form two-wallet tests pass around. */
export async function localTestWallet(seed: Uint8Array): Promise<LocalTestWallet> {
  const wallet = await localWallet(seed);
  return { ...wallet, identity: await wallet.signer.identityPublicKey() };
}

export function required<T>(value: T | undefined, what: string): T {
  if (value === undefined) {
    throw new Error(what);
  }
  return value;
}

/** The BIP-68 timelock (blocks) on a leaf's current refund transaction. */
export function refundTimelock(leaf: { refundTx: Uint8Array }): number {
  const { sequence } = Transaction.fromRaw(leaf.refundTx, {
    allowUnknownOutputs: true,
  }).getInput(0);
  if (sequence === undefined) {
    throw new Error("refund tx has no sequence");
  }
  return getTimelockFromSequence(sequence);
}

/** Sends `amountSats` and waits for the receiver to claim and report the leaf. */
export async function transferWholeLeaf(
  from: LocalTestWallet,
  to: LocalTestWallet,
  amountSats: number,
): Promise<SparkLeaf> {
  await from.client.transfers.send({ receiver: to.identity, amountSats });
  const claimed = await claimPendingUntil(to.client, Date.now() + CLAIM_DEADLINE_MS);
  const leaf = required(claimed[0], "receiver claimed nothing");
  await leavesUntil(to.client, Date.now() + CLAIM_DEADLINE_MS);
  return leaf;
}

export type PingPongResult = {
  readonly holder: LocalTestWallet;
  readonly leaf: SparkLeaf;
  readonly renewals: number;
};

/**
 * Ping-pongs `amountSats` between two wallets until the leaf's refund timelock has reset `needed`
 * times — each reset is a zero-timelock renewal (a split node plus a fresh leaf). `refundBelow`
 * keeps sending afterwards until the timelock walks down to it (fewer blocks to mine in tests); the
 * next send past ~100 renews again, so stay well above 100. Throws if `maxSends` runs out.
 */
export async function pingPongUntilRenewed(
  from: LocalTestWallet,
  to: LocalTestWallet,
  leaf: SparkLeaf,
  options: {
    readonly needed: number;
    readonly amountSats: number;
    readonly maxSends?: number;
    readonly refundBelow?: number;
  },
): Promise<PingPongResult> {
  const { needed, amountSats, maxSends = 60, refundBelow } = options;
  let holder = from;
  let other = to;
  let previousTimelock = refundTimelock(leaf);
  let renewals = 0;
  let current = leaf;
  for (let i = 1; i <= maxSends; i++) {
    const settled =
      renewals >= needed && (refundBelow === undefined || previousTimelock <= refundBelow);
    if (settled) {
      return { holder, leaf: current, renewals };
    }
    // oxlint-disable-next-line no-await-in-loop -- sends must stay sequential
    current = await transferWholeLeaf(holder, other, amountSats);
    [holder, other] = [other, holder];
    const timelock = refundTimelock(current);
    if (timelock > previousTimelock) {
      renewals += 1;
      console.log(`send ${i}: renewed (${renewals}), refund timelock ${timelock}`);
    }
    previousTimelock = timelock;
  }
  throw new Error(`only ${renewals}/${needed} renewals after ${maxSends} sends`);
}

/** The stored exit chain for `leafId`. */
export function storedExitChain(
  chains: ReadonlyArray<SparkExitChain>,
  leafId: string,
): SparkExitChain {
  const chain = chains.find((entry) => entry.leafId === leafId);
  if (chain === undefined) {
    throw new Error(`no exit chain stored for ${leafId}`);
  }
  return chain;
}

/** The exit chain's parent and grandparent — the two nodes above the leaf. */
export function chainAncestors(chain: SparkExitChain): {
  readonly parent: SparkExitChain["nodes"][number];
  readonly grandparent: SparkExitChain["nodes"][number];
} {
  const parent = required(chain.nodes.at(-2), "exit chain is missing the parent node");
  const grandparent = required(chain.nodes.at(-3), "exit chain is missing the grandparent node");
  return { parent, grandparent };
}

/** A fresh bitcoind-wallet address and its scriptPubKey — a sweep destination the test controls. */
export async function destinationFor(): Promise<{ address: string; script: Uint8Array }> {
  const address = (await bitcoinRpc("getnewaddress", [])) as string;
  const info = (await bitcoinRpc("getaddressinfo", [address])) as { scriptPubKey: string };
  return { address, script: hexToBytes(info.scriptPubKey) };
}
