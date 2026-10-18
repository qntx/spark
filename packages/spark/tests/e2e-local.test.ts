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

async function bitcoinRpc(method: string, params: ReadonlyArray<unknown>): Promise<unknown> {
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
  const body = (await response.json()) as {
    result: unknown;
    error: { message: string } | null;
  };
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

    const leaves = await client.leaves();
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
});
