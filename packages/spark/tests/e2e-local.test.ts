import { readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { randomBytes, hexToBytes } from "@noble/hashes/utils.js";
import { Agent, fetch as undiciFetch } from "undici";
import { describe, expect, test } from "vite-plus/test";

import { createSparkClient } from "../src/client/index.ts";
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
});
