import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils.js";

import { createSparkClient } from "../../src/client/index.ts";
import { createMemorySparkStore } from "../../src/exit/store.ts";
import { createSparkSigner, sparkAccountKey } from "../../src/signer/index.ts";
import { loadWasmBackend } from "./backend.ts";

// Opt-in: SPARK_E2E_HOSTED=1. The funded-account seed comes from SPARK_HOSTED_SEED or the
// gitignored .env.hosted at the repo root (mode 600); its value is never logged.
const ENV_HOSTED = fileURLToPath(new URL("../../../../.env.hosted", import.meta.url));

export function hostedSeed(): Uint8Array {
  let hex = process.env["SPARK_HOSTED_SEED"]?.trim();
  if (hex === undefined) {
    let content: string | undefined;
    try {
      content = readFileSync(ENV_HOSTED, "utf8");
    } catch {
      // The env var is the primary source; a missing file is fine.
    }
    for (const line of (content ?? "").split("\n")) {
      const [key, ...rest] = line.split("=");
      if (key?.trim() === "SPARK_HOSTED_SEED") {
        hex = rest.join("=").trim();
      }
    }
  }
  if (hex === undefined || !/^[0-9a-f]{128}$/i.test(hex)) {
    throw new Error(
      "hosted e2e needs SPARK_HOSTED_SEED (64-byte hex) in the environment or .env.hosted",
    );
  }
  return hexToBytes(hex);
}

export type HostedWallet = {
  readonly signer: ReturnType<typeof createSparkSigner>;
  readonly store: ReturnType<typeof createMemorySparkStore>;
  readonly client: ReturnType<typeof createSparkClient>;
};

/** Signer + client + memory store for one account index on the hosted regtest deployment. */
export async function hostedWallet(seed: Uint8Array, account: number): Promise<HostedWallet> {
  const crypto = await loadWasmBackend();
  const signer = createSparkSigner({
    crypto,
    accountKey: sparkAccountKey(seed, "regtest", account),
    network: "regtest",
    random: (length) => randomBytes(length),
  });
  const store = createMemorySparkStore();
  const client = createSparkClient({
    network: "regtest",
    signer,
    fetch: globalThis.fetch,
    store,
  });
  return { signer, store, client };
}

export const sleep = async (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));

// Minimal Esplora client for Lightspark's public regtest mempool — the endpoint and credentials
// the upstream open-source SDK publishes: REGTEST.PROD.ELECTRS and ELECTRS_CREDENTIALS in
// sdks/js/packages/spark-sdk/src/services/wallet-config.ts.
const ESPLORA_URL = "https://regtest-mempool.us-west-2.sparkinfra.net/api";
const ESPLORA_AUTH = `Basic ${btoa("spark-sdk:mCMk1JqlBNtetUNy")}`;

async function esplora(
  path: string,
  options?: { readonly method?: string; readonly body?: string },
): Promise<Response> {
  const response = await globalThis.fetch(`${ESPLORA_URL}${path}`, {
    method: options?.method ?? "GET",
    headers: {
      authorization: ESPLORA_AUTH,
      ...(options?.body === undefined ? {} : { "content-type": "text/plain" }),
    },
    ...(options?.body === undefined ? {} : { body: options.body }),
  });
  if (!response.ok) {
    throw new Error(`esplora ${path}: HTTP ${response.status} ${await response.text()}`);
  }
  return response;
}

/**
 * Terminal send-request statuses per upstream SparkLightningSendRequestStatus. A same-SSP
 * ("internal") lightning payment converges to TRANSFER_COMPLETED rather than
 * LIGHTNING_PAYMENT_SUCCEEDED — upstream's integration test asserts exactly that. The hosted SSP
 * still surfaces payment_preimage on the send request, which sendStatus verifies.
 */
export const SEND_DONE = new Set<string>([
  "TRANSFER_COMPLETED",
  "TRANSFER_FAILED",
  "LIGHTNING_PAYMENT_SUCCEEDED",
  "LIGHTNING_PAYMENT_FAILED",
  "USER_TRANSFER_VALIDATION_FAILED",
  "USER_SWAP_RETURNED",
  "USER_SWAP_RETURN_FAILED",
]);
export const SEND_OK = new Set<string>(["TRANSFER_COMPLETED", "LIGHTNING_PAYMENT_SUCCEEDED"]);

/** Polls `lightning.sendStatus` until the request reaches a terminal status. */
export async function sendStatusUntil(
  client: HostedWallet["client"],
  payment: { requestId: string; paymentHash: Uint8Array },
  deadline: number,
): Promise<{ status: string; outcome: string; preimage?: Uint8Array }> {
  const status = await client.lightning.sendStatus(payment);
  if (SEND_DONE.has(status.status) || Date.now() > deadline) {
    return status;
  }
  await sleep(5000);
  return sendStatusUntil(client, payment, deadline);
}

export type EsploraTxStatus = {
  readonly confirmed: boolean;
  readonly block_height?: number;
  readonly block_time?: number;
};

/** `GET /tx/:txid` — the transaction record, including confirmation status. */
export async function esploraTx(txid: string): Promise<{ status: EsploraTxStatus }> {
  const response = await esplora(`/tx/${txid}`);
  return (await response.json()) as { status: EsploraTxStatus };
}

/** `GET /tx/:txid/hex` — the raw transaction bytes. */
export async function esploraRawTx(txid: string): Promise<Uint8Array> {
  const response = await esplora(`/tx/${txid}/hex`);
  return hexToBytes(await response.text());
}

/** `POST /tx` — broadcasts a signed transaction; returns its txid. */
export async function esploraBroadcast(transaction: Uint8Array): Promise<string> {
  const response = await esplora("/tx", { method: "POST", body: bytesToHex(transaction) });
  return response.text();
}

/** Polls `esploraTx` until `txid` confirms; returns the block height. */
export async function esploraWaitConfirmed(txid: string, deadlineMs: number): Promise<number> {
  // 404s are expected: a transaction can take a while to reach the mempool after broadcast.
  const tx = await esploraTx(txid).catch(() => undefined);
  if (tx?.status.confirmed === true && tx.status.block_height !== undefined) {
    return tx.status.block_height;
  }
  if (Date.now() > deadlineMs) {
    throw new Error(`esplora: ${txid} was not confirmed in time`);
  }
  await sleep(10_000);
  return esploraWaitConfirmed(txid, deadlineMs);
}

export type EsploraUtxo = {
  readonly txid: string;
  readonly vout: number;
  readonly status: EsploraTxStatus;
  readonly value: number;
};

/** `GET /address/:address/utxo` — unspent outputs paying the address (chain + mempool). */
export async function esploraAddressUtxos(address: string): Promise<EsploraUtxo[]> {
  const response = await esplora(`/address/${address}/utxo`);
  return (await response.json()) as EsploraUtxo[];
}

/** `GET /address/:address` — net sats the address received (chain + mempool, funded − spent). */
export async function esploraAddressReceivedSats(address: string): Promise<number> {
  const response = await esplora(`/address/${address}`);
  const info = (await response.json()) as {
    chain_stats: { funded_txo_sum: number; spent_txo_sum: number };
    mempool_stats: { funded_txo_sum: number; spent_txo_sum: number };
  };
  return (
    info.chain_stats.funded_txo_sum -
    info.chain_stats.spent_txo_sum +
    info.mempool_stats.funded_txo_sum -
    info.mempool_stats.spent_txo_sum
  );
}
