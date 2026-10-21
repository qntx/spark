// Seed loading and wallet construction for the mainnet trial. The wallet is
// built exactly as a consumer would: loadSparkWasm -> createSparkSigner ->
// createSparkClient with injected fetch/store/random.
import { fileURLToPath } from "node:url";

import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils.js";

import { loadSparkWasm } from "@qntx/spark-wasm";

import { createSparkClient } from "../../src/client/index.ts";
import type { SparkClient } from "../../src/client/index.ts";
import { encodeSparkAddress } from "../../src/core/address.ts";
import type { SparkNetwork } from "../../src/core/network.ts";
import type { SparkStore } from "../../src/exit/store.ts";
import { createSparkSigner, sparkAccountKey } from "../../src/signer/index.ts";
import type { SparkSigner } from "../../src/signer/index.ts";
import { envSeed } from "../env-seed.ts";

const REPO_ROOT = new URL("../../../../", import.meta.url);
const MAINNET_ENV_FILE = fileURLToPath(new URL(".env.mainnet", REPO_ROOT));
const REGTEST_ENV_FILE = fileURLToPath(new URL(".env.hosted", REPO_ROOT));

/**
 * The 64-byte seed for `network`. Mainnet reads SPARK_MAINNET_SEED or the gitignored `.env.mainnet`
 * at the repo root and refuses a group/world-readable file; regtest uses the hosted-suite seed
 * (SPARK_HOSTED_SEED / `.env.hosted`). The value is never logged.
 */
export function trialSeed(network: SparkNetwork): Uint8Array {
  if (network === "mainnet") {
    return envSeed({
      envVar: "SPARK_MAINNET_SEED",
      envFile: MAINNET_ENV_FILE,
      requirePrivateFile: true,
    });
  }
  return envSeed({ envVar: "SPARK_HOSTED_SEED", envFile: REGTEST_ENV_FILE });
}

export type TrialWallet = {
  readonly signer: SparkSigner;
  readonly client: SparkClient;
  /** Bech32m Spark address of this account — the receive/share form of the identity key. */
  readonly sparkAddress: string;
};

/** Signer + client for `account` on `network`, backed by `store` for exit-chain persistence. */
export async function trialWallet(
  seed: Uint8Array,
  network: SparkNetwork,
  account: number,
  store: SparkStore,
): Promise<TrialWallet> {
  const crypto = await loadSparkWasm();
  const signer = createSparkSigner({
    crypto,
    accountKey: sparkAccountKey(seed, network, account),
    network,
    random: (length) => randomBytes(length),
  });
  const client = createSparkClient({
    network,
    signer,
    fetch: globalThis.fetch,
    store,
  });
  return {
    signer,
    client,
    sparkAddress: encodeSparkAddress({
      network,
      identityPublicKey: await signer.identityPublicKey(),
    }),
  };
}

/**
 * The spark address of another account on the same seed — used for `send --to account:N` without
 * building a second client. The account's signer only derives keys; no network calls happen.
 */
export async function accountSparkAddress(
  seed: Uint8Array,
  network: SparkNetwork,
  account: number,
): Promise<string> {
  const crypto = await loadSparkWasm();
  const signer = createSparkSigner({
    crypto,
    accountKey: sparkAccountKey(seed, network, account),
    network,
    random: (length) => randomBytes(length),
  });
  return encodeSparkAddress({
    network,
    identityPublicKey: await signer.identityPublicKey(),
  });
}

/** Raw transaction hex by txid from the public Esplora of `network`. */
export async function esploraTxHex(
  network: SparkNetwork,
  txid: string,
  fetchImpl: typeof globalThis.fetch,
): Promise<Uint8Array> {
  const { url, headers } =
    network === "mainnet"
      ? { url: "https://mempool.space/api", headers: {} }
      : // The upstream-published public regtest mempool credentials (sdks/js wallet-config).
        {
          url: "https://regtest-mempool.us-west-2.sparkinfra.net/api",
          headers: {
            authorization: `Basic ${btoa("spark-sdk:mCMk1JqlBNtetUNy")}`,
          },
        };
  const response = await fetchImpl(`${url}/tx/${txid}/hex`, { headers });
  if (!response.ok) {
    throw new Error(`esplora /tx/${txid}/hex: HTTP ${response.status}`);
  }
  const text = await response.text();
  const hex = text.trim();
  if (!/^([0-9a-f]{2})+$/.test(hex)) {
    throw new Error(`esplora /tx/${txid}/hex: response is not lowercase hex`);
  }
  return hexToBytes(hex);
}

/** IdentityPublicKey as display hex. */
export function identityHex(publicKey: Uint8Array): string {
  return bytesToHex(publicKey);
}
