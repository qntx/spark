// Environment → typed config. Fails fast on anything missing or malformed and never echoes a
// secret value into an error message.

import type { SparkNetwork } from "@qntx/spark";

export type LnurlServerConfig = {
  readonly domain: string;
  readonly network: SparkNetwork;
  readonly seed: Uint8Array;
  /** Undefined follows the SDK default for the network (mainnet 1, regtest 0). */
  readonly account?: number;
  readonly dbPath: string;
  readonly port: number;
  readonly minSendableMsat: number;
  readonly maxSendableMsat: number;
  readonly commentAllowed: number;
  readonly pollIntervalMs: number;
  /** 32-byte nostr secret key — set enables NIP-57 zap support. */
  readonly zapSecretKey?: Uint8Array;
};

function required(env: Record<string, string | undefined>, name: string): string {
  const value = env[name];
  if (value === undefined || value === "") {
    throw new Error(`missing required environment variable ${name}`);
  }
  return value;
}

function intOption(
  env: Record<string, string | undefined>,
  name: string,
  fallback: number,
  min = 0,
): number {
  const value = env[name];
  if (value === undefined || value === "") {
    return fallback;
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min) {
    throw new Error(`${name} must be an integer >= ${min}, got ${JSON.stringify(value)}`);
  }
  return parsed;
}

function hexBytes(name: string, value: string, bytes: number): Uint8Array {
  if (!/^[0-9a-fA-F]+$/u.test(value) || value.length !== bytes * 2) {
    throw new Error(`${name} must be ${bytes} bytes hex (not logged)`);
  }
  const out = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i += 1) {
    out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function loadConfig(env: Record<string, string | undefined>): LnurlServerConfig {
  const domain = required(env, "LNURL_DOMAIN").toLowerCase();

  const network = required(env, "LNURL_NETWORK");
  if (network !== "mainnet" && network !== "regtest") {
    throw new Error(`LNURL_NETWORK must be "mainnet" or "regtest", got ${JSON.stringify(network)}`);
  }
  const seed = hexBytes("LNURL_SPARK_SEED", required(env, "LNURL_SPARK_SEED"), 64);
  const zapValue = env["LNURL_ZAP_SECRET_KEY"];
  const accountValue = env["LNURL_SPARK_ACCOUNT"];
  return {
    domain,
    network,
    seed,
    ...(accountValue === undefined || accountValue === ""
      ? {}
      : { account: intOption(env, "LNURL_SPARK_ACCOUNT", 0) }),
    dbPath: required(env, "LNURL_DB_PATH"),
    port: intOption(env, "LNURL_PORT", 8080),
    minSendableMsat: intOption(env, "LNURL_MIN_SENDABLE_MSAT", 1000, 1),
    maxSendableMsat: intOption(env, "LNURL_MAX_SENDABLE_MSAT", 100_000_000, 1),
    commentAllowed: intOption(env, "LNURL_COMMENT_ALLOWED", 255, 0),
    pollIntervalMs: intOption(env, "LNURL_POLL_INTERVAL_MS", 5000, 1),
    ...(zapValue === undefined || zapValue === ""
      ? {}
      : { zapSecretKey: hexBytes("LNURL_ZAP_SECRET_KEY", zapValue, 32) }),
  };
}
