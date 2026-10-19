import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { hexToBytes, randomBytes } from "@noble/hashes/utils.js";

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
