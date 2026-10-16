import { randomBytes } from "@noble/hashes/utils.js";
import { expect, test } from "vite-plus/test";

import { createSparkClient } from "../src/client/index.ts";
import { connectOperator } from "../src/connection/index.ts";
import { sparkNetworkConfig } from "../src/core/network.ts";
import { createTestSigner } from "./support/test-signer.ts";

// Live smoke test against the real operators; opt-in via env since it needs network access.
const signer = createTestSigner(randomBytes(32));

test.skipIf(process.env["SPARK_E2E_MAINNET"] !== "1")(
  "mainnet: authenticate to all operators, empty balance, fee estimate, events",
  async () => {
    const config = sparkNetworkConfig("mainnet");
    const deps = {
      signer,
      fetch: globalThis.fetch,
      random: (length: number) => randomBytes(length),
    };

    const identityPublicKey = await signer.identityPublicKey();
    const responses = await Promise.all(
      config.operators.map(async (operator) => {
        const conn = connectOperator(operator, deps);
        return conn.spark.query_nodes({
          source: { case: "ownerIdentityPubkey", value: identityPublicKey },
          network: 1,
          limit: 50n,
        });
      }),
    );
    for (const response of responses) {
      expect(response.nodes).toStrictEqual({});
    }

    const client = createSparkClient({ network: "mainnet", signer, fetch: globalThis.fetch });
    await expect(client.balance()).resolves.toBe(0);
    await expect(client.leaves()).resolves.toStrictEqual([]);
    await expect(client.transfers.pending()).resolves.toStrictEqual([]);
    const fee = await client.swapFeeEstimate(100_000);
    console.log("e2e swapFeeEstimate (sats):", fee);
    expect(fee).toBeGreaterThanOrEqual(0);

    const abort = new AbortController();
    const iterator = client.events(abort.signal)[Symbol.asyncIterator]();
    const first = await Promise.race([
      iterator.next(),
      new Promise<undefined>((resolve) => setTimeout(() => resolve(undefined), 15_000)),
    ]);
    abort.abort();
    await iterator.return?.();
    console.log("e2e event:", first?.value);
  },
  60_000,
);
