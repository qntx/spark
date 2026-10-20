// Entrypoint: loads the wasm crypto backend, builds the Spark signer/client (the server wallet
// only ever creates invoices), wires the Lightning Address server over the sqlite store, serves
// the HTTP routes, and runs the settlement + zap-receipt poll loop until SIGINT/SIGTERM.

import { randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";

import { serve } from "@hono/node-server";

import { Keys, Pool } from "@qntx/nostr";
import { createMemorySparkStore, createSparkClient } from "@qntx/spark";
import { loadSparkWasm } from "@qntx/spark-wasm";
import { createLightningAddressServer } from "@qntx/spark/server";
import { createSparkSigner, sparkAccountKey } from "@qntx/spark/signer";

import { loadConfig } from "./config.ts";
import { createLnurlApp } from "./http.ts";
import { abortableSleep } from "./sleep.ts";
import { createLnurlStore } from "./store.ts";
import {
  ZAP_RECEIPT_MAX_ATTEMPTS,
  ZAP_RECEIPT_RETENTION_MS,
  publishZapReceipts,
  validateZapRequest,
} from "./zap.ts";

const log = (message: string): void => {
  process.stdout.write(`[lnurl-server] ${message}\n`);
};

export type RunningServer = {
  readonly port: number;
  readonly close: () => Promise<void>;
};

export type ServerSeams = {
  /** Test seam: an externally constructed nostr pool (e.g. backed by a fake relay network). */
  readonly pool?: Pool;
};

export async function startLnurlServer(
  env: Record<string, string | undefined>,
  seams: ServerSeams = {},
): Promise<RunningServer> {
  const config = loadConfig(env);

  const crypto = await loadSparkWasm();
  const signer = createSparkSigner({
    crypto,
    accountKey: sparkAccountKey(config.seed, config.network, config.account),
    network: config.network,
    random: (length) => randomBytes(length),
  });
  const client = createSparkClient({
    network: config.network,
    signer,
    fetch: globalThis.fetch,
    store: createMemorySparkStore(),
  });

  const store = createLnurlStore(config.dbPath);
  const zapKeys =
    config.zapSecretKey === undefined ? undefined : Keys.fromSecretKey(config.zapSecretKey);
  const pool = zapKeys === undefined ? undefined : (seams.pool ?? new Pool());

  const server = createLightningAddressServer({
    client,
    domain: config.domain,
    store,
    minSendableMsat: config.minSendableMsat,
    maxSendableMsat: config.maxSendableMsat,
    commentAllowed: config.commentAllowed,
    invoiceExpirySecs: config.invoiceExpirySecs,
    maxPendingInvoicesPerUser: config.maxPendingInvoicesPerUser,
    maxPendingInvoices: config.maxPendingInvoices,
    settleBatch: config.settleBatch,
    ...(zapKeys === undefined
      ? {}
      : {
          zap: {
            receiptPublicKey: zapKeys.publicKey,
            validateRequest: (json, amountMsat) =>
              validateZapRequest(json, amountMsat, zapKeys.publicKey),
          },
        }),
  });

  const app = createLnurlApp(server);
  // Port 0 binds an ephemeral port; the callback reports the address actually bound.
  let http: ReturnType<typeof serve>;
  const bound = new Promise<number>((resolve) => {
    http = serve({ fetch: app.fetch, port: config.port }, (info) => {
      log(`listening on :${info.port} (${config.domain}, ${config.network})`);
      resolve(info.port);
    });
  });

  // Settlement loop: never overlapping rounds; a failed round logs and the loop continues.
  // Expired invoices and stale zap receipts are pruned every `pruneEveryRounds` rounds
  // (720 × 5s ≈ hourly by default).
  const stop = new AbortController();
  let round = 0;
  const loop = (async () => {
    for (;;) {
      if (stop.signal.aborted) {
        break;
      }
      try {
        // oxlint-disable-next-line no-await-in-loop -- settle rounds must never overlap
        const settled = await server.settlePending();
        if (zapKeys !== undefined && pool !== undefined) {
          // oxlint-disable-next-line no-await-in-loop -- receipts publish within the round
          await publishZapReceipts({
            store,
            keys: zapKeys,
            pool,
            settled,
            batch: config.zapReceiptBatch,
            log,
          });
        }
        round += 1;
        if (round % config.pruneEveryRounds === 0) {
          // oxlint-disable-next-line no-await-in-loop -- prunes run inside the settle loop
          const [invoices, receipts] = await Promise.all([
            store.pruneInvoices(Date.now(), config.settledRetentionMs),
            store.pruneZapReceipts(Date.now(), ZAP_RECEIPT_RETENTION_MS, ZAP_RECEIPT_MAX_ATTEMPTS),
          ]);
          if (invoices > 0 || receipts > 0) {
            log(`pruned ${invoices} invoices and ${receipts} zap receipts`);
          }
        }
      } catch (error) {
        log(`settle round failed: ${String(error)}`);
      }
      // oxlint-disable-next-line no-await-in-loop -- the interval between rounds is deliberate
      await abortableSleep(config.pollIntervalMs, stop.signal);
    }
  })();

  const port = await bound;
  const close = async (): Promise<void> => {
    stop.abort();
    http.close();
    await loop;
    pool?.close();
    store.close();
    client.close();
    log("stopped");
  };

  return { port, close };
}

const invokedAsMain =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;

if (invokedAsMain) {
  try {
    const running = await startLnurlServer(process.env);
    for (const signal of ["SIGINT", "SIGTERM"] as const) {
      process.on(signal, () => {
        void running.close();
      });
    }
  } catch (error) {
    process.stderr.write(
      `lnurl-server: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
  }
}
