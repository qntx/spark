// Entrypoint: loads the wasm crypto backend, builds the Spark signer/client (the server wallet
// only ever creates invoices), wires the Lightning Address server over the postgres store, serves
// the HTTP routes, and runs the settlement + zap-receipt poll loop until SIGINT/SIGTERM.

import { randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";

import { serve } from "@hono/node-server";
import { Pool as PgPool } from "pg";

import { Keys, Pool } from "@qntx/nostr";
import { createMemorySparkStore, createSparkClient } from "@qntx/spark";
import { loadSparkWasm } from "@qntx/spark-wasm";
import { createLightningAddressServer } from "@qntx/spark/server";
import { createSparkSigner, sparkAccountKey } from "@qntx/spark/signer";

import { loadConfig } from "./config.ts";
import { createLnurlApp } from "./http.ts";
import { createPgSql } from "./pg.ts";
import { abortableSleep } from "./sleep.ts";
import { createLnurlStore } from "./store.ts";
import type { Sql } from "./store.ts";
import {
  ZAP_RECEIPT_MAX_ATTEMPTS,
  ZAP_RECEIPT_RETENTION_MS,
  publishZapReceipts,
  validateZapRequest,
} from "./zap.ts";

/**
 * One JSON object per line — level, msg and a fixed field set. No IPs, invoices, preimages, zap
 * request contents or secrets ever appear in a field; payer IP and payment records never share a
 * line.
 */
const log = (message: string, fields: Record<string, unknown> = {}): void => {
  process.stdout.write(`${JSON.stringify({ level: "info", msg: message, ...fields })}\n`);
};

export type RunningServer = {
  readonly port: number;
  readonly close: () => Promise<void>;
};

export type ServerSeams = {
  /** Test seam: an externally constructed nostr pool (e.g. backed by a fake relay network). */
  readonly pool?: Pool;
  /** Test seam: an injected store backend (PGlite in tests); the pg pool is then skipped. */
  readonly sql?: Sql;
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

  let dbPool: PgPool | undefined;
  const sql =
    seams.sql ?? createPgSql((dbPool = new PgPool({ connectionString: config.databaseUrl })));
  // An idle-client error (e.g. the database dropping connections) must not kill the process —
  // readiness degrades to 503 and the settle loop logs its own round failures.
  dbPool?.on("error", (error) => {
    log("postgres pool error", { level: "error", error: error.message });
  });
  const store = await createLnurlStore(sql);
  const zapKeys =
    config.zapSecretKey === undefined ? undefined : Keys.fromSecretKey(config.zapSecretKey);
  const nostrPool = zapKeys === undefined ? undefined : (seams.pool ?? new Pool());

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
    maxUsers: config.maxUsers,
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

  const app = createLnurlApp(server, {
    ready: async () => {
      // Bounded liveness of the dependency: an unreachable database reports 503.
      const probe = sql.query(`SELECT 1`);
      await Promise.race([
        probe,
        new Promise<never>((_resolve, reject) => {
          setTimeout(() => reject(new Error("database probe timed out")), 2000);
        }),
      ]);
    },
  });
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
        await server.settlePending();
        if (zapKeys !== undefined && nostrPool !== undefined) {
          // oxlint-disable-next-line no-await-in-loop -- receipts publish within the round
          await publishZapReceipts({
            store,
            keys: zapKeys,
            pool: nostrPool,
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
        log("settle round failed", {
          level: "error",
          error: error instanceof Error ? error.message : String(error),
        });
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
    nostrPool?.close();
    client.close();
    await dbPool?.end(); // the connection pool closes last (owned pools only)
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
