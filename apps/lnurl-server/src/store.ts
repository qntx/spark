// PostgreSQL persistence for the Lightning Address server: the LightningAddressStore contract
// plus zap-receipt bookkeeping for the publish retry loop. Every write is safe with several
// instances running at once — claiming is done by the database (ON CONFLICT, FOR UPDATE
// SKIP LOCKED), never by a read-then-write sequence.

import type {
  LightningAddressInvoice,
  LightningAddressStore,
  LightningAddressUser,
} from "@qntx/spark/server";

/** The narrow SQL surface the store uses — a `pg.Pool` in production, PGlite in tests. */
export type Sql = {
  // oxlint-disable-next-line typescript/no-unnecessary-type-parameters -- caller-chosen Row type
  readonly query: <Row>(text: string, params?: ReadonlyArray<unknown>) => Promise<{ rows: Row[] }>;
  readonly transaction: <T>(fn: (tx: Pick<Sql, "query">) => Promise<T>) => Promise<T>;
};

export type ZapReceiptRecord = {
  readonly paymentHash: string;
  /** Serialized signed kind-9735 event, ready to publish. */
  readonly eventJson: string;
  /** Relay URLs copied from the zap request (already capped and scheme-filtered). */
  readonly relays: ReadonlyArray<string>;
  readonly attempts: number;
  readonly published: boolean;
  readonly lastError?: string;
};

const SCHEMA: ReadonlyArray<string> = [
  `CREATE TABLE IF NOT EXISTS users (
  name TEXT PRIMARY KEY,
  pubkey TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL
)`,
  `CREATE TABLE IF NOT EXISTS statements (
  hash TEXT PRIMARY KEY,
  expires_at_ms BIGINT NOT NULL
)`,
  `CREATE INDEX IF NOT EXISTS statements_expires_at_ms ON statements (expires_at_ms)`,
  `CREATE TABLE IF NOT EXISTS invoices (
  payment_hash TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  name TEXT NOT NULL,
  pubkey TEXT NOT NULL,
  invoice TEXT NOT NULL,
  expires_at_ms BIGINT NOT NULL,
  last_checked_at_ms BIGINT NOT NULL DEFAULT 0,
  zap_request TEXT,
  comment TEXT,
  preimage_hex TEXT
)`,
  `CREATE INDEX IF NOT EXISTS invoices_pubkey ON invoices (pubkey)`,
  `CREATE INDEX IF NOT EXISTS invoices_pending
    ON invoices (last_checked_at_ms, expires_at_ms)
    WHERE preimage_hex IS NULL`,
  `CREATE TABLE IF NOT EXISTS zap_receipts (
  payment_hash TEXT PRIMARY KEY,
  event_json TEXT NOT NULL,
  relays_json TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  published BOOLEAN NOT NULL DEFAULT FALSE,
  last_error TEXT,
  updated_at_ms BIGINT NOT NULL DEFAULT 0,
  claimed_until_ms BIGINT
)`,
];

/** Postgres returns BIGINT columns as strings; every _ms column must fit a safe integer. */
function ms(value: unknown): number {
  const parsed = typeof value === "bigint" || typeof value === "string" ? Number(value) : value;
  if (typeof parsed !== "number" || !Number.isSafeInteger(parsed)) {
    throw new TypeError("lnurl-store: unsafe integer in a millisecond column");
  }
  return parsed;
}

function text(value: unknown): string {
  if (typeof value !== "string") {
    throw new TypeError("lnurl-store: unexpected non-string column");
  }
  return value;
}

function int(value: unknown): number {
  const parsed = typeof value === "bigint" || typeof value === "string" ? Number(value) : value;
  if (typeof parsed !== "number" || !Number.isSafeInteger(parsed)) {
    throw new TypeError("lnurl-store: unexpected non-integer column");
  }
  return parsed;
}

function optText(value: unknown): string | undefined {
  return value === null || value === undefined ? undefined : text(value);
}

function userOf(row: Record<string, unknown> | undefined): LightningAddressUser | undefined {
  if (row === undefined) {
    return undefined;
  }
  return {
    name: text(row["name"]),
    pubkeyHex: text(row["pubkey"]),
    description: text(row["description"]),
  };
}

function invoiceOf(row: Record<string, unknown>): LightningAddressInvoice {
  const zapRequest = optText(row["zap_request"]);
  const comment = optText(row["comment"]);
  const preimageHex = optText(row["preimage_hex"]);
  return {
    paymentHash: text(row["payment_hash"]),
    requestId: text(row["request_id"]),
    name: text(row["name"]),
    pubkeyHex: text(row["pubkey"]),
    invoice: text(row["invoice"]),
    expiresAtMs: ms(row["expires_at_ms"]),
    lastCheckedAtMs: ms(row["last_checked_at_ms"]),
    ...(zapRequest === undefined ? {} : { zapRequest }),
    ...(comment === undefined ? {} : { comment }),
    ...(preimageHex === undefined ? {} : { preimageHex }),
  };
}

/** Sentinel: the name is held by another pubkey — thrown inside the transaction so it rolls back. */
class NameTakenError extends Error {
  constructor() {
    super("name taken");
    this.name = "NameTakenError";
  }
}

function isUniqueViolation(error: unknown): boolean {
  return (
    typeof error === "object" && error !== null && (error as { code?: unknown }).code === "23505"
  );
}

/** Seconds a claimed zap-receipt row stays reserved before another instance may re-claim it. */
const RECEIPT_LEASE_MS = 120_000;

export type LnurlStore = LightningAddressStore & {
  /**
   * Settled invoices with a zap request but no `zap_receipts` row — the crash gap between settle
   * and receipt build, re-scanned every publish round. Oldest expiry first.
   */
  readonly unbuiltZapReceipts: (limit: number) => Promise<ReadonlyArray<LightningAddressInvoice>>;
  /** Queues a built receipt; an existing entry for the payment hash is kept as-is. */
  readonly putZapReceipt: (
    paymentHash: string,
    eventJson: string,
    relays: ReadonlyArray<string>,
  ) => Promise<void>;
  /**
   * Atomically claims up to `limit` unpublished receipts below the attempt cap, oldest attempt
   * first — each row's attempt count increments and a `claimed_until_ms` lease reserves it, so two
   * instances never both publish the same receipt within one lease.
   */
  readonly pendingZapReceipts: (
    maxAttempts: number,
    limit: number,
  ) => Promise<ReadonlyArray<ZapReceiptRecord>>;
  readonly markZapReceiptPublished: (paymentHash: string) => Promise<void>;
  readonly recordZapReceiptFailure: (paymentHash: string, error: string) => Promise<void>;
  readonly zapReceipt: (paymentHash: string) => Promise<ZapReceiptRecord | undefined>;
  /**
   * Deletes receipts published more than `publishedRetentionMs` ago and unpublished ones that
   * exhausted their attempts. Returns the number of rows removed.
   */
  readonly pruneZapReceipts: (
    nowMs: number,
    publishedRetentionMs: number,
    maxAttempts: number,
  ) => Promise<number>;
  readonly close: () => Promise<void>;
};

/**
 * Builds the store over `sql` (a `pg.Pool` adapter in production, PGlite in tests) and applies the
 * idempotent DDL. `now` is injectable for lease calculations.
 */
export async function createLnurlStore(
  sql: Sql,
  now: () => number = Date.now,
): Promise<LnurlStore> {
  for (const ddl of SCHEMA) {
    // oxlint-disable-next-line no-await-in-loop -- schema statements apply in order
    await sql.query(ddl);
  }

  return {
    userByName: async (name) => {
      const { rows } = await sql.query<Record<string, unknown>>(
        `SELECT name, pubkey, description FROM users WHERE name = $1`,
        [name],
      );
      return userOf(rows[0]);
    },

    userByPublicKey: async (pubkeyHex) => {
      const { rows } = await sql.query<Record<string, unknown>>(
        `SELECT name, pubkey, description FROM users WHERE pubkey = $1`,
        [pubkeyHex],
      );
      return userOf(rows[0]);
    },

    countUsers: async () => {
      const { rows } = await sql.query<Record<string, unknown>>(`SELECT COUNT(*) AS n FROM users`);
      return int(rows[0]?.["n"]);
    },

    putUser: async (user) => {
      try {
        return await sql.transaction(async (tx) => {
          // One name per pubkey: releasing the pubkey's old name is part of the claim, so
          // a failed claim rolls it back with the transaction.
          await tx.query(`DELETE FROM users WHERE pubkey = $1 AND name != $2`, [
            user.pubkeyHex,
            user.name,
          ]);
          // The conditional conflict keeps the name's current owner: on a new-name race only
          // the first committer inserts; the loser updates nothing and returns no row.
          const { rows } = await tx.query<Record<string, unknown>>(
            `INSERT INTO users (name, pubkey, description) VALUES ($1, $2, $3)
             ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description
             WHERE users.pubkey = EXCLUDED.pubkey
             RETURNING name`,
            [user.name, user.pubkeyHex, user.description],
          );
          if (rows.length === 0) {
            throw new NameTakenError();
          }
          return true;
        });
      } catch (error) {
        // The name belongs to another pubkey, or this pubkey raced itself on a second name
        // (23505 on the unique pubkey) — both report the same way.
        if (error instanceof NameTakenError || isUniqueViolation(error)) {
          return false;
        }
        throw error;
      }
    },

    deleteUser: async (pubkeyHex, name) => {
      const { rows } = await sql.query<Record<string, unknown>>(
        `DELETE FROM users WHERE name = $1 AND pubkey = $2 RETURNING name`,
        [name, pubkeyHex],
      );
      return rows.length > 0;
    },

    claimStatement: async (hashHex, expiresAtMs) => {
      await sql.query(`DELETE FROM statements WHERE expires_at_ms <= $1`, [now()]);
      const { rows } = await sql.query<Record<string, unknown>>(
        `INSERT INTO statements (hash, expires_at_ms) VALUES ($1, $2)
         ON CONFLICT (hash) DO NOTHING RETURNING hash`,
        [hashHex, expiresAtMs],
      );
      return rows.length > 0;
    },

    putInvoice: async (invoice) => {
      await sql.query(
        `INSERT INTO invoices
         (payment_hash, request_id, name, pubkey, invoice, expires_at_ms,
          zap_request, comment, preimage_hex)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         ON CONFLICT (payment_hash) DO UPDATE SET
           request_id = EXCLUDED.request_id,
           name = EXCLUDED.name,
           pubkey = EXCLUDED.pubkey,
           invoice = EXCLUDED.invoice,
           expires_at_ms = EXCLUDED.expires_at_ms,
           zap_request = EXCLUDED.zap_request,
           comment = EXCLUDED.comment`,
        [
          invoice.paymentHash,
          invoice.requestId,
          invoice.name,
          invoice.pubkeyHex,
          invoice.invoice,
          invoice.expiresAtMs,
          invoice.zapRequest ?? null,
          invoice.comment ?? null,
          invoice.preimageHex ?? null,
        ],
      );
    },

    invoiceByPaymentHash: async (hashHex) => {
      const { rows } = await sql.query<Record<string, unknown>>(
        `SELECT * FROM invoices WHERE payment_hash = $1`,
        [hashHex],
      );
      return rows[0] === undefined ? undefined : invoiceOf(rows[0]);
    },

    // The claim runs in one transaction: SKIP LOCKED rows are locked and stamped before
    // commit, so concurrent instances split the batch without overlap. The returned order is
    // the pre-claim staleness order — the stamp happens after the selection.
    pendingInvoices: async (nowMs, limit) =>
      sql.transaction(async (tx) => {
        const { rows } = await tx.query<Record<string, unknown>>(
          `SELECT * FROM invoices
           WHERE preimage_hex IS NULL AND expires_at_ms > $1
           ORDER BY last_checked_at_ms ASC, expires_at_ms ASC
           LIMIT $2 FOR UPDATE SKIP LOCKED`,
          [nowMs, limit],
        );
        if (rows.length > 0) {
          await tx.query(
            `UPDATE invoices SET last_checked_at_ms = $1 WHERE payment_hash = ANY($2)`,
            [nowMs, rows.map((row) => text(row["payment_hash"]))],
          );
        }
        return rows.map((row) => invoiceOf(row));
      }),

    // The pending claim above already stamps last_checked_at_ms — this stays only for the
    // store contract, and is a plain unconditional update.
    markChecked: async (hashHex, nowMs) => {
      await sql.query(`UPDATE invoices SET last_checked_at_ms = $1 WHERE payment_hash = $2`, [
        nowMs,
        hashHex,
      ]);
    },

    countPendingInvoices: async (nowMs, pubkeyHex) => {
      const { rows } = await sql.query<Record<string, unknown>>(
        pubkeyHex === undefined
          ? `SELECT COUNT(*) AS n FROM invoices
             WHERE preimage_hex IS NULL AND expires_at_ms > $1`
          : `SELECT COUNT(*) AS n FROM invoices
             WHERE preimage_hex IS NULL AND expires_at_ms > $1 AND pubkey = $2`,
        pubkeyHex === undefined ? [nowMs] : [nowMs, pubkeyHex],
      );
      return int(rows[0]?.["n"]);
    },

    pruneInvoices: async (nowMs, settledRetentionMs) => {
      const { rows } = await sql.query<Record<string, unknown>>(
        `DELETE FROM invoices
         WHERE (preimage_hex IS NULL AND expires_at_ms <= $1)
            OR (preimage_hex IS NOT NULL AND expires_at_ms <= $2)
         RETURNING payment_hash`,
        [nowMs, nowMs - settledRetentionMs],
      );
      return rows.length;
    },

    // Only the first settler gets the record back — a receipt is built exactly once even with
    // several instances racing the same preimage.
    settleInvoice: async (hashHex, preimageHex) => {
      const { rows } = await sql.query<Record<string, unknown>>(
        `UPDATE invoices SET preimage_hex = $2
         WHERE payment_hash = $1 AND preimage_hex IS NULL
         RETURNING *`,
        [hashHex, preimageHex],
      );
      return rows[0] === undefined ? undefined : invoiceOf(rows[0]);
    },

    putZapReceipt: async (paymentHash, eventJson, relays) => {
      // DO NOTHING: a duplicate build (crash-safe rescan or a repeated settle event) is the
      // same receipt — it must not reset attempts or steal a live claim.
      await sql.query(
        `INSERT INTO zap_receipts (payment_hash, event_json, relays_json, updated_at_ms)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (payment_hash) DO NOTHING`,
        [paymentHash, eventJson, JSON.stringify(relays), now()],
      );
    },

    // Same SKIP LOCKED claim as pendingInvoices, plus a per-row lease and the attempt
    // increment — both stamped inside the transaction. Returned rows are pre-claim order.
    unbuiltZapReceipts: async (limit) => {
      const { rows } = await sql.query<Record<string, unknown>>(
        `SELECT i.* FROM invoices i
         LEFT JOIN zap_receipts zr ON zr.payment_hash = i.payment_hash
         WHERE i.preimage_hex IS NOT NULL AND i.zap_request IS NOT NULL
           AND zr.payment_hash IS NULL
         ORDER BY i.expires_at_ms ASC LIMIT $1`,
        [limit],
      );
      return rows.map((row) => invoiceOf(row));
    },

    pendingZapReceipts: async (maxAttempts, limit) =>
      sql.transaction(async (tx) => {
        const { rows } = await tx.query<Record<string, unknown>>(
          `SELECT * FROM zap_receipts
           WHERE NOT published AND attempts < $1
             AND (claimed_until_ms IS NULL OR claimed_until_ms <= $2)
           ORDER BY updated_at_ms ASC
           LIMIT $3 FOR UPDATE SKIP LOCKED`,
          [maxAttempts, now(), limit],
        );
        if (rows.length > 0) {
          await tx.query(
            `UPDATE zap_receipts
             SET attempts = attempts + 1, claimed_until_ms = $1
             WHERE payment_hash = ANY($2)`,
            [now() + RECEIPT_LEASE_MS, rows.map((row) => text(row["payment_hash"]))],
          );
        }
        return rows.map((row) => zapReceiptOf(row));
      }),

    markZapReceiptPublished: async (paymentHash) => {
      await sql.query(
        `UPDATE zap_receipts
         SET published = TRUE, claimed_until_ms = NULL, updated_at_ms = $1
         WHERE payment_hash = $2`,
        [now(), paymentHash],
      );
    },

    recordZapReceiptFailure: async (paymentHash, error) => {
      // Clearing the lease puts the row back in rotation on the next round; attempts already
      // counted the claim, so the failure only records the cause.
      await sql.query(
        `UPDATE zap_receipts
         SET last_error = $1, claimed_until_ms = NULL, updated_at_ms = $2
         WHERE payment_hash = $3`,
        [error.slice(0, 512), now(), paymentHash],
      );
    },

    pruneZapReceipts: async (nowMs, publishedRetentionMs, maxAttempts) => {
      const { rows } = await sql.query<Record<string, unknown>>(
        `DELETE FROM zap_receipts
         WHERE (published AND updated_at_ms <= $1) OR attempts >= $2
         RETURNING payment_hash`,
        [nowMs - publishedRetentionMs, maxAttempts],
      );
      return rows.length;
    },

    zapReceipt: async (paymentHash) => {
      const { rows } = await sql.query<Record<string, unknown>>(
        `SELECT * FROM zap_receipts WHERE payment_hash = $1`,
        [paymentHash],
      );
      return rows[0] === undefined ? undefined : zapReceiptOf(rows[0]);
    },

    close: async () => {
      await Promise.resolve();
    },
  };
}

function stringArray(raw: unknown, column: string): string[] {
  if (!Array.isArray(raw)) {
    throw new TypeError(`corrupt ${column}: expected a JSON string array`);
  }
  return raw.map((v: unknown) => {
    if (typeof v !== "string") {
      throw new TypeError(`corrupt ${column}: expected a JSON string array`);
    }
    return v;
  });
}

function zapReceiptOf(row: Record<string, unknown>): ZapReceiptRecord {
  const lastError = optText(row["last_error"]);
  return {
    paymentHash: text(row["payment_hash"]),
    eventJson: text(row["event_json"]),
    relays: stringArray(JSON.parse(text(row["relays_json"])), "zap_receipts.relays_json"),
    attempts: int(row["attempts"]),
    published: row["published"] === true || row["published"] === "t",
    ...(lastError === undefined ? {} : { lastError }),
  };
}
