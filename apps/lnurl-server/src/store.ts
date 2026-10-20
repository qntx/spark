// SQLite persistence for the Lightning Address server (`node:sqlite`, Node ≥ 24): the
// LightningAddressStore contract plus zap-receipt bookkeeping for the publish retry loop.

import { DatabaseSync } from "node:sqlite";

import type {
  LightningAddressInvoice,
  LightningAddressStore,
  LightningAddressUser,
} from "@qntx/spark/server";

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

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  name TEXT PRIMARY KEY,
  pubkey TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS statements (
  hash TEXT PRIMARY KEY,
  expires_at_ms INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS invoices (
  payment_hash TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  name TEXT NOT NULL,
  pubkey TEXT NOT NULL,
  invoice TEXT NOT NULL,
  expires_at_ms INTEGER NOT NULL,
  zap_request TEXT,
  comment TEXT,
  preimage_hex TEXT
);
CREATE TABLE IF NOT EXISTS zap_receipts (
  payment_hash TEXT PRIMARY KEY,
  event_json TEXT NOT NULL,
  relays_json TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  published INTEGER NOT NULL DEFAULT 0,
  last_error TEXT
);
`;

function text(value: unknown): string {
  if (typeof value !== "string") {
    throw new TypeError("lnurl-store: unexpected non-string column");
  }
  return value;
}

function int(value: unknown): number {
  if (typeof value !== "number" && typeof value !== "bigint") {
    throw new TypeError("lnurl-store: unexpected non-integer column");
  }
  return Number(value);
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
    expiresAtMs: int(row["expires_at_ms"]),
    ...(zapRequest === undefined ? {} : { zapRequest }),
    ...(comment === undefined ? {} : { comment }),
    ...(preimageHex === undefined ? {} : { preimageHex }),
  };
}

export type LnurlStore = LightningAddressStore & {
  /** Queues a built receipt; an existing entry for the payment hash is replaced. */
  readonly putZapReceipt: (
    paymentHash: string,
    eventJson: string,
    relays: ReadonlyArray<string>,
  ) => Promise<void>;
  /** Unpublished receipts below the attempt cap. */
  readonly pendingZapReceipts: (maxAttempts: number) => Promise<ReadonlyArray<ZapReceiptRecord>>;
  readonly markZapReceiptPublished: (paymentHash: string) => Promise<void>;
  readonly recordZapReceiptFailure: (paymentHash: string, error: string) => Promise<void>;
  readonly zapReceipt: (paymentHash: string) => Promise<ZapReceiptRecord | undefined>;
  readonly close: () => void;
};

/**
 * Opens (and migrates) the database at `path`. `":memory:"` works for tests; `now` is injectable
 * for statement-claim pruning.
 */
export function createLnurlStore(path: string, now: () => number = Date.now): LnurlStore {
  const db = new DatabaseSync(path);
  db.exec(SCHEMA);

  return {
    userByName: async (name) => {
      await Promise.resolve();
      const row = db
        .prepare(`SELECT name, pubkey, description FROM users WHERE name = ?`)
        .get(name) as Record<string, unknown> | undefined;
      return userOf(row);
    },

    userByPublicKey: async (pubkeyHex) => {
      await Promise.resolve();
      const row = db
        .prepare(`SELECT name, pubkey, description FROM users WHERE pubkey = ?`)
        .get(pubkeyHex) as Record<string, unknown> | undefined;
      return userOf(row);
    },

    putUser: async (user) => {
      await Promise.resolve();
      const holder = userOf(
        db.prepare(`SELECT name, pubkey, description FROM users WHERE name = ?`).get(user.name),
      );
      if (holder !== undefined && holder.pubkeyHex !== user.pubkeyHex) {
        return false;
      }
      // One name per pubkey: a re-registration releases the old name.
      db.exec("BEGIN");
      try {
        db.prepare(`DELETE FROM users WHERE pubkey = ? AND name != ?`).run(
          user.pubkeyHex,
          user.name,
        );
        db.prepare(`INSERT OR REPLACE INTO users (name, pubkey, description) VALUES (?, ?, ?)`).run(
          user.name,
          user.pubkeyHex,
          user.description,
        );
        db.exec("COMMIT");
      } catch (error) {
        db.exec("ROLLBACK");
        throw error;
      }
      return true;
    },

    deleteUser: async (pubkeyHex, name) => {
      await Promise.resolve();
      const { changes } = db
        .prepare(`DELETE FROM users WHERE name = ? AND pubkey = ?`)
        .run(name, pubkeyHex);
      return Number(changes) > 0;
    },

    claimStatement: async (hashHex, expiresAtMs) => {
      await Promise.resolve();
      db.prepare(`DELETE FROM statements WHERE expires_at_ms <= ?`).run(now());
      const { changes } = db
        .prepare(`INSERT OR IGNORE INTO statements (hash, expires_at_ms) VALUES (?, ?)`)
        .run(hashHex, expiresAtMs);
      return Number(changes) > 0;
    },

    putInvoice: async (invoice) => {
      await Promise.resolve();
      db.prepare(
        `INSERT OR REPLACE INTO invoices
         (payment_hash, request_id, name, pubkey, invoice, expires_at_ms, zap_request, comment)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        invoice.paymentHash,
        invoice.requestId,
        invoice.name,
        invoice.pubkeyHex,
        invoice.invoice,
        invoice.expiresAtMs,
        invoice.zapRequest ?? null,
        invoice.comment ?? null,
      );
    },

    invoiceByPaymentHash: async (hashHex) => {
      await Promise.resolve();
      const row = db.prepare(`SELECT * FROM invoices WHERE payment_hash = ?`).get(hashHex) as
        | Record<string, unknown>
        | undefined;
      return row === undefined ? undefined : invoiceOf(row);
    },

    pendingInvoices: async (nowMs) => {
      await Promise.resolve();
      const rows = db
        .prepare(`SELECT * FROM invoices WHERE preimage_hex IS NULL AND expires_at_ms > ?`)
        .all(nowMs) as Array<Record<string, unknown>>;
      return rows.map(invoiceOf);
    },

    settleInvoice: async (hashHex, preimageHex) => {
      await Promise.resolve();
      db.prepare(`UPDATE invoices SET preimage_hex = ? WHERE payment_hash = ?`).run(
        preimageHex,
        hashHex,
      );
      const row = db.prepare(`SELECT * FROM invoices WHERE payment_hash = ?`).get(hashHex) as
        | Record<string, unknown>
        | undefined;
      return row === undefined ? undefined : invoiceOf(row);
    },

    putZapReceipt: async (paymentHash, eventJson, relays) => {
      await Promise.resolve();
      db.prepare(
        `INSERT OR REPLACE INTO zap_receipts (payment_hash, event_json, relays_json)
         VALUES (?, ?, ?)`,
      ).run(paymentHash, eventJson, JSON.stringify(relays));
    },

    pendingZapReceipts: async (maxAttempts) => {
      await Promise.resolve();
      const rows = db
        .prepare(`SELECT * FROM zap_receipts WHERE published = 0 AND attempts < ?`)
        .all(maxAttempts) as Array<Record<string, unknown>>;
      return rows.map((row) => zapReceiptOf(row));
    },

    markZapReceiptPublished: async (paymentHash) => {
      await Promise.resolve();
      db.prepare(`UPDATE zap_receipts SET published = 1 WHERE payment_hash = ?`).run(paymentHash);
    },

    recordZapReceiptFailure: async (paymentHash, error) => {
      await Promise.resolve();
      db.prepare(
        `UPDATE zap_receipts SET attempts = attempts + 1, last_error = ? WHERE payment_hash = ?`,
      ).run(error.slice(0, 512), paymentHash);
    },

    zapReceipt: async (paymentHash) => {
      await Promise.resolve();
      const row = db
        .prepare(`SELECT * FROM zap_receipts WHERE payment_hash = ?`)
        .get(paymentHash) as Record<string, unknown> | undefined;
      return row === undefined ? undefined : zapReceiptOf(row);
    },

    close: () => {
      db.close();
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
    published: int(row["published"]) === 1,
    ...(lastError === undefined ? {} : { lastError }),
  };
}
