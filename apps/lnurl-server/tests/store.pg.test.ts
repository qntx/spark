// Real-Postgres concurrency tests: PGlite serializes connections, so the multi-instance
// guarantees are proven here against two independent pools on an isolated schema.
// Gated on LNURL_TEST_DATABASE_URL — skipped otherwise.

import { randomBytes } from "node:crypto";

import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, test } from "vite-plus/test";

import type { LightningAddressInvoice, LightningAddressUser } from "@qntx/spark/server";

import { createPgSql } from "../src/pg.ts";
import { createLnurlStore } from "../src/store.ts";
import type { LnurlStore } from "../src/store.ts";

const PG_URL = process.env["LNURL_TEST_DATABASE_URL"];

const ALICE: LightningAddressUser = { name: "alice", pubkeyHex: "aa".repeat(33), description: "A" };
const BOB: LightningAddressUser = { name: "alice", pubkeyHex: "bb".repeat(33), description: "B" };

function invoice(overrides: Partial<LightningAddressInvoice> = {}): LightningAddressInvoice {
  return {
    paymentHash: "ab".repeat(32),
    requestId: "req-1",
    name: "alice",
    pubkeyHex: ALICE.pubkeyHex,
    invoice: "lnbcrt1...",
    expiresAtMs: 60_000,
    ...overrides,
  };
}

describe.skipIf(PG_URL === undefined)(
  "postgres store: real concurrency",
  { timeout: 60_000 },
  () => {
    let admin: Pool;
    let poolA: Pool;
    let poolB: Pool;
    let storeA: LnurlStore;
    let storeB: LnurlStore;
    const schema = `t_${randomBytes(8).toString("hex")}`;

    beforeAll(async () => {
      admin = new Pool({ connectionString: PG_URL });
      await admin.query(`CREATE SCHEMA ${schema}`);
      const url = new URL(String(PG_URL));
      url.searchParams.set("options", `-c search_path=${schema}`);
      const connection = url.toString();
      poolA = new Pool({ connectionString: connection });
      poolB = new Pool({ connectionString: connection });
      storeA = await createLnurlStore(createPgSql(poolA));
      storeB = await createLnurlStore(createPgSql(poolB));
    });

    afterAll(async () => {
      await poolA.end();
      await poolB.end();
      await admin.query(`DROP SCHEMA ${schema} CASCADE`);
      await admin.end();
    });

    test("two pools race a new name: exactly one wins", async () => {
      // Both fire before either commits — the loser's conditional conflict yields no row.
      const [a, b] = await Promise.all([storeA.putUser(ALICE), storeB.putUser(BOB)]);
      expect(a).not.toBe(b);
      const holder = await storeA.userByName("alice");
      expect(holder?.pubkeyHex === ALICE.pubkeyHex).toBe(a);
    });

    test("the same pubkey racing two names keeps exactly one", async () => {
      const hash = "cd".repeat(32);
      const [a, b] = await Promise.all([
        storeA.putUser({ name: "carol", pubkeyHex: hash, description: "c" }),
        storeB.putUser({ name: "dave", pubkeyHex: hash, description: "c" }),
      ]);
      // Either the inserts conflict on the unique pubkey (second loses) or the winner's
      // re-registration released the loser's name first — either way, one name total.
      expect([a, b].filter(Boolean).length).toBeGreaterThanOrEqual(1);
      const byCarol = await storeA.userByName("carol");
      const byDave = await storeA.userByName("dave");
      expect([byCarol, byDave].filter((u) => u !== undefined)).toHaveLength(1);
    });

    test("concurrent pendingInvoices claims are disjoint and cover the set", async () => {
      for (const hash of ["11".repeat(32), "22".repeat(32), "33".repeat(32), "44".repeat(32)]) {
        // oxlint-disable-next-line no-await-in-loop -- fixtures insert in order
        await storeA.putInvoice(invoice({ paymentHash: hash, expiresAtMs: 60_000 }));
      }
      const [a, b] = await Promise.all([
        storeA.pendingInvoices(0, 4),
        storeB.pendingInvoices(0, 4),
      ]);
      const claimed = new Set([...a, ...b].map((i) => i.paymentHash));
      // SKIP LOCKED: no row is claimed twice, and together the two passes take the whole set.
      expect(claimed.size).toBe(a.length + b.length);
      expect(claimed.size).toBe(4);
    });

    test("concurrent settleInvoice on the same hash: exactly one record returned", async () => {
      await storeA.putInvoice(invoice({ paymentHash: "55".repeat(32) }));
      const [a, b] = await Promise.all([
        storeA.settleInvoice("55".repeat(32), "66".repeat(32)),
        storeB.settleInvoice("55".repeat(32), "66".repeat(32)),
      ]);
      expect([a, b].filter((i) => i !== undefined)).toHaveLength(1);
      const row = await storeA.invoiceByPaymentHash("55".repeat(32));
      expect(row?.preimageHex).toBe("66".repeat(32));
    });

    test("concurrent pendingZapReceipts claims are disjoint", async () => {
      for (const hash of ["77".repeat(32), "88".repeat(32)]) {
        // oxlint-disable-next-line no-await-in-loop -- fixtures insert in order
        await storeA.putZapReceipt(hash, "{}", []);
      }
      const [a, b] = await Promise.all([
        storeA.pendingZapReceipts(5, 4),
        storeB.pendingZapReceipts(5, 4),
      ]);
      const claimed = new Set([...a, ...b].map((r) => r.paymentHash));
      expect(claimed.size).toBe(a.length + b.length);
      expect(claimed.size).toBe(2);
    });
  },
);
