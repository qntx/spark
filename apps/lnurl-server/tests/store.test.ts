import { afterEach, describe, expect, test } from "vite-plus/test";

import type { LightningAddressInvoice, LightningAddressUser } from "@qntx/spark/server";

import { createLnurlStore } from "../src/store.ts";
import type { LnurlStore } from "../src/store.ts";
import { createTestSql } from "./support/pglite.ts";

const ALICE: LightningAddressUser = { name: "alice", pubkeyHex: "aa".repeat(33), description: "A" };
const ALICE2: LightningAddressUser = {
  name: "alice2",
  pubkeyHex: ALICE.pubkeyHex,
  description: "A2",
};
const BOB: LightningAddressUser = { name: "alice", pubkeyHex: "bb".repeat(33), description: "B" };

const HASH = "ab".repeat(32);

function invoice(overrides: Partial<LightningAddressInvoice> = {}): LightningAddressInvoice {
  return {
    paymentHash: HASH,
    requestId: "req-1",
    name: "alice",
    pubkeyHex: ALICE.pubkeyHex,
    invoice: "lnbcrt1...",
    expiresAtMs: 10_000,
    ...overrides,
  };
}

describe("lnurl postgres store", { timeout: 30_000 }, () => {
  let cleanup: (() => Promise<void>) | undefined;
  let store: LnurlStore;

  async function open(now?: () => number): Promise<LnurlStore> {
    const { sql, close } = await createTestSql();
    store = await createLnurlStore(sql, now);
    cleanup = close;
    return store;
  }

  afterEach(async () => {
    await cleanup?.();
    cleanup = undefined;
  });

  test("users: name conflicts fail, same-key re-registration replaces the name", async () => {
    const store = await open();
    await expect(store.countUsers()).resolves.toBe(0);
    await expect(store.putUser(ALICE)).resolves.toBe(true);
    await expect(store.countUsers()).resolves.toBe(1);
    await expect(store.userByName("alice")).resolves.toStrictEqual(ALICE);
    // Another key cannot take the name.
    await expect(store.putUser(BOB)).resolves.toBe(false);
    // The same key renames: the old name is released.
    await expect(store.putUser(ALICE2)).resolves.toBe(true);
    await expect(store.countUsers()).resolves.toBe(1);
    await expect(store.userByName("alice")).resolves.toBeUndefined();
    await expect(store.userByName("alice2")).resolves.toStrictEqual(ALICE2);
    await expect(store.userByPublicKey(ALICE.pubkeyHex)).resolves.toStrictEqual(ALICE2);
    // Bob can now take the released name.
    await expect(store.putUser(BOB)).resolves.toBe(true);
    await expect(store.countUsers()).resolves.toBe(2);
    // deleteUser only removes a matching (name, key) pair.
    await expect(store.deleteUser(BOB.pubkeyHex, "alice2")).resolves.toBe(false);
    await expect(store.deleteUser(ALICE.pubkeyHex, "alice2")).resolves.toBe(true);
    await expect(store.userByPublicKey(ALICE.pubkeyHex)).resolves.toBeUndefined();
  });

  test("statements: claim once, prunes expired claims", async () => {
    let now = 1000;
    const store = await open(() => now);
    await expect(store.claimStatement("s1", 2000)).resolves.toBe(true);
    await expect(store.claimStatement("s1", 2000)).resolves.toBe(false);
    now = 2500;
    // Expired claims are pruned on the next claim — the same statement can be claimed again.
    await expect(store.claimStatement("s1", 4000)).resolves.toBe(true);
    await expect(store.claimStatement("s1", 4000)).resolves.toBe(false);
  });

  test("invoices: pending excludes settled and expired, settle persists the preimage", async () => {
    const store = await open();
    await store.putInvoice(invoice());
    await store.putInvoice(
      invoice({ paymentHash: "11".repeat(32), requestId: "req-2", expiresAtMs: 500 }),
    );
    await store.putInvoice(
      invoice({
        paymentHash: "22".repeat(32),
        requestId: "req-3",
        zapRequest: "{}",
        comment: "hi",
      }),
    );

    await expect(store.pendingInvoices(1000, 10)).resolves.toHaveLength(2); // req-2 already expired
    const settled = await store.settleInvoice(HASH, "cc".repeat(32));
    expect(settled?.preimageHex).toBe("cc".repeat(32));
    await expect(store.pendingInvoices(1000, 10)).resolves.toHaveLength(1);
    await expect(store.invoiceByPaymentHash("22".repeat(32))).resolves.toMatchObject({
      zapRequest: "{}",
      comment: "hi",
    });
    await expect(store.settleInvoice("ff".repeat(32), "cc".repeat(32))).resolves.toBeUndefined();
  });

  test("zap receipts: queue, attempt cap, publish and failure tracking", async () => {
    const store = await open();
    await store.putZapReceipt(HASH, '{"kind":9735}', ["wss://relay.example"]);
    await expect(store.pendingZapReceipts(5, 10)).resolves.toHaveLength(1);

    // The claim above already counted the attempt; a failure records the cause and frees
    // the lease for the next round.
    await store.recordZapReceiptFailure(HASH, "relay refused");
    let record = await store.zapReceipt(HASH);
    expect(record?.attempts).toBe(1);
    expect(record?.lastError).toBe("relay refused");

    await store.markZapReceiptPublished(HASH);
    await expect(store.pendingZapReceipts(5, 10)).resolves.toHaveLength(0);
    record = await store.zapReceipt(HASH);
    expect(record?.published).toBe(true);

    // An unpublished receipt past the cap stops being returned — attempts count claims.
    await store.putZapReceipt("dd".repeat(32), '{"kind":9735}', []);
    for (let i = 0; i < 5; i += 1) {
      // oxlint-disable-next-line no-await-in-loop -- sequential claim/failure rounds
      await store.pendingZapReceipts(6, 10);
      // oxlint-disable-next-line no-await-in-loop -- sequential claim/failure rounds
      await store.recordZapReceiptFailure("dd".repeat(32), "x");
    }
    await expect(store.pendingZapReceipts(5, 10)).resolves.toHaveLength(0);
  });
});

describe("pending-invoice fairness and pruning", () => {
  test("pendingInvoices caps the batch and rotates least-recently-checked first", async () => {
    const { sql, close } = await createTestSql();
    const store = await createLnurlStore(sql);
    await store.putInvoice(invoice({ requestId: "req-1", expiresAtMs: 10_000 }));
    await store.putInvoice(
      invoice({ paymentHash: "bb".repeat(32), requestId: "req-2", expiresAtMs: 20_000 }),
    );
    await store.putInvoice(
      invoice({ paymentHash: "cc".repeat(32), requestId: "req-3", expiresAtMs: 30_000 }),
    );

    const first = await store.pendingInvoices(1000, 2);
    expect(first.map((i) => i.requestId)).toStrictEqual(["req-1", "req-2"]);
    await store.markChecked(invoice().paymentHash, 1500);
    await store.markChecked("bb".repeat(32), 1600);
    const next = await store.pendingInvoices(2000, 2);
    // req-3 was never checked, so it leads; req-1 is the oldest checked.
    expect(next.map((i) => i.requestId)).toStrictEqual(["req-3", "req-1"]);
    // All rows are expired at 100_000 — nothing returns.
    await store.markChecked("cc".repeat(32), 2000);
    await expect(store.pendingInvoices(100_000, 10)).resolves.toStrictEqual([]);
    await close();
  });

  test("countPendingInvoices scopes by pubkey and ignores settled and expired rows", async () => {
    const { sql, close } = await createTestSql();
    const store = await createLnurlStore(sql);
    await store.putInvoice(invoice({ requestId: "req-1" }));
    await store.putInvoice(
      invoice({ paymentHash: "bb".repeat(32), requestId: "req-2", pubkeyHex: BOB.pubkeyHex }),
    );
    await store.putInvoice(
      invoice({ paymentHash: "cc".repeat(32), requestId: "req-3", expiresAtMs: 500 }),
    );
    await store.settleInvoice("bb".repeat(32), "ee".repeat(32));
    await expect(store.countPendingInvoices(1000)).resolves.toBe(1);
    await expect(store.countPendingInvoices(1000, ALICE.pubkeyHex)).resolves.toBe(1);
    await expect(store.countPendingInvoices(1000, BOB.pubkeyHex)).resolves.toBe(0);
    await close();
  });

  test("pruneInvoices drops expired unsettled rows and settled rows past retention", async () => {
    const { sql, close } = await createTestSql();
    const store = await createLnurlStore(sql);
    const retention = 30 * 24 * 3600 * 1000;
    const now = 100_000_000_000;
    await store.putInvoice(invoice({ requestId: "req-1", expiresAtMs: now - 1 })); // expired
    await store.putInvoice(
      invoice({
        paymentHash: "bb".repeat(32),
        requestId: "req-2",
        expiresAtMs: now - retention - 1,
        preimageHex: "ee".repeat(32),
      }),
    ); // settled long ago
    await store.putInvoice(
      invoice({
        paymentHash: "cc".repeat(32),
        requestId: "req-3",
        expiresAtMs: now - 1,
        preimageHex: "ee".repeat(32),
      }),
    ); // settled, inside retention
    await store.putInvoice(
      invoice({ paymentHash: "dd".repeat(32), requestId: "req-4", expiresAtMs: now + 60_000 }),
    ); // live
    await expect(store.pruneInvoices(now, retention)).resolves.toBe(2);
    await expect(store.invoiceByPaymentHash(invoice().paymentHash)).resolves.toBeUndefined();
    await expect(store.invoiceByPaymentHash("bb".repeat(32))).resolves.toBeUndefined();
    await expect(store.invoiceByPaymentHash("cc".repeat(32))).resolves.toBeDefined();
    await expect(store.invoiceByPaymentHash("dd".repeat(32))).resolves.toBeDefined();
    await close();
  });
});

describe("zap receipt pruning", () => {
  test("pendingZapReceipts honors the batch limit, oldest attempt first", async () => {
    let now = 1000;
    const { sql, close } = await createTestSql();
    const store = await createLnurlStore(sql, () => now);
    await store.putZapReceipt("aa".repeat(32), "{}", []);
    now = 2000;
    await store.putZapReceipt("bb".repeat(32), "{}", []);
    await store.putZapReceipt("cc".repeat(32), "{}", []);
    const pending = await store.pendingZapReceipts(3, 2);
    expect(pending.map((r) => r.paymentHash)).toStrictEqual(["aa".repeat(32), "bb".repeat(32)]);
    await close();
  });

  test("pruneZapReceipts drops published receipts past retention and exhausted attempts", async () => {
    let now = 1000;
    const { sql, close } = await createTestSql();
    const store = await createLnurlStore(sql, () => now);
    const retention = 7 * 24 * 3600 * 1000;
    const cutoff = now + 10_000;
    await store.putZapReceipt("aa".repeat(32), "{}", []); // published long ago
    await store.markZapReceiptPublished("aa".repeat(32)); // updated_at = 1000
    now = cutoff + 1;
    await store.putZapReceipt("bb".repeat(32), "{}", []);
    await store.markZapReceiptPublished("bb".repeat(32)); // inside the retention window
    await store.putZapReceipt("cc".repeat(32), "{}", []); // will exhaust attempts
    for (let i = 0; i < 5; i += 1) {
      // oxlint-disable-next-line no-await-in-loop -- sequential claim/failure rounds
      await store.pendingZapReceipts(6, 10);
      // oxlint-disable-next-line no-await-in-loop -- sequential claim/failure rounds
      await store.recordZapReceiptFailure("cc".repeat(32), "x");
    }
    await store.putZapReceipt("dd".repeat(32), "{}", []); // still retryable
    now = cutoff + retention;
    await expect(store.pruneZapReceipts(now, retention, 5)).resolves.toBe(2);
    const pending = await store.pendingZapReceipts(5, 10);
    expect(pending.map((r) => r.paymentHash)).toStrictEqual(["dd".repeat(32)]);
    await expect(store.zapReceipt("bb".repeat(32))).resolves.toBeDefined();
    await close();
  });
});

describe("concurrent instance semantics", () => {
  // PGlite runs one connection: true interleaving is impossible here. The multi-instance
  // safety is in the SQL itself — FOR UPDATE locking in putUser, SKIP LOCKED claims, ON
  // CONFLICT statements and NULL-guarded settles — so these tests prove the shapes hold:
  // sequential callers see exactly the outcomes a lock race would produce.
  let cleanup: (() => Promise<void>) | undefined;

  async function open(now?: () => number): Promise<LnurlStore> {
    const { sql, close } = await createTestSql();
    cleanup = close;
    return createLnurlStore(sql, now);
  }

  afterEach(async () => {
    await cleanup?.();
    cleanup = undefined;
  });

  test("two registrations of the same name from different keys: exactly one wins", async () => {
    const store = await open();
    const first = await store.putUser(ALICE);
    const second = await store.putUser(BOB); // same name, different pubkey
    expect([first, second].filter(Boolean)).toHaveLength(1);
    await expect(store.userByName("alice")).resolves.toStrictEqual(ALICE);
  });

  test("two pendingInvoices calls never return the same row", async () => {
    const store = await open();
    await store.putInvoice(invoice({ requestId: "req-1" }));
    await store.putInvoice(
      invoice({ paymentHash: "bb".repeat(32), requestId: "req-2", expiresAtMs: 20_000 }),
    );
    const a = await store.pendingInvoices(1000, 1);
    const b = await store.pendingInvoices(1000, 1);
    // The first call claimed and stamped req-1; the second takes the next-stalest row.
    expect(new Set([...a, ...b].map((i) => i.paymentHash)).size).toBe(a.length + b.length);
    expect(b[0]?.requestId).toBe("req-2");
  });

  test("settleInvoice returns the record to the first settler only", async () => {
    const store = await open();
    await store.putInvoice(invoice());
    const first = await store.settleInvoice(HASH, "cc".repeat(32));
    const second = await store.settleInvoice(HASH, "cc".repeat(32));
    expect(first?.preimageHex).toBe("cc".repeat(32));
    expect(second).toBeUndefined();
  });

  test("a claimed zap receipt is held by its lease until it expires or fails", async () => {
    let now = 1000;
    const store = await open(() => now);
    await store.putZapReceipt(HASH, "{}", []);
    const first = await store.pendingZapReceipts(5, 10);
    const second = await store.pendingZapReceipts(5, 10); // inside the lease — nothing
    expect(first).toHaveLength(1);
    expect(second).toHaveLength(0);
    // An explicit failure frees the row immediately.
    await store.recordZapReceiptFailure(HASH, "x");
    await expect(store.pendingZapReceipts(5, 10)).resolves.toHaveLength(1);
    // Or the lease lapses on its own past its deadline.
    await store.putZapReceipt("dd".repeat(32), "{}", []);
    now += 200_000;
    const afterLease = await store.pendingZapReceipts(5, 10);
    expect(afterLease.map((r) => r.paymentHash)).toContain("dd".repeat(32));
  });
});
