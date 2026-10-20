import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "vite-plus/test";

import type { LightningAddressInvoice, LightningAddressUser } from "@qntx/spark/server";

import { createLnurlStore } from "../src/store.ts";
import type { LnurlStore } from "../src/store.ts";

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

describe("lnurl sqlite store", () => {
  let path = "";
  let store: LnurlStore;

  function open(now?: () => number): LnurlStore {
    path = join(mkdtempSync(join(tmpdir(), "lnurl-store-")), "test.db");
    store = createLnurlStore(path, now);
    return store;
  }

  afterEach(() => {
    store.close();
    rmSync(join(path, ".."), { recursive: true, force: true });
  });

  test("users: name conflicts fail, same-key re-registration replaces the name", async () => {
    const store = open();
    await expect(store.putUser(ALICE)).resolves.toBe(true);
    await expect(store.userByName("alice")).resolves.toStrictEqual(ALICE);
    // Another key cannot take the name.
    await expect(store.putUser(BOB)).resolves.toBe(false);
    // The same key renames: the old name is released.
    await expect(store.putUser(ALICE2)).resolves.toBe(true);
    await expect(store.userByName("alice")).resolves.toBeUndefined();
    await expect(store.userByName("alice2")).resolves.toStrictEqual(ALICE2);
    await expect(store.userByPublicKey(ALICE.pubkeyHex)).resolves.toStrictEqual(ALICE2);
    // Bob can now take the released name.
    await expect(store.putUser(BOB)).resolves.toBe(true);
    // deleteUser only removes a matching (name, key) pair.
    await expect(store.deleteUser(BOB.pubkeyHex, "alice2")).resolves.toBe(false);
    await expect(store.deleteUser(ALICE.pubkeyHex, "alice2")).resolves.toBe(true);
    await expect(store.userByPublicKey(ALICE.pubkeyHex)).resolves.toBeUndefined();
  });

  test("statements: claim once, prunes expired claims", async () => {
    let now = 1000;
    const store = open(() => now);
    await expect(store.claimStatement("s1", 2000)).resolves.toBe(true);
    await expect(store.claimStatement("s1", 2000)).resolves.toBe(false);
    now = 2500;
    // Expired claims are pruned on the next claim — the same statement can be claimed again.
    await expect(store.claimStatement("s1", 4000)).resolves.toBe(true);
    await expect(store.claimStatement("s1", 4000)).resolves.toBe(false);
  });

  test("invoices: pending excludes settled and expired, settle persists the preimage", async () => {
    const store = open();
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
    const store = open();
    await store.putZapReceipt(HASH, '{"kind":9735}', ["wss://relay.example"]);
    await expect(store.pendingZapReceipts(5, 10)).resolves.toHaveLength(1);

    await store.recordZapReceiptFailure(HASH, "relay refused");
    let record = await store.zapReceipt(HASH);
    expect(record?.attempts).toBe(1);
    expect(record?.lastError).toBe("relay refused");

    await store.markZapReceiptPublished(HASH);
    await expect(store.pendingZapReceipts(5, 10)).resolves.toHaveLength(0);
    record = await store.zapReceipt(HASH);
    expect(record?.published).toBe(true);

    // An unpublished receipt past the cap stops being returned.
    await store.putZapReceipt("dd".repeat(32), '{"kind":9735}', []);
    await Promise.all(
      Array.from({ length: 5 }, async () => store.recordZapReceiptFailure("dd".repeat(32), "x")),
    );
    await expect(store.pendingZapReceipts(5, 10)).resolves.toHaveLength(0);
  });
});

describe("pending-invoice fairness and pruning", () => {
  test("pendingInvoices caps the batch and rotates least-recently-checked first", async () => {
    const store = createLnurlStore(":memory:");
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
    store.close();
  });

  test("countPendingInvoices scopes by pubkey and ignores settled and expired rows", async () => {
    const store = createLnurlStore(":memory:");
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
    store.close();
  });

  test("pruneInvoices drops expired unsettled rows and settled rows past retention", async () => {
    const store = createLnurlStore(":memory:");
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
    store.close();
  });
});

describe("zap receipt pruning", () => {
  test("pendingZapReceipts honors the batch limit, oldest attempt first", async () => {
    let now = 1000;
    const store = createLnurlStore(":memory:", () => now);
    await store.putZapReceipt("aa".repeat(32), "{}", []);
    now = 2000;
    await store.putZapReceipt("bb".repeat(32), "{}", []);
    await store.putZapReceipt("cc".repeat(32), "{}", []);
    const pending = await store.pendingZapReceipts(3, 2);
    expect(pending.map((r) => r.paymentHash)).toStrictEqual(["aa".repeat(32), "bb".repeat(32)]);
    store.close();
  });

  test("pruneZapReceipts drops published receipts past retention and exhausted attempts", async () => {
    let now = 1000;
    const store = createLnurlStore(":memory:", () => now);
    const retention = 7 * 24 * 3600 * 1000;
    const cutoff = now + 10_000;
    await store.putZapReceipt("aa".repeat(32), "{}", []); // published long ago
    await store.markZapReceiptPublished("aa".repeat(32)); // updated_at = 1000
    now = cutoff + 1;
    await store.putZapReceipt("bb".repeat(32), "{}", []);
    await store.markZapReceiptPublished("bb".repeat(32)); // inside the retention window
    await store.putZapReceipt("cc".repeat(32), "{}", []); // will exhaust attempts
    await Promise.all(
      Array.from({ length: 5 }, async () => store.recordZapReceiptFailure("cc".repeat(32), "x")),
    );
    await store.putZapReceipt("dd".repeat(32), "{}", []); // still retryable
    now = cutoff + retention;
    await expect(store.pruneZapReceipts(now, retention, 5)).resolves.toBe(2);
    const pending = await store.pendingZapReceipts(5, 10);
    expect(pending.map((r) => r.paymentHash)).toStrictEqual(["dd".repeat(32)]);
    await expect(store.zapReceipt("bb".repeat(32))).resolves.toBeDefined();
    store.close();
  });
});
