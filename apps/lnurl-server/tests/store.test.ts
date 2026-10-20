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

    await expect(store.pendingInvoices(1000)).resolves.toHaveLength(2); // req-2 already expired
    const settled = await store.settleInvoice(HASH, "cc".repeat(32));
    expect(settled?.preimageHex).toBe("cc".repeat(32));
    await expect(store.pendingInvoices(1000)).resolves.toHaveLength(1);
    await expect(store.invoiceByPaymentHash("22".repeat(32))).resolves.toMatchObject({
      zapRequest: "{}",
      comment: "hi",
    });
    await expect(store.settleInvoice("ff".repeat(32), "cc".repeat(32))).resolves.toBeUndefined();
  });

  test("zap receipts: queue, attempt cap, publish and failure tracking", async () => {
    const store = open();
    await store.putZapReceipt(HASH, '{"kind":9735}', ["wss://relay.example"]);
    await expect(store.pendingZapReceipts(5)).resolves.toHaveLength(1);

    await store.recordZapReceiptFailure(HASH, "relay refused");
    let record = await store.zapReceipt(HASH);
    expect(record?.attempts).toBe(1);
    expect(record?.lastError).toBe("relay refused");

    await store.markZapReceiptPublished(HASH);
    await expect(store.pendingZapReceipts(5)).resolves.toHaveLength(0);
    record = await store.zapReceipt(HASH);
    expect(record?.published).toBe(true);

    // An unpublished receipt past the cap stops being returned.
    await store.putZapReceipt("dd".repeat(32), '{"kind":9735}', []);
    await Promise.all(
      Array.from({ length: 5 }, async () => store.recordZapReceiptFailure("dd".repeat(32), "x")),
    );
    await expect(store.pendingZapReceipts(5)).resolves.toHaveLength(0);
  });
});
