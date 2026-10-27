import { describe, expect, test } from "vite-plus/test";

import { loadConfig } from "../src/config.ts";

const REQUIRED = {
  LNURL_DOMAIN: "example.com",
  LNURL_NETWORK: "regtest",
  LNURL_SPARK_SEED: "ab".repeat(64),
  LNURL_DATABASE_URL: "postgres://test:test@localhost:5432/test",
} as const;

describe("loadConfig", () => {
  test("resource-limit knobs default to sane values", () => {
    const config = loadConfig({ ...REQUIRED });
    expect(config.invoiceExpirySecs).toBe(3600);
    expect(config.maxPendingInvoicesPerUser).toBe(100);
    expect(config.maxPendingInvoices).toBe(10_000);
    expect(config.maxUsers).toBe(100_000);
    expect(config.settleBatch).toBe(200);
    expect(config.pruneEveryRounds).toBe(720);
    expect(config.settledRetentionMs).toBe(2_592_000_000);
    expect(config.zapReceiptBatch).toBe(50);
  });

  test("environment overrides parse as integers and reject non-integers", () => {
    const config = loadConfig({
      ...REQUIRED,
      LNURL_INVOICE_EXPIRY_SECS: "600",
      LNURL_MAX_PENDING_INVOICES_PER_USER: "5",
      LNURL_MAX_PENDING_INVOICES: "500",
      LNURL_MAX_USERS: "42",
      LNURL_SETTLE_BATCH: "25",
      LNURL_PRUNE_EVERY_ROUNDS: "12",
      LNURL_SETTLED_RETENTION_MS: "1000",
      LNURL_ZAP_RECEIPT_BATCH: "7",
    });
    expect(config.invoiceExpirySecs).toBe(600);
    expect(config.maxPendingInvoicesPerUser).toBe(5);
    expect(config.maxPendingInvoices).toBe(500);
    expect(config.maxUsers).toBe(42);
    expect(config.settleBatch).toBe(25);
    expect(config.pruneEveryRounds).toBe(12);
    expect(config.settledRetentionMs).toBe(1000);
    expect(config.zapReceiptBatch).toBe(7);

    expect(() => loadConfig({ ...REQUIRED, LNURL_MAX_PENDING_INVOICES: "lots" })).toThrow(
      /LNURL_MAX_PENDING_INVOICES/u,
    );
    expect(() => loadConfig({ ...REQUIRED, LNURL_INVOICE_EXPIRY_SECS: "0" })).toThrow(
      /LNURL_INVOICE_EXPIRY_SECS/u,
    );
  });
});
