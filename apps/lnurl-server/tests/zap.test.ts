import { createHash } from "node:crypto";

import { describe, expect, test } from "vite-plus/test";

import type { Event, Pool, PoolPublishResult } from "@qntx/nostr";
import { Keys, finalizeEvent, hexToBytes, isHex32, verifyEvent } from "@qntx/nostr";
import { makeZapRequest, validateZapReceipt } from "@qntx/nostr/nips/nip57";
import type { LightningAddressInvoice } from "@qntx/spark/server";

import { encodeTestBolt11 } from "../../../packages/spark/tests/support/bolt11.ts";
import { createLnurlStore } from "../src/store.ts";
import {
  MAX_NOSTR_EVENT_SIZE,
  ZAP_RECEIPT_KIND,
  ZAP_REQUEST_KIND,
  buildZapReceipt,
  publishZapReceipts,
  validateZapRequest,
} from "../src/zap.ts";

const RECEIPT_KEYS = Keys.generate();
const ZAPPER = Keys.generate();
const TARGET = "ab".repeat(32);
const RELAY = "wss://relay.example";
const AMOUNT_MSAT = 21_000;
const NOW = 1_700_000_000_000;

function zapRequestJson(tags: string[][]): string {
  const event = finalizeEvent(
    { kind: ZAP_REQUEST_KIND, content: "", tags, created_at: NOW / 1000 },
    ZAPPER,
  );
  return JSON.stringify(event);
}

function validTags(extra: string[][] = []): string[][] {
  return [["p", TARGET], ["relays", RELAY], ["amount", String(AMOUNT_MSAT)], ...extra];
}

function expectInvalidJson(json: string): void {
  validateZapRequest(json, AMOUNT_MSAT, RECEIPT_KEYS.publicKey);
}

describe("validateZapRequest", () => {
  test("a well-formed request validates", () => {
    expect(() =>
      validateZapRequest(zapRequestJson(validTags()), AMOUNT_MSAT, RECEIPT_KEYS.publicKey),
    ).not.toThrow();
  });

  test("makeZapRequest output validates", () => {
    const template = makeZapRequest({
      pubkey: TARGET,
      amount: AMOUNT_MSAT,
      relays: [RELAY],
    });
    const event = finalizeEvent(template, ZAPPER);
    expect(() =>
      validateZapRequest(JSON.stringify(event), AMOUNT_MSAT, RECEIPT_KEYS.publicKey),
    ).not.toThrow();
  });

  test.each([
    ["not JSON", "{"],
    [
      "wrong kind",
      JSON.stringify(
        finalizeEvent({ kind: 1, content: "", tags: [], created_at: NOW / 1000 }, ZAPPER),
      ),
    ],
    ["empty tags", zapRequestJson([])],
    ["no p tag", zapRequestJson([["relays", RELAY]])],
    ["two p tags", zapRequestJson([...validTags(), ["p", TARGET]])],
    [
      "p not a pubkey",
      zapRequestJson([
        ["p", "xyz"],
        ["relays", RELAY],
      ]),
    ],
    [
      "two e tags",
      zapRequestJson([...validTags(), ["e", "ab".repeat(32)], ["e", "cd".repeat(32)]]),
    ],
    [
      "two a tags",
      zapRequestJson([...validTags(), ["a", `30023:${TARGET}:x`], ["a", `30023:${TARGET}:y`]]),
    ],
    ["no relays tag", zapRequestJson([["p", TARGET]])],
    [
      "amount mismatch",
      zapRequestJson([
        ["p", TARGET],
        ["relays", RELAY],
        ["amount", String(AMOUNT_MSAT + 1)],
      ]),
    ],
    ["P pinned to another key", zapRequestJson([...validTags(), ["P", Keys.generate().publicKey]])],
    [
      "two P tags",
      zapRequestJson([
        ...validTags(),
        ["P", RECEIPT_KEYS.publicKey],
        ["P", RECEIPT_KEYS.publicKey],
      ]),
    ],
    ["oversized", "x".repeat(MAX_NOSTR_EVENT_SIZE + 1)],
  ])("rejects: %s", (_name, json) => {
    expect(() => expectInvalidJson(json)).toThrow(/invalid nostr event/u);
  });

  test("rejects a tampered signature", () => {
    const event = JSON.parse(zapRequestJson(validTags())) as Event;
    expect(() => expectInvalidJson(JSON.stringify({ ...event, content: "tampered" }))).toThrow(
      /invalid nostr event/u,
    );
  });

  test("accepts a P tag pinning the receipt signer and no amount tag", () => {
    const json = zapRequestJson([
      ["p", TARGET],
      ["relays", RELAY],
      ["P", RECEIPT_KEYS.publicKey],
    ]);
    expect(() => validateZapRequest(json, AMOUNT_MSAT, RECEIPT_KEYS.publicKey)).not.toThrow();
  });
});

const INVOICE_SECRET = hexToBytes("11".repeat(32));

function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

/** A real BOLT-11 invoice committing to the zap request's description hash. */
function invoiceFor(zapJson: string, preimage: Uint8Array): string {
  return encodeTestBolt11({
    network: "regtest",
    amountMsat: BigInt(AMOUNT_MSAT),
    paymentHash: sha256(preimage),
    descriptionHash: sha256(new TextEncoder().encode(zapJson)),
    secretKey: INVOICE_SECRET,
  });
}

describe("buildZapReceipt", () => {
  test("builds a validating kind-9735 receipt", () => {
    const zapJson = zapRequestJson([
      ...validTags(),
      ["e", "cd".repeat(32)],
      ["a", `30023:${TARGET}:article`],
    ]);
    const pr = invoiceFor(zapJson, hexToBytes("ee".repeat(32)));
    const { event, relays } = buildZapReceipt({
      zapRequestJson: zapJson,
      invoice: pr,
      preimageHex: "ee".repeat(32),
      keys: RECEIPT_KEYS,
      now: NOW,
    });

    expect(event.kind).toBe(ZAP_RECEIPT_KIND);
    expect(event.content).toBe("");
    expect(isHex32(event.id)).toBe(true);
    expect(verifyEvent(event)).toBe(true);
    expect(relays).toStrictEqual([RELAY]);

    const names = event.tags.map((tag) => tag[0]);
    for (const required of ["p", "P", "e", "a", "bolt11", "description", "preimage"]) {
      expect(names).toContain(required);
    }
    expect(event.tags.find((t) => t[0] === "P")?.[1]).toBe(ZAPPER.publicKey);
    expect(event.tags.find((t) => t[0] === "bolt11")?.[1]).toBe(pr);
    expect(event.tags.find((t) => t[0] === "description")?.[1]).toBe(zapJson);
    expect(event.tags.find((t) => t[0] === "preimage")?.[1]).toBe("ee".repeat(32));

    // The library's own receipt validator accepts it against the advertised nostrPubkey.
    const validation = validateZapReceipt(event, { nostrPubkey: RECEIPT_KEYS.publicKey });
    expect(validation.valid).toBe(true);
  });

  test("keeps public wss relays on port 443, explicit or implied", () => {
    const accepted = [
      "wss://relay.example",
      "wss://relay.example:443/path",
      "wss://8.8.8.8",
      "wss://172.32.0.1", // just outside 172.16/12
      "wss://100.128.0.1", // just outside 100.64/10
      "wss://198.20.0.1", // just outside 198.18/15
      "wss://223.255.255.255", // just below 224/4
    ];
    const zapJson = zapRequestJson([
      ["p", TARGET],
      ["relays", ...accepted],
    ]);
    const { relays } = buildZapReceipt({
      zapRequestJson: zapJson,
      invoice: "lnbcrt1...",
      preimageHex: "ee".repeat(32),
      keys: RECEIPT_KEYS,
      now: NOW,
    });
    expect(relays).toStrictEqual(accepted);
  });

  test.each([
    ["ws scheme", "ws://relay.example"],
    ["http scheme", "http://relay.example"],
    ["not a URL", "not a relay"],
    ["localhost", "wss://localhost"],
    ["*.localhost", "wss://foo.localhost"],
    ["localhost with a trailing dot", "wss://localhost."],
    ["IPv6 loopback", "wss://[::1]"],
    ["IPv6 link-local", "wss://[fe80::1]"],
    ["non-443 port", "wss://relay.example:7777"],
    ["non-443 port on a literal", "wss://8.8.8.8:53"],
    ["0.0.0.0/8", "wss://0.12.34.56"],
    ["10/8", "wss://10.0.0.1"],
    ["100.64/10", "wss://100.64.0.1"],
    ["127/8", "wss://127.0.0.1"],
    ["integer-form loopback", "wss://2130706433"],
    ["short-form loopback", "wss://127.1"],
    ["169.254/16", "wss://169.254.0.1"],
    ["172.16/12", "wss://172.16.0.1"],
    ["192.168/16", "wss://192.168.1.1"],
    ["192.0.0/24 IETF", "wss://192.0.0.1"],
    ["192.0.2/24 TEST-NET-1", "wss://192.0.2.1"],
    ["192.88.99/24 6to4 relay", "wss://192.88.99.1"],
    ["198.18/15", "wss://198.19.255.1"],
    ["198.51.100/24 TEST-NET-2", "wss://198.51.100.1"],
    ["203.0.113/24 TEST-NET-3", "wss://203.0.113.1"],
    ["224/4 multicast", "wss://224.0.0.1"],
    ["240/4 reserved", "wss://255.255.255.255"],
  ])("drops the relay: %s", (_name, url) => {
    const zapJson = zapRequestJson([
      ["p", TARGET],
      ["relays", url],
    ]);
    const { relays } = buildZapReceipt({
      zapRequestJson: zapJson,
      invoice: "lnbcrt1...",
      preimageHex: "ee".repeat(32),
      keys: RECEIPT_KEYS,
      now: NOW,
    });
    expect(relays).toStrictEqual([]);
  });

  test("caps accepted relays at 10", () => {
    const many = Array.from({ length: 14 }, (_, i) => `wss://r${i}.example`);
    const zapJson = zapRequestJson([
      ["p", TARGET],
      ["relays", "https://not-a-relay.example", "wss://good.example", ...many],
    ]);
    const { relays } = buildZapReceipt({
      zapRequestJson: zapJson,
      invoice: "lnbcrt1...",
      preimageHex: "ee".repeat(32),
      keys: RECEIPT_KEYS,
      now: NOW,
    });
    expect(relays).toHaveLength(10);
    expect(relays[0]).toBe("wss://good.example");
    expect(relays.every((r) => r.startsWith("wss://"))).toBe(true);
  });
});

describe("publishZapReceipts", () => {
  function settledInvoice(
    overrides: Omit<Partial<LightningAddressInvoice>, "zapRequest"> & {
      readonly zapRequest?: string | undefined;
    } = {},
  ): LightningAddressInvoice {
    return {
      paymentHash: "ab".repeat(32),
      requestId: "req-1",
      name: "alice",
      pubkeyHex: "aa".repeat(33),
      invoice: "lnbcrt1...",
      expiresAtMs: NOW + 600_000,
      preimageHex: "ee".repeat(32),
      zapRequest: zapRequestJson(validTags()),
      ...overrides,
    } as LightningAddressInvoice;
  }

  function poolOf(results: PoolPublishResult[]): {
    pool: Pool;
    calls: Array<ReadonlyArray<string>>;
  } {
    const calls: Array<ReadonlyArray<string>> = [];
    const pool = {
      publish: async (relays: ReadonlyArray<string>) => {
        calls.push([...relays]);
        await Promise.resolve();
        return results;
      },
    } as unknown as Pool;
    return { calls, pool };
  }

  test("queues receipts for settled zap invoices and publishes them", async () => {
    const store = createLnurlStore(":memory:");
    const { pool, calls } = poolOf([{ url: RELAY, status: "ok", message: "" }]);
    await publishZapReceipts({
      store,
      keys: RECEIPT_KEYS,
      pool,
      settled: [
        settledInvoice(),
        settledInvoice({ paymentHash: "ff".repeat(32), zapRequest: undefined }),
      ],
      now: NOW,
    });
    expect(calls).toStrictEqual([[RELAY]]);
    const record = await store.zapReceipt("ab".repeat(32));
    expect(record?.published).toBe(true);
    await expect(store.zapReceipt("ff".repeat(32))).resolves.toBeUndefined();
    store.close();
  });

  test("a failed publish is retried on the next round, then capped", async () => {
    const store = createLnurlStore(":memory:");
    const { pool } = poolOf([{ url: RELAY, status: "rejected", message: "blocked" }]);
    const invoice = settledInvoice();
    await publishZapReceipts({ store, keys: RECEIPT_KEYS, pool, settled: [invoice], now: NOW });
    let record = await store.zapReceipt(invoice.paymentHash);
    expect(record?.published).toBe(false);
    expect(record?.attempts).toBe(1);

    // Next round: no newly settled invoices, the stored receipt retries.
    await publishZapReceipts({ store, keys: RECEIPT_KEYS, pool, settled: [], now: NOW });
    record = await store.zapReceipt(invoice.paymentHash);
    expect(record?.attempts).toBe(2);
    store.close();
  });

  test("a throwing publish records the failure", async () => {
    const store = createLnurlStore(":memory:");
    const pool = {
      publish: async () => {
        await Promise.resolve();
        throw new Error("ws down");
      },
    } as unknown as Pool;
    await publishZapReceipts({
      store,
      keys: RECEIPT_KEYS,
      pool,
      settled: [settledInvoice()],
      now: NOW,
    });
    const record = await store.zapReceipt("ab".repeat(32));
    expect(record?.attempts).toBe(1);
    expect(record?.lastError).toContain("ws down");
    store.close();
  });
});
