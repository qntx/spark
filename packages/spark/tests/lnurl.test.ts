import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { bech32 } from "@scure/base";
import { expect, test } from "vite-plus/test";

import { SparkInputError } from "../src/errors/index.ts";
import {
  decodeLnurl,
  encodeLnurl,
  lightningAddressUrl,
  lnurlGetJson,
  lnurlSendJson,
  parseLnurlPayRequest,
  parseLnurlWithdrawRequest,
  parseSuccessAction,
  requestInvoice,
  resolveLnurl,
  submitWithdraw,
} from "../src/lnurl/index.ts";
import type { LnurlPayRequest, LnurlWithdrawRequest } from "../src/lnurl/index.ts";
import { formatLnurlUrl, parseLnurlUrl, withQuery } from "../src/lnurl/url.ts";

type JsonObject = Record<string, unknown>;

const LNURL_EXAMPLE_URL =
  "https://service.com/api?q=3fc3645b439ce8e7f2553a69e5267081d96dcd340693afabe04be7b0ccd178df";
const LNURL_EXAMPLE =
  "LNURL1DP68GURN8GHJ7UM9WFMXJCM99E3K7MF0V9CXJ0M385EKVCENXC6R2C35XVUKXEFCV5MKVV34X5EKZD3EV56NYD3HXQURZEPEXEJXXEPNXSCRVWFNV9NXZCN9XQ6XYEFHVGCXXCMYXYMNSERXFQ5FNS";

function fetchJson(body: JsonObject): typeof globalThis.fetch {
  return async () => Promise.resolve(Response.json(body));
}

function fetchHandler(handler: (url: string) => JsonObject): typeof globalThis.fetch {
  return async (input) => Promise.resolve(Response.json(handler(String(input))));
}

function fetchStatus(status: number): typeof globalThis.fetch {
  return async () => Promise.resolve(Response.json({}, { status }));
}

function fetchText(body: string): typeof globalThis.fetch {
  return async () => Promise.resolve(new Response(body));
}

test("lnurlGetJson rejects a declared Content-Length over 256 KiB before reading", async () => {
  let read = false;
  const body = {
    ok: true,
    headers: new Headers({ "content-length": String(300 * 1024) }),
    text: async () => {
      read = true;
      return Promise.resolve("{}");
    },
  } as Response;
  const fetch: typeof globalThis.fetch = async () => Promise.resolve(body);
  await expect(lnurlGetJson("https://service.com/x", fetch)).rejects.toThrow(
    "body exceeds 256 KiB",
  );
  expect(read).toBe(false);
});

test("lnurlGetJson rejects an oversized body without a Content-Length after reading", async () => {
  const big = `{ "data": "${"x".repeat(300 * 1024)}" }`;
  await expect(lnurlGetJson("https://service.com/x", fetchText(big))).rejects.toThrow(
    "body exceeds 256 KiB",
  );
});

test("lnurlSendJson enforces the same response bound on both paths", async () => {
  const declared: typeof globalThis.fetch = async () =>
    Promise.resolve(new Response("{}", { headers: { "content-length": String(300 * 1024) } }));
  await expect(
    lnurlSendJson("https://service.com/x", declared, { method: "POST", body: {} }),
  ).rejects.toThrow("body exceeds 256 KiB");
  const big = `{ "data": "${"x".repeat(300 * 1024)}" }`;
  await expect(
    lnurlSendJson("https://service.com/x", fetchText(big), { method: "POST", body: {} }),
  ).rejects.toThrow("body exceeds 256 KiB");
});

// --- test-only BOLT-11 encoder ------------------------------------------------

const INVOICE_KEY = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const PAYMENT_HASH = Uint8Array.from({ length: 32 }, () => 0xaa);
const PAYMENT_SECRET = Uint8Array.from({ length: 32 }, () => 0xbb);
const TIMESTAMP = 1_700_000_000;

function intToWords(value: number, count: number): number[] {
  const words = Array.from({ length: count }, () => 0);
  let rest = value;
  for (let i = count - 1; i >= 0; i--) {
    words[i] = rest % 32;
    rest = Math.floor(rest / 32);
  }
  return words;
}

function wordsToBytesPadded(words: ReadonlyArray<number>): Uint8Array {
  const out = new Uint8Array(Math.ceil((words.length * 5) / 8));
  let acc = 0;
  let bits = 0;
  let index = 0;
  for (const word of words) {
    acc = ((acc << 5) | word) & 0xffffffff;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out[index] = (acc >>> bits) & 0xff;
      index++;
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) {
    out[index] = (acc << (8 - bits)) & 0xff;
  }
  return out;
}

function tagField(tag: number, bytes: Uint8Array): number[] {
  const words = [...bech32.toWords(bytes)];
  return [tag, words.length >> 5, words.length & 31, ...words];
}

function descriptionWords(description: string | undefined): number[] {
  if (description === undefined) {
    return [];
  }
  return tagField(13, utf8ToBytes(description));
}

function descriptionHashWords(descriptionHash: Uint8Array | undefined): number[] {
  if (descriptionHash === undefined) {
    return [];
  }
  return tagField(23, descriptionHash);
}

function signedInvoice(options: {
  network?: "lnbc" | "lnbcrt" | undefined;
  amountMsat?: number | undefined;
  descriptionHash?: Uint8Array | undefined;
  description?: string | undefined;
}): string {
  const prefix = options.network ?? "lnbc";
  let hrp: string = prefix;
  if (options.amountMsat !== undefined) {
    hrp = `${prefix}${options.amountMsat * 10}p`;
  }
  const tagged = [
    ...intToWords(TIMESTAMP, 7),
    ...tagField(1, PAYMENT_HASH),
    ...descriptionWords(options.description),
    ...descriptionHashWords(options.descriptionHash),
    ...tagField(16, PAYMENT_SECRET),
  ];
  const preimage = concatBytes(utf8ToBytes(hrp), wordsToBytesPadded(tagged));
  const signature = secp256k1.sign(sha256(preimage), INVOICE_KEY, {
    format: "recovered",
    prehash: false,
    lowS: true,
  });
  const sigBytes = new Uint8Array(65);
  sigBytes.set(signature.subarray(1));
  sigBytes[64] = signature[0]!;
  return bech32.encode(hrp, [...tagged, ...bech32.toWords(sigBytes)], false);
}

const METADATA = '[["text/plain","pay coffee"],["text/identifier","user@service.com"]]';
const METADATA_HASH = sha256(utf8ToBytes(METADATA));

function payBody(overrides?: JsonObject): JsonObject {
  return {
    tag: "payRequest",
    callback: "https://service.com/callback",
    minSendable: 1000,
    maxSendable: 10_000_000,
    metadata: METADATA,
    ...overrides,
  };
}

function payRequest(overrides?: JsonObject): LnurlPayRequest {
  return parseLnurlPayRequest(payBody(overrides));
}

function goodInvoice(amountMsat: number, network?: "lnbc" | "lnbcrt"): string {
  return signedInvoice({ amountMsat, descriptionHash: METADATA_HASH, network });
}

// --- LUD-01 codec ---------------------------------------------------------------

test("decodes the LUD-01 spec example", () => {
  expect(decodeLnurl(LNURL_EXAMPLE)).toBe(LNURL_EXAMPLE_URL);
});

test("decodes a lowercase lnurl with lightning: prefix", () => {
  expect(decodeLnurl(`lightning:${LNURL_EXAMPLE.toLowerCase()}`)).toBe(LNURL_EXAMPLE_URL);
});

test("encodeLnurl reproduces the spec example", () => {
  expect(encodeLnurl(LNURL_EXAMPLE_URL)).toBe(LNURL_EXAMPLE.toLowerCase());
});

test("rejects mixed case, wrong hrp and clearnet http", () => {
  expect(() => decodeLnurl("LnURL1DP68Gurn8ghj7")).toThrow(SparkInputError);
  expect(() => decodeLnurl(encodeLnurl(LNURL_EXAMPLE_URL).replace("lnurl", "bc"))).toThrow(
    SparkInputError,
  );
  const http = bech32.encode("lnurl", bech32.toWords(utf8ToBytes("http://service.com/x")), false);
  expect(() => decodeLnurl(http)).toThrow(SparkInputError);
});

test("accepts http to an .onion host", () => {
  const onion = bech32.encode(
    "lnurl",
    bech32.toWords(utf8ToBytes("http://abc123def456.onion/api")),
    false,
  );
  expect(decodeLnurl(onion)).toBe("http://abc123def456.onion/api");
});

// --- LUD-16 lightning addresses ---------------------------------------------------

test("maps lightning addresses to well-known endpoints", () => {
  expect(lightningAddressUrl("satoshi@bitcoin.org")).toBe(
    "https://bitcoin.org/.well-known/lnurlp/satoshi",
  );
  expect(lightningAddressUrl("USER+tag@Bitcoin.ORG")).toBe(
    "https://bitcoin.org/.well-known/lnurlp/user+tag",
  );
  expect(lightningAddressUrl("@bitcoin.org")).toBe("https://bitcoin.org/.well-known/lnurlp/_");
  expect(lightningAddressUrl("u@abc123.onion")).toBe("http://abc123.onion/.well-known/lnurlp/u");
});

test("rejects malformed lightning addresses", () => {
  expect(() => lightningAddressUrl("no-at-sign")).toThrow(SparkInputError);
  expect(() => lightningAddressUrl("bad!name@x.com")).toThrow(SparkInputError);
  expect(() => lightningAddressUrl("u@x.com:8080")).toThrow(SparkInputError);
  expect(() => lightningAddressUrl("u@")).toThrow(SparkInputError);
  expect(() => lightningAddressUrl("u@x.com/path")).toThrow(SparkInputError);
});

// --- strict URL parser ----------------------------------------------------------

test("parses https and http urls with ports, paths, queries and IPv4 hosts", () => {
  expect(parseLnurlUrl("https://service.com/a/b?x=1")).toStrictEqual({
    scheme: "https",
    host: "service.com",
    path: "/a/b",
    query: "x=1",
  });
  expect(parseLnurlUrl("http://abc.onion:8080/x")).toStrictEqual({
    scheme: "http",
    host: "abc.onion",
    port: 8080,
    path: "/x",
    query: "",
  });
  expect(parseLnurlUrl("https://1.2.3.4")).toStrictEqual({
    scheme: "https",
    host: "1.2.3.4",
    path: "/",
    query: "",
  });
});

test("normalizes the scheme and host case, drops fragments", () => {
  expect(formatLnurlUrl(parseLnurlUrl("HTTPS://Service.COM/p?x#frag"))).toBe(
    "https://service.com/p?x",
  );
});

test("rejects non-http schemes, userinfo, bad hosts and IPv6", () => {
  const bad = [
    "ftp://service.com/",
    "https://user:pw@service.com/",
    "https://-bad.com/",
    "https://bad-.com/",
    "https://service.com:99999/",
    "https://service.com:abc/",
    "https:///nohost",
    "https://servi ce.com/",
    "https://[::1]/",
    "not a url",
    `https://${"a.".repeat(140)}com/`,
  ];
  for (const url of bad) {
    expect(() => parseLnurlUrl(url)).toThrow(SparkInputError);
  }
});

test("rejects non-canonical IPv4 host forms that WHATWG would reinterpret", () => {
  const bad = [
    "https://2130706433/",
    "https://0x7f.0.0.1/",
    "https://127.1/",
    "https://10.0x0.1/",
    "https://01.2.3.4/",
    "https://256.1.1.1/",
    "https://1.2.3.4.5/",
  ];
  for (const url of bad) {
    expect(() => parseLnurlUrl(url)).toThrow(SparkInputError);
  }
});

test("accepts dotted-quad IPv4 and numeric-looking DNS hosts", () => {
  const good = [
    "https://1.2.3.4/",
    "https://0.0.0.0/",
    "https://255.255.255.255/",
    "https://example.com/",
    "https://1a.example.com/",
    // Last label is not an IPv4 number, so WHATWG keeps these as DNS names too.
    "https://x.123abc/",
    "https://x.123/",
    "https://1.2.3.08/",
  ];
  for (const url of good) {
    expect(() => parseLnurlUrl(url)).not.toThrow();
  }
});

test("withQuery appends encoded params and preserves the existing query", () => {
  const callback = withQuery("https://service.com/cb?session=42#frag", [
    ["amount", "5000"],
    ["comment", "hi there&all"],
  ]);
  expect(callback).toBe("https://service.com/cb?session=42&amount=5000&comment=hi%20there%26all");
});

// --- payRequest parsing ---------------------------------------------------------

test("parses a minimal payRequest", () => {
  const parsed = payRequest();
  expect(parsed.tag).toBe("payRequest");
  expect(parsed.callback).toBe("https://service.com/callback");
  expect(parsed.minSendableMsat).toBe(1000);
  expect(parsed.maxSendableMsat).toBe(10_000_000);
  expect(parsed.description).toBe("pay coffee");
  expect(parsed.commentAllowed).toBe(0);
  expect(parsed.allowsNostr).toBe(false);
  expect(parsed.nostrPubkey).toBeUndefined();
});

test("parses nostr support", () => {
  const pubkey = "11".repeat(32);
  const parsed = payRequest({ allowsNostr: true, nostrPubkey: pubkey });
  expect(parsed.allowsNostr).toBe(true);
  expect(parsed.nostrPubkey).toHaveLength(32);
});

test.each([
  ["wrong tag", { tag: "withdrawRequest" }],
  ["callback not a URL", { callback: "not a url" }],
  ["clearnet http callback", { callback: "http://service.com/cb" }],
  ["minSendable below 1", { minSendable: 0 }],
  ["minSendable above maxSendable", { minSendable: 10_000_001 }],
  ["minSendable not an integer", { minSendable: 1.5 }],
  ["missing minSendable", { minSendable: undefined }],
  ["metadata not JSON", { metadata: "not json" }],
  ["metadata not an array", { metadata: "{}" }],
  ["metadata entry not an array", { metadata: '[["text/plain","x"],"oops"]' }],
  ["no text/plain", { metadata: '[["text/identifier","u@d"]]' }],
  ["two text/plain", { metadata: '[["text/plain","a"],["text/plain","b"]]' }],
  ["text/plain not a string", { metadata: '[["text/plain",1]]' }],
  ["negative commentAllowed", { commentAllowed: -1 }],
  ["allowsNostr without pubkey", { allowsNostr: true }],
  ["short nostrPubkey", { allowsNostr: true, nostrPubkey: "abcd" }],
])("rejects %s", (_title, overrides) => {
  expect(() => payRequest(overrides)).toThrow(SparkInputError);
});

// --- requestInvoice -------------------------------------------------------------

const REQUEST = payRequest({ commentAllowed: 32 });

function invoiceResponse(amountMsat: number, invoice?: string): JsonObject {
  return { pr: invoice ?? goodInvoice(amountMsat), routes: [] };
}

test("requests an invoice and verifies amount, network and description hash", async () => {
  const calls: string[] = [];
  const fetch = fetchHandler((url) => {
    calls.push(url);
    return invoiceResponse(5000);
  });
  const request = payRequest({ callback: "https://service.com/callback?session=abc" });
  const result = await requestInvoice(request, {
    fetch,
    network: "mainnet",
    amountMsat: 5000,
  });
  expect(result.invoice.startsWith("lnbc")).toBe(true);
  expect(result.decoded.amountMsat).toBe(5000n);
  const called = new URL(calls[0]!);
  expect(called.searchParams.get("session")).toBe("abc");
  expect(called.searchParams.get("amount")).toBe("5000");
});

test("appends the comment param", async () => {
  const calls: string[] = [];
  const fetch = fetchHandler((url) => {
    calls.push(url);
    return invoiceResponse(5000);
  });
  await requestInvoice(REQUEST, {
    fetch,
    network: "mainnet",
    amountMsat: 5000,
    comment: "hi there",
  });
  expect(new URL(calls[0]!).searchParams.get("comment")).toBe("hi there");
});

const ZAP_EVENT = '{"kind":9734,"content":"zap"}';
const ZAP_HASH = sha256(utf8ToBytes(ZAP_EVENT));

function zapInvoiceResponse(url: string): JsonObject {
  const params = new URL(url).searchParams;
  const zap = params.get("nostr")!;
  return {
    pr: signedInvoice({ amountMsat: Number(params.get("amount")), descriptionHash: ZAP_HASH }),
    routes: [],
    zap,
  };
}

test("sends the nostr zap request and hashes it alone", async () => {
  const calls: string[] = [];
  const fetch = fetchHandler((url) => {
    calls.push(url);
    return zapInvoiceResponse(url);
  });
  const request = payRequest({
    allowsNostr: true,
    nostrPubkey: "22".repeat(32),
  });
  const result = await requestInvoice(request, {
    fetch,
    network: "mainnet",
    amountMsat: 5000,
    zapRequest: ZAP_EVENT,
  });
  expect(new URL(calls[0]!).searchParams.get("nostr")).toBe(ZAP_EVENT);
  expect(result.decoded.descriptionHash).toStrictEqual(ZAP_HASH);
});

test("rejects amount outside the sendable bounds", async () => {
  const fetch = fetchJson({});
  await expect(
    requestInvoice(REQUEST, { fetch, network: "mainnet", amountMsat: 999 }),
  ).rejects.toThrow(SparkInputError);
  await expect(
    requestInvoice(REQUEST, { fetch, network: "mainnet", amountMsat: 10_000_001 }),
  ).rejects.toThrow(SparkInputError);
});

test("enforces the comment rules", async () => {
  const plain = payRequest();
  const fetch = fetchJson({});
  await expect(
    requestInvoice(plain, { fetch, network: "mainnet", amountMsat: 1000, comment: "x" }),
  ).rejects.toThrow(SparkInputError);
  const longComment = "x".repeat(33);
  await expect(
    requestInvoice(REQUEST, {
      fetch,
      network: "mainnet",
      amountMsat: 1000,
      comment: longComment,
    }),
  ).rejects.toThrow(SparkInputError);
});

test("rejects a zap request when the service does not allow nostr", async () => {
  await expect(
    requestInvoice(REQUEST, {
      fetch: fetchJson({}),
      network: "mainnet",
      amountMsat: 1000,
      zapRequest: "{}",
    }),
  ).rejects.toThrow(SparkInputError);
});

test("rejects amount, network and description-hash mismatches", async () => {
  const mismatchAmount = fetchJson(invoiceResponse(5000, goodInvoice(6000)));
  await expect(
    requestInvoice(REQUEST, { fetch: mismatchAmount, network: "mainnet", amountMsat: 5000 }),
  ).rejects.toThrow(SparkInputError);

  const wrongNetwork = fetchJson(
    invoiceResponse(
      5000,
      signedInvoice({ amountMsat: 5000, descriptionHash: METADATA_HASH, network: "lnbcrt" }),
    ),
  );
  await expect(
    requestInvoice(REQUEST, { fetch: wrongNetwork, network: "mainnet", amountMsat: 5000 }),
  ).rejects.toThrow(SparkInputError);

  const wrongHash = fetchJson(
    invoiceResponse(
      5000,
      signedInvoice({ amountMsat: 5000, descriptionHash: sha256(utf8ToBytes("x")) }),
    ),
  );
  await expect(
    requestInvoice(REQUEST, { fetch: wrongHash, network: "mainnet", amountMsat: 5000 }),
  ).rejects.toThrow(SparkInputError);
});

test("rejects an invoice without a description hash", async () => {
  const fetch = fetchJson(
    invoiceResponse(5000, signedInvoice({ amountMsat: 5000, description: "x" })),
  );
  await expect(
    requestInvoice(REQUEST, { fetch, network: "mainnet", amountMsat: 5000 }),
  ).rejects.toThrow(SparkInputError);
});

test("maps service ERROR bodies to lnurl_error", async () => {
  const fetch = fetchJson({ status: "ERROR", reason: "daily limit reached" });
  await expect(
    requestInvoice(REQUEST, { fetch, network: "mainnet", amountMsat: 5000 }),
  ).rejects.toMatchObject({ name: "SparkRequestError", code: "lnurl_error" });
  await expect(
    requestInvoice(REQUEST, { fetch, network: "mainnet", amountMsat: 5000 }),
  ).rejects.toThrow("daily limit reached");
});

test("strips control characters and truncates server error reasons", async () => {
  const reason = `forged\nfake-log-line\u0007 ${"x".repeat(300)}`;
  const fetch = fetchJson({ status: "ERROR", reason });
  const thrown = await requestInvoice(REQUEST, {
    fetch,
    network: "mainnet",
    amountMsat: 5000,
  }).then(
    () => {
      throw new Error("expected rejection");
    },
    (error: unknown) => error,
  );
  const { message } = thrown as Error;
  expect(message).not.toContain("\n");
  expect(message).not.toContain("\u0007");
  expect(message).toContain("forgedfake-log-line");
  expect(message.length).toBeLessThanOrEqual("lnurl error: ".length + 256 + 1);
});

test("works without the WHATWG URL global (React Native polyfill)", async () => {
  const original = globalThis.URL;
  delete (globalThis as { URL?: unknown }).URL;
  try {
    const result = await requestInvoice(REQUEST, {
      fetch: fetchJson(invoiceResponse(5000)),
      network: "mainnet",
      amountMsat: 5000,
    });
    expect(result.decoded.amountMsat).toBe(5000n);
  } finally {
    globalThis.URL = original;
  }
});

// --- successAction (LUD-09/10) ----------------------------------------------------

test("parses every successAction tag", async () => {
  const message = await requestInvoice(REQUEST, {
    fetch: fetchJson({
      pr: goodInvoice(5000),
      routes: [],
      successAction: { tag: "message", message: "thanks" },
    }),
    network: "mainnet",
    amountMsat: 5000,
  });
  expect(message.successAction!.tag).toBe("message");
  const url = await requestInvoice(REQUEST, {
    fetch: fetchJson({
      pr: goodInvoice(5000),
      routes: [],
      successAction: { tag: "url", description: "order", url: "https://service.com/order/1" },
    }),
    network: "mainnet",
    amountMsat: 5000,
  });
  expect(url.successAction!.tag).toBe("url");
  const aes = await requestInvoice(REQUEST, {
    fetch: fetchJson({
      pr: goodInvoice(5000),
      routes: [],
      successAction: { tag: "aes", description: "secret", ciphertext: "AA==", iv: "BB==" },
    }),
    network: "mainnet",
    amountMsat: 5000,
  });
  expect(aes.successAction!.tag).toBe("aes");
});

test("rejects malformed successActions", () => {
  expect(() => parseSuccessAction({ tag: "message", message: "x".repeat(145) }, "h")).toThrow(
    SparkInputError,
  );
  expect(() =>
    parseSuccessAction({ tag: "url", description: "d", url: "https://other.com/x" }, "service.com"),
  ).toThrow(SparkInputError);
  expect(() => parseSuccessAction({ tag: "fax" }, "h")).toThrow(SparkInputError);
});

// --- withdrawRequest (LUD-03) -------------------------------------------------------

function withdrawBody(overrides?: JsonObject): JsonObject {
  return {
    tag: "withdrawRequest",
    callback: "https://service.com/withdraw",
    k1: "abc123",
    defaultDescription: "withdraw",
    minWithdrawable: 0,
    maxWithdrawable: 5000,
    ...overrides,
  };
}

function withdrawRequest(overrides?: JsonObject): LnurlWithdrawRequest {
  return parseLnurlWithdrawRequest(withdrawBody(overrides));
}

test("parses a withdrawRequest including a zero balance", () => {
  const parsed = withdrawRequest();
  expect(parsed.k1).toBe("abc123");
  expect(parsed.minWithdrawableMsat).toBe(0);
  expect(parsed.maxWithdrawableMsat).toBe(5000);
  const zero = withdrawRequest({ minWithdrawable: 0, maxWithdrawable: 0 });
  expect(zero.maxWithdrawableMsat).toBe(0);
});

test.each([
  ["wrong tag", { tag: "payRequest" }],
  ["missing k1", { k1: undefined }],
  ["callback not a URL", { callback: "nope" }],
  ["min above max", { minWithdrawable: 6000 }],
  ["negative max", { maxWithdrawable: -1 }],
])("rejects %s", (_title, overrides) => {
  expect(() => withdrawRequest(overrides)).toThrow(SparkInputError);
});

test("submits the invoice with k1 and pr", async () => {
  const calls: string[] = [];
  const fetch = fetchHandler((url) => {
    calls.push(url);
    return { status: "OK" };
  });
  await submitWithdraw(withdrawRequest(), { fetch, invoice: "lnbc100p1x" });
  const called = new URL(calls[0]!);
  expect(called.searchParams.get("k1")).toBe("abc123");
  expect(called.searchParams.get("pr")).toBe("lnbc100p1x");
});

test("maps withdraw failures", async () => {
  await expect(
    submitWithdraw(withdrawRequest(), {
      fetch: fetchJson({ status: "ERROR", reason: "spent" }),
      invoice: "lnbc1x",
    }),
  ).rejects.toMatchObject({ code: "lnurl_error" });
  await expect(
    submitWithdraw(withdrawRequest(), {
      fetch: fetchJson({ status: "OTHER" }),
      invoice: "lnbc1x",
    }),
  ).rejects.toMatchObject({ code: "unexpected_response" });
});

// --- resolveLnurl -------------------------------------------------------------------

test("resolves an lnurl string, an address and a bare https url", async () => {
  const fetch = fetchJson(payBody());
  const viaLnurl = await resolveLnurl(encodeLnurl("https://service.com/pay"), { fetch });
  expect(viaLnurl.tag).toBe("payRequest");
  const viaAddress = await resolveLnurl("user@service.com", { fetch });
  expect(viaAddress.tag).toBe("payRequest");
  const viaUrl = await resolveLnurl("https://service.com/pay", { fetch });
  expect(viaUrl.tag).toBe("payRequest");
  const withdraw = await resolveLnurl("https://service.com/w", {
    fetch: fetchJson(withdrawBody()),
  });
  expect(withdraw.tag).toBe("withdrawRequest");
});

test("rejects unsupported tags and bad transports", async () => {
  await expect(
    resolveLnurl("https://service.com/x", {
      fetch: fetchJson({ tag: "channelRequest" }),
    }),
  ).rejects.toThrow(SparkInputError);
  await expect(
    resolveLnurl("https://service.com/x", { fetch: fetchStatus(404) }),
  ).rejects.toMatchObject({ code: "http_404" });
  await expect(
    resolveLnurl("https://service.com/x", { fetch: fetchText("not json") }),
  ).rejects.toMatchObject({ code: "unexpected_response" });
});
