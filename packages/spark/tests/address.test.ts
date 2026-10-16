import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { hexToBytes } from "@noble/hashes/utils.js";
import { expect, test } from "vite-plus/test";

import { decodeSparkAddress, encodeSparkAddress } from "../src/core/address.ts";
import type { SparkAddress, SparkInvoiceFields } from "../src/core/address.ts";
import { SparkInputError } from "../src/errors/index.ts";

type VectorCase = {
  address: string;
  network: "mainnet" | "regtest";
  identityPublicKey: string;
  legacy?: boolean;
  self?: boolean;
  signature?: string;
  invoice?: {
    version: number;
    id: string;
    payment?:
      | { type: "sats"; amount?: number }
      | { type: "tokens"; tokenIdentifier?: string; amount?: string };
    memo?: string;
    senderPublicKey?: string;
    expiresAt?: number;
  };
};

const { cases } = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "../../../vectors/address.json"), "utf8"),
) as { cases: VectorCase[] };

function invoiceOf(v: NonNullable<VectorCase["invoice"]>): SparkInvoiceFields {
  const payment =
    v.payment?.type === "tokens"
      ? {
          type: "tokens" as const,
          tokenIdentifier:
            v.payment.tokenIdentifier === undefined
              ? undefined
              : hexToBytes(v.payment.tokenIdentifier),
          amount: v.payment.amount === undefined ? undefined : hexToBytes(v.payment.amount),
        }
      : v.payment?.type === "sats"
        ? { type: "sats" as const, amount: v.payment.amount }
        : undefined;
  return {
    version: v.version,
    id: v.id,
    payment,
    memo: v.memo,
    senderPublicKey: v.senderPublicKey === undefined ? undefined : hexToBytes(v.senderPublicKey),
    expiresAt: v.expiresAt,
  };
}

function addressOf(v: VectorCase): SparkAddress {
  return {
    network: v.network,
    identityPublicKey: hexToBytes(v.identityPublicKey),
    invoice: v.invoice === undefined ? undefined : invoiceOf(v.invoice),
    signature: v.signature === undefined ? undefined : hexToBytes(v.signature),
  };
}

const modern = cases.filter((v) => v.legacy !== true);
const legacy = cases
  .filter((v) => v.legacy === true)
  .map((v) => ({ v, hrp: v.network === "mainnet" ? "spark" : "sparkrt" }));

test.each(cases)("decodes %#", (v) => {
  expect(decodeSparkAddress(v.address)).toStrictEqual(addressOf(v));
});

test.each(modern)("re-encodes %# byte-exact", (v) => {
  expect(encodeSparkAddress(decodeSparkAddress(v.address))).toBe(v.address);
});

test.each(modern)("constructed %# encodes byte-exact", (v) => {
  expect(encodeSparkAddress(addressOf(v))).toBe(v.address);
});

test.each(legacy)("legacy %# re-encodes to the current HRP", ({ v, hrp }) => {
  const encoded = encodeSparkAddress(decodeSparkAddress(v.address));
  expect(encoded.slice(0, hrp.length + 1)).toBe(`${hrp}1`);
  expect(decodeSparkAddress(encoded)).toStrictEqual(decodeSparkAddress(v.address));
});

const selfCase = cases.find((c) => c.self === true);
if (selfCase === undefined) {
  throw new Error("address vectors: missing the self-constructed case");
}

test("round trip for sats and tokens", () => {
  const address = addressOf(selfCase);
  expect(decodeSparkAddress(encodeSparkAddress(address))).toStrictEqual(address);
});

test("malformed addresses throw SparkInputError", () => {
  expect(() => decodeSparkAddress("spark1invalid")).toThrow(SparkInputError);
  expect(() => decodeSparkAddress("not-an-address")).toThrow(SparkInputError);
  // testnet/local prefixes are not part of SparkNetwork
  expect(() =>
    decodeSparkAddress("sparkt1pgss9qu4tmmr9vmdx685wsg53dzapt0hum8p3sqqk625jvvqc49wegnst05852"),
  ).toThrow(SparkInputError);
  expect(() =>
    decodeSparkAddress("sparkl1pgss9qesd8kc9a00ql56lgm56aylsmygg90yahqxp8tmp7ltdhje98zwv6zmy8"),
  ).toThrow(SparkInputError);
});

test("validation rejects bad input on encode", () => {
  const key = hexToBytes("0353908bac090ba741de6147a540a665537006911590f93249b2823dbe187d3213");
  const good: SparkAddress = { network: "regtest", identityPublicKey: key };
  expect(encodeSparkAddress(good)).toBe(cases[0]!.address);

  expect(() =>
    encodeSparkAddress({ network: "regtest", identityPublicKey: new Uint8Array(32) }),
  ).toThrow(SparkInputError);
  expect(() =>
    encodeSparkAddress({ network: "regtest", identityPublicKey: new Uint8Array(33) }),
  ).toThrow(SparkInputError);
  expect(() => encodeSparkAddress({ ...good, signature: new Uint8Array(63) })).toThrow(
    SparkInputError,
  );

  const invoice = (extra: object): SparkInvoiceFields => ({
    version: 1,
    id: "01992fa6-dba4-7dc0-a39d-0f4f566cf82b",
    ...extra,
  });
  const encode = (inv: SparkInvoiceFields) => encodeSparkAddress({ ...good, invoice: inv });
  expect(() => encode(invoice({ version: 2 }))).toThrow(SparkInputError);
  expect(() => encode(invoice({ id: "not-a-uuid" }))).toThrow(SparkInputError);
  expect(() => encode(invoice({ memo: "x".repeat(121) }))).toThrow(SparkInputError);
  expect(() => encode(invoice({ senderPublicKey: new Uint8Array(33) }))).toThrow(SparkInputError);
  expect(() =>
    encode(invoice({ payment: { type: "sats", amount: 2_100_000_000_000_001 } })),
  ).toThrow(SparkInputError);
  expect(() => encode(invoice({ payment: { type: "sats", amount: 1.5 } }))).toThrow(
    SparkInputError,
  );
  expect(() =>
    encode(invoice({ payment: { type: "tokens", tokenIdentifier: new Uint8Array(31) } })),
  ).toThrow(SparkInputError);
  expect(() =>
    encode(invoice({ payment: { type: "tokens", amount: new Uint8Array(17) } })),
  ).toThrow(SparkInputError);
});
