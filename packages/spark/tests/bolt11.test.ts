import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";
import { expect, test } from "vite-plus/test";

import { decodeBolt11, isExpired } from "../src/core/bolt11.ts";
import { SparkInputError } from "../src/errors/index.ts";
import { encodeTestBolt11 } from "./support/bolt11.ts";

const vectors = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "../../../vectors/bolt11.json"), "utf8"),
) as { cases: Array<{ invoice: string; valid: boolean; title: string }> };

const cases = new Map(vectors.cases.map((c) => [c.title, c]));

function byTitle(fragment: string): string {
  for (const [title, c] of cases) {
    if (title.startsWith(fragment)) {
      return c.invoice;
    }
  }
  throw new Error(`vector not found: ${fragment}`);
}

test.each(vectors.cases.filter((entry) => entry.valid))("decodes valid case %#", (c) => {
  expect(() => decodeBolt11(c.invoice)).not.toThrow();
});

test.each(vectors.cases.filter((entry) => !entry.valid))("rejects invalid case %#", (c) => {
  expect(() => decodeBolt11(c.invoice)).toThrow(SparkInputError);
});

test("donation invoice: no amount, fields decoded", () => {
  const inv = decodeBolt11(byTitle("Please make a donation"));
  expect(inv.network).toBe("mainnet");
  expect(inv.amountMsat).toBeUndefined();
  expect(inv.timestamp).toBe(1496314658);
  expect(bytesToHex(inv.paymentHash)).toBe(
    "0001020304050607080900010203040506070809000102030405060708090102",
  );
  expect(bytesToHex(inv.paymentSecret)).toBe(
    "1111111111111111111111111111111111111111111111111111111111111111",
  );
  expect(inv.description).toBe("Please consider supporting this project");
  expect(inv.expirySeconds).toBe(3600);
  expect(inv.minFinalCltvExpiry).toBe(18);
  expect(bytesToHex(inv.payee)).toBe(
    "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad",
  );
});

test("2500u invoice: amount and expiry field", () => {
  const inv = decodeBolt11(byTitle("Please send $3 for a cup of coffee"));
  expect(inv.amountMsat).toBe(250_000_000n);
  expect(inv.description).toBe("1 cup coffee");
  expect(inv.expirySeconds).toBe(60);
});

test("utf-8 description", () => {
  const inv = decodeBolt11(byTitle("Please send 0.0025 BTC"));
  expect(inv.description).toBe("ナンセンス 1杯");
});

test("hashed description invoice has descriptionHash, no d", () => {
  const inv = decodeBolt11(byTitle("Now send $24"));
  expect(inv.description).toBeUndefined();
  expect(inv.descriptionHash).toBeDefined();
  expect(bytesToHex(inv.descriptionHash!)).toBe(
    "3925b6f67e2c340036ed12093dd44e0368df1b6ea26c53dbe4811f58fd5db8c1",
  );
  expect(inv.amountMsat).toBe(2_000_000_000n);
});

const fallbackVectors: Array<{
  readonly fragment: string;
  readonly version: number;
  readonly program: string;
}> = [
  {
    fragment: "The same, on testnet",
    // mk2QpYatsKicvFVuTAQLBryyccRXMUaGHP — testnet P2PKH.
    version: 17,
    program: "3172b5654f6683c8fb146959d347ce303cae4ca7",
  },
  {
    fragment: "On mainnet, with fallback address 1Rusty",
    // 1RustyRX2oai4EYYDpQGWvEL62BBGqN9T — mainnet P2PKH.
    version: 17,
    program: "04b61f7dc1ea0dc99424464cc4064dc564d91e89",
  },
  {
    fragment: "On mainnet, with fallback (P2SH)",
    // 3EktnHQD7RiAE6uzMj2ZifT9YgRrkSgzQX — mainnet P2SH.
    version: 18,
    program: "8f55563b9a19f321c211e9b9f38cdf686ea07845",
  },
  {
    fragment: "On mainnet, with fallback (P2WPKH)",
    // bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 — v0 witness program.
    version: 0,
    program: "751e76e8199196d454941c45d1b3a323f1433bd6",
  },
  {
    fragment: "On mainnet, with fallback (P2WSH)",
    // bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qcckx79rqk — v0 witness program.
    version: 0,
    program: "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262",
  },
];

test.each(fallbackVectors)("fallback of $fragment", ({ fragment, version, program }) => {
  const inv = decodeBolt11(byTitle(fragment));
  expect(inv.fallbackAddresses).toHaveLength(1);
  expect(inv.fallbackAddresses[0]!.version).toBe(version);
  expect(bytesToHex(inv.fallbackAddresses[0]!.program)).toBe(program);
});

test("testnet fallback invoice is on testnet", () => {
  const inv = decodeBolt11(byTitle("The same, on testnet"));
  expect(inv.network).toBe("testnet");
});

test("1Rusty invoice: two-hop route hint decodes every field", () => {
  const inv = decodeBolt11(byTitle("On mainnet, with fallback address 1Rusty"));
  expect(inv.routeHints).toHaveLength(1);
  const [first, second] = inv.routeHints[0]!;
  expect(bytesToHex(first!.publicKey)).toBe(
    "029e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255",
  );
  expect(bytesToHex(first!.shortChannelId)).toBe("0102030405060708");
  expect(first!.feeBaseMsat).toBe(1);
  expect(first!.feeProportionalMillionths).toBe(20);
  expect(first!.cltvExpiryDelta).toBe(3);
  expect(bytesToHex(second!.publicKey)).toBe(
    "039e03a901b85534ff1e92c43c74431f7ce72046060fcf7a95c37e148f78c77255",
  );
  expect(bytesToHex(second!.shortChannelId)).toBe("030405060708090a");
  expect(second!.feeBaseMsat).toBe(2);
  expect(second!.feeProportionalMillionths).toBe(30);
  expect(second!.cltvExpiryDelta).toBe(4);
});

test("a multi-hop route hint decodes every 51-byte entry", () => {
  const first = secp256k1.getPublicKey(new Uint8Array(32).fill(7), true);
  const second = secp256k1.getPublicKey(new Uint8Array(32).fill(8), true);
  const inv = decodeBolt11(
    encodeTestBolt11({
      secretKey: new Uint8Array(32).fill(66),
      paymentHash: new Uint8Array(32).fill(1),
      routeHints: [
        [
          { publicKey: first, shortChannelId: hexToBytes("f42400f424000001") },
          { publicKey: second, shortChannelId: hexToBytes("0102030405060708") },
        ],
      ],
    }),
  );
  const hint = inv.routeHints[0]!;
  expect(hint).toHaveLength(2);
  expect(hint[0]!.publicKey).toStrictEqual(first);
  expect(bytesToHex(hint[0]!.shortChannelId)).toBe("f42400f424000001");
  expect(hint[1]!.publicKey).toStrictEqual(second);
  expect(bytesToHex(hint[1]!.shortChannelId)).toBe("0102030405060708");
});

test("pico amount: 9678785340p = 967878534 msat", () => {
  const inv = decodeBolt11(byTitle("Please send 0.00967878534 BTC"));
  expect(inv.amountMsat).toBe(967_878_534n);
});

test("invoice with n field verifies payee", () => {
  const inv = decodeBolt11(byTitle("Please send $30 for coffee beans"));
  expect(bytesToHex(inv.payee)).toBe(
    "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad",
  );
});

test("coffee beans features bytes encode bits 8, 14 and 99", () => {
  const inv = decodeBolt11(byTitle("Please send $30 for coffee beans"));
  // Spec bitstring b1000....00000100000100000000 — 100 wire bits, floor to 12 bytes.
  expect(inv.features).toBeDefined();
  expect(bytesToHex(inv.features!)).toBe("800000000000000000000410");
});

test("uppercase invoice decodes identically to lowercase", () => {
  const upper = decodeBolt11(byTitle("Same, but all upper case"));
  const lower = decodeBolt11(byTitle("Please send $30 for coffee beans"));
  expect(upper).toStrictEqual(lower);
});

test("ignored-fields invoice decodes, keeping the unknown f version raw", () => {
  const inv = decodeBolt11(byTitle("Same, but including fields"));
  expect(inv.description).toBe("coffee beans");
  // The spec's ignorable invoice carries an f field with version 19 (unassigned) — kept raw.
  expect(inv.fallbackAddresses).toHaveLength(1);
  expect(inv.fallbackAddresses[0]!.version).toBe(19);
  expect(inv.fallbackAddresses[0]!.program).toStrictEqual(new Uint8Array(20));
});

test("fallback fields of every version decode, including v31 spark invoices", () => {
  const witnessProgram = hexToBytes("751e76e8199196d454941c45d1b3a323f1433bd6");
  const sparkProgram = hexToBytes("a1b2c3d4e5f6");
  const inv = decodeBolt11(
    encodeTestBolt11({
      secretKey: new Uint8Array(32).fill(66),
      paymentHash: new Uint8Array(32).fill(1),
      fallbacks: [
        { version: 0, program: witnessProgram },
        { version: 31, program: sparkProgram },
      ],
    }),
  );
  expect(inv.fallbackAddresses).toHaveLength(2);
  expect(inv.fallbackAddresses[0]!.version).toBe(0);
  expect(inv.fallbackAddresses[0]!.program).toStrictEqual(witnessProgram);
  expect(inv.fallbackAddresses[1]!.version).toBe(31);
  expect(inv.fallbackAddresses[1]!.program).toStrictEqual(sparkProgram);
});

test("metadata invoice carries m field", () => {
  const inv = decodeBolt11(byTitle("Please send 0.01 BTC with payment metadata"));
  expect(bytesToHex(inv.metadata!)).toBe("01fafaf0");
});

test("isExpired", () => {
  const inv = decodeBolt11(byTitle("Please send $3 for a cup of coffee"));
  expect(inv.expirySeconds).toBe(60);
  expect(isExpired(inv, (inv.timestamp + 60) * 1000 + 1)).toBe(true);
  expect(isExpired(inv, (inv.timestamp + 60) * 1000)).toBe(false);
});

test("non-canonical high-S signature with n field is rejected but decodes without n", () => {
  const invalid = byTitle("Non canonical signature (high-S)");
  expect(() => decodeBolt11(invalid)).toThrow(SparkInputError);
  const recovered = decodeBolt11(byTitle("Public-key recovery with high-S"));
  expect(recovered.payee).toHaveLength(33);
});

const SECRET = new Uint8Array(32).fill(66);
const PAYMENT_HASH = new Uint8Array(32).fill(1);
const WRONG_LENGTH_P = Array.from({ length: 51 }, () => 0);

test("a wrong-length p field before the correct one is skipped", () => {
  const inv = decodeBolt11(
    encodeTestBolt11({
      secretKey: SECRET,
      paymentHash: PAYMENT_HASH,
      leadingFields: [{ tag: 1, data: WRONG_LENGTH_P }],
    }),
  );
  expect(inv.paymentHash).toStrictEqual(PAYMENT_HASH);
});

test("an invoice whose only p field has the wrong length is missing its payment hash", () => {
  expect(() =>
    decodeBolt11(
      encodeTestBolt11({
        secretKey: SECRET,
        paymentHash: PAYMENT_HASH,
        paymentHashData: WRONG_LENGTH_P,
      }),
    ),
  ).toThrow("missing payment hash");
});

test("non-minimal x and c fields are rejected", () => {
  for (const tag of [6, 24]) {
    expect(() =>
      decodeBolt11(
        encodeTestBolt11({
          secretKey: SECRET,
          paymentHash: PAYMENT_HASH,
          leadingFields: [{ tag, data: [0, 1] }],
        }),
      ),
    ).toThrow("non-minimal data_length");
  }
});
