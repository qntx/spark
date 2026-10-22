import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";
import { expect, test } from "vite-plus/test";

import { decodeBolt11, isExpired } from "../src/core/bolt11.ts";
import { SparkInputError } from "../src/errors/index.ts";
import {
  bytesToWords,
  encodeRawBolt11,
  encodeTestBolt11,
  wordsToBytesPadded,
} from "./support/bolt11.ts";

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

const INVALID_REASONS: ReadonlyArray<readonly [string, RegExp]> = [
  ["Same, but adding invalid unknown feature 100", /unknown required feature bit 100/],
  ["Bech32 checksum is invalid", /invalid bech32/],
  ["Malformed bech32 string (no 1)", /invalid bech32/],
  ["Malformed bech32 string (mixed case)", /invalid bech32/],
  ["Signature is not recoverable", /not recoverable/],
  ["String is too short", /too short/],
  ["Invalid multiplier", /multiplier/],
  ["Invalid sub-millisatoshi precision", /multiple of 10/],
  ["Missing required `s` field", /missing payment secret/],
  [
    "Non canonical signature (high-S) with 'n' field defined",
    /does not verify against the n field/,
  ],
];

test("every invalid vector has a mapped rejection reason", () => {
  const mapped = new Set(INVALID_REASONS.map(([title]) => title));
  for (const c of vectors.cases.filter((entry) => !entry.valid)) {
    expect(mapped.has(c.title), `unmapped invalid vector: ${c.title}`).toBe(true);
  }
});

test.each(vectors.cases.filter((entry) => !entry.valid))("rejects invalid case %#", (c) => {
  const reason = INVALID_REASONS.find(([title]) => title === c.title)?.[1];
  expect(reason, `unmapped invalid vector: ${c.title}`).toBeDefined();
  expect(() => decodeBolt11(c.invoice)).toThrow(SparkInputError);
  expect(() => decodeBolt11(c.invoice)).toThrow(reason!);
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

// Raw-word crafting helpers for negative coverage: the tagged data part is
// [7 timestamp words][tagged fields]; encodeRawBolt11 appends the signature.
const PAYMENT_SECRET = new Uint8Array(32).fill(2);
const OTHER_SECRET = new Uint8Array(32).fill(7);

function tsWords(timestamp = 1_700_000_000): number[] {
  const words: number[] = [];
  for (let i = 6; i >= 0; i--) {
    words.push(Math.floor(timestamp / 32 ** i) & 31);
  }
  return words;
}

function taggedField(tag: number, data: ReadonlyArray<number>): number[] {
  return [tag, Math.floor(data.length / 32), data.length % 32, ...data];
}

function minimalWords(): number[] {
  return [
    ...tsWords(),
    ...taggedField(1, bytesToWords(PAYMENT_HASH)),
    ...taggedField(16, bytesToWords(PAYMENT_SECRET)),
    ...taggedField(13, bytesToWords(new TextEncoder().encode("test"))),
  ];
}

function crafted(
  dataWords: ReadonlyArray<number>,
  options?: { hrp?: string; secretKey?: Uint8Array; recoveryId?: number; signature?: Uint8Array },
): string {
  return encodeRawBolt11({
    hrp: options?.hrp ?? "lnbcrt",
    dataWords,
    secretKey: SECRET,
    ...options,
  });
}

test("mixed-case crafted invoice is rejected as invalid bech32", () => {
  const valid = crafted(minimalWords());
  const mixed = `lN${valid.slice(2)}`;
  expect(() => decodeBolt11(mixed)).toThrow(/invalid bech32/);
});

test.each([
  ["zz", /expected 'ln'/],
  ["lnxy", /unknown currency/],
  ["ln123", /unknown currency/],
  ["ln1bc", /unknown currency/],
  ["lnbcrt-10u", /amount/],
  ["lnbcrt!", /amount/],
  ["lnbcrt01u", /leading zeros/],
  ["lnbcrt2500000001p", /multiple of 10/],
])("hrp %s is rejected", (hrp, reason) => {
  expect(() => decodeBolt11(crafted(minimalWords(), { hrp }))).toThrow(reason);
});

test.each([
  ["lnbcrt0u", 0n],
  ["lnbcrt3", 300_000_000_000n],
  ["lnbcrt7n", 700n],
  ["lnbcrt2500u", 250_000_000n],
])("hrp %s parses the exact msat amount", (hrp, expected) => {
  expect(decodeBolt11(crafted(minimalWords(), { hrp })).amountMsat).toBe(expected);
});

test("seven data words before the signature means missing payment hash, not too short", () => {
  expect(() => decodeBolt11(crafted(tsWords()))).toThrow(/missing payment hash/);
  expect(() => decodeBolt11(crafted(tsWords().slice(0, 6)))).toThrow(/too short/);
});

test("one or two dangling header words are a truncated header", () => {
  expect(() => decodeBolt11(crafted([...tsWords(), 5]))).toThrow(/truncated header/);
  expect(() => decodeBolt11(crafted([...tsWords(), 5, 3]))).toThrow(/truncated header/);
});

test("a field whose declared length overruns the signature is rejected", () => {
  // Tag 13 with declared length 5 but only 2 data words before the signature.
  expect(() => decodeBolt11(crafted([...tsWords(), 13, 0, 5, 1, 2]))).toThrow(/overruns/);
  // Exactly three words before the signature form a complete header whose
  // data overruns — not a truncated header.
  expect(() => decodeBolt11(crafted([...tsWords(), 13, 0, 5]))).toThrow(/overruns/);
});

test("an x field of exactly 2^53-1 still fits a safe integer", () => {
  const maxSafe = intWords(Number.MAX_SAFE_INTEGER);
  const inv = decodeBolt11(
    crafted([...tsWords(), ...taggedField(6, maxSafe), ...minimalWords().slice(7)]),
  );
  expect(inv.expirySeconds).toBe(Number.MAX_SAFE_INTEGER);
});

test("an x field larger than 2^53 overflows a safe integer", () => {
  const huge = taggedField(
    6,
    Array.from({ length: 11 }, () => 31),
  );
  expect(() => decodeBolt11(crafted([...tsWords(), ...huge]))).toThrow(/overflows a safe integer/);
});

test("minFinalCltvExpiry decodes the exact c field value", () => {
  const inv = decodeBolt11(
    encodeTestBolt11({ secretKey: SECRET, paymentHash: PAYMENT_HASH, minFinalCltvExpiry: 42 }),
  );
  expect(inv.minFinalCltvExpiry).toBe(42);
});

test("non-minimal features field is rejected", () => {
  expect(() =>
    decodeBolt11(crafted([...tsWords(), ...taggedField(5, [0, 1]), ...minimalWords().slice(7)])),
  ).toThrow(/non-minimal/);
});

test("an empty f field is missing its version", () => {
  expect(() =>
    decodeBolt11(crafted([...tsWords(), ...taggedField(9, []), ...minimalWords().slice(7)])),
  ).toThrow(/missing version/);
});

test.each([
  [[], /51-byte/],
  [bytesToWords(new Uint8Array(50)), /51-byte/],
])("a route hint that is not a multiple of 51 bytes is rejected", (data, reason) => {
  expect(() =>
    decodeBolt11(crafted([...tsWords(), ...taggedField(3, data), ...minimalWords().slice(7)])),
  ).toThrow(reason);
});

const OTHER_HASH = new Uint8Array(32).fill(9);

test.each([
  {
    name: "p",
    build: () => [
      ...tsWords(),
      ...taggedField(1, bytesToWords(OTHER_HASH)),
      ...minimalWords().slice(7),
    ],
    pick: (inv: ReturnType<typeof decodeBolt11>) => inv.paymentHash,
    expected: OTHER_HASH,
  },
  {
    name: "s",
    build: () => [
      ...tsWords(),
      ...taggedField(16, bytesToWords(OTHER_HASH)),
      ...minimalWords().slice(7),
    ],
    pick: (inv: ReturnType<typeof decodeBolt11>) => inv.paymentSecret,
    expected: OTHER_HASH,
  },
  {
    name: "h",
    build: () => [
      ...tsWords(),
      ...taggedField(1, bytesToWords(PAYMENT_HASH)),
      ...taggedField(16, bytesToWords(PAYMENT_SECRET)),
      ...taggedField(23, bytesToWords(OTHER_HASH)),
      ...taggedField(23, bytesToWords(new Uint8Array(32).fill(5))),
    ],
    pick: (inv: ReturnType<typeof decodeBolt11>) => inv.descriptionHash,
    expected: OTHER_HASH,
  },
  {
    name: "n",
    build: () => [
      ...minimalWords(),
      ...taggedField(19, bytesToWords(secp256k1.getPublicKey(SECRET, true))),
      ...taggedField(19, bytesToWords(secp256k1.getPublicKey(OTHER_SECRET, true))),
    ],
    pick: (inv: ReturnType<typeof decodeBolt11>) => inv.payee,
    expected: secp256k1.getPublicKey(SECRET, true),
  },
])("duplicate $name fields: the first wins", ({ build, pick, expected }) => {
  expect(pick(decodeBolt11(crafted(build())))).toStrictEqual(expected);
});

test("invalid UTF-8 in a d field is rejected", () => {
  const badUtf8 = bytesToWords(new Uint8Array([0xff, 0xfe, 0xfd]));
  expect(() =>
    decodeBolt11(
      crafted([
        ...tsWords(),
        ...taggedField(1, bytesToWords(PAYMENT_HASH)),
        ...taggedField(16, bytesToWords(PAYMENT_SECRET)),
        ...taggedField(13, badUtf8),
      ]),
    ),
  ).toThrow(/invalid UTF-8/);
});

test("an invoice with neither d nor h is missing its description", () => {
  expect(() =>
    decodeBolt11(
      crafted([
        ...tsWords(),
        ...taggedField(1, bytesToWords(PAYMENT_HASH)),
        ...taggedField(16, bytesToWords(PAYMENT_SECRET)),
      ]),
    ),
  ).toThrow(/missing description/);
});

test("an invoice with both d and h is rejected", () => {
  expect(() =>
    decodeBolt11(
      crafted([
        ...tsWords(),
        ...taggedField(1, bytesToWords(PAYMENT_HASH)),
        ...taggedField(16, bytesToWords(PAYMENT_SECRET)),
        ...taggedField(13, bytesToWords(new TextEncoder().encode("test"))),
        ...taggedField(23, bytesToWords(OTHER_HASH)),
      ]),
    ),
  ).toThrow(/both description/);
});

test("recovery id 3 is accepted when an n field verifies", () => {
  // Recovery ids 2/3 need r+n < p — unreachable for real signatures — but the
  // byte is still legal when the n field verifies the signature directly.
  const dataWords = [
    ...minimalWords(),
    ...taggedField(19, bytesToWords(secp256k1.getPublicKey(SECRET, true))),
  ];
  const digest = sha256(concatBytes(utf8ToBytes("lnbcrt"), wordsToBytesPadded(dataWords)));
  const recovered = secp256k1.sign(digest, SECRET, { prehash: false, format: "recovered" });
  const signature = new Uint8Array(65);
  signature.set(recovered.subarray(1), 0);
  signature[64] = 3;
  const inv = decodeBolt11(encodeRawBolt11({ hrp: "lnbcrt", dataWords, signature }));
  expect(inv.payee).toStrictEqual(secp256k1.getPublicKey(SECRET, true));
});

test("a recovery id of 4 is rejected without an n field", () => {
  expect(() => decodeBolt11(crafted(minimalWords(), { recoveryId: 4 }))).toThrow(/recovery id/);
});

test("a 33-byte n field that is not a valid point falls back to signature recovery", () => {
  const notAPoint = new Uint8Array(33); // 0x00 prefix: never a compressed point.
  const inv = decodeBolt11(
    crafted([...minimalWords(), ...taggedField(19, bytesToWords(notAPoint))], {
      secretKey: SECRET,
    }),
  );
  expect(inv.payee).toStrictEqual(secp256k1.getPublicKey(SECRET, true));
});

test("a valid n field whose signature was made by a different key is rejected", () => {
  expect(() =>
    decodeBolt11(
      crafted(
        [
          ...minimalWords(),
          ...taggedField(19, bytesToWords(secp256k1.getPublicKey(OTHER_SECRET, true))),
        ],
        { secretKey: SECRET },
      ),
    ),
  ).toThrow(/does not verify/);
});

test("a duplicated fixed-length field does not shadow a later n field", () => {
  expect(() =>
    decodeBolt11(
      crafted(
        [
          ...tsWords(),
          ...taggedField(1, bytesToWords(PAYMENT_HASH)),
          // The duplicate p is skipped; the real n still governs verification.
          ...taggedField(1, bytesToWords(OTHER_HASH)),
          ...taggedField(16, bytesToWords(PAYMENT_SECRET)),
          ...taggedField(13, bytesToWords(new TextEncoder().encode("test"))),
          ...taggedField(19, bytesToWords(secp256k1.getPublicKey(OTHER_SECRET, true))),
        ],
        { secretKey: SECRET },
      ),
    ),
  ).toThrow(/does not verify/);
});

function featureWords(bit: number): number[] {
  const words = Array.from({ length: Math.floor(bit / 5) + 1 }, () => 0);
  words[words.length - 1 - Math.floor(bit / 5)] = 1 << (bit % 5);
  return words;
}

/** Minimal big-endian base-32 words for a non-negative safe integer. */
function intWords(value: number): number[] {
  const words: number[] = [];
  for (let v = value; v > 0; v = Math.floor(v / 32)) {
    words.unshift(v % 32);
  }
  return words;
}

test.each([2, 20])("unknown even feature bit %d is rejected", (bit) => {
  expect(() =>
    decodeBolt11(
      crafted([...tsWords(), ...taggedField(5, featureWords(bit)), ...minimalWords().slice(7)]),
    ),
  ).toThrow(new RegExp(`unknown required feature bit ${bit}`));
});

test.each([14, 101])("known even or odd feature bit %d is accepted", (bit) => {
  const inv = decodeBolt11(
    crafted([...tsWords(), ...taggedField(5, featureWords(bit)), ...minimalWords().slice(7)]),
  );
  expect(inv.features).toBeDefined();
});
