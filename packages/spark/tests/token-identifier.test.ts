import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { hexToBytes } from "@noble/hashes/utils.js";
import { bech32m } from "@scure/base";
import { expect, test } from "vite-plus/test";

import { decodeTokenIdentifier, encodeTokenIdentifier } from "../src/core/token-identifier.ts";
import { SparkInputError } from "../src/errors/index.ts";

type VectorCase = {
  tokenIdentifier: string;
  network: "mainnet" | "regtest";
  encoded: string;
};

const { cases } = JSON.parse(
  readFileSync(resolve(import.meta.dirname, "../../../vectors/token-identifier.json"), "utf8"),
) as { cases: VectorCase[] };

test("encodes vectors", () => {
  for (const v of cases) {
    expect(encodeTokenIdentifier(hexToBytes(v.tokenIdentifier), v.network)).toBe(v.encoded);
  }
});

test("decodes vectors", () => {
  for (const v of cases) {
    const decoded = decodeTokenIdentifier(v.encoded);
    expect(decoded.tokenIdentifier).toStrictEqual(hexToBytes(v.tokenIdentifier));
    expect(decoded.network).toBe(v.network);
  }
});

test("rejects unknown prefixes, including other networks' upstream HRPs", () => {
  for (const bad of [
    "btknt18aaxwtn6q4smnlv8td08x5xxz0mx49c60suectq6d9p2gljtjmuqlps2vm",
    "btkns18aaxwtn6q4smnlv8td08x5xxz0mx49c60suectq6d9p2gljtjmuqsem3dn",
    "btknl18aaxwtn6q4smnlv8td08x5xxz0mx49c60suectq6d9p2gljtjmuqdl8f83",
    "sparkrt1pgssx5us3wkqjza8g80xz3a9gznx25msq6g3ty8exfym9q3ahcv86vsnxxdy83",
    "not-an-identifier",
  ]) {
    expect(() => decodeTokenIdentifier(bad)).toThrow(SparkInputError);
  }
});

test("rejects malformed encodings", () => {
  // Corrupted checksum: the regtest vector ends in '9', flipped to 'w'.
  const corrupted = `${cases[1]!.encoded.slice(0, -1)}w`;
  expect(() => decodeTokenIdentifier(corrupted)).toThrow(SparkInputError);
  // Missing separator.
  expect(() => decodeTokenIdentifier("btknrt")).toThrow(SparkInputError);
});

test("rejects wrong payload length on encode and decode", () => {
  expect(() => encodeTokenIdentifier(hexToBytes("aabb"), "regtest")).toThrow(SparkInputError);
  // A 4-byte payload bech32m-encodes fine but must be rejected on decode.
  const short = bech32m.encode("btknrt", bech32m.toWords(hexToBytes("aabbccdd")), 500);
  expect(() => decodeTokenIdentifier(short)).toThrow(SparkInputError);
});
