import { secp256k1 } from "@noble/curves/secp256k1.js";
import { describe, expect, test } from "vite-plus/test";

import { decodeSparkAddress, encodeSparkAddress } from "../src/core/address.ts";
import { decodeBolt11 } from "../src/core/bolt11.ts";
import { decodeTokenIdentifier, encodeTokenIdentifier } from "../src/core/token-identifier.ts";
import { SparkError, SparkInputError } from "../src/errors/index.ts";
import { createSatsInvoice } from "../src/invoice/index.ts";
import { parseSparkInvoice } from "../src/invoice/parse.ts";
import { decodeLnurl, encodeLnurl } from "../src/lnurl/codec.ts";
import { createSparkSigner, sparkAccountKey } from "../src/signer/index.ts";
import { loadWasmBackend } from "./support/backend.ts";
import { encodeTestBolt11 } from "./support/bolt11.ts";
import { pickInt, seededPrng } from "./support/prng.ts";

// Seeded mutation harness: every decoder input either decodes or throws a Spark error —
// never a TypeError/RangeError and never a hang (each call is synchronous and bounded).

const ITERATIONS = 400;

/** Runs `fn` on every mutated input and returns any non-Spark errors it leaked. */
function nonSparkErrors(rand: () => number, seed: string, fn: (input: string) => unknown) {
  const leaked: unknown[] = [];
  for (let i = 0; i < ITERATIONS; i++) {
    const mutated = mutate(rand, seed);
    try {
      fn(mutated);
    } catch (error) {
      if (!(error instanceof SparkError || error instanceof SparkInputError)) {
        leaked.push(error);
      }
    }
  }
  return leaked;
}

function mutate(rand: () => number, input: string): string {
  const kind = pickInt(rand, 5);
  switch (kind) {
    case 0: {
      if (input.length === 0) {
        return input;
      }
      const i = pickInt(rand, input.length);
      return input.slice(0, i) + String.fromCodePoint(33 + pickInt(rand, 94)) + input.slice(i + 1);
    }
    case 1:
      return input.slice(0, pickInt(rand, input.length + 1));
    case 2:
      return `${input}q${input.slice(pickInt(rand, input.length + 1))}`;
    case 3:
      return pickInt(rand, 2) === 0 ? input.toUpperCase() : input.toLowerCase();
    default: {
      const alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
      return Array.from({ length: pickInt(rand, 40) + 4 }, () =>
        alphabet.charAt(pickInt(rand, alphabet.length)),
      ).join("");
    }
  }
}

const NOW = 1_800_000_000_000;

const BOLT11 = encodeTestBolt11({
  network: "regtest",
  amountMsat: 250_000n,
  timestamp: 1_800_000_000,
  paymentHash: new Uint8Array(32).fill(0x42),
  description: "seed",
  expirySeconds: 3600,
  secretKey: new Uint8Array(32).fill(9),
});
const SPARK_ADDRESS = encodeSparkAddress({
  identityPublicKey: secp256k1.getPublicKey(new Uint8Array(32).fill(7), true),
  network: "regtest",
});
const TOKEN_ID = encodeTokenIdentifier(new Uint8Array(32).fill(3), "regtest");
const LNURL = encodeLnurl("https://example.com/lnurl/pay");

async function signedInvoice(): Promise<string> {
  const signer = createSparkSigner({
    crypto: await loadWasmBackend(),
    accountKey: sparkAccountKey(new Uint8Array(32).fill(5), "regtest"),
    network: "regtest",
    random: (length: number) => new Uint8Array(length).fill(4),
  });
  const invoice = await createSatsInvoice({
    signer,
    network: "regtest",
    random: (length: number) => new Uint8Array(length).fill(4),
    now: () => NOW,
    amountSats: 1000,
    expiresAtMs: NOW + 60_000,
  });
  signer.dispose();
  return invoice;
}

describe("decoder robustness under mutation", () => {
  test("decodeBolt11 never throws a non-Spark error", () => {
    expect(nonSparkErrors(seededPrng(0x51ee), BOLT11, decodeBolt11)).toStrictEqual([]);
    expect(() => decodeBolt11(BOLT11)).not.toThrow();
  });

  test("decodeSparkAddress never throws a non-Spark error", () => {
    expect(nonSparkErrors(seededPrng(0xb10c), SPARK_ADDRESS, decodeSparkAddress)).toStrictEqual([]);
  });

  test("decodeTokenIdentifier never throws a non-Spark error", () => {
    expect(nonSparkErrors(seededPrng(0x70e3), TOKEN_ID, decodeTokenIdentifier)).toStrictEqual([]);
  });

  test("decodeLnurl never throws a non-Spark error", () => {
    expect(nonSparkErrors(seededPrng(0x1e11), LNURL, decodeLnurl)).toStrictEqual([]);
  });

  test("parseSparkInvoice never throws a non-Spark error", async () => {
    const invoice = await signedInvoice();
    const rand = seededPrng(0xc0de);
    const leaked = nonSparkErrors(rand, invoice, (text) =>
      parseSparkInvoice(text, { network: "regtest", now: NOW }),
    );
    expect(leaked).toStrictEqual([]);
  });
});
