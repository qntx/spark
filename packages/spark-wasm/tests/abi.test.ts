import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vite-plus/test";

import { SparkCryptoError, SparkError } from "@qntx/spark/crypto";
import type { SparkCrypto } from "@qntx/spark/crypto";

import { instantiateSparkWasm } from "../src/abi.ts";
import { bindSparkExports } from "../src/instance.ts";
import { readWasmBytes } from "./read-wasm.ts";

const VECTORS = new URL("../../../vectors/", import.meta.url);
const ABI_FUNCTIONS = [
  "qs_abi_version",
  "qs_alloc",
  "qs_free",
  "qs_frost_commit",
  "qs_frost_sign",
  "qs_frost_aggregate",
  "qs_ecies_encrypt",
  "qs_ecies_decrypt",
  "qs_split_secret_with_proofs",
];

type Cases<T> = { cases: T[] };

async function vector<T>(name: string): Promise<T[]> {
  const doc = JSON.parse(await readFile(new URL(name, VECTORS), "utf8")) as Cases<T>;
  return doc.cases;
}

async function loadBackend(): Promise<SparkCrypto> {
  return bindSparkExports(await instantiateSparkWasm(await readWasmBytes()));
}

describe("wasm module shape", () => {
  test("declares no imports", async () => {
    const module = await WebAssembly.compile(await readWasmBytes());
    expect(WebAssembly.Module.imports(module)).toStrictEqual([]);
  });

  test("exports exactly the qs_* ABI functions plus memory", async () => {
    const module = await WebAssembly.compile(await readWasmBytes());
    const exports = WebAssembly.Module.exports(module);
    const functions = exports
      .filter((e: WebAssembly.ModuleExportDescriptor) => e.kind === "function")
      .map((e: WebAssembly.ModuleExportDescriptor) => e.name)
      .toSorted();
    const memories = exports
      .filter((e: WebAssembly.ModuleExportDescriptor) => e.kind === "memory")
      .map((e: WebAssembly.ModuleExportDescriptor) => e.name);
    expect(functions).toStrictEqual([...ABI_FUNCTIONS].toSorted());
    expect(memories).toStrictEqual(["memory"]);
    expect(exports).toHaveLength(functions.length + 1);
  });

  test("rejects a module with imports", async () => {
    // Minimal valid module: one () -> () type and (import "e" "f" (func 0)).
    const bytes = new Uint8Array([
      0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x02,
      0x07, 0x01, 0x01, 0x65, 0x01, 0x66, 0x00, 0x00,
    ]);
    await expect(instantiateSparkWasm(bytes)).rejects.toBeInstanceOf(SparkError);
  });
});

describe("frost-commit vectors", () => {
  test("every case", async () => {
    const crypto = await loadBackend();
    type Case = { hedge: string; random: string; nonces: string; commitments: string };
    const cases = await vector<Case>("frost-commit.json");
    expect(cases.length).toBeGreaterThan(0);
    for (const [index, c] of cases.entries()) {
      const out = crypto.frostCommit(hex(c.hedge), hex(c.random));
      expect(out).toHaveLength(130);
      expect(toHex(out.slice(0, 64))).toBe(c.nonces);
      expect(toHex(out.slice(64))).toBe(c.commitments);
      expect(index).toBeGreaterThanOrEqual(0);
    }
  });
});

describe("ffi-sign vectors", () => {
  test("every case", async () => {
    const crypto = await loadBackend();
    const cases = await vector<{ request: string; response: string }>("ffi-sign.json");
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      expect(toHex(crypto.frostSign(hex(c.request)))).toBe(c.response);
    }
  });
});

describe("ffi-aggregate vectors", () => {
  test("every case", async () => {
    const crypto = await loadBackend();
    const cases = await vector<{ request: string; response: string }>("ffi-aggregate.json");
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      expect(toHex(crypto.frostAggregate(hex(c.request)))).toBe(c.response);
    }
  });
});

describe("ecies vectors", () => {
  test("every case round-trips", async () => {
    const crypto = await loadBackend();
    type Case = {
      secret_key: string;
      public_key: string;
      random: string;
      plaintext: string;
      ciphertext: string;
    };
    const cases = await vector<Case>("ecies.json");
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      expect(toHex(crypto.eciesEncrypt(hex(c.public_key), hex(c.plaintext), hex(c.random)))).toBe(
        c.ciphertext,
      );
      expect(toHex(crypto.eciesDecrypt(hex(c.secret_key), hex(c.ciphertext)))).toBe(c.plaintext);
    }
  });
});

describe("vss vectors", () => {
  test("every case", async () => {
    const crypto = await loadBackend();
    type Case = {
      secret: string;
      threshold: number;
      share_count: number;
      random: string;
      proofs: string[];
      shares: string[];
    };
    const cases = await vector<Case>("vss.json");
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      const out = crypto.splitSecretWithProofs(
        hex(c.secret),
        c.threshold,
        c.share_count,
        hex(c.random),
      );
      expect(toHex(out)).toBe([...c.proofs, ...c.shares].join(""));
    }
  });

  test.each([
    ["fractional threshold", 2.7, 3],
    ["out-of-range threshold", 2 ** 32 + 3, 3],
    ["fractional shares", 2, 3.5],
    ["out-of-range shares", 2, 2 ** 32 + 3],
    ["negative threshold", -1, 3],
  ])("rejects %s before the wasm call", async (_label, threshold, shares) => {
    const crypto = await loadBackend();
    const error = syncThrow(() =>
      crypto.splitSecretWithProofs(hex("20".repeat(32)), threshold, shares, hex("21".repeat(32))),
    );
    expect(error).toBeInstanceOf(SparkError);
    expect(error).not.toBeInstanceOf(SparkCryptoError);
  });
});

describe("ffi-errors vectors", () => {
  test("every case returns the expected error code", async () => {
    const crypto = await loadBackend();
    type Case = { function: string; code: number } & Record<string, unknown>;
    const cases = await vector<Case>("ffi-errors.json");
    expect(cases.length).toBeGreaterThan(0);
    for (const c of cases) {
      const error = syncThrow(() => dispatch(crypto, c));
      expect(error, `${c.function} ${JSON.stringify(c)}`).toBeInstanceOf(SparkCryptoError);
      expect((error as SparkCryptoError).code).toBe(c.code);
    }
  });
});

function syncThrow(fn: () => unknown): unknown {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error("expected throw");
}

function dispatch(crypto: SparkCrypto, c: Record<string, unknown>): void {
  const field = (name: string): Uint8Array => hex(c[name] as string);
  switch (c["function"]) {
    case "frost_commit":
      crypto.frostCommit(field("hedge"), field("random"));
      return;

    case "frost_sign":
      crypto.frostSign(field("request"));
      return;

    case "frost_aggregate":
      crypto.frostAggregate(field("request"));
      return;

    case "ecies_encrypt":
      crypto.eciesEncrypt(field("public_key"), field("plaintext"), field("random"));
      return;

    case "ecies_decrypt":
      crypto.eciesDecrypt(field("secret_key"), field("ciphertext"));
      return;

    case "split_secret_with_proofs":
      crypto.splitSecretWithProofs(
        field("secret"),
        c["threshold"] as number,
        c["shares"] as number,
        field("random"),
      );
      return;

    default:
      throw new Error(`unknown function ${c["function"] as string}`);
  }
}

function hex(value: string): Uint8Array {
  const bytes = new Uint8Array(value.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
