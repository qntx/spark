import { describe, expect, test } from "vite-plus/test";

import { SparkCryptoError } from "@qntx/spark/crypto";

import { instantiateSparkWasm } from "../src/abi.ts";
import type { SparkWasmExports } from "../src/abi.ts";
import { WasmPoisonedError, bindSparkExports } from "../src/instance.ts";
import { loadSparkWasm } from "../src/load.ts";
import { readWasmBytes } from "./read-wasm.ts";

function trapExports(exports: SparkWasmExports): SparkWasmExports {
  return {
    ...exports,
    qs_frost_sign: () => {
      throw new WebAssembly.RuntimeError("trap");
    },
  };
}

function syncThrow(fn: () => unknown): unknown {
  try {
    fn();
  } catch (error) {
    return error;
  }
  throw new Error("expected throw");
}

describe("SparkCrypto binding", () => {
  test("abiVersion matches the SPARK_ABI_VERSION", async () => {
    const crypto = bindSparkExports(await instantiateSparkWasm(await readWasmBytes()));
    expect(crypto.abiVersion).toBe(1);
  });

  test("a RuntimeError poisons the instance", async () => {
    const crypto = bindSparkExports(trapExports(await instantiateSparkWasm(await readWasmBytes())));
    const request = new Uint8Array([0x0a, 0x00]);
    const first = syncThrow(() => crypto.frostSign(request));
    expect(first).toBeInstanceOf(WasmPoisonedError);
    expect((first as WasmPoisonedError).cause).toBeInstanceOf(WebAssembly.RuntimeError);

    // Sticky: every later call on any method throws the same error.
    expect(syncThrow(() => crypto.frostSign(request))).toBe(first);
    expect(syncThrow(() => crypto.eciesDecrypt(new Uint8Array(32), new Uint8Array(1)))).toBe(first);
  });

  test("backend error codes surface as SparkCryptoError, not poison", async () => {
    const crypto = bindSparkExports(await instantiateSparkWasm(await readWasmBytes()));
    const error = syncThrow(() =>
      crypto.eciesDecrypt(new Uint8Array(32).fill(1), new Uint8Array([1, 2, 3])),
    );
    expect(error).toBeInstanceOf(SparkCryptoError);
    expect(error).not.toBeInstanceOf(WasmPoisonedError);
    expect((error as SparkCryptoError).code).toBe(1);
  });
});

describe("loadSparkWasm ownership", () => {
  test("every call returns a fresh instance", async () => {
    const a = await loadSparkWasm({ module: await readWasmBytes() });
    const b = await loadSparkWasm({ module: await readWasmBytes() });
    expect(b).not.toBe(a);
    // Both instances work independently.
    const hedge = new Uint8Array(32).fill(1);
    const random = new Uint8Array(32).fill(7);
    expect(b.frostCommit(hedge, random)).toStrictEqual(a.frostCommit(hedge, random));
  });

  test("a failed load does not prevent later loads", async () => {
    await expect(loadSparkWasm({ module: new Uint8Array([1, 2, 3]) })).rejects.toThrow(
      WebAssembly.CompileError,
    );
    await expect(loadSparkWasm({ module: await readWasmBytes() })).resolves.toMatchObject({
      abiVersion: 1,
    });
  });
});
