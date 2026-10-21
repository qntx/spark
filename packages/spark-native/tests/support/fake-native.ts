import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { SparkCryptoError } from "@qntx/spark/crypto";
import type { SparkCrypto } from "@qntx/spark/crypto";

import { instantiateSparkWasm } from "../../../spark-wasm/src/abi.ts";
import { bindSparkExports } from "../../../spark-wasm/src/instance.ts";
import type { SparkNative } from "../../src/specs/spark-native.nitro.ts";

/**
 * A `SparkNative` fake for tests: the HybridObject contract (ArrayBuffer in/out, `qntx_spark:<n>`
 * error strings) over the real wasm backend, so the shared vectors exercise genuine crypto and
 * genuine ABI error codes. `received` records the ArrayBuffer each call was handed so tests can
 * assert the wrapper wiped its private-input copies.
 */
export type FakeSparkNative = {
  native: SparkNative;
  received: Map<string, ArrayBuffer[]>;
};

async function wasmBackend(): Promise<SparkCrypto> {
  const bytes = await readFile(
    fileURLToPath(new URL("../../../spark-wasm/src/spark.wasm", import.meta.url)),
  );
  return bindSparkExports(await instantiateSparkWasm(bytes));
}

function copyOut(bytes: Uint8Array): ArrayBuffer {
  return new Uint8Array(bytes).buffer;
}

/**
 * The C++ side reports ABI errors as `Error("qntx_spark:<code>")` and nitro rethrows them prefixed
 * with the calling function, `funcName + ": " + e.what()` (HybridFunction.hpp) — mirror that here.
 */
function toAbiError(error: unknown, name: string): Error {
  if (error instanceof SparkCryptoError) {
    return new Error(`SparkNative.${name}(...): qntx_spark:${error.code}`);
  }
  if (error instanceof Error) {
    return error;
  }
  return new Error(String(error));
}

export async function fakeSparkNative(abiVersion = 1): Promise<FakeSparkNative> {
  const crypto = await wasmBackend();
  const received = new Map<string, ArrayBuffer[]>();
  const wrap = <A extends unknown[]>(
    name: string,
    buffers: (...args: A) => ArrayBuffer[],
    invoke: (args: A, crypto: SparkCrypto) => Uint8Array,
  ) => {
    return (...args: A): ArrayBuffer => {
      received.set(name, [...(received.get(name) ?? []), ...buffers(...args)]);
      try {
        return copyOut(invoke(args, crypto));
      } catch (error) {
        throw toAbiError(error, name);
      }
    };
  };

  return {
    received,
    native: {
      name: "SparkNative",
      toString: () => "[HybridObject SparkNative]",
      equals: () => false,
      dispose: () => undefined,
      abiVersion: () => abiVersion,
      frostCommit: wrap<[ArrayBuffer, ArrayBuffer]>(
        "frostCommit",
        (hedge, random) => [hedge, random],
        ([hedge, random], c) => c.frostCommit(new Uint8Array(hedge), new Uint8Array(random)),
      ),
      frostSign: wrap<[ArrayBuffer]>(
        "frostSign",
        (request) => [request],
        ([request], c) => c.frostSign(new Uint8Array(request)),
      ),
      frostAggregate: wrap<[ArrayBuffer]>(
        "frostAggregate",
        (request) => [request],
        ([request], c) => c.frostAggregate(new Uint8Array(request)),
      ),
      eciesEncrypt: wrap<[ArrayBuffer, ArrayBuffer, ArrayBuffer]>(
        "eciesEncrypt",
        (publicKey, plaintext, random) => [publicKey, plaintext, random],
        ([publicKey, plaintext, random], c) =>
          c.eciesEncrypt(
            new Uint8Array(publicKey),
            new Uint8Array(plaintext),
            new Uint8Array(random),
          ),
      ),
      eciesDecrypt: wrap<[ArrayBuffer, ArrayBuffer]>(
        "eciesDecrypt",
        (privateKey, ciphertext) => [privateKey, ciphertext],
        ([privateKey, ciphertext], c) =>
          c.eciesDecrypt(new Uint8Array(privateKey), new Uint8Array(ciphertext)),
      ),
      splitSecretWithProofs: wrap<[ArrayBuffer, number, number, ArrayBuffer]>(
        "splitSecretWithProofs",
        (secret, _threshold, _shares, random) => [secret, random],
        ([secret, threshold, shares, random], c) =>
          c.splitSecretWithProofs(
            new Uint8Array(secret),
            threshold,
            shares,
            new Uint8Array(random),
          ),
      ),
    },
  };
}
