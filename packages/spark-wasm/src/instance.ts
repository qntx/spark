import { SPARK_ABI_VERSION, SparkCryptoError } from "@qntx/spark/crypto";
import type { SparkCrypto } from "@qntx/spark/crypto";

import {
  wasmEciesDecrypt,
  wasmEciesEncrypt,
  wasmFrostAggregate,
  wasmFrostCommit,
  wasmFrostSign,
  wasmSplitSecretWithProofs,
} from "./abi.ts";
import type { SparkWasmExports } from "./abi.ts";

export type LoadSparkWasmOptions = {
  /** Wasm module bytes. When omitted the platform loader reads the bundled `spark.wasm` artifact. */
  module?: ArrayBuffer | ArrayBufferView | undefined;
};

/** Wasm instance aborted; later calls on that instance fail. */
export class WasmPoisonedError extends SparkCryptoError {
  override name = "WasmPoisonedError";
}

/**
 * Runs `fn` unless the instance is already poisoned; a `WebAssembly.RuntimeError` aborts the
 * instance, so it is converted to {@link WasmPoisonedError} and rethrown on every later call.
 */
export function runSparkPoisoned<T>(poison: { error?: Error }, fn: () => T): T {
  if (poison.error !== undefined) {
    throw poison.error;
  }
  try {
    return fn();
  } catch (error) {
    if (error instanceof WebAssembly.RuntimeError) {
      poison.error = new WasmPoisonedError(8, { cause: error });
      throw poison.error;
    }
    throw error;
  }
}

/** Binds the raw wasm exports into a {@link SparkCrypto} backend. */
export function bindSparkExports(exports: SparkWasmExports): SparkCrypto {
  const poison: { error?: Error } = {};
  return {
    abiVersion: SPARK_ABI_VERSION,
    frostCommit: (hedge, random) =>
      runSparkPoisoned(poison, () => wasmFrostCommit(exports, hedge, random)),
    frostSign: (request) => runSparkPoisoned(poison, () => wasmFrostSign(exports, request)),
    frostAggregate: (request) =>
      runSparkPoisoned(poison, () => wasmFrostAggregate(exports, request)),
    eciesEncrypt: (publicKey, plaintext, random) =>
      runSparkPoisoned(poison, () => wasmEciesEncrypt(exports, publicKey, plaintext, random)),
    eciesDecrypt: (privateKey, ciphertext) =>
      runSparkPoisoned(poison, () => wasmEciesDecrypt(exports, privateKey, ciphertext)),
    splitSecretWithProofs: (secret, threshold, shares, random) =>
      runSparkPoisoned(poison, () =>
        wasmSplitSecretWithProofs(exports, secret, threshold, shares, random),
      ),
  };
}
