import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { loadSparkWasm } from "@qntx/spark-wasm";

import type { SparkCrypto } from "../../src/crypto/index.ts";

let wasmBytes: Uint8Array | undefined;

/**
 * The real spark-ffi wasm backend for signer tests: the checked-in `spark.wasm` artifact fed
 * through the package's own loader (aliased to sources — no pack build required).
 */
export async function loadWasmBackend(): Promise<SparkCrypto> {
  wasmBytes ??= new Uint8Array(
    readFileSync(resolve(import.meta.dirname, "../../../spark-wasm/src/spark.wasm")),
  );
  return loadSparkWasm({ module: wasmBytes });
}
