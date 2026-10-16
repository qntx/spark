import { SparkError } from "@qntx/spark/crypto";
import type { SparkCrypto } from "@qntx/spark/crypto";

import { instantiateSparkWasm } from "./abi.ts";
import { bindSparkExports } from "./instance.ts";
import type { LoadSparkWasmOptions } from "./instance.ts";

export { WasmPoisonedError } from "./instance.ts";
export type { LoadSparkWasmOptions } from "./instance.ts";

async function defaultWasmHref(): Promise<string> {
  const mod = await import("./spark.wasm?url");
  return mod.default;
}

async function wasmBytes(opts?: LoadSparkWasmOptions): Promise<BufferSource> {
  const source = opts?.module;
  if (source !== undefined) {
    return source;
  }
  const href = new URL(await defaultWasmHref(), import.meta.url);
  if (href.protocol !== "file:") {
    throw new SparkError(`spark.wasm URL must use the file: scheme, got ${href.protocol}`);
  }
  const { readFile } = await import("node:fs/promises");
  const { fileURLToPath } = await import("node:url");
  return new Uint8Array(await readFile(fileURLToPath(href)));
}

/**
 * Compiles and instantiates `spark.wasm`. Every call returns a fresh {@link SparkCrypto} the caller
 * owns.
 */
export async function loadSparkWasm(opts?: LoadSparkWasmOptions): Promise<SparkCrypto> {
  return bindSparkExports(await instantiateSparkWasm(await wasmBytes(opts)));
}
