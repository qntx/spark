import { SparkError } from "@qntx/spark/crypto";
import type { SparkCrypto } from "@qntx/spark/crypto";

import { instantiateSparkWasm } from "./abi.ts";
import { bindSparkExports } from "./instance.ts";
import type { LoadSparkWasmOptions } from "./instance.ts";

export { WasmPoisonedError } from "./instance.ts";
export type { LoadSparkWasmOptions } from "./instance.ts";

async function fetchWasmUrl(url: URL): Promise<Uint8Array> {
  const res = await fetch(url);
  if (!res.ok) {
    throw new SparkError(`spark.wasm fetch failed (HTTP ${res.status})`);
  }
  return new Uint8Array(await res.arrayBuffer());
}

async function wasmBytes(opts?: LoadSparkWasmOptions): Promise<BufferSource> {
  const source = opts?.module;
  if (source !== undefined) {
    return source;
  }
  return fetchWasmUrl(new URL("spark.wasm", import.meta.url));
}

/**
 * Compiles and instantiates `spark.wasm`. Every call returns a fresh {@link SparkCrypto} the caller
 * owns.
 */
export async function loadSparkWasm(opts?: LoadSparkWasmOptions): Promise<SparkCrypto> {
  return bindSparkExports(await instantiateSparkWasm(await wasmBytes(opts)));
}
