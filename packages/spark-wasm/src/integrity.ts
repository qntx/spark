/**
 * Subresource Integrity hash (`sha256-<base64>`) of the shipped `spark.wasm`, regenerated whenever
 * the artifact is rebuilt. Consumers that fetch the module themselves — for example a Wallet Worker
 * — can pin it at fetch time and hand the verified bytes to `loadSparkWasm`:
 *
 * ```ts
 * const res = await fetch(wasmUrl, { integrity: SPARK_WASM_INTEGRITY });
 * const crypto = await loadSparkWasm({ module: await res.arrayBuffer() });
 * ```
 *
 * `loadSparkWasm()` without `module` loads `spark.wasm` itself and does NOT verify this hash —
 * callers that want SRI enforcement must fetch with `integrity` and pass `module`.
 */
export const SPARK_WASM_INTEGRITY = "sha256-OBAVP0QjuY/JyeQh6Ay3XnczAKsMYrWoHdCJ73RSPeQ=";
