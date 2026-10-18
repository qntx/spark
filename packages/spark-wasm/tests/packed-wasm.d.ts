/**
 * Types for the packed `dist/*.mjs` entries, which exist only after `vp pack`. The wildcard ambient
 * module keeps the dist tests fully typed without the artifact on disk.
 */
// oxlint-disable typescript/consistent-type-imports -- ambient module bodies cannot use import statements
declare module "*.mjs" {
  export function loadSparkWasm(
    opts?: import("../src/instance.ts").LoadSparkWasmOptions,
  ): Promise<import("@qntx/spark/crypto").SparkCrypto>;
  // oxlint-disable-next-line unicorn/custom-error-definition -- ambient declaration only
  export class WasmPoisonedError extends Error {}
}
