/**
 * Types for the packed `@qntx/spark-wasm` entry, resolved through the package `exports` map only
 * after `vp pack`. The ambient declaration keeps the signer test backend fully typed on a fresh
 * checkout without the dist artifact.
 */
// oxlint-disable typescript/consistent-type-imports -- ambient module bodies cannot use import statements
declare module "@qntx/spark-wasm" {
  export function loadSparkWasm(opts?: {
    module?: ArrayBuffer | ArrayBufferView;
  }): Promise<import("../../src/crypto/index.ts").SparkCrypto>;
}
