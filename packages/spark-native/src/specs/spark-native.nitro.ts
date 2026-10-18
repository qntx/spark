import type { HybridObject } from "react-native-nitro-modules";

/**
 * Native `SparkCrypto` backend: the `spark-ffi` cdylib (`qntx_spark.h`, `qs_*` entry points) behind
 * a shared C++ HybridObject. Every method maps 1:1 onto the C ABI — inputs and outputs are
 * `ArrayBuffer`s, and a nonzero `qs_*` return code surfaces as an `Error` whose message is
 * `qntx_spark:<code>`. `abiVersion()` reports `qs_abi_version()`; the TypeScript wrapper compares
 * it against `SPARK_ABI_VERSION` before use.
 */
export interface SparkNative extends HybridObject<{ ios: "c++"; android: "c++" }> {
  abiVersion(): number;
  frostCommit(hedge: ArrayBuffer, random: ArrayBuffer): ArrayBuffer;
  frostSign(request: ArrayBuffer): ArrayBuffer;
  frostAggregate(request: ArrayBuffer): ArrayBuffer;
  eciesEncrypt(publicKey: ArrayBuffer, plaintext: ArrayBuffer, random: ArrayBuffer): ArrayBuffer;
  eciesDecrypt(privateKey: ArrayBuffer, ciphertext: ArrayBuffer): ArrayBuffer;
  splitSecretWithProofs(
    secret: ArrayBuffer,
    threshold: number,
    shares: number,
    random: ArrayBuffer,
  ): ArrayBuffer;
}
