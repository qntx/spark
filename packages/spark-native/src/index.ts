import { NitroModules } from "react-native-nitro-modules";

import type { SparkCrypto } from "@qntx/spark/crypto";

import { bindSparkNative } from "./bind.ts";
import type { SparkNative } from "./specs/spark-native.nitro.ts";

export { bindSparkNative } from "./bind.ts";

/**
 * `SparkCrypto` backend backed by the prebuilt `qntx_spark` native library (iOS `QntxSpark`
 * xcframework / Android `libqntx_spark.so`) through the `SparkNative` HybridObject — plug into
 * signer and crypto consumers the same way as `@qntx/spark-wasm`'s backend.
 */
export function createSparkNativeBackend(): SparkCrypto {
  return bindSparkNative(NitroModules.createHybridObject<SparkNative>("SparkNative"));
}
