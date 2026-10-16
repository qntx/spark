/**
 * Hermes smoke test: loads the packed `.`, `./crypto` and `./signer` builds. `smoke:hermes` packs
 * first; these dist files are the contract React Native bundles.
 */
import * as crypto from "../../dist/crypto.mjs";
import * as root from "../../dist/index.mjs";
import "../../dist/signer.mjs";

function assert(cond: boolean, name: string): asserts cond {
  if (!cond) {
    throw new Error(`smoke: ${name}`);
  }
}

export function main(): void {
  assert(crypto.SPARK_ABI_VERSION === 1, "SPARK_ABI_VERSION");

  const error = new crypto.SparkCryptoError(7);
  assert(error instanceof root.SparkError, "SparkCryptoError extends SparkError");
  assert(error instanceof root.SparkCryptoError, "SparkCryptoError instance");
  assert(error.name === "SparkCryptoError", "SparkCryptoError name");
  assert(error.code === 7, "SparkCryptoError code");
  assert(
    error.message === "spark crypto backend failed (code 7)",
    "SparkCryptoError message carries no inputs",
  );
}
