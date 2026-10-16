import { expect, test } from "vite-plus/test";

import * as crypto from "../src/crypto/index.ts";
import * as root from "../src/index.ts";
import * as signer from "../src/signer/index.ts";

// Type-only exports cannot be enumerated at runtime; re-exporting each expected
// name makes a missing or renamed type export a compile error.
export type { SparkNetwork } from "../src/index.ts";
export type { SparkCrypto } from "../src/crypto/index.ts";
export type { SparkNetwork as SignerNetwork } from "../src/signer/index.ts";

function names(mod: object): string[] {
  return Object.keys(mod).toSorted();
}

test("root runtime exports are exactly the S0 error surface", () => {
  expect(names(root)).toStrictEqual(["SparkCryptoError", "SparkError"]);
});

test("crypto runtime exports are exactly the backend contract", () => {
  expect(names(crypto)).toStrictEqual(["SPARK_ABI_VERSION", "SparkCryptoError"]);
  expect(crypto.SPARK_ABI_VERSION).toBe(1);
});

test("signer has no runtime exports at S0", () => {
  expect(names(signer)).toStrictEqual([]);
});
