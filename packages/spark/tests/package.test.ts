import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

import { expect, test } from "vite-plus/test";

const root = resolve(import.meta.dirname, "..");
const pkg = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")) as {
  license: string;
  files: string[];
  exports: Record<string, unknown>;
  publishConfig?: { exports?: unknown };
};

function exportTarget(value: unknown): string {
  if (typeof value === "string") {
    return value;
  }
  if (value && typeof value === "object" && "default" in value) {
    const next = value.default;
    if (typeof next === "string") {
      return next;
    }
  }
  throw new Error(`unexpected export entry: ${JSON.stringify(value)}`);
}

const dist = (name: string) => pathToFileURL(resolve(root, "dist", name)).href;

test("package exports resolve to packed files, not source", () => {
  expect(exportTarget(pkg.exports["."])).toBe("./dist/index.mjs");
  expect(exportTarget(pkg.exports["./crypto"])).toBe("./dist/crypto.mjs");
  expect(exportTarget(pkg.exports["./signer"])).toBe("./dist/signer.mjs");
  expect(exportTarget(pkg.exports["./lnurl"])).toBe("./dist/lnurl.mjs");
  expect(pkg.publishConfig?.exports).toBeUndefined();
});

test.each([
  "index.mjs",
  "index.d.mts",
  "crypto.mjs",
  "crypto.d.mts",
  "signer.mjs",
  "signer.d.mts",
  "lnurl.mjs",
  "lnurl.d.mts",
])("dist/%s exists after vp pack", (file) => {
  expect(existsSync(resolve(root, "dist", file))).toBe(true);
});

test("files and license fields match the Apache-2.0 contract", () => {
  expect(pkg.files).toStrictEqual(["dist", "LICENSE", "NOTICE"]);
  expect(pkg.license).toBe("Apache-2.0");
});

test("packed error classes are shared across entries", async () => {
  const index = (await import(dist("index.mjs"))) as { SparkCryptoError: unknown };
  const crypto = (await import(dist("crypto.mjs"))) as {
    SparkCryptoError: unknown;
    SPARK_ABI_VERSION: number;
  };
  expect(index.SparkCryptoError).toBe(crypto.SparkCryptoError);
  expect(crypto.SPARK_ABI_VERSION).toBe(1);
});
