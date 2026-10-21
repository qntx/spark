import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vite-plus/test";

// Runs against the packed artifact; `vp pack` must have run first.
describe("packed exports", () => {
  const expectedExports = ["SPARK_WASM_INTEGRITY", "WasmPoisonedError", "loadSparkWasm"];

  test("dist/index.mjs exports loadSparkWasm, WasmPoisonedError and SPARK_WASM_INTEGRITY", async () => {
    const mod = await import("../dist/index.mjs");
    expect(mod.loadSparkWasm).toBeTypeOf("function");
    expect(mod.WasmPoisonedError).toBeTypeOf("function");
    expect(Object.keys(mod).toSorted()).toStrictEqual(expectedExports);
  });

  test("dist/browser.mjs exports the same surface", async () => {
    const mod = await import("../dist/browser.mjs");
    expect(Object.keys(mod).toSorted()).toStrictEqual(expectedExports);
  });

  test("the packed wasm asset ships next to the entries", async () => {
    const stat = await readFile("dist/spark.wasm");
    const src = await readFile("src/spark.wasm");
    expect(stat.equals(src)).toBe(true);
  });

  test("the exported SPARK_WASM_INTEGRITY matches the packed spark.wasm", async () => {
    const [index, browser, wasm] = await Promise.all([
      import("../dist/index.mjs"),
      import("../dist/browser.mjs"),
      readFile("dist/spark.wasm"),
    ]);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", wasm));
    const expected = `sha256-${btoa(String.fromCodePoint(...digest))}`;
    expect(index.SPARK_WASM_INTEGRITY).toBe(expected);
    expect(browser.SPARK_WASM_INTEGRITY).toBe(expected);
  });
});
