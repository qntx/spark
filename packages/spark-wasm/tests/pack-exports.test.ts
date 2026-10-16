import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vite-plus/test";

// Runs against the packed artifact; `vp pack` must have run first.
describe("packed exports", () => {
  test("dist/index.mjs exports loadSparkWasm and WasmPoisonedError", async () => {
    const mod = await import("../dist/index.mjs");
    expect(mod.loadSparkWasm).toBeTypeOf("function");
    expect(mod.WasmPoisonedError).toBeTypeOf("function");
    expect(Object.keys(mod).toSorted()).toStrictEqual(["WasmPoisonedError", "loadSparkWasm"]);
  });

  test("dist/browser.mjs exports the same surface", async () => {
    const mod = await import("../dist/browser.mjs");
    expect(Object.keys(mod).toSorted()).toStrictEqual(["WasmPoisonedError", "loadSparkWasm"]);
  });

  test("the packed wasm asset ships next to the entries", async () => {
    const stat = await readFile("dist/spark.wasm");
    const src = await readFile("src/spark.wasm");
    expect(stat.equals(src)).toBe(true);
  });
});
