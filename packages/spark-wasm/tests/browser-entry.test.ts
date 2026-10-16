import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vite-plus/test";

// Packed entry exists only after `vp pack`.
import { loadSparkWasm } from "../dist/browser.mjs";
import { readWasmBytes } from "./read-wasm.ts";

describe("packed dist/browser.mjs", () => {
  test("contains no node: specifier", async () => {
    const src = await readFile("dist/browser.mjs", "utf8");
    expect(src).not.toMatch(/["']node:/);
  });

  test("loadSparkWasm({ module: bytes }) instantiates and runs", async () => {
    const crypto = await loadSparkWasm({ module: await readWasmBytes() });
    expect(crypto.abiVersion).toBe(1);
    expect(crypto.frostCommit(new Uint8Array(32).fill(1), new Uint8Array(32).fill(7))).toHaveLength(
      130,
    );
  });
});
