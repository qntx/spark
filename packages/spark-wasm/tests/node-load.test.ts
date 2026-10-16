import { describe, expect, test } from "vite-plus/test";

// Packed entry exists only after `vp pack`.
import { loadSparkWasm } from "../dist/index.mjs";
import { readWasmBytes } from "./read-wasm.ts";

const COMMIT_OUT = 130;

describe("packed dist/index.mjs", () => {
  test("loadSparkWasm() with omitted module instantiates from the packed sibling wasm", async () => {
    const crypto = await loadSparkWasm();
    expect(crypto.abiVersion).toBe(1);
    expect(crypto.frostCommit(new Uint8Array(32).fill(1), new Uint8Array(32).fill(7))).toHaveLength(
      COMMIT_OUT,
    );
  });

  test("loadSparkWasm({ module }) loads from BufferSource", async () => {
    const crypto = await loadSparkWasm({ module: await readWasmBytes() });
    expect(crypto.abiVersion).toBe(1);
  });
});
