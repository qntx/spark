import { describe, expect, test } from "vite-plus/test";

import { loadSparkWasm } from "../src/load.ts";
import { readWasmBytes } from "./read-wasm.ts";

// The default-bytes path resolves `spark.wasm?url`, which only exists after
// packing — it is covered by node-load.test.ts against dist/.
describe("loadSparkWasm (node entry)", () => {
  test("accepts explicit module bytes", async () => {
    const crypto = await loadSparkWasm({ module: await readWasmBytes() });
    expect(crypto.abiVersion).toBe(1);
    const out = crypto.frostCommit(new Uint8Array(32).fill(1), new Uint8Array(32).fill(7));
    expect(out).toHaveLength(130);
  });
});
