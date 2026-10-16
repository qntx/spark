import { expect, test } from "vite-plus/test";

import { SPARK_WASM_INTEGRITY } from "../src/integrity.ts";
import { readWasmBytes } from "./read-wasm.ts";

test("SPARK_WASM_INTEGRITY matches the committed spark.wasm", async () => {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", await readWasmBytes()));
  const expected = `sha256-${btoa(String.fromCodePoint(...digest))}`;
  expect(SPARK_WASM_INTEGRITY).toBe(expected);
});
