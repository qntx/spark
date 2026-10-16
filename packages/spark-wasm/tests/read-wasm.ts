import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

/** Reads the committed wasm artifact; used by the test files only. */
export async function readWasmBytes(): Promise<Uint8Array<ArrayBuffer>> {
  return new Uint8Array(
    await readFile(fileURLToPath(new URL("../src/spark.wasm", import.meta.url))),
  );
}
