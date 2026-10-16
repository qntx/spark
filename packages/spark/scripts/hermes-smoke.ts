/// <reference types="node" />
/**
 * Bundle tests/hermes/entry.ts into a single classic script and run it on the Hermes CLI (`HERMES`
 * env var). Pass = stdout contains `HERMES_SMOKE_OK`; Hermes exits 0 on unhandled async rejections,
 * so the marker is the only contract. The full Hermes output is printed either way.
 *
 * The entry imports the packed `dist/` builds, so `smoke:hermes` runs `vp pack` first.
 */
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

// The repo does not depend on @types/bun; declare the used surface.
type BunBuildOutput = {
  success: boolean;
  logs: ReadonlyArray<{ toString: () => string }>;
  outputs: ReadonlyArray<{ kind: string; text: () => Promise<string> }>;
};
declare const Bun: {
  build: (options: {
    entrypoints: string[];
    target: "browser";
    format: "iife";
  }) => Promise<BunBuildOutput>;
  write: (path: string, data: unknown) => Promise<unknown>;
  spawnSync: (
    cmd: ReadonlyArray<string>,
    options: { stdout: "pipe"; stderr: "pipe" },
  ) => {
    exitCode: number;
    stdout: { toString: () => string };
    stderr: { toString: () => string };
  };
};

const root = fileURLToPath(new URL("..", import.meta.url));
const outfile = resolve(root, ".hermes-smoke.iife.js");

async function main(): Promise<number> {
  const result = await Bun.build({
    entrypoints: [resolve(root, "tests/hermes/entry.ts")],
    target: "browser",
    format: "iife",
  });
  if (!result.success) {
    for (const log of result.logs) {
      console.error(String(log));
    }
    return 1;
  }
  const bundle = result.outputs.find((o) => o.kind === "entry-point");
  if (!bundle) {
    console.error("bun build produced no entry-point output");
    return 1;
  }
  // protobuf-es needs TextEncoder/TextDecoder at module load. RN 0.88 Hermes
  // (what CI runs) ships both; HERMES_ENCODING_SHIM=1 prepends shims only for
  // local runs against an older Hermes binary.
  const shim =
    process.env["HERMES_ENCODING_SHIM"] === "1"
      ? `${readFileSync(resolve(root, "tests/hermes/prelude.js"), "utf8")}\n`
      : "";
  await Bun.write(outfile, `${shim}${await bundle.text()}`);

  const hermes = process.env["HERMES"];
  if (hermes === undefined || hermes === "") {
    console.error("set HERMES to the hermes binary (bundle written to .hermes-smoke.iife.js)");
    return 1;
  }

  const proc = Bun.spawnSync([hermes, outfile], { stdout: "pipe", stderr: "pipe" });
  const out = proc.stdout.toString() + proc.stderr.toString();
  process.stdout.write(out);
  if (proc.exitCode !== 0 || !out.includes("HERMES_SMOKE_OK")) {
    console.error(`hermes smoke failed (exit ${proc.exitCode}): no HERMES_SMOKE_OK`);
    return 1;
  }
  return 0;
}

process.exitCode = await main();
