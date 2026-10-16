/// <reference types="node" />
import { readFileSync } from "node:fs";

// The repo does not depend on @types/bun; declare the used surface.
declare const Bun: {
  spawnSync: (
    cmd: ReadonlyArray<string>,
    options: { stdout: "pipe"; stderr: "pipe" },
  ) => {
    exitCode: number;
    stdout: { toString: () => string };
    stderr: { toString: () => string };
  };
};

const CRATE = "crates/spark-ffi";
const HEADER = `${CRATE}/include/qntx_spark.h`;

/**
 * Regenerates the spark-ffi C header with cbindgen and diffs it against the committed copy. The
 * committed header is a contract surface; drift between it and the crate source is a failure.
 *
 * When the `cbindgen` binary is not installed the check is skipped with a warning — CI's `headers`
 * job installs it explicitly (`cargo install cbindgen --locked`, version pinned in
 * crates/spark-ffi/cbindgen.toml).
 */
function main(): number {
  try {
    const found = Bun.spawnSync(["cbindgen", "--version"], {
      stdout: "pipe",
      stderr: "pipe",
    });
    if (found.exitCode !== 0) {
      console.error(`check-cbindgen: cbindgen unusable: ${found.stderr.toString()}`);
      return 1;
    }
  } catch {
    // Bun.spawnSync throws on ENOENT.
    console.warn("check-cbindgen: cbindgen not installed, skipping (CI headers job covers it)");
    return 0;
  }

  const generated = Bun.spawnSync(
    ["cbindgen", "--config", `${CRATE}/cbindgen.toml`, "--output", "/dev/stdout", CRATE],
    { stdout: "pipe", stderr: "pipe" },
  );
  if (generated.exitCode !== 0) {
    console.error(`check-cbindgen: cbindgen failed: ${generated.stderr.toString()}`);
    return 1;
  }

  const committed = readFileSync(HEADER, "utf8");
  if (generated.stdout.toString() !== committed) {
    console.error(
      `check-cbindgen: ${HEADER} is stale; regenerate with` +
        ` \`cbindgen --config ${CRATE}/cbindgen.toml --output ${HEADER} ${CRATE}\``,
    );
    return 1;
  }
  return 0;
}

process.exitCode = main();
