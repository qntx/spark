import { describe, expect, test } from "vite-plus/test";

import { checkCrates, checkTsLayers, crateFromManifest } from "./check-layers.ts";
import type { CrateInfo, SourceFile } from "./check-layers.ts";

function crate(name: string, deps: string[], publish = true): CrateInfo {
  return { name, publish, deps };
}

describe("check-layers (crates)", () => {
  test("accepts the allowed edges", () => {
    const crates = [crate("spark-crypto", []), crate("spark-ffi", ["spark-crypto"])];
    expect(checkCrates(crates)).toStrictEqual([]);
  });

  test("rejects a reverse edge", () => {
    const crates = [crate("spark-crypto", ["spark-ffi"]), crate("spark-ffi", [])];
    const errors = checkCrates(crates);
    expect(errors).toStrictEqual(["spark-crypto: must not depend on spark-ffi"]);
  });

  test("rejects a spark-crypto edge hidden in a target-specific dependency table", () => {
    const info = crateFromManifest(
      {
        package: { name: "spark-crypto" },
        dependencies: {},
        target: { "cfg(unix)": { dependencies: { "spark-ffi": { path: "../spark-ffi" } } } },
      },
      "spark-crypto",
    );
    expect(checkCrates([info])).toStrictEqual(["spark-crypto: must not depend on spark-ffi"]);
  });

  test("rejects a published crate depending on an unpublished crate", () => {
    const crates = [crate("spark-crypto", [], false), crate("spark-ffi", ["spark-crypto"])];
    expect(checkCrates(crates)).toStrictEqual([
      "spark-ffi: published crate must not depend on spark-crypto",
    ]);
  });

  test("rejects an unknown spark-* crate", () => {
    const errors = checkCrates([crate("spark-mystery", [])]);
    expect(errors).toStrictEqual(['unknown crate "spark-mystery"']);
  });

  test("ignores third-party dependencies", () => {
    const crates = [
      crate("spark-crypto", ["k256", "zeroize"]),
      crate("spark-ffi", ["spark-crypto", "prost"]),
    ];
    expect(checkCrates(crates)).toStrictEqual([]);
  });
});

const SRC = "src";

function file(path: string, source = ""): SourceFile {
  return { path: `${SRC}/${path}`, source };
}

describe("check-layers (ts)", () => {
  test("accepts a clean layered tree", () => {
    const files = [
      file("index.ts", 'export { SparkError } from "./errors/index.ts";'),
      file("errors/index.ts"),
      file("crypto/index.ts", 'import { SparkError } from "../errors/index.ts";'),
      file("core/index.ts", 'import "../errors/index.ts";'),
      file(
        "transfer/send.ts",
        'import type { SparkNetwork } from "../signer/index.ts";\n' +
          'import { conv } from "../core/index.ts";\n' +
          'import { leaf } from "../tree/index.ts";',
      ),
      file("signer/index.ts", 'export { createSparkSigner } from "./local.ts";'),
      file("signer/local.ts", 'import { pad } from "../core/index.ts";'),
    ];
    expect(checkTsLayers(files, SRC)).toStrictEqual([]);
  });

  test("rejects a layer import outside the allow list", () => {
    const files = [
      file("errors/index.ts", 'import { x } from "../crypto/index.ts";'),
      file("crypto/index.ts"),
    ];
    expect(checkTsLayers(files, SRC)).toStrictEqual([
      'src/errors/index.ts: must not import layer "crypto" (AGENTS.md layering)',
    ]);
  });

  test("rejects a value import of a type-only layer", () => {
    const files = [
      file("client/index.ts", 'import { createSparkSigner } from "../signer/index.ts";'),
      file("signer/index.ts"),
    ];
    expect(checkTsLayers(files, SRC)).toStrictEqual([
      "src/client/index.ts: signer is reachable only through import type (AGENTS.md layering)",
    ]);
  });

  test("accepts an import type of a type-only layer, incl. export type", () => {
    const files = [
      file(
        "tokens/mint.ts",
        'import type { SparkNetwork } from "../signer/index.ts";\n' +
          'export type { SparkNetwork as N } from "../signer/index.ts";',
      ),
      file("signer/index.ts"),
    ];
    expect(checkTsLayers(files, SRC)).toStrictEqual([]);
  });

  test("treats a dynamic import of a type-only layer as a value import", () => {
    const files = [
      file("client/index.ts", 'const s = await import("../signer/index.ts");'),
      file("signer/index.ts"),
    ];
    expect(checkTsLayers(files, SRC)).toStrictEqual([
      "src/client/index.ts: signer is reachable only through import type (AGENTS.md layering)",
    ]);
  });

  test("rejects an import of the package root from a layer", () => {
    const files = [
      file("errors/index.ts", 'import { SparkError } from "../index.ts";'),
      file("index.ts"),
    ];
    expect(checkTsLayers(files, SRC)).toStrictEqual([
      "src/errors/index.ts: layer files must not import the package root",
    ]);
  });

  test("rejects signer/local imports from outside src/signer", () => {
    const files = [
      file("core/x.ts", 'import type { K } from "../signer/local.ts";'),
      file("signer/local.ts"),
    ];
    expect(checkTsLayers(files, SRC)).toStrictEqual([
      "src/core/x.ts: signer/local is reachable only through src/signer/index.ts",
    ]);
  });

  test("rejects a signer file other than index.ts re-exporting local", () => {
    const files = [
      file("signer/other.ts", 'export { createSparkSigner } from "./local.ts";'),
      file("signer/local.ts"),
    ];
    expect(checkTsLayers(files, SRC)).toStrictEqual([
      "src/signer/other.ts: only src/signer/index.ts may re-export signer/local",
    ]);
  });

  test("rejects a file directly under src/ other than index.ts", () => {
    const files = [file("utils.ts")];
    expect(checkTsLayers(files, SRC)).toStrictEqual([
      "src/utils.ts: only index.ts may live directly under src/",
    ]);
  });

  test("rejects an unknown top-level directory", () => {
    const files = [file("mystery/x.ts")];
    expect(checkTsLayers(files, SRC)).toStrictEqual([
      'src/mystery/x.ts: unknown top-level directory "mystery"',
    ]);
  });

  test("rejects an import that resolves to an unknown top-level directory", () => {
    const files = [file("core/x.ts", 'import { y } from "../mystery/y.ts";'), file("mystery/y.ts")];
    expect(checkTsLayers(files, SRC)).toStrictEqual([
      'src/core/x.ts: unknown top-level directory "mystery"',
      'src/mystery/y.ts: unknown top-level directory "mystery"',
    ]);
  });

  test("reaches nested directories inside a layer", () => {
    const files = [
      file("core/bitcoin/tx.ts", 'import { P } from "../../proto/index.ts";'),
      file("core/hashing/h.ts", 'import { T } from "../../crypto/index.ts";'),
      file("proto/index.ts"),
      file("crypto/index.ts"),
    ];
    expect(checkTsLayers(files, SRC)).toStrictEqual([
      'src/core/hashing/h.ts: must not import layer "crypto" (AGENTS.md layering)',
    ]);
  });
});
