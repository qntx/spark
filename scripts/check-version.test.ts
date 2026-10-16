import { describe, expect, test } from "vite-plus/test";

import { checkVersion, peerRange } from "./check-version.ts";

const CARGO_TOML = `[workspace]
members = ["crates/spark-crypto", "crates/spark-ffi"]

[workspace.package]
version = "1.8.0"

[workspace.dependencies]
spark-crypto = { version = "=1.8.0", path = "crates/spark-crypto" }
hex = "0.4"
`;

const PARSED = {
  workspace: {
    package: { version: "1.8.0" },
    dependencies: {
      "spark-crypto": { version: "=1.8.0", path: "crates/spark-crypto" },
      hex: "0.4",
    },
  },
};

const SPARK = {
  path: "packages/spark/package.json",
  pkg: { name: "@qntx/spark", version: "1.8.0" },
};

const PRIVATE_PKG = {
  path: "packages/sandbox/package.json",
  pkg: { name: "@qntx/sandbox", version: "0.0.1", private: true },
};

const CRATES = [
  {
    path: "crates/spark-crypto/Cargo.toml",
    manifest: { package: { name: "spark-crypto", version: { workspace: true } } },
  },
  {
    path: "crates/spark-ffi/Cargo.toml",
    manifest: { package: { name: "spark-ffi", version: { workspace: true } } },
  },
];

const PACKAGES = [SPARK, PRIVATE_PKG];

describe("check-version", () => {
  test("accepts synced versions", () => {
    expect(checkVersion(PACKAGES, PARSED, CARGO_TOML, CRATES)).toStrictEqual([]);
  });

  test("rejects a package.json mismatch", () => {
    const errors = checkVersion(
      [{ ...SPARK, pkg: { ...SPARK.pkg, version: "1.8.1" } }, PRIVATE_PKG],
      PARSED,
      CARGO_TOML,
      CRATES,
    );
    expect(errors).toStrictEqual([
      "version mismatch: packages/spark/package.json has 1.8.1, Cargo.toml has 1.8.0",
    ]);
  });

  test("ignores private packages", () => {
    const pkg = { name: "@qntx/sandbox", version: "9.9.9", private: true };
    const errors = checkVersion([SPARK, { ...PRIVATE_PKG, pkg }], PARSED, CARGO_TOML, CRATES);
    expect(errors).toStrictEqual([]);
  });

  test("rejects a crate manifest that hard-codes a version", () => {
    const crates = [
      {
        path: "crates/spark-crypto/Cargo.toml",
        manifest: { package: { name: "spark-crypto", version: { workspace: true } } },
      },
      {
        path: "crates/spark-ffi/Cargo.toml",
        manifest: { package: { name: "spark-ffi", version: "1.8.0" } },
      },
    ];
    const errors = checkVersion(PACKAGES, PARSED, CARGO_TOML, crates);
    expect(errors).toStrictEqual([
      'crates/spark-ffi/Cargo.toml: package version must be "version.workspace = true"',
    ]);
  });

  test("rejects an internal dep not pinned to the workspace version", () => {
    const parsed = structuredClone(PARSED);
    parsed.workspace.dependencies["spark-crypto"].version = "=1.7.0";
    const errors = checkVersion(PACKAGES, parsed, CARGO_TOML, CRATES);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("spark-crypto");
  });

  test("rejects a third-party dep equal to the current version", () => {
    const toml = CARGO_TOML.replace('hex = "0.4"', 'hex = "1.8.0"');
    const parsed = structuredClone(PARSED);
    parsed.workspace.dependencies.hex = "1.8.0";
    const errors = checkVersion(PACKAGES, parsed, toml, CRATES);
    expect(errors).toStrictEqual([
      'Cargo.toml: "1.8.0" appears 3 times, expected 2 ([workspace.package] plus internal path dependencies)',
    ]);
  });

  test("accepts a backend package with the peer caret", () => {
    const wasm = {
      path: "packages/spark-wasm/package.json",
      pkg: {
        name: "@qntx/spark-wasm",
        version: "1.8.0",
        peerDependencies: { "@qntx/spark": "^1.0.0" },
        devDependencies: { "@qntx/spark": "1.8.0" },
      },
    };
    expect(checkVersion([SPARK, wasm], PARSED, CARGO_TOML, CRATES)).toStrictEqual([]);
  });

  test("rejects a backend package missing the peer caret", () => {
    const wasm = {
      path: "packages/spark-wasm/package.json",
      pkg: {
        name: "@qntx/spark-wasm",
        version: "1.8.0",
        dependencies: { "@qntx/spark": "^1.0.0" },
      },
    };
    expect(checkVersion([SPARK, wasm], PARSED, CARGO_TOML, CRATES)).toStrictEqual([
      'packages/spark-wasm/package.json: @qntx/spark must be a peerDependency "^1.0.0", got undefined',
      'packages/spark-wasm/package.json: @qntx/spark must not appear in "dependencies" (peer only)',
    ]);
  });

  test("peerRange uses ^0.y.0 below 1.0 and ^x.0.0 after", () => {
    expect(peerRange("0.3.0")).toBe("^0.3.0");
    expect(peerRange("1.8.0")).toBe("^1.0.0");
    expect(peerRange("2.0.0")).toBe("^2.0.0");
  });
});
