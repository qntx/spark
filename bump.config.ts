import { execFileSync } from "node:child_process";

import { defineConfig } from "bumpp";

// npm package and Cargo workspace versions are lockstep; bumpp rewrites every
// `x.y.z` occurrence of the current version in non-JSON files, so Cargo.toml
// picks up both [workspace.package].version and any `spark-* = "=x.y.z"` dep.
const config: ReturnType<typeof defineConfig> = defineConfig({
  files: [
    "packages/spark/package.json",
    "packages/spark-wasm/package.json",
    "packages/spark-native/package.json",
    "Cargo.toml",
  ],
  // crates/interop is its own workspace, so its lockfile needs a separate
  // `cargo update`. A string `execute` is not run through a shell, so the
  // updates run as separate processes.
  execute: () => {
    for (const manifest of ["Cargo.toml", "crates/interop/Cargo.toml"]) {
      execFileSync("cargo", ["update", "--workspace", "--manifest-path", manifest], {
        stdio: "inherit",
      });
    }
  },
  // execute rewrites both lockfiles; commit them too.
  all: true,
  commit: true,
  // main is protected: release through a `release/v<version>` pull request
  // opened via `gh`. No tag is created; after the release PR merges, tag the
  // merge commit by hand (GITHUB_TOKEN tags do not trigger publish workflows).
  pr: true,
  push: true,
});

export default config;
