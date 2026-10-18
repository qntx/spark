#!/usr/bin/env bun
/// <reference types="node" />
import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  rmSync,
  symlinkSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Host compile check for cpp/HybridSparkNative.cpp — clang++ -fsyntax-only against
// the generated Nitrogen spec, the real Nitro C++ headers, React Native's JSI
// headers, and qntx_spark.h. No linking: this proves the HybridObject code
// compiles on any host without a simulator or an RN app.
//
// On both platforms the spec's `<NitroModules/*.hpp>` includes resolve through a
// flattened header root (pod modulemap on iOS, the nitro prefab on Android); the
// check recreates that root as a staging dir of symlinks.

const PACKAGE_DIR = resolve(import.meta.dirname, "..");
const REPO = resolve(PACKAGE_DIR, "../..");

function requirePath(...segments: string[]): string {
  const path = join(...segments);
  if (!existsSync(path)) {
    console.error(`host-syntax: missing ${path}`);
    process.exit(1);
  }
  return path;
}

function packageDir(name: string): string {
  return dirname(fileURLToPath(import.meta.resolve(`${name}/package.json`)));
}

// The build script copies the cbindgen header into include/; do the same here so
// the check works on a fresh checkout without a full native build.
const headerSrc = join(REPO, "crates/spark-ffi/include/qntx_spark.h");
const headerDst = join(PACKAGE_DIR, "include/qntx_spark.h");
if (!existsSync(headerDst)) {
  mkdirSync(dirname(headerDst), { recursive: true });
  copyFileSync(headerSrc, headerDst);
}

const nitro = packageDir("react-native-nitro-modules");
const reactNative = packageDir("react-native");

// Flatten every nitro C++ header into a staging `NitroModules/` include root
// (no name collisions across cpp subdirectories).
const staging = mkdtempSync(join(tmpdir(), "spark-native-host-"));
const nitroRoot = join(staging, "NitroModules");
mkdirSync(nitroRoot);
const nitroCpp = join(nitro, "cpp");
function linkHeaders(dir: string): void {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      linkHeaders(path);
    } else if (entry.name.endsWith(".hpp") || entry.name.endsWith(".h")) {
      symlinkSync(path, join(nitroRoot, entry.name));
    }
  }
}
linkHeaders(nitroCpp);

const includeFlags = [
  staging,
  join(PACKAGE_DIR, "cpp"),
  join(PACKAGE_DIR, "include"),
  join(PACKAGE_DIR, "nitrogen/generated/shared/c++"),
  join(reactNative, "ReactCommon/jsi"),
].flatMap((dir) => ["-I", requirePath(dir)]);

const clang = process.env.CXX ?? "clang++";
const result = spawnSync(
  clang,
  [
    "-std=c++20",
    "-fsyntax-only",
    "-Wall",
    "-Wextra",
    ...includeFlags,
    join(PACKAGE_DIR, "cpp/HybridSparkNative.cpp"),
  ],
  { stdio: "inherit" },
);
rmSync(staging, { recursive: true, force: true });
process.exit(result.status ?? 1);
