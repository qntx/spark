#!/usr/bin/env bun
/// <reference types="node" />
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir, platform } from "node:os";
import { dirname, join, resolve } from "node:path";

// Builds the prebuilt `qntx_spark` (spark-ffi cdylib) libraries that
// @qntx/spark-native ships: an iOS `QntxSpark.xcframework` and per-ABI Android
// `libqntx_spark.so` jniLibs, plus a copy of `qntx_spark.h`. All outputs are
// gitignored build products consumed by the podspec and CMake.
//
//   bun run build:native            # iOS + Android
//   bun run build:native --ios
//   bun run build:native --android
//
// The NDK is located via $ANDROID_NDK_HOME, then $ANDROID_HOME/ndk/<pinned>,
// then ~/Library/Android/sdk/ndk/<pinned>; no cargo-ndk — the NDK's own clang
// is wired per target through CARGO_TARGET_*_LINKER.

const REPO = resolve(import.meta.dirname, "..");
const NATIVE = join(REPO, "packages/spark-native");
const HEADER_SRC = join(REPO, "crates/spark-ffi/include/qntx_spark.h");
const HEADER_DST = join(NATIVE, "include/qntx_spark.h");

// Matches packages/spark-native/android/gradle.properties.
const NDK_VERSION = "27.1.12297006";
const ANDROID_API = 24;
// React Native's minimum deployment target (min_ios_version_supported, RN >= 0.76).
const IOS_DEPLOYMENT_TARGET = "15.1";
const INSTALL_NAME = "@rpath/QntxSpark.framework/QntxSpark";

const ANDROID_TARGETS = [
  ["aarch64-linux-android", "arm64-v8a", "aarch64-linux-android"],
  ["armv7-linux-androideabi", "armeabi-v7a", "armv7a-linux-androideabi"],
  ["x86_64-linux-android", "x86_64", "x86_64-linux-android"],
  ["i686-linux-android", "x86", "i686-linux-android"],
] as const;

const IOS_TARGETS = ["aarch64-apple-ios", "aarch64-apple-ios-sim", "x86_64-apple-ios"] as const;

function fail(message: string): never {
  console.error(`build-native: ${message}`);
  process.exit(1);
}

function sh(cmd: string, args: ReadonlyArray<string>, env?: Record<string, string>): string {
  const result = spawnSync(cmd, [...args], {
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
  if (result.status !== 0) {
    process.stderr.write(result.stderr ?? "");
    fail(`${cmd} ${args.join(" ")} exited ${result.status ?? "?"}\n${result.stderr ?? ""}`);
  }
  return result.stdout ?? "";
}

function sha256(path: string): string {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

// Dynamic symbols a stripped shared library legitimately carries besides the
// ABI: ELF section-boundary markers emitted by the linker.
const PLATFORM_SYMBOLS = new Set([
  "__bss_start",
  "__end__",
  "_bss_end__",
  "__executable_start",
  "edata",
  "end",
]);

/** Parses `nm`-style output into a flat symbol-name list. */
function listExports(tool: string, args: ReadonlyArray<string>, binary: string): string[] {
  return sh(tool, [...args, binary])
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .map((line) => line.split(/\s+/).at(-1) ?? "")
    .filter((name) => name.length > 0);
}

/** Every exported dynamic symbol must be a `qs_*` entry point. Mach-O prefixes symbols with `_`. */
function checkExports(names: string[], label: string): void {
  const leaked = names.filter((name) => {
    const normalized = name.startsWith("_") && !name.startsWith("__") ? name.slice(1) : name;
    return !normalized.startsWith("qs_") && !PLATFORM_SYMBOLS.has(normalized);
  });
  if (leaked.length > 0) {
    fail(`${label}: unexpected exported symbols: ${leaked.join(", ")}`);
  }
}

function copyHeader(): void {
  // include/ is gitignored (it only holds this copy) — recreate it in clean checkouts.
  mkdirSync(dirname(HEADER_DST), { recursive: true });
  copyFileSync(HEADER_SRC, HEADER_DST);
  console.log(`header: packages/spark-native/include/qntx_spark.h sha256=${sha256(HEADER_DST)}`);
}

// --- iOS -------------------------------------------------------------------

function frameworkPlist(platforms: string[]): string {
  const platformEntries = platforms.map((name) => `    <string>${name}</string>`).join("\n");
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleDevelopmentRegion</key>
    <string>en</string>
    <key>CFBundleExecutable</key>
    <string>QntxSpark</string>
    <key>CFBundleIdentifier</key>
    <string>org.qntx.spark</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleName</key>
    <string>QntxSpark</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
    <key>CFBundleShortVersionString</key>
    <string>0.0.0</string>
    <key>CFBundleVersion</key>
    <string>1</string>
    <key>CFBundleSupportedPlatforms</key>
    <array>
${platformEntries}
    </array>
    <key>MinimumOSVersion</key>
    <string>${IOS_DEPLOYMENT_TARGET}</string>
</dict>
</plist>
`;
}

function writeFramework(dir: string, binary: string, platforms: string[]): string {
  const framework = join(dir, "QntxSpark.framework");
  mkdirSync(join(framework, "Headers"), { recursive: true });
  mkdirSync(join(framework, "Modules"), { recursive: true });
  copyFileSync(binary, join(framework, "QntxSpark"));
  copyFileSync(HEADER_SRC, join(framework, "Headers/qntx_spark.h"));
  writeFileSync(
    join(framework, "Modules/module.modulemap"),
    'framework module QntxSpark {\n  header "qntx_spark.h"\n  export *\n}\n',
  );
  writeFileSync(join(framework, "Info.plist"), frameworkPlist(platforms));
  return framework;
}

const dylib = (target: string) => join(REPO, "target", target, "release", "libspark_ffi.dylib");

function buildIos(): void {
  if (platform() !== "darwin") {
    fail("--ios requires macOS (xcodebuild, lipo)");
  }
  const rustflags = `-C link-arg=-Wl,-install_name,${INSTALL_NAME}`;
  const env = { IPHONEOS_DEPLOYMENT_TARGET: IOS_DEPLOYMENT_TARGET };

  for (const target of IOS_TARGETS) {
    sh("cargo", ["build", "--release", "-p", "spark-ffi", "--target", target], {
      ...env,
      [`CARGO_TARGET_${target.replaceAll("-", "_").toUpperCase()}_RUSTFLAGS`]: rustflags,
    });
    if (!existsSync(dylib(target))) {
      fail(`missing ${dylib(target)}`);
    }
  }

  const staging = join(NATIVE, "ios/staging");
  rmSync(staging, { recursive: true, force: true });
  mkdirSync(staging, { recursive: true });
  const simBinary = join(staging, "libspark_ffi-sim.dylib");
  sh("lipo", [
    "-create",
    dylib("aarch64-apple-ios-sim"),
    dylib("x86_64-apple-ios"),
    "-output",
    simBinary,
  ]);

  const deviceFramework = writeFramework(join(staging, "ios-arm64"), dylib("aarch64-apple-ios"), [
    "iPhoneOS",
  ]);
  const simFramework = writeFramework(join(staging, "ios-arm64_x86_64-simulator"), simBinary, [
    "iPhoneSimulator",
  ]);

  const output = join(NATIVE, "ios/QntxSpark.xcframework");
  rmSync(output, { recursive: true, force: true });
  mkdirSync(dirname(output), { recursive: true });
  sh("xcodebuild", [
    "-create-xcframework",
    "-framework",
    deviceFramework,
    "-framework",
    simFramework,
    "-output",
    output,
  ]);

  const installName = (
    sh("otool", ["-D", join(deviceFramework, "QntxSpark")])
      .trim()
      .split("\n")
      .at(-1) ?? ""
  ).trim();
  if (installName !== INSTALL_NAME) {
    fail(`install_name is ${installName}, expected ${INSTALL_NAME}`);
  }

  for (const [label, binary] of [
    ["ios-arm64", join(deviceFramework, "QntxSpark")],
    ["ios-simulator", join(simFramework, "QntxSpark")],
  ] as const) {
    const exports = listExports("nm", ["-gU"], binary);
    checkExports(exports, label);
    console.log(
      `ios ${label}: ${statSync(binary).size} B sha256=${sha256(binary)} exports=${exports.length}`,
    );
  }
  rmSync(staging, { recursive: true, force: true });
  console.log(`xcframework: packages/spark-native/ios/QntxSpark.xcframework`);
}

// --- Android ---------------------------------------------------------------

function ndkHome(): string {
  const candidates = [
    process.env["ANDROID_NDK_HOME"],
    process.env["ANDROID_NDK_ROOT"],
    process.env["ANDROID_HOME"] === undefined
      ? undefined
      : join(process.env["ANDROID_HOME"], "ndk", NDK_VERSION),
    join(homedir(), "Library/Android/sdk/ndk", NDK_VERSION),
  ];
  for (const candidate of candidates) {
    if (candidate !== undefined && existsSync(join(candidate, "toolchains"))) {
      return candidate;
    }
  }
  return fail(`Android NDK ${NDK_VERSION} not found (set ANDROID_NDK_HOME)`);
}

function ndkHostTag(): string {
  switch (platform()) {
    case "darwin":
      return "darwin-x86_64";
    case "linux":
      return "linux-x86_64";
    case "win32":
      return "windows-x86_64";
    default:
      return fail(`unsupported host platform ${platform()}`);
  }
}

function buildAndroid(): void {
  const ndk = ndkHome();
  const bin = join(ndk, "toolchains/llvm/prebuilt", ndkHostTag(), "bin");
  const llvmNm = join(bin, "llvm-nm");
  const llvmStrip = join(bin, "llvm-strip");
  if (!existsSync(llvmNm)) {
    fail(`no llvm-nm at ${bin} — wrong NDK layout?`);
  }

  const jniLibs = join(NATIVE, "android/src/main/jniLibs");
  for (const [target, abi, clangTriple] of ANDROID_TARGETS) {
    const linker = join(bin, `${clangTriple}${ANDROID_API}-clang`);
    if (!existsSync(linker)) {
      fail(`missing linker ${linker}`);
    }
    const envKey = `CARGO_TARGET_${target.replaceAll("-", "_").toUpperCase()}`;
    sh("cargo", ["build", "--release", "-p", "spark-ffi", "--target", target], {
      [`${envKey}_LINKER`]: linker,
      [`${envKey}_AR`]: join(bin, "llvm-ar"),
      [`${envKey}_RUSTFLAGS`]: "-C link-arg=-Wl,-z,max-page-size=16384",
    });
    const built = join(REPO, "target", target, "release", "libspark_ffi.so");
    if (!existsSync(built)) {
      fail(`missing ${built}`);
    }
    const destDir = join(jniLibs, abi);
    mkdirSync(destDir, { recursive: true });
    const dest = join(destDir, "libqntx_spark.so");
    copyFileSync(built, dest);
    sh(llvmStrip, ["--strip-unneeded", dest]);
    const exports = listExports(llvmNm, ["-D", "--defined-only"], dest);
    checkExports(exports, `android ${abi}`);
    console.log(
      `android ${abi}: ${statSync(dest).size} B sha256=${sha256(dest)} exports=${exports.length}`,
    );
  }
}

const flags = new Set(process.argv.slice(2));
const unknown = [...flags].filter((flag) => flag !== "--ios" && flag !== "--android");
if (unknown.length > 0) {
  fail(`unknown flags: ${unknown.join(" ")} (usage: build-native.ts [--ios] [--android])`);
}

copyHeader();
if (flags.size === 0 || flags.has("--ios")) {
  buildIos();
}
if (flags.size === 0 || flags.has("--android")) {
  buildAndroid();
}
