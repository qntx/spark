# Sizes

`packages/spark-wasm/src/spark.wasm` — the `spark-ffi` cdylib compiled to
`wasm32-unknown-unknown` with the `wasm` cargo profile (`opt-level = "z"`,
LTO, `codegen-units = 1`, stripped, `panic = "abort"`) and post-processed by
`wasm-opt -Oz` (binaryen 132.0.0). Rebuild with
`bun run --cwd packages/spark-wasm build:wasm` (requires docker).

| Artifact   | Raw       | Gzip     |
| ---------- | --------- | -------- |
| spark.wasm | 197,515 B | 82,659 B |

## Reproducibility

`build:wasm` always runs `scripts/build.sh` inside the pinned linux/amd64
image defined by `scripts/Dockerfile` (`rust:1.99.1-slim` by digest, plus the
checksum-verified binaryen 132 release). The image digest pins the whole
toolchain, and `build.sh` remaps every host path that can enter
panic-location strings: the checkout, `$HOME`, `CARGO_HOME`, the sysroot, and
the rust-src tree (to rustc's canonical `/rustc/<commit>`).

The container is required because wasm32 codegen is host-dependent: on
identical sources, flags and `Cargo.lock`, rustc 1.99.1 (58cf8f9c3) emits a
240,434 B cdylib on x86_64-unknown-linux-gnu but a 239,129 B cdylib on
aarch64-apple-darwin (the optimized modules differ by ~1.4 KB and eleven
functions). `wasm-opt` itself is output-equivalent across builds — the npm
JavaScript build and the native binary produce byte-identical output on the
same input — so only the rustc step needs pinning. Measured equivalence: the
container build of this revision reproduces CI's artifact bit-for-bit:

```text
sha256 = 1287f5c192d9b1d122f74988cf766f2507bbf2eca4da4d722b1a47e48fa6ae32
```

The `wasm` CI job rebuilds through the same image and diffs the committed
bytes, uploading its rebuild as an artifact on mismatch.

## Native

`packages/spark-native` ships the `spark-ffi` cdylib prebuilt for the React
Native targets (`bun run build:native` — cargo with the NDK clang linkers for
Android, `lipo` + `xcodebuild -create-xcframework` for iOS). The artifacts are
gitignored build outputs; the npm package ships them via `files`. These are
the measurements from the `native.yml` CI jobs (rust 1.99.1, `release`
profile: thin LTO, `codegen-units = 1`, `panic = "abort"`, `strip = true`; the
Android `.so`s additionally `llvm-strip --strip-unneeded`).

| Artifact                                           | Size        | SHA-256 (first 16) |
| -------------------------------------------------- | ----------- | ------------------ |
| ios-arm64 `QntxSpark` (dylib)                      | 529,520 B   | `b9a9ad60f2798e7d` |
| ios-arm64+x86_64-simulator `QntxSpark` (fat dylib) | 1,123,504 B | `2731c1fa18e79687` |
| android `arm64-v8a/libqntx_spark.so`               | 564,088 B   | `b32d428ed3e62b46` |
| android `armeabi-v7a/libqntx_spark.so`             | 376,976 B   | `7b97c84d0531ccef` |
| android `x86_64/libqntx_spark.so`                  | 687,920 B   | `a464d461f1ebbf48` |
| android `x86/libqntx_spark.so`                     | 675,512 B   | `0766f17157a63915` |

Unlike `spark.wasm`, the native builds are not hermetic: these hashes are
specific to the CI runner image and toolchain (`macos-latest` Xcode, NDK r27d
linkers on `ubuntu-latest`) and shift when the image or toolchain does —
consecutive CI runs at the same revision reproduce them, a local build on a
different toolchain may not. The wasm hash above is reproducible through the
pinned container and enforced by the `wasm` CI job.

Every artifact exports exactly the nine `qs_*` ABI functions
(`qs_abi_version`, `qs_alloc`, `qs_free`, `qs_frost_commit`, `qs_frost_sign`,
`qs_frost_aggregate`, `qs_ecies_encrypt`, `qs_ecies_decrypt`,
`qs_split_secret_with_proofs`) plus platform loader symbols — the build script
verifies this on each run. Full SHA-256 hashes are printed by the build.
