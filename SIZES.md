# Sizes

`packages/spark-wasm/src/spark.wasm` — the `spark-ffi` cdylib compiled to
`wasm32-unknown-unknown` with the `wasm` cargo profile (`opt-level = "z"`,
LTO, `codegen-units = 1`, stripped, `panic = "abort"`) and post-processed by
`wasm-opt -Oz` (binaryen 132.0.0). Rebuild with
`bun run --cwd packages/spark-wasm build:wasm` (requires docker).

| Artifact   | Raw       | Gzip     |
| ---------- | --------- | -------- |
| spark.wasm | 197,203 B | 82,442 B |

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
the measurements from the reference build on macOS arm64 (rust 1.99.1,
`release` profile: thin LTO, `codegen-units = 1`, `panic = "abort"`,
`strip = true`; the Android `.so`s additionally `llvm-strip --strip-unneeded`).

| Artifact                                           | Size        | SHA-256 (first 16) |
| -------------------------------------------------- | ----------- | ------------------ |
| ios-arm64 `QntxSpark` (dylib)                      | 529,512 B   | `f3911c77548de07a` |
| ios-arm64+x86_64-simulator `QntxSpark` (fat dylib) | 1,123,504 B | `38604c1ef3fbee68` |
| android `arm64-v8a/libqntx_spark.so`               | 563,728 B   | `e8cb3e1351523e35` |
| android `armeabi-v7a/libqntx_spark.so`             | 377,192 B   | `6264b9c01670fea0` |
| android `x86_64/libqntx_spark.so`                  | 687,504 B   | `b0218300b750aa3a` |
| android `x86/libqntx_spark.so`                     | 675,232 B   | `6dbecf3285510340` |

Every artifact exports exactly the nine `qs_*` ABI functions
(`qs_abi_version`, `qs_alloc`, `qs_free`, `qs_frost_commit`, `qs_frost_sign`,
`qs_frost_aggregate`, `qs_ecies_encrypt`, `qs_ecies_decrypt`,
`qs_split_secret_with_proofs`) plus platform loader symbols — the build script
verifies this on each run. Full SHA-256 hashes are printed by the build.
