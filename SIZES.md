# Sizes

`packages/spark-wasm/src/spark.wasm` — the `spark-ffi` cdylib compiled to
`wasm32-unknown-unknown` with the `wasm` cargo profile (`opt-level = "z"`,
LTO, `codegen-units = 1`, stripped, `panic = "abort"`) and post-processed by
`wasm-opt -Oz` (binaryen 132.0.0). Rebuild with
`bun run --cwd packages/spark-wasm build:wasm`.

| Artifact   | Raw       | Gzip     |
| ---------- | --------- | -------- |
| spark.wasm | 195,815 B | 81,527 B |

## Reproducibility

`scripts/build.sh` runs on the exact toolchain pinned in
`rust-toolchain.toml` (rustc 1.99.1) and remaps every host path that can enter
panic-location strings: the checkout, `$HOME`, `CARGO_HOME`, the sysroot, and
the rust-src tree (to rustc's canonical `/rustc/<commit>`).

Verified on rustc 1.99.1: a native aarch64-darwin build and a linux/amd64
build are byte-identical. An aarch64-linux build was observed to differ in
codegen (870 of 1173 functions), so regenerate the artifact on x86_64 Linux or
macOS only; the `wasm` CI job (x86_64 Linux) rebuilds and diffs the committed
bytes and uploads its rebuild on a mismatch. The committed artifact:

```
sha256 = 2e147515bf89034ac8940e912edfa6dd19d52ec5f2ff7f05d0df017b67f02f49
```
