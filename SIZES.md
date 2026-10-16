# Sizes

`packages/spark-wasm/src/spark.wasm` — the `spark-ffi` cdylib compiled to
`wasm32-unknown-unknown` with the `wasm` cargo profile (`opt-level = "z"`,
LTO, `codegen-units = 1`, stripped, `panic = "abort"`) and post-processed by
`wasm-opt -Oz` (binaryen 132.0.0). Rebuild with
`bun run --cwd packages/spark-wasm build:wasm`.

| Artifact   | Raw       | Gzip     |
| ---------- | --------- | -------- |
| spark.wasm | 196,043 B | 81,555 B |

## Reproducibility

The build applies `RUSTFLAGS="--remap-path-prefix=$HOME=~
--remap-path-prefix=$PWD=."` so source paths do not enter the artifact.
Evidence: an earlier build of this pipeline from two different checkout
paths on the same toolchain (`/Users/xu/Desktop/qntx/spark` and
`/private/tmp/spark-repro`, rustc 1.99, aarch64-apple-darwin host) produced
byte-identical output. The committed artifact:

```
sha256 = 95a6e7b807d7dec107dde06a7763950c3ed57112990b733282eeb09bf30a32fa
```

Cross-platform reproducibility (macOS ↔ Linux) is not verified locally. The
`wasm` CI job rebuilds the artifact on ubuntu-latest and diffs it against the
committed bytes; if that ever diverges across hosts, fall back to asserting
the size within ±1% plus the exact export table (which
`packages/spark-wasm/tests/abi.test.ts` already checks).
