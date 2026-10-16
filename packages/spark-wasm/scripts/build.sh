#!/usr/bin/env bash
set -euo pipefail

# Builds spark.wasm from crates/spark-ffi (cdylib, wasm32-unknown-unknown,
# the dedicated `wasm` profile in the root Cargo.toml) then wasm-opt -Oz.
# The artifact and its SRI hash are committed in this package's src/.
pkg="$(cd "$(dirname "$0")/.." && pwd)"
root="$(cd "${pkg}/../.." && pwd)"

need() { command -v "$1" >/dev/null || { echo "missing $1" >&2; exit 1; }; }
# binaryen (devDependency) provides wasm-opt on PATH inside bun/npm scripts.
need wasm-opt
need cargo
need openssl

cd "$root"
RUSTFLAGS="--remap-path-prefix=${HOME}=~ --remap-path-prefix=${root}=." \
  cargo build -p spark-ffi --profile wasm --target wasm32-unknown-unknown

out="${pkg}/src/spark.wasm"
# Rust emits memory.copy/memory.fill; binaryen needs the feature enabled.
wasm-opt -Oz --enable-bulk-memory \
  "target/wasm32-unknown-unknown/wasm/spark_ffi.wasm" -o "${out}"

digest="$(openssl dgst -sha256 -binary "${out}" | openssl base64 -A)"
printf 'export const SPARK_WASM_INTEGRITY = "sha256-%s";\n' "${digest}" \
  > "${pkg}/src/integrity.ts"

raw_size="$(wc -c <"${out}" | tr -d ' ')"
gz_size="$(gzip -cn "${out}" | wc -c | tr -d ' ')"
echo "spark.wasm: ${raw_size} B raw, ${gz_size} B gzip, sha256-${digest}"
