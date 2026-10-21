#!/usr/bin/env bash
set -euo pipefail

# Builds spark.wasm from crates/spark-ffi (cdylib, wasm32-unknown-unknown,
# the dedicated `wasm` profile in the root Cargo.toml) then wasm-opt -Oz.
# The artifact and its SRI hash are committed in this package's src/.
pkg="$(cd "$(dirname "$0")/.." && pwd)"
root="$(cd "${pkg}/../.." && pwd)"

need() { command -v "$1" >/dev/null || { echo "missing $1" >&2; exit 1; }; }
# Runs inside the pinned image (scripts/Dockerfile), which provides wasm-opt.
need wasm-opt
need cargo
need openssl

cd "$root"
# Path remaps keep panic-location strings host-independent; the LAST matching
# prefix wins, so general prefixes come first and specific ones last. Without
# them the artifact embeds ~/.rustup/toolchains/…-<host-triple> (when rust-src
# is installed) and the real CARGO_HOME, both of which differ across hosts.
# The rust-src tree is remapped to rustc's own canonical /rustc/<commit> form —
# the same shape a rust-src-less (minimal profile) toolchain produces.
sysroot="$(rustc --print sysroot)"
commit="$(rustc --version --verbose | sed -n 's/^commit-hash: //p')"
RUSTFLAGS="--remap-path-prefix=${root}=. \
  --remap-path-prefix=${HOME}=~ \
  --remap-path-prefix=${CARGO_HOME:-${HOME}/.cargo}=cargo \
  --remap-path-prefix=${sysroot}/lib/rustlib/src/rust=/rustc/${commit} \
  --remap-path-prefix=${sysroot}=rustc" \
  cargo build -p spark-ffi --profile wasm --target wasm32-unknown-unknown --locked

out="${pkg}/src/spark.wasm"
# Honour CARGO_TARGET_DIR: the container build redirects it away from the
# mounted checkout, so the cdylib is not necessarily under ./target.
cdylib="${CARGO_TARGET_DIR:-${root}/target}/wasm32-unknown-unknown/wasm/spark_ffi.wasm"
# Rust emits memory.copy/memory.fill; binaryen needs the feature enabled.
wasm-opt -Oz --enable-bulk-memory "${cdylib}" -o "${out}"

digest="$(openssl dgst -sha256 -binary "${out}" | openssl base64 -A)"
# The emitted file must stay byte-identical to the committed integrity.ts —
# the wasm CI job rebuilds it and diffs. Keep this TSDoc in sync with the file.
cat > "${pkg}/src/integrity.ts" <<EOF
/**
 * Subresource Integrity hash (\`sha256-<base64>\`) of the shipped \`spark.wasm\`, regenerated whenever
 * the artifact is rebuilt. Consumers that fetch the module themselves — for example a Wallet Worker
 * — can pin it at fetch time and hand the verified bytes to \`loadSparkWasm\`:
 *
 * \`\`\`ts
 * const res = await fetch(wasmUrl, { integrity: SPARK_WASM_INTEGRITY });
 * const crypto = await loadSparkWasm({ module: await res.arrayBuffer() });
 * \`\`\`
 *
 * \`loadSparkWasm()\` without \`module\` loads \`spark.wasm\` itself and does NOT verify this hash —
 * callers that want SRI enforcement must fetch with \`integrity\` and pass \`module\`.
 */
export const SPARK_WASM_INTEGRITY = "sha256-${digest}";
EOF

raw_size="$(wc -c <"${out}" | tr -d ' ')"
gz_size="$(gzip -cn "${out}" | wc -c | tr -d ' ')"
echo "spark.wasm: ${raw_size} B raw, ${gz_size} B gzip, sha256-${digest}"
