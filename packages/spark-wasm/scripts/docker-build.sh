#!/usr/bin/env bash
set -euo pipefail

# Hermetic spark.wasm build: runs scripts/build.sh inside the pinned
# linux/amd64 image (scripts/Dockerfile). LLVM's wasm32 codegen depends on the
# compiler host — a native macOS or aarch64 Linux build cannot reproduce the
# committed artifact byte-for-byte, so the container forces one toolchain on
# every host. The package test suite needs only bun; the image needs docker.
pkg="$(cd "$(dirname "$0")/.." && pwd)"
root="$(cd "${pkg}/../.." && pwd)"

command -v docker >/dev/null || {
  echo "missing docker: build:wasm requires the pinned container build" >&2
  exit 1
}

image="qntx-spark-wasm-build"
docker build --platform linux/amd64 --quiet \
  -f "${pkg}/scripts/Dockerfile" -t "${image}" "${pkg}"
# Run as the host user so the regenerated artifact is not root-owned on Linux;
# cargo state is redirected into the container's /tmp, which the user can write.
docker run --rm --platform linux/amd64 \
  -v "${root}:/src" -w /src \
  -u "$(id -u):$(id -g)" \
  -e HOME=/tmp \
  -e CARGO_HOME=/tmp/cargo \
  -e CARGO_TARGET_DIR=/tmp/wtarget \
  "${image}" \
  bash packages/spark-wasm/scripts/build.sh
