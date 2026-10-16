# Contributing

## Prerequisites

- **Bun 1.4** — package scripts, tests, and tooling.
- **Rust 1.99** — via `rust-toolchain.toml` (kept in sync with
  `[workspace.package].rust-version`).
- **cargo-deny** for the supply-chain check (`cargo install cargo-deny`).
- **cbindgen** for the `spark-ffi` header check
  (`cargo install cbindgen --locked`).
- **Optional**, for local portable builds: the cross-compilation rustup
  targets CI builds.

  ```bash
  rustup target add wasm32-unknown-unknown aarch64-linux-android armv7-linux-androideabi x86_64-linux-android aarch64-apple-ios aarch64-apple-ios-sim
  ```

## Repository layout

```text
packages/spark/     @qntx/spark — platform-neutral TypeScript Spark library
crates/spark-crypto/  spark-crypto — FROST, ECIES and VSS primitives (no unsafe)
crates/spark-ffi/     spark-ffi — C ABI (qntx_spark.h) over spark-crypto
crates/interop/     standalone test project diffing against the upstream crates
vectors/            shared golden data consumed by both languages (see vectors/README.md)
parity.json         capability ledger: every shared capability and its implementations
scripts/            repository checks (version lockstep, crate layers, parity, cbindgen)
```

## Local gate

Run before opening a pull request:

```bash
bun run lint && bun run typecheck && bun run test   # lint includes taplo, version,
                                                    # layer, parity and cbindgen checks
bun run test:parity                                 # seeded TS→Rust differential replay
bun run test:ffi-host                               # C host over the shared vectors
bun run --cwd packages/spark-wasm build:wasm        # spark.wasm artifact + integrity
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
(cd crates/interop && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)
```

## Versioning and release

`@qntx/spark` and the `spark-*` crates share one lockstep version. `bun run release`
runs `bumpp` (`bump.config.ts`), which bumps every `packages/*/package.json` and the
Cargo workspace version together, refreshes both lockfiles, and opens a
`release/v<version>` pull request. `scripts/check-version.ts` (part of `bun run
lint`) guards against drift: every published package version must equal
`[workspace.package].version`, internal path dependencies must pin `=<version>`,
and the version string may appear nowhere else in `Cargo.toml`.

After the release PR merges, tag the merge commit `v*.*.*` and push it by hand;
one tag publishes npm (`@qntx/spark`, `@qntx/spark-wasm`, `@qntx/spark-native`) and
the GitHub Release.
