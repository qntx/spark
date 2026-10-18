# AGENTS.md

- Do not preserve backward compatibility. Remove obsolete paths instead of adding compatibility layers, fallbacks, or migrations.
- Choose the simplest implementation that fully meets the current requirements. Avoid speculative abstractions, configuration, and indirection.
- Grow the system in layers. Start from the smallest version that works end to end, and add each new capability on top of a product that already works. Never trade a working product for unfinished complexity.
- Keep components modular and concerns clearly separated.
- Prefer established, well-maintained libraries when they reduce overall complexity or improve reliability. Do not reimplement common functionality without a clear reason.
- Lean on the dependencies already in the project before writing your own implementation or adding packages. Do not assume a library lacks a capability without checking its documentation and types.
- Make architectural decisions for the long term. Do not accept a stopgap that only works for now and is meant to be replaced later.

## Architecture invariants

- Three npm packages: `@qntx/spark` (platform-neutral TS), `@qntx/spark-wasm` and
  `@qntx/spark-native` (SparkCrypto backends). Backends import only `@qntx/spark/crypto`.
- `packages/*/src` is platform-neutral and Hermes V1-safe: no Node or browser globals, no `node:*`
  imports, no ES2023+ array methods. All I/O (fetch, random, storage) is injected; no singletons.
- One-directional layering in `packages/spark/src`, enforced by `scripts/check-layers.ts`:
  `errors` and `proto` are leaves; `crypto`, `core`; then `signer`, `connection`, `ssp`; the
  protocol services `tree`, `transfer`, `lightning`, `deposit`, `exit`, `tokens`, `invoice`
  build on them; `client` composes all services; `server` uses `client` and `lnurl`; `lnurl`
  uses `core` only. Services and `client` may use `import type` from `signer` but never import
  its implementation (`signer/local.ts` is reachable only through `signer/index.ts`).
- The client never holds private keys and never imports crypto or signer implementation modules.
  SparkSigner computes every digest it signs from full content; there is no sign-arbitrary-hash
  method. Only claimStaticDeposit returns a private key.
- SparkSigner types are protocol values: Uint8Array, safe integers, strings, booleans, arrays and
  plain objects.
- `spark-crypto` forbids unsafe code and takes randomness as input. It builds for
  `wasm32-unknown-unknown` and the iOS/Android targets; `getrandom` and `rayon` never appear in
  its dependency tree. `unsafe` is allowed only in `spark-ffi`'s `abi` module, with SAFETY
  comments.
- `SparkCrypto` maps 1:1 to `qntx_spark.h` and exchanges bytes only; `abiVersion` changes only
  when the C ABI breaks.
- Every ported function has a differential test against the upstream crate in `crates/interop`
  and a shared vector in `vectors/`; every capability is tracked in `parity.json`.
- No panics and no `unwrap`/`expect` in library code. No third-party types in public APIs except
  protobuf-es generated messages in client query results.
- npm and crate versions are lockstep (`bump.config.ts`, `scripts/check-version.ts`); crates are
  not published.
- License is Apache-2.0; ported files keep the upstream notice and a modification note.

## Commands

```bash
bun run lint && bun run typecheck && bun run test
bun run test:parity
bun run test:ffi-host                            # C host drives the shared vectors
bun run --cwd packages/spark-wasm build:wasm     # hermetic docker build (pinned linux/amd64)
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
(cd crates/interop && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)
```
