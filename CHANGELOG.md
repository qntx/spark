# Changelog

## Unreleased

### Added

- Signer-side outflow derivation: `createSparkSigner` accepts an optional
  `authorize?: (outflow: SparkOutflow) => Promise<void>` gate called before every
  signature that sends value out. `signFrost` enforces an output whitelist on
  every job's transaction and authorizes `exit` (connector refunds, with the
  connector txid) and `lightning` (HTLC-shaped refunds, with the output script
  `lightningSendHtlcScript` reproduces) before producing shares; all other
  outputs must pay an anchor, the spent prevout's script, the signer's identity,
  a signer-derived leaf key, or a pending transfer's recorded receiver.
  `transfer-package` signatures fail closed unless the package's
  `key_tweak_package` is byte-equal to this session's recorded `prepareTransfer`
  output and every leaf has a recorded refund signature; receivers decide
  `transfer` (per-receiver totals), `swap` (all receivers the bound SSP), or no
  further authorization when `signFrost` already covered the leaves. `signKeySpend`,
  `signHtlcTimeout`, `static-deposit-refund`/`watchtower-recovery` report
  `onchain` outputs decoded from the signed transaction, `token-transaction`
  reports `token` outputs with u128 amounts as `bigint`. Breaking for
  `transfer-package` signers that did not call `prepareTransfer`/`signFrost` on
  the same instance first, and for `signFrost` callers whose targets pay
  non-whitelisted outputs.

## 0.1.1

### Release

- First version published from CI through npm trusted publishing; every
  package carries npm provenance. 0.1.0 was published by hand (npm requires
  an existing package before a trusted publisher can be configured) from the
  pack artifacts of Publish run 40066238525 at `d1bec8b`; its registry
  tarballs are byte-identical to those artifacts and have no npm provenance,
  but its native binaries carry GitHub build-provenance attestations
  (`gh attestation verify <file> --repo qntx/spark`). The v0.1.0 tag run
  (40067725524) rebuilt all three packages byte-identical to the published
  0.1.0 tarballs. No library code changes.

### Known issues

- RUSTSEC-2026-0387: crypto-bigint < 0.7.6 has timing variability in
  operations meant to be constant-time; it reaches the wasm and native
  backends through k256 0.13, which frost-secp256k1-tr requires, so no
  patched version is reachable until upstream FROST supports k256 0.14.
  Exploitation needs fine-grained timing observation of signing on the
  user's device. Also applies to 0.1.0.

## 0.1.0

First public pre-release. The workspace ships three packages with lockstep versions:

- `@qntx/spark` — platform-neutral Spark client, the `SparkSigner` and `SparkCrypto`
  interfaces, and the `@qntx/spark/server` Lightning Address server.
- `@qntx/spark-wasm` — `SparkCrypto` backend built from `crates/spark-ffi` for Node
  and browsers.
- `@qntx/spark-native` — `SparkCrypto` backend for React Native via Nitro.

### Protocol coverage

- Spark transfers: single- and multi-receiver sends, idempotent `transferId`, and
  incoming-transfer claims.
- Deposits: single-use and multi-UTXO addresses, static deposits with refunds.
- Lightning: send and receive, including delegated receivers.
- Leaves: SSP swaps, leaf optimization and renewal.
- Exits: cooperative exit, unilateral exit (live `unilateralExit` and
  `offlineExitTransactions` from stored chains), and watchtower recovery.
- Tokens: create, mint, transfer and consolidate, including explicit-input retry.
- Spark invoices and the wallet privacy setting.
- LNURL client (pay, withdraw, auth, Lightning Address registration) and the
  `@qntx/spark/server` Lightning Address server; `apps/lnurl-server` is a private
  reference deployment and is not published.

### API surface

- `createSparkClient` requires an explicit `store`; use `createMemorySparkStore`
  for ephemeral wallets.
- `createSparkSigner` binds the operator set, VSS threshold and SSP identity at
  construction; signing requests do not carry them.
- `lightning.sweepHtlcTimeout` spends an expired HTLC output via
  `SparkSigner.signHtlcTimeout`.
- `withdrawals.offlineExitTransactions` builds unilateral-exit transactions from
  stored chains without contacting operators.
- `tokens.balances` and `tokens.outputs` only report rows all operators agree on.
- `invoices.pay` retries a lost response through `transferId` (sats invoices) or
  `inputOutputIds` (token invoices) instead of paying twice.
- A lost token broadcast throws `SparkTokenBroadcastError`, whose
  `inputOutputIds` are the retry handle for `tokens.transfer` and
  `tokens.consolidate`.

### Platforms and requirements

- Node and browsers via `@qntx/spark-wasm`; `SPARK_WASM_INTEGRITY` exposes the
  build-time SRI hash of the shipped `.wasm` for Worker `fetch` integrity checks.
- React Native via `@qntx/spark-native`: Hermes V1 runtime, Nitro 0.37, and a
  streaming `fetch` (such as the `expo/fetch` default in Expo SDK 56+) for events.

### Security status

- Private keys never leave `SparkSigner`; the client holds no key material.
- Lightning receive rejects an SSP invoice carrying any `f` fallback field —
  on-chain addresses and version-31 embedded Spark invoices could redirect the
  payer away from the terms we requested.
- Multiple internal review rounds have hardened the client against malicious
  operators and counterparties — see AUDIT.md and the Security section of the
  README.
- The SDK has not had a third-party audit and has not been run on mainnet.
