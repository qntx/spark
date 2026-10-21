# Changelog

## Unreleased

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
- Multiple internal review rounds have hardened the client against malicious
  operators and counterparties — see AUDIT.md and the Security section of the
  README.
- The SDK has not had a third-party audit and has not been run on mainnet.
>>>>>>> 946854f (docs(changelog): describe 0.1.0)
