# Security audit scope and code guide

Commit under review: 495e9680700dd4ef439d838edcc7a6c3b30c2761

## Purpose and deliverables

This document scopes an external security audit of the Spark wallet SDK and its
LNURL pay server. The engagement covers the client-side protocol
implementation, the cryptographic backends it depends on, the reference LNURL
server, and the build/release pipeline that produces published artifacts.

We ask for:

- Findings with a severity rating (Critical / High / Medium / Low /
  Informational), affected files and lines, a description of the root cause,
  and a proof of concept or concrete exploit scenario where possible.
- Assessment of the security properties claimed below (verified, violated, or
  partially holds, with evidence).
- Fix review for remediations we propose in response to findings.

## System overview

The repository produces three npm packages, two Rust crates, and one deployable
server app:

- `packages/spark` (`@qntx/spark`) — platform-neutral TypeScript SDK. All I/O
  (fetch, randomness, storage) is injected; `packages/spark/src` is
  Hermes V1-safe and contains no Node or browser globals.
- `packages/spark-wasm` (`@qntx/spark-wasm`) — `SparkCrypto` backend that wraps
  `spark-crypto` compiled to WebAssembly (`src/spark.wasm` + JS/TS glue).
- `packages/spark-native` (`@qntx/spark-native`) — `SparkCrypto` backend that
  loads `libqntx_spark` through a nitro-modules C++ binding (`src/` + `cpp/`).
- `crates/spark-crypto` — the Rust cryptographic library (FROST user role,
  ECIES, VSS); `unsafe` is forbidden here.
- `crates/spark-ffi` — the C ABI (`include/qntx_spark.h`); `unsafe` is allowed
  only in its `abi` module.
- `apps/lnurl-server` — the LNURL pay server built on
  `packages/spark/src/server` (Hono HTTP app + SQLite store + Nostr zap
  publishing).

Layering inside `packages/spark/src` is one-directional and enforced by
`scripts/check-layers.ts`: `errors` and `proto` are leaves; `crypto`, `core`;
then `signer`, `connection`, `ssp`; protocol services `tree`, `transfer`,
`lightning`, `deposit`, `exit`, `tokens`, `invoice`, `settings`; `client`
composes them; `server` builds on `client` and `lnurl`; `lnurl` uses `core`
only. Services may use `import type` from `signer` but never import its
implementation.

Trust boundaries:

1. Host app ↔ client SDK.
2. Client ↔ `SparkSigner` — the signer is a boundary: the client never holds
   private keys and cannot import the signer implementation.
3. `SparkSigner` ↔ `SparkCrypto` backend.
4. `SparkCrypto` ↔ WASM module / native `libqntx_spark` (C ABI, bytes only).
5. Client ↔ signing operators — gRPC; one coordinator plus the remaining
   operators (`packages/spark/src/connection/index.ts`).
6. Client ↔ SSP — GraphQL (`packages/spark/src/ssp/`).
7. LNURL server ↔ internet — HTTP callers and Nostr relays
   (`apps/lnurl-server/src/`).
8. Bitcoin chain — transactions constructed, signed, broadcast and confirmed
   by external infrastructure.

## Assets

- Identity key (secp256k1; held inside `SparkSigner`).
- Leaf keys (per-leaf keys bound to `LEAF{leafId}` derivation).
- Static-deposit keys.
- LNURL-auth keys.
- FROST nonces and the hedge secret (nonce reuse breaks signing security).
- Lightning preimages.
- Leaf funds (the UTXO value controlled via the tree).
- Token outputs.
- Exit chains — locally stored `SparkExitChain` objects are the offline exit
  capability; loss or tampering is loss of the unilateral exit.
- LNURL server keys: the server identity (zap receipt signer key) and any
  associated wallet keys.

## Adversary model

- **Malicious or compromised coordinator SO.** May return arbitrary transfer,
  leaf, and transaction data; may reorder, omit, or fabricate responses; may
  claim success or failure falsely. The client must validate every coordinator
  value that reaches a signature, a broadcast, a stored exit chain, a reported
  amount, or a loop bound. Must hold: client-side verification described in
  the properties below; the coordinator must not be able to move funds,
  inflate balances, or wedge the wallet.
- **Up to `t − 1` colluding operators.** Funds safety requires `t-of-n`
  operator cooperation for state updates — up to `t − 1` corrupt operators
  must not be able to move leaf funds (they lack the user's key share), must
  not forge signatures the client accepts, and must not convince the client
  of a false balance. The client verifies per-leaf ownership against
  signer-derived keys, cross-operator field agreement (including direct
  transaction variants), and exit-chain structure; it trusts the coordinator
  for liveness and for honestly reporting remote state. This is an assumption
  we rely on the auditor to test precisely.
- **Malicious SSP.** Controls the GraphQL API used for lightning send/receive,
  swaps, cooperative exit, and static-deposit flows. May lie about quotes,
  fees, transfer status, payment status, and settlement; may drop or forge
  responses; may attempt to make the client double-pay or accept a false
  success. Must hold: the client validates every SSP-reported state it acts
  on; retries never double-spend; SSP cannot force a signature over
  unexpected terms.
- **Malicious counterparty (sender, receiver, or payer).** May send malformed
  transfers, invoices, leaves, or lightning data; may attempt to reclaim a
  transfer after commit or claim funds they do not own.
- **Network attacker.** TLS is assumed for all remote calls. Nothing is
  pinned beyond the platform TLS stack — there is no certificate pinning or
  response signing beyond the protocol's own cryptography. A network
  attacker is bounded by TLS, but dropped/duped/delayed responses are in
  scope; retry and dedup logic must tolerate them without double-spending.
- **Malicious LNURL HTTP clients and zap requesters.** May send oversized or
  malformed bodies, register/unregister floods, callback floods, and crafted
  NIP-57 zap requests; may attempt SSRF through any URL the server fetches.
  Must hold: body caps, quotas, name validation, and the SSRF restrictions in
  the properties below.
- **Attacker with heap read access.** Defence-in-depth only. JavaScript
  cannot reliably zeroize secrets; `SparkSigner` performs best-effort
  clearing (`dispose`), but we do not claim protection against an attacker
  that can read process memory. FROST nonces live in Rust memory inside the
  backend.
- **Malicious backend binary.** Out of scope: a trojaned
  `spark.wasm`/`libqntx_spark` can do anything. The supply chain of our own
  artifacts is in scope instead — reproducible WASM build
  (`packages/spark-wasm/src/integrity.ts`) and CI-built native binaries
  (`.github/workflows/native.yml`).

## Security properties claimed

Each property names the enforcing code. Line references are approximate;
identifiers are authoritative.

- **P1 — Key custody.** No private key ever leaves `SparkSigner`: the client
  sees only public keys, signatures, and ECIES-sealed material;
  `claimStaticDeposit` returns the static-deposit key ECIES-sealed to the SSP
  identity (`packages/spark/src/signer/types.ts`, `signer/local.ts`,
  `deposit/static.ts`).
- **P2 — No sign-arbitrary-hash.** `SparkSigner` computes every digest it
  signs from full protocol content inside the signer; no method accepts a
  caller-supplied digest (`signer/types.ts`, `signer/local.ts`).
- **P3 — FROST nonce single use.** `signFrost` consumes every commitment of
  the batch up front — before any other validation, key resolution, or
  backend call — so a mid-batch failure leaves no outstanding nonces;
  commitments are removed before signing and wiped on every exit path.
  `MAX_OUTSTANDING` is enforced by evicting the oldest outstanding
  commitments (wiped, insertion order), so remote-driven leaks can never
  wedge the signer. Each commitment's hedge is
  `HMAC-SHA256(hedge key, tag ‖ u64be counter)` over a store-local monotone
  counter combined with the injected randomness, so an RNG that repeats
  within one signer instance no longer repeats nonces (`signer/nonces.ts`,
  `signer/frost.ts`, `signer/backend.ts`).
- **P4 — Local transaction validation.** Every transaction the wallet signs
  is constructed or fully validated locally: refund trees, exit chains paying
  the wallet's own leaf key, deposit trees, the cooperative-exit
  connector/payout binding, and HTLC refunds bound to the payment hash
  (`core/bitcoin/`, `exit/unilateral.ts`, `exit/coop.ts`,
  `lightning/send.ts`, `deposit/index.ts`).
- **P5 — Deposit address proof-of-possession.** `generateDepositAddress`
  verifies the operator's proof of possession before returning an address
  (`deposit/index.ts`).
- **P6 — Operator agreement and per-leaf quarantine.** `syncLeaves` requires
  field agreement across all operators — including `directTx`,
  `directRefundTx`, `directFromCpfpRefundTx`, `parentNodeId` and `treeId` —
  quarantines leaves whose exit chain fails verification, and isolates rows
  `mapTreeNode` cannot map, so a single malformed row never takes the
  wallet down. Every node on an exit chain — leaf and ancestors, on the
  sync, claim, swap, deposit and renew paths alike — must be served
  identically by the coordinator and every operator (transaction bytes,
  parent linkage, `treeId`, `vout` and the direct variants), and a leaf's
  `valueSats` must equal output 0 of its `nodeTx`; a leaf that fails either
  check is quarantined and, for an explicit exit, the error names the leaf
  and the field. A stored exit chain is swept only when no operator
  reported that node id at all in the sync, or when the coordinator's row
  is not owned and every other operator serves an agreeing row
  (`client/context.ts`, `tree/verify.ts`, `tree/index.ts`,
  `exit/unilateral.ts`).
- **P7 — Idempotent retries never double-spend.** Sats transfers take a
  caller-supplied `transferId`; retries rebind and verify the committed
  transfer rather than re-sending. Token transfers take
  `inputOutputIds`; on `SparkTokenBroadcastError` the caller retries with
  `error.inputOutputIds` and the same terms, which either returns the
  committed hash or broadcasts exactly those inputs once
  (`transfer/query.ts`, `transfer/send.ts`, `tokens/transfer.ts`).
- **P8 — Fail-closed on unverifiable SO/SSP data.** Unverifiable or
  inconsistent remote state throws (`SparkRequestError`/`SparkError`) rather
  than being trusted. Public entry points validate sats amounts and fee
  bounds (safe integers ≥ 0) before any remote call. Pending-transfer rows
  that cannot be mapped are isolated and reported as failures instead of
  starving valid transfers. SSP read-only queries retry up to three
  attempts with injected-sleep backoff, and only on transport/timeout
  errors — mutations are never retried (`client/context.ts`,
  `transfer/claim.ts`, `transfer/query.ts`, `tokens/transfer.ts`,
  `exit/coop.ts`, `ssp/index.ts`).
- **P9 — Bounded resource use.** All remote-driven loops are bounded:
  pagination caps and the coordinator's explicit `-1` end offset with
  strictly-advancing offsets on every paged RPC, request timeouts, LNURL per-user/global invoice quotas and HTTP body limits, and
  bounded zap-receipt publishing (`client/context.ts`, `transfer/query.ts`,
  `tokens/transfer.ts`, `apps/lnurl-server/src/http.ts`,
  `apps/lnurl-server/src/config.ts`, `apps/lnurl-server/src/zap.ts`).
- **P10 — Offline receive.** A committed TRANSFER-type receive cannot be
  revoked by the sender: `cancel_transfer` accepts only SenderInitiated or
  Returned states for non-preimage transfers, so a committed transfer in
  SENDER_KEY_TWEAKED cannot be cancelled even after expiry (upstream
  `so/handler/base_transfer_handler.go:1322-1333`; the after-expiry branch
  applies to PREIMAGE_SWAP sends only). The receiver can claim at any later
  time without being online when it committed (`transfer/query.ts`,
  `transfer/claim.ts`).
- **P11 — Unilateral exit availability.** Two paths produce the same
  broadcast order: `unilateralExit` queries the operators live, and
  `offlineExitTransactions` derives the list purely from the exit chains the
  store persists — no network — for when the operators are unreachable or
  withholding data; stored chains are refreshed on every leaves sync.
  Chains are built only from nodes served identically by every operator and
  walked via the agreed `parentNodeId` — truncated or retargeted chains are
  rejected — and the leaf's `valueSats` must equal output 0 of its
  `nodeTx`. Every transaction must be broadcast and confirmed within the
  `DIRECT_TIMELOCK_OFFSET` (50-block) deadline of it becoming broadcastable,
  or the watchtower may publish variants instead (`exit/unilateral.ts`,
  `exit/watchtower.ts`, `client/withdrawals.ts`).
- **P12 — LNURL server safety.** The LNURL server custodies no funds;
  preimage is verified before a settle is recorded; zap requests are
  validated per NIP-57; outbound fetches are restricted
  (`packages/spark/src/server/index.ts`, `apps/lnurl-server/src/`).

## Scope

In scope:

- `packages/spark/src`
- `packages/spark-wasm/src` (including `integrity.ts` and the WASM artifact
  contract)
- `packages/spark-native/src` and `packages/spark-native/cpp`
- `crates/spark-crypto`, `crates/spark-ffi`
- `apps/lnurl-server/src`
- Build and release pipeline: `.github/workflows/{ci,native,publish-npm,regtest}.yml`,
  `scripts/build-native.ts`, the WASM Docker build and integrity check
- Dependency set: `package.json`, `Cargo.lock`, `deny.toml`

Out of scope:

- Spark signing-operator and SSP server implementations (only our client of
  them is in scope)
- Upstream FROST fork internals (our use of it is in scope)
- Generated protobuf code under `packages/spark/src/proto/gen`
- Tests and fixtures
- Host-app integration

## Priority areas

Ranked by risk:

1. **Signer + crypto ABI** — signer/local.ts, signer/backend.ts,
   signer/nonces.ts, signer/types.ts, crypto ABI in crates/spark-ffi; key
   custody, nonce single use, digest computation, memory hygiene.
2. **Transfer send/claim** — `transfer/send.ts`, `transfer/claim.ts`,
   `transfer/query.ts`, `client/transfers.ts`; idempotency, recovery,
   remote-data validation.
3. **Lightning** — `lightning/send.ts`, `lightning/receive.ts`,
   `lightning/status.ts`, `core/bitcoin/htlc.ts`; HTLC/payment-hash binding,
   SSP response validation, retry paths.
4. **Exits** — `exit/coop.ts`, `exit/unilateral.ts`, `exit/watchtower.ts`,
   `exit/store.ts`, `client/withdrawals.ts`; resume safety, local
   construction, quarantine.
5. **Deposits** — `deposit/index.ts`, `deposit/static.ts`,
   `client/deposits.ts`; proof-of-possession, locally-built refund paths.
6. **Tokens** — `tokens/transfer.ts`, `client/tokens.ts`; idempotent retry
   under uncertainty, pagination, input/output validation.
7. **SSP client** — `ssp/index.ts`; response validation, error handling.
8. **LNURL server** — `packages/spark/src/server/`,
   `apps/lnurl-server/src/`; HTTP auth, quotas, NIP-57, SSRF, DB bounds.
9. **Build and release** — workflows, `scripts/build-native.ts`, WASM
   integrity; pinning, permissions, artifact integrity, npm provenance.

## Known limitations and accepted risks

- JavaScript zeroization is best-effort; secrets may persist in heap memory.
- The upstream `vsss-rs` internal polynomial cannot be wiped by us.
- `leafKeyCache` (`client/leaves.ts`) is unbounded; the root key is already
  resident in the signer anyway.
- Leaf index space is 31 bits.
- Swaps, optimize, and renew have no caller-visible idempotency id; the SO
  auto-returns the primary swap for ~240 s.
- Zero-amount invoice retry cannot re-verify the committed amount
  client-side beyond the fee bound.
- LNURL quota check-then-insert is soft (a race window exists).
- `users`/`statements` tables: statements are only time-window bounded;
  registered users are also row-count bounded (`LNURL_MAX_USERS`, default
  100 000, same soft-quota style as the invoice quotas). The cap is a
  storage bound — per-IP registration limiting belongs in front of the
  server.
- DNS rebinding must be mitigated at the network layer in front of the LNURL
  server.
- Per-IP rate limiting must be deployed in front of the LNURL server.
- SSP liveness is trusted for lightning send/receive, swaps, and cooperative
  exit.
- WASM vs native backends differ in error type on invalid integers.
- Pending-transfer claim time grows with transfer count.
- Reusable workflows are referenced by the moving `qntx/workflows@v2` tag;
  moving it requires a protected-environment retag approved by a second
  account (third-party actions are SHA-pinned).
- `renewLeaf` no longer trusts the coordinator's returned node: the node is
  adopted only after the same cross-operator verification and leaf-value
  binding applied to every other chain source; a disagreeing or mislabelled
  node is rejected and quarantined instead of carried until the next sync.
- `SparkSigner` enforces no transaction-semantics policy — it signs what the
  client layer asks it to. Funds safety relies on client-layer transaction
  construction and validation (P4); callers must not use the signer as a
  policy oracle.
- `claimStaticDeposit` releases the static-deposit child key ECIES-sealed to
  the SSP identity, so the SSP can hold the key for that deposit; the
  static-deposit key is derived at fixed index 0.
- Spending requires every operator online and in agreement: leaf selection,
  sync and exit-chain verification query all operators and fail closed on a
  missing or disagreeing row — one offline or dissenting operator blocks the
  spend.
- Stored exit chains are not retained for in-flight lightning leaves.
  Recovering the sender's side of an expired lightning HTLC uses
  `lightning.sweepHtlcTimeout` against the SSP-served HTLC transaction
  (BIP-342 script-path signature after `LIGHTNING_HTLC_SEQUENCE` blocks),
  not stored chains.
- `loadSparkWasm()` does not verify `SPARK_WASM_INTEGRITY` itself; consumers
  needing SRI must fetch with `integrity` and pass the bytes as `module`.
- Served exit-chain transactions are checked for linkage, output scripts
  and operator agreement, but not for signature validity or sequence
  policy; a malformed served transaction surfaces at broadcast time.
- `query_unused_deposit_addresses` upstream paging under-reports when a page
  contains used addresses (the SO applies LIMIT before filtering).

## Prior internal review

Nine review rounds have run. Rounds 1–8 were internal; round 9 was the
external audit scoped by this document, whose remediations are listed last.
Areas covered:

- Transfer claim/pending-transfer failure and pagination handling.
- LNURL invoice/database growth and repeated settlement polling; request
  timeouts and quotas.
- Token broadcast lost-response recovery and double-payment risk; explicit
  `inputOutputIds` retry handle.
- Cooperative-exit resume binding to committed state; unilateral-exit refund
  variants bound to the signer's own leaf key.
- Lightning retry/payment binding and receive-status verification.
- Event-stream cleanup, per-leaf quarantine for malformed or disagreed
  leaves, direct refund-field agreement checks.
- Nitro FFI error mapping into `SparkCryptoError`.
- RPC timeouts and bounded retries across the connection layer.
- Leaves-sync per-row isolation and union-based exit-chain retention,
  explicit end-offset paging, offline exit from stored chains, and token
  commit-status handling.

Round 9 (external audit) remediations:

- Exit chains built only from cross-operator-verified nodes — caller-provided
  rows (claim/swap/deposit/renew) verified like sync rows, `parentNodeId`
  and `treeId` compared; leaf `valueSats` bound to `nodeTx` output 0
  (H-01, H-02).
- FROST batch commitment consumption up front, nonce-store eviction instead
  of wedging, per-call HMAC hedge counter, `checkThreshold` ≥ 2, operator
  dedup, wasm linear-memory zeroization on trap (M-01, I-01, L-04, L-05,
  I-05).
- Uniform sats input validation before remote calls, malformed
  pending-transfer row isolation, invoice `transferId`/`inputOutputIds`
  retry handles, read-only SSP retries with injected-sleep backoff
  (M-04, L-01, L-02, I-12).
- Lightning HTLC timeout sweep: `signHtlcTimeout` +
  `lightning.sweepHtlcTimeout` (M-02).
- LNURL registered-user cap `LNURL_MAX_USERS`; zap `p`-tag misattribution
  risk documented as Breez parity (L-07).
- Release pipeline: tagged-release ancestry check against `origin/main`,
  WASM reproducibility job gating publish, and an unprivileged pack job
  split from the privileged OIDC publish in `qntx/workflows` (L-06, M-03).

## Build, test and reproduce

```bash
bun install

bun run lint
bun run typecheck
bun run test
bun run test:parity
bun run test:ffi-host

cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --workspace --all-targets --no-default-features -- -D warnings
cargo test --workspace --all-features
cargo deny check
(cd crates/interop && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test)
```

Fuzz targets live in `fuzz/fuzz_targets` and run via cargo fuzz on nightly
(see `.github/workflows/fuzz.yml`).

Hermes smoke: `.github/workflows/hermes.yml`.

Local SO regtest:

```bash
bun scripts/spark-local.ts up         # requires SPARK_REF set
SPARK_E2E_LOCAL=1 bunx vp test --no-file-parallelism tests/e2e-local-*.test.ts   # run from packages/spark
```

Hosted regtest requires a funded seed (`SPARK_HOSTED_SEED` or a gitignored
`.env.hosted`); the seed can be provided on request:

```bash
SPARK_E2E_HOSTED=1 bunx vp test --no-file-parallelism tests/e2e-hosted-*.test.ts
```

WASM reproducibility: `bun run --cwd packages/spark-wasm build:wasm` performs
a pinned `linux/amd64` Docker build; the `SPARK_WASM_INTEGRITY` constant
exported from `packages/spark-wasm` (`src/integrity.ts`) is the artifact's
SHA-256 SRI and is compared against the packed `spark.wasm` in tests.

## Code guide

### Directory map

- `packages/spark/src/core/` — Bitcoin transaction construction and script
  utilities (`bitcoin/tx.ts`, `bitcoin/script.ts`, `bitcoin/htlc.ts`,
  `bitcoin/address.ts`, `bitcoin/sequence.ts`, `bitcoin/varint.ts`,
  `bitcoin/checksig.ts`, `bitcoin/taproot.ts`), `mutex.ts`, `lnurl.ts`,
  `network.ts`, `types.ts`, `util.ts`.
- `packages/spark/src/errors/` — `SparkError`, `SparkRequestError`,
  `SparkInputError`, `SparkCryptoError`, `SparkTokenBroadcastError`.
- `packages/spark/src/crypto/` — `SparkCrypto` interface and ABI version.
- `packages/spark/src/signer/` — `SparkSigner` (`types.ts`), the local
  implementation (`local.ts`), backend plumbing (`backend.ts`), nonce store
  (`nonces.ts`), HD derivation (`hd.ts`).
- `packages/spark/src/connection/` — SO gRPC connection, auth, retries,
  events (`index.ts`, `events.ts`, `auth.ts`).
- `packages/spark/src/ssp/` — SSP GraphQL client.
- `packages/spark/src/tree/` — leaf/node model and verification
  (`model.ts`, `verify.ts`, `renew.ts`, `direct.ts`).
- `packages/spark/src/transfer/` — send/claim/query/refund/swap model.
- `packages/spark/src/lightning/` — invoice, send, receive, status.
- `packages/spark/src/deposit/` — regular and static deposit paths.
- `packages/spark/src/exit/` — cooperative exit, unilateral exit chains,
  watchtower recovery, `SparkStore`.
- `packages/spark/src/tokens/` — token outputs, transfer/consolidate,
  metadata.
- `packages/spark/src/invoice/` — sats/tokens invoice create and parse.
- `packages/spark/src/lnurl/` — LNURL-auth, lightning address register.
- `packages/spark/src/settings/` — wallet settings sync.
- `packages/spark/src/client/` — client composition; `context.ts` holds
  leaf/token locks, `syncLeaves`, and shared plumbing; `transfers.ts`,
  `lightning.ts`, `tokens.ts`, `deposits.ts`, `withdrawals.ts`,
  `optimize.ts`, `leaves.ts`, `invoices.ts`, `settings.ts`.
- `packages/spark/src/server/` — `createLightningAddressServer`.
- `packages/spark/src/proto/gen` — generated protobuf (out of scope).
- `packages/spark-wasm/src` — WASM loader + integrity (`instance.ts`,
  `load.ts`, `integrity.ts`, `spark.wasm`); exports `SPARK_WASM_INTEGRITY`
  for consumer-side SRI fetches.
- `packages/spark-native/src` + `cpp/` — native binding (`bind.ts`,
  `specs`, `cpp/` nitro module).
- `crates/spark-crypto/src` — `lib.rs`, `frost.rs`, `ecies.rs`, `vss.rs`,
  `error.rs`.
- `crates/spark-ffi/src` — `lib.rs`, `abi.rs`, `messages.rs`, `ops.rs`;
  header at `include/qntx_spark.h`.
- `apps/lnurl-server/src` — `main.ts`, `http.ts`, `store.ts`, `zap.ts`,
  `config.ts`, `sleep.ts`.

### Flow walkthroughs

Lock notation: `[leafLock]` means `context.leafLock` is held across the step;
`[tokenLock]` means `context.tokenLock`.

#### Spark transfer send

1. `client/transfers.ts:sendSats` enters `[leafLock]`.
2. `context.syncLeaves()` refreshes spendable leaves and quarantines bad ones.
3. `client/leaves.ts:renewStaleLeaves` renews any stale leaves under the
   same lock.
4. `client/leaves.ts:selectSendLeaves` picks leaves covering the amount.
5. `signer.prepareTransfer` derives fresh leaf keys, VSS tweaks, and per-SO
   ECIES packages (`signer/types.ts`).
6. `transfer/send.ts:prepareTransferPackage`/`sendTransfer` builds and signs
   refund jobs via `transfer/refunds.ts:signRefundJobs` and submits
   `start_transfer`.
7. On a fresh response, `assertCommittedTransfer` binds the transfer id,
   type, sender, the exact receiver set (per-receiver amounts when given),
   and the total (`transfer/query.ts`). On a lost or non-final
   response with `transferId`, `queryCommittedTransfer` probes and validates
   the same terms — retry never double-spends.
8. `exit/store.ts` `deleteExitChains` runs for spent leaves.

#### Claim

1. `client/transfers.ts:claim` enters `[leafLock]`.
2. `transfer/query.ts:queryPendingTransfers` pages pending transfers with a
   strictly-advancing offset ending at `-1` (`PENDING_MAX_PAGES`).
3. Per transfer: `signer.prepareClaim` derives the `received − LEAF{leafId}`
   tweak and per-SO ECIES packages.
4. `transfer/claim.ts:claimTransfer` submits the claim.
5. `already_exists` → `recoverCompletedClaim` + `verifyClaimedLeaves` +
   `ownsLeaf` — the recovered leaves are validated before being adopted.
6. `storeChainsFor` stores the new exit chains; a leaf whose chain fails
   verification is quarantined on the next `syncLeaves` but the claim still
   returns.

#### Lightning pay

1. `client/lightning.ts:pay` → `lightning/send.ts:payLightningInvoice`
   enters `[leafLock]`.
2. Bolt11 decoded and validated (amount, expiry, network).
3. `selectSendLeaves`/`renewStaleLeaves` pick and refresh inputs.
4. `core/bitcoin/htlc.ts:createRefundTxsForLightning` /
   `constructHtlcTransaction` build HTLC refunds bound to the payment hash.
5. `requestLightningSend` (SSP) returns the transfer target.
6. `sendTransfer` with the caller `transferId`; the response and any
   committed probe are checked by `assertCommittedPaymentHash` (rebuilds the
   expected HTLC output script) and `assertCommittedTransfer`.
7. `lightning/status.ts:lightningSendStatus` reports completion.

#### Lightning receive and delegated receiver

1. `client/lightning.ts:createInvoice` → `lightning/receive.ts:createLightningInvoice`.
2. `signer.prepareLightningReceive` generates the preimage and VSS-splits it
   across operators.
3. SSP registers the invoice; an optional `receiverIdentityPublicKey`
   creates a delegated receiver whose route hint embeds the receiver's Spark
   address.
4. `lightning/status.ts:lightningReceiveStatus` verifies the invoice's
   payment hash and `sha256(preimage)` before reporting receipt.

#### Swap / optimize

1. `client/optimize.ts:optimizeLeaves` plans one or more swap rounds.
2. Per round under `[leafLock]`: `transfer/swap.ts:swapLeaves` submits the
   primary `requestSwap` (SSP) and the counter `claimTransfer`.
3. `tree/renew.ts:renewLeaf` renews stale leaves; the renew RPC carries
   `x-idempotency-key = txid(refundTx)` so a retry does not re-spend.
4. Swaps and renews have no caller-visible idempotency id — the SO
   auto-returns the primary swap for ~240 s (accepted risk).

#### Cooperative exit (fresh and resume)

1. `client/withdrawals.ts:cooperativeExit` → `exit/coop.ts:cooperativeExit`
   enters `[leafLock]`.
2. `coopExitFeeQuote` gets the SSP quote.
3. Connector refunds and the exit transaction are built locally
   (`core/bitcoin/`).
4. `requestCoopExit` (SSP) → `cooperative_exit_v2` RPC →
   `completeWithRetries` polls the SO.
5. Resume path: a recovered coop exit rebinds connector ↔ refund ↔ exit
   txid ↔ payout address; mismatches fail closed. A lost response probes
   `queryCommittedTransfer`.

#### Unilateral exit and watchtower recovery

1. `client/withdrawals.ts:unilateralExit` →
   `exit/unilateral.ts:unilateralExitTransactions` queries the operators
   live and returns the ordered `ExitTransactions`;
   `client/withdrawals.ts:offlineExitTransactions` produces the same list
   from stored `SparkExitChain`s with no network calls. Broadcasting is the
   host's job.
2. Deadline: every transaction must be broadcast and confirmed within 50
   blocks (`DIRECT_TIMELOCK_OFFSET`) of it becoming broadcastable, or the
   watchtower may publish self-fee/direct variants instead.
3. `client/withdrawals.ts:recoverWatchtowerExit` →
   `exit/watchtower.ts:recoverWatchtowerExit` re-signs a recovery
   transaction while the SO is online; `sweepRefund` sweeps a published
   direct refund.

#### Lightning HTLC timeout sweep

1. Applies when an in-flight lightning send's HTLC refund reached the chain
   and its `LIGHTNING_HTLC_SEQUENCE` CSV has elapsed — the sender takes the
   funds back on chain.
2. `client/lightning.ts:sweepHtlcTimeout({ htlcTx, vout, paymentHash,
   destinationAddress, feeRateSatPerVbyte })` builds the sweep with
   `constructHtlcSenderSpend` (SSP identity as hash-lock key) and
   `signer.signHtlcTimeout` signs the BIP-342 script-path sighash of the
   sequence-lock leaf after the signer rebuilds the output script,
   reconstructs the prevout, and enforces the input sequence.
3. Returns the signed transaction unbroadcast — same contract as
   `sweepRefund`. Broadcasting is the host's job.
4. Known limitation: stored exit chains are not retained for in-flight
   lightning leaves — this sweep is the recovery path for the sender side.

#### Single deposit

1. `client/deposits.ts:newAddress` → `deposit/index.ts:generateDepositAddress`
   — the operator's proof-of-possession is verified first
   (`validateDepositAddress`).
2. The host funds the address on chain.
3. `client/deposits.ts:claim` → `deposit/index.ts:claimDeposit` rebuilds the
   deposit transaction deterministically and verifies each input signature.
4. The tree-creation RPC registers the leaf; it becomes spendable on the
   next `syncLeaves`.

#### Static deposit claim / refund

1. `deposit/static.ts:generateStaticDepositAddress` builds the static
   address.
2. `claimStaticDeposit` polls the SSP for the transfer (≤6 × 1 s) and
   validates sender, receiver, total, and `transferId` terms before
   returning.
3. `refundStaticDeposit` constructs a v3 one-in-one-out refund locally (fee
   floor 194 sats, dust check) and returns it unbroadcast.

#### Token transfer / consolidate and explicit-input retry

1. `client/tokens.ts:sendTokens`/`consolidate` enter `[tokenLock]`.
2. `tokens/query.ts:queryTokenOutputs` selects inputs.
3. `tokens/transfer.ts:buildTransferPartial` builds the partial transaction;
   the caller signs each input with the identity key.
4. `broadcastPartialTokenTransaction` broadcasts and verifies the final tx;
   only `COMMIT_FINALIZED` is success — `COMMIT_PROCESSING` polls the
   committed-transaction probe on a bounded backoff until finalized.
5. Lost response: one identical retry, then `probeCommittedTransfer` pages
   `query_token_transactions` (`TOKEN_TX_PAGE_SIZE` 100, advancing offset,
   `TOKEN_TX_MAX_PAGES`) — a FINALIZED match returns its hash; an uncertain
   outcome throws `SparkTokenBroadcastError` carrying `inputOutputIds`.
6. Retry with `inputOutputIds`: `transferWithInputIds` resolves the prior
   inputs from the probe rows, rebuilds the exact partial (ignoring
   `clientCreatedTimestamp`), and either returns the committed hash or
   broadcasts exactly those inputs once — input ownership, token
   identifier, availability, and output terms are validated first.

#### Leaves sync, operator agreement, exit-chain refresh, quarantine

1. `client/context.ts:syncLeaves` (called inside every spend path) queries
   all operators with a paged `queryOwnerNodes` that ends on the
   coordinator's explicit `-1` offset (`TREE_MAX_PAGES`).
2. Ancestor leaves are removed from spendable candidates; `ownsLeaf` checks
   each leaf's owner key against signer-derived keys.
3. `tree/verify.ts:operatorsDisagree` compares every field across operators,
   including `directTx`, `directRefundTx`, `directFromCpfpRefundTx` —
   disagreeing leaves are quarantined.
4. `storeChainsFor` calls `exit/unilateral.ts:queryExitChains` →
   `buildExitChains`/`buildLeafExitChain` per leaf (shared `LinkageCache`);
   valid chains are stored, rejected leaf ids are quarantined; a stale chain
   stored earlier is retained.
5. Stored chains are swept only for node ids no operator reported at all —
   mapped or unmappable — in this sync.

#### LNURL server register → callback → settle → zap receipt

1. `apps/lnurl-server/src/main.ts:startLnurlServer` builds
   `packages/spark/src/server/index.ts:createLightningAddressServer` with an
   injected Spark client and the store.
2. Wallet registers a name via `lnurl/lightning-address.ts:registerLightningAddress`
   → `POST /lnurlpay/{pubkey}` with a signed statement.
3. Payer `GET /.well-known/lnurlp/{name}` → `server.payRequest` returns the
   LUD-06 payload with the callback URL.
4. Payer `GET /lnurlp/{name}/invoice?amount=…` → `server` calls
   `client.lightning.createInvoice` and returns the bolt11.
5. Settle loop (`main.ts`) periodically calls `server.settlePending`,
   which polls `receiveStatus` per stored payment hash and marks invoices
   settled once the preimage is verified.
6. NIP-57 zap requests are validated by `apps/lnurl-server/src/zap.ts:validateZapRequest`;
   `buildZapReceipt` produces the receipt; `publishZapReceipts` pushes it to
   configured Nostr relays with bounded concurrency.

### `SparkSigner` method table

| Method                    | Signs / derives                                              | Digest computed inside signer | Inputs validated                    |
| ------------------------- | ------------------------------------------------------------ | ----------------------------- | ----------------------------------- |
| `identityPublicKey`       | —                                                            | —                             | —                                   |
| `publicKeys`              | compressed pubkeys for `SparkLeafKey`s                       | —                             | key descriptors                     |
| `receivedPublicKeys`      | pubkeys of ECIES-sealed keys                                 | —                             | 32-byte plaintext after decrypt     |
| `newCommitments`          | FROST commitment pairs; nonces stored keyed by commitment    | —                             | `count` ≤ `MAX_JOBS`                |
| `signFrost`               | per-job FROST signature shares                               | full job content              | commitment consumed before signing  |
| `aggregateFrost`          | 64-byte aggregated FROST sigs                                | full job content              | resolved private key inside signer  |
| `signIdentity`            | protocol statement (DER ECDSA / BIP-340 for `spark-invoice`) | statement content             | statement shape                     |
| `signKeySpend`            | BIP-341 key-path sig over target sighash                     | target sighash                | `SparkKey` + `SigningTarget`        |
| `signHtlcTimeout`         | BIP-342 script-path sig over the HTLC sequence-lock leaf     | prevout + leaf sighash        | single-input shape, CSV sequence    |
| `prepareTransfer`         | sender transfer package (fresh keys, VSS tweaks, ECIES)      | —                             | leaf ids, operators, threshold      |
| `prepareClaim`            | receiver claim package (VSS `received − LEAF{id}` tweaks)    | —                             | leaf ids, operators                 |
| `prepareLightningReceive` | preimage + VSS `SecretShare` per operator                    | —                             | operators, threshold                |
| `claimStaticDeposit`      | child key ECIES-sealed to `sspIdentityPublicKey` + DER sig   | claim statement               | SSP identity pubkey, request fields |
| `dispose`                 | wipes keys, cached secrets, unused nonces                    | —                             | —                                   |

### `SparkCrypto` / C ABI table

| Function                | Inputs                                                          | Output                         | Validation in Rust                                      | Validation in TS                      |
| ----------------------- | --------------------------------------------------------------- | ------------------------------ | ------------------------------------------------------- | ------------------------------------- |
| `frostCommit`           | `hedge` (32 B), `random` (n×32 B)                               | n×130 B nonce+commitment pairs | length, FROST nonce construction                        | `hedge`/`random` lengths, job cap     |
| `frostSign`             | `ffi.FrostSignRequest` proto                                    | `ffi.FrostSignResponse`        | proto decode, per-job checks, secret key inside backend | request shape, job count ≤ `MAX_JOBS` |
| `frostAggregate`        | `ffi.FrostAggregateRequest` proto                               | `ffi.FrostAggregateResponse`   | proto decode, aggregation, verification per branch      | request shape                         |
| `eciesEncrypt`          | `publicKey` (33/65 B), `plaintext`, `random` (32 B)             | `ephemeralPk‖nonce‖tag‖ct`     | key length, KDF/AES-GCM params                          | lengths                               |
| `eciesDecrypt`          | `privateKey` (32 B), `ciphertext`                               | plaintext                      | key length, ciphertext format, tag check                | lengths                               |
| `splitSecretWithProofs` | `secret` (32 B), `threshold` t≥2, `shares` n≥t, `random` (32 B) | t×33 proofs + n×32 shares      | threshold/share bounds                                  | lengths, t/n bounds                   |

C ABI is defined by `crates/spark-ffi/include/qntx_spark.h`; bytes only;
`abiVersion` bumps only on ABI break.

### Validation helper index

- `assertCommittedTransfer` — `transfer/query.ts` — binds a committed
  transfer's id, type, sender, exact receiver set (per-receiver amounts when
  given), and total.
- `assertLiveTransfer` — `transfer/query.ts` — rejects non-live transfers.
- `assertCommittedPaymentHash` — `lightning/send.ts` — rebuilds and compares
  the expected HTLC output script for the payment hash.
- `verifyClaimedLeaves` — `transfer/claim.ts` — validates recovered claimed
  leaves.
- `ownsLeaf` — `client/context.ts` — checks a leaf's owner key against
  signer-derived keys.
- `operatorsDisagree` — `tree/verify.ts` — cross-operator field agreement
  (incl. direct variants).
- `buildLeafExitChain` — `exit/unilateral.ts` — validates and builds one
  leaf's exit chain.
- `validateDepositAddress` — `deposit/index.ts` — deposit-address
  proof-of-possession.
- `assertTokenAmount` — `tokens/model.ts` — token amount bounds.
- `mapTreeNode` / `mapTransfer` / `mapTokenOutput` — proto→domain
  normalization in `tree/model.ts`, `transfer/model.ts`, `tokens/model.ts`.
- `resolveInputOutputs`/`transferWithInputIds` guards —
  `tokens/transfer.ts` — explicit-input ownership/token/terms validation.
- `validateZapRequest` — `apps/lnurl-server/src/zap.ts` — NIP-57 checks.
- `required*`/`u64ToSats`/`bigintToSafeInt`/`asSats` — conversion/bounds
  helpers under `core/util.ts` and call sites.

### Locks and stores

- `context.leafLock` (`client/context.ts`, `core/mutex.ts`) — serializes
  leaf selection, signing, and broadcast across every spend path; held
  across SSP/SO calls and leaf renewal.
- `context.tokenLock` — serializes token input selection and broadcast.
- `NonceStore` (`signer/nonces.ts`) — FROST nonce lifecycle; removes a
  commitment before signing; `MAX_OUTSTANDING` bound.
- `SparkStore` (`exit/store.ts`) — persists verified `SparkExitChain`s;
  `putExitChains`/`deleteExitChains`; `createMemorySparkStore` is the
  in-memory default.
- `apps/lnurl-server/src/store.ts` — SQLite store for registered users,
  statements, and pending/settled invoices.
