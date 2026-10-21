# @qntx/spark

Platform-neutral TypeScript implementation of the [Spark](https://github.com/buildonspark/spark)
Bitcoin L2 protocol. Cryptographic backends (`@qntx/spark-wasm`, `@qntx/spark-native`) plug into
the `SparkCrypto` interface exported from `@qntx/spark/crypto`.

Status: **pre-release**. See the [repository](https://github.com/qntx/spark) and
[CHANGELOG](https://github.com/qntx/spark/blob/main/CHANGELOG.md).

## Security

Trust model: a leaf is spendable only with the signing-operator threshold plus the wallet's key —
no single operator can move funds. The wallet verifies locally every transaction it signs
(refunds and exit transactions), that every stored exit chain's refunds pay the wallet's own
leaf key, that a deposit address's proof of possession is valid, and that every operator reports
a leaf identically — and token outputs and committed transfers likewise count only when
every operator reports them identically, so a single operator cannot inflate a balance or
forge a spend. Lightning sends and receives, leaves swaps, cooperative exits and
static-deposit claims go through the SSP; the client validates the SSP responses it acts on
(invoice and transfer-id echoes, payment-hash↔preimage proofs, connector and payout
transactions, fee bounds).

Leaf quarantine: a leaf the operators report differently, or whose served exit chain fails
verification, is excluded from balance and spending; a previously stored (verified) exit chain
is kept, and `withdrawals.unilateralExit` on that leaf reports the precise failure.

Key custody: private keys never leave the `SparkSigner` — the client only ever sees protocol
values (public keys, signatures, ciphertexts).

Idempotent retries: `transfers.send`/`sendMany`, `lightning.pay` and
`withdrawals.cooperativeExit` accept a `transferId` — reuse the same id to retry a call whose
response may have committed; the same id with different terms fails rather than paying twice.
`tokens.transfer`/`tokens.consolidate` throw `SparkTokenBroadcastError` when the broadcast
outcome is uncertain — retry with `inputOutputIds: error.inputOutputIds` and the same receiver
and amount; that retry either returns the committed transaction's hash or broadcasts exactly
those inputs once. Retrying without it would select different outputs and pay twice.

Offline receive: once a transfer commits, the sender cannot cancel it and its expiry does not
return it — `transfers.claim`/`claimPending` can pick it up at any later time.

Unilateral exit: each pre-signed transaction carries a hard deadline — once its parent confirms
and its relative timelock passes, it must confirm within 50 blocks; otherwise the operators'
watchtower may publish a self-fee variant instead. For intermediate nodes this strands
descendants as WATCHTOWER_EXITED (recover with `recoverWatchtowerExit` while the SO is online);
for refunds the watchtower publishes `direct_from_cpfp_refund_tx`, which pays the leaf key
(sweep with `sweepRefund`). Keep each exit package confirming promptly. Exit chains persist in
the `SparkStore` passed to `createSparkClient` (required — `createMemorySparkStore()` for
ephemeral wallets); a chain is deleted only when every operator endorses it as no longer
exitable by this wallet, so a withheld or fabricated coordinator response cannot erase the
offline exit path.

LNURL server (`apps/lnurl-server`): put per-IP rate limiting in front of the endpoints —
invoice creation is unauthenticated. Zap receipt relays are payer-controlled URLs that can
resolve to internal addresses (DNS rebinding): run the service where outbound connections to
internal ranges are denied at the network layer.

Status: multiple internal review rounds plus two external audit rounds scoped by
[AUDIT.md](https://github.com/qntx/spark/blob/main/AUDIT.md); not yet run on mainnet.

Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
