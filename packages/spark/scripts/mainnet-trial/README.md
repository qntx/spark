# Mainnet trial runner

A phase-by-phase, small-amount mainnet trial of `@qntx/spark` for the maintainer.
Every money-moving step is recorded in an append-only JSONL ledger and checked
against the balance before and after — a mismatch stops the run with exit code 2.
Exit chains persist on disk so the unilateral-exit package is always rebuildable.

The same commands rehearse on the hosted regtest with `--network regtest`.

## Setup

1. Build the packages once: `bun install && bun run build` at the repo root
   (the runner consumes `@qntx/spark-wasm` from `dist/` like a real consumer).
2. Derive a 64-byte hex seed **offline** from a dedicated BIP-39 mnemonic used
   only for this trial — never reuse a production seed.
3. Put it in `.env.mainnet` at the repo root (gitignored via `.env.*`):
   `SPARK_MAINNET_SEED=<128 hex chars>` and `chmod 600 .env.mainnet`. The runner
   refuses a group/world-readable file. `SPARK_MAINNET_SEED` in the environment
   works instead of the file. The seed is never printed, logged or written to
   the state directory. For regtest rehearsals use the existing
   `SPARK_HOSTED_SEED` / `.env.hosted`.
4. State lives in `.mainnet-trial/` (gitignored): per-network `ledger.jsonl`
   plus `account-N/exit-chains.json` (mode 0600, dirs 0700). Override with
   `--state-dir`. Single-process: don't run two instances on one state dir.

## Safety rules baked in

- Spending commands (`send`, `pay`, `pay-address`, `coop-exit`) require
  `--confirm` on mainnet; without it they print what would happen and exit 0.
- `MAX_TRIAL_SATS = 200_000` caps every `--amount` and `--max-fee` — no override.
- `--max-fee` is mandatory on every fee-bearing command.
- After each money-moving step the ledger compares the actual balance delta with
  the expected one; a mismatch appends a `mismatch` entry, prints STOP and exits 2. `report` re-prints every mismatch and pending entry and also exits 2 on
  mismatches.

## Commands

`bun packages/spark/scripts/mainnet-trial/main.ts <command> [options]`

| Command                           | Options                                                                     | Notes                                                                     |
| --------------------------------- | --------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `status`                          | —                                                                           | identity key, spark address, balance, leaf/chain counts, pending          |
| `receive-ln`                      | `--amount [--memo] [--timeout-min 30]`                                      | prints bolt11, waits for payment, claims                                  |
| `deposit-address`                 | —                                                                           | fresh single-use address                                                  |
| `claim-deposit`                   | `--txid`                                                                    | fetches raw tx via public esplora, claims                                 |
| `static-address` / `static-utxos` | —                                                                           | static deposit address + unspent UTXOs                                    |
| `claim-static`                    | `--txid --vout --max-fee`                                                   | shows the UTXO, claims, ledger +credit                                    |
| `send`                            | `--to <spark address\|account:N> --amount [--transfer-id]`                  | prints transferId before sending; reuse it to retry                       |
| `claim`                           | —                                                                           | claims all pending incoming transfers                                     |
| `pay`                             | `--invoice [--amount] --max-fee [--transfer-id]`                            | polls to succeeded/returned                                               |
| `pay-address`                     | `--address name@domain --amount --max-fee [--comment]`                      | LNURL pay + invoice, then `pay`                                           |
| `optimize`                        | —                                                                           | leaf optimization; ledger expects Δ0                                      |
| `exit-package`                    | `--out FILE`                                                                | compares stored-chain txids against the live query, writes hex txs (0600) |
| `coop-exit`                       | `--address [--amount] --max-fee --speed fast\|medium\|slow [--transfer-id]` | quotes first, then exits and polls                                        |
| `events`                          | `--minutes N`                                                               | prints coordinator events                                                 |
| `report`                          | —                                                                           | per-account totals, mismatches, pending                                   |

## Runbook

Run the phases in order; rehearse each phase on `--network regtest` first.

| Phase | Goal                         | Commands                                                                                                                                                          |
| ----- | ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0     | Read-only                    | `status`, `events --minutes 1`                                                                                                                                    |
| 1     | Receive                      | `receive-ln --amount 5000` then pay the invoice from a real wallet; `static-address` + small on-chain send, then `static-utxos`, `claim-static`                   |
| 2     | Spark transfers              | `send --to account:1 --amount 1000` (note the printed transferId; rerun with `--transfer-id <id>` to prove idempotent retry), `claim` on `--account 1`, send back |
| 3     | Lightning pay                | `pay` a small invoice with `--max-fee`; `pay` a zero-amount invoice with `--amount`; `pay` an unroutable invoice and watch it end `returned` (Δ0)                 |
| 4     | Optimize                     | `optimize`                                                                                                                                                        |
| 5     | Lightning Address (optional) | deploy `apps/lnurl-server`, then `pay-address --address you@your-domain --amount 1000` (a zap works the same way)                                                 |
| 6     | Exit package                 | `exit-package --out exit-package.json` — proves every leaf's stored chain reproduces the live view                                                                |
| 7     | Cooperative exit             | `coop-exit --address <your on-chain address> --amount 5000 --max-fee 500 --speed slow`                                                                            |
| 8     | Unilateral exit (optional)   | broadcast the `exit-package` for one ~10k-sat leaf by hand — see below                                                                                            |

Budget guidance: keep every send ≤ 20k sats and the whole trial under
`MAX_TRIAL_SATS`; a full pass through phases 0–7 costs a few thousand sats plus
Lightning/coop-exit fees.

### Unilateral exit by hand

`exit-package` writes the leaf's pre-signed transactions in broadcast order
with their relative timelocks — the runner deliberately never broadcasts. To
exit one leaf unilaterally: broadcast its node transaction(s) (fee-bump with a
CPFP child built via the SDK's `buildCpfpChild`), wait out each relative
timelock, broadcast the refund transaction, then sweep the confirmed refund
output with `sweepRefund`. Each transaction must confirm within
`DIRECT_TIMELOCK_OFFSET` (50) blocks of its parent's timelock maturity or the
operator watchtower publishes the direct variant — keep the package confirming
promptly.

## Stop conditions

Stop and keep the state directory when:

- any ledger `mismatch` entry appears (the runner exits 2 for you),
- a step ends `pending` and does not resolve on retry,
- any error message you cannot explain from this README or AUDIT.md.

Report the failure with the state directory and `ledger.jsonl` — never include
the seed.

## What to keep

- `.mainnet-trial/` (ledger + exit chains) until the trial is fully reviewed.
- The `exit-package` files — they are the only off-server copy of the pre-signed
  exit transactions.
