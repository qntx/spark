# @qntx/lnurl-server

Reference Lightning Address service built on `@qntx/spark/server`: LUD-06/12/16/21 endpoints,
Breez-style signed registration, and optional NIP-57 zap receipts. Runs on Node.js >= 24
(`node:sqlite`, unflagged).

## Run

```bash
LNURL_DOMAIN=example.com \
LNURL_NETWORK=regtest \
LNURL_SPARK_SEED=<64-byte hex seed> \
LNURL_DB_PATH=./lnurl.db \
LNURL_ZAP_SECRET_KEY=<32-byte hex> \
bun run start
```

The Spark wallet derived from `LNURL_SPARK_SEED`/`LNURL_SPARK_ACCOUNT` only ever creates
invoices, so it needs no balance.

## Configuration

| Variable                  | Default     | Notes                                        |
| ------------------------- | ----------- | -------------------------------------------- |
| `LNURL_DOMAIN`            | (required)  | Domain served in `name@domain` addresses     |
| `LNURL_NETWORK`           | (required)  | `mainnet` or `regtest`                       |
| `LNURL_SPARK_SEED`        | (required)  | 64-byte hex; the invoice-issuing wallet seed |
| `LNURL_SPARK_ACCOUNT`     | SDK default | Account index (mainnet 1, regtest 0)         |
| `LNURL_DB_PATH`           | (required)  | SQLite database path                         |
| `LNURL_PORT`              | `8080`      | `0` binds an ephemeral port                  |
| `LNURL_MIN_SENDABLE_MSAT` | `1000`      | LUD-06 minimum                               |
| `LNURL_MAX_SENDABLE_MSAT` | `100000000` | LUD-06 maximum                               |
| `LNURL_COMMENT_ALLOWED`   | `255`       | LUD-12 comment limit                         |
| `LNURL_POLL_INTERVAL_MS`  | `5000`      | Settlement + receipt-publish round interval  |
| `LNURL_ZAP_SECRET_KEY`    | (unset)     | 32-byte hex; set enables NIP-57 zaps         |

Secrets are never logged or echoed in errors.

## Routes

| Method | Path                        | Handler                                         |
| ------ | --------------------------- | ----------------------------------------------- |
| POST   | `/lnurlpay/:pubkey`         | Register a lightning address (signed statement) |
| DELETE | `/lnurlpay/:pubkey`         | Unregister (signed statement)                   |
| GET    | `/.well-known/lnurlp/:name` | LUD-06/LUD-16 pay request                       |
| GET    | `/lnurlp/:name`             | Same pay request                                |
| GET    | `/lnurlp/:name/invoice`     | LUD-06 callback (`amount`, `comment`, `nostr`)  |
| GET    | `/lnurlp/verify/:hash`      | LUD-21 settlement status + preimage             |
| GET    | `/health`                   | Liveness                                        |

With `LNURL_ZAP_SECRET_KEY` set the pay request advertises `allowsNostr`/`nostrPubkey` (LUD-06
zaps extension): `nostr` invoice parameters are validated per NIP-57 appendix D, and every
settled zapped invoice produces a signed kind-9735 receipt persisted in `zap_receipts` and
published to the request's `relays` (up to 10 `ws(s)://` URLs, retried up to 5 rounds).

## Layout

- `src/config.ts` — environment parsing, fail fast, no secret echoing
- `src/store.ts` — `node:sqlite` `LightningAddressStore` + `zap_receipts`
- `src/zap.ts` — NIP-57 request validation, receipt build/sign/publish
- `src/http.ts` — Hono routes over the framework-agnostic server handlers
- `src/main.ts` — composition root (wasm backend, signer, client, poll loop, signals)

## Tests

```bash
bun run test                          # unit tests
SPARK_E2E_HOSTED=1 bunx vp test tests/e2e-hosted.test.ts
```
