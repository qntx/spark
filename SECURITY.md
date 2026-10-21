# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| < 1.0   | No        |

This library is pre-release; no version receives security support yet.

## Reporting a vulnerability

Report security issues privately via GitHub Security Advisories on
[qntx/spark](https://github.com/qntx/spark/security/advisories/new), or email
`security@qntx.org` if that channel is unavailable.

Please include:

- Affected version and runtime (Node/Bun/browser/React Native)
- Minimal reproduction
- Impact assessment (e.g. private-key exposure, signature forgery, incorrect
  secret sharing)

Do not open public issues for unfixed vulnerabilities.

The audit scope, adversary model, claimed properties, and code guide live in
[AUDIT.md](AUDIT.md).

## Threat model (summary)

This library implements the Spark Bitcoin L2 protocol. Private keys live only
inside the `SparkSigner` implementation; the client never holds them. No signer
method returns plaintext private key material — `claimStaticDeposit` returns the
static-deposit key ECIES-sealed to the SSP identity. The operator set, VSS threshold
and SSP identity are bound at signer construction (defaulting to the network's
`sparkNetworkConfig`, overridable to point at another deployment such as the local
stack); no request carries them, so key-tweak shares and the deposit secret can only
be sealed to the configured destinations. The signer enforces no
transaction-semantics policy: it signs what the client layer asks it to, and
funds safety relies on the client's local construction and validation of every
transaction before signing. `createSparkClient` requires an explicit
`SparkStore`: stored exit chains are the wallet's unilateral-exit data and their
durability is a caller decision. Every read that can move funds is unanimous
across operators — leaves, token outputs, exit chains and committed transfers
resumed by a caller-supplied id count only when all operators report them
identically — so a malicious or stale
coordinator cannot inflate a balance or erase exit data on its own.

| Threat                                         | Severity | Mitigation                                                                                                                                                                                                                                  |
| ---------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Private key leaves the signer boundary         | High     | Keys never cross the `SparkCrypto` C ABI unsealed; `SparkSigner` returns only public/derived material                                                                                                                                       |
| FROST nonce reuse                              | High     | Single-use nonces consumed before signing; per-call hedge HMAC(key, tag‖counter) plus injected randomness — a repeating RNG within one signer instance cannot repeat nonces; a repeating RNG across restarts is the caller's responsibility |
| Untrusted operator input in protobuf/ABI calls | High     | Fixed error codes, no input bytes in error messages, bounds checked in `spark-ffi`                                                                                                                                                          |
| Backend ABI mismatch                           | Medium   | `abiVersion` checked at signer construction                                                                                                                                                                                                 |
