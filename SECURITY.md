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

## Threat model (summary)

This library implements the Spark Bitcoin L2 protocol. Private keys live only
inside the `SparkSigner` implementation; the client never holds them. The only
method that returns a private key is `claimStaticDeposit` (required by the SSP
claim flow).

| Threat                                         | Severity | Mitigation                                                                                                                        |
| ---------------------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Private key leaves the signer boundary         | High     | Keys never cross the `SparkCrypto` C ABI unsealed; `SparkSigner` returns only public/derived material except `claimStaticDeposit` |
| FROST nonce reuse                              | High     | Nonces are derived from a signer-held hedge secret plus injected randomness                                                       |
| Untrusted operator input in protobuf/ABI calls | High     | Fixed error codes, no input bytes in error messages, bounds checked in `spark-ffi`                                                |
| Backend ABI mismatch                           | Medium   | `abiVersion` checked at signer construction                                                                                       |
