<!-- markdownlint-disable MD033 MD041 -->

# spark

A TypeScript and Rust implementation of the [Spark](https://github.com/buildonspark/spark)
Bitcoin L2 protocol: [`@qntx/spark`](https://www.npmjs.com/package/@qntx/spark) (npm,
`packages/spark`) with cryptographic primitives in Rust (`crates/spark-crypto`) behind a
versioned C ABI (`crates/spark-ffi`).

Status: **pre-release**. `@qntx/spark` exports the full platform-neutral client
(`createSparkClient`), invoices, deposits, transfers, Lightning, tokens, exits and the LNURL
server library, plus the `SparkCrypto` backend interface (`./crypto`) and signer (`./signer`).
See the [package README](packages/spark/README.md) for the security model. The audit scope and
code guide live in [AUDIT.md](AUDIT.md).

Changes are tracked in [CHANGELOG.md](CHANGELOG.md); contributor invariants and the local
gate live in [AGENTS.md](AGENTS.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE) or
<https://www.apache.org/licenses/LICENSE-2.0>); see [NOTICE](NOTICE) and
[THIRD_PARTY.md](THIRD_PARTY.md).

Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in this project shall be licensed as above, without any additional terms or
conditions.

---

<div align="center">

A **[QuantX](https://qntx.org)** open-source project.

<a href="https://qntx.org"><img alt="QuantX" width="369" src="https://raw.githubusercontent.com/qntx/.github/main/profile/qntx.svg" /></a>

Code is law. We write both.

</div>
