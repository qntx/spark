//! C ABI over `spark-crypto`: every entry point exchanges bytes and returns an
//! error code. The committed generated header is `include/qntx_spark.h`
//! (`cbindgen.toml`).

pub mod abi;
pub mod messages;
mod ops;

/// C ABI version implemented by this build. Bumped only when `qntx_spark.h`
/// changes incompatibly; callers compare it against `SPARK_ABI_VERSION`.
pub const ABI_VERSION: u32 = 1;

// Dev-only tools are linked into test targets; keep the lib lint clean.
#[cfg(test)]
use hex as _;
#[cfg(test)]
use serde_json as _;
