//! C ABI over `spark-crypto`: every entry point exchanges bytes and returns an
//! error code. The committed generated header is `include/qntx_spark.h`
//! (`cbindgen.toml`).

pub mod abi;

/// C ABI version implemented by this build. Bumped only when `qntx_spark.h`
/// changes incompatibly; callers compare it against `SPARK_ABI_VERSION`.
pub const ABI_VERSION: u32 = 1;
