//! Cryptographic primitives for the Spark protocol: user-side FROST signing,
//! ECIES encryption and Feldman VSS secret sharing.
//!
//! Randomness is always an input — the crate never draws from the operating
//! system — so every function is deterministic for a given seed and the
//! dependency tree stays free of `getrandom` and `rayon`. The crate builds
//! for `wasm32-unknown-unknown` and the iOS/Android targets; the C ABI lives
//! in `spark-ffi`, which is the only crate allowed to use `unsafe`.

#![forbid(unsafe_code)]

pub mod ecies;
mod error;
pub mod frost;
pub mod vss;

pub use error::Error;

// Dev-only tools are linked into test targets; keep the lib lint clean.
#[cfg(test)]
use hex as _;
#[cfg(test)]
use serde_json as _;
