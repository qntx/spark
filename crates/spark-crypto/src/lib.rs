//! Cryptographic primitives for the Spark protocol: user-side FROST signing,
//! ECIES encryption and Feldman VSS secret sharing.
//!
//! Randomness is always an input — the crate never draws from the operating
//! system — so every function is deterministic for a given seed and the
//! dependency tree stays free of `getrandom` and `rayon`. The crate builds for
//! `wasm32-unknown-unknown` and the iOS/Android targets; the C ABI lives in
//! `spark-ffi`, which is the only crate allowed to use `unsafe`.

#![forbid(unsafe_code)]
