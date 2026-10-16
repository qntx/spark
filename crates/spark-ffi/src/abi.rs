//! `extern "C"` entry points. `unsafe` is confined to this module — the rest
//! of the crate inherits the workspace `unsafe_code = "deny"` — and every
//! unsafe block carries a SAFETY comment.

#![allow(
    unsafe_code,
    reason = "the C ABI boundary is the one place raw pointers are legal"
)]

/// Returns the C ABI version implemented by this library (`crate::ABI_VERSION`).
#[allow(
    clippy::missing_const_for_fn,
    reason = "extern functions cannot be const"
)]
#[unsafe(no_mangle)]
pub extern "C" fn qs_abi_version() -> u32 {
    crate::ABI_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abi_version_matches_crate_constant() {
        assert_eq!(qs_abi_version(), crate::ABI_VERSION);
        assert_eq!(qs_abi_version(), 1);
    }
}
