//! `extern "C"` entry points: argument slicing, out-param writes, and
//! allocation. `unsafe` is confined to this module — `ops` holds all safe
//! request handling — and every unsafe block carries a SAFETY comment.
//!
//! Contract (see `include/qntx_spark.h`): inputs are `(pointer, len)` pairs;
//! a null pointer is a length error unless `len == 0`. Outputs are caller-
//! provided `(uint8_t **out, size_t *out_len)` out-params written only on
//! success — on error they are left untouched and the error code is
//! returned. Successful output buffers are library-allocated and released
//! with `qs_free`. Secret input buffers stay owned by the caller, which
//! wipes them after the call.

#![allow(
    unsafe_code,
    reason = "the C ABI boundary is the one place raw pointers are legal"
)]

use spark_crypto::Error;
use zeroize::Zeroize;

use crate::ops;

/// A caller-provided `(pointer, len)` input as a slice.
///
/// Empty inputs may carry a null pointer.
///
/// # Safety
/// `ptr` must be readable for `len` bytes for the duration of the call, per
/// the `qntx_spark.h` contract.
const unsafe fn input<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(Error::Length.code());
    }
    // SAFETY: the caller guarantees `ptr` is readable for `len` bytes.
    Ok(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// [`input`] with an exact-length requirement, borrowed as a fixed array.
///
/// # Safety
/// Same contract as [`input`].
unsafe fn fixed<'a, const N: usize>(ptr: *const u8, len: usize) -> Result<&'a [u8; N], i32> {
    // SAFETY: forwarded caller contract.
    let slice = unsafe { input(ptr, len) }?;
    slice.try_into().map_err(|_| Error::Length.code())
}

/// Reads a `(pointer, len)` input for the enclosing `qs_*` call.
///
/// The unsafe block lives in the macro so every expansion carries the same
/// safety argument: each expansion site is a `qs_*` entry point whose
/// pointer inputs obey the `qntx_spark.h` contract documented on the fn.
macro_rules! read {
    ($ptr:expr, $len:expr) => {{
        // SAFETY: forwarded caller contract from the enclosing extern fn.
        unsafe { input($ptr, $len) }
    }};
}

/// [`read`] with an exact 32-byte length requirement.
macro_rules! fixed32 {
    ($ptr:expr, $len:expr) => {{
        // SAFETY: forwarded caller contract from the enclosing extern fn.
        unsafe { fixed::<32>($ptr, $len) }
    }};
}

/// Hand a freshly allocated output buffer to the caller.
///
/// Writes the out-params only when both are non-null.
///
/// # Safety
/// `out`/`out_len` must be writable out-params or null; when both are
/// written, the returned pointer is owned by the caller and must be released
/// with `qs_free`.
unsafe fn write_out(out: *mut *mut u8, out_len: *mut usize, mut bytes: Vec<u8>) -> i32 {
    if out.is_null() || out_len.is_null() {
        // The output may be secret (decrypted plaintext, shares, nonces).
        bytes.zeroize();
        return Error::Length.code();
    }
    let len = bytes.len();
    let ptr = if len == 0 {
        core::ptr::null_mut()
    } else {
        Box::into_raw(bytes.into_boxed_slice()).cast::<u8>()
    };
    // SAFETY: `out` is a valid writable out-param.
    unsafe { out.write(ptr) };
    // SAFETY: `out_len` is a valid writable out-param.
    unsafe { out_len.write(len) };
    0
}

/// Answers a `qs_*` call: output bytes go to the out-params on success, the
/// error code is returned untouched otherwise.
///
/// # Safety
/// `out`/`out_len` must be writable out-params or null, per [`write_out`].
unsafe fn respond(out: *mut *mut u8, out_len: *mut usize, result: Result<Vec<u8>, i32>) -> i32 {
    match result {
        // SAFETY: `out`/`out_len` are the caller's writable out-params.
        Ok(bytes) => unsafe { write_out(out, out_len, bytes) },
        Err(code) => code,
    }
}

/// Returns the C ABI version implemented by this library (`crate::ABI_VERSION`).
#[allow(
    clippy::missing_const_for_fn,
    reason = "extern functions cannot be const"
)]
#[unsafe(no_mangle)]
pub extern "C" fn qs_abi_version() -> u32 {
    crate::ABI_VERSION
}

/// Allocates a zeroed `len`-byte buffer for the caller.
///
/// `len == 0` returns NULL. Free with `qs_free`.
#[allow(
    clippy::missing_const_for_fn,
    reason = "extern functions cannot be const"
)]
#[unsafe(no_mangle)]
pub extern "C" fn qs_alloc(len: usize) -> *mut u8 {
    if len == 0 {
        return core::ptr::null_mut();
    }
    Box::into_raw(vec![0u8; len].into_boxed_slice()).cast::<u8>()
}

/// Wipes then frees a buffer produced by `qs_alloc` or a `qs_*` out-param.
///
/// `qs_free(NULL, 0)` is a no-op.
///
/// # Safety
/// `ptr`/`len` must be a pair previously returned by `qs_alloc` or a
/// successful `qs_*` output, and must not be used afterwards.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    let slice = core::ptr::slice_from_raw_parts_mut(ptr, len);
    // SAFETY: `slice` was built from a live `Box<[u8]>` pointer/len pair the
    // caller passes back untouched; reconstructing the box restores ownership
    // so the drop frees it.
    let mut boxed = unsafe { Box::from_raw(slice) };
    boxed.zeroize();
}

/// FROST signing nonces and commitments.
///
/// `hedge` is 32 bytes, `random` is a positive multiple of 32 up to
/// `256 * 32` bytes. Output is `n * 130` bytes (`nonces(64) ‖
/// commitments(66)` per item).
///
/// Errors: `1` wrong `hedge`/`random` length or null out-params, `2` invalid
/// hedge scalar, `5` `random` longer than the cap.
///
/// # Safety
/// `qntx_spark.h` `(pointer, len)` and out-param contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_frost_commit(
    hedge: *const u8,
    hedge_len: usize,
    random: *const u8,
    random_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let result = (|| -> Result<Vec<u8>, i32> {
        let hedge = read!(hedge, hedge_len)?;
        let random = read!(random, random_len)?;
        ops::frost_commit(hedge, random)
    })();
    // SAFETY: `out`/`out_len` are the caller's writable out-params.
    unsafe { respond(out, out_len, result) }
}

/// User-side FROST signature shares.
///
/// `req` is a protobuf `qntx.spark.ffi.FrostSignRequest`; output is a
/// `FrostSignResponse` with one 32-byte share per job, in job order.
///
/// Errors: `1` wrong field length or null out-params, `2` invalid scalar,
/// `3` invalid point, `4` protobuf decode failure, `5` zero or more than
/// 256 jobs, `6` FROST failure.
///
/// # Safety
/// `qntx_spark.h` `(pointer, len)` and out-param contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_frost_sign(
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let result = read!(req, req_len).and_then(ops::frost_sign);
    // SAFETY: `out`/`out_len` are the caller's writable out-params.
    unsafe { respond(out, out_len, result) }
}

/// FROST aggregate signatures.
///
/// `req` is a protobuf `qntx.spark.ffi.FrostAggregateRequest`; output is a
/// `FrostAggregateResponse` with one 64-byte signature per job, in job
/// order. Same error vocabulary as `qs_frost_sign`.
///
/// # Safety
/// `qntx_spark.h` `(pointer, len)` and out-param contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_frost_aggregate(
    req: *const u8,
    req_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let result = read!(req, req_len).and_then(ops::frost_aggregate);
    // SAFETY: `out`/`out_len` are the caller's writable out-params.
    unsafe { respond(out, out_len, result) }
}

/// ECIES encryption compatible with `ecies` 0.2 defaults.
///
/// `pk` is a 33- or 65-byte public key, `random` is 32 bytes; output is
/// `ephemeralPk(65) ‖ nonce(16) ‖ tag(16) ‖ ciphertext`.
///
/// Errors: `1` wrong `pk`/`random` length or null out-params, `3` invalid
/// point, `8` internal.
///
/// # Safety
/// `qntx_spark.h` `(pointer, len)` and out-param contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_ecies_encrypt(
    pk: *const u8,
    pk_len: usize,
    msg: *const u8,
    msg_len: usize,
    random: *const u8,
    random_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let result = (|| -> Result<Vec<u8>, i32> {
        let pk = read!(pk, pk_len)?;
        let msg = read!(msg, msg_len)?;
        let random = fixed32!(random, random_len)?;
        ops::ecies_encrypt(pk, msg, random)
    })();
    // SAFETY: `out`/`out_len` are the caller's writable out-params.
    unsafe { respond(out, out_len, result) }
}

/// ECIES decryption.
///
/// `sk` is 32 bytes; output is the plaintext.
///
/// Errors: `1` wrong `sk` length, too-short ciphertext or null out-params,
/// `2` invalid scalar, `3` invalid point, `7` decryption authentication
/// failure.
///
/// # Safety
/// `qntx_spark.h` `(pointer, len)` and out-param contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_ecies_decrypt(
    sk: *const u8,
    sk_len: usize,
    ct: *const u8,
    ct_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let result = (|| -> Result<Vec<u8>, i32> {
        let sk = fixed32!(sk, sk_len)?;
        let ct = read!(ct, ct_len)?;
        ops::ecies_decrypt(sk, ct)
    })();
    // SAFETY: `out`/`out_len` are the caller's writable out-params.
    unsafe { respond(out, out_len, result) }
}

/// Feldman VSS split.
///
/// `secret` and `random` are 32 bytes each, `threshold` t ≥ 2 and `shares` n
/// satisfy t ≤ n ≤ 255. Output is `t×33` proof bytes followed by `n×32`
/// share bytes; share indexes run 1..n.
///
/// Errors: `1` wrong `secret`/`random` length or null out-params, `2`
/// invalid secret scalar, `5` threshold/share range, `8` internal.
///
/// # Safety
/// `qntx_spark.h` `(pointer, len)` and out-param contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qs_split_secret_with_proofs(
    secret: *const u8,
    secret_len: usize,
    threshold: u32,
    shares: u32,
    random: *const u8,
    random_len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let result = (|| -> Result<Vec<u8>, i32> {
        let secret = fixed32!(secret, secret_len)?;
        let random = fixed32!(random, random_len)?;
        ops::split_secret_with_proofs(secret, threshold, shares, random)
    })();
    // SAFETY: `out`/`out_len` are the caller's writable out-params.
    unsafe { respond(out, out_len, result) }
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
