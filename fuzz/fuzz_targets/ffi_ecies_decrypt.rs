#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (secret_key, ciphertext) = data.split_at(data.len().min(32));
    let mut out: *mut u8 = core::ptr::null_mut();
    let mut out_len: usize = 0;
    // SAFETY: both slices are valid for the call; `out`/`out_len` are valid
    // writable out-params per the qntx_spark.h contract.
    let code = unsafe {
        spark_ffi::abi::qs_ecies_decrypt(
            secret_key.as_ptr(),
            secret_key.len(),
            ciphertext.as_ptr(),
            ciphertext.len(),
            &mut out,
            &mut out_len,
        )
    };
    if code == 0 && !out.is_null() {
        // SAFETY: on success `out`/`out_len` describe a live `qs_alloc` region.
        unsafe { spark_ffi::abi::qs_free(out, out_len) };
    }
});
