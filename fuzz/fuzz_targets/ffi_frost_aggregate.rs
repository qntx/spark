#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut out: *mut u8 = core::ptr::null_mut();
    let mut out_len: usize = 0;
    // SAFETY: `data` is a valid slice for the call; `out`/`out_len` are valid
    // writable out-params per the qntx_spark.h contract.
    let code = unsafe {
        spark_ffi::abi::qs_frost_aggregate(data.as_ptr(), data.len(), &mut out, &mut out_len)
    };
    if code == 0 && !out.is_null() {
        // SAFETY: on success `out`/`out_len` describe a live `qs_alloc` region.
        unsafe { spark_ffi::abi::qs_free(out, out_len) };
    }
});
