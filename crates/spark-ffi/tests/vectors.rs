//! Shared FFI vectors: `ffi-sign.json`, `ffi-aggregate.json` and
//! `ffi-errors.json` — protobuf request/response hex and expected error
//! codes derived from the `frost-sign.json` cases.
//!
//! `SPARK_WRITE_VECTORS=1 cargo test -p spark-ffi --test vectors`
//! regenerates the files under the repository-root `vectors/` directory;
//! otherwise this test regenerates the documents, asserts they match the
//! stored files, and replays every case through the `extern "C"` functions.

#![allow(
    unsafe_code,
    clippy::missing_assert_message,
    clippy::tests_outside_test_module,
    clippy::too_many_lines,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    reason = "the test harness exercises the C ABI directly"
)]

use std::path::{Path, PathBuf};
use std::ptr;

// Linked dev-only deps of the library; silence unused_crate_dependencies.
use spark_crypto as _;
use zeroize as _;

use prost::Message as _;
use serde_json::{Value, json};
use spark_ffi::abi;
use spark_ffi::messages;

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .canonicalize()
        .unwrap()
}

fn write_or_check(name: &str, document: &Value) {
    let path = vectors_dir().join(name);
    if std::env::var_os("SPARK_WRITE_VECTORS").is_some() {
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&document).unwrap() + "\n",
        )
        .unwrap();
        return;
    }
    let stored: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    assert_eq!(
        &stored, document,
        "{name} differs; regenerate with SPARK_WRITE_VECTORS=1"
    );
}

fn header() -> Value {
    json!({
        "source": "spark-ffi prost encoding over frost-sign.json cases",
        "note": "Test vectors only. Never use these keys for funds.",
    })
}

fn unhex(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

fn frost_cases() -> Vec<Value> {
    let path = vectors_dir().join("frost-sign.json");
    let document: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    document["cases"].as_array().unwrap().clone()
}

fn commitment(bytes: &[u8]) -> messages::Commitment {
    assert_eq!(bytes.len(), 66);
    messages::Commitment {
        hiding: bytes[..33].to_vec(),
        binding: bytes[33..].to_vec(),
    }
}

fn sign_request(case: &Value) -> messages::FrostSignRequest {
    let user_commitment = unhex(&case["user_commitment"]);
    messages::FrostSignRequest {
        jobs: vec![messages::FrostSignJob {
            message: unhex(&case["message"]),
            secret_key: unhex(&case["secret_key"]),
            verifying_key: unhex(&case["verifying_key"]),
            nonce: unhex(&case["nonce"]),
            user_commitment: Some(commitment(&user_commitment)),
            operator_commitments: case["operators"]
                .as_array()
                .unwrap()
                .iter()
                .map(|op| {
                    let commitment = unhex(&op["commitment"]);
                    messages::OperatorCommitment {
                        identifier: unhex(&op["identifier"]),
                        commitment: Some(self::commitment(&commitment)),
                    }
                })
                .collect(),
            adaptor_public_key: case["adaptor_public_key"]
                .as_str()
                .map(|s| hex::decode(s).unwrap())
                .unwrap_or_default(),
        }],
    }
}

fn aggregate_request(case: &Value) -> messages::FrostAggregateRequest {
    let user_commitment = unhex(&case["user_commitment"]);
    messages::FrostAggregateRequest {
        jobs: vec![messages::FrostAggregateJob {
            message: unhex(&case["message"]),
            verifying_key: unhex(&case["verifying_key"]),
            user_commitment: Some(commitment(&user_commitment)),
            user_public_key: unhex(&case["user_public_key"]),
            user_signature_share: unhex(&case["signature_share"]),
            operators: case["operators"]
                .as_array()
                .unwrap()
                .iter()
                .map(|op| {
                    let commitment = unhex(&op["commitment"]);
                    messages::OperatorShare {
                        identifier: unhex(&op["identifier"]),
                        commitment: Some(self::commitment(&commitment)),
                        signature_share: unhex(&op["signature_share"]),
                        public_key: unhex(&op["public_key"]),
                    }
                })
                .collect(),
            adaptor_public_key: case["adaptor_public_key"]
                .as_str()
                .map(|s| hex::decode(s).unwrap())
                .unwrap_or_default(),
        }],
    }
}

struct Out {
    ptr: *mut u8,
    len: usize,
}

impl Out {
    const fn new() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }

    /// Exposes `ptr`/`len` as the `qs_*` out-params.
    const fn params(&mut self) -> (*mut *mut u8, *mut usize) {
        (&raw mut self.ptr, &raw mut self.len)
    }

    /// Takes the output bytes and releases the buffer through `qs_free`.
    fn take(self) -> Vec<u8> {
        if self.ptr.is_null() {
            return Vec::new();
        }
        // SAFETY: `ptr`/`len` were produced by a `qs_*` out-param write.
        let bytes = unsafe { core::slice::from_raw_parts(self.ptr, self.len) }.to_vec();
        // SAFETY: returning the exact `ptr`/`len` pair the library handed us.
        unsafe { abi::qs_free(self.ptr, self.len) };
        bytes
    }
}

fn call_sign(request: &[u8]) -> (i32, Vec<u8>) {
    let mut out = Out::new();
    let (out_ptr, out_len) = out.params();
    // SAFETY: `request` outlives the call; `out` params are valid locals.
    let code = unsafe { abi::qs_frost_sign(request.as_ptr(), request.len(), out_ptr, out_len) };
    (code, out.take())
}

fn call_aggregate(request: &[u8]) -> (i32, Vec<u8>) {
    let mut out = Out::new();
    let (out_ptr, out_len) = out.params();
    // SAFETY: `request` outlives the call; `out` params are valid locals.
    let code =
        unsafe { abi::qs_frost_aggregate(request.as_ptr(), request.len(), out_ptr, out_len) };
    (code, out.take())
}

fn call_commit(hedge: &[u8], random: &[u8]) -> (i32, Vec<u8>) {
    let mut out = Out::new();
    let (out_ptr, out_len) = out.params();
    // SAFETY: inputs outlive the call; `out` params are valid locals.
    let code = unsafe {
        abi::qs_frost_commit(
            hedge.as_ptr(),
            hedge.len(),
            random.as_ptr(),
            random.len(),
            out_ptr,
            out_len,
        )
    };
    (code, out.take())
}

fn call_encrypt(pk: &[u8], msg: &[u8], random: &[u8]) -> (i32, Vec<u8>) {
    let mut out = Out::new();
    let (out_ptr, out_len) = out.params();
    // SAFETY: inputs outlive the call; `out` params are valid locals.
    let code = unsafe {
        abi::qs_ecies_encrypt(
            pk.as_ptr(),
            pk.len(),
            msg.as_ptr(),
            msg.len(),
            random.as_ptr(),
            random.len(),
            out_ptr,
            out_len,
        )
    };
    (code, out.take())
}

fn call_decrypt(sk: &[u8], ct: &[u8]) -> (i32, Vec<u8>) {
    let mut out = Out::new();
    let (out_ptr, out_len) = out.params();
    // SAFETY: inputs outlive the call; `out` params are valid locals.
    let code = unsafe {
        abi::qs_ecies_decrypt(
            sk.as_ptr(),
            sk.len(),
            ct.as_ptr(),
            ct.len(),
            out_ptr,
            out_len,
        )
    };
    (code, out.take())
}

fn call_split(secret: &[u8], threshold: u32, shares: u32, random: &[u8]) -> (i32, Vec<u8>) {
    let mut out = Out::new();
    let (out_ptr, out_len) = out.params();
    // SAFETY: inputs outlive the call; `out` params are valid locals.
    let code = unsafe {
        abi::qs_split_secret_with_proofs(
            secret.as_ptr(),
            secret.len(),
            threshold,
            shares,
            random.as_ptr(),
            random.len(),
            out_ptr,
            out_len,
        )
    };
    (code, out.take())
}

// -- ffi-sign / ffi-aggregate -------------------------------------------------

#[test]
fn vectors_ffi_sign() {
    let mut cases = Vec::new();
    let frost = frost_cases();
    for case in &frost {
        let request = sign_request(case).encode_to_vec();
        let (code, response) = call_sign(&request);
        assert_eq!(code, 0);
        // The response share must equal the upstream-proved share.
        let decoded = messages::FrostSignResponse::decode(response.as_slice()).unwrap();
        assert_eq!(decoded.signature_shares.len(), 1);
        assert_eq!(decoded.signature_shares[0], unhex(&case["signature_share"]));
        cases.push(json!({
            "request": hex::encode(&request),
            "response": hex::encode(&response),
        }));
    }
    let document = json!({ "header": header(), "cases": cases });
    write_or_check("ffi-sign.json", &document);

    // Replay the stored vectors through the ABI.
    if std::env::var_os("SPARK_WRITE_VECTORS").is_some() {
        return;
    }
    for case in document["cases"].as_array().unwrap() {
        let request = unhex(&case["request"]);
        let (code, response) = call_sign(&request);
        assert_eq!(code, 0);
        assert_eq!(response, unhex(&case["response"]));
    }
}

#[test]
fn vectors_ffi_aggregate() {
    let mut cases = Vec::new();
    let frost = frost_cases();
    for case in &frost {
        let request = aggregate_request(case).encode_to_vec();
        let (code, response) = call_aggregate(&request);
        assert_eq!(code, 0);
        let decoded = messages::FrostAggregateResponse::decode(response.as_slice()).unwrap();
        assert_eq!(decoded.signatures.len(), 1);
        assert_eq!(decoded.signatures[0], unhex(&case["signature"]));
        cases.push(json!({
            "request": hex::encode(&request),
            "response": hex::encode(&response),
        }));
    }
    let document = json!({ "header": header(), "cases": cases });
    write_or_check("ffi-aggregate.json", &document);

    if std::env::var_os("SPARK_WRITE_VECTORS").is_some() {
        return;
    }
    for case in document["cases"].as_array().unwrap() {
        let request = unhex(&case["request"]);
        let (code, response) = call_aggregate(&request);
        assert_eq!(code, 0);
        assert_eq!(response, unhex(&case["response"]));
    }
}

// -- ffi-errors ---------------------------------------------------------------

/// One generated error case; the expected code is recorded into the vector,
/// so a code of 0 here means the case no longer exercises an error path.
fn error_case(function: &str, mut inputs: Value, code: i32) -> Value {
    assert_ne!(code, 0, "{function} unexpectedly accepted the input");
    inputs["function"] = json!(function);
    inputs["code"] = json!(code);
    inputs
}

/// The 33-byte invalid compressed point used across error cases
/// (`0x02` prefix over an out-of-range x coordinate).
fn invalid_point() -> Vec<u8> {
    let mut point = vec![0x02];
    point.extend_from_slice(&[0xFF; 32]);
    point
}

fn edited_sign_request(
    base: &messages::FrostSignRequest,
    edit: impl FnOnce(&mut messages::FrostSignJob),
) -> Vec<u8> {
    let mut request = base.clone();
    if let Some(job) = request.jobs.first_mut() {
        edit(job);
    }
    request.encode_to_vec()
}

fn edited_aggregate_request(
    base: &messages::FrostAggregateRequest,
    edit: impl FnOnce(&mut messages::FrostAggregateJob),
) -> Vec<u8> {
    let mut request = base.clone();
    if let Some(job) = request.jobs.first_mut() {
        edit(job);
    }
    request.encode_to_vec()
}

fn error_cases() -> Vec<Value> {
    let frost = frost_cases();
    let case = &frost[0];
    let sign = sign_request(case);
    let aggregate = aggregate_request(case);
    let mut cases = Vec::new();

    // qs_frost_commit
    let hedge = unhex(&case["secret_key"]);
    let random = [7u8; 32];
    cases.push(error_case(
        "frost_commit",
        json!({ "hedge": hex::encode(&hedge[..31]), "random": hex::encode(random) }),
        call_commit(&hedge[..31], &random).0,
    ));
    cases.push(error_case(
        "frost_commit",
        json!({ "hedge": hex::encode(&hedge), "random": hex::encode([9u8; 33]) }),
        call_commit(&hedge, &[9u8; 33]).0,
    ));
    cases.push(error_case(
        "frost_commit",
        json!({ "hedge": hex::encode(&hedge), "random": "" }),
        call_commit(&hedge, &[]).0,
    ));
    cases.push(error_case(
        "frost_commit",
        json!({ "hedge": hex::encode(&hedge), "random": hex::encode(vec![3u8; 8224]) }),
        call_commit(&hedge, &[3u8; 8224]).0,
    ));

    // qs_frost_sign
    cases.push(error_case(
        "frost_sign",
        json!({ "request": "deadbeef" }),
        call_sign(&[0xde, 0xad, 0xbe, 0xef]).0,
    ));
    cases.push(error_case(
        "frost_sign",
        json!({ "request": "" }),
        call_sign(&[]).0,
    ));
    // The job-count check runs before per-job validation, so minimal jobs
    // keep the vector small.
    let many = messages::FrostSignRequest {
        jobs: vec![messages::FrostSignJob::default(); 257],
    }
    .encode_to_vec();
    cases.push(error_case(
        "frost_sign",
        json!({ "request": hex::encode(&many) }),
        call_sign(&many).0,
    ));
    for (name, request) in [
        (
            "short secret_key",
            edited_sign_request(&sign, |job| job.secret_key.truncate(31)),
        ),
        (
            "invalid secret_key scalar",
            edited_sign_request(&sign, |job| job.secret_key = vec![0xFF; 32]),
        ),
        (
            "invalid verifying_key point",
            edited_sign_request(&sign, |job| job.verifying_key = invalid_point()),
        ),
        (
            "missing user_commitment",
            edited_sign_request(&sign, |job| job.user_commitment = None),
        ),
        (
            "short nonce",
            edited_sign_request(&sign, |job| job.nonce.truncate(63)),
        ),
        (
            "invalid nonce scalar",
            edited_sign_request(&sign, |job| job.nonce[..32].fill(0xFF)),
        ),
        (
            "invalid binding commitment point",
            edited_sign_request(&sign, |job| {
                if let Some(commitment) = job.user_commitment.as_mut() {
                    commitment.binding = invalid_point();
                }
            }),
        ),
    ] {
        let _ = name;
        cases.push(error_case(
            "frost_sign",
            json!({ "request": hex::encode(&request) }),
            call_sign(&request).0,
        ));
    }

    // qs_frost_aggregate
    cases.push(error_case(
        "frost_aggregate",
        json!({ "request": "deadbeef" }),
        call_aggregate(&[0xde, 0xad, 0xbe, 0xef]).0,
    ));
    cases.push(error_case(
        "frost_aggregate",
        json!({ "request": "" }),
        call_aggregate(&[]).0,
    ));
    for request in [
        edited_aggregate_request(&aggregate, |job| job.user_signature_share.truncate(31)),
        edited_aggregate_request(&aggregate, |job| job.user_signature_share = vec![0xFF; 32]),
        edited_aggregate_request(&aggregate, |job| job.user_public_key = invalid_point()),
        edited_aggregate_request(&aggregate, |job| {
            job.operators[1] = job.operators[0].clone();
        }),
        edited_aggregate_request(&aggregate, |job| {
            // Identifier::derive(b"user").serialize() — the single-user FROST id.
            job.operators[0].identifier =
                hex::decode("687da64d52a16c6fc792c6fc831ec1afa797a91f77549668a6b5421f12c1ac77")
                    .unwrap();
        }),
        edited_aggregate_request(&aggregate, |job| {
            job.operators[0].signature_share = vec![0xFF; 32];
        }),
        edited_aggregate_request(&aggregate, |job| {
            job.operators[0].public_key = invalid_point();
        }),
        edited_aggregate_request(&aggregate, |job| {
            if let Some(commitment) = job.user_commitment.as_mut() {
                commitment.binding = invalid_point();
            }
        }),
        edited_aggregate_request(&aggregate, |job| job.verifying_key = invalid_point()),
        edited_aggregate_request(&aggregate, |job| job.adaptor_public_key = invalid_point()),
    ] {
        cases.push(error_case(
            "frost_aggregate",
            json!({ "request": hex::encode(&request) }),
            call_aggregate(&request).0,
        ));
    }

    // qs_ecies_encrypt / qs_ecies_decrypt
    let ecies_doc: Value =
        serde_json::from_str(&std::fs::read_to_string(vectors_dir().join("ecies.json")).unwrap())
            .unwrap();
    let ecies = &ecies_doc["cases"][0];
    let pk = unhex(&ecies["public_key"]);
    let sk = unhex(&ecies["secret_key"]);
    let plaintext = unhex(&ecies["plaintext"]);
    let ct = unhex(&ecies["ciphertext"]);
    let enc_random = unhex(&ecies["random"]);
    cases.push(error_case(
        "ecies_encrypt",
        json!({
            "public_key": hex::encode(&pk[..32]),
            "plaintext": hex::encode(&plaintext),
            "random": hex::encode(&enc_random),
        }),
        call_encrypt(&pk[..32], &plaintext, &enc_random).0,
    ));
    cases.push(error_case(
        "ecies_encrypt",
        json!({
            "public_key": hex::encode(invalid_point()),
            "plaintext": hex::encode(&plaintext),
            "random": hex::encode(&enc_random),
        }),
        call_encrypt(&invalid_point(), &plaintext, &enc_random).0,
    ));
    cases.push(error_case(
        "ecies_encrypt",
        json!({
            "public_key": hex::encode(&pk),
            "plaintext": hex::encode(&plaintext),
            "random": hex::encode(&enc_random[..31]),
        }),
        call_encrypt(&pk, &plaintext, &enc_random[..31]).0,
    ));
    cases.push(error_case(
        "ecies_decrypt",
        json!({ "secret_key": hex::encode(&sk[..31]), "ciphertext": hex::encode(&ct) }),
        call_decrypt(&sk[..31], &ct).0,
    ));
    cases.push(error_case(
        "ecies_decrypt",
        json!({ "secret_key": hex::encode(vec![0xFF; 32]), "ciphertext": hex::encode(&ct) }),
        call_decrypt(&[0xFF; 32], &ct).0,
    ));
    cases.push(error_case(
        "ecies_decrypt",
        json!({ "secret_key": hex::encode(&sk), "ciphertext": hex::encode(&ct[..40]) }),
        call_decrypt(&sk, &ct[..40]).0,
    ));
    let mut corrupted = ct;
    let last = corrupted.len() - 1;
    corrupted[last] ^= 0xFF;
    cases.push(error_case(
        "ecies_decrypt",
        json!({ "secret_key": hex::encode(&sk), "ciphertext": hex::encode(&corrupted) }),
        call_decrypt(&sk, &corrupted).0,
    ));

    // qs_split_secret_with_proofs
    let secret = unhex(&case["secret_key"]);
    let split_random = [5u8; 32];
    cases.push(error_case(
        "split_secret_with_proofs",
        json!({
            "secret": hex::encode(&secret[..31]),
            "threshold": 2,
            "shares": 3,
            "random": hex::encode(split_random),
        }),
        call_split(&secret[..31], 2, 3, &split_random).0,
    ));
    cases.push(error_case(
        "split_secret_with_proofs",
        json!({
            "secret": hex::encode(&secret),
            "threshold": 1,
            "shares": 3,
            "random": hex::encode(split_random),
        }),
        call_split(&secret, 1, 3, &split_random).0,
    ));
    cases.push(error_case(
        "split_secret_with_proofs",
        json!({
            "secret": hex::encode(&secret),
            "threshold": 3,
            "shares": 2,
            "random": hex::encode(split_random),
        }),
        call_split(&secret, 3, 2, &split_random).0,
    ));
    cases.push(error_case(
        "split_secret_with_proofs",
        json!({
            "secret": hex::encode(&secret),
            "threshold": 2,
            "shares": 3,
            "random": hex::encode(&split_random[..31]),
        }),
        call_split(&secret, 2, 3, &split_random[..31]).0,
    ));

    cases
}

#[test]
fn vectors_ffi_errors() {
    let document = json!({ "header": header(), "cases": error_cases() });
    write_or_check("ffi-errors.json", &document);

    if std::env::var_os("SPARK_WRITE_VECTORS").is_some() {
        return;
    }
    for case in document["cases"].as_array().unwrap() {
        let expected = i32::try_from(case["code"].as_i64().unwrap()).unwrap();
        let code = match case["function"].as_str().unwrap() {
            "frost_commit" => call_commit(&unhex(&case["hedge"]), &unhex(&case["random"])).0,
            "frost_sign" => call_sign(&unhex(&case["request"])).0,
            "frost_aggregate" => call_aggregate(&unhex(&case["request"])).0,
            "ecies_encrypt" => {
                call_encrypt(
                    &unhex(&case["public_key"]),
                    &unhex(&case["plaintext"]),
                    &unhex(&case["random"]),
                )
                .0
            }
            "ecies_decrypt" => {
                call_decrypt(&unhex(&case["secret_key"]), &unhex(&case["ciphertext"])).0
            }
            "split_secret_with_proofs" => {
                call_split(
                    &unhex(&case["secret"]),
                    u32::try_from(case["threshold"].as_u64().unwrap()).unwrap(),
                    u32::try_from(case["shares"].as_u64().unwrap()).unwrap(),
                    &unhex(&case["random"]),
                )
                .0
            }
            other => unreachable!("unknown function {other}"),
        };
        assert_eq!(code, expected, "{}", case["function"]);
    }
}

// -- allocation contract --------------------------------------------------------

#[test]
fn allocation_contract() {
    // qs_alloc(0) is NULL; qs_free(NULL, 0) is a no-op.
    assert!(abi::qs_alloc(0).is_null());
    // SAFETY: NULL/0 is the documented no-op.
    unsafe { abi::qs_free(ptr::null_mut(), 0) };

    let buf = abi::qs_alloc(64);
    assert!(!buf.is_null());
    // SAFETY: `buf` is a live 64-byte allocation from qs_alloc.
    unsafe { ptr::write_bytes(buf, 0xAB, 64) };
    // SAFETY: exact (ptr, len) pair from qs_alloc.
    unsafe { abi::qs_free(buf, 64) };

    // Null out-params are a length error even on an otherwise valid call.
    let hedge = [1u8; 32];
    let random = [2u8; 32];
    // SAFETY: inputs outlive the call; passing null out-params exercises the
    // documented error path.
    let code = unsafe {
        abi::qs_frost_commit(
            hedge.as_ptr(),
            hedge.len(),
            random.as_ptr(),
            random.len(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    assert_eq!(code, 1);

    // qs_abi_version matches the crate constant.
    assert_eq!(abi::qs_abi_version(), spark_ffi::ABI_VERSION);
}
