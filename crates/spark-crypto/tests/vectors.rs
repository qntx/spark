//! Replay the repository-root `vectors/` files through `spark-crypto`.
//!
//! The same files are produced and cross-checked against the upstream
//! `spark-frost` crate by `crates/interop`; this suite verifies them without
//! any upstream dependency so the root workspace can run on every platform.

#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    clippy::panic,
    reason = "test code"
)]

use std::path::{Path, PathBuf};

use serde_json::Value;

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .canonicalize()
        .unwrap()
}

fn load(name: &str) -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(vectors_dir().join(name))
            .unwrap_or_else(|e| panic!("{name}: {e}")),
    )
    .unwrap()
}

fn unhex(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap()).unwrap()
}

#[test]
fn frost_commit_vectors() {
    for case in load("frost-commit.json")["cases"].as_array().unwrap() {
        let hedge: [u8; 32] = unhex(&case["hedge"]).try_into().unwrap();
        let random: [u8; 32] = unhex(&case["random"]).try_into().unwrap();
        let commitment = spark_crypto::frost::commit(&hedge, &random).unwrap();
        assert_eq!(
            commitment.nonces().as_slice(),
            unhex(&case["nonces"]).as_slice()
        );
        assert_eq!(
            commitment.commitments().as_slice(),
            unhex(&case["commitments"]).as_slice()
        );
    }
}

#[test]
fn frost_sign_and_aggregate_vectors() {
    for case in load("frost-sign.json")["cases"].as_array().unwrap() {
        let message = unhex(&case["message"]);
        let secret_key: [u8; 32] = unhex(&case["secret_key"]).try_into().unwrap();
        let verifying_key: [u8; 33] = unhex(&case["verifying_key"]).try_into().unwrap();
        let nonce: [u8; 64] = unhex(&case["nonce"]).try_into().unwrap();
        let user_commitment: [u8; 66] = unhex(&case["user_commitment"]).try_into().unwrap();
        let user_public_key: [u8; 33] = unhex(&case["user_public_key"]).try_into().unwrap();
        let adaptor: Option<[u8; 33]> = case["adaptor_public_key"]
            .as_str()
            .map(|s| hex::decode(s).unwrap().try_into().unwrap());

        let operators: Vec<spark_crypto::frost::OperatorCommitment> = case["operators"]
            .as_array()
            .unwrap()
            .iter()
            .map(|op| spark_crypto::frost::OperatorCommitment {
                identifier: unhex(&op["identifier"]).try_into().unwrap(),
                commitment: unhex(&op["commitment"]).try_into().unwrap(),
            })
            .collect();

        let share = spark_crypto::frost::sign(&spark_crypto::frost::SignJob {
            message: &message,
            secret_key: &secret_key,
            verifying_key: &verifying_key,
            nonce: &nonce,
            user_commitment: &user_commitment,
            operators: &operators,
            adaptor_public_key: adaptor.as_ref(),
        })
        .unwrap();
        assert_eq!(
            share.as_slice(),
            unhex(&case["signature_share"]).as_slice(),
            "signature share mismatch in {case}"
        );

        let operator_shares: Vec<spark_crypto::frost::OperatorShare> = case["operators"]
            .as_array()
            .unwrap()
            .iter()
            .map(|op| spark_crypto::frost::OperatorShare {
                identifier: unhex(&op["identifier"]).try_into().unwrap(),
                commitment: unhex(&op["commitment"]).try_into().unwrap(),
                signature_share: unhex(&op["signature_share"]).try_into().unwrap(),
                public_key: unhex(&op["public_key"]).try_into().unwrap(),
            })
            .collect();

        let signature = spark_crypto::frost::aggregate(&spark_crypto::frost::AggregateJob {
            message: &message,
            verifying_key: &verifying_key,
            user_commitment: &user_commitment,
            user_public_key: &user_public_key,
            user_signature_share: &share,
            operators: &operator_shares,
            adaptor_public_key: adaptor.as_ref(),
        })
        .unwrap();
        assert_eq!(
            signature.as_slice(),
            unhex(&case["signature"]).as_slice(),
            "aggregated signature mismatch in {case}"
        );
    }
}

#[test]
fn ecies_vectors() {
    for case in load("ecies.json")["cases"].as_array().unwrap() {
        let secret_key: [u8; 32] = unhex(&case["secret_key"]).try_into().unwrap();
        let ciphertext = spark_crypto::ecies::encrypt(
            &unhex(&case["public_key"]),
            &unhex(&case["plaintext"]),
            &unhex(&case["random"]).try_into().unwrap(),
        )
        .unwrap();
        assert_eq!(ciphertext, unhex(&case["ciphertext"]));
        assert_eq!(
            spark_crypto::ecies::decrypt(&secret_key, &ciphertext).unwrap(),
            unhex(&case["plaintext"])
        );
    }
}

#[test]
fn vss_vectors() {
    for case in load("vss.json")["cases"].as_array().unwrap() {
        let secret: [u8; 32] = unhex(&case["secret"]).try_into().unwrap();
        let split = spark_crypto::vss::split_secret_with_proofs(
            &secret,
            case["threshold"].as_u64().unwrap().try_into().unwrap(),
            case["share_count"].as_u64().unwrap().try_into().unwrap(),
            &unhex(&case["random"]).try_into().unwrap(),
        )
        .unwrap();
        let proofs: Vec<Vec<u8>> = split.proofs().iter().map(Vec::from).collect();
        assert_eq!(proofs.len(), case["proofs"].as_array().unwrap().len());
        for (proof, expected) in proofs.iter().zip(case["proofs"].as_array().unwrap()) {
            assert_eq!(proof.as_slice(), unhex(expected).as_slice());
        }
        for (share, expected) in split
            .shares()
            .iter()
            .zip(case["shares"].as_array().unwrap())
        {
            assert_eq!(share.as_slice(), unhex(expected).as_slice());
        }
    }
}
