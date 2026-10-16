//! Seeded random differential against upstream `spark-frost`.
//!
//! `PARITY_SEED` (default 1) selects the `ChaCha20` stream that generates
//! keys, messages and signer sets; `PARITY_CASES` (default 200) the number
//! of rounds. Ignored by default — `bun run test:parity` runs it, and CI can
//! run any seed via `cargo test --release -- --ignored differential`.

#![allow(
    unused_crate_dependencies,
    clippy::tests_outside_test_module,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    reason = "test code"
)]

mod common;

use common::*;
use frost::SigningKey;
use frost::VerifyingKey;
use frost_secp256k1_tr as frost;
use rand_core::{RngCore, SeedableRng};

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn random_bytes(rng: &mut rand_chacha::ChaCha20Rng, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    rng.fill_bytes(&mut out);
    out
}

#[test]
#[ignore = "seeded differential; run via `bun run test:parity`"]
fn differential() {
    let seed = env_u64("PARITY_SEED", 1);
    let cases = env_u64("PARITY_CASES", 200);
    eprintln!("differential: PARITY_SEED={seed} PARITY_CASES={cases}");

    let seed_bytes = {
        let mut b = [0u8; 32];
        b[..8].copy_from_slice(&seed.to_le_bytes());
        b
    };
    let mut rand = rand_chacha::ChaCha20Rng::from_seed(seed_bytes);

    for case in 0..cases {
        // FROST: random operator sets of {1,2}, {2,3}, {1,2,3}.
        let signers: &[u16] = match case % 3 {
            0 => &[1, 2],
            1 => &[2, 3],
            _ => &[1, 2, 3],
        };
        let setup = setup(&mut rand, 3, 2, &[1, 2, 3]);
        let message = random_bytes(&mut rand, 32);
        let adaptor = (case % 2 == 1).then(|| {
            VerifyingKey::from(&SigningKey::new(&mut rand))
                .serialize()
                .unwrap()
        });
        let (round, user_round1) =
            build_round(&setup, signers, &message, adaptor, (case & 0xFF) as u8);
        let outcome = run_both(&round, &setup, &user_round1);
        assert_eq!(
            outcome.our_signature.as_slice(),
            outcome.upstream_signature.as_slice(),
            "case {case}: signature mismatch"
        );

        // ECIES: cross-decrypt in both directions.
        let sk = SigningKey::new(&mut rand);
        let sk_bytes: [u8; 32] = sk.serialize().try_into().unwrap();
        let vk = VerifyingKey::from(&sk).serialize().unwrap();
        let plaintext = random_bytes(&mut rand, 1 + usize::try_from(case % 64).unwrap());
        let mut random = [0u8; 32];
        rand.fill_bytes(&mut random);
        let ours_ct = spark_crypto::ecies::encrypt(&vk, &plaintext, &random).unwrap();
        assert_eq!(
            spark_frost::bridge::decrypt_ecies(ours_ct, sk_bytes.to_vec()).unwrap(),
            plaintext,
            "case {case}: upstream failed to decrypt our ciphertext"
        );
        let theirs_ct = spark_frost::bridge::encrypt_ecies(&plaintext, &vk).unwrap();
        assert_eq!(
            spark_crypto::ecies::decrypt(&sk_bytes, &theirs_ct).unwrap(),
            plaintext,
            "case {case}: we failed to decrypt upstream ciphertext"
        );

        // VSS: validate + recover through upstream.
        let mut secret = [0u8; 32];
        rand.fill_bytes(&mut secret);
        secret[0] &= 0x0F; // keep the scalar below the group order
        let split = spark_crypto::vss::split_secret_with_proofs(&secret, 2, 3, &random).unwrap();
        let proofs: Vec<Vec<u8>> = split.proofs().iter().map(Vec::from).collect();
        let shares: Vec<spark_frost::vss::SecretShare> = split
            .shares()
            .iter()
            .enumerate()
            .map(|(i, s)| spark_frost::vss::SecretShare {
                threshold: 2,
                index: u32::try_from(i + 1).unwrap(),
                share: s.to_vec(),
            })
            .collect();
        for share in &shares {
            spark_frost::vss::validate_share(&share.share, share.index, 2, &proofs).unwrap();
        }
        assert_eq!(
            spark_frost::vss::recover_secret(&shares[..2]).unwrap(),
            secret,
            "case {case}: upstream failed to recover our shares"
        );
    }
}
