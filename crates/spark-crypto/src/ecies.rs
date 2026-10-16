//! ECIES over secp256k1, byte-compatible with the `ecies` crate (0.2.x)
//! default configuration used by upstream `spark-frost` (`bridge.rs`,
//! commit 0b3a32a05c9ac06cc411683551dd1f1bde9d0caa).
//!
//! Wire format: `ephemeral_pk(65, uncompressed) ‖ nonce(16) ‖ tag(16) ‖
//! ciphertext`. The symmetric key is HKDF-SHA256 over
//! `ephemeral_pk(65)‖shared_point(65)` (empty salt and info, 32-byte output)
//! and encryption is AES-256-GCM (`AesGcm<Aes256, U16>`, empty AAD).
//!
//! Unlike upstream, which draws the ephemeral key and the nonce from the OS
//! RNG, both are derived from the caller-supplied 32-byte `random` seed via
//! `ChaCha20` — the ephemeral scalar first, then the nonce.

use aes_gcm::aead::AeadInPlace;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::{AesGcm, KeyInit};
use hkdf::Hkdf;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::Error;

/// AES-256-GCM with the 16-byte nonce the `ecies` crate uses by default.
type Cipher = AesGcm<aes_gcm::aes::Aes256, aes_gcm::aead::generic_array::typenum::U16>;

const UNCOMPRESSED_PK_SIZE: usize = 65;
const NONCE_LENGTH: usize = 16;
const TAG_LENGTH: usize = 16;

fn shared_key(
    ephemeral_pk: &PublicKey,
    shared_point: &PublicKey,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let ephemeral = ephemeral_pk.to_encoded_point(false);
    let shared = shared_point.to_encoded_point(false);
    let mut master = Zeroizing::new([0u8; 130]);
    let (first, second) = master.split_at_mut(65);
    first.copy_from_slice(ephemeral.as_bytes());
    second.copy_from_slice(shared.as_bytes());
    let hkdf = Hkdf::<Sha256>::new(None, master.as_slice());
    let mut key = Zeroizing::new([0u8; 32]);
    hkdf.expand(&[], key.as_mut_slice())
        .map_err(|_| Error::Internal)?;
    Ok(key)
}

/// Encrypt `plaintext` for `public_key` (33 or 65-byte SEC1 encoding).
///
/// # Errors
/// [`Error::Length`] if `public_key` is not 33 or 65 bytes,
/// [`Error::InvalidPoint`] if it is not a valid curve point,
/// [`Error::Internal`] if encryption fails.
pub fn encrypt(public_key: &[u8], plaintext: &[u8], random: &[u8; 32]) -> Result<Vec<u8>, Error> {
    if public_key.len() != 33 && public_key.len() != UNCOMPRESSED_PK_SIZE {
        return Err(Error::Length);
    }
    let receiver_pk = PublicKey::from_sec1_bytes(public_key).map_err(|_| Error::InvalidPoint)?;

    let mut rng = ChaCha20Rng::from_seed(*random);
    // k256 SecretKey already zeroizes on drop.
    let ephemeral_sk = SecretKey::random(&mut rng);
    let ephemeral_pk = ephemeral_sk.public_key();
    let mut nonce = [0u8; NONCE_LENGTH];
    rng.fill_bytes(&mut nonce);

    // shared_point = receiver_pk * ephemeral_sk
    let shared_point = PublicKey::from_affine(
        (*receiver_pk.as_affine() * *ephemeral_sk.to_nonzero_scalar().as_ref()).to_affine(),
    )
    .map_err(|_| Error::Internal)?;
    let key = shared_key(&ephemeral_pk, &shared_point)?;

    let cipher = Cipher::new_from_slice(key.as_slice()).map_err(|_| Error::Internal)?;
    let mut body = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(GenericArray::from_slice(&nonce), &[], &mut body)
        .map_err(|_| Error::Internal)?;

    let mut output = Vec::with_capacity(UNCOMPRESSED_PK_SIZE + NONCE_TAG_LENGTH + body.len());
    output.extend_from_slice(ephemeral_pk.to_encoded_point(false).as_bytes());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(tag.as_slice());
    output.extend_from_slice(&body);
    Ok(output)
}

const NONCE_TAG_LENGTH: usize = NONCE_LENGTH + TAG_LENGTH;

/// Decrypt a ciphertext produced by [`encrypt`] (or upstream `ecies`).
///
/// # Errors
/// [`Error::InvalidScalar`] if `secret_key` is not a valid scalar,
/// [`Error::Length`] if `ciphertext` is too short to contain the ephemeral
/// key, nonce and tag, [`Error::InvalidPoint`] if the ephemeral key is not a
/// valid curve point, [`Error::Decrypt`] if authentication fails.
pub fn decrypt(secret_key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    let receiver_sk = SecretKey::from_slice(secret_key).map_err(|_| Error::InvalidScalar)?;
    if ciphertext.len() < UNCOMPRESSED_PK_SIZE + NONCE_TAG_LENGTH {
        return Err(Error::Length);
    }
    let (ephemeral_bytes, encrypted) = ciphertext.split_at(UNCOMPRESSED_PK_SIZE);
    let ephemeral_pk =
        PublicKey::from_sec1_bytes(ephemeral_bytes).map_err(|_| Error::InvalidPoint)?;

    // shared_point = ephemeral_pk * receiver_sk
    let shared_point = PublicKey::from_affine(
        (*ephemeral_pk.as_affine() * *receiver_sk.to_nonzero_scalar().as_ref()).to_affine(),
    )
    .map_err(|_| Error::Internal)?;
    let key = shared_key(&ephemeral_pk, &shared_point)?;

    let cipher = Cipher::new_from_slice(key.as_slice()).map_err(|_| Error::Internal)?;
    let (nonce, rest) = encrypted.split_at(NONCE_LENGTH);
    let (tag, body) = rest.split_at(TAG_LENGTH);
    let nonce = GenericArray::from_slice(nonce);
    let tag = GenericArray::from_slice(tag);
    let mut output = body.to_vec();
    cipher
        .decrypt_in_place_detached(nonce, &[], &mut output, tag)
        .map_err(|_| Error::Decrypt)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    fn keypair() -> ([u8; 32], [u8; 65]) {
        let sk = SecretKey::random(&mut ChaCha20Rng::from_seed([1u8; 32]));
        (sk.to_bytes().into(), {
            let ep = sk.public_key().to_encoded_point(false);
            let mut out = [0u8; 65];
            out.copy_from_slice(ep.as_bytes());
            out
        })
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (sk, pk) = keypair();
        let plaintext = b"spark secret";
        let ciphertext = encrypt(&pk, plaintext, &[2u8; 32]).unwrap();
        assert_eq!(
            ciphertext.len(),
            UNCOMPRESSED_PK_SIZE + NONCE_TAG_LENGTH + plaintext.len()
        );
        assert_eq!(decrypt(&sk, &ciphertext).unwrap(), plaintext);
    }

    #[test]
    fn compressed_receiver_key_and_determinism() {
        let (sk, _) = keypair();
        let sk_obj = SecretKey::from_slice(&sk).unwrap();
        let compressed = sk_obj.public_key().to_encoded_point(true);
        let a = encrypt(compressed.as_bytes(), b"m", &[3u8; 32]).unwrap();
        let b = encrypt(compressed.as_bytes(), b"m", &[3u8; 32]).unwrap();
        assert_eq!(a, b, "same seed must produce the same ciphertext");
        assert_eq!(decrypt(&sk, &a).unwrap(), b"m");
    }

    #[test]
    fn rejects_bad_inputs() {
        let (sk, pk) = keypair();
        assert_eq!(
            encrypt(&pk.first_chunk::<32>().copied().unwrap(), b"m", &[0u8; 32]).unwrap_err(),
            Error::Length
        );

        let mut bad_pk = pk;
        bad_pk[0] = 0x02;
        assert_eq!(
            encrypt(&bad_pk, b"m", &[0u8; 32]).unwrap_err(),
            Error::InvalidPoint
        );

        assert_eq!(decrypt(&[0u8; 32], &[]).unwrap_err(), Error::InvalidScalar);
        assert_eq!(decrypt(&sk, &[0u8; 40]).unwrap_err(), Error::Length);

        let mut ciphertext = encrypt(&pk, b"m", &[4u8; 32]).unwrap();
        let last = ciphertext.len() - 1;
        let byte = ciphertext.get_mut(last).unwrap();
        *byte ^= 1;
        assert_eq!(decrypt(&sk, &ciphertext).unwrap_err(), Error::Decrypt);
    }
}
