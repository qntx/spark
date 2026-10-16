//! Feldman verifiable secret sharing over secp256k1.
//!
//! Ported from `buildonspark/spark` `signer/spark-frost/src/vss.rs`
//! (commit 0b3a32a05c9ac06cc411683551dd1f1bde9d0caa):
//! `split_secret_with_proofs` and its private helpers (`scalar_from_bytes`,
//! `scalar_to_bytes`, `point_to_compressed`, `scalar_to_index`,
//! `verifier_set_to_proofs`).
//!
//! Modifications from upstream: `OsRng` is replaced by a `ChaCha20` stream
//! seeded from the caller-supplied `random`, `shares > 255` is rejected
//! explicitly, `String` errors are mapped to [`Error`], and the share bytes
//! are zeroized on drop.

use std::fmt;

use k256::elliptic_curve::{PrimeField, sec1::ToEncodedPoint};
use k256::{ProjectivePoint, Scalar};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use vsss_rs::{FeldmanVerifierSet, IdentifierPrimeField, Share, ValueGroup, feldman};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;

type VsssShare = (IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>);
type VsssVerifier = ValueGroup<ProjectivePoint>;

fn scalar_from_bytes(bytes: &[u8; 32]) -> Result<Scalar, Error> {
    Option::from(Scalar::from_repr(k256::FieldBytes::from(*bytes))).ok_or(Error::InvalidScalar)
}

fn scalar_to_bytes(scalar: &Scalar) -> [u8; 32] {
    scalar.to_bytes().into()
}

fn point_to_compressed(point: &ProjectivePoint) -> Result<[u8; 33], Error> {
    point
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| Error::Internal)
}

/// Extract proofs (coefficient commitments) from the vsss-rs verifier set.
/// vsss-rs layout is `[generator, v0, v1, …]`; our proofs drop the
/// generator: `[v0, v1, …]`.
fn verifier_set_to_proofs(verifier_set: &Vec<VsssVerifier>) -> Result<Vec<[u8; 33]>, Error> {
    <Vec<VsssVerifier> as FeldmanVerifierSet<VsssShare, VsssVerifier>>::verifiers(verifier_set)
        .iter()
        .map(|v| point_to_compressed(&v.0))
        .collect()
}

/// Output of [`split_secret_with_proofs`].
///
/// `shares` are secret material: zeroized on drop and redacted in `Debug`.
/// `shares[i]` is the Shamir share evaluated at index `i + 1`.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Split {
    proofs: Vec<[u8; 33]>,
    shares: Vec<[u8; 32]>,
}

impl fmt::Debug for Split {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Split")
            .field("proofs", &self.proofs)
            .field("shares", &"[REDACTED]")
            .finish()
    }
}

impl Split {
    /// `t` compressed Feldman commitment points (coefficient commitments).
    #[must_use]
    pub fn proofs(&self) -> &[[u8; 33]] {
        &self.proofs
    }

    /// `n` share scalars; `shares[i]` corresponds to index `i + 1`.
    #[must_use]
    pub fn shares(&self) -> &[[u8; 32]] {
        &self.shares
    }

    /// `t×33 ‖ n×32` — the `splitSecretWithProofs` output layout.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.proofs.len() * 33 + self.shares.len() * 32);
        for proof in &self.proofs {
            out.extend_from_slice(proof);
        }
        for share in &self.shares {
            out.extend_from_slice(share);
        }
        out
    }
}

/// Split `secret` into `shares` verifiable shares with `threshold` Feldman
/// commitments.
///
/// # Errors
/// [`Error::OutOfRange`] if `threshold < 2`, `shares < threshold` or
/// `shares > 255`; [`Error::InvalidScalar`] if `secret` is not a valid
/// scalar; [`Error::Internal`] if the vsss-rs split fails.
pub fn split_secret_with_proofs(
    secret: &[u8; 32],
    threshold: usize,
    shares: usize,
    random: &[u8; 32],
) -> Result<Split, Error> {
    if threshold < 2 || shares < threshold || shares > u8::MAX as usize {
        return Err(Error::OutOfRange);
    }

    let mut secret_scalar = scalar_from_bytes(secret)?;
    let mut rng = ChaCha20Rng::from_seed(*random);

    // k256 Scalar does not zeroize on drop; the split copies it into the
    // polynomial, after which this binding is the only remaining plaintext.
    let split = feldman::split_secret(
        threshold,
        shares,
        &IdentifierPrimeField(secret_scalar),
        None,
        &mut rng,
    )
    .map_err(|_| Error::Internal);
    secret_scalar.zeroize();
    let (vsss_shares, verifier_set): (Vec<VsssShare>, Vec<VsssVerifier>) = split?;

    let proofs = verifier_set_to_proofs(&verifier_set)?;
    let share_bytes = vsss_shares
        .iter()
        .map(|share| scalar_to_bytes(&share.value().0))
        .collect();

    Ok(Split {
        proofs,
        shares: share_bytes,
    })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::excessive_nesting,
        reason = "test code"
    )]

    use super::*;

    fn secret() -> [u8; 32] {
        let mut s = [0u8; 32];
        s[31] = 42;
        s
    }

    /// Lagrange-interpolate the secret (evaluation at zero) from `indexes`
    /// selecting entries of `shares`; indexes are 1-based Shamir points.
    fn recombine(shares: &[[u8; 32]], indexes: &[u32]) -> [u8; 32] {
        let mut acc = Scalar::ZERO;
        for &i in indexes {
            let xi = Scalar::from(u64::from(i));
            let mut num = Scalar::ONE;
            let mut den = Scalar::ONE;
            for &j in indexes {
                if i == j {
                    continue;
                }
                let xj = Scalar::from(u64::from(j));
                num *= xj;
                den *= xj - xi;
            }
            let lagrange = num * den.invert().unwrap();
            acc += lagrange * scalar_from_bytes(&shares[(i - 1) as usize]).unwrap();
        }
        scalar_to_bytes(&acc)
    }

    #[test]
    fn split_recombines_for_any_threshold_subset() {
        let split = split_secret_with_proofs(&secret(), 3, 5, &[9u8; 32]).unwrap();
        assert_eq!(split.proofs().len(), 3);
        assert_eq!(split.shares().len(), 5);
        assert_eq!(split.to_bytes().len(), 3 * 33 + 5 * 32);
        for subset in [&[1u32, 2, 3][..], &[1, 3, 5], &[3, 4, 5], &[1, 2, 3, 4, 5]] {
            assert_eq!(recombine(split.shares(), subset), secret());
        }
    }

    #[test]
    fn deterministic_for_same_seed() {
        let a = split_secret_with_proofs(&secret(), 2, 3, &[9u8; 32]).unwrap();
        let b = split_secret_with_proofs(&secret(), 2, 3, &[9u8; 32]).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes());
    }

    #[test]
    fn rejects_bad_parameters() {
        for (t, n) in [(1usize, 3usize), (0, 3), (4, 3), (2, 256)] {
            assert_eq!(
                split_secret_with_proofs(&secret(), t, n, &[0u8; 32]).unwrap_err(),
                Error::OutOfRange,
                "t={t} n={n}"
            );
        }
        assert_eq!(
            split_secret_with_proofs(&[0xFFu8; 32], 2, 3, &[0u8; 32]).unwrap_err(),
            Error::InvalidScalar
        );
    }
}
