//! User-side FROST signing and aggregation.
//!
//! Ported from `buildonspark/spark` `signer/spark-frost/src/signing.rs`
//! (commit 0b3a32a05c9ac06cc411683551dd1f1bde9d0caa): `sign_frost_job` for
//! `role == USER` under `SIGNING_SCHEME_SINGLE_USER`, `aggregate_frost` for
//! the same scheme, and the `role == 1` branch of
//! `frost_key_package_from_proto`.
//!
//! Modifications from upstream:
//! - protobuf inputs are replaced by byte-oriented job structs;
//! - operator identifiers are the raw 32-byte serialized scalars that
//!   upstream carries as hex strings (`hex_string_to_identifier`);
//! - the user verifying share is computed from the signing share instead of
//!   being read from `public_shares`;
//! - duplicate operator identifiers are rejected instead of being silently
//!   deduplicated by the `BTreeMap`;
//! - a malformed adaptor public key is an error instead of silently
//!   disabling the adaptor;
//! - `rayon`, `tracing` and `String` errors are removed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use frost::keys::{EvenY, KeyPackage, PublicKeyPackage, SigningShare, Tweak, VerifyingShare};
use frost::round1::{NonceCommitment, SigningCommitments, SigningNonces};
use frost::round2::SignatureShare;
use frost::{Identifier, SigningPackage, VerifyingKey};
use frost_core::round1::Nonce;
use frost_secp256k1_tr as frost;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Error;

/// The single-user FROST identifier, derived upstream via
/// `Identifier::derive(b"user")`.
fn user_identifier() -> Result<Identifier, Error> {
    Identifier::derive(b"user").map_err(|_| Error::Internal)
}

fn identifier_from_bytes(bytes: &[u8; 32]) -> Result<Identifier, Error> {
    Identifier::deserialize(bytes).map_err(|_| Error::InvalidScalar)
}

fn nonce_from_bytes(hiding: &[u8], binding: &[u8]) -> Result<SigningNonces, Error> {
    let hiding = Nonce::deserialize(hiding).map_err(|_| Error::InvalidScalar)?;
    let binding = Nonce::deserialize(binding).map_err(|_| Error::InvalidScalar)?;
    Ok(SigningNonces::from_nonces(hiding, binding))
}

fn commitments_from_bytes(bytes: &[u8; 66]) -> Result<SigningCommitments, Error> {
    let (hiding, binding) = bytes.split_at(33);
    let hiding = NonceCommitment::deserialize(hiding).map_err(|_| Error::InvalidPoint)?;
    let binding = NonceCommitment::deserialize(binding).map_err(|_| Error::InvalidPoint)?;
    Ok(SigningCommitments::new(hiding, binding))
}

fn verifying_key_from_bytes(bytes: &[u8; 33]) -> Result<VerifyingKey, Error> {
    VerifyingKey::deserialize(bytes).map_err(|_| Error::InvalidPoint)
}

fn adaptor_from_bytes(bytes: Option<&[u8; 33]>) -> Result<Option<VerifyingKey>, Error> {
    bytes.map(verifying_key_from_bytes).transpose()
}

/// Collect the operator commitments into the FROST commitment map and return
/// the participant identifier set of the operator group.
fn operator_commitments(
    operators: &[OperatorCommitment],
) -> Result<
    (
        BTreeMap<Identifier, SigningCommitments>,
        BTreeSet<Identifier>,
    ),
    Error,
> {
    let mut commitments = BTreeMap::new();
    let mut participants = BTreeSet::new();
    for operator in operators {
        let identifier = identifier_from_bytes(&operator.identifier)?;
        // Upstream reads a proto map, which cannot hold duplicate keys; our
        // list input can, so reject them explicitly.
        if !participants.insert(identifier) {
            return Err(Error::Frost);
        }
        commitments.insert(identifier, commitments_from_bytes(&operator.commitment)?);
    }
    Ok((commitments, participants))
}

/// Result of [`commit`]: the secret nonces and their public commitments.
///
/// The nonces are secret material: they are zeroized on drop and never shown
/// by `Debug`.
#[derive(ZeroizeOnDrop)]
pub struct Commitment {
    nonces: NoncePair,
    commitments: [u8; 66],
}

/// The `hiding‖binding` nonce scalars produced by [`commit`].
#[derive(Zeroize, ZeroizeOnDrop)]
struct NoncePair([u8; 64]);

impl fmt::Debug for NoncePair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NoncePair([REDACTED])")
    }
}

impl fmt::Debug for Commitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Commitment")
            .field("nonces", &"[REDACTED]")
            .field("commitments", &self.commitments)
            .finish()
    }
}

impl Commitment {
    /// The `hiding‖binding` nonce scalars (64 bytes). Pass them back to
    /// [`sign`] as `SignJob::nonce`.
    #[must_use]
    pub const fn nonces(&self) -> &[u8; 64] {
        &self.nonces.0
    }

    /// The compressed `hiding‖binding` commitment points (66 bytes).
    #[must_use]
    pub const fn commitments(&self) -> &[u8; 66] {
        &self.commitments
    }

    /// `nonces(64)‖commitments(66)` — one 130-byte slot of the
    /// `frostCommit` output layout.
    #[must_use]
    #[allow(
        clippy::missing_const_for_fn,
        reason = "slice::split_at_mut is not const"
    )]
    pub fn to_bytes(&self) -> [u8; 130] {
        let mut out = [0u8; 130];
        let (nonces, commitments) = out.split_at_mut(64);
        nonces.copy_from_slice(&self.nonces.0);
        commitments.copy_from_slice(&self.commitments);
        out
    }
}

/// Generate FROST signing nonces for one participant.
///
/// `hedge` is the signer's own hedged secret (a valid secp256k1 scalar); it
/// takes the place of the participant's `SigningShare` in upstream
/// `frost_nonce`. `random` seeds a `ChaCha20` stream, so even a weak entropy
/// source cannot collide nonces for distinct hedges.
///
/// # Errors
/// [`Error::InvalidScalar`] if `hedge` is not a valid scalar.
pub fn commit(hedge: &[u8; 32], random: &[u8; 32]) -> Result<Commitment, Error> {
    let signing_share = SigningShare::deserialize(hedge).map_err(|_| Error::InvalidScalar)?;
    let mut rng = ChaCha20Rng::from_seed(*random);
    let nonces = SigningNonces::new(&signing_share, &mut rng);
    let commitments = nonces.commitments();

    let mut nonce_bytes = [0u8; 64];
    let (hiding_bytes, binding_bytes) = nonce_bytes.split_at_mut(32);
    hiding_bytes.copy_from_slice(&nonces.hiding().serialize());
    binding_bytes.copy_from_slice(&nonces.binding().serialize());

    let mut commitment_bytes = [0u8; 66];
    let (hiding, binding) = commitment_bytes.split_at_mut(33);
    hiding.copy_from_slice(
        &commitments
            .hiding()
            .serialize()
            .map_err(|_| Error::Internal)?,
    );
    binding.copy_from_slice(
        &commitments
            .binding()
            .serialize()
            .map_err(|_| Error::Internal)?,
    );

    Ok(Commitment {
        nonces: NoncePair(nonce_bytes),
        commitments: commitment_bytes,
    })
}

/// One operator's round-1 commitment for [`SignJob`].
#[derive(Clone, Copy)]
pub struct OperatorCommitment {
    /// The operator's FROST identifier (32-byte serialized scalar).
    pub identifier: [u8; 32],
    /// Compressed `hiding‖binding` commitment points.
    pub commitment: [u8; 66],
}

impl fmt::Debug for OperatorCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperatorCommitment")
            .field("identifier", &self.identifier)
            .field("commitment", &self.commitment)
            .finish()
    }
}

/// A single user-side FROST signing job.
///
/// Field order and semantics mirror upstream `FrostSigningJob` for
/// `role == USER`: `secret_key` is the user's private key (proto
/// `key_package.secret_share`), `verifying_key` is the combined
/// operator-group + user key (proto `verifying_key`), and `nonce`/
/// `user_commitment` are the user's round-1 output.
#[derive(Clone, Copy)]
pub struct SignJob<'a> {
    /// Message bytes to sign (a 32-byte sighash upstream).
    pub message: &'a [u8],
    /// The user's private key.
    pub secret_key: &'a [u8; 32],
    /// The combined verifying key (compressed).
    pub verifying_key: &'a [u8; 33],
    /// The user's `hiding‖binding` nonces from [`commit`].
    pub nonce: &'a [u8; 64],
    /// The user's compressed `hiding‖binding` commitments.
    pub user_commitment: &'a [u8; 66],
    /// The participating operators' commitments.
    pub operators: &'a [OperatorCommitment],
    /// Optional adaptor point (compressed); present for adaptor signing.
    pub adaptor_public_key: Option<&'a [u8; 33]>,
}

impl fmt::Debug for SignJob<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignJob")
            .field("message", &self.message)
            .field("secret_key", &"[REDACTED]")
            .field("verifying_key", &self.verifying_key)
            .field("nonce", &"[REDACTED]")
            .field("user_commitment", &self.user_commitment)
            .field("operators", &self.operators)
            .field("adaptor_public_key", &self.adaptor_public_key)
            .finish()
    }
}

/// Produce the user's FROST signature share.
///
/// # Errors
/// [`Error::InvalidScalar`] for bad scalars (secret key, nonces, identifier),
/// [`Error::InvalidPoint`] for bad points (verifying key, commitments,
/// adaptor), [`Error::Frost`] for duplicate identifiers — including an
/// operator identifier equal to the user identifier — or a rejected share,
/// [`Error::Internal`] for unrecoverable invariant failures.
pub fn sign(job: &SignJob<'_>) -> Result<[u8; 32], Error> {
    let user_identifier = user_identifier()?;

    let (mut commitments, operator_participants) = operator_commitments(job.operators)?;
    // An operator slot named `user` would be silently overwritten by the
    // user's own commitment below — reject it like any duplicate identifier.
    if operator_participants.contains(&user_identifier) {
        return Err(Error::Frost);
    }
    commitments.insert(
        user_identifier,
        commitments_from_bytes(job.user_commitment)?,
    );
    let signing_participants_groups =
        vec![operator_participants, BTreeSet::from([user_identifier])];

    let (hiding, binding) = job.nonce.split_at(32);
    let nonce = nonce_from_bytes(hiding, binding)?;

    let verifying_key = verifying_key_from_bytes(job.verifying_key)?;

    // Upstream `frost_key_package_from_proto` role == USER: the signing share
    // is the private key, min_signers is 1, and the verifying share upstream
    // reads from `public_shares` is recomputed here from the secret.
    let signing_share =
        SigningShare::deserialize(job.secret_key).map_err(|_| Error::InvalidScalar)?;
    let user_verifying_share = VerifyingShare::from(signing_share);
    let raw_package = KeyPackage::new(
        user_identifier,
        signing_share,
        user_verifying_share,
        verifying_key,
        1,
    );

    // Even-Y normalize against the untweaked combined key, but keep the
    // taproot-tweaked (empty merkle root) verifying key — exactly the
    // upstream role == 1 composition.
    let tweaked = raw_package.clone().tweak(Some(&[]));
    let even_y = raw_package.into_even_y(Some(verifying_key.has_even_y()));
    let key_package = KeyPackage::new(
        *even_y.identifier(),
        *even_y.signing_share(),
        *even_y.verifying_share(),
        *tweaked.verifying_key(),
        *tweaked.min_signers(),
    );

    let signing_package = SigningPackage::new_with_adaptor(
        commitments,
        Some(signing_participants_groups),
        job.message,
        adaptor_from_bytes(job.adaptor_public_key)?,
    );

    let signature_share =
        frost::round2::sign(&signing_package, &nonce, &key_package).map_err(|_| Error::Frost)?;

    signature_share
        .serialize()
        .as_slice()
        .try_into()
        .map_err(|_| Error::Internal)
}

/// One operator's contribution for [`AggregateJob`].
#[derive(Clone, Copy)]
pub struct OperatorShare {
    /// The operator's FROST identifier (32-byte serialized scalar).
    pub identifier: [u8; 32],
    /// Compressed `hiding‖binding` commitment points.
    pub commitment: [u8; 66],
    /// The operator's signature share (scalar).
    pub signature_share: [u8; 32],
    /// The operator's verifying share (compressed point).
    pub public_key: [u8; 33],
}

impl fmt::Debug for OperatorShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperatorShare")
            .field("identifier", &self.identifier)
            .field("commitment", &self.commitment)
            .field("signature_share", &self.signature_share)
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// A single user-side FROST aggregation job.
#[derive(Clone, Copy)]
pub struct AggregateJob<'a> {
    /// The message that was signed.
    pub message: &'a [u8],
    /// The combined verifying key (compressed).
    pub verifying_key: &'a [u8; 33],
    /// The user's compressed `hiding‖binding` commitments.
    pub user_commitment: &'a [u8; 66],
    /// The user's verifying share (compressed point).
    pub user_public_key: &'a [u8; 33],
    /// The user's signature share (scalar).
    pub user_signature_share: &'a [u8; 32],
    /// The participating operators' shares.
    pub operators: &'a [OperatorShare],
    /// Optional adaptor point (compressed).
    pub adaptor_public_key: Option<&'a [u8; 33]>,
}

impl fmt::Debug for AggregateJob<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AggregateJob")
            .field("message", &self.message)
            .field("verifying_key", &self.verifying_key)
            .field("user_commitment", &self.user_commitment)
            .field("user_public_key", &self.user_public_key)
            .field("user_signature_share", &self.user_signature_share)
            .field("operators", &self.operators)
            .field("adaptor_public_key", &self.adaptor_public_key)
            .finish()
    }
}

/// Aggregate the operator and user signature shares into a BIP-340
/// Schnorr signature.
///
/// # Errors
/// Same classes as [`sign`]; with an adaptor key the fork skips per-share
/// verification, so a wrong share surfaces as [`Error::Frost`] only when the
/// aggregation itself fails.
pub fn aggregate(job: &AggregateJob<'_>) -> Result<[u8; 64], Error> {
    let user_identifier = user_identifier()?;

    let mut commitments = BTreeMap::new();
    let mut operator_participants = BTreeSet::new();
    let mut signature_shares = BTreeMap::new();
    let mut verifying_shares = BTreeMap::new();

    for operator in job.operators {
        let identifier = identifier_from_bytes(&operator.identifier)?;
        if !operator_participants.insert(identifier) {
            return Err(Error::Frost);
        }
        commitments.insert(identifier, commitments_from_bytes(&operator.commitment)?);
        signature_shares.insert(
            identifier,
            SignatureShare::deserialize(&operator.signature_share)
                .map_err(|_| Error::InvalidScalar)?,
        );
        verifying_shares.insert(
            identifier,
            VerifyingShare::deserialize(&operator.public_key).map_err(|_| Error::InvalidPoint)?,
        );
    }

    // Same rule as `sign`: an operator slot named `user` would otherwise be
    // silently overwritten by the user's own entries below.
    if operator_participants.contains(&user_identifier) {
        return Err(Error::Frost);
    }
    commitments.insert(
        user_identifier,
        commitments_from_bytes(job.user_commitment)?,
    );
    signature_shares.insert(
        user_identifier,
        SignatureShare::deserialize(job.user_signature_share).map_err(|_| Error::InvalidScalar)?,
    );
    verifying_shares.insert(
        user_identifier,
        VerifyingShare::deserialize(job.user_public_key).map_err(|_| Error::InvalidPoint)?,
    );

    let verifying_key = verifying_key_from_bytes(job.verifying_key)?;
    let public_package = PublicKeyPackage::new(verifying_shares, verifying_key, None);

    let signing_participants_groups =
        vec![operator_participants, BTreeSet::from([user_identifier])];
    let signing_package = SigningPackage::new_with_adaptor(
        commitments,
        Some(signing_participants_groups),
        job.message,
        adaptor_from_bytes(job.adaptor_public_key)?,
    );

    let signature = frost::aggregate_with_tweak(
        &signing_package,
        &signature_shares,
        &public_package,
        Some(&[]),
    )
    .map_err(|_| Error::Frost)?;

    signature
        .serialize()
        .map_err(|_| Error::Internal)?
        .as_slice()
        .try_into()
        .map_err(|_| Error::Internal)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::missing_panics_doc,
        reason = "test code"
    )]

    use frost::SigningKey;
    use frost::keys::IdentifierList;
    use rand_core::SeedableRng;

    use super::*;

    /// A dealer-generated operator group plus a user key, mirroring the
    /// upstream `test_group_signing` setup (signing.rs tests).
    struct Keys {
        operator_key_packages: BTreeMap<Identifier, KeyPackage>,
        operator_threshold: u16,
        user_key: SigningKey,
        user_vk: VerifyingKey,
        combined_vk: VerifyingKey,
    }

    fn generate_keys(count: u16, threshold: u16) -> Keys {
        let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
        let (shares, pubkey_package) =
            frost::keys::generate_with_dealer(count, threshold, IdentifierList::Default, &mut rng)
                .unwrap();
        let operator_key_packages = shares
            .into_iter()
            .map(|(id, share)| (id, KeyPackage::try_from(share).unwrap()))
            .collect();

        let user_key = SigningKey::new(&mut rng);
        let user_vk = VerifyingKey::from(&user_key);
        let combined_vk =
            VerifyingKey::new(pubkey_package.verifying_key().to_element() + user_vk.to_element());

        Keys {
            operator_key_packages,
            operator_threshold: threshold,
            user_key,
            user_vk,
            combined_vk,
        }
    }

    fn bytes32<T>(v: T) -> [u8; 32]
    where
        T: TryInto<[u8; 32]>,
        T::Error: fmt::Debug,
    {
        v.try_into().unwrap()
    }

    fn bytes33(v: Vec<u8>) -> [u8; 33] {
        v.try_into().unwrap()
    }

    /// One complete round against our `sign`/`aggregate` using a subset of
    /// the operator group. Returns the aggregated signature.
    fn run_round(
        keys: &Keys,
        signer_ids: &[Identifier],
        message: &[u8],
        adaptor: Option<&[u8; 33]>,
    ) -> [u8; 64] {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);

        // Round 1: operator commitments (statechain role) + user commitment.
        let mut operator_commitments = Vec::new();
        let mut operator_nonces = BTreeMap::new();
        for &id in signer_ids {
            let key_package = &keys.operator_key_packages[&id];
            let (nonces, commitments) =
                frost::round1::commit(key_package.signing_share(), &mut rng);
            operator_nonces.insert(id, nonces);
            let mut commitment = [0u8; 66];
            commitment[..33].copy_from_slice(&commitments.hiding().serialize().unwrap());
            commitment[33..].copy_from_slice(&commitments.binding().serialize().unwrap());
            operator_commitments.push(OperatorCommitment {
                identifier: bytes32(id.serialize()),
                commitment,
            });
        }

        let secret_key = bytes32(keys.user_key.serialize());
        let hedge = bytes32(keys.user_key.serialize());
        let user_round1 = commit(&hedge, &[9u8; 32]).unwrap();
        let user_commitment = user_round1.commitments();
        let user_nonce = *user_round1.nonces();

        // Our user share.
        let user_share = sign(&SignJob {
            message,
            secret_key: &secret_key,
            verifying_key: &bytes33(keys.combined_vk.serialize().unwrap()),
            nonce: &user_nonce,
            user_commitment,
            operators: &operator_commitments,
            adaptor_public_key: adaptor,
        })
        .unwrap();

        // Statechain (operator) shares, upstream role == 0 path: raw dealer
        // key package under the combined key, `sign_with_tweak` with an
        // empty merkle root.
        let mut commitments_map: BTreeMap<Identifier, SigningCommitments> = BTreeMap::new();
        for op in &operator_commitments {
            let id = identifier_from_bytes(&op.identifier).unwrap();
            commitments_map.insert(id, commitments_from_bytes(&op.commitment).unwrap());
        }
        let user_identifier = Identifier::derive(b"user").unwrap();
        commitments_map.insert(
            user_identifier,
            commitments_from_bytes(user_commitment).unwrap(),
        );
        let groups = vec![
            signer_ids.iter().copied().collect::<BTreeSet<_>>(),
            BTreeSet::from([user_identifier]),
        ];
        let signing_package = SigningPackage::new_with_adaptor(
            commitments_map,
            Some(groups),
            message,
            adaptor.and_then(|pk| VerifyingKey::deserialize(pk).ok()),
        );

        let mut operator_shares = Vec::new();
        for (op, &id) in operator_commitments.iter().zip(signer_ids) {
            let dealer = &keys.operator_key_packages[&id];
            let key_package = KeyPackage::new(
                id,
                *dealer.signing_share(),
                *dealer.verifying_share(),
                keys.combined_vk,
                keys.operator_threshold,
            );
            let share = frost::round2::sign_with_tweak(
                &signing_package,
                &operator_nonces[&id],
                &key_package,
                Some(&[]),
            )
            .unwrap();
            operator_shares.push(OperatorShare {
                identifier: op.identifier,
                commitment: op.commitment,
                signature_share: bytes32(share.serialize()),
                public_key: {
                    let vs = dealer.verifying_share().serialize().unwrap();
                    vs.try_into().unwrap()
                },
            });
        }

        let user_vk_bytes: [u8; 33] = keys.user_vk.serialize().unwrap().try_into().unwrap();
        aggregate(&AggregateJob {
            message,
            verifying_key: &bytes33(keys.combined_vk.serialize().unwrap()),
            user_commitment,
            user_public_key: &user_vk_bytes,
            user_signature_share: &user_share,
            operators: &operator_shares,
            adaptor_public_key: adaptor,
        })
        .unwrap()
    }

    fn verify_signature(keys: &Keys, message: &[u8], signature: &[u8; 64]) {
        let mut shares = BTreeMap::new();
        for (id, kp) in &keys.operator_key_packages {
            shares.insert(*id, *kp.verifying_share());
        }
        let user_identifier = Identifier::derive(b"user").unwrap();
        shares.insert(
            user_identifier,
            VerifyingShare::new(keys.user_vk.to_element()),
        );
        let package = PublicKeyPackage::new(shares, keys.combined_vk, None).tweak(Some(&[]));
        let signature = frost::Signature::deserialize(signature).unwrap();
        package
            .verifying_key()
            .verify(message, &signature)
            .expect("signature must verify against tweaked combined key");
    }

    #[test]
    fn sign_and_aggregate_roundtrip() {
        let keys = generate_keys(3, 2);
        let message = b"spark test message";

        for signer_ids in [
            vec![
                Identifier::try_from(1u16).unwrap(),
                Identifier::try_from(2u16).unwrap(),
            ],
            vec![
                Identifier::try_from(1u16).unwrap(),
                Identifier::try_from(2u16).unwrap(),
                Identifier::try_from(3u16).unwrap(),
            ],
            vec![
                Identifier::try_from(2u16).unwrap(),
                Identifier::try_from(3u16).unwrap(),
            ],
        ] {
            let signature = run_round(&keys, &signer_ids, message, None);
            verify_signature(&keys, message, &signature);
        }
    }

    #[test]
    fn sign_and_aggregate_with_adaptor() {
        let keys = generate_keys(3, 2);
        let adaptor_sk = SigningKey::new(&mut ChaCha20Rng::from_seed([5u8; 32]));
        let adaptor_vk: [u8; 33] = VerifyingKey::from(&adaptor_sk)
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        // With an adaptor the aggregate skips share verification; a
        // well-formed job still aggregates.
        let signer_ids = [
            Identifier::try_from(1u16).unwrap(),
            Identifier::try_from(2u16).unwrap(),
        ];
        let _ = run_round(&keys, &signer_ids, b"adaptor", Some(&adaptor_vk));
    }

    #[test]
    fn commit_is_deterministic() {
        let hedge = [1u8; 32];
        let hedge = {
            let mut h = hedge;
            h[31] = 7;
            h
        };
        let a = commit(&hedge, &[3u8; 32]).unwrap();
        let b = commit(&hedge, &[3u8; 32]).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes());
        let c = commit(&hedge, &[4u8; 32]).unwrap();
        assert_ne!(a.to_bytes(), c.to_bytes());
        assert_eq!(
            commit(&[0xFFu8; 32], &[0u8; 32]).unwrap_err(),
            Error::InvalidScalar
        );
    }

    #[test]
    fn duplicate_operator_identifier_fails() {
        let keys = generate_keys(3, 2);
        let real = commit(&[1u8; 32], &[2u8; 32]).unwrap();
        let id = Identifier::try_from(1u16).unwrap();
        let operators = [
            OperatorCommitment {
                identifier: bytes32(id.serialize()),
                commitment: *real.commitments(),
            },
            OperatorCommitment {
                identifier: bytes32(id.serialize()),
                commitment: *real.commitments(),
            },
        ];
        let secret_key = bytes32(keys.user_key.serialize());
        let nonce = commit(&secret_key, &[8u8; 32]).unwrap();
        let user_commitment = *nonce.commitments();
        let err = sign(&SignJob {
            message: b"m",
            secret_key: &secret_key,
            verifying_key: &bytes33(keys.combined_vk.serialize().unwrap()),
            nonce: nonce.nonces(),
            user_commitment: &user_commitment,
            operators: &operators,
            adaptor_public_key: None,
        })
        .unwrap_err();
        assert_eq!(err, Error::Frost);
    }

    #[test]
    fn operator_identifier_colliding_with_user_fails() {
        let keys = generate_keys(3, 2);
        let user_id = Identifier::derive(b"user").unwrap();
        let real = commit(&[1u8; 32], &[2u8; 32]).unwrap();
        let operators = [OperatorCommitment {
            identifier: bytes32(user_id.serialize()),
            commitment: *real.commitments(),
        }];
        let secret_key = bytes32(keys.user_key.serialize());
        let nonce = commit(&secret_key, &[8u8; 32]).unwrap();
        let user_commitment = *nonce.commitments();
        let err = sign(&SignJob {
            message: b"m",
            secret_key: &secret_key,
            verifying_key: &bytes33(keys.combined_vk.serialize().unwrap()),
            nonce: nonce.nonces(),
            user_commitment: &user_commitment,
            operators: &operators,
            adaptor_public_key: None,
        })
        .unwrap_err();
        assert_eq!(err, Error::Frost);
    }

    #[test]
    fn aggregate_operator_identifier_colliding_with_user_fails() {
        let keys = generate_keys(3, 2);
        let user_id = Identifier::derive(b"user").unwrap();
        let real = commit(&[1u8; 32], &[2u8; 32]).unwrap();
        let operators = [OperatorShare {
            identifier: bytes32(user_id.serialize()),
            commitment: *real.commitments(),
            signature_share: [7u8; 32],
            public_key: bytes33(keys.user_vk.serialize().unwrap()),
        }];
        let nonce = commit(&bytes32(keys.user_key.serialize()), &[8u8; 32]).unwrap();
        let user_commitment = *nonce.commitments();
        let err = aggregate(&AggregateJob {
            message: b"m",
            verifying_key: &bytes33(keys.combined_vk.serialize().unwrap()),
            user_commitment: &user_commitment,
            user_public_key: &bytes33(keys.user_vk.serialize().unwrap()),
            user_signature_share: &[9u8; 32],
            operators: &operators,
            adaptor_public_key: None,
        })
        .unwrap_err();
        assert_eq!(err, Error::Frost);
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let keys = generate_keys(3, 2);
        let secret_key = bytes32(keys.user_key.serialize());
        let round1 = commit(&secret_key, &[8u8; 32]).unwrap();
        let user_commitment = *round1.commitments();
        let mut bad_vk = [0u8; 33];
        bad_vk[0] = 0x02;

        let err = sign(&SignJob {
            message: b"m",
            secret_key: &secret_key,
            verifying_key: &bad_vk,
            nonce: round1.nonces(),
            user_commitment: &user_commitment,
            operators: &[],
            adaptor_public_key: None,
        })
        .unwrap_err();
        assert_eq!(err, Error::InvalidPoint);

        let mut bad_nonce = *round1.nonces();
        bad_nonce[31] ^= 0xFF;
        let result = sign(&SignJob {
            message: b"m",
            secret_key: &secret_key,
            verifying_key: &bytes33(keys.combined_vk.serialize().unwrap()),
            nonce: &bad_nonce,
            user_commitment: &user_commitment,
            operators: &[],
            adaptor_public_key: None,
        });
        assert!(result.is_err());
    }
}
