//! Shared helpers for the differential and vector tests: a realistic
//! operator set produced by the upstream dealer, upstream bridge calls to
//! reproduce operator/user signing, and conversion into `spark-crypto` jobs.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_panics_doc,
    reason = "test helpers"
)]

use std::collections::{BTreeMap, HashMap};

use frost::keys::{KeyPackage, VerifyingShare};
use frost::{Identifier, SigningKey, VerifyingKey};
use frost_core::round1::NonceCommitment;
use frost_secp256k1_tr as frost;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use spark_frost::proto::common::SigningCommitment;
use spark_frost::proto::frost::{self as pb, SigningNonce};

pub const UPSTREAM_REV: &str = "0b3a32a05c9ac06cc411683551dd1f1bde9d0caa";

type SNonce = frost_core::round1::Nonce<frost::Secp256K1Sha256TR>;

pub fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

pub fn id_bytes(id: &Identifier) -> [u8; 32] {
    id.serialize().try_into().unwrap()
}

pub fn id_hex(id: &Identifier) -> String {
    hex::encode(id.serialize())
}

/// One operator's dealer material plus its round-1 nonce.
pub struct Operator {
    pub identifier: Identifier,
    pub secret_share: Vec<u8>,
    pub verifying_share: Vec<u8>,
    pub nonce: frost::round1::SigningNonces,
    pub commitment: frost::round1::SigningCommitments,
}

/// A generated operator group plus a user key, as upstream's
/// `test_group_signing` wires them: the combined verifying key is the
/// operator group key plus the user key.
pub struct Setup {
    pub operators: BTreeMap<Identifier, Operator>,
    pub threshold: u16,
    pub user_key: SigningKey,
    pub user_vk: VerifyingKey,
    pub combined_vk: VerifyingKey,
}

pub fn setup(rand: &mut ChaCha20Rng, count: u16, threshold: u16, signers: &[u16]) -> Setup {
    let (shares, pubkey_package) = frost::keys::generate_with_dealer(
        count,
        threshold,
        frost::keys::IdentifierList::Default,
        &mut *rand,
    )
    .unwrap();
    let mut key_packages: BTreeMap<Identifier, KeyPackage> = shares
        .into_iter()
        .map(|(id, ss)| (id, KeyPackage::try_from(ss).unwrap()))
        .collect();

    let user_key = SigningKey::new(&mut *rand);
    let user_vk = VerifyingKey::from(&user_key);
    let combined_vk =
        VerifyingKey::new(pubkey_package.verifying_key().to_element() + user_vk.to_element());

    let mut operators = BTreeMap::new();
    for &n in signers {
        let id = Identifier::try_from(n).unwrap();
        let kp = key_packages.remove(&id).unwrap();
        let (nonce, commitment) = frost::round1::commit(kp.signing_share(), &mut *rand);
        operators.insert(
            id,
            Operator {
                identifier: id,
                secret_share: kp.signing_share().serialize(),
                verifying_share: kp.verifying_share().serialize().unwrap(),
                nonce,
                commitment,
            },
        );
    }

    Setup {
        operators,
        threshold,
        user_key,
        user_vk,
        combined_vk,
    }
}

pub fn proto_commitment(c: &frost::round1::SigningCommitments) -> SigningCommitment {
    SigningCommitment {
        hiding: c.hiding().serialize().unwrap(),
        binding: c.binding().serialize().unwrap(),
    }
}

pub fn commitment_bytes(c: &frost::round1::SigningCommitments) -> [u8; 66] {
    let mut out = [0u8; 66];
    out[..33].copy_from_slice(&c.hiding().serialize().unwrap());
    out[33..].copy_from_slice(&c.binding().serialize().unwrap());
    out
}

/// The user's round-1 output through our own `frost::commit`.
pub struct UserRound1 {
    pub nonce_bytes: [u8; 64],
    pub commitment_bytes: [u8; 66],
    pub commitment: frost::round1::SigningCommitments,
}

pub fn user_round1(user_key: &SigningKey, seed: u8) -> UserRound1 {
    let hedge: [u8; 32] = user_key.serialize().try_into().unwrap();
    let result = spark_crypto::frost::commit(&hedge, &[seed; 32]).unwrap();
    let _ = SNonce::deserialize(&result.nonces()[..32]).unwrap();
    let _ = SNonce::deserialize(&result.nonces()[32..]).unwrap();
    let commitment = frost::round1::SigningCommitments::new(
        NonceCommitment::deserialize(&result.commitments()[..33]).unwrap(),
        NonceCommitment::deserialize(&result.commitments()[33..]).unwrap(),
    );
    UserRound1 {
        nonce_bytes: *result.nonces(),
        commitment_bytes: *result.commitments(),
        commitment,
    }
}

/// Everything both sides need to run one sign+aggregate round.
pub struct Round {
    pub message: Vec<u8>,
    pub operator_commitments: HashMap<String, SigningCommitment>,
    pub user_commitment: SigningCommitment,
    pub verifying_key: Vec<u8>,
    pub adaptor: Option<Vec<u8>>,
    /// Upstream proto jobs for the participating operators.
    pub jobs: Vec<pb::FrostSigningJob>,
    /// Upstream proto key package for the user job.
    pub user_key_package: pb::KeyPackage,
    pub user_nonce: SigningNonce,
    pub signer_ids: Vec<Identifier>,
}

pub fn build_round(
    s: &Setup,
    signers: &[u16],
    message: &[u8],
    adaptor: Option<Vec<u8>>,
    user_seed: u8,
) -> (Round, UserRound1) {
    let user_identifier = Identifier::derive(b"user").unwrap();
    let user_round1 = user_round1(&s.user_key, user_seed);

    let mut operator_commitments = HashMap::new();
    for &n in signers {
        let id = Identifier::try_from(n).unwrap();
        let op = &s.operators[&id];
        operator_commitments.insert(id_hex(&id), proto_commitment(&op.commitment));
    }

    // Per-operator proto key packages for the upstream statechain sign path.
    let mut public_shares = HashMap::new();
    for &n in signers {
        let id = Identifier::try_from(n).unwrap();
        public_shares.insert(id_hex(&id), s.operators[&id].verifying_share.clone());
    }
    let verifying_key = s.combined_vk.serialize().unwrap();
    let jobs = signers
        .iter()
        .map(|&n| {
            let id = Identifier::try_from(n).unwrap();
            let op = &s.operators[&id];
            pb::FrostSigningJob {
                job_id: id_hex(&id),
                message: message.to_vec(),
                key_package: Some(pb::KeyPackage {
                    identifier: id_hex(&id),
                    secret_share: op.secret_share.clone(),
                    public_shares: public_shares.clone(),
                    public_key: verifying_key.clone(),
                    min_signers: u32::from(s.threshold),
                }),
                verifying_key: verifying_key.clone(),
                nonce: Some(SigningNonce {
                    hiding: op.nonce.hiding().serialize(),
                    binding: op.nonce.binding().serialize(),
                }),
                commitments: operator_commitments.clone(),
                user_commitments: Some(proto_commitment(&user_round1.commitment)),
                adaptor_public_key: adaptor.clone().unwrap_or_default(),
                signing_scheme: pb::SigningScheme::SingleUser.into(),
                subuser_commitments: vec![],
            }
        })
        .collect();

    let user_verifying_share = VerifyingShare::new(s.user_vk.to_element());
    let mut user_public_shares = HashMap::new();
    user_public_shares.insert(
        id_hex(&user_identifier),
        user_verifying_share.serialize().unwrap(),
    );
    let user_key_package = pb::KeyPackage {
        identifier: id_hex(&user_identifier),
        secret_share: s.user_key.serialize(),
        public_shares: user_public_shares,
        public_key: verifying_key.clone(),
        min_signers: 1,
    };

    let signer_ids = signers
        .iter()
        .map(|&n| Identifier::try_from(n).unwrap())
        .collect();

    (
        Round {
            message: message.to_vec(),
            operator_commitments,
            user_commitment: proto_commitment(&user_round1.commitment),
            verifying_key,
            adaptor,
            jobs,
            user_key_package,
            user_nonce: SigningNonce {
                hiding: user_round1.nonce_bytes[..32].to_vec(),
                binding: user_round1.nonce_bytes[32..].to_vec(),
            },
            signer_ids,
        },
        user_round1,
    )
}

/// Outcome of [`run_both`].
pub struct Outcome {
    /// Upstream operator signature shares keyed by hex identifier.
    pub operator_shares: HashMap<String, Vec<u8>>,
    pub our_user_share: [u8; 32],
    pub upstream_user_share: Vec<u8>,
    pub our_signature: [u8; 64],
    pub upstream_signature: Vec<u8>,
}

/// Run the whole round upstream (operators via `signing::sign_frost` role
/// STATECHAIN, user via `bridge::sign_frost`, aggregate via
/// `bridge::aggregate_frost`) and ours (`frost::sign` + `frost::aggregate`),
/// asserting byte-equality at each boundary.
pub fn run_both(round: &Round, s: &Setup, user_round1: &UserRound1) -> Outcome {
    // Upstream operator shares.
    let resp = spark_frost::signing::sign_frost(&pb::SignFrostRequest {
        signing_jobs: round.jobs.clone(),
        role: pb::SigningRole::Statechain.into(),
    })
    .unwrap();
    let operator_shares: HashMap<String, Vec<u8>> = resp
        .results
        .iter()
        .map(|(k, v)| (k.clone(), v.signature_share.clone()))
        .collect();

    // Upstream user share via the bridge entry point.
    let upstream_user_share = spark_frost::bridge::sign_frost(
        round.message.clone(),
        round.user_key_package.clone(),
        round.user_nonce.clone(),
        round.user_commitment.clone(),
        round.operator_commitments.clone(),
        round.adaptor.clone(),
    )
    .unwrap();

    // Our user share.
    let operator_commitments: Vec<spark_crypto::frost::OperatorCommitment> = round
        .signer_ids
        .iter()
        .map(|id| spark_crypto::frost::OperatorCommitment {
            identifier: id_bytes(id),
            commitment: commitment_bytes(&s.operators[id].commitment),
        })
        .collect();
    let secret_key: [u8; 32] = s.user_key.serialize().try_into().unwrap();
    let verifying_key: [u8; 33] = round.verifying_key.clone().try_into().unwrap();
    let adaptor33: Option<[u8; 33]> = round
        .adaptor
        .as_ref()
        .map(|a| a.clone().try_into().unwrap());
    let our_user_share = spark_crypto::frost::sign(&spark_crypto::frost::SignJob {
        message: &round.message,
        secret_key: &secret_key,
        verifying_key: &verifying_key,
        nonce: &user_round1.nonce_bytes,
        user_commitment: &user_round1.commitment_bytes,
        operators: &operator_commitments,
        adaptor_public_key: adaptor33.as_ref(),
    })
    .unwrap();
    assert_eq!(
        our_user_share.as_slice(),
        upstream_user_share.as_slice(),
        "user signature share mismatch"
    );

    // Upstream aggregate.
    let public_keys: HashMap<String, Vec<u8>> = round
        .signer_ids
        .iter()
        .map(|id| (id_hex(id), s.operators[id].verifying_share.clone()))
        .collect();
    let upstream_signature = spark_frost::bridge::aggregate_frost(
        round.message.clone(),
        round.operator_commitments.clone(),
        round.user_commitment.clone(),
        operator_shares.clone(),
        upstream_user_share.clone(),
        public_keys,
        s.user_vk.serialize().unwrap(),
        round.verifying_key.clone(),
        round.adaptor.clone(),
    )
    .unwrap();

    // Our aggregate.
    let operator_shares_ours: Vec<spark_crypto::frost::OperatorShare> = round
        .signer_ids
        .iter()
        .map(|id| spark_crypto::frost::OperatorShare {
            identifier: id_bytes(id),
            commitment: commitment_bytes(&s.operators[id].commitment),
            signature_share: operator_shares[&id_hex(id)].clone().try_into().unwrap(),
            public_key: s.operators[id].verifying_share.clone().try_into().unwrap(),
        })
        .collect();
    let user_public_key: [u8; 33] = s.user_vk.serialize().unwrap().try_into().unwrap();
    let our_signature = spark_crypto::frost::aggregate(&spark_crypto::frost::AggregateJob {
        message: &round.message,
        verifying_key: &verifying_key,
        user_commitment: &user_round1.commitment_bytes,
        user_public_key: &user_public_key,
        user_signature_share: &our_user_share,
        operators: &operator_shares_ours,
        adaptor_public_key: adaptor33.as_ref(),
    })
    .unwrap();
    assert_eq!(
        our_signature.as_slice(),
        upstream_signature.as_slice(),
        "signature mismatch"
    );

    Outcome {
        operator_shares,
        our_user_share,
        upstream_user_share,
        our_signature,
        upstream_signature,
    }
}
