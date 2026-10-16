//! Safe request handling behind the C ABI: protobuf decoding, field-length
//! checks, conversion into `spark-crypto` jobs, and secret wiping. No
//! pointers cross this module — `abi` hands in byte slices and receives
//! `Result<Vec<u8>, i32>`.

use prost::Message as _;
use spark_crypto::Error;
use spark_crypto::frost;
use zeroize::Zeroize;

use crate::messages;

/// Return code for protobuf decode failures (code 4 has no `Error`
/// counterpart — `spark-crypto` never sees protobuf).
const DECODE_ERROR: i32 = 4;
/// Maximum jobs per batched request.
const MAX_JOBS: usize = 256;
/// `frost_commit` random input cap: `MAX_JOBS` × 32 bytes.
const MAX_RANDOM: usize = MAX_JOBS * 32;

fn as32(bytes: &[u8]) -> Result<&[u8; 32], i32> {
    bytes.try_into().map_err(|_| Error::Length.code())
}

fn as33(bytes: &[u8]) -> Result<&[u8; 33], i32> {
    bytes.try_into().map_err(|_| Error::Length.code())
}

fn as64(bytes: &[u8]) -> Result<&[u8; 64], i32> {
    bytes.try_into().map_err(|_| Error::Length.code())
}

/// A `Commitment` submessage flattened to the 66-byte `hiding‖binding`
/// layout; a missing submessage or wrong point length is a length error.
fn commitment66(message: Option<&messages::Commitment>) -> Result<[u8; 66], i32> {
    let message = message.ok_or_else(|| Error::Length.code())?;
    let hiding = as33(&message.hiding)?;
    let binding = as33(&message.binding)?;
    let mut out = [0u8; 66];
    let (h, b) = out.split_at_mut(33);
    h.copy_from_slice(hiding);
    b.copy_from_slice(binding);
    Ok(out)
}

/// Empty adaptor bytes mean `None`; a present adaptor must be compressed.
fn adaptor_opt(bytes: &[u8]) -> Result<Option<[u8; 33]>, i32> {
    if bytes.is_empty() {
        return Ok(None);
    }
    Ok(Some(*as33(bytes)?))
}

/// Zeroizes the `secret_key` and `nonce` of every decoded job on drop,
/// including on error paths. All other request fields are public protocol
/// data — messages, keys, commitments, identifiers, and signature shares —
/// and need no wipe. An aggregation request carries no secrets at all.
struct SignRequestWipe(messages::FrostSignRequest);

impl Drop for SignRequestWipe {
    fn drop(&mut self) {
        for job in &mut self.0.jobs {
            job.secret_key.zeroize();
            job.nonce.zeroize();
        }
    }
}

pub(crate) fn frost_commit(hedge: &[u8], random: &[u8]) -> Result<Vec<u8>, i32> {
    let hedge = as32(hedge)?;
    if random.is_empty() || !random.len().is_multiple_of(32) {
        return Err(Error::Length.code());
    }
    if random.len() > MAX_RANDOM {
        return Err(Error::OutOfRange.code());
    }
    let mut out = Vec::with_capacity(random.len() / 32 * 130);
    for seed in random.chunks(32) {
        let commitment = frost::commit(hedge, as32(seed)?).map_err(Error::code)?;
        out.extend_from_slice(&commitment.to_bytes());
    }
    Ok(out)
}

pub(crate) fn frost_sign(request: &[u8]) -> Result<Vec<u8>, i32> {
    let request =
        SignRequestWipe(messages::FrostSignRequest::decode(request).map_err(|_| DECODE_ERROR)?);
    let jobs = &request.0.jobs;
    if jobs.is_empty() || jobs.len() > MAX_JOBS {
        return Err(Error::OutOfRange.code());
    }

    // Owned fixed-size conversions stay alive for the `SignJob` borrows.
    let mut op_sets = Vec::with_capacity(jobs.len());
    let mut user_commitments = Vec::with_capacity(jobs.len());
    let mut adaptors = Vec::with_capacity(jobs.len());
    for job in jobs {
        let mut ops = Vec::with_capacity(job.operator_commitments.len());
        for op in &job.operator_commitments {
            ops.push(frost::OperatorCommitment {
                identifier: *as32(&op.identifier)?,
                commitment: commitment66(op.commitment.as_ref())?,
            });
        }
        op_sets.push(ops);
        user_commitments.push(commitment66(job.user_commitment.as_ref())?);
        adaptors.push(adaptor_opt(&job.adaptor_public_key)?);
    }

    let mut shares = Vec::with_capacity(jobs.len());
    for ((job, ops), (user_commitment, adaptor)) in jobs
        .iter()
        .zip(&op_sets)
        .zip(user_commitments.iter().zip(&adaptors))
    {
        let share = frost::sign(&frost::SignJob {
            message: job.message.as_slice(),
            secret_key: as32(&job.secret_key)?,
            verifying_key: as33(&job.verifying_key)?,
            nonce: as64(&job.nonce)?,
            user_commitment,
            operators: ops,
            adaptor_public_key: adaptor.as_ref(),
        })
        .map_err(Error::code)?;
        shares.push(share.to_vec());
    }
    Ok(messages::FrostSignResponse {
        signature_shares: shares,
    }
    .encode_to_vec())
}

pub(crate) fn frost_aggregate(request: &[u8]) -> Result<Vec<u8>, i32> {
    let request = messages::FrostAggregateRequest::decode(request).map_err(|_| DECODE_ERROR)?;
    let jobs = &request.jobs;
    if jobs.is_empty() || jobs.len() > MAX_JOBS {
        return Err(Error::OutOfRange.code());
    }

    let mut op_sets = Vec::with_capacity(jobs.len());
    let mut user_commitments = Vec::with_capacity(jobs.len());
    let mut adaptors = Vec::with_capacity(jobs.len());
    for job in jobs {
        let mut ops = Vec::with_capacity(job.operators.len());
        for op in &job.operators {
            ops.push(frost::OperatorShare {
                identifier: *as32(&op.identifier)?,
                commitment: commitment66(op.commitment.as_ref())?,
                signature_share: *as32(&op.signature_share)?,
                public_key: *as33(&op.public_key)?,
            });
        }
        op_sets.push(ops);
        user_commitments.push(commitment66(job.user_commitment.as_ref())?);
        adaptors.push(adaptor_opt(&job.adaptor_public_key)?);
    }

    let mut signatures = Vec::with_capacity(jobs.len());
    for ((job, ops), (user_commitment, adaptor)) in jobs
        .iter()
        .zip(&op_sets)
        .zip(user_commitments.iter().zip(&adaptors))
    {
        let signature = frost::aggregate(&frost::AggregateJob {
            message: job.message.as_slice(),
            verifying_key: as33(&job.verifying_key)?,
            user_commitment,
            user_public_key: as33(&job.user_public_key)?,
            user_signature_share: as32(&job.user_signature_share)?,
            operators: ops,
            adaptor_public_key: adaptor.as_ref(),
        })
        .map_err(Error::code)?;
        signatures.push(signature.to_vec());
    }
    Ok(messages::FrostAggregateResponse { signatures }.encode_to_vec())
}

pub(crate) fn ecies_encrypt(
    public_key: &[u8],
    message: &[u8],
    random: &[u8; 32],
) -> Result<Vec<u8>, i32> {
    spark_crypto::ecies::encrypt(public_key, message, random).map_err(Error::code)
}

/// `ecies::decrypt` returns an exact-capacity `Vec`, so the caller's
/// `into_boxed_slice` never reallocates a second copy of the secret
/// plaintext.
pub(crate) fn ecies_decrypt(secret_key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, i32> {
    spark_crypto::ecies::decrypt(secret_key, ciphertext).map_err(Error::code)
}

/// `Split::to_bytes` builds an exact-capacity `Vec`, so the secret shares
/// likewise pass to the caller without a reallocation copy.
pub(crate) fn split_secret_with_proofs(
    secret: &[u8; 32],
    threshold: u32,
    shares: u32,
    random: &[u8; 32],
) -> Result<Vec<u8>, i32> {
    let threshold = usize::try_from(threshold).unwrap_or(usize::MAX);
    let shares = usize::try_from(shares).unwrap_or(usize::MAX);
    spark_crypto::vss::split_secret_with_proofs(secret, threshold, shares, random)
        .map(|split| split.to_bytes())
        .map_err(Error::code)
}
