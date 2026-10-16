//! Wire format of the batched FROST requests exchanged through the C ABI.
//!
//! Hand-written `prost` encodings of `proto/ffi/qntx_spark_ffi.proto`
//! (`package qntx.spark.ffi`); no `build.rs`, no `protoc` at build time.
//! Field numbers are part of the ABI contract — cross-language parity with
//! the protobuf-es output is enforced by the `ffi-sign`/`ffi-aggregate`
//! vectors.

/// Compressed `hiding‖binding` nonce-commitment points, 33 bytes each.
#[derive(Clone, ::prost::Message)]
pub struct Commitment {
    /// Compressed hiding commitment point.
    #[prost(bytes = "vec", tag = "1")]
    pub hiding: Vec<u8>,
    /// Compressed binding commitment point.
    #[prost(bytes = "vec", tag = "2")]
    pub binding: Vec<u8>,
}

/// One operator's round-1 commitment.
#[derive(Clone, ::prost::Message)]
pub struct OperatorCommitment {
    /// The operator's 32-byte serialized FROST identifier scalar.
    #[prost(bytes = "vec", tag = "1")]
    pub identifier: Vec<u8>,
    /// Compressed `hiding‖binding` commitment points.
    #[prost(message, optional, tag = "2")]
    pub commitment: Option<Commitment>,
}

/// A single user-side FROST signing job.
#[derive(Clone, ::prost::Message)]
pub struct FrostSignJob {
    /// Message bytes to sign (a 32-byte sighash upstream).
    #[prost(bytes = "vec", tag = "1")]
    pub message: Vec<u8>,
    /// The user's private key (upstream `key_package.secret_share`).
    #[prost(bytes = "vec", tag = "2")]
    pub secret_key: Vec<u8>,
    /// The combined verifying key, compressed.
    #[prost(bytes = "vec", tag = "3")]
    pub verifying_key: Vec<u8>,
    /// The user's `hiding‖binding` nonces from `qs_frost_commit`, 64 bytes.
    #[prost(bytes = "vec", tag = "4")]
    pub nonce: Vec<u8>,
    /// The user's compressed `hiding‖binding` commitments.
    #[prost(message, optional, tag = "5")]
    pub user_commitment: Option<Commitment>,
    /// The participating operators' commitments.
    #[prost(message, repeated, tag = "6")]
    pub operator_commitments: Vec<OperatorCommitment>,
    /// Optional adaptor point, compressed; empty means no adaptor.
    #[prost(bytes = "vec", tag = "7")]
    pub adaptor_public_key: Vec<u8>,
}

/// Batched [`FrostSignJob`]s.
#[derive(Clone, ::prost::Message)]
pub struct FrostSignRequest {
    /// Jobs to sign, in order.
    #[prost(message, repeated, tag = "1")]
    pub jobs: Vec<FrostSignJob>,
}

/// One 32-byte signature share per job, in job order.
#[derive(Clone, ::prost::Message)]
pub struct FrostSignResponse {
    /// The signature shares.
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub signature_shares: Vec<Vec<u8>>,
}

/// One operator's contribution to an aggregation job.
#[derive(Clone, ::prost::Message)]
pub struct OperatorShare {
    /// The operator's 32-byte serialized FROST identifier scalar.
    #[prost(bytes = "vec", tag = "1")]
    pub identifier: Vec<u8>,
    /// Compressed `hiding‖binding` commitment points.
    #[prost(message, optional, tag = "2")]
    pub commitment: Option<Commitment>,
    /// The operator's 32-byte signature share.
    #[prost(bytes = "vec", tag = "3")]
    pub signature_share: Vec<u8>,
    /// The operator's verifying share, compressed.
    #[prost(bytes = "vec", tag = "4")]
    pub public_key: Vec<u8>,
}

/// A single user-side FROST aggregation job.
#[derive(Clone, ::prost::Message)]
pub struct FrostAggregateJob {
    /// The message that was signed.
    #[prost(bytes = "vec", tag = "1")]
    pub message: Vec<u8>,
    /// The combined verifying key, compressed.
    #[prost(bytes = "vec", tag = "2")]
    pub verifying_key: Vec<u8>,
    /// The user's compressed `hiding‖binding` commitments.
    #[prost(message, optional, tag = "3")]
    pub user_commitment: Option<Commitment>,
    /// The user's verifying share, compressed.
    #[prost(bytes = "vec", tag = "4")]
    pub user_public_key: Vec<u8>,
    /// The user's 32-byte signature share.
    #[prost(bytes = "vec", tag = "5")]
    pub user_signature_share: Vec<u8>,
    /// The participating operators' shares.
    #[prost(message, repeated, tag = "6")]
    pub operators: Vec<OperatorShare>,
    /// Optional adaptor point, compressed; empty means no adaptor.
    #[prost(bytes = "vec", tag = "7")]
    pub adaptor_public_key: Vec<u8>,
}

/// Batched [`FrostAggregateJob`]s.
#[derive(Clone, ::prost::Message)]
pub struct FrostAggregateRequest {
    /// Jobs to aggregate, in order.
    #[prost(message, repeated, tag = "1")]
    pub jobs: Vec<FrostAggregateJob>,
}

/// One 64-byte Schnorr signature per job, in job order.
#[derive(Clone, ::prost::Message)]
pub struct FrostAggregateResponse {
    /// The aggregated signatures.
    #[prost(bytes = "vec", repeated, tag = "1")]
    pub signatures: Vec<Vec<u8>>,
}
