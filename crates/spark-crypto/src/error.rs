//! Error type shared by all modules, with the numeric codes used by the C ABI.

use core::fmt;

/// Failure of a cryptographic operation.
///
/// Error messages never contain input bytes: secret material must not leak
/// through logs, and even public inputs are kept out of messages so the FFI
/// layer can forward `code()` without review.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Error {
    /// An input had an unexpected length.
    Length,
    /// A byte string did not decode as a valid secp256k1 scalar.
    InvalidScalar,
    /// A byte string did not decode as a valid secp256k1 point.
    InvalidPoint,
    /// A numeric parameter was out of range (threshold, share count).
    OutOfRange,
    /// The FROST protocol rejected the inputs (bad share, missing commitment).
    Frost,
    /// Authenticated decryption failed.
    Decrypt,
    /// An internal invariant failed.
    Internal,
}

impl Error {
    /// Stable numeric code, part of the C ABI contract (`qntx_spark.h`).
    /// Code 4 is reserved for protobuf decode failures in `spark-ffi`.
    #[must_use]
    pub const fn code(self) -> i32 {
        match self {
            Self::Length => 1,
            Self::InvalidScalar => 2,
            Self::InvalidPoint => 3,
            Self::OutOfRange => 5,
            Self::Frost => 6,
            Self::Decrypt => 7,
            Self::Internal => 8,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Length => "input has an unexpected length",
            Self::InvalidScalar => "input is not a valid scalar",
            Self::InvalidPoint => "input is not a valid curve point",
            Self::OutOfRange => "parameter is out of range",
            Self::Frost => "FROST protocol failure",
            Self::Decrypt => "decryption authentication failed",
            Self::Internal => "internal error",
        };
        f.write_str(message)
    }
}

impl std::error::Error for Error {}
