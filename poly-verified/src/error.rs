use thiserror::Error;

/// Internal proof system errors
#[derive(Debug, Error)]
pub enum ProofSystemError {
    #[error("invalid proof: {0}")]
    InvalidProof(String),

    #[error("merkle proof verification failed")]
    MerkleVerificationFailed,

    #[error("root mismatch: proof root does not match commitment root")]
    RootMismatch,

    #[error("transition hash mismatch")]
    TransitionHashMismatch,

    #[error("previous state hash mismatch")]
    PreviousStateHashMismatch,

    #[error("input hash mismatch")]
    InputHashMismatch,

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),

    #[error("index out of bounds: {index} >= {length}")]
    IndexOutOfBounds { index: u64, length: u64 },

    #[error("code integrity check failed")]
    CodeIntegrityFailed,

    #[error("empty commitment")]
    EmptyCommitment,

    #[error("IVC fold error: {0}")]
    IvcFoldError(String),

    #[error("proof verification failed: {0}")]
    ProofVerificationFailed(String),
}

pub type Result<T> = std::result::Result<T, ProofSystemError>;

/// User-facing verified execution errors.
/// These are "proven errors" — the proof certifies that the computation
/// correctly determined it could not complete.
#[derive(Debug, Clone, Error, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VerifiedError {
    #[error("division by zero")]
    DivisionByZero,

    #[error("integer overflow")]
    Overflow,

    #[error("bound exceeded: ran {actual} iterations, max was {max}")]
    BoundExceeded { max: u64, actual: u64 },

    #[error("assertion failed: {0}")]
    AssertionFailed(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("GPU mismatch at layer {0}")]
    GpuMismatch(usize),
}
