use thiserror::Error;

/// All errors that can occur during chain validation and state transitions.
#[derive(Debug, Error)]
pub enum ChainError {
    #[error("invalid proof: {0}")]
    InvalidProof(String),

    #[error("invalid signature")]
    InvalidSignature,

    #[error("state hash mismatch: expected {expected}, got {actual}")]
    StateHashMismatch { expected: String, actual: String },

    #[error("insufficient balance: need {needed}, have {available}")]
    InsufficientBalance { needed: u64, available: u64 },

    #[error("invalid nonce: expected {expected}, got {actual}")]
    InvalidNonce { expected: u64, actual: u64 },

    #[error("account not found: {0}")]
    AccountNotFound(String),

    #[error("identity not found: {0}")]
    IdentityNotFound(String),

    #[error("tier violation: {0}")]
    TierViolation(String),

    #[error("compliance violation: {0}")]
    ComplianceViolation(String),

    #[error("fraud detected: {0}")]
    FraudDetected(String),

    #[error("account frozen: {0}")]
    AccountFrozen(String),

    #[error("invalid encoding: {0}")]
    InvalidEncoding(String),

    #[error("duplicate identity hash")]
    DuplicateIdentity,

    #[error("stp error: {0}")]
    STPError(String),

    #[error("proof system error: {0}")]
    ProofSystem(#[from] poly_verified::error::ProofSystemError),
}

pub type Result<T> = std::result::Result<T, ChainError>;
