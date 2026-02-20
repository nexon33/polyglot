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

    #[error("swap not found: {0}")]
    SwapNotFound(String),

    #[error("swap already exists: {0}")]
    SwapAlreadyExists(String),

    #[error("swap not expired yet")]
    SwapNotExpired,

    #[error("swap has expired")]
    SwapExpired,

    #[error("invalid hash preimage")]
    InvalidPreimage,

    #[error("self-transfer not allowed")]
    SelfTransfer,

    #[error("zero amount transfer")]
    ZeroAmount,

    #[error("invalid timestamp: outside acceptable drift window")]
    InvalidTimestamp,

    #[error("block height overflow")]
    BlockHeightOverflow,

    #[error("nonce overflow: account nonce would exceed u64::MAX")]
    NonceOverflow,

    #[error("backup too large: {size} bytes (max {max})")]
    BackupTooLarge { size: usize, max: usize },

    #[error("invalid swap ID derivation")]
    InvalidSwapId,

    #[error("unauthorized STP action: {0}")]
    UnauthorizedSTPAction(String),

    #[error("duplicate fraud evidence: {0}")]
    DuplicateFraudEvidence(String),

    #[error("duplicate STP contract: official already has a registered contract")]
    DuplicateSTPContract,

    #[error("proof system error: {0}")]
    ProofSystem(#[from] poly_verified::error::ProofSystemError),
}

pub type Result<T> = std::result::Result<T, ChainError>;
