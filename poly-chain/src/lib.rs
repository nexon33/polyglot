//! # Poly Chain — Verify-Only Blockchain Protocol
//!
//! A blockchain where validators check proofs but never execute computation.
//! Computation happens client-side; the chain only verifies `VerifiedProof`
//! attestations and applies state transitions.
//!
//! ## Architecture
//!
//! - **Wallets**: Account balances and state commitments
//! - **Identity**: Tiered KYC (Anonymous → PublicOfficial)
//! - **Compliance**: Auto-generated reports when thresholds exceeded
//! - **Fraud**: Double-spend detection via conflicting state observations
//! - **STP**: Symmetric Transparency Protocol — automatic enforcement for officials
//! - **Validation**: Verify-only pipeline (proof → signature → state → fee)

pub mod block;
pub mod compliance;
pub mod error;
pub mod fee;
pub mod fraud;
pub mod identity;
pub mod primitives;
pub mod stp;
pub mod state;
pub mod transaction;
pub mod validation;
pub mod wallet;

pub mod prelude {
    pub use crate::block::{Block, BlockHeader};
    pub use crate::compliance::{check_compliance, ComplianceReport, ComplianceStatus};
    pub use crate::error::ChainError;
    pub use crate::fee::FeeSchedule;
    pub use crate::fraud::{ConflictType, FraudEvidence, FreezeReason, StateObservation};
    pub use crate::identity::{Tier, IdentityRecord};
    pub use crate::primitives::*;
    pub use crate::stp::{
        ContractStatus, InvestigationAction, InvestigationRecord, InvestigationStatus,
        ServiceContract,
    };
    pub use crate::state::GlobalState;
    pub use crate::transaction::{
        AtomicSwapClaim, AtomicSwapInit, AtomicSwapRefund, SwapStatus, Transaction,
        swap_state_hash,
    };
    pub use crate::validation::validate_transaction;
    pub use crate::wallet::{WalletState, WalletStateCommitment};
}
