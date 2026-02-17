//! # Poly Verified Execution Runtime
//!
//! Compiler-integrated verified computation for the Poly programming language.
//!
//! Mark a function `#[verified]`. The compiler does the rest. Every result
//! carries a mathematical proof that it was computed correctly.
//!
//! ## Core Types
//!
//! - [`Verified<T>`](verified_type::Verified) — A value with a proof of correct computation
//! - [`VerifiedError`](error::VerifiedError) — Proven execution errors
//! - [`FixedPoint`](fixed_point::FixedPoint) — Deterministic fixed-point arithmetic
//!
//! ## IVC Backends
//!
//! - [`HashIvc`](ivc::hash_ivc::HashIvc) — Quantum-resistant hash-chain IVC
//! - [`MockIvc`](ivc::mock_ivc::MockIvc) — Testing backend

pub mod crypto;
pub mod disclosure;
pub mod error;
pub mod fixed_point;
pub mod ivc;
pub mod proof_composition;
pub mod proof_serialize;
pub mod step;
pub mod types;
pub mod verified_type;

/// Prelude: commonly used types for verified execution.
pub mod prelude {
    pub use crate::disclosure::{
        create_disclosure, create_disclosure_range, verify_disclosure, DisclosedToken, Disclosure,
    };
    pub use crate::error::VerifiedError;
    pub use crate::fixed_point::FixedPoint;
    pub use crate::ivc::hash_ivc::HashIvc;
    pub use crate::ivc::mock_ivc::MockIvc;
    pub use crate::ivc::IvcBackend;
    pub use crate::step::StepFunction;
    pub use crate::types::{Hash, PrivacyMode, StepWitness, VerifiedProof};
    pub use crate::verified_type::Verified;
}
