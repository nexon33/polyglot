use crate::error::Result;
use crate::types::{Hash, StepWitness, VerifiedProof};

pub mod hash_ivc;
pub mod mock_ivc;

/// Trait for Incrementally Verifiable Computation backends.
///
/// Each backend can produce and verify proofs for a sequence of
/// computation steps. The computation is decomposed into steps,
/// each step's witness is folded into a running accumulator, and
/// at function exit the accumulator is finalized into a constant-size proof.
pub trait IvcBackend {
    /// The running accumulator state.
    type Accumulator: Clone;

    /// Initialize a fresh accumulator for a new verified computation.
    fn init(&self, code_hash: &Hash) -> Self::Accumulator;

    /// Fold a single step's witness into the running accumulator.
    fn fold_step(
        &self,
        accumulator: &mut Self::Accumulator,
        witness: &StepWitness,
    ) -> Result<()>;

    /// Finalize the accumulator into a verifiable proof.
    fn finalize(&self, accumulator: Self::Accumulator) -> Result<VerifiedProof>;

    /// Verify a finalized proof against expected input/output hashes.
    fn verify(
        &self,
        proof: &VerifiedProof,
        input_hash: &Hash,
        output_hash: &Hash,
    ) -> Result<bool>;

    /// Whether this backend is quantum resistant.
    fn is_quantum_resistant(&self) -> bool;
}
