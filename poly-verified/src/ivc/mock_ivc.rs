use crate::error::Result;
use crate::ivc::IvcBackend;
use crate::types::{Hash, StepWitness, VerifiedProof, ZERO_HASH};

/// Mock IVC backend for testing.
///
/// Always produces valid proofs. Used in unit tests and development.
pub struct MockIvc;

/// Mock accumulator: just tracks hashes.
#[derive(Clone, Debug)]
pub struct MockAccumulator {
    pub input_hash: Hash,
    pub output_hash: Hash,
    pub step_count: u64,
}

impl IvcBackend for MockIvc {
    type Accumulator = MockAccumulator;

    fn init(&self, _code_hash: &Hash) -> Self::Accumulator {
        MockAccumulator {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            step_count: 0,
        }
    }

    fn fold_step(
        &self,
        accumulator: &mut Self::Accumulator,
        witness: &StepWitness,
    ) -> Result<()> {
        if accumulator.step_count == 0 {
            accumulator.input_hash = witness.state_before;
        }
        accumulator.output_hash = witness.state_after;
        accumulator.step_count += 1;
        Ok(())
    }

    fn finalize(&self, accumulator: Self::Accumulator) -> Result<VerifiedProof> {
        Ok(VerifiedProof::Mock {
            input_hash: accumulator.input_hash,
            output_hash: accumulator.output_hash,
        })
    }

    fn verify(
        &self,
        proof: &VerifiedProof,
        _input_hash: &Hash,
        _output_hash: &Hash,
    ) -> Result<bool> {
        match proof {
            VerifiedProof::Mock { .. } => Ok(true),
            _ => Ok(false),
        }
    }

    fn is_quantum_resistant(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::hash_data;

    #[test]
    fn test_mock_ivc_always_succeeds() {
        let backend = MockIvc;
        let mut acc = backend.init(&ZERO_HASH);

        let witness = StepWitness {
            state_before: hash_data(b"before"),
            state_after: hash_data(b"after"),
            step_inputs: hash_data(b"inputs"),
        };
        backend.fold_step(&mut acc, &witness).unwrap();

        let proof = backend.finalize(acc).unwrap();
        assert!(backend.verify(&proof, &ZERO_HASH, &ZERO_HASH).unwrap());
    }
}
