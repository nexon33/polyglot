use crate::error::Result;
use crate::ivc::IvcBackend;
use crate::types::{Hash, PrivacyMode, StepWitness, VerifiedProof, ZERO_HASH};

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
    pub privacy_mode: PrivacyMode,
}

impl IvcBackend for MockIvc {
    type Accumulator = MockAccumulator;

    fn init(&self, _code_hash: &Hash, privacy: PrivacyMode) -> Self::Accumulator {
        MockAccumulator {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            step_count: 0,
            privacy_mode: privacy,
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
        let privacy = accumulator.privacy_mode;

        // In private modes, zero out the hashes that should be hidden
        let input_hash = if privacy.hides_inputs() {
            ZERO_HASH
        } else {
            accumulator.input_hash
        };
        let output_hash = if privacy.hides_outputs() {
            ZERO_HASH
        } else {
            accumulator.output_hash
        };

        Ok(VerifiedProof::Mock {
            input_hash,
            output_hash,
            privacy_mode: privacy,
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
        let mut acc = backend.init(&ZERO_HASH, PrivacyMode::Transparent);

        let witness = StepWitness {
            state_before: hash_data(b"before"),
            state_after: hash_data(b"after"),
            step_inputs: hash_data(b"inputs"),
        };
        backend.fold_step(&mut acc, &witness).unwrap();

        let proof = backend.finalize(acc).unwrap();
        assert!(backend.verify(&proof, &ZERO_HASH, &ZERO_HASH).unwrap());
    }

    #[test]
    fn test_mock_ivc_private_mode() {
        let backend = MockIvc;
        let mut acc = backend.init(&ZERO_HASH, PrivacyMode::Private);

        let witness = StepWitness {
            state_before: hash_data(b"secret_input"),
            state_after: hash_data(b"secret_output"),
            step_inputs: hash_data(b"inputs"),
        };
        backend.fold_step(&mut acc, &witness).unwrap();

        let proof = backend.finalize(acc).unwrap();

        match &proof {
            VerifiedProof::Mock {
                input_hash,
                output_hash,
                privacy_mode,
            } => {
                assert_eq!(*privacy_mode, PrivacyMode::Private);
                // Both hashes zeroed in full private mode
                assert_eq!(*input_hash, ZERO_HASH);
                assert_eq!(*output_hash, ZERO_HASH);
            }
            _ => panic!("wrong proof type"),
        }
    }

    #[test]
    fn test_mock_ivc_private_inputs_mode() {
        let backend = MockIvc;
        let mut acc = backend.init(&ZERO_HASH, PrivacyMode::PrivateInputs);

        let real_output = hash_data(b"visible_output");
        let witness = StepWitness {
            state_before: hash_data(b"secret_input"),
            state_after: real_output,
            step_inputs: hash_data(b"inputs"),
        };
        backend.fold_step(&mut acc, &witness).unwrap();

        let proof = backend.finalize(acc).unwrap();

        match &proof {
            VerifiedProof::Mock {
                input_hash,
                output_hash,
                privacy_mode,
            } => {
                assert_eq!(*privacy_mode, PrivacyMode::PrivateInputs);
                // Input hidden, output visible
                assert_eq!(*input_hash, ZERO_HASH);
                assert_eq!(*output_hash, real_output);
            }
            _ => panic!("wrong proof type"),
        }
    }
}
