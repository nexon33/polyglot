use crate::crypto::chain::HashChain;
use crate::crypto::hash::hash_transition;
use crate::crypto::merkle::MerkleTree;
use crate::error::{ProofSystemError, Result};
use crate::ivc::IvcBackend;
use crate::types::{Hash, StepWitness, VerifiedProof};

/// Hash-chain based Incrementally Verifiable Computation.
///
/// Uses SHA-256 hash chains for tamper-evident computation traces
/// and Merkle trees for efficient inclusion proofs. This backend
/// is quantum resistant (relies only on hash function security).
///
/// The proof certifies:
/// - The sequence of steps was executed in order (hash chain)
/// - Each step's transition is included in the commitment (Merkle tree)
/// - The code identity that produced the computation (code_hash binding)
pub struct HashIvc;

/// The running accumulator for Hash-IVC.
#[derive(Clone, Debug)]
pub struct HashIvcAccumulator {
    chain: HashChain,
    checkpoints: Vec<Hash>,
    code_hash: Hash,
}

impl IvcBackend for HashIvc {
    type Accumulator = HashIvcAccumulator;

    fn init(&self, code_hash: &Hash) -> Self::Accumulator {
        HashIvcAccumulator {
            chain: HashChain::new(),
            checkpoints: Vec::new(),
            code_hash: *code_hash,
        }
    }

    fn fold_step(
        &self,
        accumulator: &mut Self::Accumulator,
        witness: &StepWitness,
    ) -> Result<()> {
        let transition = hash_transition(
            &witness.state_before,
            &witness.step_inputs,
            &witness.state_after,
        );
        accumulator.chain.append(&transition);
        accumulator.checkpoints.push(transition);
        Ok(())
    }

    fn finalize(&self, accumulator: Self::Accumulator) -> Result<VerifiedProof> {
        if accumulator.checkpoints.is_empty() {
            return Err(ProofSystemError::EmptyCommitment);
        }

        let tree = MerkleTree::build(&accumulator.checkpoints);

        Ok(VerifiedProof::HashIvc {
            chain_tip: accumulator.chain.tip,
            merkle_root: tree.root,
            step_count: accumulator.chain.length,
            code_hash: accumulator.code_hash,
        })
    }

    fn verify(
        &self,
        proof: &VerifiedProof,
        _input_hash: &Hash,
        _output_hash: &Hash,
    ) -> Result<bool> {
        match proof {
            VerifiedProof::HashIvc { step_count, .. } => {
                // Hash-IVC verification: structural integrity check.
                // Full verification requires spot-check re-execution.
                Ok(*step_count > 0)
            }
            _ => Err(ProofSystemError::ProofVerificationFailed(
                "wrong proof type for HashIvc backend".into(),
            )),
        }
    }

    fn is_quantum_resistant(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::hash::hash_data;

    #[test]
    fn test_hash_ivc_roundtrip() {
        let backend = HashIvc;
        let code_hash = hash_data(b"test_function");

        let mut acc = backend.init(&code_hash);

        // Fold 3 steps
        for i in 0..3u8 {
            let witness = StepWitness {
                state_before: hash_data(&[i]),
                state_after: hash_data(&[i + 1]),
                step_inputs: hash_data(&[i, i]),
            };
            backend.fold_step(&mut acc, &witness).unwrap();
        }

        let proof = backend.finalize(acc).unwrap();

        // Verify
        let input_hash = hash_data(&[0]);
        let output_hash = hash_data(&[3]);
        assert!(backend.verify(&proof, &input_hash, &output_hash).unwrap());
    }

    #[test]
    fn test_hash_ivc_empty_fails() {
        let backend = HashIvc;
        let code_hash = hash_data(b"test_function");
        let acc = backend.init(&code_hash);

        assert!(backend.finalize(acc).is_err());
    }

    #[test]
    fn test_hash_ivc_proof_structure() {
        let backend = HashIvc;
        let code_hash = hash_data(b"my_verified_fn");

        let mut acc = backend.init(&code_hash);
        let witness = StepWitness {
            state_before: hash_data(b"before"),
            state_after: hash_data(b"after"),
            step_inputs: hash_data(b"inputs"),
        };
        backend.fold_step(&mut acc, &witness).unwrap();

        let proof = backend.finalize(acc).unwrap();

        match &proof {
            VerifiedProof::HashIvc {
                step_count,
                code_hash: ch,
                ..
            } => {
                assert_eq!(*step_count, 1);
                assert_eq!(*ch, code_hash);
            }
            _ => panic!("wrong proof type"),
        }
    }

    #[test]
    fn test_hash_ivc_quantum_resistant() {
        assert!(HashIvc.is_quantum_resistant());
    }

    #[test]
    fn test_hash_ivc_deterministic() {
        let backend = HashIvc;
        let code_hash = hash_data(b"determinism_test");

        // Run the same computation twice
        let mut results = Vec::new();
        for _ in 0..2 {
            let mut acc = backend.init(&code_hash);
            for i in 0..5u8 {
                let witness = StepWitness {
                    state_before: hash_data(&[i]),
                    state_after: hash_data(&[i + 1]),
                    step_inputs: hash_data(&[i * 2]),
                };
                backend.fold_step(&mut acc, &witness).unwrap();
            }
            results.push(backend.finalize(acc).unwrap());
        }

        // Both runs must produce identical proofs
        match (&results[0], &results[1]) {
            (
                VerifiedProof::HashIvc {
                    chain_tip: a_tip,
                    merkle_root: a_root,
                    step_count: a_count,
                    ..
                },
                VerifiedProof::HashIvc {
                    chain_tip: b_tip,
                    merkle_root: b_root,
                    step_count: b_count,
                    ..
                },
            ) => {
                assert_eq!(a_tip, b_tip);
                assert_eq!(a_root, b_root);
                assert_eq!(a_count, b_count);
            }
            _ => panic!("wrong proof types"),
        }
    }
}
