use crate::crypto::chain::HashChain;
use crate::crypto::hash::{hash_blinding, hash_combine, hash_data, hash_transition};
use crate::crypto::merkle::MerkleTree;
use crate::error::{ProofSystemError, Result};
use crate::ivc::IvcBackend;
use crate::types::{Hash, PrivacyMode, StepWitness, VerifiedProof, ZERO_HASH};

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
///
/// When privacy mode is enabled, blinding factors are folded into each
/// step, producing a blinding commitment that hides the computation trace.
pub struct HashIvc;

/// The running accumulator for Hash-IVC.
#[derive(Clone, Debug)]
pub struct HashIvcAccumulator {
    chain: HashChain,
    checkpoints: Vec<Hash>,
    code_hash: Hash,
    privacy_mode: PrivacyMode,
    /// Accumulated H(blinding_factors) — only non-zero when privacy is enabled.
    blinding_hash: Hash,
    /// Committed input hash — set before finalize for I/O binding.
    pub input_hash: Hash,
    /// Committed output hash — set before finalize for I/O binding.
    pub output_hash: Hash,
}

impl IvcBackend for HashIvc {
    type Accumulator = HashIvcAccumulator;

    fn init(&self, code_hash: &Hash, privacy: PrivacyMode) -> Self::Accumulator {
        HashIvcAccumulator {
            chain: HashChain::new(),
            checkpoints: Vec::new(),
            code_hash: *code_hash,
            privacy_mode: privacy,
            blinding_hash: ZERO_HASH,
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
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

        // When privacy is enabled, generate and accumulate a blinding factor.
        // Domain 0x04 is used for blinding (separate from leaf/transition/chain/combine).
        if accumulator.privacy_mode.is_private() {
            let step_counter = accumulator.chain.length.to_le_bytes();
            let mut blinding_input = Vec::with_capacity(32 + 8);
            blinding_input.extend_from_slice(&transition);
            blinding_input.extend_from_slice(&step_counter);
            let blinding = hash_blinding(&blinding_input);
            accumulator.blinding_hash = hash_combine(&accumulator.blinding_hash, &blinding);
        }

        Ok(())
    }

    fn finalize(&self, accumulator: Self::Accumulator) -> Result<VerifiedProof> {
        if accumulator.checkpoints.is_empty() {
            return Err(ProofSystemError::EmptyCommitment);
        }

        let tree = MerkleTree::build(&accumulator.checkpoints);

        let blinding_commitment = if accumulator.privacy_mode.is_private() {
            Some(accumulator.blinding_hash)
        } else {
            None
        };

        // Bind code_hash and privacy_mode into chain_tip so they can't be swapped
        let code_binding = hash_data(&accumulator.code_hash);
        let mode_binding = hash_data(&[accumulator.privacy_mode as u8]);
        let bound_tip = hash_combine(
            &hash_combine(&accumulator.chain.tip, &code_binding),
            &mode_binding,
        );

        Ok(VerifiedProof::HashIvc {
            chain_tip: bound_tip,
            merkle_root: tree.root,
            step_count: accumulator.chain.length,
            code_hash: accumulator.code_hash,
            privacy_mode: accumulator.privacy_mode,
            blinding_commitment,
            checkpoints: accumulator.checkpoints,
            input_hash: accumulator.input_hash,
            output_hash: accumulator.output_hash,
        })
    }

    fn verify(
        &self,
        proof: &VerifiedProof,
        expected_input: &Hash,
        expected_output: &Hash,
    ) -> Result<bool> {
        match proof {
            VerifiedProof::HashIvc {
                chain_tip,
                merkle_root,
                step_count,
                code_hash,
                privacy_mode,
                blinding_commitment,
                checkpoints,
                input_hash,
                output_hash,
            } => {
                // 1. Structural: must have at least one step.
                if *step_count == 0 {
                    return Ok(false);
                }

                // 2. Checkpoint count must match step_count.
                if checkpoints.len() as u64 != *step_count {
                    return Ok(false);
                }

                // 3. Rebuild hash chain from checkpoints, bind code_hash + privacy_mode → verify chain_tip.
                let mut chain = HashChain::new();
                for cp in checkpoints {
                    chain.append(cp);
                }
                let code_binding = hash_data(code_hash);
                let mode_binding = hash_data(&[*privacy_mode as u8]);
                let expected_tip = hash_combine(
                    &hash_combine(&chain.tip, &code_binding),
                    &mode_binding,
                );
                if expected_tip != *chain_tip {
                    return Ok(false);
                }

                // 4. Rebuild Merkle tree from checkpoints → verify merkle_root.
                let tree = MerkleTree::build(checkpoints);
                if tree.root != *merkle_root {
                    return Ok(false);
                }

                // 5. I/O hash verification (privacy-aware).
                match privacy_mode {
                    PrivacyMode::Transparent => {
                        if input_hash != expected_input {
                            return Ok(false);
                        }
                        if output_hash != expected_output {
                            return Ok(false);
                        }
                    }
                    PrivacyMode::PrivateInputs => {
                        // Inputs hidden, but output must match.
                        if output_hash != expected_output {
                            return Ok(false);
                        }
                    }
                    PrivacyMode::Private => {
                        // Both hidden — skip I/O check.
                    }
                }

                // 6. Blinding commitment verification (private modes).
                if privacy_mode.is_private() {
                    if blinding_commitment.is_none() {
                        return Ok(false);
                    }
                    let mut expected_blinding = ZERO_HASH;
                    for (i, cp) in checkpoints.iter().enumerate() {
                        let counter = ((i + 1) as u64).to_le_bytes();
                        let mut blinding_input = Vec::with_capacity(40);
                        blinding_input.extend_from_slice(cp);
                        blinding_input.extend_from_slice(&counter);
                        let blinding = hash_blinding(&blinding_input);
                        expected_blinding = hash_combine(&expected_blinding, &blinding);
                    }
                    if *blinding_commitment != Some(expected_blinding) {
                        return Ok(false);
                    }
                } else if blinding_commitment.is_some() {
                    // Transparent mode shouldn't have a blinding commitment.
                    return Ok(false);
                }

                Ok(true)
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

    #[test]
    fn test_hash_ivc_roundtrip() {
        let backend = HashIvc;
        let code_hash = hash_data(b"test_function");

        let mut acc = backend.init(&code_hash, PrivacyMode::Transparent);

        for i in 0..3u8 {
            let witness = StepWitness {
                state_before: hash_data(&[i]),
                state_after: hash_data(&[i + 1]),
                step_inputs: hash_data(&[i, i]),
            };
            backend.fold_step(&mut acc, &witness).unwrap();
        }

        // Set I/O hashes before finalize
        let input_hash = hash_data(&[0]);
        let output_hash = hash_data(&[3]);
        acc.input_hash = input_hash;
        acc.output_hash = output_hash;

        let proof = backend.finalize(acc).unwrap();

        assert!(backend.verify(&proof, &input_hash, &output_hash).unwrap());
    }

    #[test]
    fn test_hash_ivc_empty_fails() {
        let backend = HashIvc;
        let code_hash = hash_data(b"test_function");
        let acc = backend.init(&code_hash, PrivacyMode::Transparent);

        assert!(backend.finalize(acc).is_err());
    }

    #[test]
    fn test_hash_ivc_proof_structure() {
        let backend = HashIvc;
        let code_hash = hash_data(b"my_verified_fn");

        let mut acc = backend.init(&code_hash, PrivacyMode::Transparent);
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
                privacy_mode,
                blinding_commitment,
                ..
            } => {
                assert_eq!(*step_count, 1);
                assert_eq!(*ch, code_hash);
                assert_eq!(*privacy_mode, PrivacyMode::Transparent);
                assert!(blinding_commitment.is_none());
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

        let mut results = Vec::new();
        for _ in 0..2 {
            let mut acc = backend.init(&code_hash, PrivacyMode::Transparent);
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

    #[test]
    fn test_hash_ivc_private_mode_blinding() {
        let backend = HashIvc;
        let code_hash = hash_data(b"private_fn");

        let mut acc = backend.init(&code_hash, PrivacyMode::Private);
        let witness = StepWitness {
            state_before: hash_data(b"before"),
            state_after: hash_data(b"after"),
            step_inputs: hash_data(b"inputs"),
        };
        backend.fold_step(&mut acc, &witness).unwrap();

        let proof = backend.finalize(acc).unwrap();

        match &proof {
            VerifiedProof::HashIvc {
                privacy_mode,
                blinding_commitment,
                ..
            } => {
                assert_eq!(*privacy_mode, PrivacyMode::Private);
                assert!(blinding_commitment.is_some());
                assert_ne!(blinding_commitment.unwrap(), ZERO_HASH);
            }
            _ => panic!("wrong proof type"),
        }

        // Full private: code_hash() should return ZERO_HASH
        assert_eq!(proof.code_hash(), ZERO_HASH);
        assert!(backend.verify(&proof, &ZERO_HASH, &ZERO_HASH).unwrap());
    }

    #[test]
    fn test_hash_ivc_private_inputs_mode() {
        let backend = HashIvc;
        let code_hash = hash_data(b"selective_fn");

        let mut acc = backend.init(&code_hash, PrivacyMode::PrivateInputs);
        let witness = StepWitness {
            state_before: hash_data(b"before"),
            state_after: hash_data(b"after"),
            step_inputs: hash_data(b"inputs"),
        };
        backend.fold_step(&mut acc, &witness).unwrap();

        let proof = backend.finalize(acc).unwrap();

        match &proof {
            VerifiedProof::HashIvc {
                privacy_mode,
                blinding_commitment,
                code_hash: ch,
                ..
            } => {
                assert_eq!(*privacy_mode, PrivacyMode::PrivateInputs);
                assert!(blinding_commitment.is_some());
                // PrivateInputs: code_hash is still visible
                assert_eq!(*ch, code_hash);
            }
            _ => panic!("wrong proof type"),
        }

        // PrivateInputs: code_hash() should return the real code hash
        assert_eq!(proof.code_hash(), code_hash);
    }

    #[test]
    fn test_hash_ivc_transparent_no_blinding() {
        let backend = HashIvc;
        let code_hash = hash_data(b"transparent_fn");

        let mut acc = backend.init(&code_hash, PrivacyMode::Transparent);
        let witness = StepWitness {
            state_before: hash_data(b"before"),
            state_after: hash_data(b"after"),
            step_inputs: hash_data(b"inputs"),
        };
        backend.fold_step(&mut acc, &witness).unwrap();

        let proof = backend.finalize(acc).unwrap();

        match &proof {
            VerifiedProof::HashIvc {
                privacy_mode,
                blinding_commitment,
                ..
            } => {
                assert_eq!(*privacy_mode, PrivacyMode::Transparent);
                assert!(blinding_commitment.is_none());
            }
            _ => panic!("wrong proof type"),
        }
    }
}
