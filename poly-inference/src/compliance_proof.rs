//! Per-token compliance proof using IVC (Incrementally Verifiable Computation).
//!
//! Wraps `HashIvc` to produce a tamper-evident proof that every generated
//! token passed the content policy. Each token is folded as one IVC step.
//!
//! The resulting `ComplianceProof` contains:
//! - The IVC proof (hash chain + Merkle root)
//! - The policy hash that was enforced (committed into code_hash)
//! - Token count and final state hash for auditing

use poly_verified::crypto::hash::hash_data;
use poly_verified::ivc::hash_ivc::{HashIvc, HashIvcAccumulator};
use poly_verified::ivc::IvcBackend;
use poly_verified::types::{Hash, PrivacyMode, StepWitness, VerifiedProof, ZERO_HASH};

use crate::compliance::{PolicyChecker, TokenVerdict};

/// Running state tracked across tokens for the compliance proof.
#[derive(Clone, Debug)]
struct ComplianceState {
    /// All tokens generated so far.
    token_history: Vec<u32>,
    /// Chained state hash: H(prev_state_hash || token_id || verdict).
    state_hash: Hash,
    /// Number of tokens that passed the policy.
    compliant_count: u64,
}

impl ComplianceState {
    fn new() -> Self {
        Self {
            token_history: Vec::new(),
            state_hash: ZERO_HASH,
            compliant_count: 0,
        }
    }

    fn to_hash(&self) -> Hash {
        self.state_hash
    }
}

/// Accumulates per-token compliance proofs using HashIvc.
pub struct ComplianceAccumulator {
    backend: HashIvc,
    acc: HashIvcAccumulator,
    state: ComplianceState,
    checker: PolicyChecker,
}

impl ComplianceAccumulator {
    /// Create a new accumulator.
    ///
    /// The `code_hash` committed into the IVC proof is derived from:
    /// `H("compliance_check_v1" || policy_hash)` — binding the proof to the
    /// exact policy version that was enforced.
    pub fn new(checker: PolicyChecker) -> Self {
        let backend = HashIvc;

        // code_hash = H("compliance_check_v1" || policy_hash)
        let mut code_input = b"compliance_check_v1".to_vec();
        code_input.extend_from_slice(checker.policy_hash());
        let code_hash = hash_data(&code_input);

        // Transparent: server sees tokens anyway (they're needed for generation)
        let acc = backend.init(&code_hash, PrivacyMode::Transparent);

        Self {
            backend,
            acc,
            state: ComplianceState::new(),
            checker,
        }
    }

    /// Check a token against the policy and fold the result into the IVC proof.
    ///
    /// Returns the verdict. On `Blocked`, the caller should halt generation.
    pub fn check_and_fold(&mut self, token_id: u32) -> Result<TokenVerdict, String> {
        // 1. State before this step
        let state_before = self.state.to_hash();

        // 2. Check token against policy
        let verdict = self.checker.check_token(token_id, &self.state.token_history);

        // 3. Step inputs = H(token_id || verdict_byte)
        let mut step_data = Vec::with_capacity(5);
        step_data.extend_from_slice(&token_id.to_le_bytes());
        step_data.push(verdict.as_byte());
        let step_inputs = hash_data(&step_data);

        // 4. Update state
        self.state.token_history.push(token_id);
        if verdict.is_allowed() {
            self.state.compliant_count += 1;
        }

        // Chain state_hash: H(prev_state_hash || token_id_bytes || verdict_byte)
        let mut chain_input = Vec::with_capacity(37);
        chain_input.extend_from_slice(&self.state.state_hash);
        chain_input.extend_from_slice(&token_id.to_le_bytes());
        chain_input.push(verdict.as_byte());
        self.state.state_hash = hash_data(&chain_input);

        // 5. State after this step
        let state_after = self.state.to_hash();

        // 6. Fold into IVC accumulator
        let witness = StepWitness {
            state_before,
            state_after,
            step_inputs,
        };
        self.backend
            .fold_step(&mut self.acc, &witness)
            .map_err(|e| format!("IVC fold_step failed: {e}"))?;

        Ok(verdict)
    }

    /// How many tokens have been checked so far.
    pub fn token_count(&self) -> usize {
        self.state.token_history.len()
    }

    /// Finalize the accumulator and produce the compliance proof.
    pub fn finalize(mut self) -> Result<ComplianceProof, String> {
        let policy_hash = *self.checker.policy_hash();
        let total_tokens = self.state.token_history.len() as u64;
        let compliant_tokens = self.state.compliant_count;
        let final_state_hash = self.state.to_hash();

        // Bind I/O hashes: input is always ZERO_HASH (initial state),
        // output commits final_state_hash + total_tokens + compliant_tokens
        // so tampering with any of them breaks I/O verification.
        self.acc.input_hash = ZERO_HASH;
        let mut output_data = Vec::with_capacity(48);
        output_data.extend_from_slice(&final_state_hash);
        output_data.extend_from_slice(&total_tokens.to_le_bytes());
        output_data.extend_from_slice(&compliant_tokens.to_le_bytes());
        self.acc.output_hash = hash_data(&output_data);

        let ivc_proof = self
            .backend
            .finalize(self.acc)
            .map_err(|e| format!("IVC finalize failed: {e}"))?;

        Ok(ComplianceProof {
            ivc_proof,
            policy_hash,
            total_tokens,
            compliant_tokens,
            final_state_hash,
        })
    }
}

/// A finalized compliance proof for a generation session.
#[derive(Clone, Debug)]
pub struct ComplianceProof {
    /// The underlying IVC proof (hash chain + Merkle root).
    pub ivc_proof: VerifiedProof,
    /// Hash of the policy that was enforced.
    pub policy_hash: Hash,
    /// Total number of tokens checked.
    pub total_tokens: u64,
    /// Number of tokens that passed the policy.
    pub compliant_tokens: u64,
    /// Final chained state hash.
    pub final_state_hash: Hash,
}

impl ComplianceProof {
    /// Verify the structural and cryptographic validity of this proof.
    ///
    /// Checks:
    /// 1. IVC proof verifies with actual I/O (ZERO_HASH → final_state_hash)
    /// 2. total_tokens matches IVC step_count
    /// 3. policy_hash is bound to code_hash via `H("compliance_check_v1" || policy_hash)`
    /// 4. compliant_tokens does not exceed total_tokens
    pub fn verify(&self) -> Result<bool, String> {
        let backend = HashIvc;

        // 1. Verify IVC proof with actual I/O binding.
        let input = ZERO_HASH;
        // Recompute output binding — must match what finalize() committed
        let mut output_data = Vec::with_capacity(48);
        output_data.extend_from_slice(&self.final_state_hash);
        output_data.extend_from_slice(&self.total_tokens.to_le_bytes());
        output_data.extend_from_slice(&self.compliant_tokens.to_le_bytes());
        let output = hash_data(&output_data);
        if !backend
            .verify(&self.ivc_proof, &input, &output)
            .map_err(|e| format!("proof verification failed: {e}"))?
        {
            return Ok(false);
        }

        // 2. Cross-check: total_tokens must match IVC step_count.
        if let VerifiedProof::HashIvc { step_count, .. } = &self.ivc_proof {
            if *step_count != self.total_tokens {
                return Ok(false);
            }
        }

        // 3. Verify policy_hash is bound to code_hash.
        let mut code_input = b"compliance_check_v1".to_vec();
        code_input.extend_from_slice(&self.policy_hash);
        let expected_code = hash_data(&code_input);
        if let VerifiedProof::HashIvc { code_hash, .. } = &self.ivc_proof {
            if *code_hash != expected_code {
                return Ok(false);
            }
        }

        // 4. compliant_tokens must not exceed total_tokens.
        if self.compliant_tokens > self.total_tokens {
            return Ok(false);
        }

        Ok(true)
    }

    /// True if every token passed the policy and at least one token was checked.
    ///
    /// **WARNING**: This is a convenience check on the metadata fields ONLY.
    /// It does NOT verify the cryptographic proof. An attacker can forge a
    /// `ComplianceProof` with `total_tokens == compliant_tokens` that would
    /// pass this check but fail `verify()`.
    ///
    /// **Always call `verify()` before trusting `all_compliant()`.**
    ///
    /// R11: Now returns false for zero-token proofs (0 == 0). A proof that
    /// checked no tokens should not be considered "all compliant" since it
    /// provides no compliance evidence. This prevents attackers from constructing
    /// vacuously-true empty proofs.
    pub fn all_compliant(&self) -> bool {
        self.total_tokens > 0 && self.total_tokens == self.compliant_tokens
    }

    /// R10: Safe version of `all_compliant()` that also verifies the proof.
    ///
    /// Returns `true` only if:
    /// 1. The IVC proof cryptographically verifies
    /// 2. Every token passed the policy (total == compliant)
    ///
    /// This prevents forgery attacks where an attacker constructs a proof
    /// with `total_tokens == compliant_tokens` but invalid cryptographic chain.
    pub fn verified_all_compliant(&self) -> bool {
        self.verify().unwrap_or(false) && self.all_compliant()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compliance::ContentPolicy;

    fn test_policy() -> ContentPolicy {
        ContentPolicy {
            version: 1,
            blocked_token_ids: vec![100, 200, 300],
            blocked_ngrams: vec![vec![10, 20, 30]],
            max_sequence_length: 10,
        }
    }

    #[test]
    fn test_compliance_proof_roundtrip() {
        let checker = PolicyChecker::new(test_policy());
        let mut acc = ComplianceAccumulator::new(checker);

        // Fold 3 allowed tokens
        for token in [1, 2, 3] {
            let verdict = acc.check_and_fold(token).unwrap();
            assert!(verdict.is_allowed());
        }

        let proof = acc.finalize().unwrap();
        assert_eq!(proof.total_tokens, 3);
        assert_eq!(proof.compliant_tokens, 3);
        assert!(proof.all_compliant());
        assert!(proof.verify().unwrap());
    }

    #[test]
    fn test_proof_blocked_token_counted() {
        let checker = PolicyChecker::new(test_policy());
        let mut acc = ComplianceAccumulator::new(checker);

        // Allowed
        acc.check_and_fold(1).unwrap();
        // Blocked (but we still fold it — caller decides to stop)
        let verdict = acc.check_and_fold(100).unwrap();
        assert!(verdict.is_blocked());

        let proof = acc.finalize().unwrap();
        assert_eq!(proof.total_tokens, 2);
        assert_eq!(proof.compliant_tokens, 1); // only the first
        assert!(!proof.all_compliant());
        assert!(proof.verify().unwrap());
    }

    #[test]
    fn test_proof_step_count_matches() {
        let checker = PolicyChecker::new(test_policy());
        let mut acc = ComplianceAccumulator::new(checker);

        for t in 0..7u32 {
            acc.check_and_fold(t).unwrap();
        }

        let proof = acc.finalize().unwrap();
        match &proof.ivc_proof {
            VerifiedProof::HashIvc { step_count, .. } => {
                assert_eq!(*step_count, 7);
            }
            _ => panic!("expected HashIvc proof"),
        }
    }

    #[test]
    fn test_proof_deterministic() {
        let make_proof = || {
            let checker = PolicyChecker::new(test_policy());
            let mut acc = ComplianceAccumulator::new(checker);
            for t in [1u32, 2, 3, 4, 5] {
                acc.check_and_fold(t).unwrap();
            }
            acc.finalize().unwrap()
        };

        let p1 = make_proof();
        let p2 = make_proof();
        assert_eq!(p1.final_state_hash, p2.final_state_hash);
        assert_eq!(p1.policy_hash, p2.policy_hash);
        assert_eq!(p1.total_tokens, p2.total_tokens);

        // IVC chain tip should also match
        match (&p1.ivc_proof, &p2.ivc_proof) {
            (
                VerifiedProof::HashIvc {
                    chain_tip: a, merkle_root: ar, ..
                },
                VerifiedProof::HashIvc {
                    chain_tip: b, merkle_root: br, ..
                },
            ) => {
                assert_eq!(a, b);
                assert_eq!(ar, br);
            }
            _ => panic!("expected HashIvc"),
        }
    }

    #[test]
    fn test_server_client_agreement() {
        let policy = test_policy();
        let client_checker = PolicyChecker::new(policy.clone());
        let server_checker = PolicyChecker::new(policy);

        let tokens = [1u32, 2, 42, 100]; // 100 is blocked
        let mut history = Vec::new();

        for &t in &tokens {
            let client_verdict = client_checker.check_token(t, &history);
            let server_verdict = server_checker.check_token(t, &history);
            assert_eq!(client_verdict, server_verdict);
            history.push(t);
        }
    }

    #[test]
    fn test_ngram_block_in_proof() {
        let checker = PolicyChecker::new(test_policy());
        let mut acc = ComplianceAccumulator::new(checker);

        // Build up to the blocked ngram [10, 20, 30]
        assert!(acc.check_and_fold(10).unwrap().is_allowed());
        assert!(acc.check_and_fold(20).unwrap().is_allowed());
        assert!(acc.check_and_fold(30).unwrap().is_blocked()); // completes ngram

        let proof = acc.finalize().unwrap();
        assert_eq!(proof.total_tokens, 3);
        assert_eq!(proof.compliant_tokens, 2);
        assert!(!proof.all_compliant());
    }
}
