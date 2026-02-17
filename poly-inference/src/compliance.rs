//! Content policy enforcement for encrypted inference.
//!
//! Provides deterministic, hashable content policies that can be committed
//! into IVC proofs. The server and client both enforce the same policy —
//! belt-and-suspenders: client proves compliance via IVC hash chain,
//! server independently re-checks.

use std::collections::HashSet;

use poly_verified::crypto::hash::hash_data;
use poly_verified::types::Hash;
use serde::{Deserialize, Serialize};

/// A deterministic content policy. Serializable and hashable so the exact
/// policy version can be committed into every compliance proof.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContentPolicy {
    pub version: u32,
    /// Individual token IDs that are always blocked.
    pub blocked_token_ids: Vec<u32>,
    /// Forbidden token sequences (n-grams). If any generated subsequence
    /// matches, the token completing the match is blocked.
    pub blocked_ngrams: Vec<Vec<u32>>,
    /// Maximum number of tokens allowed in a single generation.
    pub max_sequence_length: usize,
}

impl ContentPolicy {
    /// Compute a deterministic hash of this policy for proof commitment.
    pub fn hash(&self) -> Hash {
        let serialized = serde_json::to_vec(self).expect("policy serialization");
        hash_data(&serialized)
    }
}

/// Why a token was blocked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViolationReason {
    /// Token ID is in the blocklist.
    BlockedTokenId(u32),
    /// Token completed a forbidden n-gram sequence.
    BlockedNgram(Vec<u32>),
    /// Sequence length exceeds policy limit.
    SequenceTooLong { length: usize, max: usize },
}

/// Result of checking a single token against the policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenVerdict {
    Allowed,
    Blocked(ViolationReason),
}

impl TokenVerdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, TokenVerdict::Allowed)
    }

    pub fn is_blocked(&self) -> bool {
        matches!(self, TokenVerdict::Blocked(_))
    }

    /// Returns 1 for Allowed, 0 for Blocked — used as step input in IVC fold.
    pub fn as_byte(&self) -> u8 {
        match self {
            TokenVerdict::Allowed => 1,
            TokenVerdict::Blocked(_) => 0,
        }
    }
}

/// Stateless policy checker with O(1) token-ID lookup.
pub struct PolicyChecker {
    policy: ContentPolicy,
    policy_hash: Hash,
    blocked_set: HashSet<u32>,
}

impl PolicyChecker {
    pub fn new(policy: ContentPolicy) -> Self {
        let policy_hash = policy.hash();
        let blocked_set: HashSet<u32> = policy.blocked_token_ids.iter().copied().collect();
        Self {
            policy,
            policy_hash,
            blocked_set,
        }
    }

    pub fn policy(&self) -> &ContentPolicy {
        &self.policy
    }

    pub fn policy_hash(&self) -> &Hash {
        &self.policy_hash
    }

    /// Check whether `token_id` is allowed given the generation `history`.
    ///
    /// Checks in order:
    /// 1. Token blocklist (O(1) HashSet lookup)
    /// 2. Sequence length limit
    /// 3. N-gram pattern match (sliding window)
    pub fn check_token(&self, token_id: u32, history: &[u32]) -> TokenVerdict {
        // 1. Blocked token ID
        if self.blocked_set.contains(&token_id) {
            return TokenVerdict::Blocked(ViolationReason::BlockedTokenId(token_id));
        }

        // 2. Sequence length (history + this token)
        let new_length = history.len() + 1;
        if new_length > self.policy.max_sequence_length {
            return TokenVerdict::Blocked(ViolationReason::SequenceTooLong {
                length: new_length,
                max: self.policy.max_sequence_length,
            });
        }

        // 3. N-gram match: check if appending token_id completes any forbidden sequence
        for ngram in &self.policy.blocked_ngrams {
            if ngram.is_empty() {
                continue;
            }
            let n = ngram.len();
            // The candidate sequence ending with token_id
            if n == 1 {
                // Single-token ngram (redundant with blocklist, but honor it)
                if ngram[0] == token_id {
                    return TokenVerdict::Blocked(ViolationReason::BlockedNgram(ngram.clone()));
                }
            } else if history.len() >= n - 1 {
                // Check if history tail + token_id matches the ngram
                let tail_start = history.len() - (n - 1);
                let tail = &history[tail_start..];
                if tail == &ngram[..n - 1] && ngram[n - 1] == token_id {
                    return TokenVerdict::Blocked(ViolationReason::BlockedNgram(ngram.clone()));
                }
            }
        }

        TokenVerdict::Allowed
    }
}

/// Build a default content policy for demonstration.
///
/// Blocks a set of known-harmful token patterns. In production this would
/// be loaded from a signed policy file.
pub fn default_policy() -> ContentPolicy {
    ContentPolicy {
        version: 1,
        // Block common harmful-content related tokens (Qwen3 tokenizer IDs)
        // These are illustrative — a real policy would be much more comprehensive
        blocked_token_ids: vec![
            // Placeholder: in a real deployment, populate from a curated blocklist
        ],
        blocked_ngrams: vec![
            // Placeholder: forbidden multi-token sequences
        ],
        max_sequence_length: 2048,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> ContentPolicy {
        ContentPolicy {
            version: 1,
            blocked_token_ids: vec![100, 200, 300],
            blocked_ngrams: vec![
                vec![10, 20, 30],  // 3-gram
                vec![50, 60],      // 2-gram
                vec![999],         // single token ngram
            ],
            max_sequence_length: 5,
        }
    }

    #[test]
    fn test_allowed_token() {
        let checker = PolicyChecker::new(test_policy());
        let verdict = checker.check_token(42, &[]);
        assert_eq!(verdict, TokenVerdict::Allowed);
    }

    #[test]
    fn test_blocked_token_id() {
        let checker = PolicyChecker::new(test_policy());
        let verdict = checker.check_token(200, &[]);
        assert_eq!(
            verdict,
            TokenVerdict::Blocked(ViolationReason::BlockedTokenId(200))
        );
    }

    #[test]
    fn test_blocked_ngram_3gram() {
        let checker = PolicyChecker::new(test_policy());
        // History [10, 20], next token 30 → matches [10, 20, 30]
        let verdict = checker.check_token(30, &[10, 20]);
        assert!(verdict.is_blocked());
        match verdict {
            TokenVerdict::Blocked(ViolationReason::BlockedNgram(ngram)) => {
                assert_eq!(ngram, vec![10, 20, 30]);
            }
            _ => panic!("expected BlockedNgram"),
        }
    }

    #[test]
    fn test_blocked_ngram_2gram() {
        let checker = PolicyChecker::new(test_policy());
        let verdict = checker.check_token(60, &[50]);
        assert!(verdict.is_blocked());
    }

    #[test]
    fn test_ngram_partial_no_match() {
        let checker = PolicyChecker::new(test_policy());
        // Only first 2 tokens of 3-gram, different completion
        let verdict = checker.check_token(99, &[10, 20]);
        assert!(verdict.is_allowed());
    }

    #[test]
    fn test_sequence_too_long() {
        let checker = PolicyChecker::new(test_policy());
        // max_sequence_length = 5, history has 5, adding 1 more = 6 > 5
        let verdict = checker.check_token(42, &[1, 2, 3, 4, 5]);
        assert_eq!(
            verdict,
            TokenVerdict::Blocked(ViolationReason::SequenceTooLong {
                length: 6,
                max: 5,
            })
        );
    }

    #[test]
    fn test_sequence_at_limit() {
        let checker = PolicyChecker::new(test_policy());
        // max_sequence_length = 5, history has 4, adding 1 = 5 == 5 → allowed
        let verdict = checker.check_token(42, &[1, 2, 3, 4]);
        assert!(verdict.is_allowed());
    }

    #[test]
    fn test_policy_hash_deterministic() {
        let p1 = test_policy();
        let p2 = test_policy();
        assert_eq!(p1.hash(), p2.hash());
    }

    #[test]
    fn test_policy_hash_changes_with_version() {
        let p1 = test_policy();
        let mut p2 = test_policy();
        p2.version = 2;
        assert_ne!(p1.hash(), p2.hash());
    }

    #[test]
    fn test_verdict_as_byte() {
        assert_eq!(TokenVerdict::Allowed.as_byte(), 1);
        assert_eq!(
            TokenVerdict::Blocked(ViolationReason::BlockedTokenId(0)).as_byte(),
            0
        );
    }
}
