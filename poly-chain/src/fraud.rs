use poly_verified::types::Hash;
use serde::{Deserialize, Serialize};

use crate::primitives::*;

/// Why an account is frozen.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FreezeReason {
    /// Conflicting state observations proved fraud.
    FraudDetected,
    /// Official failed to comply with STP data request.
    STPNonCompliance { deadline: Timestamp },
}

/// Type of state conflict detected between two observations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictType {
    /// Same nonce, different state hashes → tried to spend twice.
    DoubleSpend,
    /// State hash doesn't match expected transition → invalid state.
    StateInconsistency,
}

/// A signed observation of an account's state at a point in time.
///
/// Peers gossip these; two conflicting observations prove fraud.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StateObservation {
    /// Who observed (validator/peer public key hash).
    pub observer: AccountId,
    /// Which account was observed.
    pub observed_key: AccountId,
    /// The state hash they saw.
    pub observed_state_hash: Hash,
    /// The nonce they saw.
    pub observed_nonce: Nonce,
    /// Ed25519 signature over (observed_key || state_hash || nonce).
    #[serde(with = "crate::primitives::serde_byte64")]
    pub observer_signature: [u8; 64],
}

impl StateObservation {
    /// The message that is signed: observed_key || state_hash || nonce_LE.
    pub fn sign_message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(72);
        msg.extend_from_slice(&self.observed_key);
        msg.extend_from_slice(&self.observed_state_hash);
        msg.extend_from_slice(&self.observed_nonce.to_le_bytes());
        msg
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(168);
        buf.extend_from_slice(&self.observer);              // 32
        buf.extend_from_slice(&self.observed_key);           // 32
        buf.extend_from_slice(&self.observed_state_hash);    // 32
        buf.extend_from_slice(&self.observed_nonce.to_le_bytes()); // 8
        buf.extend_from_slice(&self.observer_signature);     // 64
        buf
    }
}

/// Two conflicting observations that prove fraud.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FraudEvidence {
    pub fraudulent_key: AccountId,
    pub observation_a: StateObservation,
    pub observation_b: StateObservation,
    pub conflict_type: ConflictType,
}

/// Detect a conflict between two observations of the same account.
///
/// Returns `Some(ConflictType)` if the observations are inconsistent.
pub fn detect_conflict(a: &StateObservation, b: &StateObservation) -> Option<ConflictType> {
    // Must be observing the same account
    if a.observed_key != b.observed_key {
        return None;
    }

    // Same nonce but different state → double spend
    if a.observed_nonce == b.observed_nonce
        && a.observed_state_hash != b.observed_state_hash
    {
        return Some(ConflictType::DoubleSpend);
    }

    // Lower nonce has higher state hash nonce value — indicates
    // a state that should be impossible (state went backwards).
    // This is a more nuanced check: if nonce a < nonce b but
    // someone claims state a was seen AFTER state b, that's inconsistent.
    // For now, the simple double-spend check is sufficient.

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_observation(key: AccountId, state: Hash, nonce: Nonce) -> StateObservation {
        StateObservation {
            observer: [0xBB; 32],
            observed_key: key,
            observed_state_hash: state,
            observed_nonce: nonce,
            observer_signature: [0u8; 64], // placeholder
        }
    }

    #[test]
    fn detect_double_spend() {
        let key = [1u8; 32];
        let a = make_observation(key, [0xAA; 32], 5);
        let b = make_observation(key, [0xBB; 32], 5);
        assert_eq!(detect_conflict(&a, &b), Some(ConflictType::DoubleSpend));
    }

    #[test]
    fn no_conflict_same_state() {
        let key = [1u8; 32];
        let a = make_observation(key, [0xAA; 32], 5);
        let b = make_observation(key, [0xAA; 32], 5);
        assert_eq!(detect_conflict(&a, &b), None);
    }

    #[test]
    fn no_conflict_different_nonces() {
        let key = [1u8; 32];
        let a = make_observation(key, [0xAA; 32], 5);
        let b = make_observation(key, [0xBB; 32], 6);
        assert_eq!(detect_conflict(&a, &b), None);
    }

    #[test]
    fn no_conflict_different_keys() {
        let a = make_observation([1u8; 32], [0xAA; 32], 5);
        let b = make_observation([2u8; 32], [0xBB; 32], 5);
        assert_eq!(detect_conflict(&a, &b), None);
    }
}
