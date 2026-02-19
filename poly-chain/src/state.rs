use poly_verified::crypto::hash::hash_combine;
use poly_verified::types::{Hash, ZERO_HASH};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::primitives::*;

/// A Sparse Merkle Tree mapping 32-byte keys to 32-byte value hashes.
///
/// Stores only non-empty leaves. Empty leaves are implicitly ZERO_HASH.
/// The tree is 32 levels deep (keyed on first 4 bytes of the key hash).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SparseMerkleTree {
    /// Non-empty leaf values: key → value_hash.
    leaves: BTreeMap<Hash, Hash>,
    /// Cached root hash (recomputed on mutation).
    root: Hash,
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self {
            leaves: BTreeMap::new(),
            root: ZERO_HASH,
        }
    }

    pub fn root(&self) -> Hash {
        self.root
    }

    pub fn len(&self) -> usize {
        self.leaves.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaves.is_empty()
    }

    /// Get the value hash for a key, or None if not present.
    pub fn get(&self, key: &Hash) -> Option<&Hash> {
        self.leaves.get(key)
    }

    /// Insert or update a key-value pair.
    pub fn set(&mut self, key: Hash, value: Hash) {
        if value == ZERO_HASH {
            self.leaves.remove(&key);
        } else {
            self.leaves.insert(key, value);
        }
        self.recompute_root();
    }

    /// Delete a key (set to ZERO_HASH).
    pub fn delete(&mut self, key: &Hash) {
        self.leaves.remove(key);
        self.recompute_root();
    }

    /// Check if a key exists with a non-zero value.
    pub fn contains(&self, key: &Hash) -> bool {
        self.leaves.contains_key(key)
    }

    /// Recompute root from all leaves.
    ///
    /// Simple approach: sort all (key, value) pairs and build a Merkle tree
    /// from their combined hashes. This is a "sorted-list commitment" rather
    /// than a full sparse Merkle tree (which would have 2^256 virtual leaves).
    /// Sufficient for Phase 1 — we can upgrade to a proper SMT later.
    fn recompute_root(&mut self) {
        if self.leaves.is_empty() {
            self.root = ZERO_HASH;
            return;
        }

        // Deterministic ordering via BTreeMap
        let leaf_hashes: Vec<Hash> = self
            .leaves
            .iter()
            .map(|(k, v)| hash_combine(k, v))
            .collect();

        // Build Merkle tree from leaf hashes
        let tree = poly_verified::crypto::merkle::MerkleTree::build(&leaf_hashes);
        self.root = tree.root;
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// SMT inclusion proof: value at key, plus the Merkle root.
#[derive(Clone, Debug)]
pub struct SmtProof {
    pub key: Hash,
    pub value: Option<Hash>,
    pub root: Hash,
}

// ---------------------------------------------------------------------------
// Global State — 7 subtrees
// ---------------------------------------------------------------------------

/// The complete chain state, composed of 8 independent Sparse Merkle Trees.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GlobalState {
    pub wallets: SparseMerkleTree,
    pub identities: SparseMerkleTree,
    pub compliance: SparseMerkleTree,
    pub fraud: SparseMerkleTree,
    pub backups: SparseMerkleTree,
    pub stp: SparseMerkleTree,
    pub applications: SparseMerkleTree,
    pub swaps: SparseMerkleTree,
    /// Per-account nonce tracking: prevents transaction replay.
    #[serde(default)]
    nonces: BTreeMap<AccountId, Nonce>,
}

impl GlobalState {
    /// Create an empty genesis state.
    pub fn genesis() -> Self {
        Self {
            wallets: SparseMerkleTree::new(),
            identities: SparseMerkleTree::new(),
            compliance: SparseMerkleTree::new(),
            fraud: SparseMerkleTree::new(),
            backups: SparseMerkleTree::new(),
            stp: SparseMerkleTree::new(),
            applications: SparseMerkleTree::new(),
            swaps: SparseMerkleTree::new(),
            nonces: BTreeMap::new(),
        }
    }

    /// Combined state root: H(wallets_root || identities_root || ... || swaps_root || nonces_hash).
    ///
    /// R11: The nonces map is now included in the state root commitment.
    /// Previously, nonces were excluded, meaning two states with different nonces
    /// would produce the same state_root. This allowed an attacker who obtained a
    /// state snapshot to forge a state with reset nonces, enabling transaction replays
    /// that bypass the nonce check (because the replayed nonce would match the forged state).
    pub fn state_root(&self) -> Hash {
        let mut data = Vec::with_capacity(9 * 32);
        data.extend_from_slice(&self.wallets.root());
        data.extend_from_slice(&self.identities.root());
        data.extend_from_slice(&self.compliance.root());
        data.extend_from_slice(&self.fraud.root());
        data.extend_from_slice(&self.backups.root());
        data.extend_from_slice(&self.stp.root());
        data.extend_from_slice(&self.applications.root());
        data.extend_from_slice(&self.swaps.root());
        data.extend_from_slice(&self.nonces_hash());
        hash_with_domain(DOMAIN_BLOCK, &data)
    }

    /// R11: Compute a deterministic hash of all account nonces.
    /// This ensures the nonce map is committed to in the state root,
    /// preventing state forgery attacks that reset nonces.
    fn nonces_hash(&self) -> Hash {
        if self.nonces.is_empty() {
            return ZERO_HASH;
        }
        let mut buf = Vec::new();
        for (account_id, nonce) in &self.nonces {
            buf.extend_from_slice(account_id);
            buf.extend_from_slice(&nonce.to_le_bytes());
        }
        hash_with_domain(DOMAIN_BLOCK, &buf)
    }

    // -----------------------------------------------------------------------
    // Wallet accessors
    // -----------------------------------------------------------------------

    /// Get wallet commitment by account ID.
    pub fn get_wallet(&self, account_id: &AccountId) -> Option<Hash> {
        self.wallets.get(account_id).copied()
    }

    /// Set wallet commitment hash.
    pub fn set_wallet(&mut self, account_id: AccountId, state_hash: Hash) {
        self.wallets.set(account_id, state_hash);
    }

    /// Remove wallet (e.g., on fraud burn).
    pub fn remove_wallet(&mut self, account_id: &AccountId) {
        self.wallets.delete(account_id);
    }

    // -----------------------------------------------------------------------
    // Identity accessors
    // -----------------------------------------------------------------------

    pub fn get_identity(&self, account_id: &AccountId) -> Option<Hash> {
        self.identities.get(account_id).copied()
    }

    pub fn set_identity(&mut self, account_id: AccountId, identity_hash: Hash) {
        self.identities.set(account_id, identity_hash);
    }

    // -----------------------------------------------------------------------
    // Compliance accessors
    // -----------------------------------------------------------------------

    pub fn add_compliance_report(&mut self, report_hash: Hash, report_data_hash: Hash) {
        self.compliance.set(report_hash, report_data_hash);
    }

    // -----------------------------------------------------------------------
    // Fraud accessors
    // -----------------------------------------------------------------------

    pub fn add_fraud_evidence(&mut self, evidence_hash: Hash, data_hash: Hash) {
        self.fraud.set(evidence_hash, data_hash);
    }

    // -----------------------------------------------------------------------
    // Backup accessors
    // -----------------------------------------------------------------------

    pub fn set_backup(&mut self, account_id: AccountId, backup_hash: Hash) {
        self.backups.set(account_id, backup_hash);
    }

    pub fn get_backup(&self, account_id: &AccountId) -> Option<Hash> {
        self.backups.get(account_id).copied()
    }

    // -----------------------------------------------------------------------
    // STP accessors
    // -----------------------------------------------------------------------

    pub fn set_stp_record(&mut self, key: Hash, data_hash: Hash) {
        self.stp.set(key, data_hash);
    }

    pub fn get_stp_record(&self, key: &Hash) -> Option<Hash> {
        self.stp.get(key).copied()
    }

    // -----------------------------------------------------------------------
    // Application accessors
    // -----------------------------------------------------------------------

    pub fn set_app_state(&mut self, app_key: Hash, state_hash: Hash) {
        self.applications.set(app_key, state_hash);
    }

    pub fn get_app_state(&self, app_key: &Hash) -> Option<Hash> {
        self.applications.get(app_key).copied()
    }

    // -----------------------------------------------------------------------
    // Swap accessors
    // -----------------------------------------------------------------------

    pub fn set_swap(&mut self, swap_id: Hash, state_hash: Hash) {
        self.swaps.set(swap_id, state_hash);
    }

    pub fn get_swap(&self, swap_id: &Hash) -> Option<Hash> {
        self.swaps.get(swap_id).copied()
    }

    pub fn remove_swap(&mut self, swap_id: &Hash) {
        self.swaps.delete(swap_id);
    }

    // -----------------------------------------------------------------------
    // Nonce accessors
    // -----------------------------------------------------------------------

    /// Get the current nonce for an account (0 if never seen).
    pub fn get_nonce(&self, account_id: &AccountId) -> Nonce {
        self.nonces.get(account_id).copied().unwrap_or(0)
    }

    /// Set the nonce for an account.
    pub fn set_nonce(&mut self, account_id: AccountId, nonce: Nonce) {
        self.nonces.insert(account_id, nonce);
    }
}

impl Default for GlobalState {
    fn default() -> Self {
        Self::genesis()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_smt() {
        let smt = SparseMerkleTree::new();
        assert_eq!(smt.root(), ZERO_HASH);
        assert_eq!(smt.len(), 0);
        assert!(smt.is_empty());
    }

    #[test]
    fn smt_insert_and_get() {
        let mut smt = SparseMerkleTree::new();
        let key = [1u8; 32];
        let value = [2u8; 32];
        smt.set(key, value);
        assert_eq!(smt.get(&key), Some(&value));
        assert_ne!(smt.root(), ZERO_HASH);
        assert_eq!(smt.len(), 1);
    }

    #[test]
    fn smt_delete() {
        let mut smt = SparseMerkleTree::new();
        let key = [1u8; 32];
        smt.set(key, [2u8; 32]);
        assert!(smt.contains(&key));
        smt.delete(&key);
        assert!(!smt.contains(&key));
        assert_eq!(smt.root(), ZERO_HASH);
    }

    #[test]
    fn smt_deterministic_root() {
        let mut smt1 = SparseMerkleTree::new();
        let mut smt2 = SparseMerkleTree::new();

        // Insert in different orders — same result (BTreeMap is ordered)
        smt1.set([1u8; 32], [0xAA; 32]);
        smt1.set([2u8; 32], [0xBB; 32]);

        smt2.set([2u8; 32], [0xBB; 32]);
        smt2.set([1u8; 32], [0xAA; 32]);

        assert_eq!(smt1.root(), smt2.root());
    }

    #[test]
    fn smt_set_zero_deletes() {
        let mut smt = SparseMerkleTree::new();
        smt.set([1u8; 32], [2u8; 32]);
        assert_eq!(smt.len(), 1);
        smt.set([1u8; 32], ZERO_HASH); // setting to zero = delete
        assert_eq!(smt.len(), 0);
        assert_eq!(smt.root(), ZERO_HASH);
    }

    #[test]
    fn genesis_state() {
        let state = GlobalState::genesis();
        let root = state.state_root();
        // Genesis root is deterministic
        let root2 = GlobalState::genesis().state_root();
        assert_eq!(root, root2);
    }

    #[test]
    fn state_root_changes_on_mutation() {
        let mut state = GlobalState::genesis();
        let root1 = state.state_root();
        state.set_wallet([1u8; 32], [0xAA; 32]);
        let root2 = state.state_root();
        assert_ne!(root1, root2);
    }

    #[test]
    fn wallet_crud() {
        let mut state = GlobalState::genesis();
        let account = [1u8; 32];

        assert!(state.get_wallet(&account).is_none());
        state.set_wallet(account, [0xAA; 32]);
        assert_eq!(state.get_wallet(&account), Some([0xAA; 32]));
        state.remove_wallet(&account);
        assert!(state.get_wallet(&account).is_none());
    }

    #[test]
    fn identity_set_get() {
        let mut state = GlobalState::genesis();
        let account = [2u8; 32];
        state.set_identity(account, [0xBB; 32]);
        assert_eq!(state.get_identity(&account), Some([0xBB; 32]));
    }

    #[test]
    fn backup_set_get() {
        let mut state = GlobalState::genesis();
        let account = [3u8; 32];
        state.set_backup(account, [0xCC; 32]);
        assert_eq!(state.get_backup(&account), Some([0xCC; 32]));
    }

    #[test]
    fn app_state_set_get() {
        let mut state = GlobalState::genesis();
        let key = [4u8; 32];
        state.set_app_state(key, [0xDD; 32]);
        assert_eq!(state.get_app_state(&key), Some([0xDD; 32]));
    }

    #[test]
    fn seven_subtrees_independent() {
        let mut state = GlobalState::genesis();
        let key = [5u8; 32];
        let val = [0xEE; 32];

        state.set_wallet(key, val);
        // Other subtrees unaffected
        assert!(state.get_identity(&key).is_none());
        assert!(state.get_backup(&key).is_none());
        assert!(state.get_stp_record(&key).is_none());
        assert!(state.get_app_state(&key).is_none());
    }
}
