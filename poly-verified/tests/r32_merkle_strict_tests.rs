//! Round 32 — Backlog item 4/4: `verify_proof_strict` leaf-index binding.
//!
//! The R29 sweep noted that `verify_proof_strict`'s contract claims it
//! "prevents position spoofing", but it only range-checked
//! `leaf_index < 2^depth`. `verify_proof` reconstructs the Merkle root purely
//! from the sibling `is_left` flags and never consults `leaf_index`, so a
//! genuine proof for position P could carry any in-range `leaf_index` Q and
//! still pass `verify_proof_strict` — the position guarantee was not actually
//! enforced. (Not currently exploitable: `verify_proof_strict` has no
//! production callers, and `verify_disclosure` independently binds the
//! position. Fixed now so the function delivers its documented contract
//! before anything starts to rely on it.)
//!
//! R32 binds `leaf_index` to the sibling path: at level `i` the sibling is on
//! the left iff bit `i` of `leaf_index` is 1.

use poly_verified::crypto::hash::hash_data;
use poly_verified::crypto::merkle::{verify_proof, verify_proof_strict, MerkleTree};
use poly_verified::types::ZERO_HASH;

fn tree_of(n: u8) -> MerkleTree {
    let leaves: Vec<[u8; 32]> = (0..n).map(|i| hash_data(&[i])).collect();
    MerkleTree::build(&leaves)
}

// ===========================================================================
// R32-01: verify_proof_strict binds leaf_index to the sibling path
// ===========================================================================

/// R32-01a: a genuine proof for every leaf position passes strict verification.
#[test]
fn r32_genuine_proofs_pass_strict() {
    let tree = tree_of(8);
    for idx in 0..8u64 {
        let proof = tree.generate_proof(idx, &ZERO_HASH).unwrap();
        assert!(
            verify_proof_strict(&proof),
            "R32-01a: a genuine proof for index {idx} must pass strict verification"
        );
    }
}

/// R32-01b: a proof whose `leaf_index` is changed to a DIFFERENT in-range
/// position (so the depth bound still passes) is rejected by
/// `verify_proof_strict` — the path's `is_left` flags no longer match the
/// claimed index. `verify_proof` (non-strict) still accepts it, which is
/// exactly the position-spoofing gap the strict variant must close.
#[test]
fn r32_spoofed_leaf_index_rejected_by_strict() {
    let tree = tree_of(8);
    let mut proof = tree.generate_proof(2, &ZERO_HASH).unwrap();

    // Genuine proof: both verifiers accept.
    assert!(verify_proof(&proof));
    assert!(verify_proof_strict(&proof));

    // Spoof the position: claim index 5 (still in [0, 8), so the depth bound
    // alone would not catch it). The sibling path is still index 2's.
    proof.leaf_index = 5;

    assert!(
        verify_proof(&proof),
        "R32-01b: non-strict verify_proof ignores leaf_index — still accepts (the gap)"
    );
    assert!(
        !verify_proof_strict(&proof),
        "R32-01b: verify_proof_strict must reject a leaf_index inconsistent with the path"
    );
}

/// R32-01c: regression — the depth bound still rejects an out-of-range
/// `leaf_index`.
#[test]
fn r32_out_of_range_leaf_index_rejected() {
    let tree = tree_of(8);
    let mut proof = tree.generate_proof(3, &ZERO_HASH).unwrap();
    proof.leaf_index = 999; // >= 2^depth
    assert!(
        !verify_proof_strict(&proof),
        "R32-01c: an out-of-range leaf_index must be rejected by the depth bound"
    );
}

/// R32-01d: tampering with a sibling hash is still caught (the path
/// reconstruction check is unchanged).
#[test]
fn r32_tampered_sibling_still_rejected() {
    let tree = tree_of(8);
    let mut proof = tree.generate_proof(4, &ZERO_HASH).unwrap();
    proof.siblings[0].hash[0] ^= 0xFF;
    assert!(
        !verify_proof_strict(&proof),
        "R32-01d: a tampered sibling hash must still fail strict verification"
    );
}
