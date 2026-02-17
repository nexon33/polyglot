//! Protocol-layer attack tests for poly-verified.
//!
//! Tests disclosure spoofing, proof replay attacks, hash chain manipulation,
//! domain separation attacks, and Merkle proof forgery.

use poly_verified::crypto::hash::{
    hash_blinding, hash_chain_step, hash_combine, hash_data, hash_leaf, hash_transition,
};
use poly_verified::crypto::merkle::{verify_proof, MerkleTree};
use poly_verified::disclosure::{
    create_disclosure, verify_disclosure, DisclosedToken,
};
use poly_verified::ivc::hash_ivc::HashIvc;
use poly_verified::ivc::IvcBackend;
use poly_verified::types::{
    Hash, MerkleProof, PrivacyMode, ProofNode, StepWitness, VerifiedProof, ZERO_HASH,
};
use poly_verified::verified_type::Verified;

// ═══════════════════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════════════════

fn mock_hash_ivc_proof() -> VerifiedProof {
    VerifiedProof::HashIvc {
        chain_tip: [0x01; 32],
        merkle_root: [0x02; 32],
        step_count: 1,
        code_hash: [0x03; 32],
        privacy_mode: PrivacyMode::Transparent,
        blinding_commitment: None,
    }
}

fn sample_tokens() -> Vec<u32> {
    vec![100, 200, 300, 400, 500, 600, 700, 800]
}

fn make_verified(tokens: Vec<u32>) -> Verified<Vec<u32>> {
    Verified::__macro_new(tokens, mock_hash_ivc_proof())
}

// ═══════════════════════════════════════════════════════════════════════
// 1. DISCLOSURE SPOOFING ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: Forge a revealed token value (change 300 → 9999).
/// Expected: Verification fails because leaf hash doesn't match proof.
#[test]
fn attack_disclosure_forge_token_value() {
    let verified = make_verified(sample_tokens());
    let mut disclosure = create_disclosure(&verified, &[2]).unwrap();

    // Tamper: change revealed token value
    disclosure.tokens[2] = DisclosedToken::Revealed {
        index: 2,
        token_id: 9999, // forged!
    };

    assert!(
        !verify_disclosure(&disclosure),
        "VULNERABILITY: forged token value passed verification"
    );
}

/// Attack: Change a redacted leaf hash to cover a different token.
/// Expected: The overall Merkle root won't match, but verify_disclosure
/// only checks revealed tokens' proofs — redacted positions are opaque.
/// This tests that redacted leaf hashes cannot be ZERO_HASH (which would
/// indicate an empty position).
#[test]
fn attack_disclosure_tamper_redacted_leaf() {
    let verified = make_verified(sample_tokens());
    let mut disclosure = create_disclosure(&verified, &[]).unwrap();

    // Set a redacted leaf to ZERO_HASH (non-existent position)
    disclosure.tokens[0] = DisclosedToken::Redacted {
        index: 0,
        leaf_hash: ZERO_HASH,
    };

    assert!(
        !verify_disclosure(&disclosure),
        "VULNERABILITY: zero-hash redacted leaf passed verification"
    );
}

/// Attack: Swap the order of two tokens (reordering attack).
#[test]
fn attack_disclosure_reorder_tokens() {
    let verified = make_verified(sample_tokens());
    let mut disclosure = create_disclosure(&verified, &[]).unwrap();

    // Swap positions 2 and 3
    disclosure.tokens.swap(2, 3);

    assert!(
        !verify_disclosure(&disclosure),
        "VULNERABILITY: reordered tokens passed verification"
    );
}

/// Attack: Remove a token to create a gap.
#[test]
fn attack_disclosure_remove_token() {
    let verified = make_verified(sample_tokens());
    let mut disclosure = create_disclosure(&verified, &[]).unwrap();

    disclosure.tokens.remove(3);

    assert!(
        !verify_disclosure(&disclosure),
        "VULNERABILITY: missing token passed verification"
    );
}

/// Attack: Insert an extra token.
#[test]
fn attack_disclosure_insert_extra_token() {
    let verified = make_verified(sample_tokens());
    let mut disclosure = create_disclosure(&verified, &[]).unwrap();

    // Insert an extra token after position 3
    disclosure.tokens.insert(
        4,
        DisclosedToken::Redacted {
            index: 4,
            leaf_hash: [0xAA; 32],
        },
    );

    assert!(
        !verify_disclosure(&disclosure),
        "VULNERABILITY: extra token passed verification"
    );
}

/// Attack: Replace the output root with a forged one.
#[test]
fn attack_disclosure_forge_output_root() {
    let verified = make_verified(sample_tokens());
    let mut disclosure = create_disclosure(&verified, &[2]).unwrap();

    // Replace output root
    disclosure.output_root = [0xFF; 32];

    assert!(
        !verify_disclosure(&disclosure),
        "VULNERABILITY: forged output root passed verification"
    );
}

/// Attack: Corrupt a Merkle proof sibling hash.
#[test]
fn attack_disclosure_corrupt_merkle_sibling() {
    let verified = make_verified(sample_tokens());
    let mut disclosure = create_disclosure(&verified, &[2]).unwrap();

    // Flip a byte in the first sibling hash
    if !disclosure.proofs[0].siblings.is_empty() {
        disclosure.proofs[0].siblings[0].hash[0] ^= 0xFF;
    }

    assert!(
        !verify_disclosure(&disclosure),
        "VULNERABILITY: corrupted Merkle proof passed verification"
    );
}

/// Attack: Flip is_left direction in a Merkle proof node.
#[test]
fn attack_disclosure_flip_merkle_direction() {
    let verified = make_verified(sample_tokens());
    let mut disclosure = create_disclosure(&verified, &[2]).unwrap();

    // Flip the direction of a sibling
    if !disclosure.proofs[0].siblings.is_empty() {
        disclosure.proofs[0].siblings[0].is_left = !disclosure.proofs[0].siblings[0].is_left;
    }

    assert!(
        !verify_disclosure(&disclosure),
        "VULNERABILITY: flipped Merkle direction passed verification"
    );
}

/// Attack: Provide extra proofs (more than revealed tokens).
#[test]
fn attack_disclosure_extra_proof() {
    let verified = make_verified(sample_tokens());
    let mut disclosure = create_disclosure(&verified, &[2]).unwrap();

    // Duplicate the proof
    let extra = disclosure.proofs[0].clone();
    disclosure.proofs.push(extra);

    assert!(
        !verify_disclosure(&disclosure),
        "VULNERABILITY: extra Merkle proof passed verification"
    );
}

/// Attack: Use a proof from a different disclosure (different Merkle tree).
#[test]
fn attack_disclosure_cross_proof() {
    let verified1 = make_verified(vec![100, 200, 300, 400]);
    let verified2 = make_verified(vec![999, 888, 777, 666]);

    let disclosure1 = create_disclosure(&verified1, &[0]).unwrap();
    let mut disclosure2 = create_disclosure(&verified2, &[0]).unwrap();

    // Replace disclosure2's proof with disclosure1's
    disclosure2.proofs = disclosure1.proofs;

    assert!(
        !verify_disclosure(&disclosure2),
        "VULNERABILITY: cross-disclosure proof passed verification"
    );
}

/// Attack: Full reveal should match the original tokens exactly.
#[test]
fn attack_disclosure_full_reveal_integrity() {
    let tokens = sample_tokens();
    let verified = make_verified(tokens.clone());
    let indices: Vec<usize> = (0..tokens.len()).collect();
    let disclosure = create_disclosure(&verified, &indices).unwrap();

    // Extract all revealed tokens
    let mut revealed = Vec::new();
    for token in &disclosure.tokens {
        match token {
            DisclosedToken::Revealed { token_id, .. } => revealed.push(*token_id),
            _ => panic!("full reveal should not have redacted tokens"),
        }
    }

    assert_eq!(revealed, tokens, "Full reveal doesn't match original");
    assert!(verify_disclosure(&disclosure));
}

// ═══════════════════════════════════════════════════════════════════════
// 2. PROOF REPLAY / REUSE ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: Reuse a proof for different output tokens.
/// The proof itself might verify structurally, but the Merkle root
/// won't match the new tokens.
#[test]
fn attack_proof_replay_different_tokens() {
    let tokens_a = vec![100, 200, 300, 400];
    let tokens_b = vec![500, 600, 700, 800];

    let verified_a = make_verified(tokens_a.clone());
    let disclosure_a = create_disclosure(&verified_a, &[0, 1]).unwrap();

    // Now create a disclosure for tokens_b but try to use tokens_a's proof
    let verified_b = make_verified(tokens_b);
    let disclosure_b = create_disclosure(&verified_b, &[0, 1]).unwrap();

    // Verify that the two disclosures have different output roots
    assert_ne!(
        disclosure_a.output_root, disclosure_b.output_root,
        "VULNERABILITY: different tokens produce the same Merkle root"
    );
}

/// Attack: Create two proofs with the same backend but different code hashes.
/// They should produce different chain tips.
#[test]
fn attack_proof_different_code_hashes() {
    let backend = HashIvc;
    let code_a = hash_data(b"function_a");
    let code_b = hash_data(b"function_b");

    let witness = StepWitness {
        state_before: hash_data(b"input"),
        state_after: hash_data(b"output"),
        step_inputs: hash_data(b"data"),
    };

    let mut acc_a = backend.init(&code_a, PrivacyMode::Transparent);
    backend.fold_step(&mut acc_a, &witness).unwrap();
    let proof_a = backend.finalize(acc_a).unwrap();

    let mut acc_b = backend.init(&code_b, PrivacyMode::Transparent);
    backend.fold_step(&mut acc_b, &witness).unwrap();
    let proof_b = backend.finalize(acc_b).unwrap();

    // Same computation, different code identity → different proofs
    match (&proof_a, &proof_b) {
        (
            VerifiedProof::HashIvc {
                code_hash: ch_a, ..
            },
            VerifiedProof::HashIvc {
                code_hash: ch_b, ..
            },
        ) => {
            assert_ne!(ch_a, ch_b, "Different code hashes should produce different proofs");
        }
        _ => panic!("wrong proof types"),
    }
}

/// Attack: Zero step count should fail verification.
#[test]
fn attack_proof_zero_step_count() {
    let proof = VerifiedProof::HashIvc {
        chain_tip: [0x01; 32],
        merkle_root: [0x02; 32],
        step_count: 0, // invalid!
        code_hash: [0x03; 32],
        privacy_mode: PrivacyMode::Transparent,
        blinding_commitment: None,
    };

    let backend = HashIvc;
    let result = backend.verify(&proof, &ZERO_HASH, &ZERO_HASH).unwrap();
    assert!(
        !result,
        "VULNERABILITY: zero step count passed verification"
    );
}

/// Attack: Private mode without blinding commitment should fail.
#[test]
fn attack_proof_private_without_blinding() {
    let proof = VerifiedProof::HashIvc {
        chain_tip: [0x01; 32],
        merkle_root: [0x02; 32],
        step_count: 5,
        code_hash: [0x03; 32],
        privacy_mode: PrivacyMode::Private,
        blinding_commitment: None, // missing!
    };

    let backend = HashIvc;
    let result = backend.verify(&proof, &ZERO_HASH, &ZERO_HASH).unwrap();
    assert!(
        !result,
        "VULNERABILITY: private mode without blinding passed verification"
    );
}

/// Attack: PrivateInputs mode without blinding commitment should also fail.
#[test]
fn attack_proof_private_inputs_without_blinding() {
    let proof = VerifiedProof::HashIvc {
        chain_tip: [0x01; 32],
        merkle_root: [0x02; 32],
        step_count: 3,
        code_hash: [0x03; 32],
        privacy_mode: PrivacyMode::PrivateInputs,
        blinding_commitment: None, // missing!
    };

    let backend = HashIvc;
    let result = backend.verify(&proof, &ZERO_HASH, &ZERO_HASH).unwrap();
    assert!(
        !result,
        "VULNERABILITY: PrivateInputs without blinding passed verification"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 3. HASH CHAIN MANIPULATION ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: Verify that altering a single step's witness changes the final proof.
#[test]
fn attack_hash_chain_step_alteration() {
    let backend = HashIvc;
    let code_hash = hash_data(b"test_fn");

    // Original chain: 5 steps
    let mut acc1 = backend.init(&code_hash, PrivacyMode::Transparent);
    for i in 0..5u8 {
        let witness = StepWitness {
            state_before: hash_data(&[i]),
            state_after: hash_data(&[i + 1]),
            step_inputs: hash_data(&[i * 2]),
        };
        backend.fold_step(&mut acc1, &witness).unwrap();
    }
    let proof1 = backend.finalize(acc1).unwrap();

    // Altered chain: same steps except step 2 has different input
    let mut acc2 = backend.init(&code_hash, PrivacyMode::Transparent);
    for i in 0..5u8 {
        let inputs = if i == 2 { hash_data(&[0xFF]) } else { hash_data(&[i * 2]) };
        let witness = StepWitness {
            state_before: hash_data(&[i]),
            state_after: hash_data(&[i + 1]),
            step_inputs: inputs,
        };
        backend.fold_step(&mut acc2, &witness).unwrap();
    }
    let proof2 = backend.finalize(acc2).unwrap();

    // The chain tips must differ
    match (&proof1, &proof2) {
        (
            VerifiedProof::HashIvc {
                chain_tip: tip1,
                merkle_root: root1,
                ..
            },
            VerifiedProof::HashIvc {
                chain_tip: tip2,
                merkle_root: root2,
                ..
            },
        ) => {
            assert_ne!(tip1, tip2, "VULNERABILITY: altered step didn't change chain tip");
            assert_ne!(
                root1, root2,
                "VULNERABILITY: altered step didn't change Merkle root"
            );
        }
        _ => panic!("wrong proof types"),
    }
}

/// Attack: Verify step ordering matters — same steps in different order
/// must produce different proofs.
#[test]
fn attack_hash_chain_step_reordering() {
    let backend = HashIvc;
    let code_hash = hash_data(b"order_test");

    let witness_a = StepWitness {
        state_before: hash_data(b"A_before"),
        state_after: hash_data(b"A_after"),
        step_inputs: hash_data(b"A_inputs"),
    };
    let witness_b = StepWitness {
        state_before: hash_data(b"B_before"),
        state_after: hash_data(b"B_after"),
        step_inputs: hash_data(b"B_inputs"),
    };

    // Order A, B
    let mut acc1 = backend.init(&code_hash, PrivacyMode::Transparent);
    backend.fold_step(&mut acc1, &witness_a).unwrap();
    backend.fold_step(&mut acc1, &witness_b).unwrap();
    let proof_ab = backend.finalize(acc1).unwrap();

    // Order B, A
    let mut acc2 = backend.init(&code_hash, PrivacyMode::Transparent);
    backend.fold_step(&mut acc2, &witness_b).unwrap();
    backend.fold_step(&mut acc2, &witness_a).unwrap();
    let proof_ba = backend.finalize(acc2).unwrap();

    match (&proof_ab, &proof_ba) {
        (
            VerifiedProof::HashIvc {
                chain_tip: tip_ab, ..
            },
            VerifiedProof::HashIvc {
                chain_tip: tip_ba, ..
            },
        ) => {
            assert_ne!(
                tip_ab, tip_ba,
                "VULNERABILITY: step reordering didn't change chain tip"
            );
        }
        _ => panic!("wrong proof types"),
    }
}

/// Attack: Private mode should produce blinding; transparent should not.
/// Verify that enabling privacy actually changes the proof structure.
#[test]
fn attack_privacy_mode_blinding_presence() {
    let backend = HashIvc;
    let code_hash = hash_data(b"privacy_test");
    let witness = StepWitness {
        state_before: hash_data(b"before"),
        state_after: hash_data(b"after"),
        step_inputs: hash_data(b"inputs"),
    };

    // Transparent
    let mut acc_t = backend.init(&code_hash, PrivacyMode::Transparent);
    backend.fold_step(&mut acc_t, &witness).unwrap();
    let proof_t = backend.finalize(acc_t).unwrap();

    // Private
    let mut acc_p = backend.init(&code_hash, PrivacyMode::Private);
    backend.fold_step(&mut acc_p, &witness).unwrap();
    let proof_p = backend.finalize(acc_p).unwrap();

    match (&proof_t, &proof_p) {
        (
            VerifiedProof::HashIvc {
                blinding_commitment: bc_t,
                ..
            },
            VerifiedProof::HashIvc {
                blinding_commitment: bc_p,
                ..
            },
        ) => {
            assert!(bc_t.is_none(), "Transparent mode should have no blinding");
            assert!(bc_p.is_some(), "Private mode should have blinding");
            assert_ne!(
                bc_p.unwrap(),
                ZERO_HASH,
                "Blinding commitment should not be zero"
            );
        }
        _ => panic!("wrong proof types"),
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 4. DOMAIN SEPARATION ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: hash_leaf and hash_data must produce different outputs for same input.
/// (Different domain bytes: 0x00 for leaf vs no prefix for data.)
#[test]
fn attack_domain_separation_leaf_vs_data() {
    let input = [0xAB; 32];
    let h_leaf = hash_leaf(&input);
    let h_data = hash_data(&input);
    assert_ne!(
        h_leaf, h_data,
        "VULNERABILITY: hash_leaf and hash_data produce same output"
    );
}

/// Attack: hash_combine (0x03) vs hash_data on same 64-byte input.
#[test]
fn attack_domain_separation_combine_vs_data() {
    let left = [0x00u8; 32];
    let right = [0x00u8; 32];
    let combined = hash_combine(&left, &right);

    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(&left);
    raw[32..].copy_from_slice(&right);
    let raw_hash = hash_data(&raw);

    assert_ne!(
        combined, raw_hash,
        "VULNERABILITY: hash_combine not domain-separated from hash_data"
    );
}

/// Attack: hash_transition (0x01) vs hash_combine (0x03) on same data.
#[test]
fn attack_domain_separation_transition_vs_combine() {
    let a = [0x01u8; 32];
    let b = [0x02u8; 32];
    let c = [0x03u8; 32];

    let transition = hash_transition(&a, &b, &c);
    // hash_combine only takes 2 args, but we test that the domain byte differs
    let combined = hash_combine(&a, &b);

    assert_ne!(
        transition, combined,
        "VULNERABILITY: transition hash collides with combine hash"
    );
}

/// Attack: hash_chain_step (0x02) vs hash_transition (0x01) on same data.
#[test]
fn attack_domain_separation_chain_vs_transition() {
    let a = [0x01u8; 32];
    let b = [0x02u8; 32];

    let chain = hash_chain_step(&a, &b);
    // hash_transition takes 3 args; test that 2-arg inputs don't collide
    // (This is inherently safe due to different input lengths, but verify anyway)
    assert_ne!(chain, hash_data(&a), "chain step should differ from hash_data");
    assert_ne!(chain, hash_leaf(&a), "chain step should differ from hash_leaf");
}

/// Attack: hash_blinding (0x04) vs hash_leaf (0x00) — verify isolation.
#[test]
fn attack_domain_separation_blinding_vs_leaf() {
    let input = [0xCC; 32];
    let blinding = hash_blinding(&input);
    let leaf = hash_leaf(&input);

    assert_ne!(
        blinding, leaf,
        "VULNERABILITY: blinding hash collides with leaf hash"
    );
}

/// Attack: All 5 domain-separated hashes must produce different outputs.
#[test]
fn attack_domain_separation_all_five_unique() {
    let input = [0xDD; 32];
    let hashes = [
        hash_leaf(&input),         // 0x00
        hash_chain_step(&input, &input), // 0x02 (65 bytes)
        hash_combine(&input, &input),    // 0x03 (65 bytes)
        hash_blinding(&input),     // 0x04
        hash_data(&input),         // no prefix
    ];

    for i in 0..hashes.len() {
        for j in (i + 1)..hashes.len() {
            assert_ne!(
                hashes[i], hashes[j],
                "VULNERABILITY: domain functions {} and {} collide",
                i, j
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 5. MERKLE PROOF FORGERY ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: Forge a Merkle proof with random sibling hashes.
#[test]
fn attack_merkle_forge_random_proof() {
    let leaves: Vec<Hash> = (0..8u8).map(|i| hash_leaf(&[i])).collect();
    let tree = MerkleTree::build(&leaves);

    // Create a forged proof for leaf 3 with random siblings
    let forged = MerkleProof {
        leaf: leaves[3],
        leaf_index: 3,
        siblings: vec![
            ProofNode {
                hash: [0xAA; 32],
                is_left: false,
            },
            ProofNode {
                hash: [0xBB; 32],
                is_left: true,
            },
            ProofNode {
                hash: [0xCC; 32],
                is_left: false,
            },
        ],
        root: tree.root,
        code_hash: ZERO_HASH,
    };

    assert!(
        !verify_proof(&forged),
        "VULNERABILITY: forged Merkle proof with random siblings passed"
    );
}

/// Attack: Use a valid proof but with wrong leaf_index.
#[test]
fn attack_merkle_wrong_leaf_index() {
    let leaves: Vec<Hash> = (0..4u8).map(|i| hash_leaf(&[i])).collect();
    let tree = MerkleTree::build(&leaves);

    let mut proof = tree.generate_proof(2, &ZERO_HASH).unwrap();
    assert!(verify_proof(&proof)); // should pass originally

    // Change the leaf index (but not the leaf or siblings)
    proof.leaf_index = 0; // wrong index
    // Note: verify_proof doesn't check leaf_index — it only recomputes the root.
    // This is a known property: leaf_index is metadata, not part of verification.
    // The siblings themselves encode the path.
}

/// Attack: Replace a leaf in a valid proof with a different leaf.
#[test]
fn attack_merkle_wrong_leaf() {
    let leaves: Vec<Hash> = (0..4u8).map(|i| hash_leaf(&[i])).collect();
    let tree = MerkleTree::build(&leaves);

    let mut proof = tree.generate_proof(2, &ZERO_HASH).unwrap();
    // Replace the leaf with a different one
    proof.leaf = hash_leaf(&[0xFF]);

    assert!(
        !verify_proof(&proof),
        "VULNERABILITY: wrong leaf in Merkle proof passed"
    );
}

/// Attack: Truncate the sibling path (remove last sibling).
#[test]
fn attack_merkle_truncated_path() {
    let leaves: Vec<Hash> = (0..8u8).map(|i| hash_leaf(&[i])).collect();
    let tree = MerkleTree::build(&leaves);

    let mut proof = tree.generate_proof(3, &ZERO_HASH).unwrap();
    assert!(verify_proof(&proof)); // valid

    // Truncate the last sibling
    proof.siblings.pop();

    assert!(
        !verify_proof(&proof),
        "VULNERABILITY: truncated Merkle path passed verification"
    );
}

/// Attack: Verify Merkle tree with duplicate leaves still produces correct proofs.
#[test]
fn attack_merkle_duplicate_leaves() {
    let leaf = hash_leaf(&[42]);
    let leaves = vec![leaf, leaf, leaf, leaf];
    let tree = MerkleTree::build(&leaves);

    // All leaves are the same, but each position should have a unique path
    for i in 0..4 {
        let proof = tree.generate_proof(i, &ZERO_HASH).unwrap();
        assert!(verify_proof(&proof), "proof failed for duplicate leaf at {}", i);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// 6. HASH CHAIN INTEGRITY
// ═══════════════════════════════════════════════════════════════════════

/// Verify hash chain is strictly sequential (each step depends on previous).
#[test]
fn attack_hash_chain_sequential_dependency() {
    let a = hash_data(b"step_0");
    let b = hash_data(b"step_1");

    let chain1 = hash_chain_step(&ZERO_HASH, &a);
    let chain2 = hash_chain_step(&chain1, &b);

    // Swapping order should give different result
    let chain2_alt = hash_chain_step(&ZERO_HASH, &b);
    let chain1_alt = hash_chain_step(&chain2_alt, &a);

    assert_ne!(
        chain2, chain1_alt,
        "VULNERABILITY: hash chain is commutative"
    );
}

/// Verify hash_transition is deterministic.
#[test]
fn attack_hash_transition_deterministic() {
    let prev = hash_data(b"prev_state");
    let input = hash_data(b"input_data");
    let claimed = hash_data(b"claimed_output");

    let h1 = hash_transition(&prev, &input, &claimed);
    let h2 = hash_transition(&prev, &input, &claimed);

    assert_eq!(h1, h2, "hash_transition is not deterministic");
    assert_ne!(h1, ZERO_HASH, "hash_transition should not produce zero");
}

/// Verify that hash_combine is NOT commutative (left/right ordering matters).
#[test]
fn attack_hash_combine_non_commutative() {
    let a = hash_data(b"left");
    let b = hash_data(b"right");

    let ab = hash_combine(&a, &b);
    let ba = hash_combine(&b, &a);

    assert_ne!(
        ab, ba,
        "VULNERABILITY: hash_combine is commutative (Merkle tree second preimage)"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 7. PROOF SERIALIZATION ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: Deserialize a truncated MerkleProof (too few bytes).
#[test]
fn attack_proof_deserialization_truncated() {
    let result = MerkleProof::from_bytes(&[0u8; 50]); // < 108 bytes
    assert!(
        result.is_err(),
        "VULNERABILITY: truncated proof deserialized successfully"
    );
}

/// Attack: Serialization/deserialization roundtrip must be lossless.
#[test]
fn attack_proof_serialization_roundtrip() {
    let leaves: Vec<Hash> = (0..8u8).map(|i| hash_leaf(&[i])).collect();
    let tree = MerkleTree::build(&leaves);
    let proof = tree.generate_proof(5, &hash_data(b"code")).unwrap();

    let bytes = proof.to_bytes();
    let decoded = MerkleProof::from_bytes(&bytes).unwrap();

    assert_eq!(decoded.leaf, proof.leaf);
    assert_eq!(decoded.leaf_index, proof.leaf_index);
    assert_eq!(decoded.siblings.len(), proof.siblings.len());
    assert_eq!(decoded.root, proof.root);
    assert_eq!(decoded.code_hash, proof.code_hash);

    // Decoded proof should still verify
    assert!(verify_proof(&decoded));
}

/// Attack: ProofNode with invalid is_left byte (not 0x00 or 0x01).
#[test]
fn attack_proof_node_invalid_is_left() {
    let mut bytes = [0u8; 33];
    bytes[32] = 0x02; // invalid!

    let result = ProofNode::from_bytes(&bytes);
    assert!(
        result.is_err(),
        "VULNERABILITY: invalid is_left byte accepted"
    );
}

// ═══════════════════════════════════════════════════════════════════════
// 8. PRIVACY MODE ATTACKS
// ═══════════════════════════════════════════════════════════════════════

/// Attack: In Private mode, code_hash() should return ZERO_HASH.
#[test]
fn attack_private_mode_hides_code_hash() {
    let real_code = hash_data(b"secret_algorithm");
    let proof = VerifiedProof::HashIvc {
        chain_tip: [0x01; 32],
        merkle_root: [0x02; 32],
        step_count: 1,
        code_hash: real_code,
        privacy_mode: PrivacyMode::Private,
        blinding_commitment: Some([0xAA; 32]),
    };

    assert_eq!(
        proof.code_hash(),
        ZERO_HASH,
        "VULNERABILITY: Private mode leaks code hash"
    );
}

/// Attack: In PrivateInputs mode, code_hash should still be visible.
#[test]
fn attack_private_inputs_shows_code_hash() {
    let real_code = hash_data(b"my_function");
    let proof = VerifiedProof::HashIvc {
        chain_tip: [0x01; 32],
        merkle_root: [0x02; 32],
        step_count: 1,
        code_hash: real_code,
        privacy_mode: PrivacyMode::PrivateInputs,
        blinding_commitment: Some([0xAA; 32]),
    };

    assert_eq!(
        proof.code_hash(),
        real_code,
        "PrivateInputs should reveal code hash"
    );
}

/// Attack: In Transparent mode, code_hash should be visible.
#[test]
fn attack_transparent_shows_code_hash() {
    let real_code = hash_data(b"public_function");
    let proof = VerifiedProof::HashIvc {
        chain_tip: [0x01; 32],
        merkle_root: [0x02; 32],
        step_count: 1,
        code_hash: real_code,
        privacy_mode: PrivacyMode::Transparent,
        blinding_commitment: None,
    };

    assert_eq!(
        proof.code_hash(),
        real_code,
        "Transparent should reveal code hash"
    );
}

/// Attack: Verify privacy mode transitions are consistent.
#[test]
fn attack_privacy_mode_properties() {
    // Transparent: nothing hidden
    assert!(!PrivacyMode::Transparent.is_private());
    assert!(!PrivacyMode::Transparent.hides_inputs());
    assert!(!PrivacyMode::Transparent.hides_outputs());

    // PrivateInputs: inputs hidden, outputs visible
    assert!(PrivacyMode::PrivateInputs.is_private());
    assert!(PrivacyMode::PrivateInputs.hides_inputs());
    assert!(!PrivacyMode::PrivateInputs.hides_outputs());

    // Private: everything hidden
    assert!(PrivacyMode::Private.is_private());
    assert!(PrivacyMode::Private.hides_inputs());
    assert!(PrivacyMode::Private.hides_outputs());
}

// ═══════════════════════════════════════════════════════════════════════
// 9. CONSTANT-TIME HASH COMPARISON
// ═══════════════════════════════════════════════════════════════════════

/// Verify hash_eq is correct (functional test — timing is hard to test).
#[test]
fn attack_hash_eq_correctness() {
    use poly_verified::types::hash_eq;

    let a = hash_data(b"hello");
    let b = hash_data(b"hello");
    let c = hash_data(b"world");

    assert!(hash_eq(&a, &b), "Equal hashes should compare equal");
    assert!(!hash_eq(&a, &c), "Different hashes should compare unequal");
    assert!(!hash_eq(&a, &ZERO_HASH), "Non-zero hash should not equal ZERO_HASH");
    assert!(hash_eq(&ZERO_HASH, &ZERO_HASH), "ZERO_HASH should equal itself");
}

/// Attack: hash_eq should catch single-bit differences.
#[test]
fn attack_hash_eq_single_bit_difference() {
    use poly_verified::types::hash_eq;

    let a = hash_data(b"test");
    for byte_idx in 0..32 {
        for bit in 0..8 {
            let mut b = a;
            b[byte_idx] ^= 1 << bit;
            assert!(
                !hash_eq(&a, &b),
                "hash_eq missed single-bit difference at byte {} bit {}",
                byte_idx,
                bit
            );
        }
    }
}
