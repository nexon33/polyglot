//! Adversarial break-attempt tests for HashIvc verification.
//!
//! Each test attempts a specific attack vector against the hardened
//! HashIvc verification. Tests assert:
//!   - `!result` with "HARDENED: ..." when the attack is correctly caught
//!   - `result`  with "VULNERABILITY: ..." if the attack bypasses verification
//!
//! Attack surface covered:
//!   1.  Second preimage on hash chain
//!   2.  Merkle tree odd-leaf duplication exploit
//!   3.  Privacy mode downgrade attack (Private -> Transparent)
//!   4.  Privacy mode upgrade attack (Transparent -> Private)
//!   5.  Checkpoint reordering attack
//!   6.  Empty checkpoint injection (ZERO_HASH as checkpoint)
//!   7.  Chain tip collision via repeated state_hash
//!   8.  Blinding commitment forgery for different checkpoints
//!   9.  code_hash substitution (now HARDENED: bound into chain_tip)
//!  10.  Proof with step_count = u64::MAX
//!  11.  Self-referential checkpoint (fixed-point)
//!  12.  Cross-privacy blinding leakage

use poly_verified::crypto::chain::HashChain;
use poly_verified::crypto::hash::{
    hash_blinding, hash_chain_step, hash_combine, hash_data,
};
use poly_verified::crypto::merkle::MerkleTree;
use poly_verified::ivc::hash_ivc::HashIvc;
use poly_verified::ivc::IvcBackend;
use poly_verified::types::{Hash, PrivacyMode, StepWitness, VerifiedProof, ZERO_HASH};

// ============================================================================
// Helper: build a valid proof with the given privacy mode and N steps
// ============================================================================

fn make_proof(
    privacy: PrivacyMode,
    steps: u8,
    input: &Hash,
    output: &Hash,
) -> VerifiedProof {
    let backend = HashIvc;
    let code_hash = hash_data(b"test_code");
    let mut acc = backend.init(&code_hash, privacy);
    for i in 0..steps {
        let witness = StepWitness {
            state_before: hash_data(&[i]),
            state_after: hash_data(&[i + 1]),
            step_inputs: hash_data(&[i, i]),
        };
        backend.fold_step(&mut acc, &witness).unwrap();
    }
    acc.input_hash = *input;
    acc.output_hash = *output;
    backend.finalize(acc).unwrap()
}

/// Extract all fields from a HashIvc proof for tampering.
#[allow(clippy::type_complexity)]
fn decompose(
    proof: &VerifiedProof,
) -> (Hash, Hash, u64, Hash, PrivacyMode, Option<Hash>, Vec<Hash>, Hash, Hash) {
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
        } => (
            *chain_tip,
            *merkle_root,
            *step_count,
            *code_hash,
            *privacy_mode,
            *blinding_commitment,
            checkpoints.clone(),
            *input_hash,
            *output_hash,
        ),
        _ => panic!("expected HashIvc proof"),
    }
}

fn reassemble(
    chain_tip: Hash,
    merkle_root: Hash,
    step_count: u64,
    code_hash: Hash,
    privacy_mode: PrivacyMode,
    blinding_commitment: Option<Hash>,
    checkpoints: Vec<Hash>,
    input_hash: Hash,
    output_hash: Hash,
) -> VerifiedProof {
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
    }
}

/// Compute the bound chain_tip: hash_combine(hash_combine(raw_tip, hash_data(code_hash)), hash_data([privacy as u8]))
fn bind_tip(raw_tip: &Hash, code_hash: &Hash, privacy: PrivacyMode) -> Hash {
    let code_binding = hash_data(code_hash);
    let mode_binding = hash_data(&[privacy as u8]);
    hash_combine(&hash_combine(raw_tip, &code_binding), &mode_binding)
}

// ============================================================================
// 1. Second preimage on hash chain
//
// Can we construct two DIFFERENT checkpoint sequences that produce the
// same chain_tip? The hash chain is tip = hash_chain_step(tip, cp) for each
// checkpoint. A collision requires finding cp_seq_A != cp_seq_B such that
// chaining both from ZERO_HASH yields the same tip. With SHA-256 this is
// computationally infeasible.
// ============================================================================

#[test]
fn attack_01_second_preimage_on_hash_chain() {
    let backend = HashIvc;

    // Sequence A: [hash_data(0), hash_data(1)]
    let cp_a = vec![hash_data(&[0u8]), hash_data(&[1u8])];
    // Sequence B: swap order [hash_data(1), hash_data(0)]
    let cp_b = vec![hash_data(&[1u8]), hash_data(&[0u8])];

    let mut chain_a = HashChain::new();
    for cp in &cp_a {
        chain_a.append(cp);
    }
    let mut chain_b = HashChain::new();
    for cp in &cp_b {
        chain_b.append(cp);
    }

    // The chain tips MUST differ for different sequences
    assert_ne!(
        chain_a.tip, chain_b.tip,
        "HARDENED: different checkpoint sequences produce different chain tips"
    );

    // Build a valid proof from sequence A
    let tree_a = MerkleTree::build(&cp_a);
    let code = hash_data(b"test");
    let bound_tip_a = bind_tip(&chain_a.tip, &code, PrivacyMode::Transparent);
    let proof_a = reassemble(
        bound_tip_a,
        tree_a.root,
        2,
        code,
        PrivacyMode::Transparent,
        None,
        cp_a.clone(),
        ZERO_HASH,
        ZERO_HASH,
    );
    assert!(
        backend.verify(&proof_a, &ZERO_HASH, &ZERO_HASH).unwrap(),
        "sanity: valid proof A should verify"
    );

    // Attempt: use sequence B's checkpoints but claim sequence A's bound chain_tip
    let tree_b = MerkleTree::build(&cp_b);
    let forged = reassemble(
        bound_tip_a, // from sequence A (bound)
        tree_b.root, // from sequence B
        2,
        code,
        PrivacyMode::Transparent,
        None,
        cp_b,         // sequence B checkpoints
        ZERO_HASH,
        ZERO_HASH,
    );
    let result = backend.verify(&forged, &ZERO_HASH, &ZERO_HASH).unwrap();
    assert!(
        !result,
        "HARDENED: second preimage attack on hash chain is rejected (chain_tip mismatch)"
    );
    eprintln!("ATTACK 01 RESULT: Second preimage attack on hash chain correctly rejected");
}

// ============================================================================
// 2. Merkle tree odd-leaf duplication exploit
//
// With an odd number of checkpoints, the last leaf is duplicated when
// building the Merkle tree: hash_combine(last, last). Can we exploit this
// by adding a fake duplicate checkpoint that still produces the same root?
// ============================================================================

#[test]
fn attack_02_merkle_odd_leaf_duplication() {
    let backend = HashIvc;

    // Create a valid proof with 3 steps (odd -> last leaf duplicated in Merkle tree)
    let input = ZERO_HASH;
    let output = ZERO_HASH;
    let proof = make_proof(PrivacyMode::Transparent, 3, &input, &output);

    let (chain_tip, merkle_root, step_count, code_hash, privacy, blinding, checkpoints, ih, oh) =
        decompose(&proof);
    assert_eq!(step_count, 3);
    assert_eq!(checkpoints.len(), 3);

    // The Merkle tree for 3 leaves duplicates the 3rd:
    // Layer 0: [c0, c1, c2]
    // Layer 1: [H(c0,c1), H(c2,c2)]
    // Root:    H(H(c0,c1), H(c2,c2))

    // Attack: add the duplicated leaf explicitly to get 4 checkpoints
    // [c0, c1, c2, c2] -- this gives a DIFFERENT Merkle tree:
    // Layer 0: [c0, c1, c2, c2]
    // Layer 1: [H(c0,c1), H(c2,c2)]  <-- same!
    // Root:    H(H(c0,c1), H(c2,c2)) <-- same root!
    //
    // BUT: the chain_tip will differ because we appended an extra step
    let mut forged_cps = checkpoints.clone();
    forged_cps.push(checkpoints[2]); // duplicate last

    let forged_tree = MerkleTree::build(&forged_cps);
    // Merkle roots might actually match (this is the vulnerability question)
    let merkle_roots_match = forged_tree.root == merkle_root;

    // Even if Merkle roots match, chain_tip won't, because we have 4 chain steps
    let mut forged_chain = HashChain::new();
    for cp in &forged_cps {
        forged_chain.append(cp);
    }

    let forged_bound_tip = bind_tip(&forged_chain.tip, &code_hash, privacy);
    let forged_proof = reassemble(
        forged_bound_tip, // recomputed for 4 steps, bound with code_hash + privacy
        forged_tree.root,
        4,
        code_hash,
        privacy,
        blinding,
        forged_cps,
        ih,
        oh,
    );

    let result = backend.verify(&forged_proof, &input, &output).unwrap();

    if merkle_roots_match {
        // The Merkle root collision exists, but the chain_tip and step_count differ
        // so the proof represents a DIFFERENT computation (4 steps, not 3).
        // It may verify as a VALID 4-step proof, but it is NOT the same proof as
        // the original 3-step one. The verifier doesn't know the original was 3 steps.
        // This is not exploitable because the chain_tip commits to all 4 steps.
        eprintln!(
            "ATTACK 02 INFO: Merkle root collision exists for odd-dup, \
             but chain_tip differentiates the proofs. Result: {}",
            result
        );
        // The 4-step proof should verify as a valid (different) proof
        // since its chain_tip, merkle_root, and step_count are all self-consistent.
        // This is NOT a vulnerability -- it's a different valid proof.
        assert!(
            result,
            "EXPECTED: 4-step proof with consistent fields should verify as valid"
        );
        eprintln!("ATTACK 02 RESULT: Merkle odd-leaf duplication does NOT forge the original proof");
    } else {
        assert!(
            !result,
            "HARDENED: forged 4-step proof with wrong merkle_root rejected"
        );
        eprintln!("ATTACK 02 RESULT: Merkle odd-leaf duplication correctly rejected");
    }

    // Also confirm: claiming the ORIGINAL chain_tip with the forged 4-step checkpoints fails
    let forged_with_original_tip = reassemble(
        chain_tip,        // original 3-step chain_tip
        forged_tree.root, // 4-step merkle root
        4,                // 4 steps
        code_hash,
        privacy,
        blinding,
        vec![checkpoints[0], checkpoints[1], checkpoints[2], checkpoints[2]],
        ih,
        oh,
    );
    let result2 = backend
        .verify(&forged_with_original_tip, &input, &output)
        .unwrap();
    assert!(
        !result2,
        "HARDENED: original chain_tip with 4 forged checkpoints is rejected"
    );
}

// ============================================================================
// 3. Privacy mode downgrade attack (Private -> Transparent)
//
// Take a Private proof (hides I/O), change privacy_mode to Transparent,
// and check if verify still passes. Goal: force I/O disclosure.
// ============================================================================

#[test]
fn attack_03_privacy_downgrade_private_to_transparent() {
    let backend = HashIvc;
    let input = hash_data(b"secret_input");
    let output = hash_data(b"secret_output");

    // Create a Private proof (I/O hidden, blinding present)
    let proof = make_proof(PrivacyMode::Private, 2, &input, &output);
    let (chain_tip, merkle_root, step_count, code_hash, _, blinding, checkpoints, ih, oh) =
        decompose(&proof);

    // Verify original is valid in Private mode (I/O not checked)
    assert!(backend.verify(&proof, &ZERO_HASH, &ZERO_HASH).unwrap());

    // Attack: switch to Transparent, keep blinding_commitment
    let downgraded = reassemble(
        chain_tip,
        merkle_root,
        step_count,
        code_hash,
        PrivacyMode::Transparent,
        blinding, // still has blinding from Private mode
        checkpoints.clone(),
        ih,
        oh,
    );
    let result = backend.verify(&downgraded, &ih, &oh).unwrap();
    assert!(
        !result,
        "HARDENED: downgrade from Private to Transparent rejected \
         (Transparent mode must not have blinding_commitment)"
    );

    // Attack variant: strip blinding_commitment too
    let downgraded_no_blinding = reassemble(
        chain_tip,
        merkle_root,
        step_count,
        code_hash,
        PrivacyMode::Transparent,
        None, // removed blinding
        checkpoints,
        ih,
        oh,
    );
    let result2 = backend
        .verify(&downgraded_no_blinding, &ih, &oh)
        .unwrap();
    // HARDENED: privacy_mode is now bound into chain_tip. Switching Private -> Transparent
    // changes the expected chain_tip, so even stripping the blinding doesn't help.
    assert!(
        !result2,
        "HARDENED: downgrade fully rejected even without blinding \
         (privacy_mode bound into chain_tip)"
    );
    eprintln!(
        "ATTACK 03 RESULT: Privacy downgrade fully rejected. \
         privacy_mode is bound into chain_tip."
    );
}

// ============================================================================
// 4. Privacy mode upgrade attack (Transparent -> Private)
//
// Take a Transparent proof, change to Private mode, forge a blinding
// commitment. Goal: bypass I/O verification.
// ============================================================================

#[test]
fn attack_04_privacy_upgrade_transparent_to_private() {
    let backend = HashIvc;
    let input = hash_data(b"real_input");
    let output = hash_data(b"real_output");

    // Create a Transparent proof bound to specific I/O
    let proof = make_proof(PrivacyMode::Transparent, 2, &input, &output);
    let (chain_tip, merkle_root, step_count, code_hash, _, _, checkpoints, ih, oh) =
        decompose(&proof);

    // Verify it passes with correct I/O
    assert!(backend.verify(&proof, &input, &output).unwrap());
    // Verify it FAILS with wrong I/O
    let wrong_out = hash_data(b"wrong_output");
    assert!(!backend.verify(&proof, &input, &wrong_out).unwrap());

    // Attack: switch to Private mode with a FORGED blinding commitment
    // If this passes, the attacker bypasses I/O verification
    let forged_blinding = hash_data(b"attacker_blinding");
    let upgraded = reassemble(
        chain_tip,
        merkle_root,
        step_count,
        code_hash,
        PrivacyMode::Private,
        Some(forged_blinding),
        checkpoints,
        ih,
        oh,
    );

    // In Private mode, verify() skips I/O checks -- but it checks blinding_commitment
    let result = backend.verify(&upgraded, &ZERO_HASH, &ZERO_HASH).unwrap();
    assert!(
        !result,
        "HARDENED: upgrade to Private with forged blinding commitment rejected \
         (blinding must match recomputed value from checkpoints)"
    );
    eprintln!("ATTACK 04 RESULT: Privacy upgrade with forged blinding correctly rejected");
}

// ============================================================================
// 4b. Privacy upgrade with CORRECTLY COMPUTED blinding
//
// Can an attacker compute the real blinding from the checkpoints?
// Yes -- the blinding is deterministic from the checkpoints. If the attacker
// has the checkpoints (which are in the proof), they can compute the blinding.
// ============================================================================

#[test]
fn attack_04b_privacy_upgrade_with_correct_blinding() {
    let backend = HashIvc;
    let input = hash_data(b"real_input");
    let output = hash_data(b"real_output");

    let proof = make_proof(PrivacyMode::Transparent, 2, &input, &output);
    let (chain_tip, merkle_root, step_count, code_hash, _, _, checkpoints, ih, oh) =
        decompose(&proof);

    // Attacker computes the real blinding from the public checkpoints
    let mut computed_blinding = ZERO_HASH;
    for (i, cp) in checkpoints.iter().enumerate() {
        let counter = ((i + 1) as u64).to_le_bytes();
        let mut blinding_input = Vec::with_capacity(40);
        blinding_input.extend_from_slice(cp);
        blinding_input.extend_from_slice(&counter);
        let blinding = hash_blinding(&blinding_input);
        computed_blinding = hash_combine(&computed_blinding, &blinding);
    }

    let upgraded = reassemble(
        chain_tip,
        merkle_root,
        step_count,
        code_hash,
        PrivacyMode::Private,
        Some(computed_blinding),
        checkpoints,
        ih,
        oh,
    );

    // HARDENED: privacy_mode is now bound into the chain_tip. Switching
    // Transparent -> Private changes the expected chain_tip, so even with
    // a correctly computed blinding the proof is rejected.
    let result = backend.verify(&upgraded, &ZERO_HASH, &ZERO_HASH).unwrap();
    assert!(
        !result,
        "HARDENED: privacy upgrade now rejected because privacy_mode is bound into chain_tip"
    );
    eprintln!(
        "ATTACK 04b RESULT: HARDENED -- Privacy upgrade with computed blinding \
         is now rejected (privacy_mode bound into chain_tip)"
    );
}

// ============================================================================
// 5. Checkpoint reordering attack
//
// Take valid checkpoints [c0, c1, c2], reorder to [c2, c1, c0].
// The chain_tip will differ. Can we also swap the chain_tip to match?
// ============================================================================

#[test]
fn attack_05_checkpoint_reordering() {
    let backend = HashIvc;
    let input = ZERO_HASH;
    let output = ZERO_HASH;

    let proof = make_proof(PrivacyMode::Transparent, 3, &input, &output);
    let (chain_tip, _merkle_root, _step_count, code_hash, privacy, blinding, checkpoints, ih, oh) =
        decompose(&proof);

    // Reorder: [c0, c1, c2] -> [c2, c1, c0]
    let mut reordered = checkpoints.clone();
    reordered.reverse();
    assert_ne!(reordered, checkpoints, "sanity: order is different");

    // Recompute chain_tip for reordered sequence
    let mut reordered_chain = HashChain::new();
    for cp in &reordered {
        reordered_chain.append(cp);
    }
    let reordered_tree = MerkleTree::build(&reordered);

    // The chain tip MUST differ
    assert_ne!(
        reordered_chain.tip, chain_tip,
        "HARDENED: reordered checkpoints produce a different chain_tip"
    );

    // Build a self-consistent reordered proof (with bound tip)
    let reordered_bound_tip = bind_tip(&reordered_chain.tip, &code_hash, privacy);
    let reordered_proof = reassemble(
        reordered_bound_tip,
        reordered_tree.root,
        3,
        code_hash,
        privacy,
        blinding,
        reordered,
        ih,
        oh,
    );

    // This self-consistent reordered proof IS valid -- it represents a
    // DIFFERENT computation (steps happened in reverse order).
    // The key security property: the chain_tip differs, so a verifier who
    // checks against a specific expected chain_tip can tell them apart.
    let result = backend.verify(&reordered_proof, &input, &output).unwrap();

    // The reordered proof verifies because it is internally consistent.
    // However, it represents a DIFFERENT computation with a different chain_tip.
    // The verifier would need to check chain_tip matches the expected value
    // (this is application-layer concern, not in verify() itself).
    assert!(
        result,
        "EXPECTED: self-consistent reordered proof verifies (different computation)"
    );
    eprintln!(
        "ATTACK 05 RESULT: Reordering produces a different valid proof (different chain_tip). \
         Verifiers MUST check chain_tip at the application layer."
    );

    // Confirm: claiming the original chain_tip with reordered checkpoints FAILS
    let mismatched = reassemble(
        chain_tip,           // original chain_tip
        reordered_tree.root, // reordered merkle root
        3,
        code_hash,
        privacy,
        blinding,
        vec![checkpoints[2], checkpoints[1], checkpoints[0]],
        ih,
        oh,
    );
    let result2 = backend.verify(&mismatched, &input, &output).unwrap();
    assert!(
        !result2,
        "HARDENED: original chain_tip with reordered checkpoints is rejected"
    );
}

// ============================================================================
// 6. Empty checkpoint injection
//
// Create a proof with step_count=1 but inject ZERO_HASH as the checkpoint.
// Does the chain still validate?
// ============================================================================

#[test]
fn attack_06_empty_checkpoint_injection() {
    let backend = HashIvc;

    // Manually build a proof where the checkpoint is ZERO_HASH
    let zero_cp = ZERO_HASH;
    let mut chain = HashChain::new();
    chain.append(&zero_cp);
    let tree = MerkleTree::build(&[zero_cp]);

    let code = hash_data(b"test");
    let bound_tip = bind_tip(&chain.tip, &code, PrivacyMode::Transparent);
    let proof = reassemble(
        bound_tip,
        tree.root,
        1,
        code,
        PrivacyMode::Transparent,
        None,
        vec![zero_cp],
        ZERO_HASH,
        ZERO_HASH,
    );

    // This is internally consistent -- ZERO_HASH is just another hash value.
    // The verifier rebuilds the chain and Merkle tree from the checkpoint and
    // they match. There's nothing "empty" about ZERO_HASH from the crypto
    // perspective -- it's a valid 32-byte value.
    let result = backend.verify(&proof, &ZERO_HASH, &ZERO_HASH).unwrap();

    // The chain does validate because hash_chain_step(ZERO_HASH, ZERO_HASH)
    // is a well-defined, non-zero hash. The checkpoint is not truly "empty";
    // it is a specific hash that simply happens to be all zeros.
    assert!(
        result,
        "EXPECTED: ZERO_HASH checkpoint is a valid hash value; \
         the proof is internally consistent"
    );

    // Verify the chain tip is NOT zero (hash_chain_step applies domain separation)
    assert_ne!(
        chain.tip, ZERO_HASH,
        "HARDENED: hash_chain_step(ZERO, ZERO) produces a non-zero tip (domain-separated)"
    );
    eprintln!(
        "ATTACK 06 RESULT: ZERO_HASH checkpoint accepted (it is a valid hash). \
         Chain tip is non-zero due to domain separation."
    );
}

// ============================================================================
// 7. Chain tip collision via repeated state_hash
//
// Feed the same state_hash at every step. Does the chain produce unique
// intermediate values? (Tests whether chain state evolves.)
// ============================================================================

#[test]
fn attack_07_chain_tip_collision_via_repeated_hash() {
    let repeated = hash_data(b"same_every_step");

    // Build chains of different lengths with the same repeated checkpoint
    let mut tips = Vec::new();
    for length in 1..=10u64 {
        let mut chain = HashChain::new();
        for _ in 0..length {
            chain.append(&repeated);
        }
        tips.push(chain.tip);
    }

    // All tips must be unique -- even though the same value is appended each time,
    // the chain_step function incorporates the previous tip, making each step unique.
    for i in 0..tips.len() {
        for j in (i + 1)..tips.len() {
            assert_ne!(
                tips[i], tips[j],
                "HARDENED: chain tips at step {} and {} must differ even with repeated input",
                i + 1,
                j + 1
            );
        }
    }

    // Also verify that intermediate values (during chain building) are all unique
    let mut chain = HashChain::new();
    let mut intermediates = vec![chain.tip]; // starts at ZERO_HASH
    for _ in 0..10 {
        chain.append(&repeated);
        intermediates.push(chain.tip);
    }
    // 11 values (initial + 10 steps) should all be unique
    for i in 0..intermediates.len() {
        for j in (i + 1)..intermediates.len() {
            assert_ne!(
                intermediates[i], intermediates[j],
                "HARDENED: intermediate chain values at positions {} and {} must differ",
                i, j
            );
        }
    }

    eprintln!(
        "ATTACK 07 RESULT: Repeated state_hash produces unique chain tips at every step. \
         No collision possible."
    );
}

// ============================================================================
// 8. Blinding commitment forgery for DIFFERENT checkpoints
//
// In Private mode, try to compute a valid blinding commitment for
// DIFFERENT checkpoints than those in the proof.
// ============================================================================

#[test]
fn attack_08_blinding_forgery_different_checkpoints() {
    let backend = HashIvc;

    // Create a real Private proof with checkpoints A
    let input = ZERO_HASH;
    let output = ZERO_HASH;
    let proof_a = make_proof(PrivacyMode::Private, 2, &input, &output);
    let (_, _, _, code_hash_a, _, _, checkpoints_a, _, _) = decompose(&proof_a);

    // Create a different proof with checkpoints B
    let code_hash_b = hash_data(b"different_code");
    let backend_inst = HashIvc;
    let mut acc_b = backend_inst.init(&code_hash_b, PrivacyMode::Private);
    for i in 10..12u8 {
        let witness = StepWitness {
            state_before: hash_data(&[i]),
            state_after: hash_data(&[i + 1]),
            step_inputs: hash_data(&[i, i + 1]),
        };
        backend_inst.fold_step(&mut acc_b, &witness).unwrap();
    }
    let proof_b = backend_inst.finalize(acc_b).unwrap();
    let (_, _, _, _, _, blinding_b, checkpoints_b, _, _) = decompose(&proof_b);

    // Ensure checkpoints differ
    assert_ne!(checkpoints_a, checkpoints_b, "sanity: checkpoints differ");

    // Attack: use checkpoints from A but blinding from B
    let mut chain_a = HashChain::new();
    for cp in &checkpoints_a {
        chain_a.append(cp);
    }
    let tree_a = MerkleTree::build(&checkpoints_a);

    let bound_tip_a = bind_tip(&chain_a.tip, &code_hash_a, PrivacyMode::Private);
    let forged = reassemble(
        bound_tip_a,
        tree_a.root,
        checkpoints_a.len() as u64,
        code_hash_a,
        PrivacyMode::Private,
        blinding_b, // blinding from proof B
        checkpoints_a,
        ZERO_HASH,
        ZERO_HASH,
    );

    let result = backend.verify(&forged, &ZERO_HASH, &ZERO_HASH).unwrap();
    assert!(
        !result,
        "HARDENED: blinding commitment from different checkpoints is rejected \
         (blinding is deterministically tied to checkpoint values)"
    );
    eprintln!(
        "ATTACK 08 RESULT: Blinding from different checkpoints correctly rejected. \
         Commitment is deterministically bound to checkpoint content."
    );
}

// ============================================================================
// 9. code_hash is NOT verified by HashIvc::verify()
//
// Confirm that verify() ignores code_hash entirely (it's `code_hash: _`
// in the match). Can an attacker substitute any code_hash and pass?
// ============================================================================

#[test]
fn attack_09_code_hash_not_verified() {
    let backend = HashIvc;
    let input = ZERO_HASH;
    let output = ZERO_HASH;

    // Create a valid proof
    let proof = make_proof(PrivacyMode::Transparent, 2, &input, &output);
    let (chain_tip, merkle_root, step_count, _code_hash, privacy, blinding, checkpoints, ih, oh) =
        decompose(&proof);

    // Substitute a completely different code_hash
    let fake_code = hash_data(b"totally_different_code");
    let tampered = reassemble(
        chain_tip,
        merkle_root,
        step_count,
        fake_code, // CHANGED
        privacy,
        blinding,
        checkpoints.clone(),
        ih,
        oh,
    );

    let result = backend.verify(&tampered, &input, &output).unwrap();
    assert!(
        !result,
        "HARDENED: code_hash is now bound into chain_tip. \
         Substituting a different code_hash causes chain_tip mismatch."
    );

    // Also try with ZERO_HASH code
    let zero_code = reassemble(
        chain_tip,
        merkle_root,
        step_count,
        ZERO_HASH,
        privacy,
        blinding,
        checkpoints,
        ih,
        oh,
    );
    let result2 = backend.verify(&zero_code, &input, &output).unwrap();
    assert!(
        !result2,
        "HARDENED: ZERO code_hash also rejected (code_hash bound into chain_tip)"
    );

    eprintln!(
        "ATTACK 09 RESULT: HARDENED -- code_hash is now bound into chain_tip. \
         Substituting any code_hash is detected."
    );
}

// ============================================================================
// 10. Proof with step_count = u64::MAX
//
// Set step_count to u64::MAX. Does it panic or gracefully reject?
// ============================================================================

#[test]
fn attack_10_max_step_count() {
    let backend = HashIvc;

    // Fabricate a proof claiming u64::MAX steps but with only 1 checkpoint
    let cp = hash_data(b"single_step");
    let mut chain = HashChain::new();
    chain.append(&cp);
    let tree = MerkleTree::build(&[cp]);

    let proof = reassemble(
        chain.tip,
        tree.root,
        u64::MAX, // absurdly large
        hash_data(b"test"),
        PrivacyMode::Transparent,
        None,
        vec![cp], // only 1 checkpoint
        ZERO_HASH,
        ZERO_HASH,
    );

    // This should NOT panic and should return false (step_count != checkpoints.len())
    let result = backend.verify(&proof, &ZERO_HASH, &ZERO_HASH).unwrap();
    assert!(
        !result,
        "HARDENED: step_count=u64::MAX with 1 checkpoint is gracefully rejected \
         (step_count != checkpoints.len())"
    );

    // Also try step_count=0 with zero checkpoints
    let zero_proof = reassemble(
        ZERO_HASH,
        ZERO_HASH,
        0,
        hash_data(b"test"),
        PrivacyMode::Transparent,
        None,
        vec![],
        ZERO_HASH,
        ZERO_HASH,
    );
    let result2 = backend.verify(&zero_proof, &ZERO_HASH, &ZERO_HASH).unwrap();
    assert!(
        !result2,
        "HARDENED: step_count=0 is gracefully rejected (must have at least 1 step)"
    );

    eprintln!(
        "ATTACK 10 RESULT: step_count=u64::MAX gracefully rejected without panic. \
         step_count=0 also rejected."
    );
}

// ============================================================================
// 11. Self-referential checkpoint (fixed-point)
//
// A checkpoint whose value equals the chain tip at that step.
// Does this create any exploitable fixed-point?
// ============================================================================

#[test]
fn attack_11_self_referential_checkpoint() {
    // Can we find a hash h such that hash_chain_step(ZERO_HASH, h) == h ?
    // This would be a fixed point of the chain step function.
    // With SHA-256, finding such a fixed point is computationally infeasible.

    // Try a few candidate fixed points
    let candidates = [
        ZERO_HASH,
        [0xFF; 32],
        hash_data(b"fixed_point_attempt"),
        hash_chain_step(&ZERO_HASH, &ZERO_HASH), // tip after appending zero
    ];

    for candidate in &candidates {
        let step_result = hash_chain_step(&ZERO_HASH, candidate);
        assert_ne!(
            step_result, *candidate,
            "HARDENED: hash_chain_step(ZERO, x) != x -- no trivial fixed point"
        );
    }

    // Also check: does chaining a self-referential value create any cycle?
    let mut chain = HashChain::new();
    let initial_cp = hash_data(b"start");
    chain.append(&initial_cp);
    // Now use the chain tip as the next checkpoint
    let self_ref = chain.tip;
    chain.append(&self_ref);
    let after_self_ref = chain.tip;

    // The chain should NOT cycle back to self_ref
    assert_ne!(
        after_self_ref, self_ref,
        "HARDENED: self-referential checkpoint does not create a cycle"
    );

    // Verify a proof built with self-referential checkpoints still works normally
    let backend = HashIvc;
    let checkpoints = vec![initial_cp, self_ref];
    let mut verify_chain = HashChain::new();
    for cp in &checkpoints {
        verify_chain.append(cp);
    }
    let tree = MerkleTree::build(&checkpoints);

    let code = hash_data(b"test");
    let bound_tip = bind_tip(&verify_chain.tip, &code, PrivacyMode::Transparent);
    let proof = reassemble(
        bound_tip,
        tree.root,
        2,
        code,
        PrivacyMode::Transparent,
        None,
        checkpoints,
        ZERO_HASH,
        ZERO_HASH,
    );
    let result = backend.verify(&proof, &ZERO_HASH, &ZERO_HASH).unwrap();
    assert!(
        result,
        "EXPECTED: self-referential checkpoint is just a normal hash value; proof is valid"
    );

    eprintln!(
        "ATTACK 11 RESULT: No fixed-point exploitable. Self-referential checkpoints \
         do not create cycles and produce valid proofs."
    );
}

// ============================================================================
// 12. Cross-privacy blinding leakage
//
// Create a PrivateInputs proof. Does the blinding commitment reveal the
// checkpoints to an observer?
//
// Analysis: The blinding commitment is deterministically derived from the
// checkpoints. Since the checkpoints are INCLUDED in the proof (they are
// in the `checkpoints` field), the blinding doesn't "leak" anything that
// isn't already public. The real question is whether the blinding provides
// any additional information beyond what's in the checkpoints.
// ============================================================================

#[test]
fn attack_12_cross_privacy_blinding_leakage() {
    let backend = HashIvc;
    let input = hash_data(b"private_input");
    let output = hash_data(b"visible_output");

    // Create PrivateInputs proof
    let proof = make_proof(PrivacyMode::PrivateInputs, 3, &input, &output);
    let (_, _, _, _, _, blinding, checkpoints, _, _) = decompose(&proof);
    let blinding = blinding.expect("PrivateInputs should have blinding");

    // The blinding commitment is deterministic from checkpoints
    let mut recomputed = ZERO_HASH;
    for (i, cp) in checkpoints.iter().enumerate() {
        let counter = ((i + 1) as u64).to_le_bytes();
        let mut blinding_input = Vec::with_capacity(40);
        blinding_input.extend_from_slice(cp);
        blinding_input.extend_from_slice(&counter);
        let b = hash_blinding(&blinding_input);
        recomputed = hash_combine(&recomputed, &b);
    }

    assert_eq!(
        blinding, recomputed,
        "sanity: blinding is deterministic from checkpoints"
    );

    // The blinding does NOT add entropy beyond the checkpoints.
    // An observer with the checkpoints (which are in the proof) can always
    // recompute the blinding. This means the "privacy" comes from the
    // verify() I/O check bypass, NOT from the blinding hiding anything.
    //
    // The blinding is best understood as a proof-of-correct-privacy-mode
    // (preventing downgrade attacks), not as an information-hiding mechanism.

    // Verify: changing ANY single checkpoint changes the blinding
    let mut modified_cps = checkpoints.clone();
    modified_cps[1] = hash_data(b"altered");
    let mut modified_blinding = ZERO_HASH;
    for (i, cp) in modified_cps.iter().enumerate() {
        let counter = ((i + 1) as u64).to_le_bytes();
        let mut blinding_input = Vec::with_capacity(40);
        blinding_input.extend_from_slice(cp);
        blinding_input.extend_from_slice(&counter);
        let b = hash_blinding(&blinding_input);
        modified_blinding = hash_combine(&modified_blinding, &b);
    }
    assert_ne!(
        blinding, modified_blinding,
        "HARDENED: modifying a checkpoint changes the blinding commitment"
    );

    // Verify: the proof still passes verification
    assert!(backend.verify(&proof, &ZERO_HASH, &output).unwrap());

    // Key finding: blinding is derivable from public data (checkpoints).
    // This is consistent with attack 04b -- the blinding doesn't hide anything.
    eprintln!(
        "ATTACK 12 RESULT: Blinding commitment is deterministic from checkpoints \
         (which are public in the proof). No additional information is leaked, \
         but the blinding also does not HIDE the checkpoints. \
         Privacy relies solely on verify() skipping I/O checks."
    );
}

// ============================================================================
// BONUS: Combined attack -- privacy upgrade + code_hash forgery
//
// Chain attacks 4b and 9: upgrade to Private mode AND swap code_hash.
// This lets an attacker claim any code produced any output.
// ============================================================================

#[test]
fn attack_bonus_combined_privacy_upgrade_and_code_forgery() {
    let backend = HashIvc;

    // Create a proof for "untrusted_code" with known I/O
    let real_input = hash_data(b"real_input");
    let real_output = hash_data(b"real_output");
    let proof = make_proof(PrivacyMode::Transparent, 3, &real_input, &real_output);
    let (chain_tip, merkle_root, step_count, _, _, _, checkpoints, ih, oh) = decompose(&proof);

    // Original proof correctly rejects wrong I/O
    let wrong_input = hash_data(b"attacker_input");
    let wrong_output = hash_data(b"attacker_output");
    assert!(!backend.verify(&proof, &wrong_input, &wrong_output).unwrap());

    // Attack: compute real blinding, switch to Private, swap code_hash
    let mut computed_blinding = ZERO_HASH;
    for (i, cp) in checkpoints.iter().enumerate() {
        let counter = ((i + 1) as u64).to_le_bytes();
        let mut blinding_input = Vec::with_capacity(40);
        blinding_input.extend_from_slice(cp);
        blinding_input.extend_from_slice(&counter);
        let b = hash_blinding(&blinding_input);
        computed_blinding = hash_combine(&computed_blinding, &b);
    }

    let trusted_code = hash_data(b"google_audited_safe_code_v1");
    let forged = reassemble(
        chain_tip,
        merkle_root,
        step_count,
        trusted_code,               // forged code identity
        PrivacyMode::Private,       // upgraded to bypass I/O checks
        Some(computed_blinding),    // correctly computed blinding
        checkpoints,
        ih,
        oh,
    );

    // HARDENED: Both code_hash and privacy_mode are now bound into chain_tip.
    // Changing either causes chain_tip mismatch, so the combined attack fails.
    let result = backend.verify(&forged, &ZERO_HASH, &ZERO_HASH).unwrap();
    assert!(
        !result,
        "HARDENED: combined privacy-upgrade + code_hash forgery now rejected. \
         Both code_hash and privacy_mode are bound into chain_tip."
    );

    // The forged proof hides the code hash
    assert_eq!(forged.code_hash(), ZERO_HASH);

    eprintln!(
        "ATTACK BONUS RESULT: HARDENED -- Combined attack now rejected. \
         code_hash and privacy_mode are bound into chain_tip."
    );
}
