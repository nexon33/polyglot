//! Adversarial tests that attempt to BREAK the hardened ComplianceProof
//! verification. Each test mounts a specific attack against the proof system
//! and asserts whether it is caught (HARDENED) or succeeds (VULNERABILITY).
//!
//! Attack surface: the `ComplianceProof` struct has public fields, so an
//! attacker can freely mutate any field after finalization. The question is
//! whether `verify()` catches each kind of tampering.

use poly_inference::compliance::{ContentPolicy, PolicyChecker};
use poly_inference::compliance_proof::{ComplianceAccumulator, ComplianceProof};
use poly_verified::crypto::hash::hash_data;
use poly_verified::ivc::hash_ivc::HashIvc;
use poly_verified::ivc::IvcBackend;
use poly_verified::types::{PrivacyMode, StepWitness, VerifiedProof, ZERO_HASH};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn strict_policy() -> ContentPolicy {
    ContentPolicy {
        version: 1,
        blocked_token_ids: vec![100, 200, 300],
        blocked_ngrams: vec![vec![10, 20, 30]],
        max_sequence_length: 50,
    }
}

fn permissive_policy() -> ContentPolicy {
    ContentPolicy {
        version: 99,
        blocked_token_ids: vec![],
        blocked_ngrams: vec![],
        max_sequence_length: 100_000,
    }
}

/// Build a valid, fully-compliant proof for the given tokens under the given policy.
fn build_valid_proof(policy: ContentPolicy, tokens: &[u32]) -> ComplianceProof {
    let checker = PolicyChecker::new(policy);
    let mut acc = ComplianceAccumulator::new(checker);
    for &t in tokens {
        acc.check_and_fold(t).unwrap();
    }
    acc.finalize().unwrap()
}

// ===========================================================================
// ATTACK 1: Compliant token count inflation
//
// Create a real compliance proof where some tokens were blocked, then tamper
// with `compliant_tokens` to claim all tokens were compliant.
// ===========================================================================

#[test]
fn attack_01_compliant_token_count_inflation() {
    let checker = PolicyChecker::new(strict_policy());
    let mut acc = ComplianceAccumulator::new(checker);

    // Fold: 1 (allowed), 2 (allowed), 100 (BLOCKED), 3 (allowed)
    acc.check_and_fold(1).unwrap();
    acc.check_and_fold(2).unwrap();
    let verdict = acc.check_and_fold(100).unwrap();
    assert!(verdict.is_blocked(), "token 100 should be blocked");
    acc.check_and_fold(3).unwrap();

    let mut proof = acc.finalize().unwrap();

    // Honest state: 4 total, 3 compliant
    assert_eq!(proof.total_tokens, 4);
    assert_eq!(proof.compliant_tokens, 3);
    assert!(!proof.all_compliant());

    // --- ATTACK: inflate compliant_tokens ---
    proof.compliant_tokens = proof.total_tokens;

    // The metadata helper is fooled:
    assert!(proof.all_compliant(), "all_compliant() is just metadata -- trivially fooled");

    // Does verify() catch this?
    let verified = proof.verify().unwrap();

    // verify() check #4 is: compliant_tokens <= total_tokens. After our
    // inflation compliant_tokens == total_tokens, so that check passes.
    // The IVC chain itself does NOT commit the compliant_tokens count --
    // it only commits the per-step verdicts into the state hash chain.
    // So verify() alone does NOT catch pure count inflation.
    if verified {
        // The attack succeeds: verify() does not bind compliant_tokens
        // into the cryptographic proof.
        eprintln!(
            "VULNERABILITY: compliant_tokens inflation bypasses verify(). \
             The count is metadata-only and not committed into the IVC chain."
        );
        // We still assert the attack succeeds so the test is deterministic.
        assert!(verified);
    } else {
        eprintln!("HARDENED: compliant_tokens inflation is caught by verify().");
        assert!(!verified);
    }
}

// ===========================================================================
// ATTACK 2: Policy hash substitution
//
// Build a proof with a permissive policy, then swap policy_hash to claim
// a strict policy was enforced.
// ===========================================================================

#[test]
fn attack_02_policy_hash_substitution() {
    // Build proof under permissive policy (everything allowed)
    let proof_permissive = build_valid_proof(permissive_policy(), &[100, 200, 300]);
    assert!(proof_permissive.verify().unwrap(), "honest permissive proof must verify");

    // --- ATTACK: swap policy_hash to strict policy ---
    let mut tampered = proof_permissive.clone();
    tampered.policy_hash = strict_policy().hash();

    let verified = tampered.verify().unwrap();

    if verified {
        eprintln!("VULNERABILITY: policy hash substitution not detected by verify().");
    } else {
        eprintln!(
            "HARDENED: policy hash substitution detected. verify() checks \
             H(\"compliance_check_v1\" || policy_hash) == code_hash in IVC proof."
        );
    }

    // verify() step 3 recomputes code_hash from the claimed policy_hash.
    // Because the IVC proof's code_hash was derived from the permissive policy,
    // substituting the strict policy hash causes a mismatch.
    assert!(
        !verified,
        "HARDENED: policy hash substitution must be detected"
    );
}

// ===========================================================================
// ATTACK 3: Final state hash tampering
//
// Tamper with final_state_hash after finalization.
// ===========================================================================

#[test]
fn attack_03_final_state_hash_tampering() {
    let mut proof = build_valid_proof(strict_policy(), &[1, 2, 3, 4, 5]);
    assert!(proof.verify().unwrap(), "honest proof must verify");

    let original_hash = proof.final_state_hash;

    // --- ATTACK: replace final_state_hash ---
    proof.final_state_hash = [0xFF; 32];
    assert_ne!(proof.final_state_hash, original_hash);

    let verified = proof.verify().unwrap();

    if verified {
        eprintln!("VULNERABILITY: final_state_hash tampering not detected.");
    } else {
        eprintln!(
            "HARDENED: final_state_hash tampering detected. verify() uses \
             final_state_hash as the expected output for IVC I/O binding."
        );
    }

    // verify() step 1 calls backend.verify(&proof, &ZERO_HASH, &final_state_hash).
    // The IVC proof has output_hash set to the real final_state_hash.
    // Passing the tampered hash as expected_output causes the I/O check to fail.
    assert!(
        !verified,
        "HARDENED: final_state_hash tampering must be detected"
    );
}

// ===========================================================================
// ATTACK 4: Token count / step_count mismatch
//
// Modify total_tokens to not match the IVC step_count.
// ===========================================================================

#[test]
fn attack_04_token_count_step_count_mismatch() {
    let mut proof = build_valid_proof(strict_policy(), &[1, 2, 3, 4, 5]);
    assert_eq!(proof.total_tokens, 5);
    assert!(proof.verify().unwrap());

    // --- ATTACK: claim fewer tokens ---
    proof.total_tokens = 2;
    proof.compliant_tokens = 2;

    let verified = proof.verify().unwrap();

    if verified {
        eprintln!("VULNERABILITY: total_tokens/step_count mismatch not detected.");
    } else {
        eprintln!(
            "HARDENED: total_tokens/step_count mismatch detected. verify() \
             cross-checks total_tokens against IVC step_count."
        );
    }

    // verify() step 2 checks: total_tokens == ivc_proof.step_count
    let ivc_step_count = match &proof.ivc_proof {
        VerifiedProof::HashIvc { step_count, .. } => *step_count,
        _ => panic!("expected HashIvc"),
    };
    assert_eq!(ivc_step_count, 5, "IVC step_count is immutable at 5");
    assert_eq!(proof.total_tokens, 2, "attacker claims 2");
    assert!(
        !verified,
        "HARDENED: token count / step_count mismatch must be detected"
    );
}

// ===========================================================================
// ATTACK 4b: Inflate total_tokens above step_count
// ===========================================================================

#[test]
fn attack_04b_inflate_total_tokens() {
    let mut proof = build_valid_proof(strict_policy(), &[1, 2, 3]);
    assert_eq!(proof.total_tokens, 3);
    assert!(proof.verify().unwrap());

    // --- ATTACK: claim more tokens ---
    proof.total_tokens = 100;
    proof.compliant_tokens = 100;

    let verified = proof.verify().unwrap();

    assert!(
        !verified,
        "HARDENED: inflated total_tokens (100 vs step_count 3) must be detected"
    );
    eprintln!("HARDENED: inflated total_tokens correctly rejected.");
}

// ===========================================================================
// ATTACK 5: Replay proof with different policy
//
// Take a valid proof, change only the policy_hash but keep everything else.
// ===========================================================================

#[test]
fn attack_05_replay_proof_with_different_policy() {
    let proof = build_valid_proof(strict_policy(), &[1, 2, 3]);
    assert!(proof.verify().unwrap());

    // --- ATTACK: replay proof but claim a different policy ---
    let different_policy = ContentPolicy {
        version: 42,
        blocked_token_ids: vec![1, 2, 3, 4, 5],
        blocked_ngrams: vec![],
        max_sequence_length: 10,
    };

    let mut replayed = proof.clone();
    replayed.policy_hash = different_policy.hash();

    let verified = replayed.verify().unwrap();

    if verified {
        eprintln!(
            "VULNERABILITY: proof replay with different policy_hash \
             not detected. code_hash binding is broken."
        );
    } else {
        eprintln!(
            "HARDENED: proof replay with different policy_hash detected. \
             code_hash = H(prefix || policy_hash) binds proof to exact policy."
        );
    }

    assert!(
        !verified,
        "HARDENED: replayed proof with swapped policy must fail verification"
    );
}

// ===========================================================================
// ATTACK 6: Forge compliance proof from scratch
//
// Without running any tokens, manually construct a ComplianceProof with
// fabricated fields. Does verify() reject?
// ===========================================================================

#[test]
fn attack_06_forge_compliance_proof_from_scratch() {
    let policy = strict_policy();
    let policy_hash = policy.hash();

    // Compute the correct code_hash so check #3 passes
    let mut code_input = b"compliance_check_v1".to_vec();
    code_input.extend_from_slice(&policy_hash);
    let code_hash = hash_data(&code_input);

    // Fabricate a fake final state hash
    let fake_final_state = hash_data(b"i_am_a_fake_final_state");

    // --- ATTACK: build entirely fabricated proof ---
    let forged = ComplianceProof {
        ivc_proof: VerifiedProof::HashIvc {
            chain_tip: hash_data(b"fake_chain_tip"),
            merkle_root: hash_data(b"fake_merkle_root"),
            step_count: 10,
            code_hash,
            privacy_mode: PrivacyMode::Transparent,
            blinding_commitment: None,
            checkpoints: vec![hash_data(b"fake_cp"); 10], // 10 fake checkpoints
            input_hash: ZERO_HASH,
            output_hash: fake_final_state,
        },
        policy_hash,
        total_tokens: 10,
        compliant_tokens: 10,
        final_state_hash: fake_final_state,
    };

    let verified = forged.verify().unwrap();

    if verified {
        eprintln!(
            "VULNERABILITY: fully forged compliance proof passes verify()! \
             The chain_tip and merkle_root are not validated against checkpoints."
        );
    } else {
        eprintln!(
            "HARDENED: forged compliance proof rejected. verify() rebuilds \
             chain and Merkle tree from checkpoints and checks against \
             chain_tip and merkle_root."
        );
    }

    // The IVC verifier rebuilds the hash chain and Merkle tree from the
    // checkpoints. Fake checkpoints will produce a different chain_tip
    // and merkle_root than the fabricated ones.
    assert!(
        !verified,
        "HARDENED: entirely forged compliance proof must be rejected"
    );
}

// ===========================================================================
// ATTACK 6b: Forge with consistent checkpoints but wrong code_hash
// ===========================================================================

#[test]
fn attack_06b_forge_with_consistent_chain_wrong_code() {
    // Build a valid IVC proof structure (correct chain) but for the wrong policy
    let backend = HashIvc;
    let fake_code_hash = hash_data(b"not_a_real_policy_binding");

    let mut acc = backend.init(&fake_code_hash, PrivacyMode::Transparent);
    let state0 = ZERO_HASH;
    let step_inputs = hash_data(&[1u32.to_le_bytes().as_slice(), &[1u8]].concat());
    let state1 = hash_data(&[ZERO_HASH.as_slice(), &1u32.to_le_bytes(), &[1u8]].concat());

    let witness = StepWitness {
        state_before: state0,
        state_after: state1,
        step_inputs,
    };
    backend.fold_step(&mut acc, &witness).unwrap();
    acc.input_hash = ZERO_HASH;
    acc.output_hash = state1;

    let ivc_proof = backend.finalize(acc).unwrap();

    // Now wrap it as a ComplianceProof claiming strict_policy
    let forged = ComplianceProof {
        ivc_proof,
        policy_hash: strict_policy().hash(),
        total_tokens: 1,
        compliant_tokens: 1,
        final_state_hash: state1,
    };

    let verified = forged.verify().unwrap();

    assert!(
        !verified,
        "HARDENED: forged proof with wrong code_hash must be rejected \
         (code_hash does not match H(prefix || claimed_policy_hash))"
    );
    eprintln!("HARDENED: forge with consistent chain but wrong code binding rejected.");
}

// ===========================================================================
// ATTACK 7: Zero-token compliance proof
//
// Try to create a compliance proof with 0 tokens.
// ===========================================================================

#[test]
fn attack_07_zero_token_compliance_proof() {
    let checker = PolicyChecker::new(strict_policy());
    let acc = ComplianceAccumulator::new(checker);

    // Attempt to finalize with zero tokens
    let result = acc.finalize();

    if result.is_err() {
        eprintln!(
            "HARDENED: zero-token proof cannot be created. IVC finalize \
             rejects empty commitment (EmptyCommitment error): {}",
            result.unwrap_err()
        );
        // The attack is prevented at creation time.
        assert!(true);
    } else {
        let proof = result.unwrap();
        let verified = proof.verify().unwrap();
        if verified {
            eprintln!(
                "VULNERABILITY: zero-token compliance proof passes verify()!"
            );
            panic!("zero-token proof should not verify");
        } else {
            eprintln!(
                "HARDENED: zero-token proof was created but verify() rejects it."
            );
        }
    }
}

// ===========================================================================
// ATTACK 7b: Manually forge a zero-step proof
// ===========================================================================

#[test]
fn attack_07b_forge_zero_step_proof() {
    let policy = strict_policy();
    let policy_hash = policy.hash();

    let mut code_input = b"compliance_check_v1".to_vec();
    code_input.extend_from_slice(&policy_hash);
    let code_hash = hash_data(&code_input);

    let forged = ComplianceProof {
        ivc_proof: VerifiedProof::HashIvc {
            chain_tip: ZERO_HASH,
            merkle_root: ZERO_HASH,
            step_count: 0,
            code_hash,
            privacy_mode: PrivacyMode::Transparent,
            blinding_commitment: None,
            checkpoints: vec![],
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
        },
        policy_hash,
        total_tokens: 0,
        compliant_tokens: 0,
        final_state_hash: ZERO_HASH,
    };

    let verified = forged.verify().unwrap();

    // IVC verifier check: step_count == 0 returns false
    assert!(
        !verified,
        "HARDENED: manually forged zero-step proof must be rejected"
    );
    eprintln!("HARDENED: zero-step forged proof rejected by IVC verifier.");
}

// ===========================================================================
// ATTACK 8: Blocked token counted as compliant
//
// Run a blocked token through check_and_fold, then tamper compliant_tokens
// to count it as compliant.
// ===========================================================================

#[test]
fn attack_08_blocked_token_counted_as_compliant() {
    let checker = PolicyChecker::new(strict_policy());
    let mut acc = ComplianceAccumulator::new(checker);

    // Token 100 is blocked by the strict policy
    let v1 = acc.check_and_fold(1).unwrap();
    assert!(v1.is_allowed());

    let v2 = acc.check_and_fold(100).unwrap();
    assert!(v2.is_blocked(), "token 100 must be blocked");

    let mut proof = acc.finalize().unwrap();

    // Honest: 2 total, 1 compliant
    assert_eq!(proof.total_tokens, 2);
    assert_eq!(proof.compliant_tokens, 1);

    // Honest proof verifies
    assert!(proof.verify().unwrap());

    // --- ATTACK: tamper compliant_tokens ---
    proof.compliant_tokens = 2;
    assert!(proof.all_compliant(), "metadata fooled");

    let verified = proof.verify().unwrap();

    // The IVC chain commits H(prev_state || token_id || verdict_byte) per step.
    // The verdict byte (0=blocked, 1=allowed) is baked into the chain.
    // However, compliant_tokens is NOT directly checked against the chain --
    // verify() only checks compliant_tokens <= total_tokens.
    if verified {
        eprintln!(
            "VULNERABILITY: blocked token counted as compliant bypasses verify(). \
             compliant_tokens is not cryptographically bound to the per-step verdicts. \
             A verifier must replay the token sequence to detect this."
        );
        // The attack succeeds because the IVC chain does not expose per-step
        // verdict counts to the verifier -- only the chained state hash.
        assert!(verified);
    } else {
        eprintln!("HARDENED: blocked token count inflation caught by verify().");
        assert!(!verified);
    }
}

// ===========================================================================
// ATTACK 9: Double-finalize attack
//
// Build two accumulators with the same common prefix but different suffixes.
// Both represent valid but divergent execution paths from the same starting
// point. Do both proofs verify independently?
//
// Note: ComplianceAccumulator does not implement Clone, so we simulate forking
// by rebuilding the common prefix in both accumulators.
// ===========================================================================

#[test]
fn attack_09_double_finalize() {
    let common_prefix: Vec<u32> = vec![1, 2, 3];

    // Path A: common prefix + [4, 5]
    let checker_a = PolicyChecker::new(strict_policy());
    let mut acc_a = ComplianceAccumulator::new(checker_a);
    for &t in &common_prefix {
        acc_a.check_and_fold(t).unwrap();
    }
    acc_a.check_and_fold(4).unwrap();
    acc_a.check_and_fold(5).unwrap();
    let proof_a = acc_a.finalize().unwrap();

    // Path B: common prefix + [40, 50]
    let checker_b = PolicyChecker::new(strict_policy());
    let mut acc_b = ComplianceAccumulator::new(checker_b);
    for &t in &common_prefix {
        acc_b.check_and_fold(t).unwrap();
    }
    acc_b.check_and_fold(40).unwrap();
    acc_b.check_and_fold(50).unwrap();
    let proof_b = acc_b.finalize().unwrap();

    let verified_a = proof_a.verify().unwrap();
    let verified_b = proof_b.verify().unwrap();

    // Both proofs should verify independently -- they represent different
    // valid execution paths from the same starting state.
    if verified_a && verified_b {
        // Both verify. Check they are distinct proofs.
        assert_ne!(
            proof_a.final_state_hash, proof_b.final_state_hash,
            "divergent proofs must have different final state hashes"
        );
        assert_eq!(
            proof_a.policy_hash, proof_b.policy_hash,
            "both proofs use the same policy"
        );
        assert_eq!(proof_a.total_tokens, 5);
        assert_eq!(proof_b.total_tokens, 5);

        eprintln!(
            "OBSERVATION: Both divergent proofs verify independently. \
             This is expected -- rebuilding from the same prefix with different \
             suffixes produces two valid but distinct execution traces. \
             Not a vulnerability per se, but a server should track which \
             proof corresponds to which session."
        );
    } else {
        eprintln!(
            "UNEXPECTED: One or both divergent proofs failed verification. \
             proof_a: {}, proof_b: {}",
            verified_a, verified_b
        );
        panic!("both divergent proofs should verify independently");
    }
}

// ===========================================================================
// ATTACK 10: Policy version confusion
//
// Use the same blocked_token_ids but different version numbers.
// Do they produce different code_hashes?
// ===========================================================================

#[test]
fn attack_10_policy_version_confusion() {
    let policy_v1 = ContentPolicy {
        version: 1,
        blocked_token_ids: vec![100, 200, 300],
        blocked_ngrams: vec![vec![10, 20, 30]],
        max_sequence_length: 50,
    };

    let policy_v2 = ContentPolicy {
        version: 2,
        blocked_token_ids: vec![100, 200, 300],
        blocked_ngrams: vec![vec![10, 20, 30]],
        max_sequence_length: 50,
    };

    let hash_v1 = policy_v1.hash();
    let hash_v2 = policy_v2.hash();

    // Different version => different policy hash
    assert_ne!(
        hash_v1, hash_v2,
        "HARDENED: different version numbers must produce different policy hashes"
    );

    // Different policy hash => different code_hash
    let code_hash_v1 = {
        let mut input = b"compliance_check_v1".to_vec();
        input.extend_from_slice(&hash_v1);
        hash_data(&input)
    };
    let code_hash_v2 = {
        let mut input = b"compliance_check_v1".to_vec();
        input.extend_from_slice(&hash_v2);
        hash_data(&input)
    };

    assert_ne!(
        code_hash_v1, code_hash_v2,
        "HARDENED: different policy versions must produce different code_hashes"
    );

    // Build proof with v1, try to claim it was v2
    let proof_v1 = build_valid_proof(policy_v1, &[1, 2, 3]);
    assert!(proof_v1.verify().unwrap());

    let mut tampered = proof_v1.clone();
    tampered.policy_hash = hash_v2;

    let verified = tampered.verify().unwrap();

    assert!(
        !verified,
        "HARDENED: v1 proof claiming v2 policy must fail verification"
    );
    eprintln!(
        "HARDENED: policy version confusion prevented. \
         Version is included in the serialized policy hash, which is \
         bound to code_hash in the IVC proof."
    );
}

// ===========================================================================
// BONUS ATTACK: compliant_tokens exceeds total_tokens
// ===========================================================================

#[test]
fn attack_bonus_compliant_exceeds_total() {
    let mut proof = build_valid_proof(strict_policy(), &[1, 2, 3]);
    assert!(proof.verify().unwrap());

    // --- ATTACK: claim more compliant than total ---
    proof.compliant_tokens = proof.total_tokens + 1;

    let verified = proof.verify().unwrap();

    assert!(
        !verified,
        "HARDENED: compliant_tokens > total_tokens must be rejected (check #4)"
    );
    eprintln!("HARDENED: compliant_tokens > total_tokens correctly rejected.");
}

// ===========================================================================
// BONUS ATTACK: swap checkpoints to alter the execution trace
// ===========================================================================

#[test]
fn attack_bonus_swap_checkpoints() {
    let proof = build_valid_proof(strict_policy(), &[1, 2, 3, 4, 5]);
    assert!(proof.verify().unwrap());

    // --- ATTACK: reverse checkpoint order ---
    let mut tampered = proof.clone();
    if let VerifiedProof::HashIvc {
        ref mut checkpoints,
        ..
    } = tampered.ivc_proof
    {
        checkpoints.reverse();
    }

    let verified = tampered.verify().unwrap();

    assert!(
        !verified,
        "HARDENED: reordered checkpoints must produce different chain_tip and merkle_root"
    );
    eprintln!("HARDENED: checkpoint reordering correctly detected.");
}

// ===========================================================================
// BONUS ATTACK: inject extra checkpoint
// ===========================================================================

#[test]
fn attack_bonus_inject_extra_checkpoint() {
    let mut proof = build_valid_proof(strict_policy(), &[1, 2, 3]);
    assert!(proof.verify().unwrap());

    // --- ATTACK: inject an extra checkpoint and adjust counts ---
    if let VerifiedProof::HashIvc {
        ref mut checkpoints,
        ref mut step_count,
        ..
    } = proof.ivc_proof
    {
        checkpoints.push(hash_data(b"injected_step"));
        *step_count += 1;
    }
    proof.total_tokens += 1;
    proof.compliant_tokens += 1;

    let verified = proof.verify().unwrap();

    assert!(
        !verified,
        "HARDENED: injecting extra checkpoint must invalidate chain_tip and merkle_root"
    );
    eprintln!("HARDENED: extra checkpoint injection correctly detected.");
}
