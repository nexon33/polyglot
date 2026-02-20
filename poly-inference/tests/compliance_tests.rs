//! Integration tests for the per-token compliance proof gate.

use poly_inference::compliance::{
    ContentPolicy, PolicyChecker, TokenVerdict, ViolationReason,
};
use poly_inference::compliance_proof::{ComplianceAccumulator, ComplianceProof};
use poly_verified::types::VerifiedProof;

fn test_policy() -> ContentPolicy {
    ContentPolicy {
        version: 1,
        blocked_token_ids: vec![666, 777, 888],
        blocked_ngrams: vec![
            vec![10, 20, 30],    // 3-gram
            vec![50, 60],        // 2-gram
            vec![99, 100, 101, 102], // 4-gram
        ],
        max_sequence_length: 20,
    }
}

// ─── Policy Checker Tests ──────────────────────────────────────────────

#[test]
fn test_allowed_token() {
    let checker = PolicyChecker::new(test_policy());
    assert!(checker.check_token(1, &[]).is_allowed());
    assert!(checker.check_token(42, &[1, 2, 3]).is_allowed());
}

#[test]
fn test_blocked_token_id() {
    let checker = PolicyChecker::new(test_policy());
    match checker.check_token(666, &[]) {
        TokenVerdict::Blocked(ViolationReason::BlockedTokenId(id)) => assert_eq!(id, 666),
        other => panic!("expected BlockedTokenId, got {:?}", other),
    }
}

#[test]
fn test_blocked_ngram() {
    let checker = PolicyChecker::new(test_policy());
    // [10, 20, 30] is blocked — token 30 completes the 3-gram
    let verdict = checker.check_token(30, &[10, 20]);
    match verdict {
        TokenVerdict::Blocked(ViolationReason::BlockedNgram(ngram)) => {
            assert_eq!(ngram, vec![10, 20, 30]);
        }
        other => panic!("expected BlockedNgram, got {:?}", other),
    }
}

#[test]
fn test_blocked_4gram() {
    let checker = PolicyChecker::new(test_policy());
    // [99, 100, 101, 102] — token 102 completes the 4-gram
    let verdict = checker.check_token(102, &[99, 100, 101]);
    assert!(verdict.is_blocked());
}

#[test]
fn test_ngram_partial_no_match() {
    let checker = PolicyChecker::new(test_policy());
    // Only first 2 of 3-gram [10, 20, 30], different completion
    assert!(checker.check_token(31, &[10, 20]).is_allowed());
}

#[test]
fn test_sequence_too_long() {
    let checker = PolicyChecker::new(test_policy());
    let history: Vec<u32> = (0..20).collect();
    match checker.check_token(42, &history) {
        TokenVerdict::Blocked(ViolationReason::SequenceTooLong { length, max }) => {
            assert_eq!(length, 21);
            assert_eq!(max, 20);
        }
        other => panic!("expected SequenceTooLong, got {:?}", other),
    }
}

#[test]
fn test_sequence_at_limit_allowed() {
    let checker = PolicyChecker::new(test_policy());
    let history: Vec<u32> = (0..19).collect();
    assert!(checker.check_token(42, &history).is_allowed());
}

// ─── Compliance Proof Tests ────────────────────────────────────────────

#[test]
fn test_compliance_proof_roundtrip() {
    let checker = PolicyChecker::new(test_policy());
    let mut acc = ComplianceAccumulator::new(checker);

    for token in [1, 2, 3, 4, 5] {
        let verdict = acc.check_and_fold(token).unwrap();
        assert!(verdict.is_allowed());
    }

    let proof = acc.finalize().unwrap();
    assert_eq!(proof.total_tokens, 5);
    assert_eq!(proof.compliant_tokens, 5);
    assert!(proof.all_compliant());
    assert!(proof.verify().unwrap());
}

#[test]
fn test_proof_chains_correctly() {
    let checker = PolicyChecker::new(test_policy());
    let mut acc = ComplianceAccumulator::new(checker);

    let token_count = 7;
    for t in 0..token_count {
        acc.check_and_fold(t).unwrap();
    }

    let proof = acc.finalize().unwrap();

    // IVC step_count must equal number of tokens checked
    match &proof.ivc_proof {
        VerifiedProof::HashIvc { step_count, .. } => {
            assert_eq!(*step_count, token_count as u64);
        }
        _ => panic!("expected HashIvc proof"),
    }
}

#[test]
fn test_policy_hash_deterministic() {
    let p1 = test_policy();
    let p2 = test_policy();
    assert_eq!(p1.hash(), p2.hash());

    // Different policy → different hash
    let mut p3 = test_policy();
    p3.version = 2;
    assert_ne!(p1.hash(), p3.hash());
}

#[test]
fn test_server_client_agreement() {
    let policy = test_policy();
    let client = PolicyChecker::new(policy.clone());
    let server = PolicyChecker::new(policy);

    let test_sequences: Vec<Vec<u32>> = vec![
        vec![1, 2, 3, 4, 5],
        vec![10, 20, 30],      // triggers 3-gram block
        vec![666],             // triggers ID block
        vec![50, 60],          // triggers 2-gram block
    ];

    for seq in &test_sequences {
        let mut history = Vec::new();
        for &token in seq {
            let cv = client.check_token(token, &history);
            let sv = server.check_token(token, &history);
            assert_eq!(cv, sv, "disagreement on token {} with history {:?}", token, history);
            history.push(token);
        }
    }
}

#[test]
fn test_adversarial_prompt_halts() {
    // Simulate: policy blocks token 666, generation produces it at step 3
    let checker = PolicyChecker::new(test_policy());
    let mut acc = ComplianceAccumulator::new(checker);

    let tokens = [1, 2, 666, 3, 4]; // 666 is blocked
    let mut halted_at = None;

    for (step, &token) in tokens.iter().enumerate() {
        let verdict = acc.check_and_fold(token).unwrap();
        if verdict.is_blocked() {
            halted_at = Some(step);
            break;
        }
    }

    assert_eq!(halted_at, Some(2), "should halt at token 666 (step 2)");

    let proof = acc.finalize().unwrap();
    assert_eq!(proof.total_tokens, 3); // tokens 1, 2, 666
    assert_eq!(proof.compliant_tokens, 2); // only 1, 2
    assert!(!proof.all_compliant());
    assert!(proof.verify().unwrap());
}

#[test]
fn test_empty_generation_fails_finalize() {
    let checker = PolicyChecker::new(test_policy());
    let acc = ComplianceAccumulator::new(checker);

    // No tokens folded → IVC finalize should fail (no steps)
    let result = acc.finalize();
    assert!(result.is_err());
}

#[test]
fn test_proof_deterministic_across_runs() {
    let make_proof = || -> ComplianceProof {
        let checker = PolicyChecker::new(test_policy());
        let mut acc = ComplianceAccumulator::new(checker);
        for t in [10, 20, 42, 7, 99] {
            acc.check_and_fold(t).unwrap();
        }
        acc.finalize().unwrap()
    };

    let p1 = make_proof();
    let p2 = make_proof();

    assert_eq!(p1.final_state_hash, p2.final_state_hash);
    assert_eq!(p1.policy_hash, p2.policy_hash);
    assert_eq!(p1.total_tokens, p2.total_tokens);
    assert_eq!(p1.compliant_tokens, p2.compliant_tokens);

    match (&p1.ivc_proof, &p2.ivc_proof) {
        (
            VerifiedProof::HashIvc { chain_tip: a, merkle_root: ar, .. },
            VerifiedProof::HashIvc { chain_tip: b, merkle_root: br, .. },
        ) => {
            assert_eq!(a, b, "chain tips must match");
            assert_eq!(ar, br, "merkle roots must match");
        }
        _ => panic!("expected HashIvc proofs"),
    }
}
