//! Comprehensive HTLC atomic swap integration tests.
//!
//! Tests cover: race conditions, state machine ordering, concurrent swaps,
//! boundary values, adversarial scenarios, and cross-feature interactions.

use poly_chain::prelude::*;
use poly_chain::validation::validate_transaction;
use poly_chain::wallet::WalletState;
use poly_chain::identity::Tier;
use poly_chain::state::GlobalState;
use poly_verified::types::{PrivacyMode, VerifiedProof, ZERO_HASH};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn mock_proof() -> VerifiedProof {
    VerifiedProof::Mock {
        input_hash: ZERO_HASH,
        output_hash: ZERO_HASH,
        privacy_mode: PrivacyMode::Transparent,
    }
}

/// A hand-rolled HashIvc proof with bogus `chain_tip`/`merkle_root`. It is
/// structurally a HashIvc proof but cryptographically invalid — `HashIvc::verify`
/// returns `Ok(false)` for it. Used only as a stored metadata field
/// (`execution_proof`), never as a transaction's verification `proof`.
fn hash_ivc_proof() -> VerifiedProof {
    VerifiedProof::HashIvc {
        chain_tip: [0x01; 32],
        merkle_root: [0x02; 32],
        step_count: 1,
        code_hash: [0x03; 32],
        privacy_mode: PrivacyMode::Transparent,
        blinding_commitment: None,
        checkpoints: vec![[0x04; 32]],
        input_hash: [0u8; 32],
        output_hash: [0u8; 32],
    }
}

/// Build a genuine, cryptographically-valid HashIvc proof bound to the given
/// I/O hashes — the proof a real prover would produce. `HashIvc::verify`
/// returns `Ok(true)` for it when checked against the same I/O hashes.
fn genuine_hash_ivc_proof(input_hash: [u8; 32], output_hash: [u8; 32]) -> VerifiedProof {
    use poly_verified::ivc::hash_ivc::HashIvc;
    use poly_verified::ivc::IvcBackend;
    use poly_verified::types::StepWitness;
    let ivc = HashIvc;
    let mut acc = ivc.init(&[0x03; 32], PrivacyMode::Transparent);
    ivc.fold_step(
        &mut acc,
        &StepWitness {
            state_before: input_hash,
            state_after: output_hash,
            step_inputs: input_hash,
        },
    )
    .unwrap();
    acc.input_hash = input_hash;
    acc.output_hash = output_hash;
    ivc.finalize(acc).unwrap()
}

fn setup_wallets() -> (GlobalState, AccountId, AccountId) {
    let mut state = GlobalState::genesis();
    let alice = [0xA1; 32];
    let bob = [0xB0; 32];

    let alice_wallet = WalletState::new([0xAA; 32], Tier::Identified, 1_000_000);
    let bob_wallet = WalletState::new([0xBB; 32], Tier::Identified, 500_000);

    state.set_wallet(alice, alice_wallet.state_hash());
    state.set_wallet(bob, bob_wallet.state_hash());

    (state, alice, bob)
}

fn make_swap(
    initiator: AccountId,
    responder: AccountId,
    amount: Amount,
    timeout: BlockHeight,
    nonce: Nonce,
) -> AtomicSwapInit {
    let swap_id = hash_with_domain(
        DOMAIN_SWAP,
        &[
            initiator.as_slice(),
            responder.as_slice(),
            &nonce.to_le_bytes(),
        ]
        .concat(),
    );
    let secret = [0x5E; 32];
    let hash_lock = hash_with_domain(DOMAIN_SWAP, &secret);

    AtomicSwapInit {
        swap_id,
        initiator,
        responder,
        amount,
        hash_lock,
        timeout,
        disclosure_root: None,
        execution_proof: None,
        nonce,
        timestamp: 1000,
        proof: mock_proof(),
        public_key: [0u8; 32],
        signature: [0u8; 64],
    }
}

fn init_swap(state: &GlobalState, swap: &AtomicSwapInit, block_height: BlockHeight) -> GlobalState {
    let tx = Transaction::AtomicSwapInit(swap.clone());
    validate_transaction(&tx, state, 1000, block_height).unwrap()
}

fn make_claim(swap: &AtomicSwapInit) -> AtomicSwapClaim {
    AtomicSwapClaim {
        swap_id: swap.swap_id,
        secret: [0x5E; 32],
        claimer: swap.initiator,
        original_initiator: swap.initiator,
        original_responder: swap.responder,
        original_amount: swap.amount,
        original_hash_lock: swap.hash_lock,
        original_timeout: swap.timeout,
        proof: mock_proof(),
        public_key: [0u8; 32],
        signature: [0u8; 64],
    }
}

fn make_refund(swap: &AtomicSwapInit) -> AtomicSwapRefund {
    AtomicSwapRefund {
        swap_id: swap.swap_id,
        refundee: swap.responder,
        original_initiator: swap.initiator,
        original_responder: swap.responder,
        original_amount: swap.amount,
        original_hash_lock: swap.hash_lock,
        original_timeout: swap.timeout,
        proof: mock_proof(),
        public_key: [0u8; 32],
        signature: [0u8; 64],
    }
}

// ---------------------------------------------------------------------------
// Race conditions: claim/refund ordering
// ---------------------------------------------------------------------------

#[test]
fn claim_after_refund_fails() {
    let (state, alice, bob) = setup_wallets();
    let swap = make_swap(alice, bob, 5000, 100, 0);

    // Init at block 50
    let s1 = init_swap(&state, &swap, 50);

    // Refund at block 200 (after timeout)
    let tx_refund = Transaction::AtomicSwapRefund(make_refund(&swap));
    let s2 = validate_transaction(&tx_refund, &s1, 1000, 200).unwrap();
    assert!(s2.get_swap(&swap.swap_id).is_none());

    // Now try to claim — should fail because swap was already refunded
    let tx_claim = Transaction::AtomicSwapClaim(make_claim(&swap));
    let result = validate_transaction(&tx_claim, &s2, 1000, 205);
    assert!(matches!(result, Err(ChainError::SwapNotFound(_))));
}

#[test]
fn refund_after_claim_fails() {
    let (state, alice, bob) = setup_wallets();
    let swap = make_swap(alice, bob, 5000, 100, 0);

    // Init at block 50
    let s1 = init_swap(&state, &swap, 50);

    // Claim at block 75
    let tx_claim = Transaction::AtomicSwapClaim(make_claim(&swap));
    let s2 = validate_transaction(&tx_claim, &s1, 1000, 75).unwrap();
    assert!(s2.get_swap(&swap.swap_id).is_none());

    // Now try to refund — should fail because swap was already claimed
    let tx_refund = Transaction::AtomicSwapRefund(make_refund(&swap));
    let result = validate_transaction(&tx_refund, &s2, 1000, 200);
    assert!(matches!(result, Err(ChainError::SwapNotFound(_))));
}

#[test]
fn double_claim_fails() {
    let (state, alice, bob) = setup_wallets();
    let swap = make_swap(alice, bob, 5000, 100, 0);
    let s1 = init_swap(&state, &swap, 50);

    // First claim succeeds
    let tx_claim = Transaction::AtomicSwapClaim(make_claim(&swap));
    let s2 = validate_transaction(&tx_claim, &s1, 1000, 75).unwrap();

    // Second claim on same swap fails
    let result = validate_transaction(&tx_claim, &s2, 1000, 80);
    assert!(matches!(result, Err(ChainError::SwapNotFound(_))));
}

#[test]
fn double_refund_fails() {
    let (state, alice, bob) = setup_wallets();
    let swap = make_swap(alice, bob, 5000, 100, 0);
    let s1 = init_swap(&state, &swap, 50);

    let tx_refund = Transaction::AtomicSwapRefund(make_refund(&swap));

    // First refund succeeds
    let s2 = validate_transaction(&tx_refund, &s1, 1000, 200).unwrap();

    // Second refund fails
    let result = validate_transaction(&tx_refund, &s2, 1000, 250);
    assert!(matches!(result, Err(ChainError::SwapNotFound(_))));
}

// ---------------------------------------------------------------------------
// Concurrent swaps
// ---------------------------------------------------------------------------

#[test]
fn multiple_concurrent_swaps() {
    let (state, alice, bob) = setup_wallets();

    // Create 3 independent swaps (nonces are per-account: alice=0,1; bob=0)
    let swap1 = make_swap(alice, bob, 1000, 100, 0);
    let swap2 = make_swap(alice, bob, 2000, 200, 1);
    let swap3 = make_swap(bob, alice, 3000, 300, 0); // bob's first swap as initiator

    // All three should be unique swap IDs
    assert_ne!(swap1.swap_id, swap2.swap_id);
    assert_ne!(swap2.swap_id, swap3.swap_id);
    assert_ne!(swap1.swap_id, swap3.swap_id);

    // Init all three
    let s1 = init_swap(&state, &swap1, 10);
    let s2 = init_swap(&s1, &swap2, 10);
    let s3 = init_swap(&s2, &swap3, 10);

    // All three exist
    assert!(s3.get_swap(&swap1.swap_id).is_some());
    assert!(s3.get_swap(&swap2.swap_id).is_some());
    assert!(s3.get_swap(&swap3.swap_id).is_some());

    // Claim swap1
    let tx_claim1 = Transaction::AtomicSwapClaim(make_claim(&swap1));
    let s4 = validate_transaction(&tx_claim1, &s3, 1000, 50).unwrap();

    // Swap1 gone, others still active
    assert!(s4.get_swap(&swap1.swap_id).is_none());
    assert!(s4.get_swap(&swap2.swap_id).is_some());
    assert!(s4.get_swap(&swap3.swap_id).is_some());

    // Refund swap2 after timeout
    let tx_refund2 = Transaction::AtomicSwapRefund(make_refund(&swap2));
    let s5 = validate_transaction(&tx_refund2, &s4, 1000, 250).unwrap();

    // Swap2 gone, swap3 still active
    assert!(s5.get_swap(&swap2.swap_id).is_none());
    assert!(s5.get_swap(&swap3.swap_id).is_some());

    // Claim swap3 (bob is initiator here)
    let tx_claim3 = Transaction::AtomicSwapClaim(make_claim(&swap3));
    let s6 = validate_transaction(&tx_claim3, &s5, 1000, 260).unwrap();

    // All swaps resolved
    assert!(s6.get_swap(&swap1.swap_id).is_none());
    assert!(s6.get_swap(&swap2.swap_id).is_none());
    assert!(s6.get_swap(&swap3.swap_id).is_none());
}

#[test]
fn many_swaps_stress_test() {
    let (mut state, alice, bob) = setup_wallets();

    // Init 50 swaps
    let mut swaps = Vec::new();
    for i in 0u64..50 {
        let swap = make_swap(alice, bob, 100, 1000, i);
        state = init_swap(&state, &swap, 10);
        swaps.push(swap);
    }

    // All 50 exist
    for swap in &swaps {
        assert!(state.get_swap(&swap.swap_id).is_some());
    }

    // Claim first 25
    for swap in &swaps[..25] {
        let tx_claim = Transaction::AtomicSwapClaim(make_claim(swap));
        state = validate_transaction(&tx_claim, &state, 1000, 500).unwrap();
    }

    // Refund remaining 25
    for swap in &swaps[25..] {
        let tx_refund = Transaction::AtomicSwapRefund(make_refund(swap));
        state = validate_transaction(&tx_refund, &state, 1000, 2000).unwrap();
    }

    // All gone
    for swap in &swaps {
        assert!(state.get_swap(&swap.swap_id).is_none());
    }
}

// ---------------------------------------------------------------------------
// Boundary values
// ---------------------------------------------------------------------------

#[test]
fn init_with_timeout_exactly_at_block_height_fails() {
    let (state, alice, bob) = setup_wallets();
    let swap = make_swap(alice, bob, 5000, 100, 0);

    // timeout == block_height should fail (must be strictly greater)
    let tx = Transaction::AtomicSwapInit(swap);
    let result = validate_transaction(&tx, &state, 1000, 100);
    assert!(matches!(result, Err(ChainError::SwapExpired)));
}

#[test]
fn init_with_timeout_one_past_block_height_succeeds() {
    let (state, alice, bob) = setup_wallets();
    let swap = make_swap(alice, bob, 5000, 101, 0);

    // timeout = 101, block_height = 100 → OK
    let tx = Transaction::AtomicSwapInit(swap);
    let result = validate_transaction(&tx, &state, 1000, 100);
    assert!(result.is_ok());
}

#[test]
fn init_with_amount_one() {
    let (state, alice, bob) = setup_wallets();
    let swap = make_swap(alice, bob, 1, 100, 0);

    let tx = Transaction::AtomicSwapInit(swap.clone());
    let result = validate_transaction(&tx, &state, 1000, 50);
    assert!(result.is_ok());
    assert!(result.unwrap().get_swap(&swap.swap_id).is_some());
}

#[test]
fn init_with_large_amount() {
    let (state, alice, bob) = setup_wallets();
    let swap = make_swap(alice, bob, u64::MAX / 2, 100, 0);

    // Should succeed (no balance check in verify-only mode)
    let tx = Transaction::AtomicSwapInit(swap.clone());
    let result = validate_transaction(&tx, &state, 1000, 50);
    assert!(result.is_ok());
}

#[test]
fn init_with_large_timeout() {
    let (state, alice, bob) = setup_wallets();
    // R10: u64::MAX timeout is now rejected (permanent fund lock attack).
    // A timeout within MAX_SWAP_TIMEOUT_DELTA (1,000,000) blocks is accepted.
    let swap = make_swap(alice, bob, 5000, u64::MAX, 0);

    let tx = Transaction::AtomicSwapInit(swap.clone());
    let result = validate_transaction(&tx, &state, 1000, 50);
    assert!(result.is_err(), "R10: u64::MAX timeout should be rejected");

    // But a large-but-reasonable timeout works
    let swap_reasonable = make_swap(alice, bob, 5000, 50 + 999_999, 0);
    let tx_ok = Transaction::AtomicSwapInit(swap_reasonable);
    let result_ok = validate_transaction(&tx_ok, &state, 1000, 50);
    assert!(result_ok.is_ok(), "reasonable large timeout should be accepted");
}

// ---------------------------------------------------------------------------
// State consistency
// ---------------------------------------------------------------------------

#[test]
fn state_root_deterministic_across_swap_operations() {
    let (state, alice, bob) = setup_wallets();
    let swap = make_swap(alice, bob, 5000, 100, 0);

    // Run the same sequence twice
    let s1a = init_swap(&state, &swap, 50);
    let s1b = init_swap(&state, &swap, 50);
    assert_eq!(s1a.state_root(), s1b.state_root());

    // Claim on both
    let tx_claim = Transaction::AtomicSwapClaim(make_claim(&swap));
    let s2a = validate_transaction(&tx_claim, &s1a, 1000, 75).unwrap();
    let s2b = validate_transaction(&tx_claim, &s1b, 1000, 75).unwrap();
    assert_eq!(s2a.state_root(), s2b.state_root());
}

#[test]
fn claim_vs_refund_produce_different_states() {
    let (state, alice, bob) = setup_wallets();
    let swap = make_swap(alice, bob, 5000, 100, 0);
    let s1 = init_swap(&state, &swap, 50);

    // Path A: claim
    let tx_claim = Transaction::AtomicSwapClaim(make_claim(&swap));
    let claimed = validate_transaction(&tx_claim, &s1, 1000, 75).unwrap();

    // Path B: refund
    let tx_refund = Transaction::AtomicSwapRefund(make_refund(&swap));
    let refunded = validate_transaction(&tx_refund, &s1, 1000, 200).unwrap();

    // Different outcomes → different state roots
    assert_ne!(claimed.state_root(), refunded.state_root());
}

#[test]
fn swap_state_hash_varies_by_status() {
    let (_, alice, bob) = setup_wallets();
    let swap = make_swap(alice, bob, 5000, 100, 0);

    let active = swap_state_hash(&swap, SwapStatus::Active);
    let claimed = swap_state_hash(&swap, SwapStatus::Claimed);
    let refunded = swap_state_hash(&swap, SwapStatus::Refunded);

    assert_ne!(active, claimed);
    assert_ne!(active, refunded);
    assert_ne!(claimed, refunded);
    assert_ne!(active, ZERO_HASH);
}

#[test]
fn swap_state_hash_deterministic() {
    let (_, alice, bob) = setup_wallets();
    let swap = make_swap(alice, bob, 5000, 100, 0);

    let h1 = swap_state_hash(&swap, SwapStatus::Active);
    let h2 = swap_state_hash(&swap, SwapStatus::Active);
    assert_eq!(h1, h2);
}

#[test]
fn different_swap_params_produce_different_state_hashes() {
    let (_, alice, bob) = setup_wallets();
    let swap1 = make_swap(alice, bob, 5000, 100, 0);
    let swap2 = make_swap(alice, bob, 7000, 100, 1); // different amount

    let h1 = swap_state_hash(&swap1, SwapStatus::Active);
    let h2 = swap_state_hash(&swap2, SwapStatus::Active);
    assert_ne!(h1, h2);
}

#[test]
fn same_params_same_state_hash() {
    // Two swaps with same (initiator, responder, amount, hash_lock, timeout)
    // produce the same state hash — they're distinguished by swap_id in the SMT key.
    let (_, alice, bob) = setup_wallets();
    let swap1 = make_swap(alice, bob, 5000, 100, 0);
    let swap2 = make_swap(alice, bob, 5000, 100, 1); // different nonce → different swap_id

    assert_ne!(swap1.swap_id, swap2.swap_id); // distinct keys in SMT
    let h1 = swap_state_hash(&swap1, SwapStatus::Active);
    let h2 = swap_state_hash(&swap2, SwapStatus::Active);
    assert_eq!(h1, h2); // same value hash (same parameters)
}

// ---------------------------------------------------------------------------
// Swap with disclosure root and execution proof
// ---------------------------------------------------------------------------

#[test]
fn swap_with_disclosure_and_hash_ivc_proof() {
    let (state, alice, bob) = setup_wallets();
    let mut swap = make_swap(alice, bob, 5000, 100, 0);

    // Attach disclosure root and execution proof (the Phase 4 integration).
    // `execution_proof` is a stored metadata field, not verified by validation.
    swap.disclosure_root = Some([0xDD; 32]);
    swap.execution_proof = Some(hash_ivc_proof());

    // The transaction's verification `proof` must be a genuine HashIvc proof
    // bound to the I/O hashes that `validate_atomic_swap_init` recomputes.
    let swap_input = hash_with_domain(
        DOMAIN_SWAP,
        &[
            swap.responder.as_slice(),
            &swap.amount.to_le_bytes(),
            &swap.nonce.to_le_bytes(),
        ]
        .concat(),
    );
    let swap_output = hash_with_domain(
        DOMAIN_SWAP,
        &[swap.swap_id.as_slice(), &swap.hash_lock, &swap.timeout.to_le_bytes()].concat(),
    );
    swap.proof = genuine_hash_ivc_proof(swap_input, swap_output);

    let tx = Transaction::AtomicSwapInit(swap.clone());
    let s1 = validate_transaction(&tx, &state, 1000, 50).unwrap();
    assert!(s1.get_swap(&swap.swap_id).is_some());

    // Claim still works — also with a genuine HashIvc proof.
    let mut claim = make_claim(&swap);
    let claim_input = hash_with_domain(
        DOMAIN_SWAP,
        &[claim.swap_id.as_slice(), claim.claimer.as_slice(), &claim.secret].concat(),
    );
    let claim_output = hash_with_domain(
        DOMAIN_SWAP,
        &[claim.swap_id.as_slice(), &claim.original_hash_lock].concat(),
    );
    claim.proof = genuine_hash_ivc_proof(claim_input, claim_output);
    let tx_claim = Transaction::AtomicSwapClaim(claim);
    let s2 = validate_transaction(&tx_claim, &s1, 1000, 75).unwrap();
    assert!(s2.get_swap(&swap.swap_id).is_none());
}

// ---------------------------------------------------------------------------
// Transaction tag and fee_payer for swap variants
// ---------------------------------------------------------------------------

#[test]
fn swap_tx_tags_unique() {
    let (_, alice, bob) = setup_wallets();
    let swap = make_swap(alice, bob, 5000, 100, 0);

    let init_tag = Transaction::AtomicSwapInit(swap.clone()).tag();
    let claim_tag = Transaction::AtomicSwapClaim(make_claim(&swap)).tag();
    let refund_tag = Transaction::AtomicSwapRefund(make_refund(&swap)).tag();

    assert_eq!(init_tag, 0x09);
    assert_eq!(claim_tag, 0x0A);
    assert_eq!(refund_tag, 0x0B);
    assert_ne!(init_tag, claim_tag);
    assert_ne!(claim_tag, refund_tag);
}

#[test]
fn swap_fee_payers_correct() {
    let (_, alice, bob) = setup_wallets();
    let swap = make_swap(alice, bob, 5000, 100, 0);

    // Init: responder pays
    let init_payer = Transaction::AtomicSwapInit(swap.clone()).fee_payer();
    assert_eq!(init_payer, Some(bob));

    // Claim: claimer pays
    let claim_payer = Transaction::AtomicSwapClaim(make_claim(&swap)).fee_payer();
    assert_eq!(claim_payer, Some(alice));

    // Refund: refundee pays
    let refund_payer = Transaction::AtomicSwapRefund(make_refund(&swap)).fee_payer();
    assert_eq!(refund_payer, Some(bob));
}

#[test]
fn swap_tx_hash_deterministic() {
    let (_, alice, bob) = setup_wallets();
    let swap = make_swap(alice, bob, 5000, 100, 0);

    let tx = Transaction::AtomicSwapInit(swap);
    let h1 = tx.tx_hash();
    let h2 = tx.tx_hash();
    assert_eq!(h1, h2);
    assert_ne!(h1, ZERO_HASH);
}

// ---------------------------------------------------------------------------
// 8th subtree independence
// ---------------------------------------------------------------------------

#[test]
fn swaps_subtree_independent_from_wallets() {
    let (state, alice, bob) = setup_wallets();
    let swap = make_swap(alice, bob, 5000, 100, 0);

    let s1 = init_swap(&state, &swap, 50);

    // Wallet operations don't affect swap
    let swap_hash_before = s1.get_swap(&swap.swap_id);
    let mut s2 = s1.clone();
    s2.set_wallet([0xCC; 32], [0xDD; 32]);
    let swap_hash_after = s2.get_swap(&swap.swap_id);
    assert_eq!(swap_hash_before, swap_hash_after);

    // Swap operations don't affect unrelated wallets
    // Claiming credits alice (initiator), so check bob's wallet is unchanged
    let bob_wallet_before = s1.get_wallet(&bob);
    let tx_claim = Transaction::AtomicSwapClaim(make_claim(&swap));
    let s3 = validate_transaction(&tx_claim, &s1, 1000, 75).unwrap();
    let bob_wallet_after = s3.get_wallet(&bob);
    assert_eq!(bob_wallet_before, bob_wallet_after);
}

// ---------------------------------------------------------------------------
// Genesis state with 8 subtrees
// ---------------------------------------------------------------------------

#[test]
fn genesis_has_empty_swaps_subtree() {
    let state = GlobalState::genesis();
    assert!(state.swaps.is_empty());
    assert_eq!(state.swaps.len(), 0);
}

#[test]
fn genesis_state_root_is_deterministic() {
    let r1 = GlobalState::genesis().state_root();
    let r2 = GlobalState::genesis().state_root();
    assert_eq!(r1, r2);
    assert_ne!(r1, ZERO_HASH);
}

// ---------------------------------------------------------------------------
// Fee schedule
// ---------------------------------------------------------------------------

#[test]
fn atomic_swap_fee_is_reasonable() {
    let fee = FeeSchedule::atomic_swap_fee();
    assert_eq!(fee, 100); // 0.01 MANA
    assert!(fee > 0);
    assert!(fee <= FeeSchedule::base_fee()); // swap fee == base fee
}
