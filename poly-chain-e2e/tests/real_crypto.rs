//! End-to-end tests against poly-chain's REAL verification paths.
//!
//! poly-chain's own unit/integration tests run with the `mock` feature, which
//! skips signature and proof verification — that blind spot let an `AccountId`
//! derivation bug survive 140 tests. These tests build poly-chain without
//! `mock`, so every transfer is checked with real Ed25519 signatures and a real
//! HashIvc proof.
//!
//! NOTE: run with `cargo test -p poly-chain-e2e`. A whole-workspace `cargo test`
//! unifies in `poly-chain/mock`; `mock_proof_is_rejected` below is the canary
//! that fails loudly if these tests are ever built with mock enabled.

use poly_chain::builder::{build_cash_transfer, CashTransferParams};
use poly_chain::identity::Tier;
use poly_chain::keys::Keypair;
use poly_chain::node::Testnet;
use poly_chain::transaction::Transaction;
use poly_verified::types::{PrivacyMode, VerifiedProof, ZERO_HASH};

fn funded() -> (Testnet, Keypair, Keypair) {
    let mut net = Testnet::new(1_000);
    let alice = Keypair::generate().unwrap();
    let bob = Keypair::generate().unwrap();
    net.faucet(alice.account_id(), "alice", 50_000, 1_000);
    net.faucet(bob.account_id(), "bob", 1_000, 1_000);
    (net, alice, bob)
}

fn transfer_params(net: &Testnet, from: &Keypair, to: &Keypair, amount: u64) -> CashTransferParams {
    let wallet = net.account(&from.account_id()).unwrap().wallet.clone();
    CashTransferParams {
        to: to.account_id(),
        amount,
        fee: 100,
        nonce: net.next_nonce(&from.account_id()),
        timestamp: 20_000,
        state_pre: net.on_chain_pre(&from.account_id()).unwrap(),
        sender_tier: Tier::Anonymous,
        sender_identity_hash: ZERO_HASH,
        recipient_identity_hash: ZERO_HASH,
        rolling_24h_total_after: wallet.rolling_24h_total + amount,
        jurisdiction: 0,
    }
}

#[test]
fn transfer_with_real_signature_and_proof_is_accepted() {
    let (mut net, alice, bob) = funded();
    let params = transfer_params(&net, &alice, &bob, 10_000);
    let tx = build_cash_transfer(&alice, &params).unwrap();
    net.submit(tx).unwrap();

    let report = net.produce_block(20_000).unwrap();
    assert_eq!(report.accepted, 1, "rejected: {:?}", report.rejected);
    assert_eq!(net.balance(&alice.account_id()), Some(50_000 - 10_000 - 100));
    assert_eq!(net.balance(&bob.account_id()), Some(1_000 + 10_000));
}

#[test]
fn tampered_signature_is_rejected() {
    let (mut net, alice, bob) = funded();
    let params = transfer_params(&net, &alice, &bob, 10_000);
    let Transaction::CashTransfer(mut ct) = build_cash_transfer(&alice, &params).unwrap() else {
        unreachable!()
    };
    ct.signature[0] ^= 0xFF;
    net.submit(Transaction::CashTransfer(ct)).unwrap();

    let report = net.produce_block(20_000).unwrap();
    assert_eq!(report.accepted, 0, "a tampered signature must not be accepted");
    assert_eq!(report.rejected.len(), 1);
}

#[test]
fn wrong_signer_is_rejected() {
    let (mut net, alice, bob) = funded();
    // Build a transfer for alice's account, but sign it with bob's key.
    let params = transfer_params(&net, &alice, &bob, 10_000);
    let Transaction::CashTransfer(mut ct) = build_cash_transfer(&bob, &params).unwrap() else {
        unreachable!()
    };
    ct.from = alice.account_id(); // claim to be alice; signature is bob's
    net.submit(Transaction::CashTransfer(ct)).unwrap();

    let report = net.produce_block(20_000).unwrap();
    assert_eq!(report.accepted, 0, "a transfer signed by the wrong key must be rejected");
}

/// Canary: a `Mock` proof must be rejected on the real verification path.
/// If this test ever *fails*, the suite was built with `poly-chain/mock` and is
/// not actually testing real crypto.
#[test]
fn mock_proof_is_rejected() {
    let (mut net, alice, bob) = funded();
    let params = transfer_params(&net, &alice, &bob, 10_000);
    let Transaction::CashTransfer(mut ct) = build_cash_transfer(&alice, &params).unwrap() else {
        unreachable!()
    };
    // The signing message excludes the proof, so swapping it keeps the
    // signature valid — the transaction fails only at proof verification.
    ct.proof = VerifiedProof::Mock {
        input_hash: ZERO_HASH,
        output_hash: ZERO_HASH,
        privacy_mode: PrivacyMode::Transparent,
    };
    net.submit(Transaction::CashTransfer(ct)).unwrap();

    let report = net.produce_block(20_000).unwrap();
    assert_eq!(
        report.accepted, 0,
        "a Mock proof was accepted — this suite is running with poly-chain/mock \
         enabled and is NOT testing real crypto"
    );
}

#[test]
fn two_transfers_chain_and_verify_integrity() {
    let (mut net, alice, bob) = funded();
    for _ in 0..2 {
        let params = transfer_params(&net, &alice, &bob, 5_000);
        let tx = build_cash_transfer(&alice, &params).unwrap();
        net.submit(tx).unwrap();
        let report = net.produce_block(20_000).unwrap();
        assert_eq!(report.accepted, 1, "rejected: {:?}", report.rejected);
    }
    assert_eq!(net.balance(&bob.account_id()), Some(1_000 + 10_000));
    assert!(net.verify_integrity().is_ok());
}
