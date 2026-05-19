//! Client-side construction of signed, proven transactions.
//!
//! The chain is verify-only: every transaction carries a [`VerifiedProof`] and
//! an Ed25519 signature. This module builds both for a `CashTransfer` so the
//! transaction passes `validate_transaction` against real (non-mock) crypto.

use poly_verified::ivc::hash_ivc::HashIvc;
use poly_verified::ivc::IvcBackend;
use poly_verified::types::{Hash, PrivacyMode, StepWitness, VerifiedProof, ZERO_HASH};
use sha2::{Digest, Sha256};

use crate::error::{ChainError, Result};
use crate::identity::Tier;
use crate::keys::Keypair;
use crate::primitives::*;
use crate::transaction::{CashTransfer, Transaction};
use crate::validation::cash_transfer_signing_message;

/// Everything needed to build a signed `CashTransfer`.
///
/// The caller fills these in from wallet intent plus node-supplied chain state
/// (`state_pre` and `nonce` must come from the node, not be guessed).
pub struct CashTransferParams {
    pub to: AccountId,
    pub amount: Amount,
    pub fee: Amount,
    /// Sender's next expected nonce, from the node.
    pub nonce: Nonce,
    pub timestamp: Timestamp,
    /// Sender's current on-chain wallet commitment, from the node.
    pub state_pre: Hash,
    pub sender_tier: Tier,
    pub sender_identity_hash: Hash,
    pub recipient_identity_hash: Hash,
    /// Sender's rolling 24h outgoing total *after* this transfer.
    pub rolling_24h_total_after: Amount,
    /// ISO 3166-1 numeric country code.
    pub jurisdiction: u16,
}

/// The proof input hash bound by `validate_cash_transfer`.
///
/// Must byte-for-byte match the validator's construction, or the proof check
/// fails. See `validation::validate_cash_transfer`.
fn transfer_input_hash(from: &AccountId, p: &CashTransferParams) -> Hash {
    hash_with_domain(
        DOMAIN_TRANSFER,
        &[
            from.as_slice(),
            &p.state_pre,
            &p.nonce.to_le_bytes(),
            &[p.sender_tier as u8],
            &p.sender_identity_hash,
            &[0u8], // sender_frozen — a sender can only ever build txs while unfrozen
        ]
        .concat(),
    )
}

/// The proof output hash bound by `validate_cash_transfer`.
fn transfer_output_hash(p: &CashTransferParams) -> Hash {
    hash_with_domain(
        DOMAIN_TRANSFER,
        &[
            p.to.as_slice(),
            &p.amount.to_le_bytes(),
            &p.fee.to_le_bytes(),
            &p.timestamp.to_le_bytes(),
            &p.recipient_identity_hash,
            &[0u8], // recipient_frozen
            &p.rolling_24h_total_after.to_le_bytes(),
            &p.jurisdiction.to_le_bytes(),
        ]
        .concat(),
    )
}

/// Build a real, transparent `HashIvc` proof binding `input_hash`/`output_hash`.
///
/// A single fold step is sufficient: the validator only checks the committed
/// I/O hashes plus the proof's internal chain/Merkle consistency.
pub fn build_transfer_proof(input_hash: Hash, output_hash: Hash) -> Result<VerifiedProof> {
    let mut code_hasher = Sha256::new();
    code_hasher.update(b"poly-chain/CashTransfer/v1");
    let mut code_hash = [0u8; 32];
    code_hash.copy_from_slice(&code_hasher.finalize());

    let backend = HashIvc;
    let mut acc = backend.init(&code_hash, PrivacyMode::Transparent);
    backend.fold_step(
        &mut acc,
        &StepWitness {
            state_before: input_hash,
            step_inputs: ZERO_HASH,
            state_after: output_hash,
        },
    )?;
    acc.input_hash = input_hash;
    acc.output_hash = output_hash;
    backend.finalize(acc).map_err(ChainError::from)
}

/// Build and sign a `CashTransfer` ready for submission.
pub fn build_cash_transfer(sender: &Keypair, p: &CashTransferParams) -> Result<Transaction> {
    if p.rolling_24h_total_after < p.amount {
        return Err(ChainError::ComplianceViolation(
            "rolling_24h_total_after < amount".into(),
        ));
    }

    let from = sender.account_id();
    let input_hash = transfer_input_hash(&from, p);
    let output_hash = transfer_output_hash(p);
    let proof = build_transfer_proof(input_hash, output_hash)?;

    let mut tx = CashTransfer {
        from,
        to: p.to,
        amount: p.amount,
        fee: p.fee,
        nonce: p.nonce,
        timestamp: p.timestamp,
        state_pre: p.state_pre,
        proof,
        signature: [0u8; 64],
        sender_tier: p.sender_tier,
        sender_identity_hash: p.sender_identity_hash,
        recipient_identity_hash: p.recipient_identity_hash,
        sender_frozen: false,
        recipient_frozen: false,
        rolling_24h_total_after: p.rolling_24h_total_after,
        jurisdiction: p.jurisdiction,
    };

    tx.signature = sender.sign(&cash_transfer_signing_message(&tx));
    Ok(Transaction::CashTransfer(tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::GlobalState;
    use crate::validation::validate_transaction;

    fn anon_params(to: AccountId, state_pre: Hash) -> CashTransferParams {
        CashTransferParams {
            to,
            amount: 1_000,
            fee: 100,
            nonce: 0,
            timestamp: 10_000,
            state_pre,
            sender_tier: Tier::Anonymous,
            sender_identity_hash: ZERO_HASH,
            recipient_identity_hash: ZERO_HASH,
            rolling_24h_total_after: 1_000,
            jurisdiction: 0,
        }
    }

    #[test]
    fn built_transfer_passes_validation() {
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap();

        // Seed a genesis state where both wallets already exist.
        let mut state = GlobalState::genesis();
        let alice_pre = [0x11u8; 32];
        state.set_wallet(alice.account_id(), alice_pre);
        state.set_wallet(bob.account_id(), [0x22u8; 32]);

        let params = anon_params(bob.account_id(), alice_pre);
        let tx = build_cash_transfer(&alice, &params).unwrap();

        // Real proof + real signature must satisfy the production validator.
        let new_state = validate_transaction(&tx, &state, 10_000, 1).unwrap();
        assert_eq!(new_state.get_nonce(&alice.account_id()), 1);
    }

    #[test]
    fn wrong_state_pre_is_rejected() {
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap();

        let mut state = GlobalState::genesis();
        state.set_wallet(alice.account_id(), [0x11u8; 32]);
        state.set_wallet(bob.account_id(), [0x22u8; 32]);

        // Build against a stale state_pre.
        let params = anon_params(bob.account_id(), [0x99u8; 32]);
        let tx = build_cash_transfer(&alice, &params).unwrap();
        assert!(validate_transaction(&tx, &state, 10_000, 1).is_err());
    }

    #[test]
    fn rolling_total_below_amount_rejected() {
        let alice = Keypair::generate().unwrap();
        let bob = Keypair::generate().unwrap();
        let mut params = anon_params(bob.account_id(), [0u8; 32]);
        params.rolling_24h_total_after = 1; // < amount
        assert!(build_cash_transfer(&alice, &params).is_err());
    }
}
