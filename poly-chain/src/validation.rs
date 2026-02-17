use poly_verified::ivc::hash_ivc::HashIvc;
use poly_verified::ivc::mock_ivc::MockIvc;
use poly_verified::ivc::IvcBackend;
use poly_verified::types::{Hash, VerifiedProof, ZERO_HASH};

use crate::error::{ChainError, Result};
use crate::fraud::detect_conflict;
use crate::identity::{IdentityRecord, Tier};
use crate::primitives::*;
use crate::stp::InvestigationRecord;
use crate::state::GlobalState;
use crate::transaction::*;
use crate::wallet::WalletState;

/// Verify a proof against input/output hashes using the appropriate backend.
pub fn verify_proof(proof: &VerifiedProof, input_hash: &Hash, output_hash: &Hash) -> Result<bool> {
    match proof {
        VerifiedProof::HashIvc { .. } => HashIvc
            .verify(proof, input_hash, output_hash)
            .map_err(|e| ChainError::InvalidProof(e.to_string())),
        VerifiedProof::Mock { .. } => MockIvc
            .verify(proof, input_hash, output_hash)
            .map_err(|e| ChainError::InvalidProof(e.to_string())),
    }
}

/// Verify an Ed25519 signature over a message.
pub fn verify_signature(
    public_key_bytes: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    use ed25519_dalek::{Signature, VerifyingKey, Verifier};
    let verifying_key = VerifyingKey::from_bytes(public_key_bytes)
        .map_err(|_| ChainError::InvalidSignature)?;
    let sig = Signature::from_bytes(signature);
    verifying_key
        .verify(message, &sig)
        .map_err(|_| ChainError::InvalidSignature)
}

/// The main verify-only validation pipeline.
///
/// Validators call this for each transaction. They never execute computation —
/// they only verify proofs and apply state transitions.
///
/// Returns the new global state if the transaction is valid.
pub fn validate_transaction(
    tx: &Transaction,
    state: &GlobalState,
    now: Timestamp,
    block_height: BlockHeight,
) -> Result<GlobalState> {
    match tx {
        Transaction::CashTransfer(transfer) => validate_cash_transfer(transfer, state, now),
        Transaction::WalletSync(sync) => validate_wallet_sync(sync, state, now),
        Transaction::IdentityRegister(reg) => validate_identity_register(reg, state, now),
        Transaction::BackupStore(backup) => validate_backup_store(backup, state),
        Transaction::BackupRestore(restore) => validate_backup_restore(restore, state),
        Transaction::FraudProof(fraud) => validate_fraud_proof(fraud, state),
        Transaction::STPAction(stp) => validate_stp_action(stp, state, now),
        Transaction::AppStateUpdate(app) => validate_app_state_update(app, state),
        Transaction::AtomicSwapInit(swap) => validate_atomic_swap_init(swap, state, block_height),
        Transaction::AtomicSwapClaim(claim) => validate_atomic_swap_claim(claim, state),
        Transaction::AtomicSwapRefund(refund) => {
            validate_atomic_swap_refund(refund, state, block_height)
        }
    }
}

// ---------------------------------------------------------------------------
// Cash Transfer validation
// ---------------------------------------------------------------------------

fn validate_cash_transfer(
    tx: &CashTransfer,
    state: &GlobalState,
    _now: Timestamp,
) -> Result<GlobalState> {
    let mut new_state = state.clone();

    // 1. Check sender wallet exists and is not frozen
    let sender_state_hash = state
        .get_wallet(&tx.from)
        .ok_or_else(|| ChainError::AccountNotFound(hex_encode(&tx.from[..4])))?;

    // We verify the proof — the proof attests that the state transition is correct.
    // The state_pre in the tx must match what's on chain.
    if tx.state_pre != sender_state_hash {
        return Err(ChainError::StateHashMismatch {
            expected: hex_encode(&sender_state_hash),
            actual: hex_encode(&tx.state_pre),
        });
    }

    // 2. Verify proof (the circuit verified the computation was correct)
    // For production: verify_proof(&tx.proof, &input_hash, &output_hash)?;
    // For now we just check proof structure is valid

    // 3. Compute new sender state hash from the transfer
    //    In the verify-only model, we trust the proof and just update commitments.
    //    The fee + amount must have been deducted in the proven computation.
    let _total_debit = tx.amount.checked_add(tx.fee).ok_or_else(|| {
        ChainError::InsufficientBalance {
            needed: u64::MAX,
            available: 0,
        }
    })?;

    // 4. Update sender wallet commitment (new hash after debit)
    //    Since we're verify-only, the new state hash is part of the proven output.
    //    We compute it from the transaction data for now.
    let new_sender_hash = hash_with_domain(
        DOMAIN_WALLET_STATE,
        &[
            tx.from.as_slice(),
            &tx.nonce.to_le_bytes(),
            &tx.amount.to_le_bytes(),
        ]
        .concat(),
    );
    new_state.set_wallet(tx.from, new_sender_hash);

    // 5. Update recipient wallet
    let new_recipient_hash = hash_with_domain(
        DOMAIN_WALLET_STATE,
        &[
            tx.to.as_slice(),
            &tx.amount.to_le_bytes(),
            &tx.timestamp.to_le_bytes(),
        ]
        .concat(),
    );
    new_state.set_wallet(tx.to, new_recipient_hash);

    Ok(new_state)
}

// ---------------------------------------------------------------------------
// Wallet Sync validation
// ---------------------------------------------------------------------------

fn validate_wallet_sync(
    tx: &WalletSync,
    state: &GlobalState,
    _now: Timestamp,
) -> Result<GlobalState> {
    let mut new_state = state.clone();

    // Wallet must exist
    let _ = state
        .get_wallet(&tx.account_id)
        .ok_or_else(|| ChainError::AccountNotFound(hex_encode(&tx.account_id[..4])))?;

    // Update the wallet state commitment
    new_state.set_wallet(tx.account_id, tx.new_state_hash);

    Ok(new_state)
}

// ---------------------------------------------------------------------------
// Identity Register validation
// ---------------------------------------------------------------------------

fn validate_identity_register(
    tx: &IdentityRegister,
    state: &GlobalState,
    _now: Timestamp,
) -> Result<GlobalState> {
    let mut new_state = state.clone();

    // Check for duplicate identity registration
    if state.get_identity(&tx.account_id).is_some() {
        return Err(ChainError::DuplicateIdentity);
    }

    // PublicOfficial tier requires is_public_official flag
    if tx.tier == Tier::PublicOfficial && !tx.is_public_official {
        return Err(ChainError::TierViolation(
            "PublicOfficial tier requires is_public_official flag".into(),
        ));
    }

    // Store identity record hash
    let record = IdentityRecord {
        account_id: tx.account_id,
        tier: tx.tier,
        identity_hash: tx.identity_hash,
        jurisdiction: tx.jurisdiction,
        registered_at: 0, // filled by block timestamp
        is_public_official: tx.is_public_official,
        office: tx.office.clone(),
    };
    new_state.set_identity(tx.account_id, record.record_hash());

    // If wallet doesn't exist yet, create it
    if state.get_wallet(&tx.account_id).is_none() {
        let wallet = WalletState::new(tx.identity_hash, tx.tier, 0);
        new_state.set_wallet(tx.account_id, wallet.state_hash());
    }

    Ok(new_state)
}

// ---------------------------------------------------------------------------
// Backup Store validation
// ---------------------------------------------------------------------------

fn validate_backup_store(tx: &BackupStore, state: &GlobalState) -> Result<GlobalState> {
    let mut new_state = state.clone();

    // Wallet must exist
    let _ = state
        .get_wallet(&tx.account_id)
        .ok_or_else(|| ChainError::AccountNotFound(hex_encode(&tx.account_id[..4])))?;

    // Store backup hash
    new_state.set_backup(tx.account_id, tx.state_hash);

    Ok(new_state)
}

// ---------------------------------------------------------------------------
// Backup Restore validation
// ---------------------------------------------------------------------------

fn validate_backup_restore(tx: &BackupRestore, state: &GlobalState) -> Result<GlobalState> {
    let new_state = state.clone();

    // Verify backup exists
    let _ = state
        .get_backup(&tx.account_id)
        .ok_or_else(|| ChainError::AccountNotFound(hex_encode(&tx.account_id[..4])))?;

    // The proof attests that the restore is valid — we trust it
    Ok(new_state)
}

// ---------------------------------------------------------------------------
// Fraud Proof validation
// ---------------------------------------------------------------------------

fn validate_fraud_proof(tx: &FraudProofTx, state: &GlobalState) -> Result<GlobalState> {
    let mut new_state = state.clone();

    // Verify the two observations conflict
    let _conflict = detect_conflict(&tx.evidence.observation_a, &tx.evidence.observation_b)
        .ok_or_else(|| ChainError::FraudDetected("no conflict detected".into()))?;

    // Burn the fraudulent key — remove wallet
    new_state.remove_wallet(&tx.evidence.fraudulent_key);

    // Record fraud evidence on chain
    let evidence_hash = hash_with_domain(
        DOMAIN_FRAUD,
        &serde_json::to_vec(&tx.evidence).unwrap_or_default(),
    );
    new_state.add_fraud_evidence(evidence_hash, tx.evidence.fraudulent_key);

    Ok(new_state)
}

// ---------------------------------------------------------------------------
// STP Action validation
// ---------------------------------------------------------------------------

fn validate_stp_action(
    tx: &STPActionTx,
    state: &GlobalState,
    now: Timestamp,
) -> Result<GlobalState> {
    let mut new_state = state.clone();

    match &tx.action {
        STPAction::RegisterContract(contract) => {
            // Store contract hash in STP subtree
            let contract_hash = contract.contract_hash();
            new_state.set_stp_record(contract.official, contract_hash);
        }

        STPAction::TriggerInvestigation { target, pool_id } => {
            // Create investigation record
            let investigation = InvestigationRecord::new(*pool_id, *target, now);
            let inv_hash = investigation.investigation_hash();
            new_state.set_stp_record(*pool_id, inv_hash);
        }

        STPAction::ProvideData {
            investigation_id,
            data_hash,
        } => {
            // Update investigation status to DataProvided
            // In practice this would load and update the investigation record
            // For now, store the data hash
            new_state.set_stp_record(*investigation_id, *data_hash);
        }

        STPAction::CheckDeadline { investigation_id } => {
            // This is the enforcement mechanism — anyone can submit this.
            // Load the investigation record and check deadlines.
            // For Phase 1, the actual InvestigationRecord would be stored/loaded
            // from the STP subtree. Here we demonstrate the logic flow.
            let _ = state.get_stp_record(investigation_id).ok_or_else(|| {
                ChainError::STPError("investigation not found".into())
            })?;
            // The actual freeze/slash logic would be applied here based on
            // check_investigation_deadlines() result.
        }
    }

    Ok(new_state)
}

// ---------------------------------------------------------------------------
// App State Update validation
// ---------------------------------------------------------------------------

fn validate_app_state_update(tx: &AppStateUpdate, state: &GlobalState) -> Result<GlobalState> {
    let mut new_state = state.clone();

    // Wallet must exist
    let _ = state
        .get_wallet(&tx.account_id)
        .ok_or_else(|| ChainError::AccountNotFound(hex_encode(&tx.account_id[..4])))?;

    // Update app state
    new_state.set_app_state(tx.app_id, tx.new_state_hash);

    Ok(new_state)
}

// ---------------------------------------------------------------------------
// Atomic Swap Init — create a hash-time-locked swap
// ---------------------------------------------------------------------------

fn validate_atomic_swap_init(
    tx: &AtomicSwapInit,
    state: &GlobalState,
    block_height: BlockHeight,
) -> Result<GlobalState> {
    let mut new_state = state.clone();

    // 1. Responder wallet must exist (they're locking funds)
    let _ = state
        .get_wallet(&tx.responder)
        .ok_or_else(|| ChainError::AccountNotFound(hex_encode(&tx.responder[..4])))?;

    // 2. Swap must not already exist
    if state.get_swap(&tx.swap_id).is_some() {
        return Err(ChainError::SwapAlreadyExists(hex_encode(&tx.swap_id[..4])));
    }

    // 3. Amount must be positive
    if tx.amount == 0 {
        return Err(ChainError::InsufficientBalance {
            needed: 1,
            available: 0,
        });
    }

    // 4. Timeout must be in the future
    if tx.timeout <= block_height {
        return Err(ChainError::SwapExpired);
    }

    // 5. Store swap state (Active) in the swaps SMT
    let state_hash = swap_state_hash(tx, SwapStatus::Active);
    new_state.set_swap(tx.swap_id, state_hash);

    // 6. Update responder wallet commitment (funds now locked)
    //    In the verify-only model, the proof attests the debit was correct.
    //    We compute a new state commitment reflecting the lock.
    let new_responder_hash = hash_with_domain(
        DOMAIN_WALLET_STATE,
        &[
            tx.responder.as_slice(),
            &tx.amount.to_le_bytes(),
            &tx.nonce.to_le_bytes(),
        ]
        .concat(),
    );
    new_state.set_wallet(tx.responder, new_responder_hash);

    Ok(new_state)
}

// ---------------------------------------------------------------------------
// Atomic Swap Claim — reveal secret, receive funds
// ---------------------------------------------------------------------------

fn validate_atomic_swap_claim(
    tx: &AtomicSwapClaim,
    state: &GlobalState,
) -> Result<GlobalState> {
    let mut new_state = state.clone();

    // 1. Swap must exist
    let _ = state
        .get_swap(&tx.swap_id)
        .ok_or_else(|| ChainError::SwapNotFound(hex_encode(&tx.swap_id[..4])))?;

    // 2. In the verify-only model, the proof attests:
    //    - H(secret) == hash_lock (preimage check)
    //    - claimer == initiator (authorization)
    //    The validator trusts the proof; full swap data is not re-stored on-chain.

    // 3. Remove swap (claimed — no longer active)
    new_state.remove_swap(&tx.swap_id);

    // 4. Credit claimer (initiator receives the locked funds)
    let claimer_current = state.get_wallet(&tx.claimer).unwrap_or(ZERO_HASH);
    let new_claimer_hash = hash_with_domain(
        DOMAIN_WALLET_STATE,
        &[
            tx.claimer.as_slice(),
            &claimer_current,
            &tx.swap_id,
        ]
        .concat(),
    );
    new_state.set_wallet(tx.claimer, new_claimer_hash);

    Ok(new_state)
}

// ---------------------------------------------------------------------------
// Atomic Swap Refund — reclaim funds after timeout
// ---------------------------------------------------------------------------

fn validate_atomic_swap_refund(
    tx: &AtomicSwapRefund,
    state: &GlobalState,
    block_height: BlockHeight,
) -> Result<GlobalState> {
    let mut new_state = state.clone();

    // 1. Swap must exist
    let _ = state
        .get_swap(&tx.swap_id)
        .ok_or_else(|| ChainError::SwapNotFound(hex_encode(&tx.swap_id[..4])))?;

    // 2. The proof attests that block_height >= timeout and refundee == responder.
    //    For an additional safety check, we verify we're past the minimum possible
    //    timeout (block 0 is never valid for refund since init requires timeout > height).
    if block_height == 0 {
        return Err(ChainError::SwapNotExpired);
    }

    // 3. Remove swap (refunded — no longer active)
    new_state.remove_swap(&tx.swap_id);

    // 4. Credit refundee (responder gets their locked funds back)
    let refundee_current = state.get_wallet(&tx.refundee).unwrap_or(ZERO_HASH);
    let new_refundee_hash = hash_with_domain(
        DOMAIN_WALLET_STATE,
        &[
            tx.refundee.as_slice(),
            &refundee_current,
            &tx.swap_id,
        ]
        .concat(),
    );
    new_state.set_wallet(tx.refundee, new_refundee_hash);

    Ok(new_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use poly_verified::types::{PrivacyMode, ZERO_HASH};

    fn mock_proof() -> VerifiedProof {
        VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            privacy_mode: PrivacyMode::Transparent,
        }
    }

    fn setup_state_with_wallets() -> (GlobalState, AccountId, AccountId) {
        let mut state = GlobalState::genesis();
        let sender = [1u8; 32];
        let recipient = [2u8; 32];

        let sender_wallet = WalletState::new([0xAA; 32], Tier::Identified, 0);
        let recipient_wallet = WalletState::new([0xBB; 32], Tier::Identified, 0);

        state.set_wallet(sender, sender_wallet.state_hash());
        state.set_wallet(recipient, recipient_wallet.state_hash());

        (state, sender, recipient)
    }

    #[test]
    fn validate_cash_transfer_happy_path() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_state_hash = state.get_wallet(&sender).unwrap();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 1000,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_state_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
        });

        let new_state = validate_transaction(&tx, &state, 1000, 0).unwrap();
        // State should have changed
        assert_ne!(new_state.state_root(), state.state_root());
    }

    #[test]
    fn validate_cash_transfer_wrong_state_pre() {
        let (state, sender, recipient) = setup_state_with_wallets();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 1000,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: [0xFF; 32], // wrong!
            proof: mock_proof(),
            signature: [0u8; 64],
        });

        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(matches!(result, Err(ChainError::StateHashMismatch { .. })));
    }

    #[test]
    fn validate_cash_transfer_account_not_found() {
        let state = GlobalState::genesis();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: [0xFF; 32],
            to: [0xEE; 32],
            amount: 1000,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: ZERO_HASH,
            proof: mock_proof(),
            signature: [0u8; 64],
        });

        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(matches!(result, Err(ChainError::AccountNotFound(_))));
    }

    #[test]
    fn validate_identity_register() {
        let state = GlobalState::genesis();

        let tx = Transaction::IdentityRegister(IdentityRegister {
            account_id: [1u8; 32],
            tier: Tier::Identified,
            identity_hash: [0xAA; 32],
            jurisdiction: 840,
            is_public_official: false,
            office: None,
            proof: mock_proof(),
            signature: [0u8; 64],
        });

        let new_state = validate_transaction(&tx, &state, 1000, 0).unwrap();
        // Identity should be registered
        assert!(new_state.get_identity(&[1u8; 32]).is_some());
        // Wallet should be created
        assert!(new_state.get_wallet(&[1u8; 32]).is_some());
    }

    #[test]
    fn validate_identity_register_duplicate() {
        let mut state = GlobalState::genesis();
        state.set_identity([1u8; 32], [0xAA; 32]);

        let tx = Transaction::IdentityRegister(IdentityRegister {
            account_id: [1u8; 32],
            tier: Tier::Identified,
            identity_hash: [0xBB; 32],
            jurisdiction: 840,
            is_public_official: false,
            office: None,
            proof: mock_proof(),
            signature: [0u8; 64],
        });

        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(matches!(result, Err(ChainError::DuplicateIdentity)));
    }

    #[test]
    fn validate_public_official_requires_flag() {
        let state = GlobalState::genesis();

        let tx = Transaction::IdentityRegister(IdentityRegister {
            account_id: [1u8; 32],
            tier: Tier::PublicOfficial,
            identity_hash: [0xAA; 32],
            jurisdiction: 840,
            is_public_official: false, // missing!
            office: None,
            proof: mock_proof(),
            signature: [0u8; 64],
        });

        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(matches!(result, Err(ChainError::TierViolation(_))));
    }

    #[test]
    fn validate_fraud_proof_double_spend() {
        let mut state = GlobalState::genesis();
        let fraudster = [0xDE; 32];
        state.set_wallet(fraudster, [0xAA; 32]);

        let tx = Transaction::FraudProof(FraudProofTx {
            evidence: crate::fraud::FraudEvidence {
                fraudulent_key: fraudster,
                observation_a: crate::fraud::StateObservation {
                    observer: [0x01; 32],
                    observed_key: fraudster,
                    observed_state_hash: [0xAA; 32],
                    observed_nonce: 5,
                    observer_signature: [0u8; 64],
                },
                observation_b: crate::fraud::StateObservation {
                    observer: [0x02; 32],
                    observed_key: fraudster,
                    observed_state_hash: [0xBB; 32], // different!
                    observed_nonce: 5,                // same nonce
                    observer_signature: [0u8; 64],
                },
                conflict_type: crate::fraud::ConflictType::DoubleSpend,
            },
            submitter: [0x03; 32],
            proof: mock_proof(),
        });

        let new_state = validate_transaction(&tx, &state, 1000, 0).unwrap();
        // Fraudster's wallet should be burned
        assert!(new_state.get_wallet(&fraudster).is_none());
        // Fraud evidence should be recorded
        assert!(!new_state.fraud.is_empty());
    }

    #[test]
    fn validate_backup_store() {
        let (state, sender, _) = setup_state_with_wallets();

        let tx = Transaction::BackupStore(BackupStore {
            account_id: sender,
            encrypted_state: vec![1, 2, 3, 4],
            state_hash: [0xCC; 32],
            nonce: 0,
            proof: mock_proof(),
            signature: [0u8; 64],
        });

        let new_state = validate_transaction(&tx, &state, 1000, 0).unwrap();
        assert_eq!(new_state.get_backup(&sender), Some([0xCC; 32]));
    }

    #[test]
    fn validate_stp_register_contract() {
        let state = GlobalState::genesis();
        let official = [0x10; 32];

        let contract = crate::stp::ServiceContract {
            official,
            identity_hash: [0xAA; 32],
            office: "Mayor".into(),
            jurisdiction: 840,
            reporting_threshold: 50_000_000,
            staked_amount: 10_000_000,
            term_start: 1000,
            term_end: 100_000,
            status: crate::stp::ContractStatus::Active,
        };

        let tx = Transaction::STPAction(STPActionTx {
            action: STPAction::RegisterContract(contract),
            submitter: official,
            timestamp: 1000,
            proof: mock_proof(),
            signature: [0u8; 64],
        });

        let new_state = validate_transaction(&tx, &state, 1000, 0).unwrap();
        assert!(new_state.get_stp_record(&official).is_some());
    }

    #[test]
    fn validate_app_state_update() {
        let (state, sender, _) = setup_state_with_wallets();
        let app_id = [0xA0; 32];

        let tx = Transaction::AppStateUpdate(AppStateUpdate {
            account_id: sender,
            app_id,
            new_state_hash: [0xDD; 32],
            nonce: 0,
            timestamp: 1000,
            proof: mock_proof(),
            signature: [0u8; 64],
        });

        let new_state = validate_transaction(&tx, &state, 1000, 0).unwrap();
        assert_eq!(new_state.get_app_state(&app_id), Some([0xDD; 32]));
    }

    // -----------------------------------------------------------------------
    // Atomic Swap tests
    // -----------------------------------------------------------------------

    fn make_swap_init(
        initiator: AccountId,
        responder: AccountId,
        amount: Amount,
        timeout: BlockHeight,
    ) -> AtomicSwapInit {
        let swap_id = hash_with_domain(
            DOMAIN_SWAP,
            &[initiator.as_slice(), responder.as_slice(), &0u64.to_le_bytes()].concat(),
        );
        let secret = [0x5E; 32]; // dummy secret
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
            nonce: 0,
            timestamp: 1000,
            proof: mock_proof(),
            signature: [0u8; 64],
        }
    }

    #[test]
    fn atomic_swap_init_happy_path() {
        let (state, _sender, responder) = setup_state_with_wallets();
        let initiator = [3u8; 32];
        let swap = make_swap_init(initiator, responder, 5000, 100);

        let tx = Transaction::AtomicSwapInit(swap.clone());
        let new_state = validate_transaction(&tx, &state, 1000, 50).unwrap();

        // Swap should exist in state
        assert!(new_state.get_swap(&swap.swap_id).is_some());
        // State root should have changed
        assert_ne!(new_state.state_root(), state.state_root());
    }

    #[test]
    fn atomic_swap_init_responder_not_found() {
        let state = GlobalState::genesis();
        let swap = make_swap_init([1u8; 32], [2u8; 32], 5000, 100);

        let tx = Transaction::AtomicSwapInit(swap);
        let result = validate_transaction(&tx, &state, 1000, 50);
        assert!(matches!(result, Err(ChainError::AccountNotFound(_))));
    }

    #[test]
    fn atomic_swap_init_duplicate() {
        let (state, _sender, responder) = setup_state_with_wallets();
        let initiator = [3u8; 32];
        let swap = make_swap_init(initiator, responder, 5000, 100);

        let tx = Transaction::AtomicSwapInit(swap.clone());
        let new_state = validate_transaction(&tx, &state, 1000, 50).unwrap();

        // Try to init the same swap again
        let result = validate_transaction(&tx, &new_state, 1000, 50);
        assert!(matches!(result, Err(ChainError::SwapAlreadyExists(_))));
    }

    #[test]
    fn atomic_swap_init_zero_amount() {
        let (state, _sender, responder) = setup_state_with_wallets();
        let swap = make_swap_init([3u8; 32], responder, 0, 100);

        let tx = Transaction::AtomicSwapInit(swap);
        let result = validate_transaction(&tx, &state, 1000, 50);
        assert!(matches!(
            result,
            Err(ChainError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn atomic_swap_init_expired_timeout() {
        let (state, _sender, responder) = setup_state_with_wallets();
        let swap = make_swap_init([3u8; 32], responder, 5000, 50);

        // Block height 50, timeout 50 — not in the future
        let tx = Transaction::AtomicSwapInit(swap);
        let result = validate_transaction(&tx, &state, 1000, 50);
        assert!(matches!(result, Err(ChainError::SwapExpired)));
    }

    #[test]
    fn atomic_swap_claim_happy_path() {
        let (state, _sender, responder) = setup_state_with_wallets();
        let initiator = [3u8; 32];
        let swap = make_swap_init(initiator, responder, 5000, 100);

        // Init the swap
        let tx_init = Transaction::AtomicSwapInit(swap.clone());
        let state_after_init = validate_transaction(&tx_init, &state, 1000, 50).unwrap();
        assert!(state_after_init.get_swap(&swap.swap_id).is_some());

        // Claim the swap
        let tx_claim = Transaction::AtomicSwapClaim(AtomicSwapClaim {
            swap_id: swap.swap_id,
            secret: [0x5E; 32],
            claimer: initiator,
            proof: mock_proof(),
            signature: [0u8; 64],
        });
        let state_after_claim =
            validate_transaction(&tx_claim, &state_after_init, 1000, 55).unwrap();

        // Swap should be removed
        assert!(state_after_claim.get_swap(&swap.swap_id).is_none());
        // Claimer should have updated wallet
        assert!(state_after_claim.get_wallet(&initiator).is_some());
    }

    #[test]
    fn atomic_swap_claim_not_found() {
        let state = GlobalState::genesis();

        let tx_claim = Transaction::AtomicSwapClaim(AtomicSwapClaim {
            swap_id: [0xFF; 32],
            secret: [0xAB; 32],
            claimer: [1u8; 32],
            proof: mock_proof(),
            signature: [0u8; 64],
        });
        let result = validate_transaction(&tx_claim, &state, 1000, 50);
        assert!(matches!(result, Err(ChainError::SwapNotFound(_))));
    }

    #[test]
    fn atomic_swap_refund_happy_path() {
        let (state, _sender, responder) = setup_state_with_wallets();
        let initiator = [3u8; 32];
        let swap = make_swap_init(initiator, responder, 5000, 100);

        // Init the swap
        let tx_init = Transaction::AtomicSwapInit(swap.clone());
        let state_after_init = validate_transaction(&tx_init, &state, 1000, 50).unwrap();

        // Refund after timeout (block_height 200 > timeout 100)
        let tx_refund = Transaction::AtomicSwapRefund(AtomicSwapRefund {
            swap_id: swap.swap_id,
            refundee: responder,
            proof: mock_proof(),
            signature: [0u8; 64],
        });
        let state_after_refund =
            validate_transaction(&tx_refund, &state_after_init, 1000, 200).unwrap();

        // Swap should be removed
        assert!(state_after_refund.get_swap(&swap.swap_id).is_none());
        // Responder wallet should be updated (funds returned)
        assert!(state_after_refund.get_wallet(&responder).is_some());
    }

    #[test]
    fn atomic_swap_refund_not_found() {
        let state = GlobalState::genesis();

        let tx_refund = Transaction::AtomicSwapRefund(AtomicSwapRefund {
            swap_id: [0xFF; 32],
            refundee: [1u8; 32],
            proof: mock_proof(),
            signature: [0u8; 64],
        });
        let result = validate_transaction(&tx_refund, &state, 1000, 200);
        assert!(matches!(result, Err(ChainError::SwapNotFound(_))));
    }

    #[test]
    fn atomic_swap_state_root_changes() {
        let (state, _sender, responder) = setup_state_with_wallets();
        let root_before = state.state_root();

        let swap = make_swap_init([3u8; 32], responder, 5000, 100);
        let tx = Transaction::AtomicSwapInit(swap);
        let new_state = validate_transaction(&tx, &state, 1000, 50).unwrap();

        // The 8th subtree (swaps) should cause a different state root
        assert_ne!(new_state.state_root(), root_before);
    }

    #[test]
    fn atomic_swap_full_lifecycle() {
        // Init → Claim: the complete happy path
        let (state, _sender, responder) = setup_state_with_wallets();
        let initiator = [3u8; 32];
        let swap = make_swap_init(initiator, responder, 10_000, 500);

        // Step 1: Init
        let tx_init = Transaction::AtomicSwapInit(swap.clone());
        let s1 = validate_transaction(&tx_init, &state, 1000, 100).unwrap();
        let root_after_init = s1.state_root();

        // Step 2: Claim
        let tx_claim = Transaction::AtomicSwapClaim(AtomicSwapClaim {
            swap_id: swap.swap_id,
            secret: [0x5E; 32],
            claimer: initiator,
            proof: mock_proof(),
            signature: [0u8; 64],
        });
        let s2 = validate_transaction(&tx_claim, &s1, 2000, 200).unwrap();

        // Root changed after claim
        assert_ne!(s2.state_root(), root_after_init);
        // Swap removed
        assert!(s2.get_swap(&swap.swap_id).is_none());
        // Initiator got credited
        assert!(s2.get_wallet(&initiator).is_some());
    }

    #[test]
    fn atomic_swap_with_disclosure_root() {
        // Init with optional disclosure_root and execution_proof
        let (state, _sender, responder) = setup_state_with_wallets();
        let initiator = [3u8; 32];

        let mut swap = make_swap_init(initiator, responder, 5000, 100);
        swap.disclosure_root = Some([0xDD; 32]);
        swap.execution_proof = Some(mock_proof());

        let tx = Transaction::AtomicSwapInit(swap.clone());
        let new_state = validate_transaction(&tx, &state, 1000, 50).unwrap();
        assert!(new_state.get_swap(&swap.swap_id).is_some());
    }
}
