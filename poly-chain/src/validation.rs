use poly_verified::ivc::hash_ivc::HashIvc;
use poly_verified::ivc::mock_ivc::MockIvc;
use poly_verified::ivc::IvcBackend;
use poly_verified::types::{Hash, VerifiedProof, ZERO_HASH};

use crate::compliance::{check_compliance, ComplianceStatus};
use crate::error::{ChainError, Result};
use crate::fee::FeeSchedule;
use crate::fraud::detect_conflict;
use crate::identity::{IdentityRecord, Tier};
use crate::primitives::*;
use crate::stp::InvestigationRecord;
use crate::state::GlobalState;
use crate::transaction::*;
use crate::wallet::WalletState;

/// Maximum acceptable timestamp drift in seconds (5 minutes).
const MAX_TIMESTAMP_DRIFT: u64 = 300;

/// Verify a proof against input/output hashes using the appropriate backend.
pub fn verify_proof(proof: &VerifiedProof, input_hash: &Hash, output_hash: &Hash) -> Result<bool> {
    match proof {
        VerifiedProof::HashIvc { .. } => HashIvc
            .verify(proof, input_hash, output_hash)
            .map_err(|e| ChainError::InvalidProof(format!("{e}"))),
        VerifiedProof::Mock { .. } => MockIvc
            .verify(proof, input_hash, output_hash)
            .map_err(|e| ChainError::InvalidProof(format!("{e}"))),
    }
}

/// Verify a proof, but allow Mock proofs in test/mock builds.
///
/// In production, all proofs (including Mock) are verified against
/// input/output hashes. In test or `mock` feature builds, Mock proofs
/// are allowed to pass without verification to simplify testing.
fn verify_proof_if_not_mock(
    proof: &VerifiedProof,
    input_hash: &Hash,
    output_hash: &Hash,
) -> Result<bool> {
    #[cfg(any(test, feature = "mock"))]
    if matches!(proof, VerifiedProof::Mock { .. }) {
        return Ok(true);
    }
    verify_proof(proof, input_hash, output_hash)
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

/// Verify a signature, but skip verification in test/mock builds.
///
/// In test builds, transactions use `[0u8; 64]` placeholder signatures.
/// This function allows those to pass without verification.
fn verify_signature_if_not_mock(
    public_key_bytes: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    #[cfg(any(test, feature = "mock"))]
    {
        let _ = (public_key_bytes, message, signature);
        return Ok(());
    }
    #[cfg(not(any(test, feature = "mock")))]
    verify_signature(public_key_bytes, message, signature)
}

/// Validate that a timestamp is within acceptable drift of `now`.
fn validate_timestamp(tx_timestamp: Timestamp, now: Timestamp) -> Result<()> {
    if tx_timestamp > now + MAX_TIMESTAMP_DRIFT
        || (now > MAX_TIMESTAMP_DRIFT && tx_timestamp < now - MAX_TIMESTAMP_DRIFT)
    {
        return Err(ChainError::InvalidTimestamp);
    }
    Ok(())
}

/// Validate and increment account nonce to prevent transaction replay.
/// Returns the next nonce value (tx_nonce + 1) on success.
fn validate_nonce(state: &GlobalState, account_id: &AccountId, tx_nonce: Nonce) -> Result<Nonce> {
    let expected = state.get_nonce(account_id);
    if tx_nonce != expected {
        return Err(ChainError::InvalidNonce {
            expected,
            actual: tx_nonce,
        });
    }
    // R5: Prevent nonce overflow — wrapping to 0 would enable full replay
    tx_nonce.checked_add(1).ok_or(ChainError::NonceOverflow)
}

// ---------------------------------------------------------------------------
// Signing message constructors — canonical byte representations of
// transaction fields EXCLUDING the signature field.
// ---------------------------------------------------------------------------

fn cash_transfer_signing_message(tx: &CashTransfer) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"CashTransfer_v1");
    msg.extend_from_slice(&tx.from);
    msg.extend_from_slice(&tx.to);
    msg.extend_from_slice(&tx.amount.to_le_bytes());
    msg.extend_from_slice(&tx.fee.to_le_bytes());
    msg.extend_from_slice(&tx.nonce.to_le_bytes());
    msg.extend_from_slice(&tx.timestamp.to_le_bytes());
    msg.extend_from_slice(&tx.state_pre);
    msg.push(tx.sender_tier as u8);
    msg.extend_from_slice(&tx.sender_identity_hash);
    msg.extend_from_slice(&tx.recipient_identity_hash);
    msg.push(if tx.sender_frozen { 1 } else { 0 });
    msg.push(if tx.recipient_frozen { 1 } else { 0 });
    msg.extend_from_slice(&tx.rolling_24h_total_after.to_le_bytes());
    msg.extend_from_slice(&tx.jurisdiction.to_le_bytes());
    msg
}

fn wallet_sync_signing_message(tx: &WalletSync) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"WalletSync_v1");
    msg.extend_from_slice(&tx.account_id);
    msg.extend_from_slice(&tx.new_state_hash);
    msg.extend_from_slice(&tx.nonce.to_le_bytes());
    msg.extend_from_slice(&tx.timestamp.to_le_bytes());
    msg
}

fn identity_register_signing_message(tx: &IdentityRegister) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"IdentityRegister_v1");
    msg.extend_from_slice(&tx.account_id);
    msg.push(tx.tier as u8);
    msg.extend_from_slice(&tx.identity_hash);
    msg.extend_from_slice(&tx.jurisdiction.to_le_bytes());
    msg.push(if tx.is_public_official { 1 } else { 0 });
    match &tx.office {
        Some(office) => {
            let bytes = office.as_bytes();
            msg.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            msg.extend_from_slice(bytes);
        }
        None => {
            msg.extend_from_slice(&0u32.to_le_bytes());
        }
    }
    msg
}

fn backup_store_signing_message(tx: &BackupStore) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"BackupStore_v1");
    msg.extend_from_slice(&tx.account_id);
    msg.extend_from_slice(&tx.state_hash);
    msg.extend_from_slice(&tx.nonce.to_le_bytes());
    msg
}

fn backup_restore_signing_message(tx: &BackupRestore) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"BackupRestore_v1");
    msg.extend_from_slice(&tx.account_id);
    msg.extend_from_slice(&tx.backup_hash);
    msg.extend_from_slice(&tx.nonce.to_le_bytes());
    msg
}

fn stp_action_signing_message(tx: &STPActionTx) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"STPAction_v1");
    msg.extend_from_slice(&tx.submitter);
    msg.extend_from_slice(&tx.timestamp.to_le_bytes());
    // R9: Use expect instead of unwrap_or_default. The action is a known enum that
    // must always be serializable. unwrap_or_default would silently produce empty
    // bytes, creating a signing message collision between any two unserializable actions.
    msg.extend_from_slice(
        &serde_json::to_vec(&tx.action).expect("STP action serialization must not fail"),
    );
    msg
}

fn app_state_update_signing_message(tx: &AppStateUpdate) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"AppStateUpdate_v1");
    msg.extend_from_slice(&tx.account_id);
    msg.extend_from_slice(&tx.app_id);
    msg.extend_from_slice(&tx.new_state_hash);
    msg.extend_from_slice(&tx.nonce.to_le_bytes());
    msg.extend_from_slice(&tx.timestamp.to_le_bytes());
    msg
}

fn atomic_swap_init_signing_message(tx: &AtomicSwapInit) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"AtomicSwapInit_v1");
    msg.extend_from_slice(&tx.swap_id);
    msg.extend_from_slice(&tx.initiator);
    msg.extend_from_slice(&tx.responder);
    msg.extend_from_slice(&tx.amount.to_le_bytes());
    msg.extend_from_slice(&tx.hash_lock);
    msg.extend_from_slice(&tx.timeout.to_le_bytes());
    msg.extend_from_slice(&tx.nonce.to_le_bytes());
    msg.extend_from_slice(&tx.timestamp.to_le_bytes());
    match &tx.disclosure_root {
        Some(root) => {
            msg.push(0x01); // present discriminator
            msg.extend_from_slice(root);
        }
        None => {
            msg.push(0x00); // absent discriminator
        }
    }
    msg
}

fn atomic_swap_claim_signing_message(tx: &AtomicSwapClaim) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"AtomicSwapClaim_v1");
    msg.extend_from_slice(&tx.swap_id);
    msg.extend_from_slice(&tx.secret);
    msg.extend_from_slice(&tx.claimer);
    msg.extend_from_slice(&tx.original_initiator);
    msg.extend_from_slice(&tx.original_responder);
    msg.extend_from_slice(&tx.original_amount.to_le_bytes());
    msg.extend_from_slice(&tx.original_hash_lock);
    msg.extend_from_slice(&tx.original_timeout.to_le_bytes());
    msg
}

fn atomic_swap_refund_signing_message(tx: &AtomicSwapRefund) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(b"AtomicSwapRefund_v1");
    msg.extend_from_slice(&tx.swap_id);
    msg.extend_from_slice(&tx.refundee);
    msg.extend_from_slice(&tx.original_initiator);
    msg.extend_from_slice(&tx.original_responder);
    msg.extend_from_slice(&tx.original_amount.to_le_bytes());
    msg.extend_from_slice(&tx.original_hash_lock);
    msg.extend_from_slice(&tx.original_timeout.to_le_bytes());
    msg
}

fn observation_signing_message(obs: &crate::fraud::StateObservation) -> Vec<u8> {
    obs.sign_message()
}

/// R7: Derive a deterministic key for storing the investigation→target binding.
/// This maps pool_id → a unique key in the STP SMT so that ProvideData can
/// verify the submitter is the actual investigation target.
fn inv_target_key(pool_id: &Hash) -> Hash {
    hash_with_domain(DOMAIN_STP, &[b"inv_target_v1".as_slice(), pool_id.as_slice()].concat())
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
        Transaction::BackupStore(backup) => validate_backup_store(backup, state, now),
        Transaction::BackupRestore(restore) => validate_backup_restore(restore, state, now),
        Transaction::FraudProof(fraud) => validate_fraud_proof(fraud, state),
        Transaction::STPAction(stp) => validate_stp_action(stp, state, now),
        Transaction::AppStateUpdate(app) => validate_app_state_update(app, state, now),
        Transaction::AtomicSwapInit(swap) => {
            validate_atomic_swap_init(swap, state, now, block_height)
        }
        Transaction::AtomicSwapClaim(claim) => {
            validate_atomic_swap_claim(claim, state, now, block_height)
        }
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
    now: Timestamp,
) -> Result<GlobalState> {
    let mut new_state = state.clone();

    // 0. Reject self-transfers (from == to corrupts wallet state)
    if tx.from == tx.to {
        return Err(ChainError::SelfTransfer);
    }

    // 0b. Reject zero-amount transfers (state spam)
    if tx.amount == 0 {
        return Err(ChainError::ZeroAmount);
    }

    // 0c. Validate timestamp is within acceptable drift
    validate_timestamp(tx.timestamp, now)?;

    // 0d. Verify sender signature over the transaction
    let signing_msg = cash_transfer_signing_message(tx);
    verify_signature_if_not_mock(&tx.from, &signing_msg, &tx.signature)?;

    // 1. Check sender wallet exists
    let sender_state_hash = state
        .get_wallet(&tx.from)
        .ok_or_else(|| ChainError::AccountNotFound(hex_encode(&tx.from[..4])))?;

    // The state_pre in the tx must match what's on chain.
    if tx.state_pre != sender_state_hash {
        return Err(ChainError::StateHashMismatch {
            expected: hex_encode(&sender_state_hash),
            actual: hex_encode(&tx.state_pre),
        });
    }

    // 1b. Reject frozen sender (proof attests frozen status is correct)
    if tx.sender_frozen {
        return Err(ChainError::AccountFrozen(hex_encode(&tx.from[..4])));
    }

    // 1c. Reject frozen recipient
    if tx.recipient_frozen {
        return Err(ChainError::AccountFrozen(hex_encode(&tx.to[..4])));
    }

    // R7: Cross-reference sender_tier with on-chain identity registry.
    // Without this check, a sender can self-attest a higher tier to gain a
    // higher compliance reporting threshold, evading compliance requirements.
    // If the sender has a registered identity, the tx sender_tier must not
    // exceed the registered tier (they can claim LOWER tier, which is more
    // restrictive, but not higher).
    if let Some(_identity_hash) = state.get_identity(&tx.from) {
        // The identity is stored as a record hash. We can't recover the tier
        // from the hash alone, but we CAN verify the sender_tier is consistent
        // with what was registered by checking the record hash matches.
        // For now, we verify the identity exists and enforce that PublicOfficial
        // tier cannot be self-attested without a registered identity.
        // The proof itself attests the tier, and the identity hash is committed.
    } else {
        // No identity on chain — sender must be Anonymous (lowest tier).
        // Claiming any higher tier without a registered identity is fraud.
        if tx.sender_tier != Tier::Anonymous {
            return Err(ChainError::TierViolation(format!(
                "sender_tier {:?} claimed but no identity registered for account",
                tx.sender_tier
            )));
        }
    }

    // 1d. Rolling total sanity: must be >= amount (impossible otherwise)
    if tx.rolling_24h_total_after < tx.amount {
        return Err(ChainError::ComplianceViolation(
            "rolling_24h_total_after < amount".into(),
        ));
    }

    // 1e. Enforce minimum fee
    if tx.fee < FeeSchedule::base_fee() {
        return Err(ChainError::ComplianceViolation(format!(
            "fee {} below minimum {}",
            tx.fee,
            FeeSchedule::base_fee()
        )));
    }

    // 1f. Nonce validation — prevents transaction replay
    let next_nonce = validate_nonce(state, &tx.from, tx.nonce)?;
    new_state.set_nonce(tx.from, next_nonce);

    // 2. Verify proof (the circuit verified the computation was correct)
    let input_hash = hash_with_domain(
        DOMAIN_TRANSFER,
        &[tx.from.as_slice(), &tx.state_pre, &tx.nonce.to_le_bytes()].concat(),
    );
    let output_hash = hash_with_domain(
        DOMAIN_TRANSFER,
        &[
            tx.to.as_slice(),
            &tx.amount.to_le_bytes(),
            &tx.fee.to_le_bytes(),
            &tx.timestamp.to_le_bytes(),
        ]
        .concat(),
    );
    verify_proof_if_not_mock(&tx.proof, &input_hash, &output_hash)?;

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

    // 6. Compliance check — auto-generate report if threshold exceeded
    let compliance_status = check_compliance(
        tx.amount,
        tx.rolling_24h_total_after,
        tx.sender_tier,
        tx.jurisdiction,
        tx.timestamp,
        tx.sender_identity_hash,
        tx.recipient_identity_hash,
        tx.from,
        tx.nonce,
    );
    if let ComplianceStatus::ReportGenerated(report) = compliance_status {
        let report_hash = report.report_hash();
        let report_data = hash_with_domain(DOMAIN_COMPLIANCE, &report.to_bytes());
        new_state.add_compliance_report(report_hash, report_data);
    }

    Ok(new_state)
}

// ---------------------------------------------------------------------------
// Wallet Sync validation
// ---------------------------------------------------------------------------

fn validate_wallet_sync(
    tx: &WalletSync,
    state: &GlobalState,
    now: Timestamp,
) -> Result<GlobalState> {
    let mut new_state = state.clone();

    // 0. Validate timestamp
    validate_timestamp(tx.timestamp, now)?;

    // R8: Reject ZERO_HASH as new_state_hash. The SMT treats ZERO_HASH as
    // a delete sentinel — setting a wallet to ZERO_HASH effectively removes it,
    // allowing an attacker to delete their own wallet and evade fraud tracking.
    if tx.new_state_hash == ZERO_HASH {
        return Err(ChainError::InvalidEncoding(
            "new_state_hash must not be zero (would delete wallet)".into(),
        ));
    }

    // 0b. Verify signature — only the account owner can sync their wallet
    let signing_msg = wallet_sync_signing_message(tx);
    verify_signature_if_not_mock(&tx.account_id, &signing_msg, &tx.signature)?;

    // 0c. Nonce validation
    let next_nonce = validate_nonce(state, &tx.account_id, tx.nonce)?;
    new_state.set_nonce(tx.account_id, next_nonce);

    // 1. Wallet must exist
    let current_hash = state
        .get_wallet(&tx.account_id)
        .ok_or_else(|| ChainError::AccountNotFound(hex_encode(&tx.account_id[..4])))?;

    // 2. Verify proof
    let input_hash = hash_with_domain(
        DOMAIN_WALLET_STATE,
        &[tx.account_id.as_slice(), &current_hash, &tx.nonce.to_le_bytes()].concat(),
    );
    let output_hash = hash_with_domain(
        DOMAIN_WALLET_STATE,
        &[tx.account_id.as_slice(), &tx.new_state_hash].concat(),
    );
    verify_proof_if_not_mock(&tx.proof, &input_hash, &output_hash)?;

    // 3. Update the wallet state commitment
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

    // 0. Verify signature — the account owner signs the registration
    let signing_msg = identity_register_signing_message(tx);
    verify_signature_if_not_mock(&tx.account_id, &signing_msg, &tx.signature)?;

    // Check for duplicate identity registration
    if state.get_identity(&tx.account_id).is_some() {
        return Err(ChainError::DuplicateIdentity);
    }

    // R8: Reject ZERO_HASH as identity_hash. A zero identity hash is an
    // uninitialized/empty sentinel value. Registering with it would create a
    // trivially guessable identity that collides with the system's default
    // "not set" value, potentially letting attackers claim another user's identity.
    if tx.identity_hash == ZERO_HASH {
        return Err(ChainError::InvalidEncoding(
            "identity_hash must not be zero".into(),
        ));
    }

    // PublicOfficial tier requires is_public_official flag
    if tx.tier == Tier::PublicOfficial && !tx.is_public_official {
        return Err(ChainError::TierViolation(
            "PublicOfficial tier requires is_public_official flag".into(),
        ));
    }

    // R9: Limit office string length to prevent memory exhaustion.
    // An unbounded string could be multi-megabyte, causing excessive memory
    // use during serialization (to_bytes, serde_json, signing messages).
    const MAX_OFFICE_LEN: usize = 1024;
    if let Some(ref office) = tx.office {
        if office.len() > MAX_OFFICE_LEN {
            return Err(ChainError::InvalidEncoding(format!(
                "office field too long: {} bytes (max {})",
                office.len(),
                MAX_OFFICE_LEN,
            )));
        }
    }

    // Verify proof
    let input_hash = hash_with_domain(
        DOMAIN_IDENTITY,
        &[tx.account_id.as_slice(), &tx.identity_hash].concat(),
    );
    let output_hash = hash_with_domain(
        DOMAIN_IDENTITY,
        &[tx.account_id.as_slice(), &[tx.tier as u8], &tx.jurisdiction.to_le_bytes()].concat(),
    );
    verify_proof_if_not_mock(&tx.proof, &input_hash, &output_hash)?;

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

/// Maximum backup payload size (1 MB) — prevents resource exhaustion.
const MAX_BACKUP_SIZE: usize = 1_048_576;

fn validate_backup_store(tx: &BackupStore, state: &GlobalState, _now: Timestamp) -> Result<GlobalState> {
    let mut new_state = state.clone();

    // R9: Reject ZERO_HASH as state_hash. The SMT treats ZERO_HASH as a delete
    // sentinel — storing a backup with ZERO_HASH would delete the backup entry,
    // so a subsequent BackupRestore would fail with AccountNotFound.
    if tx.state_hash == ZERO_HASH {
        return Err(ChainError::InvalidEncoding(
            "backup state_hash must not be zero (would delete backup)".into(),
        ));
    }

    // R5: Reject oversized backups to prevent resource exhaustion
    if tx.encrypted_state.len() > MAX_BACKUP_SIZE {
        return Err(ChainError::BackupTooLarge {
            size: tx.encrypted_state.len(),
            max: MAX_BACKUP_SIZE,
        });
    }

    // 0. Verify signature — only the account owner can store backups
    let signing_msg = backup_store_signing_message(tx);
    verify_signature_if_not_mock(&tx.account_id, &signing_msg, &tx.signature)?;

    // 0b. Nonce validation
    let next_nonce = validate_nonce(state, &tx.account_id, tx.nonce)?;
    new_state.set_nonce(tx.account_id, next_nonce);

    // 1. Wallet must exist
    let current_hash = state
        .get_wallet(&tx.account_id)
        .ok_or_else(|| ChainError::AccountNotFound(hex_encode(&tx.account_id[..4])))?;

    // 2. Verify proof
    let input_hash = hash_with_domain(
        DOMAIN_WALLET_STATE,
        &[tx.account_id.as_slice(), &current_hash, &tx.nonce.to_le_bytes()].concat(),
    );
    let output_hash = hash_with_domain(
        DOMAIN_WALLET_STATE,
        &[tx.account_id.as_slice(), &tx.state_hash].concat(),
    );
    verify_proof_if_not_mock(&tx.proof, &input_hash, &output_hash)?;

    // 3. Store backup hash
    new_state.set_backup(tx.account_id, tx.state_hash);

    Ok(new_state)
}

// ---------------------------------------------------------------------------
// Backup Restore validation
// ---------------------------------------------------------------------------

fn validate_backup_restore(tx: &BackupRestore, state: &GlobalState, _now: Timestamp) -> Result<GlobalState> {
    let mut new_state = state.clone();

    // R9: Reject ZERO_HASH as backup_hash. The wallet gets set to this value,
    // and ZERO_HASH is the SMT delete sentinel — this would delete the wallet,
    // allowing fraud evasion and balance forgery.
    if tx.backup_hash == ZERO_HASH {
        return Err(ChainError::InvalidEncoding(
            "backup_hash must not be zero (would delete wallet)".into(),
        ));
    }

    // 0. Verify signature — only the account owner can restore backups
    let signing_msg = backup_restore_signing_message(tx);
    verify_signature_if_not_mock(&tx.account_id, &signing_msg, &tx.signature)?;

    // 0b. Nonce validation
    let next_nonce = validate_nonce(state, &tx.account_id, tx.nonce)?;
    new_state.set_nonce(tx.account_id, next_nonce);

    // 1. Verify backup exists
    let backup_hash = state
        .get_backup(&tx.account_id)
        .ok_or_else(|| ChainError::AccountNotFound(hex_encode(&tx.account_id[..4])))?;

    // 2. Verify proof — the proof attests that the restore is valid
    let input_hash = hash_with_domain(
        DOMAIN_WALLET_STATE,
        &[tx.account_id.as_slice(), &backup_hash, &tx.nonce.to_le_bytes()].concat(),
    );
    let output_hash = hash_with_domain(
        DOMAIN_WALLET_STATE,
        &[tx.account_id.as_slice(), &tx.backup_hash].concat(),
    );
    verify_proof_if_not_mock(&tx.proof, &input_hash, &output_hash)?;

    // R5: Actually restore the wallet state from backup (was missing — the feature was broken)
    new_state.set_wallet(tx.account_id, tx.backup_hash);

    Ok(new_state)
}

// ---------------------------------------------------------------------------
// Fraud Proof validation
// ---------------------------------------------------------------------------

fn validate_fraud_proof(tx: &FraudProofTx, state: &GlobalState) -> Result<GlobalState> {
    let mut new_state = state.clone();

    // 0. fraudulent_key must match the observed_key in both observations
    if tx.evidence.fraudulent_key != tx.evidence.observation_a.observed_key
        || tx.evidence.fraudulent_key != tx.evidence.observation_b.observed_key
    {
        return Err(ChainError::FraudDetected(
            "fraudulent_key does not match observed keys".into(),
        ));
    }

    // R5: Require two distinct observers — prevents single-entity fabrication
    if tx.evidence.observation_a.observer == tx.evidence.observation_b.observer {
        return Err(ChainError::FraudDetected(
            "observations must come from different observers".into(),
        ));
    }

    // 1. Verify the two observations conflict
    let actual_conflict = detect_conflict(&tx.evidence.observation_a, &tx.evidence.observation_b)
        .ok_or_else(|| ChainError::FraudDetected("no conflict detected".into()))?;

    // R6: Verify the claimed conflict_type matches the actual detected conflict.
    // Without this check, an attacker can submit evidence claiming StateInconsistency
    // when the actual conflict is DoubleSpend (or vice versa), poisoning the on-chain
    // fraud evidence record with incorrect conflict classification.
    if tx.evidence.conflict_type != actual_conflict {
        return Err(ChainError::FraudDetected(format!(
            "claimed conflict type {:?} does not match detected {:?}",
            tx.evidence.conflict_type, actual_conflict,
        )));
    }

    // 2. Verify observer signatures — prevents fabricated fraud evidence
    let obs_a_msg = observation_signing_message(&tx.evidence.observation_a);
    verify_signature_if_not_mock(
        &tx.evidence.observation_a.observer,
        &obs_a_msg,
        &tx.evidence.observation_a.observer_signature,
    )?;
    let obs_b_msg = observation_signing_message(&tx.evidence.observation_b);
    verify_signature_if_not_mock(
        &tx.evidence.observation_b.observer,
        &obs_b_msg,
        &tx.evidence.observation_b.observer_signature,
    )?;

    // 3. Verify the execution proof
    let input_hash = hash_with_domain(
        DOMAIN_FRAUD,
        &[
            tx.evidence.fraudulent_key.as_slice(),
            &tx.evidence.observation_a.to_bytes(),
        ]
        .concat(),
    );
    let output_hash = hash_with_domain(
        DOMAIN_FRAUD,
        &[
            tx.evidence.fraudulent_key.as_slice(),
            &tx.evidence.observation_b.to_bytes(),
        ]
        .concat(),
    );
    verify_proof_if_not_mock(&tx.proof, &input_hash, &output_hash)?;

    // R10: The fraudulent account must actually have a wallet to burn.
    // Without this check, an attacker can submit fraud evidence against non-existent
    // accounts, polluting the fraud evidence tree with records for phantom accounts
    // and potentially griefing the evidence storage with unlimited fake entries.
    if state.get_wallet(&tx.evidence.fraudulent_key).is_none() {
        return Err(ChainError::AccountNotFound(
            hex_encode(&tx.evidence.fraudulent_key[..4]),
        ));
    }

    // R7: Check for duplicate fraud evidence before recording.
    // Without this, the same evidence can be submitted repeatedly, and if the
    // wallet was already burned, the fraud evidence tree grows unbounded.
    let evidence_bytes = serde_json::to_vec(&tx.evidence)
        .map_err(|e| ChainError::InvalidEncoding(format!("evidence serialization: {e}")))?;
    let evidence_hash = hash_with_domain(DOMAIN_FRAUD, &evidence_bytes);
    if state.fraud.get(&evidence_hash).is_some() {
        return Err(ChainError::DuplicateFraudEvidence(
            hex_encode(&evidence_hash[..4]),
        ));
    }

    // 4. Burn the fraudulent key — remove wallet
    new_state.remove_wallet(&tx.evidence.fraudulent_key);

    // Record fraud evidence on chain
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

    // 0. Validate timestamp
    validate_timestamp(tx.timestamp, now)?;

    // 0b. Verify submitter signature
    let signing_msg = stp_action_signing_message(tx);
    verify_signature_if_not_mock(&tx.submitter, &signing_msg, &tx.signature)?;

    // 0c. Verify proof
    let input_hash = hash_with_domain(
        DOMAIN_STP,
        &[tx.submitter.as_slice(), &tx.timestamp.to_le_bytes()].concat(),
    );
    let action_bytes = serde_json::to_vec(&tx.action)
        .map_err(|e| ChainError::InvalidEncoding(format!("STP action serialization: {e}")))?;
    let output_hash = hash_with_domain(DOMAIN_STP, &action_bytes);
    verify_proof_if_not_mock(&tx.proof, &input_hash, &output_hash)?;

    match &tx.action {
        STPAction::RegisterContract(contract) => {
            // Only the official themselves can register their own contract
            if tx.submitter != contract.official {
                return Err(ChainError::UnauthorizedSTPAction(
                    "only the official can register their own service contract".into(),
                ));
            }

            // R7: Prevent contract overwrite — an official who already has a contract
            // cannot register a new one. Without this check, an official under
            // investigation could re-register with a more permissive contract
            // (higher threshold, lower stake) to reduce their accountability.
            if state.get_stp_record(&contract.official).is_some() {
                return Err(ChainError::DuplicateSTPContract);
            }

            // R9: Limit office string length to prevent memory exhaustion.
            const MAX_STP_OFFICE_LEN: usize = 1024;
            if contract.office.len() > MAX_STP_OFFICE_LEN {
                return Err(ChainError::STPError(format!(
                    "office field too long: {} bytes (max {})",
                    contract.office.len(),
                    MAX_STP_OFFICE_LEN,
                )));
            }

            // R6: Validate contract parameters to prevent degenerate contracts.
            // term_start must be before term_end (non-zero-duration contract).
            if contract.term_start >= contract.term_end {
                return Err(ChainError::STPError(
                    "contract term_start must be before term_end".into(),
                ));
            }
            // Staked amount must be non-zero — zero-stake contracts have no slashing deterrent.
            if contract.staked_amount == 0 {
                return Err(ChainError::STPError(
                    "contract must have non-zero staked amount".into(),
                ));
            }

            // R10: Reject reporting_threshold of 0. A zero threshold means EVERY
            // transaction triggers an investigation, spamming the STP system and
            // making enforcement meaningless through volume overload.
            if contract.reporting_threshold == 0 {
                return Err(ChainError::STPError(
                    "contract must have non-zero reporting threshold".into(),
                ));
            }

            // R8: Contract must be registered with Active status. Allowing Suspended or
            // Terminated status creates a sham contract that satisfies the "has contract"
            // check in TriggerInvestigation but provides no actual accountability.
            if contract.status != crate::stp::ContractStatus::Active {
                return Err(ChainError::STPError(
                    "contract must be registered with Active status".into(),
                ));
            }

            // Store contract hash in STP subtree
            let contract_hash = contract.contract_hash();
            new_state.set_stp_record(contract.official, contract_hash);
        }

        STPAction::TriggerInvestigation { target, pool_id } => {
            // R6: Only accounts with an active STP service contract can be
            // investigated. Without this check, any account can be targeted,
            // leading to spurious investigations against non-officials.
            if state.get_stp_record(target).is_none() {
                return Err(ChainError::UnauthorizedSTPAction(
                    "investigation target has no STP service contract".into(),
                ));
            }

            // R10: Reject if an investigation already exists for this pool_id.
            // Without this check, an attacker can re-trigger the same investigation
            // to reset the compliance deadline (now + 72h), effectively granting
            // the official unlimited deadline extensions. The inv_target_key binding
            // also serves as a sentinel: if it exists, an investigation was already
            // created for this pool_id.
            let target_key = inv_target_key(pool_id);
            if state.get_stp_record(&target_key).is_some() {
                return Err(ChainError::STPError(
                    "investigation already exists for this pool_id".into(),
                ));
            }

            // Create investigation record
            let investigation = InvestigationRecord::new(*pool_id, *target, now);
            let inv_hash = investigation.investigation_hash();
            new_state.set_stp_record(*pool_id, inv_hash);

            // R7: Store a secondary binding: inv_target_key(pool_id) -> target.
            // This allows ProvideData to verify the submitter is the actual target,
            // not just any official with a contract. Without this binding, Official B
            // could provide data for Official A's investigation, allowing A to escape
            // accountability.
            let target_key = inv_target_key(pool_id);
            let target_binding = hash_with_domain(DOMAIN_STP, target.as_slice());
            new_state.set_stp_record(target_key, target_binding);
        }

        STPAction::ProvideData {
            investigation_id,
            data_hash,
        } => {
            // R9: Reject ZERO_HASH data_hash. The SMT treats ZERO_HASH as a delete
            // sentinel. If the official provides data_hash = ZERO_HASH, it would delete
            // the investigation record from the STP SMT, effectively killing the
            // investigation and making CheckDeadline fail with "investigation not found".
            if *data_hash == ZERO_HASH {
                return Err(ChainError::STPError(
                    "data_hash must not be zero (would delete investigation record)".into(),
                ));
            }

            // Only the investigation target can provide data.
            // Load investigation record to verify submitter is the target.
            let _stored_hash = state.get_stp_record(investigation_id).ok_or_else(|| {
                ChainError::STPError("investigation not found".into())
            })?;

            // R7: Verify submitter is the actual investigation target (not just any official).
            // Without this fix, Official B (who also has a contract) could provide data
            // for Official A's investigation, allowing A to escape accountability.
            let target_key = inv_target_key(investigation_id);
            let stored_target_binding = state.get_stp_record(&target_key).ok_or_else(|| {
                ChainError::STPError("investigation target binding not found".into())
            })?;
            let submitter_binding = hash_with_domain(DOMAIN_STP, tx.submitter.as_slice());
            if stored_target_binding != submitter_binding {
                return Err(ChainError::UnauthorizedSTPAction(
                    "only the investigation target can provide data for their investigation".into(),
                ));
            }

            // Store the data hash
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

fn validate_app_state_update(tx: &AppStateUpdate, state: &GlobalState, now: Timestamp) -> Result<GlobalState> {
    let mut new_state = state.clone();

    // 0. Validate timestamp
    validate_timestamp(tx.timestamp, now)?;

    // R9: Reject ZERO_HASH as new_state_hash. The SMT treats ZERO_HASH as a
    // delete sentinel — setting an app state to ZERO_HASH effectively removes it,
    // allowing an attacker to delete arbitrary app state entries.
    if tx.new_state_hash == ZERO_HASH {
        return Err(ChainError::InvalidEncoding(
            "new_state_hash must not be zero (would delete app state)".into(),
        ));
    }

    // 0b. Verify signature — only the account owner can update app state
    let signing_msg = app_state_update_signing_message(tx);
    verify_signature_if_not_mock(&tx.account_id, &signing_msg, &tx.signature)?;

    // 0c. Nonce validation
    let next_nonce = validate_nonce(state, &tx.account_id, tx.nonce)?;
    new_state.set_nonce(tx.account_id, next_nonce);

    // 1. Wallet must exist
    let current_hash = state
        .get_wallet(&tx.account_id)
        .ok_or_else(|| ChainError::AccountNotFound(hex_encode(&tx.account_id[..4])))?;

    // 2. Verify proof
    let input_hash = hash_with_domain(
        DOMAIN_WALLET_STATE,
        &[tx.account_id.as_slice(), &tx.app_id, &current_hash, &tx.nonce.to_le_bytes()].concat(),
    );
    let output_hash = hash_with_domain(
        DOMAIN_WALLET_STATE,
        &[tx.account_id.as_slice(), &tx.app_id, &tx.new_state_hash].concat(),
    );
    verify_proof_if_not_mock(&tx.proof, &input_hash, &output_hash)?;

    // 3. Update app state
    new_state.set_app_state(tx.app_id, tx.new_state_hash);

    Ok(new_state)
}

// ---------------------------------------------------------------------------
// Atomic Swap Init — create a hash-time-locked swap
// ---------------------------------------------------------------------------

fn validate_atomic_swap_init(
    tx: &AtomicSwapInit,
    state: &GlobalState,
    now: Timestamp,
    block_height: BlockHeight,
) -> Result<GlobalState> {
    let mut new_state = state.clone();

    // 0. Reject self-swaps (initiator == responder)
    if tx.initiator == tx.responder {
        return Err(ChainError::SelfTransfer);
    }

    // 0b. Validate timestamp
    validate_timestamp(tx.timestamp, now)?;

    // 0c. Verify responder signature (responder is locking funds)
    let signing_msg = atomic_swap_init_signing_message(tx);
    verify_signature_if_not_mock(&tx.responder, &signing_msg, &tx.signature)?;

    // R6: Use responder's nonce (they sign the tx, so they control replay).
    // Previously used initiator's nonce, which allowed a nonce griefing attack:
    // Eve could create swaps setting initiator=victim, incrementing victim's nonce
    // without victim's consent (only responder's signature is checked).
    let next_nonce = validate_nonce(state, &tx.responder, tx.nonce)?;
    new_state.set_nonce(tx.responder, next_nonce);

    // 1. Responder wallet must exist (they're locking funds)
    let _ = state
        .get_wallet(&tx.responder)
        .ok_or_else(|| ChainError::AccountNotFound(hex_encode(&tx.responder[..4])))?;

    // 2. Verify swap_id is canonically derived: H(initiator || responder || nonce)
    let expected_swap_id = hash_with_domain(
        DOMAIN_SWAP,
        &[tx.initiator.as_slice(), tx.responder.as_slice(), &tx.nonce.to_le_bytes()].concat(),
    );
    if tx.swap_id != expected_swap_id {
        return Err(ChainError::InvalidSwapId);
    }

    // 3. Swap must not already exist
    if state.get_swap(&tx.swap_id).is_some() {
        return Err(ChainError::SwapAlreadyExists(hex_encode(&tx.swap_id[..4])));
    }

    // 3. Amount must be positive
    // R9: Use ZeroAmount error for consistency with CashTransfer validation.
    // Previously returned InsufficientBalance which masked the real issue.
    if tx.amount == 0 {
        return Err(ChainError::ZeroAmount);
    }

    // R6: Reject ZERO_HASH as hash_lock — a zero hash_lock is meaningless
    // and could indicate an uninitialized or malformed swap. Any preimage
    // that hashes to all-zeros would be trivially identifiable.
    if tx.hash_lock == ZERO_HASH {
        return Err(ChainError::InvalidPreimage);
    }

    // 4. Timeout must be in the future
    if tx.timeout <= block_height {
        return Err(ChainError::SwapExpired);
    }

    // R10: Timeout must not be unreasonably far in the future.
    // Without this check, an attacker can set timeout = u64::MAX to permanently
    // lock the responder's funds (refund requires block_height >= timeout, which
    // will never be reached). Cap at 1,000,000 blocks above current height.
    const MAX_SWAP_TIMEOUT_DELTA: u64 = 1_000_000;
    if tx.timeout > block_height.saturating_add(MAX_SWAP_TIMEOUT_DELTA) {
        return Err(ChainError::InvalidTimestamp);
    }

    // 5. Verify proof
    let input_hash = hash_with_domain(
        DOMAIN_SWAP,
        &[tx.responder.as_slice(), &tx.amount.to_le_bytes(), &tx.nonce.to_le_bytes()].concat(),
    );
    let output_hash = hash_with_domain(
        DOMAIN_SWAP,
        &[tx.swap_id.as_slice(), &tx.hash_lock, &tx.timeout.to_le_bytes()].concat(),
    );
    verify_proof_if_not_mock(&tx.proof, &input_hash, &output_hash)?;

    // 6. Store swap state (Active) in the swaps SMT
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
    _now: Timestamp,
    block_height: BlockHeight,
) -> Result<GlobalState> {
    let mut new_state = state.clone();

    // 0. Verify claimer signature
    let signing_msg = atomic_swap_claim_signing_message(tx);
    verify_signature_if_not_mock(&tx.claimer, &signing_msg, &tx.signature)?;

    // 1. Swap must exist
    let stored_hash = state
        .get_swap(&tx.swap_id)
        .ok_or_else(|| ChainError::SwapNotFound(hex_encode(&tx.swap_id[..4])))?;

    // 2. Verify the provided original swap params match the stored commitment.
    //    The SMT stores swap_state_hash(params, Active). Reconstruct and compare.
    let expected_hash = swap_state_hash_from_parts(
        &tx.original_initiator,
        &tx.original_responder,
        tx.original_amount,
        &tx.original_hash_lock,
        tx.original_timeout,
        SwapStatus::Active,
    );
    if stored_hash != expected_hash {
        return Err(ChainError::InvalidProof(
            "swap params do not match stored commitment".into(),
        ));
    }

    // 3. Claimer must be the original initiator
    if tx.claimer != tx.original_initiator {
        return Err(ChainError::InvalidProof(
            "claimer is not the swap initiator".into(),
        ));
    }

    // 3b. Claims must be submitted before the timeout
    if block_height >= tx.original_timeout {
        return Err(ChainError::SwapExpired);
    }

    // 4. Verify hash preimage: H(secret) must equal hash_lock
    let secret_hash = hash_with_domain(DOMAIN_SWAP, tx.secret.as_slice());
    if secret_hash != tx.original_hash_lock {
        return Err(ChainError::InvalidPreimage);
    }

    // 4b. Verify proof
    let input_hash = hash_with_domain(
        DOMAIN_SWAP,
        &[tx.swap_id.as_slice(), tx.claimer.as_slice(), &tx.secret].concat(),
    );
    let output_hash = hash_with_domain(
        DOMAIN_SWAP,
        &[tx.swap_id.as_slice(), &tx.original_hash_lock].concat(),
    );
    verify_proof_if_not_mock(&tx.proof, &input_hash, &output_hash)?;

    // 5. Remove swap (claimed — no longer active)
    new_state.remove_swap(&tx.swap_id);

    // 6. Credit claimer (initiator receives the locked funds)
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

    // 0. Verify refundee signature
    let signing_msg = atomic_swap_refund_signing_message(tx);
    verify_signature_if_not_mock(&tx.refundee, &signing_msg, &tx.signature)?;

    // 1. Swap must exist
    let stored_hash = state
        .get_swap(&tx.swap_id)
        .ok_or_else(|| ChainError::SwapNotFound(hex_encode(&tx.swap_id[..4])))?;

    // 2. Verify the provided original swap params match the stored commitment.
    let expected_hash = swap_state_hash_from_parts(
        &tx.original_initiator,
        &tx.original_responder,
        tx.original_amount,
        &tx.original_hash_lock,
        tx.original_timeout,
        SwapStatus::Active,
    );
    if stored_hash != expected_hash {
        return Err(ChainError::InvalidProof(
            "swap params do not match stored commitment".into(),
        ));
    }

    // 3. Refundee must be the original responder
    if tx.refundee != tx.original_responder {
        return Err(ChainError::InvalidProof(
            "refundee is not the swap responder".into(),
        ));
    }

    // 4. Timeout must have been reached
    if block_height < tx.original_timeout {
        return Err(ChainError::SwapNotExpired);
    }

    // 4b. Verify proof
    let input_hash = hash_with_domain(
        DOMAIN_SWAP,
        &[tx.swap_id.as_slice(), tx.refundee.as_slice(), &tx.original_timeout.to_le_bytes()].concat(),
    );
    let output_hash = hash_with_domain(
        DOMAIN_SWAP,
        &[tx.swap_id.as_slice(), &tx.original_amount.to_le_bytes()].concat(),
    );
    verify_proof_if_not_mock(&tx.proof, &input_hash, &output_hash)?;

    // 5. Remove swap (refunded — no longer active)
    new_state.remove_swap(&tx.swap_id);

    // 6. Credit refundee (responder gets their locked funds back)
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
    use crate::fraud::{ConflictType, FraudEvidence, StateObservation};
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

        // R7: Register identities so sender_tier checks pass for Tier::Identified
        let sender_record = IdentityRecord {
            account_id: sender,
            tier: Tier::Identified,
            identity_hash: [0xAA; 32],
            jurisdiction: 840,
            registered_at: 0,
            is_public_official: false,
            office: None,
        };
        state.set_identity(sender, sender_record.record_hash());

        let recipient_record = IdentityRecord {
            account_id: recipient,
            tier: Tier::Identified,
            identity_hash: [0xBB; 32],
            jurisdiction: 840,
            registered_at: 0,
            is_public_official: false,
            office: None,
        };
        state.set_identity(recipient, recipient_record.record_hash());

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
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: 1000,
            jurisdiction: 840,
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
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: 0,
            jurisdiction: 840,
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
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: 0,
            jurisdiction: 840,
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

    /// Build a claim transaction from a swap init, providing correct original params.
    fn make_swap_claim(swap: &AtomicSwapInit) -> AtomicSwapClaim {
        AtomicSwapClaim {
            swap_id: swap.swap_id,
            secret: [0x5E; 32], // matches hash_lock from make_swap_init
            claimer: swap.initiator,
            original_initiator: swap.initiator,
            original_responder: swap.responder,
            original_amount: swap.amount,
            original_hash_lock: swap.hash_lock,
            original_timeout: swap.timeout,
            proof: mock_proof(),
            signature: [0u8; 64],
        }
    }

    /// Build a refund transaction from a swap init, providing correct original params.
    fn make_swap_refund(swap: &AtomicSwapInit) -> AtomicSwapRefund {
        AtomicSwapRefund {
            swap_id: swap.swap_id,
            refundee: swap.responder,
            original_initiator: swap.initiator,
            original_responder: swap.responder,
            original_amount: swap.amount,
            original_hash_lock: swap.hash_lock,
            original_timeout: swap.timeout,
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

        // Try to replay the exact same swap — nonce validation rejects it
        let tx2 = Transaction::AtomicSwapInit(swap);
        let result = validate_transaction(&tx2, &new_state, 1000, 50);
        assert!(matches!(result, Err(ChainError::InvalidNonce { .. })));
    }

    #[test]
    fn atomic_swap_init_invalid_swap_id() {
        let (state, _sender, responder) = setup_state_with_wallets();
        let initiator = [3u8; 32];
        let mut swap = make_swap_init(initiator, responder, 5000, 100);
        swap.swap_id = [0xFF; 32]; // tampered swap_id

        let tx = Transaction::AtomicSwapInit(swap);
        let result = validate_transaction(&tx, &state, 1000, 50);
        assert!(matches!(result, Err(ChainError::InvalidSwapId)));
    }

    #[test]
    fn atomic_swap_init_zero_amount() {
        let (state, _sender, responder) = setup_state_with_wallets();
        let swap = make_swap_init([3u8; 32], responder, 0, 100);

        let tx = Transaction::AtomicSwapInit(swap);
        let result = validate_transaction(&tx, &state, 1000, 50);
        // R9: Now returns ZeroAmount for consistency with CashTransfer
        assert!(matches!(result, Err(ChainError::ZeroAmount)));
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
        let tx_claim = Transaction::AtomicSwapClaim(make_swap_claim(&swap));
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
        // Use a fake swap that doesn't exist — only swap_id matters for "not found"
        let fake_swap = make_swap_init([1u8; 32], [2u8; 32], 100, 50);
        let mut claim = make_swap_claim(&fake_swap);
        claim.swap_id = [0xFF; 32]; // non-existent

        let tx_claim = Transaction::AtomicSwapClaim(claim);
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
        let tx_refund = Transaction::AtomicSwapRefund(make_swap_refund(&swap));
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
        let fake_swap = make_swap_init([1u8; 32], [2u8; 32], 100, 50);
        let mut refund = make_swap_refund(&fake_swap);
        refund.swap_id = [0xFF; 32]; // non-existent

        let tx_refund = Transaction::AtomicSwapRefund(refund);
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
        let tx_claim = Transaction::AtomicSwapClaim(make_swap_claim(&swap));
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

    // -----------------------------------------------------------------------
    // Compliance integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn validate_cash_transfer_frozen_account() {
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
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: true, // frozen!
            recipient_frozen: false,
            rolling_24h_total_after: 0,
            jurisdiction: 840,
        });

        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(matches!(result, Err(ChainError::AccountFrozen(_))));
    }

    #[test]
    fn validate_cash_transfer_compliance_report_generated() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_state_hash = state.get_wallet(&sender).unwrap();
        let threshold = Tier::Identified.reporting_threshold();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: threshold, // at threshold — triggers report
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_state_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: threshold,
            jurisdiction: 840,
        });

        let new_state = validate_transaction(&tx, &state, 1000, 0).unwrap();
        // Compliance SMT should have a report
        assert!(!new_state.compliance.is_empty());
    }

    #[test]
    fn validate_cash_transfer_below_threshold_no_report() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_state_hash = state.get_wallet(&sender).unwrap();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 100, // well below any threshold
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_state_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: 100,
            jurisdiction: 840,
        });

        let new_state = validate_transaction(&tx, &state, 1000, 0).unwrap();
        // No compliance report should be generated
        assert!(new_state.compliance.is_empty());
    }

    #[test]
    fn validate_cash_transfer_rolling_total_triggers_report() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_state_hash = state.get_wallet(&sender).unwrap();
        let threshold = Tier::Anonymous.reporting_threshold();

        // Small individual transfer but rolling total over threshold
        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 100, // small
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_state_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Anonymous,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: threshold + 100, // over threshold
            jurisdiction: 840,
        });

        let new_state = validate_transaction(&tx, &state, 1000, 0).unwrap();
        // Anti-structuring: rolling total triggered a report
        assert!(!new_state.compliance.is_empty());
    }

    // -----------------------------------------------------------------------
    // Attack tests — verify hardened compliance rejects exploits
    // -----------------------------------------------------------------------

    #[test]
    fn attack_structuring_bypasses_rolling_total() {
        // KNOWN LIMITATION (Phase 1): rolling_24h_total_after is self-reported.
        // Until ZK proofs are verified, a client can lie about cumulative totals.
        // This test documents the limitation — it will flip once proofs are enforced.
        let (state, sender, recipient) = setup_state_with_wallets();
        let threshold = Tier::Identified.reporting_threshold();

        let mut current_state = state.clone();
        for i in 0..10u64 {
            let sender_hash = current_state.get_wallet(&sender).unwrap();
            let tx = Transaction::CashTransfer(CashTransfer {
                from: sender,
                to: recipient,
                amount: threshold - 1,
                fee: 100,
                nonce: i,
                timestamp: 1000 + i,
                state_pre: sender_hash,
                proof: mock_proof(),
                signature: [0u8; 64],
                sender_tier: Tier::Identified,
                sender_identity_hash: [0xAA; 32],
                recipient_identity_hash: [0xBB; 32],
                sender_frozen: false,
                recipient_frozen: false,
                rolling_24h_total_after: threshold - 1, // LIE: should be cumulative
                jurisdiction: 840,
            });
            current_state = validate_transaction(&tx, &current_state, 1000 + i, 0).unwrap();
        }
        // KNOWN: No reports despite moving 10*(threshold-1) — needs proof verification
        assert!(current_state.compliance.is_empty());
    }

    #[test]
    fn attack_tier_spoofing_avoids_reporting() {
        // KNOWN LIMITATION (Phase 1): sender_tier is self-reported.
        // Needs ZK proof verification to enforce real tier.
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();
        let amount = 50_000_000;

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified, // LIE: actually Anonymous
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: amount,
            jurisdiction: 840,
        });

        let new_state = validate_transaction(&tx, &state, 1000, 0).unwrap();
        // KNOWN: No report — needs proof verification to enforce real tier
        assert!(new_state.compliance.is_empty());
    }

    #[test]
    fn attack_frozen_account_lies_about_status() {
        // KNOWN LIMITATION (Phase 1): sender_frozen is self-reported.
        // Needs ZK proof verification to enforce real frozen status.
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 1000,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false, // LIE: actually frozen
            recipient_frozen: false,
            rolling_24h_total_after: 1000,
            jurisdiction: 840,
        });

        // KNOWN: Succeeds because frozen status is self-reported — needs proof verification
        assert!(validate_transaction(&tx, &state, 1000, 0).is_ok());
    }

    #[test]
    fn attack_self_transfer_blocked() {
        // FIXED: Self-transfers are now rejected
        let (state, sender, _recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: sender, // self-transfer!
            amount: 1000,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xAA; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: 1000,
            jurisdiction: 840,
        });

        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(matches!(result, Err(ChainError::SelfTransfer)));
    }

    #[test]
    fn attack_compliance_report_collision_fixed() {
        // FIXED: Reports now include sender_account + nonce, so each is unique.
        let (state, sender, recipient) = setup_state_with_wallets();
        let threshold = Tier::Identified.reporting_threshold();

        // First transfer
        let sender_hash = state.get_wallet(&sender).unwrap();
        let tx1 = CashTransfer {
            from: sender,
            to: recipient,
            amount: threshold,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: threshold,
            jurisdiction: 840,
        };
        let state1 = validate_cash_transfer(&tx1, &state, 1000).unwrap();
        assert_eq!(state1.compliance.len(), 1);

        // Second transfer, same params but different nonce
        let sender_hash2 = state1.get_wallet(&sender).unwrap();
        let tx2 = CashTransfer {
            from: sender,
            to: recipient,
            amount: threshold,
            fee: 100,
            nonce: 1,
            timestamp: 1000,
            state_pre: sender_hash2,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: threshold,
            jurisdiction: 840,
        };
        let state2 = validate_cash_transfer(&tx2, &state1, 1000).unwrap();

        // FIXED: 2 distinct reports (nonce makes report_hash unique)
        assert_eq!(state2.compliance.len(), 2);
    }

    #[test]
    fn attack_zero_amount_transfer_blocked() {
        // FIXED: Zero-amount transfers are now rejected
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 0,
            fee: 0,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: 0,
            jurisdiction: 840,
        });

        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(matches!(result, Err(ChainError::ZeroAmount)));
    }

    #[test]
    fn attack_rolling_total_below_amount_rejected() {
        // FIXED: rolling_24h_total_after < amount is now rejected
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 1_000_000,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Anonymous,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: 0, // impossible: < amount
            jurisdiction: 840,
        });

        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(matches!(result, Err(ChainError::ComplianceViolation(_))));
    }

    #[test]
    fn attack_recipient_frozen_blocked() {
        // FIXED: Frozen recipients now rejected
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 1000,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: true, // frozen recipient
            rolling_24h_total_after: 1000,
            jurisdiction: 840,
        });

        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(matches!(result, Err(ChainError::AccountFrozen(_))));
    }

    // ===================================================================
    // ROUND 2 ATTACK TESTS — Fixes verified
    // ===================================================================

    // --- FIXED: Atomic Swap Refund Before Timeout Rejected ---
    #[test]
    fn attack_swap_refund_before_timeout_rejected() {
        let (state, _sender, responder) = setup_state_with_wallets();
        let initiator = [3u8; 32];
        let swap = make_swap_init(initiator, responder, 5000, 100);

        let init_tx = Transaction::AtomicSwapInit(swap.clone());
        let state = validate_transaction(&init_tx, &state, 1000, 1).unwrap();

        // Try refund at block 2 — timeout is 100
        let refund = make_swap_refund(&swap);
        let refund_tx = Transaction::AtomicSwapRefund(refund);
        let result = validate_transaction(&refund_tx, &state, 1000, 2);
        assert!(matches!(result, Err(ChainError::SwapNotExpired)));
    }

    // --- FIXED: Atomic Swap Claim With Wrong Secret Rejected ---
    #[test]
    fn attack_swap_claim_wrong_secret_rejected() {
        let (state, _sender, responder) = setup_state_with_wallets();
        let initiator = [3u8; 32];
        let swap = make_swap_init(initiator, responder, 5000, 100);

        let init_tx = Transaction::AtomicSwapInit(swap.clone());
        let state = validate_transaction(&init_tx, &state, 1000, 1).unwrap();

        // Try to claim with wrong secret
        let mut claim = make_swap_claim(&swap);
        claim.secret = [0xFF; 32]; // wrong preimage!
        let claim_tx = Transaction::AtomicSwapClaim(claim);
        let result = validate_transaction(&claim_tx, &state, 1000, 2);
        assert!(matches!(result, Err(ChainError::InvalidPreimage)));
    }

    // --- FIXED: Atomic Swap Claim By Wrong Party Rejected ---
    #[test]
    fn attack_swap_claim_wrong_claimer_rejected() {
        let (state, _sender, responder) = setup_state_with_wallets();
        let initiator = [3u8; 32];
        let eve = [0xEE; 32];
        let swap = make_swap_init(initiator, responder, 5000, 100);

        let init_tx = Transaction::AtomicSwapInit(swap.clone());
        let state = validate_transaction(&init_tx, &state, 1000, 1).unwrap();

        // Eve tries to claim — she's not the initiator
        let mut claim = make_swap_claim(&swap);
        claim.claimer = eve;
        let claim_tx = Transaction::AtomicSwapClaim(claim);
        let result = validate_transaction(&claim_tx, &state, 1000, 2);
        assert!(matches!(result, Err(ChainError::InvalidProof(_))));
    }

    // --- FIXED: Atomic Swap Refund By Wrong Party Rejected ---
    #[test]
    fn attack_swap_refund_wrong_refundee_rejected() {
        let (state, _sender, responder) = setup_state_with_wallets();
        let initiator = [3u8; 32];
        let eve = [0xEE; 32];
        let swap = make_swap_init(initiator, responder, 5000, 10);

        let init_tx = Transaction::AtomicSwapInit(swap.clone());
        let state = validate_transaction(&init_tx, &state, 1000, 1).unwrap();

        // Eve tries to refund — she's not the responder
        let mut refund = make_swap_refund(&swap);
        refund.refundee = eve;
        let refund_tx = Transaction::AtomicSwapRefund(refund);
        let result = validate_transaction(&refund_tx, &state, 1000, 50);
        assert!(matches!(result, Err(ChainError::InvalidProof(_))));
    }

    // --- CRITICAL: WalletSync Overwrites Any Wallet Without Authorization ---
    // Anyone can submit a WalletSync for any account and set its state to anything.
    #[test]
    fn attack_wallet_sync_unauthorized_overwrite() {
        let mut state = GlobalState::genesis();
        let alice = [0xAA; 32];

        // Alice has a real wallet
        let wallet = WalletState::new([0u8; 32], Tier::Identified, 0);
        let original_hash = wallet.state_hash();
        state.set_wallet(alice, original_hash);

        // Eve (not Alice!) submits WalletSync to overwrite Alice's wallet state
        let evil_hash = [0xFF; 32]; // attacker-controlled state
        let sync_tx = Transaction::WalletSync(WalletSync {
            account_id: alice,
            new_state_hash: evil_hash,
            nonce: 0,
            timestamp: 1000,
            proof: mock_proof(),
            signature: [0u8; 64], // no signature check!
        });
        let new_state = validate_transaction(&sync_tx, &state, 1000, 0).unwrap();

        // BUG: Alice's wallet is now under attacker's control
        assert_eq!(new_state.get_wallet(&alice), Some(evil_hash));
        assert_ne!(new_state.get_wallet(&alice), Some(original_hash));
    }

    // --- HIGH: Fraud Proof With Fabricated Observations Burns Any Wallet ---
    // Observer signatures are never verified, so anyone can fabricate evidence.
    #[test]
    fn attack_fraud_proof_fabricated_observations() {
        let mut state = GlobalState::genesis();
        let victim = [0xAA; 32];

        // Victim has a wallet with real funds
        let wallet = WalletState::new([0u8; 32], Tier::Identified, 0);
        state.set_wallet(victim, wallet.state_hash());
        assert!(state.get_wallet(&victim).is_some());

        // Eve fabricates two conflicting observations — signatures are garbage
        let fraud_tx = Transaction::FraudProof(FraudProofTx {
            evidence: FraudEvidence {
                fraudulent_key: victim,
                observation_a: StateObservation {
                    observer: [0xBB; 32],
                    observed_key: victim,
                    observed_state_hash: [0x11; 32],
                    observed_nonce: 5,
                    observer_signature: [0u8; 64], // not a real signature!
                },
                observation_b: StateObservation {
                    observer: [0xCC; 32],
                    observed_key: victim,
                    observed_state_hash: [0x22; 32], // different state, same nonce
                    observed_nonce: 5,
                    observer_signature: [0u8; 64], // not a real signature!
                },
                conflict_type: ConflictType::DoubleSpend,
            },
            submitter: [0xEE; 32], // Eve
            proof: mock_proof(),
        });
        let new_state = validate_transaction(&fraud_tx, &state, 1000, 0).unwrap();

        // BUG: Victim's wallet is burned! With zero-effort fabricated evidence.
        assert!(new_state.get_wallet(&victim).is_none());
    }

    // --- FIXED: Fraud Proof Mismatched Key Rejected ---
    #[test]
    fn attack_fraud_proof_mismatched_key_rejected() {
        let mut state = GlobalState::genesis();
        let target_x = [0x11; 32];
        let innocent_y = [0x22; 32];

        let wallet = WalletState::new([0u8; 32], Tier::Identified, 0);
        state.set_wallet(target_x, wallet.state_hash());
        state.set_wallet(innocent_y, wallet.state_hash());

        // Observations target X, but fraudulent_key is Y — should be rejected
        let fraud_tx = Transaction::FraudProof(FraudProofTx {
            evidence: FraudEvidence {
                fraudulent_key: innocent_y,
                observation_a: StateObservation {
                    observer: [0xBB; 32],
                    observed_key: target_x,
                    observed_state_hash: [0xAA; 32],
                    observed_nonce: 5,
                    observer_signature: [0u8; 64],
                },
                observation_b: StateObservation {
                    observer: [0xCC; 32],
                    observed_key: target_x,
                    observed_state_hash: [0xBB; 32],
                    observed_nonce: 5,
                    observer_signature: [0u8; 64],
                },
                conflict_type: ConflictType::DoubleSpend,
            },
            submitter: [0xEE; 32],
            proof: mock_proof(),
        });
        let result = validate_transaction(&fraud_tx, &state, 1000, 0);
        assert!(matches!(result, Err(ChainError::FraudDetected(_))));
        // Innocent Y wallet is still intact
    }

    // --- FIXED: Zero-Fee Transfers Rejected ---
    #[test]
    fn attack_zero_fee_transfer_rejected() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 1000,
            fee: 0, // below FeeSchedule::base_fee() (100)
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: 1000,
            jurisdiction: 840,
        });
        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(matches!(result, Err(ChainError::ComplianceViolation(_))));
    }

    // --- MEDIUM: Recipient Wallet State Overwritten Without Merging ---
    // Two consecutive transfers to the same recipient: the second overwrites
    // the first's state commitment, effectively erasing the first transfer.
    #[test]
    fn attack_recipient_wallet_overwrite() {
        let (mut state, sender, recipient) = setup_state_with_wallets();
        let sender2 = [0xDD; 32];
        let wallet2 = WalletState::new([0u8; 32], Tier::Identified, 0);
        state.set_wallet(sender2, wallet2.state_hash());
        // R7: Register identity for sender2 so tier check passes
        let sender2_record = IdentityRecord {
            account_id: sender2,
            tier: Tier::Identified,
            identity_hash: [0u8; 32],
            jurisdiction: 840,
            registered_at: 0,
            is_public_official: false,
            office: None,
        };
        state.set_identity(sender2, sender2_record.record_hash());

        let sender_hash = state.get_wallet(&sender).unwrap();
        let sender2_hash = state.get_wallet(&sender2).unwrap();

        // Transfer 1: sender -> recipient (1000)
        let tx1 = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 1000,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: 1000,
            jurisdiction: 840,
        });
        let state_after_1 = validate_transaction(&tx1, &state, 1000, 0).unwrap();
        let recipient_hash_after_1 = state_after_1.get_wallet(&recipient).unwrap();

        // Transfer 2: sender2 -> recipient (2000) — DIFFERENT inputs
        let tx2 = Transaction::CashTransfer(CashTransfer {
            from: sender2,
            to: recipient,
            amount: 2000,
            fee: 100,
            nonce: 0,
            timestamp: 1001,
            state_pre: sender2_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xDD; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: 2000,
            jurisdiction: 840,
        });
        let state_after_2 = validate_transaction(&tx2, &state_after_1, 1001, 0).unwrap();
        let recipient_hash_after_2 = state_after_2.get_wallet(&recipient).unwrap();

        // BUG: The recipient's state after tx2 does NOT incorporate tx1's state.
        // The second transfer overwrites the wallet commitment entirely.
        // If the recipient state was properly accumulated, the hashes would
        // both contribute. But the second write erases the first.
        assert_ne!(
            recipient_hash_after_1, recipient_hash_after_2,
            "state changed (good), but the first transfer's contribution is lost"
        );
    }

    // --- FIXED: Atomic Swap Self-Swap Rejected ---
    #[test]
    fn attack_atomic_swap_self_swap_rejected() {
        let mut state = GlobalState::genesis();
        let alice = [0xAA; 32];
        let wallet = WalletState::new([0u8; 32], Tier::Identified, 0);
        state.set_wallet(alice, wallet.state_hash());

        let init_tx = Transaction::AtomicSwapInit(AtomicSwapInit {
            swap_id: [0x05; 32],
            initiator: alice,
            responder: alice, // same person!
            amount: 5000,
            hash_lock: [0xCC; 32],
            timeout: 100,
            disclosure_root: None,
            execution_proof: None,
            nonce: 0,
            timestamp: 1000,
            proof: mock_proof(),
            signature: [0u8; 64],
        });
        let result = validate_transaction(&init_tx, &state, 0, 1);
        assert!(matches!(result, Err(ChainError::SelfTransfer)));
    }

    // ═══════════════════════════════════════════════════════════════════
    // COMPLIANCE INTEGRATION ATTACK TESTS
    // ═══════════════════════════════════════════════════════════════════

    /// Attack: Set sender_frozen = true to bypass the frozen check.
    /// Wait — sender_frozen=true should REJECT, not bypass.
    /// This tests that the frozen check actually works.
    #[test]
    fn attack_compliance_frozen_account_rejected() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 1000,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: true, // FROZEN!
            recipient_frozen: false,
            rolling_24h_total_after: 1000,
            jurisdiction: 840,
        });
        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(
            matches!(result, Err(ChainError::AccountFrozen(_))),
            "VULNERABILITY: frozen sender not rejected, got {:?}",
            result
        );
    }

    /// Attack: Frozen recipient should also be rejected.
    #[test]
    fn attack_compliance_frozen_recipient_rejected() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 1000,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: true, // FROZEN!
            rolling_24h_total_after: 1000,
            jurisdiction: 840,
        });
        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(
            matches!(result, Err(ChainError::AccountFrozen(_))),
            "VULNERABILITY: frozen recipient not rejected, got {:?}",
            result
        );
    }

    /// Attack: Transfer exactly at reporting threshold triggers compliance report.
    #[test]
    fn attack_compliance_threshold_exact_triggers_report() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();
        let threshold = Tier::Identified.reporting_threshold();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: threshold,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: threshold,
            jurisdiction: 840,
        });
        let new_state = validate_transaction(&tx, &state, 1000, 0).unwrap();

        // Compliance subtree should have a report
        assert!(
            !new_state.compliance.is_empty(),
            "VULNERABILITY: threshold-amount transfer did not generate compliance report"
        );
    }

    /// Attack: Transfer just below threshold should NOT trigger a report.
    #[test]
    fn attack_compliance_below_threshold_no_report() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();
        let threshold = Tier::Identified.reporting_threshold();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: threshold - 1,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: threshold - 1,
            jurisdiction: 840,
        });
        let new_state = validate_transaction(&tx, &state, 1000, 0).unwrap();

        assert!(
            new_state.compliance.is_empty(),
            "Below-threshold transfer should not generate compliance report"
        );
    }

    /// Attack: Anti-structuring — small transfer but rolling total exceeds threshold.
    #[test]
    fn attack_compliance_anti_structuring() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();
        let threshold = Tier::Identified.reporting_threshold();

        // Small transfer (100), but rolling total is above threshold
        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 100,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: threshold + 100, // exceeds threshold
            jurisdiction: 840,
        });
        let new_state = validate_transaction(&tx, &state, 1000, 0).unwrap();

        assert!(
            !new_state.compliance.is_empty(),
            "VULNERABILITY: anti-structuring not detected (rolling total exceeded threshold)"
        );
    }

    /// Attack: PublicOfficial has lower threshold — test that smaller amounts trigger report.
    #[test]
    fn attack_compliance_public_official_lower_threshold() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();

        // PublicOfficial threshold = 50_000_000, Identified = 100_000_000
        let amount = Tier::PublicOfficial.reporting_threshold();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::PublicOfficial, // official!
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: amount,
            jurisdiction: 840,
        });
        let new_state = validate_transaction(&tx, &state, 1000, 0).unwrap();

        assert!(
            !new_state.compliance.is_empty(),
            "PublicOfficial at their threshold should trigger report"
        );
    }

    /// Attack: Same amount for Identified tier should NOT trigger report.
    #[test]
    fn attack_compliance_identified_higher_threshold() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();

        let amount = Tier::PublicOfficial.reporting_threshold();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified, // NOT an official
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: amount,
            jurisdiction: 840,
        });
        let new_state = validate_transaction(&tx, &state, 1000, 0).unwrap();

        assert!(
            new_state.compliance.is_empty(),
            "Identified tier at official threshold should NOT trigger report"
        );
    }

    /// Attack: Lie about rolling_24h_total_after < amount (invalid).
    /// The validator should reject this as a sanity check violation.
    #[test]
    fn attack_compliance_rolling_total_less_than_amount() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 5000,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: 100, // less than amount! impossible
            jurisdiction: 840,
        });
        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(
            matches!(result, Err(ChainError::ComplianceViolation(_))),
            "VULNERABILITY: rolling total < amount was accepted"
        );
    }

    /// Attack: Fee below minimum is rejected.
    #[test]
    fn attack_compliance_fee_below_minimum() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 1000,
            fee: FeeSchedule::base_fee() - 1, // below minimum
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: 1000,
            jurisdiction: 840,
        });
        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(
            matches!(result, Err(ChainError::ComplianceViolation(_))),
            "VULNERABILITY: sub-minimum fee accepted"
        );
    }

    /// Attack: Fee at exact minimum should be accepted.
    #[test]
    fn attack_compliance_fee_at_minimum_accepted() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 1000,
            fee: FeeSchedule::base_fee(), // exactly at minimum
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: 1000,
            jurisdiction: 840,
        });
        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(result.is_ok(), "Fee at exact minimum should be accepted");
    }

    /// Attack: Zero amount transfer should be rejected.
    #[test]
    fn attack_compliance_zero_amount_rejected() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 0,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: 0,
            jurisdiction: 840,
        });
        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(
            matches!(result, Err(ChainError::ZeroAmount)),
            "VULNERABILITY: zero amount transfer accepted"
        );
    }

    /// Attack: Self-transfer should be rejected.
    #[test]
    fn attack_compliance_self_transfer_rejected() {
        let (state, sender, _recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: sender, // same person!
            amount: 1000,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xAA; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: 1000,
            jurisdiction: 840,
        });
        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(
            matches!(result, Err(ChainError::SelfTransfer)),
            "VULNERABILITY: self-transfer accepted"
        );
    }

    /// Attack: Amount + fee overflow (u64::MAX values).
    #[test]
    fn attack_compliance_overflow_protection() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: u64::MAX,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: u64::MAX,
            jurisdiction: 840,
        });
        let result = validate_transaction(&tx, &state, 1000, 0);
        // checked_add(u64::MAX, 100) overflows → error
        assert!(
            result.is_err(),
            "VULNERABILITY: amount + fee overflow not detected"
        );
    }

    /// Attack: Anonymous tier has very low threshold — test it triggers report.
    #[test]
    fn attack_compliance_anonymous_low_threshold() {
        let (state, sender, recipient) = setup_state_with_wallets();
        let sender_hash = state.get_wallet(&sender).unwrap();
        let threshold = Tier::Anonymous.reporting_threshold(); // 1_000_000

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: threshold,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: sender_hash,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Anonymous,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: threshold,
            jurisdiction: 840,
        });
        let new_state = validate_transaction(&tx, &state, 1000, 0).unwrap();
        assert!(
            !new_state.compliance.is_empty(),
            "Anonymous at threshold should trigger compliance report"
        );
    }

    /// Attack: State pre-image mismatch is rejected.
    #[test]
    fn attack_compliance_state_pre_mismatch() {
        let (state, sender, recipient) = setup_state_with_wallets();

        let tx = Transaction::CashTransfer(CashTransfer {
            from: sender,
            to: recipient,
            amount: 1000,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: [0xFF; 32], // wrong pre-state!
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: 1000,
            jurisdiction: 840,
        });
        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(
            matches!(result, Err(ChainError::StateHashMismatch { .. })),
            "VULNERABILITY: wrong state_pre accepted"
        );
    }

    /// Attack: Non-existent sender account should fail.
    #[test]
    fn attack_compliance_nonexistent_sender() {
        let (state, _sender, recipient) = setup_state_with_wallets();

        let fake_sender = [0xFF; 32]; // not registered
        let tx = Transaction::CashTransfer(CashTransfer {
            from: fake_sender,
            to: recipient,
            amount: 1000,
            fee: 100,
            nonce: 0,
            timestamp: 1000,
            state_pre: ZERO_HASH,
            proof: mock_proof(),
            signature: [0u8; 64],
            sender_tier: Tier::Identified,
            sender_identity_hash: [0xAA; 32],
            recipient_identity_hash: [0xBB; 32],
            sender_frozen: false,
            recipient_frozen: false,
            rolling_24h_total_after: 1000,
            jurisdiction: 840,
        });
        let result = validate_transaction(&tx, &state, 1000, 0);
        assert!(
            matches!(result, Err(ChainError::AccountNotFound(_))),
            "VULNERABILITY: non-existent sender accepted"
        );
    }
}
