//! Round 30 — Backlog item 1/4: STP `CheckDeadline` enforcement.
//!
//! The R23 audit found `STPAction::CheckDeadline` was a no-op: it confirmed the
//! investigation existed and then did nothing, so a public official who
//! ignored a transparency-protocol investigation faced no consequence. The
//! whole STP accountability mechanism was non-enforcing.
//!
//! R30 makes it real:
//!  - `TriggerInvestigation` now stores the investigation's mutable state
//!    (trigger timestamp + status) under `pool_id`, and the raw target account
//!    under `inv_target_key`.
//!  - `CheckDeadline` reads that state, checks the 72h compliance and 30d
//!    final deadlines via `check_investigation_deadlines`, and applies the
//!    status transition: AwaitingData --(72h)--> AccountFrozen --(30d)-->
//!    Slashed. A cooperative official (data provided in time) is Cleared.
//!  - A freeze writes an on-chain marker; `validate_cash_transfer` rejects any
//!    transfer to/from a frozen account, so the freeze actually bites.
//!
//! These tests exercise the full state machine and the enforcement effect.

use poly_chain::error::ChainError;
use poly_chain::identity::{IdentityRecord, Tier};
use poly_chain::state::GlobalState;
use poly_chain::stp::{
    unpack_investigation_state, ContractStatus, InvestigationStatus, ServiceContract,
};
use poly_chain::transaction::{CashTransfer, STPAction, STPActionTx, Transaction};
use poly_chain::validation::validate_transaction;
use poly_chain::wallet::WalletState;
use poly_verified::types::{Hash, PrivacyMode, VerifiedProof, ZERO_HASH};

const TRIGGER_AT: u64 = 1_000;
/// 72 hours / 30 days in seconds — the STP compliance and final deadlines
/// (mirrors the private `poly_chain::stp::SECONDS_72H` / `SECONDS_30D`).
const SECONDS_72H: u64 = 259_200;
const SECONDS_30D: u64 = 2_592_000;

fn mock_proof() -> VerifiedProof {
    VerifiedProof::Mock {
        input_hash: ZERO_HASH,
        output_hash: ZERO_HASH,
        privacy_mode: PrivacyMode::Transparent,
    }
}

/// Genesis state with `official` set up as a public official: wallet, identity,
/// and an active STP service contract.
fn state_with_official(official: Hash) -> GlobalState {
    let mut state = GlobalState::genesis();
    let ihash: Hash = [0xDD; 32];
    state.set_wallet(
        official,
        WalletState::new(ihash, Tier::PublicOfficial, 1_000_000).state_hash(),
    );
    let id = IdentityRecord {
        account_id: official,
        tier: Tier::PublicOfficial,
        identity_hash: ihash,
        jurisdiction: 840,
        registered_at: 0,
        is_public_official: true,
        office: Some("Governor".into()),
    };
    state.set_identity(official, id.record_hash());

    let contract = ServiceContract {
        official,
        identity_hash: ihash,
        office: "Governor".into(),
        jurisdiction: 840,
        reporting_threshold: 50_000_000,
        staked_amount: 10_000_000,
        term_start: 0,
        term_end: 10_000_000,
        status: ContractStatus::Active,
    };
    let tx = Transaction::STPAction(STPActionTx {
        action: STPAction::RegisterContract(contract),
        submitter: official,
        timestamp: TRIGGER_AT,
        proof: mock_proof(),
        public_key: [0u8; 32],
        signature: [0u8; 64],
    });
    validate_transaction(&tx, &state, TRIGGER_AT, 0).unwrap()
}

fn stp_tx(action: STPAction, submitter: Hash, timestamp: u64) -> Transaction {
    Transaction::STPAction(STPActionTx {
        action,
        submitter,
        timestamp,
        proof: mock_proof(),
        public_key: [0u8; 32],
        signature: [0u8; 64],
    })
}

/// Trigger an investigation against `official` and return the new state.
fn trigger(state: &GlobalState, official: Hash, pool_id: Hash) -> GlobalState {
    let tx = stp_tx(
        STPAction::TriggerInvestigation { target: official, pool_id },
        [0xF0; 32],
        TRIGGER_AT,
    );
    validate_transaction(&tx, state, TRIGGER_AT, 0).unwrap()
}

fn investigation_status(state: &GlobalState, pool_id: &Hash) -> InvestigationStatus {
    let packed = state
        .get_stp_record(pool_id)
        .expect("investigation record must exist");
    unpack_investigation_state(&packed)
        .expect("investigation state must decode")
        .1
}

// ===========================================================================
// CheckDeadline — the freeze transition (72h)
// ===========================================================================

/// Before the 72h compliance deadline there is nothing to enforce — the
/// (no-longer-no-op) handler rejects the CheckDeadline.
#[test]
fn r30_check_deadline_before_deadline_rejected() {
    let official = [0x0F; 32];
    let state = state_with_official(official);
    let pool_id: Hash = [0x77; 32];
    let state = trigger(&state, official, pool_id);

    let now = TRIGGER_AT + SECONDS_72H - 1;
    let tx = stp_tx(STPAction::CheckDeadline { investigation_id: pool_id }, [0xA1; 32], now);
    let result = validate_transaction(&tx, &state, now, 0);
    assert!(
        matches!(result, Err(ChainError::STPError(_))),
        "before the deadline CheckDeadline must be rejected (no action due), got {:?}",
        result
    );
    assert_eq!(investigation_status(&state, &pool_id), InvestigationStatus::AwaitingData);
}

/// Past the 72h deadline with no data provided, CheckDeadline freezes the
/// official's account.
#[test]
fn r30_check_deadline_past_72h_freezes_account() {
    let official = [0x0F; 32];
    let state = state_with_official(official);
    let pool_id: Hash = [0x77; 32];
    let state = trigger(&state, official, pool_id);

    let now = TRIGGER_AT + SECONDS_72H;
    let tx = stp_tx(STPAction::CheckDeadline { investigation_id: pool_id }, [0xA1; 32], now);
    let state = validate_transaction(&tx, &state, now, 0)
        .expect("CheckDeadline past the deadline must succeed");

    match investigation_status(&state, &pool_id) {
        InvestigationStatus::AccountFrozen { frozen_at } => assert_eq!(frozen_at, now),
        other => panic!("expected AccountFrozen, got {:?}", other),
    }
}

/// A frozen official cannot move funds — `validate_cash_transfer` rejects a
/// transfer from a frozen account. This is the actual enforcement bite.
#[test]
fn r30_frozen_account_cannot_transfer() {
    let official = [0x0F; 32];
    let state = state_with_official(official);
    let pool_id: Hash = [0x77; 32];
    let state = trigger(&state, official, pool_id);

    // Freeze the official.
    let now = TRIGGER_AT + SECONDS_72H;
    let freeze_tx = stp_tx(STPAction::CheckDeadline { investigation_id: pool_id }, [0xA1; 32], now);
    let state = validate_transaction(&freeze_tx, &state, now, 0).unwrap();

    // The official tries to transfer funds out.
    let transfer = Transaction::CashTransfer(CashTransfer {
        from: official,
        to: [0xB0; 32],
        amount: 100,
        fee: 100,
        nonce: 0,
        timestamp: now,
        state_pre: state.get_wallet(&official).unwrap(),
        proof: mock_proof(),
        public_key: [0u8; 32],
        signature: [0u8; 64],
        sender_tier: Tier::PublicOfficial,
        sender_identity_hash: [0xDD; 32],
        recipient_identity_hash: ZERO_HASH,
        sender_frozen: false,      // the official lies — claims not frozen
        recipient_frozen: false,
        rolling_24h_total_after: 100,
        jurisdiction: 840,
    });
    let result = validate_transaction(&transfer, &state, now, 0);
    assert!(
        matches!(result, Err(ChainError::AccountFrozen(_))),
        "a transfer from an STP-frozen account must be rejected even when the tx \
         self-attests sender_frozen=false, got {:?}",
        result
    );
}

// ===========================================================================
// CheckDeadline — the slash transition (30d) and the cooperative path
// ===========================================================================

/// After a freeze, CheckDeadline past the 30d final deadline slashes.
#[test]
fn r30_check_deadline_past_30d_slashes() {
    let official = [0x0F; 32];
    let state = state_with_official(official);
    let pool_id: Hash = [0x77; 32];
    let state = trigger(&state, official, pool_id);

    // First: freeze at 72h.
    let freeze_now = TRIGGER_AT + SECONDS_72H;
    let freeze_tx =
        stp_tx(STPAction::CheckDeadline { investigation_id: pool_id }, [0xA1; 32], freeze_now);
    let state = validate_transaction(&freeze_tx, &state, freeze_now, 0).unwrap();

    // Then: slash at the 30d final deadline.
    let slash_now = TRIGGER_AT + SECONDS_72H + SECONDS_30D;
    let slash_tx =
        stp_tx(STPAction::CheckDeadline { investigation_id: pool_id }, [0xA2; 32], slash_now);
    let state = validate_transaction(&slash_tx, &state, slash_now, 0)
        .expect("CheckDeadline past the final deadline must slash");

    match investigation_status(&state, &pool_id) {
        InvestigationStatus::Slashed { slashed_at } => assert_eq!(slashed_at, slash_now),
        other => panic!("expected Slashed, got {:?}", other),
    }
}

/// Slashing cannot be skipped: CheckDeadline cannot slash an investigation that
/// was never frozen (status is still AwaitingData past the final deadline →
/// FreezeAccount, not ExecuteSlash).
#[test]
fn r30_slash_requires_prior_freeze() {
    let official = [0x0F; 32];
    let state = state_with_official(official);
    let pool_id: Hash = [0x77; 32];
    let state = trigger(&state, official, pool_id);

    // Jump straight past the 30d mark without a prior freeze CheckDeadline.
    let now = TRIGGER_AT + SECONDS_72H + SECONDS_30D;
    let tx = stp_tx(STPAction::CheckDeadline { investigation_id: pool_id }, [0xA1; 32], now);
    let state = validate_transaction(&tx, &state, now, 0).unwrap();
    // It freezes (the first transition) — it does NOT skip straight to Slashed.
    assert!(
        matches!(investigation_status(&state, &pool_id), InvestigationStatus::AccountFrozen { .. }),
        "the first CheckDeadline must freeze, never skip to Slashed"
    );
}

/// If the official provides data while still AwaitingData, CheckDeadline marks
/// the investigation Cleared and does not freeze.
#[test]
fn r30_cooperative_official_is_cleared_not_frozen() {
    let official = [0x0F; 32];
    let state = state_with_official(official);
    let pool_id: Hash = [0x77; 32];
    let state = trigger(&state, official, pool_id);

    // The official provides the requested data, in time.
    let provide = stp_tx(
        STPAction::ProvideData { investigation_id: pool_id, data_hash: [0xAB; 32] },
        official,
        TRIGGER_AT + 10,
    );
    let state = validate_transaction(&provide, &state, TRIGGER_AT + 10, 0)
        .expect("the target providing data must succeed");

    // CheckDeadline past 72h — but data was provided, so it clears, not freezes.
    let now = TRIGGER_AT + SECONDS_72H + 5;
    let check = stp_tx(STPAction::CheckDeadline { investigation_id: pool_id }, [0xA1; 32], now);
    let state = validate_transaction(&check, &state, now, 0)
        .expect("CheckDeadline after data provided must succeed");
    assert_eq!(
        investigation_status(&state, &pool_id),
        InvestigationStatus::Cleared,
        "a cooperative official's investigation must be Cleared, not frozen"
    );
}

// ===========================================================================
// Regressions
// ===========================================================================

/// CheckDeadline on a non-existent investigation is still rejected.
#[test]
fn r30_check_deadline_unknown_investigation_rejected() {
    let official = [0x0F; 32];
    let state = state_with_official(official);
    let now = TRIGGER_AT + SECONDS_72H;
    let tx = stp_tx(STPAction::CheckDeadline { investigation_id: [0x99; 32] }, [0xA1; 32], now);
    assert!(
        matches!(validate_transaction(&tx, &state, now, 0), Err(ChainError::STPError(_))),
        "CheckDeadline on an unknown investigation must be rejected"
    );
}

/// Regression: only the investigation target may provide data (the
/// `inv_target_key` binding still works after switching it to a raw account).
#[test]
fn r30_provide_data_target_check_still_enforced() {
    let official = [0x0F; 32];
    let state = state_with_official(official);
    let pool_id: Hash = [0x77; 32];
    let state = trigger(&state, official, pool_id);

    // The target may provide data.
    let by_target = stp_tx(
        STPAction::ProvideData { investigation_id: pool_id, data_hash: [0xAB; 32] },
        official,
        TRIGGER_AT + 5,
    );
    assert!(
        validate_transaction(&by_target, &state, TRIGGER_AT + 5, 0).is_ok(),
        "the investigation target must be able to provide data"
    );

    // A non-target may not.
    let by_other = stp_tx(
        STPAction::ProvideData { investigation_id: pool_id, data_hash: [0xAB; 32] },
        [0xEE; 32],
        TRIGGER_AT + 5,
    );
    assert!(
        matches!(
            validate_transaction(&by_other, &state, TRIGGER_AT + 5, 0),
            Err(ChainError::UnauthorizedSTPAction(_))
        ),
        "a non-target must not be able to provide data for the investigation"
    );
}
