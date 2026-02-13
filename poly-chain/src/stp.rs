use poly_verified::types::Hash;
use serde::{Deserialize, Serialize};

use crate::primitives::*;

/// Status of a public official's service contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractStatus {
    Active,
    Suspended,
    Terminated,
}

/// A service contract that public officials must sign.
///
/// By signing, they agree to lower reporting thresholds and
/// automatic enforcement if they refuse to cooperate with
/// transparency protocol investigations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServiceContract {
    pub official: AccountId,
    pub identity_hash: Hash,
    pub office: String,
    pub jurisdiction: u16,
    /// Lower than standard reporting threshold.
    pub reporting_threshold: Amount,
    /// Amount staked as collateral.
    pub staked_amount: Amount,
    pub term_start: Timestamp,
    pub term_end: Timestamp,
    pub status: ContractStatus,
}

impl ServiceContract {
    pub fn contract_hash(&self) -> Hash {
        hash_with_domain(DOMAIN_STP, &self.to_bytes())
    }

    pub fn is_active(&self) -> bool {
        self.status == ContractStatus::Active
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&self.official);                       // 32
        buf.extend_from_slice(&self.identity_hash);                  // 32
        let office_bytes = self.office.as_bytes();
        buf.extend_from_slice(&(office_bytes.len() as u32).to_le_bytes()); // 4
        buf.extend_from_slice(office_bytes);                         // N
        buf.extend_from_slice(&self.jurisdiction.to_le_bytes());     // 2
        buf.extend_from_slice(&self.reporting_threshold.to_le_bytes()); // 8
        buf.extend_from_slice(&self.staked_amount.to_le_bytes());    // 8
        buf.extend_from_slice(&self.term_start.to_le_bytes());      // 8
        buf.extend_from_slice(&self.term_end.to_le_bytes());        // 8
        buf.push(match self.status {                                 // 1
            ContractStatus::Active => 0x00,
            ContractStatus::Suspended => 0x01,
            ContractStatus::Terminated => 0x02,
        });
        buf
    }
}

/// Status of an investigation triggered by the transparency protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvestigationStatus {
    /// Waiting for the official to provide data.
    AwaitingData,
    /// Official provided the requested data.
    DataProvided,
    /// Account frozen after 72h non-compliance.
    AccountFrozen { frozen_at: Timestamp },
    /// Full slashing after 30d non-compliance.
    Slashed { slashed_at: Timestamp },
    /// Investigation cleared (official cooperated, no issues found).
    Cleared,
}

/// An investigation record triggered by the STP.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InvestigationRecord {
    /// Unique ID for this investigation (hash of trigger data).
    pub id: Hash,
    /// Target official's account.
    pub target: AccountId,
    /// When the pool threshold was reached (investigation triggered).
    pub pool_threshold_reached: Timestamp,
    /// When the data request was sent.
    pub data_request_sent: Timestamp,
    /// Deadline to provide data (pool_threshold_reached + 72h).
    pub compliance_deadline: Timestamp,
    /// Final deadline before full slashing (freeze + 30d).
    pub final_deadline: Timestamp,
    pub status: InvestigationStatus,
}

impl InvestigationRecord {
    /// Create a new investigation record.
    pub fn new(id: Hash, target: AccountId, now: Timestamp) -> Self {
        Self {
            id,
            target,
            pool_threshold_reached: now,
            data_request_sent: now,
            compliance_deadline: now + SECONDS_72H,
            final_deadline: now + SECONDS_72H + SECONDS_30D,
            status: InvestigationStatus::AwaitingData,
        }
    }

    pub fn investigation_hash(&self) -> Hash {
        hash_with_domain(DOMAIN_STP, &self.to_bytes())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&self.id);                              // 32
        buf.extend_from_slice(&self.target);                          // 32
        buf.extend_from_slice(&self.pool_threshold_reached.to_le_bytes()); // 8
        buf.extend_from_slice(&self.data_request_sent.to_le_bytes()); // 8
        buf.extend_from_slice(&self.compliance_deadline.to_le_bytes()); // 8
        buf.extend_from_slice(&self.final_deadline.to_le_bytes());   // 8
        match &self.status {
            InvestigationStatus::AwaitingData => buf.push(0x00),
            InvestigationStatus::DataProvided => buf.push(0x01),
            InvestigationStatus::AccountFrozen { frozen_at } => {
                buf.push(0x02);
                buf.extend_from_slice(&frozen_at.to_le_bytes());
            }
            InvestigationStatus::Slashed { slashed_at } => {
                buf.push(0x03);
                buf.extend_from_slice(&slashed_at.to_le_bytes());
            }
            InvestigationStatus::Cleared => buf.push(0x04),
        }
        buf
    }
}

/// What action to take based on investigation deadlines.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvestigationAction {
    /// No deadline has passed yet.
    NoAction,
    /// 72h passed without data → freeze the account.
    FreezeAccount,
    /// 30d passed without compliance → full slash.
    ExecuteSlash,
}

/// Check what enforcement action should be taken based on the current time.
///
/// ```text
/// Timeline:
///   T=0              T+72h                    T+72h+30d
///   |--- Awaiting ---|--- Frozen --------------|--- Slashed
///   (data request)   (auto-freeze)             (full slash)
/// ```
pub fn check_investigation_deadlines(
    record: &InvestigationRecord,
    now: Timestamp,
) -> InvestigationAction {
    match record.status {
        InvestigationStatus::AwaitingData => {
            if now >= record.compliance_deadline {
                InvestigationAction::FreezeAccount
            } else {
                InvestigationAction::NoAction
            }
        }
        InvestigationStatus::AccountFrozen { .. } => {
            if now >= record.final_deadline {
                InvestigationAction::ExecuteSlash
            } else {
                InvestigationAction::NoAction
            }
        }
        // Already slashed, cleared, or data provided — no further action.
        _ => InvestigationAction::NoAction,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_investigation(now: Timestamp) -> InvestigationRecord {
        InvestigationRecord::new([0xAA; 32], [0xBB; 32], now)
    }

    #[test]
    fn new_investigation_deadlines() {
        let inv = make_investigation(1000);
        assert_eq!(inv.compliance_deadline, 1000 + SECONDS_72H);
        assert_eq!(inv.final_deadline, 1000 + SECONDS_72H + SECONDS_30D);
        assert_eq!(inv.status, InvestigationStatus::AwaitingData);
    }

    #[test]
    fn no_action_before_deadline() {
        let inv = make_investigation(1000);
        let action = check_investigation_deadlines(&inv, 1000 + SECONDS_72H - 1);
        assert_eq!(action, InvestigationAction::NoAction);
    }

    #[test]
    fn freeze_at_72h() {
        let inv = make_investigation(1000);
        let action = check_investigation_deadlines(&inv, 1000 + SECONDS_72H);
        assert_eq!(action, InvestigationAction::FreezeAccount);
    }

    #[test]
    fn slash_at_30d_after_freeze() {
        let freeze_time = 1000 + SECONDS_72H;
        let mut inv = make_investigation(1000);
        inv.status = InvestigationStatus::AccountFrozen {
            frozen_at: freeze_time,
        };
        // Before final deadline
        let action = check_investigation_deadlines(&inv, inv.final_deadline - 1);
        assert_eq!(action, InvestigationAction::NoAction);
        // At final deadline
        let action = check_investigation_deadlines(&inv, inv.final_deadline);
        assert_eq!(action, InvestigationAction::ExecuteSlash);
    }

    #[test]
    fn data_provided_no_action() {
        let mut inv = make_investigation(1000);
        inv.status = InvestigationStatus::DataProvided;
        let action = check_investigation_deadlines(&inv, 1000 + SECONDS_72H + SECONDS_30D + 999);
        assert_eq!(action, InvestigationAction::NoAction);
    }

    #[test]
    fn already_slashed_no_action() {
        let mut inv = make_investigation(1000);
        inv.status = InvestigationStatus::Slashed {
            slashed_at: 2000,
        };
        let action = check_investigation_deadlines(&inv, u64::MAX);
        assert_eq!(action, InvestigationAction::NoAction);
    }

    #[test]
    fn cleared_no_action() {
        let mut inv = make_investigation(1000);
        inv.status = InvestigationStatus::Cleared;
        let action = check_investigation_deadlines(&inv, u64::MAX);
        assert_eq!(action, InvestigationAction::NoAction);
    }

    #[test]
    fn contract_hash_deterministic() {
        let contract = ServiceContract {
            official: [1u8; 32],
            identity_hash: [2u8; 32],
            office: "Mayor".to_string(),
            jurisdiction: 840,
            reporting_threshold: 50_000_000,
            staked_amount: 10_000_000,
            term_start: 1000,
            term_end: 2000,
            status: ContractStatus::Active,
        };
        let h1 = contract.contract_hash();
        let h2 = contract.contract_hash();
        assert_eq!(h1, h2);
    }
}
