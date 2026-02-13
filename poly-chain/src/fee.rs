use crate::primitives::Amount;

/// Flat fee schedule for all transaction types.
///
/// All fees are in smallest Amount units (1 MANA = 10_000 units).
pub struct FeeSchedule;

impl FeeSchedule {
    /// Base fee for a standard transfer (0.01 MANA).
    pub fn base_fee() -> Amount {
        100
    }

    /// Fee for storing encrypted wallet backup on-chain.
    /// 1 unit per byte (incentivizes compact backups).
    pub fn backup_storage_fee(size_bytes: usize) -> Amount {
        size_bytes as Amount
    }

    /// Reward paid to fraud proof submitter from the offender's frozen balance.
    pub fn fraud_proof_reward() -> Amount {
        1_000_000 // 100 MANA
    }

    /// Compliance reports are free — mandatory, not optional.
    pub fn compliance_report_fee() -> Amount {
        0
    }

    /// Fee for registering an STP service contract.
    pub fn stp_registration_fee() -> Amount {
        10_000 // 1 MANA
    }

    /// Fee for identity registration.
    pub fn identity_registration_fee() -> Amount {
        1_000 // 0.1 MANA
    }

    /// Fee for an app state update.
    pub fn app_state_update_fee() -> Amount {
        100 // 0.01 MANA
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fees_are_reasonable() {
        assert!(FeeSchedule::base_fee() > 0);
        assert_eq!(FeeSchedule::compliance_report_fee(), 0);
        assert!(FeeSchedule::fraud_proof_reward() > FeeSchedule::base_fee());
    }

    #[test]
    fn backup_fee_proportional() {
        assert_eq!(FeeSchedule::backup_storage_fee(0), 0);
        assert_eq!(FeeSchedule::backup_storage_fee(1024), 1024);
    }
}
