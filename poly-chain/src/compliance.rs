use poly_verified::types::Hash;
use serde::{Deserialize, Serialize};

use crate::identity::Tier;
use crate::primitives::*;

/// Type of compliance report trigger.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReportType {
    /// Single transfer exceeded threshold.
    Single,
    /// Rolling 24h total exceeded threshold.
    RollingTotal,
}

/// Result of a compliance check.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ComplianceStatus {
    /// Transfer is below all thresholds — no report needed.
    BelowThreshold,
    /// Threshold exceeded — compliance report auto-generated.
    ReportGenerated(ComplianceReport),
}

/// An auto-generated compliance report.
///
/// These are generated deterministically by the verified circuit
/// and stored in the compliance subtree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub amount: Amount,
    pub rolling_total: Amount,
    pub sender_identity_hash: Hash,
    pub recipient_identity_hash: Hash,
    pub timestamp: Timestamp,
    /// ISO 3166-1 numeric country code of the sender.
    pub jurisdiction: u16,
    pub report_type: ReportType,
}

impl ComplianceReport {
    pub fn report_hash(&self) -> Hash {
        hash_with_domain(DOMAIN_COMPLIANCE, &self.to_bytes())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(91);
        buf.extend_from_slice(&self.amount.to_le_bytes());           // 8
        buf.extend_from_slice(&self.rolling_total.to_le_bytes());    // 8
        buf.extend_from_slice(&self.sender_identity_hash);            // 32
        buf.extend_from_slice(&self.recipient_identity_hash);         // 32
        buf.extend_from_slice(&self.timestamp.to_le_bytes());        // 8
        buf.extend_from_slice(&self.jurisdiction.to_le_bytes());     // 2
        buf.push(match self.report_type {                            // 1
            ReportType::Single => 0x01,
            ReportType::RollingTotal => 0x02,
        });
        buf
    }
}

/// Check whether a transfer triggers a compliance report.
///
/// Anti-structuring: checks both the single transfer amount AND the
/// rolling 24h total (which includes the current transfer).
pub fn check_compliance(
    amount: Amount,
    rolling_total_after: Amount,
    tier: Tier,
    jurisdiction: u16,
    timestamp: Timestamp,
    sender_identity_hash: Hash,
    recipient_identity_hash: Hash,
) -> ComplianceStatus {
    let threshold = tier.reporting_threshold();

    // Single transfer exceeds threshold
    if amount >= threshold {
        return ComplianceStatus::ReportGenerated(ComplianceReport {
            amount,
            rolling_total: rolling_total_after,
            sender_identity_hash,
            recipient_identity_hash,
            timestamp,
            jurisdiction,
            report_type: ReportType::Single,
        });
    }

    // Anti-structuring: rolling total exceeds threshold
    if rolling_total_after >= threshold {
        return ComplianceStatus::ReportGenerated(ComplianceReport {
            amount,
            rolling_total: rolling_total_after,
            sender_identity_hash,
            recipient_identity_hash,
            timestamp,
            jurisdiction,
            report_type: ReportType::RollingTotal,
        });
    }

    ComplianceStatus::BelowThreshold
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn below_threshold_no_report() {
        let status = check_compliance(
            100,        // small amount
            100,        // rolling total
            Tier::Identified,
            840,
            1000,
            [1u8; 32],
            [2u8; 32],
        );
        assert!(matches!(status, ComplianceStatus::BelowThreshold));
    }

    #[test]
    fn single_transfer_triggers_report() {
        let threshold = Tier::Identified.reporting_threshold();
        let status = check_compliance(
            threshold,
            threshold,
            Tier::Identified,
            840,
            1000,
            [1u8; 32],
            [2u8; 32],
        );
        match status {
            ComplianceStatus::ReportGenerated(report) => {
                assert_eq!(report.report_type, ReportType::Single);
                assert_eq!(report.amount, threshold);
            }
            _ => panic!("expected report"),
        }
    }

    #[test]
    fn rolling_total_triggers_report() {
        let threshold = Tier::Anonymous.reporting_threshold();
        // Small individual transfers but rolling total exceeds
        let status = check_compliance(
            100,             // small single transfer
            threshold + 100, // rolling total over threshold
            Tier::Anonymous,
            840,
            1000,
            [1u8; 32],
            [2u8; 32],
        );
        match status {
            ComplianceStatus::ReportGenerated(report) => {
                assert_eq!(report.report_type, ReportType::RollingTotal);
            }
            _ => panic!("expected rolling total report"),
        }
    }

    #[test]
    fn officials_lower_threshold() {
        let official_threshold = Tier::PublicOfficial.reporting_threshold();
        let _identified_threshold = Tier::Identified.reporting_threshold();
        // Amount between the two thresholds
        let amount = official_threshold;

        let official_status = check_compliance(
            amount, amount, Tier::PublicOfficial, 840, 1000, [1u8; 32], [2u8; 32],
        );
        let identified_status = check_compliance(
            amount, amount, Tier::Identified, 840, 1000, [1u8; 32], [2u8; 32],
        );

        assert!(matches!(official_status, ComplianceStatus::ReportGenerated(_)));
        assert!(matches!(identified_status, ComplianceStatus::BelowThreshold));
    }
}
