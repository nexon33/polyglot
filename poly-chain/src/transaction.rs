use poly_verified::types::{Hash, VerifiedProof};
use serde::{Deserialize, Serialize};

use crate::fraud::FraudEvidence;
use crate::identity::Tier;
use crate::primitives::*;
use crate::stp::ServiceContract;

/// All transaction types in the poly-chain protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Transaction {
    CashTransfer(CashTransfer),
    WalletSync(WalletSync),
    IdentityRegister(IdentityRegister),
    BackupStore(BackupStore),
    BackupRestore(BackupRestore),
    FraudProof(FraudProofTx),
    STPAction(STPActionTx),
    AppStateUpdate(AppStateUpdate),
}

impl Transaction {
    /// Tag byte for serialization.
    pub fn tag(&self) -> u8 {
        match self {
            Transaction::CashTransfer(_) => 0x01,
            Transaction::WalletSync(_) => 0x02,
            Transaction::IdentityRegister(_) => 0x03,
            Transaction::BackupStore(_) => 0x04,
            Transaction::BackupRestore(_) => 0x05,
            Transaction::FraudProof(_) => 0x06,
            Transaction::STPAction(_) => 0x07,
            Transaction::AppStateUpdate(_) => 0x08,
        }
    }

    /// Hash of this transaction for Merkle tree inclusion.
    pub fn tx_hash(&self) -> Hash {
        hash_with_domain(DOMAIN_TRANSFER, &serde_json::to_vec(self).unwrap_or_default())
    }

    /// The account that pays the fee for this transaction.
    pub fn fee_payer(&self) -> Option<AccountId> {
        match self {
            Transaction::CashTransfer(tx) => Some(tx.from),
            Transaction::WalletSync(tx) => Some(tx.account_id),
            Transaction::IdentityRegister(tx) => Some(tx.account_id),
            Transaction::BackupStore(tx) => Some(tx.account_id),
            Transaction::BackupRestore(tx) => Some(tx.account_id),
            Transaction::FraudProof(_) => None, // fraud proofs are free (rewarded)
            Transaction::STPAction(tx) => tx.fee_payer(),
            Transaction::AppStateUpdate(tx) => Some(tx.account_id),
        }
    }
}

// ---------------------------------------------------------------------------
// Cash Transfer
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CashTransfer {
    pub from: AccountId,
    pub to: AccountId,
    pub amount: Amount,
    pub fee: Amount,
    pub nonce: Nonce,
    pub timestamp: Timestamp,
    /// Expected sender wallet state hash before this transfer.
    pub state_pre: Hash,
    pub proof: VerifiedProof,
    #[serde(with = "crate::primitives::serde_byte64")]
    pub signature: [u8; 64],
}

// ---------------------------------------------------------------------------
// Wallet Sync
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletSync {
    pub account_id: AccountId,
    pub new_state_hash: Hash,
    pub nonce: Nonce,
    pub timestamp: Timestamp,
    pub proof: VerifiedProof,
    #[serde(with = "crate::primitives::serde_byte64")]
    pub signature: [u8; 64],
}

// ---------------------------------------------------------------------------
// Identity Register
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityRegister {
    pub account_id: AccountId,
    pub tier: Tier,
    pub identity_hash: Hash,
    pub jurisdiction: u16,
    pub is_public_official: bool,
    pub office: Option<String>,
    pub proof: VerifiedProof,
    #[serde(with = "crate::primitives::serde_byte64")]
    pub signature: [u8; 64],
}

// ---------------------------------------------------------------------------
// Backup Store
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupStore {
    pub account_id: AccountId,
    pub encrypted_state: Vec<u8>,
    pub state_hash: Hash,
    pub nonce: Nonce,
    pub proof: VerifiedProof,
    #[serde(with = "crate::primitives::serde_byte64")]
    pub signature: [u8; 64],
}

// ---------------------------------------------------------------------------
// Backup Restore
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupRestore {
    pub account_id: AccountId,
    pub backup_hash: Hash,
    pub nonce: Nonce,
    pub proof: VerifiedProof,
    #[serde(with = "crate::primitives::serde_byte64")]
    pub signature: [u8; 64],
}

// ---------------------------------------------------------------------------
// Fraud Proof
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FraudProofTx {
    pub evidence: FraudEvidence,
    pub submitter: AccountId,
    pub proof: VerifiedProof,
}

// ---------------------------------------------------------------------------
// STP Actions
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum STPAction {
    /// Register a new service contract for a public official.
    RegisterContract(ServiceContract),
    /// Trigger an investigation (pool threshold reached).
    TriggerInvestigation {
        target: AccountId,
        pool_id: Hash,
    },
    /// Official provides requested data.
    ProvideData {
        investigation_id: Hash,
        data_hash: Hash,
    },
    /// Check deadlines — anyone can submit this to enforce freeze/slash.
    CheckDeadline {
        investigation_id: Hash,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct STPActionTx {
    pub action: STPAction,
    pub submitter: AccountId,
    pub timestamp: Timestamp,
    pub proof: VerifiedProof,
    #[serde(with = "crate::primitives::serde_byte64")]
    pub signature: [u8; 64],
}

impl STPActionTx {
    pub fn fee_payer(&self) -> Option<AccountId> {
        match &self.action {
            STPAction::RegisterContract(_) => Some(self.submitter),
            STPAction::CheckDeadline { .. } => None, // anyone can trigger, free
            _ => Some(self.submitter),
        }
    }
}

// ---------------------------------------------------------------------------
// App State Update
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AppStateUpdate {
    pub account_id: AccountId,
    pub app_id: Hash,
    pub new_state_hash: Hash,
    pub nonce: Nonce,
    pub timestamp: Timestamp,
    pub proof: VerifiedProof,
    #[serde(with = "crate::primitives::serde_byte64")]
    pub signature: [u8; 64],
}

#[cfg(test)]
mod tests {
    use super::*;
    use poly_verified::types::{PrivacyMode, VerifiedProof, ZERO_HASH};

    fn mock_proof() -> VerifiedProof {
        VerifiedProof::Mock {
            input_hash: ZERO_HASH,
            output_hash: ZERO_HASH,
            privacy_mode: PrivacyMode::Transparent,
        }
    }

    #[test]
    fn tx_tags_unique() {
        let txs = vec![
            Transaction::CashTransfer(CashTransfer {
                from: [1u8; 32],
                to: [2u8; 32],
                amount: 100,
                fee: 10,
                nonce: 0,
                timestamp: 0,
                state_pre: ZERO_HASH,
                proof: mock_proof(),
                signature: [0u8; 64],
            }),
            Transaction::IdentityRegister(IdentityRegister {
                account_id: [1u8; 32],
                tier: Tier::Anonymous,
                identity_hash: ZERO_HASH,
                jurisdiction: 840,
                is_public_official: false,
                office: None,
                proof: mock_proof(),
                signature: [0u8; 64],
            }),
        ];
        let tags: Vec<u8> = txs.iter().map(|t| t.tag()).collect();
        assert_eq!(tags[0], 0x01);
        assert_eq!(tags[1], 0x03);
    }

    #[test]
    fn tx_hash_deterministic() {
        let tx = Transaction::CashTransfer(CashTransfer {
            from: [1u8; 32],
            to: [2u8; 32],
            amount: 100,
            fee: 10,
            nonce: 0,
            timestamp: 0,
            state_pre: ZERO_HASH,
            proof: mock_proof(),
            signature: [0u8; 64],
        });
        let h1 = tx.tx_hash();
        let h2 = tx.tx_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, ZERO_HASH);
    }

    #[test]
    fn fee_payer_correct() {
        let tx = Transaction::CashTransfer(CashTransfer {
            from: [0xAA; 32],
            to: [0xBB; 32],
            amount: 100,
            fee: 10,
            nonce: 0,
            timestamp: 0,
            state_pre: ZERO_HASH,
            proof: mock_proof(),
            signature: [0u8; 64],
        });
        assert_eq!(tx.fee_payer(), Some([0xAA; 32]));

        let fraud_tx = Transaction::FraudProof(FraudProofTx {
            evidence: crate::fraud::FraudEvidence {
                fraudulent_key: [1u8; 32],
                observation_a: crate::fraud::StateObservation {
                    observer: [2u8; 32],
                    observed_key: [1u8; 32],
                    observed_state_hash: [3u8; 32],
                    observed_nonce: 5,
                    observer_signature: [0u8; 64],
                },
                observation_b: crate::fraud::StateObservation {
                    observer: [4u8; 32],
                    observed_key: [1u8; 32],
                    observed_state_hash: [5u8; 32],
                    observed_nonce: 5,
                    observer_signature: [0u8; 64],
                },
                conflict_type: crate::fraud::ConflictType::DoubleSpend,
            },
            submitter: [6u8; 32],
            proof: mock_proof(),
        });
        assert_eq!(fraud_tx.fee_payer(), None); // fraud proofs are free
    }
}
