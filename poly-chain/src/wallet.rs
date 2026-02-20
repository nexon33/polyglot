use poly_verified::types::Hash;
use serde::{Deserialize, Serialize};

use crate::error::{ChainError, Result};
use crate::fraud::FreezeReason;
use crate::identity::Tier;
use crate::primitives::*;

/// Full wallet state for an account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletState {
    pub balance: Amount,
    pub nonce: Nonce,
    pub identity_hash: Hash,
    pub tier: Tier,
    /// Sum of outgoing transfers in the current 24h window.
    pub rolling_24h_total: Amount,
    /// Timestamp when the rolling window resets.
    pub rolling_reset_at: Timestamp,
    pub frozen: bool,
    pub freeze_reason: Option<FreezeReason>,
}

impl WalletState {
    /// Create a new wallet with zero balance.
    ///
    /// R10: Uses saturating arithmetic for rolling_reset_at to prevent overflow.
    pub fn new(identity_hash: Hash, tier: Tier, now: Timestamp) -> Self {
        Self {
            balance: 0,
            nonce: 0,
            identity_hash,
            tier,
            rolling_24h_total: 0,
            rolling_reset_at: now.saturating_add(SECONDS_24H),
            frozen: false,
            freeze_reason: None,
        }
    }

    /// Domain-separated hash of this wallet state.
    pub fn state_hash(&self) -> Hash {
        hash_with_domain(DOMAIN_WALLET_STATE, &self.to_bytes())
    }

    /// Update the rolling window: if reset_at has passed, zero the counter.
    ///
    /// R10: Uses saturating arithmetic to prevent overflow when `now` is near u64::MAX.
    pub fn maybe_reset_rolling(&mut self, now: Timestamp) {
        if now >= self.rolling_reset_at {
            self.rolling_24h_total = 0;
            self.rolling_reset_at = now.saturating_add(SECONDS_24H);
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&self.balance.to_le_bytes());          // 8
        buf.extend_from_slice(&self.nonce.to_le_bytes());            // 8
        buf.extend_from_slice(&self.identity_hash);                   // 32
        buf.push(self.tier as u8);                                    // 1
        buf.extend_from_slice(&self.rolling_24h_total.to_le_bytes()); // 8
        buf.extend_from_slice(&self.rolling_reset_at.to_le_bytes()); // 8
        buf.push(if self.frozen { 1 } else { 0 });                  // 1
        // Freeze reason tag
        match &self.freeze_reason {
            None => buf.push(0x00),
            Some(FreezeReason::FraudDetected) => buf.push(0x01),
            Some(FreezeReason::STPNonCompliance { deadline }) => {
                buf.push(0x02);
                buf.extend_from_slice(&deadline.to_le_bytes());
            }
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 67 {
            return Err(ChainError::InvalidEncoding(
                "wallet state too short".into(),
            ));
        }
        let balance = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let nonce = u64::from_le_bytes(data[8..16].try_into().unwrap());
        let mut identity_hash = [0u8; 32];
        identity_hash.copy_from_slice(&data[16..48]);
        let tier = Tier::from_u8(data[48])?;
        let rolling_24h_total = u64::from_le_bytes(data[49..57].try_into().unwrap());
        let rolling_reset_at = u64::from_le_bytes(data[57..65].try_into().unwrap());
        let frozen = data[65] != 0;
        let freeze_reason = match data[66] {
            0x00 => {
                // R10: Reject trailing garbage bytes for canonical deserialization.
                if data.len() > 67 {
                    return Err(ChainError::InvalidEncoding(format!(
                        "wallet state too long: {} bytes (expected 67 for no freeze reason)",
                        data.len()
                    )));
                }
                None
            }
            0x01 => {
                // R10: Reject trailing garbage bytes for canonical deserialization.
                if data.len() > 67 {
                    return Err(ChainError::InvalidEncoding(format!(
                        "wallet state too long: {} bytes (expected 67 for FraudDetected freeze)",
                        data.len()
                    )));
                }
                Some(FreezeReason::FraudDetected)
            }
            0x02 => {
                if data.len() < 75 {
                    return Err(ChainError::InvalidEncoding(
                        "wallet state: STP freeze reason truncated".into(),
                    ));
                }
                // R10: Reject trailing garbage bytes for canonical deserialization.
                if data.len() > 75 {
                    return Err(ChainError::InvalidEncoding(format!(
                        "wallet state too long: {} bytes (expected 75 for STP freeze reason)",
                        data.len()
                    )));
                }
                let deadline = u64::from_le_bytes(data[67..75].try_into().unwrap());
                Some(FreezeReason::STPNonCompliance { deadline })
            }
            v => {
                return Err(ChainError::InvalidEncoding(format!(
                    "unknown freeze reason tag: 0x{v:02x}"
                )))
            }
        };
        Ok(Self {
            balance,
            nonce,
            identity_hash,
            tier,
            rolling_24h_total,
            rolling_reset_at,
            frozen,
            freeze_reason,
        })
    }
}

/// Compact on-chain commitment to a wallet's state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletStateCommitment {
    pub account_id: AccountId,
    pub state_hash: Hash,
    pub nonce: Nonce,
    pub tier: Tier,
    pub last_updated: Timestamp,
}

impl WalletStateCommitment {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(81);
        buf.extend_from_slice(&self.account_id);   // 32
        buf.extend_from_slice(&self.state_hash);    // 32
        buf.extend_from_slice(&self.nonce.to_le_bytes()); // 8
        buf.push(self.tier as u8);                   // 1
        buf.extend_from_slice(&self.last_updated.to_le_bytes()); // 8
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 81 {
            return Err(ChainError::InvalidEncoding(
                "wallet commitment too short".into(),
            ));
        }
        // R10: Reject trailing garbage bytes for canonical deserialization.
        if data.len() > 81 {
            return Err(ChainError::InvalidEncoding(format!(
                "wallet commitment too long: {} bytes (expected 81)",
                data.len()
            )));
        }
        let mut account_id = [0u8; 32];
        account_id.copy_from_slice(&data[0..32]);
        let mut state_hash = [0u8; 32];
        state_hash.copy_from_slice(&data[32..64]);
        let nonce = u64::from_le_bytes(data[64..72].try_into().unwrap());
        let tier = Tier::from_u8(data[72])?;
        let last_updated = u64::from_le_bytes(data[73..81].try_into().unwrap());
        Ok(Self {
            account_id,
            state_hash,
            nonce,
            tier,
            last_updated,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use poly_verified::types::ZERO_HASH;

    #[test]
    fn new_wallet_defaults() {
        let w = WalletState::new([1u8; 32], Tier::Anonymous, 1000);
        assert_eq!(w.balance, 0);
        assert_eq!(w.nonce, 0);
        assert!(!w.frozen);
        assert!(w.freeze_reason.is_none());
        assert_eq!(w.rolling_reset_at, 1000 + SECONDS_24H);
    }

    #[test]
    fn wallet_state_roundtrip() {
        let w = WalletState {
            balance: 1_000_000,
            nonce: 5,
            identity_hash: [0xAA; 32],
            tier: Tier::Pseudonymous,
            rolling_24h_total: 500_000,
            rolling_reset_at: 2000000,
            frozen: false,
            freeze_reason: None,
        };
        let bytes = w.to_bytes();
        let decoded = WalletState::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.balance, w.balance);
        assert_eq!(decoded.nonce, w.nonce);
        assert_eq!(decoded.tier, w.tier);
        assert_eq!(decoded.rolling_24h_total, w.rolling_24h_total);
    }

    #[test]
    fn wallet_state_frozen_roundtrip() {
        let w = WalletState {
            balance: 100,
            nonce: 1,
            identity_hash: ZERO_HASH,
            tier: Tier::PublicOfficial,
            rolling_24h_total: 0,
            rolling_reset_at: 0,
            frozen: true,
            freeze_reason: Some(FreezeReason::STPNonCompliance { deadline: 9999999 }),
        };
        let bytes = w.to_bytes();
        let decoded = WalletState::from_bytes(&bytes).unwrap();
        assert!(decoded.frozen);
        assert_eq!(
            decoded.freeze_reason,
            Some(FreezeReason::STPNonCompliance { deadline: 9999999 })
        );
    }

    #[test]
    fn rolling_reset() {
        let mut w = WalletState::new([1u8; 32], Tier::Identified, 1000);
        w.rolling_24h_total = 50_000;
        w.maybe_reset_rolling(999); // before reset
        assert_eq!(w.rolling_24h_total, 50_000);
        w.maybe_reset_rolling(1000 + SECONDS_24H); // at reset
        assert_eq!(w.rolling_24h_total, 0);
    }

    #[test]
    fn state_hash_deterministic() {
        let w = WalletState::new([1u8; 32], Tier::Anonymous, 0);
        let h1 = w.state_hash();
        let h2 = w.state_hash();
        assert_eq!(h1, h2);
        assert_ne!(h1, ZERO_HASH);
    }

    #[test]
    fn commitment_roundtrip() {
        let c = WalletStateCommitment {
            account_id: [5u8; 32],
            state_hash: [6u8; 32],
            nonce: 42,
            tier: Tier::Identified,
            last_updated: 1700000000,
        };
        let bytes = c.to_bytes();
        let decoded = WalletStateCommitment::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.account_id, c.account_id);
        assert_eq!(decoded.nonce, c.nonce);
        assert_eq!(decoded.tier, c.tier);
    }
}
