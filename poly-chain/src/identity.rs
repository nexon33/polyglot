use poly_verified::types::Hash;
use serde::{Deserialize, Serialize};

use crate::error::{ChainError, Result};
use crate::primitives::*;

/// KYC tier determining balance limits and reporting thresholds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum Tier {
    /// No identity — lowest limits.
    Anonymous = 0,
    /// Pseudonymous (email/phone) — moderate limits.
    Pseudonymous = 1,
    /// Fully identified (government ID) — no balance limit.
    Identified = 2,
    /// Public official — no balance limit, lower reporting threshold.
    PublicOfficial = 3,
}

impl Tier {
    /// Maximum balance allowed for this tier (in smallest units).
    ///
    /// - Anonymous: 500.00 (5_000_000 units at 10_000 per MANA)
    /// - Pseudonymous: 5_000.00 (50_000_000 units)
    /// - Identified / PublicOfficial: u64::MAX (effectively unlimited)
    pub fn balance_limit(&self) -> Amount {
        match self {
            Tier::Anonymous => 5_000_000,
            Tier::Pseudonymous => 50_000_000,
            Tier::Identified => u64::MAX,
            Tier::PublicOfficial => u64::MAX,
        }
    }

    /// Rolling 24h transfer threshold that triggers a compliance report.
    ///
    /// Officials have a lower threshold (higher scrutiny).
    pub fn reporting_threshold(&self) -> Amount {
        match self {
            Tier::Anonymous => 1_000_000,      // 100 MANA
            Tier::Pseudonymous => 10_000_000,  // 1,000 MANA
            Tier::Identified => 100_000_000,   // 10,000 MANA
            Tier::PublicOfficial => 50_000_000, // 5,000 MANA (lower!)
        }
    }

    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            0 => Ok(Tier::Anonymous),
            1 => Ok(Tier::Pseudonymous),
            2 => Ok(Tier::Identified),
            3 => Ok(Tier::PublicOfficial),
            _ => Err(ChainError::InvalidEncoding(format!(
                "unknown tier: {v}"
            ))),
        }
    }
}

/// On-chain identity record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IdentityRecord {
    pub account_id: AccountId,
    pub tier: Tier,
    /// H(national_id || dob || country) — never stored in plaintext.
    pub identity_hash: Hash,
    /// ISO 3166-1 numeric country code.
    pub jurisdiction: u16,
    pub registered_at: Timestamp,
    pub is_public_official: bool,
    pub office: Option<String>,
}

impl IdentityRecord {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&self.account_id);        // 32
        buf.push(self.tier as u8);                       // 1
        buf.extend_from_slice(&self.identity_hash);      // 32
        buf.extend_from_slice(&self.jurisdiction.to_le_bytes()); // 2
        buf.extend_from_slice(&self.registered_at.to_le_bytes()); // 8
        buf.push(if self.is_public_official { 1 } else { 0 }); // 1
        // Variable-length office field
        if let Some(ref office) = self.office {
            let bytes = office.as_bytes();
            buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(bytes);
        } else {
            buf.extend_from_slice(&0u32.to_le_bytes());
        }
        buf
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 80 {
            return Err(ChainError::InvalidEncoding(
                "identity record too short".into(),
            ));
        }
        let mut account_id = [0u8; 32];
        account_id.copy_from_slice(&data[0..32]);
        let tier = Tier::from_u8(data[32])?;
        let mut identity_hash = [0u8; 32];
        identity_hash.copy_from_slice(&data[33..65]);
        let jurisdiction = u16::from_le_bytes(data[65..67].try_into().unwrap());
        let registered_at = u64::from_le_bytes(data[67..75].try_into().unwrap());
        let is_public_official = data[75] != 0;
        let office_len = u32::from_le_bytes(data[76..80].try_into().unwrap()) as usize;
        let office = if office_len > 0 {
            if data.len() < 80 + office_len {
                return Err(ChainError::InvalidEncoding(
                    "identity record office field truncated".into(),
                ));
            }
            // R10: Reject trailing garbage bytes for canonical deserialization.
            if data.len() > 80 + office_len {
                return Err(ChainError::InvalidEncoding(format!(
                    "identity record too long: {} bytes (expected {})",
                    data.len(),
                    80 + office_len,
                )));
            }
            Some(
                String::from_utf8(data[80..80 + office_len].to_vec())
                    .map_err(|e| ChainError::InvalidEncoding(e.to_string()))?,
            )
        } else {
            // R10: Reject trailing garbage bytes for canonical deserialization.
            if data.len() > 80 {
                return Err(ChainError::InvalidEncoding(format!(
                    "identity record too long: {} bytes (expected 80)",
                    data.len(),
                )));
            }
            None
        };
        Ok(Self {
            account_id,
            tier,
            identity_hash,
            jurisdiction,
            registered_at,
            is_public_official,
            office,
        })
    }

    /// Domain-separated hash of this identity record.
    pub fn record_hash(&self) -> Hash {
        hash_with_domain(DOMAIN_IDENTITY, &self.to_bytes())
    }
}

/// Derive an identity hash from personal data.
///
/// `H(DOMAIN_IDENTITY || len(national_id) || national_id || len(dob) || dob || len(country) || country)`
///
/// Length-prefixed to prevent concatenation collisions
/// (e.g., ("AB","CD","EF") vs ("ABC","DE","F")).
/// The plaintext is never stored on chain — only this hash.
pub fn derive_identity_hash(national_id: &[u8], dob: &[u8], country: &[u8]) -> Hash {
    let mut data = Vec::with_capacity(12 + national_id.len() + dob.len() + country.len());
    data.extend_from_slice(&(national_id.len() as u32).to_le_bytes());
    data.extend_from_slice(national_id);
    data.extend_from_slice(&(dob.len() as u32).to_le_bytes());
    data.extend_from_slice(dob);
    data.extend_from_slice(&(country.len() as u32).to_le_bytes());
    data.extend_from_slice(country);
    hash_with_domain(DOMAIN_IDENTITY, &data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use poly_verified::types::ZERO_HASH;

    #[test]
    fn tier_ordering() {
        assert!(Tier::Anonymous < Tier::Pseudonymous);
        assert!(Tier::Pseudonymous < Tier::Identified);
        assert!(Tier::Identified < Tier::PublicOfficial);
    }

    #[test]
    fn tier_balance_limits() {
        assert_eq!(Tier::Anonymous.balance_limit(), 5_000_000);
        assert_eq!(Tier::Pseudonymous.balance_limit(), 50_000_000);
        assert_eq!(Tier::Identified.balance_limit(), u64::MAX);
        assert_eq!(Tier::PublicOfficial.balance_limit(), u64::MAX);
    }

    #[test]
    fn officials_lower_reporting_threshold() {
        assert!(Tier::PublicOfficial.reporting_threshold() < Tier::Identified.reporting_threshold());
    }

    #[test]
    fn identity_record_roundtrip() {
        let record = IdentityRecord {
            account_id: [1u8; 32],
            tier: Tier::Identified,
            identity_hash: [2u8; 32],
            jurisdiction: 840, // US
            registered_at: 1700000000,
            is_public_official: false,
            office: None,
        };
        let bytes = record.to_bytes();
        let decoded = IdentityRecord::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.account_id, record.account_id);
        assert_eq!(decoded.tier, record.tier);
        assert_eq!(decoded.identity_hash, record.identity_hash);
        assert_eq!(decoded.jurisdiction, record.jurisdiction);
        assert_eq!(decoded.registered_at, record.registered_at);
        assert_eq!(decoded.is_public_official, record.is_public_official);
        assert_eq!(decoded.office, None);
    }

    #[test]
    fn identity_record_with_office_roundtrip() {
        let record = IdentityRecord {
            account_id: [3u8; 32],
            tier: Tier::PublicOfficial,
            identity_hash: [4u8; 32],
            jurisdiction: 528, // NL
            registered_at: 1700000000,
            is_public_official: true,
            office: Some("Minister of Finance".to_string()),
        };
        let bytes = record.to_bytes();
        let decoded = IdentityRecord::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.office, Some("Minister of Finance".to_string()));
        assert!(decoded.is_public_official);
    }

    #[test]
    fn derive_identity_hash_deterministic() {
        let h1 = derive_identity_hash(b"123456789", b"1990-01-01", b"US");
        let h2 = derive_identity_hash(b"123456789", b"1990-01-01", b"US");
        assert_eq!(h1, h2);
        assert_ne!(h1, ZERO_HASH);
    }

    #[test]
    fn different_inputs_different_hashes() {
        let h1 = derive_identity_hash(b"123456789", b"1990-01-01", b"US");
        let h2 = derive_identity_hash(b"987654321", b"1990-01-01", b"US");
        assert_ne!(h1, h2);
    }

    #[test]
    fn attack_identity_hash_concatenation_collision_fixed() {
        // FIXED: Length-prefixing makes field boundaries unambiguous.
        // ("AB","CD","EF") and ("ABC","DE","F") now produce different hashes.
        let h1 = derive_identity_hash(b"AB", b"CD", b"EF");
        let h2 = derive_identity_hash(b"ABC", b"DE", b"F");
        assert_ne!(h1, h2);
    }
}
