use poly_verified::types::Hash;
use sha2::{Digest, Sha256};

/// Serde helper for `[u8; 64]` fields (Ed25519 signatures).
pub mod serde_byte64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(
        bytes: &[u8; 64],
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        bytes.to_vec().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(d)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))
    }
}

/// Account identifier — SHA-256 hash of the public key.
pub type AccountId = Hash;

/// Smallest currency unit (1 MANA = 10_000 units).
pub type Amount = u64;

/// Monotonically increasing per-account counter.
pub type Nonce = u64;

/// Unix timestamp in seconds.
pub type Timestamp = u64;

/// Block height (0-indexed, genesis = 0).
pub type BlockHeight = u64;

// ---------------------------------------------------------------------------
// Chain-specific domain separators (0x10–0x1F)
//
// poly-verified uses 0x00–0x04. We use 0x10+ to avoid collisions.
// ---------------------------------------------------------------------------

pub const DOMAIN_WALLET_STATE: u8 = 0x10;
pub const DOMAIN_IDENTITY: u8 = 0x11;
pub const DOMAIN_COMPLIANCE: u8 = 0x12;
pub const DOMAIN_TRANSFER: u8 = 0x13;
pub const DOMAIN_BLOCK: u8 = 0x14;
pub const DOMAIN_FRAUD: u8 = 0x15;
pub const DOMAIN_STP: u8 = 0x16;

/// Domain-separated SHA-256 hash: H(domain_byte || data).
pub fn hash_with_domain(domain: u8, data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([domain]);
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Convenience: hex-encode a hash for display (first 8 hex chars).
pub fn hash_short(h: &Hash) -> String {
    hex_encode(&h[..4])
}

/// Full hex encoding of a byte slice.
pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// 24 hours in seconds.
pub const SECONDS_24H: u64 = 86_400;

/// 72 hours in seconds (STP compliance deadline).
pub const SECONDS_72H: u64 = 259_200;

/// 30 days in seconds (STP final deadline).
pub const SECONDS_30D: u64 = 2_592_000;

#[cfg(test)]
mod tests {
    use super::*;
    use poly_verified::types::ZERO_HASH;

    #[test]
    fn domain_hash_deterministic() {
        let a = hash_with_domain(DOMAIN_BLOCK, b"test");
        let b = hash_with_domain(DOMAIN_BLOCK, b"test");
        assert_eq!(a, b);
    }

    #[test]
    fn different_domains_different_hashes() {
        let a = hash_with_domain(DOMAIN_BLOCK, b"test");
        let b = hash_with_domain(DOMAIN_FRAUD, b"test");
        assert_ne!(a, b);
    }

    #[test]
    fn hash_short_display() {
        let s = hash_short(&ZERO_HASH);
        assert_eq!(s, "00000000");
    }
}
