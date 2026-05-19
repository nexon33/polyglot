//! On-disk wallet keyfiles.
//!
//! Testnet keyfiles store the Ed25519 secret in **plaintext** JSON. This is
//! acceptable for a local testnet only — never reuse a testnet keyfile on a
//! network holding real value.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{ChainError, Result};
use crate::keys::{account_id_from_public, Keypair};
use crate::primitives::{hex_encode, write_atomic, AccountId};

/// A persisted wallet: label plus the keypair material, all hex-encoded.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Keyfile {
    /// Human-readable wallet name.
    pub label: String,
    /// The account id, hex. For poly-chain this *is* the Ed25519 public key,
    /// so it equals `public_key` below — kept under the canonical field name.
    pub account_id: String,
    /// Ed25519 public key, hex.
    pub public_key: String,
    /// Ed25519 secret scalar, hex. Sensitive — plaintext, testnet only.
    pub secret_key: String,
}

impl Keyfile {
    /// Build a keyfile from a keypair.
    pub fn from_keypair(label: &str, keypair: &Keypair) -> Self {
        Self {
            label: label.to_string(),
            account_id: hex_encode(&keypair.account_id()),
            public_key: hex_encode(&keypair.public_bytes()),
            secret_key: hex_encode(&keypair.secret_bytes()),
        }
    }

    /// Reconstruct the keypair held by this keyfile.
    ///
    /// Verifies that the stored `account_id` / `public_key` actually match the
    /// secret key — a corrupted or tampered keyfile is rejected rather than
    /// silently producing a different account.
    pub fn keypair(&self) -> Result<Keypair> {
        let secret = decode_array::<32>(&self.secret_key, "secret_key")?;
        let keypair = Keypair::from_secret_bytes(&secret);

        let stored_public = decode_array::<32>(&self.public_key, "public_key")?;
        if stored_public != keypair.public_bytes() {
            return Err(ChainError::InvalidEncoding(
                "keyfile public_key does not match secret_key".into(),
            ));
        }
        let stored_id = decode_array::<32>(&self.account_id, "account_id")?;
        if stored_id != keypair.account_id() {
            return Err(ChainError::InvalidEncoding(
                "keyfile account_id does not match public_key".into(),
            ));
        }
        Ok(keypair)
    }

    /// The decoded 32-byte account id.
    pub fn account_id_bytes(&self) -> Result<AccountId> {
        decode_array::<32>(&self.account_id, "account_id")
    }

    /// Write the keyfile to `path` as pretty JSON (atomically).
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| ChainError::InvalidEncoding(format!("keyfile encode: {e}")))?;
        write_atomic(path, json.as_bytes())
    }

    /// Load a keyfile from `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)
            .map_err(|e| ChainError::Io(format!("read {}: {e}", path.display())))?;
        let keyfile: Keyfile = serde_json::from_slice(&bytes)
            .map_err(|e| ChainError::InvalidEncoding(format!("keyfile decode: {e}")))?;
        // Validate consistency eagerly so a bad file fails at load time.
        keyfile.keypair()?;
        Ok(keyfile)
    }
}

/// Decode a hex string into a fixed-size byte array.
fn decode_array<const N: usize>(hex: &str, field: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(hex)
        .map_err(|e| ChainError::InvalidEncoding(format!("{field} not hex: {e}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        ChainError::InvalidEncoding(format!(
            "{field} wrong length: {} bytes, expected {N}",
            v.len()
        ))
    })
}

/// Re-derive an account id from a hex public key (used by the CLI).
pub fn account_id_from_public_hex(public_hex: &str) -> Result<AccountId> {
    let public = decode_array::<32>(public_hex, "public_key")?;
    Ok(account_id_from_public(&public))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyfile_roundtrip_in_memory() {
        let kp = Keypair::generate().unwrap();
        let kf = Keyfile::from_keypair("alice", &kp);
        let restored = kf.keypair().unwrap();
        assert_eq!(restored.account_id(), kp.account_id());
        assert_eq!(kf.account_id_bytes().unwrap(), kp.account_id());
    }

    #[test]
    fn keyfile_save_load() {
        let dir = std::env::temp_dir().join(format!("pc-keystore-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("alice.json");

        let kp = Keypair::generate().unwrap();
        let kf = Keyfile::from_keypair("alice", &kp);
        kf.save(&path).unwrap();

        let loaded = Keyfile::load(&path).unwrap();
        assert_eq!(loaded.label, "alice");
        assert_eq!(loaded.keypair().unwrap().account_id(), kp.account_id());

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn tampered_public_key_rejected() {
        let kp = Keypair::generate().unwrap();
        let mut kf = Keyfile::from_keypair("bad", &kp);
        let other = Keypair::generate().unwrap();
        kf.public_key = hex_encode(&other.public_bytes());
        assert!(kf.keypair().is_err());
    }

    #[test]
    fn tampered_account_id_rejected() {
        let kp = Keypair::generate().unwrap();
        let mut kf = Keyfile::from_keypair("bad", &kp);
        kf.account_id = hex_encode(&[0xABu8; 32]);
        assert!(kf.keypair().is_err());
    }
}
