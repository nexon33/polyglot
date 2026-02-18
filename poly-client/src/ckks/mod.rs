//! # CKKS Encryption Backend
//!
//! From-scratch implementation of Cheon-Kim-Kim-Song (CKKS) encryption
//! for the Poly Network thin client. Provides real lattice-based encryption
//! where `MockEncryption` provides passthrough.
//!
//! Only encrypt/decrypt — no homomorphic evaluation. This keeps the
//! implementation minimal (~600 LOC) with a single dependency (`rand`).
//!
//! ## Security
//!
//! - Ring dimension N = 4096
//! - Ciphertext modulus q = 2^54 - 33
//! - Based on Ring-LWE hardness assumption
//! - ~128-bit security for encrypt/decrypt-only usage

pub mod ciphertext;
pub mod encoding;
pub mod encoding_f64;
pub mod eval_key;
pub mod fhe_layer;
pub mod homomorphic;
pub mod keys;
pub mod ntt;
pub mod params;
pub mod rns;
pub mod rns_ckks;
pub mod poly_eval;
pub mod rns_fhe_layer;
pub mod simd;
pub mod poly;
pub mod sampling;
#[cfg(feature = "cuda")]
pub mod gpu;

pub use ciphertext::{compute_key_id, CkksCiphertext};
pub use eval_key::CkksEvalKey;
pub use keys::{derive_mac_key, CkksPublicKey, CkksSecretKey};

use crate::encryption::EncryptionBackend;

/// CKKS encryption backend for real lattice-based encryption.
///
/// Drop-in replacement for `MockEncryption` — implements the same
/// `EncryptionBackend` trait. Token IDs are encoded into polynomial
/// ring elements and encrypted under Ring-LWE.
pub struct CkksEncryption;

impl EncryptionBackend for CkksEncryption {
    type Ciphertext = CkksCiphertext;
    type PublicKey = CkksPublicKey;
    type SecretKey = CkksSecretKey;

    fn keygen(&self) -> (Self::PublicKey, Self::SecretKey) {
        let mut rng = rand::thread_rng();
        keys::keygen(&mut rng)
    }

    fn encrypt(&self, token_ids: &[u32], pk: &Self::PublicKey, sk: &Self::SecretKey) -> Self::Ciphertext {
        let mut rng = rand::thread_rng();
        ciphertext::encrypt(token_ids, pk, sk, &mut rng)
    }

    fn decrypt(&self, ct: &Self::Ciphertext, sk: &Self::SecretKey) -> Vec<u32> {
        ciphertext::decrypt(ct, sk)
    }
}
