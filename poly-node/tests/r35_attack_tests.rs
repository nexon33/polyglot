//! Round 35 attack tests for poly-node: strict Ed25519 verification.
//!
//! R35-01: `identity::verify_signature` verified handshake signatures with
//! the cofactored `Verifier::verify`, which accepts signatures whose `R`
//! component or public key `A` has a small-order (torsion) part — a
//! signature-malleability vector. The fix switches to `verify_strict`. Node
//! handshake signatures (including the R33 connection binding) must be
//! strongly non-malleable.

use ed25519_dalek::VerifyingKey;
use poly_node::identity::{verify_signature, NodeIdentity};

/// Compressed encoding of the Ed25519 identity point — a small-order point.
fn identity_point() -> [u8; 32] {
    let mut p = [0u8; 32];
    p[0] = 1;
    p
}

/// A forged signature: `R` = the identity point, `S` = 0. Cofactored
/// `verify` accepts this under an identity-point key for any message;
/// `verify_strict` rejects it (small-order `R` and `A`).
fn forged_identity_signature() -> [u8; 64] {
    let mut s = [0u8; 64];
    s[0] = 1;
    s
}

#[test]
fn r35_regression_genuine_signature_verifies() {
    let id = NodeIdentity::generate();
    let msg = b"poly-node handshake payload";
    let sig = id.sign(msg);
    assert!(
        verify_signature(id.verifying_key(), msg, &sig),
        "R35: a genuine signature must still verify under verify_strict"
    );
}

#[test]
fn r35_attack_wrong_key_rejected() {
    let a = NodeIdentity::generate();
    let b = NodeIdentity::generate();
    let sig = a.sign(b"msg");
    assert!(!verify_signature(b.verifying_key(), b"msg", &sig));
}

#[test]
fn r35_attack_tampered_message_rejected() {
    let id = NodeIdentity::generate();
    let sig = id.sign(b"original");
    assert!(!verify_signature(id.verifying_key(), b"tampered", &sig));
}

#[test]
fn r35_attack_identity_point_key_rejected() {
    // R = identity, S = 0, key = identity point. Cofactored `verify` accepts
    // this for any message; verify_strict must reject it.
    match VerifyingKey::from_bytes(&identity_point()) {
        Ok(vk) => assert!(
            !verify_signature(&vk, b"any message", &forged_identity_signature()),
            "R35-01: signature under a small-order (identity) key must be rejected"
        ),
        Err(_) => { /* key rejected at decode — also acceptable */ }
    }
}

#[test]
fn r35_attack_zero_key_rejected() {
    match VerifyingKey::from_bytes(&[0u8; 32]) {
        Ok(vk) => assert!(
            !verify_signature(&vk, b"any message", &[0u8; 64]),
            "R35-01: signature under the all-zero small-order key must be rejected"
        ),
        Err(_) => { /* key rejected at decode — also acceptable */ }
    }
}
