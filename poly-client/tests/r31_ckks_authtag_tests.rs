//! Round 31 — Backlog item 2/4: CKKS ciphertext auth-tag re-keying.
//!
//! The R20 audit found `CkksCiphertext`'s `auth_tag` (an HMAC) was always
//! keyed by `derive_mac_key(sk)` — the *encrypting* party's secret key. The
//! `auth_tag` is verified in `decrypt` with `derive_mac_key(sk)` of the
//! *decrypting* party. For any cross-party ciphertext (e.g. a server
//! re-encrypting an inference result under the client's public key with the
//! server's own secret key) those keys differ, so the recipient's `decrypt`
//! MAC check failed — it `assert!`-panicked on every such ciphertext, and the
//! tag carried no integrity guarantee the recipient could check.
//!
//! A symmetric MAC verifiable by a *different* recipient is impossible without
//! a shared secret. R31 makes the design honest:
//!  - `encrypt` checks (via `secret_matches_public`) whether `sk` is the
//!    secret key for `pk`. Only for that *self-encryption* case does it emit
//!    an `auth_tag` — which the keypair holder can correctly verify.
//!  - For a cross-party encryption it emits `auth_tag: None`; `decrypt` then
//!    skips MAC verification (no panic). Integrity for inference outputs is
//!    assured by the verified-inference proof binding, not this tag.
//!
//! These tests run only under `--features ckks`.

use poly_client::ckks::ciphertext::{decrypt, encrypt};
use poly_client::ckks::keys::{derive_mac_key, keygen, secret_matches_public};
use rand::rngs::StdRng;
use rand::SeedableRng;

// ===========================================================================
// R31-01: self-encryption keeps a verifiable tag
// ===========================================================================

/// A ciphertext encrypted under one's own keypair carries an `auth_tag` that
/// the keypair holder can verify, and decrypts cleanly.
#[test]
fn r31_self_encryption_has_verifiable_tag() {
    let mut rng = StdRng::seed_from_u64(1);
    let (pk, sk) = keygen(&mut rng);
    let tokens = vec![11u32, 22, 33];

    let ct = encrypt(&tokens, &pk, &sk, &mut rng);

    assert!(
        ct.auth_tag.is_some(),
        "R31-01: a self-encrypted ciphertext must carry an auth_tag"
    );
    assert!(
        ct.verify_integrity(&pk, &derive_mac_key(&sk)),
        "R31-01: the keypair holder must be able to verify the self-encryption tag"
    );
    assert_eq!(decrypt(&ct, &sk), tokens, "R31-01: self-encryption must round-trip");
}

// ===========================================================================
// R31-02: cross-party encryption emits no (forgeable/unverifiable) tag
// ===========================================================================

/// Encrypting under recipient A's public key with a *different* party B's
/// secret key must NOT emit an auth_tag — B cannot produce a tag A can verify.
#[test]
fn r31_cross_party_encryption_has_no_tag() {
    let mut rng = StdRng::seed_from_u64(2);
    let (pk_a, _sk_a) = keygen(&mut rng);
    let (_pk_b, sk_b) = keygen(&mut rng);
    let tokens = vec![5u32, 6, 7];

    // Party B encrypts FOR recipient A (under A's pk) using B's own sk.
    let ct = encrypt(&tokens, &pk_a, &sk_b, &mut rng);

    assert!(
        ct.auth_tag.is_none(),
        "R31-02: a cross-party ciphertext must not carry a tag the recipient cannot verify"
    );
}

/// The recipient can decrypt a cross-party ciphertext WITHOUT panicking — this
/// is the concrete R20 bug (the MAC `assert!` fired on every cross-party
/// response). The ciphertext is encrypted under A's pk, so A's sk decrypts it.
#[test]
fn r31_cross_party_decrypt_does_not_panic() {
    let mut rng = StdRng::seed_from_u64(3);
    let (pk_a, sk_a) = keygen(&mut rng);
    let (_pk_b, sk_b) = keygen(&mut rng);
    let tokens = vec![100u32, 200, 300, 400];

    // Server (B) re-encrypts the result under the client's (A's) public key.
    let ct = encrypt(&tokens, &pk_a, &sk_b, &mut rng);

    // Client A decrypts. Before R31 this panicked on the MAC mismatch.
    let recovered = decrypt(&ct, &sk_a);
    assert_eq!(
        recovered, tokens,
        "R31-02: the recipient must decrypt a cross-party ciphertext without panicking"
    );
}

// ===========================================================================
// R31-03: tampering a self-encrypted ciphertext is still detected
// ===========================================================================

/// The self-encryption tag still does its job: tampering with a coefficient
/// makes `verify_integrity` fail.
#[test]
fn r31_tampering_self_encrypted_ciphertext_detected() {
    let mut rng = StdRng::seed_from_u64(4);
    let (pk, sk) = keygen(&mut rng);
    let tokens = vec![9u32, 8, 7, 6, 5];

    let mut ct = encrypt(&tokens, &pk, &sk, &mut rng);
    assert!(ct.verify_integrity(&pk, &derive_mac_key(&sk)));

    // Tamper with a ciphertext coefficient.
    ct.chunks[0].0.coeffs[0] ^= 0x5A5A;
    assert!(
        !ct.verify_integrity(&pk, &derive_mac_key(&sk)),
        "R31-03: tampering with a self-encrypted ciphertext must be detected"
    );
}

// ===========================================================================
// R31-04: secret_matches_public correctness
// ===========================================================================

/// `secret_matches_public` accepts a genuine keypair and rejects a mismatched
/// secret key.
#[test]
fn r31_secret_matches_public_distinguishes_keys() {
    let mut rng = StdRng::seed_from_u64(5);
    let (pk_a, sk_a) = keygen(&mut rng);
    let (_pk_b, sk_b) = keygen(&mut rng);

    assert!(
        secret_matches_public(&pk_a, &sk_a),
        "R31-04: a genuine keypair must be recognized as matching"
    );
    assert!(
        !secret_matches_public(&pk_a, &sk_b),
        "R31-04: a foreign secret key must be recognized as NOT matching"
    );
}
