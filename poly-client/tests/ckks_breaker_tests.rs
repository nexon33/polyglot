//! CKKS ciphertext authentication breaker tests.
//!
//! These tests attempt to BREAK the hardened CKKS ciphertext authentication
//! system. They probe for vulnerabilities in the auth_tag scheme.
//!
//! ## Status after fix
//!
//! The auth_tag now includes a MAC key derived from the secret key via
//! `derive_mac_key(sk)`. The attacker CANNOT recompute valid auth_tags
//! because they don't know the secret key.
//!
//! Previous vulnerability: auth_tag was SHA-256(public_data) — a checksum.
//! Now: auth_tag is SHA-256(mac_key || public_data) — a proper MAC.

#![cfg(feature = "ckks")]

use poly_client::ckks::ciphertext::{compute_key_id, decrypt, encrypt, CkksCiphertext};
use poly_client::ckks::keys::{derive_mac_key, keygen};
use poly_client::ckks::params::DELTA;
use poly_client::ckks::poly::Poly;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

fn test_rng() -> StdRng {
    StdRng::seed_from_u64(42)
}

/// Attacker's local reimplementation of the OLD compute_auth_tag (without mac_key).
///
/// This function replicates the algorithm that was used BEFORE the fix.
/// After the fix, the real compute_auth_tag includes mac_key, so this
/// attacker function produces DIFFERENT tags than the real one.
fn attacker_compute_auth_tag(
    chunks: &[(Poly, Poly)],
    token_count: usize,
    scale: i64,
    nonce: &[u8; 16],
    key_id: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ckks_auth_v1");
    // NOTE: attacker does NOT have mac_key, so cannot include it
    hasher.update(key_id);
    hasher.update(nonce);
    hasher.update((token_count as u64).to_le_bytes());
    hasher.update(scale.to_le_bytes());
    for (c0, c1) in chunks {
        for c in &c0.coeffs {
            hasher.update(c.to_le_bytes());
        }
        for c in &c1.coeffs {
            hasher.update(c.to_le_bytes());
        }
    }
    hasher.finalize().into()
}

// =========================================================================
// ATTACK 1: AUTH TAG RECOMPUTATION AFTER TOKEN_COUNT TAMPERING
//
// HARDENED: The auth_tag now includes a MAC key derived from the secret key.
// The attacker cannot recompute valid tags without the secret key.
// =========================================================================

/// HARDENED: Tamper with token_count and attempt to recompute auth_tag.
/// Without mac_key, the forged tag doesn't match.
#[test]
fn attack_auth_tag_recomputation_token_count_tamper() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let mac_key = derive_mac_key(&sk);

    let tokens = vec![100, 200, 300, 400, 500];
    let mut ct = encrypt(&tokens, &pk, &sk, &mut rng);

    // Verify original is valid
    assert!(ct.verify_integrity(&pk, &mac_key));
    assert_eq!(ct.token_count, 5);

    // --- Attacker reads all public fields ---
    let nonce = ct.nonce.unwrap();
    let key_id = ct.key_id.unwrap();

    // --- Attacker tampers with token_count ---
    ct.token_count = 2;

    // Without recomputing auth_tag, verification fails (good)
    assert!(!ct.verify_integrity(&pk, &mac_key));

    // --- Attacker recomputes auth_tag WITHOUT mac_key ---
    let forged_tag = attacker_compute_auth_tag(
        &ct.chunks,
        ct.token_count, // tampered value: 2
        ct.scale,
        &nonce,
        &key_id,
    );
    ct.auth_tag = Some(forged_tag);

    // HARDENED: verify_integrity() rejects the forged tag
    assert!(
        !ct.verify_integrity(&pk, &mac_key),
        "HARDENED: auth_tag forgery without mac_key is now detected"
    );

    eprintln!(
        "HARDENED: attacker cannot forge auth_tag without mac_key (derived from secret key)"
    );
}

// =========================================================================
// ATTACK 2: NONCE REUSE DETECTION
// =========================================================================

/// Nonce reuse test: each encryption produces unique nonces.
#[test]
fn attack_nonce_reuse_detection() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let mac_key = derive_mac_key(&sk);

    let tokens_a = vec![100, 200, 300];
    let tokens_b = vec![100, 200, 300]; // same plaintext

    let ct_a = encrypt(&tokens_a, &pk, &sk, &mut rng);
    let ct_b = encrypt(&tokens_b, &pk, &sk, &mut rng);

    // Both should verify
    assert!(ct_a.verify_integrity(&pk, &mac_key));
    assert!(ct_b.verify_integrity(&pk, &mac_key));

    // Nonces should be different (each encrypt() generates a fresh nonce)
    assert_ne!(
        ct_a.nonce, ct_b.nonce,
        "Nonces should differ between encryptions"
    );

    // Even with identical plaintexts, ciphertext coefficients differ
    // due to ephemeral randomness (u, e1, e2)
    assert_ne!(
        ct_a.chunks[0].0.coeffs, ct_b.chunks[0].0.coeffs,
        "Ciphertext coefficients should differ due to encryption randomness"
    );

    // Force nonce reuse: copy A's nonce into B and try to forge auth_tag
    let mut ct_b_reused = ct_b.clone();
    ct_b_reused.nonce = ct_a.nonce;
    let nonce = ct_a.nonce.unwrap();
    let key_id = ct_b_reused.key_id.unwrap();
    let forged_tag = attacker_compute_auth_tag(
        &ct_b_reused.chunks,
        ct_b_reused.token_count,
        ct_b_reused.scale,
        &nonce,
        &key_id,
    );
    ct_b_reused.auth_tag = Some(forged_tag);

    // HARDENED: forged tag without mac_key fails
    assert!(
        !ct_b_reused.verify_integrity(&pk, &mac_key),
        "HARDENED: nonce-reused ciphertext with forged auth_tag should fail"
    );

    // Both original ciphertexts still decrypt correctly
    assert_eq!(decrypt(&ct_a, &sk), tokens_a);
    assert_eq!(decrypt(&ct_b, &sk), tokens_b);

    eprintln!(
        "HARDENED: nonce reuse + auth forgery blocked by mac_key requirement"
    );
}

// =========================================================================
// ATTACK 3: AUTH TAG STRIPPING
// =========================================================================

/// Strip all authentication fields. verify_integrity() should reject.
#[test]
fn attack_auth_tag_stripping() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let mac_key = derive_mac_key(&sk);

    let tokens = vec![42, 43, 44];
    let mut ct = encrypt(&tokens, &pk, &sk, &mut rng);

    // Verify original passes
    assert!(ct.verify_integrity(&pk, &mac_key));

    // Strip all auth fields
    ct.auth_tag = None;
    ct.key_id = None;
    ct.nonce = None;

    // verify_integrity should reject unauthenticated ciphertext
    assert!(
        !ct.verify_integrity(&pk, &mac_key),
        "VULNERABILITY: stripped auth fields not detected"
    );

    // However, decrypt() does NOT check auth — it blindly decrypts
    let decrypted = decrypt(&ct, &sk);
    assert_eq!(
        decrypted, tokens,
        "decrypt() should still work (it does not verify auth)"
    );

    eprintln!(
        "AUTH STRIPPING: verify_integrity() correctly rejects. \
         But decrypt() does not enforce verification — caller must check."
    );
}

// =========================================================================
// ATTACK 4: PARTIAL AUTH FIELD ATTACKS
// =========================================================================

/// Partial auth fields: auth_tag present but key_id missing.
#[test]
fn attack_partial_auth_fields_missing_key_id() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let mac_key = derive_mac_key(&sk);

    let tokens = vec![10, 20, 30];
    let mut ct = encrypt(&tokens, &pk, &sk, &mut rng);
    assert!(ct.verify_integrity(&pk, &mac_key));

    // Keep auth_tag and nonce but strip key_id
    ct.key_id = None;

    assert!(
        !ct.verify_integrity(&pk, &mac_key),
        "VULNERABILITY: missing key_id not detected when auth_tag is present"
    );

    eprintln!("PARTIAL AUTH: missing key_id correctly rejected");
}

/// Partial auth fields: auth_tag present but nonce missing.
#[test]
fn attack_partial_auth_fields_missing_nonce() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let mac_key = derive_mac_key(&sk);

    let tokens = vec![10, 20, 30];
    let mut ct = encrypt(&tokens, &pk, &sk, &mut rng);
    assert!(ct.verify_integrity(&pk, &mac_key));

    // Keep auth_tag and key_id but strip nonce
    ct.nonce = None;

    assert!(
        !ct.verify_integrity(&pk, &mac_key),
        "VULNERABILITY: missing nonce not detected when auth_tag is present"
    );

    eprintln!("PARTIAL AUTH: missing nonce correctly rejected");
}

/// Partial auth fields: key_id and nonce present but auth_tag missing.
#[test]
fn attack_partial_auth_fields_missing_auth_tag() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let mac_key = derive_mac_key(&sk);

    let tokens = vec![10, 20, 30];
    let mut ct = encrypt(&tokens, &pk, &sk, &mut rng);
    assert!(ct.verify_integrity(&pk, &mac_key));

    // Strip only the auth_tag
    ct.auth_tag = None;

    assert!(
        !ct.verify_integrity(&pk, &mac_key),
        "VULNERABILITY: missing auth_tag not detected when key_id/nonce are present"
    );

    eprintln!("PARTIAL AUTH: missing auth_tag correctly rejected");
}

// =========================================================================
// ATTACK 5: SCALE OVERFLOW
//
// HARDENED: Attacker cannot forge auth_tag, so scale tampering is detected.
// =========================================================================

/// Scale overflow: set to i64::MAX. Auth forgery should fail.
#[test]
fn attack_scale_overflow_max() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let mac_key = derive_mac_key(&sk);

    let tokens = vec![42, 100, 999];
    let mut ct = encrypt(&tokens, &pk, &sk, &mut rng);

    // Tamper scale to i64::MAX
    ct.scale = i64::MAX;

    // Recompute auth tag WITHOUT mac_key
    let nonce = ct.nonce.unwrap();
    let key_id = ct.key_id.unwrap();
    let forged_tag = attacker_compute_auth_tag(
        &ct.chunks,
        ct.token_count,
        ct.scale,
        &nonce,
        &key_id,
    );
    ct.auth_tag = Some(forged_tag);

    // HARDENED: forged tag fails verification
    assert!(
        !ct.verify_integrity(&pk, &mac_key),
        "HARDENED: forged auth_tag for scale=i64::MAX should fail"
    );

    eprintln!(
        "HARDENED: scale overflow attack blocked — auth forgery without mac_key fails"
    );
}

/// Scale overflow: set to i64::MIN. Auth forgery should fail.
#[test]
fn attack_scale_overflow_min() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let mac_key = derive_mac_key(&sk);

    let tokens = vec![42, 100, 999];
    let mut ct = encrypt(&tokens, &pk, &sk, &mut rng);

    // Tamper scale to i64::MIN
    ct.scale = i64::MIN;

    let nonce = ct.nonce.unwrap();
    let key_id = ct.key_id.unwrap();
    let forged_tag = attacker_compute_auth_tag(
        &ct.chunks,
        ct.token_count,
        ct.scale,
        &nonce,
        &key_id,
    );
    ct.auth_tag = Some(forged_tag);

    // HARDENED: forged tag fails
    assert!(
        !ct.verify_integrity(&pk, &mac_key),
        "HARDENED: forged auth_tag for scale=i64::MIN should fail"
    );

    eprintln!(
        "HARDENED: scale overflow (MIN) attack blocked"
    );
}

/// Scale set to zero. Auth forgery should fail.
#[test]
fn attack_scale_zero() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let mac_key = derive_mac_key(&sk);

    let tokens = vec![42];
    let mut ct = encrypt(&tokens, &pk, &sk, &mut rng);

    ct.scale = 0;

    let nonce = ct.nonce.unwrap();
    let key_id = ct.key_id.unwrap();
    let forged_tag = attacker_compute_auth_tag(
        &ct.chunks,
        ct.token_count,
        ct.scale,
        &nonce,
        &key_id,
    );
    ct.auth_tag = Some(forged_tag);

    // HARDENED: forged tag fails
    assert!(
        !ct.verify_integrity(&pk, &mac_key),
        "HARDENED: forged auth_tag for scale=0 should fail"
    );

    eprintln!(
        "HARDENED: scale zero attack blocked"
    );
}

// =========================================================================
// ATTACK 6: CHUNK SWAPPING BETWEEN CIPHERTEXTS
//
// HARDENED: Chunk swap + auth forgery fails without mac_key.
// =========================================================================

/// Chunk swap: steal chunks from ciphertext A, place in B's auth context.
#[test]
fn attack_chunk_swap_between_ciphertexts() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let mac_key = derive_mac_key(&sk);

    let tokens_a = vec![100, 200, 300];
    let tokens_b = vec![400, 500, 600];

    let ct_a = encrypt(&tokens_a, &pk, &sk, &mut rng);
    let ct_b = encrypt(&tokens_b, &pk, &sk, &mut rng);

    assert!(ct_a.verify_integrity(&pk, &mac_key));
    assert!(ct_b.verify_integrity(&pk, &mac_key));

    // Attacker takes A's chunks but uses B's nonce/key_id
    let nonce_b = ct_b.nonce.unwrap();
    let key_id_b = ct_b.key_id.unwrap();

    let forged_tag = attacker_compute_auth_tag(
        &ct_a.chunks,          // A's encrypted data
        ct_a.token_count,      // A's token count
        ct_a.scale,            // A's scale
        &nonce_b,              // B's nonce
        &key_id_b,             // B's key_id (same key, so same key_id)
    );

    let franken_ct = CkksCiphertext {
        chunks: ct_a.chunks.clone(),
        token_count: ct_a.token_count,
        scale: ct_a.scale,
        auth_tag: Some(forged_tag),
        key_id: Some(key_id_b),
        nonce: Some(nonce_b),
    };

    // HARDENED: The Frankenstein ciphertext fails verify_integrity
    assert!(
        !franken_ct.verify_integrity(&pk, &mac_key),
        "HARDENED: chunk-swapped ciphertext with forged auth_tag should fail"
    );

    eprintln!(
        "HARDENED: chunk swap attack blocked — auth forgery without mac_key fails"
    );
}

// =========================================================================
// ATTACK 7: ZERO-COEFFICIENT CIPHERTEXT
//
// HARDENED: Auth forgery fails without mac_key.
// =========================================================================

/// Zero out all ciphertext coefficients and attempt to forge auth_tag.
#[test]
fn attack_zero_coefficient_ciphertext() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let mac_key = derive_mac_key(&sk);

    let tokens = vec![100, 200, 300, 400, 500];
    let mut ct = encrypt(&tokens, &pk, &sk, &mut rng);
    assert!(ct.verify_integrity(&pk, &mac_key));

    // Zero out all coefficients
    for chunk in &mut ct.chunks {
        chunk.0 = Poly::zero();
        chunk.1 = Poly::zero();
    }

    // Without recomputing auth_tag, verification should fail
    assert!(
        !ct.verify_integrity(&pk, &mac_key),
        "Zeroed ciphertext should fail integrity with original auth_tag"
    );

    // Attacker recomputes auth_tag WITHOUT mac_key
    let nonce = ct.nonce.unwrap();
    let key_id = ct.key_id.unwrap();
    let forged_tag = attacker_compute_auth_tag(
        &ct.chunks,
        ct.token_count,
        ct.scale,
        &nonce,
        &key_id,
    );
    ct.auth_tag = Some(forged_tag);

    // HARDENED: forged tag fails
    assert!(
        !ct.verify_integrity(&pk, &mac_key),
        "HARDENED: zeroed ciphertext with forged auth_tag should fail"
    );

    eprintln!(
        "HARDENED: zero-coefficient attack blocked — auth forgery without mac_key fails"
    );
}

// =========================================================================
// ATTACK 8: FULL AUTH TAG FORGERY WITHOUT SECRET KEY (CRITICAL)
//
// HARDENED: The auth_tag now includes mac_key derived from the secret key.
// An attacker without the secret key CANNOT forge valid auth_tags.
// =========================================================================

/// HARDENED: Full demonstration that auth_tag can NO LONGER be forged
/// without secret material. The attacker's recomputed tag doesn't match.
#[test]
fn attack_full_auth_tag_forgery_no_secret_key() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let mac_key = derive_mac_key(&sk);

    // Step 1: Legitimate encryption
    let original_tokens = vec![42, 100, 255, 1000, 50000];
    let ct = encrypt(&original_tokens, &pk, &sk, &mut rng);

    // Verify the original ciphertext is valid
    assert!(ct.verify_integrity(&pk, &mac_key));
    assert_eq!(decrypt(&ct, &sk), original_tokens);

    // Step 2: Attacker intercepts and tampers with a coefficient
    let mut tampered = ct.clone();
    let original_coeff = tampered.chunks[0].0.coeffs[0];
    tampered.chunks[0].0.coeffs[0] = {
        let v = original_coeff as i128 + DELTA as i128;
        let q = 18014398509481951i128; // Q
        let mut r = v % q;
        if r > q / 2 { r -= q; }
        if r < -(q / 2) { r += q; }
        r as i64
    };

    // Step 3: Attacker reads public fields from the ciphertext
    let nonce = tampered.nonce.unwrap();     // publicly visible
    let key_id = tampered.key_id.unwrap();   // publicly visible
    let token_count = tampered.token_count;  // publicly visible
    let scale = tampered.scale;              // publicly visible

    // Step 4: Attacker recomputes auth_tag WITHOUT mac_key
    let forged_tag = {
        let mut hasher = Sha256::new();
        hasher.update(b"ckks_auth_v1");      // domain separator (public/hardcoded)
        // NOTE: attacker does NOT have mac_key!
        hasher.update(key_id);               // from ciphertext (public)
        hasher.update(nonce);                // from ciphertext (public)
        hasher.update((token_count as u64).to_le_bytes()); // from ciphertext (public)
        hasher.update(scale.to_le_bytes());  // from ciphertext (public)
        for (c0, c1) in &tampered.chunks {
            for c in &c0.coeffs {
                hasher.update(c.to_le_bytes()); // from ciphertext (public)
            }
            for c in &c1.coeffs {
                hasher.update(c.to_le_bytes()); // from ciphertext (public)
            }
        }
        let result: [u8; 32] = hasher.finalize().into();
        result
    };

    // Step 5: Replace auth_tag with the forged one
    tampered.auth_tag = Some(forged_tag);

    // HARDENED: verify_integrity() rejects! Attacker doesn't know mac_key.
    assert!(
        !tampered.verify_integrity(&pk, &mac_key),
        "HARDENED: auth_tag forgery without mac_key should be detected"
    );

    eprintln!("========================================================");
    eprintln!("HARDENED: AUTH TAG FORGERY WITHOUT SECRET KEY NOW BLOCKED");
    eprintln!("========================================================");
    eprintln!("The auth_tag now includes mac_key = SHA-256(secret_key).");
    eprintln!("Attacker cannot recompute valid auth_tags without the secret.");
    eprintln!("========================================================");
}

/// HARDENED: Attacker cannot fabricate a ciphertext from scratch with valid auth.
#[test]
fn attack_fabricate_ciphertext_from_scratch() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let mac_key = derive_mac_key(&sk);

    // Attacker knows the public key (it's public!)
    let key_id = compute_key_id(&pk);

    // Attacker generates their own nonce
    let nonce: [u8; 16] = [0xAA; 16]; // arbitrary

    // Attacker creates a zero ciphertext
    let fake_chunks = vec![(Poly::zero(), Poly::zero())];
    let fake_token_count = 3;
    let fake_scale = DELTA;

    // Attacker computes auth_tag WITHOUT mac_key
    let auth_tag = attacker_compute_auth_tag(
        &fake_chunks,
        fake_token_count,
        fake_scale,
        &nonce,
        &key_id,
    );

    let fabricated = CkksCiphertext {
        chunks: fake_chunks,
        token_count: fake_token_count,
        scale: fake_scale,
        auth_tag: Some(auth_tag),
        key_id: Some(key_id),
        nonce: Some(nonce),
    };

    // HARDENED: Fabricated ciphertext fails verify_integrity
    assert!(
        !fabricated.verify_integrity(&pk, &mac_key),
        "HARDENED: fabricated ciphertext without mac_key should fail"
    );

    eprintln!(
        "HARDENED: ciphertext fabrication blocked — mac_key required for valid auth_tag"
    );
}

// =========================================================================
// ATTACK 9: KEY ID COLLISION
// =========================================================================

/// Key ID collision test: different public keys should have different key_ids.
#[test]
fn attack_key_id_collision() {
    let mut seen_ids: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();

    // Generate 50 key pairs with different seeds
    for seed in 0..50u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let (pk, _sk) = keygen(&mut rng);
        let kid = compute_key_id(&pk);

        let is_new = seen_ids.insert(kid);
        assert!(
            is_new,
            "KEY ID COLLISION: seed {} produced a key_id that already exists! \
             This would allow key confusion attacks.",
            seed
        );
    }

    assert_eq!(seen_ids.len(), 50);

    eprintln!(
        "KEY ID COLLISION: 50 unique keys produced 50 unique key_ids. \
         No collisions found (expected for SHA-256)."
    );
}

/// Key ID determinism: same public key always produces the same key_id.
#[test]
fn attack_key_id_determinism() {
    let mut rng = test_rng();
    let (pk, _sk) = keygen(&mut rng);

    let kid1 = compute_key_id(&pk);
    let kid2 = compute_key_id(&pk);

    assert_eq!(
        kid1, kid2,
        "Same public key should always produce the same key_id"
    );
}

// =========================================================================
// ATTACK 10: SERIALIZATION MANIPULATION
//
// HARDENED: Deserialization + tampering + auth forgery fails without mac_key.
// =========================================================================

/// Serialization attack: deserialize, tamper, re-serialize with forged auth.
#[test]
fn attack_serialization_manipulation() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let mac_key = derive_mac_key(&sk);

    let tokens = vec![10, 20, 30, 40, 50];
    let ct = encrypt(&tokens, &pk, &sk, &mut rng);

    // Serialize to JSON
    let json = serde_json::to_string(&ct).unwrap();

    // Deserialize
    let mut ct2: CkksCiphertext = serde_json::from_str(&json).unwrap();

    // Verify it's valid after deserialization
    assert!(ct2.verify_integrity(&pk, &mac_key));
    assert_eq!(decrypt(&ct2, &sk), tokens);

    // Attacker modifies a coefficient via the deserialized struct
    ct2.chunks[0].0.coeffs[2] += DELTA; // shift one token by +1

    // Without forging auth_tag, verification fails (good baseline)
    assert!(
        !ct2.verify_integrity(&pk, &mac_key),
        "Tampered ciphertext should fail with original auth_tag"
    );

    // Attacker forges the auth_tag WITHOUT mac_key
    let nonce = ct2.nonce.unwrap();
    let key_id = ct2.key_id.unwrap();
    let forged_tag = attacker_compute_auth_tag(
        &ct2.chunks,
        ct2.token_count,
        ct2.scale,
        &nonce,
        &key_id,
    );
    ct2.auth_tag = Some(forged_tag);

    // HARDENED: forged tag fails
    assert!(
        !ct2.verify_integrity(&pk, &mac_key),
        "HARDENED: serialization-tampered ciphertext with forged auth should fail"
    );

    eprintln!(
        "HARDENED: serialization manipulation attack blocked — mac_key required"
    );
}

/// Serialization: auth_tag bytes survive JSON roundtrip unchanged.
#[test]
fn attack_serialization_auth_tag_preserved() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);

    let ct = encrypt(&[1, 2, 3], &pk, &sk, &mut rng);
    let original_tag = ct.auth_tag.unwrap();
    let original_nonce = ct.nonce.unwrap();
    let original_key_id = ct.key_id.unwrap();

    let json = serde_json::to_string(&ct).unwrap();
    let ct2: CkksCiphertext = serde_json::from_str(&json).unwrap();

    assert_eq!(ct2.auth_tag.unwrap(), original_tag);
    assert_eq!(ct2.nonce.unwrap(), original_nonce);
    assert_eq!(ct2.key_id.unwrap(), original_key_id);
}

// =========================================================================
// BONUS: COMBINED ATTACKS
// =========================================================================

/// Combined attack: tamper multiple fields simultaneously and forge auth.
#[test]
fn attack_combined_multi_field_tampering() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let mac_key = derive_mac_key(&sk);

    let tokens = vec![100, 200, 300, 400, 500];
    let mut ct = encrypt(&tokens, &pk, &sk, &mut rng);
    assert!(ct.verify_integrity(&pk, &mac_key));

    // Tamper with EVERYTHING: coefficients, token_count, scale
    ct.chunks[0].0.coeffs[0] = 0;
    ct.chunks[0].0.coeffs[1] = 0;
    ct.chunks[0].1.coeffs[0] = 0;
    ct.token_count = 2;
    ct.scale = DELTA * 2;

    // Forge auth_tag WITHOUT mac_key
    let nonce = ct.nonce.unwrap();
    let key_id = ct.key_id.unwrap();
    let forged_tag = attacker_compute_auth_tag(
        &ct.chunks,
        ct.token_count,
        ct.scale,
        &nonce,
        &key_id,
    );
    ct.auth_tag = Some(forged_tag);

    // HARDENED: forged tag fails
    assert!(
        !ct.verify_integrity(&pk, &mac_key),
        "HARDENED: multi-field tampered ciphertext with forged auth should fail"
    );

    eprintln!(
        "HARDENED: combined multi-field attack blocked"
    );
}

/// Attack: replace nonce to defeat replay tracking while keeping valid auth.
#[test]
fn attack_nonce_replacement_defeats_replay_tracking() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);
    let mac_key = derive_mac_key(&sk);

    let tokens = vec![42, 43, 44];
    let ct = encrypt(&tokens, &pk, &sk, &mut rng);
    let original_nonce = ct.nonce.unwrap();
    assert!(ct.verify_integrity(&pk, &mac_key));

    // Attacker replaces the nonce to defeat server-side replay tracking
    let new_nonce: [u8; 16] = [0xFF; 16];
    assert_ne!(original_nonce, new_nonce);

    let key_id = ct.key_id.unwrap();
    let forged_tag = attacker_compute_auth_tag(
        &ct.chunks,
        ct.token_count,
        ct.scale,
        &new_nonce,
        &key_id,
    );

    let replayed = CkksCiphertext {
        chunks: ct.chunks.clone(),
        token_count: ct.token_count,
        scale: ct.scale,
        auth_tag: Some(forged_tag),
        key_id: Some(key_id),
        nonce: Some(new_nonce),
    };

    // HARDENED: nonce replacement with forged auth fails
    assert!(
        !replayed.verify_integrity(&pk, &mac_key),
        "HARDENED: nonce-replaced ciphertext with forged auth should fail"
    );

    eprintln!(
        "HARDENED: replay bypass blocked — auth forgery without mac_key fails"
    );
}
