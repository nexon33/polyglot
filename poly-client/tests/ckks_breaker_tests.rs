//! CKKS ciphertext authentication breaker tests.
//!
//! These tests attempt to BREAK the hardened CKKS ciphertext authentication
//! system. They probe for real vulnerabilities in the auth_tag scheme,
//! particularly the critical finding that compute_auth_tag uses NO secret
//! material — making it a checksum, not a MAC.
//!
//! ## Critical vulnerability demonstrated
//!
//! The auth_tag is SHA-256(key_id || nonce || token_count || scale || chunks).
//! ALL of these inputs are publicly visible in the serialized ciphertext.
//! This means ANY observer can:
//!   1. Tamper with ciphertext data
//!   2. Recompute a valid auth_tag from the tampered data
//!   3. Pass verify_integrity() with the forged tag
//!
//! The auth_tag provides INTEGRITY against accidental corruption but NOT
//! AUTHENTICITY against an active attacker who can read the ciphertext.

#![cfg(feature = "ckks")]

use poly_client::ckks::ciphertext::{compute_key_id, decrypt, encrypt, CkksCiphertext};
use poly_client::ckks::keys::keygen;
use poly_client::ckks::params::DELTA;
use poly_client::ckks::poly::Poly;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

fn test_rng() -> StdRng {
    StdRng::seed_from_u64(42)
}

/// Attacker's local reimplementation of compute_auth_tag.
///
/// This function replicates the exact algorithm used internally by the
/// ciphertext module. An attacker can derive this from:
///   - Reading the source code (open source)
///   - Reverse-engineering the binary
///   - Observing input/output pairs
///
/// All inputs (chunks, token_count, scale, nonce, key_id) are publicly
/// visible in the serialized CkksCiphertext.
fn attacker_compute_auth_tag(
    chunks: &[(Poly, Poly)],
    token_count: usize,
    scale: i64,
    nonce: &[u8; 16],
    key_id: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ckks_auth_v1");
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
// CRITICAL VULNERABILITY: The auth_tag uses only public information.
// An attacker who sees the ciphertext can tamper with token_count,
// recompute a valid auth_tag, and pass verify_integrity().
// =========================================================================

/// CRITICAL VULNERABILITY: Tamper with token_count and recompute a valid
/// auth_tag using only publicly visible fields. verify_integrity() passes.
#[test]
fn attack_auth_tag_recomputation_token_count_tamper() {
    let mut rng = test_rng();
    let (pk, _sk) = keygen(&mut rng);

    let tokens = vec![100, 200, 300, 400, 500];
    let mut ct = encrypt(&tokens, &pk, &mut rng);

    // Verify original is valid
    assert!(ct.verify_integrity(&pk));
    assert_eq!(ct.token_count, 5);

    // --- Attacker reads all public fields ---
    let nonce = ct.nonce.unwrap();
    let key_id = ct.key_id.unwrap();

    // --- Attacker tampers with token_count ---
    ct.token_count = 2;

    // Without recomputing auth_tag, verification fails (good)
    assert!(!ct.verify_integrity(&pk));

    // --- Attacker recomputes auth_tag with tampered data ---
    let forged_tag = attacker_compute_auth_tag(
        &ct.chunks,
        ct.token_count, // tampered value: 2
        ct.scale,
        &nonce,
        &key_id,
    );
    ct.auth_tag = Some(forged_tag);

    // VULNERABILITY: verify_integrity() now passes with forged tag!
    assert!(
        ct.verify_integrity(&pk),
        "UNEXPECTED: auth_tag recomputation attack failed \
         (this would mean the auth scheme uses secret material after all)"
    );

    eprintln!(
        "CRITICAL VULNERABILITY CONFIRMED: attacker tampered token_count \
         from 5 to 2 and forged a valid auth_tag without any secret key"
    );
}

// =========================================================================
// ATTACK 2: NONCE REUSE — CAN AN ATTACKER DETECT IDENTICAL PLAINTEXTS?
//
// If the same nonce is forced into two ciphertexts encrypting identical
// plaintexts with the same key, the auth_tags will match only if the
// ciphertext polynomial coefficients also match. Due to encryption
// randomness (ephemeral u, e1, e2), coefficients differ even with the
// same nonce, so auth_tags will differ. However, the nonce field itself
// is public — an attacker can observe nonce reuse.
// =========================================================================

/// Nonce reuse test: if two ciphertexts share a nonce, can an attacker
/// detect whether they encrypt the same plaintext?
#[test]
fn attack_nonce_reuse_detection() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);

    let tokens_a = vec![100, 200, 300];
    let tokens_b = vec![100, 200, 300]; // same plaintext

    let ct_a = encrypt(&tokens_a, &pk, &mut rng);
    let ct_b = encrypt(&tokens_b, &pk, &mut rng);

    // Both should verify
    assert!(ct_a.verify_integrity(&pk));
    assert!(ct_b.verify_integrity(&pk));

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

    // Force nonce reuse: copy A's nonce into B and recompute auth_tag
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

    // With reused nonce and recomputed tag, it still verifies
    assert!(
        ct_b_reused.verify_integrity(&pk),
        "Nonce-reused ciphertext with recomputed auth_tag should verify"
    );

    // Auth tags still differ because ciphertext coefficients differ
    assert_ne!(
        ct_a.auth_tag, ct_b_reused.auth_tag,
        "Even with same nonce, auth tags differ due to different ciphertext coefficients"
    );

    // Both decrypt correctly
    assert_eq!(decrypt(&ct_a, &sk), tokens_a);
    assert_eq!(decrypt(&ct_b_reused, &sk), tokens_b);

    eprintln!(
        "NONCE REUSE: identical plaintexts produce different auth_tags even with \
         same nonce (ciphertext randomness protects). But nonce reuse itself is \
         observable and should be tracked server-side."
    );
}

// =========================================================================
// ATTACK 3: AUTH TAG STRIPPING
//
// Set auth_tag, key_id, and nonce to None. Does verify_integrity reject?
// =========================================================================

/// Strip all authentication fields. verify_integrity() should reject.
#[test]
fn attack_auth_tag_stripping() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);

    let tokens = vec![42, 43, 44];
    let mut ct = encrypt(&tokens, &pk, &mut rng);

    // Verify original passes
    assert!(ct.verify_integrity(&pk));

    // Strip all auth fields
    ct.auth_tag = None;
    ct.key_id = None;
    ct.nonce = None;

    // verify_integrity should reject unauthenticated ciphertext
    assert!(
        !ct.verify_integrity(&pk),
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
// ATTACK 4: PARTIAL AUTH FIELD ATTACK
//
// Set auth_tag to Some but key_id or nonce to None. Does verify_integrity
// handle the inconsistent state correctly?
// =========================================================================

/// Partial auth fields: auth_tag present but key_id missing.
#[test]
fn attack_partial_auth_fields_missing_key_id() {
    let mut rng = test_rng();
    let (pk, _sk) = keygen(&mut rng);

    let tokens = vec![10, 20, 30];
    let mut ct = encrypt(&tokens, &pk, &mut rng);
    assert!(ct.verify_integrity(&pk));

    // Keep auth_tag and nonce but strip key_id
    ct.key_id = None;

    assert!(
        !ct.verify_integrity(&pk),
        "VULNERABILITY: missing key_id not detected when auth_tag is present"
    );

    eprintln!("PARTIAL AUTH: missing key_id correctly rejected");
}

/// Partial auth fields: auth_tag present but nonce missing.
#[test]
fn attack_partial_auth_fields_missing_nonce() {
    let mut rng = test_rng();
    let (pk, _sk) = keygen(&mut rng);

    let tokens = vec![10, 20, 30];
    let mut ct = encrypt(&tokens, &pk, &mut rng);
    assert!(ct.verify_integrity(&pk));

    // Keep auth_tag and key_id but strip nonce
    ct.nonce = None;

    assert!(
        !ct.verify_integrity(&pk),
        "VULNERABILITY: missing nonce not detected when auth_tag is present"
    );

    eprintln!("PARTIAL AUTH: missing nonce correctly rejected");
}

/// Partial auth fields: key_id and nonce present but auth_tag missing.
#[test]
fn attack_partial_auth_fields_missing_auth_tag() {
    let mut rng = test_rng();
    let (pk, _sk) = keygen(&mut rng);

    let tokens = vec![10, 20, 30];
    let mut ct = encrypt(&tokens, &pk, &mut rng);
    assert!(ct.verify_integrity(&pk));

    // Strip only the auth_tag
    ct.auth_tag = None;

    assert!(
        !ct.verify_integrity(&pk),
        "VULNERABILITY: missing auth_tag not detected when key_id/nonce are present"
    );

    eprintln!("PARTIAL AUTH: missing auth_tag correctly rejected");
}

// =========================================================================
// ATTACK 5: SCALE OVERFLOW
//
// Set scale to i64::MAX or i64::MIN. Does anything panic?
// =========================================================================

/// Scale overflow: set to i64::MAX. Should not panic.
#[test]
fn attack_scale_overflow_max() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);

    let tokens = vec![42, 100, 999];
    let mut ct = encrypt(&tokens, &pk, &mut rng);

    // Tamper scale to i64::MAX
    ct.scale = i64::MAX;

    // Recompute auth tag so verify_integrity passes (demonstrating the vuln)
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

    // Should not panic on verify
    assert!(
        ct.verify_integrity(&pk),
        "Forged auth_tag for scale=i64::MAX should pass verify_integrity"
    );

    // Decrypt with extreme scale should not panic (may produce wrong results)
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        decrypt(&ct, &sk)
    }));
    assert!(
        result.is_ok(),
        "VULNERABILITY: decrypt panics with scale=i64::MAX"
    );

    eprintln!(
        "SCALE OVERFLOW (MAX): no panic. Decryption produces garbage but does not crash."
    );
}

/// Scale overflow: set to i64::MIN. Should not panic.
#[test]
fn attack_scale_overflow_min() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);

    let tokens = vec![42, 100, 999];
    let mut ct = encrypt(&tokens, &pk, &mut rng);

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

    assert!(
        ct.verify_integrity(&pk),
        "Forged auth_tag for scale=i64::MIN should pass verify_integrity"
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        decrypt(&ct, &sk)
    }));
    assert!(
        result.is_ok(),
        "VULNERABILITY: decrypt panics with scale=i64::MIN"
    );

    eprintln!(
        "SCALE OVERFLOW (MIN): no panic. Decryption produces garbage but does not crash."
    );
}

/// Scale set to zero. Division by zero in decoding could panic.
#[test]
fn attack_scale_zero() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);

    let tokens = vec![42];
    let mut ct = encrypt(&tokens, &pk, &mut rng);

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

    assert!(
        ct.verify_integrity(&pk),
        "Forged auth_tag for scale=0 should pass verify_integrity"
    );

    // decrypt() does not use ct.scale (decode uses DELTA directly),
    // so this should not panic. But it demonstrates the auth bypass.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        decrypt(&ct, &sk)
    }));
    assert!(
        result.is_ok(),
        "decrypt panics with scale=0"
    );

    eprintln!(
        "SCALE ZERO: auth_tag forged successfully. decrypt() does not use ct.scale \
         for basic decryption (it uses the DELTA constant), so no immediate crash."
    );
}

// =========================================================================
// ATTACK 6: CHUNK SWAPPING BETWEEN CIPHERTEXTS
//
// Take chunks from ciphertext A, put them in B's structure with B's
// auth fields, and recompute the auth_tag.
// =========================================================================

/// Chunk swap: steal chunks from ciphertext A, place in B's auth context.
#[test]
fn attack_chunk_swap_between_ciphertexts() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);

    let tokens_a = vec![100, 200, 300];
    let tokens_b = vec![400, 500, 600];

    let ct_a = encrypt(&tokens_a, &pk, &mut rng);
    let ct_b = encrypt(&tokens_b, &pk, &mut rng);

    assert!(ct_a.verify_integrity(&pk));
    assert!(ct_b.verify_integrity(&pk));

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

    // VULNERABILITY: The Frankenstein ciphertext passes verify_integrity
    // because the attacker can recompute a valid auth_tag
    assert!(
        franken_ct.verify_integrity(&pk),
        "UNEXPECTED: chunk-swapped ciphertext with recomputed auth_tag should verify"
    );

    // It decrypts to A's plaintext (the stolen chunks)
    let decrypted = decrypt(&franken_ct, &sk);
    assert_eq!(
        decrypted, tokens_a,
        "Chunk-swapped ciphertext should decrypt to source ciphertext's plaintext"
    );

    eprintln!(
        "CHUNK SWAP VULNERABILITY: attacker swapped chunks from ct_a into ct_b's \
         auth context, recomputed auth_tag, and verify_integrity() passed. \
         Decrypted to ct_a's plaintext: {:?}",
        decrypted
    );
}

// =========================================================================
// ATTACK 7: ZERO-COEFFICIENT CIPHERTEXT
//
// Encrypt tokens, then zero out all coefficients and recompute auth_tag.
// =========================================================================

/// Zero out all ciphertext coefficients and forge a valid auth_tag.
#[test]
fn attack_zero_coefficient_ciphertext() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);

    let tokens = vec![100, 200, 300, 400, 500];
    let mut ct = encrypt(&tokens, &pk, &mut rng);
    assert!(ct.verify_integrity(&pk));

    // Zero out all coefficients
    for chunk in &mut ct.chunks {
        chunk.0 = Poly::zero();
        chunk.1 = Poly::zero();
    }

    // Without recomputing auth_tag, verification should fail
    assert!(
        !ct.verify_integrity(&pk),
        "Zeroed ciphertext should fail integrity with original auth_tag"
    );

    // Attacker recomputes auth_tag for the zeroed ciphertext
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

    // VULNERABILITY: verify_integrity passes with forged tag
    assert!(
        ct.verify_integrity(&pk),
        "UNEXPECTED: zeroed ciphertext with recomputed auth_tag should verify"
    );

    // Decrypts to all zeros instead of original tokens
    let decrypted = decrypt(&ct, &sk);
    assert_eq!(
        decrypted,
        vec![0, 0, 0, 0, 0],
        "Zeroed ciphertext should decrypt to zeros"
    );
    assert_ne!(decrypted, tokens);

    eprintln!(
        "ZERO-COEFF VULNERABILITY: attacker zeroed all ciphertext coefficients, \
         forged auth_tag, and verify_integrity() passed. \
         Original: {:?}, Decrypted: {:?}",
        tokens, decrypted
    );
}

// =========================================================================
// ATTACK 8: FULL AUTH TAG FORGERY WITHOUT SECRET KEY (CRITICAL)
//
// This is the most important test. It demonstrates the complete attack:
//   1. Encrypt a message normally
//   2. Tamper with a ciphertext coefficient (active attack)
//   3. Read nonce and key_id from the (public) ciphertext
//   4. Recompute a valid auth_tag using SHA-256
//   5. Show verify_integrity() passes with the forged tag
//
// This proves the auth_tag is a checksum, NOT a MAC.
// =========================================================================

/// CRITICAL: Full demonstration that auth_tag can be forged without
/// any secret material. The auth_tag is SHA-256 over entirely public data.
#[test]
fn attack_full_auth_tag_forgery_no_secret_key() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);

    // Step 1: Legitimate encryption
    let original_tokens = vec![42, 100, 255, 1000, 50000];
    let ct = encrypt(&original_tokens, &pk, &mut rng);

    // Verify the original ciphertext is valid
    assert!(ct.verify_integrity(&pk));
    assert_eq!(decrypt(&ct, &sk), original_tokens);

    // Step 2: Attacker intercepts and tampers with a coefficient
    let mut tampered = ct.clone();
    // Add a full DELTA to coefficient 0 — this shifts the decoded token by +1.
    // Using mod_reduce-safe arithmetic: adding DELTA to the encoded value
    // c0[0] means the decoded token at index 0 goes from 42 to 43.
    let original_coeff = tampered.chunks[0].0.coeffs[0];
    tampered.chunks[0].0.coeffs[0] = {
        // Add DELTA (one full encoding unit) to guarantee a token shift
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

    // Step 4: Attacker recomputes auth_tag using only public information
    // No secret key, no private key, nothing secret whatsoever
    let forged_tag = {
        let mut hasher = Sha256::new();
        hasher.update(b"ckks_auth_v1");      // domain separator (public/hardcoded)
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

    // CRITICAL VULNERABILITY: verify_integrity() passes!
    assert!(
        tampered.verify_integrity(&pk),
        "CRITICAL FAILURE: This should demonstrate that auth_tag forgery works. \
         If this assertion fails, it means the auth scheme has been upgraded to use \
         secret material (which would be good!)."
    );

    // The tampered ciphertext decrypts to corrupted data
    let tampered_decrypted = decrypt(&tampered, &sk);
    assert_ne!(
        tampered_decrypted, original_tokens,
        "Tampered ciphertext should decrypt to different tokens"
    );

    eprintln!("========================================================");
    eprintln!("CRITICAL VULNERABILITY: AUTH TAG FORGERY WITHOUT SECRET KEY");
    eprintln!("========================================================");
    eprintln!("Original tokens:  {:?}", original_tokens);
    eprintln!("Tampered decrypt: {:?}", tampered_decrypted);
    eprintln!("verify_integrity() passed with forged auth_tag!");
    eprintln!();
    eprintln!("The auth_tag is SHA-256(public_data) — a checksum, not a MAC.");
    eprintln!("Any observer can forge valid auth_tags for tampered ciphertexts.");
    eprintln!();
    eprintln!("FIX: Use HMAC-SHA256 with a shared secret, or include the secret");
    eprintln!("key (or a key-derived value) in the auth_tag computation.");
    eprintln!("========================================================");
}

/// CRITICAL: Demonstrate the attack in the other direction — attacker
/// creates a completely fabricated ciphertext from scratch with valid auth.
#[test]
fn attack_fabricate_ciphertext_from_scratch() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);

    // Attacker knows the public key (it's public!)
    let key_id = compute_key_id(&pk);

    // Attacker generates their own nonce
    let nonce: [u8; 16] = [0xAA; 16]; // arbitrary

    // Attacker creates a zero ciphertext (encrypts "nothing" / all zeros)
    let fake_chunks = vec![(Poly::zero(), Poly::zero())];
    let fake_token_count = 3;
    let fake_scale = DELTA;

    // Attacker computes a valid auth_tag
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

    // VULNERABILITY: Fabricated ciphertext passes verify_integrity!
    assert!(
        fabricated.verify_integrity(&pk),
        "Fabricated-from-scratch ciphertext should pass verify_integrity"
    );

    // It decrypts to zeros (not meaningful, but the auth check passed)
    let decrypted = decrypt(&fabricated, &sk);
    assert_eq!(decrypted, vec![0, 0, 0]);

    eprintln!(
        "FABRICATION VULNERABILITY: attacker created a ciphertext from scratch \
         (not from encrypt()) with a valid auth_tag. verify_integrity() passed."
    );
}

// =========================================================================
// ATTACK 9: KEY ID COLLISION
//
// Can two different public keys produce the same key_id?
// With SHA-256, collisions are computationally infeasible, but we test
// that different keys produce different key_ids.
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
// Deserialize a ciphertext from JSON, modify fields, re-serialize.
// The auth_tag in the JSON is just a byte array — it survives unchanged
// through serde roundtrips, so modifications are trivially detected...
// unless the attacker also updates the auth_tag.
// =========================================================================

/// Serialization attack: deserialize, tamper, re-serialize with forged auth.
#[test]
fn attack_serialization_manipulation() {
    let mut rng = test_rng();
    let (pk, sk) = keygen(&mut rng);

    let tokens = vec![10, 20, 30, 40, 50];
    let ct = encrypt(&tokens, &pk, &mut rng);

    // Serialize to JSON
    let json = serde_json::to_string(&ct).unwrap();

    // Deserialize
    let mut ct2: CkksCiphertext = serde_json::from_str(&json).unwrap();

    // Verify it's valid after deserialization
    assert!(ct2.verify_integrity(&pk));
    assert_eq!(decrypt(&ct2, &sk), tokens);

    // Attacker modifies a coefficient via the deserialized struct
    ct2.chunks[0].0.coeffs[2] += DELTA; // shift one token by +1

    // Without forging auth_tag, verification fails (good baseline)
    assert!(
        !ct2.verify_integrity(&pk),
        "Tampered ciphertext should fail with original auth_tag"
    );

    // Attacker forges the auth_tag
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

    // VULNERABILITY: passes after forgery
    assert!(
        ct2.verify_integrity(&pk),
        "Serialization-tampered ciphertext with forged auth should pass"
    );

    // Re-serialize the tampered ciphertext
    let tampered_json = serde_json::to_string(&ct2).unwrap();
    let ct3: CkksCiphertext = serde_json::from_str(&tampered_json).unwrap();

    // Still passes after another roundtrip
    assert!(ct3.verify_integrity(&pk));

    // Decrypts to modified data
    let decrypted = decrypt(&ct3, &sk);
    assert_ne!(decrypted, tokens);
    // The coefficient at index 2 was shifted by DELTA, so token at index 2
    // should be off by 1
    assert_eq!(
        decrypted[2],
        tokens[2] + 1,
        "Token at index 2 should be shifted by +1 (added DELTA to coefficient)"
    );

    eprintln!(
        "SERIALIZATION ATTACK: deserialized, tampered coeff[2] (+DELTA), \
         forged auth_tag, re-serialized. verify_integrity() passed. \
         Token[2] changed from {} to {}.",
        tokens[2], decrypted[2]
    );
}

/// Serialization: auth_tag bytes survive JSON roundtrip unchanged.
#[test]
fn attack_serialization_auth_tag_preserved() {
    let mut rng = test_rng();
    let (pk, _sk) = keygen(&mut rng);

    let ct = encrypt(&[1, 2, 3], &pk, &mut rng);
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
    let (pk, _sk) = keygen(&mut rng);

    let tokens = vec![100, 200, 300, 400, 500];
    let mut ct = encrypt(&tokens, &pk, &mut rng);
    assert!(ct.verify_integrity(&pk));

    // Tamper with EVERYTHING: coefficients, token_count, scale
    ct.chunks[0].0.coeffs[0] = 0;
    ct.chunks[0].0.coeffs[1] = 0;
    ct.chunks[0].1.coeffs[0] = 0;
    ct.token_count = 2;
    ct.scale = DELTA * 2;

    // Forge auth_tag for all the tampered data
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

    // VULNERABILITY: passes with massively tampered data
    assert!(
        ct.verify_integrity(&pk),
        "Multi-field tampered ciphertext with forged auth should pass"
    );

    eprintln!(
        "COMBINED ATTACK: tampered coefficients, token_count, and scale \
         simultaneously. Forged auth_tag. verify_integrity() passed."
    );
}

/// Attack: replace nonce to defeat replay tracking while keeping valid auth.
#[test]
fn attack_nonce_replacement_defeats_replay_tracking() {
    let mut rng = test_rng();
    let (pk, _sk) = keygen(&mut rng);

    let tokens = vec![42, 43, 44];
    let ct = encrypt(&tokens, &pk, &mut rng);
    let original_nonce = ct.nonce.unwrap();
    assert!(ct.verify_integrity(&pk));

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

    // VULNERABILITY: ciphertext with replaced nonce passes verify_integrity
    assert!(
        replayed.verify_integrity(&pk),
        "Nonce-replaced ciphertext with forged auth should pass"
    );

    eprintln!(
        "REPLAY BYPASS: attacker replaced nonce {:?} with {:?}, \
         forged auth_tag, and verify_integrity() passed. \
         Server-side nonce tracking is defeated.",
        &original_nonce[..4],
        &new_nonce[..4]
    );
}
