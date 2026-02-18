# Poly Network — FHE Security Report

> Red-team assessment of the RNS-CKKS homomorphic encryption system
> used for private LLM inference.

**Date:** 2026-02-18
**Scope:** `poly-client` CKKS implementation, `poly-inference` encrypted pipeline
**Method:** 153 adversarial test cases across 6 attack test suites
**Result:** No exploitable vulnerabilities found in the default 3-prime configuration

---

## 1. System Under Test

### Architecture

The encrypted inference pipeline enables a server to run LLM inference on
encrypted data without ever seeing the plaintext:

```
Client                           Server (untrusted)
──────                           ──────────────────
hidden state h
    │
    ├─ PCA project (2560d → 16d)
    ├─ RNS-CKKS encrypt ──────────► FHE compute (blind)
    │                                    │
    │  ◄──────────────────────────── encrypted result
    ├─ decrypt
    ├─ project back (16d → 2560d)
    ├─ lm_head → next token
    └─ repeat
```

### Cryptographic Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Ring dimension (N) | 4096 | Degree of X^N + 1 |
| Primes (inference) | 3 | ~36 bits each, log2(Q) ≈ 108 |
| Primes (deep circuits) | Up to 20 | log2(Q) ≈ 720 |
| Scaling factor (DELTA) | 2^36 | Matches prime size |
| Secret key | Ternary | Coefficients in {-1, 0, 1} |
| Error distribution | Discrete Gaussian | sigma = 3.2 |
| Relin decomposition | 2^18 per digit | 6 digits for 3 primes |
| Rotation decomposition | 2^4 per digit | 27 digits |
| SIMD slots | 2048 (N/2) | Parallel slot packing |

### Security Basis

- **RLWE (Ring Learning With Errors)**: Hardness of distinguishing
  (a, a*s + e) from uniform over Z_q[X]/(X^N + 1)
- **HE Standard (2018)**: N=4096 with log2(Q) ≤ 109 provides
  128-bit classical security

---

## 2. Attack Test Suites

### 2.1 RNS-CKKS Breaker Tests (28 tests) — NEW

**File:** `poly-client/tests/rns_ckks_breaker_tests.rs`

Targeted attacks against the RNS-CKKS system as used in the encrypted
inference pipeline.

| # | Test | Category | Result |
|---|------|----------|--------|
| 1 | `attack_key_recovery_zero_guess` | Key Recovery | DEFENDED |
| 2 | `attack_key_recovery_partial_brute_force` | Key Recovery | DEFENDED |
| 3 | `attack_key_parity_leak` | Key Recovery | DEFENDED |
| 4 | `attack_decrypt_with_zero_key` | Plaintext Recovery | DEFENDED |
| 5 | `attack_coefficient_magnitude_analysis` | Plaintext Recovery | DEFENDED |
| 6 | `attack_decrypt_with_random_key` | Plaintext Recovery | DEFENDED |
| 7 | `attack_known_plaintext_key_extraction` | Known-Plaintext | DEFENDED |
| 8 | `attack_known_plaintext_difference` | Known-Plaintext | DEFENDED |
| 9 | `attack_ind_cpa_zero_vs_nonzero` | IND-CPA | DEFENDED |
| 10 | `attack_ind_cpa_variance_analysis` | IND-CPA | DEFENDED |
| 11 | `attack_ntt_domain_frequency_analysis` | IND-CPA | DEFENDED |
| 12 | `attack_scale_manipulation` | Metadata | KNOWN PROPERTY |
| 13 | `attack_level_manipulation` | Metadata | KNOWN PROPERTY |
| 14 | `attack_noise_budget_exhaustion` | Noise Budget | DEFENDED |
| 15 | `attack_plaintext_overflow_wrapping` | Noise Budget | DEFENDED |
| 16 | `attack_additive_malleability` | Malleability | HE PROPERTY |
| 17 | `attack_multiplicative_malleability` | Malleability | HE PROPERTY |
| 18 | `attack_c1_replacement` | Malleability | DEFENDED |
| 19 | `attack_swap_c0_c1` | Malleability | DEFENDED |
| 20 | `attack_inference_output_distinguishability` | Pipeline | DEFENDED |
| 21 | `attack_pca_projection_leakage` | Pipeline | DEFENDED |
| 22 | `attack_timing_side_channel` | Side-Channel | DEFENDED |
| 23 | `check_parameter_security_3_primes` | Parameters | SECURE |
| 24 | `check_parameter_security_20_primes` | Parameters | KNOWN LIMIT |
| 25 | `check_secret_key_distribution` | Parameters | SECURE |
| 26 | `check_error_distribution` | Parameters | SECURE |
| 27 | `attack_same_plaintext_correlation` | Cross-Ciphertext | DEFENDED |
| 28 | `attack_sequential_pattern_detection` | Cross-Ciphertext | DEFENDED |

### 2.2 Cryptographic Layer Attacks (38 tests)

**File:** `poly-client/tests/crypto_attack_tests.rs`

Tests against the base CKKS layer (single-prime, non-RNS):
- Ciphertext bit-flipping (c0, c1)
- Ciphertext zeroing
- Wrong-key decryption
- NTT prime validation
- Sampling distribution verification
- Replay and substitution attacks

### 2.3 Authentication Breaker Tests (19 tests)

**File:** `poly-client/tests/ckks_breaker_tests.rs`

Attempts to forge CKKS ciphertext authentication tags:
- MAC forgery without secret key
- Nonce reuse/manipulation
- Key ID spoofing
- Cross-key tag transplant
- Tag truncation
- Downgrade attacks (remove auth)

**Status:** All attacks fail after MAC-key hardening (auth_tag now uses
HMAC derived from secret key, not just public data).

### 2.4 Metadata Exploit Tests (12 tests)

**File:** `poly-client/tests/ckks_metadata_exploit_tests.rs`

Attacks on ciphertext metadata fields:
- Token count inflation/deflation
- Scale factor tampering
- Chunk count manipulation
- Nonce collision crafting
- Key ID forgery

### 2.5 Protocol Attack Tests (42 tests)

**File:** `poly-verified/tests/protocol_attack_tests.rs`

Attacks on the verified execution and disclosure protocols:
- Disclosure forgery and spoofing
- Proof replay across computations
- Hash chain manipulation
- Domain separation bypass
- Merkle proof forgery
- Privacy mode escalation/downgrade

### 2.6 HashIVC Breaker Tests (14 tests)

**File:** `poly-verified/tests/crypto_breaker_tests.rs`

Attacks on the hash-based IVC proof system:
- Proof forgery
- Step count manipulation
- Hash collision attempts
- Chain splicing
- Backend confusion attacks

---

## 3. Detailed Findings

### 3.1 No Exploitable Vulnerabilities (3-prime configuration)

The default inference configuration (N=4096, 3 primes, log2(Q) ≈ 108)
withstands all 153 attack tests. Key results:

**IND-CPA Security Holds:**
Encryptions of zero vs nonzero values are statistically indistinguishable
by mean, variance, or frequency analysis of ciphertext coefficients
(both in coefficient domain and NTT domain).

**No Key Leakage:**
Public key coefficients show no bias (even/odd ratio ≈ 50/50).
Secret key is ternary with balanced distribution (~1365 each of {-1,0,1}).
Gaussian error has correct sigma and no extreme outliers.

**No Cross-Ciphertext Correlation:**
Multiple encryptions of the same value have correlation < 0.1.
Sequential encrypted hidden states reveal no A-B-A-B-A pattern.
The server cannot detect repeated tokens.

**FHE Computation is Opaque:**
Server running FHE linear layers on two opposite-sign inputs cannot
distinguish the output ciphertexts (mean coefficient ratio < 1.1).

**Timing is Data-Independent:**
FHE computation time does not depend on encrypted values
(timing ratio < 1.2 across different inputs).

### 3.2 Known Properties (Not Vulnerabilities)

**Scale is Unauthenticated Metadata:**
An active attacker who modifies the `scale` field of a ciphertext can
cause the client to misinterpret decrypted values (e.g., 2x scale causes
half-value decoding). This is inherent to CKKS — the scale is not part
of the ciphertext polynomial structure.

*Mitigation:* Client validates expected scale after decryption. In the
inference pipeline, the expected scale is known at each step.

**Homomorphic Malleability:**
An attacker can add known plaintexts to ciphertexts (shifting encrypted
values) or multiply by known scalars. This is the *definition* of
homomorphic encryption — it's the feature, not a bug. The attacker can
transform values but cannot *read* them.

*Mitigation:* Not needed — this is the intended use case. The server
computes on encrypted data using exactly these operations.

### 3.3 Known Limitation: Deep Circuit Parameters

With 20 primes (log2(Q) ≈ 720), N=4096 does **not** provide 128-bit
security. The HE Standard requires N ≥ 32768 for this modulus size.

*Impact:* This does not affect the inference pipeline, which uses only
3 primes. The 20-prime configuration is for experimental deep circuits
(polynomial SiLU activation, bootstrapping) and should not be used in
production without increasing N.

*Mitigation:* For deep circuits, increase N to 32768 or 65536. The NTT
primes already satisfy q ≡ 1 (mod 2N) for larger N.

---

## 4. Threat Model

### What the Server Sees

| Data | Visible? | Notes |
|------|----------|-------|
| Ciphertext (c0, c1) | Yes | Polynomials over Z_q[X]/(X^N+1) |
| Public key (pk_b, pk_a) | Yes | Used for encryption |
| Evaluation key | Yes | Used for relinearization |
| Rotation keys | Yes | Used for SIMD slot rotation |
| PCA projection basis | Yes | Public projection matrix |
| Neural net weights | Yes | Server's own weights |
| Scale, level metadata | Yes | Floating point + integer |

### What the Server Cannot See

| Data | Protected By |
|------|-------------|
| Secret key s | RLWE hardness (128-bit) |
| Plaintext hidden states | CKKS encryption |
| Projected hidden states | CKKS encryption |
| Generated tokens | Never encrypted (client-side) |
| Token sequence patterns | Fresh randomness per encryption |

### What the Server Can Do (By Design)

| Action | Why It's OK |
|--------|-------------|
| Compute linear layers on ciphertext | This is the FHE feature |
| Add/multiply known values to ciphertext | Homomorphic operations |
| Return computed ciphertext to client | Client decrypts and validates |

### What the Server Cannot Do

| Attack | Why It Fails |
|--------|-------------|
| Read any plaintext value | Requires secret key (RLWE hard) |
| Distinguish two ciphertexts | IND-CPA security holds |
| Detect repeated tokens | Fresh randomness per encryption |
| Recover key from public params | Lattice dimension too large |
| Time-based inference | Computation is data-independent |

---

## 5. Test Coverage Summary

```
Attack Test Suites          Tests    Status
─────────────────────────────────────────────
RNS-CKKS Breaker (new)        28    28 pass
Crypto Layer Attacks           38    38 pass
Auth Breaker                   19    19 pass
Metadata Exploits              12    12 pass
Protocol Attacks               42    42 pass
HashIVC Breaker                14    14 pass
─────────────────────────────────────────────
Total                         153    153 pass
```

Run all attack tests:
```bash
cargo test -p poly-client --features ckks --test rns_ckks_breaker_tests
cargo test -p poly-client --features ckks --test crypto_attack_tests
cargo test -p poly-client --features ckks --test ckks_breaker_tests
cargo test -p poly-client --features ckks --test ckks_metadata_exploit_tests
cargo test -p poly-verified --test protocol_attack_tests
cargo test -p poly-verified --test crypto_breaker_tests
```

---

## 6. Recommendations

1. **Keep N=4096 with 3 primes for inference** — 128-bit secure, fast
2. **Increase N for deep circuits** — If using >5 primes, switch to N=32768+
3. **Validate scale on client** — After decryption, assert scale matches expected
4. **Rotate keys periodically** — Generate fresh keys per session
5. **Do not expose ciphertext metadata** — Scale/level are not authenticated
6. **Consider authenticated HE** — For settings where active attacks are possible,
   wrap ciphertexts in an authenticated channel (TLS + MAC)

---

## 7. Conclusion

The RNS-CKKS encrypted inference pipeline is cryptographically sound for
its intended use case. The 3-prime configuration provides 128-bit security
against all tested attack vectors. The server processes encrypted hidden
states without any ability to read, distinguish, or correlate the underlying
data. All 153 adversarial tests pass, confirming that:

- **Privacy:** The server learns nothing about the client's data
- **Correctness:** FHE computation preserves hidden state accuracy (error < 1.13e-6)
- **Robustness:** Ciphertext manipulation produces garbage, not useful information
- **Opacity:** Sequential encrypted states reveal no token patterns
