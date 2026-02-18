//! Multi-level CKKS with RNS modulus chain.
//!
//! Uses RNS polynomials for O(N log N) multiplication and proper rescaling
//! via prime dropping. Supports L = num_primes - 1 levels of multiplication.
//!
//! Architecture:
//! - Fresh ciphertext uses all K primes (level 0, scale = Δ)
//! - After multiplication: scale = Δ² (level still 0)
//! - After rescale (drop one prime): scale ≈ Δ (level + 1)
//! - Can repeat until only 1 prime remains
//!
//! Key design decisions:
//! - DELTA = 2^36 (matches prime size ~2^36, so scale²/q ≈ scale at every level)
//! - Digit decomposition with base T = 2^18 for low-noise relinearization
//! - CRT reconstruction via Garner's algorithm with variable-width arithmetic (up to 20 primes)

use std::collections::HashMap;
#[cfg(feature = "cuda")]
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::ntt::{mod_inv, mod_pow, NttContext, NTT_PRIMES};
use super::params::N;
use super::rns::{create_ntt_contexts, RnsPoly};
use super::simd;

/// Decomposition base for relinearization: 2^18 per digit.
/// With ~36-bit primes and 3 primes (Q ≈ 2^108), this gives ceil(108/18) = 6 digits.
/// Relin noise ≈ 6 * N * 2^18 * σ ≈ 2^35, well below signal at DELTA^2 ≈ 2^60.
const DECOMP_BITS_RELIN: u32 = 18;

/// Decomposition base for rotation key-switching: 2^4 per digit.
/// Rotation operates at scale Δ (not Δ²), so we need finer decomposition.
/// ceil(108/4) = 27 digits. Noise ≈ 27 * N * 2^4 * σ ≈ 2^20, well below Δ = 2^30.
const DECOMP_BITS_ROT: u32 = 4;

// ═══════════════════════════════════════════════════════════════════════
// RNS-based CKKS Ciphertext
// ═══════════════════════════════════════════════════════════════════════

/// A CKKS ciphertext in RNS representation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RnsCiphertext {
    pub c0: RnsPoly,
    pub c1: RnsPoly,
    /// Current scaling factor (Δ for fresh, Δ² after multiply, ~Δ after rescale).
    /// Tracked as f64 so Δ can be close to the prime size (~2^35) without
    /// i64 overflow on Δ².
    pub scale: f64,
    /// Number of rescale operations performed (0 for fresh).
    pub level: usize,
    /// Authentication tag (SHA-256 HMAC over ciphertext data).
    /// None for legacy/unauthenticated ciphertexts.
    #[serde(default)]
    pub auth_tag: Option<[u8; 32]>,
}

impl RnsCiphertext {
    /// Compute an authentication tag over the ciphertext contents.
    pub fn compute_auth_tag(&self, mac_key: &[u8; 32]) -> [u8; 32] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"rns_ckks_auth_v1");
        hasher.update(mac_key);
        hasher.update(self.scale.to_le_bytes());
        hasher.update((self.level as u64).to_le_bytes());
        for ch in &self.c0.residues {
            for &coeff in ch {
                hasher.update(coeff.to_le_bytes());
            }
        }
        for ch in &self.c1.residues {
            for &coeff in ch {
                hasher.update(coeff.to_le_bytes());
            }
        }
        hasher.finalize().into()
    }

    /// Verify the authentication tag. Returns true if valid.
    pub fn verify_auth(&self, mac_key: &[u8; 32]) -> bool {
        match &self.auth_tag {
            Some(tag) => {
                let expected = self.compute_auth_tag(mac_key);
                // Constant-time comparison
                let mut diff = 0u8;
                for (a, b) in tag.iter().zip(expected.iter()) {
                    diff |= a ^ b;
                }
                diff == 0
            }
            None => false, // No auth tag means not authenticated
        }
    }

    /// Set the authentication tag.
    pub fn authenticate(&mut self, mac_key: &[u8; 32]) {
        self.auth_tag = Some(self.compute_auth_tag(mac_key));
    }
}

/// Evaluation key for RNS-based relinearization with digit decomposition.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RnsEvalKey {
    /// (b_d, a_d) pairs — one for each decomposition digit.
    /// evk_i encrypts s² · T^i under s.
    pub keys: Vec<(RnsPoly, RnsPoly)>,
}

/// Triple from ciphertext-ciphertext multiplication (before relinearization).
pub struct RnsCiphertextTriple {
    pub d0: RnsPoly,
    pub d1: RnsPoly,
    pub d2: RnsPoly,
    pub scale: f64,
    pub level: usize,
}

/// Rotation key for a single rotation amount (key-switching key).
///
/// Encrypts σ_m(s) under s using digit decomposition, where σ_m is the
/// Galois automorphism corresponding to the desired rotation.
#[derive(Clone, Serialize, Deserialize)]
pub struct RnsRotationKey {
    /// (b_d, a_d) pairs — one per decomposition digit.
    /// key_i encrypts σ_m(s) · T^i under s.
    pub keys: Vec<(RnsPoly, RnsPoly)>,
    /// The Galois element m such that σ_m(X) = X^m.
    pub galois_element: usize,
}

/// Collection of rotation keys for multiple rotation amounts.
#[derive(Clone, Serialize, Deserialize)]
pub struct RnsRotationKeySet {
    /// Maps rotation amount (signed) to its rotation key.
    pub keys: HashMap<i32, RnsRotationKey>,
}

/// Galois group generator for N = 4096 (2N = 8192).
/// 5 has order 2048 = N/2 in (Z/8192)*, generating all slot rotations.
const GALOIS_GEN: usize = 5;

// ═══════════════════════════════════════════════════════════════════════
// Context: holds NTT tables and parameters
// ═══════════════════════════════════════════════════════════════════════

/// Holds all precomputed NTT contexts and parameters for RNS-CKKS.
pub struct RnsCkksContext {
    pub ntt: Vec<NttContext>,
    pub num_primes: usize,
    /// Scaling factor. Must match prime size for scale stability in deep chains:
    /// after multiply+rescale, scale_new = scale²/q ≈ scale when scale ≈ q.
    /// With Δ = 2^36 ≈ q, the scale is perfectly preserved at every level.
    pub delta: f64,
    /// GPU NTT engine (auto-initialized when `cuda` feature is enabled).
    #[cfg(feature = "cuda")]
    pub gpu: Option<Arc<super::gpu::GpuNttEngine>>,
}

impl RnsCkksContext {
    pub fn new(num_primes: usize) -> Self {
        assert!(
            num_primes <= NTT_PRIMES.len(),
            "requested {} primes, only {} available",
            num_primes,
            NTT_PRIMES.len()
        );

        // HES 128-bit security bounds for N=4096
        if num_primes > 3 {
            eprintln!(
                "WARNING: RNS-CKKS with N=4096 and {} primes (log2(Q) ~ {}) \
                 exceeds the Homomorphic Encryption Standard bound for 128-bit security. \
                 For secure parameters, use num_primes <= 3 or increase N.",
                num_primes, num_primes as f64 * 36.5
            );
        }

        let ntt = create_ntt_contexts();
        let delta = (1u64 << 36) as f64; // DELTA = 2^36, matches prime size for stable deep chains

        #[cfg(feature = "cuda")]
        let gpu = match super::gpu::GpuNttEngine::new(0, num_primes) {
            Ok(engine) => {
                eprintln!("[CKKS] GPU NTT engine initialized ({num_primes} primes)");
                Some(Arc::new(engine))
            }
            Err(e) => {
                eprintln!("[CKKS] GPU NTT unavailable, CPU fallback: {e}");
                None
            }
        };

        Self {
            ntt,
            num_primes,
            delta,
            #[cfg(feature = "cuda")]
            gpu,
        }
    }

    /// Maximum multiplication depth supported.
    pub fn max_depth(&self) -> usize {
        self.num_primes - 1
    }

    /// NTT polynomial multiply, dispatching to GPU if available.
    pub(crate) fn poly_mul(&self, a: &RnsPoly, b: &RnsPoly) -> RnsPoly {
        #[cfg(feature = "cuda")]
        if let Some(ref gpu) = self.gpu {
            return super::gpu::gpu_poly_mul(a, b, gpu)
                .expect("GPU poly_mul failed");
        }
        a.mul(b, &self.ntt)
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Digit decomposition for relinearization
// ═══════════════════════════════════════════════════════════════════════

/// Compute number of base-T digits needed for the given number of primes.
fn num_decomp_digits(num_primes: usize, decomp_bits: u32) -> usize {
    let total_bits: u32 = NTT_PRIMES[..num_primes]
        .iter()
        .map(|&q| 64 - (q as u64).leading_zeros())
        .sum();
    ((total_bits + decomp_bits - 1) / decomp_bits) as usize
}

// ── Variable-width unsigned arithmetic for CRT ──────────────────────

/// Variable-width unsigned integer as little-endian u64 limbs.
/// Supports arbitrary prime counts (5 primes → 4 limbs, 20 primes → 12 limbs).
struct WideInt {
    limbs: Vec<u64>,
}

impl WideInt {
    fn from_u64(v: u64, num_limbs: usize) -> Self {
        let mut limbs = vec![0u64; num_limbs];
        limbs[0] = v;
        Self { limbs }
    }

    fn mul_u64(&self, b: u64) -> Self {
        let n = self.limbs.len();
        let mut result = vec![0u64; n];
        let mut carry = 0u128;
        for i in 0..n {
            let prod = self.limbs[i] as u128 * b as u128 + carry;
            result[i] = prod as u64;
            carry = prod >> 64;
        }
        Self { limbs: result }
    }

    fn add(&self, other: &Self) -> Self {
        let n = self.limbs.len();
        let mut result = vec![0u64; n];
        let mut carry = 0u128;
        for i in 0..n {
            let a = self.limbs[i] as u128;
            let b = if i < other.limbs.len() { other.limbs[i] as u128 } else { 0 };
            let sum = a + b + carry;
            result[i] = sum as u64;
            carry = sum >> 64;
        }
        Self { limbs: result }
    }

    fn shr(&self, bits: u32) -> Self {
        if bits == 0 {
            return Self { limbs: self.limbs.clone() };
        }
        let n = self.limbs.len();
        let mut result = vec![0u64; n];
        for i in 0..n {
            result[i] = self.limbs[i] >> bits;
            if i + 1 < n {
                result[i] |= self.limbs[i + 1] << (64 - bits);
            }
        }
        Self { limbs: result }
    }

    fn low_bits(&self, bits: u32) -> u64 {
        self.limbs[0] & ((1u64 << bits) - 1)
    }
}

// ── Garner CRT + digit extraction ───────────────────────────────────

/// Garner CRT reconstruction + base-B digit extraction.
///
/// Uses variable-width arithmetic so it works for any number of primes
/// (20 primes at ~36 bits → Q ≈ 2^720, needs 12 limbs).
/// Returns `num_digits` digits in base `2^decomp_bits`.
fn garner_to_digits(
    residues: &[i64],
    primes: &[i64],
    decomp_bits: u32,
    num_digits: usize,
) -> Vec<i64> {
    let k = residues.len();
    // Number of 64-bit limbs needed: ceil(k * 36 / 64) + 1 for safety
    let num_limbs = (k * 36 + 63) / 64 + 1;

    // Step 1: Garner mixed-radix coefficients (each < m_i, fits in i64)
    let mut v = vec![0i64; k];
    v[0] = residues[0];

    for i in 1..k {
        let q_i = primes[i] as i128;
        let mut u = residues[i] as i128;

        for j in 0..i {
            u = ((u - v[j] as i128) % q_i + q_i) % q_i;
            let inv = mod_inv(primes[j], primes[i]) as i128;
            u = u * inv % q_i;
        }
        v[i] = u as i64;
    }

    // Step 2: Reconstruct as wide unsigned (value in [0, Q))
    let mut result = WideInt::from_u64(v[0] as u64, num_limbs);
    let mut product = WideInt::from_u64(1, num_limbs);
    for i in 1..k {
        product = product.mul_u64(primes[i - 1] as u64);
        let term = product.mul_u64(v[i] as u64);
        result = result.add(&term);
    }

    // Step 3: Extract base-B digits
    let mut digits = vec![0i64; num_digits];
    for d in 0..num_digits {
        digits[d] = result.low_bits(decomp_bits) as i64;
        result = result.shr(decomp_bits);
    }

    digits
}

/// Decompose an RNS polynomial into base-T digit polynomials.
///
/// Pipeline: CRT reconstruct (256-bit) → base-T digit extract → back to RNS.
/// Each output digit polynomial has coefficients in [0, T).
fn decompose_digits(d2: &RnsPoly, decomp_bits: u32) -> Vec<RnsPoly> {
    let primes: Vec<i64> = NTT_PRIMES[..d2.num_primes].to_vec();
    let nd = num_decomp_digits(d2.num_primes, decomp_bits);

    let mut digit_coeffs: Vec<Vec<i64>> = vec![vec![0i64; N]; nd];

    for j in 0..N {
        let residues: Vec<i64> = (0..d2.num_primes)
            .map(|i| d2.residues[i][j])
            .collect();
        let digits = garner_to_digits(&residues, &primes, decomp_bits, nd);

        for d in 0..nd {
            digit_coeffs[d][j] = digits[d];
        }
    }

    digit_coeffs
        .iter()
        .map(|coeffs| RnsPoly::from_coeffs(coeffs, d2.num_primes))
        .collect()
}

/// Multiply each RNS channel by a per-channel scalar.
/// channel_scalars[i] is the scalar for prime i.
fn rns_channel_scalar_mul(poly: &RnsPoly, channel_scalars: &[i64]) -> RnsPoly {
    let mut residues = Vec::with_capacity(poly.num_primes);
    for i in 0..poly.num_primes {
        let q = NTT_PRIMES[i] as i128;
        let s = channel_scalars[i] as i128;
        let res: Vec<i64> = poly.residues[i]
            .iter()
            .map(|&c| ((c as i128 * s) % q + q) as i64 % NTT_PRIMES[i])
            .collect();
        residues.push(res);
    }
    RnsPoly {
        residues,
        num_primes: poly.num_primes,
    }
}

/// Truncate an RnsPoly to fewer primes.
fn rns_truncate(poly: &RnsPoly, num_primes: usize) -> RnsPoly {
    RnsPoly {
        residues: poly.residues[..num_primes].to_vec(),
        num_primes,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Key generation
// ═══════════════════════════════════════════════════════════════════════

/// Generate secret key (ternary) and public key pair.
/// Returns (secret_key, pk_b, pk_a).
pub fn rns_keygen<R: rand::Rng>(
    ctx: &RnsCkksContext,
    rng: &mut R,
) -> (RnsPoly, RnsPoly, RnsPoly) {
    let mut s_coeffs = vec![0i64; N];
    for c in s_coeffs.iter_mut() {
        *c = rng.gen_range(-1..=1);
    }
    let s = RnsPoly::from_coeffs(&s_coeffs, ctx.num_primes);

    let a = rns_sample_uniform(rng, ctx.num_primes);
    let e = rns_sample_gaussian(rng, ctx.num_primes);
    let a_s = ctx.poly_mul(&a, &s);
    let b = a_s.add(&e).neg();

    (s, b, a)
}

/// Generate evaluation key for relinearization with digit decomposition.
///
/// For each digit i, creates a key pair encrypting s² · T^i under s.
/// This bounds relinearization noise to NUM_DIGITS · N · T · σ.
pub fn rns_gen_eval_key<R: rand::Rng>(
    s: &RnsPoly,
    ctx: &RnsCkksContext,
    rng: &mut R,
) -> RnsEvalKey {
    let s_squared = ctx.poly_mul(s, s);
    let num_primes = ctx.num_primes;
    let nd = num_decomp_digits(num_primes, DECOMP_BITS_RELIN);
    let base = 1i64 << DECOMP_BITS_RELIN;

    let mut keys = Vec::with_capacity(nd);

    for i in 0..nd {
        // Compute T^i mod each prime
        let t_power: Vec<i64> = NTT_PRIMES[..num_primes]
            .iter()
            .map(|&q| mod_pow(base, i as u64, q))
            .collect();

        // s² · T^i (per-channel scalar multiply)
        let s_sq_ti = rns_channel_scalar_mul(&s_squared, &t_power);

        // evk_i: b_i = -(a_i·s + e_i) + s²·T^i, a_i = random
        let a = rns_sample_uniform(rng, num_primes);
        let e = rns_sample_gaussian(rng, num_primes);
        let a_s = ctx.poly_mul(&a, s);
        let b = a_s.add(&e).neg().add(&s_sq_ti);
        keys.push((b, a));
    }

    RnsEvalKey { keys }
}

// ═══════════════════════════════════════════════════════════════════════
// Encryption / Decryption
// ═══════════════════════════════════════════════════════════════════════

/// Encrypt a single f64 value using SIMD slot 0.
///
/// Internally uses SIMD encoding (value in slot 0, zeros elsewhere) rather
/// than raw coefficient encoding. This distributes energy across all N
/// coefficients, giving ~√N headroom before modular wrap-around.
pub fn rns_encrypt_f64<R: rand::Rng>(
    value: f64,
    pk_b: &RnsPoly,
    pk_a: &RnsPoly,
    ctx: &RnsCkksContext,
    rng: &mut R,
) -> RnsCiphertext {
    rns_encrypt_simd(&[value], pk_b, pk_a, ctx, rng)
}

/// Decrypt a ciphertext and decode to f64 (reads SIMD slot 0).
///
/// Pairs with `rns_encrypt_f64` which uses SIMD encoding.
pub fn rns_decrypt_f64(
    ct: &RnsCiphertext,
    s: &RnsPoly,
    ctx: &RnsCkksContext,
) -> f64 {
    let decoded = rns_decrypt_simd(ct, s, ctx, 1);
    decoded[0]
}

// ═══════════════════════════════════════════════════════════════════════
// SIMD Encryption / Decryption (N/2 = 2048 slots per ciphertext)
// ═══════════════════════════════════════════════════════════════════════

/// Encrypt a vector of up to N/2 = 2048 f64 values using SIMD slot packing.
///
/// Each value occupies one "slot" in the polynomial ring. Homomorphic
/// add/multiply then becomes element-wise add/multiply across all slots.
pub fn rns_encrypt_simd<R: rand::Rng>(
    values: &[f64],
    pk_b: &RnsPoly,
    pk_a: &RnsPoly,
    ctx: &RnsCkksContext,
    rng: &mut R,
) -> RnsCiphertext {
    let num_primes = ctx.num_primes;

    // Encode values into polynomial coefficients via canonical embedding
    let coeffs = simd::encode_simd(values, ctx.delta);
    let m = RnsPoly::from_coeffs(&coeffs, num_primes);

    // Same encryption as rns_encrypt_f64: c0 = pk_b*u + e1 + m, c1 = pk_a*u + e2
    let mut u_coeffs = vec![0i64; N];
    for c in u_coeffs.iter_mut() {
        *c = rng.gen_range(-1..=1);
    }
    let u = RnsPoly::from_coeffs(&u_coeffs, num_primes);
    let e1 = rns_sample_gaussian(rng, num_primes);
    let e2 = rns_sample_gaussian(rng, num_primes);

    let c0 = ctx.poly_mul(pk_b, &u).add(&e1).add(&m);
    let c1 = ctx.poly_mul(pk_a, &u).add(&e2);

    RnsCiphertext {
        c0,
        c1,
        scale: ctx.delta,
        level: 0,
        auth_tag: None,
    }
}

/// Decrypt a SIMD-packed ciphertext and decode `count` slot values.
pub fn rns_decrypt_simd(
    ct: &RnsCiphertext,
    s: &RnsPoly,
    ctx: &RnsCkksContext,
    count: usize,
) -> Vec<f64> {
    let s_at_level = if s.num_primes > ct.c0.num_primes {
        rns_truncate(s, ct.c0.num_primes)
    } else {
        s.clone()
    };

    let c1_s = ctx.poly_mul(&ct.c1, &s_at_level);
    let m_noisy = ct.c0.add(&c1_s);

    let coeffs = m_noisy.to_coeffs();
    simd::decode_simd(&coeffs, ct.scale, count)
}

// ═══════════════════════════════════════════════════════════════════════
// Homomorphic Operations
// ═══════════════════════════════════════════════════════════════════════

/// Add two ciphertexts.
pub fn rns_ct_add(a: &RnsCiphertext, b: &RnsCiphertext) -> RnsCiphertext {
    assert_eq!(a.scale, b.scale, "scale mismatch");
    assert_eq!(a.level, b.level, "level mismatch");
    RnsCiphertext {
        c0: a.c0.add(&b.c0),
        c1: a.c1.add(&b.c1),
        scale: a.scale,
        level: a.level,
        auth_tag: None,
    }
}

/// Subtract two ciphertexts.
pub fn rns_ct_sub(a: &RnsCiphertext, b: &RnsCiphertext) -> RnsCiphertext {
    assert_eq!(a.scale, b.scale, "scale mismatch");
    assert_eq!(a.level, b.level, "level mismatch");
    RnsCiphertext {
        c0: a.c0.sub(&b.c0),
        c1: a.c1.sub(&b.c1),
        scale: a.scale,
        level: a.level,
        auth_tag: None,
    }
}

/// Multiply ciphertext by integer scalar.
pub fn rns_ct_scalar_mul(ct: &RnsCiphertext, scalar: i64) -> RnsCiphertext {
    RnsCiphertext {
        c0: ct.c0.scalar_mul(scalar),
        c1: ct.c1.scalar_mul(scalar),
        scale: ct.scale,
        level: ct.level,
        auth_tag: None,
    }
}

/// Add an encoded plaintext scalar to a ciphertext.
///
/// Uses SIMD encoding (value in slot 0) to match `rns_encrypt_f64`.
pub fn rns_ct_add_plain(ct: &RnsCiphertext, plain_val: f64, delta: f64) -> RnsCiphertext {
    let coeffs = simd::encode_simd(&[plain_val], delta);
    let p = RnsPoly::from_coeffs(&coeffs, ct.c0.num_primes);
    RnsCiphertext {
        c0: ct.c0.add(&p),
        c1: ct.c1.clone(),
        scale: ct.scale,
        level: ct.level,
        auth_tag: None,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Level-aware operations (for polynomial evaluation and deep circuits)
// ═══════════════════════════════════════════════════════════════════════

/// Mod-switch a ciphertext to have `target_primes` primes.
///
/// Free operation — just drops extra RNS components without changing
/// the encrypted value or scale. Used to align levels before ct-ct multiply
/// when operands are at different depths.
pub fn rns_ct_mod_switch_to(ct: &RnsCiphertext, target_primes: usize) -> RnsCiphertext {
    assert!(target_primes >= 1 && target_primes <= ct.c0.num_primes);
    if target_primes == ct.c0.num_primes {
        return ct.clone();
    }
    let levels_dropped = ct.c0.num_primes - target_primes;
    RnsCiphertext {
        c0: rns_truncate(&ct.c0, target_primes),
        c1: rns_truncate(&ct.c1, target_primes),
        scale: ct.scale,
        level: ct.level + levels_dropped,
        auth_tag: None,
    }
}

/// Add a scalar broadcast to all SIMD slots of a ciphertext.
///
/// Encodes `scalar` at the ciphertext's current scale so the addition
/// is semantically correct. No level consumed.
pub fn rns_ct_add_scalar_broadcast(ct: &RnsCiphertext, scalar: f64) -> RnsCiphertext {
    let values = vec![scalar; simd::NUM_SLOTS];
    let coeffs = simd::encode_simd(&values, ct.scale);
    let p = RnsPoly::from_coeffs(&coeffs, ct.c0.num_primes);
    RnsCiphertext {
        c0: ct.c0.add(&p),
        c1: ct.c1.clone(),
        scale: ct.scale,
        level: ct.level,
        auth_tag: None,
    }
}

/// Multiply two ciphertexts with automatic level matching.
///
/// Unlike `rns_ct_mul`, does not require exact scale/level equality.
/// The higher-level (more primes) ciphertext is mod-switched down to
/// match the lower one. Result scale = a.scale × b.scale.
pub fn rns_ct_mul_leveled(
    a: &RnsCiphertext,
    b: &RnsCiphertext,
    ctx: &RnsCkksContext,
) -> RnsCiphertextTriple {
    let target = a.c0.num_primes.min(b.c0.num_primes);
    let a_m = rns_ct_mod_switch_to(a, target);
    let b_m = rns_ct_mod_switch_to(b, target);

    let d0 = ctx.poly_mul(&a_m.c0, &b_m.c0);
    let d1 = ctx.poly_mul(&a_m.c0, &b_m.c1).add(&ctx.poly_mul(&a_m.c1, &b_m.c0));
    let d2 = ctx.poly_mul(&a_m.c1, &b_m.c1);

    RnsCiphertextTriple {
        d0,
        d1,
        d2,
        scale: a_m.scale * b_m.scale,
        level: a_m.level,
    }
}

/// Multiply + relinearize with automatic level matching.
pub fn rns_ct_mul_relin_leveled(
    a: &RnsCiphertext,
    b: &RnsCiphertext,
    evk: &RnsEvalKey,
    ctx: &RnsCkksContext,
) -> RnsCiphertext {
    let triple = rns_ct_mul_leveled(a, b, ctx);
    rns_relinearize(triple, evk, ctx)
}

/// Add two ciphertexts with automatic level matching.
///
/// Mod-switches the higher ciphertext to match the lower one.
/// Uses the average of (approximately equal) scales.
pub fn rns_ct_add_leveled(a: &RnsCiphertext, b: &RnsCiphertext) -> RnsCiphertext {
    let target = a.c0.num_primes.min(b.c0.num_primes);
    let a_m = rns_ct_mod_switch_to(a, target);
    let b_m = rns_ct_mod_switch_to(b, target);

    RnsCiphertext {
        c0: a_m.c0.add(&b_m.c0),
        c1: a_m.c1.add(&b_m.c1),
        scale: (a_m.scale + b_m.scale) / 2.0,
        level: a_m.level,
        auth_tag: None,
    }
}

/// Multiply two ciphertexts (produces a triple).
pub fn rns_ct_mul(
    a: &RnsCiphertext,
    b: &RnsCiphertext,
    ctx: &RnsCkksContext,
) -> RnsCiphertextTriple {
    assert_eq!(a.scale, b.scale, "scale mismatch");
    assert_eq!(a.level, b.level, "level mismatch");

    let d0 = ctx.poly_mul(&a.c0, &b.c0);
    let d1 = ctx.poly_mul(&a.c0, &b.c1).add(&ctx.poly_mul(&a.c1, &b.c0));
    let d2 = ctx.poly_mul(&a.c1, &b.c1);

    RnsCiphertextTriple {
        d0,
        d1,
        d2,
        scale: a.scale * b.scale,
        level: a.level,
    }
}

/// Relinearize a triple back to a 2-component ciphertext using digit decomposition.
///
/// Decomposes d2 into base-T digits, applies each digit to the corresponding
/// eval key pair. This bounds noise to NUM_DIGITS · N · T · σ instead of
/// the catastrophic N · Q · σ from simple relinearization.
pub fn rns_relinearize(
    triple: RnsCiphertextTriple,
    evk: &RnsEvalKey,
    ctx: &RnsCkksContext,
) -> RnsCiphertext {
    let digits = decompose_digits(&triple.d2, DECOMP_BITS_RELIN);
    let np = triple.d0.num_primes;

    let mut c0 = triple.d0;
    let mut c1 = triple.d1;

    for (i, digit) in digits.iter().enumerate() {
        let (ref evk_b, ref evk_a) = evk.keys[i];

        // Truncate eval key to match ciphertext's prime count
        let evk_b_t = rns_truncate(evk_b, np);
        let evk_a_t = rns_truncate(evk_a, np);

        c0 = c0.add(&ctx.poly_mul(digit, &evk_b_t));
        c1 = c1.add(&ctx.poly_mul(digit, &evk_a_t));
    }

    RnsCiphertext {
        c0,
        c1,
        scale: triple.scale,
        level: triple.level,
        auth_tag: None,
    }
}

/// Multiply two ciphertexts with relinearization.
pub fn rns_ct_mul_relin(
    a: &RnsCiphertext,
    b: &RnsCiphertext,
    evk: &RnsEvalKey,
    ctx: &RnsCkksContext,
) -> RnsCiphertext {
    let triple = rns_ct_mul(a, b, ctx);
    rns_relinearize(triple, evk, ctx)
}

/// Rescale: drop the last prime, dividing scale by q_last.
///
/// After multiplication, scale = Δ². Rescaling divides by q_last ≈ 2^36,
/// bringing scale from ~2^60 down to ~2^24 (still high precision).
pub fn rns_rescale(ct: &RnsCiphertext) -> RnsCiphertext {
    assert!(
        ct.c0.num_primes > 1,
        "cannot rescale: only 1 prime remaining"
    );

    let q_last = NTT_PRIMES[ct.c0.num_primes - 1];

    RnsCiphertext {
        c0: ct.c0.drop_last_prime(),
        c1: ct.c1.drop_last_prime(),
        scale: ct.scale / q_last as f64,
        level: ct.level + 1,
        auth_tag: None,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Slot Rotations (Galois automorphisms + key-switching)
// ═══════════════════════════════════════════════════════════════════════

/// Compute the Galois element for rotating slots by `rotation` positions.
///
/// Rotation by r corresponds to automorphism σ_{g^r mod 2N} where g = 5.
/// Negative rotations use g^{-r} = (g^{-1})^r.
pub fn rotation_to_galois(rotation: i32) -> usize {
    let two_n = 2 * N;
    let slots = N / 2;

    // Normalize rotation to [0, slots)
    let r = ((rotation % slots as i32) + slots as i32) as usize % slots;
    if r == 0 {
        return 1; // identity
    }

    // g^r mod 2N
    let mut result = 1usize;
    for _ in 0..r {
        result = (result * GALOIS_GEN) % two_n;
    }
    result
}

/// Generate a rotation key for a single rotation amount.
///
/// The key encrypts σ_m(s) · T^i under s for each decomposition digit i.
/// This is structurally identical to eval key generation but with σ_m(s)
/// instead of s².
pub fn rns_gen_rotation_key<R: rand::Rng>(
    s: &RnsPoly,
    rotation: i32,
    ctx: &RnsCkksContext,
    rng: &mut R,
) -> RnsRotationKey {
    let galois_element = rotation_to_galois(rotation);
    let s_automorphed = s.apply_automorphism(galois_element);
    let num_primes = ctx.num_primes;
    let nd = num_decomp_digits(num_primes, DECOMP_BITS_ROT);
    let base = 1i64 << DECOMP_BITS_ROT;

    let mut keys = Vec::with_capacity(nd);
    for i in 0..nd {
        // Compute T^i mod each prime
        let t_power: Vec<i64> = NTT_PRIMES[..num_primes]
            .iter()
            .map(|&q| mod_pow(base, i as u64, q))
            .collect();

        // σ_m(s) · T^i
        let s_auto_ti = rns_channel_scalar_mul(&s_automorphed, &t_power);

        // evk_i: b_i = -(a_i·s + e_i) + σ_m(s)·T^i, a_i = random
        let a = rns_sample_uniform(rng, num_primes);
        let e = rns_sample_gaussian(rng, num_primes);
        let a_s = ctx.poly_mul(&a, s);
        let b = a_s.add(&e).neg().add(&s_auto_ti);
        keys.push((b, a));
    }

    RnsRotationKey {
        keys,
        galois_element,
    }
}

/// Generate rotation keys for a set of rotation amounts.
pub fn rns_gen_rotation_keys<R: rand::Rng>(
    s: &RnsPoly,
    rotations: &[i32],
    ctx: &RnsCkksContext,
    rng: &mut R,
) -> RnsRotationKeySet {
    let mut keys = HashMap::new();
    for &r in rotations {
        keys.insert(r, rns_gen_rotation_key(s, r, ctx, rng));
    }
    RnsRotationKeySet { keys }
}

/// Rotate SIMD slots by `rotation` positions (positive = left shift).
///
/// Pipeline:
/// 1. Apply automorphism σ_m to both c0 and c1
/// 2. Key-switch c1 from σ_m(s) back to s using rotation key
///
/// The key-switching step is identical to relinearization: decompose
/// σ_m(c1) into digits, multiply by rotation key pairs, accumulate.
pub fn rns_rotate(
    ct: &RnsCiphertext,
    rotation: i32,
    rot_keys: &RnsRotationKeySet,
    ctx: &RnsCkksContext,
) -> RnsCiphertext {
    let slots = N / 2;
    let r = ((rotation % slots as i32) + slots as i32) as usize % slots;
    if r == 0 {
        return ct.clone();
    }

    let rot_key = rot_keys
        .keys
        .get(&rotation)
        .unwrap_or_else(|| panic!("no rotation key for rotation {}", rotation));

    let galois = rot_key.galois_element;

    // Apply automorphism to both ciphertext components
    let c0_auto = ct.c0.apply_automorphism(galois);
    let c1_auto = ct.c1.apply_automorphism(galois);

    // Key-switch c1_auto from σ_m(s) to s
    // (identical to relinearization but on c1_auto instead of d2)
    let digits = decompose_digits(&c1_auto, DECOMP_BITS_ROT);
    let np = c0_auto.num_primes;

    let mut c0_new = c0_auto;
    let mut c1_new = RnsPoly::zero(np);

    for (i, digit) in digits.iter().enumerate() {
        let (ref ks_b, ref ks_a) = rot_key.keys[i];
        let ks_b_t = rns_truncate(ks_b, np);
        let ks_a_t = rns_truncate(ks_a, np);

        c0_new = c0_new.add(&ctx.poly_mul(digit, &ks_b_t));
        c1_new = c1_new.add(&ctx.poly_mul(digit, &ks_a_t));
    }

    RnsCiphertext {
        c0: c0_new,
        c1: c1_new,
        scale: ct.scale,
        level: ct.level,
        auth_tag: None,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Plaintext SIMD multiply
// ═══════════════════════════════════════════════════════════════════════

/// Multiply a ciphertext by a SIMD-packed plaintext vector.
///
/// Encodes `values` into a polynomial at scale Δ, then multiplies both
/// ciphertext components. Result scale = ct.scale × Δ (needs rescaling).
///
/// This is much cheaper than ct×ct multiplication:
/// - Only 2 polynomial multiplications (vs 4)
/// - No relinearization needed (result is still degree 1)
/// - No key-switching noise
pub fn rns_ct_mul_plain_simd(
    ct: &RnsCiphertext,
    values: &[f64],
    ctx: &RnsCkksContext,
) -> RnsCiphertext {
    let coeffs = simd::encode_simd(values, ctx.delta);
    let p = RnsPoly::from_coeffs(&coeffs, ct.c0.num_primes);

    RnsCiphertext {
        c0: ctx.poly_mul(&ct.c0, &p),
        c1: ctx.poly_mul(&ct.c1, &p),
        scale: ct.scale * ctx.delta,
        level: ct.level,
        auth_tag: None,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Matrix-vector multiply via diagonal method
// ═══════════════════════════════════════════════════════════════════════

/// Replicate a d-element vector across all NUM_SLOTS positions.
///
/// Required for `rns_matvec`: the encrypted input must be replicated
/// so that SIMD rotations wrap around correctly at d-element boundaries.
pub fn replicate_vector(values: &[f64], d: usize) -> Vec<f64> {
    let mut replicated = vec![0.0; simd::NUM_SLOTS];
    for i in 0..simd::NUM_SLOTS {
        replicated[i] = values[i % d];
    }
    replicated
}

/// Compute W·x where W is a d×d matrix and x is encrypted in SIMD slots.
///
/// Uses the diagonal method:
///     W·x = Σ_{k=0}^{d-1} diag_k(W) ⊙ rotate(x, k)
///
/// where diag_k(W)[i] = W[i%d][(i%d+k)%d] is the k-th generalized diagonal,
/// tiled across all slots so that rotation wrap-around is correct.
///
/// **Important:** The input ciphertext must contain a *replicated* vector
/// (use `replicate_vector` before encryption). The result is at scale Δ²
/// (needs rescaling by the caller).
///
/// # Arguments
/// * `ct_x` - Encrypted replicated input vector
/// * `matrix` - Row-major d×d matrix (matrix[i*d + j] = W[i][j])
/// * `d` - Dimension of the matrix
/// * `rot_keys` - Rotation keys for rotations 1..d-1
/// * `ctx` - CKKS context
pub fn rns_matvec(
    ct_x: &RnsCiphertext,
    matrix: &[f64],
    d: usize,
    rot_keys: &RnsRotationKeySet,
    ctx: &RnsCkksContext,
) -> RnsCiphertext {
    assert_eq!(matrix.len(), d * d, "matrix must be d×d");

    // k = 0: no rotation needed
    // Tile the diagonal across all slots for correct wrap-around
    let diag_0: Vec<f64> = (0..simd::NUM_SLOTS)
        .map(|i| matrix[(i % d) * d + (i % d)])
        .collect();
    let mut result = rns_ct_mul_plain_simd(ct_x, &diag_0, ctx);

    // k = 1..d-1: rotate then multiply by tiled diagonal
    for k in 1..d {
        let diag_k: Vec<f64> = (0..simd::NUM_SLOTS)
            .map(|i| matrix[(i % d) * d + ((i % d) + k) % d])
            .collect();
        let ct_rot = rns_rotate(ct_x, k as i32, rot_keys, ctx);
        let term = rns_ct_mul_plain_simd(&ct_rot, &diag_k, ctx);
        result = rns_ct_add(&result, &term);
    }

    result
}

// ═══════════════════════════════════════════════════════════════════════
// Sampling helpers
// ═══════════════════════════════════════════════════════════════════════

fn rns_sample_uniform<R: rand::Rng>(rng: &mut R, num_primes: usize) -> RnsPoly {
    let mut residues = Vec::with_capacity(num_primes);
    for i in 0..num_primes {
        let q = NTT_PRIMES[i];
        let res: Vec<i64> = (0..N).map(|_| rng.gen_range(0..q)).collect();
        residues.push(res);
    }
    RnsPoly {
        residues,
        num_primes,
    }
}

fn rns_sample_gaussian<R: rand::Rng>(rng: &mut R, num_primes: usize) -> RnsPoly {
    let sigma = 3.2f64;
    let mut coeffs = vec![0i64; N];
    for c in coeffs.iter_mut() {
        let u1: f64 = rng.gen::<f64>().max(1e-10);
        let u2: f64 = rng.gen::<f64>();
        let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
        *c = (z * sigma).round() as i64;
    }
    RnsPoly::from_coeffs(&coeffs, num_primes)
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let value = 3.14;
        let ct = rns_encrypt_f64(value, &pk_b, &pk_a, &ctx, &mut rng);
        let decrypted = rns_decrypt_f64(&ct, &s, &ctx);

        assert!(
            (decrypted - value).abs() < 0.01,
            "expected {}, got {}",
            value,
            decrypted
        );
    }

    #[test]
    fn encrypt_decrypt_negative() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let value = -7.5;
        let ct = rns_encrypt_f64(value, &pk_b, &pk_a, &ctx, &mut rng);
        let decrypted = rns_decrypt_f64(&ct, &s, &ctx);

        assert!(
            (decrypted - value).abs() < 0.01,
            "expected {}, got {}",
            value,
            decrypted
        );
    }

    #[test]
    fn homomorphic_add() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let ct1 = rns_encrypt_f64(3.0, &pk_b, &pk_a, &ctx, &mut rng);
        let ct2 = rns_encrypt_f64(7.0, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_sum = rns_ct_add(&ct1, &ct2);

        let decrypted = rns_decrypt_f64(&ct_sum, &s, &ctx);
        assert!(
            (decrypted - 10.0).abs() < 0.01,
            "expected 10.0, got {}",
            decrypted
        );
    }

    #[test]
    fn homomorphic_sub() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let ct1 = rns_encrypt_f64(10.0, &pk_b, &pk_a, &ctx, &mut rng);
        let ct2 = rns_encrypt_f64(3.0, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_diff = rns_ct_sub(&ct1, &ct2);

        let decrypted = rns_decrypt_f64(&ct_diff, &s, &ctx);
        assert!(
            (decrypted - 7.0).abs() < 0.01,
            "expected 7.0, got {}",
            decrypted
        );
    }

    #[test]
    fn homomorphic_scalar_mul() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let ct = rns_encrypt_f64(5.0, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_scaled = rns_ct_scalar_mul(&ct, 3);

        let decrypted = rns_decrypt_f64(&ct_scaled, &s, &ctx);
        assert!(
            (decrypted - 15.0).abs() < 0.01,
            "expected 15.0, got {}",
            decrypted
        );
    }

    #[test]
    fn homomorphic_multiply_and_rescale() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
        let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

        let ct1 = rns_encrypt_f64(3.0, &pk_b, &pk_a, &ctx, &mut rng);
        let ct2 = rns_encrypt_f64(4.0, &pk_b, &pk_a, &ctx, &mut rng);

        // Multiply: scale goes to Δ²
        let ct_prod = rns_ct_mul_relin(&ct1, &ct2, &evk, &ctx);
        assert!((ct_prod.scale - ctx.delta * ctx.delta).abs() < 1.0);
        assert_eq!(ct_prod.c0.num_primes, 3);

        // Rescale: drop one prime, scale goes back to ~Δ
        let ct_rescaled = rns_rescale(&ct_prod);
        assert_eq!(ct_rescaled.c0.num_primes, 2);
        assert_eq!(ct_rescaled.level, 1);

        let decrypted = rns_decrypt_f64(&ct_rescaled, &s, &ctx);
        assert!(
            (decrypted - 12.0).abs() < 1.0,
            "expected ~12.0, got {}",
            decrypted
        );
    }

    #[test]
    fn two_sequential_multiplies() {
        // This is IMPOSSIBLE with Phase 1 (single level)!
        // With 3 primes, we have 2 levels → can do 2 multiplications.
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
        let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

        let ct_x = rns_encrypt_f64(2.0, &pk_b, &pk_a, &ctx, &mut rng);

        // First multiply: x * x = x² (3 primes → 3 primes, scale Δ²)
        let ct_x2 = rns_ct_mul_relin(&ct_x, &ct_x, &evk, &ctx);
        let ct_x2_rescaled = rns_rescale(&ct_x2);
        assert_eq!(ct_x2_rescaled.c0.num_primes, 2);

        // Verify x² ≈ 4
        let dec_x2 = rns_decrypt_f64(&ct_x2_rescaled, &s, &ctx);
        assert!(
            (dec_x2 - 4.0).abs() < 1.0,
            "x² expected ~4.0, got {}",
            dec_x2
        );

        // Second multiply: x² * x² = x⁴ (2 primes → 2 primes, scale Δ²)
        let ct_x4 = rns_ct_mul_relin(&ct_x2_rescaled, &ct_x2_rescaled, &evk, &ctx);
        let ct_x4_rescaled = rns_rescale(&ct_x4);
        assert_eq!(ct_x4_rescaled.c0.num_primes, 1);

        // Verify x⁴ ≈ 16
        let dec_x4 = rns_decrypt_f64(&ct_x4_rescaled, &s, &ctx);
        assert!(
            (dec_x4 - 16.0).abs() < 5.0,
            "x⁴ expected ~16.0, got {}",
            dec_x4
        );
    }

    #[test]
    fn max_depth_reported_correctly() {
        let ctx3 = RnsCkksContext::new(3);
        assert_eq!(ctx3.max_depth(), 2);

        let ctx5 = RnsCkksContext::new(5);
        assert_eq!(ctx5.max_depth(), 4);

        let ctx10 = RnsCkksContext::new(10);
        assert_eq!(ctx10.max_depth(), 9);

        let ctx20 = RnsCkksContext::new(20);
        assert_eq!(ctx20.max_depth(), 19);
    }

    #[test]
    fn deep_chain_10_primes() {
        // Verify that 10-prime chain supports 8 sequential squarings.
        // x=1.1, square 8 times → x^256 ≈ 39.5 billion.
        // With delta=2^36 ≈ q, scale is preserved at every level.
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(10);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
        let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

        let ct = rns_encrypt_f64(1.1, &pk_b, &pk_a, &ctx, &mut rng);

        let mut ct_pow = ct.clone();
        let mut expected = 1.1f64;
        for _ in 0..8 {
            ct_pow = rns_ct_mul_relin(&ct_pow, &ct_pow, &evk, &ctx);
            ct_pow = rns_rescale(&ct_pow);
            expected *= expected;
        }

        assert_eq!(ct_pow.c0.num_primes, 2, "should have 2 primes after 8 squarings");

        let decrypted = rns_decrypt_f64(&ct_pow, &s, &ctx);
        let rel_error = (decrypted - expected).abs() / expected;
        assert!(
            rel_error < 0.01, // within 1% relative error
            "1.1^256: expected {:.2}, got {:.2}, rel_err {:.6}",
            expected, decrypted, rel_error
        );
    }

    // ═══════════════════════════════════════════════════════════════════
    // SIMD (slot packing) tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn simd_encrypt_decrypt_roundtrip() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);
        let decrypted = rns_decrypt_simd(&ct, &s, &ctx, values.len());

        for (i, (expected, got)) in values.iter().zip(decrypted.iter()).enumerate() {
            assert!(
                (expected - got).abs() < 0.01,
                "slot {} mismatch: expected {}, got {}",
                i, expected, got
            );
        }
    }

    #[test]
    fn simd_encrypt_decrypt_negative() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let values = vec![-3.5, 0.0, 7.2, -1.0, 0.001];
        let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);
        let decrypted = rns_decrypt_simd(&ct, &s, &ctx, values.len());

        for (i, (expected, got)) in values.iter().zip(decrypted.iter()).enumerate() {
            assert!(
                (expected - got).abs() < 0.01,
                "slot {} mismatch: expected {}, got {}",
                i, expected, got
            );
        }
    }

    #[test]
    fn simd_elementwise_add() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let a = vec![1.0, 2.0, 3.0, 4.0];
        let b = vec![10.0, 20.0, 30.0, 40.0];

        let ct_a = rns_encrypt_simd(&a, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_b = rns_encrypt_simd(&b, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_sum = rns_ct_add(&ct_a, &ct_b);

        let decrypted = rns_decrypt_simd(&ct_sum, &s, &ctx, 4);

        for i in 0..4 {
            let expected = a[i] + b[i];
            assert!(
                (decrypted[i] - expected).abs() < 0.01,
                "slot {} add: expected {}, got {}",
                i, expected, decrypted[i]
            );
        }
    }

    #[test]
    fn simd_elementwise_multiply() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
        let evk = rns_gen_eval_key(&s, &ctx, &mut rng);

        let a = vec![2.0, 3.0, 4.0, 5.0];
        let b = vec![10.0, 20.0, 30.0, 40.0];

        let ct_a = rns_encrypt_simd(&a, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_b = rns_encrypt_simd(&b, &pk_b, &pk_a, &ctx, &mut rng);

        let ct_prod = rns_ct_mul_relin(&ct_a, &ct_b, &evk, &ctx);
        let ct_prod = rns_rescale(&ct_prod);

        let decrypted = rns_decrypt_simd(&ct_prod, &s, &ctx, 4);

        for i in 0..4 {
            let expected = a[i] * b[i];
            assert!(
                (decrypted[i] - expected).abs() < 1.0,
                "slot {} mul: expected {}, got {}",
                i, expected, decrypted[i]
            );
        }
    }

    #[test]
    fn simd_scalar_multiply() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_scaled = rns_ct_scalar_mul(&ct, 5);

        let decrypted = rns_decrypt_simd(&ct_scaled, &s, &ctx, values.len());

        for (i, &v) in values.iter().enumerate() {
            let expected = v * 5.0;
            assert!(
                (decrypted[i] - expected).abs() < 0.05,
                "slot {} scalar: expected {}, got {}",
                i, expected, decrypted[i]
            );
        }
    }

    #[test]
    fn simd_large_vector() {
        // Fill all 2048 slots
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let values: Vec<f64> = (0..simd::NUM_SLOTS)
            .map(|i| (i as f64 * 0.1).sin() * 5.0)
            .collect();

        let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);
        let decrypted = rns_decrypt_simd(&ct, &s, &ctx, simd::NUM_SLOTS);

        let max_err = values
            .iter()
            .zip(decrypted.iter())
            .map(|(a, b)| (a - b).abs())
            .fold(0.0f64, f64::max);

        assert!(
            max_err < 0.01,
            "2048-slot roundtrip max error {} too large",
            max_err
        );
    }

    #[test]
    fn digit_decomposition_reconstructs() {
        // Verify that decomposing d2 and applying T^i gives back d2
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (_s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let ct1 = rns_encrypt_f64(3.0, &pk_b, &pk_a, &ctx, &mut rng);
        let ct2 = rns_encrypt_f64(4.0, &pk_b, &pk_a, &ctx, &mut rng);
        let triple = rns_ct_mul(&ct1, &ct2, &ctx);

        let digits = decompose_digits(&triple.d2, DECOMP_BITS_RELIN);
        let nd = digits.len();
        let base = 1i64 << DECOMP_BITS_RELIN;

        // Reconstruct: sum_i digit_i * T^i should equal d2
        let mut reconstructed = RnsPoly::from_coeffs(&[0i64], triple.d2.num_primes);
        for i in 0..nd {
            let t_power: Vec<i64> = NTT_PRIMES[..triple.d2.num_primes]
                .iter()
                .map(|&q| mod_pow(base, i as u64, q))
                .collect();
            let scaled = rns_channel_scalar_mul(&digits[i], &t_power);
            reconstructed = reconstructed.add(&scaled);
        }

        // Check equality via CRT reconstruction of first few coefficients
        let original = triple.d2.to_coeffs();
        let recon = reconstructed.to_coeffs();
        for j in 0..8 {
            assert_eq!(
                original[j], recon[j],
                "coefficient {} mismatch: {} vs {}",
                j, original[j], recon[j]
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Rotation tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn rotation_galois_element() {
        // rotation 0 → identity (m=1)
        assert_eq!(rotation_to_galois(0), 1);

        // rotation 1 → g = 5
        assert_eq!(rotation_to_galois(1), 5);

        // rotation 2 → g² = 25
        assert_eq!(rotation_to_galois(2), (5 * 5) % (2 * N));
    }

    #[test]
    fn rotation_plaintext_automorphism() {
        // Test automorphism on plaintext (no encryption) to verify slot permutation
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let delta = (1u64 << 30) as f64;
        let coeffs = simd::encode_simd(&values, delta);

        // Apply automorphism σ_5 (rotation by 1) to the plaintext polynomial
        let p = RnsPoly::from_coeffs(&coeffs, 1);
        let p_rot = p.apply_automorphism(rotation_to_galois(1));
        let rot_coeffs = p_rot.to_coeffs();

        // Decode the rotated polynomial
        let decoded = simd::decode_simd(&rot_coeffs, delta, 5);

        println!("Original: {:?}", values);
        println!("Decoded after σ_5: {:?}", decoded);

        // After rotation by 1: slot[i] should get value from slot[i+1]
        // So decoded[0] ≈ 2.0, decoded[1] ≈ 3.0, etc.
        assert!(
            (decoded[0] - 2.0).abs() < 0.01,
            "plaintext rot: slot 0 expected ~2.0, got {}",
            decoded[0]
        );
        assert!(
            (decoded[1] - 3.0).abs() < 0.01,
            "plaintext rot: slot 1 expected ~3.0, got {}",
            decoded[1]
        );
    }

    #[test]
    fn rotation_by_1() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
        let rot_keys = rns_gen_rotation_keys(&s, &[1], &ctx, &mut rng);

        // Encrypt [1, 2, 3, 4, 5, 0, 0, ...]
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);

        // Rotate by 1: expect [2, 3, 4, 5, 0, ..., 0, 1]
        let ct_rot = rns_rotate(&ct, 1, &rot_keys, &ctx);
        let decrypted = rns_decrypt_simd(&ct_rot, &s, &ctx, 5);

        // After rotation by 1: slot[i] gets value from slot[i+1]
        assert!(
            (decrypted[0] - 2.0).abs() < 0.5,
            "slot 0 after rot1: expected ~2.0, got {}",
            decrypted[0]
        );
        assert!(
            (decrypted[1] - 3.0).abs() < 0.5,
            "slot 1 after rot1: expected ~3.0, got {}",
            decrypted[1]
        );
        assert!(
            (decrypted[2] - 4.0).abs() < 0.5,
            "slot 2 after rot1: expected ~4.0, got {}",
            decrypted[2]
        );
        assert!(
            (decrypted[3] - 5.0).abs() < 0.5,
            "slot 3 after rot1: expected ~5.0, got {}",
            decrypted[3]
        );
    }

    #[test]
    fn rotation_by_2() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
        let rot_keys = rns_gen_rotation_keys(&s, &[2], &ctx, &mut rng);

        let values = vec![10.0, 20.0, 30.0, 40.0, 50.0, 60.0];
        let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);

        let ct_rot = rns_rotate(&ct, 2, &rot_keys, &ctx);
        let decrypted = rns_decrypt_simd(&ct_rot, &s, &ctx, 4);

        // After rotation by 2: slot[i] gets value from slot[i+2]
        assert!(
            (decrypted[0] - 30.0).abs() < 0.5,
            "slot 0 after rot2: expected ~30, got {}",
            decrypted[0]
        );
        assert!(
            (decrypted[1] - 40.0).abs() < 0.5,
            "slot 1 after rot2: expected ~40, got {}",
            decrypted[1]
        );
        assert!(
            (decrypted[2] - 50.0).abs() < 0.5,
            "slot 2 after rot2: expected ~50, got {}",
            decrypted[2]
        );
        assert!(
            (decrypted[3] - 60.0).abs() < 0.5,
            "slot 3 after rot2: expected ~60, got {}",
            decrypted[3]
        );
    }

    #[test]
    fn rotation_identity() {
        // Rotation by 0 should return the same ciphertext
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);
        let rot_keys = rns_gen_rotation_keys(&s, &[0], &ctx, &mut rng);

        let values = vec![1.0, 2.0, 3.0];
        let ct = rns_encrypt_simd(&values, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_rot = rns_rotate(&ct, 0, &rot_keys, &ctx);
        let decrypted = rns_decrypt_simd(&ct_rot, &s, &ctx, 3);

        for (i, &v) in values.iter().enumerate() {
            assert!(
                (decrypted[i] - v).abs() < 0.01,
                "slot {} after rot0: expected {}, got {}",
                i, v, decrypted[i]
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Plaintext SIMD multiply tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn plaintext_simd_multiply() {
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let ct_vals = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let plain_vals = vec![4.0, 5.0, 6.0, 7.0, 8.0];

        let ct = rns_encrypt_simd(&ct_vals, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_prod = rns_ct_mul_plain_simd(&ct, &plain_vals, &ctx);

        // Scale is now Δ², need to rescale
        assert!((ct_prod.scale - ctx.delta * ctx.delta).abs() < 1.0);
        let ct_rescaled = rns_rescale(&ct_prod);

        let decrypted = rns_decrypt_simd(&ct_rescaled, &s, &ctx, 5);

        for i in 0..5 {
            let expected = ct_vals[i] * plain_vals[i];
            assert!(
                (decrypted[i] - expected).abs() < 1.0,
                "slot {} plain_mul: expected {}, got {}",
                i, expected, decrypted[i]
            );
        }
    }

    #[test]
    fn plaintext_simd_multiply_identity() {
        // Multiply by all-ones plaintext → should return original values
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let ct_vals = vec![3.0, -1.5, 7.0, 0.5];
        let ones = vec![1.0, 1.0, 1.0, 1.0];

        let ct = rns_encrypt_simd(&ct_vals, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_prod = rns_ct_mul_plain_simd(&ct, &ones, &ctx);
        let ct_rescaled = rns_rescale(&ct_prod);

        let decrypted = rns_decrypt_simd(&ct_rescaled, &s, &ctx, 4);

        for i in 0..4 {
            assert!(
                (decrypted[i] - ct_vals[i]).abs() < 1.0,
                "slot {} plain_mul_id: expected {}, got {}",
                i, ct_vals[i], decrypted[i]
            );
        }
    }

    // ═══════════════════════════════════════════════════════════════════
    // Matrix-vector multiply tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn matvec_identity_matrix() {
        // I · x = x
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let d = 4;
        // Identity matrix (row-major)
        let mut identity = vec![0.0f64; d * d];
        for i in 0..d {
            identity[i * d + i] = 1.0;
        }

        let x = vec![1.0, 2.0, 3.0, 4.0];
        let x_rep = replicate_vector(&x, d);
        let rotations: Vec<i32> = (1..d as i32).collect();
        let rot_keys = rns_gen_rotation_keys(&s, &rotations, &ctx, &mut rng);

        let ct_x = rns_encrypt_simd(&x_rep, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_result = rns_matvec(&ct_x, &identity, d, &rot_keys, &ctx);
        let ct_result = rns_rescale(&ct_result);

        let decrypted = rns_decrypt_simd(&ct_result, &s, &ctx, d);

        for i in 0..d {
            assert!(
                (decrypted[i] - x[i]).abs() < 1.0,
                "slot {} identity matvec: expected {}, got {}",
                i, x[i], decrypted[i]
            );
        }
    }

    #[test]
    fn matvec_4x4() {
        // Arbitrary 4×4 matrix-vector product
        let mut rng = test_rng();
        let ctx = RnsCkksContext::new(3);
        let (s, pk_b, pk_a) = rns_keygen(&ctx, &mut rng);

        let d = 4;
        // W = [[1,2,3,4],[5,6,7,8],[9,10,11,12],[13,14,15,16]]
        let w = vec![
            1.0, 2.0, 3.0, 4.0,
            5.0, 6.0, 7.0, 8.0,
            9.0, 10.0, 11.0, 12.0,
            13.0, 14.0, 15.0, 16.0,
        ];
        let x = vec![1.0, 2.0, 3.0, 4.0];
        let x_rep = replicate_vector(&x, d);

        // Expected: W·x
        let mut expected = vec![0.0f64; d];
        for i in 0..d {
            for j in 0..d {
                expected[i] += w[i * d + j] * x[j];
            }
        }
        // expected = [30, 70, 110, 150]

        let rotations: Vec<i32> = (1..d as i32).collect();
        let rot_keys = rns_gen_rotation_keys(&s, &rotations, &ctx, &mut rng);

        let ct_x = rns_encrypt_simd(&x_rep, &pk_b, &pk_a, &ctx, &mut rng);
        let ct_result = rns_matvec(&ct_x, &w, d, &rot_keys, &ctx);
        let ct_result = rns_rescale(&ct_result);

        let decrypted = rns_decrypt_simd(&ct_result, &s, &ctx, d);

        println!("Expected: {:?}", expected);
        println!("Got:      {:?}", decrypted);

        for i in 0..d {
            assert!(
                (decrypted[i] - expected[i]).abs() < 2.0,
                "slot {} matvec: expected {}, got {}",
                i, expected[i], decrypted[i]
            );
        }
    }
}
