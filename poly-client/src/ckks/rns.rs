//! Residue Number System (RNS) polynomial representation.
//!
//! Stores a polynomial as separate residues modulo each NTT-friendly prime.
//! This enables:
//! - O(N log N) multiplication via NTT per channel (vs O(N²) naive)
//! - Multi-level modulus chain: drop a prime to rescale after multiplication
//! - Parallel-friendly: each channel is independent
//!
//! An `RnsPoly` with `k` active primes represents a polynomial in
//! Z_Q[X]/(X^N+1) where Q = q_0 * q_1 * ... * q_{k-1}.

use serde::{Deserialize, Serialize};

use super::ntt::{mod_inv, NttContext, NTT_PRIMES};
use super::params::N;

// ═══════════════════════════════════════════════════════════════════════
// RNS Polynomial
// ═══════════════════════════════════════════════════════════════════════

/// A polynomial in RNS representation.
///
/// `residues[i]` contains the polynomial's coefficients reduced mod `NTT_PRIMES[i]`,
/// stored in [0, q_i) form. The number of active primes determines the total
/// modulus Q = product of active primes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RnsPoly {
    /// Residues: `residues[i][j]` = coefficient j modulo prime i.
    /// Each inner vec has length N. Values in [0, q_i).
    pub residues: Vec<Vec<i64>>,
    /// Number of active primes (indices 0..num_primes into NTT_PRIMES).
    pub num_primes: usize,
}

impl RnsPoly {
    /// Create an RNS polynomial with all zeros using `num_primes` primes.
    pub fn zero(num_primes: usize) -> Self {
        assert!(
            num_primes <= NTT_PRIMES.len(),
            "requested {} primes, only {} available",
            num_primes,
            NTT_PRIMES.len()
        );
        let residues = (0..num_primes).map(|_| vec![0i64; N]).collect();
        Self {
            residues,
            num_primes,
        }
    }

    /// Create an RNS polynomial from centered coefficient representation.
    ///
    /// Takes coefficients in arbitrary range (typically centered around 0)
    /// and reduces them modulo each active prime.
    pub fn from_coeffs(coeffs: &[i64], num_primes: usize) -> Self {
        assert!(
            num_primes <= NTT_PRIMES.len(),
            "requested {} primes, only {} available",
            num_primes,
            NTT_PRIMES.len()
        );
        assert!(
            coeffs.len() <= N,
            "coefficient count {} exceeds ring dimension {}",
            coeffs.len(),
            N
        );

        let mut residues = Vec::with_capacity(num_primes);
        for p_idx in 0..num_primes {
            let q = NTT_PRIMES[p_idx];
            let mut res = vec![0i64; N];
            for (i, &c) in coeffs.iter().enumerate() {
                res[i] = ((c as i128 % q as i128 + q as i128) % q as i128) as i64;
            }
            residues.push(res);
        }

        Self {
            residues,
            num_primes,
        }
    }

    /// Reconstruct centered coefficients via CRT (Chinese Remainder Theorem).
    ///
    /// Only used for decryption/verification — expensive for many primes.
    /// Returns coefficients in centered range around 0.
    pub fn to_coeffs(&self) -> Vec<i64> {
        if self.num_primes == 1 {
            // Single prime: just center
            let q = NTT_PRIMES[0];
            let half = q / 2;
            return self.residues[0]
                .iter()
                .map(|&v| if v > half { v - q } else { v })
                .collect();
        }

        // Multi-prime CRT reconstruction
        // Q = product of all active primes
        // For each coefficient position, reconstruct via CRT
        let primes = &NTT_PRIMES[..self.num_primes];

        // Compute Q_i = Q / q_i and M_i = Q_i^(-1) mod q_i for each prime
        // Since Q can be very large (180+ bits), we work in i128 where possible
        // and use a Garner's algorithm approach for reconstruction
        let mut coeffs = vec![0i64; N];

        for j in 0..N {
            // Garner's algorithm: reconstruct coefficient j
            let val = garner_reconstruct(
                &(0..self.num_primes)
                    .map(|i| self.residues[i][j])
                    .collect::<Vec<_>>(),
                primes,
            );
            coeffs[j] = val;
        }

        coeffs
    }

    /// Coefficient-wise addition mod each prime.
    pub fn add(&self, other: &RnsPoly) -> RnsPoly {
        assert_eq!(self.num_primes, other.num_primes);
        let mut residues = Vec::with_capacity(self.num_primes);
        for i in 0..self.num_primes {
            let q = NTT_PRIMES[i];
            let res: Vec<i64> = self.residues[i]
                .iter()
                .zip(other.residues[i].iter())
                .map(|(&a, &b)| ((a + b) % q + q) % q)
                .collect();
            residues.push(res);
        }
        RnsPoly {
            residues,
            num_primes: self.num_primes,
        }
    }

    /// Coefficient-wise subtraction mod each prime.
    pub fn sub(&self, other: &RnsPoly) -> RnsPoly {
        assert_eq!(self.num_primes, other.num_primes);
        let mut residues = Vec::with_capacity(self.num_primes);
        for i in 0..self.num_primes {
            let q = NTT_PRIMES[i];
            let res: Vec<i64> = self.residues[i]
                .iter()
                .zip(other.residues[i].iter())
                .map(|(&a, &b)| ((a - b) % q + q) % q)
                .collect();
            residues.push(res);
        }
        RnsPoly {
            residues,
            num_primes: self.num_primes,
        }
    }

    /// Negate all coefficients mod each prime.
    pub fn neg(&self) -> RnsPoly {
        let mut residues = Vec::with_capacity(self.num_primes);
        for i in 0..self.num_primes {
            let q = NTT_PRIMES[i];
            let res: Vec<i64> = self.residues[i]
                .iter()
                .map(|&a| if a == 0 { 0 } else { q - a })
                .collect();
            residues.push(res);
        }
        RnsPoly {
            residues,
            num_primes: self.num_primes,
        }
    }

    /// Multiply by an integer scalar mod each prime.
    pub fn scalar_mul(&self, scalar: i64) -> RnsPoly {
        let mut residues = Vec::with_capacity(self.num_primes);
        for i in 0..self.num_primes {
            let q = NTT_PRIMES[i];
            let s = ((scalar as i128 % q as i128) + q as i128) as i64;
            let res: Vec<i64> = self.residues[i]
                .iter()
                .map(|&a| (a as i128 * s as i128 % q as i128) as i64)
                .collect();
            residues.push(res);
        }
        RnsPoly {
            residues,
            num_primes: self.num_primes,
        }
    }

    /// Polynomial multiplication using NTT (O(N log N) per channel).
    ///
    /// Computes negacyclic convolution in Z_Q[X]/(X^N+1) where
    /// Q = product of active primes.
    pub fn mul(&self, other: &RnsPoly, contexts: &[NttContext]) -> RnsPoly {
        assert_eq!(self.num_primes, other.num_primes);
        assert!(
            contexts.len() >= self.num_primes,
            "need {} NTT contexts, got {}",
            self.num_primes,
            contexts.len()
        );

        let mut residues = Vec::with_capacity(self.num_primes);
        for i in 0..self.num_primes {
            let c = contexts[i].mul(&self.residues[i], &other.residues[i]);
            residues.push(c);
        }
        RnsPoly {
            residues,
            num_primes: self.num_primes,
        }
    }

    /// Apply Galois automorphism σ_m: X → X^m in the ring Z[X]/(X^N+1).
    ///
    /// For each coefficient a_j at position j, the monomial X^j maps to X^{m*j}.
    /// In the quotient ring: X^k = (-1)^{floor(k/N)} · X^{k mod N} since X^N = -1.
    ///
    /// `m` must be odd and coprime to 2N. This is a permutation (no collision)
    /// because gcd(m, 2N) = 1 guarantees j → m*j mod 2N is a bijection.
    pub fn apply_automorphism(&self, m: usize) -> RnsPoly {
        let two_n = 2 * N;
        assert!(m % 2 == 1, "automorphism index must be odd");
        assert!(m < two_n, "automorphism index must be < 2N");

        let mut residues = Vec::with_capacity(self.num_primes);
        for ch in 0..self.num_primes {
            let q = NTT_PRIMES[ch];
            let mut out = vec![0i64; N];
            for j in 0..N {
                let idx = (m * j) % two_n;
                if idx < N {
                    out[idx] = self.residues[ch][j];
                } else {
                    // X^N = -1, so X^idx = -X^{idx-N}
                    out[idx - N] = (q - self.residues[ch][j]) % q;
                }
            }
            residues.push(out);
        }
        RnsPoly {
            residues,
            num_primes: self.num_primes,
        }
    }

    /// Drop the last prime (rescaling step).
    ///
    /// After multiplication doubles the scale, we divide by the last prime
    /// q_L to reduce the scale back. This is the core of leveled FHE.
    ///
    /// Steps:
    /// 1. Reconstruct the value mod q_L (the prime being dropped)
    /// 2. For each remaining prime q_i, compute: result = (self - r_L) / q_L mod q_i
    ///    where r_L = self mod q_L
    pub fn drop_last_prime(&self) -> RnsPoly {
        assert!(
            self.num_primes > 1,
            "cannot drop last prime from single-prime polynomial"
        );

        let last_idx = self.num_primes - 1;
        let q_last = NTT_PRIMES[last_idx];
        let q_last_inv: Vec<i64> = (0..last_idx)
            .map(|i| mod_inv(q_last, NTT_PRIMES[i]))
            .collect();

        let mut residues = Vec::with_capacity(last_idx);
        for i in 0..last_idx {
            let q_i = NTT_PRIMES[i] as i128;

            let res: Vec<i64> = (0..N)
                .map(|j| {
                    // r_L = value mod q_last
                    let r_last = self.residues[last_idx][j] as i128;
                    // Convert r_last to mod q_i
                    let r_last_mod_qi = (r_last % q_i + q_i) % q_i;
                    // (self_i - r_last) * q_last^(-1) mod q_i
                    let diff = (self.residues[i][j] as i128 - r_last_mod_qi + q_i) % q_i;
                    (diff * q_last_inv[i] as i128 % q_i) as i64
                })
                .collect();
            residues.push(res);
        }

        RnsPoly {
            residues,
            num_primes: last_idx,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// CRT Reconstruction (Garner's Algorithm)
// ═══════════════════════════════════════════════════════════════════════

/// Reconstruct a value from its residues using Garner's algorithm.
///
/// Returns a centered value (can be negative) that is the unique integer
/// in (-Q/2, Q/2] satisfying all the residue conditions.
fn garner_reconstruct(residues: &[i64], primes: &[i64]) -> i64 {
    let k = residues.len();
    if k == 1 {
        let q = primes[0];
        let half = q / 2;
        return if residues[0] > half {
            residues[0] - q
        } else {
            residues[0]
        };
    }

    // For small prime counts (≤ 3), use fast i128 path
    if k <= 3 {
        return garner_reconstruct_i128(residues, primes);
    }

    // For many primes, use variable-width arithmetic
    garner_reconstruct_wide(residues, primes)
}

/// Fast path for ≤ 3 primes: i128 is sufficient (~108 bits).
fn garner_reconstruct_i128(residues: &[i64], primes: &[i64]) -> i64 {
    let k = residues.len();
    let mut v = vec![0i128; k];
    v[0] = residues[0] as i128;

    for i in 1..k {
        let q_i = primes[i] as i128;
        let mut u = residues[i] as i128;
        for j in 0..i {
            u = ((u - v[j]) % q_i + q_i) % q_i;
            let inv = mod_inv(primes[j], primes[i]) as i128;
            u = u * inv % q_i;
        }
        v[i] = u;
    }

    let mut result: i128 = v[0];
    let mut product: i128 = 1;
    for i in 1..k {
        product *= primes[i - 1] as i128;
        result += v[i] * product;
    }

    let mut q_total: i128 = 1;
    for &p in primes {
        q_total *= p as i128;
    }

    result %= q_total;
    if result < 0 { result += q_total; }
    let half_q = q_total / 2;
    if result > half_q { result -= q_total; }
    result as i64
}

/// Wide path for 4+ primes: uses variable-width arithmetic.
fn garner_reconstruct_wide(residues: &[i64], primes: &[i64]) -> i64 {
    let k = residues.len();
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

    // Step 2: Reconstruct as wide unsigned
    let mut result = wide_from_u64(v[0] as u64, num_limbs);
    let mut product = wide_from_u64(1, num_limbs);
    for i in 1..k {
        product = wide_mul_u64(&product, primes[i - 1] as u64);
        let term = wide_mul_u64(&product, v[i] as u64);
        result = wide_add(&result, &term);
    }

    // Step 3: Compute Q = product of all primes
    let mut q_total = wide_from_u64(1, num_limbs);
    for &p in primes {
        q_total = wide_mul_u64(&q_total, p as u64);
    }

    // Step 4: Center — if result > Q/2, return result - Q (negative)
    let half_q = wide_shr(&q_total, 1);
    if wide_gt(&result, &half_q) {
        // Centered value = result - Q (negative, fits in i64)
        let diff = wide_sub(&q_total, &result);
        -(diff[0] as i64)
    } else {
        // Positive value, fits in i64
        result[0] as i64
    }
}

// ── Wide integer helpers for CRT reconstruction ─────────────────────

fn wide_from_u64(v: u64, n: usize) -> Vec<u64> {
    let mut limbs = vec![0u64; n];
    limbs[0] = v;
    limbs
}

fn wide_mul_u64(a: &[u64], b: u64) -> Vec<u64> {
    let n = a.len();
    let mut result = vec![0u64; n];
    let mut carry = 0u128;
    for i in 0..n {
        let prod = a[i] as u128 * b as u128 + carry;
        result[i] = prod as u64;
        carry = prod >> 64;
    }
    result
}

fn wide_add(a: &[u64], b: &[u64]) -> Vec<u64> {
    let n = a.len();
    let mut result = vec![0u64; n];
    let mut carry = 0u128;
    for i in 0..n {
        let bv = if i < b.len() { b[i] as u128 } else { 0 };
        let sum = a[i] as u128 + bv + carry;
        result[i] = sum as u64;
        carry = sum >> 64;
    }
    result
}

fn wide_sub(a: &[u64], b: &[u64]) -> Vec<u64> {
    let n = a.len();
    let mut result = vec![0u64; n];
    let mut borrow = 0i128;
    for i in 0..n {
        let bv = if i < b.len() { b[i] as i128 } else { 0 };
        let diff = a[i] as i128 - bv - borrow;
        if diff < 0 {
            result[i] = (diff + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            result[i] = diff as u64;
            borrow = 0;
        }
    }
    result
}

fn wide_shr(a: &[u64], bits: u32) -> Vec<u64> {
    let n = a.len();
    let mut result = vec![0u64; n];
    for i in 0..n {
        result[i] = a[i] >> bits;
        if i + 1 < n {
            result[i] |= a[i + 1] << (64 - bits);
        }
    }
    result
}

fn wide_gt(a: &[u64], b: &[u64]) -> bool {
    let n = a.len();
    for i in (0..n).rev() {
        let bv = if i < b.len() { b[i] } else { 0 };
        if a[i] > bv { return true; }
        if a[i] < bv { return false; }
    }
    false // equal
}

// ═══════════════════════════════════════════════════════════════════════
// Context pool
// ═══════════════════════════════════════════════════════════════════════

/// Create NTT contexts for all NTT_PRIMES.
pub fn create_ntt_contexts() -> Vec<NttContext> {
    NTT_PRIMES.iter().map(|&q| NttContext::new(q)).collect()
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn contexts() -> Vec<NttContext> {
        create_ntt_contexts()
    }

    #[test]
    fn zero_is_zero() {
        let p = RnsPoly::zero(3);
        assert_eq!(p.num_primes, 3);
        let coeffs = p.to_coeffs();
        for &c in &coeffs {
            assert_eq!(c, 0);
        }
    }

    #[test]
    fn from_coeffs_roundtrip_single_prime() {
        let coeffs = vec![1, 2, 3, -4, 5];
        let p = RnsPoly::from_coeffs(&coeffs, 1);
        let back = p.to_coeffs();
        for i in 0..5 {
            assert_eq!(back[i], coeffs[i], "mismatch at {}", i);
        }
        for i in 5..N {
            assert_eq!(back[i], 0);
        }
    }

    #[test]
    fn from_coeffs_roundtrip_multi_prime() {
        let coeffs = vec![100, -200, 300, -400, 500];
        let p = RnsPoly::from_coeffs(&coeffs, 3);
        let back = p.to_coeffs();
        for i in 0..5 {
            assert_eq!(back[i], coeffs[i], "mismatch at {}: expected {}, got {}", i, coeffs[i], back[i]);
        }
    }

    #[test]
    fn add_correctness() {
        let a = RnsPoly::from_coeffs(&[10, 20, 30], 2);
        let b = RnsPoly::from_coeffs(&[5, -10, 15], 2);
        let c = a.add(&b);
        let coeffs = c.to_coeffs();
        assert_eq!(coeffs[0], 15);
        assert_eq!(coeffs[1], 10);
        assert_eq!(coeffs[2], 45);
    }

    #[test]
    fn sub_correctness() {
        let a = RnsPoly::from_coeffs(&[10, 20, 30], 2);
        let b = RnsPoly::from_coeffs(&[5, -10, 15], 2);
        let c = a.sub(&b);
        let coeffs = c.to_coeffs();
        assert_eq!(coeffs[0], 5);
        assert_eq!(coeffs[1], 30);
        assert_eq!(coeffs[2], 15);
    }

    #[test]
    fn neg_correctness() {
        let a = RnsPoly::from_coeffs(&[10, -20, 30], 2);
        let b = a.neg();
        let coeffs = b.to_coeffs();
        assert_eq!(coeffs[0], -10);
        assert_eq!(coeffs[1], 20);
        assert_eq!(coeffs[2], -30);
    }

    #[test]
    fn scalar_mul_correctness() {
        let a = RnsPoly::from_coeffs(&[10, -20, 30], 2);
        let b = a.scalar_mul(3);
        let coeffs = b.to_coeffs();
        assert_eq!(coeffs[0], 30);
        assert_eq!(coeffs[1], -60);
        assert_eq!(coeffs[2], 90);
    }

    #[test]
    fn ntt_mul_simple() {
        let ctxs = contexts();
        // (3 + X) * (2 + 4X) = 6 + 14X + 4X^2
        let a = RnsPoly::from_coeffs(&[3, 1], 3);
        let b = RnsPoly::from_coeffs(&[2, 4], 3);
        let c = a.mul(&b, &ctxs);
        let coeffs = c.to_coeffs();
        assert_eq!(coeffs[0], 6);
        assert_eq!(coeffs[1], 14);
        assert_eq!(coeffs[2], 4);
        for i in 3..N {
            assert_eq!(coeffs[i], 0, "non-zero at {}", i);
        }
    }

    #[test]
    fn ntt_mul_negacyclic() {
        let ctxs = contexts();
        // X^(N-1) * X = X^N = -1
        let mut a_coeffs = vec![0i64; N];
        a_coeffs[N - 1] = 1;
        let mut b_coeffs = vec![0i64; N];
        b_coeffs[1] = 1;

        let a = RnsPoly::from_coeffs(&a_coeffs, 3);
        let b = RnsPoly::from_coeffs(&b_coeffs, 3);
        let c = a.mul(&b, &ctxs);
        let coeffs = c.to_coeffs();
        assert_eq!(coeffs[0], -1, "X^N should be -1");
        for i in 1..N {
            assert_eq!(coeffs[i], 0);
        }
    }

    #[test]
    fn drop_last_prime_divides() {
        // drop_last_prime divides by q_last
        // Value = 42 * q_last → after dividing, should get ~42
        let q_last = NTT_PRIMES[2]; // third prime
        let val = 42 * q_last;
        let a = RnsPoly::from_coeffs(&[val], 3);
        assert_eq!(a.num_primes, 3);

        let b = a.drop_last_prime();
        assert_eq!(b.num_primes, 2);
        let coeffs = b.to_coeffs();

        assert!(
            (coeffs[0] - 42).abs() <= 1,
            "expected ~42 after dividing by q_last, got {}",
            coeffs[0]
        );
    }

    #[test]
    fn drop_last_prime_small_value_goes_to_zero() {
        // A small value (42) divided by q_last (68 billion) → ~0
        let a = RnsPoly::from_coeffs(&[42], 3);
        let b = a.drop_last_prime();
        let coeffs = b.to_coeffs();
        assert_eq!(coeffs[0], 0, "42 / q_last should round to 0");
    }

    #[test]
    fn garner_crt_basic() {
        // 2-prime CRT: find x such that x ≡ 3 (mod 5), x ≡ 1 (mod 7)
        // Answer: x = 8 (since 8 % 5 = 3, 8 % 7 = 1)
        let val = garner_reconstruct(&[3, 1], &[5, 7]);
        assert_eq!(val, 8);
    }

    #[test]
    fn garner_crt_ntt_primes() {
        // Encode a small value and reconstruct
        let val = 12345i64;
        let residues: Vec<i64> = NTT_PRIMES[..3]
            .iter()
            .map(|&q| val % q)
            .collect();
        let reconstructed = garner_reconstruct(&residues, &NTT_PRIMES[..3]);
        assert_eq!(reconstructed, val);
    }

    // ═══════════════════════════════════════════════════════════════════
    // Automorphism tests
    // ═══════════════════════════════════════════════════════════════════

    #[test]
    fn automorphism_identity() {
        // σ_1: X → X (identity automorphism)
        let coeffs = vec![1, 2, 3, -4, 5];
        let p = RnsPoly::from_coeffs(&coeffs, 3);
        let q = p.apply_automorphism(1);
        let result = q.to_coeffs();
        for i in 0..5 {
            assert_eq!(result[i], coeffs[i], "identity failed at {}", i);
        }
    }

    #[test]
    fn automorphism_x_to_x3() {
        // σ_3: X → X^3
        // Polynomial: a_0 + a_1·X
        // After: a_0 + a_1·X^3
        let p = RnsPoly::from_coeffs(&[10, 20], 3);
        let q = p.apply_automorphism(3);
        let result = q.to_coeffs();
        // coeff[0] = 10, coeff[3] = 20, rest = 0
        assert_eq!(result[0], 10);
        assert_eq!(result[3], 20);
        assert_eq!(result[1], 0);
        assert_eq!(result[2], 0);
    }

    #[test]
    fn automorphism_negacyclic_wrap() {
        // σ_3 on X^{N-1}: (X^3)^{N-1} = X^{3N-3} = X^N · X^{2N-3} = -X^{2N-3}
        // 2N-3 mod N = N-3, and there's one factor of X^N so sign = -1
        // More precisely: 3*(N-1) = 3N - 3.
        // (3N-3) mod 2N = N - 3 (since 3N-3 - 2N = N-3 < N, and N-3 < N).
        // Wait: 3*(N-1) = 3N - 3. (3N-3) % (2N) = N - 3. Since N-3 < N, no sign flip.
        // Actually: idx = 3*(N-1) % (2*N) = (3*4095) % 8192 = 12285 % 8192 = 4093
        // 4093 < N=4096, so output[4093] = input[N-1], no sign flip
        let mut coeffs = vec![0i64; N];
        coeffs[N - 1] = 7;
        let p = RnsPoly::from_coeffs(&coeffs, 2);
        let q = p.apply_automorphism(3);
        let result = q.to_coeffs();
        let expected_idx = (3 * (N - 1)) % (2 * N);
        if expected_idx < N {
            assert_eq!(result[expected_idx], 7);
        } else {
            assert_eq!(result[expected_idx - N], -7);
        }
    }

    #[test]
    fn automorphism_roundtrip() {
        // σ_m then σ_{m^{-1}} should return original polynomial
        // m = 5, m^{-1} mod 2N = 5^{-1} mod 8192
        // 5 * x ≡ 1 (mod 8192)
        // x = 5^{-1} mod 8192
        let two_n = 2 * N;
        let m = 5usize;
        // Compute m_inv such that m * m_inv ≡ 1 (mod 2N)
        let m_inv = {
            let mut inv = 1usize;
            for candidate in (1..two_n).step_by(2) {
                if (m * candidate) % two_n == 1 {
                    inv = candidate;
                    break;
                }
            }
            inv
        };
        assert_eq!((m * m_inv) % two_n, 1, "failed to find inverse");

        let coeffs: Vec<i64> = (0..N as i64).map(|i| (i * 7 + 3) % 100 - 50).collect();
        let p = RnsPoly::from_coeffs(&coeffs, 3);
        let q = p.apply_automorphism(m).apply_automorphism(m_inv);
        let result = q.to_coeffs();
        for i in 0..N {
            assert_eq!(result[i], coeffs[i], "roundtrip failed at {}", i);
        }
    }

    #[test]
    fn garner_crt_negative() {
        let val = -5678i64;
        let residues: Vec<i64> = NTT_PRIMES[..3]
            .iter()
            .map(|&q| ((val as i128 % q as i128 + q as i128) % q as i128) as i64)
            .collect();
        let reconstructed = garner_reconstruct(&residues, &NTT_PRIMES[..3]);
        assert_eq!(reconstructed, val);
    }
}
