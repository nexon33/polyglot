//! Number Theoretic Transform (NTT) for O(N log N) polynomial multiplication.
//!
//! Replaces the naive O(N²) negacyclic convolution in `poly.rs` with NTT-based
//! multiplication. Each NTT-friendly prime q must satisfy q ≡ 1 (mod 2N) so
//! that primitive 2N-th roots of unity exist in Z_q.
//!
//! # Architecture
//!
//! NTT operates in the "evaluation" domain: forward NTT converts coefficient
//! representation to point-value form, element-wise multiply is polynomial
//! product, inverse NTT converts back. For negacyclic convolution (X^N + 1),
//! we use the "twisted" NTT with a 2N-th root of unity.
//!
//! # Primes
//!
//! We use multiple NTT-friendly primes for the RNS/CRT modulus chain.
//! Each prime is ~36 bits, and we pick enough primes to support L multiplication
//! levels plus a special prime for key switching.

use super::params::N;

// ═══════════════════════════════════════════════════════════════════════
// NTT-friendly primes: q ≡ 1 (mod 2N) where 2N = 8192
// ═══════════════════════════════════════════════════════════════════════

/// NTT-friendly primes for the modulus chain.
///
/// Each prime q satisfies:
/// - q ≡ 1 (mod 8192), so primitive 2N-th roots of unity exist
/// - q fits comfortably in i64 (< 2^37)
/// - q * q fits in i128 for multiplication without overflow
///
/// 20 primes of ~36 bits each. Use any prefix for the desired depth:
/// - 5 primes → 4 levels (basic neural net inference)
/// - 10 primes → 9 levels (polynomial activations, degree-7 SiLU)
/// - 15 primes → 14 levels (bootstrapping, deep circuits)
/// - 20 primes → 19 levels (full transformer inference)
pub const NTT_PRIMES: [i64; 20] = [
    68719403009,
    68719230977,
    68719206401,
    68719190017,
    68719157249,
    68718764033,
    68718428161,
    68718346241,
    68718305281,
    68717928449,
    68717740033,
    68717682689,
    68717592577,
    68717363201,
    68717223937,
    68717142017,
    68717076481,
    68717068289,
    68716781569,
    68716707841,
];

/// Precomputed primitive 2N-th roots of unity (ψ) for each prime.
/// ψ = g^((q-1)/(2N)) where g is the smallest generator that works.
/// Satisfies ψ^N ≡ -1 (mod q) and ψ^(2N) ≡ 1 (mod q).
const NTT_ROOTS: [i64; 20] = [
    5546991020,
    41019061109,
    41978190371,
    60726334289,
    36981953102,
    1937762328,
    22370218154,
    6173043660,
    67995098886,
    59422617459,
    54640452894,
    52499569528,
    36661170687,
    63942896849,
    12605105312,
    27475774088,
    37399532359,
    45270410758,
    20421207940,
    18573596375,
];

/// Number of levels supported = num_primes - 1.
/// We keep one prime as the "base" that's never dropped.
pub const MAX_LEVELS: usize = NTT_PRIMES.len() - 1;

// ═══════════════════════════════════════════════════════════════════════
// Modular arithmetic helpers
// ═══════════════════════════════════════════════════════════════════════

/// Modular exponentiation: base^exp mod modulus.
/// Uses binary method with i128 intermediates to avoid overflow.
pub fn mod_pow(mut base: i64, mut exp: u64, modulus: i64) -> i64 {
    let m = modulus as i128;
    let mut result: i128 = 1;
    base = ((base as i128 % m + m) % m) as i64;
    let mut b = base as i128;
    while exp > 0 {
        if exp & 1 == 1 {
            result = result * b % m;
        }
        exp >>= 1;
        b = b * b % m;
    }
    result as i64
}

/// Modular inverse via Fermat's little theorem: a^(-1) = a^(p-2) mod p.
/// Only valid when p is prime and a ≢ 0 (mod p).
pub fn mod_inv(a: i64, p: i64) -> i64 {
    mod_pow(a, (p - 2) as u64, p)
}

/// Find a primitive 2N-th root of unity modulo q.
///
/// Since q ≡ 1 (mod 2N), such a root exists. We find a generator g
/// of Z_q* and compute ψ = g^((q-1)/(2N)).
///
/// Verifies: ψ^N = -1 (mod q) and ψ^(2N) = 1 (mod q).
pub fn find_primitive_root(q: i64) -> i64 {
    // Check precomputed roots first
    for (i, &prime) in NTT_PRIMES.iter().enumerate() {
        if prime == q {
            return NTT_ROOTS[i];
        }
    }

    // Fallback: brute-force search for unknown primes
    let two_n = (2 * N) as u64;
    let exp = ((q - 1) as u64) / two_n;

    for g in 2..1000 {
        let psi = mod_pow(g, exp, q);
        let psi_n = mod_pow(psi, N as u64, q);
        if psi_n == q - 1 {
            return psi;
        }
    }
    panic!("no primitive 2N-th root found for q={}", q);
}

// ═══════════════════════════════════════════════════════════════════════
// NTT: Forward and Inverse
// ═══════════════════════════════════════════════════════════════════════

/// Precomputed NTT tables for a specific prime.
///
/// Stores the twiddle factors (powers of ψ and ψ^(-1)) so they don't
/// need to be recomputed on every NTT call.
#[derive(Clone, Debug)]
pub struct NttContext {
    /// The NTT-friendly prime.
    pub q: i64,
    /// Primitive 2N-th root of unity (ψ).
    pub psi: i64,
    /// Inverse of ψ.
    pub psi_inv: i64,
    /// Inverse of N mod q (for inverse NTT scaling).
    pub n_inv: i64,
    /// Powers of ψ for twist.
    pub psi_powers: Vec<i64>,
    /// Powers of ψ^(-1) for inverse twist.
    pub psi_inv_powers: Vec<i64>,
}

impl NttContext {
    /// Create an NTT context for the given prime.
    pub fn new(q: i64) -> Self {
        let psi = find_primitive_root(q);
        let psi_inv = mod_inv(psi, q);
        let n_inv = mod_inv(N as i64, q);

        let psi_powers = precompute_twiddles(psi, q);
        let psi_inv_powers = precompute_twiddles(psi_inv, q);

        Self {
            q,
            psi,
            psi_inv,
            n_inv,
            psi_powers,
            psi_inv_powers,
        }
    }

    /// Forward NTT: coefficient → evaluation domain.
    ///
    /// Input: N coefficients in [0, q) or centered range.
    /// Output: N evaluation points in [0, q).
    ///
    /// Uses the "negacyclic" NTT by premultiplying with powers of ψ,
    /// which computes the cyclic NTT of (a[i] * ψ^i), equivalent to
    /// evaluation on the ring Z_q[X]/(X^N + 1).
    pub fn forward(&self, a: &[i64]) -> Vec<i64> {
        assert_eq!(a.len(), N);
        let q = self.q;
        let q128 = q as i128;

        // Step 1: Pre-multiply by powers of ψ (twist for negacyclic)
        let mut data: Vec<i64> = a
            .iter()
            .enumerate()
            .map(|(i, &coeff)| {
                let c = ((coeff as i128 % q128) + q128) % q128;
                let pw = self.psi_powers[i] as i128;
                ((c * pw) % q128) as i64
            })
            .collect();

        // Step 2: In-place Cooley-Tukey radix-2 NTT
        bit_reverse_permutation(&mut data);

        let mut len = 2;
        while len <= N {
            let half = len / 2;
            // ω = ψ^(2N/len) = primitive len-th root of unity
            let w = mod_pow(self.psi, (2 * N / len) as u64, q);
            let mut j = 0;
            while j < N {
                let mut wk: i128 = 1;
                for k in 0..half {
                    let u = data[j + k] as i128;
                    let v = (data[j + k + half] as i128 * wk) % q128;
                    data[j + k] = ((u + v) % q128) as i64;
                    data[j + k + half] = ((u - v + q128) % q128) as i64;
                    wk = wk * w as i128 % q128;
                }
                j += len;
            }
            len <<= 1;
        }

        data
    }

    /// Inverse NTT: evaluation → coefficient domain.
    ///
    /// Reverses the forward NTT, recovering the original coefficients.
    pub fn inverse(&self, a: &[i64]) -> Vec<i64> {
        assert_eq!(a.len(), N);
        let q = self.q;
        let q128 = q as i128;

        let mut data = a.to_vec();

        // Step 1: In-place Gentleman-Sande radix-2 inverse NTT
        bit_reverse_permutation(&mut data);

        let mut len = 2;
        while len <= N {
            let half = len / 2;
            let w_inv = mod_pow(self.psi_inv, (2 * N / len) as u64, q);
            let mut j = 0;
            while j < N {
                let mut wk: i128 = 1;
                for k in 0..half {
                    let u = data[j + k] as i128;
                    let v = (data[j + k + half] as i128 * wk) % q128;
                    data[j + k] = ((u + v) % q128) as i64;
                    data[j + k + half] = ((u - v + q128) % q128) as i64;
                    wk = wk * w_inv as i128 % q128;
                }
                j += len;
            }
            len <<= 1;
        }

        // Step 2: Scale by N^(-1) and undo twist (divide by ψ^i)
        for i in 0..N {
            let v = data[i] as i128;
            let scaled = v * self.n_inv as i128 % q128;
            let untwisted = scaled * self.psi_inv_powers[i] as i128 % q128;
            data[i] = untwisted as i64;
        }

        data
    }

    /// Multiply two polynomials in Z_q[X]/(X^N+1) using NTT.
    ///
    /// O(N log N) instead of O(N²).
    pub fn mul(&self, a: &[i64], b: &[i64]) -> Vec<i64> {
        let a_ntt = self.forward(a);
        let b_ntt = self.forward(b);

        let q128 = self.q as i128;
        let mut c_ntt = vec![0i64; N];
        for i in 0..N {
            c_ntt[i] = (a_ntt[i] as i128 * b_ntt[i] as i128 % q128) as i64;
        }

        self.inverse(&c_ntt)
    }

    /// Reduce a coefficient to centered range (-q/2, q/2].
    pub fn center(&self, v: i64) -> i64 {
        let half = self.q / 2;
        if v > half {
            v - self.q
        } else if v < -half {
            v + self.q
        } else {
            v
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Internal helpers
// ═══════════════════════════════════════════════════════════════════════

/// Precompute twiddle factors (powers of root in order [0..N]).
fn precompute_twiddles(root: i64, q: i64) -> Vec<i64> {
    let q128 = q as i128;
    let mut powers = vec![0i64; N];
    powers[0] = 1;
    for i in 1..N {
        powers[i] = (powers[i - 1] as i128 * root as i128 % q128) as i64;
    }
    powers
}

/// Bit-reversal permutation (in-place).
fn bit_reverse_permutation(data: &mut [i64]) {
    let n = data.len();
    let log_n = n.trailing_zeros();
    for i in 0..n {
        let j = bit_reverse(i as u32, log_n) as usize;
        if i < j {
            data.swap(i, j);
        }
    }
}

/// Reverse the bottom `bits` bits of `v`.
fn bit_reverse(v: u32, bits: u32) -> u32 {
    let mut r = 0u32;
    let mut v = v;
    for _ in 0..bits {
        r = (r << 1) | (v & 1);
        v >>= 1;
    }
    r
}

/// Check if a number is prime (trial division, only for parameter setup).
pub fn is_prime(n: i64) -> bool {
    if n < 2 {
        return false;
    }
    if n < 4 {
        return true;
    }
    if n % 2 == 0 || n % 3 == 0 {
        return false;
    }
    let mut i = 5i64;
    while i * i <= n {
        if n % i == 0 || n % (i + 2) == 0 {
            return false;
        }
        i += 6;
    }
    true
}

/// Find NTT-friendly primes near a target bit size.
/// Returns primes q where q ≡ 1 (mod 2N) and q is close to 2^target_bits.
pub fn find_ntt_primes(target_bits: u32, count: usize) -> Vec<i64> {
    let two_n = (2 * N) as i64;
    let start = 1i64 << target_bits;
    let mut primes = Vec::with_capacity(count);

    let mut k = start / two_n;
    while primes.len() < count && k > 0 {
        let candidate = two_n * k + 1;
        if is_prime(candidate) {
            primes.push(candidate);
        }
        k -= 1;
    }

    primes
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntt_primes_are_valid() {
        for &q in &NTT_PRIMES {
            assert!(is_prime(q), "{} is not prime", q);
            assert_eq!(q % (2 * N as i64), 1, "{} is not ≡ 1 (mod {})", q, 2 * N);
            assert!(q < (1i64 << 40), "{} is too large", q);
        }
    }

    #[test]
    fn ntt_primes_are_distinct() {
        for i in 0..NTT_PRIMES.len() {
            for j in (i + 1)..NTT_PRIMES.len() {
                assert_ne!(NTT_PRIMES[i], NTT_PRIMES[j]);
            }
        }
    }

    #[test]
    fn precomputed_roots_are_valid() {
        for (i, &q) in NTT_PRIMES.iter().enumerate() {
            let psi = NTT_ROOTS[i];
            // ψ^N = -1 (mod q)
            let psi_n = mod_pow(psi, N as u64, q);
            assert_eq!(psi_n, q - 1, "ψ^N should be -1 for prime {}", q);
            // ψ^(2N) = 1 (mod q)
            let psi_2n = mod_pow(psi, (2 * N) as u64, q);
            assert_eq!(psi_2n, 1, "ψ^(2N) should be 1 for prime {}", q);
        }
    }

    #[test]
    fn primitive_root_is_primitive() {
        let q = NTT_PRIMES[0];
        let psi = find_primitive_root(q);

        // ψ^k ≠ 1 for 0 < k < 2N
        for k in 1..(2 * N as u64) {
            let v = mod_pow(psi, k, q);
            if k == N as u64 {
                assert_eq!(v, q - 1, "ψ^N should be -1");
            } else {
                assert_ne!(v, 1, "ψ^{} should not be 1 (not primitive)", k);
            }
        }
    }

    #[test]
    fn ntt_roundtrip() {
        let ctx = NttContext::new(NTT_PRIMES[0]);

        let mut a = vec![0i64; N];
        a[0] = 1;
        a[1] = 2;
        a[2] = 3;

        let ntt_a = ctx.forward(&a);
        let back = ctx.inverse(&ntt_a);

        for i in 0..N {
            let v = ctx.center(back[i]);
            assert_eq!(v, a[i], "mismatch at index {}: expected {}, got {}", i, a[i], v);
        }
    }

    #[test]
    fn ntt_roundtrip_negative_coeffs() {
        let q = NTT_PRIMES[0];
        let ctx = NttContext::new(q);

        let mut a = vec![0i64; N];
        a[0] = q - 5; // represents -5 in [0, q)
        a[1] = 10;
        a[2] = q - 1; // represents -1

        let ntt_a = ctx.forward(&a);
        let back = ctx.inverse(&ntt_a);

        for i in 0..N {
            assert_eq!(back[i], a[i], "mismatch at index {}", i);
        }
    }

    #[test]
    fn ntt_mul_matches_naive() {
        let q = NTT_PRIMES[0];
        let ctx = NttContext::new(q);

        // a = [3, 1, 0, ...], b = [2, 4, 0, ...]
        // (3+X)*(2+4X) = 6 + 14X + 4X^2
        let mut a = vec![0i64; N];
        a[0] = 3;
        a[1] = 1;
        let mut b = vec![0i64; N];
        b[0] = 2;
        b[1] = 4;

        let c = ctx.mul(&a, &b);

        assert_eq!(ctx.center(c[0]), 6);
        assert_eq!(ctx.center(c[1]), 14);
        assert_eq!(ctx.center(c[2]), 4);
        for i in 3..N {
            assert_eq!(ctx.center(c[i]), 0, "non-zero at index {}: {}", i, ctx.center(c[i]));
        }
    }

    #[test]
    fn ntt_mul_negacyclic_wrap() {
        let q = NTT_PRIMES[0];
        let ctx = NttContext::new(q);

        // X^(N-1) * X = X^N = -1 in Z[X]/(X^N+1)
        let mut a = vec![0i64; N];
        a[N - 1] = 1;
        let mut b = vec![0i64; N];
        b[1] = 1;

        let c = ctx.mul(&a, &b);

        assert_eq!(ctx.center(c[0]), -1, "X^N should be -1");
        for i in 1..N {
            assert_eq!(ctx.center(c[i]), 0, "non-zero at index {}", i);
        }
    }

    #[test]
    fn ntt_mul_larger_polynomials() {
        let q = NTT_PRIMES[0];
        let ctx = NttContext::new(q);

        let mut a = vec![0i64; N];
        let mut b = vec![0i64; N];

        for i in 0..32 {
            a[i] = ((i as i64 * 7 + 3) % 100) - 50;
            b[i] = ((i as i64 * 13 + 5) % 100) - 50;
        }

        // Convert to [0, q) for NTT
        let a_pos: Vec<i64> = a.iter().map(|&v| ((v % q) + q) % q).collect();
        let b_pos: Vec<i64> = b.iter().map(|&v| ((v % q) + q) % q).collect();
        let c_ntt = ctx.mul(&a_pos, &b_pos);

        // Naive negacyclic convolution for reference
        let mut c_naive = vec![0i128; N];
        for i in 0..N {
            if a[i] == 0 { continue; }
            for j in 0..N {
                if b[j] == 0 { continue; }
                let prod = a[i] as i128 * b[j] as i128;
                let k = i + j;
                if k < N {
                    c_naive[k] += prod;
                } else {
                    c_naive[k - N] -= prod;
                }
            }
        }

        for i in 0..N {
            let ntt_val = ctx.center(c_ntt[i]);
            let naive_val = ((c_naive[i] % q as i128 + q as i128) % q as i128) as i64;
            let naive_centered = if naive_val > q / 2 { naive_val - q } else { naive_val };
            assert_eq!(
                ntt_val, naive_centered,
                "mismatch at index {}: ntt={}, naive={}",
                i, ntt_val, naive_centered
            );
        }
    }

    #[test]
    fn find_ntt_primes_works() {
        let primes = find_ntt_primes(36, 3);
        assert!(primes.len() >= 3, "should find at least 3 primes");
        for &p in &primes {
            assert!(is_prime(p));
            assert_eq!(p % (2 * N as i64), 1);
        }
    }


    #[test]
    fn mod_pow_basic() {
        assert_eq!(mod_pow(2, 10, 1000), 24); // 1024 mod 1000
        assert_eq!(mod_pow(3, 0, 7), 1);
        assert_eq!(mod_pow(5, 1, 7), 5);
    }

    #[test]
    fn mod_inv_basic() {
        let q = NTT_PRIMES[0];
        for a in [2, 3, 42, 12345, q - 1] {
            let inv = mod_inv(a, q);
            let product = (a as i128 * inv as i128 % q as i128) as i64;
            assert_eq!(product, 1, "{}^(-1) mod {} failed", a, q);
        }
    }

    #[test]
    fn all_primes_have_valid_contexts() {
        for &q in &NTT_PRIMES {
            let ctx = NttContext::new(q);
            assert_eq!(ctx.q, q);

            // Quick roundtrip
            let mut a = vec![0i64; N];
            a[0] = 42;
            let back = ctx.inverse(&ctx.forward(&a));
            assert_eq!(ctx.center(back[0]), 42);
        }
    }
}
