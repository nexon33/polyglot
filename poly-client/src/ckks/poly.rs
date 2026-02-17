//! Polynomial ring Z_q[X]/(X^N + 1).
//!
//! All arithmetic is performed modulo the cyclotomic polynomial X^N + 1
//! with coefficients reduced modulo q into the centered range (-q/2, q/2].
//! Multiplication uses naive O(N²) negacyclic convolution — sufficient
//! since keygen and encrypt each need only 2-3 multiplications per session.

use serde::{Deserialize, Serialize};

use super::params::{DECOMP_BASE, N, NUM_DIGITS, Q};

/// A polynomial in Z_q[X]/(X^N + 1). Always has exactly N coefficients.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Poly {
    pub coeffs: Vec<i64>,
}

impl Poly {
    /// The zero polynomial.
    pub fn zero() -> Self {
        Self {
            coeffs: vec![0i64; N],
        }
    }

    /// Create from a coefficient vector. Pads or truncates to length N.
    pub fn from_coeffs(mut coeffs: Vec<i64>) -> Self {
        coeffs.resize(N, 0);
        for c in coeffs.iter_mut() {
            *c = mod_reduce(*c);
        }
        Self { coeffs }
    }

    /// Coefficient-wise addition mod q.
    pub fn add(&self, other: &Poly) -> Poly {
        let mut out = vec![0i64; N];
        for i in 0..N {
            out[i] = mod_reduce(self.coeffs[i] + other.coeffs[i]);
        }
        Poly { coeffs: out }
    }

    /// Coefficient-wise subtraction mod q.
    pub fn sub(&self, other: &Poly) -> Poly {
        let mut out = vec![0i64; N];
        for i in 0..N {
            out[i] = mod_reduce(self.coeffs[i] - other.coeffs[i]);
        }
        Poly { coeffs: out }
    }

    /// Negate all coefficients mod q.
    pub fn neg(&self) -> Poly {
        let mut out = vec![0i64; N];
        for i in 0..N {
            out[i] = mod_reduce(-self.coeffs[i]);
        }
        Poly { coeffs: out }
    }

    /// Multiply by a scalar mod q.
    pub fn scalar_mul(&self, scalar: i64) -> Poly {
        let mut out = vec![0i64; N];
        let s = scalar as i128;
        for i in 0..N {
            let v = (self.coeffs[i] as i128 * s) % Q as i128;
            out[i] = mod_reduce(v as i64);
        }
        Poly { coeffs: out }
    }

    /// Rounding division of each coefficient by a divisor.
    ///
    /// Rounds to the nearest integer (ties to even not needed — standard rounding).
    /// Used by rescaling after ciphertext-ciphertext multiplication.
    pub fn div_round(&self, divisor: i64) -> Poly {
        let half = divisor.abs() / 2;
        let mut out = vec![0i64; N];
        for i in 0..N {
            let c = self.coeffs[i];
            // Round-to-nearest: (c + sign(c)*half) / divisor
            let rounded = if c >= 0 {
                (c + half) / divisor
            } else {
                -(((-c) + half) / divisor)
            };
            out[i] = mod_reduce(rounded);
        }
        Poly { coeffs: out }
    }

    /// Decompose each coefficient into base-T digits.
    ///
    /// Returns `NUM_DIGITS` polynomials where digit[d] contains the d-th
    /// base-T digit of each coefficient. Used for relinearization:
    /// instead of multiplying by the full value, we multiply each digit
    /// by the corresponding evaluation key component.
    pub fn decompose_base_t(&self) -> Vec<Poly> {
        let t = DECOMP_BASE;
        let mut digits = vec![Poly::zero(); NUM_DIGITS];

        for i in 0..N {
            // Work with the positive representative in [0, Q)
            let mut val = self.coeffs[i];
            if val < 0 {
                val += Q;
            }

            for d in 0..NUM_DIGITS {
                let digit = val % t;
                val /= t;
                // Keep digit in centered range for correct arithmetic
                digits[d].coeffs[i] = mod_reduce(digit);
            }
        }

        digits
    }

    /// Negacyclic polynomial multiplication in Z_q[X]/(X^N + 1).
    ///
    /// Uses naive O(N²) convolution with i128 accumulators.
    /// X^N ≡ -1, so terms wrapping past degree N-1 are negated.
    pub fn mul(&self, other: &Poly) -> Poly {
        let mut out = vec![0i128; N];
        let q128 = Q as i128;

        for i in 0..N {
            if self.coeffs[i] == 0 {
                continue;
            }
            let ai = self.coeffs[i] as i128;
            for j in 0..N {
                if other.coeffs[j] == 0 {
                    continue;
                }
                let prod = ai * other.coeffs[j] as i128;
                let k = i + j;
                if k < N {
                    out[k] += prod;
                } else {
                    // X^N = -1, so wrap with negation
                    out[k - N] -= prod;
                }
            }
        }

        // Reduce all accumulators mod q
        let mut coeffs = vec![0i64; N];
        for i in 0..N {
            let v = ((out[i] % q128) + q128) % q128;
            coeffs[i] = mod_reduce(v as i64);
        }
        Poly { coeffs }
    }
}

/// Centered modular reduction into (-q/2, q/2].
pub fn mod_reduce(val: i64) -> i64 {
    let q = Q;
    let half = q / 2;
    let mut r = val % q;
    if r > half {
        r -= q;
    } else if r < -half {
        r += q;
    }
    r
}

impl PartialEq for Poly {
    fn eq(&self, other: &Self) -> bool {
        self.coeffs == other.coeffs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_additive_identity() {
        let a = Poly::from_coeffs(vec![1, 2, 3, -4]);
        let z = Poly::zero();
        assert_eq!(a.add(&z), a);
        assert_eq!(z.add(&a), a);
    }

    #[test]
    fn add_sub_inverse() {
        let a = Poly::from_coeffs(vec![100, -200, 300]);
        let b = Poly::from_coeffs(vec![50, 150, -100]);
        let sum = a.add(&b);
        let back = sum.sub(&b);
        assert_eq!(back, a);
    }

    #[test]
    fn neg_double_is_identity() {
        let a = Poly::from_coeffs(vec![42, -17, 0, 999]);
        assert_eq!(a.neg().neg(), a);
    }

    #[test]
    fn add_neg_is_zero() {
        let a = Poly::from_coeffs(vec![1, 2, 3]);
        let z = a.add(&a.neg());
        assert_eq!(z, Poly::zero());
    }

    #[test]
    fn mul_by_one() {
        // Polynomial "1" = [1, 0, 0, ...]
        let one = Poly::from_coeffs(vec![1]);
        let a = Poly::from_coeffs(vec![10, 20, 30]);
        assert_eq!(a.mul(&one), a);
        assert_eq!(one.mul(&a), a);
    }

    #[test]
    fn negacyclic_wrap() {
        // In X^N+1: X^(N-1) * X = X^N = -1
        // So poly [0,...,0,1] (= X^{N-1}) * [0,1,0,...] (= X) should give [-1,0,...,0]
        let mut x_n_minus_1 = vec![0i64; N];
        x_n_minus_1[N - 1] = 1;
        let p1 = Poly::from_coeffs(x_n_minus_1);

        let mut x = vec![0i64; N];
        x[1] = 1;
        let p2 = Poly::from_coeffs(x);

        let result = p1.mul(&p2);
        // X^{N-1} * X = X^N = -1 (constant term)
        assert_eq!(result.coeffs[0], -1);
        for i in 1..N {
            assert_eq!(result.coeffs[i], 0);
        }
    }

    #[test]
    fn mod_reduce_centered() {
        let half = Q / 2;
        assert_eq!(mod_reduce(0), 0);
        assert_eq!(mod_reduce(1), 1);
        assert_eq!(mod_reduce(-1), -1);
        assert_eq!(mod_reduce(Q), 0);
        assert_eq!(mod_reduce(-Q), 0);
        assert!(mod_reduce(half + 1) <= half);
        assert!(mod_reduce(-(half + 1)) >= -half);
    }

    #[test]
    fn scalar_mul_basic() {
        let a = Poly::from_coeffs(vec![1, 2, 3]);
        let doubled = a.scalar_mul(2);
        assert_eq!(doubled.coeffs[0], 2);
        assert_eq!(doubled.coeffs[1], 4);
        assert_eq!(doubled.coeffs[2], 6);
    }

    #[test]
    fn div_round_exact() {
        let a = Poly::from_coeffs(vec![100, 200, -300]);
        let result = a.div_round(100);
        assert_eq!(result.coeffs[0], 1);
        assert_eq!(result.coeffs[1], 2);
        assert_eq!(result.coeffs[2], -3);
    }

    #[test]
    fn div_round_rounds_correctly() {
        // 150 / 100 = 1.5, rounds to 2
        // 149 / 100 = 1.49, rounds to 1
        // -150 / 100 = -1.5, rounds to -2
        let a = Poly::from_coeffs(vec![150, 149, -150, -149]);
        let result = a.div_round(100);
        assert_eq!(result.coeffs[0], 2);
        assert_eq!(result.coeffs[1], 1);
        assert_eq!(result.coeffs[2], -2);
        assert_eq!(result.coeffs[3], -1);
    }

    #[test]
    fn div_round_by_delta() {
        use crate::ckks::params::DELTA;
        // Encode a value as coeff * DELTA, then div_round should recover it
        let val = 42i64;
        let a = Poly::from_coeffs(vec![val * DELTA]);
        let result = a.div_round(DELTA);
        assert_eq!(result.coeffs[0], val);
    }

    #[test]
    fn decompose_base_t_reconstruction() {
        use crate::ckks::params::DECOMP_BASE;
        // A value should be reconstructable from its digits: sum(digit[d] * T^d)
        let a = Poly::from_coeffs(vec![123456789, -987654, 42]);
        let digits = a.decompose_base_t();
        assert_eq!(digits.len(), NUM_DIGITS);

        // Reconstruct and verify
        for i in 0..3 {
            let original = {
                let v = a.coeffs[i];
                if v < 0 { v + Q } else { v }
            };
            let mut reconstructed: i64 = 0;
            let mut power: i64 = 1;
            for d in 0..NUM_DIGITS {
                let digit = {
                    let v = digits[d].coeffs[i];
                    if v < 0 { v + Q } else { v }
                };
                reconstructed += digit * power;
                power *= DECOMP_BASE;
            }
            assert_eq!(
                reconstructed % Q, original % Q,
                "reconstruction failed for coeff {}: {} != {}",
                i, reconstructed % Q, original % Q
            );
        }
    }

    #[test]
    fn decompose_base_t_digit_count() {
        let a = Poly::from_coeffs(vec![1]);
        let digits = a.decompose_base_t();
        assert_eq!(digits.len(), NUM_DIGITS);
        for d in &digits {
            assert_eq!(d.coeffs.len(), N);
        }
    }
}
