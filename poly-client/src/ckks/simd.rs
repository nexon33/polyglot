//! CKKS SIMD slot packing via the canonical embedding.
//!
//! Encodes N/2 = 2048 real values into a single polynomial using the
//! isomorphism Z[X]/(X^N+1) ≅ C^{N/2}. Polynomial add/multiply then
//! becomes element-wise add/multiply across all slots simultaneously.
//!
//! # Encoding pipeline
//!
//! 1. Place N/2 real values into a conjugate-symmetric C^N vector
//! 2. Inverse FFT → twisted coefficients
//! 3. Untwist by ψ^{-j} → polynomial coefficients
//! 4. Scale by DELTA and round to integers
//!
//! # Decoding pipeline
//!
//! 1. Twist coefficients by ψ^j
//! 2. Forward FFT → evaluations at roots of X^N+1
//! 3. Take real parts of first N/2 entries

use std::f64::consts::PI;

use super::params::N;

/// Number of SIMD slots = N/2.
pub const NUM_SLOTS: usize = N / 2;

// ═══════════════════════════════════════════════════════════════════════
// Complex number type
// ═══════════════════════════════════════════════════════════════════════

#[derive(Clone, Copy, Debug)]
struct Complex {
    re: f64,
    im: f64,
}

impl Complex {
    fn new(re: f64, im: f64) -> Self {
        Self { re, im }
    }

    fn zero() -> Self {
        Self { re: 0.0, im: 0.0 }
    }

    fn from_real(re: f64) -> Self {
        Self { re, im: 0.0 }
    }

    fn add(self, other: Self) -> Self {
        Self {
            re: self.re + other.re,
            im: self.im + other.im,
        }
    }

    fn sub(self, other: Self) -> Self {
        Self {
            re: self.re - other.re,
            im: self.im - other.im,
        }
    }

    fn mul(self, other: Self) -> Self {
        Self {
            re: self.re * other.re - self.im * other.im,
            im: self.re * other.im + self.im * other.re,
        }
    }

    fn conj(self) -> Self {
        Self {
            re: self.re,
            im: -self.im,
        }
    }

    fn scale(self, s: f64) -> Self {
        Self {
            re: self.re * s,
            im: self.im * s,
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Radix-2 Cooley-Tukey FFT
// ═══════════════════════════════════════════════════════════════════════

/// In-place radix-2 Cooley-Tukey FFT.
/// Computes Z_k = Σ_{j=0}^{N-1} X_j · e^{2πijk/N}.
fn fft(a: &mut [Complex]) {
    let n = a.len();
    assert!(n.is_power_of_two(), "FFT size must be power of 2");
    if n <= 1 {
        return;
    }

    // Bit-reverse permutation
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            a.swap(i, j);
        }
    }

    // Butterfly stages
    let mut len = 2;
    while len <= n {
        let half = len / 2;
        let angle = 2.0 * PI / len as f64;
        let w_base = Complex::new(angle.cos(), angle.sin());

        let mut start = 0;
        while start < n {
            let mut w = Complex::new(1.0, 0.0);
            for k in 0..half {
                let u = a[start + k];
                let t = a[start + k + half].mul(w);
                a[start + k] = u.add(t);
                a[start + k + half] = u.sub(t);
                w = w.mul(w_base);
            }
            start += len;
        }
        len <<= 1;
    }
}

/// Inverse FFT: X_j = (1/N) Σ_{k=0}^{N-1} Z_k · e^{-2πijk/N}.
fn ifft(a: &mut [Complex]) {
    let n = a.len();
    // Conjugate → FFT → conjugate → scale by 1/N
    for x in a.iter_mut() {
        *x = x.conj();
    }
    fft(a);
    let inv_n = 1.0 / n as f64;
    for x in a.iter_mut() {
        *x = x.conj().scale(inv_n);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Galois-aligned slot permutation
// ═══════════════════════════════════════════════════════════════════════

/// Galois generator: 5 has order N/2 = 2048 in (Z/2N)*.
/// σ_5 rotates slots by 1 position when using Galois-aligned indexing.
const GALOIS_GEN: usize = 5;

/// Compute the Galois-aligned slot → FFT position mapping.
///
/// Slot i maps to root ψ^{g^i mod 2N}, which is FFT position (g^i - 1)/2.
/// This ensures σ_g (X → X^g) cyclically shifts slots by 1 position.
fn slot_permutation() -> (Vec<usize>, Vec<usize>) {
    let two_n = 2 * N;
    let mut slot_to_fft = vec![0usize; NUM_SLOTS];
    let mut fft_to_slot = vec![NUM_SLOTS; N]; // sentinel for unmapped

    let mut root_idx = 1usize; // g^0 = 1
    for i in 0..NUM_SLOTS {
        // root_idx = g^i mod 2N (always odd)
        let fft_pos = (root_idx - 1) / 2;
        slot_to_fft[i] = fft_pos;
        fft_to_slot[fft_pos] = i;
        root_idx = (root_idx * GALOIS_GEN) % two_n;
    }

    (slot_to_fft, fft_to_slot)
}

// ═══════════════════════════════════════════════════════════════════════
// CKKS SIMD Encoding / Decoding (Galois-aligned)
// ═══════════════════════════════════════════════════════════════════════

/// Encode up to N/2 real values into N polynomial coefficients.
///
/// Uses the inverse canonical embedding with Galois-aligned slot ordering:
/// 1. Map slot values to FFT positions via g^i permutation
/// 2. Form conjugate-symmetric evaluation vector
/// 3. IFFT to get twisted coefficients
/// 4. Untwist by ψ^{-j}
/// 5. Scale by `delta` and round
///
/// The Galois alignment ensures σ_g (X → X^5) cyclically shifts slots by 1.
pub fn encode_simd(values: &[f64], delta: f64) -> Vec<i64> {
    assert!(
        values.len() <= NUM_SLOTS,
        "too many values: {} > {}",
        values.len(),
        NUM_SLOTS
    );
    // R11: Validate delta — NaN/Inf/zero/negative delta produces garbage coefficients
    // after scaling (c.re * NaN → NaN → 0 after round-as-i64, or Inf → platform-dependent).
    // While internal callers always pass ctx.delta (which is valid), encode_simd is a
    // public function and can be called with arbitrary delta by users or attackers.
    assert!(
        delta.is_finite() && delta > 0.0,
        "encode_simd: delta must be finite and positive, got {}",
        delta
    );

    let mut padded = vec![0.0f64; NUM_SLOTS];
    padded[..values.len()].copy_from_slice(values);

    let (slot_to_fft, _) = slot_permutation();

    // Form conjugate-symmetric evaluation vector using Galois-aligned positions
    let mut z = vec![Complex::zero(); N];
    for i in 0..NUM_SLOTS {
        let fft_pos = slot_to_fft[i];
        let conj_pos = N - 1 - fft_pos;
        z[fft_pos] = Complex::from_real(padded[i]);
        z[conj_pos] = Complex::from_real(padded[i]);
    }

    // IFFT: get twisted coefficients b = IFFT(z)
    ifft(&mut z);

    // Untwist: p_j = b_j · ψ^{-j} where ψ = e^{2πi/(2N)}
    let psi_angle = PI / N as f64;
    for j in 0..N {
        let angle = -(j as f64) * psi_angle;
        let psi_neg_j = Complex::new(angle.cos(), angle.sin());
        z[j] = z[j].mul(psi_neg_j);
    }

    // Scale by delta and round. Coefficients should be real (im ≈ 0).
    z.iter().map(|c| (c.re * delta).round() as i64).collect()
}

/// Decode N polynomial coefficients back to real values.
///
/// Uses the forward canonical embedding with Galois-aligned slot ordering:
/// 1. Twist by ψ^j
/// 2. FFT to get evaluations
/// 3. Read real parts from Galois-aligned FFT positions
pub fn decode_simd(coeffs: &[i64], scale: f64, count: usize) -> Vec<f64> {
    assert!(count <= NUM_SLOTS, "count {} > NUM_SLOTS {}", count, NUM_SLOTS);
    // R11: Validate scale — dividing coefficients by NaN/Inf/zero/negative scale
    // produces NaN, zero, or garbage values. While rns_decrypt_simd_unchecked
    // validates ct.scale before calling this, decode_simd is a public function
    // and can be called directly with an invalid scale.
    assert!(
        scale.is_finite() && scale > 0.0,
        "decode_simd: scale must be finite and positive, got {}",
        scale
    );

    // Twist: b_j = (coeff_j / scale) · ψ^j
    let psi_angle = PI / N as f64;
    let mut b: Vec<Complex> = (0..N)
        .map(|j| {
            let val = if j < coeffs.len() {
                coeffs[j] as f64 / scale
            } else {
                0.0
            };
            let angle = j as f64 * psi_angle;
            let psi_j = Complex::new(angle.cos(), angle.sin());
            Complex::from_real(val).mul(psi_j)
        })
        .collect();

    // FFT to get evaluations at roots of X^N+1
    fft(&mut b);

    // Read values from Galois-aligned positions
    let (slot_to_fft, _) = slot_permutation();
    (0..count).map(|i| b[slot_to_fft[i]].re).collect()
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fft_ifft_roundtrip() {
        let mut data: Vec<Complex> = (0..16)
            .map(|i| Complex::new(i as f64, -(i as f64) * 0.5))
            .collect();
        let original: Vec<Complex> = data.clone();

        fft(&mut data);
        ifft(&mut data);

        for (i, (a, b)) in data.iter().zip(original.iter()).enumerate() {
            assert!(
                (a.re - b.re).abs() < 1e-10 && (a.im - b.im).abs() < 1e-10,
                "FFT roundtrip failed at {}: ({}, {}) vs ({}, {})",
                i,
                a.re,
                a.im,
                b.re,
                b.im,
            );
        }
    }

    #[test]
    fn fft_ifft_roundtrip_large() {
        // Test with N=4096 (the actual ring size)
        let mut data: Vec<Complex> = (0..N)
            .map(|i| Complex::new((i as f64 * 0.01).sin(), (i as f64 * 0.01).cos()))
            .collect();
        let original: Vec<Complex> = data.clone();

        fft(&mut data);
        ifft(&mut data);

        let max_err = data
            .iter()
            .zip(original.iter())
            .map(|(a, b)| (a.re - b.re).abs().max((a.im - b.im).abs()))
            .fold(0.0f64, f64::max);

        assert!(
            max_err < 1e-8,
            "FFT roundtrip max error {} too large",
            max_err
        );
    }

    #[test]
    fn encode_decode_roundtrip_simple() {
        let values = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let delta = (1u64 << 30) as f64;

        let coeffs = encode_simd(&values, delta);
        assert_eq!(coeffs.len(), N);

        let decoded = decode_simd(&coeffs, delta, values.len());

        for (i, (expected, got)) in values.iter().zip(decoded.iter()).enumerate() {
            assert!(
                (expected - got).abs() < 0.01,
                "slot {} mismatch: expected {}, got {}",
                i,
                expected,
                got
            );
        }
    }

    #[test]
    fn encode_decode_roundtrip_negative() {
        let values = vec![-3.5, 0.0, 7.2, -1.0, 0.001];
        let delta = (1u64 << 30) as f64;

        let coeffs = encode_simd(&values, delta);
        let decoded = decode_simd(&coeffs, delta, values.len());

        for (i, (expected, got)) in values.iter().zip(decoded.iter()).enumerate() {
            assert!(
                (expected - got).abs() < 0.01,
                "slot {} mismatch: expected {}, got {}",
                i,
                expected,
                got
            );
        }
    }

    #[test]
    fn encode_decode_all_slots() {
        // Fill all 2048 slots
        let values: Vec<f64> = (0..NUM_SLOTS)
            .map(|i| (i as f64 * 0.1).sin() * 5.0)
            .collect();
        let delta = (1u64 << 30) as f64;

        let coeffs = encode_simd(&values, delta);
        let decoded = decode_simd(&coeffs, delta, NUM_SLOTS);

        let max_err = values
            .iter()
            .zip(decoded.iter())
            .map(|(a, b)| (a - b).abs())
            .fold(0.0f64, f64::max);

        assert!(
            max_err < 0.01,
            "all-slots roundtrip max error {} too large",
            max_err
        );
    }

    #[test]
    fn encode_produces_real_coefficients() {
        // For real inputs, the polynomial coefficients should be real
        // (imaginary parts ≈ 0 before rounding to i64)
        let values = vec![1.0, 2.0, 3.0];
        let _delta = (1u64 << 30) as f64;

        // Do encode without the final rounding, check imaginary parts
        let mut padded = vec![0.0f64; NUM_SLOTS];
        padded[..values.len()].copy_from_slice(&values);

        let mut z = vec![Complex::zero(); N];
        for k in 0..NUM_SLOTS {
            z[k] = Complex::from_real(padded[k]);
            z[N - 1 - k] = Complex::from_real(padded[k]);
        }
        ifft(&mut z);

        let psi_angle = PI / N as f64;
        for j in 0..N {
            let angle = -(j as f64) * psi_angle;
            let psi_neg_j = Complex::new(angle.cos(), angle.sin());
            z[j] = z[j].mul(psi_neg_j);
        }

        let max_imag = z.iter().map(|c| c.im.abs()).fold(0.0f64, f64::max);
        assert!(
            max_imag < 1e-10,
            "imaginary part should be ~0 for real inputs, got {}",
            max_imag
        );
    }

    #[test]
    fn elementwise_add_in_coefficient_domain() {
        // Verify that adding encoded polynomials corresponds to element-wise
        // addition of the slot values
        let a = vec![1.0, 2.0, 3.0, 4.0];
        let b = vec![10.0, 20.0, 30.0, 40.0];
        let delta = (1u64 << 30) as f64;

        let ca = encode_simd(&a, delta);
        let cb = encode_simd(&b, delta);

        // Add coefficient-wise (simulating homomorphic addition)
        let c_sum: Vec<i64> = ca.iter().zip(cb.iter()).map(|(x, y)| x + y).collect();

        let decoded = decode_simd(&c_sum, delta, 4);

        for i in 0..4 {
            let expected = a[i] + b[i];
            assert!(
                (decoded[i] - expected).abs() < 0.01,
                "slot {} add: expected {}, got {}",
                i,
                expected,
                decoded[i]
            );
        }
    }
}
