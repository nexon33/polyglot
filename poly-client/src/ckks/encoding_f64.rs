//! Float encoding for CKKS homomorphic operations.
//!
//! Unlike integer token encoding (encoding.rs), this module encodes f64 values
//! for use in homomorphic computation. Neural network activations, weights,
//! and intermediate values are all floating-point.
//!
//! Encoding: coeff[i] = round(value[i] * DELTA)
//! Decoding: value[i] = coeff[i] / DELTA
//!
//! For activations in [-10, 10], coefficients are in [-10M, 10M] — well within Q.

use super::params::{DELTA, N, Q};
use super::poly::{mod_reduce, Poly};

/// Encode floating-point values into a polynomial.
///
/// Each value is scaled by DELTA and rounded to the nearest integer.
/// Values should be in a range where `|value * DELTA| << Q/2` to avoid
/// overflow — typical activation range [-10, 10] is safe.
///
/// Panics if `values.len() > N`.
pub fn encode_f64(values: &[f64]) -> Poly {
    assert!(
        values.len() <= N,
        "value count {} exceeds ring dimension {}",
        values.len(),
        N
    );
    let mut coeffs = vec![0i64; N];
    for (i, &v) in values.iter().enumerate() {
        coeffs[i] = mod_reduce((v * DELTA as f64).round() as i64);
    }
    Poly { coeffs }
}

/// Encode floating-point values into a polynomial at a custom scale.
///
/// Use this when you need to create a plaintext matching a ciphertext
/// that has been through multiplication (scale = DELTA^2).
/// For fresh ciphertexts (scale = DELTA), use `encode_f64` instead.
pub fn encode_f64_at_scale(values: &[f64], scale: i64) -> Poly {
    assert!(
        values.len() <= N,
        "value count {} exceeds ring dimension {}",
        values.len(),
        N
    );
    let mut coeffs = vec![0i64; N];
    for (i, &v) in values.iter().enumerate() {
        coeffs[i] = mod_reduce((v * scale as f64).round() as i64);
    }
    Poly { coeffs }
}

/// Decode a polynomial back to floating-point values.
///
/// Divides each coefficient by DELTA to recover the original scale.
/// The `count` parameter specifies how many values to extract.
pub fn decode_f64(poly: &Poly, count: usize) -> Vec<f64> {
    decode_f64_with_scale(poly, count, DELTA)
}

/// Decode a polynomial with a custom scale factor.
///
/// After homomorphic multiplication, the scale becomes DELTA^2.
/// Use this function with the ciphertext's actual scale to decode correctly.
pub fn decode_f64_with_scale(poly: &Poly, count: usize, scale: i64) -> Vec<f64> {
    let mut values = Vec::with_capacity(count);
    for i in 0..count {
        let c = poly.coeffs[i];
        let effective = if c.abs() > Q / 2 {
            if c > 0 { c - Q } else { c + Q }
        } else {
            c
        };
        values.push(effective as f64 / scale as f64);
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_simple() {
        let values = vec![1.0, 2.5, -3.7, 0.0];
        let poly = encode_f64(&values);
        let decoded = decode_f64(&poly, values.len());
        for (a, b) in values.iter().zip(decoded.iter()) {
            assert!(
                (a - b).abs() < 1e-5,
                "mismatch: expected {}, got {}",
                a,
                b
            );
        }
    }

    #[test]
    fn roundtrip_negative_values() {
        let values = vec![-1.0, -5.5, -0.001, -9.99];
        let poly = encode_f64(&values);
        let decoded = decode_f64(&poly, values.len());
        for (a, b) in values.iter().zip(decoded.iter()) {
            assert!(
                (a - b).abs() < 1e-5,
                "mismatch: expected {}, got {}",
                a,
                b
            );
        }
    }

    #[test]
    fn roundtrip_activation_range() {
        // Typical neural network activation values
        let values: Vec<f64> = (-100..=100).map(|i| i as f64 / 10.0).collect();
        let poly = encode_f64(&values);
        let decoded = decode_f64(&poly, values.len());
        for (a, b) in values.iter().zip(decoded.iter()) {
            assert!(
                (a - b).abs() < 1e-5,
                "mismatch at value {}: got {}",
                a,
                b
            );
        }
    }

    #[test]
    fn encode_zero() {
        let values = vec![0.0, 0.0, 0.0];
        let poly = encode_f64(&values);
        for i in 0..3 {
            assert_eq!(poly.coeffs[i], 0);
        }
    }

    #[test]
    fn precision_within_delta() {
        // Precision is 1/DELTA ≈ 9.5e-7
        let val = 3.141592653589793;
        let poly = encode_f64(&[val]);
        let decoded = decode_f64(&poly, 1);
        assert!(
            (val - decoded[0]).abs() < 1.0 / DELTA as f64,
            "precision worse than 1/DELTA"
        );
    }

    #[test]
    #[should_panic(expected = "value count")]
    fn encode_too_many_panics() {
        let values = vec![0.0; N + 1];
        encode_f64(&values);
    }
}
