//! CKKS coefficient encoding: token IDs ↔ polynomial coefficients.
//!
//! Each token ID occupies one coefficient position, scaled by Δ (DELTA).
//! This is simpler than full CKKS slot packing (which uses FFT/canonical
//! embedding) because we only need encrypt/decrypt — no homomorphic ops.

use super::params::{DELTA, N, Q};
use super::poly::{mod_reduce, Poly};

/// Encode token IDs into a polynomial. Each token occupies one coefficient
/// scaled by Δ. Panics if tokens.len() > N.
pub fn encode(tokens: &[u32]) -> Poly {
    assert!(
        tokens.len() <= N,
        "token count {} exceeds ring dimension {}",
        tokens.len(),
        N
    );
    let mut coeffs = vec![0i64; N];
    for (i, &t) in tokens.iter().enumerate() {
        coeffs[i] = mod_reduce(t as i64 * DELTA);
    }
    Poly { coeffs }
}

/// Decode a polynomial back to token IDs. Divides each coefficient by Δ
/// and rounds to the nearest non-negative integer.
pub fn decode(poly: &Poly, count: usize) -> Vec<u32> {
    let mut tokens = Vec::with_capacity(count);
    let half_delta = DELTA / 2;
    for i in 0..count {
        let c = poly.coeffs[i];
        // Centered coefficient may be negative for large token IDs that wrapped.
        // Unwrap: if c < 0, the true value is c + Q (since we're in centered rep).
        let positive = if c < 0 { c + Q } else { c };
        // Round: (positive + DELTA/2) / DELTA
        let rounded = (positive + half_delta) / DELTA;
        tokens.push(rounded as u32);
    }
    tokens
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_simple() {
        let tokens = vec![0, 1, 2, 100, 1000];
        let poly = encode(&tokens);
        let decoded = decode(&poly, tokens.len());
        assert_eq!(decoded, tokens);
    }

    #[test]
    fn roundtrip_zero() {
        let tokens = vec![0, 0, 0];
        let poly = encode(&tokens);
        let decoded = decode(&poly, tokens.len());
        assert_eq!(decoded, tokens);
    }

    #[test]
    fn roundtrip_max_u32() {
        let tokens = vec![u32::MAX];
        let poly = encode(&tokens);
        let decoded = decode(&poly, tokens.len());
        assert_eq!(decoded, tokens);
    }

    #[test]
    fn roundtrip_large_values() {
        let tokens = vec![u32::MAX, u32::MAX - 1, 0, 1, 50000];
        let poly = encode(&tokens);
        let decoded = decode(&poly, tokens.len());
        assert_eq!(decoded, tokens);
    }

    #[test]
    fn empty_roundtrip() {
        let tokens: Vec<u32> = vec![];
        let poly = encode(&tokens);
        let decoded = decode(&poly, 0);
        assert_eq!(decoded, tokens);
    }

    #[test]
    #[should_panic(expected = "token count")]
    fn encode_too_many_panics() {
        let tokens = vec![0u32; N + 1];
        encode(&tokens);
    }
}
