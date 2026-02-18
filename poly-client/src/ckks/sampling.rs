//! Random sampling for CKKS: uniform, ternary, and discrete Gaussian.

use rand::Rng;

use super::params::{N, Q, SIGMA};
use super::poly::{mod_reduce, Poly};

/// Sample a polynomial with coefficients uniform in [0, Q).
pub fn sample_uniform<R: Rng>(rng: &mut R) -> Poly {
    let mut coeffs = vec![0i64; N];
    for c in coeffs.iter_mut() {
        // gen_range produces uniform values in the half-open range
        *c = mod_reduce(rng.gen_range(0..Q));
    }
    Poly { coeffs }
}

/// Sample a polynomial from the ternary distribution {-1, 0, 1}.
/// P(0) = 0.5, P(-1) = P(1) = 0.25.
pub fn sample_ternary<R: Rng>(rng: &mut R) -> Poly {
    let mut coeffs = vec![0i64; N];
    for c in coeffs.iter_mut() {
        let v: u8 = rng.gen_range(0..4);
        *c = match v {
            0 => -1,
            1 => 1,
            _ => 0, // 2,3 → 0 (probability 0.5)
        };
    }
    Poly { coeffs }
}

/// Sample a polynomial from the discrete Gaussian distribution with σ = SIGMA.
/// Uses Box-Muller transform + rounding with 6σ tail rejection.
pub fn sample_gaussian<R: Rng>(rng: &mut R) -> Poly {
    let tail_bound = (SIGMA * 6.0).ceil() as i64; // reject |e| > 6σ
    let mut coeffs = vec![0i64; N];
    let mut i = 0;
    while i < N {
        // Box-Muller: generate two Gaussian samples from two uniforms
        let u1: f64 = rng.gen_range(1e-15_f64..1.0_f64);
        let u2: f64 = rng.gen_range(0.0_f64..std::f64::consts::TAU);
        let r = (-2.0 * u1.ln()).sqrt() * SIGMA;
        let z0 = r * u2.cos();
        let z1 = r * u2.sin();

        let s0 = z0.round() as i64;
        if s0.abs() <= tail_bound {
            coeffs[i] = s0;
            i += 1;
        }
        if i < N {
            let s1 = z1.round() as i64;
            if s1.abs() <= tail_bound {
                coeffs[i] = s1;
                i += 1;
            }
        }
    }
    Poly { coeffs }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(42)
    }

    #[test]
    fn ternary_values_in_range() {
        let mut rng = test_rng();
        let p = sample_ternary(&mut rng);
        for &c in &p.coeffs {
            assert!(c >= -1 && c <= 1, "ternary coefficient out of range: {}", c);
        }
    }

    #[test]
    fn ternary_has_all_three_values() {
        let mut rng = test_rng();
        let p = sample_ternary(&mut rng);
        let has_neg = p.coeffs.iter().any(|&c| c == -1);
        let has_zero = p.coeffs.iter().any(|&c| c == 0);
        let has_pos = p.coeffs.iter().any(|&c| c == 1);
        assert!(has_neg && has_zero && has_pos);
    }

    #[test]
    fn uniform_in_range() {
        let mut rng = test_rng();
        let p = sample_uniform(&mut rng);
        let half = Q / 2;
        for &c in &p.coeffs {
            assert!(
                c >= -half && c <= half,
                "uniform coefficient out of centered range: {}",
                c
            );
        }
    }

    #[test]
    fn gaussian_small_values() {
        let mut rng = test_rng();
        let p = sample_gaussian(&mut rng);
        // With σ=3.2, values > 20 are astronomically unlikely
        for &c in &p.coeffs {
            assert!(
                c.abs() < 50,
                "gaussian coefficient unexpectedly large: {}",
                c
            );
        }
    }

    #[test]
    fn gaussian_mean_near_zero() {
        let mut rng = test_rng();
        let p = sample_gaussian(&mut rng);
        let mean: f64 = p.coeffs.iter().map(|&c| c as f64).sum::<f64>() / N as f64;
        assert!(
            mean.abs() < 1.0,
            "gaussian mean too far from zero: {}",
            mean
        );
    }
}
