//! CUDA GPU acceleration for NTT-based polynomial multiplication.
//!
//! Provides `GpuNttEngine` (device + precomputed buffers) and `GpuRnsPoly`
//! (GPU-resident RNS polynomial) that mirror the CPU `NttContext` / `RnsPoly`
//! with identical results but ~50-200x faster for batched operations.

mod engine;
mod gpu_rns_poly;

pub use engine::GpuNttEngine;
pub use gpu_rns_poly::{gpu_poly_mul, GpuRnsPoly};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ckks::ntt::NTT_PRIMES;
    use crate::ckks::params::N;
    use crate::ckks::rns::{create_ntt_contexts, RnsPoly};

    fn gpu_engine(num_primes: usize) -> GpuNttEngine {
        GpuNttEngine::new(0, num_primes).expect("GPU engine init failed")
    }

    #[test]
    fn gpu_ntt_roundtrip() {
        let engine = gpu_engine(3);
        let coeffs = vec![42, -17, 100, 0, -999];
        let poly = RnsPoly::from_coeffs(&coeffs, 3);

        let mut gpu_poly = GpuRnsPoly::from_cpu(&poly, &engine).unwrap();
        gpu_poly.ntt_forward(&engine).unwrap();
        gpu_poly.ntt_inverse(&engine).unwrap();
        let result = gpu_poly.to_cpu(&engine).unwrap();

        let result_coeffs = result.to_coeffs();
        for i in 0..5 {
            assert_eq!(result_coeffs[i], coeffs[i], "roundtrip mismatch at {i}");
        }
        for i in 5..N {
            assert_eq!(result_coeffs[i], 0, "nonzero at {i}");
        }
    }

    #[test]
    fn gpu_ntt_mul_matches_cpu() {
        let engine = gpu_engine(3);
        let ctxs = create_ntt_contexts();

        // (3 + X) * (2 + 4X) = 6 + 14X + 4X^2
        let a = RnsPoly::from_coeffs(&[3, 1], 3);
        let b = RnsPoly::from_coeffs(&[2, 4], 3);
        let cpu_result = a.mul(&b, &ctxs);

        let ga = GpuRnsPoly::from_cpu(&a, &engine).unwrap();
        let gb = GpuRnsPoly::from_cpu(&b, &engine).unwrap();
        let gc = ga.mul(&gb, &engine).unwrap();
        let gpu_result = gc.to_cpu(&engine).unwrap();

        let cpu_coeffs = cpu_result.to_coeffs();
        let gpu_coeffs = gpu_result.to_coeffs();
        for i in 0..N {
            assert_eq!(
                cpu_coeffs[i], gpu_coeffs[i],
                "CPU vs GPU mismatch at coeff {i}: cpu={} gpu={}",
                cpu_coeffs[i], gpu_coeffs[i]
            );
        }
    }

    #[test]
    fn gpu_ntt_mul_negacyclic() {
        let engine = gpu_engine(3);

        // X^(N-1) * X = X^N = -1
        let mut a_coeffs = vec![0i64; N];
        a_coeffs[N - 1] = 1;
        let mut b_coeffs = vec![0i64; N];
        b_coeffs[1] = 1;

        let a = RnsPoly::from_coeffs(&a_coeffs, 3);
        let b = RnsPoly::from_coeffs(&b_coeffs, 3);

        let ga = GpuRnsPoly::from_cpu(&a, &engine).unwrap();
        let gb = GpuRnsPoly::from_cpu(&b, &engine).unwrap();
        let gc = ga.mul(&gb, &engine).unwrap();
        let result = gc.to_cpu(&engine).unwrap().to_coeffs();

        assert_eq!(result[0], -1, "X^N should be -1");
        for i in 1..N {
            assert_eq!(result[i], 0);
        }
    }

    #[test]
    fn gpu_add_sub_matches_cpu() {
        let engine = gpu_engine(2);
        let a = RnsPoly::from_coeffs(&[10, 20, 30], 2);
        let b = RnsPoly::from_coeffs(&[5, -10, 15], 2);

        let ga = GpuRnsPoly::from_cpu(&a, &engine).unwrap();
        let gb = GpuRnsPoly::from_cpu(&b, &engine).unwrap();

        // Add
        let sum = ga.add(&gb, &engine).unwrap().to_cpu(&engine).unwrap();
        let sum_coeffs = sum.to_coeffs();
        assert_eq!(sum_coeffs[0], 15);
        assert_eq!(sum_coeffs[1], 10);
        assert_eq!(sum_coeffs[2], 45);

        // Sub
        let diff = ga.sub(&gb, &engine).unwrap().to_cpu(&engine).unwrap();
        let diff_coeffs = diff.to_coeffs();
        assert_eq!(diff_coeffs[0], 5);
        assert_eq!(diff_coeffs[1], 30);
        assert_eq!(diff_coeffs[2], 15);
    }

    #[test]
    fn gpu_neg_matches_cpu() {
        let engine = gpu_engine(2);
        let a = RnsPoly::from_coeffs(&[10, -20, 30], 2);
        let ga = GpuRnsPoly::from_cpu(&a, &engine).unwrap();
        let neg = ga.neg(&engine).unwrap().to_cpu(&engine).unwrap();
        let coeffs = neg.to_coeffs();
        assert_eq!(coeffs[0], -10);
        assert_eq!(coeffs[1], 20);
        assert_eq!(coeffs[2], -30);
    }

    #[test]
    fn gpu_scalar_mul_matches_cpu() {
        let engine = gpu_engine(2);
        let a = RnsPoly::from_coeffs(&[10, -20, 30], 2);
        let ga = GpuRnsPoly::from_cpu(&a, &engine).unwrap();
        let scaled = ga.scalar_mul(3, &engine).unwrap().to_cpu(&engine).unwrap();
        let coeffs = scaled.to_coeffs();
        assert_eq!(coeffs[0], 30);
        assert_eq!(coeffs[1], -60);
        assert_eq!(coeffs[2], 90);
    }

    #[test]
    fn gpu_automorphism_identity() {
        let engine = gpu_engine(3);
        let coeffs_in = vec![1, 2, 3, -4, 5];
        let a = RnsPoly::from_coeffs(&coeffs_in, 3);
        let ga = GpuRnsPoly::from_cpu(&a, &engine).unwrap();
        let result = ga
            .apply_automorphism(1, &engine)
            .unwrap()
            .to_cpu(&engine)
            .unwrap()
            .to_coeffs();
        for i in 0..5 {
            assert_eq!(result[i], coeffs_in[i], "identity failed at {i}");
        }
    }

    #[test]
    fn gpu_automorphism_matches_cpu() {
        let engine = gpu_engine(3);
        let coeffs_in: Vec<i64> = (0..N as i64).map(|i| (i * 7 + 3) % 100 - 50).collect();
        let a = RnsPoly::from_coeffs(&coeffs_in, 3);
        let cpu_result = a.apply_automorphism(3);

        let ga = GpuRnsPoly::from_cpu(&a, &engine).unwrap();
        let gpu_result = ga
            .apply_automorphism(3, &engine)
            .unwrap()
            .to_cpu(&engine)
            .unwrap();

        let cpu_c = cpu_result.to_coeffs();
        let gpu_c = gpu_result.to_coeffs();
        for i in 0..N {
            assert_eq!(cpu_c[i], gpu_c[i], "automorphism mismatch at {i}");
        }
    }

    #[test]
    fn gpu_drop_last_prime_matches_cpu() {
        let engine = gpu_engine(3);
        let q_last = NTT_PRIMES[2];
        let val = 42 * q_last;
        let a = RnsPoly::from_coeffs(&[val], 3);

        let cpu_b = a.drop_last_prime();
        let ga = GpuRnsPoly::from_cpu(&a, &engine).unwrap();
        let gpu_b = ga.drop_last_prime(&engine).unwrap().to_cpu(&engine).unwrap();

        let cpu_c = cpu_b.to_coeffs();
        let gpu_c = gpu_b.to_coeffs();
        for i in 0..N {
            assert_eq!(cpu_c[i], gpu_c[i], "drop_last_prime mismatch at {i}");
        }
    }

    #[test]
    fn gpu_full_mul_random_matches_cpu() {
        let engine = gpu_engine(3);
        let ctxs = create_ntt_contexts();

        // Random-ish polynomial multiply
        let a_coeffs: Vec<i64> = (0..N as i64).map(|i| (i * 13 + 7) % 1000 - 500).collect();
        let b_coeffs: Vec<i64> = (0..N as i64).map(|i| (i * 29 + 11) % 1000 - 500).collect();

        let a = RnsPoly::from_coeffs(&a_coeffs, 3);
        let b = RnsPoly::from_coeffs(&b_coeffs, 3);
        let cpu_result = a.mul(&b, &ctxs);

        let ga = GpuRnsPoly::from_cpu(&a, &engine).unwrap();
        let gb = GpuRnsPoly::from_cpu(&b, &engine).unwrap();
        let gc = ga.mul(&gb, &engine).unwrap();
        let gpu_result = gc.to_cpu(&engine).unwrap();

        let cpu_c = cpu_result.to_coeffs();
        let gpu_c = gpu_result.to_coeffs();
        for i in 0..N {
            assert_eq!(
                cpu_c[i], gpu_c[i],
                "random mul mismatch at {i}: cpu={} gpu={}",
                cpu_c[i], gpu_c[i]
            );
        }
    }
}
