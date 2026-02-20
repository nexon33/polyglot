//! GPU-resident RNS polynomial with CUDA-accelerated NTT and modular ops.

use cudarc::driver::{CudaSlice, LaunchAsync};

use crate::ckks::params::N;
use crate::ckks::rns::RnsPoly;

use super::engine::GpuNttEngine;

/// An RNS polynomial living in GPU memory.
///
/// Data layout: flat `[num_primes * N]` array of i64, where
/// `data[p * N + i]` = coefficient i of prime channel p.
pub struct GpuRnsPoly {
    pub data: CudaSlice<i64>,
    pub num_primes: usize,
}

impl GpuRnsPoly {
    /// Upload a CPU `RnsPoly` to the GPU.
    pub fn from_cpu(poly: &RnsPoly, engine: &GpuNttEngine) -> Result<Self, String> {
        let mut flat = Vec::with_capacity(poly.num_primes * N);
        for ch in &poly.residues {
            flat.extend_from_slice(ch);
        }
        let data = engine
            .device
            .htod_copy(flat)
            .map_err(|e| format!("upload RnsPoly: {e}"))?;
        Ok(Self {
            data,
            num_primes: poly.num_primes,
        })
    }

    /// Download to a CPU `RnsPoly`.
    pub fn to_cpu(&self, engine: &GpuNttEngine) -> Result<RnsPoly, String> {
        let flat = engine
            .device
            .dtoh_sync_copy(&self.data)
            .map_err(|e| format!("download RnsPoly: {e}"))?;
        let mut residues = Vec::with_capacity(self.num_primes);
        for p in 0..self.num_primes {
            residues.push(flat[p * N..(p + 1) * N].to_vec());
        }
        Ok(RnsPoly {
            residues,
            num_primes: self.num_primes,
        })
    }

    /// Allocate a zero polynomial on the GPU.
    pub fn zeros(num_primes: usize, engine: &GpuNttEngine) -> Result<Self, String> {
        let data = engine
            .device
            .alloc_zeros::<i64>(num_primes * N)
            .map_err(|e| format!("alloc zeros: {e}"))?;
        Ok(Self { data, num_primes })
    }

    // ── NTT operations (in-place, batched across all prime channels) ───

    /// Forward NTT: coefficient → evaluation domain (in-place).
    pub fn ntt_forward(&mut self, engine: &GpuNttEngine) -> Result<(), String> {
        let cfg = engine.ntt_config(self.num_primes);
        let func = engine
            .device
            .get_func("ntt", "ntt_forward_batched")
            .ok_or("ntt_forward_batched not found")?;
        unsafe {
            func.launch(
                cfg,
                (
                    &mut self.data,
                    &engine.psi_powers,
                    &engine.primes_buf,
                    self.num_primes as i32,
                ),
            )
        }
        .map_err(|e| format!("ntt_forward launch: {e}"))
    }

    /// Inverse NTT: evaluation → coefficient domain (in-place).
    pub fn ntt_inverse(&mut self, engine: &GpuNttEngine) -> Result<(), String> {
        let cfg = engine.ntt_config(self.num_primes);
        let func = engine
            .device
            .get_func("ntt", "ntt_inverse_batched")
            .ok_or("ntt_inverse_batched not found")?;
        unsafe {
            func.launch(
                cfg,
                (
                    &mut self.data,
                    &engine.psi_inv_powers,
                    &engine.primes_buf,
                    &engine.n_inv_buf,
                    self.num_primes as i32,
                ),
            )
        }
        .map_err(|e| format!("ntt_inverse launch: {e}"))
    }

    // ── Element-wise operations ────────────────────────────────────────

    /// Pointwise multiply in evaluation domain: `result[i] = (self[i] * other[i]) mod q`.
    pub fn pointwise_mul(
        &self,
        other: &GpuRnsPoly,
        engine: &GpuNttEngine,
    ) -> Result<GpuRnsPoly, String> {
        assert_eq!(self.num_primes, other.num_primes);
        let mut out = GpuRnsPoly::zeros(self.num_primes, engine)?;
        let cfg = engine.elemwise_config(self.num_primes);
        let func = engine
            .device
            .get_func("ops", "pointwise_mul_batched")
            .ok_or("pointwise_mul_batched not found")?;
        unsafe {
            func.launch(
                cfg,
                (
                    &mut out.data,
                    &self.data,
                    &other.data,
                    &engine.primes_buf,
                    self.num_primes as i32,
                ),
            )
        }
        .map_err(|e| format!("pointwise_mul launch: {e}"))?;
        Ok(out)
    }

    /// Full NTT polynomial multiply: forward(self), forward(other), pointwise, inverse.
    pub fn mul(&self, other: &GpuRnsPoly, engine: &GpuNttEngine) -> Result<GpuRnsPoly, String> {
        // Clone both inputs to NTT domain (don't mutate originals)
        let mut a = self.clone_on_gpu(engine)?;
        let mut b = other.clone_on_gpu(engine)?;
        a.ntt_forward(engine)?;
        b.ntt_forward(engine)?;
        let mut c = a.pointwise_mul(&b, engine)?;
        c.ntt_inverse(engine)?;
        Ok(c)
    }

    /// Coefficient-wise addition: `(self + other) mod q`.
    pub fn add(&self, other: &GpuRnsPoly, engine: &GpuNttEngine) -> Result<GpuRnsPoly, String> {
        assert_eq!(self.num_primes, other.num_primes);
        let mut out = GpuRnsPoly::zeros(self.num_primes, engine)?;
        let cfg = engine.elemwise_config(self.num_primes);
        let func = engine
            .device
            .get_func("ops", "pointwise_add_batched")
            .ok_or("pointwise_add_batched not found")?;
        unsafe {
            func.launch(
                cfg,
                (
                    &mut out.data,
                    &self.data,
                    &other.data,
                    &engine.primes_buf,
                    self.num_primes as i32,
                ),
            )
        }
        .map_err(|e| format!("add launch: {e}"))?;
        Ok(out)
    }

    /// Coefficient-wise subtraction: `(self - other + q) mod q`.
    pub fn sub(&self, other: &GpuRnsPoly, engine: &GpuNttEngine) -> Result<GpuRnsPoly, String> {
        assert_eq!(self.num_primes, other.num_primes);
        let mut out = GpuRnsPoly::zeros(self.num_primes, engine)?;
        let cfg = engine.elemwise_config(self.num_primes);
        let func = engine
            .device
            .get_func("ops", "pointwise_sub_batched")
            .ok_or("pointwise_sub_batched not found")?;
        unsafe {
            func.launch(
                cfg,
                (
                    &mut out.data,
                    &self.data,
                    &other.data,
                    &engine.primes_buf,
                    self.num_primes as i32,
                ),
            )
        }
        .map_err(|e| format!("sub launch: {e}"))?;
        Ok(out)
    }

    /// Negate all coefficients: `(q - self) mod q`.
    pub fn neg(&self, engine: &GpuNttEngine) -> Result<GpuRnsPoly, String> {
        let mut out = GpuRnsPoly::zeros(self.num_primes, engine)?;
        let cfg = engine.elemwise_config(self.num_primes);
        let func = engine
            .device
            .get_func("ops", "negate_batched")
            .ok_or("negate_batched not found")?;
        unsafe {
            func.launch(
                cfg,
                (
                    &mut out.data,
                    &self.data,
                    &engine.primes_buf,
                    self.num_primes as i32,
                ),
            )
        }
        .map_err(|e| format!("neg launch: {e}"))?;
        Ok(out)
    }

    /// Scalar multiply: `(self * scalar) mod q` per prime.
    pub fn scalar_mul(
        &self,
        scalar: i64,
        engine: &GpuNttEngine,
    ) -> Result<GpuRnsPoly, String> {
        use crate::ckks::ntt::NTT_PRIMES;
        // Reduce scalar mod each prime and upload
        let scalars: Vec<i64> = (0..self.num_primes)
            .map(|i| {
                let q = NTT_PRIMES[i];
                ((scalar as i128 % q as i128 + q as i128) % q as i128) as i64
            })
            .collect();
        let scalars_buf = engine
            .device
            .htod_copy(scalars)
            .map_err(|e| format!("upload scalars: {e}"))?;

        let mut out = GpuRnsPoly::zeros(self.num_primes, engine)?;
        let cfg = engine.elemwise_config(self.num_primes);
        let func = engine
            .device
            .get_func("ops", "scalar_mul_batched")
            .ok_or("scalar_mul_batched not found")?;
        unsafe {
            func.launch(
                cfg,
                (
                    &mut out.data,
                    &self.data,
                    &scalars_buf,
                    &engine.primes_buf,
                    self.num_primes as i32,
                ),
            )
        }
        .map_err(|e| format!("scalar_mul launch: {e}"))?;
        Ok(out)
    }

    /// Apply Galois automorphism σ_m: X → X^m.
    pub fn apply_automorphism(
        &self,
        m: usize,
        engine: &GpuNttEngine,
    ) -> Result<GpuRnsPoly, String> {
        let mut out = GpuRnsPoly::zeros(self.num_primes, engine)?;
        let cfg = engine.elemwise_config(self.num_primes);
        let func = engine
            .device
            .get_func("ops", "automorphism_batched")
            .ok_or("automorphism_batched not found")?;
        unsafe {
            func.launch(
                cfg,
                (
                    &mut out.data,
                    &self.data,
                    &engine.primes_buf,
                    m as i32,
                    self.num_primes as i32,
                ),
            )
        }
        .map_err(|e| format!("automorphism launch: {e}"))?;
        Ok(out)
    }

    /// Drop the last prime (rescaling step).
    pub fn drop_last_prime(&self, engine: &GpuNttEngine) -> Result<GpuRnsPoly, String> {
        assert!(self.num_primes > 1, "cannot drop last prime from single-prime poly");
        let new_primes = self.num_primes - 1;
        let mut out = GpuRnsPoly::zeros(new_primes, engine)?;

        let q_last_inv = engine.upload_q_last_inv(self.num_primes)?;

        let cfg = engine.elemwise_config(new_primes);
        let func = engine
            .device
            .get_func("ops", "drop_last_prime_batched")
            .ok_or("drop_last_prime_batched not found")?;
        unsafe {
            func.launch(
                cfg,
                (
                    &mut out.data,
                    &self.data,
                    &engine.primes_buf,
                    &q_last_inv,
                    self.num_primes as i32,
                ),
            )
        }
        .map_err(|e| format!("drop_last_prime launch: {e}"))?;
        Ok(out)
    }

    // ── Utility ────────────────────────────────────────────────────────

    /// Clone this polynomial on the GPU (device-to-device copy).
    pub fn clone_on_gpu(&self, engine: &GpuNttEngine) -> Result<GpuRnsPoly, String> {
        // Download and re-upload (simple path; could use device-to-device copy)
        let flat = engine
            .device
            .dtoh_sync_copy(&self.data)
            .map_err(|e| format!("clone download: {e}"))?;
        let data = engine
            .device
            .htod_copy(flat)
            .map_err(|e| format!("clone upload: {e}"))?;
        Ok(GpuRnsPoly {
            data,
            num_primes: self.num_primes,
        })
    }
}

/// Convenience: multiply two CPU `RnsPoly` via GPU (upload → NTT mul → download).
pub fn gpu_poly_mul(a: &RnsPoly, b: &RnsPoly, engine: &GpuNttEngine) -> Result<RnsPoly, String> {
    let ga = GpuRnsPoly::from_cpu(a, engine)?;
    let gb = GpuRnsPoly::from_cpu(b, engine)?;
    let gc = ga.mul(&gb, engine)?;
    gc.to_cpu(engine)
}
