//! GPU NTT engine: CUDA device, loaded kernels, and precomputed twiddle tables.

use std::sync::Arc;

use cudarc::driver::{CudaDevice, CudaSlice, LaunchConfig};
use cudarc::nvrtc::Ptx;

use crate::ckks::ntt::{mod_inv, NttContext, NTT_PRIMES};
use crate::ckks::params::N;

// PTX embedded at compile time from build.rs output.
const NTT_PTX: &str = include_str!(concat!(env!("OUT_DIR"), "/ntt.ptx"));
const OPS_PTX: &str = include_str!(concat!(env!("OUT_DIR"), "/modular_ops.ptx"));

/// NTT function names loaded from ntt.ptx.
const NTT_FUNCS: &[&str] = &["ntt_forward_batched", "ntt_inverse_batched"];

/// Modular-ops function names loaded from modular_ops.ptx.
const OPS_FUNCS: &[&str] = &[
    "pointwise_mul_batched",
    "pointwise_add_batched",
    "pointwise_sub_batched",
    "automorphism_batched",
    "drop_last_prime_batched",
    "scalar_mul_batched",
    "negate_batched",
];

/// GPU engine holding the CUDA device, loaded kernel modules, and
/// precomputed twiddle/prime buffers for all NTT primes.
pub struct GpuNttEngine {
    pub device: Arc<CudaDevice>,

    /// ψ^i per prime, flat [num_primes * N].
    pub psi_powers: CudaSlice<i64>,
    /// ψ_inv^i per prime, flat [num_primes * N].
    pub psi_inv_powers: CudaSlice<i64>,
    /// The NTT-friendly primes, [num_primes].
    pub primes_buf: CudaSlice<i64>,
    /// N^{-1} mod q per prime, [num_primes].
    pub n_inv_buf: CudaSlice<i64>,

    /// Number of active primes.
    pub num_primes: usize,

    /// CPU-side NTT contexts (for reference / CPU fallback).
    pub cpu_contexts: Vec<NttContext>,
}

impl GpuNttEngine {
    /// Create a new GPU engine for `num_primes` NTT primes on device `ordinal`.
    ///
    /// Loads the compiled CUDA kernels and uploads precomputed twiddle tables.
    pub fn new(ordinal: usize, num_primes: usize) -> Result<Self, String> {
        assert!(
            num_primes <= NTT_PRIMES.len(),
            "requested {} primes, only {} available",
            num_primes,
            NTT_PRIMES.len()
        );

        let device = CudaDevice::new(ordinal).map_err(|e| format!("CUDA device init: {e}"))?;

        // Load kernel modules
        device
            .load_ptx(Ptx::from_src(NTT_PTX), "ntt", NTT_FUNCS)
            .map_err(|e| format!("load ntt.ptx: {e}"))?;
        device
            .load_ptx(Ptx::from_src(OPS_PTX), "ops", OPS_FUNCS)
            .map_err(|e| format!("load modular_ops.ptx: {e}"))?;

        // Build CPU contexts for twiddle extraction
        let cpu_contexts: Vec<NttContext> = NTT_PRIMES[..num_primes]
            .iter()
            .map(|&q| NttContext::new(q))
            .collect();

        // Flatten twiddle tables: [prime0_psi0, prime0_psi1, ..., prime1_psi0, ...]
        let mut psi_flat = Vec::with_capacity(num_primes * N);
        let mut psi_inv_flat = Vec::with_capacity(num_primes * N);
        let mut primes_vec = Vec::with_capacity(num_primes);
        let mut n_inv_vec = Vec::with_capacity(num_primes);

        for ctx in &cpu_contexts {
            psi_flat.extend_from_slice(&ctx.psi_powers);
            psi_inv_flat.extend_from_slice(&ctx.psi_inv_powers);
            primes_vec.push(ctx.q);
            n_inv_vec.push(ctx.n_inv);
        }

        // Upload to GPU
        let psi_powers = device
            .htod_copy(psi_flat)
            .map_err(|e| format!("upload psi_powers: {e}"))?;
        let psi_inv_powers = device
            .htod_copy(psi_inv_flat)
            .map_err(|e| format!("upload psi_inv_powers: {e}"))?;
        let primes_buf = device
            .htod_copy(primes_vec)
            .map_err(|e| format!("upload primes: {e}"))?;
        let n_inv_buf = device
            .htod_copy(n_inv_vec)
            .map_err(|e| format!("upload n_inv: {e}"))?;

        Ok(Self {
            device,
            psi_powers,
            psi_inv_powers,
            primes_buf,
            n_inv_buf,
            num_primes,
            cpu_contexts,
        })
    }

    // ── Kernel launch helpers ──────────────────────────────────────────

    /// Launch config for NTT kernels (one block per prime, shared memory).
    pub(crate) fn ntt_config(&self, active_primes: usize) -> LaunchConfig {
        LaunchConfig {
            grid_dim: (1, 1, active_primes as u32),
            block_dim: (512, 1, 1),
            shared_mem_bytes: (N * std::mem::size_of::<i64>()) as u32,
        }
    }

    /// Launch config for element-wise kernels.
    pub(crate) fn elemwise_config(&self, active_primes: usize) -> LaunchConfig {
        LaunchConfig {
            grid_dim: ((N as u32 + 255) / 256, active_primes as u32, 1),
            block_dim: (256, 1, 1),
            shared_mem_bytes: 0,
        }
    }

    /// Compute `q_last_inv[i] = q_last^{-1} mod q_i` for drop-last-prime and upload.
    pub(crate) fn upload_q_last_inv(
        &self,
        active_primes: usize,
    ) -> Result<CudaSlice<i64>, String> {
        let last = active_primes - 1;
        let q_last = NTT_PRIMES[last];
        let inv_vec: Vec<i64> = (0..last).map(|i| mod_inv(q_last, NTT_PRIMES[i])).collect();
        self.device
            .htod_copy(inv_vec)
            .map_err(|e| format!("upload q_last_inv: {e}"))
    }
}
