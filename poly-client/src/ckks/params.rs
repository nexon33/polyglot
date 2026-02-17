//! CKKS scheme parameters.
//!
//! N=4096 ring dimension with q=2^54-33 gives 128-bit security
//! for encrypt/decrypt-only (no homomorphic evaluation levels needed).

/// Ring dimension — degree of the cyclotomic polynomial X^N + 1.
pub const N: usize = 4096;

/// Ciphertext modulus. Prime, fits in i64, and N*Q² fits in i128.
pub const Q: i64 = (1i64 << 54) - 33; // 18014398509481951

/// Scaling factor. token_id * DELTA < Q for all u32 values.
/// max(u32) * DELTA = 4,294,967,295 * 1,048,576 ≈ 4.5e15 < 1.8e16 = Q.
pub const DELTA: i64 = 1i64 << 20; // 1048576

/// Standard deviation for discrete Gaussian error sampling.
pub const SIGMA: f64 = 3.2;
