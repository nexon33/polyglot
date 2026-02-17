// ============================================================================
// Element-wise modular operations for RNS polynomials on GPU.
//
// Grid:  (ceil(N/256), num_primes, 1)
// Block: (256, 1, 1)
//
// All arrays are flattened [num_primes * N] with prime index = blockIdx.y.
// ============================================================================

#define N 4096

// ── Modular arithmetic (same as ntt.cu) ────────────────────────────────────

__device__ __forceinline__
long long mod_mul(long long a, long long b, long long q) {
    unsigned long long au = (unsigned long long)a;
    unsigned long long bu = (unsigned long long)b;
    unsigned long long qu = (unsigned long long)q;
    unsigned long long b_lo = bu & 0x3FFFFULL;
    unsigned long long b_hi = bu >> 18;
    unsigned long long t1 = (au * b_lo) % qu;
    unsigned long long t2 = (au * b_hi) % qu;
    unsigned long long t3 = (t2 << 18) % qu;
    return (long long)((t1 + t3) % qu);
}

// ── Pointwise multiply: c[i] = (a[i] * b[i]) mod q ───────────────────────

extern "C" __global__
void pointwise_mul_batched(
    long long* __restrict__ out,
    const long long* __restrict__ a,
    const long long* __restrict__ b,
    const long long* __restrict__ primes,
    int num_primes)
{
    int pid = blockIdx.y;
    if (pid >= num_primes) return;
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= N) return;

    long long q = primes[pid];
    int idx = pid * N + i;
    out[idx] = mod_mul(a[idx], b[idx], q);
}

// ── Pointwise add: c[i] = (a[i] + b[i]) mod q ───────────────────────────

extern "C" __global__
void pointwise_add_batched(
    long long* __restrict__ out,
    const long long* __restrict__ a,
    const long long* __restrict__ b,
    const long long* __restrict__ primes,
    int num_primes)
{
    int pid = blockIdx.y;
    if (pid >= num_primes) return;
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= N) return;

    long long q = primes[pid];
    int idx = pid * N + i;
    long long r = a[idx] + b[idx];
    out[idx] = r >= q ? r - q : r;
}

// ── Pointwise subtract: c[i] = (a[i] - b[i] + q) mod q ──────────────────

extern "C" __global__
void pointwise_sub_batched(
    long long* __restrict__ out,
    const long long* __restrict__ a,
    const long long* __restrict__ b,
    const long long* __restrict__ primes,
    int num_primes)
{
    int pid = blockIdx.y;
    if (pid >= num_primes) return;
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= N) return;

    long long q = primes[pid];
    int idx = pid * N + i;
    long long r = a[idx] - b[idx];
    out[idx] = r < 0 ? r + q : r;
}

// ── Automorphism: σ_m sends X → X^m in Z[X]/(X^N + 1) ───────────────────
//
// For each coefficient j: output[(m*j) % (2N)] = ±input[j]
// Sign flip when (m*j) % (2N) >= N (because X^N = -1).
//
// Grid:  (ceil(N/256), num_primes, 1)
// Block: (256, 1, 1)

extern "C" __global__
void automorphism_batched(
    long long* __restrict__ out,
    const long long* __restrict__ in_data,
    const long long* __restrict__ primes,
    int m,
    int num_primes)
{
    int pid = blockIdx.y;
    if (pid >= num_primes) return;
    int j = blockIdx.x * blockDim.x + threadIdx.x;
    if (j >= N) return;

    long long q = primes[pid];
    int base = pid * N;
    int two_n = 2 * N;

    int target = ((long long)m * j) % two_n;
    long long val = in_data[base + j];

    if (target < N) {
        out[base + target] = val;
    } else {
        // X^N = -1, so negate
        out[base + target - N] = val == 0 ? 0 : q - val;
    }
}

// ── Drop last prime (rescaling) ───────────────────────────────────────────
//
// For each remaining prime i < (num_primes - 1):
//   result[i][j] = (data[i][j] - data[last][j]) * q_last_inv[i] mod q_i
//
// Grid:  (ceil(N/256), num_primes - 1, 1)
// Block: (256, 1, 1)
//
// Parameters:
//   out             [(num_primes-1) * N]  — output with one fewer prime
//   data            [num_primes * N]      — input (all primes)
//   primes          [num_primes]
//   q_last_inv      [num_primes - 1]      — q_last^{-1} mod q_i for i < last
//   num_primes      scalar (original count including the prime being dropped)

extern "C" __global__
void drop_last_prime_batched(
    long long* __restrict__ out,
    const long long* __restrict__ data,
    const long long* __restrict__ primes,
    const long long* __restrict__ q_last_inv,
    int num_primes)
{
    int pid = blockIdx.y;              // prime index (0..num_primes-2)
    int last = num_primes - 1;
    if (pid >= last) return;
    int j = blockIdx.x * blockDim.x + threadIdx.x;
    if (j >= N) return;

    long long q_i = primes[pid];

    // r_last = data[last][j] mod q_i
    long long r_last = data[last * N + j] % q_i;
    if (r_last < 0) r_last += q_i;

    // diff = (data[pid][j] - r_last) mod q_i
    long long diff = data[pid * N + j] - r_last;
    if (diff < 0) diff += q_i;

    // result = diff * q_last^{-1} mod q_i
    out[pid * N + j] = mod_mul(diff, q_last_inv[pid], q_i);
}

// ── Scalar multiply: out[i] = (data[i] * scalar) mod q ───────────────────

extern "C" __global__
void scalar_mul_batched(
    long long* __restrict__ out,
    const long long* __restrict__ data,
    const long long* __restrict__ scalars,   // [num_primes] — scalar mod q_i
    const long long* __restrict__ primes,
    int num_primes)
{
    int pid = blockIdx.y;
    if (pid >= num_primes) return;
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= N) return;

    long long q = primes[pid];
    int idx = pid * N + i;
    out[idx] = mod_mul(data[idx], scalars[pid], q);
}

// ── Negate: out[i] = (q - data[i]) mod q ─────────────────────────────────

extern "C" __global__
void negate_batched(
    long long* __restrict__ out,
    const long long* __restrict__ data,
    const long long* __restrict__ primes,
    int num_primes)
{
    int pid = blockIdx.y;
    if (pid >= num_primes) return;
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= N) return;

    long long q = primes[pid];
    int idx = pid * N + i;
    long long val = data[idx];
    out[idx] = val == 0 ? 0 : q - val;
}
