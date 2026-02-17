// ============================================================================
// Batched NTT Forward/Inverse kernels for CKKS polynomial multiplication.
//
// N = 4096 (ring dimension), LOG_N = 12 butterfly stages.
// Primes are ~36 bits (< 2^37). All intermediate arithmetic uses
// split-multiply to stay within 64-bit without i128.
//
// Grid:  (1, 1, num_primes)  — one Z-block per prime
// Block: (512, 1, 1)
// Shared memory: N * sizeof(long long) = 32 KB
// ============================================================================

#define N      4096
#define LOG_N  12

// ── Modular arithmetic for primes < 2^37 ─────────────────────────────────

// Split-multiply: a*b mod q without 128-bit intermediates.
// Both a, b in [0, q), q < 2^37.
// Split b into low 18 bits and high 19 bits so partial products fit in u64.
__device__ __forceinline__
long long mod_mul(long long a, long long b, long long q) {
    unsigned long long au = (unsigned long long)a;
    unsigned long long bu = (unsigned long long)b;
    unsigned long long qu = (unsigned long long)q;

    unsigned long long b_lo = bu & 0x3FFFFULL;   // low 18 bits
    unsigned long long b_hi = bu >> 18;           // high ≤19 bits

    // au * b_lo < 2^37 * 2^18 = 2^55, fits u64
    unsigned long long t1 = (au * b_lo) % qu;
    // au * b_hi < 2^37 * 2^19 = 2^56, fits u64
    unsigned long long t2 = (au * b_hi) % qu;
    // t2 < q < 2^37, shift < 2^55, fits u64
    unsigned long long t3 = (t2 << 18) % qu;

    return (long long)((t1 + t3) % qu);           // t1+t3 < 2q < 2^38
}

__device__ __forceinline__
long long mod_add(long long a, long long b, long long q) {
    long long r = a + b;
    return r >= q ? r - q : r;
}

__device__ __forceinline__
long long mod_sub(long long a, long long b, long long q) {
    long long r = a - b;
    return r < 0 ? r + q : r;
}

// Bit-reverse the bottom LOG_N bits of v.
__device__ __forceinline__
unsigned int bit_rev(unsigned int v) {
    return __brev(v) >> (32 - LOG_N);
}

// ── Forward NTT: coefficient → evaluation domain ──────────────────────────
//
// Parameters:
//   data        [num_primes * N]  — in-place, i64
//   psi_powers  [num_primes * N]  — precomputed ψ^i per prime
//   primes      [num_primes]      — the NTT-friendly primes
//   num_primes  scalar
//
// Computes negacyclic NTT via:
//   1. Pre-twist:  data[i] *= ψ^i   (converts negacyclic → standard)
//   2. Bit-reverse permutation
//   3. 12 Cooley-Tukey butterfly stages in shared memory
extern "C" __global__
void ntt_forward_batched(
    long long* __restrict__ data,
    const long long* __restrict__ psi_powers,
    const long long* __restrict__ primes,
    int num_primes)
{
    int pid = blockIdx.z;
    if (pid >= num_primes) return;

    long long q = primes[pid];
    int base = pid * N;

    extern __shared__ long long sdata[];

    // Step 1: Load with pre-twist (multiply by ψ^i for negacyclic NTT)
    for (int i = threadIdx.x; i < N; i += blockDim.x) {
        long long val = data[base + i];
        // Normalise to [0, q)
        val = ((val % q) + q) % q;
        long long psi = psi_powers[base + i];
        sdata[i] = mod_mul(val, psi, q);
    }
    __syncthreads();

    // Step 2: Bit-reverse permutation
    for (int i = threadIdx.x; i < N; i += blockDim.x) {
        unsigned int j = bit_rev((unsigned int)i);
        if (i < (int)j) {
            long long tmp = sdata[i];
            sdata[i] = sdata[j];
            sdata[j] = tmp;
        }
    }
    __syncthreads();

    // Step 3: Cooley-Tukey butterfly stages (len = 2, 4, 8, ..., N)
    for (int s = 1; s <= LOG_N; s++) {
        int len  = 1 << s;
        int half = len >> 1;
        // Twiddle step: index stride in psi_powers to get w^k = ψ^(k * step)
        // where step = 2N/len = N >> (s-1)
        int tw_step = N >> (s - 1);

        for (int i = threadIdx.x; i < (N >> 1); i += blockDim.x) {
            int group = i / half;
            int k     = i % half;
            int idx   = group * len + k;

            // Twiddle: ψ^(k * tw_step).  k * tw_step < N always.
            long long w = psi_powers[base + k * tw_step];

            long long u = sdata[idx];
            long long v = mod_mul(sdata[idx + half], w, q);
            sdata[idx]        = mod_add(u, v, q);
            sdata[idx + half] = mod_sub(u, v, q);
        }
        __syncthreads();
    }

    // Step 4: Write back to global memory
    for (int i = threadIdx.x; i < N; i += blockDim.x) {
        data[base + i] = sdata[i];
    }
}

// ── Inverse NTT: evaluation → coefficient domain ──────────────────────────
//
// Parameters:
//   data            [num_primes * N]  — in-place
//   psi_inv_powers  [num_primes * N]  — precomputed ψ_inv^i per prime
//   primes          [num_primes]
//   n_inv           [num_primes]      — N^{-1} mod q per prime
//   num_primes      scalar
//
// Computes inverse negacyclic NTT via:
//   1. Bit-reverse permutation
//   2. 12 butterfly stages with ψ_inv twiddles
//   3. Scale by N^{-1} and un-twist (multiply by ψ_inv^i)
extern "C" __global__
void ntt_inverse_batched(
    long long* __restrict__ data,
    const long long* __restrict__ psi_inv_powers,
    const long long* __restrict__ primes,
    const long long* __restrict__ n_inv,
    int num_primes)
{
    int pid = blockIdx.z;
    if (pid >= num_primes) return;

    long long q  = primes[pid];
    long long ni = n_inv[pid];
    int base = pid * N;

    extern __shared__ long long sdata[];

    // Step 1: Load data to shared memory
    for (int i = threadIdx.x; i < N; i += blockDim.x) {
        sdata[i] = data[base + i];
    }
    __syncthreads();

    // Step 2: Bit-reverse permutation
    for (int i = threadIdx.x; i < N; i += blockDim.x) {
        unsigned int j = bit_rev((unsigned int)i);
        if (i < (int)j) {
            long long tmp = sdata[i];
            sdata[i] = sdata[j];
            sdata[j] = tmp;
        }
    }
    __syncthreads();

    // Step 3: Butterfly stages with inverse twiddles
    for (int s = 1; s <= LOG_N; s++) {
        int len  = 1 << s;
        int half = len >> 1;
        int tw_step = N >> (s - 1);

        for (int i = threadIdx.x; i < (N >> 1); i += blockDim.x) {
            int group = i / half;
            int k     = i % half;
            int idx   = group * len + k;

            long long w = psi_inv_powers[base + k * tw_step];

            long long u = sdata[idx];
            long long v = mod_mul(sdata[idx + half], w, q);
            sdata[idx]        = mod_add(u, v, q);
            sdata[idx + half] = mod_sub(u, v, q);
        }
        __syncthreads();
    }

    // Step 4: Scale by N^{-1} and undo twist (multiply by ψ_inv^i)
    for (int i = threadIdx.x; i < N; i += blockDim.x) {
        long long val = mod_mul(sdata[i], ni, q);
        long long psi_inv = psi_inv_powers[base + i];
        sdata[i] = mod_mul(val, psi_inv, q);
    }
    __syncthreads();

    // Step 5: Write back
    for (int i = threadIdx.x; i < N; i += blockDim.x) {
        data[base + i] = sdata[i];
    }
}
