# Poly Network — Encrypted Inference Benchmark

## Qwen3-0.6B: Plaintext vs RNS-CKKS Encrypted Generation

Full autoregressive generation through homomorphic encryption,
producing coherent, factually correct text without the server ever seeing
the plaintext data.

### Setup

- **Model**: Qwen3-0.6B (28 transformer layers, 1024-dim hidden state, 151936 vocab)
- **FHE scheme**: RNS-CKKS (N=4096, 3 NTT primes, DELTA=2^36)
- **Projection**: 1024d → 16d (h-aligned + PCA signal-preserving)
- **Network**: 16×16 identity linear (Activation::None)
- **Hardware**: NVIDIA GPU (CUDA for both LLM inference and FHE NTT acceleration)

### Output (10 tokens)

**Plaintext (Part A)**:
> The capital of France is Paris. The capital of Italy is Rome. The

**Encrypted (Part B)**:
> The capital of France is Paris. The capital of France is also the capital

Both produce coherent text. The first 5 tokens match exactly; divergence
after that is expected since Part A uses temperature-0.7 sampling while
Part B uses greedy argmax.

### Performance

| Metric | Plaintext | Encrypted (GPU) | Encrypted (CPU) |
|--------|-----------|-----------------|-----------------|
| Tokens generated | 10 | 10 | 50 |
| Speed | 19.9 tok/s | 0.80 tok/s | 0.103 tok/s |
| Per-token time | 50ms | 1.25s | 9.7s |
| Overhead vs plaintext | 1x | **25x** | 197x |

**GPU NTT acceleration provides an 8x speedup** over CPU-only FHE, reducing
overhead from 197x to 25x vs plaintext inference.

### Per-Token Breakdown (Encrypted, GPU)

| Stage | Per token | % |
|-------|-----------|---|
| Qwen3 forward (28 layers, CUDA) | 45ms | 3.6% |
| H-aligned + PCA projection | 0.1ms | <0.1% |
| RNS-CKKS encrypt | 3ms | 0.2% |
| **FHE blind compute (GPU NTT)** | **1,190ms** | **95.2%** |
| RNS-CKKS decrypt | 6ms | 0.5% |
| lm_head projection | 9ms | 0.7% |

FHE computation still dominates but is 8x faster with CUDA NTT.

### CPU vs GPU FHE Comparison

| Metric | CPU NTT | GPU NTT | Speedup |
|--------|---------|---------|---------|
| FHE compute/token | 9,352ms | 1,190ms | **7.9x** |
| Total pipeline/token | 9,491ms | 1,248ms | **7.6x** |
| Overhead vs plaintext | 197x | 25x | - |

### One-Time Setup Costs

| Stage | Time |
|-------|------|
| Model load (CUDA) | 3.1s |
| PCA eigenvectors (W^T W) | 2.8s |
| RNS-CKKS keygen (GPU NTT) | 0.7s |

### FHE Verification

- **Max error across tokens**: 1.13e-6
- **Verification**: PASS (threshold: 0.5)
- **Privacy guarantee**: Server performs blind computation on encrypted data — never sees plaintext

### Architecture

```
Per-token encrypted inference pipeline:

  Qwen3 Base Model (CUDA)  Client                    Server (blind)
  ─────────────────────  ──────────────────     ─────────────────────
  forward(token, pos)    h-aligned projection   RNS-CKKS FHE compute
  → hidden state h       1024d → 16d            on encrypted 16d vector
  (1024d, 28 layers)     → RNS-CKKS encrypt     (GPU NTT-accelerated,
                         → send ciphertext        no secret key access)
                                                 → return ciphertext
                         decrypt → 16d
                         project back 16d→1024d
                         → lm_head → next token
```

### GPU NTT Acceleration

All NTT polynomial multiplications are dispatched to CUDA via
`RnsCkksContext::poly_mul()`, with automatic CPU fallback:

- **CUDA kernels**: Batched NTT forward/inverse (shared memory, 512 threads/block),
  pointwise modular ops, automorphism, rescaling
- **Split-multiply**: 36-bit primes multiplied via 18-bit split to avoid i128 on GPU
- **Transparent dispatch**: `#[cfg(feature = "cuda")]` — same API, no code changes needed
- **271 tests pass** including 10 GPU-specific correctness tests verifying
  bit-identical results to CPU

### Signal-Preserving Projection

The 1024→16 projection uses a custom h-aligned + PCA basis:

1. **Direction 1**: h/||h|| — preserves ALL logit information since
   logit_t = w_t · h = ||h|| · (w_t · e₁)
2. **Directions 2-16**: Top PCA eigenvectors of W^T W (embed_tokens weight),
   orthogonalized against h via Gram-Schmidt

This outperforms random projection by preserving the specific signal
direction that determines token predictions.

### Running

```bash
# GPU-accelerated (requires CUDA + --features cuda)
cargo run --release -p poly-inference --features cuda --bin poly-demo-rns-fhe-e2e -- "The capital of France is" 10

# CPU-only fallback
cargo run --release -p poly-inference --bin poly-demo-rns-fhe-e2e -- "The capital of France is" 10

# Custom prompt
cargo run --release -p poly-inference --features cuda --bin poly-demo-rns-fhe-e2e -- "The largest ocean is" 20
```

### Security

- **526 tests** including 94 adversarial attack tests
- **38 crypto-layer attacks**: CKKS noise bounds, NTT prime verification,
  sampling bias, ciphertext malleability, RLWE security
- **42 protocol-layer attacks**: disclosure spoofing, proof replay,
  domain separation, Merkle forgery, privacy mode enforcement
- **14 compliance attacks**: frozen accounts, anti-structuring detection,
  overflow protection, fee validation
- **Side-channel resistance**: Fixed ciphertext size eliminates
  token-length inference (Whisper Leak immune by construction)
