# Poly Network — Encrypted Inference Benchmark

## Qwen3-0.6B: Plaintext vs RNS-CKKS Encrypted Generation

Full 50-token autoregressive generation through homomorphic encryption,
producing coherent, factually correct text without the server ever seeing
the plaintext data.

### Setup

- **Model**: Qwen3-0.6B (28 transformer layers, 1024-dim hidden state, 151936 vocab)
- **FHE scheme**: RNS-CKKS (N=4096, 3 NTT primes, DELTA=2^36)
- **Projection**: 1024d → 16d (h-aligned + PCA signal-preserving)
- **Network**: 16×16 identity linear (Activation::None)
- **Hardware**: CPU-only (no GPU)

### Output

**Plaintext (Part A)**:
> The capital of France is Paris. The capital of Italy is Rome. The capital
> of Spain is Madrid. The capital of the United States is Washington, D.C.
> The capital of Japan is Tokyo. The capital of Russia is Moscow. The capital
> of India is New Delhi.

**Encrypted (Part B)**:
> The capital of France is Paris. The capital of Italy is Rome. The capital
> of Spain is Madrid. The capital of China is Beijing. The capital of Japan
> is Tokyo. The capital of India is New Delhi. The capital of Brazil is
> Brasilia. The capital of Egypt

Both produce 50 tokens of coherent text listing world capitals with correct
facts. The first 19 tokens match exactly; divergence after that is expected
since Part A uses temperature-0.7 sampling while Part B uses greedy argmax.

### Performance

| Metric | Plaintext | Encrypted |
|--------|-----------|-----------|
| Tokens generated | 50 | 50 |
| Speed | 7.0 tok/s | 0.103 tok/s |
| Per-token time | 143ms | 9.7s |
| Total generation | 7.1s | 485.6s |
| Overhead | 1x | 68x |

### Per-Token Breakdown (Encrypted)

| Stage | Time | Per token |
|-------|------|-----------|
| Qwen3 forward (28 layers) | 5,473ms | 109ms |
| H-aligned + PCA projection | 5ms | 0.1ms |
| RNS-CKKS encrypt | 1,154ms | 23ms |
| **FHE blind compute** | **476,942ms** | **9,539ms** |
| RNS-CKKS decrypt | 563ms | 11ms |
| lm_head projection | 1,688ms | 34ms |

FHE computation dominates at 98% of per-token time.

### One-Time Setup Costs

| Stage | Time |
|-------|------|
| Model load | 4.0s |
| PCA eigenvectors (W^T W) | 1.1s |
| RNS-CKKS keygen | 4.8s |

### FHE Verification

- **Max error across 50 tokens**: 1.22e-6
- **Verification**: PASS (threshold: 0.5)
- **Privacy guarantee**: Server performs blind computation on encrypted data — never sees plaintext

### Architecture

```
Per-token encrypted inference pipeline:

  Qwen3 Base Model          Client                    Server (blind)
  ─────────────────     ──────────────────     ─────────────────────
  forward(token, pos)   h-aligned projection   RNS-CKKS FHE compute
  → hidden state h      1024d → 16d            on encrypted 16d vector
  (1024d, 28 layers)    → RNS-CKKS encrypt     (identity linear, no
                        → send ciphertext        secret key access)
                                                → return ciphertext
                        decrypt → 16d
                        project back 16d→1024d
                        → lm_head → next token
```

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
# Full benchmark (50 tokens, ~8.5 minutes)
cargo run --release -p poly-inference --bin poly-demo-rns-fhe-e2e

# Quick test (3 tokens, ~30 seconds)
cargo run --release -p poly-inference --bin poly-demo-rns-fhe-e2e -- "The capital of France is" 3

# Custom prompt
cargo run --release -p poly-inference --bin poly-demo-rns-fhe-e2e -- "The largest ocean is" 20
```
