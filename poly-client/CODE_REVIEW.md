# poly-client — Documentation & Code Review

## Overview

`poly-client` is the thin-client SDK and CKKS homomorphic-encryption library for the
Poly Network private verified-inference toolchain. It provides two layers:

1. A small protocol/SDK surface ([poly-client/src/lib.rs](poly-client/src/lib.rs),
   [poly-client/src/encryption.rs](poly-client/src/encryption.rs),
   [poly-client/src/protocol.rs](poly-client/src/protocol.rs)) — an `EncryptionBackend`
   trait with a `MockEncryption` passthrough and a `CkksEncryption` lattice backend,
   plus the `InferRequest`/`InferResponse` wire types and a `VerifiedResponse`
   wrapper that binds decrypted output tokens to an execution proof.
2. A from-scratch **CKKS** homomorphic encryption library under
   [poly-client/src/ckks/](poly-client/src/ckks/): RNS-based CKKS with NTT polynomial
   multiplication, key generation, encrypt/decrypt, homomorphic
   add/sub/multiply/rescale/rotate, leveled polynomial evaluation, FHE neural-net
   layers, optional CUDA acceleration, and a PFHE compression wire format.

The primary consumer is `poly-inference`, which runs encrypted transformer inference
on the server (encrypted activations, public weights) and uses the streaming and
batch demo pipelines documented in the project memory. The crate is deliberately
"thin": a client needs only a key pair and tokenizer vocabulary — no model weights,
no ML framework — so it can run in browsers or on mobile.

The CKKS code is gated behind the `ckks` Cargo feature; CUDA behind `cuda`.

## Architecture

The CKKS library is layered. Note that there are **two parallel CKKS stacks**: a
legacy single-modulus stack (`poly.rs` + `params.rs` + `ciphertext.rs` +
`homomorphic.rs` + `eval_key.rs` + `encoding*.rs`) used by `CkksEncryption` for
token encrypt/decrypt, and the production multi-level RNS stack (`ntt.rs` +
`rns.rs` + `rns_ckks.rs` + `poly_eval.rs` + `rns_fhe_layer.rs` + `simd.rs`) used by
`poly-inference` for encrypted neural-net evaluation.

```
                         ┌───────────────────────────────────────────┐
   SDK / protocol        │  lib.rs  PolyClient / VerifiedResponse     │
                         │  protocol.rs  InferRequest/InferResponse   │
                         │  encryption.rs  EncryptionBackend trait    │
                         └───────────────┬───────────────────────────┘
                                         │
            ┌────────────────────────────┴──────────────────────────┐
            │  Legacy single-modulus CKKS   │   RNS multi-level CKKS  │
            │  (token encrypt/decrypt)      │   (encrypted inference) │
            ├───────────────────────────────┼─────────────────────────┤
 params     │ params.rs  N=4096, Q=2^54-33  │ ntt.rs  20 NTT primes   │
 (scheme    │            DELTA=2^20         │         (~36-bit each)  │
  constants)│                               │                         │
            ├───────────────────────────────┼─────────────────────────┤
 poly       │ poly.rs  Poly (naive O(N^2)   │ rns.rs  RnsPoly         │
 layer      │          negacyclic mul)      │   residues[prime][N],   │
            │                               │   NTT mul, CRT (Garner),│
            │                               │   drop_last_prime       │
            ├───────────────────────────────┼─────────────────────────┤
 ciphertext │ ciphertext.rs CkksCiphertext  │ rns_ckks.rs             │
 / homom.   │ keys.rs, eval_key.rs          │   RnsCiphertext (c0,c1, │
 ops        │ homomorphic.rs (add/mul/relin)│   scale, level, auth)   │
            │ encoding.rs / encoding_f64.rs │   keygen, encrypt,      │
            │ sampling.rs                   │   decrypt, add/sub/mul, │
            │                               │   relinearize, rescale, │
            │                               │   mod_switch, rotate,   │
            │                               │   matvec                │
            ├───────────────────────────────┴─────────────────────────┤
 encoding   │ simd.rs  canonical embedding (FFT) — N/2 SIMD slots      │
            ├──────────────────────────────────────────────────────────┤
 leveled    │ poly_eval.rs  Horner + Paterson-Stockmeyer poly eval     │
 circuits   │ rns_fhe_layer.rs  linear layers, Square/SiLU activations │
            │ fhe_layer.rs  (legacy single-level FHE layer)            │
            ├──────────────────────────────────────────────────────────┤
 GPU        │ gpu/engine.rs   CUDA device + twiddle tables             │
            │ gpu/gpu_rns_poly.rs  batched NTT/elementwise kernels     │
            │ (dispatched from RnsCkksContext::poly_mul)               │
            ├──────────────────────────────────────────────────────────┤
 wire       │ compress.rs  PFHE format (bincode + zstd + byte-shuffle) │
            └──────────────────────────────────────────────────────────┘
```

Key types: `RnsPoly` (RNS polynomial), `RnsCiphertext` (`c0`, `c1`, `scale: f64`,
`level`, optional HMAC `auth_tag`), `RnsEvalKey` / `RnsRotationKey` (digit-decomposed
key-switching keys), `RnsCkksContext` (NTT tables, `delta = 2^36`, optional GPU
engine). Scale stability is the central design decision: `DELTA = 2^36` is chosen to
match the ~36-bit prime size so that `scale²/q ≈ scale` after multiply+rescale,
keeping scale constant down the modulus chain.

GPU path: when the `cuda` feature is on, `RnsCkksContext::poly_mul` dispatches NTT
multiplication to `gpu_poly_mul`; all other operations stay on the CPU.

PFHE compression: `compress.rs` defines a versioned wire format (`b"PFHE"` magic)
with three lossless levels and a decompression-bomb guard, plus an `entropy_check`
that uses compression ratio as a continuous IND-CPA monitor.

## Module Reference

### `src/lib.rs`
[poly-client/src/lib.rs](poly-client/src/lib.rs) — `PolyClient<E>` SDK entry point
and `VerifiedResponse`. `prepare_request` (lines 83-102) encrypts token IDs and
builds an `InferRequest`; `process_response` (lines 111-123) decrypts and pairs
tokens with a proof; `VerifiedResponse::is_verified` (lines 155-165) re-derives the
disclosure output hash and checks it against the proof's committed `output_hash`
(the [R25-01] fix preventing proof-reuse).

### `src/encryption.rs`
[poly-client/src/encryption.rs](poly-client/src/encryption.rs) — `EncryptionBackend`
trait (lines 15-31), `MockEncryption` passthrough, and the re-export of CKKS types.

### `src/protocol.rs`
[poly-client/src/protocol.rs](poly-client/src/protocol.rs) — `Mode` enum,
`InferRequest`, `InferResponse`. `Mode::to_privacy_mode` maps SDK modes to
`poly-verified` privacy modes.

### `src/ckks/mod.rs`
[poly-client/src/ckks/mod.rs](poly-client/src/ckks/mod.rs) — module wiring and
`CkksEncryption` (the legacy single-modulus `EncryptionBackend` impl).

### `src/ckks/params.rs`
[poly-client/src/ckks/params.rs](poly-client/src/ckks/params.rs) — legacy scheme
constants: `N = 4096`, `Q = 2^54-33`, `DELTA = 2^20`, `SIGMA = 3.2`, base-T
decomposition parameters.

### `src/ckks/poly.rs`
[poly-client/src/ckks/poly.rs](poly-client/src/ckks/poly.rs) — `Poly`, the legacy
single-modulus ring element. Naive O(N²) negacyclic `mul` (lines 150-181). Manual
`Deserialize` (lines 29-41) routes untrusted input through `from_coeffs` to restore
the "exactly N coefficients" invariant ([R40-01]). `decompose_base_t` and
`mod_reduce` (centered reduction).

### `src/ckks/ntt.rs`
[poly-client/src/ckks/ntt.rs](poly-client/src/ckks/ntt.rs) — NTT-friendly primes
(`NTT_PRIMES`, 20 primes ~36-bit) and precomputed roots; `NttContext` with
`forward`/`inverse`/`mul` (Cooley-Tukey, twisted for negacyclic). `mod_pow`,
`mod_inv` (Fermat, panics on zero), `find_primitive_root`, `is_prime`.

### `src/ckks/rns.rs`
[poly-client/src/ckks/rns.rs](poly-client/src/ckks/rns.rs) — `RnsPoly` (residues per
prime). `add`/`sub`/`neg`/`scalar_mul`/`mul`, `apply_automorphism`,
`drop_last_prime` (rescaling, lines 298-332), `validate_residue_ranges` (lines
130-156). CRT reconstruction via Garner's algorithm with an i128 fast path (≤3
primes) and a wide-integer path (4+ primes).

### `src/ckks/rns_ckks.rs`
[poly-client/src/ckks/rns_ckks.rs](poly-client/src/ckks/rns_ckks.rs) — the core
RNS-CKKS scheme (~1750 lines). `RnsCiphertext` with HMAC `auth_tag`
(`compute_auth_tag`, lines 64-103). `rns_keygen`, `rns_gen_eval_key`,
`rns_encrypt_simd`/`rns_decrypt_simd*`, `rns_ct_add`/`sub`/`mul`/`mul_relin`,
`rns_relinearize` (digit-decomposed key switching), `rns_rescale`,
`rns_ct_mod_switch_to`, leveled variants, `rns_rotate`, `rns_matvec`,
`rns_sample_uniform`/`rns_sample_gaussian`.

### `src/ckks/ciphertext.rs`
[poly-client/src/ckks/ciphertext.rs](poly-client/src/ckks/ciphertext.rs) — legacy
`CkksCiphertext` (token encrypt/decrypt). HMAC auth tag, `key_id`, `nonce`.
`encrypt`/`decrypt`/`decrypt_unchecked`; `decrypt_unchecked` (lines 264-289) caps
pre-allocation by `chunks.len()` ([R40-01]).

### `src/ckks/keys.rs`
[poly-client/src/ckks/keys.rs](poly-client/src/ckks/keys.rs) — `CkksPublicKey`,
`CkksSecretKey`, `keygen`, `derive_mac_key` (HKDF-SHA256),
`secret_matches_public` (RLWE residual heuristic).

### `src/ckks/eval_key.rs`
[poly-client/src/ckks/eval_key.rs](poly-client/src/ckks/eval_key.rs) — legacy
`CkksEvalKey` and `gen_eval_key` (digit-decomposed encryption of s²·Tᵈ).

### `src/ckks/encoding.rs` / `encoding_f64.rs`
[poly-client/src/ckks/encoding.rs](poly-client/src/ckks/encoding.rs) — integer token
↔ coefficient encoding.
[poly-client/src/ckks/encoding_f64.rs](poly-client/src/ckks/encoding_f64.rs) — float
↔ coefficient encoding at a configurable scale.

### `src/ckks/simd.rs`
[poly-client/src/ckks/simd.rs](poly-client/src/ckks/simd.rs) — canonical-embedding
SIMD slot packing (N/2 slots) via radix-2 FFT; Galois-aligned `slot_permutation` so
σ₅ rotates slots by one. `encode_simd`/`decode_simd`.

### `src/ckks/homomorphic.rs`
[poly-client/src/ckks/homomorphic.rs](poly-client/src/ckks/homomorphic.rs) — legacy
single-level homomorphic ops on `CkksCiphertext`: `ct_add`/`sub`/`negate`,
`ct_mul_plain`, `ct_scalar_mul`, `ct_mul` + `relinearize`.

### `src/ckks/poly_eval.rs`
[poly-client/src/ckks/poly_eval.rs](poly-client/src/ckks/poly_eval.rs) — encrypted
polynomial evaluation: `rns_poly_eval` (Horner) and `rns_poly_eval_bsgs`
(Paterson-Stockmeyer).

### `src/ckks/fhe_layer.rs`
[poly-client/src/ckks/fhe_layer.rs](poly-client/src/ckks/fhe_layer.rs) — legacy
single-level FHE neural-net layer (`encrypted_linear`, `encrypted_quadratic_activation`).

### `src/ckks/rns_fhe_layer.rs`
[poly-client/src/ckks/rns_fhe_layer.rs](poly-client/src/ckks/rns_fhe_layer.rs) —
production RNS FHE layers. `Activation` enum (None/Square/SiLU), `SILU_COEFFS`
degree-6 minimax, `rns_linear_layer`, `rns_square_activation`, `rns_silu_activation`,
`rns_forward`/`rns_forward_encrypted`.

### `src/ckks/compress.rs`
[poly-client/src/ckks/compress.rs](poly-client/src/ckks/compress.rs) — PFHE wire
format: `compress`/`compress_with`/`decompress`, byte-shuffle filter,
`decompress_with_limit` (bomb guard), `entropy_check` IND-CPA monitor.

### `src/ckks/gpu/`
[poly-client/src/ckks/gpu/engine.rs](poly-client/src/ckks/gpu/engine.rs) —
`GpuNttEngine` (CUDA device, loaded PTX kernels, uploaded twiddle tables).
[poly-client/src/ckks/gpu/gpu_rns_poly.rs](poly-client/src/ckks/gpu/gpu_rns_poly.rs)
— `GpuRnsPoly` and batched kernel launches; `gpu_poly_mul` convenience wrapper.

## Code Review

The recent pentest-loop commits (R5–R43) have hardened the crate substantially
against malformed-ciphertext panics and added many input-validation asserts. The
findings below are issues that remain.

### Critical

**C1 — Encryption-only "128-bit security" claim is false for the parameters used by
the inference pipeline.**
[poly-client/src/ckks/rns_ckks.rs](poly-client/src/ckks/rns_ckks.rs#L194-L202)
emits a `WARNING` to stderr when `num_primes > 3` and then proceeds. The FHE
inference tests and the documented `poly-inference` demos use 4, 5, 10, and 20
primes ([poly-client/src/ckks/poly_eval.rs](poly-client/src/ckks/poly_eval.rs#L285)
uses 5, line 340 uses 10; [poly-client/src/ckks/rns_fhe_layer.rs](poly-client/src/ckks/rns_fhe_layer.rs#L759)
uses 10). With N=4096 and 20 primes, log₂(Q) ≈ 730, which is far below the
Homomorphic Encryption Standard bound for 128-bit security at N=4096 (≈109 bits of
modulus). A stderr `eprintln!` is not a safety mechanism — the library silently
operates at an insecure parameter set in its main use case. Why it matters: the
whole product promise is private inference; running CKKS below the RLWE hardness
bound undermines IND-CPA security entirely. Suggested fix: make N a function of the
modulus chain length (e.g. N=2^15 or 2^16 for 20 primes), or hard-fail (return
`Result::Err`) for parameter sets that violate the HES table rather than warning.

**C2 — Uniform sampling is not uniform: modulo bias in `rng.gen_range(0..q)` is
relied upon for RLWE security.**
[poly-client/src/ckks/rns_ckks.rs](poly-client/src/ckks/rns_ckks.rs#L1524-L1535)
(`rns_sample_uniform`) and [poly-client/src/ckks/sampling.rs](poly-client/src/ckks/sampling.rs#L9-L16)
(`sample_uniform`) both rely on `rand::Rng::gen_range`. `gen_range` itself is
unbiased, so the sampling is acceptable — *however*, `sample_uniform` then calls
`mod_reduce`, and `rns_sample_uniform` samples directly in `[0,q)`. The real concern
is the **RNG source**: `keygen` and `encrypt` in
[poly-client/src/ckks/mod.rs](poly-client/src/ckks/mod.rs#L55-L63) use
`rand::thread_rng()`. `thread_rng` is a CSPRNG (ChaCha-based) so this is acceptable,
but the public-key `a` polynomial, the encryption randomness `u`, and the Gaussian
errors are **the entire security basis** and there is no API to inject a vetted
DRBG, no test that the RNG is CSPRNG-backed, and the Gaussian sampler (next finding)
is statistically wrong. Treat as Critical because a future refactor swapping in a
non-crypto RNG would silently break security with no compile-time or test guard.
Suggested fix: take an explicit `CryptoRng + RngCore` bound on the public keygen/encrypt
APIs (the RNS layer already does — `mod.rs` does not) and add a documented invariant.

**C3 — Discrete Gaussian sampling is biased and pairs-correlated, weakening the noise
distribution.**
[poly-client/src/ckks/rns_ckks.rs](poly-client/src/ckks/rns_ckks.rs#L1537-L1555)
(`rns_sample_gaussian`) uses Box-Muller but **discards `z1`** — it only uses the
cosine component and resamples both uniforms for every coefficient. More importantly
it does `rng.gen::<f64>().max(1e-10)` and `rng.gen::<f64>()` — `gen::<f64>()`
produces values in `[0,1)`, so `u1` can be 0 (clamped to 1e-10, producing a huge
tail sample that is then rejected) and the rounding of a continuous Gaussian to the
nearest integer is **not** a discrete Gaussian — it is a rounded Gaussian, which has
a measurably different distribution (especially the modes at 0/±1). The legacy
[poly-client/src/ckks/sampling.rs](poly-client/src/ckks/sampling.rs#L35-L61)
`sample_gaussian` has the same rounded-Gaussian flaw. For CKKS the error
distribution directly determines both the noise budget *and* the security level;
RLWE security proofs assume a true discrete Gaussian (or a carefully analyzed
rounded variant). Why it matters: a non-standard error distribution invalidates the
RLWE reduction and the noise-growth analysis simultaneously. Suggested fix: use a
constant-time discrete Gaussian sampler (e.g. a cumulative-distribution-table sampler
or the convolution sampler from the FALCON/FrodoKEM literature), and use both
Box-Muller outputs.

### High

**H1 — `auth_tag` is recomputed and stripped on every homomorphic op, so integrity
is unverifiable for any computed ciphertext.**
Every homomorphic constructor in `rns_ckks.rs` sets `auth_tag: None` (e.g.
[rns_ct_add](poly-client/src/ckks/rns_ckks.rs#L734-L740),
[rns_relinearize](poly-client/src/ckks/rns_ckks.rs#L1125-L1131),
[rns_rescale](poly-client/src/ckks/rns_ckks.rs#L1191-L1197)). `rns_decrypt_simd`
([line 613](poly-client/src/ckks/rns_ckks.rs#L613)) is a thin wrapper around
`rns_decrypt_simd_unchecked` and never verifies. Only `rns_decrypt_simd_checked`
verifies, and it can only be used on a freshly authenticated ciphertext. In the
inference pipeline the server returns a *computed* ciphertext, which by construction
has `auth_tag: None`, so the client's decrypt path performs **no** integrity check —
the HMAC machinery is dead code for the actual product flow. Why it matters: a
malicious or buggy server can return arbitrary `(c0,c1)` and the client decrypts it
silently; the comment in `ciphertext.rs` claims "integrity for inference outputs is
assured by the verified-inference proof", but the RNS ciphertext is *not* bound to
that proof anywhere in this crate. Suggested fix: bind the ciphertext to the
execution proof (hash the ciphertext into the proof's `output_hash` preimage), or
document explicitly that RNS ciphertext integrity is out of scope and remove the
misleading auth-tag API from the RNS layer.

**H2 — `verify_auth` constant-time comparison is undermined by an early-return on the
`None` arm and non-constant HMAC recomputation.**
[poly-client/src/ckks/rns_ckks.rs](poly-client/src/ckks/rns_ckks.rs#L106-L119):
the tag comparison loop is constant-time, but `compute_auth_tag` iterates
`self.c0.residues` / `self.c1.residues` whose length depends on `num_primes`, so the
verification time leaks the prime count. More subtly, `verify_integrity` in
[poly-client/src/ckks/ciphertext.rs](poly-client/src/ckks/ciphertext.rs#L137-L153)
returns early (`return false`) when auth fields are missing or when `key_id`
mismatches *before* the tag comparison — an attacker can distinguish "wrong key" from
"wrong tag" by timing. Why it matters: for a MAC keyed by a secret-derived key, tag
forgery resistance assumes attackers cannot learn partial verification state via
timing. Suggested fix: always compute the full tag and compare in constant time;
fold the key-id check into the same constant-time accumulator.

**H3 — Scale tracking uses `f64`, so two ciphertexts that are semantically
incompatible can pass the `assert_eq!(a.scale, b.scale)` check or fail spuriously.**
`rns_ct_add` ([line 732](poly-client/src/ckks/rns_ckks.rs#L732)) and `rns_ct_mul`
([line 1041](poly-client/src/ckks/rns_ckks.rs#L1041)) do `assert_eq!(a.scale,
b.scale)` on `f64`. After a rescale, `scale = scale / q_last` where `q_last` is a
prime — the result is generally not exactly representable, so two independently
rescaled ciphertexts that *should* be addable can have scales differing in the last
ULP and panic; conversely, `rns_ct_add_leveled` accepts up to a 2× ratio
([line 1003](poly-client/src/ckks/rns_ckks.rs#L1003)) and silently averages, which
masks genuine level-mismatch bugs. Why it matters: CKKS correctness depends on exact
scale bookkeeping; floating-point scale is fragile and the "average the scales"
behavior in leveled-add can decrypt to wrong values without any error. Suggested fix:
track scale as an exact rational or as an integer exponent of `delta` and the dropped
primes, and make add require exact equality of that exact representation.

**H4 — GPU NTT path can produce different results from the CPU path and there is no
runtime parity check.**
`RnsCkksContext::poly_mul` ([line 234-241](poly-client/src/ckks/rns_ckks.rs#L234-L241))
dispatches to `gpu_poly_mul` and `.expect("GPU poly_mul failed")` — any GPU error
panics the whole process. The CUDA kernels (`ntt_forward_batched` etc.) are external
PTX, not reviewed here; the CPU NTT uses i128 intermediates
([ntt.rs forward/inverse](poly-client/src/ckks/ntt.rs#L207-L290)) while GPU kernels
presumably use 64-bit modular arithmetic. The only parity check is in `#[cfg(test)]`
GPU tests ([gpu/mod.rs](poly-client/src/ckks/gpu/mod.rs#L44-L68)). In production the
GPU result is trusted blindly. Why it matters: a modular-reduction bug in the kernel
(e.g. Montgomery vs. Barrett edge cases at the ~36-bit prime boundary) would silently
corrupt ciphertexts; encrypted inference would produce wrong tokens with no error.
Suggested fix: add an opt-in sampled CPU-vs-GPU cross-check in debug/canary mode, and
return `Result` from `poly_mul` instead of `.expect()`.

**H5 — `find_primitive_root` brute-force fallback can return a non-primitive root.**
[poly-client/src/ckks/ntt.rs](poly-client/src/ckks/ntt.rs#L133-L153): the fallback
checks only `psi^N == q-1`. That condition is satisfied by any element of order
exactly 2N **or** of order 2N/d for odd d — e.g. an element of order 2N/3 also
satisfies `psi^N = -1`. A non-primitive 2N-th root makes the NTT non-invertible /
incorrect. The 20 hard-coded primes are covered by the precomputed table, so this is
latent, but `find_ntt_primes` + `NttContext::new` on a custom prime would hit the
fallback. Why it matters: silent NTT corruption. Suggested fix: additionally verify
`psi^(N) == q-1` *and* `psi^(2N/p) != 1` for every prime factor p of 2N (here only
p=2), i.e. confirm the order is exactly 2N.

### Medium

**M1 — `garner_reconstruct_wide` only `debug_assert!`s that the centered CRT result
fits in `i64`.**
[poly-client/src/ckks/rns.rs](poly-client/src/ckks/rns.rs#L440-L456): in release
builds the `debug_assert!` is compiled out and the function returns `result[0] as
i64`, silently truncating the high limbs. The contract of `to_coeffs` is that the
decrypted plaintext is small enough to fit in i64, but a malformed/tampered
ciphertext (or a noise blow-up) can violate that. Why it matters: silent truncation
during decryption produces a plausible-looking wrong value rather than an error.
Suggested fix: promote to a real `assert!` or return `Result`.

**M2 — `rns_ct_scalar_mul` rejects `scalar == 0` but not the equally-destructive case
where every channel scalar reduces to 0.**
[poly-client/src/ckks/rns_ckks.rs](poly-client/src/ckks/rns_ckks.rs#L789-L792): a
non-zero `scalar` that is a multiple of a small prime is fine, but the guard's stated
purpose ("would destroy ciphertext") is only partially served. More importantly,
`RnsPoly::scalar_mul` reduces the scalar mod each prime independently — a `scalar`
that is a multiple of one of the `NTT_PRIMES` (all ~36-bit, so `scalar` would have to
be huge) zeroes only that channel, silently corrupting the RNS representation. This is
an edge case but worth a documented bound. Suggested fix: document the valid scalar
range and assert `scalar.unsigned_abs()` is well below `min(NTT_PRIMES)`.

**M3 — Legacy `decode` can underflow on negative coefficients near zero.**
[poly-client/src/ckks/encoding.rs](poly-client/src/ckks/encoding.rs#L28-L41):
`decode` does `let positive = if c < 0 { c + Q } else { c };` then
`(positive + half_delta) / DELTA` and `rounded as u32`. For a coefficient that is a
small negative number representing a value that should decode to 0 (noise around
zero), `c + Q` is near `Q`, `(Q + half_delta)/DELTA` is a huge number, and
`as u32` truncates it to garbage rather than 0. The token round-trip tests only use
exact encodings, so noise-induced negatives near 0 are untested. Why it matters: any
homomorphically-computed or noisy token ciphertext decrypts to nonsense token IDs.
Suggested fix: decode by centered reduction first, then clamp negatives to 0 before
dividing.

**M4 — `apply_automorphism` index map silently overwrites instead of asserting
bijectivity.**
[poly-client/src/ckks/rns.rs](poly-client/src/ckks/rns.rs#L263-L287): the doc comment
says `m` must be odd and coprime to 2N for the map `j → m·j mod 2N` to be a
bijection, but the code only asserts `m % 2 == 1` and `m < 2N`. An odd `m` that
shares a factor with N (impossible here since 2N is a power of two and m is odd, so
gcd is always 1) — so for N a power of two the assertion is actually sufficient. This
is *not* a bug for the current parameters, but the safety argument is implicit;
`rotation_to_galois` always yields odd `m`. Suggested fix: add a comment noting that
2N being a power of two makes "odd" equivalent to "coprime", so the check is
sufficient — currently a reader cannot tell whether the missing coprimality check is
a bug.

**M5 — Two divergent CKKS stacks with overlapping names invite misuse.**
There are two `relinearize`s, two eval-key types (`CkksEvalKey` vs `RnsEvalKey`), two
ciphertext types, two `gen_eval_key`s, and `params::DELTA = 2^20` vs
`RnsCkksContext::delta = 2^36`. `homomorphic.rs` and `fhe_layer.rs` are legacy
single-level code that the inference pipeline does not use, yet they are fully public.
Why it matters: maintainability and the risk that a caller mixes a `2^20`-scale
plaintext with a `2^36`-scale ciphertext. Suggested fix: either delete the legacy
single-modulus stack or move it behind a `legacy` feature / `pub(crate)` and document
which stack is canonical.

**M6 — `compute_auth_tag` indexes `NTT_PRIMES[ch_idx]` without bounding `ch_idx`.**
[poly-client/src/ckks/rns_ckks.rs](poly-client/src/ckks/rns_ckks.rs#L88-L101): the
loop does `NTT_PRIMES[ch_idx]` for `ch_idx` over `c0.residues` / `c1.residues`. A
deserialized `RnsCiphertext` whose `residues` vector is longer than `NTT_PRIMES.len()`
(20) panics here with an index-out-of-bounds. `verify_auth` calls `compute_auth_tag`,
so this is reachable from untrusted input. The decrypt path validates ranges, but the
auth path runs first and unguarded. Suggested fix: bound-check `ch_idx < NTT_PRIMES.len()`
and return a sentinel/`false` rather than panicking.

### Low

**L1 — Pervasive `panic!`/`assert!`/`.expect()` as the error-handling strategy.**
Almost every public CKKS function panics on bad input (`rns_decrypt_simd_unchecked`
has ~5 asserts; `rns_rotate` panics on a missing rotation key,
[line 1323](poly-client/src/ckks/rns_ckks.rs#L1323)). For a library consumed by a
network server, a panic is a DoS. The pentest commits show this is a recurring class
of bug being fixed one assert at a time. Suggested fix: introduce a `CkksError` enum
and return `Result` from all public entry points; reserve `assert!` for genuine
internal invariants.

**L2 — `lib.rs` uses `.expect()` on serialization/deserialization of attacker-shaped
data.**
[poly-client/src/lib.rs](poly-client/src/lib.rs#L91-L92) `prepare_request` does
`.expect("encryption backend produced unserializable ciphertext")` and
[line 113](poly-client/src/lib.rs#L113) `process_response` does
`serde_json::from_slice(...).expect("invalid ciphertext")` — a malformed server
response panics the client. Suggested fix: return `Result` from `process_response`.

**L3 — `rotation_to_galois` computes `g^r` with an O(r) loop.**
[poly-client/src/ckks/rns_ckks.rs](poly-client/src/ckks/rns_ckks.rs#L1208-L1224):
fine for small rotation counts, but the same `mod_pow` used elsewhere would be O(log r)
and is already available. Minor. Suggested fix: use `mod_pow` (note the modulus 2N
here is not prime, but `mod_pow` does not require primality).

**L4 — `is_prime` is trial division; `find_ntt_primes` is only correct for inputs
already known prime.**
[poly-client/src/ckks/ntt.rs](poly-client/src/ckks/ntt.rs#L360-L397): acceptable for
one-time parameter setup, but `find_ntt_primes` is `pub` and would be slow / unsafe
for large `target_bits`. Suggested fix: document it as setup-only or use a
Miller-Rabin test.

**L5 — `RnsPoly` derives `Deserialize` with public fields and no invariant
enforcement, unlike `Poly`.**
`Poly` got a hand-written `Deserialize` ([poly.rs lines 29-41]) to enforce the
length-N invariant, but `RnsPoly`
([rns.rs lines 26-33](poly-client/src/ckks/rns.rs#L26-L33)) still `#[derive]`s it.
The decrypt path calls `validate_residue_ranges` and explicit asserts, but other
entry points (e.g. `compute_auth_tag`, `RnsPoly::add`) do not, so a deserialized
`RnsPoly` with ragged inner vectors panics. Suggested fix: give `RnsPoly` the same
hand-written `Deserialize` that normalizes `residues` to `num_primes × N`.

**L6 — `entropy_check` swallows serialization errors with `unwrap_or_default()`.**
[poly-client/src/ckks/compress.rs](poly-client/src/ckks/compress.rs#L303-L318): if
`bincode::serialize` fails, `raw` is empty, `ratio` becomes 0.0, and `pass` is `true`
— a failed entropy check reports success. Suggested fix: return `Result` or treat a
serialization failure as a failed check.

## Strengths

- **Genuinely from-scratch, readable RNS-CKKS.** The modulus-chain design, the
  `DELTA = 2^36` scale-stability rationale, the digit-decomposed key switching, and
  the Garner CRT with an i128 fast path and a wide-integer slow path are all
  well-documented and the math is sound.
- **Strong test coverage.** Every module has unit tests; NTT correctness is checked
  against naive convolution, GPU results against CPU, FFT round-trips, automorphism
  round-trips, and end-to-end FHE neural-net layers including SiLU. The project
  memory reports 280+ tests for this crate.
- **Extensive hardening against malformed ciphertexts.** The R5–R43 pentest commits
  added systematic validation: NaN/Inf scale rejection on every op, `num_primes`
  consistency checks, residue-range validation at decrypt, capacity-overflow guards,
  decompression-bomb limits, and the manual `Poly::Deserialize`.
- **Thoughtful protocol-level security.** The `VerifiedResponse::is_verified`
  [R25-01] fix (binding tokens to the proof's `output_hash`) and the Cargo.toml note
  keeping the forgeable `mock` proof feature out of production builds show real
  attention to the trust model.
- **Clean GPU/CPU mirroring.** `GpuRnsPoly` exposes the same operation set as
  `RnsPoly`, dispatch is centralized in one method, and the design degrades to CPU
  when CUDA is unavailable.
- **Proper HMAC and HKDF usage.** Auth tags use real HMAC (not prefix-MAC) and MAC
  keys are derived with HKDF with domain separation — the length-extension and
  cross-context pitfalls were explicitly considered.

## Recommendations

Prioritized, actionable:

1. **Fix the security parameters (C1).** Make N scale with the modulus-chain length
   so the 5/10/20-prime configurations the inference pipeline actually uses meet the
   HES 128-bit bound, and hard-fail (not warn) on insecure parameter sets.
2. **Replace the Gaussian sampler (C3).** Use a vetted constant-time discrete
   Gaussian sampler; the current rounded-Box-Muller is both statistically incorrect
   and not constant-time. This affects security and noise analysis simultaneously.
3. **Pin the RNG contract (C2).** Require `CryptoRng` on all public keygen/encrypt
   APIs (including `CkksEncryption` in `mod.rs`) and document the invariant.
4. **Decide what RNS-ciphertext integrity means (H1).** Either bind the computed
   ciphertext to the verified-inference proof, or remove the misleading auth-tag API
   from the RNS layer so callers do not assume protection that does not exist.
5. **Make scale tracking exact (H3).** Represent scale as an integer exponent (of
   `delta` and dropped primes) instead of `f64`; require exact equality for add.
6. **Convert library panics to `Result` (L1, L2, M1).** Introduce `CkksError`; for a
   network-facing library every `assert!`/`panic!`/`.expect()` on external data is a
   DoS. Promote the release-stripped `debug_assert!` in `garner_reconstruct_wide`.
7. **Add GPU/CPU parity safety (H4).** Return `Result` from `poly_mul` instead of
   `.expect()`, and add an opt-in sampled cross-check.
8. **Harden `find_primitive_root` and auth-tag indexing (H5, M6).** Verify the root's
   order is exactly 2N; bound-check `NTT_PRIMES[ch_idx]` before indexing.
9. **Consolidate the two CKKS stacks (M5).** Remove or `pub(crate)`-scope the legacy
   single-modulus code (`poly.rs`, `homomorphic.rs`, `fhe_layer.rs`, `eval_key.rs`,
   `encoding*.rs`) and document the RNS stack as canonical.
10. **Fix `decode` underflow and `RnsPoly` deserialization (M3, L5).** Center before
    dividing in `decode`; give `RnsPoly` an invariant-enforcing `Deserialize`.
