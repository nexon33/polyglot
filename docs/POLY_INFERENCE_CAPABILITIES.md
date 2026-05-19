# poly-inference — Capabilities

`poly-inference` is the **server side** of the verified-inference protocol. It
connects the thin client (`poly-client`) to real model inference, produces
cryptographic execution proofs, and enforces a content-compliance policy on
every generated token.

This document describes *what the crate can do*. For the client SDK see
[POLY_CLIENT_CAPABILITIES.md](POLY_CLIENT_CAPABILITIES.md).

---

## 1. HTTP API

The server (`http::HttpServer`, built on `tiny_http`) exposes four routes:

| Route | Purpose |
|-------|---------|
| `GET  /pubkey` | Returns the server's CKKS public key (hex JSON) |
| `POST /infer` | Full protocol — encrypted input, proof, encrypted output |
| `POST /generate` | Simple batch — prompt in, text + proof out |
| `POST /generate/encrypted` | End-to-end encrypted batch — CKKS tokens in/out |

### `/generate` privacy modes

- `transparent` (default) — verifier sees input/output/code hashes.
- `private` — full zero-knowledge: verifier learns only proof validity.
- `private_inputs` — selective disclosure: output visible, inputs hidden.

### `/generate/encrypted` flow

1. Client encrypts token IDs with the server's CKKS public key.
2. Server decrypts, runs inference, **re-encrypts** the output with the
   *client's* public key.
3. The proof is always zero-knowledge.
4. Plaintext tokens never appear in the HTTP request or response — the body is
   raw PFHE-compressed binary (`application/x-pfhe`).

## 2. Inference backends (`server::InferenceBackend`)

A single trait, three implementations:

| Backend | Description |
|---------|-------------|
| `MockInferenceBackend` | Deterministic output, **real** HashIvc proofs, no weights — for protocol testing |
| `RealInferenceBackend` | Actual model inference via Candle |
| `ComplianceInferenceBackend` | Real model **plus** per-token compliance enforcement |

## 3. Models

`model.rs` loads and tokenizes:

- **Qwen3-0.6B** — full-precision (safetensors).
- **LLaMA / Nanbeige** family — including quantized GGUF (e.g. Nanbeige4.1-3B
  Q4_K_M).
- GPU acceleration via CUDA (feature `cuda`); CPU fallback otherwise.

## 4. Verified generation (`inference.rs`)

Generation is wrapped by the `#[verified]` macro, which builds an
**Incrementally Verifiable Computation (IVC)** hash chain as tokens are
produced. The result is a `VerifiedProof` (`HashIvc`) carrying:

- a chain tip and Merkle root over the step witnesses,
- a `code_hash` identifying the inference function,
- `input_hash` / `output_hash` binding the proof to specific I/O,
- a privacy mode and optional blinding commitment.

Three generation paths exist — `generate_verified` (transparent),
`generate_private_inputs`, and `generate_private` — selected by request mode.

## 5. Compliance enforcement

Every token emitted by `generate_compliant` is checked against a
deterministic, hashable `ContentPolicy`:

- **Blocked token IDs** — O(1) blocklist.
- **Blocked n-grams** — forbidden token sequences (harmful terms tokenized at
  startup via `init_runtime_policy`).
- **Sequence-length limit**.

The check runs twice — once in the client-mirrored `ComplianceAccumulator`
(which builds a tamper-evident IVC compliance proof) and once in an
independent server-side `PolicyChecker` ("belt and suspenders"). If a token
violates the policy, generation halts and the proof records the violation.

The n-gram gate is given a bounded suffix of the prompt as context so a
forbidden term that **straddles the prompt/completion boundary** is still
detected (pentest round 47; see `tests/r47_pentest_attack_tests.rs`).

### Text-level safety filters (`compliance.rs`)

- `check_prompt` — pre-inference gate rejecting known jailbreak and
  harmful-request patterns. Applies Unicode normalization (zero-width strip,
  homoglyph/confusable folding, fullwidth → ASCII, interleaved-punctuation
  stripping) to defeat evasion.
- `check_output_text` — post-generation backstop scanning decoded output for
  harmful terms that token-level n-gram matching might miss.

## 6. Compliance & execution proofs

Each response carries two summaries:

- **`ProofSummary`** — the execution proof, with `input_hash`/`output_hash` for
  I/O binding. Clients should call `verify_proof_io_binding` to confirm the
  proof actually describes the output they decrypted.
- **`ComplianceSummary`** — total/compliant token counts, policy version and
  hash, and the compliance IVC chain tip/root.

## 7. Hardening

The HTTP layer has been hardened across an ongoing series of pentest rounds —
body-size caps, JSON depth limits, path-traversal rejection, Content-Type
validation, a full set of security headers, generic error messages,
ciphertext chunk-count bounds, and rejection of degenerate client public keys.
Each round is recorded as a `tests/rNN_pentest_attack_tests.rs` regression
suite and a `fix: pentest round NN` commit. See
[SECURITY_REPORT.md](SECURITY_REPORT.md) for the overall security posture.
