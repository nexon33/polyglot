# poly-inference — Documentation & Code Review

## Overview

`poly-inference` is the **server-side inference crate** of the Poly Network
polyglot toolchain. It runs real LLM inference (via [Candle](https://github.com/huggingface/candle))
and pairs every generation with a cryptographic execution proof and a
per-token content-compliance proof. It connects the thin client SDK
(`poly-client`) to actual model weights, exposes an HTTP API, and ships a
client CLI plus several demo binaries.

It supports two architectures (Qwen3 and LLaMA/Nanbeige), full-precision
(safetensors) and GGUF-quantized weights, and runs on CPU or CUDA GPU
(auto-detected). Model weights are downloaded from HuggingFace Hub.

Two FHE ("encrypted inference") pipeline modes exist in the demo binaries:

- **Streaming** — token-by-token CKKS verification; each step blocks the next
  (~1.2 s/token).
- **Batch** (`--batch`) — Phase 1 collects all plaintext hidden states at GPU
  speed, Phase 2 runs batch CKKS verification.

The "encrypted inference" path is verification-oriented: a plaintext model
runs the actual generation, then the last-layer hidden state (recovered from
logits via conjugate gradient when raw hidden states are unavailable) is
projected through PCA and re-checked homomorphically under CKKS, so the
client gets a proof that the linear head was computed correctly on encrypted
data.

The production HTTP server (`main.rs --serve`) uses the
`ComplianceInferenceBackend`, which enforces a per-token content policy and
emits a `ComplianceProof` for every request.

## Architecture

```
                    ┌──────────────────────────────────────────────┐
   poly-client-cli  │  HTTP layer (http.rs, tiny_http)               │
   (client_cli.rs)  │  POST /generate            (JSON, plaintext)   │
        │           │  POST /generate/encrypted  (PFHE binary, CKKS) │
   CKKS encrypt ───▶│  POST /infer               (JSON, full proto)  │
        │           │  GET  /pubkey              (server CKKS pk)    │
        │           │  validation: size/depth/temp/path/Content-Type │
        ▼           └───────────────────┬──────────────────────────┘
   PFHE wire format                     │
   (bincode + zstd,                     ▼
    magic "PFHE")          ┌─────────────────────────────┐
                           │ InferenceBackend (server.rs) │
                           │  Mock / Real / Compliance     │
                           └──────────────┬───────────────┘
                                          │
                          ┌───────────────▼───────────────┐
                          │ inference.rs                   │
                          │  generate / generate_verified  │
                          │  generate_private(_inputs)     │
                          │  generate_compliant            │
                          │   ├─ per-token PolicyChecker    │
                          │   └─ ComplianceAccumulator (IVC)│
                          └───────────────┬───────────────┘
                                          │
                          ┌───────────────▼───────────────┐
                          │ model.rs                       │
                          │  ModelKind dispatch:            │
                          │   Qwen3Full / Qwen3Quantized    │
                          │   LlamaFull / LlamaQuantized    │
                          │  global OnceLock statics        │
                          │  forward / KV cache / tokenizer │
                          └───────────────┬───────────────┘
                                          │
                          ┌───────────────▼───────────────┐
                          │ Candle (CPU / CUDA)             │
                          └─────────────────────────────────┘

   Encrypted-inference (FHE verification) path — demo binaries:
     logits ──CG solve (W^T W)h = W^T·logits──▶ hidden state
            ──PCA projection (power iteration)──▶ low-dim vector
            ──CKKS encrypt──▶ homomorphic lm_head matvec ──▶ proof
```

**Model loading** ([model.rs](poly-inference/src/model.rs)): a `ModelSpec`
catalog (`MODELS`, [model.rs:92](poly-inference/src/model.rs#L92)) maps short
names to HF repos. `load_model_by_name` dispatches on
`(Architecture, quantized)` to four loaders, populating a set of global
`OnceLock` statics (`MODEL`, `TOKENIZER`, `DEVICE`, `EMBED_TENSOR`, etc.).

**Inference loop** ([inference.rs](poly-inference/src/inference.rs)): the
`generate_body!` macro implements prefill + autoregressive decode with a
`LogitsProcessor`. Four public entry points wrap the same body; three are
annotated with the `#[verified]` proc macro for transparent / private /
private-inputs proof modes.

**Encrypted-inference path** ([model.rs](poly-inference/src/model.rs),
demo binaries): `recover_hidden_from_logits` solves `(WᵀW)h = Wᵀ·logits` by
conjugate gradient to recover an exact hidden state from any model;
`compute_pca_projection` derives PCA directions of the lm_head weight via
power iteration with deflation; demos then CKKS-encrypt and homomorphically
re-evaluate the head.

**HTTP server/client** ([http.rs](poly-inference/src/http.rs),
[client_cli.rs](poly-inference/src/client_cli.rs)): `HttpServer` generates a
CKKS key pair on startup and serves requests sequentially. The CLI tokenizes
locally, fetches the server public key, encrypts, and round-trips.

**PFHE wire format**: the `/generate/encrypted` endpoint uses a custom binary
format (bincode + zstd, magic `b"PFHE"`) from `poly_client::ckks::compress`.
The whole body, plus nested ciphertext and public-key blobs, are PFHE blobs.

## Module Reference

### [poly-inference/src/lib.rs](poly-inference/src/lib.rs)
Crate root. Re-exports modules `compliance`, `compliance_proof`, `inference`,
`model`, `server`, `http`.

### [poly-inference/src/main.rs](poly-inference/src/main.rs)
The `poly-inference` binary. Parses a `--model` flag plus positional args; in
`--serve` mode runs `run_server` ([main.rs:271](poly-inference/src/main.rs#L271)),
otherwise runs a 7-stage demo: load → tokenize → unverified → 3 verified modes
→ proof printout. Key helpers: `time_verified`, `print_proof`, `proof_json`.

### [poly-inference/src/model.rs](poly-inference/src/model.rs)
Model abstraction and catalog. Key types: `ModelKind` (4-variant enum),
`Architecture`, `ModelSpec`, `MODELS`. Key functions: `load_model_by_name`
([L242](poly-inference/src/model.rs#L242)), `tokenize`/`decode`,
`vocab_size`, `forward_model_logits`, `recover_hidden_from_logits`
([L717](poly-inference/src/model.rs#L717)), `compute_pca_projection`
([L528](poly-inference/src/model.rs#L528)),
`logits_to_pca_hidden`, `lm_head_top_k`, `argmax_token`. Holds all global
state via `OnceLock`.

### [poly-inference/src/inference.rs](poly-inference/src/inference.rs)
Core generation. `generate_body!` macro ([L55](poly-inference/src/inference.rs#L55)),
`last_position_logits` ([L25](poly-inference/src/inference.rs#L25)),
`validate_temperature`, `validate_token_ids`,
`generate`/`generate_verified`/`generate_private`/`generate_private_inputs`,
`generate_compliant` ([L209](poly-inference/src/inference.rs#L209)).

### [poly-inference/src/server.rs](poly-inference/src/server.rs)
`InferenceBackend` trait and three implementations: `MockInferenceBackend`
(deterministic, no weights), `RealInferenceBackend`, `ComplianceInferenceBackend`
([L179](poly-inference/src/server.rs#L179)). Helper `create_proof`
([L263](poly-inference/src/server.rs#L263)) builds a `HashIvc` proof.

### [poly-inference/src/http.rs](poly-inference/src/http.rs)
HTTP transport via `tiny_http`. `HttpServer`, `handle_request` router with
path/Content-Type validation, `handle_infer`/`handle_generate`/
`handle_generate_encrypted`. Request/response types `GenerateRequest`,
`EncryptedGenerateRequest`, `ProofSummary`. Helpers: `read_body`,
`check_json_depth`, `security_headers`, `json_error`.

### [poly-inference/src/compliance.rs](poly-inference/src/compliance.rs)
Content policy. `ContentPolicy`, `PolicyChecker` (O(1) blocklist + n-gram
sliding window, [L104](poly-inference/src/compliance.rs#L104)), prompt/output
text filters `check_prompt`/`check_output_text`, and an extensive Unicode
`normalize_prompt` that strips invisible chars and folds confusables.

### [poly-inference/src/compliance_proof.rs](poly-inference/src/compliance_proof.rs)
IVC-based per-token compliance proof. `ComplianceAccumulator` folds each token
as one `HashIvc` step; `ComplianceProof::verify` ([L196](poly-inference/src/compliance_proof.rs#L196))
checks IVC validity, step-count match, policy/code-hash binding, count sanity,
and proof freshness.

### Demo binaries — group
[demo_e2e.rs](poly-inference/src/demo_e2e.rs),
[demo_fhe.rs](poly-inference/src/demo_fhe.rs),
[demo_fhe_e2e.rs](poly-inference/src/demo_fhe_e2e.rs),
[demo_rns_fhe.rs](poly-inference/src/demo_rns_fhe.rs),
[demo_rns_fhe_e2e.rs](poly-inference/src/demo_rns_fhe_e2e.rs).
Standalone `main()` binaries that exercise the full protocol and the CKKS
encrypted-inference pipeline (plaintext vs encrypted benchmarking, streaming
vs `--batch`). They are presentation/benchmark code: liberal `expect`/`unwrap`,
heavy `eprintln!` formatting, and they hardcode demo parameters.

## Code Review

### Critical

None. The network-facing surface has clearly been hardened over many "pentest
rounds" (R6–R43); the obvious crash and bypass vectors are closed.

### High

**H1 — `tiny_http` server is single-threaded; one slow request stalls all clients.**
[http.rs:196-201](poly-inference/src/http.rs#L196) — `serve()` iterates
`incoming_requests()` and handles each request inline. Inference (`generate_compliant`)
holds the global `MODEL` mutex and can take seconds to minutes per request.
A single client requesting `max_tokens = 4096` on a large model blocks every
other client for the full generation time — a trivial denial of service even
without malicious payloads. *Fix:* bound `max_tokens` far lower by default,
and/or process requests on a worker pool with a request queue and per-request
timeout. At minimum document that the server is single-tenant.

**H2 — Multiple unconditional `unwrap()` calls in the request hot path.**
In [http.rs](poly-inference/src/http.rs): `server_public_key_hex` unwraps
`serde_json::to_vec` ([L192](poly-inference/src/http.rs#L192)), `addr()`
unwraps `to_ip()` ([L218-219](poly-inference/src/http.rs#L218)), and several
response builders unwrap `serde_json::to_vec(&response)`
([L437](poly-inference/src/http.rs#L437),
[L644](poly-inference/src/http.rs#L644)). `handle_generate_encrypted` calls
`.expect("compress output ciphertext")` ([L832](poly-inference/src/http.rs#L832))
and `.expect("compress response")` ([L878](poly-inference/src/http.rs#L878)),
and `acc.finalize().expect("compliance finalize")`
([L827](poly-inference/src/http.rs#L827)). Any failure there aborts the entire
server process, not just the one request. While these particular operations
are unlikely to fail on well-formed internal data, a serialization or
compression error on attacker-influenced sizes would take down the server.
*Fix:* convert to `match`/`?` returning a 500 `json_error`, consistent with
how the JSON-parse errors are already handled.

**H3 — `generate_body!` and `generate_compliant` `.unwrap()` every Candle call.**
[inference.rs:77-105](poly-inference/src/inference.rs#L77) and
[inference.rs:242-298](poly-inference/src/inference.rs#L242) unwrap
`Tensor::new`, `model.forward`, and `logits_processor.sample`. The crate has
correctly added `validate_token_ids` to stop OOB-token panics
([inference.rs:138](poly-inference/src/inference.rs#L138)), but that only
covers one failure class. A CUDA OOM, a shape mismatch, or any other Candle
error inside the decode loop still panics the whole server. Because `serve()`
is single-threaded (H1), one panic ends the process. *Fix:* make
`generate_body!` return `Result<Vec<u32>, String>` and propagate to a 500,
or wrap inference in `std::panic::catch_unwind` at the backend boundary.

**H4 — `run_encrypted` CLI slices `output_tokens[token_ids.len()..]` unchecked.**
[client_cli.rs:204](poly-inference/src/client_cli.rs#L204) —
`model::decode(&output_tokens[token_ids.len()..])`. If the server returns
fewer output tokens than the prompt length (e.g. immediate EOS, or a
compliance block on the first token so generation returns just the prompt
minus tail), this slice panics. The server side correctly uses
`prompt_len.min(output_tokens.len())` everywhere
([http.rs:578](poly-inference/src/http.rs#L578)); the client does not. *Fix:*
apply the same `min` clamp before slicing.

### Medium

**M1 — Global `OnceLock` model state prevents reloading and is racy at init.**
[model.rs:161-180](poly-inference/src/model.rs#L161) — `MODEL`, `TOKENIZER`,
`DEVICE`, `EMBED_TENSOR` etc. are process-global `OnceLock`s.
`load_model_by_name` returns an error if a model is already loaded
([model.rs:266](poly-inference/src/model.rs#L266)), so the server can never
switch models without a restart, and tests cannot run two models in one
process. Worse, partial initialization is possible: if `DEVICE.set` succeeds
but `MODEL.set` then fails, the process is left in a half-loaded state. The
encrypted demos also reach directly into these statics
(`BASE_MODEL`, `EOS_TOKENS`, `LOADED_ARCHITECTURE`), coupling demo code to
internal state. *Fix:* encapsulate model state in a struct owned by the
backend; pass it explicitly rather than via globals.

**M2 — `get_last_hidden_state` re-mmaps and reconstructs the whole model on every call.**
[model.rs:788-812](poly-inference/src/model.rs#L788) — each invocation reads
`config.json`, mmaps the safetensors files, and builds a fresh `qwen3::Model`.
In a streaming encrypted-inference loop this is done per token, which is
extremely expensive. A cached `BASE_MODEL` already exists
([model.rs:163](poly-inference/src/model.rs#L163)) and `forward_base`
([model.rs:504](poly-inference/src/model.rs#L504)) uses it correctly — this
function should too, or be removed if superseded.

**M3 — `proof_to_summary` recomputes I/O hashes that differ from what the proof binds.**
[http.rs:895-911](poly-inference/src/http.rs#L895) hashes tokens with
`hash_data` over `to_le_bytes`, then calls `backend.verify(proof, &input_hash,
&output_hash)`. But `create_proof` ([server.rs:286](poly-inference/src/server.rs#L286))
binds `output_hash = disclosure_output_hash(output_tokens)` — a *different*
hash function — and `generate_compliant`'s proof binds yet another scheme via
the `#[verified]` macro. The `verified` field in `ProofSummary` is therefore
likely to be reported `false` for genuine proofs (it is computed with
`unwrap_or(false)`), silently degrading the audit signal. *Fix:* make the
summary use the exact same hashing the proof was finalized with, or expose the
bound hashes from the proof itself.

**M4 — `create_proof` always hashes a fixed code-hash string regardless of privacy mode.**
[server.rs:267](poly-inference/src/server.rs#L267) —
`code_hash = sha256(b"poly_inference::inference::generate_verified")` even
when `privacy` is `Private`. The `#[verified(private)]` path in
`inference.rs` is designed to *hide* the code hash; here the server-side
`create_proof` (used by `MockInferenceBackend` and `ComplianceInferenceBackend`)
ignores the mode for code-hash purposes. This is inconsistent with the privacy
contract the demos advertise and should either honour the mode or be
documented as a known mock-path simplification.

**M5 — `decrypt_unchecked` on attacker-supplied ciphertext with no integrity check.**
[http.rs:743-744](poly-inference/src/http.rs#L743) — the encrypted endpoint
decrypts the input with `decrypt_unchecked`, deliberately skipping the MAC
because the tag is the client's. That means a tampered/garbage ciphertext
decrypts to arbitrary token ids. `validate_token_ids` runs later inside the
backend so OOB ids are caught, but garbage *in-range* ids will be silently run
through the model and "verified". The comment explains *why* the MAC is
skipped but not the residual risk. *Fix:* document explicitly that the
encrypted endpoint provides confidentiality but not input integrity, or add a
client-key-based authentication step.

**M6 — `recover_hidden_from_logits` / power-iteration have no convergence reporting.**
[model.rs:717-781](poly-inference/src/model.rs#L717) runs conjugate gradient
for up to 500 iterations and [model.rs:548](poly-inference/src/model.rs#L548)
runs power iteration for a fixed 200 iterations. Both silently return whatever
they have if they fail to converge (e.g. ill-conditioned or rank-deficient
`WᵀW`). The compliance/verification claims downstream assume an *exact* hidden
state; a non-converged solve would produce a wrong proof with no error
surfaced. The PCA initial vector is also fully deterministic
([model.rs:544](poly-inference/src/model.rs#L544)), so a vector orthogonal to
the top eigenspace would never converge. *Fix:* return the final residual norm
and let callers reject non-converged results; randomize the seed vector.

**M7 — Demo-code duplication.** The five `demo_*` binaries plus `main.rs`
re-implement near-identical argument parsing, the
`Device::cuda_if_available(0).unwrap_or(Device::Cpu)` snippet
([main.rs:123](poly-inference/src/main.rs#L123),
[main.rs:278](poly-inference/src/main.rs#L278),
[demo_rns_fhe_e2e.rs:83](poly-inference/src/demo_rns_fhe_e2e.rs#L83)),
separator printing, and proof-printing helpers. ~7100 lines, a large fraction
of it copy-pasted demo scaffolding. *Fix:* extract a small `demo_common`
module (device selection, arg parsing, proof formatting) and have all demos +
`main.rs` share it.

### Low

**L1 — Default seed entropy vs. determinism claim.** `default_seed()` now uses
`rand::random()` ([http.rs:79](poly-inference/src/http.rs#L79)) — a good
security fix — but `main.rs` still prints "all 4 runs produce identical
tokens" ([main.rs:194](poly-inference/src/main.rs#L194)) using a fixed seed of
42 from CLI args. The two paths are consistent internally but the determinism
narrative should note it depends on an explicit seed.

**L2 — `MAX_PROOF_AGE_SECS` rejects legitimately old proofs and `created_at==0` bypasses it.**
[compliance_proof.rs:255](poly-inference/src/compliance_proof.rs#L255) — a
proof with `created_at == 0` is treated as "legacy" and skips the freshness
check entirely. An attacker who can construct a proof can simply set
`created_at = 0` to make a stale proof pass. Since `ComplianceProof` is a
plain `pub` struct with public fields and no enforced constructor, this is a
real bypass of the replay protection. *Fix:* drop the `created_at == 0`
exemption, or require a signed/committed timestamp.

**L3 — `vocab_size()` vs. embedding matrix size mismatch risk.**
[model.rs:230](poly-inference/src/model.rs#L230) documents that the embedding
matrix is "typically padded *up*" from the tokenizer vocab, so
`id < vocab_size()` is a safe bound. For quantized models loaded via GGUF this
assumption is not verified against the actual tensor shape; if a model ever
had a *smaller* embedding table than the tokenizer vocab, `validate_token_ids`
would pass an OOB id. *Fix:* derive the bound from `EMBED_TENSOR.dim(0)` when
available rather than the tokenizer.

**L4 — `handle_one()` / `last_compliance_proof()` TOCTOU.** Already documented
in [server.rs:179-182](poly-inference/src/server.rs#L179): the `last_proof`
single-slot mutex can return another request's proof under concurrent access.
Acceptable today because `serve()` is sequential, but it is a latent bug if
H1 is fixed with concurrency. *Fix:* key proofs by request id.

**L5 — `check_json_depth` does not bound total token/array element count.**
[http.rs:989](poly-inference/src/http.rs#L989) bounds nesting depth but a flat
1 MB JSON array of numbers still allocates a large `Vec` in serde. The 1 MB
body cap limits the blast radius, so this is minor, but a huge `tokens`/array
field is still cheaper for the attacker than for the server.

**L6 — `Tokenizer::from_file` / HF download failures are fatal `expect` in `main.rs`.**
[main.rs:125](poly-inference/src/main.rs#L125) `.expect("failed to load model")`
— a transient network failure to HuggingFace kills the server at startup with
a bare panic. Acceptable for a demo binary but worth a friendlier message and
exit code for the `--serve` path.

## Strengths

- **Network surface is genuinely hardened.** The HTTP layer has thorough,
  well-commented defenses: body-size cap, JSON depth limit, path-traversal and
  double-encoding rejection, Content-Type enforcement, a full suite of
  security headers, generic error messages that avoid leaking which filter
  matched, and pre/post compliance checks on every endpoint.
- **Defense-in-depth compliance.** Per-token policy enforcement *during*
  generation, plus a post-generation text-level backstop that explicitly
  addresses n-gram evasion via punctuation interleaving, plus an IVC proof
  binding the exact policy version into `code_hash`.
- **Crash-resilience improvements are deliberate and documented.** Poisoned
  mutexes are recovered (`unwrap_or_else(|e| e.into_inner())`), saturating
  arithmetic prevents overflow panics, `last_position_logits` returns `Result`
  instead of panicking on unexpected rank, and `validate_token_ids` closes the
  OOB-embedding crash.
- **Clean architecture for the model layer.** `ModelKind` cleanly abstracts
  four architecture/quantization combinations behind one `forward` interface;
  the `ModelSpec` catalog is a tidy data-driven design.
- **`ComplianceProof::verify` is carefully reasoned** — the R36 fix rejecting
  non-`Transparent` IVC proofs (which would skip output-hash binding) shows
  real attention to proof-soundness corner cases, and `all_compliant()`
  carries an explicit warning never to trust it without `verify()`.
- **Strong test coverage** — 18 test files including many dedicated pentest
  regression suites.

## Recommendations

Prioritized, actionable:

1. **Make inference panic-safe (H2, H3).** Convert `generate_body!` and
   `generate_compliant` to return `Result`, and replace hot-path `unwrap()`/
   `expect()` in `http.rs` with 500 responses. This is the single biggest
   robustness gap: today any Candle error crashes the whole process.
2. **Address the single-threaded DoS (H1).** Lower the default `max_tokens`,
   add a per-request wall-clock timeout, and move inference onto a bounded
   worker pool with a request queue. Document the server's tenancy model.
3. **Fix the client-side unchecked slice (H4).** One-line `min` clamp in
   `client_cli.rs::run_encrypted`.
4. **Reconcile proof I/O hashing (M3, M4).** Ensure `proof_to_summary` uses the
   same hash scheme the proof was finalized with so `verified` is meaningful,
   and make `create_proof` honour the privacy mode for `code_hash`.
5. **Encapsulate model state (M1, M2).** Replace global `OnceLock`s with a
   backend-owned struct; fix `get_last_hidden_state` to reuse `BASE_MODEL`.
6. **Harden the verification math (M6).** Have `recover_hidden_from_logits`
   and `compute_pca_projection` report residual/convergence and let callers
   reject non-converged solves; randomize the power-iteration seed vector.
7. **Close the `created_at == 0` replay exemption (L2).**
8. **Deduplicate demo scaffolding (M7).** Extract a shared `demo_common`
   module for device selection, arg parsing, and proof formatting.
9. **Document the encrypted endpoint's integrity model (M5).** State clearly
   that `/generate/encrypted` provides confidentiality but not input
   integrity, given `decrypt_unchecked`.
