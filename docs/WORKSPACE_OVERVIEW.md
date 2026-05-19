# pyrs polyglot — Workspace Overview & Review Index

This document is the top-level map of the `pyrs polyglot` Rust workspace. It links the
per-crate documentation + code review files and consolidates the highest-severity
findings across all crates.

Each crate folder contains its own `CODE_REVIEW.md` with full documentation
(overview, architecture diagram, module-by-module reference) and a severity-ranked
code review.

## Workspace Layout

The workspace has 10 members (see [Cargo.toml](../Cargo.toml)):

```
pyrs/
├── src/                  polyglot      — core compiler + CLI (.poly → wasm/native/apk)
├── gridmesh/             gridmesh      — cross-language tensor handle
├── poly-lsp/             poly-lsp      — Language Server Protocol implementation
├── polyglot-macros/      polyglot-macros   — proc macros (#[verified], py!/js!/ts!, …)
├── polyglot-runtime/     polyglot-runtime  — runtime for embedded JS/TS/Python
├── poly-verified/        poly-verified — verified execution / IVC + crypto proofs
├── poly-chain/           poly-chain    — verify-only blockchain / ledger
├── poly-client/          poly-client   — CKKS homomorphic encryption library + SDK
├── poly-inference/       poly-inference— LLM inference server with FHE verification
└── poly-node/            poly-node     — decentralized compute-network node (QUIC)
```

## Dependency / Data Flow

```
              .poly source
                   │
            ┌──────▼───────┐      ┌──────────────────┐
            │  polyglot    │─uses─│  gridmesh        │
            │  (compiler)  │      └──────────────────┘
            └──────┬───────┘
                   │ emits wasm / native / apk
   editors ───▶ poly-lsp (LSP intelligence for .poly)

   #[verified] / py! / js! / ts!
            │
   polyglot-macros ──expands to──▶ polyglot-runtime  (embedded JS/TS/Python)
            │
            └──expands to──▶ poly-verified  (IVC accumulator, Verified<T>)
                                   │
                                   ▼
                               poly-chain  (verifies VerifiedProof, applies state)

   poly-client (CKKS FHE) ──▶ poly-inference (encrypted LLM inference + HTTP server)
                                   │
                                   ▼
                               poly-node  (QUIC node serving inference on a P2P network)
```

## Per-Crate Reviews

| Crate | Lines | Documentation & Review |
|-------|------:|------------------------|
| polyglot (core compiler) | ~16.7k | [CODE_REVIEW.md](../CODE_REVIEW.md) |
| gridmesh | ~0.3k | [gridmesh/CODE_REVIEW.md](../gridmesh/CODE_REVIEW.md) |
| poly-lsp | ~3.9k | [poly-lsp/CODE_REVIEW.md](../poly-lsp/CODE_REVIEW.md) |
| polyglot-macros | ~1.0k | [polyglot-macros/CODE_REVIEW.md](../polyglot-macros/CODE_REVIEW.md) |
| polyglot-runtime | ~1.1k | [polyglot-runtime/CODE_REVIEW.md](../polyglot-runtime/CODE_REVIEW.md) |
| poly-verified | ~4.1k | [poly-verified/CODE_REVIEW.md](../poly-verified/CODE_REVIEW.md) |
| poly-chain | ~6.4k | [poly-chain/CODE_REVIEW.md](../poly-chain/CODE_REVIEW.md) |
| poly-client | ~9.9k | [poly-client/CODE_REVIEW.md](../poly-client/CODE_REVIEW.md) |
| poly-inference | ~7.1k | [poly-inference/CODE_REVIEW.md](../poly-inference/CODE_REVIEW.md) |
| poly-node | ~2.6k | [poly-node/CODE_REVIEW.md](../poly-node/CODE_REVIEW.md) |

## Consolidated Critical / High Findings

These are the headline issues surfaced per crate. See each crate's `CODE_REVIEW.md`
for the full severity-ranked list, locations, and suggested fixes.

### polyglot — core compiler
- **Critical** — Regex-literal heuristic in [src/parser.rs:113](../src/parser.rs#L113) treats `/` after `= ( , : [` as a JS regex start, silently swallowing Rust/Python division and even closing braces.
- **Critical** — APK builder is Windows-only and ships a hardcoded "LoRaChat" app unrelated to the user's program ([src/apk_builder.rs](../src/apk_builder.rs)).
- **High** — Stubbed cross-language calls compile to fake `println!` stubs; `link_modules` drops all but the first module — both produce silently-wrong binaries instead of failing loudly.

### gridmesh
- **Critical** — `wasm_free` is a no-op stub: every `Tensor::zeros` permanently leaks all three heap allocations.
- **Critical** — `TensorRefMut::as_mut_slice` derives `&mut [T]` provenance through a shared `&TensorHeader` — latent aliasing UB.
- **High** — Release-mode `unborrow` does a blind `fetch_sub`; underflow on a free header fabricates an exclusive borrow.

### poly-lsp
- **High** — Unbounded `Content-Length` allocation in [json_rpc.rs:30](../poly-lsp/src/json_rpc.rs#L30): a malformed child frame can OOM/abort the process.
- **High** — Panic-prone Tree-sitter scan: positional `m.captures[2]` indexing + pervasive `unwrap()` in `type_graph.rs`.
- **High** — UTF-16/byte column confusion: `goto_definition`/`references` byte-slice strings with character columns, panicking on non-ASCII content.

### polyglot-macros
- **Critical** — Generated `#[verified]`/`fold!` code uses `sha2`, which is not a crate dependency: consumers without `sha2` fail to compile.
- **Critical** — Input/output hashing via `format!("{:?}", x)` is unsound (lossy floats, non-deterministic `HashMap` ordering), undermining the proof guarantee.
- **High** — Attribute args parsed by raw `.contains("mock"/"private")` substring matching, causing silent misbehaviour.

### polyglot-runtime
- **Critical** — The `js!` macro emits `JsRuntime::eval` and `marshal::FromJs`, neither of which exist — any `js!` use is a hard compile break.
- **High** — JS/TS runtimes build a fresh `Context` per call: define-then-call snippets silently lose all state.
- **High** — `ForeignHandle::call_method` ignores the receiver, swallows errors to `Null`, and force-stringifies results.

### poly-verified
- **High** — `verify_disclosure`/`verify_composition` pass a proof's own I/O hashes back as the "expected" values, making I/O binding a tautology (proof splicing).
- **High** — A fully-private (empty-indices) disclosure is self-certifying — nothing binds its tokens.
- **Medium** — `VerifiedResponse` offers no helper that binds the embedded proof to the transported value.

### poly-chain
- **Critical** — No on-chain balance enforcement: `validate_cash_transfer` discards the computed debit and fabricates wallet commitment hashes; no balance check, fee collection, or value-level double-spend protection.
- **Critical** — The `mock` feature disables all proof/signature verification; Cargo feature unification means any consumer enabling `poly-chain/mock` silently disables ledger integrity workspace-wide.
- **Critical** — STP slash deadline is derived from `pool_threshold_reached` instead of stored `frozen_at`, allowing slashing before the 30-day frozen window elapses.

### poly-client — CKKS FHE
- **Critical** — Insecure parameters: the library only warns to stderr then proceeds above 3 primes, yet the inference pipeline routinely uses 5/10/20 primes at N=4096 — far below the 128-bit HE Standard bound.
- **Critical** — Broken Gaussian sampler: `rns_sample_gaussian` uses rounded Box-Muller (not a discrete Gaussian, not constant-time), invalidating the RLWE security reduction and noise-budget analysis.
- **High** — Ciphertext integrity is dead code for computed results: homomorphic ops set `auth_tag: None` and the default decrypt path never verifies.

### poly-inference
- **High** — Single-threaded server: `serve()` handles requests inline holding the global model mutex; one slow `max_tokens=4096` request stalls all clients. `generate_body!` `.unwrap()`s every Candle call — any error panics the whole process.
- **High** — Hot-path `unwrap()`/`expect()` in [http.rs:832](../poly-inference/src/http.rs#L832) / [L878](../poly-inference/src/http.rs#L878): response serialization / PFHE compression aborts crash the server instead of returning 500.
- **High** — `client_cli.rs:204` slices `output_tokens[token_ids.len()..]` without clamping (panics on short output); `proof_to_summary` hashes I/O differently from `create_proof`, so the reported `verified` flag is likely wrong.

### poly-node
- **High** — `handle_connection` detaches spawned stream tasks and releases its connection-semaphore permit before they finish — the semaphore counts accept-loops, not in-flight work.
- **High** — `Frame::encode`'s `u32::MAX` `assert!` panic is reachable on the hot response path; `try_encode` should be used.
- **Medium** — No inference replay protection: a captured `InferRequest` replays indefinitely.

## Cross-Cutting Themes

1. **"Mock" / stub paths leak into production builds** — `poly-chain`'s `mock` feature, the compiler's stubbed cross-language calls, and `gridmesh`'s no-op `wasm_free` all silently degrade correctness instead of failing loudly. Stubs should `panic!`/`compile_error!`/return `Err` rather than fake success.
2. **Soundness of the "verified" story has gaps at the seams** — `polyglot-macros` hashes via `Debug`, `poly-verified` makes I/O binding a tautology, `poly-chain` delegates all value soundness off-chain, and `poly-client` leaves computed ciphertexts unauthenticated. The end-to-end proof chain is weaker than any single crate suggests.
3. **Cryptographic parameter / primitive quality** — `poly-client` ships insecure FHE parameters and a non-discrete Gaussian sampler; these undermine the security claims of the whole encrypted-inference product.
4. **Panic-on-untrusted-input on hot paths** — `poly-lsp`, `poly-inference`, and `poly-node` each have reachable `unwrap()`/`assert!`/unbounded-allocation paths driven by network or editor input. Pentest rounds have hardened many, but server hot paths still abort the process.

## Suggested Triage Order

1. Fix the soundness tautologies and unauthenticated-ciphertext gaps (`poly-verified`, `poly-client`, `polyglot-macros`) — they invalidate the core product claim.
2. Gate or remove `mock`/stub code paths so they cannot reach production (`poly-chain`, compiler stubs, `gridmesh::wasm_free`).
3. Harden the FHE parameters and sampler in `poly-client`.
4. Make server hot paths panic-free (`poly-inference`, `poly-node`, `poly-lsp`).
5. Address the compiler regex-parser corruption — it can miscompile ordinary code.
