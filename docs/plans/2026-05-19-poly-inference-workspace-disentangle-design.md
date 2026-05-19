# Verified + Encrypted Inference — Disentangled Workspace

**Date:** 2026-05-19
**Destination:** `C:\Users\adria\Documents\Claude\Projects\poly`
**Goal:** Extract the verified + encrypted inference code from the `polyglot`
monorepo into a self-contained, buildable Cargo workspace with clear crate and
module boundaries — a clean base for further refactoring of this alpha code.

## Problem

The inference code is tangled across the `polyglot` monorepo in three ways:

1. **`poly-client`** mixes a pure CKKS/FHE crypto library (`ckks/`, ~9.9K
   lines) with thin-client SDK code (`encryption.rs`, `protocol.rs`).
2. **`polyglot-macros`** buries the one inference-relevant macro
   (`#[verified]`) among 10 unrelated language-bridge macros, and drags in the
   entire `polyglot-runtime` crate as a dependency.
3. **`poly-inference`** has the HTTP server, model loading, the inference
   loop, content-compliance filtering, the CLI, and demo binaries all flat in
   one `src/`.

## Target structure — 5 crates, acyclic dependency graph

```
poly/
  Cargo.toml                 # workspace
  README.md                  # structure map + build/test instructions
  crates/
    poly-fhe/                # CKKS homomorphic encryption (pure crypto, leaf)
    poly-proof/              # verified computation: IVC + disclosure/redaction (leaf)
    poly-proof-macros/       # the #[verified] proc macro
    poly-protocol/           # thin-client protocol + encryption-backend trait
    poly-inference/          # HTTP server, model, inference, compliance, CLI, demos
```

Dependency DAG (verified acyclic):

```
poly-fhe            (leaf — confirmed: ckks/ has zero poly-verified usage)
poly-proof          (leaf)
poly-proof-macros   -> poly-proof
poly-protocol       -> poly-fhe, poly-proof
poly-inference      -> poly-fhe, poly-proof, poly-proof-macros, poly-protocol
```

## Crate mapping

| New crate | Source | Notes |
|---|---|---|
| `poly-fhe` | `poly-client/src/ckks/**` | `ckks/`'s 20 flat files regrouped into `core/` (params, sampling, poly, keys, ciphertext, encoding), `rns/` (rns, ntt, rns_ckks, encoding_f64), `homomorphic/` (homomorphic, eval_key, poly_eval, fhe_layer, rns_fhe_layer, simd), `wire/` (compress), `gpu/`. |
| `poly-proof` | `poly-verified/**` | Already organized (`crypto/`, `ivc/`); group `disclosure`, `verified_type`, `types`, `step` under `core/`. Keep the `mock` feature. |
| `poly-proof-macros` | `polyglot-macros/src/verified_macro.rs` + the `#[verified]` export from `lib.rs` | Drops `polyglot-runtime` dep and the 10 unrelated macros. Deps: `proc-macro2`, `quote`, `syn` only. Generated code's `poly_verified::` paths rewritten to `poly_proof::`. |
| `poly-protocol` | `poly-client/src/{encryption.rs, protocol.rs, lib.rs}` | The thin-client protocol types and the `EncryptionBackend` trait. |
| `poly-inference` | `poly-inference/**` | Flat `src/` regrouped: `compliance/` (compliance + compliance_proof), `bin/` (server, client, demos). Other modules keep their names. |

## What is dropped

- `polyglot-runtime` dependency (eliminated entirely).
- The 10 non-inference macros: `bridge`, `py`, `js`, `ts`, `sql`, `gpu`,
  `pure`, `fold`, `capture` macros.
- Anything in the monorepo not reachable from the inference path.

## Crate-rename rewrites

- `poly_client::ckks::*` -> `poly_fhe::*`
- `poly_client::{encryption,protocol}::*` -> `poly_protocol::*`
- `poly_verified::*` -> `poly_proof::*`
- `polyglot_macros::verified` -> `poly_proof_macros::verified`

## Verification bar

The disentangling must provably not change behavior:

1. Each crate `cargo build` clean.
2. Each crate `cargo test` green, **pass counts matching the originals**.
3. Full-workspace `cargo test` green.
4. crates.io dependencies (candle, tokenizers, hf-hub, ed25519-dalek, …)
   carry over unchanged. `cuda`/`gpu` features preserved but off by default.

## Out of scope (documented follow-up)

This effort disentangles **crate and module boundaries**. It does **not**
rewrite tangled module internals — e.g. the 2,240-line `rns_ckks.rs`, the
1,454-line `compliance.rs`. Those are deeper refactors to be planned
separately once the boundaries are clean.
