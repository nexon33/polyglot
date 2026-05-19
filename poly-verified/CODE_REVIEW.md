# poly-verified — Documentation & Code Review

## Overview

`poly-verified` is the verified-execution runtime for the Poly programming
language. It implements **Incrementally Verifiable Computation (IVC)**: a
computation is decomposed into discrete steps, each step's witness is folded
into a running accumulator, and at function exit the accumulator is finalized
into a constant-size cryptographic proof. The proof certifies that the result
was computed by a specific piece of code, executing a specific sequence of
steps, on specific (or hidden) inputs — and it can be checked by any receiver
in milliseconds without re-executing the computation.

The crate's central type is **`Verified<T>`** ([poly-verified/src/verified_type.rs](poly-verified/src/verified_type.rs)):
a value `T` paired with a `VerifiedProof`. It is the load-bearing trust
boundary of the system. Key design properties:

- The honest constructor `new_proven` is `pub(crate)`; only the proof system
  can mint `Verified<T>` values internally.
- `__macro_new` is `#[doc(hidden)]` but `pub`, because the `#[verified]` proc
  macro (in the separate `polyglot-macros` crate) expands in the caller's
  crate and must call it. It rejects `Mock` proofs in production builds
  (`not(feature = "mock")` and `not(test)`).
- `Verified<T>` deliberately does **not** implement `Deserialize` — that would
  let an attacker pair arbitrary data with a stolen proof. Transport is meant
  to go through `proof_serialize::VerifiedResponse` with re-validation.

How it is consumed: a user marks a function `#[verified]`; the macro expands
to drive an `IvcBackend` (`HashIvc` in production, `MockIvc` in tests),
producing a `Verified<T>`. Downstream code can `map`, `flatten`, inspect the
privacy mode, create selective `Disclosure`s over `Verified<Vec<u32>>` token
outputs, or serialize for transport. The MEMORY notes 163 tests including a
42-test adversarial/pentest suite; many `[Vnn-xx FIX]` / `[Rnn-xx FIX]`
comments throughout the source mark previously-patched attack findings.

## Architecture

### IVC accumulator lifecycle

The `IvcBackend` trait ([poly-verified/src/ivc/mod.rs:13](poly-verified/src/ivc/mod.rs)) defines four phases:

1. `init(code_hash, privacy)` → fresh `Accumulator`.
2. `fold_step(&mut acc, witness)` → one `StepWitness` (`state_before`,
   `state_after`, `step_inputs`) absorbed per computation step.
3. `finalize(acc)` → constant-size `VerifiedProof`.
4. `verify(proof, input_hash, output_hash)` → re-derives all commitments and
   checks them.

`HashIvc` ([poly-verified/src/ivc/hash_ivc.rs](poly-verified/src/ivc/hash_ivc.rs)) is the production,
quantum-resistant backend (hash security only). Each step's transition hash
`H(0x01 ‖ prev ‖ inputs ‖ claimed)` is appended to a domain-separated SHA-256
**hash chain** (order-dependent tamper evidence) and pushed into a
`checkpoints` vector. At `finalize`, a **Merkle tree** is built over the
checkpoints, and `code_hash` + `privacy_mode` are bound into the chain tip
(`bound_tip = combine(combine(tip, H(code_hash)), H(privacy_mode))`) so they
cannot be swapped post hoc. In private modes a per-step blinding factor
(`hash_blinding`, domain `0x04`) is folded into a `blinding_commitment`.

`verify` reconstructs the chain and Merkle tree from `checkpoints`, recomputes
the bound tip, checks the root, performs privacy-aware I/O hash comparison,
and recomputes the blinding commitment — all using the constant-time
`hash_eq`.

### Proof composition and serialization

`CompositeProof` ([poly-verified/src/proof_composition.rs](poly-verified/src/proof_composition.rs)) handles nested
`#[verified]` calls: an outer proof plus a vector of inner proofs, bound by a
`composition_hash` over the JSON-serialized proofs and the effective (most
restrictive) privacy mode. `verify_composition` re-runs the **full** `HashIvc`
verifier on every contained proof, not just structural checks.

`VerifiedResponse` ([poly-verified/src/proof_serialize.rs](poly-verified/src/proof_serialize.rs)) is the wire
format for transmitting a value+proof. It zeroes hidden fields by privacy
mode, caps `proof_len` at 16 MiB, and offers `validate_proof_bytes` /
`validate_header_consistency` to detect header tampering.

### Crypto primitives

- **hash** ([poly-verified/src/crypto/hash.rs](poly-verified/src/crypto/hash.rs)): SHA-256 with one-byte
  domain-separation tags — `0x00` leaf, `0x01` transition, `0x02` chain step,
  `0x03` Merkle interior, `0x04` blinding.
- **merkle** ([poly-verified/src/crypto/merkle.rs](poly-verified/src/crypto/merkle.rs)): binary tree with
  odd-element duplication; `verify_proof` (path only) and `verify_proof_strict`
  (also binds `leaf_index` to the `is_left` flag sequence, depth-capped at 64).
- **chain** ([poly-verified/src/crypto/chain.rs](poly-verified/src/crypto/chain.rs)): sequential hash chain
  with overflow-checked length.
- **commitment** ([poly-verified/src/crypto/commitment.rs](poly-verified/src/crypto/commitment.rs)): builds a
  `Commitment` (Merkle root + chain tip + code hash) and Ed25519-signs it.
- **signing** ([poly-verified/src/crypto/signing.rs](poly-verified/src/crypto/signing.rs)): `CodeAttestation`
  Ed25519 signing/verification, code integrity check.

```text
  #[verified] fn  ──>  IvcBackend::init(code_hash, privacy)
                              │
                              ▼
                       ┌─────────────┐   per computation step
        StepWitness ──▶│  fold_step  │◀── (state_before, inputs, state_after)
        (×N)           └─────┬───────┘
                             │  transition = H(0x01‖prev‖in‖claimed)
                             ▼
              HashChain.append(transition)   checkpoints.push(transition)
              (tip = H(0x02‖tip‖t))          [+ blinding fold if private]
                             │
                             ▼
                       ┌─────────────┐
                       │  finalize   │  MerkleTree::build(checkpoints)
                       └─────┬───────┘  bound_tip = combine(combine(tip,
                             │                       H(code)), H(mode))
                             ▼
                  VerifiedProof::HashIvc { chain_tip, merkle_root,
                       step_count, checkpoints, code_hash,
                       privacy_mode, blinding_commitment, in/out_hash }
                             │
            ┌────────────────┼─────────────────┐
            ▼                ▼                 ▼
      Verified<T>      VerifiedResponse    CompositeProof
      (value+proof)    (wire format)      (nested proofs)
            │                │                 │
            ▼                ▼                 ▼
   Disclosure over    from_bytes +       verify_composition →
   Verified<Vec<u32>> validate_*()       HashIvc.verify(each)
            │
            ▼
     IvcBackend::verify  ── rebuild chain + Merkle tree, recompute
                            bound_tip, blinding; constant-time hash_eq
```

## Module Reference

### `lib.rs` — [poly-verified/src/lib.rs](poly-verified/src/lib.rs)
Crate root and module declarations. Exposes a `prelude` re-exporting the
common surface (`Verified`, `VerifiedProof`, `HashIvc`, `MockIvc`,
`IvcBackend`, `FixedPoint`, disclosure API, `VerifiedError`).

### `error.rs` — [poly-verified/src/error.rs](poly-verified/src/error.rs)
`ProofSystemError` — internal proof-system failures (`InvalidProof`,
`MerkleVerificationFailed`, `SignatureVerificationFailed`, `InvalidEncoding`,
`IndexOutOfBounds`, etc.) and `Result<T>` alias. `VerifiedError` — user-facing
"proven errors" (`DivisionByZero`, `Overflow`, `BoundExceeded`,
`AssertionFailed`, `InvalidInput`, `GpuMismatch`); `Serialize`/`Deserialize`
so they can travel inside `Verified<Result<T, VerifiedError>>`.

### `types.rs` — [poly-verified/src/types.rs](poly-verified/src/types.rs)
Core wire types: `Hash` (`[u8;32]`), `ZERO_HASH`, the constant-time
`hash_eq` ([poly-verified/src/types.rs:32](poly-verified/src/types.rs)), `Commitment`,
`SignedCommitment`, `ProofNode`, `MerkleProof`, `CodeAttestation`, `BackendId`,
`PrivacyMode`, `VerifiedProof` enum, `StepWitness`. All fixed-size structs
have strict `from_bytes` parsers (`!= SIZE` rejects trailing bytes, `[V10-01]`).

### `step.rs` — [poly-verified/src/step.rs](poly-verified/src/step.rs)
`StepFunction` trait (`execute(state, inputs) -> Vec<u8>`) with a blanket impl
for closures. Contract requires determinism but does not enforce it.

### `verified_type.rs` — [poly-verified/src/verified_type.rs](poly-verified/src/verified_type.rs)
`Verified<T>` — value+proof wrapper. Constructors `new_proven` (`pub(crate)`)
and `__macro_new` (`#[doc(hidden)] pub`, rejects Mock proofs in production).
`map`, `flatten`, `is_verified`, `privacy_mode`, disclosure helpers on
`Verified<Vec<u32>>`, `is_ok`/`is_err` on `Verified<Result<…>>`.

### `fixed_point.rs` — [poly-verified/src/fixed_point.rs](poly-verified/src/fixed_point.rs)
`FixedPoint` — deterministic Q80.48 fixed-point over `i128`. Saturating
`Add`/`Sub`/`Mul`/`Neg`, panicking `Div` (line 243), `checked_mul`/`checked_div`,
`exp_approx` Taylor series with sign-deterministic overflow saturation.

### `disclosure.rs` — [poly-verified/src/disclosure.rs](poly-verified/src/disclosure.rs)
Selective disclosure over `Verified<Vec<u32>>`. `Disclosure` carries
revealed/redacted tokens, Merkle proofs for revealed positions, an
`output_root`, the `execution_proof`, and an `output_binding`.
`create_disclosure`/`create_disclosure_range` produce it; `verify_disclosure`
checks sequential indices, leaf/proof consistency, Merkle reconstruction over
all leaves, and binds the disclosure to the execution proof's `output_hash`.

### `proof_composition.rs` — [poly-verified/src/proof_composition.rs](poly-verified/src/proof_composition.rs)
`CompositeProof` for nested verified calls. `compose` (asserts
`MAX_INNER_PROOFS = 1024`), `verify_composition` (full crypto verification of
every contained proof + privacy-mode binding check).

### `proof_serialize.rs` — [poly-verified/src/proof_serialize.rs](poly-verified/src/proof_serialize.rs)
`VerifiedResponse` wire format. `new`, `to_bytes`, `from_bytes` (16 MiB proof
cap), `verify_value_integrity`, `validate_proof_bytes`,
`validate_header_consistency`.

### `crypto/mod.rs` — [poly-verified/src/crypto/mod.rs](poly-verified/src/crypto/mod.rs)
Module aggregator for `hash`, `merkle`, `chain`, `commitment`, `signing`.

### `crypto/hash.rs` — [poly-verified/src/crypto/hash.rs](poly-verified/src/crypto/hash.rs)
Domain-separated SHA-256: `hash_data`, `hash_combine` (0x03), `hash_leaf`
(0x00), `hash_transition` (0x01), `hash_blinding` (0x04), `hash_chain_step`
(0x02). Verified against test vectors.

### `crypto/merkle.rs` — [poly-verified/src/crypto/merkle.rs](poly-verified/src/crypto/merkle.rs)
`MerkleTree::build`/`generate_proof`; `verify_proof` (path only) and
`verify_proof_strict` ([poly-verified/src/crypto/merkle.rs:143](poly-verified/src/crypto/merkle.rs))
with depth cap and `leaf_index`↔path binding.

### `crypto/chain.rs` — [poly-verified/src/crypto/chain.rs](poly-verified/src/crypto/chain.rs)
`HashChain` — `tip` + `length`; `append` is overflow-checked.

### `crypto/commitment.rs` — [poly-verified/src/crypto/commitment.rs](poly-verified/src/crypto/commitment.rs)
`create_commitment`, `sign_commitment`, `verify_signed_commitment` (Ed25519
`verify_strict`), `verify_chain_tip`.

### `crypto/signing.rs` — [poly-verified/src/crypto/signing.rs](poly-verified/src/crypto/signing.rs)
`check_code_integrity`, `sign_attestation`, `verify_attestation` (Ed25519
`verify_strict`).

### `ivc/mod.rs` — [poly-verified/src/ivc/mod.rs](poly-verified/src/ivc/mod.rs)
`IvcBackend` trait definition.

### `ivc/hash_ivc.rs` — [poly-verified/src/ivc/hash_ivc.rs](poly-verified/src/ivc/hash_ivc.rs)
`HashIvc` + `HashIvcAccumulator` — production hash-chain IVC. `verify` caps
checkpoints at 1,000,000 and rebuilds all commitments.

### `ivc/mock_ivc.rs` — [poly-verified/src/ivc/mock_ivc.rs](poly-verified/src/ivc/mock_ivc.rs)
`MockIvc` — test-only backend whose `verify` returns `Ok(true)` for any
`Mock` proof. Gated out of production by callers.

## Code Review

The crate has clearly been through many adversarial review rounds, and most
obvious flaws are already patched (and annotated). The findings below are
issues that remain.

### Critical

None identified. The most security-sensitive paths (`HashIvc::verify`,
`verify_disclosure`, `verify_composition`, signature verification) reconstruct
commitments from first principles, use constant-time comparison, gate Mock
proofs out of production, and use Ed25519 `verify_strict`.

### High

**H1 — `verify_value_integrity` does not bind the proof to the value; `code_hash` from `Private` proofs is unverifiable.**
Location: [poly-verified/src/proof_serialize.rs:152](poly-verified/src/proof_serialize.rs).
`VerifiedResponse` exposes `verify_value_integrity` (value bytes hash to
`value_hash`), `validate_proof_bytes`, and `validate_header_consistency`, but
nothing in this module actually runs the IVC `verify` on the embedded proof,
nor cross-checks that `value_hash`/`input_hash` equal the proof's
`output_hash`/`input_hash`. A receiver that calls only these three methods
(the natural reading of the doc comments) accepts a response whose proof was
generated for a *completely different* value, as long as `value_hash` matches
`hash_data(value_bytes)` and the header is internally consistent. The
value↔proof binding — the entire point of `Verified<T>` not being
`Deserialize` — is left to the caller with no helper and no doc warning. Fix:
add a `verify_full(&self, expected_input, backend)` method that runs the
backend `verify` and asserts `value_hash`/`code_hash`/`input_hash` match the
proof, and document that the individual `validate_*` methods are necessary but
not sufficient.

**H2 — `verify_disclosure` accepts a fully-private (empty-indices) disclosure that proves nothing about its tokens.**
Location: [poly-verified/src/disclosure.rs:208](poly-verified/src/disclosure.rs)
(see `test_fully_private_empty_indices`, line 517). With zero revealed
indices, every position is `Redacted` and the only token-side check is
"redacted leaf hash != ZERO_HASH" plus Merkle reconstruction over the
*attacker-supplied* redacted leaf hashes. An attacker can pick any
`output_root` they like, fill `tokens` with arbitrary non-zero `leaf_hash`
values that reconstruct it, then set the execution proof's `output_hash` to
`hash_combine(output_binding, output_root)` — and `verify_disclosure` returns
`true`. Because the all-revealed `tokens_hash` cross-check at line 307–321
only runs when `all_revealed`, a fully-redacted disclosure has *no* binding
between `output_binding` and the actual token leaves. This is acceptable
*only* if `output_binding`/`output_hash` themselves come from an independently
trusted execution proof, but `verify_disclosure` also calls `HashIvc::verify`
with the proof's *own* `input_hash`/`output_hash` as the expected values
(line 348), making that comparison a tautology (same issue as H3). Net: a
fully-private disclosure is self-certifying. Fix: require the verifier to
supply the expected `output_hash` (or expected `output_root`) from a trusted
channel, rather than reading it from the proof being verified.

**H3 — IVC `verify` is called with the proof's own I/O hashes as the "expected" values.**
Locations: [poly-verified/src/disclosure.rs:348](poly-verified/src/disclosure.rs)
and [poly-verified/src/proof_composition.rs:181](poly-verified/src/proof_composition.rs).
`HashIvc::verify(proof, input_hash, output_hash)` is designed to check a proof
against *externally* known expected I/O. In both call sites the `input_hash`
and `output_hash` destructured from the proof are passed straight back in as
the "expected" arguments. Step 5 of `HashIvc::verify`
([poly-verified/src/ivc/hash_ivc.rs:174](poly-verified/src/ivc/hash_ivc.rs)) then compares
`input_hash == input_hash` — always true. The chain/Merkle/blinding rebuild
still runs, so this is not fully toothless, but the I/O-binding half of
verification is silently disabled. `proof_composition.rs` documents this
("the I/O comparison is then a tautology"), which means the composite has *no*
guarantee that inner proofs' inputs/outputs chain together — an attacker can
splice unrelated-but-individually-valid inner proofs. Fix: composition should
verify that each inner proof's `output_hash` feeds the next step's
`input_hash` (a real call-graph binding), and disclosure should take the
expected output from a trusted source.

### Medium

**M1 — `FixedPoint`'s `Div` operator panics on division by zero.**
Location: [poly-verified/src/fixed_point.rs:243](poly-verified/src/fixed_point.rs)
(`assert!(rhs.raw != 0, "division by zero")`). Every other `FixedPoint`
arithmetic operator saturates instead of panicking, and the type's stated
purpose is *deterministic* arithmetic for verified computation. A `/` on
attacker-influenced operands inside a `#[verified]` function aborts the
process. `checked_div` exists for the safe path, but the `Div` trait impl is
the one that ordinary `a / b` code resolves to. Fix: either saturate `Div`
(consistent with `Mul`/`Add`) returning `ZERO` or a documented sentinel, or
clearly document that `/` may panic and that verified code must use
`checked_div`.

**M2 — `Verified<T>` derives `Serialize` while deliberately omitting `Deserialize`.**
Location: [poly-verified/src/verified_type.rs:24](poly-verified/src/verified_type.rs).
The security note explains why `Deserialize` is omitted, but `Serialize` is
still derived. The serialized form exposes both `value` and `proof` and — more
importantly — invites consumers to write their own `Deserialize` (or use
`serde_json::Value` round-tripping) and reconstruct a `Verified<T>` via a
manual struct literal in *this* crate, or to assume the serialized form is a
safe transport. Since the intended transport is `VerifiedResponse`, deriving
`Serialize` on `Verified<T>` is an attractive-nuisance. Fix: either drop the
`Serialize` derive or document precisely that the serialized output is for
debugging/logging only and must never be deserialized back into a trusted
value.

**M3 — `Verified::flatten` blindly discards the inner proof.**
Location: [poly-verified/src/verified_type.rs:153](poly-verified/src/verified_type.rs).
`Verified<Verified<T>>::flatten` keeps the outer proof and drops the inner
one, with a comment asserting "the outer proof encompasses the inner
computation." Nothing in the type system or runtime enforces that
relationship — `new_proven`/`__macro_new` will happily build a
`Verified<Verified<T>>` from two unrelated proofs (the unit test
`test_verified_flatten` does exactly that with two independent mock proofs).
After `flatten`, the inner value is now certified by a proof that may have
nothing to do with it. Fix: either compose the two proofs via `CompositeProof`
during flatten, or restrict `flatten` to cases where the macro guarantees
containment, and document the precondition.

**M4 — `Verified::map` lets the proof outlive the value it certifies.**
Location: [poly-verified/src/verified_type.rs:115](poly-verified/src/verified_type.rs).
`map` applies an arbitrary `F: FnOnce(T) -> U` and carries the *same* proof
onto the result. The proof's `output_hash` certifies the *original* value;
after `map(|x| x * 2)` the proof no longer corresponds to the wrapped value,
yet `is_verified()` still returns `true` and `verify_disclosure`/wire checks
that recompute `output_hash` from the new value would fail confusingly (or, in
`Private` mode where the value is not hashed, pass while certifying nothing).
This is a deliberate API affordance, but it is a soundness foot-gun. Fix:
document loudly that `map` invalidates the value↔proof binding for any
verifier that recomputes the output hash, or downgrade the proof's effective
status after `map`.

**M5 — `verify_disclosure` returns a bare `bool`, collapsing all failure causes.**
Location: [poly-verified/src/disclosure.rs:208](poly-verified/src/disclosure.rs).
Every failure path returns `false` with no indication of *why* (out-of-order
tokens vs. bad Merkle proof vs. proof-binding mismatch vs. rejected Mock
proof). For a security-critical verifier this hampers auditing and incident
response, and makes it easy for a caller to misattribute a failure. The
internal `ProofSystemError` enum is rich enough to express these. Fix: return
`Result<(), ProofSystemError>` (or a dedicated `DisclosureError`).

### Low

**L1 — `most_restrictive_privacy` ordering is fragile to enum extension.**
Location: [poly-verified/src/proof_composition.rs:90](poly-verified/src/proof_composition.rs).
The "most restrictive" lattice is hand-coded with match arms. If a new
`PrivacyMode` variant is added, the catch-all `_ => Transparent` arm silently
treats it as the *least* restrictive mode — a privacy downgrade. Fix: implement
`Ord` on `PrivacyMode` with an explicit restrictiveness ranking and use
`.max()`, so a new variant forces a compile decision.

**L2 — `MerkleProof::to_bytes` and `CompositeProof::compose` panic on oversized input.**
Locations: [poly-verified/src/types.rs:216](poly-verified/src/types.rs) and
[poly-verified/src/proof_composition.rs:39](poly-verified/src/proof_composition.rs). Both use
`assert!` to enforce caps (64 siblings, 1024 inner proofs). `from_bytes` and
`verify_composition` correctly return errors / `false` for the same condition,
so the panic only fires on programmatic misuse — but a serialization helper
that aborts the process is still a hazard if a `MerkleProof` is ever built
from deserialized/untrusted data and re-serialized. Fix: make `to_bytes`
return `Result`, or guarantee via types that the cap holds before serialization.

**L3 — `VerifiedResponse` exposes private `value_bytes` length even in `Private` mode.**
Location: [poly-verified/src/proof_serialize.rs:67](poly-verified/src/proof_serialize.rs).
In `Private` mode `value_bytes` is emptied, but `proof_bytes` is the
JSON-serialized proof and its length still varies with `step_count` /
`checkpoints.len()`. A network observer learns the step count of a "fully
private" computation from the wire-format size. This is a metadata leak, not a
value leak; acceptable for many threat models but worth documenting. Fix: note
the limitation, or pad proof bytes to a bucketed size in `Private` mode.

**L4 — `code_hash()` returns `ZERO_HASH` for `Private` proofs, which collides with a genuine zero code hash.**
Location: [poly-verified/src/types.rs:470](poly-verified/src/types.rs). `Private`
mode and `Mock` proofs both return `ZERO_HASH` from `code_hash()`. A consumer
cannot distinguish "code identity intentionally hidden" from "code hash is
genuinely all-zero" from "this is a mock." Fix: return `Option<Hash>` (`None`
for hidden/mock) so the absence is explicit.

**L5 — `exp_approx` overflow saturation can still be inaccurate for moderate negative `x`.**
Location: [poly-verified/src/fixed_point.rs:174](poly-verified/src/fixed_point.rs).
The `[R26-01]` fix correctly saturates to `ZERO` for negative `x` on overflow,
but for moderate negative `x` that does *not* overflow, the alternating Taylor
series with a fixed `terms` count can produce a meaningfully wrong (even
negative) result for `e^x`, since the true value is small and positive.
`exp_approx` has no clamp to `[0, ∞)`. Fix: clamp the final result to be
non-negative, or document the accuracy envelope and recommended `terms` for a
given input range.

**L6 — `StepFunction` determinism is contractual only.**
Location: [poly-verified/src/step.rs:5](poly-verified/src/step.rs). The doc says
"must be deterministic" but the blanket impl accepts any `Fn`, including
closures that read clocks/RNG. Non-deterministic steps silently break
reproducibility of proofs. Fix: document that this is an unchecked invariant
and that verification will fail (rather than the contract being enforced).

## Strengths

- **Thorough domain separation.** Every hash context has a distinct one-byte
  tag ([poly-verified/src/crypto/hash.rs](poly-verified/src/crypto/hash.rs)), with explicit tests
  confirming `hash_data`/`hash_leaf`/`hash_combine` differ on identical input.
- **Constant-time comparisons everywhere it matters.** `hash_eq` is
  branch-free, `Commitment::eq` XOR-compares the `total_checkpoints` field to
  avoid short-circuit leakage, and verification paths consistently use it.
- **Strong, defense-annotated adversarial hardening.** Strict fixed-size
  parsers (reject trailing bytes), DoS caps on checkpoints / inner proofs /
  sibling depth, Ed25519 `verify_strict` (rejects small-order points and
  malleable signatures), and the `verify_proof_strict` depth cap that fixes the
  recent `>64-sibling` panic — each tied to a referenced finding ID.
- **Mock-proof containment.** `__macro_new`, `is_verified`, `verify_disclosure`
  and `verify_contained_proof` all gate `Mock` proofs behind
  `cfg!(any(test, feature = "mock"))`, with a documented rationale for why a
  production verifier must reject them.
- **`verify_composition` does real cryptographic verification.** The `[V34-01]`
  fix replaced a structural-only check with a full chain/Merkle rebuild of
  every contained proof.
- **Genuinely deterministic arithmetic.** `FixedPoint` is pure integer math
  with saturating operators and explicit overflow handling — no floating point
  anywhere — which is the right foundation for reproducible proofs.
- **Clean trait-based backend abstraction.** `IvcBackend` cleanly separates the
  proof system from the production (`HashIvc`) and test (`MockIvc`) backends,
  and leaves room for the declared `Nova`/`HyperNova` variants.

## Recommendations

Prioritized, actionable:

1. **(H3, H2) Stop feeding a proof its own I/O hashes as "expected" values.**
   Make `verify_disclosure` and `CompositeProof::verify_composition` take the
   expected `output_hash`/`input_hash` from a trusted caller, and have
   composition verify the inner-proof I/O actually chains. This restores the
   I/O-binding half of soundness that is currently a tautology.
2. **(H1) Add a single `VerifiedResponse::verify_full` entry point** that runs
   the backend `verify` and cross-checks `value_hash`/`input_hash`/`code_hash`
   against the proof — and document the standalone `validate_*` methods as
   necessary-but-not-sufficient.
3. **(M3, M4) Fix the proof-binding foot-guns in `Verified<T>`:** make
   `flatten` compose proofs (or restrict it), and document/limit `map` so
   callers cannot end up with a proof that certifies a stale value.
4. **(M1) Make `FixedPoint`'s `Div` operator consistent** with the other
   saturating operators (no panic), or document the panic and steer verified
   code to `checked_div`.
5. **(M5) Return `Result<(), ProofSystemError>` from `verify_disclosure`** so
   failures are auditable instead of an opaque `false`.
6. **(M2, L4) Tighten the `Verified<T>` / `VerifiedProof` API surface:** drop
   or document the `Serialize` derive on `Verified<T>`; change `code_hash()` to
   return `Option<Hash>`.
7. **(L1) Implement `Ord` on `PrivacyMode`** and compute the most-restrictive
   mode via `.max()`, so future variants force an explicit decision.
8. **(L2) Convert the `assert!` caps in `to_bytes` / `compose` to `Result`**
   returns so no serialization path can abort the process.
9. **(L3, L5, L6) Documentation hardening:** note the `proof_bytes`-size
   metadata leak in `Private` mode, the `exp_approx` accuracy envelope, and the
   unchecked `StepFunction` determinism invariant.
10. **Add cross-call integration/attack tests** that specifically attempt the
    H2/H3 splicing attacks (fully-private fabricated disclosure; composite of
    unrelated valid inner proofs) to lock in the fixes.
