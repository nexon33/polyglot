# Encrypted & Verified Inference — What This Makes Possible

`poly-client` and `poly-inference` together form a complete protocol for
running an LLM on data the operator never sees, and proving the run was
honest. This document walks through *what you can actually build* with that.

For component-level detail see
[POLY_CLIENT_CAPABILITIES.md](POLY_CLIENT_CAPABILITIES.md) and
[POLY_INFERENCE_CAPABILITIES.md](POLY_INFERENCE_CAPABILITIES.md).

---

## The three guarantees

Every possibility below rests on one or more of these:

1. **Confidentiality** — with `Mode::Encrypted` / `POST /generate/encrypted`,
   the prompt and the answer exist in plaintext *only on the client*. The
   server computes over CKKS ciphertext.
2. **Verifiability** — every response carries an IVC execution proof binding
   the output to the exact input and inference code. A client can detect a
   server that returned a different model's output, a cached answer, or
   fabricated tokens.
3. **Compliance attestation** — a separate IVC proof attests that every
   emitted token passed a named, hash-pinned content policy.

These are independent. You can take verifiability without encryption (cheap),
or stack all three.

---

## Possibility 1 — Private inference from a thin device

A browser tab or a phone holds only a tokenizer vocab and a key pair (tens of
KB). It can:

- encrypt a sensitive prompt locally,
- offload the heavy model run to an untrusted GPU server,
- decrypt the answer locally.

**Use it for:** medical-symptom queries, legal questions, private journaling
assistants — anything where "the AI vendor can read everything you type" is
unacceptable. The operator hosting the GPU cannot build a profile of users,
because it only ever holds ciphertext.

## Possibility 2 — Auditable AI decisions

Because each answer ships with an execution proof, the *output* becomes
evidence. A regulator, insurer, or counterparty can be handed:

- the answer,
- the proof,
- the `code_hash` of the inference function.

…and verify that *this* output came from *that* model on *that* input — months
later, without trusting the party that produced it.

**Use it for:** automated underwriting, claims triage, content moderation
decisions — settings where "show your work" is a legal or contractual
requirement.

## Possibility 3 — Selective disclosure to many audiences

One inference run, many need-to-know views. From a single `VerifiedResponse`:

```rust
let pharmacist = response.disclose(&[8, 9, 10])?;   // dosage tokens only
let insurer    = response.disclose_range(15..16)?;  // billing code only
```

Each recipient verifies their slice against the same Merkle output root and
learns nothing else.

**Use it for:** a medical summary where the pharmacist sees the prescription,
the insurer sees the billing code, and the patient sees everything — all
provably the same underlying generation. See
[PRIVACY_ACCOUNTABILITY.md](PRIVACY_ACCOUNTABILITY.md).

## Possibility 4 — Provably-compliant generation

`generate_compliant` checks every token against a hash-pinned `ContentPolicy`
and produces a compliance proof. The `ComplianceSummary` states the policy
version, the policy hash, and how many tokens were compliant.

**Use it for:** demonstrating to an auditor that a deployed assistant could not
have emitted blocked content under policy version *N* — and proving *which*
policy was in force, since the policy hash is committed into the proof.

## Possibility 5 — Homomorphic computation beyond token I/O

The RNS-CKKS layer (`ckks::rns_ckks`, `ckks::rns_fhe_layer`) supports
homomorphic add/multiply, rescaling, rotation, encrypted matrix–vector
products, polynomial evaluation, and encrypted neural-network layers with
`Square` / `SiLU` activations.

**Use it for:** encrypted feature extraction, private scoring models, or
verifying a model's forward pass on encrypted hidden states — the building
blocks for inference where even intermediate activations stay private.

## Possibility 6 — Compact transport for big ciphertexts

CKKS ciphertexts and keys are large. The PFHE format (`ckks::compress`) gives
~2× lossless compression and doubles as an IND-CPA sanity monitor: structured
or accidentally-plaintext data compresses anomalously and is flagged.

**Use it for:** making encrypted inference practical over mobile networks, and
catching a misconfiguration that would otherwise ship low-entropy data.

---

## What this is *not*

Be honest about the boundaries:

- The CKKS implementation is **from-scratch** and targets ~128-bit security for
  encrypt/decrypt usage; it is a research/demo system, not an audited library.
- `POST /generate/encrypted` responses are **not signed**. The proof is
  publicly recomputable, so the I/O-binding check is a *consistency* guarantee,
  not protection against an active MITM that coherently rewrites a whole
  response. Run it over an authenticated channel (TLS).
- Compliance filtering is **policy-list based**. It blocks known harmful terms
  and n-grams; it is a guardrail, not a guarantee of model safety.
- `MockEncryption` / `MockInferenceBackend` are passthrough/deterministic —
  they exercise the protocol, not real cryptography or real model weights.

## Quick start

```bash
# Encrypted end-to-end demo (CPU)
cargo run --release -p poly-inference --bin poly-demo-rns-fhe-e2e

# With CUDA + a quantized model
cargo run --release -p poly-inference --features cuda \
  --bin poly-demo-rns-fhe-e2e -- --model nanbeige-3b-q4
```

See [API_REFERENCE.md](API_REFERENCE.md) for endpoint payloads and
[ARCHITECTURE.md](ARCHITECTURE.md) for how the crates fit together.
