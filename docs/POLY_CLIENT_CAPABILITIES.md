# poly-client — Capabilities

`poly-client` is the **thin client SDK** for private, verified LLM inference.
It is deliberately small: a client needs only a tokenizer vocabulary and a
cryptographic key pair — **no model weights, no GPU, no ML framework** — so it
runs from a browser, a phone, or any constrained device.

This document describes *what the crate can do*. For the wire protocol see
[API_REFERENCE.md](API_REFERENCE.md); for the server side see
[POLY_INFERENCE_CAPABILITIES.md](POLY_INFERENCE_CAPABILITIES.md).

---

## 1. Thin-client inference (`PolyClient`)

`PolyClient<E: EncryptionBackend>` orchestrates a full request/response cycle:

| Step | What the client does |
|------|----------------------|
| `new(model_id, mode, encryption)` | Generates a fresh key pair |
| `prepare_request(token_ids, max_tokens, temperature, seed)` | Encrypts the prompt tokens into an `InferRequest` |
| `process_response(&InferResponse)` | Decrypts output tokens, pairs them with the execution proof |

The encryption layer is pluggable through the `EncryptionBackend` trait:

- **`MockEncryption`** — passthrough, for development and protocol testing.
- **`CkksEncryption`** — real lattice-based encryption (feature `ckks`).

## 2. Computation modes

The protocol exposes four privacy/performance trade-offs (`protocol::Mode`):

| Mode | Server sees input? | Proof reveals | Overhead |
|------|--------------------|--------------------|---------|
| `Transparent` | yes | input/output/code hash | ~0% |
| `PrivateProven` | yes | nothing about input | ~0% |
| `Private` | yes | nothing about input or code | ~0% |
| `Encrypted` | **never** (plaintext stays client-side) | nothing | 3–15× |

## 3. Selective disclosure

A `VerifiedResponse` can produce **per-audience views** of the same output
without re-running inference or weakening the proof:

```rust
let pharmacist_view = response.disclose(&[8, 9, 10])?;   // specific token positions
let insurer_view    = response.disclose_range(15..16)?;  // a contiguous range
```

Each `Disclosure` carries Merkle proofs binding the revealed tokens to the same
output root, so different parties can independently verify their slice while
learning nothing about the rest of the output.

`is_verified()` performs a **binding** check: the proof's committed
`output_hash` must equal the disclosure hash of the tokens actually received —
this defeats proof-reuse, where a server attaches a genuine proof minted for a
different output.

## 4. CKKS homomorphic encryption (`ckks` feature)

`poly-client::ckks` is a from-scratch implementation of the
Cheon-Kim-Kim-Song scheme. It provides two layers:

### 4.1 Encrypt / decrypt (`ckks::ciphertext`, `ckks::keys`)

- Ring dimension `N = 4096`, ciphertext modulus `q = 2^54 − 33`.
- Ring-LWE hardness, ~128-bit security for encrypt/decrypt usage.
- Token-ID sequences of any length (chunked into `N`-token blocks).
- **Authenticated ciphertexts**: HMAC-SHA256 `auth_tag`, `key_id` binding, and a
  random `nonce`. `verify_integrity()` detects tampering; `decrypt()` enforces
  the MAC fail-closed.
- Degenerate / low-norm public keys are rejected (`CkksPublicKey::is_well_formed`).

### 4.2 Homomorphic evaluation (RNS-CKKS)

The RNS (Residue Number System) variant supports computation **on ciphertext**:

- Homomorphic add, ciphertext×ciphertext and ciphertext×plaintext multiply.
- Rescaling and level-aware operations across a 20-prime modulus chain.
- Ciphertext rotation and encrypted matrix–vector products.
- Polynomial evaluation (Horner and Paterson-Stockmeyer).
- Encrypted neural-network layers (`rns_fhe_layer`) with selectable
  activations (`None`, `Square`, `SiLU`).

This is what makes **encrypted inference** possible: the model can run forward
passes over data it never sees in the clear.

## 5. PFHE compression (`ckks::compress`)

Ciphertexts and evaluation/rotation keys are large. The PFHE wire format
(bincode + zstd) offers three **lossless** levels:

| Level | Ratio | Technique |
|-------|-------|-----------|
| `Lossless` | ~1.4× | bincode + zstd |
| `Compact` | ~2× | byte-shuffle + zstd |
| `Max` | ~2.2× | zstd level 19 |

Decompression is bounded (32 MB cap) to resist decompression bombs. The
compression ratio doubles as a **continuous IND-CPA monitor**: a real
ciphertext compresses near 1.6×, while structured/low-entropy data compresses
far more and is flagged by `entropy_check()`.

## 6. Putting it together

A device with 20 KB of code and a vocab file can:

1. Encrypt a sensitive prompt locally.
2. Send it to an untrusted inference server.
3. Receive an encrypted answer plus a proof of correct execution.
4. Decrypt locally and verify the proof.
5. Hand auditors a *selective disclosure* of only the parts they may see.

No step requires the client to trust the server with plaintext.
