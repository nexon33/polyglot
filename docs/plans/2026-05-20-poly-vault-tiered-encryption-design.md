# poly-vault: Tiered Encryption & `.polyvault` Container

**Date:** 2026-05-20
**Status:** Design — ready for implementation
**Scope:** Phase 1 of the Poly Verified Textual & Spatial Redaction Platform.
Builds the cryptographic core: onion hash-chain keys, per-token AEAD,
KEM-wrapped recipient keys, and the `.polyvault` binary container.
Defers Argon2 auth/vault, image tiles, and frontend UI to later phases.

---

## Context

The repo already has a working selective-disclosure pipeline
(`poly-verified::disclosure`): tokens are leaves of a Merkle tree, the
tree root binds to a Hash-IVC `VerifiedProof`, and authors emit a
`Disclosure { tokens: Vec<Revealed | Redacted>, proofs, … }` JSON.
See `Untitled.disclosure.json` for the current shape.

What's missing for the PDF spec:

1. Tokens are binary `Revealed | Redacted` — no notion of *clearance levels*.
2. No tiered key hierarchy (the K4→K3→K2→K1 onion).
3. No standard transport container that bundles disclosure + proof +
   per-recipient key wrapping.

`poly-vault` adds these without touching `poly-verified` — purely
additive, with `Disclosure` as its input.

## Goals & non-goals

**Goals (this phase):**
- Onion key chain K4→K3→K2→K1 with one-way derivation.
- Per-token AEAD: each redacted token sealed under its tier's key,
  recoverable by anyone holding a key ≥ that tier.
- KEM-wrapped tier keys per authorized recipient (X25519 ECDH + AEAD).
- `.polyvault` binary container with signed manifest and IVC binding.
- Forward-compatible section framing (unknown sections are skipped).
- Reproducible builds: same inputs → byte-identical output.

**Non-goals (later phases, explicit YAGNI):**
- Argon2/password-derived KEK and encrypted user vault.
- 16×16 image tile Merkle trees.
- Recipient revocation / rekeying / forward secrecy.
- Streaming reads for >1 GB payloads.
- Frontend DOM-to-token UI.

## Crate layout

```
poly-vault/
├── Cargo.toml
└── src/
    ├── lib.rs                    public API surface, re-exports
    ├── error.rs                  VaultError, Result alias
    │
    ├── keys/                     anything that produces/holds key material
    │   ├── mod.rs
    │   ├── tier.rs               Tier enum, ordering, salt constants
    │   ├── chain.rs              KeyChain: K4→K3→K2→K1 derivation
    │   ├── derive.rs             HKDF / domain-separation helpers
    │   └── wrap.rs               KEM-wrap of Kn under recipient pubkeys
    │
    ├── crypto/                   primitives, no policy
    │   ├── mod.rs
    │   ├── aead.rs               ChaCha20-Poly1305 wrapper, AAD builder
    │   ├── kem.rs                X25519 ECDH → HKDF → AEAD key
    │   ├── sig.rs                Ed25519 sign/verify wrapper
    │   └── rng.rs                central CSPRNG injection point
    │
    ├── tokens/                   text-token tiered payload
    │   ├── mod.rs
    │   ├── tiered.rs             DisclosedToken::Tiered variant
    │   ├── encrypt.rs            seal_tokens
    │   └── decrypt.rs            open_tokens
    │
    ├── tiles/                    image-tile payload — phase 2 placeholder
    │   └── mod.rs
    │
    ├── identity/                 auth/vault — phase 3 placeholder
    │   └── mod.rs
    │
    └── container/                .polyvault binary format
        ├── mod.rs
        ├── header.rs             magic, version, manifest
        ├── manifest.rs           payload index, tier map, root hashes
        ├── kem_block.rs          array of wrapped Kn keys
        ├── payload.rs            typed payload sections
        ├── codec.rs              bincode + length-prefixed framing
        ├── writer.rs
        └── reader.rs

tests/
├── keychain_derivation.rs        known-answer tests
├── tier_access_matrix.rs         4×4 holder×payload matrix
├── container_roundtrip.rs        full end-to-end
├── reproducibility.rs            byte-identical reissuance
├── forward_compat.rs             unknown sections skipped
└── attack/
    ├── mod.rs
    └── tamper_tests.rs           six negative cases
```

## Key derivation (the onion)

### `keys/tier.rs`

```rust
#[repr(u8)]
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Serialize, Deserialize)]
pub enum Tier {
    Public    = 1,
    Internal  = 2,
    Executive = 3,
    TopSecret = 4,
}

const SALTS: [&[u8]; 4] = [
    b"poly-vault/v1/L1",
    b"poly-vault/v1/L2",
    b"poly-vault/v1/L3",
    b"poly-vault/v1/L4",
];
```

Salts are domain-separated and versioned — a future v2 chain can coexist
without confusion.

### `keys/chain.rs`

```rust
pub struct TierKey([u8; 32]);   // Zeroize + ZeroizeOnDrop

pub struct KeyChain {
    top: Tier,
    keys: BTreeMap<Tier, TierKey>,
}

impl KeyChain {
    /// Author side: fresh master seed for the document's top tier.
    pub fn generate(top: Tier, rng: &mut impl RngCore) -> Self;

    /// Recipient side: rebuild the chain from a single distributed key.
    pub fn from_tier_key(tier: Tier, k: TierKey) -> Self;

    pub fn get(&self, t: Tier) -> Option<&TierKey>;
    pub fn can_read(&self, t: Tier) -> bool { t <= self.top }
}
```

Derivation uses BLAKE3 `derive_key` (HKDF-equivalent), not raw SHA-256
as in the PDF — same one-way preimage resistance, faster, no
length-extension concern, purpose-built for KDF use.

Three deliberate choices:

1. **BLAKE3 keyed derivation** for one-way descent K(n) → K(n-1).
2. **`TierKey` is `Zeroize` + `ZeroizeOnDrop`** — key material is
   wiped on drop.
3. **No `Clone` on `KeyChain`**, only on individual `TierKey` when
   wrapping for transport. Forces explicit handling.

## Per-token AEAD encryption

### `crypto/aead.rs`

Only place ChaCha20-Poly1305 is touched:

```rust
pub fn aead_seal(key: &TierKey, nonce: &[u8; 12], aad: &[u8], pt: &[u8]) -> Vec<u8>;
pub fn aead_open(key: &TierKey, nonce: &[u8; 12], aad: &[u8], ct: &[u8])
    -> Result<Vec<u8>, VaultError>;
```

### `tokens/tiered.rs`

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DisclosedToken {
    Revealed { index: u32, token_id: u32 },
    Redacted { index: u32, leaf_hash: Hash },
    Tiered {
        index: u32,
        tier: Tier,
        leaf_hash: Hash,        // still in Merkle tree
        nonce: [u8; 12],
        ciphertext: Vec<u8>,    // sealed token_id (4B + 16B tag = 20B)
    },
}
```

A `Tiered` token replaces `Redacted` semantically when a tier key
exists. Holders without the key see the leaf hash and verify Merkle
inclusion (existing flow). Holders with the key recover `token_id`,
recompute `hash_leaf(token_id.to_le_bytes())`, and assert equality
with `leaf_hash` — tamper detection survives decryption.

### AAD construction

```text
AAD = b"poly-vault/v1/token"
    || merkle_root          (32B)
    || index.to_le_bytes()  ( 4B)
    || tier as u8           ( 1B)
```

Binds the ciphertext to: this document, this position, this clearance,
this protocol version. Forging requires the right `Kn` and matching
metadata — impossible to lift a ciphertext from one vault into another.

### Nonce construction

```text
nonce = SHA256(merkle_root || index_le || tier_byte)[..12]
```

Deterministic from public data. Same author re-encrypting the same
document produces the same nonce — safe because the key is fresh per
document, and nonce reuse across documents is prevented by the unique
`merkle_root`. Determinism gives us reproducible `.polyvault` builds.

### Encryption flow

```rust
pub fn seal_tokens(
    plaintext_tokens: &[u32],
    tier_assignment: &[Tier],
    merkle_root: &Hash,
    chain: &KeyChain,
) -> Result<Vec<DisclosedToken>>;
```

The author always holds the top-tier chain. In the typical onion-vault
flow every token is `Tiered` — public tokens go through K1 AEAD, so the
holder still needs the document's K1 to read them. `Revealed` is kept
in the enum for backward compatibility with existing `poly-verified`
consumers.

## `.polyvault` container format

Single self-contained binary, length-prefixed sections, forward-compat
on unknown section types.

```
┌─────────────────────────────────────────────────────────────┐
│ MAGIC          b"PVLT"           4B                         │
│ VERSION        u16 LE            2B    (= 1)                │
│ FLAGS          u16 LE            2B    (bit0: signed)       │
├─────────────────────────────────────────────────────────────┤
│ Section: HEADER       (type=0x01, len, bincode payload)     │
│ Section: KEM_BLOCK    (type=0x02, len, bincode payload)     │
│ Section: PAYLOAD      (type=0x03, len, bincode payload) ×N  │
│ Section: PROOF        (type=0x04, len, bincode payload)     │
│ Section: SIGNATURE    (type=0xFF, len, 64B Ed25519)         │ optional
└─────────────────────────────────────────────────────────────┘
```

Section framing: `u8 type || u32 LE length || bytes`. Unknown sections
are skipped on read.

### Header

```rust
pub struct Header {
    pub dossier_id: Hash,            // SHA-256 of canonical metadata
    pub created_unix: u64,
    pub author_pubkey: [u8; 32],     // Ed25519
    pub top_tier: Tier,
    pub merkle_root: Hash,           // binds payload tree to IVC
    pub payload_count: u32,
    pub payload_index: Vec<PayloadDescriptor>,
}
```

### KEM block

```rust
pub struct KemBlock { pub recipients: Vec<WrappedKey> }

pub struct WrappedKey {
    pub recipient_pubkey: [u8; 32],
    pub tier: Tier,
    pub ephemeral_pubkey: [u8; 32],
    pub nonce: [u8; 12],
    pub wrapped: Vec<u8>,            // sealed TierKey (32B + 16B tag)
}
```

Each authorized recipient appears once per tier they're cleared for —
usually just their highest. Recipient runs X25519 ECDH against
`ephemeral_pubkey`, derives wrap key via HKDF, AEAD-opens `wrapped`,
expands downward with `KeyChain::from_tier_key`.

### Payload sections

```rust
pub enum Payload {
    Tokens(TokenPayload),
    Tiles(TilePayload),       // phase 2 stub
}

pub struct TokenPayload {
    pub total_tokens: u32,
    pub tokens: Vec<DisclosedToken>,
    pub proofs: Vec<MerkleProof>,
}
```

### Proof & signature

Proof section carries the existing `VerifiedProof` (HashIvc).
`output_hash` must equal `merkle_root` from the header.

Signature: Ed25519 over `SHA-256(everything before SIGNATURE section)`.
Detached so unsigned drafts are valid container shape.

### Reader invariants

Three bindings verified before exposing any decrypted token:

1. `header.merkle_root == proof.output_hash` (proof not detached).
2. Signature valid (if present).
3. For each Tiered token decrypted: `hash_leaf(token_id) == leaf_hash`.

Any failure → whole vault rejected, no partial state exposed.

## Integration with `poly-verified`

```
poly-verified::create_disclosure(verified, indices)
         │  Disclosure { tokens, proofs, output_root, … }
         ▼
poly-vault::seal_into_container(disclosure, tier_assignment, recipients, signing_key)
         │  - convert Redacted → Tiered (per-token AEAD)
         │  - wrap each Kn under recipient pubkeys
         │  - write .polyvault binary
         ▼
.polyvault file
         ▼
poly-vault::open_container(bytes, my_x25519_secret)
         │  - parse, verify signature + IVC binding
         │  - unwrap matching WrappedKey → top TierKey
         │  - KeyChain::from_tier_key expands downward
         │  - decrypt every Tiered token whose tier ≤ holder
         ▼
OpenedVault { tokens, readable_tiers }
```

`poly-verified::disclosure` is untouched. The `DisclosedToken` enum
gains a `Tiered` variant — old code matching it gets a compile error
and must handle the new case (deliberate — forces audit of every read
site).

## Dependencies

New, all well-established:

- `chacha20poly1305` — AEAD
- `x25519-dalek` — KEM
- `blake3` — KDF
- `zeroize` — secret hygiene

Already in workspace:
- `ed25519-dalek` (via `poly-node`)
- `sha2`, `serde`, `bincode`

Deferred to later phases:
- `argon2` (auth)

## Test plan

1. **`keychain_derivation.rs`** — known-answer test: fixed seed → fixed
   K3/K2/K1 byte vectors. Prevents accidental derivation changes from
   silently re-keying old vaults.

2. **`tier_access_matrix.rs`** — for every holder ∈ {K1..K4} × payload
   tier ∈ {L1..L4}, assert `can_read(payload_tier) == (payload_tier ≤
   holder)`. 16 cases, exhaustive.

3. **`container_roundtrip.rs`** — author with K4 writes 26-token
   document (matches existing `Untitled.disclosure.json` shape), three
   recipients with K1/K2/K3. Each opens, asserts which tokens they
   read, asserts the rest stay opaque.

4. **`attack/tamper_tests.rs`** — six negative tests:
   - Flip a ciphertext byte → AEAD open fails.
   - Swap two Tiered tokens' positions → AAD mismatch.
   - Substitute Tiered token from another vault → AAD mismatch.
   - Strip PROOF section → reader rejects (binding check fails).
   - Replace `merkle_root` in header → IVC binding mismatch.
   - Resign with attacker key → signature check fails against
     `author_pubkey` in header.

5. **`reproducibility.rs`** — same inputs (seed + tokens + tier
   assignment + recipients) produce byte-identical `.polyvault`.
   Validates the deterministic-nonce choice.

6. **`forward_compat.rs`** — synthetic vault with unknown section type
   (e.g. `0x77`) between known sections; reader skips it and still
   opens successfully.

## Risks & mitigations

- **Nonce-reuse if `merkle_root` collides** — collision implies SHA-256
  break; out of threat model.
- **`Revealed` tokens leak plaintext alongside Tiered ones** —
  intentional for backward compat. Documented in `tokens/tiered.rs`:
  use all-Tiered for true onion semantics.
- **Recipient revocation** — not supported in v1; would require
  rekeying and reissuing the vault. Acceptable for v1; revisit when
  needed.
- **No streaming reader** — single in-memory pass. For documents up to
  ~100 MB this is fine; large image-tile payloads in phase 2 may need
  streaming.

## Next phases (out of scope here)

- **Phase 2 — Image tiles**: 16×16 tile Merkle trees, tile payloads in
  `tiles/`, SVG-polygon-to-tile-set mapping. Reuses the same KEM block
  and tier keys; no container-format break.
- **Phase 3 — Auth & vault**: Argon2-KEK, X25519 user identity vault.
  Slots into `identity/`. No container-format break.
- **Phase 4 — Frontend UI**: DOM-to-token redaction editor, vault
  opener in browser via WASM.
