# Poly Wallet + Local Testnet — Design

Date: 2026-05-19

## Goal

Make `poly-chain` runnable: a **wallet** (key management + transaction signing) and a
**local testnet** (a node that maintains a chain, accepts transactions, and produces
blocks) so the verify-only ledger can actually be exercised end to end.

## Constraints discovered

- `poly-chain` today is a pure library: validation primitives, no binary, no node, no
  keypairs. `WalletState` exists but there is no Ed25519 keypair / signing helper.
- The chain is **verify-only**: `validate_cash_transfer` checks a `VerifiedProof` and
  updates opaque wallet *commitment hashes*. It does **not** track balances — real
  balances must be held off-chain by a full node.
- Every transaction carries a `VerifiedProof`. Real `HashIvc` proofs are cheap to
  construct (`init` → one `fold_step` → set I/O hashes → `finalize`), so the testnet
  runs **production verification paths** — no `mock` feature, real signatures, real
  proofs. This also avoids the `mock`-feature-unification hazard flagged in review.

## Architecture

```
 poly-chain CLI (src/bin/poly-chain.rs)
        │
        ├── keys.rs       Keypair = Ed25519; AccountId = SHA-256(pubkey)
        ├── keystore.rs   Keyfile JSON on disk (testnet: plaintext secret key)
        ├── builder.rs    build + sign CashTransfer; attach real HashIvc proof
        └── node.rs       Testnet { chain, state, mempool, ledger }
                              │
                              ├── on-chain  GlobalState  (commitment hashes)
                              └── off-chain ledger        (real WalletState balances)
```

### Flow

1. `wallet new` → generate Ed25519 keypair, derive `AccountId`, write keyfile.
2. `node init` → create `Testnet` with a genesis block + empty state, persist to disk.
3. `faucet <addr> <amount>` → node-admin op: create an Anonymous-tier `WalletState`
   in the off-chain ledger, set the on-chain wallet commitment. (No transaction —
   faucet is a genesis-style mutation.)
4. `send --from <keyfile> --to <addr> --amount N` → read `state_pre` + `nonce` from
   the node, build a `CashTransfer`, attach a real `HashIvc` proof whose input/output
   hashes match `validate_cash_transfer`, sign with Ed25519, push to mempool.
5. `mine` → for each mempool tx: run `validate_transaction`; if the node's off-chain
   ledger has sufficient balance, apply the debit/credit and adopt the returned
   `GlobalState`; pack accepted txs into a `Block`.
6. `balance` / `status` → query off-chain ledger / chain head.

## Components

- **keys.rs**: `Keypair::generate()` (getrandom-seeded), `from_secret_bytes`,
  `account_id()`, `sign()`, `verify()`.
- **keystore.rs**: `Keyfile { label, account_id, public_key, secret_key }`, hex-encoded,
  `save`/`load`. Plaintext — testnet only; documented as such.
- **builder.rs**: `build_cash_transfer(...)` replicates the canonical signing message
  and the proof I/O hashes from `validation.rs`, builds a `HashIvc` proof, signs.
- **node.rs**: `Testnet` with JSON persistence. Off-chain ledger keyed by hex account
  id. `faucet`, `submit`, `produce_block`, `balance`, `wallet_state`, `on_chain_pre`.
- **bin/poly-chain.rs**: clap CLI, `--data-dir` (default `./testnet-data`).

## Out of scope (this iteration)

- Networked multi-node testnet (poly-node QUIC integration) — local single-process
  first; it is the foundation a networked testnet would build on.
- Transaction types other than `CashTransfer` flowing through the CLI (identity,
  swaps, STP). Faucet covers account creation directly.

## Refinements made during implementation

- **`AccountId == Ed25519 public key`.** The chain's `verify_signature` feeds
  `tx.from` straight into `VerifiedKey::from_bytes`, so the account id must be the
  raw public key (the `primitives.rs` "SHA-256 hash" doc comment was wrong; no test
  caught it because unit tests run under `cfg(test)`, which skips signature checks).
- **Balances are committed into `state_root`.** Every participant keeps the full
  ledger locally; after each transfer the node writes the *real*,
  balance-inclusive `WalletState::state_hash()` into the on-chain `wallets` tree
  (overwriting the opaque `H(from||nonce||amount)` commitment that
  `validate_cash_transfer` leaves). A transaction therefore replaces **only the two
  affected account hashes**; every other leaf is untouched. Two honest participants
  replaying the same blocks derive an identical 32-byte `state_root`, so comparing
  that one hash instantly detects any cheating — a forged balance changes the root.

## Testing

Unit tests per module (`keys`, `keystore`, `builder`, `node`); `node` tests drive
genesis → faucet → send → mine → balance, assert balances move, that a transfer
replaces only the affected hashes, that independent replay yields an identical
`state_root`, and that a forged balance diverges the root.

**Real-crypto coverage** lives in the separate `poly-chain-e2e` crate, because
`poly-chain`'s own tests force-enable `poly-chain/mock` (a self dev-dependency),
which skips signature and proof verification — the blind spot that let the
`AccountId` bug survive 140 tests. `poly-chain-e2e` depends on `poly-chain`
without `mock`, so `cargo test -p poly-chain-e2e` exercises real Ed25519 and
real HashIvc verification. `mock_proof_is_rejected` is a canary that fails if the
suite is ever built with mock enabled.

## Pentest hardening (round T1–T4)

A security pass (plus an independent audit) found and fixed:

- **T1 (Critical)** — `SparseMerkleTree` trusted the cached `root` from
  deserialization, so a forged file could keep an honest root over forged
  leaves. Fixed: a manual `Deserialize` recomputes the root from `leaves`.
- **T2 (Critical)** — `Testnet::load` did no validation. Added
  `verify_integrity`: genesis well-formed, every block links to its parent,
  mempool only holds supported txs, and the off-chain ledger matches on-chain
  committed hashes and nonces exactly. `load` now calls it.
- **T3 (Medium)** — `--label` flowed unsanitized into a file path (traversal).
  Labels are now restricted to `[A-Za-z0-9_-]`, 1–64 chars.
- **T4 (Medium)** — saves were non-atomic (crash = corrupt testnet) and
  concurrent CLI processes raced. Saves now write-temp-then-rename; mutating
  commands take an exclusive `.lock`.

`poly-chain/tests/testnet_pentest.rs` holds 12 attack tests covering these.

## Post-pentest follow-ups (#1, #2)

- **#1 — `AccountId = SHA-256(public key)`.** Previously the account id had to be
  the raw Ed25519 key. Every signed transaction (and `StateObservation`) now
  carries the signer's `public_key`; the validator checks the signature *and*
  that `SHA-256(public_key)` equals the account id.
- **#2a — faucet recorded on-chain.** Faucet mints are logged in
  `genesis_allocations` and only allowed before the first block. `verify_integrity`
  now replays allocations + the full block history from genesis and checks the
  result matches the stored state — the chain is independently verifiable.
- **#2b — chain id bound into signatures.** `GlobalState` carries a random
  `chain_id`; every transaction signature is taken over `chain_id || message`,
  so a transaction cannot be replayed onto another testnet.

### Deferred to the networked phase

- Snapshot sync for bootstrapping nodes (replaying from genesis is fine for a
  local testnet but not for a long-lived networked chain).
- Tiered nodes (light client / full node / validator), gossip, K-of-N light
  client queries, hardcoded bootstrap seeds.
