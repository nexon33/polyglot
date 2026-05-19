# poly-chain — Documentation & Code Review

## Overview

`poly-chain` is the **blockchain / ledger crate** of the *pyrs polyglot* workspace.
It implements a *verify-only* chain: validators **never execute computation** — they
only verify cryptographic `VerifiedProof` attestations (from the sibling
[`poly-verified`](../poly-verified) crate) and apply the resulting state
transitions. Computation happens client-side (or on the decentralized compute
network `poly-node`); the chain is the settlement and accountability layer.

The crate ties three things together:

1. **Verified execution** — every transaction carries a `VerifiedProof`
   ([`poly_verified::types::VerifiedProof`]). The validator binds transaction
   fields into proof input/output hashes and rejects the transaction unless the
   proof verifies. This is the same IVC machinery `#[verified]` produces
   elsewhere in the workspace.
2. **A ledger** — accounts, balances (conceptually), nonces, wallets, fees, and
   atomic swaps.
3. **A compliance / accountability regime** — tiered KYC identities, automatic
   compliance reports, peer-attested fraud proofs, and the "Symmetric
   Transparency Protocol" (STP) that holds public officials accountable.

The chain is the trust anchor for the compute network: a node that performs
inference produces a proof, and that proof becomes a chain transaction that can
move value (e.g. an `AtomicSwap` releasing MANA against a verified-inference
proof).

## Architecture

### Block / transaction / state model

- **Block** ([poly-chain/src/block.rs](poly-chain/src/block.rs)) — a
  fixed-layout `BlockHeader` (116 bytes: height, timestamp, prev hash, state
  root, transactions root, tx count) plus a `Vec<Transaction>`. Blocks chain by
  `prev_block_hash` and commit transactions via a Merkle root.
- **Transaction** ([poly-chain/src/transaction.rs](poly-chain/src/transaction.rs))
  — an 11-variant enum: `CashTransfer`, `WalletSync`, `IdentityRegister`,
  `BackupStore`, `BackupRestore`, `FraudProof`, `STPAction`, `AppStateUpdate`,
  and three atomic-swap variants. Every variant carries a `VerifiedProof`; most
  carry an Ed25519 signature.
- **State** ([poly-chain/src/state.rs](poly-chain/src/state.rs)) — `GlobalState`
  is 9 independent `SparseMerkleTree`s (wallets, identities, identity reverse
  index, compliance, fraud, backups, stp, applications, swaps) plus a per-account
  `nonces` map. `state_root()` is the domain-separated hash of all subtree roots
  plus a nonce-map hash.

### Validation flow

```
            ┌─────────────────────────────────────────────┐
 untrusted  │            validate_transaction()           │
   tx  ───▶ │  (poly-chain/src/validation.rs)              │
            └───────────────────┬─────────────────────────┘
                                │ dispatch on Transaction variant
        ┌───────────────────────┼────────────────────────────┐
        ▼                       ▼                            ▼
  CashTransfer            AtomicSwap*                   STPAction / Fraud
        │                       │                            │
        ▼ per-variant pipeline (verify-only):                 │
   1. structural checks (self-transfer, zero amount, ZERO_HASH sentinels)
   2. validate_timestamp()  — drift window ±300s
   3. verify_signature()    — Ed25519 verify_strict over canonical msg
   4. state lookups         — wallet/identity/swap must exist; state_pre match
   5. nonce check           — tx.nonce == state nonce; bump (replay protection)
   6. verify_proof()        — bind tx fields into I/O hashes, run IVC verify
   7. domain-specific rules — tier, freeze, compliance, swap timeout, ...
        │
        ▼
   returns a NEW GlobalState (clone-and-mutate); subtree roots recomputed
```

There is **no block-level apply function** in this crate: `Block` only offers
`validate_against_parent()` (height continuity, parent-hash chaining, timestamp
ordering, tx-count, Merkle root). Iterating transactions and threading state is
left to a caller.

### The STP protocol

The Symmetric Transparency Protocol
([poly-chain/src/stp.rs](poly-chain/src/stp.rs),
[poly-chain/src/validation.rs:1001](poly-chain/src/validation.rs)) makes public
officials accountable:

```
 RegisterContract ──▶ official stakes collateral, accepts lower thresholds
        │
 TriggerInvestigation ──▶ writes pack_investigation_state(now, AwaitingData)
        │                  under pool_id; binds inv_target_key -> target
        ▼
 ProvideData ──▶ official writes data_hash under H("stp_data_v1"||inv_id)
        │
 CheckDeadline (anyone) ──▶ reads investigation state, applies:
        │      72h elapsed, no data  -> FreezeAccount  (writes frozen_key)
        │      30d after freeze      -> ExecuteSlash
        ▼
 frozen_key(account) presence ──▶ value-movement validators reject the account
```

### Fraud & compliance subsystems

- **Fraud** ([poly-chain/src/fraud.rs](poly-chain/src/fraud.rs)) — two signed
  `StateObservation`s of the same account with the same nonce but different
  state hashes prove a double-spend (`detect_conflict`). A valid `FraudProofTx`
  burns the offender's wallet.
- **Compliance** ([poly-chain/src/compliance.rs](poly-chain/src/compliance.rs))
  — `check_compliance` auto-generates a `ComplianceReport` when a single
  transfer or the rolling-24h total crosses the tier threshold
  ([poly-chain/src/identity.rs](poly-chain/src/identity.rs)). Reports are stored
  in the `compliance` subtree.

## Module Reference

### [poly-chain/src/lib.rs](poly-chain/src/lib.rs)
Crate root. Declares the 12 modules and a `prelude`
([lib.rs:29](poly-chain/src/lib.rs)) re-exporting the public API.

### [poly-chain/src/primitives.rs](poly-chain/src/primitives.rs)
Shared primitives. Type aliases `AccountId`/`Amount`/`Nonce`/`Timestamp`/
`BlockHeight` ([primitives.rs:25-37](poly-chain/src/primitives.rs)); domain
separators `0x10`–`0x18` ([primitives.rs:45-56](poly-chain/src/primitives.rs));
`hash_with_domain` ([primitives.rs:59](poly-chain/src/primitives.rs)); the
`serde_byte64` helper for Ed25519 signatures
([primitives.rs:5](poly-chain/src/primitives.rs)); `hex_encode`.

### [poly-chain/src/error.rs](poly-chain/src/error.rs)
`ChainError` ([error.rs:5](poly-chain/src/error.rs)) — a `thiserror` enum of ~30
variants; `Result<T>` alias.

### [poly-chain/src/block.rs](poly-chain/src/block.rs)
`BlockHeader` with fixed `to_bytes`/`from_bytes`
([block.rs:27-70](poly-chain/src/block.rs)) and `block_hash`. `Block` with
`compute_transactions_root`/`verify_transactions_root`
([block.rs:82-94](poly-chain/src/block.rs)), `genesis`, `new`/`try_new`, and
`validate_against_parent` ([block.rs:134](poly-chain/src/block.rs)).

### [poly-chain/src/transaction.rs](poly-chain/src/transaction.rs)
The `Transaction` enum ([transaction.rs:11](poly-chain/src/transaction.rs)) and
all payload structs. `tag()`, `tx_hash()`
([transaction.rs:44](poly-chain/src/transaction.rs)), `fee_payer()`. Atomic-swap
types and `swap_state_hash*` helpers
([transaction.rs:250-282](poly-chain/src/transaction.rs)).

### [poly-chain/src/state.rs](poly-chain/src/state.rs)
`SparseMerkleTree` ([state.rs:109](poly-chain/src/state.rs)) — a *sorted-list
commitment* (not a true SMT, see [state.rs:172](poly-chain/src/state.rs)).
`GlobalState` ([state.rs:224](poly-chain/src/state.rs)) with `state_root()`,
`nonces_hash()`, and per-subtree accessors. Custom hex serde for `[u8;32]` map
keys ([state.rs:24-102](poly-chain/src/state.rs)).

### [poly-chain/src/validation.rs](poly-chain/src/validation.rs)
The heart of the crate (~1700 lines). `validate_transaction`
([validation.rs:316](poly-chain/src/validation.rs)) dispatches to per-variant
validators. Helpers: `verify_proof`
([validation.rs:23](poly-chain/src/validation.rs)), `verify_signature`
([validation.rs:64](poly-chain/src/validation.rs), `verify_strict`),
`validate_timestamp`, `validate_nonce`
([validation.rs:114](poly-chain/src/validation.rs)), per-tx signing-message
constructors, and the STP key derivations `inv_target_key`/`frozen_key`/
`reject_if_frozen` ([validation.rs:282-308](poly-chain/src/validation.rs)).

### [poly-chain/src/identity.rs](poly-chain/src/identity.rs)
`Tier` enum ([identity.rs:10](poly-chain/src/identity.rs)) with
`balance_limit`/`reporting_threshold`. `IdentityRecord` with `to_bytes`/
`from_bytes`/`record_hash`. `derive_identity_hash`
([identity.rs:162](poly-chain/src/identity.rs)) — length-prefixed.

### [poly-chain/src/wallet.rs](poly-chain/src/wallet.rs)
`WalletState` ([wallet.rs:11](poly-chain/src/wallet.rs)) — balance, nonce, tier,
rolling-24h total, freeze state; `maybe_reset_rolling`, `state_hash`,
`to_bytes`/`from_bytes`. `WalletStateCommitment` — compact on-chain form.

### [poly-chain/src/fee.rs](poly-chain/src/fee.rs)
`FeeSchedule` ([fee.rs:6](poly-chain/src/fee.rs)) — flat per-operation fee
constants.

### [poly-chain/src/fraud.rs](poly-chain/src/fraud.rs)
`FreezeReason`, `ConflictType`, `StateObservation` (with `sign_message`),
`FraudEvidence`, and `detect_conflict`
([fraud.rs:75](poly-chain/src/fraud.rs)).

### [poly-chain/src/compliance.rs](poly-chain/src/compliance.rs)
`ReportType`, `ComplianceStatus`, `ComplianceReport` (with `report_hash`/
`to_bytes`), and `check_compliance`
([compliance.rs:75](poly-chain/src/compliance.rs)).

### [poly-chain/src/stp.rs](poly-chain/src/stp.rs)
`ContractStatus`, `ServiceContract`, `InvestigationStatus`,
`InvestigationRecord` ([stp.rs:81](poly-chain/src/stp.rs)),
`check_investigation_deadlines` ([stp.rs:163](poly-chain/src/stp.rs)), and the
`pack_investigation_state`/`unpack_investigation_state` codec
([stp.rs:194-227](poly-chain/src/stp.rs)).

## Code Review

The crate shows a long, well-documented history of pentest hardening (the `R5`–
`R37` comments). The findings below are issues that **remain** in the code as
read.

### Critical

**C1 — The verify-only model never enforces balances or actual debits.**
[poly-chain/src/validation.rs:498-540](poly-chain/src/validation.rs).
In `validate_cash_transfer`, the total debit is computed only to detect
overflow and then *discarded* (`let _total_debit = tx.amount.checked_add(tx.fee)…`
at [validation.rs:501](poly-chain/src/validation.rs)). No code ever reads a
sender balance, compares it to `amount + fee`, or computes the post-transfer
balance. The new sender/recipient wallet commitments are *fabricated* hashes
(`hash_with_domain(DOMAIN_WALLET_STATE, &[from, nonce, amount])`,
[validation.rs:511](poly-chain/src/validation.rs)) that have no arithmetic
relationship to any prior balance. The same pattern appears in
`validate_atomic_swap_init/claim/refund`
([validation.rs:1501](poly-chain/src/validation.rs),
[validation.rs:1603](poly-chain/src/validation.rs),
[validation.rs:1697](poly-chain/src/validation.rs)).
*Why it matters:* in any build where proofs are not real (`test`/`mock`
features, see C2) a sender can transfer unlimited MANA out of an empty account
— there is no balance conservation, no double-spend protection on *value*
(only on *nonce*), and no fee collection to any recipient. Even with real
proofs, the chain delegates 100% of value soundness to the off-chain circuit;
the validator cannot independently detect a balance violation, so a buggy or
malicious prover is unconstrained by the ledger.
*Suggested fix:* store `WalletState` (or at least a balance commitment the
validator can recompute) on-chain rather than an opaque hash, and assert
`new_balance == old_balance - amount - fee` inside the validator. At minimum,
make the wallet commitment a deterministic function of the *proven output*
hash so the proof actually binds the post-state.

**C2 — Mock proofs and signatures are accepted whenever the `mock` feature is
enabled, not only under `cfg(test)`.**
[poly-chain/src/validation.rs:34](poly-chain/src/validation.rs),
[validation.rs:43-53](poly-chain/src/validation.rs),
[validation.rs:82-94](poly-chain/src/validation.rs).
`verify_proof` returns `Ok(cfg!(any(test, feature = "mock")))` for
`VerifiedProof::Mock`, and `verify_signature_if_not_mock` /
`verify_proof_if_not_mock` short-circuit to `Ok(true)` under
`cfg(any(test, feature = "mock"))`. A `mock` feature is a normal, unification-prone
Cargo feature: if *any* crate in the workspace (or a downstream consumer) enables
`poly-chain/mock`, every production build of `poly-chain` linked in that graph
**silently disables all signature and proof verification**. Combined with C1 this
means total loss of ledger integrity.
*Why it matters:* feature unification makes this a realistic supply-chain /
build-configuration foot-gun, not just a test convenience.
*Suggested fix:* gate the bypass on `cfg(test)` only, or on a deliberately
ugly, non-default feature name that can never be enabled transitively (and add a
`compile_error!` if it is set together with a `production` feature).

**C3 — `CheckDeadline` recomputes investigation deadlines from the wrong base,
so the 30-day slash window is mis-timed.**
[poly-chain/src/validation.rs:1266-1318](poly-chain/src/validation.rs) with
[poly-chain/src/stp.rs:103-113](poly-chain/src/stp.rs).
`CheckDeadline` reconstructs the record with
`InvestigationRecord::new(*investigation_id, target, pool_threshold_reached)`
and then overwrites only `record.status`. But `InvestigationRecord::new`
derives `final_deadline = pool_threshold_reached + 72h + 30d`
([stp.rs:110](poly-chain/src/stp.rs)). The packed state stores
`frozen_at` as the status timestamp, yet that value is **never fed back into
`final_deadline`**. `check_investigation_deadlines` then compares `now` against
`pool_threshold_reached + 72h + 30d` instead of `frozen_at + 30d`
([stp.rs:176](poly-chain/src/stp.rs)). If the account was frozen *late* (a
`CheckDeadline` submitted long after the 72h mark), the slash can fire **before
30 days of frozen time have actually elapsed** — the doc comment for
`InvestigationStatus::Slashed` explicitly says "freeze + 30d".
*Why it matters:* an enforcement deadline that does not match the documented
policy is a soundness bug in the accountability mechanism — an official can be
slashed early, or (symmetrically) escape slashing.
*Suggested fix:* compute `final_deadline` from the `frozen_at` timestamp stored
in the packed status, not from `pool_threshold_reached`.

### High

**H1 — No block-level transaction validation; `validate_against_parent` does not
verify any proof or apply state.**
[poly-chain/src/block.rs:134-178](poly-chain/src/block.rs).
`Block` validation checks only structural integrity (height, parent hash,
timestamp ordering, tx-count, Merkle root). It never calls
`validate_transaction`, never threads `GlobalState`, and never checks that the
header's `state_root` equals the state produced by applying the block's
transactions. A block whose `state_root` is arbitrary still passes
`validate_against_parent`.
*Why it matters:* a consumer that trusts `validate_against_parent` as "the block
is valid" accepts blocks with forged state roots and unverified transactions.
*Suggested fix:* add a `Block::apply(&self, &GlobalState) -> Result<GlobalState>`
that iterates transactions through `validate_transaction` and asserts the
resulting `state_root()` matches `header.state_root`.

**H2 — Transaction hashing and several proof I/O bindings use `serde_json`,
which is not a canonical encoding.**
[poly-chain/src/transaction.rs:44-50](poly-chain/src/transaction.rs);
[validation.rs:208-210](poly-chain/src/validation.rs),
[validation.rs:979-981](poly-chain/src/validation.rs),
[validation.rs:1020-1022](poly-chain/src/validation.rs).
`tx_hash()` is `H(DOMAIN || serde_json::to_vec(self))`. JSON is not a canonical
serialization: object key ordering for struct fields *is* stable in serde, but
JSON permits whitespace/escaping variants and, more importantly, JSON cannot
round-trip every byte pattern losslessly. The crate elsewhere went to great
lengths to reject non-canonical fixed-layout encodings (`R9`/`R10` "trailing
garbage" checks in block.rs, identity.rs, wallet.rs) — yet the *transaction
identity itself* depends on a non-canonical encoder. The same `serde_json`
bytes feed the fraud-evidence hash and STP-action proof binding.
*Why it matters:* inconsistent with the crate's own canonicalization discipline;
makes `tx_hash` (a Merkle leaf and de-facto transaction ID) depend on serde_json
implementation details rather than a spec.
*Suggested fix:* hash a hand-written, length-prefixed canonical byte encoding of
each transaction (the crate already has `to_bytes` for most other types).

**H3 — Signing messages omit fields that proof I/O hashes include — the two
authenticated views of a transaction disagree.**
[poly-chain/src/validation.rs:248-273](poly-chain/src/validation.rs).
`atomic_swap_claim_signing_message` and `atomic_swap_refund_signing_message`
cover the `original_*` fields, but the *proof* input for a claim binds
`(swap_id, claimer, secret)` and the output binds `(swap_id, original_hash_lock)`
([validation.rs:1577-1584](poly-chain/src/validation.rs)) — `secret` is signed
in neither message (it is not in the claim signing message either). For
`AtomicSwapInit`, the signing message includes `disclosure_root` but **not**
`execution_proof` ([validation.rs:225-246](poly-chain/src/validation.rs)), so
`execution_proof` is entirely unauthenticated — a relayer can strip or swap it.
*Why it matters:* fields that are neither signed nor proof-bound are
attacker-malleable; a third party can mutate them while the transaction still
validates.
*Suggested fix:* make the signing message a strict superset of every
semantically meaningful field, and assert that the set of signed fields equals
the set of proof-bound fields per transaction type.

**H4 — `from_bytes` decoders index fixed offsets after a single length check,
relying on it for *every* subsequent slice.**
[poly-chain/src/wallet.rs:77-133](poly-chain/src/wallet.rs),
[poly-chain/src/identity.rs:95-147](poly-chain/src/identity.rs),
[poly-chain/src/block.rs:38-70](poly-chain/src/block.rs).
These decoders check one minimum length, then perform many `data[a..b]` slices
and `.try_into().unwrap()`. For `block.rs`/`wallet.rs`/`identity.rs` the initial
checks do cover the indices used, so today they do not panic — but the pattern
is fragile: any future field addition that updates the struct but not the length
guard converts a malformed input into a panic. `identity.rs:109` reads
`office_len` as `u32 as usize`; on a 32-bit target `80 + office_len` in the
`data.len() < 80 + office_len` check ([identity.rs:111](poly-chain/src/identity.rs))
can overflow `usize` for `office_len` near `u32::MAX`, wrapping the bound and
admitting a truncated buffer.
*Why it matters:* decoders run on fully untrusted bytes; a panic is a DoS and an
overflow-wrapped bound is a memory-safety-adjacent parsing bug.
*Suggested fix:* use `checked_add` for all computed offsets, and prefer a cursor
helper that returns `Result` on every read.

**H5 — `SparseMerkleTree` is a sorted-list commitment and provides no real
inclusion/exclusion proofs.**
[poly-chain/src/state.rs:166-201](poly-chain/src/state.rs),
[state.rs:210-216](poly-chain/src/state.rs).
The doc comment is candid that this is "a sorted-list commitment rather than a
full sparse Merkle tree". `SmtProof` is declared but no `prove`/`verify` methods
exist. Consequently a light client cannot be given a succinct proof that an
account *is* or *is not* in the state; verification requires the entire leaf
set. `recompute_root` also rebuilds the whole Merkle tree on **every** `set`
([state.rs:152](poly-chain/src/state.rs)) — O(n) per mutation, O(n²) to apply a
block.
*Why it matters:* "verify-only blockchain" implies light verification; without
membership proofs the state model cannot support it, and the per-mutation
rebuild does not scale.
*Suggested fix:* implement a real sparse Merkle tree (or an incremental Merkle
structure) with inclusion/exclusion proofs and incremental root updates.

### Medium

**M1 — `CashTransfer` sender-tier check is effectively a no-op when an identity
exists.** [poly-chain/src/validation.rs:413-429](poly-chain/src/validation.rs).
The `if let Some(_identity_hash) = state.get_identity(&tx.from)` branch contains
only comments — it does *nothing*. The intended invariant ("tx `sender_tier`
must not exceed the registered tier") is unenforced: a registered Anonymous user
can self-attest `PublicOfficial` to get a lower reporting threshold... actually
to get a *different* threshold, evading single-transfer reports. The code
comment admits "we can't recover the tier from the hash alone".
*Why it matters:* compliance-threshold evasion for any account that has *any*
identity registered.
*Suggested fix:* store the tier (or full `IdentityRecord`) on-chain in a form
the validator can read, and assert `tx.sender_tier == registered_tier`.

**M2 — `validate_against_parent` enforces only non-decreasing timestamps, with
no upper bound vs. wall clock.** [poly-chain/src/block.rs:154-157](poly-chain/src/block.rs).
A block timestamp far in the future is accepted as long as it is `>=` the
parent's. Transactions inside have a ±300s drift check
([validation.rs:97-110](poly-chain/src/validation.rs)) but the *block header*
does not. A future-dated block can be used to prematurely cross STP/swap
deadlines that key off `now`.
*Suggested fix:* pass a wall-clock `now` into `validate_against_parent` and
reject `header.timestamp > now + MAX_DRIFT`.

**M3 — Fraud detection only catches same-nonce double-spends; the documented
"state went backwards" check is unimplemented.**
[poly-chain/src/fraud.rs:88-94](poly-chain/src/fraud.rs).
`detect_conflict` has a comment block describing a nonce-ordering inconsistency
check and then does nothing ("For now, the simple double-spend check is
sufficient"). `ConflictType::StateInconsistency` therefore can never be produced
by `detect_conflict`, yet `validate_fraud_proof` requires the claimed
`conflict_type` to *equal* the detected one
([validation.rs:922](poly-chain/src/validation.rs)) — so a legitimate
`StateInconsistency` fraud proof is unprovable.
*Suggested fix:* either implement the inconsistency check or remove the
`StateInconsistency` variant so the type system reflects reality.

**M4 — Fraud-proof burn destroys the wallet but never pays the
`fraud_proof_reward`, and never credits the submitter.**
[poly-chain/src/validation.rs:988-994](poly-chain/src/validation.rs),
[fee.rs:21-23](poly-chain/src/fee.rs).
`FeeSchedule::fraud_proof_reward()` exists and `fee_payer` returns `None`
("fraud proofs are free (rewarded)"), but `validate_fraud_proof` only calls
`remove_wallet` and records evidence — the reward is never transferred to
`tx.submitter`. The incentive the design relies on does not exist.
*Suggested fix:* credit the submitter (this also depends on fixing C1's lack of
real balances).

**M5 — `IdentityRecord.registered_at` is hard-coded to `0`.**
[poly-chain/src/validation.rs:726](poly-chain/src/validation.rs).
The comment says "filled by block timestamp" but `validate_identity_register`
takes `_now: Timestamp` (unused) and stores `registered_at: 0`. The record hash
committed on-chain therefore carries a meaningless timestamp.
*Suggested fix:* thread `now` (or block timestamp) into the record.

**M6 — `validate_identity_register` ignores its `_now` parameter and creates
wallets with timestamp `0`.** [poly-chain/src/validation.rs:737](poly-chain/src/validation.rs).
`WalletState::new(tx.identity_hash, tx.tier, 0)` sets `rolling_reset_at = 0 +
SECONDS_24H`, i.e. a rolling window that "resets" at a fixed past time — the
first transfer always sees an already-expired window. Minor, but it makes the
anti-structuring window meaningless for freshly created wallets.
*Suggested fix:* use the real block timestamp.

### Low

**L1 — `Block::new` panics on height overflow.**
[poly-chain/src/block.rs:116-124](poly-chain/src/block.rs). Documented, and a
fallible `try_new` exists, but a panicking constructor on a chain type is a
latent DoS if reached with untrusted input. Prefer making `try_new` the only
public constructor.

**L2 — `tx_hash` / signing-message constructors `expect` on serialization.**
[transaction.rs:48](poly-chain/src/transaction.rs),
[validation.rs:209](poly-chain/src/validation.rs). `serde_json::to_vec` of a
plain enum will not fail in practice, but an `expect` inside a hot path that
processes untrusted transactions is worth replacing with explicit error
propagation for defense in depth.

**L3 — `compute_transactions_root` returns `ZERO_HASH` for an empty block, the
same sentinel used for "no value" across the SMT layer.**
[block.rs:82-89](poly-chain/src/block.rs). Not exploitable on its own, but
overloading `ZERO_HASH` as both "empty" and "deleted" everywhere increases the
chance a future change confuses the two. Consider a distinct empty-marker.

**L4 — Inconsistent domain separation for composite hashes.**
[state.rs:286](poly-chain/src/state.rs), [state.rs:301](poly-chain/src/state.rs).
`state_root()` and `nonces_hash()` both use `DOMAIN_BLOCK`, the same domain as
`BlockHeader::block_hash()` ([block.rs:24](poly-chain/src/block.rs)). Three
structurally different objects share one domain byte; a dedicated
`DOMAIN_STATE_ROOT` / `DOMAIN_NONCES` would preserve the separation discipline
the rest of the crate follows.

**L5 — `STPAction::ProvideData` does not transition the investigation status to
`DataProvided`.** [poly-chain/src/validation.rs:1198-1242](poly-chain/src/validation.rs).
It writes the data hash under a side key but leaves the packed status as
`AwaitingData`; `CheckDeadline` then infers cooperation by probing for that side
key ([validation.rs:1277-1285](poly-chain/src/validation.rs)). It works, but the
`DataProvided` status variant is dead, and the investigation's own record never
reflects that data was provided. Consider transitioning the status directly.

## Strengths

- **Disciplined, traceable hardening history.** Almost every defensive check
  carries an `R<n>` rationale comment explaining the attack it prevents. This is
  excellent for auditability and shows real adversarial review.
- **Solid replay protection at the nonce layer.** `validate_nonce`
  ([validation.rs:114](poly-chain/src/validation.rs)) requires exact nonce
  equality, uses `checked_add` to refuse wraparound, and the nonce map is
  committed into `state_root` (the documented R11 fix).
- **Correct strict signature verification.** `verify_strict`
  ([validation.rs:64](poly-chain/src/validation.rs)) is the right choice and the
  comment correctly explains the malleability vector.
- **Consistent domain separation** for the bulk of hashing, including the
  leaf/interior fix (`DOMAIN_SMT_LEAF`) and length-prefixed
  `derive_identity_hash` that defeats concatenation collisions.
- **Canonical fixed-layout decoders** for headers/records/wallets reject
  trailing garbage (R9/R10), preventing non-canonical re-encodings.
- **Overflow-aware arithmetic** in most timestamp/deadline math
  (`saturating_add`, `checked_add` for block height and nonces).
- **Good unit-test coverage** of each module's happy path and several
  adversarial cases.
- **Clean module boundaries** — error, primitives, and per-domain modules are
  cohesive and the `prelude` gives a tidy public surface.

## Recommendations

Prioritized, actionable:

1. **Make value soundness verifiable on-chain (C1).** Store balances (or a
   recomputable balance commitment) in state and assert
   `new = old - amount - fee` inside `validate_cash_transfer` and the swap
   validators. Without this the ledger has no independent notion of "enough
   funds".
2. **Eliminate the `mock` feature production bypass (C2).** Gate proof/signature
   skipping on `cfg(test)` only, or behind a feature that cannot be enabled by
   transitive unification; add `compile_error!` guarding against a
   `production`+`mock` combination.
3. **Fix the STP slash-deadline base (C3).** Derive `final_deadline` from the
   stored `frozen_at`, not `pool_threshold_reached`.
4. **Add a real block-apply path (H1).** A `Block::apply` that runs every
   transaction through `validate_transaction` and checks the resulting
   `state_root` against the header — the chain currently has no enforced link
   between a block and the state it claims.
5. **Replace `serde_json`-based hashing with canonical byte encodings (H2).**
   Transaction IDs and proof bindings should not depend on a non-canonical
   encoder, especially given the crate's own canonicalization discipline
   elsewhere.
6. **Unify signed and proof-bound field sets per transaction type (H3).** Audit
   each signing message against its proof I/O hash; ensure no semantically
   meaningful field (`secret`, `execution_proof`, `state_pre`, fee, etc.) is
   left unauthenticated.
7. **Harden decoders (H4).** Use `checked_add` for every computed offset and a
   cursor abstraction that returns `Result` per read; add fuzz tests for all
   `from_bytes`.
8. **Implement a proper sparse Merkle tree with inclusion/exclusion proofs and
   incremental roots (H5)** — a prerequisite for genuine light-client
   verification and for blocks larger than a handful of transactions.
9. **Enforce on-chain tier consistency (M1)** and **pay the fraud reward (M4)**
   — both make documented mechanisms actually function.
10. **Tidy correctness gaps:** thread real timestamps into identity/wallet
    creation (M5/M6), bound block timestamps against wall clock (M2), and either
    implement or remove `ConflictType::StateInconsistency` and the
    `DataProvided` status (M3/L5).
