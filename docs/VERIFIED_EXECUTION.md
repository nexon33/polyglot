# Verified Execution

> Compiler-integrated provable computation for the Poly language.

## Overview

Mark a function `#[verified]`. The compiler does the rest. Every result carries a mathematical proof that it was computed correctly.

```poly
#[rust] {
    use poly_verified::prelude::*;
    use polyglot_macros::verified;

    #[verified]
    fn add_scores(a: u64, b: u64) -> u64 {
        a.saturating_add(b)
    }

    fn main() {
        let result = add_scores(42, 58);
        println!("Value: {}", result.value());         // 100
        println!("Verified: {}", result.is_verified()); // true
        println!("Backend: {:?}", result.proof().backend_id()); // HashIvc
    }
}
```

## How It Works

1. **Compile time:** The determinism checker scans `#[verified]` function bodies and rejects non-deterministic operations (floats, IO, unsafe, randomness, etc.)

2. **Macro expansion:** The `#[verified]` proc macro wraps the function body in an IVC (Incrementally Verifiable Computation) accumulator lifecycle:
   - Hash the function identity (code hash)
   - Hash all inputs
   - Execute the original function body
   - Hash the output
   - Fold a step witness into the accumulator
   - Finalize into a `VerifiedProof`
   - Wrap the result in `Verified<T>`

3. **Runtime:** The function returns `Verified<T>` instead of `T`. The proof can be inspected, serialized, and transmitted.

## Core Types

### `Verified<T>`

An opaque wrapper that pairs a value with its proof. Cannot be constructed outside the `poly-verified` crate (`new_proven` is `pub(crate)`).

```rust
let result: Verified<u64> = add_scores(42, 58);

result.value()            // &u64 — borrow the value
result.unwrap_verified()  // u64 — consume and get the value
result.proof()            // &VerifiedProof — the cryptographic proof
result.is_verified()      // bool — structural validity check

// Transform the inner value
let doubled = result.map(|v| v * 2);

// Flatten nested verified values
let nested: Verified<Verified<u64>> = ...;
let flat: Verified<u64> = nested.flatten();
```

### `VerifiedProof`

The proof attached to a `Verified<T>`:

```rust
pub enum VerifiedProof {
    HashIvc {
        chain_tip: Hash,      // Final hash chain state
        merkle_root: Hash,    // Merkle root of all checkpoints
        step_count: u64,      // Number of fold steps
        code_hash: Hash,      // Hash of the function identity
    },
    Mock {
        input_hash: Hash,
        output_hash: Hash,
    },
}
```

### `FixedPoint`

Deterministic fixed-point arithmetic (i128 with 48 fractional bits). Use this instead of `f32`/`f64` in verified functions.

```rust
use poly_verified::fixed_point::FixedPoint;

let a = FixedPoint::from_int(3);
let b = FixedPoint::from_decimal(14, 2);  // 0.14
let pi_approx = a + b;                    // 3.14

let result = pi_approx * FixedPoint::from_int(2);
println!("{}", result);  // 6.280000000000000
```

### `VerifiedError`

Proven computation failures:

```rust
pub enum VerifiedError {
    DivisionByZero,
    Overflow,
    BoundExceeded { max: u64, actual: u64 },
    AssertionFailed(String),
    InvalidInput(String),
    GpuMismatch(usize),
}
```

Use with `Verified<Result<T, VerifiedError>>` for functions that can fail provably.

## Macros

### `#[verified]`

Attribute macro that transforms a function for verified execution.

```rust
#[verified]
fn compute(x: u64) -> u64 {
    x.saturating_mul(2)
}
// Return type becomes Verified<u64>
```

**Backend selection:**
```rust
#[verified]         // Uses HashIvc (default, quantum-resistant)
#[verified(mock)]   // Uses MockIvc (for testing)
```

### `#[pure]`

Marks a helper function as pure (no side effects). Pure functions can be called from `#[verified]` functions without generating their own proof.

```rust
#[pure]
fn double(x: u64) -> u64 {
    x * 2
}
```

Compile-time checks reject:
- IO, networking, filesystem access
- Console output (`println!`, `eprintln!`)
- Thread/task spawning
- Unsafe code

### `fold!(expr)`

Creates an explicit fold checkpoint. The expression's value is hashed and can be used by the enclosing IVC accumulator.

```rust
#[verified]
fn batch_sum(data: Vec<u64>) -> u64 {
    let mut sum = 0u64;
    for chunk in data.chunks(32) {
        sum += chunk.iter().sum::<u64>();
        fold!(sum);  // Checkpoint after each batch
    }
    sum
}
```

## Determinism Rules

The compiler enforces determinism in `#[verified]` functions with error codes V001-V015:

| Code | Rule | Example violation |
|------|------|-------------------|
| V001 | No IO/net/random | `std::fs::read()`, `rand::thread_rng()` |
| V002 | No floating point | `let x: f64 = 3.14;` |
| V003 | Bounded loops | `loop { ... }` without bound |
| V005 | No unsafe/raw ptrs | `unsafe { }`, `*const T` |
| V006 | Deterministic iteration | `HashMap::iter()` |
| V007 | No global mut state | `static mut X: i32 = 0;` |
| V008 | No interior mutability | `Cell<T>`, `RefCell<T>`, `Mutex<T>` |
| V009 | No system time | `SystemTime::now()` |
| V010 | No env variables | `std::env::var("KEY")` |
| V011 | No thread spawning | `std::thread::spawn()` |
| V013 | No inline assembly | `asm!()` |
| V014 | No process spawning | `Command::new()` |

**Allowed alternatives:**
- `f64` → `FixedPoint` (deterministic arithmetic)
- `HashMap` → `BTreeMap` (deterministic iteration)
- `rand` → deterministic seed-based PRNG
- `SystemTime` → pass time as function parameter

## IVC Backends

### Hash-IVC (default)

Quantum-resistant backend using SHA-256 hash chains and Merkle trees.

- **Fold:** `hash_transition(state_before, inputs, state_after)` appended to chain
- **Finalize:** Builds Merkle tree from checkpoints, returns chain tip + root
- **Verify:** Structural integrity check of chain and tree

```toml
# poly.toml
[verified]
backend = "hash-ivc"
```

### Mock (testing)

Always-valid proofs. Use for development and testing.

```toml
[verified]
backend = "mock"
```

Or per-function:
```rust
#[verified(mock)]
fn test_fn(x: u64) -> u64 { x + 1 }
```

## Proof Serialization

Proofs can be serialized for network transmission using the wire format:

```
value_hash(32) | input_hash(32) | code_hash(32) | proof_scheme(1) |
proof_length(4) | proof_bytes(N) | verifier_key_hash(32) | value_bytes(M)
```

```rust
use poly_verified::proof_serialize::VerifiedResponse;

let response = VerifiedResponse::new(
    &value_hash, &input_hash, &code_hash,
    BackendId::HashIvc, &proof_bytes,
    &verifier_key_hash, &value_bytes,
);

let wire_bytes = response.to_bytes();
let decoded = VerifiedResponse::from_bytes(&wire_bytes)?;
assert!(decoded.verify_value_integrity(&value_bytes));
```

## Proof Composition

When `#[verified]` functions call other `#[verified]` functions, proofs compose:

```rust
use poly_verified::proof_composition::CompositeProof;

let composite = CompositeProof::compose(outer_proof, vec![inner_proof_1, inner_proof_2]);
assert!(composite.verify_composition());
```

## poly.toml Configuration

```toml
[verified]
backend = "hash-ivc"    # IVC backend: "hash-ivc" or "mock"
fold_interval = 32       # Auto-fold every N operations
```

## Crate Structure

The `poly-verified` crate provides the runtime:

| Module | Purpose |
|--------|---------|
| `crypto::hash` | Domain-separated SHA-256 (4 domains) |
| `crypto::merkle` | Merkle tree + inclusion proofs |
| `crypto::chain` | Hash chain accumulator |
| `crypto::commitment` | Commitment signing/verification |
| `crypto::signing` | Ed25519 code attestation |
| `types` | Hash, Commitment, VerifiedProof, StepWitness |
| `error` | ProofSystemError, VerifiedError |
| `verified_type` | `Verified<T>` wrapper |
| `fixed_point` | Deterministic FixedPoint arithmetic |
| `ivc` | IvcBackend trait + implementations |
| `proof_serialize` | Wire format for proof transmission |
| `proof_composition` | Composite proofs for nested calls |
