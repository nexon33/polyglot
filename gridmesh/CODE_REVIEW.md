# gridmesh — Documentation & Code Review

## Overview

`gridmesh` is a small, dependency-free crate (`gridmesh/Cargo.toml` declares no
external dependencies, deliberately kept lightweight for WebAssembly) that
provides a **cross-language tensor handle** for the *pyrs polyglot* toolchain.

It models a tensor as a `#[repr(C)]` header struct ([gridmesh/src/header.rs](gridmesh/src/header.rs))
plus separately-allocated data and shape buffers. The header carries an
ARC-style reference count and a single-word borrow state, so a tensor can be
safely shared and borrowed across language boundaries that all operate on one
shared linear-memory address space (the WASM "shared-nothing-but-linear-memory"
model described in the comments of [gridmesh/src/tensor.rs](gridmesh/src/tensor.rs#L21)).

It is consumed by the workspace root crate — `lib.rs` and `module.rs` both
contain `use gridmesh::tensor::Tensor;` — and is a declared dependency of the
root `Cargo.toml` and of `poly-lsp`. The `#[types]` polyglot syntax surfaces it
to users as the canonical mapping `rust:gridmesh::Tensor<f32> | python:gridmesh.Tensor`
(see `poly-lsp/src/main.rs:670`), i.e. the type a Python block and a Rust block
agree on when they pass tensors to each other.

## Architecture

A `Tensor<T>` is a thin owning handle: it holds a single raw pointer to a
heap-allocated `TensorHeader`. The header in turn holds **integer addresses**
(`u32`) of the data buffer and the shape buffer, which are allocated separately.
Reference counting governs the header's lifetime; the borrow state enforces
Rust-style aliasing rules dynamically at runtime.

```
   Tensor<T>                    TensorHeader (#[repr(C)], heap)
  +-----------+                +-------------------------------+
  | header ---+--------------> | ref_count   : AtomicU32       |
  | _marker   |                | borrow_state: AtomicU32       |
  +-----------+                | data_ptr    : u32  --------+  |
        ^                      | data_len    : u32          |  |
        |                      | shape_ptr   : u32  -----+  |  |
   Clone bumps                 | ndim        : u32       |  |  |
   ref_count                   | dtype, flags: u32       |  |  |
                               +-------------------------+--+--+
                                                         |  |
                            shape buffer (Vec<u32>) <----+  |
                            [d0, d1, ... d(ndim-1)]         |
                                                            |
                            data buffer (Vec<T>)  <---------+
                            [ total = product(shape) elems ]

  Borrow state machine (borrow_state word):
      0            = free
      1 .. MAX-1   = N shared (immutable) borrows
      u32::MAX     = exclusive (mutable) borrow   [EXCLUSIVE_BORROW]

  RAII guards:
      Tensor::borrow()      -> TensorRef     (Drop -> unborrow)
      Tensor::borrow_mut()  -> TensorRefMut  (Drop -> unborrow_mut)
```

Three allocations back one live tensor (header, data, shape). When the
reference count reaches zero, `Drop` is expected to free all three via
`wasm_free`.

## Module Reference

### [gridmesh/src/lib.rs](gridmesh/src/lib.rs)

Crate root. Two lines: re-declares `pub mod header;` and `pub mod tensor;`. No
crate-level docs.

### [gridmesh/src/header.rs](gridmesh/src/header.rs)

Responsibility: the `#[repr(C)]` memory layout and the atomic safety
primitives (reference counting + borrow state machine).

Key public items:
- `TensorHeader` ([gridmesh/src/header.rs:4](gridmesh/src/header.rs#L4)) — the
  C-layout struct. Comment marks the two atomic safety fields as "must be
  first".
- `BorrowError` ([gridmesh/src/header.rs:18](gridmesh/src/header.rs#L18)) —
  `AlreadyMutablyBorrowed | AlreadyImmutablyBorrowed | TooManyBorrows`.
- `TensorHeader::EXCLUSIVE_BORROW` ([gridmesh/src/header.rs:26](gridmesh/src/header.rs#L26))
  — the `u32::MAX` sentinel for an exclusive borrow.
- `retain` / `release` ([gridmesh/src/header.rs:29](gridmesh/src/header.rs#L29),
  [:37](gridmesh/src/header.rs#L37)) — `SeqCst` ref-count inc/dec; `release`
  returns `true` when the count drops to zero.
- `try_borrow` / `unborrow` ([gridmesh/src/header.rs:46](gridmesh/src/header.rs#L46),
  [:78](gridmesh/src/header.rs#L78)) — CAS loop to acquire a shared borrow, and
  `fetch_sub` to release one.
- `try_borrow_mut` / `unborrow_mut` ([gridmesh/src/header.rs:84](gridmesh/src/header.rs#L84),
  [:103](gridmesh/src/header.rs#L103)) — CAS `0 -> EXCLUSIVE_BORROW`, and
  `swap(0)` to release.

### [gridmesh/src/tensor.rs](gridmesh/src/tensor.rs)

Responsibility: the safe(-ish) Rust handle `Tensor<T>`, allocation/construction,
RAII borrow guards, and deallocation.

Key public items:
- `TensorElement` ([gridmesh/src/tensor.rs:5](gridmesh/src/tensor.rs#L5)) —
  marker trait, implemented for `f64, f32, i64, i32, u64, u32, u8`.
- `Tensor<T>` ([gridmesh/src/tensor.rs:16](gridmesh/src/tensor.rs#L16)) — owning
  handle wrapping `*mut TensorHeader`.
- `Tensor::from_raw` ([gridmesh/src/tensor.rs:55](gridmesh/src/tensor.rs#L55)) —
  `unsafe`; wraps an existing header pointer and `retain`s it.
- `Tensor::zeros` ([gridmesh/src/tensor.rs:64](gridmesh/src/tensor.rs#L64)) —
  allocates data + shape + header for a zero-filled tensor.
- `Tensor::borrow` / `borrow_mut` ([gridmesh/src/tensor.rs:100](gridmesh/src/tensor.rs#L100),
  [:108](gridmesh/src/tensor.rs#L108)) — return RAII guards.
- `Tensor::shape` ([gridmesh/src/tensor.rs:115](gridmesh/src/tensor.rs#L115)) —
  reconstructs a `Vec<usize>` from the raw shape buffer.
- `Drop for Tensor<T>` ([gridmesh/src/tensor.rs:126](gridmesh/src/tensor.rs#L126))
  and `Clone for Tensor<T>` ([gridmesh/src/tensor.rs:147](gridmesh/src/tensor.rs#L147)).
- `TensorRef` / `TensorRefMut` ([gridmesh/src/tensor.rs:160](gridmesh/src/tensor.rs#L160),
  [:183](gridmesh/src/tensor.rs#L183)) — borrow guards exposing `as_slice` /
  `as_mut_slice`.
- `wasm_free` ([gridmesh/src/tensor.rs:39](gridmesh/src/tensor.rs#L39)) —
  `unsafe` deallocation stub (currently a no-op).

## Code Review

### Critical

**C1 — `wasm_free` is a no-op, so dropping any tensor leaks all three allocations.**
Location: [gridmesh/src/tensor.rs:39](gridmesh/src/tensor.rs#L39), used at
[gridmesh/src/tensor.rs:132](gridmesh/src/tensor.rs#L132)-[134](gridmesh/src/tensor.rs#L134).
`wasm_free` only contains commented-out code; its body does nothing when
`ptr != 0`. For tensors created by `Tensor::zeros`, the data and shape buffers
are produced by `Vec` + `std::mem::forget` ([:74](gridmesh/src/tensor.rs#L74),
[:79](gridmesh/src/tensor.rs#L79)) and the header by `Box::into_raw`
([:94](gridmesh/src/tensor.rs#L94)). On drop, `release()` returns `true` but
nothing is reclaimed — every `Tensor::zeros` permanently leaks heap memory.
Why it matters: a tensor library that never frees memory is unusable in any
long-running process. Suggested fix: for `zeros`-created tensors, reconstruct
the `Vec<T>` / `Vec<u32>` with `Vec::from_raw_parts` and `drop` them, and free
the header with `Box::from_raw`. For externally-supplied headers (`from_raw`),
free via the agreed host allocator. The two ownership origins must be tracked
(see H3).

**C2 — `Tensor::zeros` frees with the wrong allocator / wrong layout.**
Location: [gridmesh/src/tensor.rs:64](gridmesh/src/tensor.rs#L64) vs
[gridmesh/src/tensor.rs:126](gridmesh/src/tensor.rs#L126).
Even if `wasm_free` were implemented as a generic C `free(void*)`, it would be
**undefined behavior**: `zeros` allocates via Rust's global allocator
(`Vec`/`Box`), but `Drop` routes deallocation through `wasm_free`, which the
comments describe as a linked C `free`. Rust's allocator and C's `free` are not
interchangeable, and `Box`/`Vec` deallocation requires the original `Layout`,
which a `void*`-style `free` does not have. Why it matters: allocator mismatch
is immediate UB (heap corruption). Suggested fix: make deallocation symmetric
with allocation — track whether a tensor owns Rust-allocated buffers and, if so,
deallocate with `Vec::from_raw_parts` / `Box::from_raw` rather than `wasm_free`.

**C3 — `as_mut_slice` derives a `&mut [T]` from a `*const` header through a shared reference.**
Location: [gridmesh/src/tensor.rs:196](gridmesh/src/tensor.rs#L196)-[202](gridmesh/src/tensor.rs#L202).
`TensorRefMut::as_mut_slice` does `let header = &*self.tensor.header;` (a shared
`&TensorHeader`) and then casts `header.data_ptr as *mut T` to build a mutable
slice. Producing a `&mut [T]` whose provenance traces back through a `&T` is
unsound under stacked/tree-borrows aliasing rules. The borrow guard mechanism
prevents *logical* aliasing, but the pointer-provenance chain is still invalid.
Why it matters: latent UB that can miscompile under optimization. Suggested
fix: keep the data pointer as a raw `*mut TensorHeader` access path
(`(*self.tensor.header).data_ptr`) and never narrow it to `&TensorHeader`
before forming the `&mut` slice; ideally store the data pointer with `mut`
provenance from the start.

### High

**H1 — `try_borrow_mut` can grant an exclusive borrow while shared borrows still exist.**
Location: [gridmesh/src/header.rs:84](gridmesh/src/header.rs#L84).
`try_borrow_mut` does `compare_exchange(0, EXCLUSIVE_BORROW, ...)`. That is
correct *only* because it requires state `0`. However, there is no symmetric
guarantee in the reverse direction within a multi-step sequence: this is fine
in isolation, but combined with H2 the borrow machine has no overflow-safe
upper edge. The real high-severity issue is the **shared/exclusive collision
the round-42 fix only partially addressed** — see H2.

**H2 — Borrow-state overflow check, while fixed, still has a fragile invariant.**
Location: [gridmesh/src/header.rs:54](gridmesh/src/header.rs#L54)-[64](gridmesh/src/header.rs#L64).
The round-42 fix (commit "gridmesh shared-borrow count collides with sentinel")
is present and correct: `try_borrow` now rejects any increment whose result
would reach `EXCLUSIVE_BORROW` (`if new_state >= Self::EXCLUSIVE_BORROW`), and
the attack tests in
[gridmesh/tests/r42_pentest_attack_tests.rs](gridmesh/tests/r42_pentest_attack_tests.rs)
verify it. However the `checked_add` on line 54 is now dead defensive code —
the subsequent `>=` check makes it unreachable, since `state` can never exceed
`EXCLUSIVE_BORROW`. More importantly, the *invariant* "`borrow_state` is always
`0..=MAX-1` or exactly `MAX`" is enforced only by `try_borrow`; `unborrow`
([:78](gridmesh/src/header.rs#L78)) blindly does `fetch_sub(1)` with only a
`debug_assert`. In a release build, calling `unborrow` on a free (`0`) header
underflows to `u32::MAX`, **silently fabricating an exclusive borrow**. Why it
matters: a single misuse permanently wedges the tensor as "mutably borrowed".
Suggested fix: replace the `debug_assert` in `unborrow`/`unborrow_mut` with a
checked CAS loop (or at minimum `debug_assert` plus a release-mode saturating
guard), and simplify `try_borrow` to a single explicit bound check.

**H3 — `Tensor` cannot distinguish Rust-owned vs. externally-owned headers.**
Location: [gridmesh/src/tensor.rs:55](gridmesh/src/tensor.rs#L55) vs
[:64](gridmesh/src/tensor.rs#L64), freed uniformly at
[:126](gridmesh/src/tensor.rs#L126).
`from_raw` wraps a header allocated by *another* language; `zeros` allocates a
header with `Box`. Both are dropped through the identical `wasm_free` path. A
correct implementation must free a `Box`-allocated header with `Box::from_raw`
and a foreign header with the foreign allocator — they are not interchangeable.
Why it matters: prerequisite for fixing C1/C2 correctly. Suggested fix: add an
ownership flag (e.g. a bit in `TensorHeader::flags`, or a field on `Tensor`)
recording the allocation origin, and branch in `Drop`.

**H4 — `Tensor<T>` is `Send`/`Sync` by accident, but is not thread-safe.**
Location: [gridmesh/src/tensor.rs:16](gridmesh/src/tensor.rs#L16).
`Tensor<T>` holds a raw pointer, so it is *not* auto-`Send`/`Sync` — good. But
the header's fields are `AtomicU32`, and the comments describe cross-boundary
sharing. If a future change adds `unsafe impl Send`/`Sync`, the data buffer
access (`as_slice`/`as_mut_slice`) is **not** synchronized — only the borrow
*counter* is atomic, not the data. Why it matters: an easy future foot-gun.
Suggested fix: document explicitly that `Tensor` is single-threaded-only, or
that the `SeqCst` borrow operations are the sole synchronization point and data
races on payload bytes remain the caller's responsibility.

### Medium

**M1 — `release()` panics on double-free instead of being defensive.**
Location: [gridmesh/src/header.rs:37](gridmesh/src/header.rs#L37)-[43](gridmesh/src/header.rs#L43).
`release` does `fetch_sub(1)` first, then checks `if old == 0 { panic! }`. The
decrement has already happened — on a genuine double-free the count has already
wrapped to `u32::MAX` before the panic, so the panic message is accurate but the
state is corrupt. A panic across a WASM/FFI boundary is also itself UB unless
the boundary is `catch_unwind`-guarded. Why it matters: turns a logic bug into
an FFI safety violation. Suggested fix: check-then-decrement with a CAS loop,
or `fetch_update`, so the count is never transiently corrupted.

**M2 — `Tensor::shape` ignores the borrow state.**
Location: [gridmesh/src/tensor.rs:115](gridmesh/src/tensor.rs#L115).
`shape()` reads `shape_ptr` directly without acquiring a borrow. While the
shape buffer is logically immutable, reading it concurrently with a header that
is being mutated (e.g. a future reshape) would race. It also dereferences
`shape_ptr` unconditionally — if a foreign caller supplied a header with
`shape_ptr == 0` and `ndim > 0`, this is a null-pointer read. Why it matters:
unchecked trust of foreign-supplied header fields. Suggested fix: validate
`shape_ptr != 0` when `ndim != 0`, and document the immutability assumption.

**M3 — `from_raw` and `zeros` never validate header invariants.**
Location: [gridmesh/src/tensor.rs:55](gridmesh/src/tensor.rs#L55).
`from_raw` trusts every field of a foreign header. `data_len` could exceed the
real allocation, `data_ptr` could be misaligned for `T`, `dtype` is never
checked against `T`. `as_slice` then builds a slice of `data_len` elements
([:165](gridmesh/src/tensor.rs#L165)) — an out-of-bounds or misaligned read.
Why it matters: the security boundary of a polyglot runtime is exactly these
foreign headers. Suggested fix: add a `validate()` that checks alignment of
`data_ptr` for `T`, that `data_len * size_of::<T>()` is plausible, and that
`dtype` matches `T`; call it in `from_raw`.

**M4 — `data_len` is element count, not byte count, but `dtype`/`T` agreement is unenforced.**
Location: [gridmesh/src/tensor.rs:169](gridmesh/src/tensor.rs#L169),
[:192](gridmesh/src/tensor.rs#L192).
`as_slice` interprets `data_len` as a count of `T`. Nothing ties the `T` of the
handle to the `dtype` field (always written as `0` by `zeros`,
[gridmesh/src/header.rs:14](gridmesh/src/header.rs#L14) /
[gridmesh/src/tensor.rs:89](gridmesh/src/tensor.rs#L89)). A `Tensor<f64>` built
from a header whose data is actually `f32` would read 2x the bytes. Why it
matters: type confusion across the language boundary. Suggested fix: define a
`dtype` enum, set it in `zeros`, and assert it in `from_raw`/borrow accessors.

**M5 — Integer truncation: `usize` shape/length narrowed to `u32` without checks.**
Location: [gridmesh/src/tensor.rs:73](gridmesh/src/tensor.rs#L73),
[:77](gridmesh/src/tensor.rs#L77), [:87](gridmesh/src/tensor.rs#L87)-[:88](gridmesh/src/tensor.rs#L88),
[:94](gridmesh/src/tensor.rs#L94)/[:134](gridmesh/src/tensor.rs#L134).
`zeros` casts `total_len as u32`, each shape dim `x as u32`, and pointers
`as u32`. On a 64-bit host the pointer-to-`u32` cast (`data_ptr`, and
`self.header as u32` at line 134) **silently truncates** the address — the
header is only `u32`-addressable inside a 32-bit WASM linear memory. On native
64-bit builds (which the test suite uses) these casts are lossy and the freed
pointer is wrong. Also `shape.iter().product()` can overflow `usize` with no
check. Why it matters: the crate compiles and tests on 64-bit native but its
pointer model is only valid on wasm32; this is a silent portability landmine.
Suggested fix: store pointers as `usize`/`*mut`, or gate the crate to
`target_pointer_width = "32"`, and use `checked_mul`/`try_into` for the size
math.

### Low

**L1 — `unborrow` / `unborrow_mut` assertions are debug-only.**
Location: [gridmesh/src/header.rs:80](gridmesh/src/header.rs#L80),
[:105](gridmesh/src/header.rs#L105). `debug_assert!` compiles out in release;
misuse goes undetected. See H2 for the underflow consequence.

**L2 — No crate-, module-, or struct-level documentation.**
Location: [gridmesh/src/lib.rs](gridmesh/src/lib.rs). The crate root has zero
`//!` docs; most public items lack `///` docs. For a type exposed in the
user-facing `#[types]` syntax, this is thin.

**L3 — Dead/misleading code and stale comments.**
The `checked_add` in `try_borrow` ([gridmesh/src/header.rs:54](gridmesh/src/header.rs#L54))
is unreachable after the round-42 fix. The long comment block in
[gridmesh/src/tensor.rs:21](gridmesh/src/tensor.rs#L21)-[:51](gridmesh/src/tensor.rs#L51)
describes design indecision ("can be expanded", "we'll assume", "we will stub
this") rather than the actual contract. Suggested fix: prune to one decisive
sentence each.

**L4 — `TensorElement` trait is empty and unenforced for layout.**
Location: [gridmesh/src/tensor.rs:5](gridmesh/src/tensor.rs#L5). It is a pure
marker; it does not (and cannot, as written) constrain alignment or size, so it
provides no real safety guarantee for the raw-pointer reinterpretation in
`as_slice`. Consider associating a `dtype` constant with it.

**L5 — Test coverage is narrow.**
Location: [gridmesh/tests/r42_pentest_attack_tests.rs](gridmesh/tests/r42_pentest_attack_tests.rs).
The only test file targets the round-42 borrow-overflow fix. There are no tests
for `Tensor::zeros`, `Drop`/leak behavior, `Clone` ref-counting, `as_slice`
round-trips, or `from_raw`. The most safety-critical paths are untested.

## Strengths

- **Zero dependencies**, genuinely lightweight, and a clean `#[repr(C)]` layout
  with safety fields placed first — sensible for an FFI/WASM ABI.
- **RAII borrow guards** (`TensorRef`/`TensorRefMut`) give an ergonomic, hard-to-
  misuse borrowing API on top of the raw header, and `Drop` releases borrows
  automatically.
- The **borrow state machine is a compact, well-chosen encoding** (one word:
  `0` free / `N` shared / `MAX` exclusive) and the round-42 sentinel-collision
  fix is correct and is backed by focused regression tests.
- `retain`/`release`/`try_borrow` consistently use `SeqCst`, avoiding subtle
  ordering bugs (at some performance cost).
- Honest, descriptive comments about the cross-language allocator problem —
  the hard issue is acknowledged even though it is not yet solved.

## Recommendations

Prioritized, actionable:

1. **Fix the memory leak / allocator mismatch (C1, C2, H3).** Implement real
   deallocation: track allocation origin per tensor, free `zeros`-allocated
   buffers with `Vec::from_raw_parts`/`Box::from_raw`, and only route foreign
   headers through the host allocator. This is the single most important fix —
   the crate currently either leaks every tensor or invokes UB.
2. **Fix the `as_mut_slice` provenance bug (C3).** Form the `&mut [T]` from a
   raw mutable pointer path, never narrowing through `&TensorHeader` first.
3. **Make `unborrow`/`release` release-mode-safe (H2, M1, L1).** Replace
   `debug_assert` + blind `fetch_sub` with checked CAS / `fetch_update` so that
   underflow cannot silently fabricate an exclusive borrow or corrupt the ref
   count.
4. **Validate foreign headers in `from_raw` (M2, M3, M4).** Check `data_ptr`
   alignment for `T`, non-null `shape_ptr` when `ndim != 0`, plausible
   `data_len`, and `dtype`↔`T` agreement; introduce a real `dtype` enum.
5. **Resolve the 32-bit pointer model (M5).** Either store pointers as
   `usize`/raw pointers, or `#[cfg]`-gate the crate to `wasm32`; use
   `checked_mul` for shape-product math.
6. **Add tests for `zeros`, `Clone`, `Drop`, and `as_slice` round-trips (L5),**
   including a Miri run to catch the provenance and allocator issues above.
7. **Add crate/module/type documentation and prune stale comments (L2, L3).**
