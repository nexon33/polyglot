# poly-node — Documentation & Code Review

## Overview

`poly-node` is the decentralized compute-network node for the **pyrs polyglot**
toolchain. A node is a long-running daemon that:

- holds a persistent Ed25519 identity (`NodeId = SHA-256(public_key)`),
- listens for QUIC connections from other nodes / clients,
- performs an Ed25519-authenticated application-layer handshake, and
- serves encrypted inference requests by delegating to a pluggable
  `InferenceBackend` (currently only `MockInferenceBackend`).

**Current phase — Phase 1 (QUIC transport + inference).** Only the handshake
(`Hello`/`HelloBinding`/`HelloAck`), health-check (`Ping`/`Pong`), and
inference (`InferRequest`/`InferResponse`) message paths are implemented and
authenticated end-to-end.

**Planned phases**, visible as reserved `MessageType` variants and code
comments:

- **Phase 2 — gossip discovery** (`GetPeers`, `Peers`, `Announce`): peer-table
  exchange and `NodeInfo`-based load balancing.
- **Phase 3 — relay** (`RelayOpen`/`RelayAccept`/`RelayDeny`/`RelayData`/
  `RelayClose`): forwarding opaque PFHE ciphertext for NAT-traversed peers.
- **Phase 4 — CLI integration**: wiring the node into the main toolchain CLI.

All Phase 2/3 message types are currently rejected (with handshake gating) in
[poly-node/src/node.rs](poly-node/src/node.rs#L1174).

The crate has been through ~33 numbered penetration-testing rounds; each round
left a dedicated regression suite in `poly-node/tests/` (`r5_…` through
`r35_…`, plus `security_attack_tests.rs`).

## Architecture

### QUIC transport

Transport is QUIC via `quinn` 0.11 over `rustls` 0.23 (ring backend). The
server endpoint ([poly-node/src/net/transport.rs](poly-node/src/net/transport.rs#L28))
uses a self-signed certificate, ALPN `poly/1`, a 90-second QUIC idle timeout,
and per-connection caps of 4 concurrent bidi + 4 uni streams. The client
endpoint ([poly-node/src/net/transport.rs](poly-node/src/net/transport.rs#L60))
uses a `SkipServerVerification` certificate verifier — TLS provides transport
encryption only; peer authenticity is established at the application layer by
the Ed25519 handshake.

### Handshake (Ed25519 sign / verify)

1. The connecting peer opens a bidi stream and writes a `Hello` frame
   (protocol version + signed `NodeInfo`) followed, on the **same stream**, by
   a `HelloBinding` frame.
2. `NodeInfo` is self-authenticating: it carries an Ed25519 signature over a
   canonical message (`compute_nodeinfo_signing_message`,
   [poly-node/src/protocol/wire.rs](poly-node/src/protocol/wire.rs#L238))
   covering *all* fields plus a domain-separation tag.
3. The `HelloBinding` payload is an Ed25519 signature over
   `compute_handshake_binding_message` — domain tag + public key + the QUIC
   connection's RFC 5705 exported keying material
   ([poly-node/src/protocol/wire.rs](poly-node/src/protocol/wire.rs#L300)).
   This binds a `Hello` to one specific connection, defeating verbatim replay.
4. The server validates version, signature, `NodeInfo` field bounds, timestamp
   freshness, and the connection binding, then replies with a `HelloAck`. On
   rejection it returns a *minimal* zeroed `NodeInfo` to avoid leaking server
   identity to unauthenticated peers.
5. `connect_and_infer` mirrors all checks on the client side (server signature,
   version, timestamp, `NodeInfo` bounds).

### Wire framing protocol

Every message is a `Frame`: `[1-byte type][4-byte big-endian length][payload]`.
Payloads are bincode-serialized structs. `Frame::decode`
([poly-node/src/protocol/wire.rs](poly-node/src/protocol/wire.rs#L135))
rejects unknown type bytes, lengths above `MAX_FRAME_PAYLOAD` (16 MB), and
incomplete buffers, and returns `bytes_consumed` so callers can reject trailing
data. Higher layers (`handshake`, `inference`) wrap bincode with
`with_limit(...)` and `with_fixint_encoding()` (no `allow_trailing_bytes`).

### Inference request flow

```
client                                      poly-node (server)
  |                                                  |
  |-- QUIC connect (TLS, ALPN poly/1) -------------->|
  |                                                  | accept(): conn_semaphore.try_acquire()
  |== stream 1: Hello + HelloBinding ===============>|
  |                                                  | handle_stream: verify sig + binding
  |<============ HelloAck (accepted) ================|  handshake_done = true
  |                                                  |
  |== stream 2: InferRequest =======================>|
  |                                                  | validate model_id/max_tokens/size/temp
  |                                                  | infer_semaphore.acquire()
  |                                                  | spawn_blocking: backend.infer()
  |<============ InferResponse ======================|
  |-- conn.close() --------------------------------->|
```

### Concurrency model

- `tokio` multi-threaded runtime; `PolyNode::run` accept-loop is single-task.
- Two `tokio::sync::Semaphore`s sized to `max_sessions`: `conn_semaphore`
  (acquired with `try_acquire`, rejects excess connections) and
  `infer_semaphore` (acquired with `.await`, serializes compute).
- Per-connection: each accepted stream is `tokio::spawn`-ed; shared state
  (`handshake_done`, `handshake_attempted`, `stream_count`,
  `pre_handshake_count`) uses `AtomicBool`/`AtomicU64` with `SeqCst` ordering.
- Blocking inference runs in `tokio::task::spawn_blocking`.
- `server_info` is an `Arc<RwLock<NodeInfo>>` regenerated periodically; lock
  poisoning is handled via `into_inner()` recovery rather than panicking.

## Module Reference

### [poly-node/src/lib.rs](poly-node/src/lib.rs)
Crate root. Declares the public modules `config`, `identity`, `net`, `node`,
`protocol`. Documentation-only otherwise.

### [poly-node/src/main.rs](poly-node/src/main.rs)
Binary entry point. `Cli` (clap) parses `--listen`, `--model`, `--bootstrap`,
`--max-sessions`, `--relay`. Builds a `MockInferenceBackend` (any non-`mock`
model falls back to mock with a warning, [main.rs:38](poly-node/src/main.rs#L38)),
constructs `NodeConfig` + `PolyNode`, and calls `run().await`.

### [poly-node/src/config.rs](poly-node/src/config.rs)
`NodeConfig` plain struct: `listen_addr`, `model_name`, `bootstrap_addrs`,
`max_sessions`, `relay`. No validation here — all validation lives in
`PolyNode::new`.

### [poly-node/src/identity.rs](poly-node/src/identity.rs)
Ed25519 identity. `NodeId = [u8; 32]` alias. `NodeIdentity` (`generate`,
`sign`, `verifying_key`, `public_key_bytes`). Free functions
`compute_node_id` ([identity.rs:50](poly-node/src/identity.rs#L50)) and
`verify_signature` ([identity.rs:63](poly-node/src/identity.rs#L63)) — the
latter correctly uses `verify_strict` to reject malleable / torsion-tainted
signatures. 6 unit tests.

### [poly-node/src/net/transport.rs](poly-node/src/net/transport.rs)
QUIC endpoint construction. `generate_self_signed_cert`,
`create_server_endpoint` ([transport.rs:28](poly-node/src/net/transport.rs#L28)),
`create_client_endpoint` ([transport.rs:60](poly-node/src/net/transport.rs#L60)),
and `SkipServerVerification` — a `rustls` `ServerCertVerifier` that accepts any
certificate.

### [poly-node/src/protocol/wire.rs](poly-node/src/protocol/wire.rs)
Wire types and framing. `MessageType` enum (`repr(u8)`) + `from_u8`;
`Frame` with `new`/`new_checked`/`encode`/`try_encode`/`decode`; `FrameError`;
`NodeInfo`, `ModelCapability`, `NodeCapacity`;
`compute_nodeinfo_signing_message` ([wire.rs:238](poly-node/src/protocol/wire.rs#L238))
and `compute_handshake_binding_message` ([wire.rs:300](poly-node/src/protocol/wire.rs#L300)).
9 unit tests.

### [poly-node/src/protocol/handshake.rs](poly-node/src/protocol/handshake.rs)
`Hello`, `HelloAck` structs; `PROTOCOL_VERSION = 1`. `encode_hello` /
`decode_hello` / `encode_hello_ack` / `decode_hello_ack` — size-validated
(64 KB) bincode codecs.

### [poly-node/src/protocol/inference.rs](poly-node/src/protocol/inference.rs)
Bincode codecs for `poly_client::protocol::{InferRequest, InferResponse}`
with 4 MB request / 16 MB response limits. `handle_infer`
([inference.rs:89](poly-node/src/protocol/inference.rs#L89)) is `#[deprecated]`
dead code that bypasses validation.

### [poly-node/src/node.rs](poly-node/src/node.rs)
The daemon. `PolyNode` struct; `PolyNode::new`
([node.rs:198](poly-node/src/node.rs#L198)) performs extensive config
validation; `own_node_info`; `run` ([node.rs:334](poly-node/src/node.rs#L334))
accept-loop; `connection_exporter` ([node.rs:437](poly-node/src/node.rs#L437));
`handle_connection` ([node.rs:444](poly-node/src/node.rs#L444)) stream
accept-loop; `handle_stream` ([node.rs:556](poly-node/src/node.rs#L556)) the
per-message state machine; `build_signed_node_info[_with]`; and
`connect_and_infer` ([node.rs:1295](poly-node/src/node.rs#L1295)) the client
helper. ~150 lines of leading `//!` doc enumerate every pentest fix R5–R35.

## Code Review

### Critical

None. The handshake, signature verification, frame parsing, and DoS controls
are all present and exercised by tests.

### High

**H1 — Connection-level concurrency: `handle_connection` spawns stream tasks
but never joins them, and stream caps are advisory.**
[poly-node/src/node.rs:542](poly-node/src/node.rs#L542). Each stream is
`tokio::spawn`-ed and detached. `handle_connection` returns (releasing the
`conn_semaphore` permit, [node.rs:405](poly-node/src/node.rs#L405)) as soon as
its accept-loop breaks, even while spawned stream tasks — including
`spawn_blocking` inference — are still running. Consequence: the connection
semaphore counts *accept-loops*, not *in-flight work*; a peer can churn
connections, each releasing its permit immediately while leaving inference
tasks queued on `infer_semaphore`. The `infer_semaphore` still bounds
concurrent compute, but the intended "max_sessions" coupling between
connections and work is looser than the docs imply. *Fix:* collect stream
`JoinHandle`s and `join`/abort them before returning, or hold the connection
permit inside an `Arc` cloned into each stream task.

**H2 — `Frame::encode` panics on payloads larger than `u32::MAX`.**
[poly-node/src/protocol/wire.rs:107](poly-node/src/protocol/wire.rs#L107). The
`assert!` is reachable from response paths that call `.encode()` directly
(e.g. `send.write_all(&response_frame.encode())`,
[node.rs:1220](poly-node/src/node.rs#L1220)). In practice payloads are bounded
well below 4 GB by upstream size checks, so this is not currently exploitable,
but `try_encode` exists precisely to avoid the panic and the hot response path
does not use it. *Fix:* use `try_encode` in `handle_stream` and
`connect_and_infer`, and treat the failure as a stream error.

**H3 — `node.run()` takes `&self`, yet `main` calls it on a node it owns; the
accept loop runs forever and stream handlers capture `self.backend` clones.**
[poly-node/src/node.rs:334](poly-node/src/node.rs#L334). This works because
`run` only reads `self`, but the `identity_for_regen` tuple
([node.rs:364](poly-node/src/node.rs#L364)) is built, immediately discarded
(`let _ = identity_for_regen;`), and the comment admits "actual regen below" —
the regeneration actually re-derives from `self.own_node_info()`. This is dead,
misleading scaffolding that suggests an unfinished refactor. *Fix:* delete the
`identity_for_regen` block; it contributes nothing and confuses readers about
the locking model.

### Medium

**M1 — No inference replay protection.**
[poly-node/tests/security_attack_tests.rs:625](poly-node/tests/security_attack_tests.rs#L625)
(`attack_replay_inference_request`) documents that an identical
`InferRequest`, captured after a valid handshake, can be replayed indefinitely
within (or across) connections. `InferRequest` carries `seed` but no nonce or
request-id, and the server keeps no seen-request set. Each replay burns an
`infer_semaphore` permit and a `spawn_blocking` slot. *Fix:* add a
monotonic/nonce field to `InferRequest` and a bounded per-connection
seen-set, or rate-limit per identity once Phase 2 lands.

**M2 — `connect_and_infer` generates a fresh throwaway identity per call.**
[poly-node/src/node.rs:1303](poly-node/src/node.rs#L1303). Every client call
mints a new `NodeIdentity`, so the node identity is meaningless for clients and
no per-identity accounting / authorization is possible. This is acceptable for
Phase 1 testing but undermines the entire `NodeId` design once gossip/relay
add per-identity trust. *Fix:* accept a `&NodeIdentity` parameter (or load a
persistent client key) so the identity is stable.

**M3 — `expected_id` (NodeId binding) is computed and discarded.**
[poly-node/src/node.rs:705](poly-node/src/node.rs#L705): `let _ = expected_id;`.
The server verifies the `NodeInfo` signature but never checks that the claimed
`NodeId` equals `SHA-256(public_key)`, nor uses it for anything. Today the
`NodeId` is purely `public_key`-derived so there is no spoof, but the dangling
binding is a latent bug magnet for Phase 2 routing. *Fix:* either remove the
computation or wire it into a peer table now with a clear TODO.

**M4 — `MockInferenceBackend` is the only backend; non-mock models silently
degrade.** [poly-node/src/main.rs:38](poly-node/src/main.rs#L38). Requesting a
real model prints a warning and serves mock results. A node will advertise
`model_name` in its signed `NodeInfo` while actually running mock inference —
a correctness/trust mismatch once gossip advertises capabilities. *Fix:* fail
fast on an unsupported model, or clearly mark capability as `mock` in
`NodeInfo`.

**M5 — Persistent identity is not persisted.**
[poly-node/src/node.rs:281](poly-node/src/node.rs#L281). `PolyNode::new` calls
`NodeIdentity::generate()` every startup; the doc comment in `identity.rs`
says "each node has a *persistent* Ed25519 keypair", but nothing reads/writes a
keyfile. A node's identity changes on every restart, breaking any future
gossip reputation/peer-table continuity. *Fix:* load from / persist to a
keyfile path in `NodeConfig`.

### Low

**L1 — `signing_key` / `verifying_key` are unused-warning candidates and
`verifying_key` is redundant.** [poly-node/src/identity.rs:14](poly-node/src/identity.rs#L14).
`verifying_key` can always be derived from `signing_key`; storing both is
harmless but slightly redundant.

**L2 — `MAX_HELLO_SIZE` is duplicated.** Defined as `MAX_HELLO_SIZE`
([node.rs:100](poly-node/src/node.rs#L100)) and again as
`MAX_HANDSHAKE_MSG_SIZE` ([handshake.rs:12](poly-node/src/protocol/handshake.rs#L12)),
both 64 KB, with a comment noting they must match. *Fix:* export one constant
and reference it from both sites to prevent silent drift.

**L3 — The R12 trailing-data check is bypassed for `Hello` then re-implemented
inline.** [poly-node/src/node.rs:600](poly-node/src/node.rs#L600) and
[node.rs:972](poly-node/src/node.rs#L972). The `Hello` arm parses a second
frame (`HelloBinding`) from `data[consumed..]` inside a closure that returns
`Option`. The logic is correct and tested (R33 suite), but the special-case
and the closure are subtle; a small framing helper that decodes "exactly two
frames" would be clearer and less error-prone.

**L4 — `handle_infer` deprecated dead code remains in the crate.**
[poly-node/src/protocol/inference.rs:89](poly-node/src/protocol/inference.rs#L89).
`#[deprecated]` is good, but the function is genuinely unreachable from the
server path and could be deleted to shrink attack surface.

**L5 — The ~150-line `//!` changelog in `node.rs` is unmaintainable in the
source file.** [poly-node/src/node.rs:1](poly-node/src/node.rs#L1). It is
valuable history but better placed in a `CHANGELOG.md` or the pentest test
files (which already document each round). It dwarfs the module's own
description and will keep growing.

**L6 — `MockInferenceBackend` is constructed via `Arc::new(...)` twice in
`main` for the same fallback.** [poly-node/src/main.rs:37](poly-node/src/main.rs#L37)
and [main.rs:43](poly-node/src/main.rs#L43). Minor duplication; collapse the
match into a single constructor since both arms build the same backend.

## Strengths

- **Defense-in-depth, symmetric client/server validation.** Every check the
  server performs on a `Hello` is mirrored by `connect_and_infer` on the
  `HelloAck` (signature, version, timestamp, address/model/capacity bounds).
- **Sound cryptographic hygiene.** `verify_strict` rejects malleable
  signatures; signing messages carry explicit domain-separation tags and length
  prefixes; the `HelloBinding` ties a handshake to a specific QUIC connection
  via RFC 5705 keying material — a genuinely strong replay defense.
- **Robust framing.** Length-prefix overflow, 16 MB payload cap, unknown type
  bytes, incomplete buffers, and trailing data are all handled without panics;
  `bytes_consumed` is checked everywhere.
- **DoS controls are layered.** Connection semaphore, inference semaphore,
  per-connection stream cap, separate (lower) pre-handshake stream cap,
  read timeouts on both sides, QUIC idle timeout, application idle timeout,
  size-limited bincode, and per-field bounds on `NodeInfo`.
- **No `unwrap()` on network input.** Network reads and decodes propagate
  errors with `?`/`map_err`; `unwrap`s are confined to system-time and
  infallible-constant paths.
- **Exceptional regression coverage.** 17 numbered pentest suites plus
  `security_attack_tests.rs` and `quic_integration.rs` lock in each fix.
- **RwLock poisoning is handled gracefully** rather than propagating a panic
  into the server accept loop.

## Recommendations

Prioritized, actionable:

1. **(H1) Fix connection/stream lifetime coupling.** Track spawned stream
   `JoinHandle`s and join or abort them before `handle_connection` returns, so
   the connection semaphore actually bounds in-flight work.
2. **(H2) Switch response encoding to `Frame::try_encode`** in `handle_stream`
   and `connect_and_infer`; remove the reachable `assert!`-panic from the hot
   path.
3. **(M5) Persist the node identity** to a keyfile referenced by `NodeConfig`
   so `NodeId` is stable across restarts — a prerequisite for Phase 2 gossip
   trust.
4. **(M1) Add inference replay protection** (nonce/request-id + bounded
   seen-set, or per-identity rate limiting) before exposing the node beyond
   localhost.
5. **(M2) Make `connect_and_infer` accept a stable client identity** instead of
   minting a throwaway keypair per call.
6. **(M3) Resolve the dangling `expected_id` NodeId binding** — either remove
   it or wire it into a real peer table.
7. **(M4) Fail fast on unsupported models**, or honestly advertise mock
   capability, so signed `NodeInfo` never misrepresents what the node serves.
8. **(H3/L5) Clean up `node.rs`:** delete the dead `identity_for_regen`
   scaffold and move the R5–R35 changelog out of the `//!` block into
   `CHANGELOG.md`.
9. **(L2) De-duplicate the 64 KB handshake-size constant** into a single shared
   `pub const`.
10. **(L4) Delete the deprecated `handle_infer`** to shrink attack surface.
11. **General — split `handle_stream`.** The function is ~670 lines; extract
    per-message-type handlers (`handle_hello`, `handle_infer_request`, etc.) to
    improve testability and reviewability as Phase 2/3 message handling lands.
