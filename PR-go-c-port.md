## Summary

- Ports `poly-verified` and `poly-client` from Rust to **Go** and **C**, establishing polyglot parity across three languages for the hash-IVC verified inference proof system
- Both implementations use identical SHA-256 domain-separated hashing (leaf `0x00`, transition `0x01`, chain step `0x02`, combine `0x03`, blinding `0x04`), constant-time hash comparison, and Merkle tree construction matching the Rust wire format
- Selective disclosure system enables revealing arbitrary token positions to different parties (e.g. pharmacist sees medications, insurer sees diagnosis) while sharing a common Merkle root and execution proof

## What's new

**`poly-verified-go`** — Core proof library in Go
- `Verified[T]` generic wrapper pairing computed values with cryptographic proofs
- Merkle-tree-backed selective disclosure (`CreateDisclosure` / `CreateDisclosureRange` / `VerifyDisclosure`)
- Wire-compatible JSON serialization bridging to Rust serde `{"HashIvc":{...}}` envelope with `[u8; 32]` integer-array encoding
- `EncryptionBackend` interface with mock implementation
- 4 privacy modes: Transparent, PrivateProven, Private, Encrypted

**`poly-verified-c`** — Core proof library in C
- Full C implementation using OpenSSL EVP for SHA-256
- Cache-friendly flattened Merkle tree with layer offsets
- Hand-rolled recursive descent JSON parser for wire format
- Dynamic IVC checkpoint array (initial cap 16, doubles on overflow)
- Both hex-encoded (`pv_proof_to_json`) and wire-compatible (`pv_proof_to_wire_json`) serialization

**`poly-client-go`** — Client SDK in Go
- Thin client: keygen, encrypt input, build request, decrypt response, access proofs
- Selective disclosure from verified responses via `Disclose()` / `DiscloseRange()`
- Comprehensive test suite: 10 tests covering all modes, edge cases, stress (10k tokens), serialization round-trips

**`poly-client-c`** — Client SDK in C
- Functionally equivalent C client with mock encryption (deterministic keys `0xAA*32` / `0xBB*32`)
- JSON request/response handling with depth-counted nested brace parsing
- Delegates proof parsing to `poly-verified-c`

## Stats

- **20 files**, **3,554 lines** added
- 4 new modules across 2 languages
- Go tests cover all 4 privacy modes, empty/large inputs, disclosure verification, and JSON round-trips
- C tests cover hashing, Merkle proofs, IVC fold/finalize, disclosure, and wire format parsing

## Test plan

- [ ] `cd poly-verified-go && go test ./...`
- [ ] `cd poly-client-go && go test ./...`
- [ ] `cd poly-verified-c && make test`
- [ ] `cd poly-client-c && make test`
- [ ] Cross-language wire format: verify Go `MarshalWireProof` output parses with C `pv_proof_from_wire_json` and vice versa
