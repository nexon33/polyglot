//! Real-crypto end-to-end tests for poly-chain.
//!
//! This crate has no library code — see `tests/real_crypto.rs`. It exists only
//! to depend on `poly-chain` *without* the `mock` feature, so the tests run
//! against real Ed25519 signature verification and real HashIvc proof
//! verification (the production code paths).
