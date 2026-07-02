//! # cheers-verify — the edge-safe, verify-only surface
//!
//! The verify half of edge-verifiable auth (R019). Everything here can *check* a
//! session but cannot *create* one:
//!
//! - [`PasetoV4PublicVerifier`] — PASETO v4.public (Ed25519) verification with a
//!   public key alone. The only [`TokenVerifier`](cheers_core::TokenVerifier) that
//!   cannot also mint (the symmetric codecs in `cheers-server` impl both halves).
//! - [`RevocationReader`] — the read side of the revocation split: a point
//!   membership check against an eventually-consistent replica (CF KV / gossip).
//! - [`EdgeVerifier`] — the facade a CF Worker holds: verify a token, then check
//!   it hasn't been revoked. It takes a `TokenVerifier`, so there is *no code
//!   path to mint* — that absence is what makes shipping it to the edge safe.
//!
//! This crate depends on `cheers-core` and `pasetors`, but on **no minter**.
//! `cheers-server` depends on this crate, never the reverse — that single
//! direction is what guarantees a verify-only consumer has no minter in its
//! dependency graph.

pub mod edge;
pub mod public_verifier;
pub mod revocation;

pub use edge::EdgeVerifier;
pub use public_verifier::{codec_err, PasetoV4PublicVerifier};
pub use revocation::RevocationReader;
