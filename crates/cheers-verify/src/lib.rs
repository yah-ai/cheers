//! # cheers-verify — the edge-safe, verify-only surface
//!
//! The verify half of edge-verifiable auth (R019). Everything here can *check* a
//! session but cannot *create* one:
//!
//! - [`PasetoV4PublicVerifier`] — PASETO v4.public (Ed25519) verification with a
//!   public key alone. The only [`TokenVerifier`](cheers_core::TokenVerifier) that
//!   cannot also mint (the symmetric codecs in `cheers-server` impl both halves).
//! - [`RevocationReader`] — the read side of the revocation split: point
//!   checks (jti, device, membership) against an eventually-consistent replica
//!   (CF KV / gossip). [`ReplicatedRevocations`] is the offline replica: it
//!   adopts issuer-signed revocation sets by epoch (R732-F6).
//! - [`IssuerTrust`] — "was this artifact signed by the issuer I trust?",
//!   against a pinned key or a JWKS key set; exportable as a [`TrustDoc`] so
//!   an offline edge restarts against the keys it persisted.
//! - [`StandingVerifier`] — admits a standing node binding (R732-F5): no
//!   expiry, bound to the peer's node key, ended only by revocation or by a
//!   newer binding for the same device ([`BindingLedger`]).
//! - [`EdgeVerifier`] — the facade a CF Worker holds: verify a token, then check
//!   it hasn't been revoked. It takes a `TokenVerifier`, so there is *no code
//!   path to mint* — that absence is what makes shipping it to the edge safe.
//!
//! - [`KeySetVerifier`] — verification against a JWKS key set with key-role
//!   enforcement (§D5), fed by a static [`KeySet`] or the W159 [`JwksCache`]
//!   (fetching over HTTP behind the `jwks-http` feature).
//!
//! This crate depends on `cheers-core` and `pasetors`, but on **no minter**.
//! `cheers-server` depends on this crate, never the reverse — that single
//! direction is what guarantees a verify-only consumer has no minter in its
//! dependency graph.

pub mod admit;
pub mod artifact;
pub mod edge;
pub mod jwks;
pub mod key_set;
pub mod public_verifier;
pub mod revocation;
pub mod snapshot;
pub mod standing;

pub use edge::EdgeVerifier;
pub use jwks::{JwkKey, JwksCache, JwksCacheConfig, JwksDoc, JwksError, JwksSource, KeyEntry, KeySet};
#[cfg(feature = "jwks-http")]
pub use jwks::HttpJwksSource;
pub use key_set::{KeySetVerifier, VerifyError};
pub use public_verifier::{codec_err, kid_for, PasetoV4PublicVerifier};
pub use admit::{artifact_hash, verify_admit_with, verify_device_artifact, AdmitAuthority, AdmitError, Approval, IssuerAdmitAuthority, VerifiedAdmit};
pub use artifact::{AnchorDoc, IssuerTrust, TrustDoc};
pub use revocation::{membership_tag, revocation_entry, test_revocation_key, AdoptError, Adopted, ReplicatedRevocations, RevocationReader};
pub use snapshot::{SnapshotError, SnapshotLedger, SnapshotLedgerDoc, SnapshotVerifier, VerifiedSnapshot};
pub use standing::{BindingLedger, ForeignLedger, LedgerDoc, StandingError, StandingVerifier, VerifiedStanding};
