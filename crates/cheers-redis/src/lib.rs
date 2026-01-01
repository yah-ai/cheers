//! # cheers-redis — TTL-tier store impls for cheers
//!
//! Redis-backed implementations of cheers's hot-path TTL traits:
//!
//! | Trait | Module |
//! |---|---|
//! | [`RefreshStore`](cheers_server::RefreshStore) | [`refresh_store`] |
//! | [`RevocationWriter`](cheers_server::RevocationWriter) + [`RevocationReader`](cheers_verify::RevocationReader) | [`revocation`] |
//!
//! This crate does **not** ship `UserStore` or `PasskeyCredentialStore` —
//! those are long-lived, indexed-by-user data that belong in a relational
//! store (`cheers-sqlx`). The intended wiring:
//!
//! - Identity, OIDC links, passkey credentials → `cheers-sqlx` (`pg` /
//!   `sqlite`)
//! - Refresh-token rotation chains → `cheers-redis`
//! - Access-token revocation kill list → `cheers-redis`
//!
//! Single-engine deployments (dev, first-cut prod) can use `cheers-sqlx` for
//! the TTL traits too — see that crate's module docs. Switch to
//! `cheers-redis` once per-request-validation latency or revocation fan-out
//! demands it.
//!
//! ## Key layout
//!
//! All keys are prefixed `cheers:` to keep them isolated from other tenants of
//! the same redis. The defaults:
//!
//! | Purpose | Key shape | Type | TTL |
//! |---|---|---|---|
//! | Refresh record | `cheers:refresh:{token}` | string (JSON) | `expires_at - now` at put time |
//! | Chain index | `cheers:chain:{chain_id}` | set of tokens | matches the longest member |
//! | Revocation set | `cheers:revoked:{jti}` | string (revoked_at) | matches access TTL |
//!
//! The prefix is configurable per-store ([`RedisRefreshStore::with_prefix`]
//! and [`RedisRevocationStore::with_prefix`]) for multi-tenant redis
//! deployments.

pub mod refresh_store;
pub mod revocation;

pub use refresh_store::RedisRefreshStore;
pub use revocation::RedisRevocationStore;

/// Default redis key prefix.
pub const DEFAULT_PREFIX: &str = "cheers";
