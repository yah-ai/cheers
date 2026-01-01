//! The **write** side of the revocation split.
//!
//! Edge-verifiable auth (R019) keeps revocation's two sides physically apart.
//! This crate holds the origin half:
//!
//! - [`RevocationWriter`] — the **cold path**, run at the origin on logout /
//!   device-revoke. Adds a token's `jti` to the set.
//! - The **hot-path** reader (`cheers_verify::RevocationReader`) lives in
//!   `cheers-verify` — the verify-only edge holds it without the power to revoke
//!   anyone else's sessions.
//!
//! The set is **eventually consistent** by design: a `revoke` here propagates to
//! edge readers asynchronously (KV replication / gossip), bounded by the access
//! token TTL (see [`SessionPolicy`](crate::session::SessionPolicy)). Full
//! contract on `cheers_verify::RevocationReader`.
//!
//! # Revoking a session vs. a whole login
//!
//! The set is keyed on `jti`, so [`RevocationWriter::revoke`] kills **one**
//! access token immediately (edge-visible within the propagation window). The
//! coarser flows compose it with the refresh cold path:
//!
//! - **Logout / single device-revoke:** call
//!   [`RefreshStore::revoke_chain`](crate::store::RefreshStore::revoke_chain) so
//!   the chain can mint no *further* access tokens, and `revoke(jti)` for the
//!   session's current access token. Any access tokens already issued on that
//!   chain die on their own within the access TTL.
//! - **Account-wide revoke:** revoke every chain via the
//!   [`UserStore`](crate::store::UserStore) device list; same TTL bound applies.
//!
//! [`SessionAuthority`](crate::session::SessionAuthority) is where these calls
//! are composed — it holds both the [`RevocationWriter`] and the
//! [`RefreshStore`](crate::store::RefreshStore).

use async_trait::async_trait;

use cheers_core::StoreError;

/// Origin-side revocation write. Held by
/// [`SessionAuthority`](crate::session::SessionAuthority) on the cold path.
#[async_trait]
pub trait RevocationWriter: Send + Sync {
    /// Add `jti` to the revocation set. **Idempotent** — revoking an
    /// already-revoked `jti` is a no-op, not an error. Propagation to edge
    /// `cheers_verify::RevocationReader`s is asynchronous (see the module-level
    /// contract).
    async fn revoke(&self, jti: &str) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemRevocations(Mutex<HashSet<String>>);

    #[async_trait]
    impl RevocationWriter for MemRevocations {
        async fn revoke(&self, jti: &str) -> Result<(), StoreError> {
            self.0.lock().unwrap().insert(jti.to_owned());
            Ok(())
        }
    }

    #[test]
    fn revoke_is_idempotent() {
        let set = MemRevocations::default();
        pollster::block_on(async {
            set.revoke("tok-1").await.unwrap();
            // Re-revoking is a no-op, not an error.
            set.revoke("tok-1").await.unwrap();
            assert!(set.0.lock().unwrap().contains("tok-1"));
        });
    }

    #[test]
    fn trait_is_dyn_compatible() {
        fn _writer(_: &dyn RevocationWriter) {}
    }
}
