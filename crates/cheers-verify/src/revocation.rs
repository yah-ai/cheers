//! The **read** side of the revocation split.
//!
//! Revocation has two physically distinct sides, and edge-verifiable auth (R019)
//! depends on keeping them apart. This crate holds the edge half:
//!
//! - [`RevocationReader`] — the **hot path**, run at the edge on every request.
//!   A point membership check (`is_revoked(jti)`) against a locally-replicated,
//!   read-mostly set (CF KV / a Yubaba gossip replica).
//! - The **cold path** writer (`RevocationWriter`) lives in `cheers-server` —
//!   keeping it out of this crate means a verify-only edge consumer can check
//!   revocation without holding the power to revoke anyone else's sessions, the
//!   same capability-by-type discipline as the `TokenVerifier` / `TokenMinter`
//!   split.
//!
//! # The consistency contract
//!
//! The set is **eventually consistent** by design. A `revoke` at the origin
//! propagates to edge readers asynchronously (KV replication / gossip), so an
//! edge reader may briefly answer `false` for a `jti` the origin has already
//! revoked. That lag is bounded by the **access-token TTL**
//! (`cheers_server::SessionPolicy`): a revoked-but-not-yet-propagated access
//! token outlives its revocation by at most one short TTL, then expires on its
//! own signature.
//!
//! This is sound because auth has no cross-session OLTP — every check validates
//! *one* session, so the global hot path never needs a consistent view across
//! sessions. Revocation membership is the *only* shared auth state the edge
//! reads, and it tolerates lag.

use async_trait::async_trait;

use cheers_core::StoreError;

/// Edge-side revocation check. The verify-only consumer depends on *this* — it
/// can ask whether a `jti` is revoked but holds no power to revoke.
///
/// `async` + dyn-compatible (via [`async_trait`]) to match the rest of the store
/// surface, so an edge can hold a `dyn RevocationReader` backed by CF KV.
#[async_trait]
pub trait RevocationReader: Send + Sync {
    /// `true` if a session with this `jti` has been revoked.
    ///
    /// A point membership check against a read-mostly, eventually-consistent
    /// replica. A `false` answer is not a *proof* of liveness — only that the
    /// revocation, if any, has not yet propagated to this replica (bounded by
    /// the access-token TTL). Cryptographic expiry is still enforced separately
    /// by the [`TokenVerifier`](cheers_core::TokenVerifier).
    async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemRevocations(Mutex<HashSet<String>>);

    #[async_trait]
    impl RevocationReader for MemRevocations {
        async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
            Ok(self.0.lock().unwrap().contains(jti))
        }
    }

    #[test]
    fn unrevoked_jti_reads_false() {
        let set = MemRevocations::default();
        pollster::block_on(async {
            assert!(!set.is_revoked("tok-1").await.unwrap());
        });
    }

    #[test]
    fn trait_is_dyn_compatible() {
        fn _reader(_: &dyn RevocationReader) {}
    }
}
