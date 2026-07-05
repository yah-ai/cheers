//! Refresh-token rotation with replay detection.
//!
//! Sessions are minted by a [`TokenMinter`](cheers_core::TokenMinter); refresh
//! tokens are the *stateful* half — short-lived access tokens are exchanged
//! through a long-lived refresh token that rotates on every use. Each rotation:
//!
//! 1. consumes the presented token,
//! 2. issues a fresh successor sharing the same `chain_id`,
//! 3. links the successor back to its parent.
//!
//! If a *consumed* token is presented again, that's a replay — the entire
//! chain is revoked. The pattern (audited in Rauthy
//! `src/data/src/entity/sessions.rs`) keeps a stolen refresh token from
//! being usable indefinitely: the moment either the legitimate client or
//! the attacker rotates it, the next rotation by the other party trips the
//! replay path and severs both.
//!
//! ```no_run
//! # use cheers_server::refresh::RefreshRotator;
//! # use cheers_server::store::RefreshStore;
//! # use cheers_core::{RefreshError, UserId, DeviceId};
//! # async fn demo<S: RefreshStore + ?Sized>(store: &S) -> Result<(), RefreshError> {
//! let rotator = RefreshRotator::new(store, /* ttl_seconds */ 60 * 60 * 24 * 30);
//! let root = rotator.mint_root(UserId::new("u1"), DeviceId::new("d1"), 1_700_000_000).await?;
//! let next = rotator.rotate(root.token.as_str(), 1_700_000_001).await?;
//! assert_eq!(next.record.parent.as_deref(), Some(root.token.as_str()));
//! # Ok(()) }
//! ```

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use cheers_core::{DeviceId, RefreshError, UserId};

use crate::store::{RefreshStore, RefreshTokenRecord};

/// Length of the opaque refresh secret in bytes (256 bits of CSPRNG).
pub const REFRESH_TOKEN_BYTES: usize = 32;

/// Length of the chain identifier in bytes (128 bits — uniqueness only,
/// not a secret).
pub const CHAIN_ID_BYTES: usize = 16;

/// Opaque refresh-token secret. 32 random bytes, base64url-encoded for
/// transport. The wire format is what gets stored in `RefreshTokenRecord::token`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RefreshToken(String);

impl RefreshToken {
    /// Generate a fresh token from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; REFRESH_TOKEN_BYTES];
        getrandom::fill(&mut bytes).expect("OS CSPRNG must be available");
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Display for RefreshToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Identifier shared by every token in a single rotation chain.
///
/// One chain = one `(user, device)` login session. Revoking a chain logs out
/// that device.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ChainId(String);

impl ChainId {
    /// Generate a fresh chain id from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; CHAIN_ID_BYTES];
        getrandom::fill(&mut bytes).expect("OS CSPRNG must be available");
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Display for ChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Result of [`RefreshRotator::mint_root`] / [`RefreshRotator::rotate`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Rotated {
    /// The freshly issued secret. Hand this to the client; everything else
    /// in `record` is what's persisted.
    pub token: RefreshToken,
    pub record: RefreshTokenRecord,
}

/// Mint and rotate refresh tokens against a [`RefreshStore`].
///
/// Holds a borrow of the store; the rotator itself is cheap to construct
/// per request. `ttl_seconds` is the lifetime applied to every freshly
/// minted token (root *and* successor).
pub struct RefreshRotator<'s, S: RefreshStore + ?Sized> {
    store: &'s S,
    ttl_seconds: i64,
}

impl<'s, S: RefreshStore + ?Sized> RefreshRotator<'s, S> {
    pub fn new(store: &'s S, ttl_seconds: i64) -> Self {
        Self { store, ttl_seconds }
    }

    pub fn ttl_seconds(&self) -> i64 {
        self.ttl_seconds
    }

    /// Start a fresh chain. Returns the root token + persisted record.
    pub async fn mint_root(
        &self,
        user_id: UserId,
        device_id: DeviceId,
        now: i64,
    ) -> Result<Rotated, RefreshError> {
        let token = RefreshToken::generate();
        let chain_id = ChainId::generate();
        let record = RefreshTokenRecord {
            token: token.0.clone(),
            chain_id: chain_id.into_inner(),
            parent: None,
            user_id,
            device_id,
            issued_at: now,
            expires_at: now + self.ttl_seconds,
            consumed: false,
            revoked: false,
        };
        self.store.put(&record).await?;
        Ok(Rotated { token, record })
    }

    /// Rotate `presented` → fresh successor.
    ///
    /// Failure modes (in priority order):
    /// - [`RefreshError::Unknown`] — no record matches.
    /// - [`RefreshError::ChainRevoked`] — record exists but the chain is dead.
    /// - [`RefreshError::Replay`] — the token was already consumed; the
    ///   chain is revoked as a side effect of this call.
    /// - [`RefreshError::Expired`] — within TTL is required.
    pub async fn rotate(&self, presented: &str, now: i64) -> Result<Rotated, RefreshError> {
        let existing = self
            .store
            .get(presented)
            .await?
            .ok_or(RefreshError::Unknown)?;

        if existing.revoked {
            return Err(RefreshError::ChainRevoked);
        }
        if existing.consumed {
            // Replay: the token was already exchanged for a successor.
            // Revoke the entire chain so neither the legitimate client nor
            // the attacker can continue.
            self.store.revoke_chain(&existing.chain_id).await?;
            return Err(RefreshError::Replay);
        }
        if existing.expires_at <= now {
            return Err(RefreshError::Expired);
        }

        // Atomically consume *first*, and treat losing the race as a replay.
        // The `existing.consumed` check above is only a fast path off a stale
        // read — two concurrent rotations of the same live token can both pass
        // it. `mark_consumed` is the real gate: it flips false→true in a single
        // atomic step and returns `true` only to the winner. A `false` here
        // means a concurrent rotation already consumed this token (a
        // double-spend / stolen-token replay), so revoke the whole chain and
        // reject — exactly as if the caller had re-presented a consumed token.
        //
        // Consuming before minting the successor is deliberate: if the
        // successor `put` fails afterwards the worst case is a chain that can't
        // rotate further (the client retries, gets `Replay`, re-authenticates)
        // — far better than handing out two live tokens for one consume.
        if !self.store.mark_consumed(&existing.token).await? {
            self.store.revoke_chain(&existing.chain_id).await?;
            return Err(RefreshError::Replay);
        }

        let token = RefreshToken::generate();
        let record = RefreshTokenRecord {
            token: token.0.clone(),
            chain_id: existing.chain_id.clone(),
            parent: Some(existing.token.clone()),
            user_id: existing.user_id.clone(),
            device_id: existing.device_id.clone(),
            issued_at: now,
            expires_at: now + self.ttl_seconds,
            consumed: false,
            revoked: false,
        };
        self.store.put(&record).await?;
        Ok(Rotated { token, record })
    }

    /// Revoke every token in `chain_id`. Idempotent. Use on logout or
    /// device-revoke flows.
    pub async fn revoke_chain(&self, chain_id: &str) -> Result<(), RefreshError> {
        self.store.revoke_chain(chain_id).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use cheers_core::StoreError;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemRefreshStore(Mutex<HashMap<String, RefreshTokenRecord>>);

    #[async_trait]
    impl RefreshStore for MemRefreshStore {
        async fn put(&self, record: &RefreshTokenRecord) -> Result<(), StoreError> {
            self.0
                .lock()
                .unwrap()
                .insert(record.token.clone(), record.clone());
            Ok(())
        }
        async fn get(&self, token: &str) -> Result<Option<RefreshTokenRecord>, StoreError> {
            Ok(self.0.lock().unwrap().get(token).cloned())
        }
        async fn mark_consumed(&self, token: &str) -> Result<bool, StoreError> {
            let mut g = self.0.lock().unwrap();
            match g.get_mut(token) {
                Some(r) if !r.consumed => {
                    r.consumed = true;
                    Ok(true)
                }
                _ => Ok(false),
            }
        }
        async fn revoke_chain(&self, chain_id: &str) -> Result<(), StoreError> {
            let mut g = self.0.lock().unwrap();
            for r in g.values_mut() {
                if r.chain_id == chain_id {
                    r.revoked = true;
                }
            }
            Ok(())
        }
    }

    fn user() -> UserId {
        UserId::new("u1")
    }
    fn device() -> DeviceId {
        DeviceId::new("d1")
    }

    #[test]
    fn token_generation_is_random_and_long() {
        let a = RefreshToken::generate();
        let b = RefreshToken::generate();
        assert_ne!(a, b, "two generations must not collide");
        // base64url-no-pad of 32 bytes = ceil(32 * 4 / 3) = 43 chars.
        assert_eq!(a.as_str().len(), 43);
    }

    #[test]
    fn chain_id_generation_is_random() {
        let a = ChainId::generate();
        let b = ChainId::generate();
        assert_ne!(a, b);
        // 16 bytes b64url-no-pad = 22 chars.
        assert_eq!(a.as_str().len(), 22);
    }

    #[test]
    fn happy_path_mint_and_rotate() {
        let store = MemRefreshStore::default();
        let r = RefreshRotator::new(&store, 3_600);
        pollster::block_on(async {
            let root = r.mint_root(user(), device(), 100).await.unwrap();
            assert!(root.record.parent.is_none());
            assert!(!root.record.consumed);
            assert!(!root.record.revoked);
            assert_eq!(root.record.expires_at, 3_700);

            let next = r.rotate(root.token.as_str(), 200).await.unwrap();
            assert_eq!(next.record.parent.as_deref(), Some(root.token.as_str()));
            assert_eq!(next.record.chain_id, root.record.chain_id);
            assert_eq!(next.record.user_id, root.record.user_id);
            assert_eq!(next.record.device_id, root.record.device_id);
            assert_ne!(next.token, root.token);

            // Old token now reads as consumed.
            let stored_root = store.get(root.token.as_str()).await.unwrap().unwrap();
            assert!(stored_root.consumed);
            assert!(!stored_root.revoked);

            // The successor is fresh.
            let stored_next = store.get(next.token.as_str()).await.unwrap().unwrap();
            assert!(!stored_next.consumed);
            assert!(!stored_next.revoked);
        });
    }

    #[test]
    fn rotate_chain_continues_across_multiple_hops() {
        let store = MemRefreshStore::default();
        let r = RefreshRotator::new(&store, 3_600);
        pollster::block_on(async {
            let a = r.mint_root(user(), device(), 100).await.unwrap();
            let b = r.rotate(a.token.as_str(), 110).await.unwrap();
            let c = r.rotate(b.token.as_str(), 120).await.unwrap();
            let d = r.rotate(c.token.as_str(), 130).await.unwrap();

            for hop in [&a, &b, &c, &d] {
                assert_eq!(hop.record.chain_id, a.record.chain_id);
            }
            assert_eq!(b.record.parent.as_deref(), Some(a.token.as_str()));
            assert_eq!(c.record.parent.as_deref(), Some(b.token.as_str()));
            assert_eq!(d.record.parent.as_deref(), Some(c.token.as_str()));
        });
    }

    #[test]
    fn replay_revokes_entire_chain() {
        let store = MemRefreshStore::default();
        let r = RefreshRotator::new(&store, 3_600);
        pollster::block_on(async {
            let a = r.mint_root(user(), device(), 100).await.unwrap();
            let b = r.rotate(a.token.as_str(), 110).await.unwrap();
            let c = r.rotate(b.token.as_str(), 120).await.unwrap();

            // Replay `a` — it's already been rotated.
            let err = r.rotate(a.token.as_str(), 130).await.unwrap_err();
            assert!(matches!(err, RefreshError::Replay), "got {err:?}");

            // Every record in the chain is now revoked.
            for tok in [a.token.as_str(), b.token.as_str(), c.token.as_str()] {
                let rec = store.get(tok).await.unwrap().unwrap();
                assert!(rec.revoked, "{tok} should be revoked");
            }

            // Even the still-fresh tip can no longer rotate.
            let err = r.rotate(c.token.as_str(), 140).await.unwrap_err();
            assert!(matches!(err, RefreshError::ChainRevoked), "got {err:?}");
        });
    }

    #[test]
    fn lost_consume_race_is_treated_as_replay() {
        // Two concurrent rotations of the same live token: `get` still sees it
        // unconsumed (so the fast-path replay check passes), but the atomic
        // `mark_consumed` reports `false` because the other rotation won the
        // race. The rotator must treat that as a replay and revoke the chain —
        // otherwise a double-spend mints two live successors.
        struct LostRace(MemRefreshStore);
        #[async_trait]
        impl RefreshStore for LostRace {
            async fn put(&self, r: &RefreshTokenRecord) -> Result<(), StoreError> {
                self.0.put(r).await
            }
            async fn get(&self, t: &str) -> Result<Option<RefreshTokenRecord>, StoreError> {
                self.0.get(t).await
            }
            async fn mark_consumed(&self, _t: &str) -> Result<bool, StoreError> {
                Ok(false) // always "lost the race"
            }
            async fn revoke_chain(&self, c: &str) -> Result<(), StoreError> {
                self.0.revoke_chain(c).await
            }
        }
        let store = LostRace(MemRefreshStore::default());
        let r = RefreshRotator::new(&store, 3_600);
        pollster::block_on(async {
            let a = r.mint_root(user(), device(), 100).await.unwrap();
            let err = r.rotate(a.token.as_str(), 110).await.unwrap_err();
            assert!(matches!(err, RefreshError::Replay), "got {err:?}");
            // The chain is revoked as a side effect of the lost race.
            assert!(
                store.0.get(a.token.as_str()).await.unwrap().unwrap().revoked,
                "chain should be revoked when a rotation loses the consume race"
            );
        });
    }

    #[test]
    fn expired_token_rejected() {
        let store = MemRefreshStore::default();
        let r = RefreshRotator::new(&store, 60);
        pollster::block_on(async {
            let a = r.mint_root(user(), device(), 100).await.unwrap();
            // expires_at = 160; presenting at exactly 160 is expired.
            let err = r.rotate(a.token.as_str(), 160).await.unwrap_err();
            assert!(matches!(err, RefreshError::Expired), "got {err:?}");

            // The expired token is *not* marked consumed (the store is untouched
            // beyond the read), so a future call still reports Expired rather
            // than Replay. That matters for ops: an expired client should
            // re-auth without tripping the alarm-bell replay path.
            let stored = store.get(a.token.as_str()).await.unwrap().unwrap();
            assert!(!stored.consumed);
            assert!(!stored.revoked);
        });
    }

    #[test]
    fn unknown_token_rejected() {
        let store = MemRefreshStore::default();
        let r = RefreshRotator::new(&store, 60);
        pollster::block_on(async {
            let err = r.rotate("nope", 100).await.unwrap_err();
            assert!(matches!(err, RefreshError::Unknown), "got {err:?}");
        });
    }

    #[test]
    fn explicit_revoke_chain_blocks_future_rotation() {
        let store = MemRefreshStore::default();
        let r = RefreshRotator::new(&store, 3_600);
        pollster::block_on(async {
            let a = r.mint_root(user(), device(), 100).await.unwrap();
            r.revoke_chain(&a.record.chain_id).await.unwrap();

            let err = r.rotate(a.token.as_str(), 110).await.unwrap_err();
            assert!(matches!(err, RefreshError::ChainRevoked), "got {err:?}");
        });
    }

    #[test]
    fn revoke_chain_only_touches_its_own_chain() {
        let store = MemRefreshStore::default();
        let r = RefreshRotator::new(&store, 3_600);
        pollster::block_on(async {
            let a = r.mint_root(user(), device(), 100).await.unwrap();
            let other = r.mint_root(user(), device(), 100).await.unwrap();
            assert_ne!(a.record.chain_id, other.record.chain_id);

            r.revoke_chain(&a.record.chain_id).await.unwrap();
            assert!(store.get(a.token.as_str()).await.unwrap().unwrap().revoked);
            assert!(!store
                .get(other.token.as_str())
                .await
                .unwrap()
                .unwrap()
                .revoked);
        });
    }
}
