//! User API tokens (PATs) — the *metadata* half.
//!
//! A cheers API token is not a new credential kind. It is an ordinary
//! `v4.public` MCP token minted by
//! [`McpAuthority::mint_api_token`](crate::mcp_authority::McpAuthority::mint_api_token),
//! carrying `auth_strength: "api-token"`, verified at the edge by the same
//! [`PasetoV4PublicVerifier`](cheers_verify::PasetoV4PublicVerifier) and killed
//! by the same [`RevocationWriter`](crate::revocation::RevocationWriter) /
//! [`RevocationReader`](cheers_verify::RevocationReader) pair every other token
//! goes through. There is no second verification path and no secret-hash
//! lookup on the hot path.
//!
//! What *is* genuinely new is a row the user can look at: "you have a token
//! called `ci-deploy`, minted on the 3rd, expiring in November, scoped to
//! `cloud:read cloud:deploy`". That row is this module.
//!
//! ## No secret, and no hash of one, is stored
//!
//! [`UserTokenRecord`] has no `secret` and no `secret_hash` column, on
//! purpose. Verification is by signature — cheers never looks the presented
//! bytes up — so a stored hash would have no reader. A column with no reader
//! that nonetheless has to be protected is a liability with no benefit: it
//! widens what a database leak is worth and invites a future edge to "just
//! check the hash", which is the parallel stack this design exists to avoid.
//! The secret is returned by `POST /me/tokens` exactly once and then exists
//! only in the holder's hands.
//!
//! ## `last_used_at`
//!
//! The column exists and is surfaced, but **cheers never writes it.** The only
//! place a use could be observed is the verify edge, and an
//! [`EdgeVerifier`](cheers_verify::EdgeVerifier) deliberately holds a
//! `RevocationReader` and no writer at all — giving it a store write would
//! undo the property that a compromised edge cannot mutate origin state.
//! [`UserTokenStore::touch_last_used`] is the seam for a *resource server*
//! (which is already doing per-call work and already holds writable state) to
//! record the touch. Absent one, the field stays `None`, and that is an honest
//! "cheers doesn't know" rather than a silently stale timestamp.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use cheers_core::{Scope, StoreError, UserId};

/// One user API token's metadata — everything except the secret.
///
/// `jti` is the token's own id: the value baked into the signed claim, the key
/// the revocation set is keyed on, and the `{id}` in
/// `DELETE /me/tokens/{id}`. One id, three places, no mapping table.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UserTokenRecord {
    /// The minted token's `jti` — also the public id of this row.
    pub jti: String,
    /// Owner. Every read path filters on this; a `jti` alone is never enough
    /// to act on a row.
    pub user_id: UserId,
    /// Human label the user chose ("ci-deploy", "laptop"). Opaque to cheers.
    pub name: String,
    /// The scopes actually minted into the token — already intersected with
    /// the caller's entitlement, so this is what the token *can do*, not what
    /// was asked for.
    pub scopes: Vec<Scope>,
    /// The audience the token was minted for. Grants are keyed
    /// `(principal, aud)`, so a token is never audience-portable.
    pub aud: String,
    pub created_at: i64,
    /// Last observed use, when a resource server reports one. See the module
    /// docs — cheers itself never writes this.
    pub last_used_at: Option<i64>,
    pub expires_at: i64,
    /// Set by [`UserTokenStore::mark_revoked`]. The signed token is killed by
    /// the revocation set; this is the half that makes the kill *visible* on
    /// `GET /me/tokens`.
    pub revoked: bool,
}

impl UserTokenRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        jti: impl Into<String>,
        user_id: UserId,
        name: impl Into<String>,
        scopes: Vec<Scope>,
        aud: impl Into<String>,
        created_at: i64,
        expires_at: i64,
    ) -> Self {
        Self {
            jti: jti.into(),
            user_id,
            name: name.into(),
            scopes,
            aud: aud.into(),
            created_at,
            last_used_at: None,
            expires_at,
            revoked: false,
        }
    }

    /// Live at `now` — neither revoked nor past its expiry.
    pub fn is_live_at(&self, now: i64) -> bool {
        !self.revoked && self.expires_at > now
    }
}

/// Wire form of the `user_tokens.scopes` column: the scopes' wire strings,
/// space-separated, in order.
///
/// Lives here rather than in each backend so `cheers-sqlx` and `cheers-turso`
/// cannot drift — a row written by one family must be readable by the other,
/// which is exactly what `cheers-turso/tests/flip.rs` exists to prove. Space
/// is safe as a separator because [`Scope`]'s closed vocabulary contains no
/// whitespace, and it matches the OAuth `scope` convention the claim itself
/// uses.
pub fn encode_scopes(scopes: &[Scope]) -> String {
    scopes
        .iter()
        .map(|s| s.as_wire())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Inverse of [`encode_scopes`].
///
/// A token outside the closed vocabulary is [`StoreError::Backend`], not a
/// silent skip: a scope cheers cannot parse in a row it wrote itself means the
/// table has drifted from the code, and quietly handing back a shorter list
/// would present the user a token weaker than the one they hold.
pub fn decode_scopes(raw: &str) -> Result<Vec<Scope>, StoreError> {
    raw.split_whitespace()
        .map(|s| {
            s.parse::<Scope>()
                .map_err(|e| StoreError::Backend(format!("user_tokens.scopes: {e}")))
        })
        .collect()
}

/// Persistence for the user-API-token metadata table.
///
/// Deliberately *not* part of the token's trust path: nothing here is
/// consulted to decide whether a presented token is valid. An impl that
/// returned garbage would corrupt the user's token list and nothing else.
#[async_trait]
pub trait UserTokenStore: Send + Sync {
    /// Record a freshly minted token. The `jti` is unique by construction
    /// (fresh per mint); an impl MAY reject a duplicate with
    /// [`StoreError::Conflict`]-shaped semantics but is not required to check.
    async fn insert(&self, record: &UserTokenRecord) -> Result<(), StoreError>;

    /// Every **live** token the user holds at `now` — impls filter out revoked
    /// and expired rows, the same contract
    /// [`SessionDirectory`](https://docs.rs/cheers-axum) carries for sessions.
    /// Order is unspecified.
    async fn list_live_for_user(
        &self,
        user_id: &UserId,
        now: i64,
    ) -> Result<Vec<UserTokenRecord>, StoreError>;

    /// One row by `jti`, revoked or expired rows included — the revoke path
    /// needs to distinguish "not yours" from "already dead", and only the
    /// caller of this decides which of those the client gets told.
    async fn get(&self, jti: &str) -> Result<Option<UserTokenRecord>, StoreError>;

    /// Flip `revoked`. Idempotent: revoking an already-revoked row is `Ok`.
    /// A `jti` with no row is [`StoreError::NotFound`].
    async fn mark_revoked(&self, jti: &str) -> Result<(), StoreError>;

    /// Stamp `last_used_at`. Called by a resource server, never by cheers —
    /// see the module docs. A `jti` with no row is [`StoreError::NotFound`].
    async fn touch_last_used(&self, jti: &str, now: i64) -> Result<(), StoreError>;
}

/// In-memory [`UserTokenStore`] for tests and single-node bootstrapping.
/// Cheap to `clone` — shares one backing map.
#[derive(Default, Clone)]
pub struct MemoryUserTokenStore {
    inner: Arc<Mutex<HashMap<String, UserTokenRecord>>>,
}

impl MemoryUserTokenStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Row count, live and dead. Test affordance.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("user token store poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl UserTokenStore for MemoryUserTokenStore {
    async fn insert(&self, record: &UserTokenRecord) -> Result<(), StoreError> {
        self.inner
            .lock()
            .expect("user token store poisoned")
            .insert(record.jti.clone(), record.clone());
        Ok(())
    }

    async fn list_live_for_user(
        &self,
        user_id: &UserId,
        now: i64,
    ) -> Result<Vec<UserTokenRecord>, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("user token store poisoned")
            .values()
            .filter(|r| &r.user_id == user_id && r.is_live_at(now))
            .cloned()
            .collect())
    }

    async fn get(&self, jti: &str) -> Result<Option<UserTokenRecord>, StoreError> {
        Ok(self
            .inner
            .lock()
            .expect("user token store poisoned")
            .get(jti)
            .cloned())
    }

    async fn mark_revoked(&self, jti: &str) -> Result<(), StoreError> {
        let mut guard = self.inner.lock().expect("user token store poisoned");
        match guard.get_mut(jti) {
            Some(row) => {
                row.revoked = true;
                Ok(())
            }
            None => Err(StoreError::NotFound),
        }
    }

    async fn touch_last_used(&self, jti: &str, now: i64) -> Result<(), StoreError> {
        let mut guard = self.inner.lock().expect("user token store poisoned");
        match guard.get_mut(jti) {
            Some(row) => {
                row.last_used_at = Some(now);
                Ok(())
            }
            None => Err(StoreError::NotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pollster::block_on;

    fn rec(jti: &str, user: &str, expires_at: i64) -> UserTokenRecord {
        UserTokenRecord::new(
            jti,
            UserId::new(user),
            "ci",
            vec![Scope::CloudRead],
            "https://kamaji.example",
            1_000,
            expires_at,
        )
    }

    #[test]
    fn insert_then_list_returns_only_the_owner_s_live_rows() {
        let store = MemoryUserTokenStore::new();
        block_on(store.insert(&rec("j1", "alice", 9_000))).unwrap();
        block_on(store.insert(&rec("j2", "bob", 9_000))).unwrap();

        let alice = block_on(store.list_live_for_user(&UserId::new("alice"), 2_000)).unwrap();
        assert_eq!(alice.len(), 1);
        assert_eq!(alice[0].jti, "j1");
    }

    #[test]
    fn expired_and_revoked_rows_drop_out_of_the_live_list_but_stay_gettable() {
        let store = MemoryUserTokenStore::new();
        block_on(store.insert(&rec("live", "alice", 9_000))).unwrap();
        block_on(store.insert(&rec("expired", "alice", 1_500))).unwrap();
        block_on(store.insert(&rec("revoked", "alice", 9_000))).unwrap();
        block_on(store.mark_revoked("revoked")).unwrap();

        let live = block_on(store.list_live_for_user(&UserId::new("alice"), 2_000)).unwrap();
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].jti, "live");

        // Revocation is not deletion — the row survives so the revoke path can
        // tell "not yours" from "already dead".
        assert!(block_on(store.get("revoked")).unwrap().unwrap().revoked);
        assert!(block_on(store.get("expired")).unwrap().is_some());
    }

    #[test]
    fn mark_revoked_is_idempotent_and_unknown_jti_is_not_found() {
        let store = MemoryUserTokenStore::new();
        block_on(store.insert(&rec("j1", "alice", 9_000))).unwrap();
        block_on(store.mark_revoked("j1")).unwrap();
        block_on(store.mark_revoked("j1")).unwrap();
        match block_on(store.mark_revoked("nope")) {
            Err(StoreError::NotFound) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn scopes_round_trip_through_the_column_encoding() {
        let scopes = vec![Scope::CloudRead, Scope::BoardWrite, Scope::CampAdmin];
        let raw = encode_scopes(&scopes);
        assert_eq!(raw, "cloud:read board:write camp:admin");
        assert_eq!(decode_scopes(&raw).unwrap(), scopes);

        // The empty list is a legal value and must survive the round trip —
        // it is not the same thing as a NULL column.
        assert_eq!(encode_scopes(&[]), "");
        assert_eq!(decode_scopes("").unwrap(), Vec::<Scope>::new());
    }

    /// A scope cheers cannot parse in a row cheers wrote means the table has
    /// drifted from the code. Loud, not a silently shorter list.
    #[test]
    fn decode_scopes_refuses_an_unknown_token() {
        match decode_scopes("cloud:read cloud:teleport") {
            Err(StoreError::Backend(msg)) => assert!(msg.contains("cloud:teleport"), "{msg}"),
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn touch_last_used_stamps_the_row() {
        let store = MemoryUserTokenStore::new();
        block_on(store.insert(&rec("j1", "alice", 9_000))).unwrap();
        assert!(block_on(store.get("j1")).unwrap().unwrap().last_used_at.is_none());
        block_on(store.touch_last_used("j1", 4_242)).unwrap();
        assert_eq!(
            block_on(store.get("j1")).unwrap().unwrap().last_used_at,
            Some(4_242)
        );
        match block_on(store.touch_last_used("nope", 1)) {
            Err(StoreError::NotFound) => {}
            other => panic!("expected NotFound, got {other:?}"),
        }
    }
}
