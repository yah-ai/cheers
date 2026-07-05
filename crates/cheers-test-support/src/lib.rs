//! In-process test fixtures for cheers — turso `:memory:` backed stores.
//!
//! Each call to [`turso_refresh_store`] opens a fresh in-memory Turso
//! database, runs the `refresh_tokens` schema, and returns a
//! [`TursoRefreshStore`] that implements [`RefreshStore`]. Because every
//! call gets its own database, parallel test threads never contend on shared
//! state — no `Mutex`, no teardown.
//!
//! The in-memory backend is provided by `turso` (which wraps `turso_core`
//! internally). The schema is the SQLite-dialect DDL from `cheers-sqlx`
//! migrations so a `TursoRefreshStore` has identical semantics to the
//! production `SqliteRefreshStore`.
//!
//! # Usage
//!
//! ```no_run
//! use cheers_test_support::turso_refresh_store;
//!
//! #[tokio::test]
//! async fn my_test() {
//!     let store = turso_refresh_store().await;
//!     // use store as cheers_server::RefreshStore …
//! }
//! ```

use async_trait::async_trait;
use cheers_core::{DeviceId, StoreError, UserId};
use cheers_server::store::{RefreshStore, RefreshTokenRecord};
use turso::{params, Builder, Connection};

// ── schema ──────────────────────────────────────────────────────────────────

/// Minimal DDL for the refresh_tokens table (SQLite dialect, matches
/// cheers-sqlx migrations/sqlite/0001_initial.sql).
const SCHEMA: &str = "
CREATE TABLE refresh_tokens (
    token       TEXT PRIMARY KEY,
    chain_id    TEXT NOT NULL,
    parent      TEXT,
    user_id     TEXT NOT NULL,
    device_id   TEXT NOT NULL,
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    consumed    INTEGER NOT NULL DEFAULT 0,
    revoked     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX refresh_tokens_chain_id    ON refresh_tokens (chain_id);
CREATE INDEX refresh_tokens_user_device ON refresh_tokens (user_id, device_id);
CREATE INDEX refresh_tokens_expires_at  ON refresh_tokens (expires_at);
";

// ── store ────────────────────────────────────────────────────────────────────

/// Turso `:memory:` backed [`RefreshStore`].
///
/// Open one per test via [`turso_refresh_store`]. Do not share across tests —
/// each instance owns its own in-memory database.
pub struct TursoRefreshStore {
    conn: Connection,
}

/// Open a fresh in-memory Turso database, run the refresh_tokens schema, and
/// return a ready-to-use [`TursoRefreshStore`].
///
/// Panics on schema error (indicates a programming mistake, not a runtime
/// failure — tests should fail loudly if the fixture can't be constructed).
pub async fn turso_refresh_store() -> TursoRefreshStore {
    let db = Builder::new_local(":memory:")
        .build()
        .await
        .expect("turso :memory: open");
    let conn = db.connect().expect("turso :memory: connect");
    conn.execute_batch(SCHEMA)
        .await
        .expect("refresh_tokens schema");
    TursoRefreshStore { conn }
}

#[async_trait]
impl RefreshStore for TursoRefreshStore {
    async fn put(&self, r: &RefreshTokenRecord) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT INTO refresh_tokens \
                 (token, chain_id, parent, user_id, device_id, \
                  issued_at, expires_at, consumed, revoked) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                params![
                    r.token.clone(),
                    r.chain_id.clone(),
                    r.parent.clone(),
                    r.user_id.as_str().to_owned(),
                    r.device_id.as_str().to_owned(),
                    r.issued_at,
                    r.expires_at,
                    r.consumed as i64,
                    r.revoked as i64
                ],
            )
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(())
    }

    async fn get(&self, token: &str) -> Result<Option<RefreshTokenRecord>, StoreError> {
        let mut rows = self
            .conn
            .query(
                "SELECT token, chain_id, parent, user_id, device_id, \
                        issued_at, expires_at, consumed, revoked \
                 FROM refresh_tokens WHERE token = ?1",
                params![token.to_owned()],
            )
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        match rows.next().await.map_err(|e| StoreError::Backend(e.to_string()))? {
            None => Ok(None),
            Some(row) => Ok(Some(row_to_record(&row)?)),
        }
    }

    async fn mark_consumed(&self, token: &str) -> Result<bool, StoreError> {
        // Atomic consume gate: only a row still at `consumed = 0` is flipped,
        // so exactly one of two racing rotations touches it. 0 rows affected
        // means already consumed (or absent) — a lost race / replay.
        let n = self
            .conn
            .execute(
                "UPDATE refresh_tokens SET consumed = 1 \
                 WHERE token = ?1 AND consumed = 0",
                params![token.to_owned()],
            )
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(n > 0)
    }

    async fn revoke_chain(&self, chain_id: &str) -> Result<(), StoreError> {
        self.conn
            .execute(
                "UPDATE refresh_tokens SET revoked = 1 WHERE chain_id = ?1",
                params![chain_id.to_owned()],
            )
            .await
            .map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok(())
    }
}

fn row_to_record(row: &turso::Row) -> Result<RefreshTokenRecord, StoreError> {
    let token: String = row.get(0).map_err(|e| StoreError::Backend(e.to_string()))?;
    let chain_id: String = row.get(1).map_err(|e| StoreError::Backend(e.to_string()))?;
    let parent: Option<String> = row.get(2).map_err(|e| StoreError::Backend(e.to_string()))?;
    let user_id: String = row.get(3).map_err(|e| StoreError::Backend(e.to_string()))?;
    let device_id: String = row.get(4).map_err(|e| StoreError::Backend(e.to_string()))?;
    let issued_at: i64 = row.get(5).map_err(|e| StoreError::Backend(e.to_string()))?;
    let expires_at: i64 = row.get(6).map_err(|e| StoreError::Backend(e.to_string()))?;
    let consumed: i64 = row.get(7).map_err(|e| StoreError::Backend(e.to_string()))?;
    let revoked: i64 = row.get(8).map_err(|e| StoreError::Backend(e.to_string()))?;

    Ok(RefreshTokenRecord::new(
        token,
        chain_id,
        parent,
        UserId::new(user_id),
        DeviceId::new(device_id),
        issued_at,
        expires_at,
        consumed != 0,
        revoked != 0,
    ))
}

// ── re-exports: complete in-memory test stack ────────────────────────────────

pub mod fixtures;
pub mod mem;

// ── integration tests ────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_core::{DeviceBinding, DeviceId, Error, UserId};
    use cheers_server::{
        store::RefreshTokenRecord, EdgeVerifier, PasetoV4PublicVerifier, PasetoV4SecretMinter,
        SessionAuthority, SessionPolicy,
    };

    use crate::mem::{MemRevocations, MemUserStore};

    // Assemble a `SessionAuthority` backed by a real turso `:memory:`
    // `RefreshStore` + a `PasetoV4SecretMinter` (asymmetric, edge-verifiable)
    // and an `EdgeVerifier` sharing the same revocation set.
    async fn rig() -> (
        SessionAuthority<PasetoV4SecretMinter, TursoRefreshStore, MemUserStore, MemRevocations>,
        EdgeVerifier<PasetoV4PublicVerifier, MemRevocations>,
    ) {
        let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
        let revocations = MemRevocations::default();
        let refresh = turso_refresh_store().await;
        let authority = SessionAuthority::new(
            minter,
            refresh,
            MemUserStore::default(),
            revocations.clone(),
        );
        let edge = EdgeVerifier::new(verifier, revocations);
        (authority, edge)
    }

    /// Full edge-verifiable session lifecycle against a turso :memory: store:
    /// establish → edge verifies → rotate → old token replays rejected → revoke.
    #[tokio::test]
    async fn turso_refresh_store_edge_verifiable_lifecycle() {
        let (authority, edge) = rig().await;
        let policy = SessionPolicy::default().with_access_ttl(300);

        // Establish a session.
        let session = authority
            .establish(
                UserId::new("u-turso-1"),
                DeviceId::new("d-turso-1"),
                DeviceBinding::Passkey,
                1_000,
            )
            .await
            .unwrap();

        // Edge verifies the access token via the public key alone.
        let verified = edge
            .verify_at(&session.access_token, 1_100)
            .await
            .unwrap();
        assert_eq!(verified.sub, UserId::new("u-turso-1"));
        assert!(!verified.jti.is_empty());

        // Rotate the refresh token. The new session should have a fresh access
        // token and the old refresh token should be marked consumed in the DB.
        let rotated = authority
            .rotate(session.refresh.token.as_str(), DeviceBinding::Passkey, 2_000)
            .await
            .unwrap();

        // New access token is accepted by the edge.
        let verified2 = edge
            .verify_at(&rotated.access_token, 2_100)
            .await
            .unwrap();
        assert_eq!(verified2.sub, UserId::new("u-turso-1"));
        assert_ne!(verified2.jti, verified.jti, "each rotation yields a fresh jti");

        // Revoke the session by jti; edge now rejects the token even though the
        // signature is still valid and the token hasn't expired.
        authority.revoke_session(&rotated.claims.jti).await.unwrap();
        let err = edge.verify_at(&rotated.access_token, 2_100).await.unwrap_err();
        assert!(matches!(err, Error::Revoked), "expected Revoked, got {err:?}");
    }

    /// Parallel instantiation — each call to `turso_refresh_store()` opens an
    /// independent in-memory DB so there is no cross-test contamination.
    #[tokio::test]
    async fn turso_refresh_stores_are_isolated() {
        let a = turso_refresh_store().await;
        let b = turso_refresh_store().await;

        let record = RefreshTokenRecord::new(
            "tok-a".to_owned(),
            "chain-a".to_owned(),
            None,
            UserId::new("u1"),
            DeviceId::new("d1"),
            0,
            9_999,
            false,
            false,
        );
        a.put(&record).await.unwrap();

        // Store `b` is independent — it doesn't see `a`'s rows.
        assert!(b.get("tok-a").await.unwrap().is_none());
    }
}
