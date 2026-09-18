//! [`UserTokenStore`] over the in-process engine — R728-F1.
//!
//! The persistent half of user API tokens (PATs). Schema-identical to
//! `cheers-sqlx`'s `SqliteUserTokenStore` by construction (migration 0007 is
//! byte-identical across both trees), so an account database can move between
//! the two families without a rewrite — `tests/flip.rs` is what keeps that
//! honest.
//!
//! **Nothing here is on a token's trust path.** A PAT is verified by signature
//! and killed through the revocation set; this table only records what the
//! user should see on `GET /me/tokens`. No secret and no hash of one is
//! stored — see [`cheers_server::user_tokens`] for why a column with no reader
//! would be a liability rather than a belt.

use std::sync::Arc;

use async_trait::async_trait;
use cheers_core::{StoreError, UserId};
use cheers_server::{decode_scopes, encode_scopes, UserTokenRecord, UserTokenStore};
use turso::Row;

use crate::conn::TursoConn;
use crate::util::{col, col_bool, opt_int};

/// Columns every read selects, in this order — one constant so the queries
/// and [`row_to_record`] cannot drift apart.
const COLUMNS: &str =
    "jti, user_id, name, scopes, aud, created_at, last_used_at, expires_at, revoked";

/// User API token metadata.
pub struct TursoUserTokenStore {
    conn: Arc<TursoConn>,
}

impl TursoUserTokenStore {
    pub fn new(conn: Arc<TursoConn>) -> Self {
        Self { conn }
    }

    pub fn conn(&self) -> &Arc<TursoConn> {
        &self.conn
    }

    /// Delete rows that expired at or before `now`.
    ///
    /// Optional hygiene, not correctness: an expired token is already dead by
    /// its own `exp` claim and `list_live_for_user` filters it out anyway.
    /// Revoked-but-unexpired rows are deliberately **not** collected — they
    /// are the user's record that a kill happened, and sweeping them would
    /// make a revoked token indistinguishable from one that never existed.
    pub async fn gc(&self, now: i64) -> Result<u64, StoreError> {
        self.conn
            .execute(
                "DELETE FROM user_tokens WHERE expires_at <= ?",
                vec![now.into()],
            )
            .await
    }
}

impl std::fmt::Debug for TursoUserTokenStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TursoUserTokenStore").finish_non_exhaustive()
    }
}

fn row_to_record(row: &Row) -> Result<UserTokenRecord, StoreError> {
    let scopes_raw: String = col(row, 3, "scopes")?;
    let mut rec = UserTokenRecord::new(
        col::<String>(row, 0, "jti")?,
        UserId::new(col::<String>(row, 1, "user_id")?),
        col::<String>(row, 2, "name")?,
        decode_scopes(&scopes_raw)?,
        col::<String>(row, 4, "aud")?,
        col::<i64>(row, 5, "created_at")?,
        col::<i64>(row, 7, "expires_at")?,
    );
    // `last_used_at` is the one nullable column; everything else is NOT NULL
    // in the migration, so only this one goes through an Option decode.
    rec.last_used_at = row.get::<Option<i64>>(6).map_err(|e| {
        StoreError::Backend(format!("decode column last_used_at: {e}"))
    })?;
    rec.revoked = col_bool(row, 8, "revoked")?;
    Ok(rec)
}

#[async_trait]
impl UserTokenStore for TursoUserTokenStore {
    async fn insert(&self, record: &UserTokenRecord) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT INTO user_tokens
                    (jti, user_id, name, scopes, aud, created_at, last_used_at,
                     expires_at, revoked)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    record.jti.as_str().into(),
                    record.user_id.as_str().into(),
                    record.name.as_str().into(),
                    encode_scopes(&record.scopes).into(),
                    record.aud.as_str().into(),
                    record.created_at.into(),
                    opt_int(record.last_used_at),
                    record.expires_at.into(),
                    i64::from(record.revoked).into(),
                ],
            )
            .await?;
        Ok(())
    }

    async fn list_live_for_user(
        &self,
        user_id: &UserId,
        now: i64,
    ) -> Result<Vec<UserTokenRecord>, StoreError> {
        // Newest first, matching the (user_id, created_at DESC) index the
        // migration ships. `revoked = 0` rather than `= FALSE` because this
        // column is INTEGER in the SQLite-flavor schema.
        let rows = self
            .conn
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM user_tokens
                     WHERE user_id = ? AND revoked = 0 AND expires_at > ?
                     ORDER BY created_at DESC"
                ),
                vec![user_id.as_str().into(), now.into()],
            )
            .await?;
        rows.iter().map(row_to_record).collect()
    }

    async fn get(&self, jti: &str) -> Result<Option<UserTokenRecord>, StoreError> {
        let row = self
            .conn
            .query_one(
                &format!("SELECT {COLUMNS} FROM user_tokens WHERE jti = ?"),
                vec![jti.into()],
            )
            .await?;
        row.as_ref().map(row_to_record).transpose()
    }

    async fn mark_revoked(&self, jti: &str) -> Result<(), StoreError> {
        // Unconditional on `revoked` so re-revoking is a no-op rather than a
        // NotFound — the contract is "this row ends up revoked". Zero rows
        // affected genuinely means there is no such row.
        let affected = self
            .conn
            .execute(
                "UPDATE user_tokens SET revoked = 1 WHERE jti = ?",
                vec![jti.into()],
            )
            .await?;
        if affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn touch_last_used(&self, jti: &str, now: i64) -> Result<(), StoreError> {
        let affected = self
            .conn
            .execute(
                "UPDATE user_tokens SET last_used_at = ? WHERE jti = ?",
                vec![now.into(), jti.into()],
            )
            .await?;
        if affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}
