//! [`RefreshStore`] over the in-process engine.
//!
//! The rotation *contract* is enforced by `cheers_server::RefreshRotator`;
//! this impl owns persistence only — get / put / mark_consumed / revoke_chain
//! mapped one-to-one onto SQL.

use std::sync::Arc;

use async_trait::async_trait;
use cheers_core::{DeviceId, StoreError, UserId};
use cheers_server::store::{RefreshStore, RefreshTokenRecord};

use crate::conn::TursoConn;
use crate::util::{col, col_bool, opt_text};

/// The column list every read shares, in the order [`row_to_record`] expects.
const COLUMNS: &str = "token, chain_id, parent, user_id, device_id, \
                       issued_at, expires_at, consumed, revoked";

/// [`RefreshStore`] backed by an in-process Turso database.
pub struct TursoRefreshStore {
    conn: Arc<TursoConn>,
}

impl TursoRefreshStore {
    pub fn new(conn: Arc<TursoConn>) -> Self {
        Self { conn }
    }

    pub fn conn(&self) -> &Arc<TursoConn> {
        &self.conn
    }
}

impl std::fmt::Debug for TursoRefreshStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TursoRefreshStore").finish_non_exhaustive()
    }
}

fn row_to_record(row: &turso::Row) -> Result<RefreshTokenRecord, StoreError> {
    Ok(RefreshTokenRecord::new(
        col::<String>(row, 0, "token")?,
        col::<String>(row, 1, "chain_id")?,
        col::<Option<String>>(row, 2, "parent")?,
        UserId::new(col::<String>(row, 3, "user_id")?),
        DeviceId::new(col::<String>(row, 4, "device_id")?),
        col::<i64>(row, 5, "issued_at")?,
        col::<i64>(row, 6, "expires_at")?,
        col_bool(row, 7, "consumed")?,
        col_bool(row, 8, "revoked")?,
    ))
}

#[async_trait]
impl RefreshStore for TursoRefreshStore {
    async fn put(&self, record: &RefreshTokenRecord) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT INTO refresh_tokens
                    (token, chain_id, parent, user_id, device_id,
                     issued_at, expires_at, consumed, revoked)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    record.token.as_str().into(),
                    record.chain_id.as_str().into(),
                    opt_text(record.parent.as_deref()),
                    record.user_id.as_str().into(),
                    record.device_id.as_str().into(),
                    record.issued_at.into(),
                    record.expires_at.into(),
                    i64::from(record.consumed).into(),
                    i64::from(record.revoked).into(),
                ],
            )
            .await?;
        Ok(())
    }

    async fn get(&self, token: &str) -> Result<Option<RefreshTokenRecord>, StoreError> {
        let row = self
            .conn
            .query_one(
                &format!("SELECT {COLUMNS} FROM refresh_tokens WHERE token = ?"),
                vec![token.into()],
            )
            .await?;
        row.as_ref().map(row_to_record).transpose()
    }

    async fn mark_consumed(&self, token: &str) -> Result<bool, StoreError> {
        // The conditional UPDATE *is* the atomic consume gate: only a row still
        // at `consumed = 0` is flipped, so exactly one of two racing rotations
        // touches it. Zero rows affected means already-consumed (or absent),
        // which the rotator reads as a lost race / replay and turns into a
        // chain revocation. Splitting this into a read-then-write would let
        // both racers observe `consumed = 0` and each mint a live successor —
        // that is the replay hole this method exists to close.
        let affected = self
            .conn
            .execute(
                "UPDATE refresh_tokens SET consumed = 1 WHERE token = ? AND consumed = 0",
                vec![token.into()],
            )
            .await?;
        Ok(affected > 0)
    }

    async fn revoke_chain(&self, chain_id: &str) -> Result<(), StoreError> {
        // Idempotent — the contract is "every record in this chain ends up
        // revoked", so an empty chain is a success, not a NotFound.
        self.conn
            .execute(
                "UPDATE refresh_tokens SET revoked = 1 WHERE chain_id = ?",
                vec![chain_id.into()],
            )
            .await?;
        Ok(())
    }
}
