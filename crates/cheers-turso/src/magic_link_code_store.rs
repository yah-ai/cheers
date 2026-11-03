//! [`MagicLinkCodeStore`](cheers_core::MagicLinkCodeStore) over the in-process
//! engine (migration 0019; CHE-R961).
//!
//! Sign-in codes for bound magic-link grants, one row per S256 challenge. The
//! attempt counter is charged by a single `UPDATE … RETURNING`, so concurrent
//! guesses against one code can never spend more than the cap between them.

use std::sync::Arc;

use async_trait::async_trait;
use cheers_core::{MagicLinkCode, MagicLinkCodeStore, StoreError};
use turso::Row;

use crate::conn::TursoConn;
use crate::util::col;

/// Persistent [`MagicLinkCodeStore`] over the in-process engine.
pub struct TursoMagicLinkCodeStore {
    conn: Arc<TursoConn>,
}

impl TursoMagicLinkCodeStore {
    pub fn new(conn: Arc<TursoConn>) -> Self {
        Self { conn }
    }

    pub fn conn(&self) -> &Arc<TursoConn> {
        &self.conn
    }

    /// Delete codes whose `expires_at` is at or before `now`. A code that
    /// expires unredeemed is otherwise never touched again.
    pub async fn gc(&self, now: i64) -> Result<u64, String> {
        self.conn
            .execute(
                "DELETE FROM magic_link_codes WHERE expires_at <= ?",
                vec![now.into()],
            )
            .await
            .map_err(|e| e.to_string())
    }
}

impl std::fmt::Debug for TursoMagicLinkCodeStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TursoMagicLinkCodeStore").finish_non_exhaustive()
    }
}

fn row_to_code(row: &Row) -> Result<MagicLinkCode, StoreError> {
    let attempts = col::<i64>(row, 4, "attempts")?;
    let mut code = MagicLinkCode::new(
        col::<String>(row, 0, "challenge")?,
        col::<String>(row, 1, "jti")?,
        col::<String>(row, 2, "email")?,
        col::<String>(row, 3, "code_hash")?,
        col::<i64>(row, 5, "expires_at")?,
        col::<i64>(row, 6, "grant_expires_at")?,
    );
    code.attempts = u32::try_from(attempts)
        .map_err(|_| StoreError::Backend(format!("bad attempts count {attempts}")))?;
    Ok(code)
}

#[async_trait]
impl MagicLinkCodeStore for TursoMagicLinkCodeStore {
    async fn put(&self, code: &MagicLinkCode) -> Result<(), String> {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO magic_link_codes
                     (challenge, jti, email, code_hash, attempts, expires_at, grant_expires_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
                vec![
                    code.challenge.as_str().into(),
                    code.jti.as_str().into(),
                    code.email.as_str().into(),
                    code.code_hash.as_str().into(),
                    i64::from(code.attempts).into(),
                    code.expires_at.into(),
                    code.grant_expires_at.into(),
                ],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    async fn take_attempt(
        &self,
        challenge: &str,
        max_attempts: u32,
        now: i64,
    ) -> Result<Option<MagicLinkCode>, String> {
        // `query`, not `query_one`: it steps the statement to completion, so
        // the increment is written before the connection is released.
        let rows = self
            .conn
            .query(
                "UPDATE magic_link_codes SET attempts = attempts + 1
                 WHERE challenge = ? AND expires_at > ? AND attempts < ?
                 RETURNING challenge, jti, email, code_hash, attempts, expires_at, grant_expires_at",
                vec![challenge.into(), now.into(), i64::from(max_attempts).into()],
            )
            .await
            .map_err(|e| e.to_string())?;
        rows.first()
            .map(row_to_code)
            .transpose()
            .map_err(|e| e.to_string())
    }

    async fn delete_for_jti(&self, jti: &str) -> Result<(), String> {
        self.conn
            .execute(
                "DELETE FROM magic_link_codes WHERE jti = ?",
                vec![jti.into()],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(())
    }
}
