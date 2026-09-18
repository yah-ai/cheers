//! [`UsedJtiStore`](cheers_core::UsedJtiStore) over the in-process engine.
//!
//! Persistent single-use tracking for magic-link tokens — R727-B1. The
//! previous (and until this crate, only) impl was
//! `cheers::email::magic_link::MemoryUsedJtiStore`, an in-process
//! `Mutex<HashMap>` that forgets every redeemed jti on restart, re-arming
//! every outstanding magic-link URL for the rest of its TTL. This impl
//! survives a restart by construction: it's the same `used_jti` table
//! whichever process opens the file.

use std::sync::Arc;

use async_trait::async_trait;
use cheers_core::UsedJtiStore;

use crate::conn::TursoConn;

/// Persistent [`UsedJtiStore`] over the in-process engine.
pub struct TursoUsedJtiStore {
    conn: Arc<TursoConn>,
}

impl TursoUsedJtiStore {
    pub fn new(conn: Arc<TursoConn>) -> Self {
        Self { conn }
    }

    pub fn conn(&self) -> &Arc<TursoConn> {
        &self.conn
    }

    /// Garbage-collect entries whose `expires_at` is at or before `now`.
    ///
    /// Call periodically to keep the table bounded — every magic-link ever
    /// requested (clicked or not) is its own row until this runs.
    pub async fn gc(&self, now: i64) -> Result<u64, String> {
        self.conn
            .execute(
                "DELETE FROM used_jti WHERE expires_at <= ?",
                vec![now.into()],
            )
            .await
            .map_err(|e| e.to_string())
    }
}

impl std::fmt::Debug for TursoUsedJtiStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TursoUsedJtiStore").finish_non_exhaustive()
    }
}

#[async_trait]
impl UsedJtiStore for TursoUsedJtiStore {
    async fn try_mark_used(&self, jti: &str, expires_at: i64) -> Result<bool, String> {
        // ON CONFLICT DO NOTHING makes the insert-if-absent atomic; the
        // affected-row count tells us whether this call was the one that
        // claimed the jti (1) or a replay of an already-claimed one (0).
        let rows = self
            .conn
            .execute(
                "INSERT INTO used_jti (jti, expires_at) VALUES (?, ?)
                 ON CONFLICT (jti) DO NOTHING",
                vec![jti.into(), expires_at.into()],
            )
            .await
            .map_err(|e| e.to_string())?;
        Ok(rows == 1)
    }
}
