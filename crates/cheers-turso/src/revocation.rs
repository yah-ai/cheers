//! [`RevocationWriter`] + [`RevocationReader`] over the in-process engine.
//!
//! One struct implements both halves, because in the cell-hosted model they
//! are the same process: the account cell writes the kill-list and answers
//! `is_revoked` for it. There is no edge/origin split to arrange here — the
//! engine's exclusive file lock means a separate edge process could not open
//! this database even if you wanted it to. An edge that needs its own copy
//! takes one over the capability surface (or runs `cheers-redis`), it does not
//! open the file.

use std::sync::Arc;

use async_trait::async_trait;
use cheers_core::StoreError;
use cheers_server::RevocationWriter;
use cheers_verify::RevocationReader;

use crate::conn::{ReadOnlyConn, TursoConn};
use crate::util::now;

/// The revocation set, both halves.
pub struct TursoRevocationStore {
    conn: Arc<TursoConn>,
}

impl TursoRevocationStore {
    pub fn new(conn: Arc<TursoConn>) -> Self {
        Self { conn }
    }

    pub fn conn(&self) -> &Arc<TursoConn> {
        &self.conn
    }

    /// Hand out a reader that structurally cannot write the kill-list.
    ///
    /// This is the read-capability path: a component that only needs to answer
    /// "is this jti dead?" gets a [`TursoRevocationReader`], which holds a
    /// [`ReadOnlyConn`] and implements [`RevocationReader`] and nothing else.
    pub fn reader(&self) -> TursoRevocationReader {
        TursoRevocationReader {
            conn: ReadOnlyConn::new(self.conn.clone()),
        }
    }

    /// Garbage-collect entries whose `expires_at` is at or before `now`.
    ///
    /// Call periodically to keep the table bounded. Rows with a NULL
    /// `expires_at` are never collected — that is the "revoked forever"
    /// spelling, and sweeping it would resurrect a dead token.
    pub async fn gc(&self, now: i64) -> Result<u64, StoreError> {
        self.conn
            .execute(
                "DELETE FROM revocations WHERE expires_at IS NOT NULL AND expires_at <= ?",
                vec![now.into()],
            )
            .await
    }
}

impl std::fmt::Debug for TursoRevocationStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TursoRevocationStore").finish_non_exhaustive()
    }
}

#[async_trait]
impl RevocationWriter for TursoRevocationStore {
    async fn revoke(&self, jti: &str) -> Result<(), StoreError> {
        // Idempotent by contract: re-revoking is a no-op, not a Conflict. The
        // first revocation's timestamp is the one that stands.
        self.conn
            .execute(
                "INSERT INTO revocations (jti, revoked_at) VALUES (?, ?)
                 ON CONFLICT (jti) DO NOTHING",
                vec![jti.into(), now().into()],
            )
            .await?;
        Ok(())
    }
}

#[async_trait]
impl RevocationReader for TursoRevocationStore {
    async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
        let row = self
            .conn
            .query_one(
                "SELECT 1 FROM revocations WHERE jti = ?",
                vec![jti.into()],
            )
            .await?;
        Ok(row.is_some())
    }
}

/// The read-only half of the revocation set.
///
/// Constructed via [`TursoRevocationStore::reader`]. It implements
/// [`RevocationReader`] only, and its handle refuses non-read statements — so
/// a component holding one cannot revoke, un-revoke, or garbage-collect,
/// whatever it does with it.
#[derive(Debug, Clone)]
pub struct TursoRevocationReader {
    conn: ReadOnlyConn,
}

#[async_trait]
impl RevocationReader for TursoRevocationReader {
    async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
        let row = self
            .conn
            .query_one(
                "SELECT 1 FROM revocations WHERE jti = ?",
                vec![jti.into()],
            )
            .await?;
        Ok(row.is_some())
    }
}
