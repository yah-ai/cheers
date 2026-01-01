//! [`RevocationWriter`](cheers_server::RevocationWriter) +
//! [`RevocationReader`](cheers_verify::RevocationReader) over `sqlx`.
//!
//! Single struct implements both halves — the typical pg/sqlite deployment
//! has the same DB host serving the origin's write side and the edge's read
//! side. For a real edge/origin split, swap in `cheers_redis` (eventually-
//! consistent KV) on the edge and let the origin keep this one too.

use async_trait::async_trait;
use cheers_core::StoreError;
use cheers_server::RevocationWriter;
use cheers_verify::RevocationReader;

use crate::error::map_sqlx_error;

#[cfg(feature = "pg")]
pub use pg::PgRevocationStore;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteRevocationStore;

#[cfg(feature = "pg")]
mod pg {
    use super::*;
    use sqlx::PgPool;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Revocation set over Postgres. Implements both
    /// [`RevocationWriter`] (origin side) and
    /// [`RevocationReader`](cheers_verify::RevocationReader) (edge side).
    pub struct PgRevocationStore {
        pool: PgPool,
    }

    impl PgRevocationStore {
        pub fn new(pool: PgPool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &PgPool {
            &self.pool
        }

        /// Garbage-collect entries whose `expires_at` is at or before `now`.
        /// Call periodically (e.g. once an hour from a cron / background
        /// task) to keep the table bounded. Returns the number of rows
        /// deleted.
        pub async fn gc(&self, now: i64) -> Result<u64, StoreError> {
            let res = sqlx::query(
                "DELETE FROM revocations WHERE expires_at IS NOT NULL AND expires_at <= $1",
            )
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(res.rows_affected())
        }
    }

    impl std::fmt::Debug for PgRevocationStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PgRevocationStore").finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl RevocationWriter for PgRevocationStore {
        async fn revoke(&self, jti: &str) -> Result<(), StoreError> {
            // Idempotent: re-revoking the same jti is a no-op (the contract).
            sqlx::query(
                "INSERT INTO revocations (jti, revoked_at) VALUES ($1, $2)
                 ON CONFLICT (jti) DO NOTHING",
            )
            .bind(jti)
            .bind(now())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(())
        }
    }

    #[async_trait]
    impl RevocationReader for PgRevocationStore {
        async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
            let row = sqlx::query("SELECT 1 AS one FROM revocations WHERE jti = $1")
                .bind(jti)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            Ok(row.is_some())
        }
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use sqlx::SqlitePool;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Revocation set over SQLite.
    pub struct SqliteRevocationStore {
        pool: SqlitePool,
    }

    impl SqliteRevocationStore {
        pub fn new(pool: SqlitePool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &SqlitePool {
            &self.pool
        }

        /// See [`PgRevocationStore::gc`](super::pg::PgRevocationStore::gc).
        pub async fn gc(&self, now: i64) -> Result<u64, StoreError> {
            let res = sqlx::query(
                "DELETE FROM revocations WHERE expires_at IS NOT NULL AND expires_at <= ?",
            )
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(res.rows_affected())
        }
    }

    impl std::fmt::Debug for SqliteRevocationStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SqliteRevocationStore").finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl RevocationWriter for SqliteRevocationStore {
        async fn revoke(&self, jti: &str) -> Result<(), StoreError> {
            sqlx::query(
                "INSERT INTO revocations (jti, revoked_at) VALUES (?, ?)
                 ON CONFLICT (jti) DO NOTHING",
            )
            .bind(jti)
            .bind(now())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(())
        }
    }

    #[async_trait]
    impl RevocationReader for SqliteRevocationStore {
        async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
            let row = sqlx::query("SELECT 1 AS one FROM revocations WHERE jti = ?")
                .bind(jti)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            Ok(row.is_some())
        }
    }
}
