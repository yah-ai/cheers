//! [`UsedJtiStore`](cheers_core::UsedJtiStore) over `sqlx` — R727-B1.
//!
//! SQLite only: `noisetable-account` (the one production consumer) runs on
//! SQLite via `cheers-sqlx` or the schema-identical `cheers-turso`
//! (`tests/flip.rs` in that crate proves the two stay interchangeable). There
//! is no Postgres consumer of the magic-link flow today, so a `PgUsedJtiStore`
//! would ship with no caller and no test — add one alongside the first pg
//! consumer instead of speculatively now.

use async_trait::async_trait;
use cheers_core::UsedJtiStore;

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteUsedJtiStore;

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use sqlx::SqlitePool;

    /// Persistent [`UsedJtiStore`] over SQLite.
    pub struct SqliteUsedJtiStore {
        pool: SqlitePool,
    }

    impl SqliteUsedJtiStore {
        pub fn new(pool: SqlitePool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &SqlitePool {
            &self.pool
        }

        /// Garbage-collect entries whose `expires_at` is at or before `now`.
        /// Call periodically to keep the table bounded. Returns the number of
        /// rows deleted.
        pub async fn gc(&self, now: i64) -> Result<u64, String> {
            let res = sqlx::query("DELETE FROM used_jti WHERE expires_at <= ?")
                .bind(now)
                .execute(&self.pool)
                .await
                .map_err(|e| e.to_string())?;
            Ok(res.rows_affected())
        }
    }

    impl std::fmt::Debug for SqliteUsedJtiStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SqliteUsedJtiStore").finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl UsedJtiStore for SqliteUsedJtiStore {
        async fn try_mark_used(&self, jti: &str, expires_at: i64) -> Result<bool, String> {
            let res = sqlx::query(
                "INSERT INTO used_jti (jti, expires_at) VALUES (?, ?)
                 ON CONFLICT (jti) DO NOTHING",
            )
            .bind(jti)
            .bind(expires_at)
            .execute(&self.pool)
            .await
            .map_err(|e| e.to_string())?;
            Ok(res.rows_affected() == 1)
        }
    }
}
