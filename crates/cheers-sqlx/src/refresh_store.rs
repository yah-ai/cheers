//! [`RefreshStore`](cheers_server::RefreshStore) over `sqlx`.
//!
//! The rotation contract is enforced by
//! [`RefreshRotator`](cheers_server::RefreshRotator) — this impl only owns
//! persistence: get / put / mark_consumed / revoke_chain mapped one-to-one
//! to SQL.
//!
//! Backends:
//! - [`PgRefreshStore`] — `JSONB`-friendly Postgres
//! - [`SqliteRefreshStore`] — single-file SQLite (dev + first-cut prod)
//!
//! Both will happily serve refresh chains forever, but they're playing
//! redis's role — a high-traffic deployment should swap in
//! `cheers_redis::RedisRefreshStore` and demote SQL to identity + passkeys.

use async_trait::async_trait;
use cheers_core::StoreError;
use cheers_server::store::{RefreshStore, RefreshTokenRecord};

use crate::error::map_sqlx_error;

#[cfg(feature = "pg")]
pub use pg::PgRefreshStore;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteRefreshStore;

#[cfg(feature = "pg")]
mod pg {
    use super::*;
    use cheers_core::{DeviceId, UserId};
    use sqlx::{PgPool, Row};

    /// [`RefreshStore`] over a `sqlx` Postgres pool.
    pub struct PgRefreshStore {
        pool: PgPool,
    }

    impl PgRefreshStore {
        pub fn new(pool: PgPool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &PgPool {
            &self.pool
        }
    }

    impl std::fmt::Debug for PgRefreshStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PgRefreshStore").finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl RefreshStore for PgRefreshStore {
        async fn put(&self, record: &RefreshTokenRecord) -> Result<(), StoreError> {
            sqlx::query(
                "INSERT INTO refresh_tokens
                    (token, chain_id, parent, user_id, device_id,
                     issued_at, expires_at, consumed, revoked)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(&record.token)
            .bind(&record.chain_id)
            .bind(record.parent.as_deref())
            .bind(record.user_id.as_str())
            .bind(record.device_id.as_str())
            .bind(record.issued_at)
            .bind(record.expires_at)
            .bind(record.consumed)
            .bind(record.revoked)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(())
        }

        async fn get(&self, token: &str) -> Result<Option<RefreshTokenRecord>, StoreError> {
            let row = sqlx::query(
                "SELECT token, chain_id, parent, user_id, device_id,
                        issued_at, expires_at, consumed, revoked
                 FROM refresh_tokens WHERE token = $1",
            )
            .bind(token)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

            Ok(row.map(|row| {
                RefreshTokenRecord::new(
                    row.get("token"),
                    row.get("chain_id"),
                    row.get("parent"),
                    UserId::new(row.get::<String, _>("user_id")),
                    DeviceId::new(row.get::<String, _>("device_id")),
                    row.get("issued_at"),
                    row.get("expires_at"),
                    row.get("consumed"),
                    row.get("revoked"),
                )
            }))
        }

        async fn mark_consumed(&self, token: &str) -> Result<(), StoreError> {
            let res = sqlx::query("UPDATE refresh_tokens SET consumed = TRUE WHERE token = $1")
                .bind(token)
                .execute(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            if res.rows_affected() == 0 {
                return Err(StoreError::NotFound);
            }
            Ok(())
        }

        async fn revoke_chain(&self, chain_id: &str) -> Result<(), StoreError> {
            // Idempotent — no NotFound on an empty chain. The contract is
            // "every record in this chain ends up revoked"; 0 rows is fine.
            sqlx::query("UPDATE refresh_tokens SET revoked = TRUE WHERE chain_id = $1")
                .bind(chain_id)
                .execute(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            Ok(())
        }
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use cheers_core::{DeviceId, UserId};
    use sqlx::{Row, SqlitePool};

    /// [`RefreshStore`] over a `sqlx` SQLite pool.
    pub struct SqliteRefreshStore {
        pool: SqlitePool,
    }

    impl SqliteRefreshStore {
        pub fn new(pool: SqlitePool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &SqlitePool {
            &self.pool
        }
    }

    impl std::fmt::Debug for SqliteRefreshStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SqliteRefreshStore").finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl RefreshStore for SqliteRefreshStore {
        async fn put(&self, record: &RefreshTokenRecord) -> Result<(), StoreError> {
            sqlx::query(
                "INSERT INTO refresh_tokens
                    (token, chain_id, parent, user_id, device_id,
                     issued_at, expires_at, consumed, revoked)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&record.token)
            .bind(&record.chain_id)
            .bind(record.parent.as_deref())
            .bind(record.user_id.as_str())
            .bind(record.device_id.as_str())
            .bind(record.issued_at)
            .bind(record.expires_at)
            .bind(record.consumed as i32)
            .bind(record.revoked as i32)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(())
        }

        async fn get(&self, token: &str) -> Result<Option<RefreshTokenRecord>, StoreError> {
            let row = sqlx::query(
                "SELECT token, chain_id, parent, user_id, device_id,
                        issued_at, expires_at, consumed, revoked
                 FROM refresh_tokens WHERE token = ?",
            )
            .bind(token)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

            Ok(row.map(|row| {
                RefreshTokenRecord::new(
                    row.get("token"),
                    row.get("chain_id"),
                    row.get("parent"),
                    UserId::new(row.get::<String, _>("user_id")),
                    DeviceId::new(row.get::<String, _>("device_id")),
                    row.get("issued_at"),
                    row.get("expires_at"),
                    row.get::<i64, _>("consumed") != 0,
                    row.get::<i64, _>("revoked") != 0,
                )
            }))
        }

        async fn mark_consumed(&self, token: &str) -> Result<(), StoreError> {
            let res = sqlx::query("UPDATE refresh_tokens SET consumed = 1 WHERE token = ?")
                .bind(token)
                .execute(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            if res.rows_affected() == 0 {
                return Err(StoreError::NotFound);
            }
            Ok(())
        }

        async fn revoke_chain(&self, chain_id: &str) -> Result<(), StoreError> {
            sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE chain_id = ?")
                .bind(chain_id)
                .execute(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            Ok(())
        }
    }
}
