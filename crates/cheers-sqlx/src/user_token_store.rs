//! [`UserTokenStore`](cheers_server::UserTokenStore) over `sqlx` — R728-F1.
//!
//! The persistent half of user API tokens (PATs). Both backends, because
//! unlike the magic-link `used_jti` table this one is not tied to a single
//! flow: any cheers deployment that mounts `/me/tokens` needs it, and the
//! relational deployments split roughly evenly between Postgres and SQLite.
//!
//! **Nothing here is on a token's trust path.** A PAT is verified by signature
//! and killed through the revocation set; this table only records what the
//! user should *see* on `GET /me/tokens`. An impl returning garbage would
//! corrupt a token list and nothing else — which is why the table holds no
//! secret and no hash of one (see [`cheers_server::user_tokens`] for the full
//! argument).
//!
//! `scopes` is stored as the space-joined wire strings via
//! [`encode_scopes`](cheers_server::encode_scopes) /
//! [`decode_scopes`](cheers_server::decode_scopes), which live in
//! `cheers-server` precisely so this crate and `cheers-turso` cannot drift on
//! the column format — `cheers-turso/tests/flip.rs` drives both families
//! against one file to keep that honest.

use async_trait::async_trait;
use cheers_core::{StoreError, UserId};
use cheers_server::{decode_scopes, encode_scopes, UserTokenRecord, UserTokenStore};

use crate::error::map_sqlx_error;

#[cfg(feature = "pg")]
pub use pg::PgUserTokenStore;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteUserTokenStore;

/// Columns every read in this module selects, in this order. One constant so
/// the two backends' `SELECT`s cannot drift from each other or from the row
/// decoder.
const COLUMNS: &str =
    "jti, user_id, name, scopes, aud, created_at, last_used_at, expires_at, revoked";

#[cfg(feature = "pg")]
mod pg {
    use super::*;
    use sqlx::{PgPool, Row};

    /// Persistent [`UserTokenStore`] over Postgres.
    pub struct PgUserTokenStore {
        pool: PgPool,
    }

    impl PgUserTokenStore {
        pub fn new(pool: PgPool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &PgPool {
            &self.pool
        }

        /// Delete rows that expired at or before `now`.
        ///
        /// Optional hygiene, not a correctness requirement: an expired token
        /// is already dead by its own `exp` claim, and `list_live_for_user`
        /// filters it out regardless. Revoked-but-unexpired rows are
        /// deliberately **not** collected — they are the user's record of a
        /// kill, and sweeping them would make a revoked token look like one
        /// that never existed.
        pub async fn gc(&self, now: i64) -> Result<u64, StoreError> {
            let res = sqlx::query("DELETE FROM user_tokens WHERE expires_at <= $1")
                .bind(now)
                .execute(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            Ok(res.rows_affected())
        }
    }

    impl std::fmt::Debug for PgUserTokenStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PgUserTokenStore").finish_non_exhaustive()
        }
    }

    fn row_to_record(row: &sqlx::postgres::PgRow) -> Result<UserTokenRecord, StoreError> {
        let mut rec = UserTokenRecord::new(
            row.get::<String, _>("jti"),
            UserId::new(row.get::<String, _>("user_id")),
            row.get::<String, _>("name"),
            decode_scopes(row.get::<String, _>("scopes").as_str())?,
            row.get::<String, _>("aud"),
            row.get::<i64, _>("created_at"),
            row.get::<i64, _>("expires_at"),
        );
        rec.last_used_at = row.get::<Option<i64>, _>("last_used_at");
        rec.revoked = row.get::<bool, _>("revoked");
        Ok(rec)
    }

    #[async_trait]
    impl UserTokenStore for PgUserTokenStore {
        async fn insert(&self, record: &UserTokenRecord) -> Result<(), StoreError> {
            sqlx::query(
                "INSERT INTO user_tokens
                    (jti, user_id, name, scopes, aud, created_at, last_used_at,
                     expires_at, revoked)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(&record.jti)
            .bind(record.user_id.as_str())
            .bind(&record.name)
            .bind(encode_scopes(&record.scopes))
            .bind(&record.aud)
            .bind(record.created_at)
            .bind(record.last_used_at)
            .bind(record.expires_at)
            .bind(record.revoked)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(())
        }

        async fn list_live_for_user(
            &self,
            user_id: &UserId,
            now: i64,
        ) -> Result<Vec<UserTokenRecord>, StoreError> {
            // Newest first, matching the (user_id, created_at DESC) index the
            // migration ships.
            let sql = format!(
                "SELECT {COLUMNS} FROM user_tokens
                 WHERE user_id = $1 AND revoked = FALSE AND expires_at > $2
                 ORDER BY created_at DESC"
            );
            let rows = sqlx::query(&sql)
                .bind(user_id.as_str())
                .bind(now)
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            rows.iter().map(row_to_record).collect()
        }

        async fn get(&self, jti: &str) -> Result<Option<UserTokenRecord>, StoreError> {
            let sql = format!("SELECT {COLUMNS} FROM user_tokens WHERE jti = $1");
            let row = sqlx::query(&sql)
                .bind(jti)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            row.as_ref().map(row_to_record).transpose()
        }

        async fn mark_revoked(&self, jti: &str) -> Result<(), StoreError> {
            // Unconditional on `revoked` so re-revoking is a no-op rather than
            // a NotFound — the contract is "this row ends up revoked". The
            // zero-rows case genuinely means no such row.
            let res = sqlx::query("UPDATE user_tokens SET revoked = TRUE WHERE jti = $1")
                .bind(jti)
                .execute(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            if res.rows_affected() == 0 {
                return Err(StoreError::NotFound);
            }
            Ok(())
        }

        async fn touch_last_used(&self, jti: &str, now: i64) -> Result<(), StoreError> {
            let res = sqlx::query("UPDATE user_tokens SET last_used_at = $1 WHERE jti = $2")
                .bind(now)
                .bind(jti)
                .execute(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            if res.rows_affected() == 0 {
                return Err(StoreError::NotFound);
            }
            Ok(())
        }
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use sqlx::{Row, SqlitePool};

    /// Persistent [`UserTokenStore`] over SQLite.
    pub struct SqliteUserTokenStore {
        pool: SqlitePool,
    }

    impl SqliteUserTokenStore {
        pub fn new(pool: SqlitePool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &SqlitePool {
            &self.pool
        }

        /// See [`PgUserTokenStore::gc`](super::pg::PgUserTokenStore::gc).
        pub async fn gc(&self, now: i64) -> Result<u64, StoreError> {
            let res = sqlx::query("DELETE FROM user_tokens WHERE expires_at <= ?")
                .bind(now)
                .execute(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            Ok(res.rows_affected())
        }
    }

    impl std::fmt::Debug for SqliteUserTokenStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SqliteUserTokenStore").finish_non_exhaustive()
        }
    }

    fn row_to_record(row: &sqlx::sqlite::SqliteRow) -> Result<UserTokenRecord, StoreError> {
        let mut rec = UserTokenRecord::new(
            row.get::<String, _>("jti"),
            UserId::new(row.get::<String, _>("user_id")),
            row.get::<String, _>("name"),
            decode_scopes(row.get::<String, _>("scopes").as_str())?,
            row.get::<String, _>("aud"),
            row.get::<i64, _>("created_at"),
            row.get::<i64, _>("expires_at"),
        );
        rec.last_used_at = row.get::<Option<i64>, _>("last_used_at");
        rec.revoked = row.get::<bool, _>("revoked");
        Ok(rec)
    }

    #[async_trait]
    impl UserTokenStore for SqliteUserTokenStore {
        async fn insert(&self, record: &UserTokenRecord) -> Result<(), StoreError> {
            sqlx::query(
                "INSERT INTO user_tokens
                    (jti, user_id, name, scopes, aud, created_at, last_used_at,
                     expires_at, revoked)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&record.jti)
            .bind(record.user_id.as_str())
            .bind(&record.name)
            .bind(encode_scopes(&record.scopes))
            .bind(&record.aud)
            .bind(record.created_at)
            .bind(record.last_used_at)
            .bind(record.expires_at)
            .bind(record.revoked)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(())
        }

        async fn list_live_for_user(
            &self,
            user_id: &UserId,
            now: i64,
        ) -> Result<Vec<UserTokenRecord>, StoreError> {
            let sql = format!(
                "SELECT {COLUMNS} FROM user_tokens
                 WHERE user_id = ? AND revoked = FALSE AND expires_at > ?
                 ORDER BY created_at DESC"
            );
            let rows = sqlx::query(&sql)
                .bind(user_id.as_str())
                .bind(now)
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            rows.iter().map(row_to_record).collect()
        }

        async fn get(&self, jti: &str) -> Result<Option<UserTokenRecord>, StoreError> {
            let sql = format!("SELECT {COLUMNS} FROM user_tokens WHERE jti = ?");
            let row = sqlx::query(&sql)
                .bind(jti)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            row.as_ref().map(row_to_record).transpose()
        }

        async fn mark_revoked(&self, jti: &str) -> Result<(), StoreError> {
            let res = sqlx::query("UPDATE user_tokens SET revoked = TRUE WHERE jti = ?")
                .bind(jti)
                .execute(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            if res.rows_affected() == 0 {
                return Err(StoreError::NotFound);
            }
            Ok(())
        }

        async fn touch_last_used(&self, jti: &str, now: i64) -> Result<(), StoreError> {
            let res = sqlx::query("UPDATE user_tokens SET last_used_at = ? WHERE jti = ?")
                .bind(now)
                .bind(jti)
                .execute(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            if res.rows_affected() == 0 {
                return Err(StoreError::NotFound);
            }
            Ok(())
        }
    }
}
