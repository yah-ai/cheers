//! [`OwnershipStore`](cheers_server::OwnershipStore) over `sqlx`.
//!
//! The trait-level invariants on `granted_by` / `on_behalf_of` are also
//! enforced by SQL `CHECK` constraints in the schema (see
//! `migrations/{pg,sqlite}/0002_ownership.sql`). The CHECK is the belt; the
//! Rust-side validation in [`NewOwnership::new`](cheers_server::NewOwnership)
//! is the suspenders — a misconfigured insert never makes a round-trip to be
//! rejected.

use async_trait::async_trait;
use cheers_core::{PrincipalId, StoreError};
use cheers_server::ownership::{NewOwnership, OwnershipRow, OwnershipStore};

use crate::error::map_sqlx_error;

#[cfg(feature = "pg")]
pub use pg::PgOwnershipStore;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteOwnershipStore;

/// Mint a fresh opaque row id. Matches the UUIDv4 shape `mint_user_id` in
/// `user_store.rs` uses — the doc spec calls for "ULID", but what's
/// load-bearing is "opaque crypto-random 128-bit id", not the encoding.
fn mint_row_id() -> String {
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("OS CSPRNG must be available");
    buf[6] = (buf[6] & 0x0f) | 0x40;
    buf[8] = (buf[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        buf[0], buf[1], buf[2], buf[3],
        buf[4], buf[5],
        buf[6], buf[7],
        buf[8], buf[9],
        buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    )
}

/// Parse a `principal_id` column back into a [`PrincipalId`]. The CHECK
/// constraints in the schema guarantee well-formed inputs at the SQL level;
/// a parse failure here is a hard data-integrity error, not a normal NotFound.
fn parse_pid(s: String, column: &'static str) -> Result<PrincipalId, StoreError> {
    s.parse::<PrincipalId>().map_err(|e| {
        StoreError::Backend(format!("invalid {column} principal id in ownership row: {e}"))
    })
}

#[cfg(feature = "pg")]
mod pg {
    use super::*;
    use sqlx::{PgPool, Row};

    /// [`OwnershipStore`] over Postgres.
    pub struct PgOwnershipStore {
        pool: PgPool,
    }

    impl PgOwnershipStore {
        pub fn new(pool: PgPool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &PgPool {
            &self.pool
        }
    }

    impl std::fmt::Debug for PgOwnershipStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PgOwnershipStore").finish_non_exhaustive()
        }
    }

    fn row_from(row: sqlx::postgres::PgRow) -> Result<OwnershipRow, StoreError> {
        let on_behalf_of = row
            .get::<Option<String>, _>("on_behalf_of")
            .map(|s| parse_pid(s, "on_behalf_of"))
            .transpose()?;
        Ok(OwnershipRow::new(
            row.get("id"),
            parse_pid(row.get("principal_id"), "principal_id")?,
            row.get("resource_kind"),
            row.get("resource_id"),
            row.get("relationship"),
            parse_pid(row.get("granted_by"), "granted_by")?,
            on_behalf_of,
            row.get("granted_at"),
            row.get("revoked_at"),
        ))
    }

    #[async_trait]
    impl OwnershipStore for PgOwnershipStore {
        async fn insert(
            &self,
            o: &NewOwnership,
            now: i64,
        ) -> Result<OwnershipRow, StoreError> {
            let id = mint_row_id();
            let principal = o.principal_id.to_string();
            let granted_by = o.granted_by.to_string();
            let on_behalf_of = o.on_behalf_of.as_ref().map(|p| p.to_string());
            sqlx::query(
                "INSERT INTO ownership
                    (id, principal_id, resource_kind, resource_id, relationship,
                     granted_by, on_behalf_of, granted_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(&id)
            .bind(&principal)
            .bind(&o.resource_kind)
            .bind(&o.resource_id)
            .bind(&o.relationship)
            .bind(&granted_by)
            .bind(on_behalf_of.as_deref())
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(OwnershipRow::new(
                id,
                o.principal_id.clone(),
                o.resource_kind.clone(),
                o.resource_id.clone(),
                o.relationship.clone(),
                o.granted_by.clone(),
                o.on_behalf_of.clone(),
                now,
                None,
            ))
        }

        async fn get(&self, id: &str) -> Result<Option<OwnershipRow>, StoreError> {
            let row = sqlx::query(
                "SELECT id, principal_id, resource_kind, resource_id, relationship,
                        granted_by, on_behalf_of, granted_at, revoked_at
                 FROM ownership WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            row.map(row_from).transpose()
        }

        async fn revoke_by_id(&self, id: &str, now: i64) -> Result<(), StoreError> {
            let res = sqlx::query(
                "UPDATE ownership SET revoked_at = $1
                 WHERE id = $2 AND revoked_at IS NULL",
            )
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            if res.rows_affected() == 0 {
                // Distinguish "unknown" from "already revoked" — only the
                // former is NotFound, the latter is an idempotent no-op.
                let exists = sqlx::query("SELECT 1 AS one FROM ownership WHERE id = $1")
                    .bind(id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?
                    .is_some();
                if !exists {
                    return Err(StoreError::NotFound);
                }
            }
            Ok(())
        }

        async fn revoke_by_on_behalf_of(
            &self,
            user: &PrincipalId,
            now: i64,
        ) -> Result<u64, StoreError> {
            let res = sqlx::query(
                "UPDATE ownership SET revoked_at = $1
                 WHERE on_behalf_of = $2 AND revoked_at IS NULL",
            )
            .bind(now)
            .bind(user.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(res.rows_affected())
        }

        async fn list_for_principal(
            &self,
            principal: &PrincipalId,
        ) -> Result<Vec<OwnershipRow>, StoreError> {
            let rows = sqlx::query(
                "SELECT id, principal_id, resource_kind, resource_id, relationship,
                        granted_by, on_behalf_of, granted_at, revoked_at
                 FROM ownership
                 WHERE principal_id = $1 AND revoked_at IS NULL",
            )
            .bind(principal.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            rows.into_iter().map(row_from).collect()
        }
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use sqlx::{Row, SqlitePool};

    /// [`OwnershipStore`] over SQLite.
    pub struct SqliteOwnershipStore {
        pool: SqlitePool,
    }

    impl SqliteOwnershipStore {
        pub fn new(pool: SqlitePool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &SqlitePool {
            &self.pool
        }
    }

    impl std::fmt::Debug for SqliteOwnershipStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SqliteOwnershipStore").finish_non_exhaustive()
        }
    }

    fn row_from(row: sqlx::sqlite::SqliteRow) -> Result<OwnershipRow, StoreError> {
        let on_behalf_of = row
            .get::<Option<String>, _>("on_behalf_of")
            .map(|s| parse_pid(s, "on_behalf_of"))
            .transpose()?;
        Ok(OwnershipRow::new(
            row.get("id"),
            parse_pid(row.get("principal_id"), "principal_id")?,
            row.get("resource_kind"),
            row.get("resource_id"),
            row.get("relationship"),
            parse_pid(row.get("granted_by"), "granted_by")?,
            on_behalf_of,
            row.get("granted_at"),
            row.get("revoked_at"),
        ))
    }

    #[async_trait]
    impl OwnershipStore for SqliteOwnershipStore {
        async fn insert(
            &self,
            o: &NewOwnership,
            now: i64,
        ) -> Result<OwnershipRow, StoreError> {
            let id = mint_row_id();
            let principal = o.principal_id.to_string();
            let granted_by = o.granted_by.to_string();
            let on_behalf_of = o.on_behalf_of.as_ref().map(|p| p.to_string());
            sqlx::query(
                "INSERT INTO ownership
                    (id, principal_id, resource_kind, resource_id, relationship,
                     granted_by, on_behalf_of, granted_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&id)
            .bind(&principal)
            .bind(&o.resource_kind)
            .bind(&o.resource_id)
            .bind(&o.relationship)
            .bind(&granted_by)
            .bind(on_behalf_of.as_deref())
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(OwnershipRow::new(
                id,
                o.principal_id.clone(),
                o.resource_kind.clone(),
                o.resource_id.clone(),
                o.relationship.clone(),
                o.granted_by.clone(),
                o.on_behalf_of.clone(),
                now,
                None,
            ))
        }

        async fn get(&self, id: &str) -> Result<Option<OwnershipRow>, StoreError> {
            let row = sqlx::query(
                "SELECT id, principal_id, resource_kind, resource_id, relationship,
                        granted_by, on_behalf_of, granted_at, revoked_at
                 FROM ownership WHERE id = ?",
            )
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            row.map(row_from).transpose()
        }

        async fn revoke_by_id(&self, id: &str, now: i64) -> Result<(), StoreError> {
            let res = sqlx::query(
                "UPDATE ownership SET revoked_at = ?
                 WHERE id = ? AND revoked_at IS NULL",
            )
            .bind(now)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            if res.rows_affected() == 0 {
                let exists = sqlx::query("SELECT 1 AS one FROM ownership WHERE id = ?")
                    .bind(id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?
                    .is_some();
                if !exists {
                    return Err(StoreError::NotFound);
                }
            }
            Ok(())
        }

        async fn revoke_by_on_behalf_of(
            &self,
            user: &PrincipalId,
            now: i64,
        ) -> Result<u64, StoreError> {
            let res = sqlx::query(
                "UPDATE ownership SET revoked_at = ?
                 WHERE on_behalf_of = ? AND revoked_at IS NULL",
            )
            .bind(now)
            .bind(user.to_string())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(res.rows_affected())
        }

        async fn list_for_principal(
            &self,
            principal: &PrincipalId,
        ) -> Result<Vec<OwnershipRow>, StoreError> {
            let rows = sqlx::query(
                "SELECT id, principal_id, resource_kind, resource_id, relationship,
                        granted_by, on_behalf_of, granted_at, revoked_at
                 FROM ownership
                 WHERE principal_id = ? AND revoked_at IS NULL",
            )
            .bind(principal.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            rows.into_iter().map(row_from).collect()
        }
    }
}
