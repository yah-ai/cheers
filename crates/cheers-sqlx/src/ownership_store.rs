//! [`OwnershipStore`](cheers_server::OwnershipStore) over `sqlx`.
//!
//! The trait-level invariants on `on_behalf_of` and the one-form subject are
//! also enforced by SQL `CHECK` constraints in the schema (see
//! `migrations/{pg,sqlite}/0009_ownership_subject_sets.sql`). The CHECK is the belt; the
//! Rust-side validation in [`NewOwnership::new`](cheers_server::NewOwnership)
//! is the suspenders — a misconfigured insert never makes a round-trip to be
//! rejected.

use async_trait::async_trait;
use cheers_core::{AdmissionPolicy, PrincipalId, RevocationKey, StoreError, Subject};
use cheers_server::ownership::{
    TupleLease, decode_admission_policy, encode_admission_policy, new_revocation_key, Inserted, NewOwnership, OwnershipRow, OwnershipStore};

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

/// An `ownership_version` column value as the trait's `u64`. The column only
/// ever holds `max(v + 1, now)` from 0, so a negative value is corruption.
#[cfg(any(feature = "pg", feature = "sqlite"))]
fn version_from_sql(version: i64) -> Result<u64, StoreError> {
    u64::try_from(version).map_err(|_| StoreError::Backend(format!("negative ownership version {version}")))
}

/// The column list every read shares, in the order both `row_from`s read.
const COLUMNS: &str = "id, principal_id, subject_kind, subject_id, subject_relation, \
                       resource_kind, resource_id, relationship, \
                       granted_by, on_behalf_of, granted_at, revoked_at, \
                       lease_iat, lease_refresh_after, lease_exp";

/// Rebuild a row's [`Subject`] from its four subject columns. The schema's
/// one-form CHECK makes a failure here a data-integrity error, like
/// [`parse_pid`].
fn parse_subject(
    principal_id: Option<String>,
    kind: Option<String>,
    id: Option<String>,
    relation: Option<String>,
) -> Result<Subject, StoreError> {
    let principal = principal_id.map(|s| parse_pid(s, "principal_id")).transpose()?;
    Subject::from_parts(principal, kind, id, relation)
        .map_err(|e| StoreError::Backend(format!("invalid subject in ownership row: {e}")))
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
            parse_subject(
                row.get("principal_id"),
                row.get("subject_kind"),
                row.get("subject_id"),
                row.get("subject_relation"),
            )?,
            row.get("resource_kind"),
            row.get("resource_id"),
            row.get("relationship"),
            parse_pid(row.get("granted_by"), "granted_by")?,
            on_behalf_of,
            row.get("granted_at"),
            row.get("revoked_at"),
        )
        .with_lease(TupleLease::from_columns(row.get("lease_iat"), row.get("lease_refresh_after"), row.get("lease_exp"))?))
    }

    /// Advance the ownership version inside `tx` and return it — the same
    /// transaction as the row change it versions.
    async fn advance_version(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>, now: i64) -> Result<u64, StoreError> {
        let version: i64 =
            sqlx::query_scalar("UPDATE ownership_version SET version = GREATEST(version + 1, $1) RETURNING version")
                .bind(now)
                .fetch_one(&mut **tx)
                .await
                .map_err(map_sqlx_error)?;
        version_from_sql(version)
    }

    #[async_trait]
    impl OwnershipStore for PgOwnershipStore {
        async fn insert(&self, o: &NewOwnership, now: i64) -> Result<Inserted, StoreError> {
            let id = mint_row_id();
            let principal = o.subject.principal().map(|p| p.to_string());
            let set = o.subject.as_set();
            let granted_by = o.granted_by.to_string();
            let on_behalf_of = o.on_behalf_of.as_ref().map(|p| p.to_string());
            let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
            sqlx::query(
                "INSERT INTO ownership
                    (id, principal_id, subject_kind, subject_id, subject_relation,
                     resource_kind, resource_id, relationship,
                     granted_by, on_behalf_of, granted_at,
                     lease_iat, lease_refresh_after, lease_exp)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
            )
            .bind(&id)
            .bind(principal.as_deref())
            .bind(set.map(|s| s.0))
            .bind(set.map(|s| s.1))
            .bind(set.map(|s| s.2))
            .bind(&o.resource_kind)
            .bind(&o.resource_id)
            .bind(&o.relationship)
            .bind(&granted_by)
            .bind(on_behalf_of.as_deref())
            .bind(now)
            .bind(o.lease.map(|l| l.iat))
            .bind(o.lease.map(|l| l.lease.refresh_after()))
            .bind(o.lease.and_then(|l| l.lease.exp()))
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
            let version = advance_version(&mut tx, now).await?;
            tx.commit().await.map_err(map_sqlx_error)?;
            let row = OwnershipRow::new(
                id,
                o.subject.clone(),
                o.resource_kind.clone(),
                o.resource_id.clone(),
                o.relationship.clone(),
                o.granted_by.clone(),
                o.on_behalf_of.clone(),
                now,
                None,
            )
            .with_lease(o.lease);
            Ok(Inserted { row, version })
        }

        async fn get(&self, id: &str) -> Result<Option<OwnershipRow>, StoreError> {
            let row = sqlx::query(&format!(
                "SELECT {COLUMNS} FROM ownership WHERE id = $1"
            ))
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            row.map(row_from).transpose()
        }

        async fn revoke_by_id(&self, id: &str, now: i64) -> Result<u64, StoreError> {
            let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
            let res = sqlx::query(
                "UPDATE ownership SET revoked_at = $1
                 WHERE id = $2 AND revoked_at IS NULL",
            )
            .bind(now)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
            if res.rows_affected() > 0 {
                let version = advance_version(&mut tx, now).await?;
                tx.commit().await.map_err(map_sqlx_error)?;
                return Ok(version);
            }
            tx.rollback().await.map_err(map_sqlx_error)?;
            // Nothing changed: unknown id (NotFound), or already revoked — an
            // idempotent no-op that reports the version as it stands.
            let exists = sqlx::query("SELECT 1 AS one FROM ownership WHERE id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx_error)?
                .is_some();
            if !exists {
                return Err(StoreError::NotFound);
            }
            self.current_version().await
        }

        async fn revoke_by_principal(
            &self,
            principal: &PrincipalId,
            now: i64,
        ) -> Result<u64, StoreError> {
            let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
            let swept = sqlx::query(
                "UPDATE ownership SET revoked_at = $1
                 WHERE principal_id = $2 AND revoked_at IS NULL",
            )
            .bind(now)
            .bind(principal.to_string())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?
            .rows_affected();
            if swept > 0 {
                let version = advance_version(&mut tx, now).await?;
                tx.commit().await.map_err(map_sqlx_error)?;
                return Ok(version);
            }
            tx.rollback().await.map_err(map_sqlx_error)?;
            self.current_version().await
        }

        async fn list_history_for_principal(
            &self,
            principal: &PrincipalId,
        ) -> Result<Vec<OwnershipRow>, StoreError> {
            let rows = sqlx::query(&format!("SELECT {COLUMNS} FROM ownership WHERE principal_id = $1"))
                .bind(principal.to_string())
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            rows.into_iter().map(row_from).collect()
        }

        async fn current_version(&self) -> Result<u64, StoreError> {
            let version: i64 = sqlx::query_scalar("SELECT version FROM ownership_version")
                .fetch_one(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            version_from_sql(version)
        }

        async fn list_for_principal(
            &self,
            principal: &PrincipalId,
        ) -> Result<Vec<OwnershipRow>, StoreError> {
            let rows = sqlx::query(&format!(
                "SELECT {COLUMNS} FROM ownership
                 WHERE principal_id = $1 AND revoked_at IS NULL"
            ))
            .bind(principal.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            rows.into_iter().map(row_from).collect()
        }

        async fn list_for_resource(
            &self,
            resource_kind: &str,
            resource_id: &str,
        ) -> Result<Vec<OwnershipRow>, StoreError> {
            let rows = sqlx::query(&format!(
                "SELECT {COLUMNS} FROM ownership
                 WHERE resource_kind = $1 AND resource_id = $2 AND revoked_at IS NULL"
            ))
            .bind(resource_kind)
            .bind(resource_id)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            rows.into_iter().map(row_from).collect()
        }

        async fn list_for_subject_set(
            &self,
            kind: &str,
            id: &str,
        ) -> Result<Vec<OwnershipRow>, StoreError> {
            let rows = sqlx::query(&format!(
                "SELECT {COLUMNS} FROM ownership
                 WHERE subject_kind = $1 AND subject_id = $2 AND revoked_at IS NULL"
            ))
            .bind(kind)
            .bind(id)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            rows.into_iter().map(row_from).collect()
        }

        async fn list_for_kind(
            &self,
            resource_kind: &str,
        ) -> Result<Vec<OwnershipRow>, StoreError> {
            let rows = sqlx::query(&format!(
                "SELECT {COLUMNS} FROM ownership
                 WHERE resource_kind = $1 AND revoked_at IS NULL"
            ))
            .bind(resource_kind)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            rows.into_iter().map(row_from).collect()
        }

        async fn revocation_key(&self, kind: &str, id: &str) -> Result<RevocationKey, StoreError> {
            // Insert-or-ignore, then reread: a concurrent creator's row wins
            // and both callers return it (migration 0014).
            sqlx::query(
                "INSERT INTO revocation_keys (resource_kind, resource_id, key) VALUES ($1, $2, $3)
                 ON CONFLICT (resource_kind, resource_id) DO NOTHING",
            )
            .bind(kind)
            .bind(id)
            .bind(new_revocation_key().as_bytes().to_vec())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            let bytes: Vec<u8> =
                sqlx::query_scalar("SELECT key FROM revocation_keys WHERE resource_kind = $1 AND resource_id = $2")
                    .bind(kind)
                    .bind(id)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?;
            super::revocation_key_from_sql(kind, id, bytes)
        }

        async fn admission_policy(&self, kind: &str, id: &str) -> Result<Option<AdmissionPolicy>, StoreError> {
            let column: Option<String> = sqlx::query_scalar(
                "SELECT policy FROM admission_policies WHERE resource_kind = $1 AND resource_id = $2",
            )
            .bind(kind)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            column.map(|c| decode_admission_policy(kind, id, &c)).transpose()
        }

        async fn set_admission_policy(
            &self,
            kind: &str,
            id: &str,
            policy: Option<&AdmissionPolicy>,
            now: i64,
        ) -> Result<u64, StoreError> {
            let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
            match policy {
                Some(p) => sqlx::query(
                    "INSERT INTO admission_policies (resource_kind, resource_id, policy) VALUES ($1, $2, $3)
                     ON CONFLICT (resource_kind, resource_id) DO UPDATE SET policy = excluded.policy",
                )
                .bind(kind)
                .bind(id)
                .bind(encode_admission_policy(p)),
                None => sqlx::query("DELETE FROM admission_policies WHERE resource_kind = $1 AND resource_id = $2")
                    .bind(kind)
                    .bind(id),
            }
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
            let version = advance_version(&mut tx, now).await?;
            tx.commit().await.map_err(map_sqlx_error)?;
            Ok(version)
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
            parse_subject(
                row.get("principal_id"),
                row.get("subject_kind"),
                row.get("subject_id"),
                row.get("subject_relation"),
            )?,
            row.get("resource_kind"),
            row.get("resource_id"),
            row.get("relationship"),
            parse_pid(row.get("granted_by"), "granted_by")?,
            on_behalf_of,
            row.get("granted_at"),
            row.get("revoked_at"),
        )
        .with_lease(TupleLease::from_columns(row.get("lease_iat"), row.get("lease_refresh_after"), row.get("lease_exp"))?))
    }

    /// Advance the ownership version inside `tx` and return it — the same
    /// transaction as the row change it versions.
    async fn advance_version(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>, now: i64) -> Result<u64, StoreError> {
        let version: i64 =
            sqlx::query_scalar("UPDATE ownership_version SET version = MAX(version + 1, ?) RETURNING version")
                .bind(now)
                .fetch_one(&mut **tx)
                .await
                .map_err(map_sqlx_error)?;
        version_from_sql(version)
    }

    #[async_trait]
    impl OwnershipStore for SqliteOwnershipStore {
        async fn insert(&self, o: &NewOwnership, now: i64) -> Result<Inserted, StoreError> {
            let id = mint_row_id();
            let principal = o.subject.principal().map(|p| p.to_string());
            let set = o.subject.as_set();
            let granted_by = o.granted_by.to_string();
            let on_behalf_of = o.on_behalf_of.as_ref().map(|p| p.to_string());
            let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
            sqlx::query(
                "INSERT INTO ownership
                    (id, principal_id, subject_kind, subject_id, subject_relation,
                     resource_kind, resource_id, relationship,
                     granted_by, on_behalf_of, granted_at,
                     lease_iat, lease_refresh_after, lease_exp)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&id)
            .bind(principal.as_deref())
            .bind(set.map(|s| s.0))
            .bind(set.map(|s| s.1))
            .bind(set.map(|s| s.2))
            .bind(&o.resource_kind)
            .bind(&o.resource_id)
            .bind(&o.relationship)
            .bind(&granted_by)
            .bind(on_behalf_of.as_deref())
            .bind(now)
            .bind(o.lease.map(|l| l.iat))
            .bind(o.lease.map(|l| l.lease.refresh_after()))
            .bind(o.lease.and_then(|l| l.lease.exp()))
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
            let version = advance_version(&mut tx, now).await?;
            tx.commit().await.map_err(map_sqlx_error)?;
            let row = OwnershipRow::new(
                id,
                o.subject.clone(),
                o.resource_kind.clone(),
                o.resource_id.clone(),
                o.relationship.clone(),
                o.granted_by.clone(),
                o.on_behalf_of.clone(),
                now,
                None,
            )
            .with_lease(o.lease);
            Ok(Inserted { row, version })
        }

        async fn get(&self, id: &str) -> Result<Option<OwnershipRow>, StoreError> {
            let row = sqlx::query(&format!(
                "SELECT {COLUMNS} FROM ownership WHERE id = ?"
            ))
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            row.map(row_from).transpose()
        }

        async fn revoke_by_id(&self, id: &str, now: i64) -> Result<u64, StoreError> {
            let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
            let res = sqlx::query(
                "UPDATE ownership SET revoked_at = ?
                 WHERE id = ? AND revoked_at IS NULL",
            )
            .bind(now)
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
            if res.rows_affected() > 0 {
                let version = advance_version(&mut tx, now).await?;
                tx.commit().await.map_err(map_sqlx_error)?;
                return Ok(version);
            }
            tx.rollback().await.map_err(map_sqlx_error)?;
            // Nothing changed: unknown id (NotFound), or already revoked — an
            // idempotent no-op that reports the version as it stands.
            let exists = sqlx::query("SELECT 1 AS one FROM ownership WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_sqlx_error)?
                .is_some();
            if !exists {
                return Err(StoreError::NotFound);
            }
            self.current_version().await
        }

        async fn revoke_by_principal(
            &self,
            principal: &PrincipalId,
            now: i64,
        ) -> Result<u64, StoreError> {
            let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
            let swept = sqlx::query(
                "UPDATE ownership SET revoked_at = ?
                 WHERE principal_id = ? AND revoked_at IS NULL",
            )
            .bind(now)
            .bind(principal.to_string())
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?
            .rows_affected();
            if swept > 0 {
                let version = advance_version(&mut tx, now).await?;
                tx.commit().await.map_err(map_sqlx_error)?;
                return Ok(version);
            }
            tx.rollback().await.map_err(map_sqlx_error)?;
            self.current_version().await
        }

        async fn list_history_for_principal(
            &self,
            principal: &PrincipalId,
        ) -> Result<Vec<OwnershipRow>, StoreError> {
            let rows = sqlx::query(&format!("SELECT {COLUMNS} FROM ownership WHERE principal_id = ?"))
                .bind(principal.to_string())
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            rows.into_iter().map(row_from).collect()
        }

        async fn current_version(&self) -> Result<u64, StoreError> {
            let version: i64 = sqlx::query_scalar("SELECT version FROM ownership_version")
                .fetch_one(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            version_from_sql(version)
        }

        async fn list_for_principal(
            &self,
            principal: &PrincipalId,
        ) -> Result<Vec<OwnershipRow>, StoreError> {
            let rows = sqlx::query(&format!(
                "SELECT {COLUMNS} FROM ownership
                 WHERE principal_id = ? AND revoked_at IS NULL"
            ))
            .bind(principal.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            rows.into_iter().map(row_from).collect()
        }

        async fn list_for_resource(
            &self,
            resource_kind: &str,
            resource_id: &str,
        ) -> Result<Vec<OwnershipRow>, StoreError> {
            let rows = sqlx::query(&format!(
                "SELECT {COLUMNS} FROM ownership
                 WHERE resource_kind = ? AND resource_id = ? AND revoked_at IS NULL"
            ))
            .bind(resource_kind)
            .bind(resource_id)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            rows.into_iter().map(row_from).collect()
        }

        async fn list_for_subject_set(
            &self,
            kind: &str,
            id: &str,
        ) -> Result<Vec<OwnershipRow>, StoreError> {
            let rows = sqlx::query(&format!(
                "SELECT {COLUMNS} FROM ownership
                 WHERE subject_kind = ? AND subject_id = ? AND revoked_at IS NULL"
            ))
            .bind(kind)
            .bind(id)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            rows.into_iter().map(row_from).collect()
        }

        async fn list_for_kind(
            &self,
            resource_kind: &str,
        ) -> Result<Vec<OwnershipRow>, StoreError> {
            let rows = sqlx::query(&format!(
                "SELECT {COLUMNS} FROM ownership
                 WHERE resource_kind = ? AND revoked_at IS NULL"
            ))
            .bind(resource_kind)
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            rows.into_iter().map(row_from).collect()
        }

        async fn revocation_key(&self, kind: &str, id: &str) -> Result<RevocationKey, StoreError> {
            // Insert-or-ignore, then reread: a concurrent creator's row wins
            // and both callers return it (migration 0014).
            sqlx::query(
                "INSERT INTO revocation_keys (resource_kind, resource_id, key) VALUES (?, ?, ?)
                 ON CONFLICT (resource_kind, resource_id) DO NOTHING",
            )
            .bind(kind)
            .bind(id)
            .bind(new_revocation_key().as_bytes().to_vec())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            let bytes: Vec<u8> =
                sqlx::query_scalar("SELECT key FROM revocation_keys WHERE resource_kind = ? AND resource_id = ?")
                    .bind(kind)
                    .bind(id)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(map_sqlx_error)?;
            super::revocation_key_from_sql(kind, id, bytes)
        }

        async fn admission_policy(&self, kind: &str, id: &str) -> Result<Option<AdmissionPolicy>, StoreError> {
            let column: Option<String> = sqlx::query_scalar(
                "SELECT policy FROM admission_policies WHERE resource_kind = ? AND resource_id = ?",
            )
            .bind(kind)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            column.map(|c| decode_admission_policy(kind, id, &c)).transpose()
        }

        async fn set_admission_policy(
            &self,
            kind: &str,
            id: &str,
            policy: Option<&AdmissionPolicy>,
            now: i64,
        ) -> Result<u64, StoreError> {
            let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
            match policy {
                Some(p) => sqlx::query(
                    "INSERT INTO admission_policies (resource_kind, resource_id, policy) VALUES (?, ?, ?)
                     ON CONFLICT (resource_kind, resource_id) DO UPDATE SET policy = excluded.policy",
                )
                .bind(kind)
                .bind(id)
                .bind(encode_admission_policy(p)),
                None => sqlx::query("DELETE FROM admission_policies WHERE resource_kind = ? AND resource_id = ?")
                    .bind(kind)
                    .bind(id),
            }
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?;
            let version = advance_version(&mut tx, now).await?;
            tx.commit().await.map_err(map_sqlx_error)?;
            Ok(version)
        }
    }
}

/// The 32 bytes a `revocation_keys.key` column read back as.
fn revocation_key_from_sql(kind: &str, id: &str, bytes: Vec<u8>) -> Result<RevocationKey, StoreError> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| StoreError::Backend(format!("revocation key for {kind}/{id} is not 32 bytes")))?;
    Ok(RevocationKey::from_bytes(bytes))
}
