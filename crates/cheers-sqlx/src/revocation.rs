//! [`RevocationWriter`](cheers_server::RevocationWriter) +
//! [`RevocationReader`](cheers_verify::RevocationReader) over `sqlx`.
//!
//! Single struct implements both halves — the typical pg/sqlite deployment
//! has the same DB host serving the origin's write side and the edge's read
//! side. For a real edge/origin split, swap in `cheers_redis` (eventually-
//! consistent KV) on the edge and let the origin keep this one too.
//!
//! Schema (migrations 0010 + 0012, R732-F6/T7): `revocations` holds one row
//! per identity keyed on `(kind, subject, resource_kind, resource_id)`, with
//! its bound in `bound` / `expires_at` — see
//! [`revoked_columns`](cheers_server::revoked_columns) — and the one-row
//! `revocation_epoch` holds the set's epoch. Every write that changes the
//! entries advances the epoch in the same transaction; [`snapshot`] reads both
//! in one statement, so the epoch and the contents always agree.
//!
//! [`snapshot`]: cheers_server::RevocationWriter::snapshot

use async_trait::async_trait;
use cheers_core::{DeviceId, PrincipalId, Revoked, StoreError};
#[cfg(any(feature = "pg", feature = "sqlite"))]
use cheers_server::RevokedColumns;
use cheers_server::{
    epoch_from_sql, revoked_columns, revoked_from_columns, RevocationSnapshot, RevocationWriter,
};
use cheers_verify::RevocationReader;
use sqlx::Row;

use crate::error::map_sqlx_error;

#[cfg(feature = "pg")]
pub use pg::PgRevocationStore;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteRevocationStore;

/// One statement, so Postgres's READ COMMITTED and SQLite both see the epoch
/// and the entries from the same snapshot. The epoch row always exists, so an
/// empty set is one row of NULL entry columns.
#[cfg(any(feature = "pg", feature = "sqlite"))]
const SNAPSHOT_SQL: &str = "SELECT e.epoch, r.kind, r.subject, r.resource_kind, r.resource_id, r.bound, r.expires_at
     FROM revocation_epoch e LEFT JOIN revocations r ON 1 = 1";

/// The upsert's `WHERE` on conflict: the new bound is strictly greater than
/// the held one. A device / membership compares `bound`; a jti compares
/// `expires_at`, where `NULL` (never lapses) is the top. For a device or
/// membership both `expires_at` are NULL, so the second arm is false; for a
/// jti both `bound` are NULL, so the first arm is NULL (false).
#[cfg(any(feature = "pg", feature = "sqlite"))]
const RAISES_SQL: &str = "excluded.bound > revocations.bound
     OR (revocations.expires_at IS NOT NULL
         AND (excluded.expires_at IS NULL OR excluded.expires_at > revocations.expires_at))";

/// The held bound of `probe`'s identity: `bound`, `expires_at`.
#[cfg(any(feature = "pg", feature = "sqlite"))]
type HeldBound = (Option<i64>, Option<i64>);

/// `true` if a held device / membership `bound` masks `at` (`at < bound`).
#[cfg(any(feature = "pg", feature = "sqlite"))]
fn masks(held: Option<HeldBound>, at: u64) -> bool {
    held.and_then(|(bound, _)| bound)
        .is_some_and(|bound| u64::try_from(bound).is_ok_and(|bound| at < bound))
}

#[cfg(any(feature = "pg", feature = "sqlite"))]
fn upsert_sql(placeholders: [&str; 7]) -> String {
    let [k, s, rk, ri, b, e, at] = placeholders;
    format!(
        "INSERT INTO revocations (kind, subject, resource_kind, resource_id, bound, expires_at, revoked_at)
         VALUES ({k}, {s}, {rk}, {ri}, {b}, {e}, {at})
         ON CONFLICT (kind, subject, resource_kind, resource_id)
         DO UPDATE SET bound = excluded.bound, expires_at = excluded.expires_at, revoked_at = excluded.revoked_at
         WHERE {RAISES_SQL}"
    )
}

#[cfg(any(feature = "pg", feature = "sqlite"))]
fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(any(feature = "pg", feature = "sqlite"))]
fn snapshot_from_rows<R: Row>(rows: Vec<R>) -> Result<RevocationSnapshot, StoreError>
where
    usize: sqlx::ColumnIndex<R>,
    i64: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    Option<String>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
    Option<i64>: for<'r> sqlx::Decode<'r, R::Database> + sqlx::Type<R::Database>,
{
    let mut epoch = None;
    let mut revoked = Vec::with_capacity(rows.len());
    for row in rows {
        epoch = Some(row.try_get::<i64, _>(0).map_err(map_sqlx_error)?);
        let Some(kind) = row.try_get::<Option<String>, _>(1).map_err(map_sqlx_error)? else {
            continue;
        };
        let text = |i: usize| -> Result<String, StoreError> {
            Ok(row.try_get::<Option<String>, _>(i).map_err(map_sqlx_error)?.unwrap_or_default())
        };
        let int = |i: usize| row.try_get::<Option<i64>, _>(i).map_err(map_sqlx_error);
        revoked.push(revoked_from_columns(&kind, text(2)?, text(3)?, text(4)?, int(5)?, int(6)?)?);
    }
    let epoch = epoch.ok_or_else(|| StoreError::Backend("revocation_epoch row missing".into()))?;
    Ok(RevocationSnapshot {
        epoch: epoch_from_sql(epoch)?,
        revoked,
    })
}

#[cfg(feature = "pg")]
mod pg {
    use super::*;
    use sqlx::PgPool;

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

        /// Garbage-collect entries whose `expires_at` is at or before `now`,
        /// advancing the epoch when anything went. Call periodically (e.g.
        /// once an hour from a cron / background task) to keep the table
        /// bounded. Returns the number of rows deleted.
        pub async fn gc(&self, now: i64) -> Result<u64, StoreError> {
            let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
            let deleted = sqlx::query(
                "DELETE FROM revocations WHERE expires_at IS NOT NULL AND expires_at <= $1",
            )
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?
            .rows_affected();
            if deleted > 0 {
                advance_epoch(&mut tx).await?;
            }
            tx.commit().await.map_err(map_sqlx_error)?;
            Ok(deleted)
        }

        async fn held(&self, probe: &Revoked) -> Result<Option<HeldBound>, StoreError> {
            let RevokedColumns { kind, subject, resource_kind, resource_id, .. } = revoked_columns(probe);
            let row = sqlx::query(
                "SELECT bound, expires_at FROM revocations
                 WHERE kind = $1 AND subject = $2 AND resource_kind = $3 AND resource_id = $4",
            )
            .bind(kind)
            .bind(subject)
            .bind(resource_kind)
            .bind(resource_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            row.map(|row| -> Result<HeldBound, StoreError> {
                Ok((
                    row.try_get::<Option<i64>, _>(0).map_err(map_sqlx_error)?,
                    row.try_get::<Option<i64>, _>(1).map_err(map_sqlx_error)?,
                ))
            })
            .transpose()
        }
    }

    async fn advance_epoch(tx: &mut sqlx::Transaction<'_, sqlx::Postgres>) -> Result<(), StoreError> {
        sqlx::query("UPDATE revocation_epoch SET epoch = GREATEST(epoch + 1, $1)")
            .bind(now())
            .execute(&mut **tx)
            .await
            .map_err(map_sqlx_error)?;
        Ok(())
    }

    impl std::fmt::Debug for PgRevocationStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PgRevocationStore").finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl RevocationWriter for PgRevocationStore {
        async fn revoke(&self, entry: &Revoked) -> Result<(), StoreError> {
            let c = revoked_columns(entry);
            let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
            // One row per identity; re-revoking keeps the larger bound, and
            // the epoch moves only when a row was inserted or its bound rose.
            let inserted = sqlx::query(&upsert_sql(["$1", "$2", "$3", "$4", "$5", "$6", "$7"]))
                .bind(c.kind)
                .bind(c.subject)
                .bind(c.resource_kind)
                .bind(c.resource_id)
                .bind(c.bound)
                .bind(c.expires_at)
                .bind(now())
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_error)?
                .rows_affected();
            if inserted > 0 {
                advance_epoch(&mut tx).await?;
            }
            tx.commit().await.map_err(map_sqlx_error)?;
            Ok(())
        }

        async fn snapshot(&self) -> Result<RevocationSnapshot, StoreError> {
            let rows = sqlx::query(SNAPSHOT_SQL)
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            snapshot_from_rows(rows)
        }
    }

    #[async_trait]
    impl RevocationReader for PgRevocationStore {
        async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
            Ok(self.held(&Revoked::jti(jti, None)).await?.is_some())
        }

        async fn is_device_revoked(&self, device: &DeviceId, seq: u64) -> Result<bool, StoreError> {
            Ok(masks(self.held(&Revoked::device(device.clone(), 0)).await?, seq))
        }

        async fn is_membership_revoked(
            &self,
            _key: &cheers_core::RevocationKey,
            kind: &str,
            id: &str,
            principal: &PrincipalId,
            snapshot_epoch: u64,
        ) -> Result<bool, StoreError> {
            let probe = Revoked::membership(kind, id, principal.clone(), 0);
            Ok(masks(self.held(&probe).await?, snapshot_epoch))
        }
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use sqlx::SqlitePool;

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
            let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
            let deleted = sqlx::query(
                "DELETE FROM revocations WHERE expires_at IS NOT NULL AND expires_at <= ?",
            )
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(map_sqlx_error)?
            .rows_affected();
            if deleted > 0 {
                advance_epoch(&mut tx).await?;
            }
            tx.commit().await.map_err(map_sqlx_error)?;
            Ok(deleted)
        }

        async fn held(&self, probe: &Revoked) -> Result<Option<HeldBound>, StoreError> {
            let RevokedColumns { kind, subject, resource_kind, resource_id, .. } = revoked_columns(probe);
            let row = sqlx::query(
                "SELECT bound, expires_at FROM revocations
                 WHERE kind = ? AND subject = ? AND resource_kind = ? AND resource_id = ?",
            )
            .bind(kind)
            .bind(subject)
            .bind(resource_kind)
            .bind(resource_id)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            row.map(|row| -> Result<HeldBound, StoreError> {
                Ok((
                    row.try_get::<Option<i64>, _>(0).map_err(map_sqlx_error)?,
                    row.try_get::<Option<i64>, _>(1).map_err(map_sqlx_error)?,
                ))
            })
            .transpose()
        }
    }

    async fn advance_epoch(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>) -> Result<(), StoreError> {
        sqlx::query("UPDATE revocation_epoch SET epoch = MAX(epoch + 1, ?)")
            .bind(now())
            .execute(&mut **tx)
            .await
            .map_err(map_sqlx_error)?;
        Ok(())
    }

    impl std::fmt::Debug for SqliteRevocationStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SqliteRevocationStore").finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl RevocationWriter for SqliteRevocationStore {
        async fn revoke(&self, entry: &Revoked) -> Result<(), StoreError> {
            let c = revoked_columns(entry);
            let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
            // One row per identity; re-revoking keeps the larger bound, and
            // the epoch moves only when a row was inserted or its bound rose.
            let inserted = sqlx::query(&upsert_sql(["?", "?", "?", "?", "?", "?", "?"]))
                .bind(c.kind)
                .bind(c.subject)
                .bind(c.resource_kind)
                .bind(c.resource_id)
                .bind(c.bound)
                .bind(c.expires_at)
                .bind(now())
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_error)?
                .rows_affected();
            if inserted > 0 {
                advance_epoch(&mut tx).await?;
            }
            tx.commit().await.map_err(map_sqlx_error)?;
            Ok(())
        }

        async fn snapshot(&self) -> Result<RevocationSnapshot, StoreError> {
            let rows = sqlx::query(SNAPSHOT_SQL)
                .fetch_all(&self.pool)
                .await
                .map_err(map_sqlx_error)?;
            snapshot_from_rows(rows)
        }
    }

    #[async_trait]
    impl RevocationReader for SqliteRevocationStore {
        async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
            Ok(self.held(&Revoked::jti(jti, None)).await?.is_some())
        }

        async fn is_device_revoked(&self, device: &DeviceId, seq: u64) -> Result<bool, StoreError> {
            Ok(masks(self.held(&Revoked::device(device.clone(), 0)).await?, seq))
        }

        async fn is_membership_revoked(
            &self,
            _key: &cheers_core::RevocationKey,
            kind: &str,
            id: &str,
            principal: &PrincipalId,
            snapshot_epoch: u64,
        ) -> Result<bool, StoreError> {
            let probe = Revoked::membership(kind, id, principal.clone(), 0);
            Ok(masks(self.held(&probe).await?, snapshot_epoch))
        }
    }
}
