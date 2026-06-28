//! [`AuditStore`](cheers_server::AuditStore) over `sqlx`.
//!
//! Append-only. The only mutation method is [`insert_batch`]; reads (paged by
//! `on_behalf_of`) land alongside F14 atop the same schema.
//!
//! Each batch runs inside a single transaction so a mid-batch DB failure
//! leaves the table untouched — kamaji's bounded-backoff retry sees a
//! clean 4xx/5xx, never a partial commit.

use async_trait::async_trait;
use serde_json;

use cheers_core::StoreError;
use cheers_server::audit::{AuditRecord, AuditRow, AuditStore};

use crate::error::map_sqlx_error;

#[cfg(feature = "pg")]
pub use pg::PgAuditStore;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteAuditStore;

/// Mint a fresh opaque row id — matches the UUIDv4 shape used by every
/// other store in this crate.
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

/// Encode the `scope` column. Stored as a JSON array of the wire scope
/// strings — keeps the column human-readable and forward-compatible if the
/// `Scope` enum grows variants between writer and reader.
fn encode_scope(record: &AuditRecord) -> Result<String, StoreError> {
    serde_json::to_string(&record.scope)
        .map_err(|e| StoreError::Backend(format!("audit scope encode: {e}")))
}

#[cfg(feature = "pg")]
mod pg {
    use super::*;
    use sqlx::PgPool;

    /// [`AuditStore`] over Postgres.
    pub struct PgAuditStore {
        pool: PgPool,
    }

    impl PgAuditStore {
        pub fn new(pool: PgPool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &PgPool {
            &self.pool
        }
    }

    impl std::fmt::Debug for PgAuditStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PgAuditStore").finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl AuditStore for PgAuditStore {
        async fn insert_batch(
            &self,
            records: &[AuditRecord],
            ingested_at: i64,
        ) -> Result<Vec<AuditRow>, StoreError> {
            if records.is_empty() {
                return Ok(Vec::new());
            }
            let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
            let mut out = Vec::with_capacity(records.len());
            for rec in records {
                let id = mint_row_id();
                let sub = rec.sub.to_string();
                let act_sub = rec.act.as_ref().map(|a| a.sub.to_string());
                let scope_json = encode_scope(rec)?;
                sqlx::query(
                    "INSERT INTO audit
                        (id, at, sub, act_sub, camp_id, aud, method, scope, result, request_id, ingested_at)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                )
                .bind(&id)
                .bind(rec.at)
                .bind(&sub)
                .bind(act_sub.as_deref())
                .bind(rec.camp_id.as_deref())
                .bind(&rec.aud)
                .bind(&rec.method)
                .bind(&scope_json)
                .bind(&rec.result)
                .bind(&rec.request_id)
                .bind(ingested_at)
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_error)?;
                out.push(AuditRow::new(id, rec.clone(), ingested_at));
            }
            tx.commit().await.map_err(map_sqlx_error)?;
            Ok(out)
        }
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use sqlx::SqlitePool;

    /// [`AuditStore`] over SQLite.
    pub struct SqliteAuditStore {
        pool: SqlitePool,
    }

    impl SqliteAuditStore {
        pub fn new(pool: SqlitePool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &SqlitePool {
            &self.pool
        }
    }

    impl std::fmt::Debug for SqliteAuditStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SqliteAuditStore").finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl AuditStore for SqliteAuditStore {
        async fn insert_batch(
            &self,
            records: &[AuditRecord],
            ingested_at: i64,
        ) -> Result<Vec<AuditRow>, StoreError> {
            if records.is_empty() {
                return Ok(Vec::new());
            }
            let mut tx = self.pool.begin().await.map_err(map_sqlx_error)?;
            let mut out = Vec::with_capacity(records.len());
            for rec in records {
                let id = mint_row_id();
                let sub = rec.sub.to_string();
                let act_sub = rec.act.as_ref().map(|a| a.sub.to_string());
                let scope_json = encode_scope(rec)?;
                sqlx::query(
                    "INSERT INTO audit
                        (id, at, sub, act_sub, camp_id, aud, method, scope, result, request_id, ingested_at)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                )
                .bind(&id)
                .bind(rec.at)
                .bind(&sub)
                .bind(act_sub.as_deref())
                .bind(rec.camp_id.as_deref())
                .bind(&rec.aud)
                .bind(&rec.method)
                .bind(&scope_json)
                .bind(&rec.result)
                .bind(&rec.request_id)
                .bind(ingested_at)
                .execute(&mut *tx)
                .await
                .map_err(map_sqlx_error)?;
                out.push(AuditRow::new(id, rec.clone(), ingested_at));
            }
            tx.commit().await.map_err(map_sqlx_error)?;
            Ok(out)
        }
    }
}
