//! [`AuditStore`](cheers_server::AuditStore) over `sqlx`.
//!
//! Append-only. The only mutation method is [`insert_batch`]; the read side
//! is [`query_by_on_behalf_of`](cheers_server::AuditStore::query_by_on_behalf_of),
//! a keyset page over the `ix_audit_sub_at` index laid down by
//! `migrations/{pg,sqlite}/0004_audit.sql`.
//!
//! Each batch runs inside a single transaction so a mid-batch DB failure
//! leaves the table untouched — kamaji's bounded-backoff retry sees a
//! clean 4xx/5xx, never a partial commit.

use std::str::FromStr;

use async_trait::async_trait;
use serde_json;

use cheers_core::{Actor, PrincipalId, Scope, StoreError};
use cheers_server::audit::{AuditPage, AuditQuery, AuditRecord, AuditRow, AuditStore};

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

/// Every column of one `audit` row, straight out of the driver. The two
/// backends differ only in how they pull these out; assembling the typed
/// [`AuditRow`] is identical, so it lives once in [`assemble_row`].
struct RawAuditRow {
    id: String,
    at: i64,
    sub: String,
    act_sub: Option<String>,
    camp_id: Option<String>,
    aud: String,
    method: String,
    scope: String,
    result: String,
    request_id: String,
    ingested_at: i64,
}

/// The column list every read shares, in the order [`assemble_row`] expects.
const AUDIT_COLUMNS: &str =
    "id, at, sub, act_sub, camp_id, aud, method, scope, result, request_id, ingested_at";

/// Rebuild the typed row. A stored row that no longer parses (unknown
/// principal prefix, a `Scope` variant this binary doesn't know, a field
/// emptied by a hand-written INSERT) surfaces as
/// [`StoreError::Backend`] naming the offending row id — the read fails
/// loudly rather than silently dropping audit history from the page.
fn assemble_row(raw: RawAuditRow) -> Result<AuditRow, StoreError> {
    let sub = parse_pid(&raw.sub, &raw.id, "sub")?;
    let act = raw
        .act_sub
        .as_deref()
        .map(|s| parse_pid(s, &raw.id, "act_sub"))
        .transpose()?
        .map(Actor::new);
    let scope: Vec<Scope> = serde_json::from_str(&raw.scope)
        .map_err(|e| StoreError::Backend(format!("audit row {}: scope decode: {e}", raw.id)))?;
    let record = AuditRecord::new(
        raw.at,
        sub,
        act,
        raw.camp_id,
        raw.aud,
        raw.method,
        scope,
        raw.result,
        raw.request_id,
    )
    .map_err(|e| StoreError::Backend(format!("audit row {}: {e}", raw.id)))?;
    Ok(AuditRow::new(raw.id, record, raw.ingested_at))
}

fn parse_pid(s: &str, row_id: &str, field: &str) -> Result<PrincipalId, StoreError> {
    PrincipalId::from_str(s)
        .map_err(|e| StoreError::Backend(format!("audit row {row_id}: {field}: {e}")))
}

/// `LIKE` pattern matching a literal prefix.
///
/// `%` and `_` inside a caller-supplied `method_prefix` are ordinary
/// characters as far as the API contract is concerned ("the method starts
/// with this string"), so they are escaped before the trailing wildcard is
/// appended. Pair with `ESCAPE '\'` — both Postgres and SQLite honour it.
fn like_prefix_pattern(prefix: &str) -> String {
    let mut out = String::with_capacity(prefix.len() + 1);
    for ch in prefix.chars() {
        if matches!(ch, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('%');
    out
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

        async fn query_by_on_behalf_of(
            &self,
            query: &AuditQuery,
        ) -> Result<AuditPage, StoreError> {
            use sqlx::Row as _;

            // `sub = $1` leads so the planner walks ix_audit_sub_at
            // (sub, at DESC) — the index 0004_audit.sql laid down for exactly
            // this query. The cursor predicate narrows within that range;
            // the `id` tie-break sorts inside one `at` value.
            let mut sql = format!("SELECT {AUDIT_COLUMNS} FROM audit WHERE sub = $1");
            let mut n = 1;
            if query.since.is_some() {
                n += 1;
                sql.push_str(&format!(" AND at >= ${n}"));
            }
            if query.method_prefix.is_some() {
                n += 1;
                sql.push_str(&format!(" AND method LIKE ${n} ESCAPE '\\'"));
            }
            if query.cursor.is_some() {
                sql.push_str(&format!(
                    " AND (at < ${} OR (at = ${} AND id < ${}))",
                    n + 1,
                    n + 1,
                    n + 2
                ));
                n += 2;
            }
            n += 1;
            sql.push_str(&format!(" ORDER BY at DESC, id DESC LIMIT ${n}"));

            let mut q = sqlx::query(&sql).bind(query.on_behalf_of.to_string());
            if let Some(since) = query.since {
                q = q.bind(since);
            }
            if let Some(prefix) = &query.method_prefix {
                q = q.bind(like_prefix_pattern(prefix));
            }
            if let Some(cursor) = &query.cursor {
                q = q.bind(cursor.at).bind(cursor.id.clone());
            }
            // Over-fetch one: AuditPage::from_overfetch turns the extra row
            // into `next_cursor` and drops it.
            q = q.bind(query.limit as i64 + 1);

            let rows = q.fetch_all(&self.pool).await.map_err(map_sqlx_error)?;
            let decoded = rows
                .into_iter()
                .map(|row| {
                    assemble_row(RawAuditRow {
                        id: row.get("id"),
                        at: row.get("at"),
                        sub: row.get("sub"),
                        act_sub: row.get("act_sub"),
                        camp_id: row.get("camp_id"),
                        aud: row.get("aud"),
                        method: row.get("method"),
                        scope: row.get("scope"),
                        result: row.get("result"),
                        request_id: row.get("request_id"),
                        ingested_at: row.get("ingested_at"),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(AuditPage::from_overfetch(decoded, query.limit))
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

        async fn query_by_on_behalf_of(
            &self,
            query: &AuditQuery,
        ) -> Result<AuditPage, StoreError> {
            use sqlx::Row as _;

            // Same shape as the Postgres arm — see its comment for why the
            // predicate is ordered this way. Positional `?` params, so the
            // cursor is bound twice (SQLite has no `$n` re-use).
            let mut sql = format!("SELECT {AUDIT_COLUMNS} FROM audit WHERE sub = ?");
            if query.since.is_some() {
                sql.push_str(" AND at >= ?");
            }
            if query.method_prefix.is_some() {
                sql.push_str(" AND method LIKE ? ESCAPE '\\'");
            }
            if query.cursor.is_some() {
                sql.push_str(" AND (at < ? OR (at = ? AND id < ?))");
            }
            sql.push_str(" ORDER BY at DESC, id DESC LIMIT ?");

            let mut q = sqlx::query(&sql).bind(query.on_behalf_of.to_string());
            if let Some(since) = query.since {
                q = q.bind(since);
            }
            if let Some(prefix) = &query.method_prefix {
                q = q.bind(like_prefix_pattern(prefix));
            }
            if let Some(cursor) = &query.cursor {
                q = q.bind(cursor.at).bind(cursor.at).bind(cursor.id.clone());
            }
            q = q.bind(query.limit as i64 + 1);

            let rows = q.fetch_all(&self.pool).await.map_err(map_sqlx_error)?;
            let decoded = rows
                .into_iter()
                .map(|row| {
                    assemble_row(RawAuditRow {
                        id: row.get("id"),
                        at: row.get("at"),
                        sub: row.get("sub"),
                        act_sub: row.get("act_sub"),
                        camp_id: row.get("camp_id"),
                        aud: row.get("aud"),
                        method: row.get("method"),
                        scope: row.get("scope"),
                        result: row.get("result"),
                        request_id: row.get("request_id"),
                        ingested_at: row.get("ingested_at"),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(AuditPage::from_overfetch(decoded, query.limit))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_prefix_escapes_wildcards_so_a_prefix_stays_literal() {
        assert_eq!(like_prefix_pattern("cloud.deploy"), "cloud.deploy%");
        // A caller asking for methods starting with "a_b" must not match
        // "axb" — `_` is a single-char wildcard in SQL LIKE.
        assert_eq!(like_prefix_pattern("a_b"), r"a\_b%");
        assert_eq!(like_prefix_pattern("100%"), r"100\%%");
        assert_eq!(like_prefix_pattern(r"back\slash"), r"back\\slash%");
    }

    #[test]
    fn audit_columns_match_the_assemble_order() {
        // The SELECT list is only safe to reuse across backends because it
        // names every field RawAuditRow needs.
        for col in [
            "id",
            "at",
            "sub",
            "act_sub",
            "camp_id",
            "aud",
            "method",
            "scope",
            "result",
            "request_id",
            "ingested_at",
        ] {
            assert!(
                AUDIT_COLUMNS.split(", ").any(|c| c == col),
                "AUDIT_COLUMNS is missing `{col}`",
            );
        }
    }
}
