//! [`AuditStore`] over the in-process engine.
//!
//! Append-only. The one mutation is [`insert_batch`](AuditStore::insert_batch);
//! the read side is a keyset page walking the `ix_audit_sub_at` index.
//!
//! Each batch commits inside a single transaction, so a mid-batch failure
//! leaves the table untouched. That is not tidiness — it is the contract the
//! ingest caller's bounded-backoff retry depends on. A partial commit would
//! mean a retried batch double-writes its prefix, and an append-only ledger
//! has nowhere to put a correction.

use std::str::FromStr;
use std::sync::Arc;

use async_trait::async_trait;
use cheers_core::{Actor, PrincipalId, Scope, StoreError};
use cheers_server::audit::{AuditPage, AuditQuery, AuditRecord, AuditRow, AuditStore};

use crate::conn::{TursoConn, Unit};
use crate::util::{col, mint_id, opt_text};

/// The column list every read shares, in the order [`assemble_row`] expects.
const AUDIT_COLUMNS: &str =
    "id, at, sub, act_sub, camp_id, aud, method, scope, result, request_id, ingested_at";

/// [`AuditStore`] backed by an in-process Turso database.
pub struct TursoAuditStore {
    conn: Arc<TursoConn>,
}

impl TursoAuditStore {
    pub fn new(conn: Arc<TursoConn>) -> Self {
        Self { conn }
    }

    pub fn conn(&self) -> &Arc<TursoConn> {
        &self.conn
    }
}

impl std::fmt::Debug for TursoAuditStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TursoAuditStore").finish_non_exhaustive()
    }
}

/// Encode the `scope` column as a JSON array of the wire scope strings — human
/// readable, and forward-compatible if `Scope` grows variants between the
/// writer and a later reader.
fn encode_scope(record: &AuditRecord) -> Result<String, StoreError> {
    serde_json::to_string(&record.scope)
        .map_err(|e| StoreError::Backend(format!("audit scope encode: {e}")))
}

fn parse_pid(s: &str, row_id: &str, field: &str) -> Result<PrincipalId, StoreError> {
    PrincipalId::from_str(s)
        .map_err(|e| StoreError::Backend(format!("audit row {row_id}: {field}: {e}")))
}

/// Rebuild the typed row.
///
/// A stored row that no longer parses — an unknown principal prefix, a `Scope`
/// variant this binary doesn't know, a field emptied by a hand-written INSERT —
/// fails the whole read rather than being dropped from the page. Silently
/// omitting a row from an audit query is the one failure mode an audit log
/// must not have.
fn assemble_row(row: &turso::Row) -> Result<AuditRow, StoreError> {
    let id = col::<String>(row, 0, "id")?;
    let sub = parse_pid(&col::<String>(row, 2, "sub")?, &id, "sub")?;
    let act = col::<Option<String>>(row, 3, "act_sub")?
        .map(|s| parse_pid(&s, &id, "act_sub"))
        .transpose()?
        .map(Actor::new);
    let scope_json = col::<String>(row, 7, "scope")?;
    let scope: Vec<Scope> = serde_json::from_str(&scope_json)
        .map_err(|e| StoreError::Backend(format!("audit row {id}: scope decode: {e}")))?;

    let record = AuditRecord::new(
        col::<i64>(row, 1, "at")?,
        sub,
        act,
        col::<Option<String>>(row, 4, "camp_id")?,
        col::<String>(row, 5, "aud")?,
        col::<String>(row, 6, "method")?,
        scope,
        col::<String>(row, 8, "result")?,
        col::<String>(row, 9, "request_id")?,
    )
    .map_err(|e| StoreError::Backend(format!("audit row {id}: {e}")))?;

    Ok(AuditRow::new(id, record, col::<i64>(row, 10, "ingested_at")?))
}

/// `LIKE` pattern matching a literal prefix.
///
/// `%` and `_` inside a caller-supplied `method_prefix` are ordinary
/// characters as far as the API contract goes ("the method starts with this
/// string"), so they are escaped before the trailing wildcard is appended.
/// Pairs with `ESCAPE '\'` in the query.
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

#[async_trait]
impl AuditStore for TursoAuditStore {
    async fn insert_batch(
        &self,
        records: &[AuditRecord],
        ingested_at: i64,
    ) -> Result<Vec<AuditRow>, StoreError> {
        if records.is_empty() {
            return Ok(Vec::new());
        }

        let mut units = Vec::with_capacity(records.len());
        let mut out = Vec::with_capacity(records.len());
        for rec in records {
            let id = mint_id();
            let act_sub = rec.act.as_ref().map(|a| a.sub.to_string());
            units.push(Unit::stmt(
                "INSERT INTO audit
                    (id, at, sub, act_sub, camp_id, aud, method, scope, result, request_id, ingested_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    id.as_str().into(),
                    rec.at.into(),
                    rec.sub.to_string().into(),
                    opt_text(act_sub.as_deref()),
                    opt_text(rec.camp_id.as_deref()),
                    rec.aud.as_str().into(),
                    rec.method.as_str().into(),
                    encode_scope(rec)?.into(),
                    rec.result.as_str().into(),
                    rec.request_id.as_str().into(),
                    ingested_at.into(),
                ],
            ));
            out.push(AuditRow::new(id, rec.clone(), ingested_at));
        }

        self.conn.transaction(units).await?;
        Ok(out)
    }

    async fn query_by_on_behalf_of(&self, query: &AuditQuery) -> Result<AuditPage, StoreError> {
        // `sub = ?` leads so the planner walks ix_audit_sub_at (sub, at DESC) —
        // the index 0004_audit.sql laid down for exactly this query. The cursor
        // predicate narrows within that range; the `id` tie-break orders rows
        // sharing one `at` value, which is what makes the keyset page stable.
        let mut sql = format!("SELECT {AUDIT_COLUMNS} FROM audit WHERE sub = ?");
        let mut params = vec![query.on_behalf_of.to_string().into()];

        if let Some(since) = query.since {
            sql.push_str(" AND at >= ?");
            params.push(since.into());
        }
        if let Some(prefix) = &query.method_prefix {
            sql.push_str(" AND method LIKE ? ESCAPE '\\'");
            params.push(like_prefix_pattern(prefix).into());
        }
        if let Some(cursor) = &query.cursor {
            // Positional params, so `at` is bound twice — there is no `$n`
            // re-use to lean on here.
            sql.push_str(" AND (at < ? OR (at = ? AND id < ?))");
            params.push(cursor.at.into());
            params.push(cursor.at.into());
            params.push(cursor.id.as_str().into());
        }
        sql.push_str(" ORDER BY at DESC, id DESC LIMIT ?");
        // Over-fetch one: `AuditPage::from_overfetch` turns the extra row into
        // `next_cursor` and drops it.
        params.push((query.limit as i64 + 1).into());

        let rows = self.conn.query(&sql, params).await?;
        let decoded = rows
            .iter()
            .map(assemble_row)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AuditPage::from_overfetch(decoded, query.limit))
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
        // assemble_row reads by position, so the SELECT list is load-bearing.
        assert_eq!(
            AUDIT_COLUMNS.split(", ").collect::<Vec<_>>(),
            vec![
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
            ]
        );
    }
}
