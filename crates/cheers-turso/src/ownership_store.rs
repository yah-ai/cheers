//! [`OwnershipStore`] over the in-process engine.
//!
//! The `granted_by` / `on_behalf_of` invariants are enforced twice on purpose:
//! `NewOwnership::new` rejects a bad grant before it costs a round trip, and
//! the schema's `CHECK` constraints reject it if it somehow arrives anyway
//! (a raw INSERT, a future code path). The engine enforces those CHECKs —
//! verified, not assumed; see `ownership_check_constraints_reject_bad_rows` in
//! the shared suite.

use std::sync::Arc;

use async_trait::async_trait;
use cheers_core::{PrincipalId, StoreError};
use cheers_server::ownership::{NewOwnership, OwnershipRow, OwnershipStore};

use crate::conn::TursoConn;
use crate::util::{col, mint_id, opt_text};

/// The column list every read shares, in the order [`row_to_ownership`] expects.
const COLUMNS: &str = "id, principal_id, resource_kind, resource_id, relationship, \
                       granted_by, on_behalf_of, granted_at, revoked_at";

/// Parse a principal-id column back into a [`PrincipalId`].
///
/// The schema's CHECK constraints guarantee well-formed values at write time,
/// so a parse failure on read is a data-integrity error — surfaced as
/// `Backend`, never quietly skipped, because silently dropping an ownership
/// row from a list is a permission decision made by a bug.
fn parse_pid(s: String, column: &'static str) -> Result<PrincipalId, StoreError> {
    s.parse::<PrincipalId>().map_err(|e| {
        StoreError::Backend(format!("invalid {column} principal id in ownership row: {e}"))
    })
}

/// [`OwnershipStore`] backed by an in-process Turso database.
pub struct TursoOwnershipStore {
    conn: Arc<TursoConn>,
}

impl TursoOwnershipStore {
    pub fn new(conn: Arc<TursoConn>) -> Self {
        Self { conn }
    }

    pub fn conn(&self) -> &Arc<TursoConn> {
        &self.conn
    }
}

impl std::fmt::Debug for TursoOwnershipStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TursoOwnershipStore").finish_non_exhaustive()
    }
}

fn row_to_ownership(row: &turso::Row) -> Result<OwnershipRow, StoreError> {
    let on_behalf_of = col::<Option<String>>(row, 6, "on_behalf_of")?
        .map(|s| parse_pid(s, "on_behalf_of"))
        .transpose()?;
    Ok(OwnershipRow::new(
        col::<String>(row, 0, "id")?,
        parse_pid(col::<String>(row, 1, "principal_id")?, "principal_id")?,
        col::<String>(row, 2, "resource_kind")?,
        col::<String>(row, 3, "resource_id")?,
        col::<String>(row, 4, "relationship")?,
        parse_pid(col::<String>(row, 5, "granted_by")?, "granted_by")?,
        on_behalf_of,
        col::<i64>(row, 7, "granted_at")?,
        col::<Option<i64>>(row, 8, "revoked_at")?,
    ))
}

#[async_trait]
impl OwnershipStore for TursoOwnershipStore {
    async fn insert(&self, o: &NewOwnership, now: i64) -> Result<OwnershipRow, StoreError> {
        let id = mint_id();
        let on_behalf_of = o.on_behalf_of.as_ref().map(|p| p.to_string());
        self.conn
            .execute(
                "INSERT INTO ownership
                    (id, principal_id, resource_kind, resource_id, relationship,
                     granted_by, on_behalf_of, granted_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    id.as_str().into(),
                    o.principal_id.to_string().into(),
                    o.resource_kind.as_str().into(),
                    o.resource_id.as_str().into(),
                    o.relationship.as_str().into(),
                    o.granted_by.to_string().into(),
                    opt_text(on_behalf_of.as_deref()),
                    now.into(),
                ],
            )
            .await?;
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
        let row = self
            .conn
            .query_one(
                &format!("SELECT {COLUMNS} FROM ownership WHERE id = ?"),
                vec![id.into()],
            )
            .await?;
        row.as_ref().map(row_to_ownership).transpose()
    }

    async fn revoke_by_id(&self, id: &str, now: i64) -> Result<(), StoreError> {
        let affected = self
            .conn
            .execute(
                "UPDATE ownership SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                vec![now.into(), id.into()],
            )
            .await?;
        if affected == 0 {
            // Zero rows is ambiguous: unknown id, or already revoked. Only the
            // first is NotFound — re-revoking is idempotent and must not
            // overwrite the original revoked_at, which is why the UPDATE
            // carries `revoked_at IS NULL` in the first place.
            let exists = self
                .conn
                .query_one("SELECT 1 FROM ownership WHERE id = ?", vec![id.into()])
                .await?
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
        // The cascade primitive: one statement sweeps every live grant made on
        // this user's behalf, and returns how many it caught.
        self.conn
            .execute(
                "UPDATE ownership SET revoked_at = ?
                 WHERE on_behalf_of = ? AND revoked_at IS NULL",
                vec![now.into(), user.to_string().into()],
            )
            .await
    }

    async fn list_for_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<Vec<OwnershipRow>, StoreError> {
        let rows = self
            .conn
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM ownership
                     WHERE principal_id = ? AND revoked_at IS NULL"
                ),
                vec![principal.to_string().into()],
            )
            .await?;
        rows.iter().map(row_to_ownership).collect()
    }

    async fn list_for_resource(
        &self,
        resource_kind: &str,
        resource_id: &str,
    ) -> Result<Vec<OwnershipRow>, StoreError> {
        let rows = self
            .conn
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM ownership
                     WHERE resource_kind = ? AND resource_id = ? AND revoked_at IS NULL"
                ),
                vec![resource_kind.into(), resource_id.into()],
            )
            .await?;
        rows.iter().map(row_to_ownership).collect()
    }
}
