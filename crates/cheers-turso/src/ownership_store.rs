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
use cheers_core::{AdmissionPolicy, PrincipalId, RevocationKey, StoreError, Subject};
use cheers_server::ownership::{
    decode_admission_policy, encode_admission_policy, TupleLease, new_revocation_key, Inserted, NewOwnership, OwnershipRow, OwnershipStore,
};

use crate::conn::{TursoConn, Unit};
use crate::util::{col, mint_id, opt_int, opt_text};

/// The column list every read shares, in the order [`row_to_ownership`] expects.
const COLUMNS: &str = "id, principal_id, subject_kind, subject_id, subject_relation, \
                       resource_kind, resource_id, relationship, \
                       granted_by, on_behalf_of, granted_at, revoked_at, \
                       lease_iat, lease_refresh_after, lease_exp";

/// Advance the ownership version (migration 0013) — one unit of the write's
/// own transaction.
const ADVANCE_VERSION: &str = "UPDATE ownership_version SET version = MAX(version + 1, ?)";

const READ_VERSION: &str = "SELECT version FROM ownership_version";

/// The version a transaction's [`READ_VERSION`] unit read.
fn version_from(rows: Option<&Vec<turso::Row>>) -> Result<u64, StoreError> {
    let row = rows
        .and_then(|r| r.first())
        .ok_or_else(|| StoreError::Backend("ownership_version row missing".into()))?;
    let version = col::<i64>(row, 0, "version")?;
    u64::try_from(version).map_err(|_| StoreError::Backend(format!("negative ownership version {version}")))
}

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

/// Rebuild a row's [`Subject`] from its four subject columns. The schema's
/// one-form CHECK makes a failure here a data-integrity error, like
/// [`parse_pid`].
fn parse_subject(row: &turso::Row) -> Result<Subject, StoreError> {
    let principal = col::<Option<String>>(row, 1, "principal_id")?
        .map(|s| parse_pid(s, "principal_id"))
        .transpose()?;
    Subject::from_parts(
        principal,
        col::<Option<String>>(row, 2, "subject_kind")?,
        col::<Option<String>>(row, 3, "subject_id")?,
        col::<Option<String>>(row, 4, "subject_relation")?,
    )
    .map_err(|e| StoreError::Backend(format!("invalid subject in ownership row: {e}")))
}

fn row_to_ownership(row: &turso::Row) -> Result<OwnershipRow, StoreError> {
    let on_behalf_of = col::<Option<String>>(row, 9, "on_behalf_of")?
        .map(|s| parse_pid(s, "on_behalf_of"))
        .transpose()?;
    Ok(OwnershipRow::new(
        col::<String>(row, 0, "id")?,
        parse_subject(row)?,
        col::<String>(row, 5, "resource_kind")?,
        col::<String>(row, 6, "resource_id")?,
        col::<String>(row, 7, "relationship")?,
        parse_pid(col::<String>(row, 8, "granted_by")?, "granted_by")?,
        on_behalf_of,
        col::<i64>(row, 10, "granted_at")?,
        col::<Option<i64>>(row, 11, "revoked_at")?,
    )
    .with_lease(TupleLease::from_columns(
        col::<Option<i64>>(row, 12, "lease_iat")?,
        col::<Option<i64>>(row, 13, "lease_refresh_after")?,
        col::<Option<i64>>(row, 14, "lease_exp")?,
    )?))
}

#[async_trait]
impl OwnershipStore for TursoOwnershipStore {
    async fn insert(&self, o: &NewOwnership, now: i64) -> Result<Inserted, StoreError> {
        let id = mint_id();
        let principal = o.subject.principal().map(|p| p.to_string());
        let set = o.subject.as_set();
        let on_behalf_of = o.on_behalf_of.as_ref().map(|p| p.to_string());
        let read = self
            .conn
            .transaction_rows(vec![
                Unit::stmt(
                    "INSERT INTO ownership
                        (id, principal_id, subject_kind, subject_id, subject_relation,
                         resource_kind, resource_id, relationship,
                         granted_by, on_behalf_of, granted_at,
                         lease_iat, lease_refresh_after, lease_exp)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    vec![
                        id.as_str().into(),
                        opt_text(principal.as_deref()),
                        opt_text(set.map(|s| s.0)),
                        opt_text(set.map(|s| s.1)),
                        opt_text(set.map(|s| s.2)),
                        o.resource_kind.as_str().into(),
                        o.resource_id.as_str().into(),
                        o.relationship.as_str().into(),
                        o.granted_by.to_string().into(),
                        opt_text(on_behalf_of.as_deref()),
                        now.into(),
                        opt_int(o.lease.map(|l| l.iat)),
                        opt_int(o.lease.map(|l| l.lease.refresh_after())),
                        opt_int(o.lease.and_then(|l| l.lease.exp())),
                    ],
                ),
                Unit::stmt(ADVANCE_VERSION, vec![now.into()]),
                Unit::query(READ_VERSION, vec![]),
            ])
            .await?;
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
        Ok(Inserted { row, version: version_from(read.first())? })
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

    async fn revoke_by_id(&self, id: &str, now: i64) -> Result<u64, StoreError> {
        // A transaction cannot branch on the UPDATE's row count, so the
        // version advance is conditioned on the row still being live and runs
        // first, while it still is. Re-revoking is then a no-op on both rows
        // — it must not overwrite the original revoked_at, which is why the
        // UPDATE carries `revoked_at IS NULL` in the first place.
        let read = self
            .conn
            .transaction_rows(vec![
                Unit::query("SELECT 1 FROM ownership WHERE id = ?", vec![id.into()]),
                Unit::stmt(
                    "UPDATE ownership_version SET version = MAX(version + 1, ?)
                     WHERE EXISTS (SELECT 1 FROM ownership WHERE id = ? AND revoked_at IS NULL)",
                    vec![now.into(), id.into()],
                ),
                Unit::stmt(
                    "UPDATE ownership SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                    vec![now.into(), id.into()],
                ),
                Unit::query(READ_VERSION, vec![]),
            ])
            .await?;
        if read.first().is_none_or(|rows| rows.is_empty()) {
            return Err(StoreError::NotFound);
        }
        version_from(read.get(1))
    }

    async fn revoke_by_principal(
        &self,
        principal: &PrincipalId,
        now: i64,
    ) -> Result<u64, StoreError> {
        // The cascade primitive: one statement sweeps every live grant this
        // principal holds. As in revoke_by_id, the version advance is
        // conditioned on there being something live and runs first.
        let p = principal.to_string();
        let read = self
            .conn
            .transaction_rows(vec![
                Unit::stmt(
                    "UPDATE ownership_version SET version = MAX(version + 1, ?)
                     WHERE EXISTS (SELECT 1 FROM ownership WHERE principal_id = ? AND revoked_at IS NULL)",
                    vec![now.into(), p.as_str().into()],
                ),
                Unit::stmt(
                    "UPDATE ownership SET revoked_at = ?
                     WHERE principal_id = ? AND revoked_at IS NULL",
                    vec![now.into(), p.as_str().into()],
                ),
                Unit::query(READ_VERSION, vec![]),
            ])
            .await?;
        version_from(read.first())
    }

    async fn list_history_for_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<Vec<OwnershipRow>, StoreError> {
        let rows = self
            .conn
            .query(
                &format!("SELECT {COLUMNS} FROM ownership WHERE principal_id = ?"),
                vec![principal.to_string().into()],
            )
            .await?;
        rows.iter().map(row_to_ownership).collect()
    }

    async fn current_version(&self) -> Result<u64, StoreError> {
        let rows = self.conn.query(READ_VERSION, vec![]).await?;
        version_from(Some(&rows))
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

    async fn list_for_subject_set(
        &self,
        kind: &str,
        id: &str,
    ) -> Result<Vec<OwnershipRow>, StoreError> {
        let rows = self
            .conn
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM ownership
                     WHERE subject_kind = ? AND subject_id = ? AND revoked_at IS NULL"
                ),
                vec![kind.into(), id.into()],
            )
            .await?;
        rows.iter().map(row_to_ownership).collect()
    }

    async fn list_for_kind(&self, resource_kind: &str) -> Result<Vec<OwnershipRow>, StoreError> {
        let rows = self
            .conn
            .query(
                &format!(
                    "SELECT {COLUMNS} FROM ownership
                     WHERE resource_kind = ? AND revoked_at IS NULL"
                ),
                vec![resource_kind.into()],
            )
            .await?;
        rows.iter().map(row_to_ownership).collect()
    }

    async fn revocation_key(&self, kind: &str, id: &str) -> Result<RevocationKey, StoreError> {
        // Insert-or-ignore, then reread: a concurrent creator's row wins and
        // both callers return it (migration 0014).
        let fresh = new_revocation_key();
        self.conn
            .execute(
                "INSERT INTO revocation_keys (resource_kind, resource_id, key) VALUES (?, ?, ?)
                 ON CONFLICT (resource_kind, resource_id) DO NOTHING",
                vec![kind.into(), id.into(), fresh.as_bytes().to_vec().into()],
            )
            .await?;
        let row = self
            .conn
            .query_one(
                "SELECT key FROM revocation_keys WHERE resource_kind = ? AND resource_id = ?",
                vec![kind.into(), id.into()],
            )
            .await?
            .ok_or_else(|| StoreError::Backend(format!("revocation key for {kind}/{id} vanished")))?;
        let bytes: [u8; 32] = col::<Vec<u8>>(&row, 0, "key")?
            .try_into()
            .map_err(|_| StoreError::Backend(format!("revocation key for {kind}/{id} is not 32 bytes")))?;
        Ok(RevocationKey::from_bytes(bytes))
    }

    async fn admission_policy(&self, kind: &str, id: &str) -> Result<Option<AdmissionPolicy>, StoreError> {
        let row = self
            .conn
            .query_one(
                "SELECT policy FROM admission_policies WHERE resource_kind = ? AND resource_id = ?",
                vec![kind.into(), id.into()],
            )
            .await?;
        row.map(|r| decode_admission_policy(kind, id, &col::<String>(&r, 0, "policy")?)).transpose()
    }

    async fn set_admission_policy(
        &self,
        kind: &str,
        id: &str,
        policy: Option<&AdmissionPolicy>,
        now: i64,
    ) -> Result<u64, StoreError> {
        let write = match policy {
            Some(p) => Unit::stmt(
                "INSERT INTO admission_policies (resource_kind, resource_id, policy) VALUES (?, ?, ?)
                 ON CONFLICT (resource_kind, resource_id) DO UPDATE SET policy = excluded.policy",
                vec![kind.into(), id.into(), encode_admission_policy(p).into()],
            ),
            None => Unit::stmt(
                "DELETE FROM admission_policies WHERE resource_kind = ? AND resource_id = ?",
                vec![kind.into(), id.into()],
            ),
        };
        let read = self
            .conn
            .transaction_rows(vec![write, Unit::stmt(ADVANCE_VERSION, vec![now.into()]), Unit::query(READ_VERSION, vec![])])
            .await?;
        version_from(read.first())
    }
}
