//! [`ServicePrincipalStore`] over the in-process engine.
//!
//! Two tables — `service_principals` (one row per `svc:<id>`) and
//! `service_principal_keys` (one Active plus zero or more Retiring rows per
//! principal during a rotation window).

use std::sync::Arc;

use async_trait::async_trait;
use cheers_core::{Principal, PrincipalId, PrincipalKind, PrincipalStatus, StoreError};
use cheers_server::{ServicePrincipalStore, SigningKey, SigningKeyStatus};

use crate::conn::TursoConn;
use crate::util::{col, opt_int};

/// The signing-key column list, in the order [`row_to_signing_key`] expects.
const KEY_COLUMNS: &str = "kid, principal_id, public_key, status, created_at, retire_at";

fn pstatus_to_str(s: PrincipalStatus) -> Result<&'static str, StoreError> {
    match s {
        PrincipalStatus::Active => Ok("active"),
        PrincipalStatus::Revoked => Ok("revoked"),
        // PrincipalStatus is #[non_exhaustive]; a variant this build doesn't
        // know must not be flattened into one it does. The column has a CHECK
        // over the vocabulary anyway, but failing here names the real cause.
        other => Err(StoreError::Backend(format!(
            "cheers-turso cannot serialize unknown PrincipalStatus {other:?}; \
             this version was compiled against an older cheers-core."
        ))),
    }
}

fn pstatus_from_str(s: &str) -> Result<PrincipalStatus, StoreError> {
    match s {
        "active" => Ok(PrincipalStatus::Active),
        "revoked" => Ok(PrincipalStatus::Revoked),
        other => Err(StoreError::Backend(format!(
            "invalid principal status '{other}'"
        ))),
    }
}

fn kstatus_to_str(s: SigningKeyStatus) -> Result<&'static str, StoreError> {
    match s {
        SigningKeyStatus::Active => Ok("active"),
        SigningKeyStatus::Retiring => Ok("retiring"),
        other => Err(StoreError::Backend(format!(
            "cheers-turso cannot serialize unknown SigningKeyStatus {other:?}; \
             this version was compiled against an older cheers-server."
        ))),
    }
}

fn kstatus_from_str(s: &str) -> Result<SigningKeyStatus, StoreError> {
    match s {
        "active" => Ok(SigningKeyStatus::Active),
        "retiring" => Ok(SigningKeyStatus::Retiring),
        other => Err(StoreError::Backend(format!(
            "invalid signing-key status '{other}'"
        ))),
    }
}

fn parse_pid(s: String) -> Result<PrincipalId, StoreError> {
    s.parse::<PrincipalId>()
        .map_err(|e| StoreError::Backend(format!("invalid principal_id in row: {e}")))
}

/// [`ServicePrincipalStore`] backed by an in-process Turso database.
pub struct TursoServicePrincipalStore {
    conn: Arc<TursoConn>,
}

impl TursoServicePrincipalStore {
    pub fn new(conn: Arc<TursoConn>) -> Self {
        Self { conn }
    }

    pub fn conn(&self) -> &Arc<TursoConn> {
        &self.conn
    }
}

impl std::fmt::Debug for TursoServicePrincipalStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TursoServicePrincipalStore")
            .finish_non_exhaustive()
    }
}

fn row_to_principal(row: &turso::Row) -> Result<Principal, StoreError> {
    let id = parse_pid(col::<String>(row, 0, "id")?)?;
    let status = pstatus_from_str(&col::<String>(row, 1, "status")?)?;
    let created_at = col::<i64>(row, 2, "created_at")?;
    // Service principals always have bound_to = None; `try_new` enforces it.
    Principal::try_new(id, None, status, created_at)
        .map_err(|e| StoreError::Backend(format!("invalid principal row: {e}")))
}

fn row_to_signing_key(row: &turso::Row) -> Result<SigningKey, StoreError> {
    // The column is a 32-byte BLOB; decoding straight into `[u8; 32]` makes a
    // wrong-length key a typed failure here rather than a panic downstream.
    let public_key = col::<[u8; 32]>(row, 2, "public_key")?;
    Ok(SigningKey::new(
        col::<String>(row, 0, "kid")?,
        parse_pid(col::<String>(row, 1, "principal_id")?)?,
        public_key,
        kstatus_from_str(&col::<String>(row, 3, "status")?)?,
        col::<i64>(row, 4, "created_at")?,
        col::<Option<i64>>(row, 5, "retire_at")?,
    ))
}

#[async_trait]
impl ServicePrincipalStore for TursoServicePrincipalStore {
    async fn insert_principal(&self, principal: &Principal) -> Result<(), StoreError> {
        if principal.id.kind != PrincipalKind::Service {
            return Err(StoreError::Backend(format!(
                "service-principal store rejects kind={}",
                principal.id.kind
            )));
        }
        self.conn
            .execute(
                "INSERT INTO service_principals (id, status, created_at) VALUES (?, ?, ?)",
                vec![
                    principal.id.to_string().into(),
                    pstatus_to_str(principal.status)?.into(),
                    principal.created_at.into(),
                ],
            )
            .await?;
        Ok(())
    }

    async fn get_principal(&self, id: &PrincipalId) -> Result<Option<Principal>, StoreError> {
        let row = self
            .conn
            .query_one(
                "SELECT id, status, created_at FROM service_principals WHERE id = ?",
                vec![id.to_string().into()],
            )
            .await?;
        row.as_ref().map(row_to_principal).transpose()
    }

    async fn insert_signing_key(&self, key: &SigningKey) -> Result<(), StoreError> {
        self.conn
            .execute(
                "INSERT INTO service_principal_keys
                    (kid, principal_id, public_key, status, created_at, retire_at)
                 VALUES (?, ?, ?, ?, ?, ?)",
                vec![
                    key.kid.as_str().into(),
                    key.principal_id.to_string().into(),
                    // Raw bytes, not base64 — only the JWKS wire shape encodes.
                    key.public_key.to_vec().into(),
                    kstatus_to_str(key.status)?.into(),
                    key.created_at.into(),
                    opt_int(key.retire_at),
                ],
            )
            .await?;
        Ok(())
    }

    async fn list_signing_keys(
        &self,
        principal: &PrincipalId,
    ) -> Result<Vec<SigningKey>, StoreError> {
        let rows = self
            .conn
            .query(
                &format!("SELECT {KEY_COLUMNS} FROM service_principal_keys WHERE principal_id = ?"),
                vec![principal.to_string().into()],
            )
            .await?;
        rows.iter().map(row_to_signing_key).collect()
    }

    async fn list_all_signing_keys(&self) -> Result<Vec<SigningKey>, StoreError> {
        let rows = self
            .conn
            .query(
                &format!("SELECT {KEY_COLUMNS} FROM service_principal_keys"),
                vec![],
            )
            .await?;
        rows.iter().map(row_to_signing_key).collect()
    }

    async fn retire_signing_key(&self, kid: &str, retire_at: i64) -> Result<(), StoreError> {
        // Single statement: flip to 'retiring' and set the window. Idempotent —
        // re-retiring an already-retiring key just resets the window.
        let affected = self
            .conn
            .execute(
                "UPDATE service_principal_keys SET status = 'retiring', retire_at = ? WHERE kid = ?",
                vec![retire_at.into(), kid.into()],
            )
            .await?;
        if affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn prune_retired_keys(&self, now: i64) -> Result<u64, StoreError> {
        // One atomic DELETE: idempotent (a second call with the same `now`
        // matches nothing) and it yields the count without a second query.
        self.conn
            .execute(
                "DELETE FROM service_principal_keys
                  WHERE status = 'retiring' AND retire_at <= ?",
                vec![now.into()],
            )
            .await
    }
}
