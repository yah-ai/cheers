//! [`ServicePrincipalStore`](cheers_server::ServicePrincipalStore) over `sqlx`.
//!
//! Two tables — `service_principals` (one row per `svc:<id>`) and
//! `service_principal_keys` (one Active + zero or more Retiring rows per
//! principal during a rotation window). See
//! `migrations/{pg,sqlite}/0003_service_principals.sql` for the schema and
//! `cheers_server::service_principal` for the authority that drives it.

use async_trait::async_trait;
use cheers_core::{
    Principal, PrincipalId, PrincipalKind, PrincipalStatus, StoreError,
};
use cheers_server::{ServicePrincipalStore, SigningKey, SigningKeyStatus};

use crate::error::map_sqlx_error;

#[cfg(feature = "pg")]
pub use pg::PgServicePrincipalStore;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteServicePrincipalStore;

fn pstatus_to_str(s: PrincipalStatus) -> Result<&'static str, StoreError> {
    match s {
        PrincipalStatus::Active => Ok("active"),
        PrincipalStatus::Revoked => Ok("revoked"),
        other => Err(StoreError::Backend(format!(
            "cheers-sqlx cannot serialize unknown PrincipalStatus {other:?}; \
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
            "cheers-sqlx cannot serialize unknown SigningKeyStatus {other:?}; \
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

fn parse_public_key(bytes: Vec<u8>) -> Result<[u8; 32], StoreError> {
    bytes.try_into().map_err(|v: Vec<u8>| {
        StoreError::Backend(format!(
            "expected 32-byte public_key, got {} bytes",
            v.len()
        ))
    })
}

fn principal_from_parts(
    id: PrincipalId,
    status: PrincipalStatus,
    created_at: i64,
) -> Result<Principal, StoreError> {
    // Service principals always have bound_to=None; Principal::try_new
    // enforces it. A row whose id is not svc:* (CHECK would have caught it on
    // write) parses as the wrong kind here and surfaces as Backend.
    Principal::try_new(id, None, status, created_at)
        .map_err(|e| StoreError::Backend(format!("invalid principal row: {e}")))
}

#[cfg(feature = "pg")]
mod pg {
    use super::*;
    use sqlx::{PgPool, Row};

    /// [`ServicePrincipalStore`] over Postgres.
    pub struct PgServicePrincipalStore {
        pool: PgPool,
    }

    impl PgServicePrincipalStore {
        pub fn new(pool: PgPool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &PgPool {
            &self.pool
        }
    }

    impl std::fmt::Debug for PgServicePrincipalStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PgServicePrincipalStore")
                .finish_non_exhaustive()
        }
    }

    fn row_to_principal(row: sqlx::postgres::PgRow) -> Result<Principal, StoreError> {
        let id = parse_pid(row.get("id"))?;
        let status = pstatus_from_str(row.get::<String, _>("status").as_str())?;
        let created_at: i64 = row.get("created_at");
        principal_from_parts(id, status, created_at)
    }

    fn row_to_signing_key(row: sqlx::postgres::PgRow) -> Result<SigningKey, StoreError> {
        let public_key = parse_public_key(row.get::<Vec<u8>, _>("public_key"))?;
        Ok(SigningKey::new(
            row.get::<String, _>("kid"),
            parse_pid(row.get("principal_id"))?,
            public_key,
            kstatus_from_str(row.get::<String, _>("status").as_str())?,
            row.get("created_at"),
            row.get("retire_at"),
        ))
    }

    #[async_trait]
    impl ServicePrincipalStore for PgServicePrincipalStore {
        async fn insert_principal(&self, principal: &Principal) -> Result<(), StoreError> {
            if principal.id.kind != PrincipalKind::Service {
                return Err(StoreError::Backend(format!(
                    "service-principal store rejects kind={}",
                    principal.id.kind
                )));
            }
            sqlx::query(
                "INSERT INTO service_principals (id, status, created_at)
                 VALUES ($1, $2, $3)",
            )
            .bind(principal.id.to_string())
            .bind(pstatus_to_str(principal.status)?)
            .bind(principal.created_at)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(())
        }

        async fn get_principal(
            &self,
            id: &PrincipalId,
        ) -> Result<Option<Principal>, StoreError> {
            let row = sqlx::query(
                "SELECT id, status, created_at FROM service_principals WHERE id = $1",
            )
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            row.map(row_to_principal).transpose()
        }

        async fn insert_signing_key(&self, key: &SigningKey) -> Result<(), StoreError> {
            sqlx::query(
                "INSERT INTO service_principal_keys
                    (kid, principal_id, public_key, status, created_at, retire_at)
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(&key.kid)
            .bind(key.principal_id.to_string())
            .bind(key.public_key.as_slice())
            .bind(kstatus_to_str(key.status)?)
            .bind(key.created_at)
            .bind(key.retire_at)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(())
        }

        async fn list_signing_keys(
            &self,
            principal: &PrincipalId,
        ) -> Result<Vec<SigningKey>, StoreError> {
            let rows = sqlx::query(
                "SELECT kid, principal_id, public_key, status, created_at, retire_at
                 FROM service_principal_keys WHERE principal_id = $1",
            )
            .bind(principal.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            rows.into_iter().map(row_to_signing_key).collect()
        }

        async fn list_all_signing_keys(&self) -> Result<Vec<SigningKey>, StoreError> {
            let rows = sqlx::query(
                "SELECT kid, principal_id, public_key, status, created_at, retire_at
                 FROM service_principal_keys",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            rows.into_iter().map(row_to_signing_key).collect()
        }

        async fn retire_signing_key(
            &self,
            kid: &str,
            retire_at: i64,
        ) -> Result<(), StoreError> {
            // Single statement: flip to 'retiring' and overwrite retire_at.
            // Idempotent — re-retiring an already-retiring key just resets the
            // window, matching the in-memory impl and the trait doc.
            let res = sqlx::query(
                "UPDATE service_principal_keys
                    SET status = 'retiring', retire_at = $1
                  WHERE kid = $2",
            )
            .bind(retire_at)
            .bind(kid)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            if res.rows_affected() == 0 {
                return Err(StoreError::NotFound);
            }
            Ok(())
        }

        async fn prune_retired_keys(&self, now: i64) -> Result<u64, StoreError> {
            // Single atomic DELETE — idempotent (second call with the same
            // `now` matches no rows) and gives the count without a separate
            // count query.
            let res = sqlx::query(
                "DELETE FROM service_principal_keys
                  WHERE status = 'retiring' AND retire_at <= $1",
            )
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(res.rows_affected())
        }
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use sqlx::{Row, SqlitePool};

    /// [`ServicePrincipalStore`] over SQLite.
    pub struct SqliteServicePrincipalStore {
        pool: SqlitePool,
    }

    impl SqliteServicePrincipalStore {
        pub fn new(pool: SqlitePool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &SqlitePool {
            &self.pool
        }
    }

    impl std::fmt::Debug for SqliteServicePrincipalStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SqliteServicePrincipalStore")
                .finish_non_exhaustive()
        }
    }

    fn row_to_principal(row: sqlx::sqlite::SqliteRow) -> Result<Principal, StoreError> {
        let id = parse_pid(row.get("id"))?;
        let status = pstatus_from_str(row.get::<String, _>("status").as_str())?;
        let created_at: i64 = row.get("created_at");
        principal_from_parts(id, status, created_at)
    }

    fn row_to_signing_key(row: sqlx::sqlite::SqliteRow) -> Result<SigningKey, StoreError> {
        let public_key = parse_public_key(row.get::<Vec<u8>, _>("public_key"))?;
        Ok(SigningKey::new(
            row.get::<String, _>("kid"),
            parse_pid(row.get("principal_id"))?,
            public_key,
            kstatus_from_str(row.get::<String, _>("status").as_str())?,
            row.get("created_at"),
            row.get("retire_at"),
        ))
    }

    #[async_trait]
    impl ServicePrincipalStore for SqliteServicePrincipalStore {
        async fn insert_principal(&self, principal: &Principal) -> Result<(), StoreError> {
            if principal.id.kind != PrincipalKind::Service {
                return Err(StoreError::Backend(format!(
                    "service-principal store rejects kind={}",
                    principal.id.kind
                )));
            }
            sqlx::query(
                "INSERT INTO service_principals (id, status, created_at)
                 VALUES (?, ?, ?)",
            )
            .bind(principal.id.to_string())
            .bind(pstatus_to_str(principal.status)?)
            .bind(principal.created_at)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(())
        }

        async fn get_principal(
            &self,
            id: &PrincipalId,
        ) -> Result<Option<Principal>, StoreError> {
            let row = sqlx::query(
                "SELECT id, status, created_at FROM service_principals WHERE id = ?",
            )
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            row.map(row_to_principal).transpose()
        }

        async fn insert_signing_key(&self, key: &SigningKey) -> Result<(), StoreError> {
            sqlx::query(
                "INSERT INTO service_principal_keys
                    (kid, principal_id, public_key, status, created_at, retire_at)
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(&key.kid)
            .bind(key.principal_id.to_string())
            .bind(key.public_key.as_slice())
            .bind(kstatus_to_str(key.status)?)
            .bind(key.created_at)
            .bind(key.retire_at)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(())
        }

        async fn list_signing_keys(
            &self,
            principal: &PrincipalId,
        ) -> Result<Vec<SigningKey>, StoreError> {
            let rows = sqlx::query(
                "SELECT kid, principal_id, public_key, status, created_at, retire_at
                 FROM service_principal_keys WHERE principal_id = ?",
            )
            .bind(principal.to_string())
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            rows.into_iter().map(row_to_signing_key).collect()
        }

        async fn list_all_signing_keys(&self) -> Result<Vec<SigningKey>, StoreError> {
            let rows = sqlx::query(
                "SELECT kid, principal_id, public_key, status, created_at, retire_at
                 FROM service_principal_keys",
            )
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            rows.into_iter().map(row_to_signing_key).collect()
        }

        async fn retire_signing_key(
            &self,
            kid: &str,
            retire_at: i64,
        ) -> Result<(), StoreError> {
            let res = sqlx::query(
                "UPDATE service_principal_keys
                    SET status = 'retiring', retire_at = ?
                  WHERE kid = ?",
            )
            .bind(retire_at)
            .bind(kid)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            if res.rows_affected() == 0 {
                return Err(StoreError::NotFound);
            }
            Ok(())
        }

        async fn prune_retired_keys(&self, now: i64) -> Result<u64, StoreError> {
            let res = sqlx::query(
                "DELETE FROM service_principal_keys
                  WHERE status = 'retiring' AND retire_at <= ?",
            )
            .bind(now)
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(res.rows_affected())
        }
    }
}
