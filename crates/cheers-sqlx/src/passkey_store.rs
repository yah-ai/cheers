//! [`PasskeyCredentialStore`](cheers_server::PasskeyCredentialStore) over `sqlx`.
//!
//! The trait sits on `cheers-core`'s [`Credential`], so this impl never names
//! `webauthn-rs::Passkey` — products call
//! `cheers::passkey::passkey_to_credential` to turn a finished registration
//! into a row.
//!
//! Schema layout: `(user_id, device_id)` PK, with `material` holding the
//! serde_json'd `Passkey` blob (`JSONB` on pg, `TEXT` on sqlite). Decoded
//! back into [`Credential::material`] as bytes — the original byte sequence
//! is preserved (it's the JSON encoding of the Passkey, so the JSON column
//! stores it natively + retrievable as a UTF-8 byte string).

use async_trait::async_trait;
use cheers_core::{Credential, DeviceBinding, DeviceId, StoreError, UserId};
use cheers_server::store::PasskeyCredentialStore;

use crate::error::map_sqlx_error;

#[cfg(feature = "pg")]
pub use pg::PgPasskeyCredentialStore;
#[cfg(feature = "sqlite")]
pub use sqlite::SqlitePasskeyCredentialStore;

/// Decode `Credential::material` (the raw JSON bytes of a `Passkey`) into a
/// `serde_json::Value` so we can store it as a real JSON column on pg /
/// validate-on-write on sqlite. Failure here means the caller didn't pass us
/// a passkey credential; surface a typed error rather than letting the SQL
/// driver reject the bind.
fn decode_material(material: &[u8]) -> Result<serde_json::Value, StoreError> {
    serde_json::from_slice(material).map_err(|e| {
        StoreError::Backend(format!(
            "passkey material is not valid JSON (expected a serde_json'd webauthn-rs Passkey): {e}"
        ))
    })
}

/// Ensure the caller isn't accidentally `put`-ing an OAuth/email credential
/// into the passkey table. The trait docs spell this out but a runtime check
/// keeps the misuse from corrupting the table.
fn require_passkey_binding(binding: &DeviceBinding) -> Result<(), StoreError> {
    match binding {
        DeviceBinding::Passkey => Ok(()),
        other => Err(StoreError::Backend(format!(
            "PasskeyCredentialStore only stores DeviceBinding::Passkey credentials; got {other:?}"
        ))),
    }
}

fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(feature = "pg")]
mod pg {
    use super::*;
    use sqlx::{PgPool, Row};

    pub struct PgPasskeyCredentialStore {
        pool: PgPool,
    }

    impl PgPasskeyCredentialStore {
        pub fn new(pool: PgPool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &PgPool {
            &self.pool
        }
    }

    impl std::fmt::Debug for PgPasskeyCredentialStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PgPasskeyCredentialStore")
                .finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl PasskeyCredentialStore for PgPasskeyCredentialStore {
        async fn put(&self, cred: &Credential) -> Result<(), StoreError> {
            require_passkey_binding(&cred.binding)?;
            let material = decode_material(&cred.material)?;
            sqlx::query(
                "INSERT INTO passkey_credentials (user_id, device_id, material, created_at)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(cred.user_id.as_str())
            .bind(cred.device_id.as_str())
            .bind(sqlx::types::Json(material))
            .bind(now())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(())
        }

        async fn list_for_user(&self, user_id: &UserId) -> Result<Vec<Credential>, StoreError> {
            let rows = sqlx::query(
                "SELECT device_id, material FROM passkey_credentials WHERE user_id = $1",
            )
            .bind(user_id.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                let device_id: String = row.get("device_id");
                let material: sqlx::types::Json<serde_json::Value> = row.get("material");
                let bytes = serde_json::to_vec(&material.0).map_err(|e| {
                    StoreError::Backend(format!("re-encoding stored passkey material: {e}"))
                })?;
                out.push(Credential::new(
                    user_id.clone(),
                    DeviceId::new(device_id),
                    DeviceBinding::Passkey,
                    bytes,
                ));
            }
            Ok(out)
        }

        async fn delete(
            &self,
            user_id: &UserId,
            device_id: &DeviceId,
        ) -> Result<(), StoreError> {
            let res = sqlx::query(
                "DELETE FROM passkey_credentials WHERE user_id = $1 AND device_id = $2",
            )
            .bind(user_id.as_str())
            .bind(device_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            if res.rows_affected() == 0 {
                return Err(StoreError::NotFound);
            }
            Ok(())
        }

        async fn update(&self, cred: &Credential) -> Result<(), StoreError> {
            require_passkey_binding(&cred.binding)?;
            let material = decode_material(&cred.material)?;
            let res = sqlx::query(
                "UPDATE passkey_credentials SET material = $1
                 WHERE user_id = $2 AND device_id = $3",
            )
            .bind(sqlx::types::Json(material))
            .bind(cred.user_id.as_str())
            .bind(cred.device_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            if res.rows_affected() == 0 {
                return Err(StoreError::NotFound);
            }
            Ok(())
        }
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use sqlx::{Row, SqlitePool};

    pub struct SqlitePasskeyCredentialStore {
        pool: SqlitePool,
    }

    impl SqlitePasskeyCredentialStore {
        pub fn new(pool: SqlitePool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &SqlitePool {
            &self.pool
        }
    }

    impl std::fmt::Debug for SqlitePasskeyCredentialStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SqlitePasskeyCredentialStore")
                .finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl PasskeyCredentialStore for SqlitePasskeyCredentialStore {
        async fn put(&self, cred: &Credential) -> Result<(), StoreError> {
            require_passkey_binding(&cred.binding)?;
            // Validate the material parses as JSON, but write the canonical
            // bytes (sqlite stores TEXT, not native JSON). Round-trip safe.
            let material = decode_material(&cred.material)?;
            let serialized = serde_json::to_string(&material).map_err(|e| {
                StoreError::Backend(format!("re-encoding passkey material: {e}"))
            })?;
            sqlx::query(
                "INSERT INTO passkey_credentials (user_id, device_id, material, created_at)
                 VALUES (?, ?, ?, ?)",
            )
            .bind(cred.user_id.as_str())
            .bind(cred.device_id.as_str())
            .bind(serialized)
            .bind(now())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            Ok(())
        }

        async fn list_for_user(&self, user_id: &UserId) -> Result<Vec<Credential>, StoreError> {
            let rows = sqlx::query(
                "SELECT device_id, material FROM passkey_credentials WHERE user_id = ?",
            )
            .bind(user_id.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

            let mut out = Vec::with_capacity(rows.len());
            for row in rows {
                let device_id: String = row.get("device_id");
                let material: String = row.get("material");
                out.push(Credential::new(
                    user_id.clone(),
                    DeviceId::new(device_id),
                    DeviceBinding::Passkey,
                    material.into_bytes(),
                ));
            }
            Ok(out)
        }

        async fn delete(
            &self,
            user_id: &UserId,
            device_id: &DeviceId,
        ) -> Result<(), StoreError> {
            let res = sqlx::query(
                "DELETE FROM passkey_credentials WHERE user_id = ? AND device_id = ?",
            )
            .bind(user_id.as_str())
            .bind(device_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            if res.rows_affected() == 0 {
                return Err(StoreError::NotFound);
            }
            Ok(())
        }

        async fn update(&self, cred: &Credential) -> Result<(), StoreError> {
            require_passkey_binding(&cred.binding)?;
            let material = decode_material(&cred.material)?;
            let serialized = serde_json::to_string(&material).map_err(|e| {
                StoreError::Backend(format!("re-encoding passkey material: {e}"))
            })?;
            let res = sqlx::query(
                "UPDATE passkey_credentials SET material = ?
                 WHERE user_id = ? AND device_id = ?",
            )
            .bind(serialized)
            .bind(cred.user_id.as_str())
            .bind(cred.device_id.as_str())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            if res.rows_affected() == 0 {
                return Err(StoreError::NotFound);
            }
            Ok(())
        }
    }
}
