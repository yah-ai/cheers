//! [`PasskeyCredentialStore`] over the in-process engine.
//!
//! The trait sits on `cheers-core`'s [`Credential`], so this impl never names
//! `webauthn-rs::Passkey` — products bridge with
//! `cheers::passkey::passkey_to_credential`.
//!
//! Layout: `(user_id, device_id)` primary key, with `material` holding the
//! `serde_json`'d `Passkey` blob as TEXT.

use std::sync::Arc;

use async_trait::async_trait;
use cheers_core::{Credential, DeviceBinding, DeviceId, StoreError, UserId};
use cheers_server::store::PasskeyCredentialStore;

use crate::conn::TursoConn;
use crate::util::{col, now};

/// Validate that the material really is the JSON a passkey credential carries.
///
/// The column is TEXT, so the engine would accept any bytes. Parsing on the
/// way in means a caller that hands us an OAuth blob fails at the write with a
/// typed error, instead of at some later read with a deserialization panic in
/// the authentication path.
fn canonical_material(material: &[u8]) -> Result<String, StoreError> {
    let value: serde_json::Value = serde_json::from_slice(material).map_err(|e| {
        StoreError::Backend(format!(
            "passkey material is not valid JSON (expected a serde_json'd webauthn-rs Passkey): {e}"
        ))
    })?;
    serde_json::to_string(&value)
        .map_err(|e| StoreError::Backend(format!("re-encoding passkey material: {e}")))
}

/// Keep non-passkey credentials out of the passkey table. The trait docs say
/// so; a runtime check means a misuse fails loudly rather than corrupting the
/// table for every later `list_for_user`.
fn require_passkey_binding(binding: &DeviceBinding) -> Result<(), StoreError> {
    match binding {
        DeviceBinding::Passkey => Ok(()),
        other => Err(StoreError::Backend(format!(
            "PasskeyCredentialStore only stores DeviceBinding::Passkey credentials; got {other:?}"
        ))),
    }
}

/// [`PasskeyCredentialStore`] backed by an in-process Turso database.
pub struct TursoPasskeyCredentialStore {
    conn: Arc<TursoConn>,
}

impl TursoPasskeyCredentialStore {
    pub fn new(conn: Arc<TursoConn>) -> Self {
        Self { conn }
    }

    pub fn conn(&self) -> &Arc<TursoConn> {
        &self.conn
    }
}

impl std::fmt::Debug for TursoPasskeyCredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TursoPasskeyCredentialStore")
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl PasskeyCredentialStore for TursoPasskeyCredentialStore {
    async fn put(&self, cred: &Credential) -> Result<(), StoreError> {
        require_passkey_binding(&cred.binding)?;
        let material = canonical_material(&cred.material)?;
        self.conn
            .execute(
                "INSERT INTO passkey_credentials (user_id, device_id, material, created_at)
                 VALUES (?, ?, ?, ?)",
                vec![
                    cred.user_id.as_str().into(),
                    cred.device_id.as_str().into(),
                    material.into(),
                    now().into(),
                ],
            )
            .await?;
        Ok(())
    }

    async fn list_for_user(&self, user_id: &UserId) -> Result<Vec<Credential>, StoreError> {
        let rows = self
            .conn
            .query(
                "SELECT device_id, material FROM passkey_credentials WHERE user_id = ?",
                vec![user_id.as_str().into()],
            )
            .await?;

        rows.iter()
            .map(|row| {
                Ok(Credential::new(
                    user_id.clone(),
                    DeviceId::new(col::<String>(row, 0, "device_id")?),
                    DeviceBinding::Passkey,
                    col::<String>(row, 1, "material")?.into_bytes(),
                ))
            })
            .collect()
    }

    async fn delete(&self, user_id: &UserId, device_id: &DeviceId) -> Result<(), StoreError> {
        let affected = self
            .conn
            .execute(
                "DELETE FROM passkey_credentials WHERE user_id = ? AND device_id = ?",
                vec![user_id.as_str().into(), device_id.as_str().into()],
            )
            .await?;
        if affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    async fn update(&self, cred: &Credential) -> Result<(), StoreError> {
        require_passkey_binding(&cred.binding)?;
        let material = canonical_material(&cred.material)?;
        let affected = self
            .conn
            .execute(
                "UPDATE passkey_credentials SET material = ?
                 WHERE user_id = ? AND device_id = ?",
                vec![
                    material.into(),
                    cred.user_id.as_str().into(),
                    cred.device_id.as_str().into(),
                ],
            )
            .await?;
        if affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}
