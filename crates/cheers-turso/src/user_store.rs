//! [`UserStore`] over the in-process engine.

use std::sync::Arc;

use async_trait::async_trait;
use cheers_core::{DeviceId, StoreError, User, UserId};
use cheers_server::store::{NewUser, ProviderKey, UserStore};

use crate::conn::TursoConn;
use crate::util::{col, mint_id, now, opt_text};

/// Serialize a [`ProviderKey`] into the `(provider, issuer)` pair the schema
/// stores. Non-generic providers use an empty-string issuer so the composite
/// primary key is honored.
///
/// The strings here are the on-disk vocabulary and are shared with
/// `cheers-sqlx` — changing one without the other splits the identity table in
/// two, with the same user reachable under two provider spellings.
fn provider_pair(p: &ProviderKey) -> Result<(&'static str, String), StoreError> {
    match p {
        ProviderKey::OidcGoogle => Ok(("oidc_google", String::new())),
        ProviderKey::OidcApple => Ok(("oidc_apple", String::new())),
        ProviderKey::OidcGeneric { issuer } => Ok(("oidc_generic", issuer.clone())),
        ProviderKey::Email => Ok(("email", String::new())),
        ProviderKey::LanPair => Ok(("lan_pair", String::new())),
        // ProviderKey is #[non_exhaustive]. If cheers-server adds a variant and
        // a deployment hasn't rebuilt this crate, refuse rather than silently
        // filing credentials under the wrong namespace.
        _ => Err(StoreError::Backend(format!(
            "cheers-turso does not know how to serialize ProviderKey variant {p:?}; \
             this version was compiled against an older cheers-server."
        ))),
    }
}

/// [`UserStore`] backed by an in-process Turso database.
pub struct TursoUserStore {
    conn: Arc<TursoConn>,
}

impl TursoUserStore {
    pub fn new(conn: Arc<TursoConn>) -> Self {
        Self { conn }
    }

    pub fn conn(&self) -> &Arc<TursoConn> {
        &self.conn
    }
}

impl std::fmt::Debug for TursoUserStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TursoUserStore").finish_non_exhaustive()
    }
}

#[async_trait]
impl UserStore for TursoUserStore {
    async fn find_by_provider(
        &self,
        provider: &ProviderKey,
        subject: &str,
    ) -> Result<Option<User>, StoreError> {
        let (provider_str, issuer) = provider_pair(provider)?;
        let row = self
            .conn
            .query_one(
                "SELECT users.user_id, users.email, users.name
                 FROM users
                 JOIN oauth_identities
                     ON oauth_identities.user_id = users.user_id
                 WHERE oauth_identities.provider = ?
                     AND oauth_identities.issuer = ?
                     AND oauth_identities.subject = ?",
                vec![provider_str.into(), issuer.into(), subject.into()],
            )
            .await?;

        let Some(row) = row else { return Ok(None) };
        let mut user = User::new(UserId::new(col::<String>(&row, 0, "user_id")?));
        user.email = col::<Option<String>>(&row, 1, "email")?;
        user.name = col::<Option<String>>(&row, 2, "name")?;
        Ok(Some(user))
    }

    async fn create(&self, new_user: NewUser) -> Result<User, StoreError> {
        let user_id = mint_id();
        self.conn
            .execute(
                "INSERT INTO users (user_id, email, name, created_at) VALUES (?, ?, ?, ?)",
                vec![
                    user_id.as_str().into(),
                    opt_text(new_user.email.as_deref()),
                    opt_text(new_user.name.as_deref()),
                    now().into(),
                ],
            )
            .await?;

        let mut user = User::new(UserId::new(user_id));
        user.email = new_user.email;
        user.name = new_user.name;
        Ok(user)
    }

    async fn link_provider(
        &self,
        user_id: &UserId,
        provider: &ProviderKey,
        subject: &str,
    ) -> Result<(), StoreError> {
        let (provider_str, issuer) = provider_pair(provider)?;
        // Idempotent insert. `DO NOTHING` means a duplicate link reports zero
        // rows affected instead of erroring, which lets us tell the two cases
        // apart below without paying for a read on the common path.
        let affected = self
            .conn
            .execute(
                "INSERT INTO oauth_identities (provider, issuer, subject, user_id, linked_at)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT (provider, issuer, subject) DO NOTHING",
                vec![
                    provider_str.into(),
                    issuer.as_str().into(),
                    subject.into(),
                    user_id.as_str().into(),
                    now().into(),
                ],
            )
            .await?;

        if affected == 1 {
            return Ok(());
        }

        // No insert — either a duplicate link to the same user (idempotent
        // success) or a link claimed by a different user (Conflict).
        let existing = self
            .conn
            .query_one(
                "SELECT user_id FROM oauth_identities
                 WHERE provider = ? AND issuer = ? AND subject = ?",
                vec![provider_str.into(), issuer.as_str().into(), subject.into()],
            )
            .await?
            .map(|row| col::<String>(&row, 0, "user_id"))
            .transpose()?;

        match existing.as_deref() {
            Some(s) if s == user_id.as_str() => Ok(()),
            Some(_) => Err(StoreError::Conflict),
            None => Err(StoreError::Backend(
                "link_provider: insert returned 0 rows but no existing row found".into(),
            )),
        }
    }

    async fn list_devices(&self, user_id: &UserId) -> Result<Vec<DeviceId>, StoreError> {
        // Active devices are the distinct device_ids on non-revoked refresh
        // chains; a user with no chains has no active devices.
        let rows = self
            .conn
            .query(
                "SELECT DISTINCT device_id
                 FROM refresh_tokens
                 WHERE user_id = ? AND revoked = 0",
                vec![user_id.as_str().into()],
            )
            .await?;

        rows.iter()
            .map(|row| Ok(DeviceId::new(col::<String>(row, 0, "device_id")?)))
            .collect()
    }

    async fn revoke_device(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> Result<(), StoreError> {
        // Records device-level intent by revoking every live refresh chain for
        // (user_id, device_id). Killing the in-flight access token by its jti
        // is a separate call; composing the two is SessionAuthority's job.
        let affected = self
            .conn
            .execute(
                "UPDATE refresh_tokens SET revoked = 1
                 WHERE user_id = ? AND device_id = ? AND revoked = 0",
                vec![user_id.as_str().into(), device_id.as_str().into()],
            )
            .await?;

        if affected == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }
}
