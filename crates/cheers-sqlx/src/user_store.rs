//! [`UserStore`](cheers_server::UserStore) over `sqlx`.
//!
//! Pg and SQLite both available behind their respective features. The two
//! impls share an SQL contract (column names, ordering, error mapping); the
//! one place they diverge is `find_by_provider`, which casts `issuer` to TEXT
//! differently in each dialect — handled with separate but parallel functions.

use async_trait::async_trait;
use cheers_core::{DeviceId, StoreError, User, UserId};
use cheers_server::store::{NewUser, ProviderKey, UserStore};

use crate::error::map_sqlx_error;

/// Serialize a [`ProviderKey`] into the `(provider, issuer)` pair the schema
/// stores. Non-generic providers use empty-string issuer so the composite PK
/// is honored.
fn provider_pair(p: &ProviderKey) -> Result<(&'static str, String), StoreError> {
    match p {
        ProviderKey::OidcGoogle => Ok(("oidc_google", String::new())),
        ProviderKey::OidcApple => Ok(("oidc_apple", String::new())),
        ProviderKey::OidcGeneric { issuer } => Ok(("oidc_generic", issuer.clone())),
        ProviderKey::Email => Ok(("email", String::new())),
        ProviderKey::LanPair => Ok(("lan_pair", String::new())),
        // ProviderKey is #[non_exhaustive]; if cheers-server adds a variant
        // and a deployment hasn't updated cheers-sqlx, refuse to silently
        // store credentials under the wrong namespace.
        _ => Err(StoreError::Backend(format!(
            "cheers-sqlx does not know how to serialize ProviderKey variant {p:?}; \
             this version was compiled against an older cheers-server."
        ))),
    }
}

/// Generate a fresh user id (UUIDv4 as a string, hyphenated). cheers's
/// [`UserId`] is opaque — products can override the shape by writing their
/// own [`UserStore`] impl; this default is what `Pg`/`SqliteUserStore` use
/// when [`create`](UserStore::create) is called.
fn mint_user_id() -> String {
    // Avoid pulling the `uuid` crate as a direct dep — 16 random bytes with
    // the v4 version+variant bits forced, formatted as the canonical
    // 8-4-4-4-12 hex layout. A future migration to the `uuid` crate parses
    // these rows directly.
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

/// Current unix-seconds clock, used by [`UserStore::create`] /
/// [`UserStore::link_provider`] for the `created_at` / `linked_at` columns.
fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Postgres impl
// ---------------------------------------------------------------------------

#[cfg(feature = "pg")]
pub use pg::PgUserStore;

#[cfg(feature = "pg")]
mod pg {
    use super::*;
    use sqlx::{PgPool, Row};

    /// [`UserStore`] backed by a `sqlx` Postgres connection pool.
    pub struct PgUserStore {
        pool: PgPool,
    }

    impl PgUserStore {
        pub fn new(pool: PgPool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &PgPool {
            &self.pool
        }
    }

    impl std::fmt::Debug for PgUserStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("PgUserStore").finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl UserStore for PgUserStore {
        async fn find_by_provider(
            &self,
            provider: &ProviderKey,
            subject: &str,
        ) -> Result<Option<User>, StoreError> {
            let (provider_str, issuer) = provider_pair(provider)?;
            let row = sqlx::query(
                "SELECT users.user_id, users.email, users.name
                 FROM users
                 JOIN oauth_identities
                     ON oauth_identities.user_id = users.user_id
                 WHERE oauth_identities.provider = $1
                     AND oauth_identities.issuer = $2
                     AND oauth_identities.subject = $3",
            )
            .bind(provider_str)
            .bind(issuer)
            .bind(subject)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

            Ok(row.map(|row| {
                let user_id: String = row.get("user_id");
                let email: Option<String> = row.get("email");
                let name: Option<String> = row.get("name");
                let mut user = User::new(UserId::new(user_id));
                user.email = email;
                user.name = name;
                user
            }))
        }

        async fn create(&self, new_user: NewUser) -> Result<User, StoreError> {
            let user_id = mint_user_id();
            sqlx::query(
                "INSERT INTO users (user_id, email, name, created_at)
                 VALUES ($1, $2, $3, $4)",
            )
            .bind(&user_id)
            .bind(new_user.email.as_deref())
            .bind(new_user.name.as_deref())
            .bind(now())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

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
            // Idempotent insert: on conflict, succeed only if the existing row
            // already points at the same user_id; else surface Conflict.
            let res = sqlx::query(
                "INSERT INTO oauth_identities (provider, issuer, subject, user_id, linked_at)
                 VALUES ($1, $2, $3, $4, $5)
                 ON CONFLICT (provider, issuer, subject) DO NOTHING",
            )
            .bind(provider_str)
            .bind(&issuer)
            .bind(subject)
            .bind(user_id.as_str())
            .bind(now())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

            if res.rows_affected() == 1 {
                return Ok(());
            }
            // No insert — either a duplicate link to the same user (Ok) or
            // a link to a different user (Conflict).
            let existing: Option<String> = sqlx::query(
                "SELECT user_id FROM oauth_identities
                 WHERE provider = $1 AND issuer = $2 AND subject = $3",
            )
            .bind(provider_str)
            .bind(&issuer)
            .bind(subject)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?
            .map(|row| row.get("user_id"));

            match existing.as_deref() {
                Some(s) if s == user_id.as_str() => Ok(()),
                Some(_) => Err(StoreError::Conflict),
                None => Err(StoreError::Backend(
                    "link_provider: insert returned 0 rows but no existing row found".into(),
                )),
            }
        }

        async fn list_devices(&self, user_id: &UserId) -> Result<Vec<DeviceId>, StoreError> {
            // Active devices = distinct device_ids on non-revoked refresh
            // chains. A user with no refresh chains has no active devices.
            let rows = sqlx::query(
                "SELECT DISTINCT device_id
                 FROM refresh_tokens
                 WHERE user_id = $1 AND NOT revoked",
            )
            .bind(user_id.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

            Ok(rows
                .into_iter()
                .map(|row| {
                    let s: String = row.get("device_id");
                    DeviceId::new(s)
                })
                .collect())
        }

        async fn revoke_device(
            &self,
            user_id: &UserId,
            device_id: &DeviceId,
        ) -> Result<(), StoreError> {
            // Records device-level intent by revoking every refresh chain for
            // (user_id, device_id). Composing this with `revoke(jti)` for the
            // current access token is SessionAuthority's job (Rule per
            // cheers-server::session docs).
            let res = sqlx::query(
                "UPDATE refresh_tokens SET revoked = TRUE
                 WHERE user_id = $1 AND device_id = $2 AND NOT revoked",
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
    }
}

// ---------------------------------------------------------------------------
// SQLite impl
// ---------------------------------------------------------------------------

#[cfg(feature = "sqlite")]
pub use sqlite::SqliteUserStore;

#[cfg(feature = "sqlite")]
mod sqlite {
    use super::*;
    use sqlx::{Row, SqlitePool};

    /// [`UserStore`] backed by a `sqlx` SQLite connection pool.
    pub struct SqliteUserStore {
        pool: SqlitePool,
    }

    impl SqliteUserStore {
        pub fn new(pool: SqlitePool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &SqlitePool {
            &self.pool
        }
    }

    impl std::fmt::Debug for SqliteUserStore {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("SqliteUserStore").finish_non_exhaustive()
        }
    }

    #[async_trait]
    impl UserStore for SqliteUserStore {
        async fn find_by_provider(
            &self,
            provider: &ProviderKey,
            subject: &str,
        ) -> Result<Option<User>, StoreError> {
            let (provider_str, issuer) = provider_pair(provider)?;
            let row = sqlx::query(
                "SELECT users.user_id, users.email, users.name
                 FROM users
                 JOIN oauth_identities
                     ON oauth_identities.user_id = users.user_id
                 WHERE oauth_identities.provider = ?
                     AND oauth_identities.issuer = ?
                     AND oauth_identities.subject = ?",
            )
            .bind(provider_str)
            .bind(issuer)
            .bind(subject)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

            Ok(row.map(|row| {
                let user_id: String = row.get("user_id");
                let email: Option<String> = row.get("email");
                let name: Option<String> = row.get("name");
                let mut user = User::new(UserId::new(user_id));
                user.email = email;
                user.name = name;
                user
            }))
        }

        async fn create(&self, new_user: NewUser) -> Result<User, StoreError> {
            let user_id = mint_user_id();
            sqlx::query(
                "INSERT INTO users (user_id, email, name, created_at)
                 VALUES (?, ?, ?, ?)",
            )
            .bind(&user_id)
            .bind(new_user.email.as_deref())
            .bind(new_user.name.as_deref())
            .bind(now())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

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
            let res = sqlx::query(
                "INSERT INTO oauth_identities (provider, issuer, subject, user_id, linked_at)
                 VALUES (?, ?, ?, ?, ?)
                 ON CONFLICT (provider, issuer, subject) DO NOTHING",
            )
            .bind(provider_str)
            .bind(&issuer)
            .bind(subject)
            .bind(user_id.as_str())
            .bind(now())
            .execute(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

            if res.rows_affected() == 1 {
                return Ok(());
            }
            let existing: Option<String> = sqlx::query(
                "SELECT user_id FROM oauth_identities
                 WHERE provider = ? AND issuer = ? AND subject = ?",
            )
            .bind(provider_str)
            .bind(&issuer)
            .bind(subject)
            .fetch_optional(&self.pool)
            .await
            .map_err(map_sqlx_error)?
            .map(|row| row.get("user_id"));

            match existing.as_deref() {
                Some(s) if s == user_id.as_str() => Ok(()),
                Some(_) => Err(StoreError::Conflict),
                None => Err(StoreError::Backend(
                    "link_provider: insert returned 0 rows but no existing row found".into(),
                )),
            }
        }

        async fn list_devices(&self, user_id: &UserId) -> Result<Vec<DeviceId>, StoreError> {
            let rows = sqlx::query(
                "SELECT DISTINCT device_id
                 FROM refresh_tokens
                 WHERE user_id = ? AND revoked = 0",
            )
            .bind(user_id.as_str())
            .fetch_all(&self.pool)
            .await
            .map_err(map_sqlx_error)?;

            Ok(rows
                .into_iter()
                .map(|row| {
                    let s: String = row.get("device_id");
                    DeviceId::new(s)
                })
                .collect())
        }

        async fn revoke_device(
            &self,
            user_id: &UserId,
            device_id: &DeviceId,
        ) -> Result<(), StoreError> {
            let res = sqlx::query(
                "UPDATE refresh_tokens SET revoked = 1
                 WHERE user_id = ? AND device_id = ? AND revoked = 0",
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
    }
}
