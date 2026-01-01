//! [`RevocationWriter`](cheers_server::RevocationWriter) +
//! [`RevocationReader`](cheers_verify::RevocationReader) over redis.
//!
//! Key layout: `{prefix}:revoked:{jti}` — value is `revoked_at` (unix
//! seconds). The key carries an `EXPIRE` matching the access-token TTL so the
//! kill list naturally GCs itself. `is_revoked` is a single `EXISTS`.

use async_trait::async_trait;
use cheers_core::StoreError;
use cheers_server::RevocationWriter;
use cheers_verify::RevocationReader;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::DEFAULT_PREFIX;

fn map_redis_err(err: redis::RedisError) -> StoreError {
    StoreError::Backend(err.to_string())
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Default TTL applied to a freshly revoked `jti` (in seconds). Matches
/// [`SessionPolicy::DEFAULT_ACCESS_TTL_SECONDS`](cheers_server::SessionPolicy::DEFAULT_ACCESS_TTL_SECONDS):
/// after this long the token has expired on its own, so the kill-list entry
/// can be dropped.
pub const DEFAULT_REVOKE_TTL_SECONDS: u64 = 15 * 60;

/// Redis-backed revocation set. Implements both
/// [`RevocationWriter`] (origin) and [`RevocationReader`] (edge).
#[derive(Clone)]
pub struct RedisRevocationStore {
    conn: ConnectionManager,
    prefix: String,
    revoke_ttl_seconds: u64,
}

impl RedisRevocationStore {
    pub fn new(conn: ConnectionManager) -> Self {
        Self {
            conn,
            prefix: DEFAULT_PREFIX.to_owned(),
            revoke_ttl_seconds: DEFAULT_REVOKE_TTL_SECONDS,
        }
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    /// Override the TTL applied to freshly revoked jtis. Should match the
    /// access-token TTL — shorter risks accepting a revoked token after the
    /// entry expires but before the access token would; longer wastes redis
    /// memory holding entries past the point the access token would expire
    /// on its own.
    pub fn with_revoke_ttl_seconds(mut self, seconds: u64) -> Self {
        self.revoke_ttl_seconds = seconds;
        self
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    pub fn revoke_ttl_seconds(&self) -> u64 {
        self.revoke_ttl_seconds
    }

    fn key(&self, jti: &str) -> String {
        format!("{}:revoked:{jti}", self.prefix)
    }
}

impl std::fmt::Debug for RedisRevocationStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisRevocationStore")
            .field("prefix", &self.prefix)
            .field("revoke_ttl_seconds", &self.revoke_ttl_seconds)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl RevocationWriter for RedisRevocationStore {
    async fn revoke(&self, jti: &str) -> Result<(), StoreError> {
        let mut conn = self.conn.clone();
        // SETEX is idempotent — re-revoking just refreshes the TTL window,
        // which is the correct semantics (the token is still revoked).
        let _: () = conn
            .set_ex(self.key(jti), now_unix(), self.revoke_ttl_seconds)
            .await
            .map_err(map_redis_err)?;
        Ok(())
    }
}

#[async_trait]
impl RevocationReader for RedisRevocationStore {
    async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
        let mut conn = self.conn.clone();
        let exists: bool = conn.exists(self.key(jti)).await.map_err(map_redis_err)?;
        Ok(exists)
    }
}
