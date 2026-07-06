//! [`RefreshStore`](cheers_server::RefreshStore) over redis.
//!
//! Key layout (per crate-level docs):
//! - `{prefix}:refresh:{token}` — JSON-encoded
//!   [`RefreshTokenRecord`](cheers_server::RefreshTokenRecord), expires at the
//!   record's `expires_at`.
//! - `{prefix}:chain:{chain_id}` — `SET` of every token in the chain. Lets
//!   [`revoke_chain`](RefreshStore::revoke_chain) flip every record without a
//!   `SCAN`.
//!
//! Rotation semantics ([`RefreshRotator`](cheers_server::RefreshRotator)) call
//! the trait three times per rotation: `get` → `mark_consumed` → `put`. The
//! atomic-revoke contract is handled here via a per-revoke iteration over the
//! chain set; the rotator itself stays backend-agnostic.

use async_trait::async_trait;
use cheers_core::StoreError;
use cheers_server::store::{RefreshStore, RefreshTokenRecord};
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::DEFAULT_PREFIX;

/// Atomic compare-and-set backing [`RefreshStore::mark_consumed`]. A Lua script
/// runs to completion without interleaving, so it is the consume gate: GET the
/// record, return 0 if it is missing / undecodable / already consumed,
/// otherwise flip `consumed`, re-SET preserving the remaining TTL, and return 1.
/// Exactly one of two racing rotations can get 1 back.
static MARK_CONSUMED_CAS: LazyLock<redis::Script> = LazyLock::new(|| {
    redis::Script::new(
        r"
        local v = redis.call('GET', KEYS[1])
        if not v then return 0 end
        local ok, rec = pcall(cjson.decode, v)
        if not ok or rec.consumed then return 0 end
        rec.consumed = true
        local ttl = redis.call('TTL', KEYS[1])
        local nv = cjson.encode(rec)
        if ttl and ttl > 0 then
            redis.call('SET', KEYS[1], nv, 'EX', ttl)
        else
            redis.call('SET', KEYS[1], nv)
        end
        return 1
        ",
    )
});

fn map_redis_err(err: redis::RedisError) -> StoreError {
    StoreError::Backend(err.to_string())
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Redis-backed [`RefreshStore`].
///
/// Construct from a [`ConnectionManager`] (the recommended redis-rs primitive
/// for production — reconnects on connection loss without losing in-flight
/// requests).
#[derive(Clone)]
pub struct RedisRefreshStore {
    conn: ConnectionManager,
    prefix: String,
}

impl RedisRefreshStore {
    /// Construct with the default key prefix (`cheers`).
    pub fn new(conn: ConnectionManager) -> Self {
        Self {
            conn,
            prefix: DEFAULT_PREFIX.to_owned(),
        }
    }

    /// Override the key prefix (e.g. for multi-tenant redis isolation).
    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    fn token_key(&self, token: &str) -> String {
        format!("{}:refresh:{token}", self.prefix)
    }

    fn chain_key(&self, chain_id: &str) -> String {
        format!("{}:chain:{chain_id}", self.prefix)
    }
}

impl std::fmt::Debug for RedisRefreshStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisRefreshStore")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl RefreshStore for RedisRefreshStore {
    async fn put(&self, record: &RefreshTokenRecord) -> Result<(), StoreError> {
        let mut conn = self.conn.clone();
        let token_key = self.token_key(&record.token);
        let chain_key = self.chain_key(&record.chain_id);

        let payload = serde_json::to_vec(record).map_err(|e| {
            StoreError::Backend(format!("serializing RefreshTokenRecord: {e}"))
        })?;

        // TTL on the per-token key — when it expires, the record is gone and
        // any rotation attempt sees `Unknown`. We add a small grace so the
        // chain set entry doesn't outlive the last record by long.
        let ttl_seconds = (record.expires_at - now_unix()).max(1);

        // Pipeline: SET the record with TTL, SADD it to the chain set, set
        // the chain set's own TTL to at least the record's TTL.
        let _: () = redis::pipe()
            .atomic()
            .set_ex(&token_key, payload.as_slice(), ttl_seconds as u64)
            .sadd(&chain_key, &record.token)
            .expire(&chain_key, ttl_seconds)
            .query_async(&mut conn)
            .await
            .map_err(map_redis_err)?;
        Ok(())
    }

    async fn get(&self, token: &str) -> Result<Option<RefreshTokenRecord>, StoreError> {
        let mut conn = self.conn.clone();
        let key = self.token_key(token);
        let payload: Option<Vec<u8>> = conn.get(&key).await.map_err(map_redis_err)?;
        match payload {
            None => Ok(None),
            Some(bytes) => {
                let rec: RefreshTokenRecord = serde_json::from_slice(&bytes).map_err(|e| {
                    StoreError::Backend(format!("deserializing RefreshTokenRecord: {e}"))
                })?;
                Ok(Some(rec))
            }
        }
    }

    async fn mark_consumed(&self, token: &str) -> Result<bool, StoreError> {
        let mut conn = self.conn.clone();
        let key = self.token_key(token);
        // The read-modify-write must be atomic, or two concurrent rotations of
        // the same token both read `consumed = false` and each mint a live
        // successor (the H2 double-spend). A Lua script executes to completion
        // without interleaving, so it is the compare-and-set: decode the
        // record, bail with 0 if it is missing or already consumed, otherwise
        // flip `consumed`, re-encode preserving the remaining TTL, and return 1.
        //
        // cjson round-trips this record faithfully — every field is a string,
        // bool, or small integer timestamp (well within cjson's integer
        // precision), and serde reads a dropped null `parent` back as `None`.
        let flipped: i64 = MARK_CONSUMED_CAS
            .key(&key)
            .invoke_async(&mut conn)
            .await
            .map_err(map_redis_err)?;
        Ok(flipped == 1)
    }

    async fn revoke_chain(&self, chain_id: &str) -> Result<(), StoreError> {
        let mut conn = self.conn.clone();
        let chain_key = self.chain_key(chain_id);
        let tokens: Vec<String> = conn.smembers(&chain_key).await.map_err(map_redis_err)?;
        // For each token, fetch + update the `revoked` flag.
        for token in tokens {
            let key = self.token_key(&token);
            let payload: Option<Vec<u8>> = conn.get(&key).await.map_err(map_redis_err)?;
            let bytes = match payload {
                Some(b) => b,
                None => continue, // Member of the set but the record TTL'd out — skip.
            };
            let mut rec: RefreshTokenRecord = match serde_json::from_slice(&bytes) {
                Ok(r) => r,
                Err(_) => continue, // Corrupted entry — best-effort, don't fail the call.
            };
            if rec.revoked {
                continue;
            }
            rec.revoked = true;
            let new_payload = serde_json::to_vec(&rec).map_err(|e| {
                StoreError::Backend(format!("re-serializing RefreshTokenRecord: {e}"))
            })?;
            let ttl: i64 = conn.ttl(&key).await.map_err(map_redis_err)?;
            if ttl > 0 {
                let _: () = conn
                    .set_ex(&key, new_payload.as_slice(), ttl as u64)
                    .await
                    .map_err(map_redis_err)?;
            } else {
                let _: () = conn.set(&key, new_payload.as_slice()).await.map_err(map_redis_err)?;
            }
        }
        Ok(())
    }
}
