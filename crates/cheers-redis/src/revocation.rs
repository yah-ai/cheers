//! [`RevocationWriter`](cheers_server::RevocationWriter) +
//! [`RevocationReader`](cheers_verify::RevocationReader) over redis.
//!
//! Key layout (R732-F6, re-keyed by identity in R732-T7):
//!
//! - `{prefix}:revocations` — a hash, identity -> the JSON of the [`Revoked`]
//!   entry holding that identity's bound. The identity
//!   ([`Revoked::identity`]) is the field, never the full entry: the bound is
//!   inside the entry JSON, so matching on it would split one identity into
//!   one member per bound.
//! - `{prefix}:revocations:rank` — a hash, identity -> the bound as a number
//!   the revoke script compares (`inf` for a jti with no `exp`).
//! - `{prefix}:revocations:lapse` — a sorted set, identity -> the unix second
//!   a jti lapses (its `exp`). Only jtis with an `exp` are in it; devices,
//!   memberships and `exp: None` jtis never lapse (noisetable W235 §0.1).
//! - `{prefix}:revocations:epoch` — the set's epoch.
//!
//! A revoke is one Lua script: write the entry only if the identity is new or
//! its bound rose, and only then advance the epoch to `max(epoch + 1, now)` —
//! atomic, so the epoch and the contents never disagree. The `is_*` reads are
//! one `HGET` each and treat a lapsed jti as unrevoked. A lapsed entry stays in
//! the snapshot (whose contents are fixed per epoch) until
//! [`RedisRevocationStore::gc`] removes it and advances the epoch; the
//! published set omits it already (`RevocationPublisher::current`).

use async_trait::async_trait;
use cheers_core::{DeviceId, PrincipalId, Revoked, StoreError};
use cheers_server::{RevocationSnapshot, RevocationWriter};
use cheers_verify::RevocationReader;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Script};
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

/// KEYS: entries, rank, lapse, epoch. ARGV: identity, entry JSON, rank,
/// lapse score (`""` for none), now. Returns 1 if the identity was new or its
/// rank rose, and only then writes and advances the epoch to
/// `max(epoch + 1, now)`.
const REVOKE_LUA: &str = r"
local function num(s) if s == 'inf' then return math.huge end return tonumber(s) end
local old = redis.call('HGET', KEYS[2], ARGV[1])
if old and num(ARGV[3]) <= num(old) then
  return 0
end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
redis.call('HSET', KEYS[2], ARGV[1], ARGV[3])
if ARGV[4] == '' then
  redis.call('ZREM', KEYS[3], ARGV[1])
else
  redis.call('ZADD', KEYS[3], ARGV[4], ARGV[1])
end
local nxt = tonumber(redis.call('GET', KEYS[4]) or '0') + 1
local now = tonumber(ARGV[5])
if now > nxt then nxt = now end
redis.call('SET', KEYS[4], string.format('%d', nxt))
return 1
";

/// KEYS: entries, rank, lapse, epoch. ARGV: cutoff, now. Removes every
/// identity that lapsed at or before cutoff; returns the number removed, and
/// advances the epoch only if that is non-zero.
const GC_LUA: &str = r"
local ids = redis.call('ZRANGEBYSCORE', KEYS[3], '-inf', ARGV[1])
for _, id in ipairs(ids) do
  redis.call('HDEL', KEYS[1], id)
  redis.call('HDEL', KEYS[2], id)
  redis.call('ZREM', KEYS[3], id)
end
if #ids > 0 then
  local nxt = tonumber(redis.call('GET', KEYS[4]) or '0') + 1
  local now = tonumber(ARGV[2])
  if now > nxt then nxt = now end
  redis.call('SET', KEYS[4], string.format('%d', nxt))
end
return #ids
";

/// Redis-backed revocation set. Implements both
/// [`RevocationWriter`] (origin) and [`RevocationReader`] (edge).
#[derive(Clone)]
pub struct RedisRevocationStore {
    conn: ConnectionManager,
    prefix: String,
}

impl RedisRevocationStore {
    pub fn new(conn: ConnectionManager) -> Self {
        Self {
            conn,
            prefix: DEFAULT_PREFIX.to_owned(),
        }
    }

    pub fn with_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.prefix = prefix.into();
        self
    }

    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// Remove jtis that lapsed at or before `now`, advancing the epoch when
    /// anything went. Returns the number removed.
    pub async fn gc(&self, now: i64) -> Result<u64, StoreError> {
        let mut conn = self.conn.clone();
        let removed: u64 = Script::new(GC_LUA)
            .key(self.entries_key())
            .key(self.rank_key())
            .key(self.lapse_key())
            .key(self.epoch_key())
            .arg(now)
            .arg(now_unix())
            .invoke_async(&mut conn)
            .await
            .map_err(map_redis_err)?;
        Ok(removed)
    }

    fn entries_key(&self) -> String {
        format!("{}:revocations", self.prefix)
    }

    fn rank_key(&self) -> String {
        format!("{}:revocations:rank", self.prefix)
    }

    fn lapse_key(&self) -> String {
        format!("{}:revocations:lapse", self.prefix)
    }

    fn epoch_key(&self) -> String {
        format!("{}:revocations:epoch", self.prefix)
    }

    /// The hash field of `entry`'s identity.
    fn identity(entry: &Revoked) -> Result<String, StoreError> {
        serde_json::to_string(&entry.identity()).map_err(|e| StoreError::Backend(e.to_string()))
    }

    /// The held entry with `probe`'s identity; a lapsed jti reads as absent.
    async fn held(&self, probe: &Revoked) -> Result<Option<Revoked>, StoreError> {
        let mut conn = self.conn.clone();
        let json: Option<String> = conn
            .hget(self.entries_key(), Self::identity(probe)?)
            .await
            .map_err(map_redis_err)?;
        let Some(json) = json else { return Ok(None) };
        let entry: Revoked = serde_json::from_str(&json).map_err(|e| StoreError::Backend(e.to_string()))?;
        Ok((!entry.is_lapsed_at(now_unix())).then_some(entry))
    }
}

impl std::fmt::Debug for RedisRevocationStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisRevocationStore")
            .field("prefix", &self.prefix)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl RevocationWriter for RedisRevocationStore {
    async fn revoke(&self, entry: &Revoked) -> Result<(), StoreError> {
        let (rank, lapse) = match entry {
            Revoked::Jti { exp: Some(exp), .. } => (exp.to_string(), exp.to_string()),
            Revoked::Jti { exp: None, .. } => ("inf".to_owned(), String::new()),
            Revoked::Device { at_seq: b, .. } | Revoked::Membership { at_epoch: b, .. } => (b.to_string(), String::new()),
        };
        let json = serde_json::to_string(entry).map_err(|e| StoreError::Backend(e.to_string()))?;
        let mut conn = self.conn.clone();
        let _written: i64 = Script::new(REVOKE_LUA)
            .key(self.entries_key())
            .key(self.rank_key())
            .key(self.lapse_key())
            .key(self.epoch_key())
            .arg(Self::identity(entry)?)
            .arg(json)
            .arg(rank)
            .arg(lapse)
            .arg(now_unix())
            .invoke_async(&mut conn)
            .await
            .map_err(map_redis_err)?;
        Ok(())
    }

    async fn snapshot(&self) -> Result<RevocationSnapshot, StoreError> {
        let mut conn = self.conn.clone();
        // MULTI/EXEC: the epoch and the entries from one point in time.
        let (epoch, entries): (Option<u64>, Vec<String>) = redis::pipe()
            .atomic()
            .get(self.epoch_key())
            .hvals(self.entries_key())
            .query_async(&mut conn)
            .await
            .map_err(map_redis_err)?;
        let revoked = entries
            .iter()
            .map(|m| serde_json::from_str(m).map_err(|e| StoreError::Backend(e.to_string())))
            .collect::<Result<_, _>>()?;
        Ok(RevocationSnapshot {
            epoch: epoch.unwrap_or(0),
            revoked,
        })
    }
}

#[async_trait]
impl RevocationReader for RedisRevocationStore {
    async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
        Ok(self.held(&Revoked::jti(jti, None)).await?.is_some())
    }

    async fn is_device_revoked(&self, device: &DeviceId, seq: u64) -> Result<bool, StoreError> {
        Ok(matches!(
            self.held(&Revoked::device(device.clone(), 0)).await?,
            Some(Revoked::Device { at_seq, .. }) if seq < at_seq
        ))
    }

    async fn is_membership_revoked(
        &self,
        _key: &cheers_core::RevocationKey,
        kind: &str,
        id: &str,
        principal: &PrincipalId,
        snapshot_epoch: u64,
    ) -> Result<bool, StoreError> {
        Ok(matches!(
            self.held(&Revoked::membership(kind, id, principal.clone(), 0)).await?,
            Some(Revoked::Membership { at_epoch, .. }) if snapshot_epoch < at_epoch
        ))
    }
}
