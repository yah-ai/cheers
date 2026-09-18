-- Single-use tracking for magic-link tokens (cheers-core's UsedJtiStore) —
-- SQLite flavor. One row per consumed magic-link jti, kept until at least
-- expires_at so a replay within the token's own TTL is refused even across a
-- process restart; GC'd after expiry (the codec's own expiry check already
-- rejects a token whose record is missing).

CREATE TABLE used_jti (
    jti        TEXT PRIMARY KEY,
    expires_at INTEGER NOT NULL
);

CREATE INDEX used_jti_expires_at ON used_jti (expires_at);
