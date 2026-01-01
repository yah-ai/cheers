-- cheers schema — SQLite flavor.
--
-- Differences from the pg flavor:
-- - BOOLEAN → INTEGER (0/1); sqlx's Decode for bool handles either column type
-- - JSONB → TEXT (sqlite has no JSON column type, JSON1 functions read TEXT)
-- - No partial UNIQUE index on email (sqlite supports it, but we keep the
--   schema parallel; products that want it can add it manually).

CREATE TABLE users (
    user_id    TEXT PRIMARY KEY,
    email      TEXT,
    name       TEXT,
    created_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX users_email_unique
    ON users (email)
    WHERE email IS NOT NULL;

CREATE TABLE oauth_identities (
    provider   TEXT NOT NULL,
    issuer     TEXT NOT NULL DEFAULT '',
    subject    TEXT NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    linked_at  INTEGER NOT NULL,
    PRIMARY KEY (provider, issuer, subject)
);

CREATE INDEX oauth_identities_user_id ON oauth_identities (user_id);

CREATE TABLE refresh_tokens (
    token       TEXT PRIMARY KEY,
    chain_id    TEXT NOT NULL,
    parent      TEXT,
    user_id     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id   TEXT NOT NULL,
    issued_at   INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    consumed    INTEGER NOT NULL DEFAULT 0,
    revoked     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX refresh_tokens_chain_id ON refresh_tokens (chain_id);
CREATE INDEX refresh_tokens_user_device ON refresh_tokens (user_id, device_id);
CREATE INDEX refresh_tokens_expires_at ON refresh_tokens (expires_at);

CREATE TABLE passkey_credentials (
    user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id  TEXT NOT NULL,
    material   TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (user_id, device_id)
);

CREATE TABLE revocations (
    jti        TEXT PRIMARY KEY,
    revoked_at INTEGER NOT NULL,
    expires_at INTEGER
);

CREATE INDEX revocations_expires_at
    ON revocations (expires_at)
    WHERE expires_at IS NOT NULL;
