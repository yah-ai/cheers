-- cheers schema — Postgres flavor.
--
-- All identifiers are TEXT (cheers's UserId/DeviceId are opaque strings — the
-- product picks UUID/ULID/whatever); cheers doesn't interpret them. Timestamps
-- are BIGINT (unix seconds, signed) to match cheers-core's `Claims`/refresh
-- record shapes exactly — no clock conversion at the SQL boundary.

CREATE TABLE users (
    user_id    TEXT PRIMARY KEY,
    email      TEXT,
    name       TEXT,
    created_at BIGINT NOT NULL
);

-- Optional uniqueness on email when present (one human, one email at the
-- identity layer). Two NULLs are allowed (Postgres NULLs don't collide on
-- UNIQUE), so unlinked accounts still work.
CREATE UNIQUE INDEX users_email_unique ON users (email) WHERE email IS NOT NULL;

-- (provider, subject) is the namespace tag from cheers_server::ProviderKey
-- serialized via #[serde(tag="provider", rename_all="snake_case")]. Provider
-- is a small set ("oidc_google", "oidc_apple", "oidc_generic", "email",
-- "lan_pair"); the OidcGeneric issuer URL is stuffed into `issuer` (NULL for
-- the non-generic variants). Subject is the IdP's `sub` claim (or the email
-- address for the Email variant).
-- `issuer` is empty-string for non-generic providers; the OidcGeneric variant
-- writes its real issuer URL. Stored NOT NULL so the composite PK is honored
-- (NULLs in a PK column don't collide on UNIQUE — would let duplicate rows in).
CREATE TABLE oauth_identities (
    provider   TEXT NOT NULL,
    issuer     TEXT NOT NULL DEFAULT '',
    subject    TEXT NOT NULL,
    user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    linked_at  BIGINT NOT NULL,
    PRIMARY KEY (provider, issuer, subject)
);

CREATE INDEX oauth_identities_user_id ON oauth_identities (user_id);

-- Refresh token rotation chains. token PK is opaque base64url, never indexed
-- on as a substring. (user_id, device_id) drives /api/me/sessions joins.
CREATE TABLE refresh_tokens (
    token       TEXT PRIMARY KEY,
    chain_id    TEXT NOT NULL,
    parent      TEXT,
    user_id     TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id   TEXT NOT NULL,
    issued_at   BIGINT NOT NULL,
    expires_at  BIGINT NOT NULL,
    consumed    BOOLEAN NOT NULL DEFAULT FALSE,
    revoked     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX refresh_tokens_chain_id ON refresh_tokens (chain_id);
CREATE INDEX refresh_tokens_user_device ON refresh_tokens (user_id, device_id);
CREATE INDEX refresh_tokens_expires_at ON refresh_tokens (expires_at);

-- Passkey credentials, one row per (user, device). The non-discoverable
-- WebAuthn flow looks credentials up by user (via UserStore.list_devices →
-- PasskeyCredentialStore.list_for_user) then matches the assertion's
-- credential id in memory, so no cred_id index is needed here. material is
-- the serde_json'd webauthn-rs Passkey blob, stored as JSONB so a future
-- query (e.g. by backup_eligible flag) can read it without a full
-- deserialize.
CREATE TABLE passkey_credentials (
    user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id  TEXT NOT NULL,
    material   JSONB NOT NULL,
    created_at BIGINT NOT NULL,
    PRIMARY KEY (user_id, device_id)
);

-- Revocation kill-list keyed on access-token jti. expires_at is the access
-- token's expiry — once past, the kill-list entry can be GC'd (the underlying
-- token rejects on its own expiry check). Periodic
-- `DELETE FROM revocations WHERE expires_at < now-as-unix-seconds` keeps the
-- table small.
CREATE TABLE revocations (
    jti        TEXT PRIMARY KEY,
    revoked_at BIGINT NOT NULL,
    expires_at BIGINT
);

CREATE INDEX revocations_expires_at ON revocations (expires_at) WHERE expires_at IS NOT NULL;
