-- Service-principal records + signing keys — SQLite flavor. See
-- migrations/pg/0003_service_principals.sql for the wire contract and the
-- CHECK / partial-index reasoning.
--
-- Type differences from pg: BIGINT -> INTEGER (sqlite affinity), BYTEA -> BLOB
-- (sqlite stores raw bytes natively). Partial indexes are supported by
-- sqlite from 3.8.0, so the WHERE clause carries through verbatim.

CREATE TABLE service_principals (
    id          TEXT PRIMARY KEY,
    status      TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    CHECK (id LIKE 'svc:%'),
    CHECK (status IN ('active', 'revoked'))
);

CREATE TABLE service_principal_keys (
    kid             TEXT PRIMARY KEY,
    principal_id    TEXT NOT NULL REFERENCES service_principals(id) ON DELETE CASCADE,
    public_key      BLOB NOT NULL,
    status          TEXT NOT NULL,
    created_at      INTEGER NOT NULL,
    retire_at       INTEGER,
    CHECK (status IN ('active', 'retiring')),
    CHECK (
        (status = 'active'   AND retire_at IS NULL) OR
        (status = 'retiring' AND retire_at IS NOT NULL)
    )
);

CREATE INDEX ix_spk_principal_active
    ON service_principal_keys (principal_id)
    WHERE status = 'active';
