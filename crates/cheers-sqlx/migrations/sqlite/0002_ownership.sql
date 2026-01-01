-- Ownership table — SQLite flavor. See migrations/pg/0002_ownership.sql for
-- the wire contract and the CHECK / partial-index reasoning.
--
-- Type differences from pg: BIGINT -> INTEGER (sqlite affinity). Partial
-- indexes are supported by sqlite from 3.8.0, so the WHERE clauses carry
-- through verbatim.

CREATE TABLE ownership (
    id              TEXT PRIMARY KEY,
    principal_id    TEXT NOT NULL,
    resource_kind   TEXT NOT NULL,
    resource_id     TEXT NOT NULL,
    relationship    TEXT NOT NULL,
    granted_by      TEXT NOT NULL,
    on_behalf_of    TEXT,
    granted_at      INTEGER NOT NULL,
    revoked_at      INTEGER,
    CHECK (granted_by LIKE 'svc:%'),
    CHECK (on_behalf_of IS NULL OR on_behalf_of LIKE 'user:%')
);

CREATE INDEX ix_ownership_principal
    ON ownership (principal_id, resource_kind, resource_id)
    WHERE revoked_at IS NULL;

CREATE INDEX ix_ownership_on_behalf_of
    ON ownership (on_behalf_of)
    WHERE revoked_at IS NULL;
