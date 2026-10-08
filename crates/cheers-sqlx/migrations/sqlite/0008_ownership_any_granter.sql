-- D4 (operator 2026-10-06): granted_by is the writer's verified sub, of any
-- kind. SQLite cannot drop a CHECK, so rebuild the ownership table without
-- `CHECK (granted_by LIKE 'svc:%')`. The on_behalf_of CHECK stays.
--
-- Revocation now follows the holder (principal_id), so the on_behalf_of
-- index that served the old cascade is not recreated. No table references
-- ownership, so the rebuild needs no foreign-key handling.

CREATE TABLE ownership_new (
    id              TEXT PRIMARY KEY,
    principal_id    TEXT NOT NULL,
    resource_kind   TEXT NOT NULL,
    resource_id     TEXT NOT NULL,
    relationship    TEXT NOT NULL,
    granted_by      TEXT NOT NULL,
    on_behalf_of    TEXT,
    granted_at      INTEGER NOT NULL,
    revoked_at      INTEGER,
    CHECK (on_behalf_of IS NULL OR on_behalf_of LIKE 'user:%')
);

INSERT INTO ownership_new
    (id, principal_id, resource_kind, resource_id, relationship,
     granted_by, on_behalf_of, granted_at, revoked_at)
SELECT id, principal_id, resource_kind, resource_id, relationship,
       granted_by, on_behalf_of, granted_at, revoked_at
FROM ownership;

DROP TABLE ownership;

ALTER TABLE ownership_new RENAME TO ownership;

CREATE INDEX ix_ownership_principal
    ON ownership (principal_id, resource_kind, resource_id)
    WHERE revoked_at IS NULL;
