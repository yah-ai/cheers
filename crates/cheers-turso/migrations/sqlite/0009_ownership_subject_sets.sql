-- Subject sets (R732-F1, noisetable W235 §2.1): a tuple's holder is either
-- one principal (principal_id) or a set, "every holder of subject_relation
-- on (subject_kind, subject_id)". principal_id becomes nullable, the three
-- subject_* columns are added, and a CHECK requires exactly one form.
--
-- SQLite cannot relax NOT NULL or add a CHECK in place, so this rebuilds the
-- table as 0008 did. Existing rows are all principal rows and copy across
-- with NULL subject_* columns. No table references ownership, so the rebuild
-- needs no foreign-key handling.

CREATE TABLE ownership_new (
    id                TEXT PRIMARY KEY,
    principal_id      TEXT,
    subject_kind      TEXT,
    subject_id        TEXT,
    subject_relation  TEXT,
    resource_kind     TEXT NOT NULL,
    resource_id       TEXT NOT NULL,
    relationship      TEXT NOT NULL,
    granted_by        TEXT NOT NULL,
    on_behalf_of      TEXT,
    granted_at        INTEGER NOT NULL,
    revoked_at        INTEGER,
    CHECK (on_behalf_of IS NULL OR on_behalf_of LIKE 'user:%'),
    CHECK (
        (principal_id IS NOT NULL
            AND subject_kind IS NULL AND subject_id IS NULL AND subject_relation IS NULL)
        OR (principal_id IS NULL
            AND subject_kind IS NOT NULL AND subject_id IS NOT NULL AND subject_relation IS NOT NULL)
    )
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

-- list_for_subject_set: live tuples whose subject is a set on one resource.
CREATE INDEX ix_ownership_subject_set
    ON ownership (subject_kind, subject_id)
    WHERE revoked_at IS NULL AND subject_kind IS NOT NULL;
