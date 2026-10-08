-- R732-F6: the revocation set. Entries are no longer only access-token jtis:
-- a device (ends a standing node binding) and a (resource, user) membership
-- (ends a member's place in a membership snapshot) join them, and the whole
-- set carries one strictly monotonic epoch that every change advances. The
-- issuer signs (epoch, entries) and offline peers keep the highest epoch.
--
-- `subject` is the jti, the device id, or the member's user id (spelled like
-- Claims.sub); `resource_kind` / `resource_id` are set only for memberships
-- and are '' otherwise, so they can sit in the primary key.
--
-- SQLite cannot change a primary key in place, so the table is rebuilt; every
-- existing row is a jti.

CREATE TABLE revocations_new (
    kind          TEXT NOT NULL CHECK (kind IN ('jti', 'device', 'membership')),
    subject       TEXT NOT NULL,
    resource_kind TEXT NOT NULL DEFAULT '',
    resource_id   TEXT NOT NULL DEFAULT '',
    revoked_at    INTEGER NOT NULL,
    expires_at    INTEGER,
    PRIMARY KEY (kind, subject, resource_kind, resource_id)
);

INSERT INTO revocations_new (kind, subject, revoked_at, expires_at)
SELECT 'jti', jti, revoked_at, expires_at
FROM revocations;

DROP TABLE revocations;

ALTER TABLE revocations_new RENAME TO revocations;

CREATE INDEX revocations_expires_at
    ON revocations (expires_at)
    WHERE expires_at IS NOT NULL;

-- One row: the store is one issuer's log. Advanced to max(epoch + 1, now) by
-- every write that changes the entries, in the same transaction.
CREATE TABLE revocation_epoch (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    epoch     INTEGER NOT NULL
);

INSERT INTO revocation_epoch (singleton, epoch) VALUES (1, 0);
