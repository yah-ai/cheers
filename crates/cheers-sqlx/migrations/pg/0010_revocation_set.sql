-- R732-F6: the revocation set. Entries are no longer only access-token jtis:
-- a device (ends a standing node binding) and a (resource, user) membership
-- (ends a member's place in a membership snapshot) join them, and the whole
-- set carries one strictly monotonic epoch that every change advances. The
-- issuer signs (epoch, entries) and offline peers keep the highest epoch.
--
-- `subject` is the jti, the device id, or the member's user id (spelled like
-- Claims.sub); `resource_kind` / `resource_id` are set only for memberships
-- and are '' otherwise, so they can sit in the primary key. Every existing
-- row is a jti. 0001 declared the key inline, so Postgres named it
-- `revocations_pkey`.

ALTER TABLE revocations RENAME COLUMN jti TO subject;

ALTER TABLE revocations
    ADD COLUMN kind TEXT NOT NULL DEFAULT 'jti'
        CHECK (kind IN ('jti', 'device', 'membership')),
    ADD COLUMN resource_kind TEXT NOT NULL DEFAULT '',
    ADD COLUMN resource_id TEXT NOT NULL DEFAULT '';

ALTER TABLE revocations ALTER COLUMN kind DROP DEFAULT;

ALTER TABLE revocations DROP CONSTRAINT revocations_pkey;

ALTER TABLE revocations
    ADD PRIMARY KEY (kind, subject, resource_kind, resource_id);

-- One row: the store is one issuer's log. Advanced to
-- GREATEST(epoch + 1, now) by every write that changes the entries, in the
-- same transaction.
CREATE TABLE revocation_epoch (
    singleton SMALLINT PRIMARY KEY CHECK (singleton = 1),
    epoch     BIGINT NOT NULL
);

INSERT INTO revocation_epoch (singleton, epoch) VALUES (1, 0);
