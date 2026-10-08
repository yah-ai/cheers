-- R732-F4: the store-wide ownership version, and the per-resource index the
-- set-aware checks read through.
--
-- `ownership_version` is the epoch of a membership snapshot. Every write that
-- changes an ownership row advances it to GREATEST(version + 1, now) in the
-- same transaction, so two reads of an equal version saw equal rows. One row,
-- not one per resource: subject-set tuples (child#guest <- parent#member) make
-- one resource's flattened membership depend on other resources' rows, so a
-- per-resource counter would not move when a parent membership changed. The
-- clock floor keeps a store restored from an older backup above the versions
-- edges already hold.

CREATE TABLE ownership_version (
    singleton SMALLINT PRIMARY KEY CHECK (singleton = 1),
    version   BIGINT NOT NULL
);

INSERT INTO ownership_version (singleton, version) VALUES (1, 0);

-- list_for_resource: live tuples on one resource. The down-walk behind holds,
-- may_grant and members reads one resource per node (R732-F2).
CREATE INDEX ix_ownership_resource
    ON ownership (resource_kind, resource_id)
    WHERE revoked_at IS NULL;
