-- R734-F3: admission policy as signed resource data (knock.md, "The dial").
--
-- One row per resource that has a policy; a resource with none reads as
-- closed for offline admits. `policy` is the AdmissionPolicy JSON wire form,
-- validated on read. Writing or deleting a row advances ownership_version in
-- the same transaction, so the change ships at a higher snapshot epoch and the
-- edge ledger refuses any older, looser snapshot.

CREATE TABLE admission_policies (
    resource_kind TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    policy        TEXT NOT NULL,
    PRIMARY KEY (resource_kind, resource_id)
);
