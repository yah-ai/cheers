-- Subject sets (R732-F1, noisetable W235 §2.1): a tuple's holder is either
-- one principal (principal_id) or a set, "every holder of subject_relation
-- on (subject_kind, subject_id)". principal_id becomes nullable, the three
-- subject_* columns are added, and a CHECK requires exactly one form.
-- Existing rows are all principal rows, so the CHECK holds for them as-is.

ALTER TABLE ownership ALTER COLUMN principal_id DROP NOT NULL;

ALTER TABLE ownership
    ADD COLUMN subject_kind TEXT,
    ADD COLUMN subject_id TEXT,
    ADD COLUMN subject_relation TEXT;

ALTER TABLE ownership ADD CONSTRAINT ownership_subject_one_form CHECK (
    (principal_id IS NOT NULL
        AND subject_kind IS NULL AND subject_id IS NULL AND subject_relation IS NULL)
    OR (principal_id IS NULL
        AND subject_kind IS NOT NULL AND subject_id IS NOT NULL AND subject_relation IS NOT NULL)
);

-- list_for_subject_set: live tuples whose subject is a set on one resource.
CREATE INDEX ix_ownership_subject_set
    ON ownership (subject_kind, subject_id)
    WHERE revoked_at IS NULL AND subject_kind IS NOT NULL;
