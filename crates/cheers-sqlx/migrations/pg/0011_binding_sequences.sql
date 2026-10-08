-- R732-F5: the standing node binding's per-device sequence. Every binding the
-- issuer mints for a device is stamped with the next value, advanced to
-- GREATEST(seq + 1, now) by one upsert, so a newer binding for a device always
-- carries a higher seq than every earlier one. The clock floor keeps that
-- true after a restore from an older backup: the next seq lands above what
-- edges already hold. Keyed by device alone, so a device re-bound to another
-- user still supersedes its previous binding.

CREATE TABLE binding_sequences (
    device_id TEXT PRIMARY KEY,
    seq       BIGINT NOT NULL
);
