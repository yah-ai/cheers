-- R732-T7: every revocation entry carries a bound, so the set stays bounded
-- and a revoke masks only what existed when it was made.
--
--   jti        -> expires_at (existing column): the credential's own exp. The
--                 row lapses once expires_at <= now and gc drops it. NULL
--                 never lapses (standing bindings, non-expiring user tokens).
--   device     -> bound = at_seq: masks standing bindings with seq < at_seq,
--                 so re-enrolling the device (a higher seq) is admitted.
--   membership -> bound = at_epoch: masks snapshots with epoch < at_epoch.
--
-- The row key (kind, subject, resource_kind, resource_id) stays the identity:
-- one row per identity, one bound; a re-revoke keeps the larger.
--
-- LEGACY ROWS. A device or membership row written before this migration meant
-- "masks everything", so it gets bound = i64::MAX: fail-closed, it still
-- masks every sequence and epoch. Legacy jti rows keep their expires_at
-- (NULL: never lapse).

ALTER TABLE revocations ADD COLUMN bound INTEGER;

UPDATE revocations SET bound = 9223372036854775807 WHERE kind IN ('device', 'membership');
