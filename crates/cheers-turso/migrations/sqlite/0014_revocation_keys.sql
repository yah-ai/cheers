-- R732-T10: per-resource membership-revocation keys.
--
-- The published revocation set names a membership by
-- HMAC-SHA256(key, kind, id, user), never in plaintext. `key` is 32 random
-- bytes, created on first use (insert-or-ignore, then reread, so concurrent
-- creators converge on one row) and never updated: a changed key would make
-- edges holding older snapshots miss every new entry, failing revocation open.
-- It lives beside the ownership rows so a restore cannot separate the two. It
-- is secret: it leaves the issuer only inside signed membership snapshots.

CREATE TABLE revocation_keys (
    resource_kind TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    key           BLOB NOT NULL CHECK (length(key) = 32),
    PRIMARY KEY (resource_kind, resource_id)
);
