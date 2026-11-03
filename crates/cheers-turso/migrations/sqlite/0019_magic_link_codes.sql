-- Sign-in codes for bound magic-link grants (CHE-R961; noisetable W275 §4)
-- (cheers-core's MagicLinkCodeStore) — SQLite flavor. One row per S256
-- challenge: a resend under the same verifier replaces the previous code.
-- code_hash is the hex SHA-256 of jti:code; the code itself is never stored.
-- A row dies on any redemption of its grant (deleted by jti), on its fifth
-- spent attempt, or at expires_at (now + 600 at mint); grant_expires_at is how
-- long the used_jti mark a code redemption writes must last.

CREATE TABLE magic_link_codes (
    challenge        TEXT PRIMARY KEY,
    jti              TEXT NOT NULL,
    email            TEXT NOT NULL,
    code_hash        TEXT NOT NULL,
    attempts         INTEGER NOT NULL DEFAULT 0,
    expires_at       INTEGER NOT NULL,
    grant_expires_at INTEGER NOT NULL
);

CREATE INDEX magic_link_codes_jti ON magic_link_codes (jti);
CREATE INDEX magic_link_codes_expires_at ON magic_link_codes (expires_at);
