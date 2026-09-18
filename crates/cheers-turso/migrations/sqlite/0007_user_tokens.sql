-- User API tokens (PATs) — the METADATA half only (R728-F1). SQLite flavor.
--
-- A cheers API token is an ordinary signed v4.public MCP token carrying
-- auth_strength "api-token". It is verified by SIGNATURE and killed through
-- the same revocation set as every other token, so nothing in this table is
-- on the token's trust path. The table exists so a user can SEE what they
-- have issued, name it, and revoke it by id.
--
-- There is deliberately NO secret and NO secret_hash column. Cheers never
-- looks up presented bytes, so a hash here would have no reader — a column
-- with no reader that nonetheless has to be protected widens what a database
-- leak is worth for no benefit, and invites a future edge to "just check the
-- hash", which is the parallel verification stack this design exists to
-- avoid. The secret is returned by POST /me/tokens exactly once.
--
-- `jti` is the token's own claim value, the key the revocation set is keyed
-- on, and the public id in DELETE /me/tokens/{id}: one id, three places, no
-- mapping table.
--
-- `revoked` is the VISIBLE half of a revoke. The kill itself is the
-- revocation-set entry; this flag is what makes GET /me/tokens tell the truth
-- afterwards. Revocation is not deletion — the row survives so the revoke
-- path can tell "not yours" (404) from "already dead" (204).
--
-- `last_used_at` is nullable and cheers never writes it. The only place a use
-- could be observed is the verify edge, which deliberately holds a revocation
-- READER and no writer at all; giving it a store write would undo the
-- property that a compromised edge cannot mutate origin state. A resource
-- server that consumes these tokens is the intended writer.

CREATE TABLE user_tokens (
    jti          TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    scopes       TEXT NOT NULL,
    aud          TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    last_used_at INTEGER,
    expires_at   INTEGER NOT NULL,
    revoked      INTEGER NOT NULL DEFAULT 0
);

-- The one read pattern: "this user's tokens, newest first".
CREATE INDEX user_tokens_user_created
    ON user_tokens (user_id, created_at DESC);
