-- Ownership table — embedded-ownership source of truth that cheers reads at
-- MCP-token mint time and bakes into the `owns` claim.
--
-- See .yah/docs/working/mcp-auth-and-ownership.md §Ownership table for the
-- wire-claim contract this backs (W159 Layer 2 — local resource-membership
-- check on constable's host, no per-call cheers round-trip).
--
-- Two CHECK constraints encode the invariants the doc calls out:
-- - granted_by is ALWAYS a service principal (humans never write ownership).
-- - on_behalf_of, when present, is ALWAYS a user principal (services never
--   appear here; self-grants use NULL).
-- The same invariants are checked Rust-side by NewOwnership::new before the
-- insert ever hits the DB.

CREATE TABLE ownership (
    id              TEXT PRIMARY KEY,
    principal_id    TEXT NOT NULL,
    resource_kind   TEXT NOT NULL,
    resource_id     TEXT NOT NULL,
    relationship    TEXT NOT NULL,
    granted_by      TEXT NOT NULL,
    on_behalf_of    TEXT,
    granted_at      BIGINT NOT NULL,
    revoked_at      BIGINT,
    CHECK (granted_by LIKE 'svc:%'),
    CHECK (on_behalf_of IS NULL OR on_behalf_of LIKE 'user:%')
);

-- Partial index — list_for_principal hot path scans live rows by principal +
-- resource kind. Revoked rows are excluded so the index stays small.
CREATE INDEX ix_ownership_principal
    ON ownership (principal_id, resource_kind, resource_id)
    WHERE revoked_at IS NULL;

-- Cascading revoke ("revoking user U sweeps every row with that on_behalf_of")
-- is an UPDATE … WHERE on_behalf_of = $1 AND revoked_at IS NULL. The partial
-- index keeps that update O(rows-actually-affected).
CREATE INDEX ix_ownership_on_behalf_of
    ON ownership (on_behalf_of)
    WHERE revoked_at IS NULL;
