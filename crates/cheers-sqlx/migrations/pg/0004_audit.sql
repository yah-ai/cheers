-- Centralized audit table — append-only durable copy of every MCP-mediated
-- action constable observes (the cheers-side half of W159 §Audit journal).
--
-- See .yah/docs/working/mcp-auth-and-ownership.md §Audit ingest for the
-- ingest contract this backs (constable retains the local JSONL with bounded
-- backoff; cheers's responsibility ends at "accepted and durable on cheers's
-- side").
--
-- Append-only by convention: the only writes the AuditStore trait allows are
-- INSERTs, and there are no indexes positioned to make a hot-path UPDATE
-- cheap. A future retention sweep (drop rows older than N) is the only
-- non-INSERT operation expected here.
--
-- Field shape mirrors the wire record verbatim — at, sub, act, camp_id, aud,
-- method, scope, result, request_id — plus the two columns cheers contributes
-- (id, ingested_at).

CREATE TABLE audit (
    id            TEXT PRIMARY KEY,
    -- Constable's local clock at the time of the action.
    at            BIGINT NOT NULL,
    -- "user:<id>" | "svc:<id>" | "camp:<id>" — the verified token's sub.
    sub           TEXT NOT NULL,
    -- "svc:agent-<variant>" when an agent acted on sub's behalf; null otherwise.
    act_sub       TEXT,
    -- Camp the call was scoped to; null for camp-less actions.
    camp_id       TEXT,
    -- Target resource URI (the verified token's aud).
    aud           TEXT NOT NULL,
    -- Free-form method identifier (e.g. "POST /cloud/deploy").
    method        TEXT NOT NULL,
    -- Scope list the call presented, JSON-encoded array of wire scope strings
    -- (no wildcards — composition rule (1) enforced at parse time).
    scope         TEXT NOT NULL,
    -- Outcome string ("allow" | "deny" | "error" by convention; cheers does
    -- not constrain the vocabulary — it's append-only durable storage).
    result        TEXT NOT NULL,
    -- Correlator into constable's local JSONL.
    request_id    TEXT NOT NULL,
    -- Cheers's server clock at ingest time. Distinct from `at` so an operator
    -- can see ingest latency without joining clocks at query time.
    ingested_at   BIGINT NOT NULL
);

-- F14 ("who deployed what") pages by acting principal + time. Both common
-- subject shapes (user-fresh = sub is a user; bootstrap = sub is a camp,
-- act_sub names the agent) flow through `sub` — the index covers both.
CREATE INDEX ix_audit_sub_at ON audit (sub, at DESC);

-- The act_sub lane is the agent-attribution view. Partial so the index stays
-- small for the common case (sub-only calls have act_sub = NULL).
CREATE INDEX ix_audit_act_sub_at ON audit (act_sub, at DESC) WHERE act_sub IS NOT NULL;
