-- Centralized audit table — SQLite flavor. See migrations/pg/0004_audit.sql
-- for the wire contract and the per-column reasoning.
--
-- Type differences from pg: BIGINT -> INTEGER (sqlite affinity). Partial
-- indexes ride through verbatim (sqlite >= 3.8.0).

CREATE TABLE audit (
    id            TEXT PRIMARY KEY,
    at            INTEGER NOT NULL,
    sub           TEXT NOT NULL,
    act_sub       TEXT,
    camp_id       TEXT,
    aud           TEXT NOT NULL,
    method        TEXT NOT NULL,
    scope         TEXT NOT NULL,
    result        TEXT NOT NULL,
    request_id    TEXT NOT NULL,
    ingested_at   INTEGER NOT NULL
);

CREATE INDEX ix_audit_sub_at ON audit (sub, at DESC);

CREATE INDEX ix_audit_act_sub_at ON audit (act_sub, at DESC) WHERE act_sub IS NOT NULL;
