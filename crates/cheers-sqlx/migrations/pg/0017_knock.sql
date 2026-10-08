-- R734-F4: knock (knock.md, "Reconciliation", "Sybil controls").
--
-- Ownership tuples gain an optional lease: a guest admitted through a Knock,
-- an Offer or an uploaded Admit keeps that Admit's lease, and confers nothing
-- once lease_exp has passed. All three are NULL on a standing tuple, or all of
-- lease_iat and lease_refresh_after are set (lease_exp may stay NULL).

ALTER TABLE ownership ADD COLUMN lease_iat BIGINT;
ALTER TABLE ownership ADD COLUMN lease_refresh_after BIGINT;
ALTER TABLE ownership ADD COLUMN lease_exp BIGINT;

-- Online knocks waiting for an approver. One per requester key per resource
-- (a second replaces the first); each lapses at expires_at; the per-resource
-- cap is enforced by the writer. `token` is the signed Knock, kept so an
-- approver can see exactly what was asked.
CREATE TABLE pending_knocks (
    id             TEXT PRIMARY KEY,
    resource_kind  TEXT NOT NULL,
    resource_id    TEXT NOT NULL,
    requester      TEXT NOT NULL,
    relation       TEXT NOT NULL,
    label          TEXT NOT NULL,
    requester_user TEXT,
    renews         TEXT,
    token          TEXT NOT NULL,
    created_at     BIGINT NOT NULL,
    expires_at     BIGINT NOT NULL,
    UNIQUE (resource_kind, resource_id, requester)
);

-- Online offers, and who redeemed each. A redemption is one row per
-- (offer, redeemer key), so redeeming twice is idempotent and max_uses counts
-- distinct keys.
CREATE TABLE offers (
    jti           TEXT PRIMARY KEY,
    resource_kind TEXT NOT NULL,
    resource_id   TEXT NOT NULL,
    relation      TEXT NOT NULL,
    created_by    TEXT NOT NULL,
    max_uses      BIGINT NOT NULL CHECK (max_uses > 0),
    created_at    BIGINT NOT NULL,
    exp           BIGINT NOT NULL
);

CREATE TABLE offer_redemptions (
    offer_jti   TEXT NOT NULL REFERENCES offers (jti),
    redeemer    TEXT NOT NULL,
    redeemed_at BIGINT NOT NULL,
    PRIMARY KEY (offer_jti, redeemer)
);

-- The outcome of every admission by jti (an uploaded Admit's, or the one an
-- online admit mints), so uploads are idempotent per jti: accepted with the
-- tuple it wrote, or refused with why.
CREATE TABLE admissions (
    jti          TEXT PRIMARY KEY,
    ownership_id TEXT,
    refusal      TEXT,
    recorded_at  BIGINT NOT NULL,
    CHECK ((ownership_id IS NULL) <> (refusal IS NULL))
);
