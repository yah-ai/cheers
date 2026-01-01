-- Service-principal records + their JWKS signing keys. Backs the
-- ServicePrincipalStore trait (cheers-server::service_principal). See
-- .yah/docs/working/mcp-auth-and-ownership.md §Service principal bootstrap.
--
-- Two tables, normalised one-to-many: one principal row per `svc:<id>`, many
-- signing-key rows per principal during a rotation window (one Active + zero
-- or more Retiring). The authority layer (cheers_server::ServicePrincipalAuthority)
-- mediates the lifecycle; CHECK constraints here are the suspenders.

CREATE TABLE service_principals (
    id          TEXT PRIMARY KEY,
    status      TEXT NOT NULL,
    created_at  BIGINT NOT NULL,
    CHECK (id LIKE 'svc:%'),
    CHECK (status IN ('active', 'revoked'))
);

-- Signing keys (PASETO V4.public / Ed25519). `public_key` is the raw 32-byte
-- pubkey; the wire shape (JWKS publication, R020-F11) base64url-encodes it,
-- but at the storage layer we keep raw bytes — the gotcha in the ticket.
--
-- `retire_at` invariant: NULL iff status='active'. The Rust authority layer
-- preserves this; the CHECK guards against a direct INSERT/UPDATE breaking it.
CREATE TABLE service_principal_keys (
    kid             TEXT PRIMARY KEY,
    principal_id    TEXT NOT NULL REFERENCES service_principals(id) ON DELETE CASCADE,
    public_key      BYTEA NOT NULL,
    status          TEXT NOT NULL,
    created_at      BIGINT NOT NULL,
    retire_at       BIGINT,
    CHECK (status IN ('active', 'retiring')),
    CHECK (
        (status = 'active'   AND retire_at IS NULL) OR
        (status = 'retiring' AND retire_at IS NOT NULL)
    )
);

-- list_signing_keys hot path filters by principal_id; the JWKS publication
-- path filters by status='active'. Partial index keeps the active set hot.
CREATE INDEX ix_spk_principal_active
    ON service_principal_keys (principal_id)
    WHERE status = 'active';
