<!--
@yah:ticket(R020-S1, "Decide MCP wire envelope: PASETO v4.public vs JWT/Ed25519")
@yah:assignee(agent:claude)
@yah:at(2026-06-04T01:34:57Z)
@yah:kind(spike)
@yah:status(review)
@yah:phase(P0)
@yah:parent(R020)
@yah:next("Write decision into mcp-auth-and-ownership.md §Wire envelope (replace the open question with the chosen envelope + 2-line rationale).")
@yah:next("Coordinate with yah/W159 — constable links cheers-verify; whatever envelope cheers mints is what constable verifies.")
@yah:verify("Open question in §Wire envelope is replaced by a decision line in the doc.")
@yah:verify("Decision propagated to W159 (yah workspace) before any P2 mint-path ticket starts.")
@arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
@yah:handoff("Verify item #2 (W159 propagation in the yah workspace) is OUT OF REACH from this cheers-side session — needs a yah-side agent to add 'verifier expects v4.public.* tokens' to W159 / R426. Flagged in §Wire envelope and a hard gate before R020-F6/F7/F8 claim. User: please coordinate with yah-side OR confirm the cheers-side write alone is enough to sign off.")
@yah:next("Sign off → archive R020-S1. Foundation tickets (R020-F2/F3/F4/F5) unblocked. Mint-path tickets (R020-F6/F7/F8) wait on W159 propagation.")
-->

<!-- @yah:covered-by(R020, status=open, 2026-06-03) -->

# MCP auth and ownership — producer spec

**Status:** proposal (2026-06-03). Paired with the yah-side consumer spec at
`.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md` in the yah
workspace.

**Driver:** yah introduces JWT-bounded MCP boundaries — camp ↔ camp on a
shared warden, camp ↔ warden control plane, camp ↔ sage / hosted cheers /
other environments. Verification is local on constable's host (workerd-
pattern, no per-call cheers round-trip). This doc pins what cheers *produces*
to make that work: the JWT shape, the ownership table, the principal kinds,
the discovery endpoints, and the service-principal install / rotation flows.

## Relationship to `edge-verifiable-auth.md`

These are two distinct boundary classes, both consuming the same crate split:

| Doc | Boundary | Verifier | Lifetime |
|---|---|---|---|
| `edge-verifiable-auth.md` | session — browser/native ↔ origin | CF edge worker | short-TTL access + long refresh |
| **this doc** | MCP — camp ↔ camp/warden/sage | constable (camp/warden host) | short-TTL per call, ownership embedded |

Both rely on **R019's crate split** (`cheers-server` mints, `cheers-verify`
verifies). The asymmetric public verifier in `cheers-verify` is what
constable links against — same property as the edge worker: verify-only by
dependency DAG, cannot mint by construction. MCP-call tokens are
`PasetoV4Public` (see §Wire envelope for the rationale) signed with the
same `cheers-server` secret-key path as session access tokens; verifying
them is the same code path on the consumer side.

## Principal kinds

Today `cheers-core::User` is the only principal. MCP auth needs three:

| Kind | `sub` claim | Credential | Lifetime | Issued by |
|---|---|---|---|---|
| `user` | `user:<id>` | passkey (existing) | indefinite | self-registration via providers |
| `service` | `svc:<id>` | install-time keypair | 1–2 years, `--rotate` | `/admin/service-principals` (operator-scoped) |
| `camp` | `camp:<id>` (`bound_to: user:<U>`) | bootstrap delegation signed by the bound user | revocable, refresh-rotated | `/admin/camps/bootstrap` (user passkey + warden RPC) |

Principal record (shape — names are illustrative; pick the canonical form
when implementing):

```
Principal {
  id,
  kind: user | service | camp,
  bound_to?: PrincipalId,        // camp principals name their user
  status: active | revoked,
  created_at,
}
```

Why three kinds rather than one with a `kind` column on `User`:

- Distinct audit trails. "Camp X took this action" vs. "user U took this
  action" must be unambiguously distinguishable in the ownership and audit
  tables (yah/W159 §Service principals — non-human cheers identities).
- Distinct revocation cascades. Revoking a user revokes all camps `bound_to`
  that user; revoking a camp does not touch its user.
- Distinct grant constraints. `ownership:write` is grantable to `service`
  only; cheers's grant API rejects `(principal_kind=user, scope=ownership:write)`
  at write time.

## JWT claim schema (the wire contract)

Verbatim with yah/W159 §The wire — three layers of validation. Required:

```
iss   = ${cheers_issuer}
aud   = <resource URI — the constable/sage the call targets>
exp   = short TTL (see §TTLs)
iat
jti
sub   = "user:<id>" | "svc:<id>" | "camp:<id>"
scope = ["cloud:deploy", "cloud:read", ...]   // verbatim list, NO wildcards
```

Conditional:

```
act           = { "sub": "agent:<variant>" }   // RFC 8693, user-acted-on-by-agent
camp_id       = "<id>"                          // call context — which camp the action is scoped to
owns          = { "service": ["svc-abc", ...], "arch_doc": [...] }   // embedded ownership
auth_strength = "bootstrap" | "user-fresh"      // how the camp's identity was last asserted
```

Notes:

- **`owns` is the embedded-ownership claim** (yah/W159 §Layer 2). Cheers reads
  the ownership table at mint time and bakes the list in. Constable checks
  resource membership locally — no per-call cheers round trip.
- **`act` carries the agent variant**, not a principal of its own. The agent
  is never the primary `sub`; it appears only as the actor on a user's behalf.
- **`auth_strength`** is set by the mint path: `bootstrap` for tokens minted
  off a camp's long-lived bootstrap credential (autonomous ops); `user-fresh`
  for tokens minted within ~N minutes of a fresh passkey assertion (sensitive
  ops). Constable / downstream services MAY require `user-fresh` for specific
  operations (mirrors yah/W127's elevation pattern).

## Scope vocabulary and composition rules

Mirror yah/W159 §Scope vocabulary verbatim. Today's vocabulary:

```
arch:read     arch:write
board:read    board:write
camp:read     camp:admin
cloud:read    cloud:deploy    cloud:destroy
party:read    party:write
subagent:spawn  subagent:control
ownership:write    audit:write       // service-only
audit:read                            // for centralized querying (W127)
```

Composition rules cheers enforces at grant time and at mint time (per yah/W159
§Composition rules):

1. **No wildcards on the wire.** Scope claim is a JSON array of literal
   strings; `cloud:*` is rejected.
2. **Role bundles expand at mint.** Cheers's UI grants named bundles
   (`"camp-operator"`, `"deploy-admin"`); at mint, cheers expands the bundle
   into the explicit scope list before signing. The wire never sees the
   bundle name — only the expansion. Bundle changes therefore propagate on
   next token mint, not on next grant rewrite.
3. **`<category>:admin` is distinct.** Granting `camp:admin` does NOT imply
   `camp:read` or `camp:write` — they must be in the same grant or a
   separate one. Constable does exact-match against the token's scope list.
4. **`ownership:write` is `kind=service` only.** Grant API rejects
   `(principal_kind=user, scope=ownership:write)`. Same for `audit:write`.
5. **`aud`-scoping is mandatory.** Cheers refuses to mint a token whose `aud`
   the principal isn't entitled to (membership check at mint).

## Ownership table

Generic `principal × resource × kind` shape so cheers doesn't grow a per-kind
table for every new resource type yah adds.

```sql
CREATE TABLE ownership (
  id              BLOB PRIMARY KEY,            -- ULID
  principal_id    TEXT NOT NULL,               -- the principal that holds the relationship
  resource_kind   TEXT NOT NULL,               -- 'service' | 'arch_doc' | 'camp' | ...
  resource_id     TEXT NOT NULL,
  relationship    TEXT NOT NULL,               -- 'owns' | 'member' | ...
  granted_by      TEXT NOT NULL,               -- ALWAYS a service principal: 'svc:<id>'
  on_behalf_of    TEXT,                        -- the human who triggered the grant: 'user:<id>' (null for self-grants)
  granted_at      INTEGER NOT NULL,
  revoked_at      INTEGER,
  CHECK (granted_by LIKE 'svc:%'),
  CHECK (on_behalf_of IS NULL OR on_behalf_of LIKE 'user:%')
);

CREATE INDEX ix_ownership_principal ON ownership(principal_id, resource_kind, resource_id) WHERE revoked_at IS NULL;
CREATE INDEX ix_ownership_on_behalf_of ON ownership(on_behalf_of) WHERE revoked_at IS NULL;
```

The `CHECK` constraints encode the invariants yah/W159 §Service principals
calls out: humans never appear in `granted_by`; services never appear in
`on_behalf_of`. A row violating either is a bug.

Writes are reachable only via:

- `POST /ownership` with a token bearing `ownership:write` (warden only). The
  caller's `sub` becomes `granted_by`; the call body supplies `on_behalf_of`.
- `DELETE /ownership/<id>` with same auth — sets `revoked_at`, does not hard-
  delete.
- Cascading revoke: revoking a user-principal sweeps `revoked_at` across rows
  with that `on_behalf_of`. (Cheaper than per-call freshness checks; matches
  the staleness budget yah accepts on access tokens.)

`ownership_version` (yah/W159 §Layer 3) is **deferred in v1**. When added, it
becomes a monotonic counter incremented on every `ownership` mutation, served
from a small `GET /ownership/version` endpoint, and embedded as a token claim.

## Mint flows

Three paths into the mint:

### 1. User-initiated (passkey-fresh)

Same as existing edge-verifiable-auth.md flow plus the MCP shape:

1. User authenticates via passkey ceremony (existing).
2. Cheers looks up the user's camp memberships + active grants.
3. Bundle expansion → explicit scope list.
4. Ownership lookup for `(camp_id, resource_kind)` → `owns` claim.
5. Token signed:
   `{sub: user:<U>, act: {sub: agent:<V>}, camp_id, scope: [...], owns: {...}, auth_strength: "user-fresh"}`.

### 2. Bootstrapped camp (autonomous)

For warden-hosted camps operating without a live user session:

1. Camp's bootstrap credential (provisioned at camp provision time — see
   §Camp bootstrap below) presents itself to cheers.
2. Cheers verifies the credential, looks up the camp's grants + owns.
3. Token signed:
   `{sub: camp:<C>, camp_id: <C>, scope: [...], owns: {...}, auth_strength: "bootstrap"}`.

Per yah/W159 §Local desktop vs remote camp option 1 (bootstrap-bound,
recommended for v1).

### 3. Token exchange — multi-player camp daemons (RFC 8693)

When a camp daemon hosts multiple human passkey sessions and needs to attribute
outbound calls to the *human* who originated the work, not to the camp:

```
POST /token
  grant_type        = urn:ietf:params:oauth:grant-type:token-exchange
  subject_token     = <camp bootstrap credential>
  subject_token_type= urn:ietf:params:oauth:token-type:jwt   // or paseto-flavored equivalent
  actor_token       = <human's session token>
  actor_token_type  = ...
  audience          = <target resource URI>
  scope             = "cloud:deploy cloud:read"               // intersected against both principals' grants
```

Returns: `{sub: user:<U>, act: {sub: agent:<V>}, camp_id: <C>, scope: [...intersection...], owns: {...},
auth_strength: "user-fresh"}`. Short TTL (≤ access-token TTL).

This is the only path that *crosses principals* — the user authenticates
locally, the camp is the bearer, the resulting token attributes to the user
with the camp as context. RFC 8693 vocabulary; same envelope as everything
else.

## Service principal bootstrap

Warden's service principal is provisioned out-of-band at warden install:

1. Operator runs the warden install flow (parallel to `crates/yah/almanac/src/receiver.rs`'s
   operator-key seed in yah).
2. Install flow presents the operator's passkey to cheers and calls
   `POST /admin/service-principals` with `{kind: "service", desired_id, grants: [...]}`. The
   grants typically include `ownership:write` and `audit:write`.
3. Cheers:
   - allocates the principal record,
   - generates an **Ed25519 keypair** for the principal (cheers retains the public key),
   - returns the secret half **once**, plus the principal record.
4. Warden writes `{principal_id, ed25519_secret}` to its config dir (mode 0600).
   Warden mints its own short-lived tokens from this keypair, signing tokens
   whose `sub: svc:warden-<id>`, `aud: <call target>`, `scope: [..., "ownership:write"]`.
   Cheers verifies these on receipt at `POST /ownership` etc.

Lean toward Ed25519-keypair over client-credentials-style fetch because:

- Warden can operate when cheers's API is briefly unreachable (mints its own
  tokens; downstream constable verifies via JWKS that includes warden's
  pubkey, no cheers call needed).
- One uniform "verify with public key" path on the consumer side (constable
  has cheers's pubkey *and* warden's pubkey, both via the JWKS endpoint).

Rotation: `warden install --rotate` registers a fresh keypair; cheers keeps
the old keypair active for `service_overlap_window` (default 24h) so in-
flight tokens still verify; after the window, cheers drops the old key from
the JWKS.

## Camp bootstrap (provision-time delegation)

When warden provisions a camp on behalf of user U:

1. Warden requests a camp principal:
   `POST /admin/camps/bootstrap` with `{bound_to: user:<U>, desired_id, initial_grants: [...]}`.
   Authenticated as warden's service principal; the user U's delegation
   (signed by U's local cheers daemon or mobile app via a QR-pair flow, per
   yah/W122) is included in the body.
2. Cheers verifies the user-signed delegation and warden's identity, then:
   - allocates the camp principal record with `bound_to: user:<U>`,
   - issues a long-lived refresh credential bound to the camp,
   - returns the credential to warden (warden stores it alongside the camp's
     runtime state).
3. The camp uses this credential to request short-TTL access tokens (mint
   flow #2 above). The user's delegation is the auditable "user U authorized
   camp C" record — cheers retains it.

Revocation:
- Revoking U cascades to all camps `bound_to: U`.
- Revoking C alone does NOT touch U.

## JWKS publication

```
GET ${issuer}/.well-known/jwks.json
  Cache-Control: max-age=300
  ETag: "..."
```

The JWKS includes:

- Cheers's signing key(s) — current + outgoing during rotation.
- Service-principal public keys — warden's pubkey lives here so constable
  can verify warden-minted tokens without a separate fetch path.

Key rotation:

- New key generated, added to JWKS alongside the old.
- 24–72h overlap window (configurable per key kind). During the window, both
  keys are in the JWKS; cheers mints with the new key only.
- After the window, the old key is dropped from the JWKS.

`kid` is the rotation handle. Constable matches by `kid` and falls back to a
one-shot out-of-band refresh (rate-limited 1/sec on the constable side) if a
`kid` arrives that's not in its cache — yah/W159 §Constable startup and JWKS
lifecycle.

## Discovery — well-known endpoints

```
GET ${issuer}/.well-known/openid-configuration
```

Standard OIDC discovery shape. Key fields:

```json
{
  "issuer":                         "${issuer}",
  "jwks_uri":                       "${issuer}/.well-known/jwks.json",
  "token_endpoint":                 "${issuer}/token",
  "scopes_supported":               ["arch:read", ...],
  "grant_types_supported":          ["urn:ietf:params:oauth:grant-type:token-exchange", "passkey", ...],
  "subject_types_supported":        ["user", "service", "camp"]
}
```

Yah's constable serves its own `${constable}/.well-known/oauth-protected-resource`
that points back at cheers's issuer; that's the discovery hop MCP clients
follow to find cheers.

## Audit ingest

```
POST ${issuer}/audit/ingest
  Authorization: Bearer <constable's service-principal token; scope=audit:write>
  Content-Type: application/json
  Body: [<record>, <record>, ...]
```

Record shape (yah/W159 §Audit journal — who did what, where it lives):

```
{ at, sub, act, camp_id, aud, method, scope, result, request_id }
```

Cheers appends to a centralized audit table. Failed forwards bubble back as
4xx/5xx; constable's local JSONL is the durable copy and retries with
bounded backoff. Cheers's responsibility ends at "accepted and durable on
cheers's side."

Reads:

- `GET /audit/by-on-behalf-of/<user>?since=...&method-prefix=...` — paged. The
  query shape yah/W127's "who deployed what" view consumes.
- Authorization: `audit:read` (granted to W127-dashboard service principal
  and to the user themselves for self-queries).

## Wire envelope

**Decision (R020-S1, 2026-06-03): PASETO v4.public.**

Same envelope as `edge-verifiable-auth.md`'s session tokens. MCP-call tokens
are minted by `cheers-server`'s `PasetoV4SecretMinter` and verified by
`cheers-verify`'s `PasetoV4PublicVerifier` — the same single verifier
constable already links. No new crypto code, no new verifier audit surface,
one JWKS endpoint covers both boundary classes, and the "edge cannot mint"
crate-split invariant holds for MCP by construction (it's the same DAG).

The runner-up — JWT with Ed25519 — was rejected for v1:

- It would add a JWT library to `cheers-verify` and require explicit `alg`
  pinning to dodge the `alg:none` / RS256↔HS256 confusion footguns. PASETO
  v4.public pins Ed25519 in the format itself.
- The "MCP ecosystem expects JWT" argument doesn't apply to v1's consumer
  set: every consumer (constable, warden, sage, hosted cheers) is
  cheers-aware and links `cheers-verify` already. The OIDC discovery
  endpoint exists for these clients, not arbitrary third-party MCP servers.

When we'd revisit: a v2 driver requiring non-cheers MCP clients to verify
cheers-minted tokens without linking `cheers-verify`. At that point, the
trait split (`TokenMinter` / `TokenVerifier`) makes a JWT sibling additive
— a new minter/verifier pair alongside the PASETO ones — not a rewrite.

**Cross-workspace propagation:** yah-side W159 / R426–R428 must record
"verifier expects `v4.public.*` tokens" before any MCP mint-path ticket
(R020-F6/F7/F8) lands.

## TTLs

| Token | TTL | Refresh |
|---|---|---|
| Access (per MCP call) | 5–15 min | implicit — mint another |
| Bootstrap (camp credential) | long-lived, refresh-rotated | refresh chain per `edge-verifiable-auth.md` §RefreshStore |
| Service-principal keypair | 1–2 years | `--rotate` install flow, 24h overlap |
| JWKS signing key | per-kind rotation, 24–72h overlap | scheduled |

Short access TTL bounds the staleness window for revocations and ownership
changes without per-call cheers lookups. Yah's `ownership_version` backstop
(deferred) is the freshness escape hatch for ops that can't tolerate the TTL
window.

## Implementation hooks

The crate split from R019 covers this work:

- **`cheers-core`** grows the principal-kind enum (`user | service | camp`),
  the principal record type, the MCP claim shapes (`owns`, `camp_id`,
  `act`, `auth_strength`), and the scope vocabulary as a typed enum.
- **`cheers-server`** grows the ownership table writers, the MCP-token mint
  paths (user-initiated, bootstrap, RFC 8693 exchange), service-principal
  admin endpoints, audit-ingest endpoint.
- **`cheers-verify`** grows nothing new for MCP — same verifier path verifies
  MCP-call tokens. Constable consumes `cheers-verify` and works.

That last property is the load-bearing one: **MCP auth on the verifier side
is structurally identical to session auth.** A single asymmetric public
verifier in the crate-split DAG covers both boundary classes.

## Open questions

- ~~**Wire envelope** — PASETO v4.public vs JWT/Ed25519.~~ **Decided
  R020-S1, 2026-06-03: PASETO v4.public.** See §Wire envelope above.
- **Service-principal credential shape** — Ed25519 keypair (warden mints
  short-lived tokens itself) vs. client_credentials (warden fetches per
  token). Lean keypair (above). Decide before bootstrap endpoint lands.
- **Bundle expansion timing** — at grant time (frozen list in DB) vs at mint
  time (re-expanded each call). Lean mint-time so bundle edits propagate on
  next mint. Costs a join per mint; acceptable at SMB scale.
- **`audit:write` scope ownership** — does constable carry its own service
  principal, or does warden's principal also cover audit ingest? Lean
  separate principal — constable on a warden host should NOT inherit
  warden's `ownership:write` capability.
- **Ownership-write authoritativeness during a partition** — if warden writes
  ownership but cheers's centralized ownership table is briefly unreachable,
  warden's local "ownership pending" state needs a reconciler. Inherits the
  same eventual-consistency story as `RevocationReader` in
  `edge-verifiable-auth.md`. Detail when warden's pond shape lands.

## Status

Sequencing relative to existing cheers work:

- **Prerequisite:** R019-F5/F6 — crate split must land before MCP-token mint
  paths can be added to `cheers-server` (otherwise the symmetric codecs leak
  into the verifier path).
- **Foundation work:** principal-kind enum + ownership table schema land in
  `cheers-core` and `cheers-server`. Suggested attachment: extend R019 or
  open a peer relay.
- **Mint paths + admin endpoints:** separate ticket per path (user-passkey,
  bootstrap, RFC 8693).
- **Audit ingest endpoint:** separate ticket, can run in parallel.
- **JWKS publication for service principal pubkeys:** small ticket;
  augments existing JWKS endpoint.

Filed as standalone to avoid presuming the right quest. Slot where it fits.

## Related

- `edge-verifiable-auth.md` — session auth (paired sibling, same crate split,
  same verifier semantics).
- yah workspace: `.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md`
  — the consumer-side spec. Stable F-number cross-references in that doc map
  to board tickets `R426-F*` (P1: verifier core), `R427-F*` / `R427-T*`
  (P2: warden ownership writes), `R428-F*` (P3: multi-player + audit).
- R019 — crate split, sequence-blocker for the mint-path work here.
- R007 — codec foundation; the verify/mint split landed in there originally.
- R008 — refresh rotation; the bootstrap credential's refresh chain piggybacks.
- R018 — `yah_session` cookie + `/account/sessions` — adjacent surface; this
  doc adds MCP-call tokens as a peer to session access tokens.
