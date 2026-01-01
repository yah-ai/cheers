//! The [`SessionAuthority`] origin facade + [`SessionPolicy`] TTL defaults.
//!
//! `SessionAuthority` assembles the origin-tier capabilities into the role that
//! can *create or destroy* sessions. Its edge counterpart,
//! [`EdgeVerifier`](cheers_verify::EdgeVerifier), lives in `cheers-verify` and
//! holds only a [`TokenVerifier`] + a `RevocationReader` — no minter, so it is
//! physically unable to forge sessions. That asymmetry is the whole point of the
//! split: minting power is structurally confined to this crate.
//!
//! A [`SessionPolicy`] carries the TTL defaults (access ≈ minutes, refresh ≈
//! days) so a consumer doesn't have to invent durations — and the short access
//! TTL is the bound on revocation-propagation lag (see
//! `cheers_verify::RevocationReader`).
//!
//! @yah:ticket(R020-F5, "Bundle expansion at mint time (named bundles → explicit scope list)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T01:35:29Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R020)
//! @yah:verify("Integration: grant 'camp-operator' to a user, mint a token, observe the expanded literal scope list on the wire; edit the bundle to remove a scope, re-mint, observe the removal propagates without rewriting the grant.")
//! @yah:assumes("Bundle expansion at mint time (vs at grant time) so bundle edits propagate on next mint. Costs one join per mint — acceptable at SMB scale per doc §Open questions.")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @yah:depends_on(R020-F3)
//! @yah:next("R020-F6/F7 mint paths: after expand_scopes, run validate_grant(kind, scope) per expanded Scope before signing — the defense-in-depth for composition rule 4 (a bundle granted to a User principal must not carry ownership:write through to the wire).")
//! @yah:next("When the persistent ownership/grant store lands (peer of R020-F4), add a PgBundleStore + SqliteBundleStore impl mirroring the MemoryBundleStore shape — same trait, swap the backing map for a table.")
//! @yah:handoff("Landed crates/cheers-server/src/bundles.rs (exported from cheers-server::*): BundleName newtype, ScopeOrBundle enum (the grant-time entry), BundleStore trait, MemoryBundleStore::with_defaults() seeding 'camp-operator' and 'deploy-admin', expand_scopes(store, &[ScopeOrBundle]) -> Result<Vec<Scope>, BundleExpansionError>.")
//! @yah:handoff("Wire-shape invariant is structural, not runtime: McpClaims.scope is Vec<Scope>, Scope::from_str only accepts the closed-vocabulary wire strings, so a BundleName fed in by mistake fails parse — pinned with the expanded_scopes_serialize_as_wire_strings_no_bundle_name test (asserts 'camp-operator' string is absent from the McpClaims JSON and the literal scope list roundtrips).")
//! @yah:handoff("Mint-time propagation pinned by bundle_edit_propagates_on_next_expand_without_rewriting_grant: expand once, store.put() mutates the bundle to drop CloudDestroy, expand AGAIN against the SAME grants vector, observe removal — no grant rewrite needed.")
//! @yah:handoff("Bundles hold literal Scopes only — no nested bundles. Rules out cycles by construction; documented at module top.")
//! @yah:handoff("ScopeOrBundle serializes as externally-tagged JSON ({\"scope\":\"cloud:deploy\"} or {\"bundle\":\"camp-operator\"}) so a grant row can persist + audit + reload without losing the distinction.")
//! @yah:handoff("Default 'camp-operator' / 'deploy-admin' scope contents are illustrative — operator-side choice in production, not a wire contract; called out in MemoryBundleStore::with_defaults docs.")
//! @yah:handoff("Verified GREEN: cargo test -p cheers-core -p cheers-server -p cheers-verify — 10 new bundle tests pass; nothing else regressed.")
//! @yah:handoff("FOLLOW-UP for R020-F6/F7: at mint, after expand_scopes, the caller MUST still run validate_grant(kind, scope) per expanded scope (composition rule 4 — bundle expansion could otherwise let a user-kind grant of a bundle reach ownership:write). This is a mint-path concern, intentionally not bolted into expand_scopes — keeps the helper focused.")
//!
//! @yah:ticket(R020-F6, "Mint path 1: user-initiated MCP token (passkey-fresh, auth_strength=user-fresh)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T01:35:38Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R020)
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @yah:depends_on(R020-S1)
//! @yah:depends_on(R020-F2)
//! @yah:depends_on(R020-F3)
//! @yah:depends_on(R020-F4)
//! @yah:depends_on(R020-F5)
//! @yah:depends_on(R020-T15)
//! @yah:depends_on(R019-F6)
//! @yah:next("JWKS publication (R020-F11) so origin can publish the verify pubkey + edge constable can fetch it. Until then, tests use the in-process PasetoV4PublicVerifier from the same keypair — equivalent property, narrower wiring.")
//! @yah:next("Promote the inline test-only MemOwnershipStore to a pub MemoryOwnershipStore in ownership.rs when R020-F7 (camp bootstrap mint) lands — it'll want the same shape.")
//! @yah:next("GrantStore writes (HTTP grant API): the grant-time validate_grant call belongs there (composition rule (4) is enforced at the grant API per cheers_core::mcp docs; the mint path is defence in depth).")
//! @yah:next("R020-T16 (Bearer/McpClaims middleware in cheers-axum) consumes MintedMcpToken + verify_mcp_at — wire McpMintError::AudNotEntitled → 401/403, WrongPrincipalKind/GrantMisconfigured → 500, Store → 503.")
//! @yah:handoff("Landed crates/cheers-server/src/mcp_authority.rs (exported from cheers-server::*): McpAuthority<B,G,O>{minter:PasetoV4SecretMinter, bundles:B, grants:G, ownership:O, iss, policy} + McpPolicy (default 10 min access TTL, middle of doc's 5–15 min) + MintedMcpToken{token, claims} + McpMintError (AudNotEntitled, WrongPrincipalKind, GrantMisconfigured(GrantError), BundleExpansion, Store, Codec). Generic over B/G/O so the assembled capability set is visible in the type — same shape as SessionAuthority.")
//! @yah:handoff("Landed crates/cheers-server/src/grants.rs: GrantStore trait (list_for(principal, aud) -> Vec<ScopeOrBundle>) + MemoryGrantStore for tests / single-node bootstrap. Empty result = no entitlement; mint MUST reject (composition rule (5), aud-scoping mandatory). Grants store ScopeOrBundle entries verbatim — bundles deferred to mint time per F5 (rule (2)).")
//! @yah:handoff("mint_user_fresh pipeline matches the doc §Mint flows step-for-step: (1) check user.kind == User (WrongPrincipalKind otherwise); (2) grants.list_for(user, aud), empty → AudNotEntitled; (3) expand_scopes(bundles, entries) per F5; (4) validate_grant(user.kind, scope) per expanded scope — defence in depth for rule (4), catches ownership:write smuggled through a bundle BEFORE signing (test: mint_user_fresh_rejects_service_only_scope_smuggled_via_bundle); (5) ownership.list_for_principal(camp:<camp_id>) → rows_to_owns (service/arch_doc named fields + extra spill via F3's forward-compat slot); (6) McpClaims with auth_strength=user-fresh + jti from session::generate_jti (made pub(crate) to share with this module) + iat=now / exp=now+policy.access_ttl; (7) mint_mcp via T15.")
//! @yah:handoff("McpMintError → cheers_core::Error mapping is intentional: Store/Codec stay typed; AudNotEntitled / WrongPrincipalKind / GrantMisconfigured / BundleExpansion::Unknown route through Error::InvalidInput so non-MCP callers still get a sensible umbrella error. HTTP layer (T16/T17) should pattern-match on McpMintError directly for typed status codes (403 / 500 / 503).")
//! @yah:handoff("owns claim is omitted on the wire when empty (covered by McpClaims's skip_serializing_if = Owns::is_empty) — pinned by mint_user_fresh_omits_owns_when_camp_owns_nothing. Constable's local membership check therefore won't see a phantom empty {} that could be mistaken for 'no resources, fail open'.")
//! @yah:handoff("Tests landed: 8 in mcp_authority::tests (edge-roundtrip via verify_mcp_at, bundle-expansion-at-mint propagation, act+camp_id+owns population, owns-omitted-when-empty, AudNotEntitled rejection, WrongPrincipalKind rejection, service-only-scope-via-bundle rejection, error-conversion) + 1 policy default. 3 in grants::tests (missing-key empty, put-then-list, per-aud isolation). Inline MemOwnershipStore in mcp_authority::tests covers what cheers-sqlx persists in pg/sqlite — left inline since promoting to a public memory store is F7-scoped follow-up.")
//! @yah:handoff("Verified GREEN: cargo test -p cheers-server (67 unit + 9 proptest + 2 doctest, up from 49+9+2 — 8 new mcp_authority tests + 3 new grants tests + Mc Policy = 12 new), cargo test -p cheers-core (unchanged), cargo test -p cheers-verify (unchanged), cargo check --workspace --all-features clean.")
//! @yah:handoff("FOLLOW-UP wire to W159: this lands the cheers-side producer of mint path 1; constable's verify-only consumer on yah/R426 already has verify_mcp_at via cheers-verify. No new wire-shape — McpClaims fields unchanged from T15/F3, so no coordinated change required.")
//! @yah:verify("cargo test -p cheers-server (mcp_authority::tests::mint_user_fresh_signs_token_verifiable_at_edge: round-trips through PasetoV4PublicVerifier::verify_mcp_at, asserts auth_strength=user-fresh, jti non-empty, exp=iat+policy.access_ttl).")
//! @yah:verify("cargo test -p cheers-server (mcp_authority::tests::mint_user_fresh_rejects_unentitled_aud: empty grants for (user, aud) → McpMintError::AudNotEntitled BEFORE signing).")
//! @yah:verify("cargo test -p cheers-core && cargo test -p cheers-server && cargo test -p cheers-verify (parent relay smoke — catches regressions in adjacent sub-tickets).")
//!
//! @yah:ticket(R020-F7, "Mint path 2: bootstrapped camp MCP token (auth_strength=bootstrap)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T01:35:45Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R020)
//! @yah:next("Camp presents its bootstrap credential to cheers; verify the credential, fetch the camp's grants + ownership rows, expand bundles, sign with auth_strength=bootstrap.")
//! @yah:next("Sign: { sub: camp:<C>, camp_id: <C>, scope: [...], owns: {...}, auth_strength: 'bootstrap' }. No act claim on this path.")
//! @yah:verify("Mint a token from a camp's bootstrap credential; auth_strength=bootstrap; owns claim reflects ownership table state at mint time.")
//! @yah:verify("Downstream constable accepts the token via cheers-verify with no per-call cheers round trip.")
//! @yah:assumes("Bootstrap-bound model (yah/W159 Local desktop vs remote camp option 1) is the v1 shape — a single bootstrap credential per camp, refresh-rotated.")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @yah:depends_on(R020-S1)
//! @yah:depends_on(R020-F2)
//! @yah:depends_on(R020-F3)
//! @yah:depends_on(R020-F4)
//! @yah:depends_on(R020-F5)
//! @yah:depends_on(R019-F6)
//! @yah:handoff("Landed McpAuthority::mint_bootstrap in crates/cheers-server/src/mcp_authority.rs: same B/G/O capability surface as mint_user_fresh, pipeline matches doc §Mint flows step 2 — (1) reject non-Camp principal (WrongPrincipalKind); (2) grants.list_for(&camp, &aud), empty → AudNotEntitled (composition rule (5)); (3) expand_scopes (R020-F5, rule (2) propagation); (4) validate_grant(Camp, scope) per expanded scope — defence in depth for rule (4), catches ownership:write smuggled through a camp bundle BEFORE signing; (5) ownership.list_for_principal(&camp) → rows_to_owns; (6) McpClaims { sub: camp, camp_id: camp.id (bare, no prefix), owns, auth_strength: Bootstrap, jti, iat, exp } — NO act claim on this path; (7) mint_mcp via T15.")
//! @yah:handoff("Credential verification deliberately UPSTREAM of mint_bootstrap — the function takes an already-verified Camp principal, mirroring mint_user_fresh which takes the user principal after passkey assertion. The HTTP token endpoint that handles credential→mint dispatch is the right home for verifying the bootstrap credential against R008's refresh chain; that's the separate concern T16/F10 or the token-endpoint ticket will pick up.")
//! @yah:handoff("camp_id claim is set to the bare id (no `camp:` prefix) so a consumer doesn't have to re-parse sub. Pinned by mint_bootstrap_signs_token_verifiable_at_edge (asserts claims.camp_id.as_deref() == Some('c-xyz') when sub is camp:c-xyz). When sub is a camp principal the camp_id is always present — bootstrap tokens are always camp-scoped by construction.")
//! @yah:handoff("owns claim is omitted on the wire when empty (skip_serializing_if = Owns::is_empty in McpClaims) — re-pinned independently of F6 by mint_bootstrap_omits_owns_when_camp_owns_nothing (asserts no 'owns' key in JSON, but camp_id is still present). Constable's local membership check won't see a phantom empty {} that could be mistaken for 'no resources, fail open'.")
//! @yah:handoff("7 new tests in mcp_authority::tests (74 total in -p cheers-server up from 67): mint_bootstrap_signs_token_verifiable_at_edge (round-trip via PasetoV4PublicVerifier::verify_mcp_at, auth_strength=Bootstrap, jti non-empty, exp=iat+policy.access_ttl, act is None); mint_bootstrap_owns_reflects_ownership_table_state (seeds service+arch_doc ownership rows on the camp principal, asserts owns claim populated); mint_bootstrap_omits_owns_when_camp_owns_nothing (wire-shape pin); mint_bootstrap_expands_bundles_at_mint_time (rule (2) re-pin on bootstrap path); mint_bootstrap_rejects_non_camp_principal (User and Service both rejected with WrongPrincipalKind); mint_bootstrap_rejects_unentitled_aud (composition rule (5)); mint_bootstrap_rejects_service_only_scope_smuggled_via_bundle (composition rule (4) defence-in-depth on Camp path — bundle containing OwnershipWrite is caught BEFORE signing).")
//! @yah:handoff("No wire-shape change — McpClaims fields unchanged from T15/F3 (sub, camp_id, owns, auth_strength all pre-existed). Yah-side W159/R426 already consumes the same envelope via cheers-verify::verify_mcp_at. No coordinated cross-workspace change required.")
//! @yah:handoff("Verified GREEN: cargo test -p cheers-core (51 + 1 doctest), cargo test -p cheers-server (74 unit + 9 proptest + 2 doctest, up from 67+9+2 = 7 new bootstrap tests), cargo test -p cheers-verify (4).")
//! @yah:next("R020-F8 (mint path 3 — RFC 8693 token-exchange) now has both mint primitives it needs: mint_user_fresh (F6) + mint_bootstrap (F7). The exchange endpoint verifies subject_token (camp bootstrap) AND actor_token (user session), intersects grants from both, and signs a user-fresh claim with the camp as context. Reuse rows_to_owns and the validate_grant defence-in-depth pattern.")
//! @yah:next("Token endpoint / HTTP dispatch (probably under R020-T16 Bearer/McpClaims middleware): the camp's bootstrap credential is presented at the token endpoint, verified against R008's RefreshStore (the refresh chain piggybacks per doc §TTLs), THEN mint_bootstrap is called with the now-verified Camp principal. Credential verification is the endpoint's job, not the mint function's.")
//! @yah:next("When persistent OwnershipStore lands (peer of R020-F4), promote the inline MemOwnershipStore in mcp_authority::tests to a pub MemoryOwnershipStore in ownership.rs — both mint_user_fresh and mint_bootstrap tests want the same shape now.")
//! @yah:verify("cargo test -p cheers-server mcp_authority::tests::mint_bootstrap_signs_token_verifiable_at_edge — round-trips through PasetoV4PublicVerifier::verify_mcp_at, asserts auth_strength=Bootstrap, act=None, camp_id=Some(bare-id), jti non-empty, exp=iat+policy.access_ttl.")
//! @yah:verify("cargo test -p cheers-server mcp_authority::tests::mint_bootstrap_owns_reflects_ownership_table_state — seeds 2 ownership rows under camp principal, mints, asserts owns claim service/arch_doc fields populated from the table.")
//! @yah:verify("cargo test -p cheers-server mcp_authority::tests::mint_bootstrap_rejects_service_only_scope_smuggled_via_bundle — Camp principal granted a bundle that expands to OwnershipWrite → McpMintError::GrantMisconfigured(GrantError::ServiceOnlyScope{scope: OwnershipWrite, kind: Camp}) BEFORE signing.")
//! @yah:verify("cargo test -p cheers-core && cargo test -p cheers-server && cargo test -p cheers-verify (parent relay smoke).")
//!
//! @yah:ticket(R020-F8, "Mint path 3: RFC 8693 token-exchange endpoint (multi-player camp daemons)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T01:35:52Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R020)
//! @yah:next("POST /token with grant_type=urn:ietf:params:oauth:grant-type:token-exchange.")
//! @yah:next("Verify subject_token (camp bootstrap credential) AND actor_token (human session token); intersect both principals' grants against requested scope; reject if intersection is empty for any requested scope.")
//! @yah:next("Sign: { sub: user:<U>, act: { sub: agent:<V> }, camp_id: <C>, scope: […intersection…], owns: {…}, auth_strength: 'user-fresh' }. TTL ≤ access-token TTL.")
//! @yah:verify("Exchange a (camp, user) pair for a token; scope is the intersection (verify by removing a scope from one side and seeing it drop from the result).")
//! @yah:verify("Empty intersection on a requested scope yields invalid_scope per RFC 8693, not a partial token.")
//! @yah:gotcha("This is the ONLY path that crosses principals — user authenticates, camp is the bearer, resulting token attributes to the user with camp as context. Audit must capture both legs.")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @yah:depends_on(R020-F6)
//! @yah:depends_on(R020-F7)
//! @yah:handoff("Landed McpAuthority::mint_token_exchange in crates/cheers-server/src/mcp_authority.rs: same B/G/O capability surface as the other mint paths. Pipeline matches doc §Mint flows step 3 — (1) reject non-User user-slot and non-Camp camp-slot (WrongPrincipalKind); (2) user's grants.list_for(&user, &aud), empty → AudNotEntitled (composition rule (5) on user side); (3) expand + validate_grant(User, _) per scope (defence in depth); (4) camp's grants.list_for(&camp, &aud), empty → AudNotEntitled (composition rule (5) on camp side too — even though sub is user, the camp must also be entitled); (5) expand + validate_grant(Camp, _) per scope; (6) RFC 8693 intersection — for each requested scope: if !user_scopes.contains(s) || !camp_scopes.contains(s) → InvalidScope; (7) ownership.list_for_principal(&camp) → rows_to_owns (camp is the resource context, NOT the user); (8) McpClaims { sub: user, act, camp_id: camp.id (bare), owns from camp, auth_strength: UserFresh, jti, iat, exp }; (9) mint_mcp via T15.")
//! @yah:handoff("Added McpMintError::InvalidScope { scope: Scope, aud: String } variant for the RFC 8693 reject-all-or-nothing case — routes through Error::InvalidInput in the umbrella conversion (existing 'other' arm catches it). HTTP layer should map this to 400 invalid_scope per RFC 8693. To use Scope in the variant, added `Scope` to the cheers_core imports.")
//! @yah:handoff("auth_strength is UserFresh on this path (NOT Bootstrap) — the doc §Mint flows is explicit: 'the user authenticated locally, the camp is the bearer'. The user's session token is the freshness evidence; the camp bootstrap credential is just the HTTP-layer bearer. Pinned by mint_token_exchange_attributes_to_user_with_camp_as_context asserting AuthStrength::UserFresh and sub == user (not camp).")
//! @yah:handoff("owns comes from the CAMP, not the user — the call is scoped to the camp's resources. This is intentionally asymmetric with mint_user_fresh where camp_id is optional; the exchange path always has a camp. Pinned in the success test (asserts owns.service contains the camp's seeded svc-prod, not anything seeded under the user).")
//! @yah:handoff("Credential verification deliberately UPSTREAM, mirroring F6/F7. The function takes already-verified User + Camp principals. The HTTP /token endpoint (likely under T16 or its peer) is the place that decodes subject_token (camp bootstrap) and actor_token (user session) into PrincipalIds before calling mint_token_exchange.")
//! @yah:handoff("All-or-nothing intersection per the doc §Mint flows + the F8 verify: 'Empty intersection on a requested scope yields invalid_scope per RFC 8693, not a partial token.' Tests pin both directions: mint_token_exchange_intersection_drops_scope_one_side_lacks (camp lacks CloudDeploy → InvalidScope) and mint_token_exchange_rejects_scope_user_lacks (user lacks CloudDeploy → InvalidScope).")
//! @yah:handoff("8 new tests in mcp_authority::tests (82 unit total, up from 74): mint_token_exchange_attributes_to_user_with_camp_as_context (edge-roundtrip; sub=user, camp_id=camp, act=agent, owns from camp, auth_strength=UserFresh); mint_token_exchange_intersection_drops_scope_one_side_lacks (camp-narrows-user); mint_token_exchange_rejects_scope_user_lacks (mirror); mint_token_exchange_rejects_wrong_user_kind; mint_token_exchange_rejects_wrong_camp_kind; mint_token_exchange_rejects_unentitled_user; mint_token_exchange_rejects_unentitled_camp; mint_token_exchange_catches_service_only_scope_smuggled_via_camp_bundle (rule (4) defence on camp side).")
//! @yah:handoff("Audit (R020-F13) capture-both-legs concern is satisfied by the result claim shape: sub records the user, camp_id records the camp, act records the agent variant — all three principal identities are in the signed token, so the audit layer can ingest them straight from the verified claim without a side-channel from the /token endpoint.")
//! @yah:handoff("Verified GREEN: cargo test -p cheers-core (51 + 1 doctest), cargo test -p cheers-server (82 unit + 9 proptest + 2 doctest, up from 74+9+2 — 8 new exchange tests), cargo test -p cheers-verify (4), cargo check --workspace --all-features clean.")
//! @yah:next("Mint primitives trilogy (F6 + F7 + F8) is now complete. T16 (Bearer/McpClaims auth middleware in cheers-axum) is the next piece that wires these to HTTP — the /token endpoint dispatches grant_type to mint_user_fresh / mint_bootstrap / mint_token_exchange, the Bearer middleware verifies inbound McpClaims via cheers-verify::verify_mcp_at.")
//! @yah:next("The /token endpoint's RFC 8693 dispatch needs to decode subject_token (camp PASETO bootstrap credential) AND actor_token (user session token). The session-side verification path already exists in cheers-verify for the actor_token; the camp bootstrap credential's refresh chain piggybacks on R008's RefreshStore per doc §TTLs, so reuse RefreshRotator there.")
//! @yah:next("McpMintError::InvalidScope → HTTP 400 invalid_scope in T16/T17's mapping (per RFC 8693 §6.2). The existing mapping table in mcp_authority.rs doc comment (AudNotEntitled → 403, GrantMisconfigured → 500, Store → 503, Codec → 500) should grow this row.")
//! @yah:verify("cargo test -p cheers-server mcp_authority::tests::mint_token_exchange_attributes_to_user_with_camp_as_context — round-trips through PasetoV4PublicVerifier::verify_mcp_at, asserts sub=user, camp_id=camp, act=agent, owns sourced from camp, auth_strength=UserFresh, jti non-empty.")
//! @yah:verify("cargo test -p cheers-server mcp_authority::tests::mint_token_exchange_intersection_drops_scope_one_side_lacks — user has [CloudDeploy, CloudRead], camp has [CloudRead]; requesting CloudRead succeeds, requesting [CloudRead, CloudDeploy] rejects with InvalidScope{scope: CloudDeploy}. Mirror test mint_token_exchange_rejects_scope_user_lacks pins the other direction.")
//! @yah:verify("cargo test -p cheers-server mcp_authority::tests::mint_token_exchange_catches_service_only_scope_smuggled_via_camp_bundle — camp granted a bundle expanding to OwnershipWrite → GrantMisconfigured(ServiceOnlyScope{scope: OwnershipWrite, kind: Camp}) BEFORE intersection.")
//! @yah:verify("cargo test -p cheers-core && cargo test -p cheers-server && cargo test -p cheers-verify (parent relay smoke).")

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use cheers_core::{Claims, DeviceBinding, DeviceId, Error, TokenMinter, UserId};

use crate::refresh::{RefreshRotator, Rotated};
use crate::revocation::RevocationWriter;
use crate::store::{RefreshStore, UserStore};

/// Length of a generated `jti` in bytes (128 bits — uniqueness only, not a
/// secret). base64url-no-pad encodes to 22 chars.
const JTI_BYTES: usize = 16;

/// Generate a fresh `jti` from the OS CSPRNG. Origin-only — the device and edge
/// tiers never mint, so this never compiles into them.
pub(crate) fn generate_jti() -> String {
    let mut bytes = [0u8; JTI_BYTES];
    getrandom::fill(&mut bytes).expect("OS CSPRNG must be available");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// TTL defaults for a session, so consumers don't pick the wrong durations.
///
/// Access tokens are minutes-scale (a stateless token can't be un-minted, so
/// it's kept short — that short window is also the revocation-propagation
/// bound); refresh tokens are days-scale (the stateful, rotatable half).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct SessionPolicy {
    /// Access-token lifetime in seconds. Also the upper bound on how long a
    /// revoked-but-not-yet-propagated access token stays accepted at the edge.
    pub access_ttl_seconds: i64,
    /// Refresh-token lifetime in seconds (applied to root and every successor).
    pub refresh_ttl_seconds: i64,
}

impl SessionPolicy {
    /// 15 minutes — short enough to bound revocation lag, long enough to avoid
    /// rotating on every request.
    pub const DEFAULT_ACCESS_TTL_SECONDS: i64 = 15 * 60;
    /// 30 days.
    pub const DEFAULT_REFRESH_TTL_SECONDS: i64 = 30 * 24 * 60 * 60;

    pub fn new(access_ttl_seconds: i64, refresh_ttl_seconds: i64) -> Self {
        Self {
            access_ttl_seconds,
            refresh_ttl_seconds,
        }
    }

    pub fn with_access_ttl(mut self, seconds: i64) -> Self {
        self.access_ttl_seconds = seconds;
        self
    }

    pub fn with_refresh_ttl(mut self, seconds: i64) -> Self {
        self.refresh_ttl_seconds = seconds;
        self
    }
}

impl Default for SessionPolicy {
    fn default() -> Self {
        Self {
            access_ttl_seconds: Self::DEFAULT_ACCESS_TTL_SECONDS,
            refresh_ttl_seconds: Self::DEFAULT_REFRESH_TTL_SECONDS,
        }
    }
}

/// A freshly established or rotated session: the minted access token (hand to
/// the client as a bearer/cookie), the [`Claims`] it carries (so the caller can
/// read `jti` / expiry without re-verifying), and the refresh token + record.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NewSession {
    /// The signed/encrypted access token string.
    pub access_token: String,
    /// The claims embedded in `access_token`, including the freshly minted `jti`.
    pub claims: Claims,
    /// The refresh token + persisted record (the stateful, rotatable half).
    pub refresh: Rotated,
}

/// Origin facade: everything that can *create or destroy* sessions.
///
/// Holds the four origin-tier capabilities — a [`TokenMinter`], a
/// [`RefreshStore`], a [`UserStore`], and a [`RevocationWriter`] — plus a
/// [`SessionPolicy`]. Generic (not `dyn`) so the assembled capability set is
/// visible in the type; a consumer wires concrete impls (e.g.
/// [`PasetoV4SecretMinter`](crate::codec::PasetoV4SecretMinter) + Warden-backed
/// stores).
pub struct SessionAuthority<M, R, U, W> {
    minter: M,
    refresh: R,
    users: U,
    revoke: W,
    policy: SessionPolicy,
}

impl<M, R, U, W> SessionAuthority<M, R, U, W>
where
    M: TokenMinter + Send + Sync,
    R: RefreshStore,
    U: UserStore,
    W: RevocationWriter,
{
    /// Assemble an authority with the [default policy](SessionPolicy::default).
    pub fn new(minter: M, refresh: R, users: U, revoke: W) -> Self {
        Self {
            minter,
            refresh,
            users,
            revoke,
            policy: SessionPolicy::default(),
        }
    }

    /// Override the TTL policy.
    pub fn with_policy(mut self, policy: SessionPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn policy(&self) -> &SessionPolicy {
        &self.policy
    }

    /// The held [`UserStore`], for device-management reads
    /// ([`list_devices`](UserStore::list_devices)).
    pub fn users(&self) -> &U {
        &self.users
    }

    /// Establish a fresh session: mint a short-TTL access token (with a fresh
    /// `jti`) and start a homed refresh chain for `(sub, device)`.
    pub async fn establish(
        &self,
        sub: UserId,
        device: DeviceId,
        binding: DeviceBinding,
        now: i64,
    ) -> Result<NewSession, Error> {
        let claims = self.mint_access(sub.clone(), device.clone(), binding, now)?;
        let refresh = RefreshRotator::new(&self.refresh, self.policy.refresh_ttl_seconds)
            .mint_root(sub, device, now)
            .await?;
        Ok(NewSession {
            access_token: self.minter.mint(&claims)?,
            claims,
            refresh,
        })
    }

    /// Rotate `presented_refresh` → fresh access token + successor refresh
    /// token. Replay detection / chain revocation are the rotator's
    /// (see [`RefreshRotator::rotate`]). The `binding` is supplied by the caller
    /// because the refresh record doesn't carry it — guide by omission, the
    /// refresh chain is about *which session*, not *how it authenticated*.
    pub async fn rotate(
        &self,
        presented_refresh: &str,
        binding: DeviceBinding,
        now: i64,
    ) -> Result<NewSession, Error> {
        let refresh = RefreshRotator::new(&self.refresh, self.policy.refresh_ttl_seconds)
            .rotate(presented_refresh, now)
            .await?;
        let claims = self.mint_access(
            refresh.record.user_id.clone(),
            refresh.record.device_id.clone(),
            binding,
            now,
        )?;
        Ok(NewSession {
            access_token: self.minter.mint(&claims)?,
            claims,
            refresh,
        })
    }

    /// Revoke a single access token by its `jti` — the immediate, edge-visible
    /// kill (within the propagation window bounded by the access TTL).
    pub async fn revoke_session(&self, jti: &str) -> Result<(), Error> {
        self.revoke.revoke(jti).await?;
        Ok(())
    }

    /// Records device-level revocation intent via the [`UserStore`]. Blocking
    /// *new* sessions also means revoking that device's refresh chains via the
    /// [`RefreshStore`]; killing an *in-flight* access token is
    /// [`revoke_session`](Self::revoke_session). The product owns the
    /// device→chain index that drives the first, so this facade exposes the
    /// store call and the per-jti kill, not a magic "log out everywhere".
    pub async fn revoke_device(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> Result<(), Error> {
        self.users.revoke_device(user_id, device_id).await?;
        Ok(())
    }

    /// Build access-token claims with a fresh `jti` and the policy's access TTL.
    fn mint_access(
        &self,
        sub: UserId,
        device: DeviceId,
        binding: DeviceBinding,
        now: i64,
    ) -> Result<Claims, Error> {
        Ok(
            Claims::new(sub, device, binding, now, now + self.policy.access_ttl_seconds)
                .with_jti(generate_jti()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::PasetoV4SecretMinter;
    use crate::store::{NewUser, ProviderKey, RefreshTokenRecord};
    use cheers_core::{DeviceBinding, StoreError, User};
    use cheers_verify::{EdgeVerifier, PasetoV4PublicVerifier, RevocationReader};
    use async_trait::async_trait;
    use std::collections::{HashMap, HashSet};
    use std::sync::{Arc, Mutex};

    // ---- minimal in-memory capability impls --------------------------------

    #[derive(Default)]
    struct MemRefreshStore(Mutex<HashMap<String, RefreshTokenRecord>>);

    #[async_trait]
    impl RefreshStore for MemRefreshStore {
        async fn put(&self, record: &RefreshTokenRecord) -> Result<(), StoreError> {
            self.0
                .lock()
                .unwrap()
                .insert(record.token.clone(), record.clone());
            Ok(())
        }
        async fn get(&self, token: &str) -> Result<Option<RefreshTokenRecord>, StoreError> {
            Ok(self.0.lock().unwrap().get(token).cloned())
        }
        async fn mark_consumed(&self, token: &str) -> Result<(), StoreError> {
            let mut g = self.0.lock().unwrap();
            g.get_mut(token).ok_or(StoreError::NotFound)?.consumed = true;
            Ok(())
        }
        async fn revoke_chain(&self, chain_id: &str) -> Result<(), StoreError> {
            let mut g = self.0.lock().unwrap();
            for r in g.values_mut() {
                if r.chain_id == chain_id {
                    r.revoked = true;
                }
            }
            Ok(())
        }
    }

    /// A `UserStore` stub — `SessionAuthority` holds one for the management
    /// surface, but `establish`/`rotate` don't touch it.
    #[derive(Default)]
    struct StubUsers {
        revoked: Mutex<Vec<(String, String)>>,
    }

    #[async_trait]
    impl UserStore for StubUsers {
        async fn find_by_provider(
            &self,
            _: &ProviderKey,
            _: &str,
        ) -> Result<Option<User>, StoreError> {
            Ok(None)
        }
        async fn create(&self, _: NewUser) -> Result<User, StoreError> {
            Ok(User::new(UserId::new("u")))
        }
        async fn link_provider(
            &self,
            _: &UserId,
            _: &ProviderKey,
            _: &str,
        ) -> Result<(), StoreError> {
            Ok(())
        }
        async fn list_devices(&self, _: &UserId) -> Result<Vec<DeviceId>, StoreError> {
            Ok(vec![])
        }
        async fn revoke_device(
            &self,
            user_id: &UserId,
            device_id: &DeviceId,
        ) -> Result<(), StoreError> {
            self.revoked
                .lock()
                .unwrap()
                .push((user_id.to_string(), device_id.to_string()));
            Ok(())
        }
    }

    /// Process-local revocation set; clone shares the backing store so an
    /// authority-side writer and an edge-side reader see the same set.
    #[derive(Clone, Default)]
    struct MemRevocations(Arc<Mutex<HashSet<String>>>);

    #[async_trait]
    impl RevocationReader for MemRevocations {
        async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
            Ok(self.0.lock().unwrap().contains(jti))
        }
    }

    #[async_trait]
    impl RevocationWriter for MemRevocations {
        async fn revoke(&self, jti: &str) -> Result<(), StoreError> {
            self.0.lock().unwrap().insert(jti.to_owned());
            Ok(())
        }
    }

    /// Assemble an authority + an edge verifier sharing one revocation set and
    /// one Ed25519 keypair (origin holds the secret minter, edge the public
    /// verifier — the asymmetric, edge-safe shape).
    fn rig() -> (
        SessionAuthority<PasetoV4SecretMinter, MemRefreshStore, StubUsers, MemRevocations>,
        EdgeVerifier<PasetoV4PublicVerifier, MemRevocations>,
        MemRevocations,
    ) {
        let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
        let revocations = MemRevocations::default();
        let authority = SessionAuthority::new(
            minter,
            MemRefreshStore::default(),
            StubUsers::default(),
            revocations.clone(),
        );
        let edge = EdgeVerifier::new(verifier, revocations.clone());
        (authority, edge, revocations)
    }

    #[test]
    fn session_policy_defaults_are_minutes_and_days() {
        let p = SessionPolicy::default();
        assert_eq!(p.access_ttl_seconds, 15 * 60);
        assert_eq!(p.refresh_ttl_seconds, 30 * 24 * 60 * 60);
        // Builder overrides.
        let p = SessionPolicy::default().with_access_ttl(60);
        assert_eq!(p.access_ttl_seconds, 60);
        assert_eq!(p.refresh_ttl_seconds, 30 * 24 * 60 * 60);
    }

    #[test]
    fn establish_mints_access_with_jti_and_starts_refresh_chain() {
        let (authority, edge, _) = rig();
        pollster::block_on(async {
            let s = authority
                .establish(
                    UserId::new("u1"),
                    DeviceId::new("d1"),
                    DeviceBinding::Passkey,
                    1_000,
                )
                .await
                .unwrap();

            // Access token carries a fresh, non-empty jti and the policy TTL.
            assert!(!s.claims.jti.is_empty());
            assert_eq!(s.claims.expires_at, 1_000 + SessionPolicy::DEFAULT_ACCESS_TTL_SECONDS);
            // Refresh root: fresh, unconsumed, days-scale TTL.
            assert!(s.refresh.record.parent.is_none());
            assert!(!s.refresh.record.consumed);
            assert_eq!(
                s.refresh.record.expires_at,
                1_000 + SessionPolicy::DEFAULT_REFRESH_TTL_SECONDS
            );

            // The edge verifies the freshly minted token.
            let back = edge.verify_at(&s.access_token, 1_100).await.unwrap();
            assert_eq!(back.jti, s.claims.jti);
            assert_eq!(back.sub, UserId::new("u1"));
        });
    }

    #[test]
    fn edge_accepts_then_rejects_after_revoke() {
        let (authority, edge, _) = rig();
        pollster::block_on(async {
            let s = authority
                .establish(
                    UserId::new("u1"),
                    DeviceId::new("d1"),
                    DeviceBinding::OidcGoogle,
                    1_000,
                )
                .await
                .unwrap();

            // Accepted before revocation.
            assert!(edge.verify_at(&s.access_token, 1_100).await.is_ok());

            // Origin revokes the jti; the edge (sharing the set) now rejects it
            // even though the signature is still valid and it hasn't expired.
            authority.revoke_session(&s.claims.jti).await.unwrap();
            let err = edge.verify_at(&s.access_token, 1_100).await.unwrap_err();
            assert!(matches!(err, Error::Revoked), "got {err:?}");
        });
    }

    #[test]
    fn edge_rejects_expired_before_consulting_revocation() {
        let (authority, edge, _) = rig();
        pollster::block_on(async {
            let s = authority
                .establish(
                    UserId::new("u1"),
                    DeviceId::new("d1"),
                    DeviceBinding::Passkey,
                    1_000,
                )
                .await
                .unwrap();
            // now == expires_at -> expired (Codec layer), not Revoked.
            let now = 1_000 + SessionPolicy::DEFAULT_ACCESS_TTL_SECONDS;
            let err = edge.verify_at(&s.access_token, now).await.unwrap_err();
            assert!(matches!(err, Error::Codec(_)), "got {err:?}");
        });
    }

    #[test]
    fn rotate_issues_fresh_access_and_successor_refresh() {
        let (authority, edge, _) = rig();
        pollster::block_on(async {
            let first = authority
                .establish(
                    UserId::new("u1"),
                    DeviceId::new("d1"),
                    DeviceBinding::Passkey,
                    1_000,
                )
                .await
                .unwrap();

            let rotated = authority
                .rotate(first.refresh.token.as_str(), DeviceBinding::Passkey, 1_050)
                .await
                .unwrap();

            // Successor refresh links back to the root and shares the chain.
            assert_eq!(
                rotated.refresh.record.parent.as_deref(),
                Some(first.refresh.token.as_str())
            );
            assert_eq!(
                rotated.refresh.record.chain_id,
                first.refresh.record.chain_id
            );
            // Fresh access token with a *different* jti, still edge-verifiable.
            assert_ne!(rotated.claims.jti, first.claims.jti);
            assert_eq!(rotated.claims.sub, UserId::new("u1"));
            assert!(edge.verify_at(&rotated.access_token, 1_100).await.is_ok());
        });
    }

    #[test]
    fn revoke_device_records_intent_through_user_store() {
        let (minter, _verifier) = PasetoV4SecretMinter::generate().unwrap();
        let users = StubUsers::default();
        let authority = SessionAuthority::new(
            minter,
            MemRefreshStore::default(),
            users,
            MemRevocations::default(),
        );
        pollster::block_on(async {
            authority
                .revoke_device(&UserId::new("u1"), &DeviceId::new("d1"))
                .await
                .unwrap();
            let recorded = authority.users().revoked.lock().unwrap().clone();
            assert_eq!(recorded, vec![("u1".to_string(), "d1".to_string())]);
        });
    }
}
