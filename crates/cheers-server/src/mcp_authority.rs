//! The [`McpAuthority`] origin facade for minting MCP-call tokens.
//!
//! Composes the moving parts the doc lays out in `.yah/docs/working/
//! mcp-auth-and-ownership.md` §Mint flows:
//!
//! - [`PasetoV4SecretMinter::mint_mcp`](crate::codec::PasetoV4SecretMinter::mint_mcp)
//!   — the signing primitive (R020-T15, v4.public over Ed25519).
//! - [`GrantStore`](crate::grants::GrantStore) — per-(principal, aud) grant
//!   entries; empty result = no entitlement = mint rejected (composition rule
//!   (5)).
//! - [`BundleStore`](crate::bundles::BundleStore) +
//!   [`expand_scopes`](crate::bundles::expand_scopes) — bundle expansion at
//!   mint time (R020-F5, rule (2)).
//! - [`validate_grant`] — composition rule (4) defence in depth: a bundle
//!   that smuggles a service-only scope into a user grant is caught here
//!   before signing.
//! - [`OwnershipStore`](crate::ownership::OwnershipStore) — the `owns` claim
//!   source of truth, read at mint time and baked into the token (R020-F4 /
//!   W159 §Layer 2).
//!
//! Mirrors the [`SessionAuthority`](crate::session::SessionAuthority) shape:
//! generic over the capability set so the assembled deployment is visible in
//! the type, and the absence of a verifier here keeps mint power confined to
//! this crate (the edge holds
//! [`PasetoV4PublicVerifier`](cheers_verify::PasetoV4PublicVerifier), never a
//! minter).
//!
//! @yah:ticket(R731-F3, "Relationship schema with derived grants — mint walks live tuples through the schema (D2)")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-10-06T23:18:35Z)
//! @yah:phase(P1)
//! @yah:parent(R731)
//! @yah:next("Doc D2. Per resource kind the product declares relations, what each implies, the scopes each unlocks, and which relations a holder may grant and revoke on the same resource (the D4 authority).")
//! @yah:next("GrantStore becomes a derived view of the ownership table. Delete hand-coded impls as consumers move (noisetable PublishGrants). Lean: no direct-scope escape hatch until a consumer needs one.")
//! @yah:next("Decide here: how a machine writer such as yubaba gets grant authority over a resource it just created. Lean a kind-level relation (provisioner on kind service grants owns on any service) over parent relations.")
//! @yah:next("The check stays at mint (TTL at most 1 h); ownership_version stays deferred.")
//! @yah:verify("mint paths derive scopes from tuples through the schema; admin does not imply read unless the schema says so.")
//! @yah:depends_on(R731-F2)
//! @yah:tier(Wizard)
//! @yah:next("F3 DESIGN DECIDED (leader, 2026-10-06), in cheers-core beside ScopeRegistry. (1) Products declare const data: `ResourceSchema { kind, relations: &[RelationDef], kind_relations: &[RelationDef] }` with `RelationDef { name, membership: true, implies: &[&str], scopes: &[Scope], grants: &[&str] }`. (2) `SchemaRegistry::build(&[ResourceSchema], &ScopeRegistry)` validates at startup: every implies/grants target is declared in the same kind, the implies graph is acyclic, every scope is registered, and duplicates are refused. It precomputes each relation's implies-closure. (3) The closure applies to BOTH scopes and grant rights: a holder of admin, where admin implies triager, holds triager, so it gets triager's scopes and grants. Nothing is implied unless the schema says so. (4) Kind-level relations (the yubaba provisioner case) are stored as tuples on the reserved resource_kind `kind` with resource_id = the kind name, e.g. `kind/service#provisioner`. A kind_relation's grants apply to every resource of that kind and its scopes unlock as usual. No parent relations, no wildcard ids.")
//! @yah:gotcha("F3 DERIVATION + AUTHORITY DECIDED (leader). (5) `SchemaGrantStore<O: OwnershipStore>` implements GrantStore: list_for(principal, aud) = the principal's live rows, expanded through the schema closure, scopes filtered by ScopeRegistry::is_valid_at(aud), returned as ScopeOrBundle::Scope. Empty output means the mint rejects, as today. Rows whose resource_kind has no schema are ignored by derivation (camp `owns` rows still serve the owns claim at mcp_authority ~327/610/733). An unknown relation on a known kind is skipped with tracing::warn. (6) No direct-scope escape hatch. Delete MemoryGrantStore (it has no production constructor in cheers or the yah tree; tests seed tuples through a test schema instead). Keep the GrantStore TRAIT: noisetable's PublishGrants implements it until its phase-4 migration. (7) F3 also ships the pure authority check F8 wires into the router: `SchemaRegistry::may_grant(caller_rows, kind, id, relation) -> bool`. It is true iff the caller holds on (kind,id), by closure, a relation whose grants include `relation`, OR holds on (kind, <kind>) a kind_relation whose grants include it. Revoke uses the same rule. Seed tuples are F8's.")
//! @yah:handoff("cheers-core/src/schema.rs (new, re-exported from lib.rs): ResourceSchema{kind,relations,kind_relations}, RelationDef{name,implies,scopes,grants}, SchemaRegistry::build(&[ResourceSchema], &ScopeRegistry) -> Result<_, SchemaError> (refuses reserved kind 'kind', duplicate kind/relation, unknown implies/grants target, implies cycle via 3-colour DFS, unregistered scope) and precomputes per-relation closure (ResolvedRelation{scopes, grants}). lookup(kind,id,rel) -> Lookup::{NoSchema,UnknownRelation,Resolved}. KIND_RESOURCE='kind'; kind_relation grants name the kind's per-resource relations.")
//! @yah:handoff("SchemaRegistry::may_grant<T: RelationTuple>(caller_rows: &[T], kind, id, relation) -> bool lives in cheers-core/src/schema.rs. It takes a RelationTuple trait (not OwnershipRow) because OwnershipRow is in cheers-server; cheers-server/src/ownership.rs implements RelationTuple for OwnershipRow, so F8 calls it with &[OwnershipRow] directly.")
//! @yah:handoff("cheers-server/src/grants.rs: MemoryGrantStore deleted; SchemaGrantStore<O: OwnershipStore>::new(ownership, Arc<SchemaRegistry>, Arc<ScopeRegistry>) implements GrantStore (live rows -> closure -> is_valid_at(aud) -> ScopeOrBundle::Scope, sorted/deduped; NoSchema ignored; UnknownRelation tracing::warn). GrantStore trait kept. cheers-server gained a tracing dep and lib.rs exports SchemaGrantStore.")
//! @yah:handoff("EXTRA: ownership.rs adds blanket `impl OwnershipStore for Arc<T>` so SchemaGrantStore and McpAuthority share one table. mcp_authority.rs rows_to_owns now skips resource_kind 'kind' rows: kind-level tuples are authority, not owned resources, and would otherwise leak into owns.extra['kind'].")
//! @yah:handoff("Tests moved: mcp_authority tests seed scopes as kind/grant#<scope> tuples via a leaked test schema (TestGrants wraps SchemaGrantStore plus a `raw` map that stands in for a hand-coded GrantStore like noisetable's, used only for bundle cases and the unregistered-scope case, which no schema can express). cheers-axum tokens_basic.rs and camps.rs seed tuples through const test schemas. Behaviour changes in 3 tests: derived scopes come back in scope order (2 order asserts updated), and the 'aud with no grant' 403 now checks before any tuple exists, because yah scopes are Audiences::Any so a derived grant is held at every aud.")
//! @yah:verify("cargo test --workspace in oss/cheers: 683 passed / 0 failed / 3 ignored (baseline 652/0/3, measured before the first edit; the delta includes peer F6 tests).")
//! @yah:verify("cheers-core schema tests: admin_does_not_imply_read_unless_declared, implied_relations_carry_their_grants, may_grant_rules (incl. revoked row), may_grant_kind_level, build_refuses_bad_schemas, lookup_distinguishes_no_schema_and_unknown_relation. cheers-server grants::tests cover closure+aud filter, unknown kind/relation ignored, revoked confers nothing, and kind-level scopes.")
//! @yah:handoff("FOLLOW-UP (leader decision): removed Audiences::Any. The enum is now Only(&'static [&'static str]) | BoundAtStartup, and the scopes! arm with no audiences emits BoundAtStartup. ScopeRegistryBuilder::bind_audiences(namespace, auds) binds every BoundAtStartup scope in that namespace; the registry stores the resolved audiences per scope (ScopeRegistry::audiences(scope)), and is_valid_at and validate_grant are exact. build() returns ScopeRegistryError::{Duplicate, Unbound, NoAudiences, UnusedBinding}, replacing DuplicateScope. The UnusedBinding refusal, for a namespace bound but never used, is my own addition: it catches a typo'd namespace.")
//! @yah:handoff("yah_scopes: every scope is BoundAtStartup. registry() is gone, replaced by NAMESPACES (8), builder() (DEFS preloaded, bind per namespace from config) and registry_at(auds) for single-audience issuers and tests. cheers itself constructs no production registry. The only production site is yah app/yah/cli/src/cloud_cheers.rs::token, now bound to its --aud (one issuer serves one consumer). kamaji-bin builds no registry, so the fence held. The yah-tree compile of cloud_cheers.rs is UNVERIFIED: `cargo check -p yah --tests` is blocked by 23 unrelated pre-existing errors in crates/yah/agent-tools/src/board_tools.rs (TicketStatus::Open etc.), none of them in cheers code.")
//! @yah:handoff("Tests: scope.rs unbound_or_empty_or_unused_bindings_fail_build; yah_scopes namespaces_cover_defs_and_unbound_fails and a_scope_is_valid_only_where_its_namespace_was_bound; tokens_basic's 403 test is back to its original shape. There a derived cloud:read tuple exists but is refused at the unbound https://not-granted.test (BOUND_AUDS). Product Only scopes behave as before (scope.rs, mcp.rs pinned test). Every test registry now binds the audiences it mints at.")
//! @yah:verify("cargo test --workspace (oss/cheers) after the audience follow-up: 686 passed / 0 failed / 3 ignored (previous end state 683/0/3).")
//! @yah:verify("Leader re-verify 2026-10-06, after the Audiences::Any removal: cargo test --workspace (oss/cheers) 686 pass / 0 fail / 3 ignored, no build skew; 0 remaining yah_scopes::registry() or Audiences::Any call sites across cheers, kamaji, passway, yubaba and the yah crates/app.")

use std::sync::Arc;

use cheers_core::{
    validate_grant, Actor, AuthStrength, ClientAssertion, CodecError, Error, GrantError,
    McpClaims, Owns, PrincipalId, PrincipalKind, Scope, ScopeRegistry, StoreError, UsedJtiStore,
};
use pasetors::keys::AsymmetricPublicKey;
use pasetors::token::UntrustedToken;
use pasetors::version4::{PublicToken, V4};

use crate::bundles::{expand_scopes, BundleExpansionError, BundleStore};
use crate::codec::PasetoV4SecretMinter;
use crate::grants::GrantStore;
use crate::ownership::{OwnershipRow, OwnershipStore};
use crate::service_principal::{ServicePrincipalStore, SigningKeyStatus};
use crate::session::generate_jti;

/// TTL defaults for an MCP-call token.
///
/// Short by design — per `.yah/docs/working/mcp-auth-and-ownership.md` §TTLs,
/// the 5–15 minute access window is also the propagation bound for
/// revocations and ownership-table edits when no `ownership_version`
/// freshness backstop is in play.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct McpPolicy {
    /// Per-call access-token lifetime in seconds.
    pub access_ttl_seconds: i64,
    /// Lifetime of a user API token when the mint request names none.
    ///
    /// Deliberately **not** session-shaped: a PAT is the credential a CI job
    /// or a headless agent holds, and re-minting it is a human ceremony, so
    /// the minutes-scale access TTL above would make it useless. 90 days is
    /// long enough to not be a weekly chore and short enough that a forgotten
    /// token dies on its own.
    pub api_token_default_ttl_seconds: i64,
    /// Hard ceiling on a user API token's lifetime. A request above it is
    /// rejected ([`McpMintError::TtlOutOfRange`]) rather than clamped —
    /// silently handing back a token that expires sooner than asked is the
    /// kind of surprise that surfaces as a 2am outage.
    pub api_token_max_ttl_seconds: i64,
}

impl McpPolicy {
    /// 10 minutes — middle of the doc's 5–15 min range.
    pub const DEFAULT_ACCESS_TTL_SECONDS: i64 = 10 * 60;
    /// 90 days.
    pub const DEFAULT_API_TOKEN_TTL_SECONDS: i64 = 90 * 24 * 60 * 60;
    /// 365 days.
    pub const MAX_API_TOKEN_TTL_SECONDS: i64 = 365 * 24 * 60 * 60;

    pub fn new(access_ttl_seconds: i64) -> Self {
        Self {
            access_ttl_seconds,
            ..Self::default()
        }
    }

    pub fn with_access_ttl(mut self, seconds: i64) -> Self {
        self.access_ttl_seconds = seconds;
        self
    }

    /// Override both API-token TTL bounds. `default` is what an omitted
    /// `expires_in_secs` resolves to; `max` is the ceiling a named one is
    /// checked against.
    pub fn with_api_token_ttls(mut self, default: i64, max: i64) -> Self {
        self.api_token_default_ttl_seconds = default;
        self.api_token_max_ttl_seconds = max;
        self
    }
}

impl Default for McpPolicy {
    fn default() -> Self {
        Self {
            access_ttl_seconds: Self::DEFAULT_ACCESS_TTL_SECONDS,
            api_token_default_ttl_seconds: Self::DEFAULT_API_TOKEN_TTL_SECONDS,
            api_token_max_ttl_seconds: Self::MAX_API_TOKEN_TTL_SECONDS,
        }
    }
}

/// A freshly-minted MCP-call token plus the [`McpClaims`] it carries.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct MintedMcpToken {
    /// The signed `v4.public.*` token string.
    pub token: String,
    /// The claims embedded in `token`, including the freshly minted `jti`.
    pub claims: McpClaims,
}

/// Why a mint attempt failed before (or after) the signing step.
///
/// Typed so the HTTP layer (R020-T17 routes) can map specific failures to the
/// right status code: `AudNotEntitled` → 403, `GrantMisconfigured` → 500
/// (server-side data bug), `Store` → 503, `Codec` → 500.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum McpMintError {
    /// Composition rule (5) — the principal holds no grant for the requested
    /// `aud`. Per-call rejection, returned before any signing happens.
    #[error("no entitlement: principal '{principal}' has no grant for aud '{aud}'")]
    AudNotEntitled { principal: String, aud: String },
    /// RFC 8693 — a requested scope on a token-exchange is not in the
    /// intersection of both principals' grants for this `aud`. Per the doc
    /// (`§Mint flows` → token exchange), the whole exchange is rejected —
    /// `invalid_scope`, not a partial token. Maps to HTTP 400 `invalid_scope`.
    #[error("requested scope '{scope}' is not granted by both principals for aud '{aud}'")]
    InvalidScope { scope: Scope, aud: String },
    /// The caller passed the wrong principal kind for this mint path — e.g.
    /// `mint_user_fresh` invoked with `svc:` or `camp:` in the `sub` slot.
    /// A programmer-error, not a user-input rejection: surface 500, not 403.
    #[error("mint path expects {expected} principal; got {got}")]
    WrongPrincipalKind {
        expected: PrincipalKind,
        got: PrincipalKind,
    },
    /// [`mint_api_token`](McpAuthority::mint_api_token) was asked for scopes
    /// the principal's grants do not currently expand to. **Every** offender
    /// is named: silently dropping the unheld ones would hand back a token
    /// quietly weaker than the one asked for, which fails later, elsewhere,
    /// as an unexplained 403. Maps to HTTP 400.
    #[error(
        "principal '{principal}' does not hold {} for aud '{aud}'",
        .scopes.iter().map(|s| s.as_wire()).collect::<Vec<_>>().join(", ")
    )]
    UnentitledScopes {
        principal: String,
        scopes: Vec<Scope>,
        aud: String,
    },
    /// A user-API-token mint named an `expires_in_secs` outside
    /// `1..=policy.api_token_max_ttl_seconds`. Rejected, never clamped.
    /// Maps to HTTP 400.
    #[error("requested ttl {requested}s is outside the allowed range 1..={max}s")]
    TtlOutOfRange { requested: i64, max: i64 },
    /// Composition rule (4) defence in depth — bundle expansion produced a
    /// service-only scope for a non-service principal. Indicates a
    /// misconfigured bundle or a grant that should have been rejected at the
    /// grant API; surface as 500.
    #[error(transparent)]
    GrantMisconfigured(#[from] GrantError),
    /// Bundle expansion failed (unknown bundle / store error inside
    /// expansion).
    #[error(transparent)]
    BundleExpansion(#[from] BundleExpansionError),
    /// Underlying store failure (grants / ownership).
    #[error(transparent)]
    Store(#[from] StoreError),
    /// Signing failure inside the codec layer.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// [`mint_service`](McpAuthority::mint_service) was called on an
    /// authority assembled without
    /// [`with_service_assertions`](McpAuthority::with_service_assertions).
    /// A wiring bug; surface 500.
    #[error("service assertions are not configured on this authority")]
    ServiceAssertionsUnconfigured,
    /// The client assertion is not a well-formed PASETO v4.public token, has
    /// no readable footer `kid`, fails signature verification, carries an
    /// undecodable payload, or has an empty `jti`. Maps to 400
    /// `invalid_client`.
    #[error("malformed client assertion: {0}")]
    AssertionMalformed(String),
    /// The footer `kid` names no service-principal key cheers holds.
    #[error("client assertion kid '{0}' is unknown")]
    AssertionUnknownKid(String),
    /// The footer `kid` names a key that has been rotated out (`Retiring`).
    /// Only an ACTIVE key may sign an assertion, even inside the overlap
    /// window that still publishes it.
    #[error("client assertion kid '{0}' is a retired key")]
    AssertionRetiredKey(String),
    /// `iss` or `sub` is not the service principal that owns the signing key
    /// (or `iss != sub`).
    #[error("client assertion names '{iss}'/'{sub}' but kid '{kid}' belongs to '{owner}'")]
    AssertionPrincipalMismatch {
        kid: String,
        owner: PrincipalId,
        iss: PrincipalId,
        sub: PrincipalId,
    },
    /// `aud` is not this deployment's token endpoint URL.
    #[error("client assertion aud '{got}' is not the token endpoint '{expected}'")]
    AssertionBadAudience { got: String, expected: String },
    /// `exp <= now`.
    #[error("client assertion expired at {exp} (now {now})")]
    AssertionExpired { exp: i64, now: i64 },
    /// `exp - iat` exceeds [`ClientAssertion::MAX_LIFETIME_SECONDS`].
    #[error("client assertion lifetime {lifetime}s exceeds the {max}s maximum")]
    AssertionLifetimeTooLong { lifetime: i64, max: i64 },
    /// The assertion's `jti` was already consumed.
    #[error("client assertion jti '{0}' was already used")]
    AssertionReplayed(String),
    /// The used-jti backend failed; the assertion was neither accepted nor
    /// rejected. Surface 503.
    #[error("used-jti store failure: {0}")]
    JtiStore(String),
    /// The principal's relationship-derived scopes for `aud`, intersected
    /// with the request, are empty. Maps to 400 `invalid_scope`.
    #[error("principal '{principal}' holds none of the requested scopes for aud '{aud}'")]
    NoGrantedScopes { principal: String, aud: String },
}

impl From<McpMintError> for Error {
    fn from(e: McpMintError) -> Self {
        match e {
            McpMintError::Store(s) => Error::Store(s),
            McpMintError::Codec(c) => Error::Codec(c),
            McpMintError::BundleExpansion(BundleExpansionError::Store(s)) => Error::Store(s),
            // Structured rejections (AudNotEntitled, WrongPrincipalKind,
            // GrantMisconfigured, BundleExpansion::Unknown) carry a message
            // that's safe to surface; route them through InvalidInput so a
            // caller that doesn't pattern-match on McpMintError still gets a
            // sensible umbrella error.
            other => Error::InvalidInput(other.to_string()),
        }
    }
}

/// Origin facade: everything that can *mint* an MCP-call token.
///
/// Holds the four origin-tier capabilities for the MCP boundary — a
/// [`PasetoV4SecretMinter`], a [`BundleStore`], a [`GrantStore`], and an
/// [`OwnershipStore`] — plus the cheers issuer URL and an [`McpPolicy`].
/// Generic (not `dyn`) so the assembled capability set is visible in the
/// type. The matching edge-side verifier is
/// [`PasetoV4PublicVerifier`](cheers_verify::PasetoV4PublicVerifier) +
/// `verify_mcp_at`; the verify-only consumer (kamaji) never depends on
/// this crate.
pub struct McpAuthority<B, G, O> {
    minter: PasetoV4SecretMinter,
    bundles: B,
    grants: G,
    ownership: O,
    /// The deployment's scope vocabulary. Every scope a mint path is about to
    /// sign runs through [`validate_grant`] against it.
    scopes: Arc<ScopeRegistry>,
    iss: String,
    /// `kid` stamped into every minted token's PASETO footer (R592-B7 wire
    /// convention) — identifies which published key `minter` signs with, so
    /// an edge verifier's JWKS/footer lookup can find the matching pubkey.
    kid: String,
    policy: McpPolicy,
    /// Service-principal key table + used-jti ledger for
    /// [`mint_service`](Self::mint_service). `None` until
    /// [`with_service_assertions`](Self::with_service_assertions).
    service: Option<ServiceAssertions>,
}

/// What [`McpAuthority::mint_service`] needs beyond the user-facing paths.
struct ServiceAssertions {
    keys: Arc<dyn ServicePrincipalStore>,
    used_jtis: Arc<dyn UsedJtiStore>,
}

impl<B, G, O> McpAuthority<B, G, O>
where
    B: BundleStore,
    G: GrantStore,
    O: OwnershipStore,
{
    /// Assemble an authority with the [default policy](McpPolicy::default).
    ///
    /// `kid` is the footer identifier published alongside `minter`'s public
    /// key (e.g. in cheers's JWKS) — every token this authority mints carries
    /// it so a verifier can select the right key.
    pub fn new(
        minter: PasetoV4SecretMinter,
        bundles: B,
        grants: G,
        ownership: O,
        scopes: Arc<ScopeRegistry>,
        iss: impl Into<String>,
        kid: impl Into<String>,
    ) -> Self {
        Self {
            minter,
            bundles,
            grants,
            ownership,
            scopes,
            iss: iss.into(),
            kid: kid.into(),
            policy: McpPolicy::default(),
            service: None,
        }
    }

    /// Override the TTL policy.
    pub fn with_policy(mut self, policy: McpPolicy) -> Self {
        self.policy = policy;
        self
    }

    pub fn policy(&self) -> &McpPolicy {
        &self.policy
    }

    /// Enable [`mint_service`](Self::mint_service): `keys` resolves an
    /// assertion's footer `kid` to a service-principal signing key, and
    /// `used_jtis` consumes each assertion `jti` exactly once.
    pub fn with_service_assertions(
        mut self,
        keys: Arc<dyn ServicePrincipalStore>,
        used_jtis: Arc<dyn UsedJtiStore>,
    ) -> Self {
        self.service = Some(ServiceAssertions { keys, used_jtis });
        self
    }

    /// The URL a client assertion's `aud` must name: `<issuer>/token`.
    pub fn token_endpoint(&self) -> String {
        format!("{}/token", self.iss.trim_end_matches('/'))
    }

    pub fn scopes(&self) -> &ScopeRegistry {
        &self.scopes
    }

    pub fn issuer(&self) -> &str {
        &self.iss
    }

    /// **Mint path 1** — user-initiated, passkey-fresh (R020-F6).
    ///
    /// Returns a token bearing
    /// `{sub: user:<U>, act?, camp_id?, scope: [...], owns: {...}, auth_strength: "user-fresh"}`.
    /// Required inputs:
    ///
    /// - `user`: the authenticated user's principal (kind MUST be
    ///   [`PrincipalKind::User`]).
    /// - `actor`: the optional `act` claim (RFC 8693) — the agent acting on
    ///   the user's behalf. The agent is never the primary `sub`.
    /// - `camp_id`: when set, both populates the `camp_id` claim and is the
    ///   key used to look up the `owns` claim (rows held by
    ///   `camp:<camp_id>`).
    /// - `aud`: the target resource URI for this call. Per composition rule
    ///   (5) the principal MUST hold at least one grant entry for `aud` — an
    ///   empty grant list returns [`McpMintError::AudNotEntitled`] before
    ///   any signing happens.
    /// - `now`: unix seconds. `iat = now`, `exp = now + policy.access_ttl`.
    ///
    /// The pipeline: grants → [`expand_scopes`] → [`validate_grant`] per
    /// scope (rule (4) defence) → ownership lookup → sign with `mint_mcp`.
    pub async fn mint_user_fresh(
        &self,
        user: PrincipalId,
        actor: Option<Actor>,
        camp_id: Option<String>,
        aud: impl Into<String>,
        now: i64,
    ) -> Result<MintedMcpToken, McpMintError> {
        if user.kind != PrincipalKind::User {
            return Err(McpMintError::WrongPrincipalKind {
                expected: PrincipalKind::User,
                got: user.kind,
            });
        }
        let aud = aud.into();

        let entries = self.grants.list_for(&user, &aud).await?;
        if entries.is_empty() {
            return Err(McpMintError::AudNotEntitled {
                principal: user.to_string(),
                aud,
            });
        }

        let scopes = expand_scopes(&self.bundles, &entries).await?;
        for s in &scopes {
            validate_grant(&self.scopes, user.kind, s, &aud)?;
        }

        let owns = match &camp_id {
            Some(id) => {
                let camp_principal = PrincipalId::camp(id);
                let rows = self.ownership.list_for_principal(&camp_principal).await?;
                rows_to_owns(&rows)
            }
            None => Owns::default(),
        };

        let mut claims = McpClaims::new(
            self.iss.clone(),
            aud,
            user,
            now,
            now + self.policy.access_ttl_seconds,
            generate_jti(),
            scopes,
        )
        .with_auth_strength(AuthStrength::UserFresh);
        if let Some(a) = actor {
            claims = claims.with_act(a);
        }
        if let Some(c) = camp_id {
            claims = claims.with_camp_id(c);
        }
        if !owns.is_empty() {
            claims = claims.with_owns(owns);
        }

        let token = self.minter.mint_mcp(&claims, &self.kid)?;
        Ok(MintedMcpToken { token, claims })
    }

    /// **Mint path 3** — a long-lived user API token (PAT), R728-F1.
    ///
    /// The credential a CI job, a script or a headless agent holds so it can
    /// *be* the user without a browser. Returns a token bearing
    /// `{sub: user:<U>, scope: [...], auth_strength: "api-token"}`.
    ///
    /// ## It is the same stack, not a parallel one
    ///
    /// Same signing key, same `jti`, same revocation set the edge already
    /// reads. A PAT differs from a
    /// [`mint_user_fresh`](Self::mint_user_fresh) token in exactly three
    /// claim-level ways — `auth_strength`, a caller-chosen `exp`, and a
    /// possibly-narrower `scope` — so nothing downstream needs a new verify
    /// path to accept one, and a route that must refuse one reads
    /// [`AuthStrength`].
    ///
    /// ## Attenuation is the point
    ///
    /// `requested` is **intersected**, never taken verbatim:
    ///
    /// - The principal's grants for `aud` are looked up and expanded, exactly
    ///   as [`mint_user_fresh`](Self::mint_user_fresh) does — empty ⇒
    ///   [`McpMintError::AudNotEntitled`] before any signing.
    /// - [`validate_grant`] runs over every expanded scope (rule (4) defence)
    ///   *before* signing, so a bundle smuggling a service-only scope into a
    ///   user grant is caught here.
    /// - An empty `requested` means "everything I currently hold for this
    ///   aud" — the effective set, not a wildcard, and it is frozen into the
    ///   token at mint time.
    /// - A requested scope outside the effective set is
    ///   [`McpMintError::UnentitledScopes`] naming every offender, **not** a
    ///   silent drop.
    ///
    /// So a PAT can never be wider than its minter was at mint time. It can
    /// outlive that entitlement — a grant revoked afterwards does not shrink
    /// an already-signed token — which is what the revocation set and the TTL
    /// ceiling are for.
    ///
    /// ## No `owns`, no `camp_id`, no `act`
    ///
    /// Deliberate, and the reason is the TTL. The `owns` claim is a snapshot
    /// of the ownership table read at mint time, and the token's lifetime is
    /// the propagation bound for edits to it (see [`McpPolicy`]) — fine at 10
    /// minutes, a 90-day stale-authorization hole here. A PAT therefore
    /// asserts identity and scope only; a consumer needing per-resource
    /// ownership looks it up live. `act` is absent for a simpler reason: the
    /// user minted this themselves, nobody is acting on their behalf.
    ///
    /// `ttl_seconds`: `None` ⇒ [`McpPolicy::api_token_default_ttl_seconds`].
    /// `Some(n)` outside `1..=api_token_max_ttl_seconds` ⇒
    /// [`McpMintError::TtlOutOfRange`] — rejected, not clamped.
    pub async fn mint_api_token(
        &self,
        user: PrincipalId,
        aud: impl Into<String>,
        requested: &[Scope],
        ttl_seconds: Option<i64>,
        now: i64,
    ) -> Result<MintedMcpToken, McpMintError> {
        if user.kind != PrincipalKind::User {
            return Err(McpMintError::WrongPrincipalKind {
                expected: PrincipalKind::User,
                got: user.kind,
            });
        }
        let aud = aud.into();

        let ttl = self.api_token_ttl(ttl_seconds)?;

        let entries = self.grants.list_for(&user, &aud).await?;
        if entries.is_empty() {
            return Err(McpMintError::AudNotEntitled {
                principal: user.to_string(),
                aud,
            });
        }

        let effective = expand_scopes(&self.bundles, &entries).await?;
        for s in &effective {
            validate_grant(&self.scopes, user.kind, s, &aud)?;
        }

        let scopes = attenuate(requested, effective, &user, &aud)?;

        self.sign_api_token(user, aud, scopes, ttl, now)
    }

    /// **Mint path 3b** — roll a user API token over, R728-F2.
    ///
    /// Backs `POST /me/tokens/{id}/rotate`: the caller presents a credential
    /// they already hold and gets a replacement, so a leaked or ageing PAT can
    /// be replaced *by the token itself* without a browser ceremony. "A
    /// credential must be able to roll itself" is an operator requirement
    /// (2026-09-12), and this is the mint it needs.
    ///
    /// ## `held` is the entire authority ceiling, and the grant table is NOT read
    ///
    /// Note the signature: **not `async`**, because this path performs no
    /// store I/O at all — that absence is the security property, not an
    /// optimization. [`mint_api_token`](Self::mint_api_token) derives the
    /// ceiling from `grants.list_for`; if rotation did the same, a token
    /// minted when the user held `cloud:read` would silently come back
    /// carrying `cloud:destroy` the moment an operator widened the grant.
    /// That would unpick the property
    /// `a_minted_pat_is_frozen_and_does_not_track_later_grant_edits` exists to
    /// pin. So the ceiling here is `held` — the authority the presented
    /// credential *already* carries — and nothing else. A rotation can narrow
    /// and can never widen.
    ///
    /// `requested` empty ⇒ the replacement carries exactly `held`. A requested
    /// scope outside `held` is [`McpMintError::UnentitledScopes`] naming every
    /// offender, the same refusal (and the same 400) as the create path.
    ///
    /// ## Lifetime is refreshed, but still bounded
    ///
    /// The replacement gets a *fresh* TTL from the same policy
    /// ([`McpPolicy::api_token_default_ttl_seconds`], ceiling
    /// [`McpPolicy::api_token_max_ttl_seconds`], out of range rejected rather
    /// than clamped) — rotation is how a long-lived credential stays alive, so
    /// inheriting the old token's remaining life would make it useless. The
    /// ceiling is what keeps that from being indefinite extension: every hop
    /// is bounded by the same policy a first mint is, and the caller can only
    /// ever hold one live token per rotation because the old `jti` is revoked
    /// by the route immediately after.
    ///
    /// [`validate_grant`] still runs over the resulting scopes: a service-only
    /// scope riding inside a user's token is a data bug wherever it came from,
    /// and re-signing it would launder it forward.
    pub fn rotate_api_token(
        &self,
        user: PrincipalId,
        aud: impl Into<String>,
        held: &[Scope],
        requested: &[Scope],
        ttl_seconds: Option<i64>,
        now: i64,
    ) -> Result<MintedMcpToken, McpMintError> {
        if user.kind != PrincipalKind::User {
            return Err(McpMintError::WrongPrincipalKind {
                expected: PrincipalKind::User,
                got: user.kind,
            });
        }
        let aud = aud.into();
        let ttl = self.api_token_ttl(ttl_seconds)?;

        let mut ceiling: Vec<Scope> = Vec::with_capacity(held.len());
        for s in held {
            validate_grant(&self.scopes, user.kind, s, &aud)?;
            if !ceiling.contains(s) {
                ceiling.push(s.clone());
            }
        }

        let scopes = attenuate(requested, ceiling, &user, &aud)?;

        self.sign_api_token(user, aud, scopes, ttl, now)
    }

    /// `None` ⇒ the policy default; `Some(n)` outside
    /// `1..=api_token_max_ttl_seconds` ⇒ [`McpMintError::TtlOutOfRange`].
    /// Rejected, never clamped — shared by both API-token mint paths so a
    /// rotation cannot outlive the ceiling a first mint is held to.
    fn api_token_ttl(&self, ttl_seconds: Option<i64>) -> Result<i64, McpMintError> {
        match ttl_seconds {
            None => Ok(self.policy.api_token_default_ttl_seconds),
            Some(n) if n >= 1 && n <= self.policy.api_token_max_ttl_seconds => Ok(n),
            Some(n) => Err(McpMintError::TtlOutOfRange {
                requested: n,
                max: self.policy.api_token_max_ttl_seconds,
            }),
        }
    }

    /// The last two steps both API-token paths share: build the claim with
    /// `auth_strength: "api-token"` and sign it. Neither path adds `owns`,
    /// `camp_id` or `act` — see [`mint_api_token`](Self::mint_api_token) for
    /// why.
    fn sign_api_token(
        &self,
        user: PrincipalId,
        aud: String,
        scopes: Vec<Scope>,
        ttl: i64,
        now: i64,
    ) -> Result<MintedMcpToken, McpMintError> {
        let claims = McpClaims::new(
            self.iss.clone(),
            aud,
            user,
            now,
            now + ttl,
            generate_jti(),
            scopes,
        )
        .with_auth_strength(AuthStrength::ApiToken);

        let token = self.minter.mint_mcp(&claims, &self.kid)?;
        Ok(MintedMcpToken { token, claims })
    }

    /// **Mint path 2** — bootstrapped camp, autonomous (R020-F7).
    ///
    /// For yubaba-hosted camps operating without a live user session: the
    /// camp's bootstrap credential authenticates upstream of this call, and
    /// the verified camp principal is what arrives here. Returns a token
    /// bearing
    /// `{sub: camp:<C>, camp_id: <C>, scope: [...], owns: {...}, auth_strength: "bootstrap"}`
    /// — note **no `act` claim** on this path, the camp itself is the
    /// principal (not a user acted-on-by an agent).
    ///
    /// Required inputs:
    ///
    /// - `camp`: the authenticated camp's principal (kind MUST be
    ///   [`PrincipalKind::Camp`]). `camp_id` on the resulting claim is the
    ///   bare id (sans `camp:` prefix), so a consumer doesn't have to re-
    ///   parse `sub` to learn it.
    /// - `aud`: the target resource URI for this call. Per composition rule
    ///   (5) the camp MUST hold at least one grant entry for `aud` — an empty
    ///   grant list returns [`McpMintError::AudNotEntitled`] before signing.
    /// - `now`: unix seconds. `iat = now`, `exp = now + policy.access_ttl`.
    ///
    /// Same pipeline as [`mint_user_fresh`](Self::mint_user_fresh): grants →
    /// [`expand_scopes`] → [`validate_grant`] per scope (rule (4) defence —
    /// catches a bundle that smuggles `audit:write` into a camp grant) →
    /// ownership lookup → sign with `mint_mcp`.
    pub async fn mint_bootstrap(
        &self,
        camp: PrincipalId,
        aud: impl Into<String>,
        now: i64,
    ) -> Result<MintedMcpToken, McpMintError> {
        if camp.kind != PrincipalKind::Camp {
            return Err(McpMintError::WrongPrincipalKind {
                expected: PrincipalKind::Camp,
                got: camp.kind,
            });
        }
        let aud = aud.into();

        let entries = self.grants.list_for(&camp, &aud).await?;
        if entries.is_empty() {
            return Err(McpMintError::AudNotEntitled {
                principal: camp.to_string(),
                aud,
            });
        }

        let scopes = expand_scopes(&self.bundles, &entries).await?;
        for s in &scopes {
            validate_grant(&self.scopes, camp.kind, s, &aud)?;
        }

        let rows = self.ownership.list_for_principal(&camp).await?;
        let owns = rows_to_owns(&rows);

        let camp_id = camp.id.clone();
        let mut claims = McpClaims::new(
            self.iss.clone(),
            aud,
            camp,
            now,
            now + self.policy.access_ttl_seconds,
            generate_jti(),
            scopes,
        )
        .with_camp_id(camp_id)
        .with_auth_strength(AuthStrength::Bootstrap);
        if !owns.is_empty() {
            claims = claims.with_owns(owns);
        }

        let token = self.minter.mint_mcp(&claims, &self.kid)?;
        Ok(MintedMcpToken { token, claims })
    }

    /// **Mint path 3** — RFC 8693 token-exchange (R020-F8).
    ///
    /// The ONLY path that crosses principals: a multi-player camp daemon
    /// (`subject_token` = camp bootstrap credential) presents a human's
    /// session token (`actor_token` = user's session) and asks for a token
    /// attributed to the *human*, with the camp as call context. The result
    /// looks like a `mint_user_fresh` token — same `auth_strength=user-fresh`
    /// because the user authenticated locally — but the camp's grants
    /// constrain it.
    ///
    /// Inputs (already-verified principals — credential checks live at the
    /// HTTP `/token` endpoint, same way passkey assertion sits upstream of
    /// [`mint_user_fresh`](Self::mint_user_fresh)):
    ///
    /// - `user`: the verified user from `actor_token` (kind MUST be
    ///   [`PrincipalKind::User`]).
    /// - `camp`: the verified camp from `subject_token` (kind MUST be
    ///   [`PrincipalKind::Camp`]).
    /// - `actor`: the optional `act` claim — the agent variant acting on the
    ///   user's behalf (RFC 8693).
    /// - `aud`: target resource URI. BOTH principals must hold a grant for
    ///   it (composition rule (5) applies per side).
    /// - `requested_scope`: the scopes the exchange asks for. EVERY entry
    ///   must be in the intersection of the user's expanded-grant scopes AND
    ///   the camp's expanded-grant scopes for this aud. A requested scope
    ///   outside the intersection rejects the whole exchange with
    ///   [`McpMintError::InvalidScope`] — no partial token (RFC 8693 / doc
    ///   §Mint flows).
    /// - `now`: unix seconds. `iat = now`, `exp = now + policy.access_ttl`.
    ///
    /// Result claim:
    /// `{sub: user:<U>, act: {sub: agent:<V>}?, camp_id: <C>, scope: [...requested...], owns: {...}, auth_strength: "user-fresh"}`.
    /// `owns` is the CAMP's ownership (not the user's) — the call is scoped
    /// to the camp's resources. Audit (R020-F13) captures both legs from the
    /// resulting claim plus the endpoint's request context.
    pub async fn mint_token_exchange(
        &self,
        user: PrincipalId,
        camp: PrincipalId,
        actor: Option<Actor>,
        aud: impl Into<String>,
        requested_scope: Vec<Scope>,
        now: i64,
    ) -> Result<MintedMcpToken, McpMintError> {
        if user.kind != PrincipalKind::User {
            return Err(McpMintError::WrongPrincipalKind {
                expected: PrincipalKind::User,
                got: user.kind,
            });
        }
        if camp.kind != PrincipalKind::Camp {
            return Err(McpMintError::WrongPrincipalKind {
                expected: PrincipalKind::Camp,
                got: camp.kind,
            });
        }
        let aud = aud.into();

        // (1) User side — composition rule (5) per side.
        let user_entries = self.grants.list_for(&user, &aud).await?;
        if user_entries.is_empty() {
            return Err(McpMintError::AudNotEntitled {
                principal: user.to_string(),
                aud,
            });
        }
        let user_scopes = expand_scopes(&self.bundles, &user_entries).await?;
        for s in &user_scopes {
            validate_grant(&self.scopes, user.kind, s, &aud)?;
        }

        // (2) Camp side — same rule (5) check. Even though the result is
        //     user-attributed, the camp must also be entitled to the
        //     audience.
        let camp_entries = self.grants.list_for(&camp, &aud).await?;
        if camp_entries.is_empty() {
            return Err(McpMintError::AudNotEntitled {
                principal: camp.to_string(),
                aud,
            });
        }
        let camp_scopes = expand_scopes(&self.bundles, &camp_entries).await?;
        for s in &camp_scopes {
            validate_grant(&self.scopes, camp.kind, s, &aud)?;
        }

        // (3) RFC 8693 — every requested scope must be in BOTH principals'
        //     expanded grants. Any miss → reject the WHOLE exchange (not a
        //     partial token).
        for s in &requested_scope {
            if !user_scopes.contains(s) || !camp_scopes.contains(s) {
                return Err(McpMintError::InvalidScope {
                    scope: s.clone(),
                    aud: aud.clone(),
                });
            }
        }

        // (4) `owns` comes from the CAMP — the camp is the resource context,
        //     even though `sub` is the user.
        let rows = self.ownership.list_for_principal(&camp).await?;
        let owns = rows_to_owns(&rows);

        let camp_id = camp.id.clone();
        let mut claims = McpClaims::new(
            self.iss.clone(),
            aud,
            user,
            now,
            now + self.policy.access_ttl_seconds,
            generate_jti(),
            requested_scope,
        )
        .with_camp_id(camp_id)
        .with_auth_strength(AuthStrength::UserFresh);
        if let Some(a) = actor {
            claims = claims.with_act(a);
        }
        if !owns.is_empty() {
            claims = claims.with_owns(owns);
        }

        let token = self.minter.mint_mcp(&claims, &self.kid)?;
        Ok(MintedMcpToken { token, claims })
    }

    /// **Mint path 5** — service principal via RFC 7523 client assertion
    /// (R731-F4, doc D3).
    ///
    /// `assertion` is a PASETO v4.public token carrying [`ClientAssertion`]
    /// claims, signed by one of the principal's own ACTIVE keys and naming it
    /// in the footer `kid`. Checks, in order: footer kid → key known → key
    /// active → signature → `iss == sub ==` the key's owner → `aud ==`
    /// [`token_endpoint`](Self::token_endpoint) → `exp > now` →
    /// `exp - iat <= 300s` → `jti` consumed (replay rejected). Each failure is
    /// its own [`McpMintError`] variant.
    ///
    /// Scopes are the principal's relationship-derived grants for `aud`
    /// intersected with `requested_scopes` (an empty request takes every held
    /// scope); an empty result is [`McpMintError::NoGrantedScopes`]. The
    /// access token is signed by cheers's issuer key with `sub = svc:<id>`,
    /// TTL `min(policy.access_ttl, 1h)`, and no ceiling.
    pub async fn mint_service(
        &self,
        assertion: &str,
        aud: impl Into<String>,
        requested_scopes: &[Scope],
        now: i64,
    ) -> Result<MintedMcpToken, McpMintError> {
        let aud = aud.into();
        let svc = self
            .service
            .as_ref()
            .ok_or(McpMintError::ServiceAssertionsUnconfigured)?;
        let malformed = |m: &str| McpMintError::AssertionMalformed(m.to_owned());

        let untrusted = UntrustedToken::<pasetors::token::Public, V4>::try_from(assertion)
            .map_err(|_| malformed("not a v4.public token"))?;
        // The footer is bound into the signature; reading it first only
        // selects the key.
        let kid = serde_json::from_slice::<serde_json::Value>(untrusted.untrusted_footer())
            .ok()
            .and_then(|f| f.get("kid").and_then(|k| k.as_str()).map(str::to_owned))
            .ok_or_else(|| malformed("footer has no kid"))?;

        let key = svc
            .keys
            .list_all_signing_keys()
            .await?
            .into_iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| McpMintError::AssertionUnknownKid(kid.clone()))?;
        if key.status != SigningKeyStatus::Active {
            return Err(McpMintError::AssertionRetiredKey(kid));
        }

        let public = AsymmetricPublicKey::<V4>::from(&key.public_key[..])
            .map_err(|_| malformed("stored public key is not Ed25519"))?;
        let trusted = PublicToken::verify(&public, &untrusted, None, None)
            .map_err(|_| malformed("signature verification failed"))?;
        let claims: ClientAssertion = serde_json::from_str(trusted.payload())
            .map_err(|e| McpMintError::AssertionMalformed(format!("payload: {e}")))?;

        if claims.iss != key.principal_id
            || claims.sub != key.principal_id
            || key.principal_id.kind != PrincipalKind::Service
        {
            return Err(McpMintError::AssertionPrincipalMismatch {
                kid,
                owner: key.principal_id,
                iss: claims.iss,
                sub: claims.sub,
            });
        }
        let expected = self.token_endpoint();
        if claims.aud != expected {
            return Err(McpMintError::AssertionBadAudience {
                got: claims.aud,
                expected,
            });
        }
        if claims.exp <= now {
            return Err(McpMintError::AssertionExpired { exp: claims.exp, now });
        }
        let lifetime = claims.exp - claims.iat;
        if lifetime > ClientAssertion::MAX_LIFETIME_SECONDS {
            return Err(McpMintError::AssertionLifetimeTooLong {
                lifetime,
                max: ClientAssertion::MAX_LIFETIME_SECONDS,
            });
        }
        if claims.jti.is_empty() {
            return Err(malformed("empty jti"));
        }
        // Consume the jti last, so a rejected assertion doesn't burn it.
        if !svc
            .used_jtis
            .try_mark_used(&claims.jti, claims.exp)
            .await
            .map_err(McpMintError::JtiStore)?
        {
            return Err(McpMintError::AssertionReplayed(claims.jti));
        }

        let principal = claims.sub;
        let entries = self.grants.list_for(&principal, &aud).await?;
        let held = expand_scopes(&self.bundles, &entries).await?;
        for s in &held {
            validate_grant(&self.scopes, principal.kind, s, &aud)?;
        }
        let scopes: Vec<Scope> = if requested_scopes.is_empty() {
            held
        } else {
            held.into_iter()
                .filter(|s| requested_scopes.contains(s))
                .collect()
        };
        if scopes.is_empty() {
            return Err(McpMintError::NoGrantedScopes {
                principal: principal.to_string(),
                aud,
            });
        }

        let ttl = self.policy.access_ttl_seconds.min(SERVICE_MAX_TTL_SECONDS);
        let claims = McpClaims::new(
            self.iss.clone(),
            aud,
            principal,
            now,
            now + ttl,
            generate_jti(),
            scopes,
        );
        let token = self.minter.mint_mcp(&claims, &self.kid)?;
        Ok(MintedMcpToken { token, claims })
    }
}

/// Hard cap on a service access token's lifetime (doc D3: TTL <= 1 h).
const SERVICE_MAX_TTL_SECONDS: i64 = 60 * 60;

/// Intersect what a caller *asked* for with the `ceiling` they are entitled
/// to, or take the whole ceiling when they asked for nothing.
///
/// Shared by both API-token mint paths (R728-F2) — they differ only in where
/// the ceiling comes from (the grant table on create, the presented token's
/// own claims on rotate), and the intersection rule must not differ at all.
/// An unheld scope is [`McpMintError::UnentitledScopes`] naming **every**
/// offender: a token silently narrower than the one requested is a debugging
/// trap that surfaces days later as an unexplained 403.
fn attenuate(
    requested: &[Scope],
    ceiling: Vec<Scope>,
    user: &PrincipalId,
    aud: &str,
) -> Result<Vec<Scope>, McpMintError> {
    if requested.is_empty() {
        return Ok(ceiling);
    }
    let unentitled: Vec<Scope> = requested
        .iter()
        .filter(|s| !ceiling.contains(s))
        .cloned()
        .collect();
    if !unentitled.is_empty() {
        return Err(McpMintError::UnentitledScopes {
            principal: user.to_string(),
            scopes: unentitled,
            aud: aud.to_owned(),
        });
    }
    // Dedupe while preserving the caller's order — `requested` is client
    // input and may repeat.
    let mut out: Vec<Scope> = Vec::with_capacity(requested.len());
    for s in requested {
        if !out.contains(s) {
            out.push(s.clone());
        }
    }
    Ok(out)
}

/// Convert ownership rows into the [`Owns`] claim shape. Revoked rows are
/// filtered out (the store already excludes them, but a belt-and-braces
/// check keeps the wire shape from leaking stale entries if the store
/// contract evolves). Unknown resource kinds spill into
/// [`Owns::extra`](cheers_core::Owns).
///
/// Duplicate `(kind, resource_id)` pairs collapse to one entry — ownership
/// is set-membership, and while `POST /ownership` is idempotent for
/// identical live rows, historical duplicates (or the residual
/// concurrent-write race) may still exist in a store. The claim shape must
/// not amplify them onto every minted token.
fn rows_to_owns(rows: &[OwnershipRow]) -> Owns {
    fn push_unique(list: &mut Vec<String>, id: &str) {
        if !list.iter().any(|existing| existing == id) {
            list.push(id.to_owned());
        }
    }
    let mut o = Owns::default();
    for r in rows {
        // Kind-level tuples (`kind/<kind>#rel`) are authority, not ownership
        // of a resource — they never appear in the owns claim.
        if r.is_revoked() || r.resource_kind == cheers_core::KIND_RESOURCE {
            continue;
        }
        match r.resource_kind.as_str() {
            "service" => push_unique(&mut o.service, &r.resource_id),
            "arch_doc" => push_unique(&mut o.arch_doc, &r.resource_id),
            "node" => push_unique(&mut o.node, &r.resource_id),
            other => push_unique(
                o.extra.entry(other.to_owned()).or_default(),
                &r.resource_id,
            ),
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundles::{BundleName, MemoryBundleStore, ScopeOrBundle};
    use crate::codec::PasetoV4SecretMinter;
    use crate::grants::SchemaGrantStore;
    use cheers_core::{RelationDef, ResourceSchema, SchemaRegistry, KIND_RESOURCE};
    use std::collections::HashMap;
    use crate::ownership::{MemoryOwnershipStore, NewOwnership, OwnershipStore};
    use async_trait::async_trait;
    use cheers_core::{yah_scopes, Scope, StoreError};
    use cheers_verify::PasetoV4PublicVerifier;
    use std::sync::Mutex;

    // ---- grants ------------------------------------------------------------
    //
    // Scopes are seeded as ownership tuples through a test schema: kind
    // `grant`, one kind-level relation per yah scope (named by its wire form)
    // unlocking exactly that scope. Kind-level rows stay out of `owns`, so the
    // owns assertions below see only the resource rows each test inserts.
    // `raw` stands in for a hand-coded GrantStore (noisetable's
    // PublishGrants): bundles and unregistered scopes, which no schema can
    // express, go there.

    const GRANT_KIND: &str = "grant";

    fn test_schema(scopes: &cheers_core::ScopeRegistry) -> SchemaRegistry {
        let rels: Vec<RelationDef> = yah_scopes::DEFS
            .iter()
            .map(|d| RelationDef {
                name: Box::leak(d.scope.as_wire().to_owned().into_boxed_str()),
                membership: true,
                implies: &[],
                scopes: Box::leak(vec![d.scope.clone()].into_boxed_slice()),
                grants: &[],
            })
            .collect();
        SchemaRegistry::build(
            &[ResourceSchema {
                kind: GRANT_KIND,
                relations: &[],
                kind_relations: Box::leak(rels.into_boxed_slice()),
            }],
            scopes,
        )
        .unwrap()
    }

    struct TestGrants {
        schema: SchemaGrantStore<MemoryOwnershipStore>,
        ownership: MemoryOwnershipStore,
        raw: Mutex<HashMap<(PrincipalId, String), Vec<ScopeOrBundle>>>,
    }

    impl TestGrants {
        fn put_raw(&self, principal: PrincipalId, aud: &str, entries: Vec<ScopeOrBundle>) {
            self.raw.lock().unwrap().insert((principal, aud.to_owned()), entries);
        }
    }

    #[async_trait]
    impl GrantStore for TestGrants {
        async fn list_for(
            &self,
            principal: &PrincipalId,
            aud: &str,
        ) -> Result<Vec<ScopeOrBundle>, StoreError> {
            let mut out = self.schema.list_for(principal, aud).await?;
            if let Some(raw) = self.raw.lock().unwrap().get(&(principal.clone(), aud.to_owned())) {
                out.extend(raw.iter().cloned());
            }
            Ok(out)
        }
    }

    // ---- assembly ----------------------------------------------------------

    /// `kid` this test rig's authority stamps into every mint — tests that
    /// verify a minted token must pass the same value to `verify_mcp_at`.
    const RIG_KID: &str = "mcp-authority-test-kid-1";

    fn rig() -> (
        McpAuthority<MemoryBundleStore, TestGrants, MemoryOwnershipStore>,
        PasetoV4PublicVerifier,
    ) {
        let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
        let bundles = MemoryBundleStore::with_defaults();
        let ownership = MemoryOwnershipStore::new();
        let scopes = Arc::new(
            yah_scopes::registry_at([
                "https://aud.example",
                "https://kamaji.camp.example",
                "https://kamaji.example",
            ])
            .unwrap(),
        );
        let grants = TestGrants {
            schema: SchemaGrantStore::new(
                ownership.clone(),
                Arc::new(test_schema(&scopes)),
                scopes.clone(),
            ),
            ownership: ownership.clone(),
            raw: Mutex::default(),
        };
        let authority = McpAuthority::new(
            minter,
            bundles,
            grants,
            ownership,
            scopes,
            "https://cheers.example",
            RIG_KID,
        );
        (authority, verifier)
    }

    /// Scopes become `kind/grant#<scope>` tuples; bundles go to the raw
    /// store. `aud` only matters for raw entries — derived scopes are filtered
    /// by the registry's audiences (all `Any` for yah).
    fn put_simple_grant(
        authority: &McpAuthority<MemoryBundleStore, TestGrants, MemoryOwnershipStore>,
        principal: PrincipalId,
        aud: &str,
        entries: Vec<ScopeOrBundle>,
    ) {
        let mut raw = Vec::new();
        for e in entries {
            match e {
                ScopeOrBundle::Scope(scope) => {
                    let n = NewOwnership::new(
                        principal.clone(),
                        KIND_RESOURCE,
                        GRANT_KIND,
                        scope.as_wire(),
                        PrincipalId::service("seed"),
                        None,
                    )
                    .unwrap();
                    pollster::block_on(authority.grants.ownership.insert(&n, 1)).unwrap();
                }
                bundle => raw.push(bundle),
            }
        }
        if !raw.is_empty() {
            authority.grants.put_raw(principal, aud, raw);
        }
    }

    // ---- McpPolicy ---------------------------------------------------------

    #[test]
    fn mcp_policy_default_is_ten_minutes() {
        let p = McpPolicy::default();
        assert_eq!(p.access_ttl_seconds, 10 * 60);
        let p = McpPolicy::new(300);
        assert_eq!(p.access_ttl_seconds, 300);
        let p = McpPolicy::default().with_access_ttl(5 * 60);
        assert_eq!(p.access_ttl_seconds, 5 * 60);
    }

    // ---- mint_user_fresh: success paths ------------------------------------

    #[test]
    fn mint_user_fresh_signs_token_verifiable_at_edge() {
        let (authority, verifier) = rig();
        let user = PrincipalId::user("alice");
        let aud = "https://kamaji.camp.example";
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![ScopeOrBundle::Scope(yah_scopes::CLOUD_DEPLOY), ScopeOrBundle::Scope(yah_scopes::CLOUD_READ)],
        );

        pollster::block_on(async {
            let minted = authority
                .mint_user_fresh(user.clone(), None, None, aud, 1_000)
                .await
                .unwrap();

            // Token starts with v4.public — the doc-pinned envelope.
            assert!(minted.token.starts_with("v4.public."));
            // auth_strength is user-fresh on this path.
            assert_eq!(minted.claims.auth_strength, Some(AuthStrength::UserFresh));
            // jti is non-empty + iat/exp respect the default TTL (10 min).
            assert!(!minted.claims.jti.is_empty());
            assert_eq!(minted.claims.iat, 1_000);
            assert_eq!(
                minted.claims.exp,
                1_000 + McpPolicy::DEFAULT_ACCESS_TTL_SECONDS
            );
            // Edge verifies the freshly minted token under the public key.
            let back = verifier.verify_mcp_at(&minted.token, 1_100, RIG_KID).unwrap();
            assert_eq!(back, minted.claims);
            assert_eq!(back.sub, user);
            assert_eq!(back.scope, vec![yah_scopes::CLOUD_DEPLOY, yah_scopes::CLOUD_READ]);
        });
    }

    #[test]
    fn mint_user_fresh_expands_bundles_at_mint_time() {
        // A grant of `{"bundle":"deploy-admin"}` lands on the wire as the
        // literal scope list (rule (2)). Edit the bundle, re-mint, see the
        // change without rewriting the grant.
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("bob");
        let aud = "https://kamaji.example";
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![ScopeOrBundle::Bundle(BundleName::new("deploy-admin"))],
        );

        pollster::block_on(async {
            let first = authority
                .mint_user_fresh(user.clone(), None, None, aud, 1_000)
                .await
                .unwrap();
            assert!(first.claims.scope.contains(&yah_scopes::CLOUD_DESTROY));

            // Edit the bundle: drop CloudDestroy. Grant is untouched.
            authority
                .bundles
                .put(
                    &BundleName::new("deploy-admin"),
                    &[yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY],
                )
                .await
                .unwrap();

            let second = authority
                .mint_user_fresh(user, None, None, aud, 1_100)
                .await
                .unwrap();
            assert!(!second.claims.scope.contains(&yah_scopes::CLOUD_DESTROY));
            assert_eq!(second.claims.scope, vec![yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY]);
        });
    }

    #[test]
    fn mint_user_fresh_populates_act_camp_id_and_owns() {
        let (authority, verifier) = rig();
        let user = PrincipalId::user("carol");
        let camp_id = "camp-xyz";
        let aud = "https://aud.example";
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![ScopeOrBundle::Scope(yah_scopes::CAMP_READ)],
        );
        // Seed two owned resources under the camp principal.
        pollster::block_on(async {
            let svc = NewOwnership::new(
                PrincipalId::camp(camp_id),
                "service",
                "svc-a",
                "owns",
                PrincipalId::service("yubaba"),
                Some(user.clone()),
            )
            .unwrap();
            authority.ownership.insert(&svc, 500).await.unwrap();

            let doc = NewOwnership::new(
                PrincipalId::camp(camp_id),
                "arch_doc",
                "doc-1",
                "owns",
                PrincipalId::service("yubaba"),
                Some(user.clone()),
            )
            .unwrap();
            authority.ownership.insert(&doc, 500).await.unwrap();

            let minted = authority
                .mint_user_fresh(
                    user.clone(),
                    Some(Actor::new(PrincipalId::service("agent-claude"))),
                    Some(camp_id.to_owned()),
                    aud,
                    1_000,
                )
                .await
                .unwrap();

            assert_eq!(
                minted.claims.act.as_ref().unwrap().sub,
                PrincipalId::service("agent-claude")
            );
            assert_eq!(minted.claims.camp_id.as_deref(), Some(camp_id));
            assert_eq!(minted.claims.owns.service, vec!["svc-a".to_string()]);
            assert_eq!(minted.claims.owns.arch_doc, vec!["doc-1".to_string()]);

            // Edge accepts it.
            let back = verifier.verify_mcp_at(&minted.token, 1_100, RIG_KID).unwrap();
            assert_eq!(back, minted.claims);
        });
    }

    #[test]
    fn mint_user_fresh_omits_owns_when_camp_owns_nothing() {
        // No ownership rows + camp_id present → owns is empty/omitted on the
        // wire. The claim skip_serializing_if guards this; the test pins it.
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("dan");
        let aud = "https://aud.example";
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![ScopeOrBundle::Scope(yah_scopes::CAMP_READ)],
        );

        pollster::block_on(async {
            let minted = authority
                .mint_user_fresh(user, None, Some("camp-empty".into()), aud, 1_000)
                .await
                .unwrap();
            assert!(minted.claims.owns.is_empty());
            let json = serde_json::to_string(&minted.claims).unwrap();
            assert!(!json.contains("\"owns\""), "empty owns must omit: {json}");
        });
    }

    // ---- mint_user_fresh: rejection paths ----------------------------------

    #[test]
    fn mint_user_fresh_rejects_unentitled_aud() {
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("eve");
        // No grant placed for any aud.
        pollster::block_on(async {
            let err = authority
                .mint_user_fresh(user, None, None, "https://aud.example", 1_000)
                .await
                .unwrap_err();
            match err {
                McpMintError::AudNotEntitled { principal, aud } => {
                    assert_eq!(principal, "user:eve");
                    assert_eq!(aud, "https://aud.example");
                }
                other => panic!("expected AudNotEntitled, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_user_fresh_rejects_non_user_principal() {
        let (authority, _verifier) = rig();
        pollster::block_on(async {
            let err = authority
                .mint_user_fresh(
                    PrincipalId::service("yubaba"),
                    None,
                    None,
                    "https://aud.example",
                    1_000,
                )
                .await
                .unwrap_err();
            match err {
                McpMintError::WrongPrincipalKind { expected, got } => {
                    assert_eq!(expected, PrincipalKind::User);
                    assert_eq!(got, PrincipalKind::Service);
                }
                other => panic!("expected WrongPrincipalKind, got {other:?}"),
            }
        });
    }

    // ---- mint_api_token (R728-F1) ------------------------------------------

    #[test]
    fn mint_api_token_defaults_to_ninety_days_and_the_full_effective_scope_set() {
        let (authority, verifier) = rig();
        let user = PrincipalId::user("alice");
        let aud = "https://kamaji.example";
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![
                ScopeOrBundle::Scope(yah_scopes::CLOUD_READ),
                ScopeOrBundle::Scope(yah_scopes::CLOUD_DEPLOY),
            ],
        );

        pollster::block_on(async {
            let minted = authority
                .mint_api_token(user.clone(), aud, &[], None, 1_000)
                .await
                .unwrap();
            assert_eq!(
                minted.claims.exp,
                1_000 + McpPolicy::DEFAULT_API_TOKEN_TTL_SECONDS
            );
            assert_eq!(minted.claims.auth_strength, Some(AuthStrength::ApiToken));
            assert_eq!(minted.claims.sub, user);
            // Empty `requested` = everything held for this aud, frozen now.
            // Derived grants come back in scope order, not seed order.
            assert_eq!(
                minted.claims.scope,
                vec![yah_scopes::CLOUD_DEPLOY, yah_scopes::CLOUD_READ]
            );
            // Same signing key, same envelope — it verifies at the ordinary
            // edge with no new verification path.
            let back = verifier.verify_mcp_at(&minted.token, 1_100, RIG_KID).unwrap();
            assert_eq!(back, minted.claims);
        });
    }

    /// The whole point: a PAT is never wider than its minter. Asking for a
    /// subset yields exactly that subset.
    #[test]
    fn mint_api_token_attenuates_to_the_requested_subset() {
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("alice");
        let aud = "https://kamaji.example";
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![
                ScopeOrBundle::Scope(yah_scopes::CLOUD_READ),
                ScopeOrBundle::Scope(yah_scopes::CLOUD_DEPLOY),
                ScopeOrBundle::Scope(yah_scopes::CLOUD_DESTROY),
            ],
        );

        pollster::block_on(async {
            let minted = authority
                .mint_api_token(user, aud, &[yah_scopes::CLOUD_READ], None, 1_000)
                .await
                .unwrap();
            assert_eq!(minted.claims.scope, vec![yah_scopes::CLOUD_READ]);
        });
    }

    /// A scope the caller does not hold is NAMED, not silently dropped. A
    /// token quietly weaker than the one asked for fails days later somewhere
    /// else as an unexplained 403.
    #[test]
    fn mint_api_token_names_every_unentitled_scope_instead_of_dropping_it() {
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("alice");
        let aud = "https://kamaji.example";
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![ScopeOrBundle::Scope(yah_scopes::CLOUD_READ)],
        );

        pollster::block_on(async {
            let err = authority
                .mint_api_token(
                    user,
                    aud,
                    &[yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DESTROY, yah_scopes::CAMP_ADMIN],
                    None,
                    1_000,
                )
                .await
                .unwrap_err();
            match err {
                McpMintError::UnentitledScopes { ref scopes, .. } => {
                    assert_eq!(scopes, &vec![yah_scopes::CLOUD_DESTROY, yah_scopes::CAMP_ADMIN]);
                    let msg = err.to_string();
                    assert!(msg.contains("cloud:destroy"), "{msg}");
                    assert!(msg.contains("camp:admin"), "{msg}");
                }
                other => panic!("expected UnentitledScopes, got {other:?}"),
            }
        });
    }

    /// Composition rule (4) defence in depth applies to this path too: a
    /// bundle smuggling a service-only scope into a user grant is caught
    /// BEFORE signing, exactly as on `mint_user_fresh`.
    #[test]
    fn mint_api_token_rejects_service_only_scope_smuggled_via_bundle() {
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("mallory");
        let aud = "https://aud.example";

        pollster::block_on(async {
            authority
                .bundles
                .put(
                    &BundleName::new("dangerous"),
                    &[yah_scopes::CAMP_READ, yah_scopes::AUDIT_WRITE],
                )
                .await
                .unwrap();
            authority.grants.put_raw(
                user.clone(),
                aud,
                vec![ScopeOrBundle::Bundle(BundleName::new("dangerous"))],
            );
            match authority.mint_api_token(user, aud, &[], None, 1_000).await {
                Err(McpMintError::GrantMisconfigured(GrantError::ServiceOnlyScope {
                    scope,
                    kind,
                })) => {
                    assert_eq!(scope, yah_scopes::AUDIT_WRITE);
                    assert_eq!(kind, PrincipalKind::User);
                }
                other => panic!("expected GrantMisconfigured, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_api_token_rejects_an_out_of_range_ttl_rather_than_clamping() {
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("alice");
        let aud = "https://kamaji.example";
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![ScopeOrBundle::Scope(yah_scopes::CLOUD_READ)],
        );

        pollster::block_on(async {
            for bad in [0, -1, McpPolicy::MAX_API_TOKEN_TTL_SECONDS + 1] {
                match authority
                    .mint_api_token(user.clone(), aud, &[], Some(bad), 1_000)
                    .await
                {
                    Err(McpMintError::TtlOutOfRange { requested, max }) => {
                        assert_eq!(requested, bad);
                        assert_eq!(max, McpPolicy::MAX_API_TOKEN_TTL_SECONDS);
                    }
                    other => panic!("expected TtlOutOfRange for {bad}, got {other:?}"),
                }
            }
            // The ceiling itself is accepted — the range is inclusive.
            let ok = authority
                .mint_api_token(
                    user,
                    aud,
                    &[],
                    Some(McpPolicy::MAX_API_TOKEN_TTL_SECONDS),
                    1_000,
                )
                .await
                .unwrap();
            assert_eq!(
                ok.claims.exp,
                1_000 + McpPolicy::MAX_API_TOKEN_TTL_SECONDS
            );
        });
    }

    #[test]
    fn mint_api_token_rejects_an_unentitled_aud_before_signing() {
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("alice");
        pollster::block_on(async {
            match authority
                .mint_api_token(user, "https://nothing-granted.example", &[], None, 1_000)
                .await
            {
                Err(McpMintError::AudNotEntitled { principal, aud }) => {
                    assert_eq!(principal, "user:alice");
                    assert_eq!(aud, "https://nothing-granted.example");
                }
                other => panic!("expected AudNotEntitled, got {other:?}"),
            }
        });
    }

    /// `owns` is a mint-time snapshot whose staleness bound is the token's
    /// lifetime. At 10 minutes that is fine; at 90 days it would be a
    /// stale-authorization hole, so a PAT carries none — nor a `camp_id`
    /// (whose job is keying that lookup) nor an `act` (nobody is acting on
    /// the user's behalf; they minted it themselves).
    #[test]
    fn mint_api_token_carries_no_owns_no_camp_id_and_no_act() {
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("alice");
        let aud = "https://kamaji.example";
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![ScopeOrBundle::Scope(yah_scopes::CLOUD_READ)],
        );

        pollster::block_on(async {
            let minted = authority
                .mint_api_token(user, aud, &[], None, 1_000)
                .await
                .unwrap();
            assert!(minted.claims.owns.is_empty());
            assert_eq!(minted.claims.camp_id, None);
            assert_eq!(minted.claims.act, None);
        });
    }

    #[test]
    fn mint_api_token_rejects_a_non_user_principal() {
        let (authority, _verifier) = rig();
        pollster::block_on(async {
            match authority
                .mint_api_token(PrincipalId::camp("c1"), "https://aud.example", &[], None, 1)
                .await
            {
                Err(McpMintError::WrongPrincipalKind { expected, got }) => {
                    assert_eq!(expected, PrincipalKind::User);
                    assert_eq!(got, PrincipalKind::Camp);
                }
                other => panic!("expected WrongPrincipalKind, got {other:?}"),
            }
        });
    }

    // ---- rotate_api_token (R728-F2) ----------------------------------------

    /// The whole point of the rotate path: the ceiling is the presented
    /// token's own scopes, so an EMPTY grant table still rolls a token.
    ///
    /// Stated as a contrast, because the contrast IS the property — the same
    /// inputs through `mint_api_token` are an `AudNotEntitled` 403. If this
    /// test ever starts needing a grant, someone has put a `grants.list_for`
    /// back on the rotate path and a frozen token can silently re-widen
    /// itself to whatever the grant table says today.
    #[test]
    fn rotate_api_token_mints_from_the_presented_scopes_without_reading_grants() {
        let (authority, verifier) = rig();
        let user = PrincipalId::user("alice");
        let aud = "https://kamaji.example";
        // No grant, deliberately.

        let minted = authority
            .rotate_api_token(
                user.clone(),
                aud,
                &[yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY],
                &[],
                None,
                1_000,
            )
            .unwrap();
        assert_eq!(minted.claims.scope, vec![yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY]);
        assert_eq!(minted.claims.auth_strength, Some(AuthStrength::ApiToken));
        assert_eq!(minted.claims.sub, user.clone());
        assert_eq!(minted.claims.aud, aud);
        assert!(minted.claims.owns.is_empty());
        // A real token on the same stack, verifiable by the ordinary verifier.
        let claims = verifier.verify_mcp_at(&minted.token, 1_001, RIG_KID).unwrap();
        assert_eq!(claims.jti, minted.claims.jti);

        // And the contrast: the same call through the create path is refused.
        pollster::block_on(async {
            assert!(matches!(
                authority.mint_api_token(user, aud, &[], None, 1_000).await,
                Err(McpMintError::AudNotEntitled { .. })
            ));
        });
    }

    #[test]
    fn rotate_api_token_can_narrow_but_never_widen() {
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("alice");
        let aud = "https://kamaji.example";
        // A wide grant table is present and must be ignored.
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![
                ScopeOrBundle::Scope(yah_scopes::CLOUD_READ),
                ScopeOrBundle::Scope(yah_scopes::CLOUD_DEPLOY),
                ScopeOrBundle::Scope(yah_scopes::CLOUD_DESTROY),
            ],
        );

        // Narrowing works.
        let narrowed = authority
            .rotate_api_token(
                user.clone(),
                aud,
                &[yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY],
                &[yah_scopes::CLOUD_READ],
                None,
                1_000,
            )
            .unwrap();
        assert_eq!(narrowed.claims.scope, vec![yah_scopes::CLOUD_READ]);

        // Widening — to a scope the GRANT holds but the token does not — is
        // refused by name.
        match authority.rotate_api_token(
            user,
            aud,
            &[yah_scopes::CLOUD_READ],
            &[yah_scopes::CLOUD_DESTROY],
            None,
            1_000,
        ) {
            Err(McpMintError::UnentitledScopes { scopes, .. }) => {
                assert_eq!(scopes, vec![yah_scopes::CLOUD_DESTROY]);
            }
            other => panic!("expected UnentitledScopes, got {other:?}"),
        }
    }

    /// Rotation refreshes the clock — that is what keeps a long-lived
    /// credential alive — but under the SAME ceiling a first mint is held to,
    /// so repeated hops cannot extend authority indefinitely.
    #[test]
    fn rotate_api_token_gets_a_fresh_ttl_under_the_same_ceiling() {
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("alice");
        let aud = "https://kamaji.example";

        let default_ttl = authority
            .rotate_api_token(user.clone(), aud, &[yah_scopes::CLOUD_READ], &[], None, 5_000)
            .unwrap();
        assert_eq!(
            default_ttl.claims.exp - default_ttl.claims.iat,
            McpPolicy::DEFAULT_API_TOKEN_TTL_SECONDS
        );
        assert_eq!(default_ttl.claims.iat, 5_000, "the clock restarts at `now`");

        for bad in [0, -1, McpPolicy::MAX_API_TOKEN_TTL_SECONDS + 1] {
            match authority.rotate_api_token(
                user.clone(),
                aud,
                &[yah_scopes::CLOUD_READ],
                &[],
                Some(bad),
                5_000,
            ) {
                Err(McpMintError::TtlOutOfRange { requested, max }) => {
                    assert_eq!(requested, bad);
                    assert_eq!(max, McpPolicy::MAX_API_TOKEN_TTL_SECONDS);
                }
                other => panic!("expected TtlOutOfRange for {bad}, got {other:?}"),
            }
        }
    }

    /// Composition rule (4) is not laundered by a re-sign: a service-only
    /// scope sitting in a user's token is refused on the way out, wherever it
    /// came from.
    #[test]
    fn rotate_api_token_rejects_a_service_only_scope_in_the_presented_token() {
        let (authority, _verifier) = rig();
        assert!(matches!(
            authority.rotate_api_token(
                PrincipalId::user("alice"),
                "https://kamaji.example",
                &[yah_scopes::AUDIT_WRITE],
                &[],
                None,
                1_000,
            ),
            Err(McpMintError::GrantMisconfigured(_))
        ));
    }

    #[test]
    fn rotate_api_token_rejects_a_non_user_principal() {
        let (authority, _verifier) = rig();
        match authority.rotate_api_token(
            PrincipalId::camp("c1"),
            "https://aud.example",
            &[yah_scopes::CLOUD_READ],
            &[],
            None,
            1,
        ) {
            Err(McpMintError::WrongPrincipalKind { expected, got }) => {
                assert_eq!(expected, PrincipalKind::User);
                assert_eq!(got, PrincipalKind::Camp);
            }
            other => panic!("expected WrongPrincipalKind, got {other:?}"),
        }
    }

    #[test]
    fn mint_user_fresh_rejects_scope_missing_from_registry() {
        // R731-F2: a grant row naming a well-formed scope the deployment's
        // registry does not declare is refused at mint, before signing.
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("alice");
        let aud = "https://aud.example";
        let unknown: Scope = "cloud:nuke".parse().unwrap();
        authority.grants.put_raw(
            user.clone(),
            aud,
            vec![ScopeOrBundle::Scope(yah_scopes::CLOUD_READ), ScopeOrBundle::Scope(unknown.clone())],
        );
        let err = pollster::block_on(authority.mint_user_fresh(user, None, None, aud, 1_000))
            .unwrap_err();
        match err {
            McpMintError::GrantMisconfigured(GrantError::UnknownScope { scope }) => {
                assert_eq!(scope, unknown);
            }
            other => panic!("expected UnknownScope, got {other:?}"),
        }
    }

    #[test]
    fn mint_user_fresh_rejects_service_only_scope_smuggled_via_bundle() {
        // Defence in depth for composition rule (4): if a bundle granted to
        // a User principal contains audit:write, the mint path catches
        // it via validate_grant BEFORE signing — the misconfigured bundle
        // never becomes a mintable token.
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("mallory");
        let aud = "https://aud.example";

        pollster::block_on(async {
            authority
                .bundles
                .put(
                    &BundleName::new("dangerous"),
                    &[yah_scopes::CAMP_READ, yah_scopes::AUDIT_WRITE],
                )
                .await
                .unwrap();
            authority.grants.put_raw(
                user.clone(),
                aud,
                vec![ScopeOrBundle::Bundle(BundleName::new("dangerous"))],
            );

            let err = authority
                .mint_user_fresh(user, None, None, aud, 1_000)
                .await
                .unwrap_err();
            match err {
                McpMintError::GrantMisconfigured(GrantError::ServiceOnlyScope { scope, kind }) => {
                    assert_eq!(scope, yah_scopes::AUDIT_WRITE);
                    assert_eq!(kind, PrincipalKind::User);
                }
                other => panic!("expected GrantMisconfigured(ServiceOnlyScope), got {other:?}"),
            }
        });
    }

    // ---- mint_bootstrap: success paths -------------------------------------

    #[test]
    fn mint_bootstrap_signs_token_verifiable_at_edge() {
        let (authority, verifier) = rig();
        let camp = PrincipalId::camp("c-xyz");
        let aud = "https://kamaji.camp.example";
        put_simple_grant(
            &authority,
            camp.clone(),
            aud,
            vec![
                ScopeOrBundle::Scope(yah_scopes::CLOUD_DEPLOY),
                ScopeOrBundle::Scope(yah_scopes::CLOUD_READ),
            ],
        );

        pollster::block_on(async {
            let minted = authority
                .mint_bootstrap(camp.clone(), aud, 1_000)
                .await
                .unwrap();

            // Same v4.public envelope as mint path 1.
            assert!(minted.token.starts_with("v4.public."));
            // auth_strength is bootstrap on this path.
            assert_eq!(minted.claims.auth_strength, Some(AuthStrength::Bootstrap));
            // sub is the camp principal; camp_id is the bare id (no prefix) so
            // a consumer doesn't have to re-parse sub.
            assert_eq!(minted.claims.sub, camp);
            assert_eq!(minted.claims.camp_id.as_deref(), Some("c-xyz"));
            // No act claim — bootstrap is the camp acting as itself, not a
            // user acted-on-by an agent.
            assert!(minted.claims.act.is_none());
            assert!(!minted.claims.jti.is_empty());
            assert_eq!(minted.claims.iat, 1_000);
            assert_eq!(
                minted.claims.exp,
                1_000 + McpPolicy::DEFAULT_ACCESS_TTL_SECONDS
            );

            // Edge verifies the freshly minted token under the public key —
            // no per-call cheers round trip.
            let back = verifier.verify_mcp_at(&minted.token, 1_100, RIG_KID).unwrap();
            assert_eq!(back, minted.claims);
            assert_eq!(back.scope, vec![yah_scopes::CLOUD_DEPLOY, yah_scopes::CLOUD_READ]);
        });
    }

    #[test]
    fn mint_bootstrap_owns_reflects_ownership_table_state() {
        let (authority, _verifier) = rig();
        let camp = PrincipalId::camp("c-with-owns");
        let user = PrincipalId::user("u-on-behalf");
        let aud = "https://aud.example";
        put_simple_grant(
            &authority,
            camp.clone(),
            aud,
            vec![ScopeOrBundle::Scope(yah_scopes::CAMP_READ)],
        );

        pollster::block_on(async {
            // Seed two owned resources under the camp principal — the camp is
            // the holder, the user is the human on whose behalf the grant
            // happened (W159 §audit / on_behalf_of).
            let svc = NewOwnership::new(
                camp.clone(),
                "service",
                "svc-a",
                "owns",
                PrincipalId::service("yubaba"),
                Some(user.clone()),
            )
            .unwrap();
            authority.ownership.insert(&svc, 500).await.unwrap();

            let doc = NewOwnership::new(
                camp.clone(),
                "arch_doc",
                "doc-1",
                "owns",
                PrincipalId::service("yubaba"),
                Some(user.clone()),
            )
            .unwrap();
            authority.ownership.insert(&doc, 500).await.unwrap();

            let minted = authority
                .mint_bootstrap(camp.clone(), aud, 1_000)
                .await
                .unwrap();

            assert_eq!(minted.claims.owns.service, vec!["svc-a".to_string()]);
            assert_eq!(minted.claims.owns.arch_doc, vec!["doc-1".to_string()]);
        });
    }

    #[test]
    fn rows_to_owns_dedups_duplicate_resource_ids() {
        // Historical duplicate rows (pre-idempotent-create stores, or the
        // residual concurrent-write race) must collapse to one entry per
        // (kind, resource_id) — the owns claim is set-membership.
        let camp = PrincipalId::camp("c-dup");
        let svc = PrincipalId::service("yubaba");
        let mk = |id: &str, kind: &str, rid: &str| {
            OwnershipRow::new(
                id.to_owned(),
                camp.clone().into(),
                kind.to_owned(),
                rid.to_owned(),
                "owns".to_owned(),
                svc.clone(),
                None,
                500,
                None,
            )
        };
        let rows = vec![
            mk("row-1", "service", "svc-a"),
            mk("row-2", "service", "svc-a"), // duplicate
            mk("row-3", "service", "svc-b"),
            mk("row-4", "node", "aa11"),
            mk("row-5", "node", "aa11"), // duplicate
            mk("row-6", "pond", "p-1"),
            mk("row-7", "pond", "p-1"), // duplicate in the extra spill
        ];

        let owns = rows_to_owns(&rows);
        assert_eq!(owns.service, vec!["svc-a".to_string(), "svc-b".to_string()]);
        assert_eq!(owns.node, vec!["aa11".to_string()]);
        assert_eq!(
            owns.extra.get("pond"),
            Some(&vec!["p-1".to_string()])
        );
    }

    #[test]
    fn mint_bootstrap_omits_owns_when_camp_owns_nothing() {
        // No ownership rows → owns is empty and omitted on the wire. Same
        // skip_serializing_if guard as mint path 1, pinned independently here
        // because the bootstrap mint path always sets camp_id (a token whose
        // sub is `camp:<C>` is always scoped to that camp).
        let (authority, _verifier) = rig();
        let camp = PrincipalId::camp("c-empty");
        let aud = "https://aud.example";
        put_simple_grant(
            &authority,
            camp.clone(),
            aud,
            vec![ScopeOrBundle::Scope(yah_scopes::CAMP_READ)],
        );

        pollster::block_on(async {
            let minted = authority
                .mint_bootstrap(camp, aud, 1_000)
                .await
                .unwrap();
            assert!(minted.claims.owns.is_empty());
            let json = serde_json::to_string(&minted.claims).unwrap();
            assert!(!json.contains("\"owns\""), "empty owns must omit: {json}");
            // camp_id is still present even when owns is empty.
            assert!(json.contains("\"camp_id\":\"c-empty\""), "camp_id must remain: {json}");
        });
    }

    #[test]
    fn mint_bootstrap_expands_bundles_at_mint_time() {
        // Same propagation property as F5/F6: a bundle edit shows up on the
        // next mint without rewriting the camp's grant.
        let (authority, _verifier) = rig();
        let camp = PrincipalId::camp("c-deploy");
        let aud = "https://aud.example";
        put_simple_grant(
            &authority,
            camp.clone(),
            aud,
            vec![ScopeOrBundle::Bundle(BundleName::new("deploy-admin"))],
        );

        pollster::block_on(async {
            let first = authority
                .mint_bootstrap(camp.clone(), aud, 1_000)
                .await
                .unwrap();
            assert!(first.claims.scope.contains(&yah_scopes::CLOUD_DESTROY));

            authority
                .bundles
                .put(
                    &BundleName::new("deploy-admin"),
                    &[yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY],
                )
                .await
                .unwrap();

            let second = authority
                .mint_bootstrap(camp, aud, 1_100)
                .await
                .unwrap();
            assert!(!second.claims.scope.contains(&yah_scopes::CLOUD_DESTROY));
            assert_eq!(second.claims.scope, vec![yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY]);
        });
    }

    // ---- mint_bootstrap: rejection paths -----------------------------------

    #[test]
    fn mint_bootstrap_rejects_non_camp_principal() {
        let (authority, _verifier) = rig();
        pollster::block_on(async {
            // A user principal handed to the bootstrap path is a programmer
            // error — surfaces WrongPrincipalKind, not a 403.
            let err = authority
                .mint_bootstrap(
                    PrincipalId::user("alice"),
                    "https://aud.example",
                    1_000,
                )
                .await
                .unwrap_err();
            match err {
                McpMintError::WrongPrincipalKind { expected, got } => {
                    assert_eq!(expected, PrincipalKind::Camp);
                    assert_eq!(got, PrincipalKind::User);
                }
                other => panic!("expected WrongPrincipalKind, got {other:?}"),
            }

            // Same for a service principal.
            let err = authority
                .mint_bootstrap(
                    PrincipalId::service("yubaba"),
                    "https://aud.example",
                    1_000,
                )
                .await
                .unwrap_err();
            match err {
                McpMintError::WrongPrincipalKind { expected, got } => {
                    assert_eq!(expected, PrincipalKind::Camp);
                    assert_eq!(got, PrincipalKind::Service);
                }
                other => panic!("expected WrongPrincipalKind, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_bootstrap_rejects_unentitled_aud() {
        let (authority, _verifier) = rig();
        let camp = PrincipalId::camp("c-no-grants");
        // No grant placed for any aud — composition rule (5).
        pollster::block_on(async {
            let err = authority
                .mint_bootstrap(camp, "https://aud.example", 1_000)
                .await
                .unwrap_err();
            match err {
                McpMintError::AudNotEntitled { principal, aud } => {
                    assert_eq!(principal, "camp:c-no-grants");
                    assert_eq!(aud, "https://aud.example");
                }
                other => panic!("expected AudNotEntitled, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_bootstrap_rejects_service_only_scope_smuggled_via_bundle() {
        // Composition rule (4) — `audit:write` is
        // grantable to kind=service ONLY. A bundle granted to a camp
        // principal that expands to a service-only scope is rejected by
        // validate_grant BEFORE signing, mirroring F6's defence in depth on
        // the user path.
        let (authority, _verifier) = rig();
        let camp = PrincipalId::camp("c-sneaky");
        let aud = "https://aud.example";

        pollster::block_on(async {
            authority
                .bundles
                .put(
                    &BundleName::new("dangerous"),
                    &[yah_scopes::CAMP_READ, yah_scopes::AUDIT_WRITE],
                )
                .await
                .unwrap();
            authority.grants.put_raw(
                camp.clone(),
                aud,
                vec![ScopeOrBundle::Bundle(BundleName::new("dangerous"))],
            );

            let err = authority
                .mint_bootstrap(camp, aud, 1_000)
                .await
                .unwrap_err();
            match err {
                McpMintError::GrantMisconfigured(GrantError::ServiceOnlyScope { scope, kind }) => {
                    assert_eq!(scope, yah_scopes::AUDIT_WRITE);
                    assert_eq!(kind, PrincipalKind::Camp);
                }
                other => panic!("expected GrantMisconfigured(ServiceOnlyScope), got {other:?}"),
            }
        });
    }

    // ---- mint_token_exchange: success paths --------------------------------

    #[test]
    fn mint_token_exchange_attributes_to_user_with_camp_as_context() {
        let (authority, verifier) = rig();
        let user = PrincipalId::user("alice");
        let camp = PrincipalId::camp("c-multi");
        let aud = "https://kamaji.camp.example";

        // User holds CloudDeploy + CloudRead for this aud; camp holds the
        // same. Requested scope is a subset.
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![
                ScopeOrBundle::Scope(yah_scopes::CLOUD_DEPLOY),
                ScopeOrBundle::Scope(yah_scopes::CLOUD_READ),
            ],
        );
        put_simple_grant(
            &authority,
            camp.clone(),
            aud,
            vec![
                ScopeOrBundle::Scope(yah_scopes::CLOUD_DEPLOY),
                ScopeOrBundle::Scope(yah_scopes::CLOUD_READ),
            ],
        );

        // Camp owns a service — owns claim must come from the camp.
        pollster::block_on(async {
            let svc = NewOwnership::new(
                camp.clone(),
                "service",
                "svc-prod",
                "owns",
                PrincipalId::service("yubaba"),
                Some(user.clone()),
            )
            .unwrap();
            authority.ownership.insert(&svc, 500).await.unwrap();

            let minted = authority
                .mint_token_exchange(
                    user.clone(),
                    camp.clone(),
                    Some(Actor::new(PrincipalId::service("agent-claude"))),
                    aud,
                    vec![yah_scopes::CLOUD_DEPLOY],
                    1_000,
                )
                .await
                .unwrap();

            assert!(minted.token.starts_with("v4.public."));
            // sub is the USER, not the camp — exchange attributes to the
            // human even though the camp is the bearer at the HTTP layer.
            assert_eq!(minted.claims.sub, user);
            // camp_id carries the camp context (bare id, no prefix).
            assert_eq!(minted.claims.camp_id.as_deref(), Some("c-multi"));
            // act carries the agent variant.
            assert_eq!(
                minted.claims.act.as_ref().unwrap().sub,
                PrincipalId::service("agent-claude"),
            );
            // user-fresh — the user authenticated locally.
            assert_eq!(minted.claims.auth_strength, Some(AuthStrength::UserFresh));
            // Result scope is the requested scope (verified in intersection).
            assert_eq!(minted.claims.scope, vec![yah_scopes::CLOUD_DEPLOY]);
            // owns comes from the CAMP, not the user.
            assert_eq!(minted.claims.owns.service, vec!["svc-prod".to_string()]);
            // jti present, iat/exp respect policy.
            assert!(!minted.claims.jti.is_empty());
            assert_eq!(minted.claims.iat, 1_000);
            assert_eq!(
                minted.claims.exp,
                1_000 + McpPolicy::DEFAULT_ACCESS_TTL_SECONDS
            );
            // Edge verifies.
            let back = verifier.verify_mcp_at(&minted.token, 1_100, RIG_KID).unwrap();
            assert_eq!(back, minted.claims);
        });
    }

    #[test]
    fn mint_token_exchange_intersection_drops_scope_one_side_lacks() {
        // Verify intersection by removing a scope from one side and observing
        // it's rejected at the requested-scope check — proves the camp's
        // grants actually narrow the user's, not just rubber-stamp the
        // request.
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("bob");
        let camp = PrincipalId::camp("c-narrow");
        let aud = "https://aud.example";

        // User has both; camp has only CloudRead.
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![
                ScopeOrBundle::Scope(yah_scopes::CLOUD_DEPLOY),
                ScopeOrBundle::Scope(yah_scopes::CLOUD_READ),
            ],
        );
        put_simple_grant(
            &authority,
            camp.clone(),
            aud,
            vec![ScopeOrBundle::Scope(yah_scopes::CLOUD_READ)],
        );

        pollster::block_on(async {
            // Requesting CloudRead alone succeeds — in both.
            let minted = authority
                .mint_token_exchange(
                    user.clone(),
                    camp.clone(),
                    None,
                    aud,
                    vec![yah_scopes::CLOUD_READ],
                    1_000,
                )
                .await
                .unwrap();
            assert_eq!(minted.claims.scope, vec![yah_scopes::CLOUD_READ]);

            // Requesting CloudDeploy fails — camp lacks it. The whole
            // exchange rejects (not a partial token).
            let err = authority
                .mint_token_exchange(
                    user,
                    camp,
                    None,
                    aud,
                    vec![yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY],
                    1_000,
                )
                .await
                .unwrap_err();
            match err {
                McpMintError::InvalidScope { scope, aud: a } => {
                    assert_eq!(scope, yah_scopes::CLOUD_DEPLOY);
                    assert_eq!(a, aud);
                }
                other => panic!("expected InvalidScope, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_token_exchange_rejects_scope_user_lacks() {
        // Mirror case: camp has it, user doesn't. Same all-or-nothing reject.
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("carol");
        let camp = PrincipalId::camp("c-wide");
        let aud = "https://aud.example";

        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![ScopeOrBundle::Scope(yah_scopes::CLOUD_READ)],
        );
        put_simple_grant(
            &authority,
            camp.clone(),
            aud,
            vec![
                ScopeOrBundle::Scope(yah_scopes::CLOUD_READ),
                ScopeOrBundle::Scope(yah_scopes::CLOUD_DEPLOY),
            ],
        );

        pollster::block_on(async {
            let err = authority
                .mint_token_exchange(
                    user,
                    camp,
                    None,
                    aud,
                    vec![yah_scopes::CLOUD_DEPLOY],
                    1_000,
                )
                .await
                .unwrap_err();
            match err {
                McpMintError::InvalidScope { scope, aud: _ } => {
                    assert_eq!(scope, yah_scopes::CLOUD_DEPLOY);
                }
                other => panic!("expected InvalidScope, got {other:?}"),
            }
        });
    }

    // ---- mint_token_exchange: rejection paths ------------------------------

    #[test]
    fn mint_token_exchange_rejects_wrong_user_kind() {
        let (authority, _verifier) = rig();
        pollster::block_on(async {
            let err = authority
                .mint_token_exchange(
                    PrincipalId::camp("c-as-user"),
                    PrincipalId::camp("c"),
                    None,
                    "https://aud.example",
                    vec![],
                    1_000,
                )
                .await
                .unwrap_err();
            match err {
                McpMintError::WrongPrincipalKind { expected, got } => {
                    assert_eq!(expected, PrincipalKind::User);
                    assert_eq!(got, PrincipalKind::Camp);
                }
                other => panic!("expected WrongPrincipalKind, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_token_exchange_rejects_wrong_camp_kind() {
        let (authority, _verifier) = rig();
        pollster::block_on(async {
            let err = authority
                .mint_token_exchange(
                    PrincipalId::user("alice"),
                    PrincipalId::service("yubaba"),
                    None,
                    "https://aud.example",
                    vec![],
                    1_000,
                )
                .await
                .unwrap_err();
            match err {
                McpMintError::WrongPrincipalKind { expected, got } => {
                    assert_eq!(expected, PrincipalKind::Camp);
                    assert_eq!(got, PrincipalKind::Service);
                }
                other => panic!("expected WrongPrincipalKind, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_token_exchange_rejects_unentitled_user() {
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("eve");
        let camp = PrincipalId::camp("c");
        let aud = "https://aud.example";
        // Camp has a grant, user doesn't — must reject on the user side.
        put_simple_grant(
            &authority,
            camp.clone(),
            aud,
            vec![ScopeOrBundle::Scope(yah_scopes::CLOUD_READ)],
        );

        pollster::block_on(async {
            let err = authority
                .mint_token_exchange(user, camp, None, aud, vec![yah_scopes::CLOUD_READ], 1_000)
                .await
                .unwrap_err();
            match err {
                McpMintError::AudNotEntitled { principal, aud: _ } => {
                    assert_eq!(principal, "user:eve");
                }
                other => panic!("expected AudNotEntitled, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_token_exchange_rejects_unentitled_camp() {
        // Mirror: user has a grant, camp doesn't. Composition rule (5)
        // applies per side, so the camp's empty grant list rejects.
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("frank");
        let camp = PrincipalId::camp("c-no-grants");
        let aud = "https://aud.example";
        put_simple_grant(
            &authority,
            user.clone(),
            aud,
            vec![ScopeOrBundle::Scope(yah_scopes::CLOUD_READ)],
        );

        pollster::block_on(async {
            let err = authority
                .mint_token_exchange(user, camp, None, aud, vec![yah_scopes::CLOUD_READ], 1_000)
                .await
                .unwrap_err();
            match err {
                McpMintError::AudNotEntitled { principal, aud: _ } => {
                    assert_eq!(principal, "camp:c-no-grants");
                }
                other => panic!("expected AudNotEntitled, got {other:?}"),
            }
        });
    }

    #[test]
    fn mint_token_exchange_catches_service_only_scope_smuggled_via_camp_bundle() {
        // Defence in depth — composition rule (4) — even on the exchange
        // path: a camp bundle that expands to OwnershipWrite is caught by
        // validate_grant(Camp, scope) BEFORE intersection is computed.
        let (authority, _verifier) = rig();
        let user = PrincipalId::user("g");
        let camp = PrincipalId::camp("c-sneaky");
        let aud = "https://aud.example";

        pollster::block_on(async {
            authority
                .bundles
                .put(
                    &BundleName::new("dangerous"),
                    &[yah_scopes::CAMP_READ, yah_scopes::AUDIT_WRITE],
                )
                .await
                .unwrap();
            put_simple_grant(
                &authority,
                user.clone(),
                aud,
                vec![ScopeOrBundle::Scope(yah_scopes::CAMP_READ)],
            );
            put_simple_grant(
                &authority,
                camp,
                aud,
                vec![ScopeOrBundle::Bundle(BundleName::new("dangerous"))],
            );

            let err = authority
                .mint_token_exchange(
                    user,
                    PrincipalId::camp("c-sneaky"),
                    None,
                    aud,
                    vec![yah_scopes::CAMP_READ],
                    1_000,
                )
                .await
                .unwrap_err();
            match err {
                McpMintError::GrantMisconfigured(GrantError::ServiceOnlyScope { scope, kind }) => {
                    assert_eq!(scope, yah_scopes::AUDIT_WRITE);
                    assert_eq!(kind, PrincipalKind::Camp);
                }
                other => panic!("expected GrantMisconfigured(ServiceOnlyScope), got {other:?}"),
            }
        });
    }

    // ---- McpMintError → Error conversion -----------------------------------

    #[test]
    fn mcp_mint_error_converts_to_umbrella_error() {
        let e: Error = McpMintError::AudNotEntitled {
            principal: "user:x".into(),
            aud: "a".into(),
        }
        .into();
        match e {
            Error::InvalidInput(msg) => assert!(msg.contains("aud")),
            other => panic!("expected InvalidInput, got {other:?}"),
        }

        let e: Error = McpMintError::Store(StoreError::Conflict).into();
        assert!(matches!(e, Error::Store(StoreError::Conflict)));

        let e: Error = McpMintError::Codec(CodecError::Malformed).into();
        assert!(matches!(e, Error::Codec(CodecError::Malformed)));
    }

    // ---- mint_service (R731-F4) ---------------------------------------------

    use crate::service_principal::{
        MemoryServicePrincipalStore, NewServicePrincipal, ProvisionedKey, ServicePrincipalAuthority,
    };
    use cheers_core::{ClientAssertion, MemoryUsedJtiStore};

    const TOKEN_ENDPOINT: &str = "https://cheers.example/token";
    const SVC_AUD: &str = "https://kamaji.example";

    struct SvcRig {
        authority: McpAuthority<MemoryBundleStore, TestGrants, MemoryOwnershipStore>,
        verifier: PasetoV4PublicVerifier,
        sps: ServicePrincipalAuthority<MemoryServicePrincipalStore>,
        key: ProvisionedKey,
    }

    fn svc_rig() -> SvcRig {
        let (authority, verifier) = rig();
        let store = MemoryServicePrincipalStore::new();
        let authority = authority.with_service_assertions(
            Arc::new(store.clone()),
            Arc::new(MemoryUsedJtiStore::new()),
        );
        let sps = ServicePrincipalAuthority::new(store);
        let key = pollster::block_on(sps.provision(NewServicePrincipal::new("yubaba"), 1)).unwrap();
        SvcRig { authority, verifier, sps, key }
    }

    fn sign_assertion(key: &ProvisionedKey, claims: &ClientAssertion) -> String {
        let sk = pasetors::keys::AsymmetricSecretKey::<V4>::from(&key.secret_key[..]).unwrap();
        let footer = serde_json::to_vec(&serde_json::json!({ "kid": key.signing_key.kid })).unwrap();
        let payload = serde_json::to_vec(claims).unwrap();
        PublicToken::sign(&sk, &payload, Some(&footer), None).unwrap()
    }

    fn good_assertion(jti: &str) -> ClientAssertion {
        ClientAssertion::new(PrincipalId::service("yubaba"), TOKEN_ENDPOINT, jti, 1000, 1060)
    }

    fn seed_svc_scope(r: &SvcRig, scope: Scope) {
        put_simple_grant(
            &r.authority,
            PrincipalId::service("yubaba"),
            SVC_AUD,
            vec![ScopeOrBundle::Scope(scope)],
        );
    }

    fn mint(r: &SvcRig, a: &ClientAssertion) -> Result<MintedMcpToken, McpMintError> {
        let t = sign_assertion(&r.key, a);
        pollster::block_on(r.authority.mint_service(&t, SVC_AUD, &[], 1010))
    }

    #[test]
    fn mint_service_happy_path_scopes_from_relationship() {
        let r = svc_rig();
        seed_svc_scope(&r, yah_scopes::CLOUD_READ);
        let minted = mint(&r, &good_assertion("j-ok")).unwrap();
        let claims = r.verifier.verify_mcp_at(&minted.token, 1010, RIG_KID).unwrap();
        assert_eq!(claims.sub, PrincipalId::service("yubaba"));
        assert_eq!(claims.aud, SVC_AUD);
        assert_eq!(claims.scope, vec![yah_scopes::CLOUD_READ]);
        assert!(claims.exp - claims.iat <= 3600);
        assert!(claims.ceiling.is_none());
    }

    #[test]
    fn mint_service_intersects_requested_and_rejects_empty() {
        let r = svc_rig();
        seed_svc_scope(&r, yah_scopes::CLOUD_READ);
        let t = sign_assertion(&r.key, &good_assertion("j-a"));
        let other = [yah_scopes::CLOUD_DEPLOY];
        let err = pollster::block_on(r.authority.mint_service(&t, SVC_AUD, &other, 1010)).unwrap_err();
        assert!(matches!(err, McpMintError::NoGrantedScopes { .. }), "{err:?}");
        // No relationship at all: also rejected.
        let r = svc_rig();
        let err = mint(&r, &good_assertion("j-b")).unwrap_err();
        assert!(matches!(err, McpMintError::NoGrantedScopes { .. }), "{err:?}");
    }

    #[test]
    fn mint_service_rejects_unknown_kid() {
        let r = svc_rig();
        seed_svc_scope(&r, yah_scopes::CLOUD_READ);
        let other = pollster::block_on(
            ServicePrincipalAuthority::new(MemoryServicePrincipalStore::new())
                .provision(NewServicePrincipal::new("yubaba"), 1),
        )
        .unwrap();
        let t = sign_assertion(&other, &good_assertion("j"));
        let err = pollster::block_on(r.authority.mint_service(&t, SVC_AUD, &[], 1010)).unwrap_err();
        assert!(matches!(err, McpMintError::AssertionUnknownKid(_)), "{err:?}");
    }

    #[test]
    fn mint_service_rejects_retired_key() {
        let r = svc_rig();
        seed_svc_scope(&r, yah_scopes::CLOUD_READ);
        pollster::block_on(r.sps.rotate(&PrincipalId::service("yubaba"), 2)).unwrap();
        let err = mint(&r, &good_assertion("j")).unwrap_err();
        assert!(matches!(err, McpMintError::AssertionRetiredKey(_)), "{err:?}");
    }

    #[test]
    fn mint_service_rejects_principal_mismatch() {
        let r = svc_rig();
        seed_svc_scope(&r, yah_scopes::CLOUD_READ);
        let mut a = good_assertion("j1");
        a.sub = PrincipalId::service("someone-else");
        let err = mint(&r, &a).unwrap_err();
        assert!(matches!(err, McpMintError::AssertionPrincipalMismatch { .. }), "{err:?}");
        let mut a = good_assertion("j2");
        a.iss = PrincipalId::service("someone-else");
        let err = mint(&r, &a).unwrap_err();
        assert!(matches!(err, McpMintError::AssertionPrincipalMismatch { .. }), "{err:?}");
    }

    #[test]
    fn mint_service_rejects_bad_aud() {
        let r = svc_rig();
        seed_svc_scope(&r, yah_scopes::CLOUD_READ);
        let mut a = good_assertion("j");
        a.aud = SVC_AUD.into();
        let err = mint(&r, &a).unwrap_err();
        assert!(matches!(err, McpMintError::AssertionBadAudience { .. }), "{err:?}");
    }

    #[test]
    fn mint_service_rejects_expired_and_too_long_assertions() {
        let r = svc_rig();
        seed_svc_scope(&r, yah_scopes::CLOUD_READ);
        let mut a = good_assertion("j1");
        a.exp = 1010;
        let err = mint(&r, &a).unwrap_err();
        assert!(matches!(err, McpMintError::AssertionExpired { .. }), "{err:?}");
        let mut a = good_assertion("j2");
        a.exp = a.iat + ClientAssertion::MAX_LIFETIME_SECONDS + 1;
        let err = mint(&r, &a).unwrap_err();
        assert!(matches!(err, McpMintError::AssertionLifetimeTooLong { .. }), "{err:?}");
        // Exactly the maximum is fine.
        let mut a = good_assertion("j3");
        a.exp = a.iat + ClientAssertion::MAX_LIFETIME_SECONDS;
        mint(&r, &a).unwrap();
    }

    #[test]
    fn mint_service_rejects_replay() {
        let r = svc_rig();
        seed_svc_scope(&r, yah_scopes::CLOUD_READ);
        let a = good_assertion("j-once");
        mint(&r, &a).unwrap();
        let err = mint(&r, &a).unwrap_err();
        assert!(matches!(err, McpMintError::AssertionReplayed(_)), "{err:?}");
    }

    #[test]
    fn mint_service_requires_configuration_and_wellformed_token() {
        let (authority, _) = rig();
        let err = pollster::block_on(authority.mint_service("x", SVC_AUD, &[], 0)).unwrap_err();
        assert!(matches!(err, McpMintError::ServiceAssertionsUnconfigured));
        let r = svc_rig();
        let err = pollster::block_on(r.authority.mint_service("v4.public.garbage", SVC_AUD, &[], 0)).unwrap_err();
        assert!(matches!(err, McpMintError::AssertionMalformed(_)), "{err:?}");
    }
}
