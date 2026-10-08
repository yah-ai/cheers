//! MCP wire contract — scope vocabulary, composition rules, and the
//! `McpClaims` shape carried on a per-call token.
//!
//! See `.yah/docs/working/mcp-auth-and-ownership.md` §Scope vocabulary,
//! §JWT claim schema, and §Scope vocabulary and composition rules. The
//! shapes here are the producer side of the verbatim wire contract yah's
//! kamaji consumes (W159 §The wire / §Layer 2 / §Layer 3).
//!
//! Three pieces:
//!
//! - [`Scope`] — the validated `<namespace>:<verb>` wire type, declared per
//!   product with [`scopes!`](crate::scopes) and checked against a
//!   [`ScopeRegistry`] (see [`crate::scope`]; yah's set is
//!   [`crate::yah_scopes`]).
//! - [`validate_grant`] — the grant/mint-time check against the registry:
//!   refuses unknown scopes, scopes not valid at `aud`, and service-only
//!   scopes for `User` / `Camp` principals (composition rule (4)).
//! - [`McpClaims`] + [`Actor`] / [`Owns`] / [`AuthStrength`] — the per-call
//!   JWT-style claim bundle. `sub` is a [`PrincipalId`] (prefixed); `scope` is
//!   a `Vec<Scope>` (no wildcards on the wire); `act` carries the agent
//!   variant on a user's behalf (RFC 8693); `owns` is the embedded-ownership
//!   claim cheers reads off the ownership table at mint time.
//!
//! @yah:ticket(R731-F2, "Scope registry — replace the closed Scope enum with namespaced, registry-validated scopes (D1)")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-10-06T23:08:28Z)
//! @yah:phase(P1)
//! @yah:parent(R731)
//! @yah:next("Doc D1. The wire type becomes a validated namespace:verb string checked against a registry built at startup; entries carry service_only, a description and valid audiences. The 17 yah scopes become one built-in namespace set.")
//! @yah:next("Discovery scopes_supported reads the registry (cheers-axum/src/discovery.rs:125 reads Scope::ALL today).")
//! @yah:next("Decide inside this ticket: a scopes! macro or a ProductScopes trait. It must work for verify-only crates that never link cheers-server (cheers-verify, noisetable issues and inference).")
//! @yah:next("Blast radius: McpClaims.scope is Vec<Scope>; at least 14 yah-tree files name Scope beside cheers (kamaji, cloud-admin, yubaba). Change the type and fix the call sites; no dual parse. Coordinate with yah R426.")
//! @yah:next("Composition rules carry over: no wildcards, :admin distinct from :read/:write, service-only refused at grant, aud mandatory.")
//! @yah:verify("cargo test -p cheers-core; the discovery test pins scopes_supported to the registry.")
//! @yah:tier(Wizard)
//! @yah:gotcha("Scheduling edge (leader, 2026-10-06): F2 changes McpClaims.scope's type and leaves every cheers crate + kamaji uncompilable until all call sites are fixed, which would stall B1's and F7's test runs on the shared tree. F2 waits for both.")
//! @yah:depends_on(R731-B1)
//! @yah:depends_on(R731-F7)
//! @yah:next("D1 TYPING DECIDED (leader, 2026-10-06): use a declarative `cheers_core::scopes!` macro_rules, not a trait. A product declares a set in one place, and the macro emits (a) a typed `pub const` per scope, so a typo is a compile error, and (b) `pub const DEFS: &[ScopeDef]` carrying {scope, service_only, description, audiences}. It needs only cheers-core, so verify-only crates (cheers-verify, noisetable issues/inference) declare or import constants without ever linking cheers-server. Scope is a validated newtype (owned Arc<str> or Cow), grammar `<ns>:<verb>` with each side matching [a-z][a-z0-9-]*, exactly one colon, '*' refused. Validation runs at parse/deserialize, and the macro's constructor is a const fn that panics at compile time on bad input.")
//! @yah:gotcha("D1 REGISTRY DECIDED (leader): `ScopeRegistry` is built at startup from DEFS slices and fails on a duplicate scope. It answers service_only, description and is_valid_at(aud). Audience metadata is `Audiences::Any | Audiences::Only(&[..])`. yah's 17 built-ins become `cheers_core::yah_scopes` (declared with the same macro) with Audiences::Any, which preserves today's behavior; pinning them to yah audiences is yah-side R426 work. Product scopes declare Only. Consumers: validate_grant and the mint paths take the registry (Scope::is_service_only is deleted; an unknown scope is refused at grant and at mint), and discovery's scopes_supported reads the registry from app state. Verifiers do NOT consult the registry: they compare claims against typed constants. Storage (audit stores, user_tokens) keeps wire strings, and decode accepts any syntactically valid scope. Keep ownership:write for now; R731-F8 deletes it. Call sites outside cheers to fix: yah crates/yah/cloud-admin/src/{auth.rs,lib.rs}, app/yah/cli/src/cloud_cheers.rs, oss/passway tests, plus any hub-cheers-rpc use. kamaji imports no cheers Scope.")
//! @yah:handoff("LANDED. New crates/cheers-core/src/scope.rs: Scope is a newtype over Cow<'static, str> (Cow, not Arc, because a const fn can build Cow::Borrowed). It is Clone, not Copy. The grammar is [a-z][a-z0-9-]*:[a-z][a-z0-9-]*: exactly one colon, and '*' is refused as Wildcard. FromStr and Deserialize accept any well-formed scope. ScopeParseError::Unknown was replaced by Malformed. Scope::from_static is a const fn whose assert panics at compile time. The file also has #[macro_export] scopes! (entries look like `NAME = \"ns:verb\" { description: \"..\" [, service_only: true] [, audiences: [..]] };` and emit a pub const per scope plus pub const DEFS: &[ScopeDef]), Audiences {Any, Only(&'static [&'static str])}, ScopeDef {scope, service_only, description, audiences}, and ScopeRegistry with ScopeRegistryBuilder::with(defs).build() -> Result<_, DuplicateScope>. The registry offers get, contains, service_only, description, is_valid_at, iter (in declaration order), len and is_empty.")
//! @yah:handoff("New crates/cheers-core/src/yah_scopes.rs declares the 17 scopes with scopes!, all Audiences::Any, with ownership:write and audit:write service_only. It adds yah_scopes::registry_at([AUD]).unwrap(). Scope::ALL, Scope::is_service_only and as_wire(self)->&'static str are deleted; as_wire is now (&self)->&str.")
//! @yah:handoff("validate_grant(registry, kind, &scope, aud) in mcp.rs refuses UnknownScope, then NotValidAtAud, then ServiceOnlyScope (all GrantError variants). McpAuthority::new takes a new Arc<ScopeRegistry> argument after `ownership`, and McpAuthority::scopes() exposes it. All 6 mint call sites pass (&self.scopes, kind, s, &aud). DiscoveryState::new(issuer, Arc<ScopeRegistry>), and scopes_supported is read from the registry.")
//! @yah:handoff("Extra work: cheers-axum tokens.rs parse_scopes now takes the registry and returns 400 InvalidTokenRequest for an undeclared scope. Before this, parse_scopes rejected unknown scopes at parse time. Storage decode (user_tokens::decode_scopes) now accepts any well-formed scope (decision 6), and its test was renamed decode_scopes_accepts_undeclared_and_refuses_malformed. The discovery test is now scopes_supported_equals_the_registry, which uses a 17+1 registry, and the cheers-axum lib.rs @yah:verify line was updated to the new name. New mint test: mint_user_fresh_rejects_scope_missing_from_registry.")
//! @yah:handoff("GRANT-TIME NOTE: the GrantStore trait has no write method (MemoryGrantStore::put is test-only), so the registry is threaded through McpAuthority. There, validate_grant runs on every expanded scope before signing. That check covers both 'at grant' and 'at mint' until a persistent grant write API exists. F3's SchemaGrantStore should call validate_grant/is_valid_at when it lands.")
//! @yah:handoff("yah tree, type migration only: crates/yah/cloud-admin/src/auth.rs and lib.rs (tests), app/yah/cli/src/cloud_cheers.rs (validate_grant now takes yah_scopes::registry_at([AUD]).unwrap() and the --aud value), and oss/passway/crates/passway/tests/{auth_gate,path_confusion}.rs. hub-cheers-rpc and kamaji name no cheers Scope. R426 has a coordination gotcha appended.")
//! @yah:verify("cargo test --workspace in oss/cheers: 652 passed / 0 failed / 3 ignored (baseline 640/0/3; +12 new tests). Golden fixtures (cheers-server/tests/golden_fixtures.rs and the cheers-test-support fixtures) pass without regeneration. The only modified fixture is cheers-test-support/fixtures/jwks.json, whose mtime predates this ticket's edits; it belongs to B1.")
//! @yah:verify("cargo test -p yah-cloud-admin: 60 passed / 0 failed. cargo check -p yah --all-targets: exit 0.")
//! @yah:verify("oss/passway cargo test FAILS BEFORE COMPILING. The failure is in a file I did not touch: oss/passway/crates/passway/Cargo.toml pins cheers-core/cheers-verify version 0.8.42, and cheers is at 0.8.43-pre.1, so cargo can't select a version. That is a peer's or a release bump's skew. The 2 passway test files are migrated but unverified until that manifest is bumped.")
//! @yah:verify("Remaining warning: unused variable `policy` in cheers-test-support/src/lib.rs:222. It is pre-existing and not in a file I touched.")
//! @yah:gotcha("PRE-EXISTING, NOT R731: oss/passway can't resolve against in-tree cheers. crates/passway/Cargo.toml:69-70 pins cheers-core/cheers-verify at version \"0.8.42\", while cheers has been 0.8.43-pre.1 since commit ea6a4b29 (2026-10-04 sync), and a caret req never matches a prerelease. So F2's two passway test edits (tests/{auth_gate,path_confusion}.rs: Scope::CloudRead -> yah_scopes::CLOUD_READ) are checked by inspection only. Bumping the pin is a release-lockstep call (passway itself is 0.8.42 and would then require a prerelease cheers), so it is left to the release owner.")
//! @yah:verify("Leader re-verify 2026-10-06: cargo test --workspace (oss/cheers) 652 pass / 0 fail / 3 ignored, no build skew; 0 non-comment references to Scope::ALL / is_service_only remain in cheers crates.")

use serde::{Deserialize, Serialize};

use crate::principal::{PrincipalId, PrincipalKind};

use crate::scope::{Scope, ScopeRegistry};

/// A failed grant — the rule that fired and the offending pair.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    /// The deployment's [`ScopeRegistry`] does not declare this scope.
    #[error("scope {scope} is not declared in this deployment's scope registry")]
    UnknownScope { scope: Scope },
    /// The scope is declared, but not valid at this `aud`.
    #[error("scope {scope} is not valid at aud '{aud}'")]
    NotValidAtAud { scope: Scope, aud: String },
    /// Composition rule (4): service-only scopes (`audit:write`, or any
    /// registry entry marked `service_only`) are
    /// grantable to `Service` principals only.
    #[error("scope {scope} is service-only; cannot grant to {kind} principal")]
    ServiceOnlyScope { scope: Scope, kind: PrincipalKind },
}

/// Grant-time validation against the deployment's [`ScopeRegistry`]. The
/// mint paths run it per expanded scope before signing.
///
/// Refuses, in order: a scope the registry does not declare, a scope not
/// valid at `aud`, and a service-only scope for a non-`Service` principal
/// (composition rule (4)). The other rules:
///
/// - (1) No wildcards: enforced by `Scope::from_str` — a wildcard never
///   parses into a `Scope`.
/// - (3) `<category>:admin` is distinct: scopes are opaque strings with no
///   implication between them, so a grant of `camp:admin` is literally not a
///   grant of `camp:read`.
/// - (5) `aud` is mandatory: it is a required argument here, and the mint
///   paths refuse a principal with no grant for `aud`.
pub fn validate_grant(
    registry: &ScopeRegistry,
    kind: PrincipalKind,
    scope: &Scope,
    aud: &str,
) -> Result<(), GrantError> {
    let Some(def) = registry.get(scope) else {
        return Err(GrantError::UnknownScope { scope: scope.clone() });
    };
    if !registry.is_valid_at(scope, aud) {
        return Err(GrantError::NotValidAtAud { scope: scope.clone(), aud: aud.to_owned() });
    }
    if def.service_only && kind != PrincipalKind::Service {
        return Err(GrantError::ServiceOnlyScope { scope: scope.clone(), kind });
    }
    Ok(())
}

/// The `act` claim — RFC 8693 acted-on-by — identifies the agent variant
/// acting on the primary subject's behalf. The agent is never the primary
/// `sub`; it appears only here.
///
/// `sub` here is the agent's principal id (typically `svc:agent-<variant>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Actor {
    pub sub: PrincipalId,
}

impl Actor {
    pub fn new(sub: PrincipalId) -> Self {
        Self { sub }
    }
}

/// The `owns` claim — embedded ownership cheers bakes into the token at mint
/// time. Per W159 §Layer 2, this is what lets kamaji check resource
/// membership locally with no per-call cheers round-trip.
///
/// Open-ended: explicit fields for the resource kinds cheers currently writes
/// (`service`, `arch_doc`, `node`) plus a `flatten`ed catch-all for future
/// kinds so adding one doesn't break the wire contract.
///
/// `node` (W268 §The binding: enrollment is an ownership row) is the
/// machine-identity resource kind: a row `principal owns node:<NodeId>`
/// records that a fleet machine (or paired end-user device) is enrolled to
/// `principal`. `resource_id` is the mshr `NodeId` in the same hex encoding
/// yubaba's `/identity` route serves.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Owns {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arch_doc: Vec<String>,
    /// NodeIds (hex-encoded mshr identity) enrolled to this principal.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node: Vec<String>,
    /// Forward-compatibility spill for resource kinds added after this lands.
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, Vec<String>>,
}

impl Owns {
    pub fn is_empty(&self) -> bool {
        self.service.is_empty()
            && self.arch_doc.is_empty()
            && self.node.is_empty()
            && self.extra.is_empty()
    }
}

/// How the principal's identity was last asserted — `bootstrap` for tokens
/// minted off a camp's long-lived bootstrap credential, `user-fresh` for
/// tokens minted within ~N minutes of a fresh passkey assertion,
/// `api-token` for a long-lived user API token (PAT).
///
/// Downstream services MAY require `user-fresh` for sensitive ops
/// (mirrors W127's elevation pattern). [`ApiToken`](Self::ApiToken) exists so
/// that requirement is decidable: a PAT carries the user's *identity* and a
/// subset of their scopes, but no live ceremony stands behind it, so a route
/// guarding a destructive verb can demand `user-fresh` and refuse a PAT by
/// reading one claim rather than inferring it from TTL or scope shape.
///
/// **Ordering is deliberately absent.** These are not ranked strengths — a
/// consumer states the set it accepts (`matches!(s, UserFresh)`), because
/// "at least X" has no meaning across a camp bootstrap credential and a
/// user's PAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum AuthStrength {
    Bootstrap,
    UserFresh,
    /// Minted by
    /// [`McpAuthority::mint_api_token`](https://docs.rs/cheers-server) off an
    /// already-authenticated user session. Long-lived (90 days by default,
    /// 365 max), non-interactive, and never wider than the grants its holder
    /// had at mint time.
    ApiToken,
}

/// MCP-call token claims — verbatim with W159 §The wire.
///
/// Required: `iss`, `aud`, `exp`, `iat`, `jti`, `sub`, `scope`.
/// Conditional: `act` (when an agent is acting on the user's behalf),
/// `camp_id` (when scoped to a camp), `owns` (embedded ownership),
/// `auth_strength` (set by the mint path).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct McpClaims {
    pub iss: String,
    pub aud: String,
    pub sub: PrincipalId,
    pub iat: i64,
    pub exp: i64,
    pub jti: String,
    pub scope: Vec<Scope>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Actor>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub camp_id: Option<String>,
    #[serde(default, skip_serializing_if = "Owns::is_empty")]
    pub owns: Owns,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_strength: Option<AuthStrength>,
    /// A self-signed token's [`ServiceCeiling`](crate::ServiceCeiling), as the
    /// PASETO v4.public cheers signed it (§D5). `None` on issuer-signed
    /// tokens; required by verifiers when the signing key is a self-signer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ceiling: Option<String>,
}

impl McpClaims {
    /// Build a minimal `McpClaims` with only the required fields set.
    pub fn new(
        iss: impl Into<String>,
        aud: impl Into<String>,
        sub: PrincipalId,
        iat: i64,
        exp: i64,
        jti: impl Into<String>,
        scope: Vec<Scope>,
    ) -> Self {
        Self {
            iss: iss.into(),
            aud: aud.into(),
            sub,
            iat,
            exp,
            jti: jti.into(),
            scope,
            act: None,
            camp_id: None,
            owns: Owns::default(),
            auth_strength: None,
            ceiling: None,
        }
    }

    pub fn with_act(mut self, act: Actor) -> Self {
        self.act = Some(act);
        self
    }

    pub fn with_camp_id(mut self, camp_id: impl Into<String>) -> Self {
        self.camp_id = Some(camp_id.into());
        self
    }

    pub fn with_owns(mut self, owns: Owns) -> Self {
        self.owns = owns;
        self
    }

    pub fn with_ceiling(mut self, ceiling: impl Into<String>) -> Self {
        self.ceiling = Some(ceiling.into());
        self
    }

    pub fn with_auth_strength(mut self, strength: AuthStrength) -> Self {
        self.auth_strength = Some(strength);
        self
    }

    /// `true` if `exp` is at or before `now` (unix seconds) — mirrors
    /// [`crate::Claims::is_expired_at`].
    pub fn is_expired_at(&self, now: i64) -> bool {
        self.exp <= now
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yah_scopes;
    use std::str::FromStr;

    #[test]
    fn scope_wire_string_roundtrips_for_every_yah_scope() {
        for d in yah_scopes::DEFS {
            let wire = d.scope.as_wire();
            assert_eq!(Scope::from_str(wire).unwrap(), d.scope, "roundtrip failed for {wire}");
        }
    }

    #[test]
    fn scope_parser_accepts_undeclared_but_well_formed() {
        // Syntax is not registry membership: storage and verifiers decode any
        // well-formed scope.
        assert_eq!(Scope::from_str("cloud:nuke").unwrap().as_wire(), "cloud:nuke");
    }

    #[test]
    fn scope_serialize_is_plain_string() {
        let v = vec![yah_scopes::CLOUD_DEPLOY, yah_scopes::CLOUD_READ];
        let json = serde_json::to_string(&v).unwrap();
        assert_eq!(json, r#"["cloud:deploy","cloud:read"]"#);
        let back: Vec<Scope> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn scope_deserialize_rejects_wildcard_in_list() {
        let err = serde_json::from_str::<Vec<Scope>>(r#"["cloud:read","cloud:*"]"#).unwrap_err();
        assert!(
            err.to_string().contains("wildcard"),
            "expected wildcard message, got: {err}"
        );
    }

    #[test]
    fn scope_deserialize_rejects_malformed() {
        let err = serde_json::from_str::<Vec<Scope>>(r#"["cloud"]"#).unwrap_err();
        assert!(err.to_string().contains("malformed"), "got: {err}");
    }

    const AUD: &str = "https://aud.example";

    #[test]
    fn validate_grant_rejects_service_only_for_user() {
        let reg = yah_scopes::registry_at([AUD]).unwrap();
        for s in [yah_scopes::AUDIT_WRITE] {
            let err = validate_grant(&reg, PrincipalKind::User, &s, AUD).unwrap_err();
            assert_eq!(err, GrantError::ServiceOnlyScope { scope: s, kind: PrincipalKind::User });
        }
    }

    #[test]
    fn validate_grant_rejects_service_only_for_camp() {
        let reg = yah_scopes::registry_at([AUD]).unwrap();
        let err =
            validate_grant(&reg, PrincipalKind::Camp, &yah_scopes::AUDIT_WRITE, AUD).unwrap_err();
        assert!(matches!(err, GrantError::ServiceOnlyScope { kind: PrincipalKind::Camp, .. }));
    }

    #[test]
    fn validate_grant_allows_service_principal_for_service_only_scopes() {
        let reg = yah_scopes::registry_at([AUD]).unwrap();
        validate_grant(&reg, PrincipalKind::Service, &yah_scopes::AUDIT_WRITE, AUD).unwrap();
    }

    #[test]
    fn validate_grant_allows_normal_scopes_for_any_principal() {
        let reg = yah_scopes::registry_at([AUD]).unwrap();
        for k in [PrincipalKind::User, PrincipalKind::Service, PrincipalKind::Camp] {
            for s in [
                yah_scopes::ARCH_READ,
                yah_scopes::CLOUD_DEPLOY,
                yah_scopes::CAMP_ADMIN,
                yah_scopes::AUDIT_READ,
            ] {
                validate_grant(&reg, k, &s, AUD).unwrap();
            }
        }
    }

    #[test]
    fn validate_grant_rejects_unknown_scope() {
        let reg = yah_scopes::registry_at([AUD]).unwrap();
        let s = Scope::from_str("cloud:nuke").unwrap();
        let err = validate_grant(&reg, PrincipalKind::Service, &s, AUD).unwrap_err();
        assert_eq!(err, GrantError::UnknownScope { scope: s });
    }

    #[test]
    fn validate_grant_rejects_scope_not_valid_at_aud() {
        mod pinned {
            crate::scopes! {
                TRIAGE = "issues:triage" {
                    description: "triage",
                    audiences: ["https://issues.example"],
                };
            }
        }
        let reg = ScopeRegistry::builder().with(pinned::DEFS).build().unwrap();
        validate_grant(&reg, PrincipalKind::User, &pinned::TRIAGE, "https://issues.example")
            .unwrap();
        let err = validate_grant(&reg, PrincipalKind::User, &pinned::TRIAGE, AUD).unwrap_err();
        assert_eq!(
            err,
            GrantError::NotValidAtAud { scope: pinned::TRIAGE, aud: AUD.to_owned() }
        );
    }

    #[test]
    fn camp_admin_is_distinct_from_camp_read_and_camp_write() {
        // No implication between scopes: distinct strings are distinct grants.
        assert_ne!(yah_scopes::CAMP_ADMIN, yah_scopes::CAMP_READ);
        // camp:write is well-formed but not in yah's vocabulary.
        let reg = yah_scopes::registry_at([AUD]).unwrap();
        assert!(!reg.contains(&Scope::from_str("camp:write").unwrap()));
    }

    #[test]
    fn auth_strength_serializes_kebab_case() {
        assert_eq!(serde_json::to_string(&AuthStrength::Bootstrap).unwrap(), "\"bootstrap\"");
        assert_eq!(serde_json::to_string(&AuthStrength::UserFresh).unwrap(), "\"user-fresh\"");
        assert_eq!(serde_json::to_string(&AuthStrength::ApiToken).unwrap(), "\"api-token\"");
        let back: AuthStrength = serde_json::from_str("\"user-fresh\"").unwrap();
        assert_eq!(back, AuthStrength::UserFresh);
        let back: AuthStrength = serde_json::from_str("\"api-token\"").unwrap();
        assert_eq!(back, AuthStrength::ApiToken);
    }

    /// A PAT is not a fresh ceremony, and nothing may quietly treat it as one.
    /// The elevation check downstream services run is `== UserFresh`; this
    /// pins that `ApiToken` is a distinct value rather than an alias.
    #[test]
    fn api_token_is_not_user_fresh() {
        assert_ne!(AuthStrength::ApiToken, AuthStrength::UserFresh);
        assert_ne!(AuthStrength::ApiToken, AuthStrength::Bootstrap);
    }

    #[test]
    fn owns_omits_empty_lists_on_wire_but_roundtrips() {
        let o = Owns::default();
        let json = serde_json::to_string(&o).unwrap();
        assert_eq!(json, "{}");

        let o = Owns {
            service: vec!["svc-a".into()],
            arch_doc: vec![],
            node: vec![],
            extra: Default::default(),
        };
        let json = serde_json::to_string(&o).unwrap();
        assert_eq!(json, r#"{"service":["svc-a"]}"#);
        let back: Owns = serde_json::from_str(&json).unwrap();
        assert_eq!(back, o);
    }

    #[test]
    fn owns_extra_carries_unknown_resource_kinds() {
        let json = r#"{"service":["s1"],"pond":["p1","p2"]}"#;
        let o: Owns = serde_json::from_str(json).unwrap();
        assert_eq!(o.service, vec!["s1".to_string()]);
        assert_eq!(o.extra.get("pond"), Some(&vec!["p1".into(), "p2".into()]));

        // Roundtrip preserves the extra kind.
        let back = serde_json::to_string(&o).unwrap();
        assert!(back.contains(r#""pond":["p1","p2"]"#));
    }

    fn sample_claims() -> McpClaims {
        McpClaims::new(
            "https://cheers.example",
            "https://kamaji.camp.example",
            PrincipalId::user("alice"),
            1000,
            1300,
            "jti-1",
            vec![yah_scopes::CLOUD_DEPLOY, yah_scopes::CLOUD_READ],
        )
        .with_act(Actor::new(PrincipalId::service("agent-claude")))
        .with_camp_id("camp-xyz")
        .with_owns(Owns {
            service: vec!["svc-a".into()],
            arch_doc: vec!["doc-1".into()],
            node: vec![],
            extra: Default::default(),
        })
        .with_auth_strength(AuthStrength::UserFresh)
    }

    #[test]
    fn mcp_claims_roundtrip_full_shape() {
        let c = sample_claims();
        let json = serde_json::to_string(&c).unwrap();
        // sub preserved as a prefixed string.
        assert!(json.contains(r#""sub":"user:alice""#));
        assert!(json.contains(r#""act":{"sub":"svc:agent-claude"}"#));
        assert!(json.contains(r#""camp_id":"camp-xyz""#));
        assert!(json.contains(r#""auth_strength":"user-fresh""#));
        assert!(json.contains(r#""scope":["cloud:deploy","cloud:read"]"#));
        let back: McpClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn mcp_claims_minimal_shape_omits_optionals() {
        let c = McpClaims::new(
            "iss",
            "aud",
            PrincipalId::service("yubaba"),
            1000,
            1300,
            "jti-2",
            vec![yah_scopes::AUDIT_WRITE],
        );
        let json = serde_json::to_string(&c).unwrap();
        for absent in ["\"act\"", "\"camp_id\"", "\"owns\"", "\"auth_strength\""] {
            assert!(
                !json.contains(absent),
                "{absent} must be omitted when unset: {json}"
            );
        }
        let back: McpClaims = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn mcp_claims_expiry_check() {
        let c = sample_claims();
        assert!(!c.is_expired_at(1299));
        assert!(c.is_expired_at(1300));
        assert!(c.is_expired_at(1301));
    }

    #[test]
    fn mcp_claims_deserialize_rejects_unprefixed_sub() {
        let json = r#"{"iss":"i","aud":"a","sub":"alice","iat":1,"exp":2,"jti":"j","scope":[]}"#;
        let err = serde_json::from_str::<McpClaims>(json).unwrap_err();
        assert!(
            err.to_string().contains("must be prefixed"),
            "expected prefix-required error: {err}"
        );
    }

    #[test]
    fn mcp_claims_deserialize_rejects_wildcard_scope() {
        let json = r#"{"iss":"i","aud":"a","sub":"user:alice","iat":1,"exp":2,"jti":"j","scope":["cloud:*"]}"#;
        let err = serde_json::from_str::<McpClaims>(json).unwrap_err();
        assert!(err.to_string().contains("wildcard"), "expected wildcard rejection: {err}");
    }
}
