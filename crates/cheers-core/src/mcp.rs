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
//! - [`Scope`] — the closed enum of MCP scopes. `Display`/`FromStr`/serde
//!   roundtrip through the literal wire string (`"cloud:deploy"`). The parser
//!   rejects wildcards (`"cloud:*"`) at parse time — composition rule (1).
//! - [`validate_grant`] — the grant-time check that rejects writing
//!   `ownership:write` or `audit:write` to a `User` or `Camp` principal
//!   (composition rule (4)). The rule lives at the **grant API**, not the
//!   mint path, so a misconfigured grant can never become a mintable token.
//! - [`McpClaims`] + [`Actor`] / [`Owns`] / [`AuthStrength`] — the per-call
//!   JWT-style claim bundle. `sub` is a [`PrincipalId`] (prefixed); `scope` is
//!   a `Vec<Scope>` (no wildcards on the wire); `act` carries the agent
//!   variant on a user's behalf (RFC 8693); `owns` is the embedded-ownership
//!   claim cheers reads off the ownership table at mint time.

use serde::{Deserialize, Serialize};

use crate::principal::{PrincipalId, PrincipalKind};

/// The closed set of MCP scopes — verbatim with W159 §Scope vocabulary.
///
/// Each variant maps to one literal wire string via [`Scope::as_wire`].
/// `<category>:admin` is **distinct** from `<category>:read`/`<category>:write`:
/// granting `camp:admin` does NOT imply `camp:read` (composition rule (3)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Scope {
    ArchRead,
    ArchWrite,
    BoardRead,
    BoardWrite,
    CampRead,
    CampAdmin,
    CloudRead,
    CloudDeploy,
    CloudDestroy,
    /// Fleet-operator admin — sees every machine/workload in the cloud
    /// snapshot (the yah-cloud-admin dashboard's gate; R568-F5). Distinct
    /// from `CloudRead` (which is the tenant-facing read scope, filtered by
    /// principal ownership).
    CloudAdmin,
    PartyRead,
    PartyWrite,
    SubagentSpawn,
    SubagentControl,
    /// Service-principals only — see [`validate_grant`].
    OwnershipWrite,
    AuditRead,
    /// Service-principals only — see [`validate_grant`].
    AuditWrite,
}

impl Scope {
    /// The literal wire string (e.g. `"cloud:deploy"`).
    pub const fn as_wire(self) -> &'static str {
        match self {
            Self::ArchRead => "arch:read",
            Self::ArchWrite => "arch:write",
            Self::BoardRead => "board:read",
            Self::BoardWrite => "board:write",
            Self::CampRead => "camp:read",
            Self::CampAdmin => "camp:admin",
            Self::CloudRead => "cloud:read",
            Self::CloudDeploy => "cloud:deploy",
            Self::CloudDestroy => "cloud:destroy",
            Self::CloudAdmin => "cloud:admin",
            Self::PartyRead => "party:read",
            Self::PartyWrite => "party:write",
            Self::SubagentSpawn => "subagent:spawn",
            Self::SubagentControl => "subagent:control",
            Self::OwnershipWrite => "ownership:write",
            Self::AuditRead => "audit:read",
            Self::AuditWrite => "audit:write",
        }
    }

    /// `true` iff this scope is grantable only to a [`PrincipalKind::Service`]
    /// principal — composition rule (4).
    pub const fn is_service_only(self) -> bool {
        matches!(self, Self::OwnershipWrite | Self::AuditWrite)
    }

    /// Every variant in the closed scope vocabulary.
    ///
    /// `cheers-axum`'s OIDC discovery endpoint reads `scopes_supported`
    /// straight from this constant so the discovery doc cannot drift from
    /// what the mint path accepts. The companion `scope_all_is_exhaustive`
    /// test below uses an exhaustive intra-crate match against
    /// [`Scope`] (which is `#[non_exhaustive]` for *external* users but
    /// fully matchable here) — adding a variant without listing it in
    /// `ALL` either fails to compile (missing match arm) or fails the
    /// per-arm assertion.
    pub const ALL: &'static [Scope] = &[
        Self::ArchRead,
        Self::ArchWrite,
        Self::BoardRead,
        Self::BoardWrite,
        Self::CampRead,
        Self::CampAdmin,
        Self::CloudRead,
        Self::CloudDeploy,
        Self::CloudDestroy,
        Self::CloudAdmin,
        Self::PartyRead,
        Self::PartyWrite,
        Self::SubagentSpawn,
        Self::SubagentControl,
        Self::OwnershipWrite,
        Self::AuditRead,
        Self::AuditWrite,
    ];
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_wire())
    }
}

/// Why a scope string failed to parse.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeParseError {
    /// `cloud:*` and friends are rejected — composition rule (1), no wildcards
    /// on the wire.
    #[error("wildcard scope '{0}' is not allowed on the wire")]
    Wildcard(String),
    /// Not one of the closed-vocabulary literals.
    #[error("unknown scope '{0}'")]
    Unknown(String),
}

impl std::str::FromStr for Scope {
    type Err = ScopeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains('*') {
            return Err(ScopeParseError::Wildcard(s.to_owned()));
        }
        Ok(match s {
            "arch:read" => Self::ArchRead,
            "arch:write" => Self::ArchWrite,
            "board:read" => Self::BoardRead,
            "board:write" => Self::BoardWrite,
            "camp:read" => Self::CampRead,
            "camp:admin" => Self::CampAdmin,
            "cloud:read" => Self::CloudRead,
            "cloud:deploy" => Self::CloudDeploy,
            "cloud:destroy" => Self::CloudDestroy,
            "cloud:admin" => Self::CloudAdmin,
            "party:read" => Self::PartyRead,
            "party:write" => Self::PartyWrite,
            "subagent:spawn" => Self::SubagentSpawn,
            "subagent:control" => Self::SubagentControl,
            "ownership:write" => Self::OwnershipWrite,
            "audit:read" => Self::AuditRead,
            "audit:write" => Self::AuditWrite,
            other => return Err(ScopeParseError::Unknown(other.to_owned())),
        })
    }
}

impl Serialize for Scope {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self.as_wire())
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A failed grant — the rule that fired and the offending pair.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    /// Composition rule (4): `ownership:write` and `audit:write` are
    /// grantable to `Service` principals only.
    #[error("scope {scope} is service-only; cannot grant to {kind} principal")]
    ServiceOnlyScope { scope: Scope, kind: PrincipalKind },
}

/// Grant-time validation. Call this on the write path of the grant API —
/// `POST /grants` etc. — before persisting; the mint path is a defense in
/// depth, not the primary check.
///
/// Currently enforces composition rule (4) (service-only scopes). Other rules:
///
/// - (1) No wildcards: enforced by [`Scope::from_str`] — a wildcard never
///   reaches this function because it can't parse into a `Scope`.
/// - (3) `<category>:admin` is distinct: enforced by the enum shape —
///   `CampAdmin`, `CampRead`, `CampWrite` are independent variants, so a
///   grant of one is literally not a grant of the other.
/// - (5) `aud`-scoping is mandatory: a mint-path concern (the principal's
///   `aud` membership), not a per-scope predicate.
pub fn validate_grant(kind: PrincipalKind, scope: Scope) -> Result<(), GrantError> {
    if scope.is_service_only() && kind != PrincipalKind::Service {
        return Err(GrantError::ServiceOnlyScope { scope, kind });
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
/// (`service`, `arch_doc`) plus a `flatten`ed catch-all for future kinds so
/// adding one doesn't break the wire contract.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Owns {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arch_doc: Vec<String>,
    /// Forward-compatibility spill for resource kinds added after this lands.
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, Vec<String>>,
}

impl Owns {
    pub fn is_empty(&self) -> bool {
        self.service.is_empty() && self.arch_doc.is_empty() && self.extra.is_empty()
    }
}

/// How the principal's identity was last asserted — `bootstrap` for tokens
/// minted off a camp's long-lived bootstrap credential, `user-fresh` for
/// tokens minted within ~N minutes of a fresh passkey assertion.
///
/// Downstream services MAY require `user-fresh` for sensitive ops
/// (mirrors W127's elevation pattern).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "kebab-case")]
pub enum AuthStrength {
    Bootstrap,
    UserFresh,
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
    use std::str::FromStr;

    #[test]
    fn scope_wire_string_roundtrips_for_every_variant() {
        // Every named scope from the doc.
        let all = [
            Scope::ArchRead,
            Scope::ArchWrite,
            Scope::BoardRead,
            Scope::BoardWrite,
            Scope::CampRead,
            Scope::CampAdmin,
            Scope::CloudRead,
            Scope::CloudDeploy,
            Scope::CloudDestroy,
            Scope::CloudAdmin,
            Scope::PartyRead,
            Scope::PartyWrite,
            Scope::SubagentSpawn,
            Scope::SubagentControl,
            Scope::OwnershipWrite,
            Scope::AuditRead,
            Scope::AuditWrite,
        ];
        for s in all {
            let wire = s.as_wire();
            assert_eq!(Scope::from_str(wire).unwrap(), s, "roundtrip failed for {wire}");
            assert!(wire.contains(':'), "wire form must contain ':' — {wire}");
        }
    }

    #[test]
    fn scope_all_is_exhaustive() {
        // Exhaustive intra-crate match — adding a `Scope` variant without
        // updating this test is a compile error. Each arm asserts the
        // variant is also present in `Scope::ALL`; forgetting to update
        // `ALL` fails the assertion at test time.
        fn assert_in_all(s: Scope) {
            let in_all = match s {
                Scope::ArchRead => Scope::ALL.contains(&Scope::ArchRead),
                Scope::ArchWrite => Scope::ALL.contains(&Scope::ArchWrite),
                Scope::BoardRead => Scope::ALL.contains(&Scope::BoardRead),
                Scope::BoardWrite => Scope::ALL.contains(&Scope::BoardWrite),
                Scope::CampRead => Scope::ALL.contains(&Scope::CampRead),
                Scope::CampAdmin => Scope::ALL.contains(&Scope::CampAdmin),
                Scope::CloudRead => Scope::ALL.contains(&Scope::CloudRead),
                Scope::CloudDeploy => Scope::ALL.contains(&Scope::CloudDeploy),
                Scope::CloudDestroy => Scope::ALL.contains(&Scope::CloudDestroy),
                Scope::CloudAdmin => Scope::ALL.contains(&Scope::CloudAdmin),
                Scope::PartyRead => Scope::ALL.contains(&Scope::PartyRead),
                Scope::PartyWrite => Scope::ALL.contains(&Scope::PartyWrite),
                Scope::SubagentSpawn => Scope::ALL.contains(&Scope::SubagentSpawn),
                Scope::SubagentControl => Scope::ALL.contains(&Scope::SubagentControl),
                Scope::OwnershipWrite => Scope::ALL.contains(&Scope::OwnershipWrite),
                Scope::AuditRead => Scope::ALL.contains(&Scope::AuditRead),
                Scope::AuditWrite => Scope::ALL.contains(&Scope::AuditWrite),
            };
            assert!(in_all, "{s} reachable in match but missing from Scope::ALL");
        }
        for s in Scope::ALL {
            assert_in_all(*s);
        }
    }

    #[test]
    fn scope_parser_rejects_wildcards() {
        for w in ["cloud:*", "*", "*:read", "ownership:*"] {
            let err = Scope::from_str(w).unwrap_err();
            assert!(
                matches!(err, ScopeParseError::Wildcard(ref s) if s == w),
                "{w}: expected Wildcard, got {err:?}"
            );
        }
    }

    #[test]
    fn scope_parser_rejects_unknown_literals() {
        let err = Scope::from_str("cloud:nuke").unwrap_err();
        assert!(matches!(err, ScopeParseError::Unknown(ref s) if s == "cloud:nuke"));
    }

    #[test]
    fn scope_serialize_is_plain_string() {
        let v = vec![Scope::CloudDeploy, Scope::CloudRead];
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
    fn validate_grant_rejects_service_only_for_user() {
        let err = validate_grant(PrincipalKind::User, Scope::OwnershipWrite).unwrap_err();
        assert_eq!(
            err,
            GrantError::ServiceOnlyScope {
                scope: Scope::OwnershipWrite,
                kind: PrincipalKind::User,
            }
        );

        let err = validate_grant(PrincipalKind::User, Scope::AuditWrite).unwrap_err();
        assert_eq!(
            err,
            GrantError::ServiceOnlyScope {
                scope: Scope::AuditWrite,
                kind: PrincipalKind::User,
            }
        );
    }

    #[test]
    fn validate_grant_rejects_service_only_for_camp() {
        let err = validate_grant(PrincipalKind::Camp, Scope::OwnershipWrite).unwrap_err();
        assert!(matches!(
            err,
            GrantError::ServiceOnlyScope {
                scope: Scope::OwnershipWrite,
                kind: PrincipalKind::Camp,
            }
        ));
    }

    #[test]
    fn validate_grant_allows_service_principal_for_service_only_scopes() {
        validate_grant(PrincipalKind::Service, Scope::OwnershipWrite).unwrap();
        validate_grant(PrincipalKind::Service, Scope::AuditWrite).unwrap();
    }

    #[test]
    fn validate_grant_allows_normal_scopes_for_any_principal() {
        for k in [
            PrincipalKind::User,
            PrincipalKind::Service,
            PrincipalKind::Camp,
        ] {
            for s in [
                Scope::ArchRead,
                Scope::CloudDeploy,
                Scope::CampAdmin,
                Scope::AuditRead,
            ] {
                validate_grant(k, s).unwrap();
            }
        }
    }

    #[test]
    fn camp_admin_is_distinct_from_camp_read_and_camp_write() {
        // The enum shape *is* the enforcement: each is its own variant.
        // A holder of CampAdmin does not equal a holder of CampRead.
        assert_ne!(Scope::CampAdmin, Scope::CampRead);
        // CampWrite isn't even in the vocabulary; the doc lists only
        // camp:read + camp:admin. This test pins that fact.
        assert!(Scope::from_str("camp:write").is_err());
    }

    #[test]
    fn auth_strength_serializes_kebab_case() {
        assert_eq!(serde_json::to_string(&AuthStrength::Bootstrap).unwrap(), "\"bootstrap\"");
        assert_eq!(serde_json::to_string(&AuthStrength::UserFresh).unwrap(), "\"user-fresh\"");
        let back: AuthStrength = serde_json::from_str("\"user-fresh\"").unwrap();
        assert_eq!(back, AuthStrength::UserFresh);
    }

    #[test]
    fn owns_omits_empty_lists_on_wire_but_roundtrips() {
        let o = Owns::default();
        let json = serde_json::to_string(&o).unwrap();
        assert_eq!(json, "{}");

        let o = Owns {
            service: vec!["svc-a".into()],
            arch_doc: vec![],
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
            vec![Scope::CloudDeploy, Scope::CloudRead],
        )
        .with_act(Actor::new(PrincipalId::service("agent-claude")))
        .with_camp_id("camp-xyz")
        .with_owns(Owns {
            service: vec!["svc-a".into()],
            arch_doc: vec!["doc-1".into()],
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
            vec![Scope::OwnershipWrite],
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
