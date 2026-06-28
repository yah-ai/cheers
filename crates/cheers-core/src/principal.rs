//! Principal kinds and identifier types for MCP authentication.
//!
//! Cheers's session contract has one principal kind (`User`); MCP auth needs
//! three — see `.yah/docs/working/mcp-auth-and-ownership.md` §Principal kinds.
//! [`PrincipalKind`] enumerates them; [`PrincipalId`] is the typed `sub`-claim
//! shape carried on the wire (`user:<id>`, `svc:<id>`, `camp:<id>`);
//! [`Principal`] is the durable record stored in cheers's principal table.
//!
//! The wire-form parser [`PrincipalId::from_str`] **rejects unprefixed input**
//! at parse time — the prefix is the discriminator, and an MCP token whose
//! `sub` is bare (legacy session shape) must not be confused for a user
//! principal silently.
//!
//! [`Principal`]'s deserializer enforces the invariants the doc calls out:
//!
//! - `Camp` principals MUST set `bound_to: Some(user:<U>)`.
//! - `User` and `Service` principals MUST set `bound_to: None`.
//! - A `Camp` whose `bound_to` names a non-user principal is a parse error.
//!
//! Use [`Principal::try_new`] to construct from owned parts; the validation
//! path is the same.

use serde::{Deserialize, Serialize};

/// The three principal kinds MCP auth recognises.
///
/// See `.yah/docs/working/mcp-auth-and-ownership.md` §Principal kinds for the
/// audit-trail / revocation-cascade / grant-constraint reasoning behind the
/// split.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    User,
    Service,
    Camp,
}

impl PrincipalKind {
    /// The wire prefix used in `sub` claims: `user`, `svc`, `camp`.
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Service => "svc",
            Self::Camp => "camp",
        }
    }

    /// Inverse of [`prefix`](Self::prefix). Returns `None` for any other
    /// string — the parser uses this to reject unknown discriminators.
    pub fn from_prefix(prefix: &str) -> Option<Self> {
        Some(match prefix {
            "user" => Self::User,
            "svc" => Self::Service,
            "camp" => Self::Camp,
            _ => return None,
        })
    }
}

impl std::fmt::Display for PrincipalKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.prefix())
    }
}

/// Typed `sub`-claim shape — a principal kind paired with an opaque id.
///
/// Wire format is the single string `<prefix>:<id>` (e.g. `user:alice`,
/// `svc:yubaba-1`, `camp:abc`). [`Serialize`] writes that string;
/// [`Deserialize`] / [`FromStr`](std::str::FromStr) parse it back and reject
/// unprefixed input.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PrincipalId {
    pub kind: PrincipalKind,
    pub id: String,
}

impl PrincipalId {
    pub fn new(kind: PrincipalKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
        }
    }

    pub fn user(id: impl Into<String>) -> Self {
        Self::new(PrincipalKind::User, id)
    }

    pub fn service(id: impl Into<String>) -> Self {
        Self::new(PrincipalKind::Service, id)
    }

    pub fn camp(id: impl Into<String>) -> Self {
        Self::new(PrincipalKind::Camp, id)
    }
}

impl std::fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.kind.prefix(), self.id)
    }
}

/// Why a `sub`-claim string failed to parse into a [`PrincipalId`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrincipalIdParseError {
    /// No `:` separator — an unprefixed `sub` (the legacy session shape) is
    /// rejected so it cannot be mistaken for a `user:` principal.
    #[error("sub claim must be prefixed 'user:<id>', 'svc:<id>', or 'camp:<id>' — got '{0}'")]
    MissingPrefix(String),
    /// Prefix isn't one of `user`, `svc`, `camp`.
    #[error("unknown principal kind prefix '{0}' — expected user, svc, or camp")]
    UnknownPrefix(String),
    /// Empty id after the prefix (`"user:"`).
    #[error("empty principal id after prefix")]
    EmptyId,
}

impl std::str::FromStr for PrincipalId {
    type Err = PrincipalIdParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (prefix, id) = s
            .split_once(':')
            .ok_or_else(|| PrincipalIdParseError::MissingPrefix(s.to_owned()))?;
        let kind = PrincipalKind::from_prefix(prefix)
            .ok_or_else(|| PrincipalIdParseError::UnknownPrefix(prefix.to_owned()))?;
        if id.is_empty() {
            return Err(PrincipalIdParseError::EmptyId);
        }
        Ok(Self {
            kind,
            id: id.to_owned(),
        })
    }
}

impl Serialize for PrincipalId {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PrincipalId {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Lifecycle state of a [`Principal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum PrincipalStatus {
    Active,
    Revoked,
}

/// Invariant violations a [`Principal`] constructor / deserializer rejects.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PrincipalError {
    /// `Camp` requires `bound_to: Some(user:<id>)` (the user the camp was
    /// bootstrapped on behalf of).
    #[error("camp principal must declare bound_to: Some(user:<id>); got None")]
    CampMissingBoundTo,
    /// `Camp.bound_to` must name a user, not a service or another camp.
    #[error("camp principal's bound_to must be a user (got {0})")]
    CampBoundToWrongKind(PrincipalKind),
    /// `User` and `Service` principals are not bound to anything.
    #[error("{0} principal must not declare bound_to")]
    NonCampHasBoundTo(PrincipalKind),
}

/// The durable principal record stored in cheers's principal table.
///
/// Invariants (enforced by [`Principal::try_new`] and the [`Deserialize`] impl):
///
/// - `kind == Camp` ⇒ `bound_to == Some(PrincipalId { kind: User, .. })`
/// - `kind ∈ {User, Service}` ⇒ `bound_to == None`
///
/// A `Camp { bound_to: None }` JSON payload is a parse error — see the
/// roundtrip test in this module.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Principal {
    pub id: PrincipalId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_to: Option<PrincipalId>,
    pub status: PrincipalStatus,
    pub created_at: i64,
}

impl Principal {
    /// Build a `Principal` and check the kind ↔ `bound_to` invariants.
    pub fn try_new(
        id: PrincipalId,
        bound_to: Option<PrincipalId>,
        status: PrincipalStatus,
        created_at: i64,
    ) -> Result<Self, PrincipalError> {
        match (id.kind, &bound_to) {
            (PrincipalKind::Camp, None) => Err(PrincipalError::CampMissingBoundTo),
            (PrincipalKind::Camp, Some(b)) if b.kind != PrincipalKind::User => {
                Err(PrincipalError::CampBoundToWrongKind(b.kind))
            }
            (PrincipalKind::User | PrincipalKind::Service, Some(_)) => {
                Err(PrincipalError::NonCampHasBoundTo(id.kind))
            }
            _ => Ok(Self {
                id,
                bound_to,
                status,
                created_at,
            }),
        }
    }

    /// Convenience accessor — same as `self.id.kind`.
    pub fn kind(&self) -> PrincipalKind {
        self.id.kind
    }
}

#[derive(Deserialize)]
struct RawPrincipal {
    id: PrincipalId,
    #[serde(default)]
    bound_to: Option<PrincipalId>,
    status: PrincipalStatus,
    created_at: i64,
}

impl<'de> Deserialize<'de> for Principal {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let raw = RawPrincipal::deserialize(de)?;
        Principal::try_new(raw.id, raw.bound_to, raw.status, raw.created_at)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn principal_kind_prefix_roundtrip() {
        for k in [
            PrincipalKind::User,
            PrincipalKind::Service,
            PrincipalKind::Camp,
        ] {
            assert_eq!(PrincipalKind::from_prefix(k.prefix()), Some(k));
        }
        assert_eq!(PrincipalKind::from_prefix("agent"), None);
        assert_eq!(PrincipalKind::from_prefix(""), None);
        // The legacy long form must NOT match: prefix is `svc`, not `service`.
        assert_eq!(PrincipalKind::from_prefix("service"), None);
    }

    #[test]
    fn principal_id_display_and_parse() {
        let cases = [
            (PrincipalId::user("alice"), "user:alice"),
            (PrincipalId::service("yubaba-1"), "svc:yubaba-1"),
            (PrincipalId::camp("camp-xyz"), "camp:camp-xyz"),
        ];
        for (pid, wire) in cases {
            assert_eq!(pid.to_string(), wire);
            assert_eq!(wire.parse::<PrincipalId>().unwrap(), pid);
        }
    }

    #[test]
    fn principal_id_id_may_contain_colons() {
        // Only the *first* `:` is the separator — opaque ids may contain more.
        let parsed: PrincipalId = "user:tenant:42".parse().unwrap();
        assert_eq!(parsed.kind, PrincipalKind::User);
        assert_eq!(parsed.id, "tenant:42");
        assert_eq!(parsed.to_string(), "user:tenant:42");
    }

    #[test]
    fn principal_id_rejects_unprefixed() {
        let err = "alice".parse::<PrincipalId>().unwrap_err();
        assert!(matches!(err, PrincipalIdParseError::MissingPrefix(ref s) if s == "alice"));
    }

    #[test]
    fn principal_id_rejects_unknown_prefix() {
        let err = "service:abc".parse::<PrincipalId>().unwrap_err();
        assert!(matches!(err, PrincipalIdParseError::UnknownPrefix(ref s) if s == "service"));

        let err = "agent:claude".parse::<PrincipalId>().unwrap_err();
        assert!(matches!(err, PrincipalIdParseError::UnknownPrefix(ref s) if s == "agent"));
    }

    #[test]
    fn principal_id_rejects_empty_id() {
        let err = "user:".parse::<PrincipalId>().unwrap_err();
        assert_eq!(err, PrincipalIdParseError::EmptyId);
    }

    #[test]
    fn principal_id_serde_is_transparent_string() {
        let pid = PrincipalId::camp("c-1");
        let json = serde_json::to_string(&pid).unwrap();
        assert_eq!(json, "\"camp:c-1\"");
        let back: PrincipalId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, pid);
    }

    #[test]
    fn principal_id_deserialize_rejects_unprefixed_string() {
        let err = serde_json::from_str::<PrincipalId>("\"alice\"").unwrap_err();
        assert!(err.to_string().contains("must be prefixed"));
    }

    #[test]
    fn try_new_camp_requires_bound_to() {
        let err = Principal::try_new(
            PrincipalId::camp("c-1"),
            None,
            PrincipalStatus::Active,
            100,
        )
        .unwrap_err();
        assert_eq!(err, PrincipalError::CampMissingBoundTo);
    }

    #[test]
    fn try_new_camp_rejects_non_user_bound_to() {
        let err = Principal::try_new(
            PrincipalId::camp("c-1"),
            Some(PrincipalId::service("yubaba")),
            PrincipalStatus::Active,
            100,
        )
        .unwrap_err();
        assert_eq!(
            err,
            PrincipalError::CampBoundToWrongKind(PrincipalKind::Service)
        );
    }

    #[test]
    fn try_new_user_or_service_rejects_bound_to() {
        let err = Principal::try_new(
            PrincipalId::user("alice"),
            Some(PrincipalId::user("bob")),
            PrincipalStatus::Active,
            100,
        )
        .unwrap_err();
        assert_eq!(err, PrincipalError::NonCampHasBoundTo(PrincipalKind::User));

        let err = Principal::try_new(
            PrincipalId::service("yubaba"),
            Some(PrincipalId::user("alice")),
            PrincipalStatus::Active,
            100,
        )
        .unwrap_err();
        assert_eq!(
            err,
            PrincipalError::NonCampHasBoundTo(PrincipalKind::Service)
        );
    }

    #[test]
    fn try_new_accepts_valid_combinations() {
        Principal::try_new(
            PrincipalId::user("alice"),
            None,
            PrincipalStatus::Active,
            100,
        )
        .unwrap();
        Principal::try_new(
            PrincipalId::service("yubaba"),
            None,
            PrincipalStatus::Active,
            100,
        )
        .unwrap();
        let camp = Principal::try_new(
            PrincipalId::camp("c-1"),
            Some(PrincipalId::user("alice")),
            PrincipalStatus::Active,
            100,
        )
        .unwrap();
        assert_eq!(camp.kind(), PrincipalKind::Camp);
    }

    #[test]
    fn camp_principal_roundtrips_json() {
        let p = Principal::try_new(
            PrincipalId::camp("c-1"),
            Some(PrincipalId::user("alice")),
            PrincipalStatus::Active,
            12345,
        )
        .unwrap();
        let json = serde_json::to_string(&p).unwrap();
        // PrincipalIds serialize as plain strings.
        assert!(json.contains("\"id\":\"camp:c-1\""));
        assert!(json.contains("\"bound_to\":\"user:alice\""));
        assert!(json.contains("\"status\":\"active\""));
        let back: Principal = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn user_principal_omits_bound_to_on_wire() {
        let p = Principal::try_new(
            PrincipalId::user("alice"),
            None,
            PrincipalStatus::Active,
            12345,
        )
        .unwrap();
        let json = serde_json::to_string(&p).unwrap();
        assert!(!json.contains("bound_to"), "unset bound_to must be omitted: {json}");
        let back: Principal = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn deserializing_camp_without_bound_to_fails() {
        // Bare camp record with no bound_to is a parse error.
        let json = r#"{"id":"camp:c-1","status":"active","created_at":1}"#;
        let err = serde_json::from_str::<Principal>(json).unwrap_err();
        assert!(
            err.to_string().contains("camp principal must declare bound_to"),
            "wrong error: {err}"
        );

        // Explicit null is rejected too.
        let json = r#"{"id":"camp:c-1","bound_to":null,"status":"active","created_at":1}"#;
        let err = serde_json::from_str::<Principal>(json).unwrap_err();
        assert!(err.to_string().contains("camp principal must declare bound_to"));
    }

    #[test]
    fn deserializing_user_with_bound_to_fails() {
        let json = r#"{"id":"user:alice","bound_to":"user:bob","status":"active","created_at":1}"#;
        let err = serde_json::from_str::<Principal>(json).unwrap_err();
        assert!(
            err.to_string().contains("must not declare bound_to"),
            "wrong error: {err}"
        );
    }

    #[test]
    fn deserializing_camp_with_service_bound_to_fails() {
        let json = r#"{"id":"camp:c-1","bound_to":"svc:yubaba","status":"active","created_at":1}"#;
        let err = serde_json::from_str::<Principal>(json).unwrap_err();
        assert!(
            err.to_string().contains("bound_to must be a user"),
            "wrong error: {err}"
        );
    }
}
