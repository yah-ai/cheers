//! Identifiers, device bindings, and the `Claims` carried by a verified session token.
//!
//! These types are the **mesofact ↔ cheers contract**: any change after the
//! mesofact integration (P11) ships requires a coordinated migration. Public
//! structs and enums are `#[non_exhaustive]` so adding fields or variants
//! later is not a SemVer-breaking change. Construct new values through the
//! provided constructors (and builder-style setters where present), not
//! struct literals.
//!
//! @yah:ticket(R020-F2, "Principal kinds: user|service|camp enum + Principal record in cheers-core")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T01:35:04Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R020)
//! @yah:next("Add PrincipalKind { User, Service, Camp } and Principal { id, kind, bound_to: Option<PrincipalId>, status, created_at } to cheers-core.")
//! @yah:next("Extend sub-claim parser to accept 'user:<id>' | 'svc:<id>' | 'camp:<id>' prefixes; reject unprefixed sub at parse time.")
//! @yah:verify("cargo test -p cheers-core")
//! @yah:verify("Roundtrip test: Principal { kind: Camp, bound_to: Some(user) } serializes/parses; bound_to=None on a Camp is a parse error.")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @yah:depends_on(R019-F5)
//! @yah:handoff("Landed new module crates/cheers-core/src/principal.rs (exported from lib.rs): PrincipalKind { User, Service, Camp } + PrincipalId { kind, id } + PrincipalStatus { Active, Revoked } + Principal { id: PrincipalId, bound_to: Option<PrincipalId>, status, created_at } + PrincipalError + PrincipalIdParseError. All #[non_exhaustive].")
//! @yah:handoff("PrincipalId is the typed sub-claim — serializes transparent as 'user:<id>' | 'svc:<id>' | 'camp:<id>'. FromStr/Deserialize reject unprefixed input (MissingPrefix), unknown prefixes (UnknownPrefix incl. legacy 'service'/'agent'), and empty ids — so a session-shaped bare sub cannot silently be read as a user principal. PrincipalKind::prefix uses 'svc' (matches the doc), not 'service'.")
//! @yah:handoff("Principal invariants enforced in BOTH try_new and the Deserialize impl (via RawPrincipal intermediate): Camp ⇒ bound_to=Some(user:_); User/Service ⇒ bound_to=None; Camp bound_to that isn't a user is rejected. JSON omits bound_to when None (skip_serializing_if).")
//! @yah:handoff("Did NOT touch existing Claims.sub: UserId — that's the session contract; the MCP-claims shape (act/owns/camp_id/auth_strength) lands in R020-F3 alongside the Scope enum and will be where PrincipalId actually replaces a sub field. Foundation laid; R020-F3 builds on PrincipalId for its sub typing.")
//! @yah:handoff("Verified GREEN: cargo test -p cheers-core (33 unit incl. 17 new principal tests, 1 doctest), cargo test -p cheers-server (35+9+2+4+0 across binaries/integration), cargo test -p cheers-verify (clean). R020 parent verify smoke passes.")
//!
//! @yah:ticket(R020-F3, "Scope vocabulary as typed enum + composition rules in cheers-core")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T01:35:12Z)
//! @yah:status(review)
//! @yah:phase(P1)
//! @yah:parent(R020)
//! @yah:next("Add Scope enum covering arch:* board:* camp:* cloud:* party:* subagent:* ownership:write audit:* per §Scope vocabulary.")
//! @yah:next("Enforce composition rules at grant/mint: no wildcards on the wire; <category>:admin does NOT imply read/write; ownership:write and audit:write are kind=service only; aud-scoping mandatory.")
//! @yah:next("Add MCP claim shapes alongside Scope: act { sub }, owns { service: [], arch_doc: [] }, camp_id, auth_strength enum { Bootstrap, UserFresh }.")
//! @yah:verify("cargo test -p cheers-core")
//! @yah:verify("Negative test: serializing a Scope list containing 'cloud:*' fails; granting ownership:write to a User principal returns a typed error.")
//! @yah:gotcha("A user-kind grant with ownership:write or audit:write must be rejected at write time, not just at mint. Rule (4) is a CHECK that lives in the grant API, not the mint path.")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @yah:handoff("Landed new module crates/cheers-core/src/mcp.rs (exported from lib.rs): closed-vocabulary Scope enum (16 variants — arch/board/camp/cloud/party/subagent + ownership:write + audit:{read,write}), GrantError, validate_grant(), and the MCP claim shapes (Actor, Owns, AuthStrength, McpClaims). All #[non_exhaustive].")
//! @yah:handoff("Composition rules: (1) wildcards — enforced by Scope::from_str rejecting any '*' BEFORE the literal match, so a wildcard cannot be deserialized into a Vec<Scope> on the wire (tested via Vec<Scope> mid-list rejection). (3) <category>:admin distinct — enforced structurally: CampAdmin and CampRead are independent variants; a grant of one literally isn't a grant of the other; pinned with a test. (4) ownership:write + audit:write service-only — enforced by validate_grant(kind, scope), which rejects BOTH User and Camp (not just User — doc says 'kind=service only'). Service principals pass. (5) aud-scoping is documented as a mint-path concern, not a per-scope predicate.")
//! @yah:handoff("Scope serializes as the literal wire string ('cloud:deploy'), not the variant name — hand-rolled Serialize/Deserialize via as_wire()/FromStr, NOT serde rename. McpClaims.sub is a PrincipalId (R020-F2), so a token whose sub is bare 'alice' fails deserialize with the 'must be prefixed' message inherited from PrincipalId. Owns has explicit service+arch_doc Vec<String> fields PLUS #[serde(flatten)] extra: BTreeMap<String,Vec<String>> so adding a new resource kind in the ownership table doesn't break the wire contract.")
//! @yah:handoff("AuthStrength uses #[serde(rename_all=\"kebab-case\")] — Bootstrap→'bootstrap', UserFresh→'user-fresh' (matches the doc verbatim).")
//! @yah:handoff("Did NOT touch the existing Claims.sub: UserId (session contract). McpClaims is the peer for MCP-call tokens. R020-F4 (ownership table writers) bolts the ownership lookups onto cheers-server and reads them into Owns at mint.")
//! @yah:handoff("Verified GREEN: cargo test -p cheers-core (51 unit incl. 18 new mcp tests + 1 doctest), cargo test -p cheers-server (35+9+2+4+0), cargo test -p cheers-verify (clean). R020 parent verify smoke passes.")

use serde::{Deserialize, Serialize};

/// Stable user identifier — minted by `UserStore` on first sight of a credential.
///
/// Opaque to consumers; cheers does not interpret the inner string. Products
/// pick the shape (UUID, base32 ULID, …); cheers passes it through.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UserId(String);

impl UserId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for UserId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for UserId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// Per-device identifier — minted on the first sign-in from a given device.
///
/// One user has many devices; one device has one `DeviceId` per user.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeviceId(String);

impl DeviceId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_inner(self) -> String {
        self.0
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for DeviceId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for DeviceId {
    fn from(s: &str) -> Self {
        Self(s.to_owned())
    }
}

/// How a device proved its identity to mint this session.
///
/// One variant per first-class provider in the build plan. `OidcGeneric`
/// is the escape hatch for ad-hoc OIDC issuers (e.g. enterprise SSO) that
/// aren't named providers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeviceBinding {
    Passkey,
    OidcGoogle,
    OidcApple,
    OidcGeneric { issuer: String },
    EmailPassword,
    EmailMagicLink,
    LanPair,
}

/// Resolved user record returned by `UserStore`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct User {
    pub id: UserId,
    pub email: Option<String>,
    pub name: Option<String>,
}

impl User {
    pub fn new(id: UserId) -> Self {
        Self {
            id,
            email: None,
            name: None,
        }
    }

    pub fn with_email(mut self, email: impl Into<String>) -> Self {
        self.email = Some(email.into());
        self
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

/// One stored proof-of-identity bound to a `(UserId, DeviceId)` pair.
///
/// The shape that `CredentialStore` reads and writes. The `binding` field
/// records *how* the credential was established; provider-specific secrets
/// live in `material` as an opaque byte blob (e.g. a passkey credential ID,
/// an Argon2id hash, a refresh-token chain root, …) whose interpretation is
/// owned by the provider that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Credential {
    pub user_id: UserId,
    pub device_id: DeviceId,
    pub binding: DeviceBinding,
    pub material: Vec<u8>,
}

impl Credential {
    pub fn new(
        user_id: UserId,
        device_id: DeviceId,
        binding: DeviceBinding,
        material: Vec<u8>,
    ) -> Self {
        Self {
            user_id,
            device_id,
            binding,
            material,
        }
    }
}

/// Verified session claims — what a `TokenVerifier::verify` returns on success.
///
/// Stable shape; new fields land behind `#[non_exhaustive]`. Timestamps are
/// unix seconds (signed to leave room for pre-epoch sentinels in tests).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Claims {
    pub sub: UserId,
    pub device: DeviceId,
    pub binding: DeviceBinding,
    pub issued_at: i64,
    pub expires_at: i64,
    /// Unique token id — the key the revocation set is keyed on (R019-F4).
    ///
    /// Empty means *unset / not individually revocable*; sessions minted through
    /// `cheers-server`'s `SessionAuthority` get a fresh value via
    /// [`with_jti`](Self::with_jti). `#[serde(default, skip_serializing_if)]`
    /// keeps the wire format byte-identical to a pre-`jti` token when unset —
    /// important for the mesofact cookie contract.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub jti: String,
}

impl Claims {
    pub fn new(
        sub: UserId,
        device: DeviceId,
        binding: DeviceBinding,
        issued_at: i64,
        expires_at: i64,
    ) -> Self {
        Self {
            sub,
            device,
            binding,
            issued_at,
            expires_at,
            jti: String::new(),
        }
    }

    /// Attach a `jti` (the revocation key). Builder-style so existing
    /// five-arg [`new`](Self::new) call sites are unaffected.
    pub fn with_jti(mut self, jti: impl Into<String>) -> Self {
        self.jti = jti.into();
        self
    }

    /// `true` if `expires_at` is at or before `now` (unix seconds).
    pub fn is_expired_at(&self, now: i64) -> bool {
        self.expires_at <= now
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_id_roundtrips_through_string() {
        let u = UserId::new("alice");
        assert_eq!(u.as_str(), "alice");
        assert_eq!(u.to_string(), "alice");
        assert_eq!(UserId::from("alice"), u);
    }

    #[test]
    fn user_id_serde_is_transparent() {
        let u = UserId::new("u-123");
        let json = serde_json::to_string(&u).unwrap();
        assert_eq!(json, "\"u-123\"");
        let back: UserId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, u);
    }

    #[test]
    fn device_binding_serializes_with_kind_tag() {
        let b = DeviceBinding::OidcGeneric {
            issuer: "https://idp.example".into(),
        };
        let json = serde_json::to_string(&b).unwrap();
        assert!(json.contains("\"kind\":\"oidc_generic\""));
        assert!(json.contains("\"issuer\":\"https://idp.example\""));
        let back: DeviceBinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, b);

        let unit = DeviceBinding::Passkey;
        let json = serde_json::to_string(&unit).unwrap();
        assert_eq!(json, "{\"kind\":\"passkey\"}");
    }

    #[test]
    fn user_builder_sets_optional_fields() {
        let u = User::new(UserId::new("u1"))
            .with_email("a@b")
            .with_name("Alice");
        assert_eq!(u.email.as_deref(), Some("a@b"));
        assert_eq!(u.name.as_deref(), Some("Alice"));
    }

    #[test]
    fn claims_expiry_check() {
        let c = Claims::new(
            UserId::new("u1"),
            DeviceId::new("d1"),
            DeviceBinding::Passkey,
            100,
            200,
        );
        assert!(!c.is_expired_at(199));
        assert!(c.is_expired_at(200));
        assert!(c.is_expired_at(201));
    }

    #[test]
    fn claims_jti_defaults_empty_and_omitted_from_wire() {
        let c = Claims::new(
            UserId::new("u1"),
            DeviceId::new("d1"),
            DeviceBinding::Passkey,
            100,
            200,
        );
        assert_eq!(c.jti, "");
        // Unset jti must not appear on the wire — keeps the cookie format
        // identical to a pre-jti token.
        let json = serde_json::to_string(&c).unwrap();
        assert!(!json.contains("jti"), "empty jti must be skipped: {json}");

        let c = c.with_jti("tok-123");
        assert_eq!(c.jti, "tok-123");
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"jti\":\"tok-123\""));
        let back: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn claims_roundtrip_json() {
        let c = Claims::new(
            UserId::new("u1"),
            DeviceId::new("d1"),
            DeviceBinding::OidcGeneric {
                issuer: "https://idp".into(),
            },
            100,
            200,
        );
        let json = serde_json::to_string(&c).unwrap();
        let back: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn credential_holds_opaque_material() {
        let cred = Credential::new(
            UserId::new("u1"),
            DeviceId::new("d1"),
            DeviceBinding::EmailPassword,
            b"argon2id$...".to_vec(),
        );
        assert_eq!(cred.material, b"argon2id$...");
    }
}
