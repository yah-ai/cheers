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
//!
//! @yah:relay(R515, "Bind a session claim to a long-lived public key, so an edge can prove token holder == connecting peer")
//! @yah:at(2026-09-03T06:37:07Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @arch:see(.yah/docs/working/edge-verifiable-auth.md)

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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

/// Why a [`PeerKey`] failed to construct or deserialize.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PeerKeyError {
    /// Zero-length key bytes — a binding to nothing is never meaningful.
    #[error("peer key must be non-empty")]
    EmptyKey,
    /// An [`Other`](PeerKeyAlgorithm::Other) label with no characters in it.
    #[error("peer key algorithm must be non-empty")]
    EmptyAlgorithm,
    /// The algorithm names a fixed key length and the bytes don't match it.
    #[error("{algorithm} peer key must be {expected} bytes, got {actual}")]
    WrongKeyLength {
        algorithm: String,
        expected: usize,
        actual: usize,
    },
}

/// Which algorithm a bound [`PeerKey`]'s bytes belong to.
///
/// cheers is a general auth library, so the *field* on [`Claims`] must not name
/// one curve. The discriminant rides next to the bytes instead, and a key only
/// ever matches another key of the same algorithm — so a byte string that is a
/// valid public key under two schemes can't be confused across them.
///
/// [`Other`](Self::Other) is the escape hatch for a scheme cheers hasn't named:
/// unknown labels still round-trip and still compare, so a consumer isn't
/// version-locked to a cheers release to bind a key type of its own. Labels are
/// canonicalized on the way in ([`from_wire`](Self::from_wire) returns
/// [`Ed25519`](Self::Ed25519) for `"ed25519"`, never `Other("ed25519")`), so
/// each algorithm has exactly one representation and equality is total.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PeerKeyAlgorithm {
    /// Ed25519 — 32-byte public key. What iroh/QUIC node identities use.
    Ed25519,
    /// A scheme cheers doesn't name. Carries the wire label verbatim.
    Other(String),
}

impl PeerKeyAlgorithm {
    /// The wire label. Stable — it *is* the serialized form.
    pub fn as_wire(&self) -> &str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::Other(s) => s,
        }
    }

    /// Parse a wire label, canonicalizing known ones onto their named variant.
    pub fn from_wire(s: &str) -> Result<Self, PeerKeyError> {
        match s {
            "" => Err(PeerKeyError::EmptyAlgorithm),
            "ed25519" => Ok(Self::Ed25519),
            other => Ok(Self::Other(other.to_owned())),
        }
    }

    /// The exact key length this algorithm requires, when it has one.
    /// `None` for [`Other`](Self::Other) — cheers can't police a scheme it
    /// doesn't know.
    pub fn expected_key_len(&self) -> Option<usize> {
        match self {
            Self::Ed25519 => Some(32),
            Self::Other(_) => None,
        }
    }
}

impl std::fmt::Display for PeerKeyAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_wire())
    }
}

impl Serialize for PeerKeyAlgorithm {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(self.as_wire())
    }
}

impl<'de> Deserialize<'de> for PeerKeyAlgorithm {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let s = String::deserialize(de)?;
        Self::from_wire(&s).map_err(D::Error::custom)
    }
}

/// A long-lived, client-held **public** key a session token can be bound to.
///
/// Raw bytes plus an algorithm discriminant — deliberately *not* an
/// `ed25519-dalek` (or any other crypto crate's) type. Consumers straddle a
/// real version split (iroh resolves ed25519-dalek 3.0.0-pre, other trust
/// crates resolve 2.2), so a crypto type here would hand every consumer a
/// version pin it cannot satisfy. cheers only ever *compares* these bytes; it
/// never verifies a signature under them, so it needs no crypto to hold one.
///
/// Wire form is `{"alg": "<label>", "key": "<base64url-no-pad>"}` — the same
/// base64url-no-pad encoding [`UserDelegation`](crate::UserDelegation) uses,
/// which every cross-platform Ed25519 toolchain agrees on.
///
/// Nothing secret lives in this type (a public key is public), so equality is
/// plain `==`, not constant-time.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub struct PeerKey {
    /// Which scheme [`key`](Self::key) belongs to.
    #[serde(rename = "alg")]
    pub algorithm: PeerKeyAlgorithm,
    /// The raw public key bytes. Wire form: base64url-no-pad.
    #[serde(rename = "key", with = "peer_key_bytes_serde")]
    pub key: Vec<u8>,
}

impl PeerKey {
    /// Construct + validate: rejects empty bytes, and a length that disagrees
    /// with an algorithm that names one ([`expected_key_len`]).
    ///
    /// [`expected_key_len`]: PeerKeyAlgorithm::expected_key_len
    pub fn new(algorithm: PeerKeyAlgorithm, key: impl Into<Vec<u8>>) -> Result<Self, PeerKeyError> {
        let key = key.into();
        if key.is_empty() {
            return Err(PeerKeyError::EmptyKey);
        }
        // Canonicalize here too, not just on the wire: an `Other("ed25519")`
        // built in Rust would otherwise serialize to the same JSON as
        // `Ed25519`, deserialize back as `Ed25519`, and compare unequal to
        // itself — one algorithm, two representations, and a binding check
        // that fails on a key that matches.
        let algorithm = match algorithm {
            PeerKeyAlgorithm::Other(label) => PeerKeyAlgorithm::from_wire(&label)?,
            named => named,
        };
        if let Some(expected) = algorithm.expected_key_len() {
            if key.len() != expected {
                return Err(PeerKeyError::WrongKeyLength {
                    algorithm: algorithm.as_wire().to_owned(),
                    expected,
                    actual: key.len(),
                });
            }
        }
        Ok(Self { algorithm, key })
    }

    /// The common case — an Ed25519 node public key. Infallible: the length
    /// invariant is carried by the array type.
    pub fn ed25519(key: [u8; 32]) -> Self {
        Self {
            algorithm: PeerKeyAlgorithm::Ed25519,
            key: key.to_vec(),
        }
    }

    pub fn algorithm(&self) -> &PeerKeyAlgorithm {
        &self.algorithm
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// The key's wire encoding (base64url-no-pad), for logs and roster files.
    pub fn to_base64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(&self.key)
    }
}

/// The wire shape [`PeerKey`] deserializes *through* — a structural mirror
/// with no invariant checks, reconstructed via [`PeerKey::new`] so a
/// hand-crafted payload can't bypass the constructor (mirrors
/// [`Principal`](crate::Principal) / `RawPrincipal`).
#[derive(Deserialize)]
struct RawPeerKey {
    alg: PeerKeyAlgorithm,
    #[serde(with = "peer_key_bytes_serde")]
    key: Vec<u8>,
}

impl<'de> Deserialize<'de> for PeerKey {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;
        let raw = RawPeerKey::deserialize(de)?;
        PeerKey::new(raw.alg, raw.key).map_err(D::Error::custom)
    }
}

mod peer_key_bytes_serde {
    use super::*;
    use serde::de::Error as DeError;

    pub fn serialize<S: serde::Serializer>(bytes: &[u8], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(|e| D::Error::custom(format!("invalid base64url peer key: {e}")))
    }
}

/// Verified session claims — what a `TokenVerifier::verify` returns on success.
///
/// Stable shape; new fields land behind `#[non_exhaustive]`. Timestamps are
/// unix seconds (signed to leave room for pre-epoch sentinels in tests).
///
/// @yah:ticket(R515-F1, "Add an optional long-lived public-key binding to cheers_core::Claims")
/// @yah:status(review)
/// @yah:at(2026-09-03T07:47:27Z)
/// @yah:assignee(agent:bundle-anthropic-ashguard)
/// @yah:parent(R515)
/// @yah:next("WHY A NEW FIELD RATHER THAN REUSING `device`. Claims.device is a DeviceId(String) that cheers-axum mints as a freshly generated random base64url value per sign-in (magic_link.rs, google.rs, apple.rs — their unit tests assert uniqueness per call). Its job is keying the refresh chain and per-device revocation: disposable, per-sign-in, server-chosen. A society/mesh node key is the opposite — long-lived, public, client-held, and the thing a QUIC handshake already authenticates. Overloading one column with both was considered and rejected by the noisetable operator 2026-09-02: (UserId, DeviceId) is the CredentialStore key, so the overload would make a long-lived public key a credential-store key, which reads fine now and is very hard to unpick later.")
/// @yah:next("SHAPE. Claims is #[non_exhaustive], so this is additive. Add an optional binding to a caller-supplied long-lived public key, serde-skipped when unset so the wire format stays byte-identical to a pre-field token (the same discipline `jti` already uses for the mesofact cookie contract). TAKE RAW BYTES, NOT AN ed25519-dalek TYPE: consumers straddle a real version split — iroh (under mshr) resolves ed25519-dalek 3.0.0-pre while noisetable's trust crates resolve 2.2, so a dalek type in this struct hands every consumer a version pin it cannot satisfy. Keep the field key-agnostic (bytes + an algorithm/kind discriminant) rather than naming Ed25519, since cheers is a general auth library.")
/// @yah:next("THE CONSUMER, and the security property it buys. noisetable's society rooms (that camp's R117-T5) admit peers by an Ed25519 roster today — layer 1 of its A120 identity model. A user token is layer 2 and may only ADD a claim about WHICH HUMAN a machine key belongs to; it must never become a second admission door. For that to mean anything at the door, the signed claim has to name the peer's node public key, because the peer already proved possession of exactly that key in the QUIC/TLS handshake. Without the binding in the token, a STOLEN token replays under the attacker's own node key and they become the victim user — which is why binding-at-presentation was rejected as an alternative. Verification is offline via cheers-verify's PasetoV4PublicVerifier against a pinned issuer pubkey, so a LAN peer with no internet can still check a token minted a week ago.")
/// @yah:gotcha("SCOPE: this ticket is the CLAIM FIELD plus mint/verify support, NOT an enrollment ceremony. Nothing in cheers-axum's existing ceremonies can populate it — a browser passkey or magic-link sign-in has no node key, because the key lives in a different process (a desktop app or a headless appliance). The flow that fills this field is a node-enrollment mint (app proves possession of key N, presents the user's existing session, receives a token binding U to N), and that lives in the CONSUMING service, not here. noisetable is filing its own ticket for that side. Ship the field so both sides can be built against it; do not try to infer the key from an HTTP ceremony.")
/// @yah:handoff("LANDED the field + both wire halves. cheers-core/src/claims.rs: PeerKey { algorithm: PeerKeyAlgorithm, key: Vec<u8> } + PeerKeyAlgorithm { Ed25519, Other(String) } + PeerKeyError, and Claims.peer_key: Option<PeerKey> with #[serde(default, skip_serializing_if = \"Option::is_none\")] — an unset token is byte-identical to a pre-R515 one (pinned by claims_peer_key_defaults_none_and_is_omitted_from_wire). Builder Claims::with_peer_key + predicate Claims::is_bound_to(&PeerKey). All exported from cheers_core.")
/// @yah:handoff("KEY-AGNOSTIC, AS THE TICKET REQUIRED: raw bytes + algorithm discriminant, no ed25519-dalek (or any crypto crate) type — cheers only ever COMPARES these bytes, never verifies a signature under them, so cheers-core stays crypto-free and no consumer inherits a dalek version pin. Wire form {\"alg\":\"ed25519\",\"key\":\"<base64url-no-pad>\"} reusing UserDelegation's encoding. PeerKeyAlgorithm::Other(String) is the escape hatch so a consumer isn't version-locked to a cheers release for a scheme cheers hasn't named.")
/// @yah:handoff("MINT (cheers-server/src/session.rs): SessionAuthority::establish_bound(sub, device, binding, peer_key, now) and rotate_bound(refresh, binding, peer_key, now). Existing establish/rotate signatures unchanged — both now delegate to a private establish_inner/rotate_inner taking Option<PeerKey>, and mint_access gained the Option param. Peer key is CALLER-SUPPLIED on rotation for the same reason `binding` is: the refresh record is about which session, not how this access token is presented. So a plain rotate() yields an UNBOUND token rather than a silently stale binding, and a rekeyed node rebinds on the next rotate_bound.")
/// @yah:handoff("DOOR (cheers-verify/src/edge.rs): EdgeVerifier::verify_bound_at(token, presented: &PeerKey, now) — signature, then binding (byte compare, still offline), then the revocation read. New Error::PeerKeyMismatch in cheers-core/src/error.rs (Error is #[non_exhaustive], so additive). An UNBOUND token fails verify_bound_at: it asserts nothing about any node key, so it can't satisfy a binding check. A deployment that also admits unbound tokens must call verify_at and branch on claims.peer_key itself — that choice is deliberately forced to the call site rather than silently passing.")
/// @yah:handoff("BUG MY OWN TEST CAUGHT: PeerKey::new originally accepted PeerKeyAlgorithm::Other(\"ed25519\") verbatim, which serializes to the same JSON as Ed25519 and deserializes back AS Ed25519 — so a token bound that way would fail its own is_bound_to check after one wire round-trip. new() now canonicalizes through PeerKeyAlgorithm::from_wire, giving each algorithm exactly one representation. Pinned by unknown_algorithm_round_trips_but_canonicalizes_known_labels.")
/// @yah:handoff("DOC (in scope, not scope creep): .yah/docs/working/edge-verifiable-auth.md gained §6 \"Peer-key binding — the token names the key, not the connection (R515)\". Needed because that doc's §5 says \"guide by omission — do NOT add a field to Claims\", and without §6 the next reader parses this ticket as violating its own arch:see doc. §6 states the distinction (routing metadata is about where data lives; a peer key is about who holds the token — that is identity), why binding-at-presentation was rejected (needs a live round-trip + challenge cache, exactly the coordination the locality contract buys freedom from), the mint/door surface, and the layering rule that a bound token is layer 2 and never a second admission door.")
/// @yah:handoff("SCOPE HELD as the ticket's gotcha demanded: no enrollment ceremony, and cheers-axum is untouched. Nothing in cheers establishes that a caller POSSESSES the key it asks to bind — that proof is the consuming service's node-enrollment mint. cheers ships the field and both sides of the wire so noisetable's side can be built against it.")
/// @yah:verify("cargo test -p cheers-core -p cheers-server -p cheers-verify — GREEN: cheers-core 70 passed (5 new peer-key tests), cheers-server 139 passed (3 new end-to-end tests), cheers-verify green, 0 failed anywhere. The 3 server tests run the real rig (PasetoV4SecretMinter origin + PasetoV4PublicVerifier edge), so the binding is proven to survive the SIGNED token, not just the in-memory struct.")
/// @yah:verify("The security property is pinned, not just the plumbing: establish_bound_survives_the_wire_and_proves_holder_is_the_peer replays a valid bound token under a DIFFERENT node key and asserts Error::PeerKeyMismatch (the stolen-token case), then revokes the jti and asserts Error::Revoked for a correctly-bound token (binding is layer 2, revocation still kills). unbound_token_is_wire_compatible_but_fails_a_binding_check asserts an unbound token still passes plain verify_at (no regression for existing consumers) but fails verify_bound_at.")
/// @yah:verify("Wire compatibility with pre-R515 tokens: claims_peer_key_defaults_none_and_is_omitted_from_wire asserts the string \"peer_key\" is absent from an unset token's JSON and that such JSON round-trips back equal. No golden fixture needed rebasing — cheers-test-support/fixtures/*.claims.json are McpClaims (a different shape), which this ticket does not touch.")
/// @yah:gotcha("PeerKey's fields are `pub` (matching UserDelegation / Principal house style: pub fields + validating constructor + validating Deserialize via a Raw mirror). #[non_exhaustive] blocks struct-literal construction, so every value enters through PeerKey::new or ::ed25519 — but a holder CAN still mutate `key` in place and break the ed25519-is-32-bytes invariant after construction. Consequence is a failed comparison (fail-closed), never an accepted forgery, so it was left consistent with the crate rather than hidden behind accessors.")
/// @yah:gotcha("NOT DONE, deliberately, and the consumer needs to know: McpClaims (cheers-core/src/mcp.rs — the MCP-token shape) did NOT get a peer_key. This ticket named cheers_core::Claims, the session shape, and that is what noisetable's society door verifies. If an MCP-call token ever needs the same holder==peer proof, it is a separate additive field on McpClaims, not a change here.")
/// @yah:gotcha("This monorepo builds cheers via PATH deps at version 0.8.31 (crates/yah/cloud-admin, app/yah/cli), so the new field ships to those consumers on the next build, not on a crates.io release. Nothing breaks — Claims and Error are both #[non_exhaustive], so no external crate can struct-literal Claims or match Error exhaustively, and the only external construction site is a 5-arg Claims::new in oss/mesofact/crates/mesofact-core/tests/proxy.rs, whose signature is unchanged.")
/// @yah:verify("Whole-workspace regression sweep, not just the touched crates: cargo test --workspace from oss/cheers — 560 passed, 0 failed across 33 test binaries (cheers, cheers-axum, cheers-sqlx, cheers-turso, cheers-redis, cheers-store, cheers-test-support and the three touched crates), doctests included. Nothing in the untouched crates regressed on the new Claims field.")
/// @yah:verify("NOT VERIFIED BY BUILD, stated rather than hedged: the cross-workspace consumer check (cargo check -p yah-cloud-admin, which pulls cheers-core/-verify/-server by path from the root monorepo workspace) sat \"Blocking waiting for file lock on build directory\" for ~15min behind peer sessions and never got the root target dir. The argument it would have confirmed is structural, not empirical: this change removes nothing and alters no signature, Claims and Error are both #[non_exhaustive] (so no external crate can struct-literal Claims or match Error exhaustively), cloud-admin imports cheers_core by explicit name (`use cheers_core::{McpClaims, Scope}`) not a glob, and the only external Claims construction site in the monorepo is a 5-arg Claims::new in oss/mesofact/crates/mesofact-core/tests/proxy.rs. Re-run that check when the camp's root target is free.")
/// @yah:handoff("DONE: the claim field plus both wire halves. cheers-core gains PeerKey/PeerKeyAlgorithm/PeerKeyError and Claims.peer_key: Option<PeerKey> (serde-skipped when unset, so a pre-R515 token is byte-identical) with with_peer_key + is_bound_to; cheers-server gains SessionAuthority::establish_bound / rotate_bound; cheers-verify gains EdgeVerifier::verify_bound_at + Error::PeerKeyMismatch. Key-agnostic bytes + algorithm discriminant, no dalek type, so no consumer inherits a version pin. Enrollment ceremony deliberately NOT built — that is the consuming service's, per the ticket's scope gotcha.")
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
    /// Optional binding to a long-lived, client-held public key (R515).
    ///
    /// When set, the token asserts *"the holder of this key is
    /// [`sub`](Self::sub)"* — so a verifier that has already authenticated the
    /// connecting peer under that same key (a QUIC/TLS handshake does exactly
    /// this) can prove **token holder == connecting peer**, and a stolen token
    /// replayed under the thief's own key fails
    /// [`is_bound_to`](Self::is_bound_to).
    ///
    /// Distinct from [`device`](Self::device) on purpose: a `DeviceId` is a
    /// freshly generated, server-chosen, per-sign-in value that keys the
    /// refresh chain and per-device revocation. A peer key is the opposite —
    /// long-lived, client-held, public, and already proven in the transport.
    /// `(UserId, DeviceId)` is the `CredentialStore` key, so overloading it
    /// with a node key would make a long-lived public key a credential-store
    /// key.
    ///
    /// `#[serde(default, skip_serializing_if)]` keeps the wire format
    /// byte-identical to a pre-`peer_key` token when unset — the same
    /// discipline [`jti`](Self::jti) uses for the mesofact cookie contract.
    ///
    /// Nothing in cheers's own HTTP ceremonies populates this: a browser
    /// passkey or magic-link sign-in has no node key, because the key lives in
    /// a different process. The flow that fills it is a node-enrollment mint —
    /// the app proves possession of key `N`, presents the user's existing
    /// session, and receives a token binding `U` to `N` — and that ceremony
    /// belongs to the consuming service. See
    /// [`SessionAuthority::establish_bound`] in `cheers-server` for the mint
    /// side and `EdgeVerifier::verify_bound_at` in `cheers-verify` for the
    /// door side.
    ///
    /// [`SessionAuthority::establish_bound`]: https://docs.rs/cheers-server
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_key: Option<PeerKey>,
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
            peer_key: None,
        }
    }

    /// Attach a `jti` (the revocation key). Builder-style so existing
    /// five-arg [`new`](Self::new) call sites are unaffected.
    pub fn with_jti(mut self, jti: impl Into<String>) -> Self {
        self.jti = jti.into();
        self
    }

    /// Bind these claims to a long-lived peer public key. Builder-style, for
    /// the same reason [`with_jti`](Self::with_jti) is.
    pub fn with_peer_key(mut self, peer_key: PeerKey) -> Self {
        self.peer_key = Some(peer_key);
        self
    }

    /// `true` iff these claims name **exactly** `presented` as their peer key.
    ///
    /// An *unbound* token returns `false`: it makes no claim about any node
    /// key, so it is not bound to this one. That is a deliberate fail-closed —
    /// a caller that accepts unbound tokens (say, a browser session that never
    /// had a node key) must say so explicitly by checking
    /// [`peer_key`](Self::peer_key) itself, rather than getting a silent pass
    /// from a "binding" check.
    pub fn is_bound_to(&self, presented: &PeerKey) -> bool {
        self.peer_key.as_ref() == Some(presented)
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

    // ---- R515: peer-key binding ------------------------------------------

    fn node_key(byte: u8) -> PeerKey {
        PeerKey::ed25519([byte; 32])
    }

    #[test]
    fn peer_key_wire_shape_is_alg_plus_base64url() {
        let k = node_key(0xAB);
        let json = serde_json::to_string(&k).unwrap();
        assert_eq!(
            json,
            format!(
                "{{\"alg\":\"ed25519\",\"key\":\"{}\"}}",
                URL_SAFE_NO_PAD.encode([0xABu8; 32])
            )
        );
        let back: PeerKey = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
        assert_eq!(back.as_bytes(), &[0xABu8; 32]);
        assert_eq!(back.to_base64url(), URL_SAFE_NO_PAD.encode([0xABu8; 32]));
    }

    #[test]
    fn peer_key_rejects_empty_and_wrong_length() {
        assert_eq!(
            PeerKey::new(PeerKeyAlgorithm::Ed25519, Vec::new()),
            Err(PeerKeyError::EmptyKey)
        );
        assert_eq!(
            PeerKey::new(PeerKeyAlgorithm::Ed25519, vec![1u8; 31]),
            Err(PeerKeyError::WrongKeyLength {
                algorithm: "ed25519".into(),
                expected: 32,
                actual: 31,
            })
        );
        // …and the same check runs on the wire, so a hand-crafted payload
        // can't smuggle a short "ed25519" key past the constructor.
        let json = format!(
            "{{\"alg\":\"ed25519\",\"key\":\"{}\"}}",
            URL_SAFE_NO_PAD.encode([1u8; 31])
        );
        let err = serde_json::from_str::<PeerKey>(&json).unwrap_err();
        assert!(
            err.to_string().contains("must be 32 bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn unknown_algorithm_round_trips_but_canonicalizes_known_labels() {
        // cheers is key-agnostic: a scheme it doesn't name still rides.
        let k = PeerKey::new(PeerKeyAlgorithm::Other("p256".into()), vec![7u8; 65]).unwrap();
        let json = serde_json::to_string(&k).unwrap();
        assert!(json.contains("\"alg\":\"p256\""));
        assert_eq!(serde_json::from_str::<PeerKey>(&json).unwrap(), k);

        // But one algorithm gets exactly one representation — otherwise a
        // token minted with Other("ed25519") would fail its own binding check
        // after a wire round-trip.
        let spelled_out =
            PeerKey::new(PeerKeyAlgorithm::Other("ed25519".into()), vec![9u8; 32]).unwrap();
        assert_eq!(spelled_out.algorithm(), &PeerKeyAlgorithm::Ed25519);
        assert_eq!(spelled_out, PeerKey::ed25519([9u8; 32]));

        assert_eq!(
            PeerKey::new(PeerKeyAlgorithm::Other(String::new()), vec![1u8; 4]),
            Err(PeerKeyError::EmptyAlgorithm)
        );
        let err = serde_json::from_str::<PeerKey>("{\"alg\":\"\",\"key\":\"AQID\"}").unwrap_err();
        assert!(
            err.to_string().contains("non-empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn claims_peer_key_defaults_none_and_is_omitted_from_wire() {
        let c = Claims::new(
            UserId::new("u1"),
            DeviceId::new("d1"),
            DeviceBinding::Passkey,
            100,
            200,
        );
        assert_eq!(c.peer_key, None);
        // Unset must not appear on the wire — a pre-R515 token is byte-identical.
        let json = serde_json::to_string(&c).unwrap();
        assert!(
            !json.contains("peer_key"),
            "unset peer_key must be skipped: {json}"
        );
        // …and a pre-R515 token still deserializes into the new shape.
        let back: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn claims_roundtrip_with_peer_key() {
        let c = Claims::new(
            UserId::new("u1"),
            DeviceId::new("d1"),
            DeviceBinding::Passkey,
            100,
            200,
        )
        .with_jti("tok-1")
        .with_peer_key(node_key(0x11));
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"peer_key\":{\"alg\":\"ed25519\""), "{json}");
        let back: Claims = serde_json::from_str(&json).unwrap();
        assert_eq!(back, c);
        assert!(back.is_bound_to(&node_key(0x11)));
    }

    #[test]
    fn is_bound_to_matches_only_the_exact_key() {
        let bound = Claims::new(
            UserId::new("u1"),
            DeviceId::new("d1"),
            DeviceBinding::Passkey,
            100,
            200,
        )
        .with_peer_key(node_key(0x11));

        assert!(bound.is_bound_to(&node_key(0x11)));
        // A stolen token replayed under the thief's own node key.
        assert!(!bound.is_bound_to(&node_key(0x22)));
        // Same bytes, different scheme — no cross-algorithm confusion.
        let same_bytes_other_alg =
            PeerKey::new(PeerKeyAlgorithm::Other("p256".into()), vec![0x11u8; 32]).unwrap();
        assert!(!bound.is_bound_to(&same_bytes_other_alg));

        // An unbound token is bound to nothing — fail closed.
        let unbound = Claims::new(
            UserId::new("u1"),
            DeviceId::new("d1"),
            DeviceBinding::Passkey,
            100,
            200,
        );
        assert!(!unbound.is_bound_to(&node_key(0x11)));
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
