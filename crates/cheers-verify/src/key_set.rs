//! [`KeySetVerifier`] — PASETO v4.public verification against a JWKS key set,
//! with key-role enforcement (product-scopes-and-authorization.md §D5).
//!
//! The footer `kid` selects a [`KeyEntry`]; its role decides what it may sign:
//!
//! | Role | Accepted as an access-token signer when |
//! |---|---|
//! | `issuer` | always (any `sub`) |
//! | `assertion` | never — assertions go only to `/token`, never to a resource server |
//! | `self-signer` | `sub` == the key's principal AND the token carries a valid [`ServiceCeiling`] |
//!
//! A ceiling is itself a PASETO v4.public, signed by an **issuer**-role key in
//! the same set, riding in the token's `ceiling` claim. It must name the same
//! principal as `sub`, list the token's `aud`, cover every token scope, and be
//! unexpired.
//!
//! Keys come from a static [`KeySet`] (in-process / tests / edge) or a live
//! [`JwksCache`] (remote; kid-miss triggers its rate-limited refetch).

use std::sync::Arc;

use pasetors::keys::AsymmetricPublicKey;
use pasetors::token::UntrustedToken;
use pasetors::version4::{PublicToken, V4};
use serde::de::DeserializeOwned;
use serde::Deserialize;

use cheers_core::{KeyRole, McpClaims, ServiceCeiling, SignedArtifact};

use crate::jwks::{JwkKey, JwksCache, JwksDoc, KeyEntry, KeySet};

/// Why a token was refused. Callers on an HTTP boundary should collapse these
/// into one 401; the variants exist for logs and audit.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("malformed token: {0}")]
    Malformed(String),

    #[error("token footer missing or unreadable kid")]
    MissingKid,

    #[error("unknown kid {0:?} after refresh")]
    UnknownKid(String),

    #[error("kid {kid:?} is a {role:?} key and may not sign this token: {reason}")]
    KeyRoleRejected {
        kid: String,
        role: KeyRole,
        reason: String,
    },

    #[error("signature verification failed")]
    SignatureMismatch,

    #[error("token expired at {exp}, now {now}")]
    Expired { exp: i64, now: i64 },

    #[error("issuer mismatch: expected {expected:?}, got {got:?}")]
    BadIssuer { expected: String, got: String },

    #[error("audience mismatch: expected {expected:?}, got {got:?}")]
    BadAudience { expected: String, got: String },

    #[error("claim shape violation: {0}")]
    BadClaims(String),
}

#[derive(Debug, Clone)]
enum Keys {
    Static(Arc<KeySet>),
    Cached(Arc<JwksCache>),
}

/// Verifies access tokens against a key set. Cheap to clone.
#[derive(Debug, Clone)]
pub struct KeySetVerifier {
    keys: Keys,
}

/// The claims every role check needs, whatever the caller's claim type.
#[derive(Deserialize)]
struct RoleView {
    iss: String,
    aud: String,
    sub: String,
    exp: i64,
    #[serde(default)]
    scope: Vec<String>,
    #[serde(default)]
    ceiling: Option<String>,
}

#[derive(Deserialize)]
struct Footer {
    kid: String,
}

impl KeySetVerifier {
    /// A fixed key set (in-process, tests, an edge with keys baked in).
    pub fn from_key_set(keys: KeySet) -> Self {
        Self {
            keys: Keys::Static(Arc::new(keys)),
        }
    }

    /// A live W159 cache; a kid-miss triggers its rate-limited refetch.
    pub fn from_cache(cache: Arc<JwksCache>) -> Self {
        Self {
            keys: Keys::Cached(cache),
        }
    }

    /// One issuer-role key, owned by `issuer`. The static set an in-process
    /// cheers surface verifies its own platform key with.
    pub fn from_issuer_key(kid: impl Into<String>, public_key: &[u8; 32], issuer: impl Into<String>) -> Self {
        let doc = JwksDoc {
            keys: vec![JwkKey::ed25519(kid, public_key, issuer, KeyRole::Issuer)],
        };
        Self::from_key_set(KeySet::from_doc(doc).expect("one Ed25519 key decodes"))
    }

    /// Verify `token` at `now` and return its payload as `T`.
    ///
    /// Checks, in order: footer kid, key lookup, role (assertion keys refused
    /// before any crypto), signature, `iss == expected_iss`, `aud ==
    /// expected_aud` when `Some`, expiry, then the self-signer rules.
    pub async fn verify<T: DeserializeOwned>(
        &self,
        token: &str,
        now: i64,
        expected_iss: &str,
        expected_aud: Option<&str>,
    ) -> Result<T, VerifyError> {
        let untrusted = parse(token)?;
        let kid = footer_kid(&untrusted)?;
        let set = self.keys_for(&kid).await;
        let entry = set
            .get(&kid)
            .ok_or_else(|| VerifyError::UnknownKid(kid.clone()))?;
        if entry.role == KeyRole::Assertion {
            return Err(rejected(&kid, entry, "assertion keys sign only client assertions presented to /token"));
        }
        let payload = verify_sig(entry, &untrusted, None)?;
        let view: RoleView =
            serde_json::from_str(&payload).map_err(|e| VerifyError::BadClaims(e.to_string()))?;
        if view.iss != expected_iss {
            return Err(VerifyError::BadIssuer {
                expected: expected_iss.into(),
                got: view.iss,
            });
        }
        if let Some(aud) = expected_aud {
            if view.aud != aud {
                return Err(VerifyError::BadAudience {
                    expected: aud.into(),
                    got: view.aud,
                });
            }
        }
        if view.exp <= now {
            return Err(VerifyError::Expired { exp: view.exp, now });
        }
        if entry.role == KeyRole::SelfSigner {
            check_self_signed(&set, &kid, entry, &view, now)?;
        }
        serde_json::from_str(&payload).map_err(|e| VerifyError::BadClaims(e.to_string()))
    }

    /// [`verify`](Self::verify) into cheers's own [`McpClaims`].
    pub async fn verify_mcp(
        &self,
        token: &str,
        now: i64,
        expected_iss: &str,
        expected_aud: Option<&str>,
    ) -> Result<McpClaims, VerifyError> {
        self.verify(token, now, expected_iss, expected_aud).await
    }

    /// Verify a [`SignedArtifact`] (R732-F6) and return its payload.
    ///
    /// The footer kid must name an **issuer**-role key (assertion and
    /// self-signer keys are refused before any crypto), the signature must
    /// carry `T::IMPLICIT_ASSERTION` — so an access token never verifies here
    /// and an artifact never verifies in [`verify`](Self::verify) — and the
    /// payload's issuer must be the key's owner. There is no clock check:
    /// artifacts have no edge-enforced expiry (noisetable W235 §0.1).
    pub async fn verify_artifact<T: SignedArtifact>(&self, token: &str) -> Result<T, VerifyError> {
        let untrusted = parse(token)?;
        let kid = footer_kid(&untrusted)?;
        let set = self.keys_for(&kid).await;
        let entry = set
            .get(&kid)
            .ok_or_else(|| VerifyError::UnknownKid(kid.clone()))?;
        if entry.role != KeyRole::Issuer {
            return Err(rejected(&kid, entry, "only issuer keys sign artifacts"));
        }
        let payload = verify_sig(entry, &untrusted, Some(T::IMPLICIT_ASSERTION))?;
        let artifact: T =
            serde_json::from_str(&payload).map_err(|e| VerifyError::BadClaims(e.to_string()))?;
        if artifact.issuer() != entry.principal {
            return Err(VerifyError::BadIssuer {
                expected: entry.principal.clone(),
                got: artifact.issuer().to_owned(),
            });
        }
        Ok(artifact)
    }

    /// The keys this verifier trusts right now — the static set, or the
    /// cache's current one. Persist [`KeySet::doc`] and rebuild with
    /// [`KeySet::from_doc`] + [`from_key_set`](Self::from_key_set) to verify
    /// offline against exactly these keys (R732-F5; see `IssuerTrust::export`).
    pub fn key_set(&self) -> Arc<KeySet> {
        match &self.keys {
            Keys::Static(s) => s.clone(),
            Keys::Cached(c) => c.keys(),
        }
    }

    async fn keys_for(&self, kid: &str) -> Arc<KeySet> {
        match &self.keys {
            Keys::Static(s) => s.clone(),
            Keys::Cached(c) => c.keys_for(kid).await,
        }
    }
}

fn parse(token: &str) -> Result<UntrustedToken<pasetors::token::Public, V4>, VerifyError> {
    UntrustedToken::<pasetors::token::Public, V4>::try_from(token)
        .map_err(|e| VerifyError::Malformed(format!("{e:?}")))
}

/// The footer is bound into the signature, so reading it first weakens nothing.
fn footer_kid(t: &UntrustedToken<pasetors::token::Public, V4>) -> Result<String, VerifyError> {
    let bytes = t.untrusted_footer();
    if bytes.is_empty() {
        return Err(VerifyError::MissingKid);
    }
    let footer: Footer =
        serde_json::from_slice(bytes).map_err(|e| VerifyError::Malformed(format!("footer: {e}")))?;
    Ok(footer.kid)
}

/// Low-level `PublicToken::verify`, never `pasetors::public::verify`: the
/// high-level path rejects the i64 `exp`/`iat` these payloads carry (R592-B7).
/// `implicit_assertion` is `None` for access tokens and ceilings, and the
/// artifact kind's own assertion for a [`SignedArtifact`].
fn verify_sig(
    entry: &KeyEntry,
    t: &UntrustedToken<pasetors::token::Public, V4>,
    implicit_assertion: Option<&[u8]>,
) -> Result<String, VerifyError> {
    let key = AsymmetricPublicKey::<V4>::from(&entry.public_key)
        .map_err(|e| VerifyError::Malformed(format!("pubkey: {e:?}")))?;
    let trusted = PublicToken::verify(&key, t, None, implicit_assertion).map_err(|e| match e {
        pasetors::errors::Error::TokenValidation => VerifyError::SignatureMismatch,
        other => VerifyError::Malformed(format!("{other:?}")),
    })?;
    Ok(trusted.payload().to_string())
}

fn rejected(kid: &str, entry: &KeyEntry, reason: impl Into<String>) -> VerifyError {
    VerifyError::KeyRoleRejected {
        kid: kid.into(),
        role: entry.role,
        reason: reason.into(),
    }
}

fn check_self_signed(
    set: &KeySet,
    kid: &str,
    entry: &KeyEntry,
    view: &RoleView,
    now: i64,
) -> Result<(), VerifyError> {
    let deny = |reason: &str| rejected(kid, entry, reason);
    if view.sub != entry.principal {
        return Err(deny("self-signed sub is not the key's principal"));
    }
    let raw = view.ceiling.as_deref().ok_or_else(|| deny("self-signed token carries no ceiling"))?;
    let ct = parse(raw).map_err(|_| deny("ceiling is not a PASETO v4.public"))?;
    let ckid = footer_kid(&ct).map_err(|_| deny("ceiling footer has no kid"))?;
    let issuer = set.get(&ckid).ok_or_else(|| deny("ceiling signed by an unknown kid"))?;
    if issuer.role != KeyRole::Issuer {
        return Err(deny("ceiling not signed by an issuer key"));
    }
    let payload = verify_sig(issuer, &ct, None).map_err(|_| deny("ceiling signature invalid"))?;
    let ceiling: ServiceCeiling =
        serde_json::from_str(&payload).map_err(|_| deny("ceiling payload malformed"))?;
    if ceiling.principal.to_string() != view.sub {
        return Err(deny("ceiling names a different principal"));
    }
    if ceiling.is_expired_at(now) {
        return Err(deny("ceiling expired"));
    }
    if !ceiling.allows_audience(&view.aud) {
        return Err(deny("token aud outside ceiling"));
    }
    if !ceiling.covers(view.scope.iter().map(String::as_str)) {
        return Err(deny("token scope exceeds ceiling"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_core::{yah_scopes, PrincipalId};
    use pasetors::keys::{AsymmetricKeyPair, AsymmetricSecretKey, Generate};

    const ISS: &str = "https://cheers.test";
    const AUD: &str = "https://inference.test";
    const SVC: &str = "svc:issues";

    fn kp() -> AsymmetricKeyPair<V4> {
        AsymmetricKeyPair::<V4>::generate().unwrap()
    }

    fn pub_bytes(k: &AsymmetricKeyPair<V4>) -> [u8; 32] {
        k.public.as_bytes().try_into().unwrap()
    }

    fn sign(secret: &AsymmetricSecretKey<V4>, kid: &str, payload: &impl serde::Serialize) -> String {
        let body = serde_json::to_vec(payload).unwrap();
        let footer = format!(r#"{{"kid":"{kid}"}}"#);
        PublicToken::sign(secret, &body, Some(footer.as_bytes()), None).unwrap()
    }

    struct Rig {
        issuer: AsymmetricKeyPair<V4>,
        assertion: AsymmetricKeyPair<V4>,
        selfsig: AsymmetricKeyPair<V4>,
        v: KeySetVerifier,
    }

    fn rig() -> Rig {
        let (issuer, assertion, selfsig) = (kp(), kp(), kp());
        let doc = JwksDoc {
            keys: vec![
                JwkKey::ed25519("iss-1", &pub_bytes(&issuer), ISS, KeyRole::Issuer),
                JwkKey::ed25519("asr-1", &pub_bytes(&assertion), SVC, KeyRole::Assertion),
                JwkKey::ed25519("self-1", &pub_bytes(&selfsig), SVC, KeyRole::SelfSigner),
            ],
        };
        Rig {
            v: KeySetVerifier::from_key_set(KeySet::from_doc(doc).unwrap()),
            issuer,
            assertion,
            selfsig,
        }
    }

    fn claims(sub: PrincipalId, scope: Vec<cheers_core::Scope>) -> McpClaims {
        McpClaims::new(ISS, AUD, sub, 1_000, 2_000, "jti", scope)
    }

    fn ceiling(r: &Rig, scopes: Vec<cheers_core::Scope>) -> String {
        let c = ServiceCeiling::new(PrincipalId::service("issues"), vec![AUD.into()], scopes, 900, 3_000)
            .unwrap();
        sign(&r.issuer.secret, "iss-1", &c)
    }

    fn verify(r: &Rig, token: &str) -> Result<McpClaims, VerifyError> {
        pollster::block_on(r.v.verify_mcp(token, 1_500, ISS, Some(AUD)))
    }

    fn role_rejected(res: Result<McpClaims, VerifyError>) -> String {
        match res {
            Err(VerifyError::KeyRoleRejected { reason, .. }) => reason,
            other => panic!("expected KeyRoleRejected, got {other:?}"),
        }
    }

    #[test]
    fn issuer_key_signs_any_sub() {
        let r = rig();
        let c = claims(PrincipalId::user("alice"), vec![yah_scopes::CLOUD_READ]);
        assert_eq!(verify(&r, &sign(&r.issuer.secret, "iss-1", &c)).unwrap(), c);
    }

    #[test]
    fn assertion_key_is_always_rejected() {
        let r = rig();
        let c = claims(PrincipalId::service("issues"), vec![]);
        role_rejected(verify(&r, &sign(&r.assertion.secret, "asr-1", &c)));
    }

    #[test]
    fn self_signer_without_ceiling_is_rejected() {
        let r = rig();
        let c = claims(PrincipalId::service("issues"), vec![yah_scopes::CLOUD_READ]);
        assert!(role_rejected(verify(&r, &sign(&r.selfsig.secret, "self-1", &c))).contains("no ceiling"));
    }

    #[test]
    fn self_signer_for_another_sub_is_rejected() {
        let r = rig();
        let c = claims(PrincipalId::service("other"), vec![yah_scopes::CLOUD_READ])
            .with_ceiling(ceiling(&r, vec![yah_scopes::CLOUD_READ]));
        assert!(role_rejected(verify(&r, &sign(&r.selfsig.secret, "self-1", &c))).contains("principal"));
    }

    #[test]
    fn self_signer_exceeding_ceiling_is_rejected() {
        let r = rig();
        let c = claims(PrincipalId::service("issues"), vec![yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY])
            .with_ceiling(ceiling(&r, vec![yah_scopes::CLOUD_READ]));
        assert!(role_rejected(verify(&r, &sign(&r.selfsig.secret, "self-1", &c))).contains("exceeds"));
    }

    #[test]
    fn self_signer_within_ceiling_is_accepted() {
        let r = rig();
        let c = claims(PrincipalId::service("issues"), vec![yah_scopes::CLOUD_READ])
            .with_ceiling(ceiling(&r, vec![yah_scopes::CLOUD_READ, yah_scopes::CLOUD_DEPLOY]));
        assert_eq!(verify(&r, &sign(&r.selfsig.secret, "self-1", &c)).unwrap(), c);
    }

    #[test]
    fn ceiling_signed_by_a_non_issuer_key_is_rejected() {
        let r = rig();
        let forged = ServiceCeiling::new(PrincipalId::service("issues"), vec![AUD.into()], vec![yah_scopes::CLOUD_DEPLOY], 900, 3_000)
            .unwrap();
        let c = claims(PrincipalId::service("issues"), vec![yah_scopes::CLOUD_DEPLOY])
            .with_ceiling(sign(&r.selfsig.secret, "self-1", &forged));
        assert!(role_rejected(verify(&r, &sign(&r.selfsig.secret, "self-1", &c))).contains("issuer key"));
    }

    #[test]
    fn expired_ceiling_and_foreign_audience_are_rejected() {
        let r = rig();
        let stale = ServiceCeiling::new(PrincipalId::service("issues"), vec![AUD.into()], vec![yah_scopes::CLOUD_READ], 100, 1_200)
            .unwrap();
        let c = claims(PrincipalId::service("issues"), vec![yah_scopes::CLOUD_READ])
            .with_ceiling(sign(&r.issuer.secret, "iss-1", &stale));
        assert!(role_rejected(verify(&r, &sign(&r.selfsig.secret, "self-1", &c))).contains("expired"));

        let other = ServiceCeiling::new(PrincipalId::service("issues"), vec!["https://x.test".into()], vec![yah_scopes::CLOUD_READ], 900, 3_000)
            .unwrap();
        let c = claims(PrincipalId::service("issues"), vec![yah_scopes::CLOUD_READ])
            .with_ceiling(sign(&r.issuer.secret, "iss-1", &other));
        assert!(role_rejected(verify(&r, &sign(&r.selfsig.secret, "self-1", &c))).contains("aud"));
    }

    #[test]
    fn standard_claim_checks() {
        let r = rig();
        let c = claims(PrincipalId::user("alice"), vec![]);
        let t = sign(&r.issuer.secret, "iss-1", &c);
        assert!(matches!(pollster::block_on(r.v.verify_mcp(&t, 2_000, ISS, Some(AUD))), Err(VerifyError::Expired { .. })));
        assert!(matches!(pollster::block_on(r.v.verify_mcp(&t, 1_500, "https://evil", Some(AUD))), Err(VerifyError::BadIssuer { .. })));
        assert!(matches!(pollster::block_on(r.v.verify_mcp(&t, 1_500, ISS, Some("https://x"))), Err(VerifyError::BadAudience { .. })));
        assert!(pollster::block_on(r.v.verify_mcp(&t, 1_500, ISS, None)).is_ok());
        let unknown = sign(&r.issuer.secret, "nope", &c);
        assert!(matches!(verify(&r, &unknown), Err(VerifyError::UnknownKid(_))));
        let wrong_key = sign(&r.selfsig.secret, "iss-1", &c);
        assert!(matches!(verify(&r, &wrong_key), Err(VerifyError::SignatureMismatch)));
        let no_footer = PublicToken::sign(&r.issuer.secret, &serde_json::to_vec(&c).unwrap(), None, None).unwrap();
        assert!(matches!(verify(&r, &no_footer), Err(VerifyError::MissingKid)));
    }
}
