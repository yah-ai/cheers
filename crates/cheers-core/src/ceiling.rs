//! [`ServiceCeiling`] — the cheers-issued bound on what a self-signing service
//! may mint for itself (product-scopes-and-authorization.md §D5).
//!
//! A JWKS key with role [`KeyRole::SelfSigner`](crate::KeyRole::SelfSigner)
//! may sign access tokens whose `sub` is its own `svc:<id>`, but only within a
//! ceiling cheers issued. The ceiling travels inside the access token as
//! [`McpClaims::ceiling`](crate::McpClaims::ceiling): a PASETO v4.public whose
//! payload is this struct, signed by an issuer-role key from the same JWKS.
//!
//! Same shape family as [`UserDelegation`](crate::UserDelegation): a principal,
//! what it may do, and an issued/expires window. This module is shape only —
//! the signature check lives in `cheers-verify` so cheers-core stays
//! crypto-free. Nothing mints ceilings yet; R731-F5's `/token` will.

use serde::{Deserialize, Serialize};

use crate::principal::{PrincipalId, PrincipalKind};
use crate::scope::Scope;

/// Why a [`ServiceCeiling`] failed to validate.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CeilingError {
    /// `principal` must name a service principal (`svc:<id>`).
    #[error("ceiling principal must be a service principal; got {0}")]
    PrincipalNotService(PrincipalKind),
    /// `expires_at <= issued_at`.
    #[error("expires_at must be strictly greater than issued_at")]
    ExpiresBeforeIssued,
}

/// The audiences and scopes a self-signing service may issue itself tokens
/// for. Construct via [`ServiceCeiling::new`]; deserialization runs the same
/// checks, so a wire payload can't bypass them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ServiceCeiling {
    /// The service this ceiling bounds. MUST be `svc:<id>`.
    pub principal: PrincipalId,
    /// Audiences a self-signed token may name as `aud`.
    pub audiences: Vec<String>,
    /// Upper bound on a self-signed token's `scope`.
    pub scopes: Vec<Scope>,
    /// Unix seconds cheers issued the ceiling at.
    pub issued_at: i64,
    /// Unix seconds the ceiling stops being acceptable.
    pub expires_at: i64,
}

impl ServiceCeiling {
    pub fn new(
        principal: PrincipalId,
        audiences: Vec<String>,
        scopes: Vec<Scope>,
        issued_at: i64,
        expires_at: i64,
    ) -> Result<Self, CeilingError> {
        if principal.kind != PrincipalKind::Service {
            return Err(CeilingError::PrincipalNotService(principal.kind));
        }
        if expires_at <= issued_at {
            return Err(CeilingError::ExpiresBeforeIssued);
        }
        Ok(Self {
            principal,
            audiences,
            scopes,
            issued_at,
            expires_at,
        })
    }

    /// `true` iff `expires_at <= now` — same rule as
    /// [`McpClaims::is_expired_at`](crate::McpClaims::is_expired_at).
    pub fn is_expired_at(&self, now: i64) -> bool {
        self.expires_at <= now
    }

    /// `true` iff `aud` is one of the ceiling's audiences.
    pub fn allows_audience(&self, aud: &str) -> bool {
        self.audiences.iter().any(|a| a == aud)
    }

    /// `true` iff every scope in `requested` is in the ceiling. Compared on the
    /// wire string so a verifier holding foreign claim types can ask too.
    pub fn covers<'a>(&self, requested: impl IntoIterator<Item = &'a str>) -> bool {
        requested
            .into_iter()
            .all(|s| self.scopes.iter().any(|c| c.as_wire() == s))
    }
}

#[derive(Deserialize)]
struct RawServiceCeiling {
    principal: PrincipalId,
    audiences: Vec<String>,
    scopes: Vec<Scope>,
    issued_at: i64,
    expires_at: i64,
}

impl<'de> Deserialize<'de> for ServiceCeiling {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let r = RawServiceCeiling::deserialize(d)?;
        Self::new(r.principal, r.audiences, r.scopes, r.issued_at, r.expires_at)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::yah_scopes;

    fn ceiling() -> ServiceCeiling {
        ServiceCeiling::new(
            PrincipalId::service("issues"),
            vec!["https://inference.example".into()],
            vec![yah_scopes::CLOUD_READ],
            100,
            200,
        )
        .unwrap()
    }

    #[test]
    fn rejects_non_service_principal() {
        let e = ServiceCeiling::new(PrincipalId::user("u"), vec![], vec![], 1, 2).unwrap_err();
        assert_eq!(e, CeilingError::PrincipalNotService(PrincipalKind::User));
    }

    #[test]
    fn roundtrips_and_revalidates_on_the_wire() {
        let c = ceiling();
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<ServiceCeiling>(&json).unwrap(), c);
        let bad = json.replace("\"expires_at\":200", "\"expires_at\":50");
        assert!(serde_json::from_str::<ServiceCeiling>(&bad).is_err());
    }

    #[test]
    fn covers_and_audience_checks() {
        let c = ceiling();
        assert!(c.covers([yah_scopes::CLOUD_READ.as_wire()]));
        assert!(!c.covers([yah_scopes::CLOUD_DEPLOY.as_wire()]));
        assert!(c.allows_audience("https://inference.example"));
        assert!(!c.allows_audience("https://other.example"));
        assert!(c.is_expired_at(200) && !c.is_expired_at(199));
    }
}
