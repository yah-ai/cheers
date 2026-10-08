//! RFC 7523 client-assertion claims — how a service principal authenticates
//! to cheers's token endpoint (R731-F4, doc D3).
//!
//! A service principal holds an Ed25519 key cheers published with
//! `role=assertion` ([`KeyRole`](crate::KeyRole)). It signs a short-lived
//! PASETO v4.public assertion carrying these claims (flat JSON payload, `kid`
//! in the footer, same envelope as [`McpClaims`](crate::McpClaims)) and trades
//! it at the token endpoint for an access token minted by cheers's issuer key.
//! The assertion itself is never valid at a resource server.

use serde::{Deserialize, Serialize};

use crate::principal::PrincipalId;

/// Claims of a service principal's client assertion.
///
/// `iss` and `sub` both name the principal (`svc:<id>`), `aud` is the token
/// endpoint URL, and `jti` is consumed once so a captured assertion cannot be
/// replayed. Lifetime (`exp - iat`) is capped at
/// [`MAX_LIFETIME_SECONDS`](Self::MAX_LIFETIME_SECONDS).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ClientAssertion {
    pub iss: PrincipalId,
    pub sub: PrincipalId,
    pub aud: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
}

impl ClientAssertion {
    /// 5 minutes — the longest assertion lifetime the token endpoint accepts.
    pub const MAX_LIFETIME_SECONDS: i64 = 300;

    /// An assertion for `principal` (as both `iss` and `sub`).
    pub fn new(
        principal: PrincipalId,
        aud: impl Into<String>,
        jti: impl Into<String>,
        iat: i64,
        exp: i64,
    ) -> Self {
        Self {
            iss: principal.clone(),
            sub: principal,
            aud: aud.into(),
            jti: jti.into(),
            iat,
            exp,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_with_wire_principal_ids() {
        let a = ClientAssertion::new(PrincipalId::service("yubaba"), "https://c.example/token", "j1", 10, 70);
        let v = serde_json::to_value(&a).unwrap();
        assert_eq!(v["iss"], "svc:yubaba");
        assert_eq!(v["sub"], "svc:yubaba");
        let back: ClientAssertion = serde_json::from_value(v).unwrap();
        assert_eq!(back, a);
    }
}
