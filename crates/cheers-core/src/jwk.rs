//! What a published JWKS key is allowed to sign (product-scopes doc §D5).
//!
//! Every key cheers publishes at `/.well-known/jwks.json` carries a `role`.
//! A verifier must check it: a kid's presence in the set says only that cheers
//! vouches for the public half, not what that key may assert. Lives in
//! cheers-core so verifiers (kamaji) can share the type without linking
//! cheers-server.

use serde::{Deserialize, Serialize};

/// The closed set of key roles, serialized kebab-case on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KeyRole {
    /// cheers's own platform key. The only role that may sign access tokens.
    Issuer,
    /// A service principal's key. Signs assertions presented TO cheers
    /// (client authentication), never access tokens a resource server accepts.
    Assertion,
    /// A principal key allowed to self-sign tokens under a ceiling. Nothing
    /// emits this yet; verifiers reject it until delegation lands (R731-F6).
    SelfSigner,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serializes_kebab_case() {
        assert_eq!(serde_json::to_string(&KeyRole::Issuer).unwrap(), "\"issuer\"");
        assert_eq!(serde_json::to_string(&KeyRole::Assertion).unwrap(), "\"assertion\"");
        assert_eq!(serde_json::to_string(&KeyRole::SelfSigner).unwrap(), "\"self-signer\"");
        assert!(serde_json::from_str::<KeyRole>("\"admin\"").is_err());
    }
}
