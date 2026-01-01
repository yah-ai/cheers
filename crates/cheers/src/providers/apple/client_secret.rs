//! Apple Sign In `client_secret` — ES256 JWT generator + cache.
//!
//! Apple is the unusual OIDC provider: the value cheers presents as
//! `client_secret` to `https://appleid.apple.com/auth/token` is not a static
//! string but a short-lived, *self-signed* JWT proving the relying party
//! holds the ECDSA P-256 private key Apple issued in the developer console.
//!
//! [`AppleClientSecret`] holds the key material once and serves
//! [`current`](AppleClientSecret::current) on demand. Each value carries
//! its own `iat`/`exp`; the struct memoizes the most recently signed JWT
//! and re-signs only when within [`refresh_margin_seconds`](
//! AppleClientSecret::refresh_margin_seconds) of expiry.
//!
//! # Claim shape
//!
//! Apple requires exactly five claims (per its
//! [Generate and Validate Tokens] doc):
//!
//! | claim | source                                                |
//! |-------|-------------------------------------------------------|
//! | `iss` | Apple **Team ID** (10-char identifier)                |
//! | `iat` | unix-seconds at signing time                          |
//! | `exp` | `iat + ttl_seconds`, at most six months in the future |
//! | `aud` | always [`APPLE_AUDIENCE`]                             |
//! | `sub` | Apple **Services ID** / Bundle ID — same as `client_id` |
//!
//! and one header field: `kid` set to the **Key ID** shown next to the
//! `.p8` download in the Apple Developer console (Algorithm is `ES256`,
//! type is `JWT`).
//!
//! [Generate and Validate Tokens]:
//!     https://developer.apple.com/documentation/sign_in_with_apple/generate_and_validate_tokens
//!
//! # Why mint short
//!
//! Apple permits `exp - iat <= 15_777_000` seconds (~6 months). cheers
//! defaults to one hour ([`DEFAULT_TOKEN_TTL_SECONDS`]) — signing is
//! microseconds, and a short window narrows the blast radius if a JWT is
//! ever logged or leaked. Tune up with
//! [`with_ttl_seconds`](AppleClientSecret::with_ttl_seconds).
//!
//! # Invalidating the cache
//!
//! Wire [`invalidate`](AppleClientSecret::invalidate) into the Apple-side
//! error path. If `/auth/token` rejects the secret (e.g. `invalid_client`
//! after a developer-console key rotation), force a fresh mint before the
//! next attempt rather than serving the same stale JWT.
//!
//! # Example
//!
//! ```no_run
//! use cheers::providers::apple::AppleClientSecret;
//!
//! # fn run(p8_pem: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
//! let secret = AppleClientSecret::from_p8_pem(
//!     /* team_id */ "TEAM123ABC",
//!     /* key_id  */ "KEYID45678",
//!     /* client_id (Services ID) */ "com.example.signin",
//!     p8_pem,
//! )?;
//!
//! // unix seconds — caller supplies for testability
//! let now = std::time::SystemTime::now()
//!     .duration_since(std::time::UNIX_EPOCH)?
//!     .as_secs() as i64;
//! let jwt = secret.current(now)?;
//! // ...send as `client_secret` form field on /auth/token...
//! # Ok(()) }
//! ```

use std::sync::Mutex;

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

/// The only `aud` Apple accepts on a `client_secret` JWT.
pub const APPLE_AUDIENCE: &str = "https://appleid.apple.com";

/// Apple's documented hard ceiling on `exp - iat` — six months.
pub const APPLE_MAX_TTL_SECONDS: i64 = 15_777_000;

/// Default JWT lifetime — one hour. Short enough to be cheap re-signing,
/// long enough that a routine token exchange doesn't sit on the
/// regeneration path.
pub const DEFAULT_TOKEN_TTL_SECONDS: i64 = 60 * 60;

/// When the cached JWT has this many seconds (or fewer) of life remaining,
/// [`AppleClientSecret::current`] re-signs instead of serving the cache.
pub const DEFAULT_REFRESH_MARGIN_SECONDS: i64 = 5 * 60;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ClientSecretError {
    /// `EncodingKey::from_ec_pem` rejected the input. Most often: the byte
    /// slice wasn't a PEM-armored PKCS#8 EC private key, or the inner curve
    /// wasn't P-256.
    #[error("invalid p8 private key: {0}")]
    InvalidKey(String),

    /// `ttl_seconds` was zero/negative or exceeded [`APPLE_MAX_TTL_SECONDS`].
    #[error("ttl out of range (1..={max} seconds): got {got}", max = APPLE_MAX_TTL_SECONDS)]
    TtlOutOfRange { got: i64 },

    /// The refresh margin was negative, or `>= ttl_seconds` (which would
    /// mean every call re-signs and the cache is dead weight).
    #[error("refresh margin must be in 0..ttl_seconds: margin={margin} ttl={ttl}")]
    InvalidRefreshMargin { margin: i64, ttl: i64 },

    /// `jsonwebtoken::encode` failed. Indicates a bug — by this point the
    /// key parsed and the claims are simple owned strings + i64s.
    #[error("jwt sign: {0}")]
    Sign(String),
}

/// The five-claim payload Apple requires.
#[derive(Debug, Serialize)]
struct AppleClaims<'a> {
    iss: &'a str,
    iat: i64,
    exp: i64,
    aud: &'a str,
    sub: &'a str,
}

#[derive(Clone)]
struct Cached {
    token: String,
    /// `exp` of the cached JWT — re-mint when `now >= exp - refresh_margin`.
    expires_at: i64,
}

/// Generator for Apple `client_secret` ES256 JWTs.
///
/// Construct once at boot (the EC key parse is the only expensive bit) and
/// share via `&AppleClientSecret` everywhere a token-endpoint call is made.
/// Internally caches the most recently signed JWT; threadsafe via
/// `Mutex`.
pub struct AppleClientSecret {
    team_id: String,
    key_id: String,
    client_id: String,
    encoding_key: EncodingKey,
    ttl_seconds: i64,
    refresh_margin_seconds: i64,
    cache: Mutex<Option<Cached>>,
}

impl AppleClientSecret {
    /// Build from a PEM-encoded ECDSA P-256 private key — the literal
    /// contents of the `.p8` Apple ships from the developer console.
    ///
    /// `team_id` is the 10-character Apple Team ID; `key_id` is the matching
    /// 10-character key identifier shown next to the `.p8` download.
    /// `client_id` is the Services ID (or Bundle ID for native flows).
    pub fn from_p8_pem(
        team_id: impl Into<String>,
        key_id: impl Into<String>,
        client_id: impl Into<String>,
        p8_pem: &[u8],
    ) -> Result<Self, ClientSecretError> {
        let encoding_key = EncodingKey::from_ec_pem(p8_pem)
            .map_err(|e| ClientSecretError::InvalidKey(e.to_string()))?;
        Ok(Self {
            team_id: team_id.into(),
            key_id: key_id.into(),
            client_id: client_id.into(),
            encoding_key,
            ttl_seconds: DEFAULT_TOKEN_TTL_SECONDS,
            refresh_margin_seconds: DEFAULT_REFRESH_MARGIN_SECONDS,
            cache: Mutex::new(None),
        })
    }

    /// Override the JWT lifetime (`exp - iat`). Apple's hard ceiling is
    /// [`APPLE_MAX_TTL_SECONDS`] (~6 months). Re-signing is microseconds,
    /// so the default of one hour is a sensible floor.
    ///
    /// Calling this invalidates any cached JWT — the next
    /// [`current`](Self::current) signs fresh under the new TTL.
    pub fn with_ttl_seconds(mut self, ttl: i64) -> Result<Self, ClientSecretError> {
        if ttl <= 0 || ttl > APPLE_MAX_TTL_SECONDS {
            return Err(ClientSecretError::TtlOutOfRange { got: ttl });
        }
        if self.refresh_margin_seconds >= ttl {
            return Err(ClientSecretError::InvalidRefreshMargin {
                margin: self.refresh_margin_seconds,
                ttl,
            });
        }
        self.ttl_seconds = ttl;
        *self.cache.lock().expect("cache mutex") = None;
        Ok(self)
    }

    /// Override how soon before `exp` a cached JWT is treated as stale.
    /// Must be `0 <= margin < ttl_seconds`.
    pub fn with_refresh_margin_seconds(mut self, margin: i64) -> Result<Self, ClientSecretError> {
        if margin < 0 || margin >= self.ttl_seconds {
            return Err(ClientSecretError::InvalidRefreshMargin {
                margin,
                ttl: self.ttl_seconds,
            });
        }
        self.refresh_margin_seconds = margin;
        Ok(self)
    }

    pub fn team_id(&self) -> &str {
        &self.team_id
    }
    pub fn key_id(&self) -> &str {
        &self.key_id
    }
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn ttl_seconds(&self) -> i64 {
        self.ttl_seconds
    }
    pub fn refresh_margin_seconds(&self) -> i64 {
        self.refresh_margin_seconds
    }

    /// Return the current `client_secret` JWT for the configured
    /// `(team_id, key_id, client_id)`. Serves the cache if its remaining
    /// life is greater than [`refresh_margin_seconds`](Self::refresh_margin_seconds);
    /// otherwise signs fresh with `iat = now` and `exp = now + ttl_seconds`.
    ///
    /// `now` is unix-seconds — caller supplies so tests can pin the clock.
    pub fn current(&self, now: i64) -> Result<String, ClientSecretError> {
        {
            let cache = self.cache.lock().expect("cache mutex");
            if let Some(c) = cache.as_ref() {
                if c.expires_at.saturating_sub(self.refresh_margin_seconds) > now {
                    return Ok(c.token.clone());
                }
            }
        }
        let exp = now.saturating_add(self.ttl_seconds);
        let claims = AppleClaims {
            iss: &self.team_id,
            iat: now,
            exp,
            aud: APPLE_AUDIENCE,
            sub: &self.client_id,
        };
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let token = jsonwebtoken::encode(&header, &claims, &self.encoding_key)
            .map_err(|e| ClientSecretError::Sign(e.to_string()))?;
        *self.cache.lock().expect("cache mutex") = Some(Cached {
            token: token.clone(),
            expires_at: exp,
        });
        Ok(token)
    }

    /// Drop the cached JWT — wire this into Apple `/auth/token` error
    /// handling so a key rotation or transient mint bug doesn't keep
    /// returning the same stale secret.
    pub fn invalidate(&self) {
        *self.cache.lock().expect("cache mutex") = None;
    }

    /// Test/observability: the `exp` of the cached JWT, if one is held.
    pub fn cache_expires_at(&self) -> Option<i64> {
        self.cache
            .lock()
            .expect("cache mutex")
            .as_ref()
            .map(|c| c.expires_at)
    }
}

impl std::fmt::Debug for AppleClientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `EncodingKey` stays opaque so accidental logs don't leak the
        // Apple-issued private key.
        f.debug_struct("AppleClientSecret")
            .field("team_id", &self.team_id)
            .field("key_id", &self.key_id)
            .field("client_id", &self.client_id)
            .field("encoding_key", &"<redacted>")
            .field("ttl_seconds", &self.ttl_seconds)
            .field("refresh_margin_seconds", &self.refresh_margin_seconds)
            .field(
                "cache_expires_at",
                &self
                    .cache
                    .lock()
                    .expect("cache mutex")
                    .as_ref()
                    .map(|c| c.expires_at),
            )
            .finish()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
    use serde::Deserialize;

    /// Any non-zero scalar below P-256's order works as a deterministic
    /// private key for tests. Reusing it across cases also means the
    /// derived public key is fixed — convenient for verifying signatures
    /// without threading a keypair through every test.
    fn fixed_keypair() -> (String, String) {
        let mut bytes = [0u8; 32];
        bytes[31] = 0x42;
        let sk = p256::SecretKey::from_slice(&bytes).expect("valid P-256 scalar");
        let p8 = sk
            .to_pkcs8_pem(LineEnding::LF)
            .expect("P-256 PKCS#8 PEM encode")
            .to_string();
        let pubpem = sk
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .expect("P-256 SPKI PEM encode");
        (p8, pubpem)
    }

    fn make_secret() -> AppleClientSecret {
        let (p8, _) = fixed_keypair();
        AppleClientSecret::from_p8_pem(
            "TEAM123ABC",
            "KEYID45678",
            "com.example.signin",
            p8.as_bytes(),
        )
        .expect("valid p8 PEM parses")
    }

    fn validation_no_exp() -> Validation {
        // Tests pin `now` explicitly; defer to manual claim asserts rather
        // than jsonwebtoken's system-clock-driven exp check.
        let mut v = Validation::new(Algorithm::ES256);
        v.set_audience(&[APPLE_AUDIENCE]);
        v.set_issuer(&["TEAM123ABC"]);
        v.set_required_spec_claims(&["iss", "iat", "exp", "aud", "sub"]);
        v.validate_exp = false;
        v.validate_nbf = false;
        v
    }

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    struct DecodedClaims {
        iss: String,
        iat: i64,
        exp: i64,
        aud: String,
        sub: String,
    }

    // -- key parsing ---------------------------------------------------------

    #[test]
    fn from_p8_pem_rejects_garbage() {
        let err = AppleClientSecret::from_p8_pem("T", "K", "C", b"not a PEM").unwrap_err();
        assert!(matches!(err, ClientSecretError::InvalidKey(_)));
    }

    #[test]
    fn from_p8_pem_accepts_pkcs8_p256() {
        // The Apple .p8 happy path: PEM-armored PKCS#8 P-256 private key.
        let _ = make_secret();
    }

    // -- defaults + builders -------------------------------------------------

    #[test]
    fn defaults_match_documented_constants() {
        let s = make_secret();
        assert_eq!(s.team_id(), "TEAM123ABC");
        assert_eq!(s.key_id(), "KEYID45678");
        assert_eq!(s.client_id(), "com.example.signin");
        assert_eq!(s.ttl_seconds(), DEFAULT_TOKEN_TTL_SECONDS);
        assert_eq!(s.refresh_margin_seconds(), DEFAULT_REFRESH_MARGIN_SECONDS);
        assert!(s.cache_expires_at().is_none());
    }

    #[test]
    fn with_ttl_rejects_out_of_range() {
        let s = make_secret();
        assert!(matches!(
            s.with_ttl_seconds(0).unwrap_err(),
            ClientSecretError::TtlOutOfRange { got: 0 }
        ));
        let s = make_secret();
        assert!(matches!(
            s.with_ttl_seconds(-1).unwrap_err(),
            ClientSecretError::TtlOutOfRange { got: -1 }
        ));
        let s = make_secret();
        assert!(matches!(
            s.with_ttl_seconds(APPLE_MAX_TTL_SECONDS + 1).unwrap_err(),
            ClientSecretError::TtlOutOfRange { .. }
        ));
    }

    #[test]
    fn with_ttl_accepts_one_and_max() {
        // Margin default (300s) exceeds ttl=1, so explicitly reset it first.
        let s = make_secret()
            .with_refresh_margin_seconds(0)
            .unwrap()
            .with_ttl_seconds(1)
            .unwrap();
        assert_eq!(s.ttl_seconds(), 1);
        let s = make_secret().with_ttl_seconds(APPLE_MAX_TTL_SECONDS).unwrap();
        assert_eq!(s.ttl_seconds(), APPLE_MAX_TTL_SECONDS);
    }

    #[test]
    fn with_ttl_rejects_when_existing_margin_would_consume_it() {
        // default margin = 300s; setting ttl=300 leaves zero usable window.
        let err = make_secret().with_ttl_seconds(300).unwrap_err();
        assert!(matches!(err, ClientSecretError::InvalidRefreshMargin { .. }));
    }

    #[test]
    fn with_refresh_margin_rejects_out_of_range() {
        let s = make_secret();
        assert!(matches!(
            s.with_refresh_margin_seconds(-1).unwrap_err(),
            ClientSecretError::InvalidRefreshMargin { margin: -1, .. }
        ));
        let s = make_secret();
        // margin == ttl: every call would re-sign, cache is dead weight.
        assert!(matches!(
            s.with_refresh_margin_seconds(DEFAULT_TOKEN_TTL_SECONDS)
                .unwrap_err(),
            ClientSecretError::InvalidRefreshMargin { .. }
        ));
    }

    // -- minted JWT shape ----------------------------------------------------

    #[test]
    fn current_mints_jwt_with_expected_header() {
        let secret = make_secret();
        let token = secret.current(1_700_000_000).unwrap();
        let header = decode_header(&token).expect("decode header");
        assert_eq!(header.alg, Algorithm::ES256);
        assert_eq!(header.kid.as_deref(), Some("KEYID45678"));
        // `jsonwebtoken` defaults `typ` to "JWT" — defensive assert.
        assert_eq!(header.typ.as_deref(), Some("JWT"));
    }

    #[test]
    fn current_mints_jwt_with_expected_claims() {
        let secret = make_secret();
        let (_, pubpem) = fixed_keypair();
        let now = 1_700_000_000;
        let token = secret.current(now).unwrap();
        let key = DecodingKey::from_ec_pem(pubpem.as_bytes()).expect("decoding key");
        let data =
            decode::<DecodedClaims>(&token, &key, &validation_no_exp()).expect("verify ES256");
        assert_eq!(data.claims.iss, "TEAM123ABC");
        assert_eq!(data.claims.aud, APPLE_AUDIENCE);
        assert_eq!(data.claims.sub, "com.example.signin");
        assert_eq!(data.claims.iat, now);
        assert_eq!(data.claims.exp, now + DEFAULT_TOKEN_TTL_SECONDS);
    }

    #[test]
    fn current_signature_does_not_verify_under_wrong_key() {
        let secret = make_secret();
        let token = secret.current(1_700_000_000).unwrap();
        // Different scalar → different public key → ES256 signature fails.
        let mut bytes = [0u8; 32];
        bytes[31] = 0x43;
        let other = p256::SecretKey::from_slice(&bytes).unwrap();
        let other_pub = other
            .public_key()
            .to_public_key_pem(LineEnding::LF)
            .unwrap();
        let key = DecodingKey::from_ec_pem(other_pub.as_bytes()).unwrap();
        let err =
            decode::<DecodedClaims>(&token, &key, &validation_no_exp()).expect_err("wrong key");
        // jsonwebtoken returns InvalidSignature for this case.
        assert!(
            format!("{err}").to_lowercase().contains("signature"),
            "{err}"
        );
    }

    // -- caching -------------------------------------------------------------

    #[test]
    fn current_returns_same_token_inside_window() {
        let secret = make_secret();
        let t1 = secret.current(1_700_000_000).unwrap();
        let t2 = secret.current(1_700_000_001).unwrap();
        assert_eq!(t1, t2, "cached token should be reused");
        assert_eq!(
            secret.cache_expires_at(),
            Some(1_700_000_000 + DEFAULT_TOKEN_TTL_SECONDS)
        );
    }

    #[test]
    fn current_re_mints_when_within_refresh_margin() {
        let secret = make_secret(); // ttl=3600, margin=300
        let now_a = 1_700_000_000;
        let t1 = secret.current(now_a).unwrap();
        // exp = now_a + 3600. Re-mint threshold = exp - 300 = now_a + 3300.
        // At now_b == threshold we should re-mint (`exp - margin > now` false).
        let now_b = now_a + 3300;
        let t2 = secret.current(now_b).unwrap();
        assert_ne!(t1, t2, "expected fresh JWT inside refresh margin");
        assert_eq!(
            secret.cache_expires_at(),
            Some(now_b + DEFAULT_TOKEN_TTL_SECONDS)
        );
    }

    #[test]
    fn current_serves_cache_right_up_to_refresh_margin_edge() {
        let secret = make_secret(); // ttl=3600, margin=300
        let now_a = 1_700_000_000;
        let t1 = secret.current(now_a).unwrap();
        // threshold - 1: still outside the margin, cache valid.
        let t2 = secret.current(now_a + 3299).unwrap();
        assert_eq!(t1, t2);
    }

    #[test]
    fn invalidate_forces_re_mint() {
        let secret = make_secret();
        let t1 = secret.current(1_700_000_000).unwrap();
        secret.invalidate();
        assert!(secret.cache_expires_at().is_none());
        let t2 = secret.current(1_700_000_001).unwrap();
        assert_ne!(t1, t2);
    }

    #[test]
    fn with_ttl_invalidates_cache() {
        let secret = make_secret();
        let _ = secret.current(1_700_000_000).unwrap();
        let secret = secret.with_ttl_seconds(7200).unwrap();
        assert!(secret.cache_expires_at().is_none());
    }

    // -- redaction -----------------------------------------------------------

    #[test]
    fn debug_redacts_encoding_key() {
        let dbg = format!("{:?}", make_secret());
        assert!(dbg.contains("AppleClientSecret"));
        assert!(dbg.contains("team_id: \"TEAM123ABC\""));
        assert!(dbg.contains("encoding_key: \"<redacted>\""));
        // The base64-encoded EC private bits shouldn't leak through.
        assert!(!dbg.to_lowercase().contains("begin private key"));
    }

    // -- Send+Sync proves cache mutex is reachable from concurrent callers ---

    #[test]
    fn is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AppleClientSecret>();
    }
}
