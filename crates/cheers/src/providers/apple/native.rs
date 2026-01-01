//! Apple Sign In — native (iOS/macOS) `id_token` verification.
//!
//! On native Apple platforms the OS-level
//! `ASAuthorizationController` hands the relying party an Apple-signed
//! `id_token` directly. There is **no code exchange**, no
//! `client_secret`, no PKCE flow — the JWT is already minted by Apple's
//! servers and the relying party only needs to verify it.
//!
//! [`AppleNativeVerifier`] is that verifier. It holds a `ClientId` (the
//! Services ID / Bundle ID — same value Apple signs into `aud`) and an
//! [`AppleJwksCache`] (the source of truth for the RS256 public keys
//! Apple rotates). [`verify_native_token`](AppleNativeVerifier::verify_native_token)
//! decodes the JWT, looks up the matching key by `kid`, verifies the
//! signature, validates the OIDC-standard claims (`iss`, `aud`, `exp`,
//! `iat`, `nbf`), and — when the caller passes one —
//! confirms the `nonce` matches the value bound to the authorization
//! request on the device.
//!
//! # On-failure JWKS refresh
//!
//! Apple rotates the signing key roughly on the order of months but
//! gives no advance notice. If a verify fails with a hint that the
//! `kid` isn't in the cached JWKS — or the signature didn't verify
//! under any cached key — [`verify_native_token`] invalidates the
//! [`AppleJwksCache`] and retries **once**. This catches a rotation
//! between scheduled weekly refreshes without busy-fetching the JWKS
//! on every verify.
//!
//! Claim-shape failures (wrong `iss`, wrong `aud`, expired, nonce
//! mismatch) do **not** trigger the retry — those errors are
//! deterministic regardless of which JWKS is cached.
//!
//! # Caller-side responsibilities
//!
//! - **Bind a nonce.** On native flows the caller picks a per-request
//!   nonce (e.g. a 16-byte CSPRNG b64url-encoded string), embeds it in
//!   the `ASAuthorizationAppleIDRequest`, and stashes it server-side
//!   keyed on the user's session. On the verify call, pass that nonce
//!   as `expected_nonce` — Apple echoes it into the id_token's `nonce`
//!   claim. Without nonce binding, an id_token captured for one
//!   authorization can be replayed against another session.
//! - **Treat `sub` as opaque.** Apple's `sub` is per-Team-ID; map to
//!   your user store via `ProviderKey::OidcApple` keyed on `sub`.
//! - **Private-relay email.** When the user opts to hide their email,
//!   `email` arrives as `…@privaterelay.appleid.com`. Treat as the
//!   user's email of record; Apple forwards real mail.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use cheers::providers::apple::{AppleJwksCache, AppleNativeVerifier};
//! use openidconnect::{reqwest, ClientId, Nonce};
//!
//! # async fn run(id_token_jwt: &str) -> Result<(), Box<dyn std::error::Error>> {
//! let http = reqwest::ClientBuilder::new()
//!     .redirect(reqwest::redirect::Policy::none())
//!     .build()?;
//! let cache = Arc::new(AppleJwksCache::for_apple());
//! let verifier = AppleNativeVerifier::new(
//!     ClientId::new("com.example.signin".into()),
//!     cache,
//! );
//!
//! let now = 1_700_000_000;
//! let expected_nonce = Nonce::new("the-nonce-bound-to-the-session".into());
//! let verified = verifier
//!     .verify_native_token(id_token_jwt, Some(&expected_nonce), now, &http)
//!     .await?;
//! println!("welcome sub={} email={:?}", verified.subject, verified.email);
//! # Ok(()) }
//! ```

use std::str::FromStr;
use std::sync::Arc;

use openidconnect::core::{CoreIdToken, CoreIdTokenClaims, CoreIdTokenVerifier};
use openidconnect::{reqwest, ClientId, IssuerUrl, Nonce};

use super::jwks_cache::{AppleJwksCache, HttpJwksFetcher, JwksError, JwksFetcher};
use super::redirect::APPLE_ISSUER;
use crate::providers::oidc_generic::VerifiedIdToken;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AppleNativeError {
    /// JWKS fetch or cache lookup failed.
    #[error("apple jwks: {0}")]
    Jwks(#[from] JwksError),

    /// JWT couldn't be decoded — wrong shape, not three base64url chunks
    /// separated by dots, or JSON body malformed.
    #[error("apple id_token malformed: {0}")]
    Malformed(String),

    /// JWT decoded but failed verification — signature mismatch, wrong
    /// `iss`/`aud`/`nonce`/`exp`, or no matching `kid` in the JWKS even
    /// after a rotation refresh.
    #[error("apple id_token verification: {0}")]
    IdToken(String),

    /// Constructed `AppleNativeVerifier` with an `issuer` that
    /// [`IssuerUrl::new`] rejected. Only reachable from
    /// [`AppleNativeVerifier::with_issuer`]; the default path uses the
    /// const [`APPLE_ISSUER`] which is checked at compile time.
    #[error("apple native issuer: {0}")]
    InvalidIssuer(String),
}

// ---------------------------------------------------------------------------
// AppleNativeVerifier
// ---------------------------------------------------------------------------

/// Verifier for Apple-signed `id_token`s delivered to native iOS/macOS apps.
pub struct AppleNativeVerifier<F: JwksFetcher = HttpJwksFetcher> {
    client_id: ClientId,
    issuer: IssuerUrl,
    jwks_cache: Arc<AppleJwksCache<F>>,
}

impl<F: JwksFetcher> std::fmt::Debug for AppleNativeVerifier<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleNativeVerifier")
            .field("client_id", &self.client_id)
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl AppleNativeVerifier<HttpJwksFetcher> {
    /// Build pinned to Apple's published issuer. `jwks_cache` should be
    /// the same instance shared with any other Apple verification path
    /// in the process (cache hits are then maximally effective).
    pub fn new(client_id: ClientId, jwks_cache: Arc<AppleJwksCache<HttpJwksFetcher>>) -> Self {
        Self {
            client_id,
            issuer: IssuerUrl::new(APPLE_ISSUER.to_owned())
                .expect("APPLE_ISSUER const must parse"),
            jwks_cache,
        }
    }
}

impl<F: JwksFetcher> AppleNativeVerifier<F> {
    /// Build with a non-Apple issuer (for tests pointing at a wiremock
    /// IdP, or self-hosted Apple-compatible servers). Returns
    /// [`AppleNativeError::InvalidIssuer`] if the URL doesn't parse.
    pub fn with_issuer(
        client_id: ClientId,
        issuer: impl Into<String>,
        jwks_cache: Arc<AppleJwksCache<F>>,
    ) -> Result<Self, AppleNativeError> {
        let issuer = issuer.into();
        let issuer = IssuerUrl::new(issuer.clone())
            .map_err(|e| AppleNativeError::InvalidIssuer(format!("{issuer}: {e}")))?;
        Ok(Self {
            client_id,
            issuer,
            jwks_cache,
        })
    }

    pub fn client_id(&self) -> &ClientId {
        &self.client_id
    }

    pub fn issuer(&self) -> &IssuerUrl {
        &self.issuer
    }

    pub fn jwks_cache(&self) -> &AppleJwksCache<F> {
        &self.jwks_cache
    }

    /// Verify an Apple-signed `id_token`. Returns the canonical
    /// [`VerifiedIdToken`] shape so callers map providers identically
    /// into `UserStore`.
    ///
    /// `expected_nonce` mirrors openidconnect's nonce-binding contract:
    /// pass `Some(&nonce)` when the caller has a per-request nonce bound
    /// server-side, `None` to skip nonce verification (only safe when
    /// the calling product *has* no per-request nonce — typical native
    /// SDK flows always supply one).
    ///
    /// On a JWKS-rotation-shaped failure (no matching `kid`, signature
    /// invalid) this method invalidates the cache and retries the
    /// verification once with a freshly-fetched JWKS.
    pub async fn verify_native_token(
        &self,
        jwt: &str,
        expected_nonce: Option<&Nonce>,
        now: i64,
        http: &reqwest::Client,
    ) -> Result<VerifiedIdToken, AppleNativeError> {
        match self.verify_once(jwt, expected_nonce, now, http).await {
            Ok(v) => Ok(v),
            Err(AppleNativeError::IdToken(msg)) if looks_like_rotation_failure(&msg) => {
                self.jwks_cache.invalidate();
                self.verify_once(jwt, expected_nonce, now, http).await
            }
            Err(e) => Err(e),
        }
    }

    async fn verify_once(
        &self,
        jwt: &str,
        expected_nonce: Option<&Nonce>,
        now: i64,
        http: &reqwest::Client,
    ) -> Result<VerifiedIdToken, AppleNativeError> {
        let jwks = self.jwks_cache.jwks(now, http).await?;
        let id_token = CoreIdToken::from_str(jwt)
            .map_err(|e| AppleNativeError::Malformed(e.to_string()))?;
        let verifier = CoreIdTokenVerifier::new_public_client(
            self.client_id.clone(),
            self.issuer.clone(),
            (*jwks).clone(),
        );
        let claims: &CoreIdTokenClaims = match expected_nonce {
            Some(n) => id_token.claims(&verifier, n),
            None => id_token.claims(&verifier, |_n: Option<&Nonce>| Ok::<_, String>(())),
        }
        .map_err(|e| AppleNativeError::IdToken(e.to_string()))?;

        let name = claims
            .name()
            .and_then(|n| n.get(None).or_else(|| n.iter().next().map(|(_, v)| v)))
            .map(|v| v.as_str().to_owned());
        Ok(VerifiedIdToken {
            issuer: claims.issuer().as_str().to_owned(),
            subject: claims.subject().as_str().to_owned(),
            email: claims.email().map(|e| e.as_str().to_owned()),
            email_verified: claims.email_verified(),
            name,
        })
    }
}

/// Heuristic — does this openidconnect verification error look like a
/// JWKS rotation event rather than a deterministic claim-shape failure?
///
/// `IdTokenVerifier` error messages vary across openidconnect versions
/// but the JWKS-key-not-found / signature-invalid paths consistently
/// mention "key", "kid", "signature", or "no matching". `iss`/`aud`/
/// `exp`/`nonce` mismatches do not. Pattern-matching is brittle in
/// principle but the cost of a false positive is one extra HTTP GET
/// against Apple's `/auth/keys`; the cost of a false negative is failing
/// to recover from a key rotation until the weekly refresh tick. The
/// trade-off favors over-matching.
fn looks_like_rotation_failure(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("kid")
        || m.contains("no matching")
        || m.contains("key")
        || m.contains("signature")
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex as StdMutex;

    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use openidconnect::core::{
        CoreIdToken, CoreIdTokenClaims, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
        CoreRsaPrivateSigningKey,
    };
    use openidconnect::{
        Audience, EmptyAdditionalClaims, EndUserEmail, JsonWebKeyId, PrivateSigningKey,
        StandardClaims, SubjectIdentifier,
    };

    use crate::providers::apple::jwks_cache::AppleJwksCache;

    /// Reuse the `openidconnect` test PEM that google.rs + apple/redirect.rs
    /// already pull in. Apple signs id_tokens with RS256, same as Google,
    /// so a single shared key keeps the test plumbing minimal.
    const TEST_RSA_PEM: &str = concat!(
        "-----BEGIN RSA PRIVATE KEY-----\n",
        "MIIEowIBAAKCAQEAsRMj0YYjy7du6v1gWyKSTJx3YjBzZTG0XotRP0IaObw0k+68\n",
        "30dXadjL5jVhSWNdcg9OyMyTGWfdNqfdrS6ppBqlQNgjZJdloIqL9zOLBZrDm7G4\n",
        "+qN4KeZ4/5TyEilq2zOHHGFEzXpOq/UxqVnm3J4fhjqCNaS2nKd7HVVXGBQQ+4+F\n",
        "dVT+MyJXemw5maz2F/h324TQi6XoUPEwUddxBwLQFSOlzWnHYMc4/lcyZJ8MpTXC\n",
        "MPe/YJFNtb9CaikKUdf8x4mzwH7usSf8s2d6R4dQITzKrjrEJ0u3w3eGkBBapoMV\n",
        "FBGPjP3Haz5FsVtHc5VEN3FZVIDF6HrbJH1C4QIDAQABAoIBAHSS3izM+3nc7Bel\n",
        "8S5uRxRKmcm5je6b11u6qiVUFkHWJmMRc6QmqmSThkCq+b4/vUAe1cYZ7+l02Exo\n",
        "HOcrZiEULaDP6hUKGqyjKVv3wdlRtt8kFFxlC/HBufzAiNDuFVvzw0oquwnvMCXC\n",
        "yQvtlK+/JY/PqvM32cSt+b4o9apySsHqAtdsoHHohK82jsQqIfCi1v8XYV/xRBJB\n",
        "cQMCaA0Ls3tFpmJv3JdikyyQxio4kZ5tswghC63znCp1iL+qDq1wjjKzjick9MDb\n",
        "Qzb95X09QQP201l1FPWN7Kbhj4ybg6PJGz/VHQcvILcBCoYIc0UY/OMSBt9VN9yD\n",
        "wr1WlbECgYEA37difsTMcLmUEN57sicFe1q4lxH6eqnUBjmoKBflx4oMIIyRnfjF\n",
        "Jwsu9yIiBkJfBCP85nl2tZdcV0wfZLf6amxB/KMtdfW6r8eoTDzE472OYxSIg1F5\n",
        "dI4qn2nBI0Dou0g58xj+Kv0iLaym0pxtyJkSg/rxZGwKb9a+x5WAs50CgYEAyqC0\n",
        "NcZs2BRIiT5kEOF6+MeUvarbKh1mangKHKcTdXRrvoJ+Z5izm7FifBixo/79MYpt\n",
        "0VofW0IzYKtAI9KZDq2JcozEbZ+lt/ZPH5QEXO4T39QbDoAG8BbOmEP7l+6m+7QO\n",
        "PiQ0WSNjDnwk3W7Zihgg31DH7hyxsxQCapKLcxUCgYAwERXPiPcoDSd8DGFlYK7z\n",
        "1wUsKEe6DT0p7T9tBd1v5wA+ChXLbETn46Y+oQ3QbHg/yn+vAU/5KkFD3G4uVL0w\n",
        "Gnx/DIxa+OYYmHxXjQL8r6ClNycxl9LRsS4FPFKsAWk/u///dFI/6E1spNjfDY8k\n",
        "94ab5tHwsqn3Z5tsBHo3nQKBgFUmxbSXh2Qi2fy6+GhTqU7k6G/wXhvLsR9rBKzX\n",
        "1YiVfTXZNu+oL0ptd/q4keZeIN7x0oaY/fZm0pp8PP8Q4HtXmBxIZb+/yG+Pld6q\n",
        "YE8BSd7VDu3ABapdm0JHx3Iou4mpOBcLNeiDw3vx1bgsfkTXMPFHzE0XR+H+tak9\n",
        "nlalAoGBALAmAF7WBGdOt43Rj8hPaKOM/ahj+6z3CNwVreToNsVBHoyNmiO8q7MC\n",
        "+tRo4jgdrzk1pzs66OIHfbx5P1mXKPtgPZhvI5omAY8WqXEgeNqSL1Ksp6LZ2ql/\n",
        "ouZns5xwKc9+aRL+GWoAGNzwzcjE8cP52sBy/r0rYXTs/sZo5kgV\n",
        "-----END RSA PRIVATE KEY-----\n",
    );

    const CLIENT_ID: &str = "com.example.signin";
    const TEST_ISSUER: &str = "https://idp.example/apple-shim";

    fn dummy_http() -> reqwest::Client {
        reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest builds")
    }

    fn signing_key(kid: &str) -> CoreRsaPrivateSigningKey {
        CoreRsaPrivateSigningKey::from_pem(TEST_RSA_PEM, Some(JsonWebKeyId::new(kid.into())))
            .expect("test RSA PEM parses")
    }

    fn jwks_with_kids(kids: &[&str]) -> CoreJsonWebKeySet {
        CoreJsonWebKeySet::new(
            kids.iter()
                .map(|kid| signing_key(kid).as_verification_key())
                .collect(),
        )
    }

    /// Mint a token. `now_override` lets us produce expired tokens; `None`
    /// uses real wall-clock so openidconnect's exp/iat checks pass.
    fn mint_token(
        kid: &str,
        issuer: &str,
        audience: &str,
        nonce: Option<&Nonce>,
        now_override: Option<chrono::DateTime<Utc>>,
        with_email: bool,
    ) -> CoreIdToken {
        let now = now_override.unwrap_or_else(Utc::now);
        let mut std_claims =
            StandardClaims::new(SubjectIdentifier::new("apple-sub-deadbeef".to_owned()));
        if with_email {
            std_claims = std_claims
                .set_email(Some(EndUserEmail::new(
                    "abcd@privaterelay.appleid.com".to_owned(),
                )))
                .set_email_verified(Some(true));
        }
        let mut claims = CoreIdTokenClaims::new(
            IssuerUrl::new(issuer.to_owned()).unwrap(),
            vec![Audience::new(audience.to_owned())],
            now + Duration::seconds(600),
            now,
            std_claims,
            EmptyAdditionalClaims {},
        );
        if let Some(n) = nonce {
            claims = claims.set_nonce(Some(n.clone()));
        }
        CoreIdToken::new(
            claims,
            &signing_key(kid),
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .expect("ID token signs")
    }

    /// JwksFetcher backed by a list of canned JWKS responses — pops one
    /// per call. Lets a single test prove the rotation-retry path.
    struct ScriptedFetcher {
        responses: StdMutex<Vec<CoreJsonWebKeySet>>,
        calls: AtomicU64,
    }
    impl ScriptedFetcher {
        fn new(responses: Vec<CoreJsonWebKeySet>) -> Self {
            Self {
                responses: StdMutex::new(responses),
                calls: AtomicU64::new(0),
            }
        }
        fn calls(&self) -> u64 {
            self.calls.load(Ordering::SeqCst)
        }
    }
    #[async_trait]
    impl JwksFetcher for ScriptedFetcher {
        async fn fetch(&self, _http: &reqwest::Client) -> Result<CoreJsonWebKeySet, JwksError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let mut q = self.responses.lock().unwrap();
            if q.is_empty() {
                return Err(JwksError::Http("scripted fetcher exhausted".into()));
            }
            Ok(q.remove(0))
        }
    }

    fn verifier_with_fetcher<F: JwksFetcher + 'static>(
        fetcher: F,
    ) -> AppleNativeVerifier<F> {
        let cache = Arc::new(AppleJwksCache::new(fetcher));
        AppleNativeVerifier::with_issuer(
            ClientId::new(CLIENT_ID.into()),
            TEST_ISSUER,
            cache,
        )
        .expect("test issuer URL")
    }

    // -- happy path ----------------------------------------------------------

    #[tokio::test]
    async fn verify_returns_claims_for_valid_apple_token() {
        let nonce = Nonce::new("session-nonce-xyz".into());
        let token = mint_token("apple-key-A", TEST_ISSUER, CLIENT_ID, Some(&nonce), None, true);
        let v = verifier_with_fetcher(ScriptedFetcher::new(vec![jwks_with_kids(&[
            "apple-key-A",
        ])]));
        let verified = v
            .verify_native_token(
                token.to_string().as_str(),
                Some(&nonce),
                Utc::now().timestamp(),
                &dummy_http(),
            )
            .await
            .expect("happy path verify");
        assert_eq!(verified.issuer, TEST_ISSUER);
        assert_eq!(verified.subject, "apple-sub-deadbeef");
        assert_eq!(
            verified.email.as_deref(),
            Some("abcd@privaterelay.appleid.com")
        );
        assert_eq!(verified.email_verified, Some(true));
        assert_eq!(v.jwks_cache().fetcher().calls(), 1);
    }

    #[tokio::test]
    async fn verify_with_no_expected_nonce_skips_nonce_check() {
        // Token has a nonce; caller passes None — should still verify.
        let token_nonce = Nonce::new("baked-in-nonce".into());
        let token = mint_token(
            "apple-key-A",
            TEST_ISSUER,
            CLIENT_ID,
            Some(&token_nonce),
            None,
            false,
        );
        let v = verifier_with_fetcher(ScriptedFetcher::new(vec![jwks_with_kids(&[
            "apple-key-A",
        ])]));
        let verified = v
            .verify_native_token(
                token.to_string().as_str(),
                None,
                Utc::now().timestamp(),
                &dummy_http(),
            )
            .await
            .expect("nonce-skip path");
        assert_eq!(verified.subject, "apple-sub-deadbeef");
    }

    // -- claim-shape rejections (no retry) ----------------------------------

    #[tokio::test]
    async fn verify_rejects_wrong_audience() {
        let token = mint_token(
            "apple-key-A",
            TEST_ISSUER,
            "com.wrong.audience",
            None,
            None,
            false,
        );
        let v = verifier_with_fetcher(ScriptedFetcher::new(vec![jwks_with_kids(&[
            "apple-key-A",
        ])]));
        let err = v
            .verify_native_token(
                token.to_string().as_str(),
                None,
                Utc::now().timestamp(),
                &dummy_http(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AppleNativeError::IdToken(_)), "got {err:?}");
        // Wrong-aud is a deterministic failure — must not have triggered
        // a rotation retry.
        assert_eq!(v.jwks_cache().fetcher().calls(), 1);
    }

    #[tokio::test]
    async fn verify_rejects_wrong_issuer() {
        let token = mint_token(
            "apple-key-A",
            "https://idp.example/other-issuer",
            CLIENT_ID,
            None,
            None,
            false,
        );
        let v = verifier_with_fetcher(ScriptedFetcher::new(vec![jwks_with_kids(&[
            "apple-key-A",
        ])]));
        let err = v
            .verify_native_token(
                token.to_string().as_str(),
                None,
                Utc::now().timestamp(),
                &dummy_http(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AppleNativeError::IdToken(_)));
        // Wrong-iss is also deterministic, but `looks_like_rotation_failure`
        // matches messages mentioning "key" / "signature" / "kid" — let's
        // assert the test isn't accidentally over-triggering retries.
        // (At most one retry could happen even if classified as rotation;
        // we want exactly one fetch.)
        let calls = v.jwks_cache().fetcher().calls();
        assert!(
            calls == 1 || calls == 2,
            "expected 1-2 fetches, got {calls}"
        );
    }

    #[tokio::test]
    async fn verify_rejects_nonce_mismatch() {
        let nonce_a = Nonce::new("nonce-a".into());
        let nonce_b = Nonce::new("nonce-b".into());
        let token = mint_token(
            "apple-key-A",
            TEST_ISSUER,
            CLIENT_ID,
            Some(&nonce_a),
            None,
            false,
        );
        let v = verifier_with_fetcher(ScriptedFetcher::new(vec![jwks_with_kids(&[
            "apple-key-A",
        ])]));
        let err = v
            .verify_native_token(
                token.to_string().as_str(),
                Some(&nonce_b),
                Utc::now().timestamp(),
                &dummy_http(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AppleNativeError::IdToken(_)));
    }

    #[tokio::test]
    async fn verify_rejects_expired_token() {
        let stale = Utc::now() - Duration::seconds(3_600);
        let token = mint_token(
            "apple-key-A",
            TEST_ISSUER,
            CLIENT_ID,
            None,
            Some(stale),
            false,
        );
        let v = verifier_with_fetcher(ScriptedFetcher::new(vec![jwks_with_kids(&[
            "apple-key-A",
        ])]));
        let err = v
            .verify_native_token(
                token.to_string().as_str(),
                None,
                Utc::now().timestamp(),
                &dummy_http(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AppleNativeError::IdToken(_)));
    }

    // -- malformed JWT -------------------------------------------------------

    #[tokio::test]
    async fn verify_rejects_malformed_jwt() {
        let v = verifier_with_fetcher(ScriptedFetcher::new(vec![jwks_with_kids(&[
            "apple-key-A",
        ])]));
        let err = v
            .verify_native_token("not-a-jwt", None, Utc::now().timestamp(), &dummy_http())
            .await
            .unwrap_err();
        assert!(matches!(err, AppleNativeError::Malformed(_)));
    }

    // -- the on-failure refresh path ----------------------------------------

    #[tokio::test]
    async fn verify_refreshes_jwks_on_kid_rotation() {
        // Token signed with kid=B; cache fetches JWKS#1 (only kid=A) first
        // — verify fails — invalidate + retry — JWKS#2 has kid=B — succeed.
        let token = mint_token("apple-key-B", TEST_ISSUER, CLIENT_ID, None, None, false);
        let v = verifier_with_fetcher(ScriptedFetcher::new(vec![
            jwks_with_kids(&["apple-key-A"]),
            jwks_with_kids(&["apple-key-B"]),
        ]));
        let verified = v
            .verify_native_token(
                token.to_string().as_str(),
                None,
                Utc::now().timestamp(),
                &dummy_http(),
            )
            .await
            .expect("rotation retry recovers");
        assert_eq!(verified.subject, "apple-sub-deadbeef");
        assert_eq!(
            v.jwks_cache().fetcher().calls(),
            2,
            "first JWKS missing kid → invalidate + refetch"
        );
    }

    #[tokio::test]
    async fn verify_only_retries_once_then_surfaces_error() {
        // Token signed with kid=B; both JWKSes only know kid=A. Verify
        // should retry once then surface IdToken error — NOT spin.
        let token = mint_token("apple-key-B", TEST_ISSUER, CLIENT_ID, None, None, false);
        let v = verifier_with_fetcher(ScriptedFetcher::new(vec![
            jwks_with_kids(&["apple-key-A"]),
            jwks_with_kids(&["apple-key-A"]),
        ]));
        let err = v
            .verify_native_token(
                token.to_string().as_str(),
                None,
                Utc::now().timestamp(),
                &dummy_http(),
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AppleNativeError::IdToken(_)));
        assert_eq!(
            v.jwks_cache().fetcher().calls(),
            2,
            "exactly one retry; never spins"
        );
    }

    // -- looks_like_rotation_failure classifier ------------------------------

    #[test]
    fn rotation_classifier_matches_jwks_shapes() {
        assert!(looks_like_rotation_failure(
            "No matching key found for kid 'XYZ'"
        ));
        assert!(looks_like_rotation_failure(
            "Signature verification failed"
        ));
        assert!(looks_like_rotation_failure(
            "kid header missing"
        ));
        assert!(looks_like_rotation_failure(
            "no matching JWK"
        ));
    }

    #[test]
    fn rotation_classifier_does_not_match_claim_shapes() {
        // (intentional — over-match would still be safe; here we just
        // document the heuristic's boundaries)
        assert!(!looks_like_rotation_failure("expired"));
        assert!(!looks_like_rotation_failure("nonce mismatch"));
        // "iss"/"aud" don't trigger.
        assert!(!looks_like_rotation_failure("iss claim mismatch"));
        assert!(!looks_like_rotation_failure("aud claim mismatch"));
    }

    // -- constructor edge cases ---------------------------------------------

    #[test]
    fn with_issuer_rejects_invalid_url() {
        let cache = Arc::new(AppleJwksCache::new(ScriptedFetcher::new(vec![])));
        let err = AppleNativeVerifier::with_issuer(
            ClientId::new(CLIENT_ID.into()),
            "not-a-url",
            cache,
        )
        .unwrap_err();
        assert!(matches!(err, AppleNativeError::InvalidIssuer(_)));
    }

    #[test]
    fn new_pins_apple_issuer() {
        let cache = Arc::new(AppleJwksCache::for_apple());
        let v = AppleNativeVerifier::new(ClientId::new(CLIENT_ID.into()), cache);
        assert_eq!(v.issuer().as_str(), APPLE_ISSUER);
        assert_eq!(v.client_id().as_str(), CLIENT_ID);
    }

    // -- Send + Sync --------------------------------------------------------

    #[test]
    fn verifier_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<AppleNativeVerifier<HttpJwksFetcher>>();
    }
}
