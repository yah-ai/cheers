//! Google Sign-In as a generic OIDC consumer.
//!
//! [`GoogleProvider`] is a thin newtype over [`OidcProvider`]: same flow
//! lifecycle (`begin` / `finish`), same flow store, same [`VerifiedIdToken`]
//! shape. The newtype only exists to bake in Google's published issuer URL
//! ([`GOOGLE_ISSUER`]) so a caller can't accidentally point Google's branding
//! at a phishing IdP. Everything else is delegated via [`Deref`].
//!
//! # Typical use
//!
//! ```no_run
//! use cheers::providers::google::GoogleProvider;
//! use cheers::providers::oidc_generic::MemoryOidcFlowStore;
//! use openidconnect::{reqwest, ClientId, ClientSecret, RedirectUrl};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let http = reqwest::ClientBuilder::new()
//!     .redirect(reqwest::redirect::Policy::none())
//!     .build()?;
//! let provider = GoogleProvider::discover(
//!     ClientId::new("MY-GOOGLE-CLIENT.apps.googleusercontent.com".into()),
//!     Some(ClientSecret::new("the-secret".into())),
//!     RedirectUrl::new("https://app.example/auth/callback/google".into())?,
//!     MemoryOidcFlowStore::new(),
//!     &http,
//! ).await?;
//!
//! let begin = provider.begin(1_700_000_000).await?;
//! // ...redirect user to `begin.authorize_url`, bind `begin.csrf_state` to the
//! //    session via cookie, etc...
//! # Ok(()) }
//! ```
//!
//! # Gotcha — bind the flow to the calling session
//!
//! [`OidcProvider`]'s flow store is keyed on `csrf_state` alone; cheers has no
//! way to enforce session ↔ flow binding from inside this crate. The calling
//! product must set an `Http-Only`, `SameSite=Lax` cookie at `begin()` carrying
//! the same `csrf_state.secret()` (or store it server-side keyed by session
//! ID) and refuse a callback where the cookie doesn't match. Otherwise an
//! attacker who learns a victim's CSRF state can complete the flow against the
//! victim's account.
//!
//! # Scopes
//!
//! The default scope set is `openid email profile` (see
//! [`oidc_generic::DEFAULT_SCOPES`]) — that's what every consumer Google login
//! needs and what makes Google return `email`, `email_verified`, and `name` in
//! the ID token. Use [`with_scopes`] (proxied via `Deref`) to add scopes like
//! `https://www.googleapis.com/auth/drive.file` for product-specific access.
//!
//! [`with_scopes`]: OidcProvider::with_scopes
//! [`oidc_generic::DEFAULT_SCOPES`]: super::oidc_generic::DEFAULT_SCOPES

use std::ops::Deref;

use openidconnect::core::CoreProviderMetadata;
use openidconnect::reqwest;
use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl};

use super::oidc_generic::{OidcError, OidcProvider};

/// Google's published OIDC issuer. Matches the `iss` claim Google signs into
/// every ID token. Constant so the typo lives in this file, not at every call
/// site.
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";

/// Newtype wrapper around [`OidcProvider`] that bakes in [`GOOGLE_ISSUER`].
///
/// `Deref<Target = OidcProvider<S>>` means every method on the inner provider
/// (`begin`, `finish`, `with_scopes`, `with_flow_ttl_seconds`, `scopes`,
/// `flow_ttl_seconds`, `flows`) is reachable transparently — `GoogleProvider`
/// adds no surface beyond construction.
pub struct GoogleProvider<S>(OidcProvider<S>);

impl<S> GoogleProvider<S> {
    /// Build from a pre-fetched `CoreProviderMetadata` (or a hand-built fixture
    /// for tests). The caller is responsible for the metadata being Google's —
    /// no issuer check beyond what [`OidcProvider`]'s verifier does at `finish`
    /// time (which checks `iss` claim against the metadata `issuer`).
    pub fn from_provider_metadata(
        metadata: CoreProviderMetadata,
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        redirect_uri: RedirectUrl,
        flows: S,
    ) -> Self {
        Self(OidcProvider::from_provider_metadata(
            metadata,
            client_id,
            client_secret,
            redirect_uri,
            flows,
        ))
    }

    /// Discover provider metadata at [`GOOGLE_ISSUER`], then build.
    ///
    /// `http` should be configured to refuse redirects (per `openidconnect`'s
    /// own example) — Google's discovery endpoint doesn't redirect, but a
    /// hostile network can.
    pub async fn discover(
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        redirect_uri: RedirectUrl,
        flows: S,
        http: &reqwest::Client,
    ) -> Result<Self, OidcError> {
        let issuer = IssuerUrl::new(GOOGLE_ISSUER.to_owned())
            .map_err(|e| OidcError::Config(format!("invalid Google issuer URL: {e}")))?;
        Ok(Self(
            OidcProvider::discover(issuer, client_id, client_secret, redirect_uri, flows, http)
                .await?,
        ))
    }

    /// Unwrap to the underlying [`OidcProvider`]. Useful when a caller wants
    /// to hand the inner provider to a function with a generic `OidcProvider`
    /// bound.
    pub fn into_inner(self) -> OidcProvider<S> {
        self.0
    }
}

impl<S> Deref for GoogleProvider<S> {
    type Target = OidcProvider<S>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    //! Wiremock-driven round-trip tests. We stand up a localhost HTTP server
    //! impersonating Google's discovery + JWKS + token endpoints, mint a real
    //! RS256-signed ID token via openidconnect's own signing types, and drive
    //! the full `begin` → `finish` flow end-to-end. The verifier inside
    //! `finish` is the same one Google's tokens hit in production — we're
    //! exercising the actual signature, issuer, audience, and nonce checks.

    use super::*;

    use chrono::{Duration, Utc};
    use openidconnect::core::{
        CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields,
        CoreJsonWebKeySet, CoreJwsSigningAlgorithm, CoreResponseType, CoreRsaPrivateSigningKey,
        CoreSubjectIdentifierType, CoreTokenResponse, CoreTokenType,
    };
    use openidconnect::{
        AccessToken, AuthUrl, Audience, AuthorizationCode, ClientId, ClientSecret,
        EmptyAdditionalClaims, EmptyAdditionalProviderMetadata, EmptyExtraTokenFields,
        EndUserEmail, EndUserName, IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl, LanguageTag,
        LocalizedClaim, Nonce, PrivateSigningKey, RedirectUrl, ResponseTypes, StandardClaims,
        SubjectIdentifier, TokenUrl,
    };
    use openidconnect::reqwest;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::providers::oidc_generic::{MemoryOidcFlowStore, OidcCallback, OidcFlowStore};

    /// PKCS#1 RSA private key shipped with `openidconnect`'s own test fixtures
    /// (`src/core/jwk/tests.rs`). Reusing a published test key keeps these
    /// tests deterministic and self-contained — no PEM file on disk, no
    /// per-run keygen cost.
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
    const TEST_KID: &str = "cheers-test-key";

    const CLIENT_ID: &str = "test-client.apps.googleusercontent.com";
    const CLIENT_SECRET: &str = "test-secret";
    const REDIRECT_URI: &str = "https://app.example/auth/callback/google";

    fn signing_key() -> CoreRsaPrivateSigningKey {
        CoreRsaPrivateSigningKey::from_pem(
            TEST_RSA_PEM,
            Some(JsonWebKeyId::new(TEST_KID.into())),
        )
        .expect("test RSA PEM parses")
    }

    fn dummy_http() -> reqwest::Client {
        reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest builds")
    }

    /// What name shape to bake into the test ID token.
    enum NameClaim {
        /// Single un-locale-tagged entry — `"name": "Alice"` on the wire.
        /// This is what Google actually sends.
        UnTagged(&'static str),
        /// One or more locale-tagged entries with no un-tagged fallback — for
        /// the extract() fallback path that picks the first localized value.
        LocalizedOnly(&'static [(&'static str, &'static str)]),
    }

    fn build_id_token(
        issuer: &str,
        nonce: &Nonce,
        email_verified: bool,
        name: NameClaim,
    ) -> CoreIdToken {
        let now = Utc::now();
        let mut std_claims =
            StandardClaims::new(SubjectIdentifier::new("user-1234567890".to_owned()))
                .set_email(Some(EndUserEmail::new("alice@example.com".to_owned())))
                .set_email_verified(Some(email_verified));

        match name {
            NameClaim::UnTagged(s) => {
                let mut lc: LocalizedClaim<EndUserName> = LocalizedClaim::default();
                lc.insert(None, EndUserName::new(s.to_owned()));
                std_claims = std_claims.set_name(Some(lc));
            }
            NameClaim::LocalizedOnly(entries) => {
                let mut lc: LocalizedClaim<EndUserName> = LocalizedClaim::default();
                for (tag, value) in entries {
                    lc.insert(
                        Some(LanguageTag::new((*tag).to_owned())),
                        EndUserName::new((*value).to_owned()),
                    );
                }
                std_claims = std_claims.set_name(Some(lc));
            }
        }

        let claims = CoreIdTokenClaims::new(
            IssuerUrl::new(issuer.to_owned()).expect("test issuer URL parses"),
            vec![Audience::new(CLIENT_ID.to_owned())],
            now + Duration::seconds(600),
            now,
            std_claims,
            EmptyAdditionalClaims {},
        )
        .set_nonce(Some(nonce.clone()));

        CoreIdToken::new(
            claims,
            &signing_key(),
            CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256,
            None,
            None,
        )
        .expect("ID token signs cleanly")
    }

    /// Mount the static discovery + JWKS endpoints on a fresh wiremock server.
    /// The `/token` endpoint is mounted later by each test once `begin()` has
    /// run — the token response must reference the freshly-minted nonce, so
    /// it can't be precomputed.
    async fn mount_discovery_and_jwks(server: &MockServer, base: &str) {
        let metadata = CoreProviderMetadata::new(
            IssuerUrl::new(base.to_owned()).unwrap(),
            AuthUrl::new(format!("{base}/o/oauth2/auth")).unwrap(),
            JsonWebKeySetUrl::new(format!("{base}/jwks")).unwrap(),
            vec![ResponseTypes::new(vec![CoreResponseType::Code])],
            vec![CoreSubjectIdentifierType::Public],
            vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
            EmptyAdditionalProviderMetadata {},
        )
        .set_token_endpoint(Some(TokenUrl::new(format!("{base}/token")).unwrap()));

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&metadata))
            .mount(server)
            .await;

        let jwks = CoreJsonWebKeySet::new(vec![signing_key().as_verification_key()]);
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(server)
            .await;
    }

    /// Pull the nonce out of the stashed flow without consuming it: take, peek
    /// at the nonce, put back. The store's atomic-take API doesn't expose
    /// peek, so this round-trip is the cleanest way for tests to bind the
    /// minted ID token to the in-flight flow.
    async fn peek_stashed_nonce(
        provider: &GoogleProvider<MemoryOidcFlowStore>,
        csrf_state_secret: &str,
    ) -> Nonce {
        let st = provider
            .flows()
            .take(csrf_state_secret)
            .await
            .expect("store ok")
            .expect("flow stashed");
        let nonce = st.nonce().clone();
        provider
            .flows()
            .put(csrf_state_secret, st)
            .await
            .expect("re-put");
        nonce
    }

    /// Build a `GoogleProvider` pointed at a wiremock IdP. Uses the underlying
    /// `OidcProvider::discover` rather than `GoogleProvider::discover` so the
    /// issuer URL can be the wiremock URL (a real `GoogleProvider::discover`
    /// would target Google and can't be talked to from tests).
    async fn build_provider_via_discovery(
        server: &MockServer,
        http: &reqwest::Client,
    ) -> GoogleProvider<MemoryOidcFlowStore> {
        let issuer = IssuerUrl::new(server.uri()).expect("issuer URL parses");
        let inner = OidcProvider::discover(
            issuer,
            ClientId::new(CLIENT_ID.into()),
            Some(ClientSecret::new(CLIENT_SECRET.into())),
            RedirectUrl::new(REDIRECT_URI.into()).expect("redirect URL parses"),
            MemoryOidcFlowStore::new(),
            http,
        )
        .await
        .expect("discovery succeeds");
        // GoogleProvider is just a newtype — wrap manually after using the
        // wiremock-targeted discover.
        GoogleProvider(inner)
    }

    // -- happy path ----------------------------------------------------------

    async fn mount_token_endpoint(server: &MockServer, id_token: CoreIdToken) {
        let token_response = CoreTokenResponse::new(
            AccessToken::new("test-access-token".to_owned()),
            CoreTokenType::Bearer,
            CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
        );
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&token_response))
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn discover_then_finish_round_trip_extracts_claims() {
        let http = dummy_http();
        let server = MockServer::start().await;
        let base = server.uri();
        mount_discovery_and_jwks(&server, &base).await;

        let provider = build_provider_via_discovery(&server, &http).await;
        let now_seconds = Utc::now().timestamp();
        let begin = provider.begin(now_seconds).await.expect("begin succeeds");

        // Mint the ID token after begin so it can carry the just-stashed
        // nonce. Tests re-put the flow state so finish() finds it.
        let nonce = peek_stashed_nonce(&provider, begin.csrf_state.secret()).await;
        let id_token =
            build_id_token(&base, &nonce, true, NameClaim::UnTagged("Alice Anderson"));
        mount_token_endpoint(&server, id_token).await;

        let verified = provider
            .finish(
                OidcCallback::new(
                    AuthorizationCode::new("auth-code-xyz".into()),
                    begin.csrf_state,
                ),
                &http,
                now_seconds,
            )
            .await
            .expect("finish round-trip");

        assert_eq!(verified.issuer, base);
        assert_eq!(verified.subject, "user-1234567890");
        assert_eq!(verified.email.as_deref(), Some("alice@example.com"));
        assert_eq!(verified.email_verified, Some(true));
        assert_eq!(verified.name.as_deref(), Some("Alice Anderson"));
    }

    #[tokio::test]
    async fn finish_falls_back_to_localized_name_when_untagged_missing() {
        let http = dummy_http();
        let server = MockServer::start().await;
        let base = server.uri();
        mount_discovery_and_jwks(&server, &base).await;

        let provider = build_provider_via_discovery(&server, &http).await;
        let now_seconds = Utc::now().timestamp();
        let begin = provider.begin(now_seconds).await.expect("begin");

        let nonce = peek_stashed_nonce(&provider, begin.csrf_state.secret()).await;
        let id_token = build_id_token(
            &base,
            &nonce,
            false,
            NameClaim::LocalizedOnly(&[("en", "Bob Localized")]),
        );
        mount_token_endpoint(&server, id_token).await;

        let verified = provider
            .finish(
                OidcCallback::new(
                    AuthorizationCode::new("auth-code-2".into()),
                    begin.csrf_state,
                ),
                &http,
                now_seconds,
            )
            .await
            .expect("finish round-trip");

        assert_eq!(verified.email_verified, Some(false));
        assert_eq!(verified.name.as_deref(), Some("Bob Localized"));
    }

    // -- newtype shape -------------------------------------------------------

    #[test]
    fn google_issuer_constant_is_the_canonical_url() {
        assert_eq!(GOOGLE_ISSUER, "https://accounts.google.com");
        // Sanity: the constant parses as an IssuerUrl.
        let _ = IssuerUrl::new(GOOGLE_ISSUER.to_owned())
            .expect("Google issuer URL parses");
    }

    #[tokio::test]
    async fn from_provider_metadata_derefs_to_oidc_provider() {
        // Hand-rolled minimal metadata — same shape oidc_generic.rs uses.
        const FIXTURE: &str = r#"{
            "issuer": "https://accounts.google.com",
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/auth",
            "token_endpoint": "https://accounts.google.com/o/oauth2/token",
            "jwks_uri": "https://accounts.google.com/o/oauth2/jwks",
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"]
        }"#;
        let metadata: CoreProviderMetadata =
            serde_json::from_str(FIXTURE).expect("fixture parses");

        let provider = GoogleProvider::from_provider_metadata(
            metadata,
            ClientId::new(CLIENT_ID.into()),
            Some(ClientSecret::new(CLIENT_SECRET.into())),
            RedirectUrl::new(REDIRECT_URI.into()).unwrap(),
            MemoryOidcFlowStore::new(),
        );
        // Deref-reached: begin() works straight through.
        let begin = provider.begin(1_000).await.expect("begin");
        assert_eq!(
            begin.authorize_url.host_str(),
            Some("accounts.google.com"),
            "Google-baked authorization endpoint should still drive the begin URL"
        );
        // and into_inner returns the wrapped OidcProvider.
        let inner = provider.into_inner();
        assert_eq!(inner.flow_ttl_seconds(), 300);
    }
}
