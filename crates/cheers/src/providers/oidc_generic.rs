//! Generic OIDC Authorization Code + PKCE consumer.
//!
//! Wraps `openidconnect::core::CoreClient` with the bookkeeping a safe OIDC
//! login needs:
//!
//! - A **PKCE** `code_verifier` (SHA-256 challenge) so the authorization code
//!   can't be redeemed by anyone but the originating user-agent.
//! - A **CSRF state** binding the redirect-out to the callback-in.
//! - A **nonce** carried into the `id_token` so a replayed ID token can't
//!   re-authenticate a different session.
//!
//! All three live in [`OidcFlowState`], stashed by [`OidcProvider::begin`] in
//! an [`OidcFlowStore`] keyed on the CSRF state, and atomically taken (one
//! shot) by [`OidcProvider::finish`].
//!
//! # Gotcha — bind the flow to the calling session
//!
//! cheers stores the flow by its CSRF token, but the caller is responsible
//! for binding *which session* opened a given flow. The standard pattern is
//! to set an `Http-Only`, `SameSite=Lax` cookie at `begin()` carrying the
//! same `csrf_state.secret()` and require it to match on the callback —
//! otherwise an attacker who learns a victim's CSRF state (e.g. by reading
//! a phishing page) can finish the flow against the victim's account.
//!
//! # Example
//!
//! ```no_run
//! use cheers::providers::oidc_generic::{
//!     MemoryOidcFlowStore, OidcCallback, OidcProvider,
//! };
//! use openidconnect::core::CoreProviderMetadata;
//! use openidconnect::reqwest;
//! use openidconnect::{
//!     AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, RedirectUrl,
//! };
//!
//! # async fn run(metadata: CoreProviderMetadata) -> Result<(), Box<dyn std::error::Error>> {
//! let provider = OidcProvider::from_provider_metadata(
//!     metadata,
//!     ClientId::new("my-client".into()),
//!     Some(ClientSecret::new("my-secret".into())),
//!     RedirectUrl::new("https://app.example/oauth/callback".into())?,
//!     MemoryOidcFlowStore::new(),
//! );
//!
//! // 1. Redirect the user out:
//! let begin = provider.begin(1_700_000_000).await?;
//! // ...redirect to begin.authorize_url...
//!
//! // 2. Callback comes back with `?state=...&code=...`:
//! let http = reqwest::ClientBuilder::new()
//!     .redirect(reqwest::redirect::Policy::none())
//!     .build()?;
//! let verified = provider
//!     .finish(
//!         OidcCallback::new(
//!             AuthorizationCode::new("the-code-from-the-callback".into()),
//!             begin.csrf_state.clone(),
//!         ),
//!         &http,
//!         1_700_000_030,
//!     )
//!     .await?;
//! assert!(verified.subject.is_empty() || !verified.subject.is_empty()); // documented surface
//! # Ok(()) }
//! ```

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreIdTokenClaims, CoreProviderMetadata,
};
use openidconnect::reqwest;
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope,
    TokenResponse,
};

/// Recommended TTL for the begin→finish window. Five minutes covers normal
/// IdP UI latency without leaving abandoned flows around forever.
pub const DEFAULT_FLOW_TTL_SECONDS: i64 = 5 * 60;

/// Default scope set requested by [`OidcProvider`] — the OIDC baseline plus
/// the two most commonly-useful profile claims.
pub const DEFAULT_SCOPES: &[&str] = &["openid", "email", "profile"];

/// Concrete typestate of the `CoreClient` we hold.
///
/// `from_provider_metadata` returns a client with `HasAuthUrl = EndpointSet`
/// (discovery always carries `authorization_endpoint`) and
/// `HasTokenUrl = EndpointMaybeSet` (discovery *may* carry `token_endpoint`).
/// Both `authorize_url` and `exchange_code` are valid for that typestate.
type Client = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors surfaced by the OIDC consumer flow.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OidcError {
    /// `CoreProviderMetadata::discover_async` failed (network, parse, …).
    #[error("oidc discovery: {0}")]
    Discovery(String),
    /// The `openidconnect` client refused the request shape (e.g. missing
    /// token endpoint). Indicates a misconfigured provider metadata.
    #[error("oidc config: {0}")]
    Config(String),
    /// Code-exchange HTTP / transport failure.
    #[error("oidc http: {0}")]
    Http(String),
    /// The flow keyed on the inbound `state` was not in the store. Either
    /// already consumed (replay) or fabricated.
    #[error("unknown or already-consumed oidc flow")]
    UnknownFlow,
    /// Flow was in the store but exceeded `flow_ttl_seconds`.
    #[error("oidc flow expired")]
    FlowExpired,
    /// `state` in the stored flow doesn't match the callback (defense in
    /// depth — `take` keys on the secret so this shouldn't normally fire).
    #[error("oidc csrf state mismatch")]
    StateMismatch,
    /// Server didn't return an `id_token` in the token response — a generic
    /// OAuth 2.0 server may answer the token endpoint without OIDC claims.
    #[error("token response carried no id_token")]
    MissingIdToken,
    /// `id_token` failed verification (signature, nonce, audience, expiry).
    #[error("id token verification: {0}")]
    IdToken(String),
    /// Underlying `OidcFlowStore` backend failed.
    #[error("oidc flow store: {0}")]
    Store(String),
}

// ---------------------------------------------------------------------------
// Verified payload
// ---------------------------------------------------------------------------

/// What [`OidcProvider::finish`] returns on success — the subset of
/// `id_token` claims cheers consumes.
///
/// The full set is available via the underlying `openidconnect` types if a
/// caller needs it; cheers normalizes to the fields it'll map into a
/// `cheers_core::User` + `ProviderKey::OidcGeneric { issuer }`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedIdToken {
    /// The `iss` claim — fed into `ProviderKey::OidcGeneric { issuer }` so
    /// two providers can't collide on `sub`.
    pub issuer: String,
    /// The `sub` claim — stable identifier within `issuer`.
    pub subject: String,
    /// `email` claim if present. Not guaranteed by spec; Google + Apple
    /// include it when the corresponding scope is granted.
    pub email: Option<String>,
    /// `email_verified` claim. Treat `None` as unverified.
    pub email_verified: Option<bool>,
    /// `name` claim (the un-locale-tagged form, with the first localized
    /// entry as a fallback).
    pub name: Option<String>,
}

// ---------------------------------------------------------------------------
// FlowState + Store + memory impl
// ---------------------------------------------------------------------------

/// Server-side state for one in-flight flow — stashed between `begin()` and
/// `finish()` by an [`OidcFlowStore`] impl.
///
/// All three fields are secrets:
/// - `csrf_token` is matched against the callback's `?state=` query param.
/// - `nonce` is matched against the verified `id_token`'s `nonce` claim.
/// - `pkce_verifier` is sent to the token endpoint to prove this user-agent
///   is the one that started the flow.
pub struct OidcFlowState {
    csrf_token: CsrfToken,
    nonce: Nonce,
    pkce_verifier: PkceCodeVerifier,
    expires_at: i64,
}

impl OidcFlowState {
    /// Construct from already-minted secrets + an absolute expiry.
    ///
    /// The cheers-built [`OidcProvider::begin`] path doesn't need this — it
    /// owns the freshly-minted PKCE verifier / CSRF state / nonce already.
    /// Use this constructor when (a) hydrating an [`OidcFlowStore`] entry
    /// from an out-of-process backend (Redis/Postgres) on `finish`, or
    /// (b) a provider that wraps cheers's flow types (e.g.
    /// `apple::redirect::AppleRedirectProvider`) re-implements `begin`
    /// because it needs Apple-specific authorization-URL extras.
    pub fn from_parts(
        csrf_token: CsrfToken,
        nonce: Nonce,
        pkce_verifier: PkceCodeVerifier,
        expires_at: i64,
    ) -> Self {
        Self {
            csrf_token,
            nonce,
            pkce_verifier,
            expires_at,
        }
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    pub fn is_expired_at(&self, now: i64) -> bool {
        self.expires_at <= now
    }

    /// Borrow the stashed CSRF token. A custom [`OidcFlowStore`] impl can use
    /// this to bind the flow to a session/cookie before persisting.
    pub fn csrf_token(&self) -> &CsrfToken {
        &self.csrf_token
    }

    /// Borrow the stashed nonce. Same caveat as [`csrf_token`](Self::csrf_token):
    /// only expose to trusted storage; the `Debug` impl redacts it.
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Borrow the stashed PKCE verifier. Treated as a secret — never log.
    pub fn pkce_verifier(&self) -> &PkceCodeVerifier {
        &self.pkce_verifier
    }

    /// Consume the state and return its parts.
    ///
    /// `openidconnect`'s `PkceCodeVerifier` deliberately does not implement
    /// `Clone` — it's a one-shot secret — so any provider that re-implements
    /// `finish` (e.g. [`apple::redirect`](super::apple::redirect) so it can
    /// rebuild the `CoreClient` with a freshly-minted `client_secret` JWT)
    /// needs ownership of the verifier rather than a borrow.
    pub fn into_parts(self) -> (CsrfToken, Nonce, PkceCodeVerifier, i64) {
        (
            self.csrf_token,
            self.nonce,
            self.pkce_verifier,
            self.expires_at,
        )
    }
}

impl std::fmt::Debug for OidcFlowState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Secrets stay opaque so accidental logs don't leak the verifier /
        // nonce / state.
        f.debug_struct("OidcFlowState")
            .field("csrf_token", &"<redacted>")
            .field("nonce", &"<redacted>")
            .field("pkce_verifier", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Single-use storage for in-flight flows. Keyed by `csrf_state.secret()`.
///
/// `put` writes a fresh flow; `take` atomically reads-and-removes so a
/// replay of the same callback URL gets `UnknownFlow`. Implementors should
/// hold each entry until at least `state.expires_at()` so a still-live flow
/// can complete; expired entries can be GC'd.
///
/// `Err(_)` is reserved for backend failure, not "not found".
#[async_trait]
pub trait OidcFlowStore: Send + Sync {
    async fn put(&self, id: &str, state: OidcFlowState) -> Result<(), String>;

    /// Atomically take + remove the flow keyed by `id`. `Ok(None)` for an
    /// unknown or already-consumed flow.
    async fn take(&self, id: &str) -> Result<Option<OidcFlowState>, String>;
}

/// In-process [`OidcFlowStore`] backed by a `Mutex<HashMap>`. For tests, dev,
/// and single-replica deployments. Multi-replica production wants a shared
/// backend (Redis, Postgres, …) so a redirect issued by node A can be
/// finished on node B.
#[derive(Default)]
pub struct MemoryOidcFlowStore {
    inner: Mutex<HashMap<String, OidcFlowState>>,
}

impl MemoryOidcFlowStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop entries whose `expires_at <= now`. Caller-driven (no background
    /// timer) — wire on a tick if accumulating expired flows matters.
    pub fn gc(&self, now: i64) {
        self.inner
            .lock()
            .unwrap()
            .retain(|_, s| s.expires_at > now);
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().is_empty()
    }
}

#[async_trait]
impl OidcFlowStore for MemoryOidcFlowStore {
    async fn put(&self, id: &str, state: OidcFlowState) -> Result<(), String> {
        self.inner.lock().unwrap().insert(id.to_owned(), state);
        Ok(())
    }

    async fn take(&self, id: &str) -> Result<Option<OidcFlowState>, String> {
        Ok(self.inner.lock().unwrap().remove(id))
    }
}

// ---------------------------------------------------------------------------
// Begin / Callback types
// ---------------------------------------------------------------------------

/// Output of [`OidcProvider::begin`] — hand `authorize_url` off to the
/// browser. `csrf_state.secret()` is what the OIDC server will echo back as
/// `?state=` on the callback; callers also bind it to a cookie (see the
/// module gotcha) so a stolen state alone can't drive the flow.
#[derive(Debug)]
#[non_exhaustive]
pub struct OidcBegin {
    pub authorize_url: openidconnect::url::Url,
    pub csrf_state: CsrfToken,
}

/// Parameters the OIDC server sent back to the callback URL.
#[derive(Debug)]
#[non_exhaustive]
pub struct OidcCallback {
    pub code: AuthorizationCode,
    pub state: CsrfToken,
}

impl OidcCallback {
    pub fn new(code: AuthorizationCode, state: CsrfToken) -> Self {
        Self { code, state }
    }
}

// ---------------------------------------------------------------------------
// OidcProvider
// ---------------------------------------------------------------------------

/// Generic OIDC consumer — wraps an `openidconnect::CoreClient` configured
/// against one `(issuer, client_id, redirect_uri)` triple, plus the
/// requested scopes and a flow store.
///
/// Concrete providers (`GoogleProvider` in R012-T2, `AppleRedirectProvider`
/// in R013-T2, generic enterprise SSO) are newtypes around this one.
pub struct OidcProvider<S> {
    client: Client,
    scopes: Vec<Scope>,
    flow_ttl_seconds: i64,
    flows: S,
}

impl<S> OidcProvider<S> {
    /// Build from a pre-fetched `CoreProviderMetadata`. Use this when you
    /// already hold the metadata (e.g. cached at process boot) or when
    /// testing with a hand-built metadata fixture.
    pub fn from_provider_metadata(
        metadata: CoreProviderMetadata,
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        redirect_uri: RedirectUrl,
        flows: S,
    ) -> Self {
        let client = CoreClient::from_provider_metadata(metadata, client_id, client_secret)
            .set_redirect_uri(redirect_uri);
        Self {
            client,
            scopes: DEFAULT_SCOPES
                .iter()
                .map(|s| Scope::new((*s).to_owned()))
                .collect(),
            flow_ttl_seconds: DEFAULT_FLOW_TTL_SECONDS,
            flows,
        }
    }

    /// Fetch provider metadata at `issuer` over `http`, then build.
    ///
    /// `http` should be configured to refuse redirects — following them
    /// opens the consumer up to SSRF when the issuer URL is attacker-chosen
    /// (per `openidconnect`'s own example).
    pub async fn discover(
        issuer: IssuerUrl,
        client_id: ClientId,
        client_secret: Option<ClientSecret>,
        redirect_uri: RedirectUrl,
        flows: S,
        http: &reqwest::Client,
    ) -> Result<Self, OidcError> {
        let metadata = CoreProviderMetadata::discover_async(issuer, http)
            .await
            .map_err(|e| OidcError::Discovery(format!("{e}")))?;
        Ok(Self::from_provider_metadata(
            metadata,
            client_id,
            client_secret,
            redirect_uri,
            flows,
        ))
    }

    /// Replace the requested scopes. Default is [`DEFAULT_SCOPES`]
    /// (`openid`, `email`, `profile`).
    pub fn with_scopes<I, V>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = V>,
        V: Into<String>,
    {
        self.scopes = scopes.into_iter().map(|s| Scope::new(s.into())).collect();
        self
    }

    /// Override the begin→finish window. Default is
    /// [`DEFAULT_FLOW_TTL_SECONDS`] (5 minutes).
    pub fn with_flow_ttl_seconds(mut self, ttl: i64) -> Self {
        self.flow_ttl_seconds = ttl;
        self
    }

    pub fn scopes(&self) -> &[Scope] {
        &self.scopes
    }

    pub fn flow_ttl_seconds(&self) -> i64 {
        self.flow_ttl_seconds
    }

    pub fn flows(&self) -> &S {
        &self.flows
    }
}

impl<S: OidcFlowStore> OidcProvider<S> {
    /// Start a fresh login flow. Mints PKCE + CSRF state + nonce, builds the
    /// authorization URL, stashes the flow state keyed by
    /// `csrf_state.secret()`, returns the URL to redirect to.
    pub async fn begin(&self, now: i64) -> Result<OidcBegin, OidcError> {
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut req = self.client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for scope in &self.scopes {
            req = req.add_scope(scope.clone());
        }
        let (authorize_url, csrf_state, nonce) = req.set_pkce_challenge(pkce_challenge).url();

        let flow_state = OidcFlowState {
            csrf_token: csrf_state.clone(),
            nonce,
            pkce_verifier,
            expires_at: now.saturating_add(self.flow_ttl_seconds),
        };
        let id = csrf_state.secret().to_owned();
        self.flows
            .put(&id, flow_state)
            .await
            .map_err(OidcError::Store)?;
        Ok(OidcBegin {
            authorize_url,
            csrf_state,
        })
    }

    /// Finish a flow. Atomically takes the stashed [`OidcFlowState`] keyed
    /// on `callback.state.secret()`, exchanges the code at the token
    /// endpoint with the PKCE verifier, verifies the returned `id_token`
    /// against the stashed nonce, and returns the normalized claims.
    pub async fn finish(
        &self,
        callback: OidcCallback,
        http: &reqwest::Client,
        now: i64,
    ) -> Result<VerifiedIdToken, OidcError> {
        let flow_state = self
            .flows
            .take(callback.state.secret())
            .await
            .map_err(OidcError::Store)?
            .ok_or(OidcError::UnknownFlow)?;

        // Take is keyed on the same secret string so this *should* always
        // match, but the explicit recheck guards against a buggy store impl
        // that returned an entry under the wrong key.
        if flow_state.csrf_token.secret() != callback.state.secret() {
            return Err(OidcError::StateMismatch);
        }
        if flow_state.is_expired_at(now) {
            return Err(OidcError::FlowExpired);
        }

        let token_response = self
            .client
            .exchange_code(callback.code)
            .map_err(|e| OidcError::Config(format!("{e}")))?
            .set_pkce_verifier(flow_state.pkce_verifier)
            .request_async(http)
            .await
            .map_err(|e| OidcError::Http(format!("{e}")))?;

        let id_token = token_response.id_token().ok_or(OidcError::MissingIdToken)?;
        let verifier = self.client.id_token_verifier();
        let claims: &CoreIdTokenClaims = id_token
            .claims(&verifier, &flow_state.nonce)
            .map_err(|e| OidcError::IdToken(format!("{e}")))?;
        Ok(extract(claims))
    }
}

fn extract(c: &CoreIdTokenClaims) -> VerifiedIdToken {
    let name = c
        .name()
        .and_then(|n| n.get(None).or_else(|| n.iter().next().map(|(_, v)| v)))
        .map(|v| v.as_str().to_owned());
    VerifiedIdToken {
        issuer: c.issuer().as_str().to_owned(),
        subject: c.subject().as_str().to_owned(),
        email: c.email().map(|e| e.as_str().to_owned()),
        email_verified: c.email_verified(),
        name,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use openidconnect::url::Url;

    /// Hand-rolled discovery JSON — a minimal but real OIDC metadata blob.
    /// Sufficient to drive `from_provider_metadata` + `authorize_url`; the
    /// `jwks_uri` is only fetched by `id_token.claims(...)` (P5 T2's wiremock
    /// territory), so it can be a syntactically-valid URL with no live JWKS.
    const FIXTURE_METADATA: &str = r#"{
        "issuer": "https://idp.example",
        "authorization_endpoint": "https://idp.example/o/oauth2/auth",
        "token_endpoint": "https://idp.example/o/oauth2/token",
        "jwks_uri": "https://idp.example/o/oauth2/jwks",
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"]
    }"#;

    fn metadata() -> CoreProviderMetadata {
        serde_json::from_str(FIXTURE_METADATA).expect("fixture parses as CoreProviderMetadata")
    }

    fn provider() -> OidcProvider<MemoryOidcFlowStore> {
        OidcProvider::from_provider_metadata(
            metadata(),
            ClientId::new("test-client".into()),
            Some(ClientSecret::new("test-secret".into())),
            RedirectUrl::new("https://app.example/oauth/callback".into()).unwrap(),
            MemoryOidcFlowStore::new(),
        )
    }

    fn query_pairs(u: &Url) -> Vec<(String, String)> {
        u.query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    fn first(qs: &[(String, String)], k: &str) -> Option<String> {
        qs.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone())
    }

    // -- flow store ---------------------------------------------------------

    #[tokio::test]
    async fn memory_store_put_then_take_is_single_use() {
        let s = MemoryOidcFlowStore::new();
        let st = OidcFlowState {
            csrf_token: CsrfToken::new("STATE".into()),
            nonce: Nonce::new("NONCE".into()),
            pkce_verifier: PkceCodeVerifier::new("VERIFIER".repeat(8)),
            expires_at: 1_000,
        };
        s.put("k", st).await.unwrap();
        assert_eq!(s.len(), 1);
        let taken = s.take("k").await.unwrap().expect("entry");
        assert_eq!(taken.csrf_token.secret(), "STATE");
        // Second take returns None — single-use.
        assert!(s.take("k").await.unwrap().is_none());
        assert!(s.is_empty());
    }

    #[tokio::test]
    async fn memory_store_take_missing_returns_none() {
        let s = MemoryOidcFlowStore::new();
        assert!(s.take("nope").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn memory_store_gc_drops_expired_entries() {
        let s = MemoryOidcFlowStore::new();
        s.put(
            "a",
            OidcFlowState {
                csrf_token: CsrfToken::new("a".into()),
                nonce: Nonce::new("n".into()),
                pkce_verifier: PkceCodeVerifier::new("v".repeat(64)),
                expires_at: 100,
            },
        )
        .await
        .unwrap();
        s.put(
            "b",
            OidcFlowState {
                csrf_token: CsrfToken::new("b".into()),
                nonce: Nonce::new("n".into()),
                pkce_verifier: PkceCodeVerifier::new("v".repeat(64)),
                expires_at: 500,
            },
        )
        .await
        .unwrap();
        assert_eq!(s.len(), 2);
        s.gc(200);
        assert_eq!(s.len(), 1);
        assert!(s.take("a").await.unwrap().is_none());
        assert!(s.take("b").await.unwrap().is_some());
    }

    // -- provider construction / config --------------------------------------

    #[test]
    fn from_provider_metadata_seeds_default_scopes_and_ttl() {
        let p = provider();
        let scope_strs: Vec<&str> = p.scopes().iter().map(|s| s.as_str()).collect();
        assert_eq!(scope_strs, DEFAULT_SCOPES);
        assert_eq!(p.flow_ttl_seconds(), DEFAULT_FLOW_TTL_SECONDS);
    }

    #[test]
    fn with_scopes_replaces_the_set() {
        let p = provider().with_scopes(["openid", "email"]);
        let scope_strs: Vec<&str> = p.scopes().iter().map(|s| s.as_str()).collect();
        assert_eq!(scope_strs, ["openid", "email"]);
    }

    #[test]
    fn with_flow_ttl_overrides_default() {
        let p = provider().with_flow_ttl_seconds(60);
        assert_eq!(p.flow_ttl_seconds(), 60);
    }

    // -- begin() URL shape ---------------------------------------------------

    #[tokio::test]
    async fn begin_url_has_oidc_params_pinned() {
        let p = provider();
        let begin = p.begin(1_000).await.unwrap();
        let u = &begin.authorize_url;

        assert_eq!(u.scheme(), "https");
        assert_eq!(u.host_str(), Some("idp.example"));
        assert_eq!(u.path(), "/o/oauth2/auth");

        let qs = query_pairs(u);
        assert_eq!(first(&qs, "response_type").as_deref(), Some("code"));
        assert_eq!(first(&qs, "client_id").as_deref(), Some("test-client"));
        assert_eq!(
            first(&qs, "redirect_uri").as_deref(),
            Some("https://app.example/oauth/callback")
        );
        let scope = first(&qs, "scope").unwrap();
        for s in DEFAULT_SCOPES {
            assert!(scope.split(' ').any(|x| x == *s), "missing scope {s}");
        }
        assert_eq!(first(&qs, "code_challenge_method").as_deref(), Some("S256"));
        assert!(
            !first(&qs, "code_challenge").unwrap_or_default().is_empty(),
            "PKCE challenge missing"
        );
        assert!(
            !first(&qs, "state").unwrap_or_default().is_empty(),
            "csrf state missing"
        );
        assert!(
            !first(&qs, "nonce").unwrap_or_default().is_empty(),
            "nonce missing"
        );

        // The csrf_state returned matches `?state=` in the URL exactly.
        assert_eq!(first(&qs, "state").as_deref(), Some(begin.csrf_state.secret().as_str()));
    }

    #[tokio::test]
    async fn begin_stashes_flow_state_keyed_by_csrf_secret() {
        let p = provider();
        let begin = p.begin(1_000).await.unwrap();
        assert_eq!(p.flows().len(), 1);
        // Stashed entry keyed by the csrf secret.
        let taken = p
            .flows()
            .take(begin.csrf_state.secret())
            .await
            .unwrap()
            .expect("stashed");
        assert_eq!(taken.csrf_token.secret(), begin.csrf_state.secret());
        assert_eq!(taken.expires_at(), 1_000 + DEFAULT_FLOW_TTL_SECONDS);
    }

    #[tokio::test]
    async fn begin_generates_unique_state_per_call() {
        let p = provider();
        let a = p.begin(1_000).await.unwrap();
        let b = p.begin(1_000).await.unwrap();
        assert_ne!(a.csrf_state.secret(), b.csrf_state.secret());
        assert_eq!(p.flows().len(), 2);
    }

    #[tokio::test]
    async fn begin_respects_custom_scopes() {
        let p = provider().with_scopes(["openid", "profile"]);
        let begin = p.begin(1_000).await.unwrap();
        let qs = query_pairs(&begin.authorize_url);
        let scope = first(&qs, "scope").unwrap();
        let parts: Vec<&str> = scope.split(' ').collect();
        assert!(parts.contains(&"openid"));
        assert!(parts.contains(&"profile"));
        assert!(!parts.contains(&"email"));
    }

    // -- finish() unhappy paths (HTTP-free) ---------------------------------

    fn dummy_http() -> reqwest::Client {
        reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client builds")
    }

    #[tokio::test]
    async fn finish_with_unknown_state_returns_unknown_flow() {
        let p = provider();
        let err = p
            .finish(
                OidcCallback::new(
                    AuthorizationCode::new("CODE".into()),
                    CsrfToken::new("never-stashed".into()),
                ),
                &dummy_http(),
                1_000,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::UnknownFlow), "got {err:?}");
    }

    #[tokio::test]
    async fn finish_consumes_flow_on_first_call_replay_is_unknown() {
        // First call exchanges the flow — it'll fail at the HTTP step
        // (idp.example has no token endpoint) but the flow entry has been
        // taken. A second call with the same state returns UnknownFlow.
        let p = provider();
        let begin = p.begin(1_000).await.unwrap();
        let state = begin.csrf_state.clone();
        let cb = || {
            OidcCallback::new(
                AuthorizationCode::new("CODE".into()),
                state.clone(),
            )
        };
        let first = p.finish(cb(), &dummy_http(), 1_000).await.unwrap_err();
        assert!(
            matches!(first, OidcError::Http(_)),
            "expected Http error, got {first:?}"
        );
        let second = p.finish(cb(), &dummy_http(), 1_000).await.unwrap_err();
        assert!(
            matches!(second, OidcError::UnknownFlow),
            "expected UnknownFlow on replay, got {second:?}"
        );
    }

    #[tokio::test]
    async fn finish_with_expired_flow_returns_flow_expired() {
        let p = provider().with_flow_ttl_seconds(60);
        let begin = p.begin(1_000).await.unwrap();
        let err = p
            .finish(
                OidcCallback::new(AuthorizationCode::new("CODE".into()), begin.csrf_state),
                &dummy_http(),
                1_000 + 60, // == expires_at → expired by `<=` check
            )
            .await
            .unwrap_err();
        assert!(matches!(err, OidcError::FlowExpired), "got {err:?}");
    }

    #[tokio::test]
    async fn flow_state_debug_redacts_secrets() {
        let st = OidcFlowState {
            csrf_token: CsrfToken::new("SUPER-SECRET-STATE".into()),
            nonce: Nonce::new("SUPER-SECRET-NONCE".into()),
            pkce_verifier: PkceCodeVerifier::new("v".repeat(64)),
            expires_at: 100,
        };
        let dbg = format!("{st:?}");
        assert!(!dbg.contains("SUPER-SECRET-STATE"));
        assert!(!dbg.contains("SUPER-SECRET-NONCE"));
        assert!(dbg.contains("expires_at: 100"));
    }

    // -- VerifiedIdToken normalization --------------------------------------

    #[test]
    fn verified_id_token_round_trips_through_eq() {
        let v1 = VerifiedIdToken {
            issuer: "https://idp".into(),
            subject: "u-1".into(),
            email: Some("a@b.co".into()),
            email_verified: Some(true),
            name: Some("Alice".into()),
        };
        let v2 = v1.clone();
        assert_eq!(v1, v2);
    }
}
