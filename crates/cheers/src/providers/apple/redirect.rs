//! Apple Sign In — `response_mode=form_post` redirect flow with one-shot
//! first-login name capture.
//!
//! Apple is the OIDC provider where every shape deviates from spec just
//! enough to be load-bearing:
//!
//! 1. **Form-post response mode.** When `scope=name` is requested, Apple
//!    returns the authorization code by POSTing an
//!    `application/x-www-form-urlencoded` body to the redirect URI instead
//!    of using the GET-with-query-params shape the rest of OIDC uses. The
//!    `user` JSON Apple appends to the form would otherwise show up in
//!    browser URL bars and proxy logs.
//! 2. **One-shot user name.** The `user` form field carries the user's
//!    real name (`firstName` + `lastName`) and email **only on the first
//!    auth response** after they grant consent. Apple does not send it
//!    again on subsequent logins. **Persist on first sight.** If you drop
//!    this value, it is gone unless the user revokes the app entirely and
//!    re-authorizes — and even then only under specific conditions.
//!    [`FirstLoginName`] makes this contract explicit.
//! 3. **ES256 `client_secret`.** Apple's `client_secret` is a self-signed
//!    JWT minted from the developer's `.p8` private key — see
//!    [`super::client_secret`]. [`AppleRedirectProvider`] holds an
//!    `Arc<AppleClientSecret>` and rebuilds the `openidconnect::CoreClient`
//!    with a freshly-minted JWT each `finish_form_post` so a long-running
//!    process never serves a stale secret.
//! 4. **Pairwise `sub`.** Apple's `sub` is a per-Team-ID opaque identifier,
//!    not an email address. Treat as opaque; map to a user via your
//!    `UserStore` keyed on `(ProviderKey::OidcApple, sub)`.
//! 5. **Private relay email.** When the user opts to hide their email,
//!    Apple's `email` claim is `…@privaterelay.appleid.com`. Apple
//!    forwards mail to the user's real address; treat the relay address
//!    as their email of record.
//!
//! # Hand-built provider metadata
//!
//! Apple's `https://appleid.apple.com/.well-known/openid-configuration`
//! has historically drifted in and out of strict OIDC spec compliance.
//! [`apple_provider_metadata`] returns a [`CoreProviderMetadata`] pinned
//! to Apple's documented endpoints — use it when you don't want a network
//! hop at process boot, or when discovery is failing.
//!
//! # Caller-side responsibilities
//!
//! - **Session ↔ flow binding.** Same gotcha as the generic OIDC consumer
//!   (see [`super::super::oidc_generic`]): bind `begin().csrf_state` to
//!   an `Http-Only`, `SameSite=None` cookie at `begin()` and require it to
//!   match on the callback. (Apple specifically requires `SameSite=None`
//!   on the bound cookie because the form-post callback is a cross-site
//!   POST — `SameSite=Lax` cookies are *not* sent.)
//! - **Invalidate on token failure.** On a `4xx` from Apple's `/auth/token`
//!   (most often `invalid_client` when the cached JWT is stale relative to
//!   a developer-console key rotation), call
//!   [`AppleRedirectProvider::invalidate_client_secret`] before retrying.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use cheers::providers::apple::{
//!     apple_provider_metadata, AppleClientSecret, AppleCallbackForm,
//!     AppleRedirectProvider,
//! };
//! use cheers::providers::oidc_generic::MemoryOidcFlowStore;
//! use openidconnect::{reqwest, ClientId, RedirectUrl};
//!
//! # async fn run(p8_pem: &[u8], form_body: &str) -> Result<(), Box<dyn std::error::Error>> {
//! let http = reqwest::ClientBuilder::new()
//!     .redirect(reqwest::redirect::Policy::none())
//!     .build()?;
//! let secret = Arc::new(AppleClientSecret::from_p8_pem(
//!     "TEAM123ABC", "KEYID45678", "com.example.signin", p8_pem,
//! )?);
//! let provider = AppleRedirectProvider::from_provider_metadata(
//!     apple_provider_metadata(),
//!     ClientId::new("com.example.signin".into()),
//!     RedirectUrl::new("https://app.example/auth/callback/apple".into())?,
//!     secret,
//!     MemoryOidcFlowStore::new(),
//! );
//!
//! let now = 1_700_000_000;
//! let begin = provider.begin(now).await?;
//! // …redirect user to begin.authorize_url and bind begin.csrf_state to a cookie…
//!
//! // Later, Apple POSTs a form-urlencoded body to the redirect URI:
//! let form = AppleCallbackForm::parse(form_body)?;
//! let verified = provider.finish_form_post(form, &http, now + 30).await?;
//! if let Some(name) = verified.first_login.as_str() {
//!     // Persist this — Apple won't send it again.
//!     println!("welcome, {name}");
//! }
//! # Ok(()) }
//! ```

use std::sync::Arc;

use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreIdTokenClaims, CoreJwsSigningAlgorithm,
    CoreProviderMetadata, CoreResponseType, CoreSubjectIdentifierType,
};
use openidconnect::reqwest;
use openidconnect::url::form_urlencoded;
use openidconnect::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EmptyAdditionalProviderMetadata, EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl,
    JsonWebKeySetUrl, Nonce, PkceCodeChallenge, RedirectUrl, ResponseTypes, Scope, TokenResponse,
    TokenUrl,
};
use serde::Deserialize;

use super::client_secret::{AppleClientSecret, ClientSecretError};
use crate::providers::oidc_generic::{
    OidcBegin, OidcError, OidcFlowState, OidcFlowStore, VerifiedIdToken, DEFAULT_FLOW_TTL_SECONDS,
};

/// Apple's published OIDC issuer URL. The `iss` claim Apple signs into
/// every ID token.
pub const APPLE_ISSUER: &str = "https://appleid.apple.com";

/// Apple's `/auth/authorize` endpoint.
pub const APPLE_AUTHORIZATION_ENDPOINT: &str = "https://appleid.apple.com/auth/authorize";

/// Apple's `/auth/token` endpoint.
pub const APPLE_TOKEN_ENDPOINT: &str = "https://appleid.apple.com/auth/token";

/// Apple's JWKS endpoint (verifies `id_token` signatures).
pub const APPLE_JWKS_URI: &str = "https://appleid.apple.com/auth/keys";

/// Default scopes — what makes Apple send back `email` and the one-shot
/// `user` JSON name field. Anything narrower and the `user` payload is
/// dropped silently.
pub const APPLE_DEFAULT_SCOPES: &[&str] = &["name", "email"];

// ---------------------------------------------------------------------------
// Hand-built provider metadata
// ---------------------------------------------------------------------------

/// [`CoreProviderMetadata`] pinned to Apple's documented endpoints.
///
/// Use this in place of `discover_async` when you don't want a network hop
/// at process boot, or when Apple's discovery doc has drifted in a way
/// `openidconnect` refuses to parse. The fields baked in here are exactly
/// what Apple's
/// `https://appleid.apple.com/.well-known/openid-configuration` advertised
/// as of the last review.
pub fn apple_provider_metadata() -> CoreProviderMetadata {
    CoreProviderMetadata::new(
        IssuerUrl::new(APPLE_ISSUER.to_owned()).expect("Apple issuer URL parses"),
        AuthUrl::new(APPLE_AUTHORIZATION_ENDPOINT.to_owned())
            .expect("Apple authorization endpoint URL parses"),
        JsonWebKeySetUrl::new(APPLE_JWKS_URI.to_owned()).expect("Apple JWKS URL parses"),
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        // Apple's `sub` is per-Team-ID, opaque — pairwise.
        vec![CoreSubjectIdentifierType::Pairwise],
        // Apple's id_tokens are RS256 (despite the `client_secret` being
        // ES256 — different keys, different roles).
        vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(
        TokenUrl::new(APPLE_TOKEN_ENDPOINT.to_owned()).expect("Apple token endpoint URL parses"),
    ))
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AppleRedirectError {
    /// Underlying generic OIDC flow error (state mismatch, expired flow,
    /// id_token verification, token-endpoint HTTP failure, …).
    #[error("oidc: {0}")]
    Oidc(#[from] OidcError),

    /// Apple's form-post body was missing a required field.
    #[error("apple form missing required field `{0}`")]
    MissingFormField(&'static str),

    /// Apple returned an `error` field in the form-post body (`access_denied`,
    /// `invalid_request`, etc).
    #[error("apple provider returned error: {0}")]
    Provider(String),

    /// Could not mint a fresh `client_secret` JWT.
    #[error("apple client_secret: {0}")]
    ClientSecret(#[from] ClientSecretError),
}

// ---------------------------------------------------------------------------
// Callback form parsing
// ---------------------------------------------------------------------------

/// What Apple POSTs to the redirect URI when `response_mode=form_post`.
///
/// Field shape per
/// [Apple's Sign-in form-post docs][apple-form-post]:
///
/// - `code`  — authorization code (always present on success).
/// - `state` — echoed CSRF state (always present).
/// - `user`  — JSON `{"name":{"firstName":…,"lastName":…},"email":…}`,
///   present **only on first auth**.
/// - `error` — set instead of `code` when the user cancels or Apple
///   rejects the request.
/// - `id_token` — Apple may include an `id_token` directly in the form
///   body when `response_type=code id_token`; cheers uses
///   `response_type=code` so this field is not parsed (kept implicit so
///   callers receive the canonical verified token from `/auth/token`).
///
/// [apple-form-post]:
///   https://developer.apple.com/documentation/sign_in_with_apple/sign_in_with_apple_js/configuring_your_webpage_for_sign_in_with_apple
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AppleCallbackForm {
    pub code: AuthorizationCode,
    pub state: CsrfToken,
    /// Raw `user` JSON — pass through [`FirstLoginName::from_apple_user_field`]
    /// to extract the display name.
    pub user_json: Option<String>,
    /// Set when Apple returned an error instead of a successful auth code.
    pub error: Option<String>,
}

impl AppleCallbackForm {
    /// Parse an `application/x-www-form-urlencoded` body.
    ///
    /// Returns an [`AppleRedirectError::Provider`] if Apple's `error` field
    /// is set — calling `finish_form_post` on a parsed-but-error form is a
    /// caller bug, so the typed error is surfaced at parse time.
    pub fn parse(body: &str) -> Result<Self, AppleRedirectError> {
        let mut code: Option<String> = None;
        let mut state: Option<String> = None;
        let mut user_json: Option<String> = None;
        let mut error: Option<String> = None;

        for (k, v) in form_urlencoded::parse(body.as_bytes()) {
            match k.as_ref() {
                "code" => code = Some(v.into_owned()),
                "state" => state = Some(v.into_owned()),
                "user" => user_json = Some(v.into_owned()),
                "error" => error = Some(v.into_owned()),
                _ => {}
            }
        }

        if let Some(err) = error {
            // Surface the provider-side rejection eagerly. Don't require
            // code/state to be present — Apple may omit them on error.
            return Err(AppleRedirectError::Provider(err));
        }

        let code = code
            .map(AuthorizationCode::new)
            .ok_or(AppleRedirectError::MissingFormField("code"))?;
        let state = state
            .map(CsrfToken::new)
            .ok_or(AppleRedirectError::MissingFormField("state"))?;

        Ok(Self {
            code,
            state,
            user_json,
            error: None,
        })
    }
}

// ---------------------------------------------------------------------------
// FirstLoginName — one-shot persistence contract
// ---------------------------------------------------------------------------

/// **PERSISTENCE REQUIRED ON FIRST SIGHT.**
///
/// Apple sends the user's real name in the `user` form field on the **first
/// auth response** after they grant the app permission. cheers extracts it
/// into this newtype to make the lifecycle explicit at the type level.
/// Subsequent logins arrive with `as_str()` returning `None`. If you drop
/// this value without persisting it, you cannot recover it — Apple will
/// not include it again until the user revokes the app entirely *and*
/// re-authorizes.
///
/// `from_apple_user_field` is forgiving — Apple sometimes omits the JSON
/// even on first auth (the documented contract is "may include," not
/// "always includes"), and a malformed body should not bring down the auth
/// flow. Treat absence as "user prefers not to disclose."
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FirstLoginName(Option<String>);

#[derive(Debug, Deserialize)]
struct AppleUserField {
    name: Option<AppleUserName>,
    // `email` arrives via the ID-token claim as well; we ignore the form-
    // body copy so there's one source of truth.
}

#[derive(Debug, Deserialize)]
struct AppleUserName {
    #[serde(rename = "firstName")]
    first_name: Option<String>,
    #[serde(rename = "lastName")]
    last_name: Option<String>,
}

impl FirstLoginName {
    /// Empty — no name disclosed. Same as [`FirstLoginName::default`].
    pub fn empty() -> Self {
        Self(None)
    }

    /// Borrow the display name (`"<firstName> <lastName>"` joined with a
    /// single space, or whichever component was present). `None` when
    /// Apple sent no name or sent malformed JSON.
    pub fn as_str(&self) -> Option<&str> {
        self.0.as_deref()
    }

    /// `true` when there's a name to persist.
    pub fn is_some(&self) -> bool {
        self.0.is_some()
    }

    pub fn into_inner(self) -> Option<String> {
        self.0
    }

    /// Parse the raw `user` field straight from Apple's form-post body.
    /// Empty/absent input and malformed JSON both yield [`Self::empty`] —
    /// Apple's docs only promise the field "may be present on first
    /// authorization."
    pub fn from_apple_user_field(s: Option<&str>) -> Self {
        let Some(s) = s.filter(|x| !x.is_empty()) else {
            return Self::empty();
        };
        let Ok(parsed) = serde_json::from_str::<AppleUserField>(s) else {
            return Self::empty();
        };
        let Some(name) = parsed.name else {
            return Self::empty();
        };
        let combined = match (
            name.first_name.as_deref().map(str::trim).filter(|x| !x.is_empty()),
            name.last_name.as_deref().map(str::trim).filter(|x| !x.is_empty()),
        ) {
            (Some(f), Some(l)) => Some(format!("{f} {l}")),
            (Some(f), None) => Some(f.to_owned()),
            (None, Some(l)) => Some(l.to_owned()),
            (None, None) => None,
        };
        Self(combined)
    }
}

// ---------------------------------------------------------------------------
// AppleVerified — bundled output of finish_form_post
// ---------------------------------------------------------------------------

/// What [`AppleRedirectProvider::finish_form_post`] returns on success.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AppleVerified {
    /// Subject / email / issuer claims pulled from the verified ID token.
    pub id_token: VerifiedIdToken,
    /// User's real name from the first-auth `user` form field, if any.
    /// See [`FirstLoginName`] for the persistence contract.
    pub first_login: FirstLoginName,
}

// ---------------------------------------------------------------------------
// AppleRedirectProvider
// ---------------------------------------------------------------------------

/// Concrete typestate of the `CoreClient` we rebuild per request. Same as
/// [`super::super::oidc_generic`]'s `Client` alias — `from_provider_metadata`
/// plus `set_redirect_uri` leaves us here.
type AppleCoreClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// Apple Sign-In via the form-post redirect flow.
///
/// Holds the cached [`CoreProviderMetadata`] (so each request rebuilds the
/// `CoreClient` locally without a discovery round-trip), the `ClientId`,
/// the redirect URI, an [`AppleClientSecret`] for ES256 JWT minting, the
/// requested scopes, and an [`OidcFlowStore`] for begin↔finish state.
///
/// Why we rebuild the inner client per request: `openidconnect::CoreClient`
/// bakes the `ClientSecret` in at construction with no setter — so to rotate
/// the `client_secret` JWT we reconstruct from cached metadata each call.
/// The reconstruction is cheap (URL strings + supported-algorithm lists);
/// the costly bits (network discovery, key parse) happen once at
/// construction.
pub struct AppleRedirectProvider<S> {
    metadata: CoreProviderMetadata,
    client_id: ClientId,
    redirect_uri: RedirectUrl,
    secret_gen: Arc<AppleClientSecret>,
    scopes: Vec<Scope>,
    flow_ttl_seconds: i64,
    flows: S,
}

impl<S> AppleRedirectProvider<S> {
    /// Build from pre-fetched [`CoreProviderMetadata`] — use
    /// [`apple_provider_metadata`] for the offline-friendly path, or a
    /// `discover_async`-fetched metadata for the live path.
    pub fn from_provider_metadata(
        metadata: CoreProviderMetadata,
        client_id: ClientId,
        redirect_uri: RedirectUrl,
        secret_gen: Arc<AppleClientSecret>,
        flows: S,
    ) -> Self {
        Self {
            metadata,
            client_id,
            redirect_uri,
            secret_gen,
            scopes: APPLE_DEFAULT_SCOPES
                .iter()
                .map(|s| Scope::new((*s).to_owned()))
                .collect(),
            flow_ttl_seconds: DEFAULT_FLOW_TTL_SECONDS,
            flows,
        }
    }

    /// Discover provider metadata at [`APPLE_ISSUER`], then build.
    ///
    /// `http` should refuse redirects (per `openidconnect`'s own example).
    /// If Apple's discovery JSON ever stops parsing as
    /// [`CoreProviderMetadata`], fall back to
    /// [`from_provider_metadata`](Self::from_provider_metadata) +
    /// [`apple_provider_metadata`].
    pub async fn discover(
        client_id: ClientId,
        redirect_uri: RedirectUrl,
        secret_gen: Arc<AppleClientSecret>,
        flows: S,
        http: &reqwest::Client,
    ) -> Result<Self, AppleRedirectError> {
        let issuer = IssuerUrl::new(APPLE_ISSUER.to_owned())
            .map_err(|e| OidcError::Discovery(format!("invalid Apple issuer URL: {e}")))?;
        let metadata = CoreProviderMetadata::discover_async(issuer, http)
            .await
            .map_err(|e| OidcError::Discovery(format!("{e}")))?;
        Ok(Self::from_provider_metadata(
            metadata,
            client_id,
            redirect_uri,
            secret_gen,
            flows,
        ))
    }

    /// Replace the requested scopes. Default is [`APPLE_DEFAULT_SCOPES`]
    /// (`name email`) — anything narrower and Apple won't include the
    /// `user` JSON on first auth.
    pub fn with_scopes<I, V>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = V>,
        V: Into<String>,
    {
        self.scopes = scopes.into_iter().map(|s| Scope::new(s.into())).collect();
        self
    }

    /// Override the begin→finish window. Default is
    /// [`DEFAULT_FLOW_TTL_SECONDS`] (5 min).
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

    /// Borrow the ES256 client_secret generator — wire this into the Apple
    /// `/auth/token` error path:
    /// `provider.secret_gen().invalidate()` forces the next request to
    /// mint a fresh JWT.
    pub fn secret_gen(&self) -> &AppleClientSecret {
        &self.secret_gen
    }

    /// Convenience pass-through: drops the cached `client_secret` JWT.
    /// Wire on `invalid_client` from Apple's `/auth/token`.
    pub fn invalidate_client_secret(&self) {
        self.secret_gen.invalidate();
    }

    /// Build a fresh `CoreClient` carrying a JWT-just-signed-now as the
    /// `client_secret`. Used by `finish_form_post`; `begin` doesn't need a
    /// real secret (auth URL alone) so it passes the same path with `None`.
    ///
    /// `AuthType::RequestBody` is the **load-bearing** Apple-ism here:
    /// `openidconnect`/`oauth2`'s default `AuthType::BasicAuth` sends
    /// `Authorization: Basic base64(client_id:client_secret)`, which
    /// Apple rejects ("the request body must include the client
    /// credentials"). Form-body auth is what Apple's documented
    /// `/auth/token` contract demands.
    fn build_client(
        &self,
        client_secret: Option<ClientSecret>,
    ) -> AppleCoreClient {
        CoreClient::from_provider_metadata(
            self.metadata.clone(),
            self.client_id.clone(),
            client_secret,
        )
        .set_redirect_uri(self.redirect_uri.clone())
        .set_auth_type(AuthType::RequestBody)
    }
}

impl<S: OidcFlowStore> AppleRedirectProvider<S> {
    /// Start a fresh Apple login flow.
    ///
    /// Mints PKCE + CSRF state + nonce, builds the authorization URL with
    /// `response_mode=form_post` and the Apple-specific scopes, stashes the
    /// flow state, and returns the URL to redirect to.
    pub async fn begin(&self, now: i64) -> Result<OidcBegin, AppleRedirectError> {
        // `begin()` doesn't make a /auth/token call so the secret doesn't
        // matter — we pass `None` and avoid the ES256 signing cost on
        // every redirect.
        let client = self.build_client(None);

        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        let mut req = client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for scope in &self.scopes {
            req = req.add_scope(scope.clone());
        }
        // Apple requires `response_mode=form_post` when `scope=name` is
        // requested — without it Apple drops the `user` JSON on the floor.
        req = req.add_extra_param("response_mode", "form_post");

        let (authorize_url, csrf_state, nonce) = req.set_pkce_challenge(pkce_challenge).url();

        let flow_state = OidcFlowState::from_parts(
            csrf_state.clone(),
            nonce,
            pkce_verifier,
            now.saturating_add(self.flow_ttl_seconds),
        );
        self.flows
            .put(csrf_state.secret(), flow_state)
            .await
            .map_err(OidcError::Store)?;

        Ok(OidcBegin {
            authorize_url,
            csrf_state,
        })
    }

    /// Finish a flow against Apple's form-post callback.
    ///
    /// Atomically takes the stashed flow state, mints a fresh ES256
    /// `client_secret` JWT, exchanges the authorization code at
    /// `/auth/token`, verifies the returned ID token against Apple's JWKS
    /// + the stashed nonce, and bundles the result with a one-shot
    /// [`FirstLoginName`] extracted from the form's `user` field.
    pub async fn finish_form_post(
        &self,
        form: AppleCallbackForm,
        http: &reqwest::Client,
        now: i64,
    ) -> Result<AppleVerified, AppleRedirectError> {
        let flow_state = self
            .flows
            .take(form.state.secret())
            .await
            .map_err(OidcError::Store)?
            .ok_or(OidcError::UnknownFlow)?;
        // Consume immediately — `PkceCodeVerifier` is intentionally non-Clone
        // (one-shot secret) and `exchange_code` takes it by value.
        let (csrf_token, nonce, pkce_verifier, expires_at) = flow_state.into_parts();

        if csrf_token.secret() != form.state.secret() {
            return Err(OidcError::StateMismatch.into());
        }
        if expires_at <= now {
            return Err(OidcError::FlowExpired.into());
        }

        // Mint a fresh JWT and rebuild the client so /auth/token carries it.
        let jwt = self.secret_gen.current(now)?;
        let client = self.build_client(Some(ClientSecret::new(jwt)));

        let token_response = client
            .exchange_code(form.code)
            .map_err(|e| OidcError::Config(format!("{e}")))?
            .set_pkce_verifier(pkce_verifier)
            .request_async(http)
            .await
            .map_err(|e| OidcError::Http(format!("{e}")))?;

        let id_token = token_response
            .id_token()
            .ok_or(OidcError::MissingIdToken)?;
        let verifier = client.id_token_verifier();
        let claims: &CoreIdTokenClaims = id_token
            .claims(&verifier, &nonce)
            .map_err(|e| OidcError::IdToken(format!("{e}")))?;

        let first_login = FirstLoginName::from_apple_user_field(form.user_json.as_deref());

        Ok(AppleVerified {
            id_token: VerifiedIdToken {
                issuer: claims.issuer().as_str().to_owned(),
                subject: claims.subject().as_str().to_owned(),
                email: claims.email().map(|e| e.as_str().to_owned()),
                email_verified: claims.email_verified(),
                name: claims
                    .name()
                    .and_then(|n| n.get(None).or_else(|| n.iter().next().map(|(_, v)| v)))
                    .map(|v| v.as_str().to_owned()),
            },
            first_login,
        })
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    //! Tests cover (a) the cheap unit-level surface (form parsing,
    //! FirstLoginName parsing, hand-built metadata, begin URL shape +
    //! unhappy finish paths) and (b) a wiremock'd round-trip exercising
    //! the full ES256 `client_secret` → RS256 `id_token` integration
    //! against a localhost fake-Apple.

    use super::*;

    use chrono::{Duration, Utc};
    use openidconnect::core::{
        CoreIdToken, CoreIdTokenClaims, CoreIdTokenFields, CoreJsonWebKeySet,
        CoreRsaPrivateSigningKey, CoreTokenResponse, CoreTokenType,
    };
    use openidconnect::{
        AccessToken, Audience, EmptyAdditionalClaims, EmptyExtraTokenFields, EndUserEmail,
        EndUserName, JsonWebKeyId, LocalizedClaim, PrivateSigningKey, StandardClaims,
        SubjectIdentifier,
    };
    use wiremock::matchers::{body_string_contains, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::providers::apple::client_secret::{
        AppleClientSecret, APPLE_AUDIENCE, DEFAULT_TOKEN_TTL_SECONDS,
    };
    use crate::providers::oidc_generic::{MemoryOidcFlowStore, OidcFlowStore};

    // -- shared fixtures (mirrors the google.rs wiremock pattern) -----------

    /// Same PKCS#1 PEM `google.rs` uses — `openidconnect`'s own test
    /// fixture. Apple signs id_tokens with RS256, same as Google, so a
    /// shared key keeps test plumbing minimal.
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
    const TEST_KID: &str = "apple-test-key";

    const CLIENT_ID: &str = "com.example.signin";
    const REDIRECT_URI: &str = "https://app.example/auth/callback/apple";

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

    /// Same deterministic P-256 scalar `client_secret.rs` tests use — the
    /// public key is fixed, the JWT signatures are reproducible.
    fn p8_pem() -> String {
        use p256::pkcs8::{EncodePrivateKey, LineEnding};
        let mut bytes = [0u8; 32];
        bytes[31] = 0x42;
        let sk = p256::SecretKey::from_slice(&bytes).expect("valid P-256 scalar");
        sk.to_pkcs8_pem(LineEnding::LF)
            .expect("P-256 PKCS#8 PEM")
            .to_string()
    }

    fn apple_secret() -> Arc<AppleClientSecret> {
        Arc::new(
            AppleClientSecret::from_p8_pem(
                "TEAM123ABC",
                "KEYID45678",
                CLIENT_ID,
                p8_pem().as_bytes(),
            )
            .expect("p8 pem parses"),
        )
    }

    // -- AppleCallbackForm parsing ------------------------------------------

    #[test]
    fn form_parse_happy_path_no_user() {
        let body = "code=ABC123&state=STATE-XYZ";
        let form = AppleCallbackForm::parse(body).unwrap();
        assert_eq!(form.code.secret(), "ABC123");
        assert_eq!(form.state.secret(), "STATE-XYZ");
        assert!(form.user_json.is_none());
        assert!(form.error.is_none());
    }

    #[test]
    fn form_parse_extracts_user_field_verbatim() {
        // `user` is JSON, percent-encoded on the wire.
        let body =
            "code=C&state=S&user=%7B%22name%22%3A%7B%22firstName%22%3A%22Ada%22%2C%22lastName%22%3A%22Lovelace%22%7D%7D";
        let form = AppleCallbackForm::parse(body).unwrap();
        assert_eq!(form.code.secret(), "C");
        assert_eq!(form.state.secret(), "S");
        assert_eq!(
            form.user_json.as_deref(),
            Some(r#"{"name":{"firstName":"Ada","lastName":"Lovelace"}}"#)
        );
    }

    #[test]
    fn form_parse_provider_error_short_circuits() {
        let body = "error=access_denied";
        let err = AppleCallbackForm::parse(body).unwrap_err();
        match err {
            AppleRedirectError::Provider(s) => assert_eq!(s, "access_denied"),
            other => panic!("expected Provider error, got {other:?}"),
        }
    }

    #[test]
    fn form_parse_missing_code_errors() {
        let body = "state=ONLY";
        let err = AppleCallbackForm::parse(body).unwrap_err();
        assert!(matches!(err, AppleRedirectError::MissingFormField("code")));
    }

    #[test]
    fn form_parse_missing_state_errors() {
        let body = "code=ONLY";
        let err = AppleCallbackForm::parse(body).unwrap_err();
        assert!(matches!(err, AppleRedirectError::MissingFormField("state")));
    }

    #[test]
    fn form_parse_ignores_unknown_fields() {
        let body = "code=C&state=S&extra=junk&id_token=ignored";
        let form = AppleCallbackForm::parse(body).unwrap();
        assert_eq!(form.code.secret(), "C");
        assert_eq!(form.state.secret(), "S");
    }

    // -- FirstLoginName parsing ---------------------------------------------

    #[test]
    fn first_login_name_combines_first_and_last() {
        let name = FirstLoginName::from_apple_user_field(Some(
            r#"{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"a@l.com"}"#,
        ));
        assert_eq!(name.as_str(), Some("Ada Lovelace"));
        assert!(name.is_some());
    }

    #[test]
    fn first_login_name_first_only() {
        let name = FirstLoginName::from_apple_user_field(Some(
            r#"{"name":{"firstName":"Cher"}}"#,
        ));
        assert_eq!(name.as_str(), Some("Cher"));
    }

    #[test]
    fn first_login_name_last_only() {
        let name = FirstLoginName::from_apple_user_field(Some(
            r#"{"name":{"lastName":"Lovelace"}}"#,
        ));
        assert_eq!(name.as_str(), Some("Lovelace"));
    }

    #[test]
    fn first_login_name_trims_whitespace_components() {
        let name = FirstLoginName::from_apple_user_field(Some(
            r#"{"name":{"firstName":"  Ada  ","lastName":"  "}}"#,
        ));
        assert_eq!(name.as_str(), Some("Ada"));
    }

    #[test]
    fn first_login_name_empty_when_absent() {
        assert!(FirstLoginName::from_apple_user_field(None).as_str().is_none());
        assert!(FirstLoginName::from_apple_user_field(Some("")).as_str().is_none());
        assert!(
            FirstLoginName::from_apple_user_field(Some(r#"{"email":"x@y.com"}"#))
                .as_str()
                .is_none()
        );
        assert!(
            FirstLoginName::from_apple_user_field(Some(r#"{"name":{}}"#))
                .as_str()
                .is_none()
        );
    }

    #[test]
    fn first_login_name_malformed_json_is_empty() {
        assert!(
            FirstLoginName::from_apple_user_field(Some("not json"))
                .as_str()
                .is_none()
        );
        assert!(
            FirstLoginName::from_apple_user_field(Some(r#"{"name":"plain string"}"#))
                .as_str()
                .is_none()
        );
    }

    // -- hand-built metadata -------------------------------------------------

    #[test]
    fn apple_provider_metadata_constants_match_published_urls() {
        let meta = apple_provider_metadata();
        assert_eq!(meta.issuer().as_str(), APPLE_ISSUER);
        assert_eq!(
            meta.authorization_endpoint().as_str(),
            APPLE_AUTHORIZATION_ENDPOINT
        );
        assert_eq!(
            meta.token_endpoint().expect("token endpoint").as_str(),
            APPLE_TOKEN_ENDPOINT
        );
        assert_eq!(meta.jwks_uri().as_str(), APPLE_JWKS_URI);
    }

    // -- begin URL shape -----------------------------------------------------

    fn provider_pinned_to_apple() -> AppleRedirectProvider<MemoryOidcFlowStore> {
        AppleRedirectProvider::from_provider_metadata(
            apple_provider_metadata(),
            ClientId::new(CLIENT_ID.into()),
            RedirectUrl::new(REDIRECT_URI.into()).unwrap(),
            apple_secret(),
            MemoryOidcFlowStore::new(),
        )
    }

    #[tokio::test]
    async fn begin_url_targets_apple_authorize_with_form_post_mode() {
        let p = provider_pinned_to_apple();
        let begin = p.begin(1_000).await.unwrap();
        let u = &begin.authorize_url;
        assert_eq!(u.scheme(), "https");
        assert_eq!(u.host_str(), Some("appleid.apple.com"));
        assert_eq!(u.path(), "/auth/authorize");

        let qs: Vec<(String, String)> = u
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let lookup = |k: &str| qs.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone());
        assert_eq!(lookup("response_type").as_deref(), Some("code"));
        assert_eq!(lookup("response_mode").as_deref(), Some("form_post"));
        assert_eq!(lookup("client_id").as_deref(), Some(CLIENT_ID));
        assert_eq!(lookup("redirect_uri").as_deref(), Some(REDIRECT_URI));
        let scope = lookup("scope").expect("scope param");
        let parts: Vec<&str> = scope.split(' ').collect();
        assert!(parts.contains(&"name"));
        assert!(parts.contains(&"email"));
        assert_eq!(lookup("code_challenge_method").as_deref(), Some("S256"));
        assert!(!lookup("code_challenge").unwrap_or_default().is_empty());
        assert!(!lookup("state").unwrap_or_default().is_empty());
        assert!(!lookup("nonce").unwrap_or_default().is_empty());
    }

    #[tokio::test]
    async fn begin_stashes_flow_keyed_by_csrf_state() {
        let p = provider_pinned_to_apple();
        let begin = p.begin(1_000).await.unwrap();
        assert_eq!(p.flows().len(), 1);
        let stashed = p
            .flows()
            .take(begin.csrf_state.secret())
            .await
            .unwrap()
            .expect("stashed");
        assert_eq!(stashed.csrf_token().secret(), begin.csrf_state.secret());
        assert_eq!(stashed.expires_at(), 1_000 + DEFAULT_FLOW_TTL_SECONDS);
    }

    // -- finish unhappy paths (HTTP-free) ------------------------------------

    #[tokio::test]
    async fn finish_with_unknown_state_returns_unknown_flow() {
        let p = provider_pinned_to_apple();
        let form = AppleCallbackForm {
            code: AuthorizationCode::new("C".into()),
            state: CsrfToken::new("never-stashed".into()),
            user_json: None,
            error: None,
        };
        let err = p
            .finish_form_post(form, &dummy_http(), 1_000)
            .await
            .unwrap_err();
        match err {
            AppleRedirectError::Oidc(OidcError::UnknownFlow) => {}
            other => panic!("expected UnknownFlow, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn finish_with_expired_flow_returns_flow_expired() {
        let p = provider_pinned_to_apple().with_flow_ttl_seconds(60);
        let begin = p.begin(1_000).await.unwrap();
        let form = AppleCallbackForm {
            code: AuthorizationCode::new("C".into()),
            state: begin.csrf_state,
            user_json: None,
            error: None,
        };
        let err = p
            .finish_form_post(form, &dummy_http(), 1_000 + 60)
            .await
            .unwrap_err();
        match err {
            AppleRedirectError::Oidc(OidcError::FlowExpired) => {}
            other => panic!("expected FlowExpired, got {other:?}"),
        }
    }

    // -- wiremock'd full round-trip ------------------------------------------

    /// Stand up a localhost fake-Apple. `/auth/keys` serves the test
    /// JWKS; `/.well-known/openid-configuration` advertises the wiremock
    /// URL as the issuer. The `/auth/token` endpoint is mounted per-test
    /// once the id_token's bound nonce is known.
    async fn mount_apple_discovery_and_jwks(server: &MockServer, base: &str) {
        let metadata = CoreProviderMetadata::new(
            IssuerUrl::new(base.to_owned()).unwrap(),
            AuthUrl::new(format!("{base}/auth/authorize")).unwrap(),
            JsonWebKeySetUrl::new(format!("{base}/auth/keys")).unwrap(),
            vec![ResponseTypes::new(vec![CoreResponseType::Code])],
            vec![CoreSubjectIdentifierType::Pairwise],
            vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
            EmptyAdditionalProviderMetadata {},
        )
        .set_token_endpoint(Some(TokenUrl::new(format!("{base}/auth/token")).unwrap()));

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&metadata))
            .mount(server)
            .await;

        let jwks = CoreJsonWebKeySet::new(vec![signing_key().as_verification_key()]);
        Mock::given(method("GET"))
            .and(path("/auth/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&jwks))
            .mount(server)
            .await;
    }

    fn build_id_token(issuer: &str, nonce: &Nonce, name: Option<&str>) -> CoreIdToken {
        let now = Utc::now();
        let mut std_claims =
            StandardClaims::new(SubjectIdentifier::new("apple-sub-abcdef".to_owned()))
                .set_email(Some(EndUserEmail::new(
                    "abc@privaterelay.appleid.com".to_owned(),
                )))
                .set_email_verified(Some(true));
        if let Some(n) = name {
            let mut lc: LocalizedClaim<EndUserName> = LocalizedClaim::default();
            lc.insert(None, EndUserName::new(n.to_owned()));
            std_claims = std_claims.set_name(Some(lc));
        }
        let claims = CoreIdTokenClaims::new(
            IssuerUrl::new(issuer.to_owned()).unwrap(),
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
        .expect("ID token signs")
    }

    async fn mount_token_endpoint(server: &MockServer, id_token: CoreIdToken) {
        let resp = CoreTokenResponse::new(
            AccessToken::new("test-access-token".to_owned()),
            CoreTokenType::Bearer,
            CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
        );
        Mock::given(method("POST"))
            .and(path("/auth/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&resp))
            .mount(server)
            .await;
    }

    /// Same trick `google.rs` uses — peek the stashed nonce so the
    /// minted id_token carries the value `finish` will verify against.
    async fn peek_stashed_nonce(
        provider: &AppleRedirectProvider<MemoryOidcFlowStore>,
        csrf_state_secret: &str,
    ) -> Nonce {
        let st = provider
            .flows()
            .take(csrf_state_secret)
            .await
            .expect("store ok")
            .expect("flow stashed");
        let nonce = st.nonce().clone();
        let put_back = OidcFlowState::from_parts(
            st.csrf_token().clone(),
            st.nonce().clone(),
            // PkceCodeVerifier doesn't implement Clone, so reconstruct from
            // its secret bytes — same value, fresh wrapper.
            openidconnect::PkceCodeVerifier::new(st.pkce_verifier().secret().clone()),
            st.expires_at(),
        );
        provider
            .flows()
            .put(csrf_state_secret, put_back)
            .await
            .expect("re-put");
        nonce
    }

    async fn build_provider_via_discovery(
        server: &MockServer,
        http: &reqwest::Client,
    ) -> AppleRedirectProvider<MemoryOidcFlowStore> {
        let issuer = IssuerUrl::new(server.uri()).unwrap();
        let metadata = CoreProviderMetadata::discover_async(issuer, http)
            .await
            .expect("wiremock discovery succeeds");
        AppleRedirectProvider::from_provider_metadata(
            metadata,
            ClientId::new(CLIENT_ID.into()),
            RedirectUrl::new(REDIRECT_URI.into()).unwrap(),
            apple_secret(),
            MemoryOidcFlowStore::new(),
        )
    }

    #[tokio::test]
    async fn form_post_round_trip_captures_first_login_name() {
        let http = dummy_http();
        let server = MockServer::start().await;
        let base = server.uri();
        mount_apple_discovery_and_jwks(&server, &base).await;
        let provider = build_provider_via_discovery(&server, &http).await;
        let now_seconds = Utc::now().timestamp();
        let begin = provider.begin(now_seconds).await.unwrap();

        let nonce = peek_stashed_nonce(&provider, begin.csrf_state.secret()).await;
        let id_token = build_id_token(&base, &nonce, None); // Apple omits `name` from id_token
        mount_token_endpoint(&server, id_token).await;

        // Apple's first-auth form body — code+state echoed, user JSON
        // appended verbatim. Build it through form_urlencoded so the
        // `user` JSON's braces/quotes round-trip correctly.
        let user_json = r#"{"name":{"firstName":"Ada","lastName":"Lovelace"},"email":"ada@example.com"}"#;
        let body = form_urlencoded::Serializer::new(String::new())
            .append_pair("code", "the-code")
            .append_pair("state", begin.csrf_state.secret())
            .append_pair("user", user_json)
            .finish();
        let form = AppleCallbackForm::parse(&body).expect("parse form-post body");

        let verified = provider
            .finish_form_post(form, &http, now_seconds)
            .await
            .expect("form_post round-trip");

        assert_eq!(verified.id_token.issuer, base);
        assert_eq!(verified.id_token.subject, "apple-sub-abcdef");
        assert_eq!(
            verified.id_token.email.as_deref(),
            Some("abc@privaterelay.appleid.com")
        );
        assert_eq!(verified.id_token.email_verified, Some(true));
        assert_eq!(verified.first_login.as_str(), Some("Ada Lovelace"));
    }

    #[tokio::test]
    async fn form_post_round_trip_returning_user_has_no_first_login_name() {
        // Returning user — no `user` field on the form body.
        let http = dummy_http();
        let server = MockServer::start().await;
        let base = server.uri();
        mount_apple_discovery_and_jwks(&server, &base).await;
        let provider = build_provider_via_discovery(&server, &http).await;
        let now_seconds = Utc::now().timestamp();
        let begin = provider.begin(now_seconds).await.unwrap();

        let nonce = peek_stashed_nonce(&provider, begin.csrf_state.secret()).await;
        let id_token = build_id_token(&base, &nonce, None);
        mount_token_endpoint(&server, id_token).await;

        let body = format!("code=C&state={}", begin.csrf_state.secret());
        let form = AppleCallbackForm::parse(&body).unwrap();
        let verified = provider
            .finish_form_post(form, &http, now_seconds)
            .await
            .unwrap();
        assert!(verified.first_login.as_str().is_none());
    }

    #[tokio::test]
    async fn token_endpoint_receives_es256_client_secret_jwt() {
        // Proves the AppleClientSecret JWT is what reaches /auth/token.
        // We don't pin the exact JWT string in the matcher because ring's
        // ECDSA signer mixes randomization in alongside RFC 6979 — so even
        // identical payloads produce different signatures across calls.
        // The matcher instead checks the header.payload prefix (which
        // *is* deterministic for fixed claims+key) plus the dot before
        // the signature.
        use jsonwebtoken::{Algorithm, EncodingKey, Header};
        use serde::Serialize;
        let http = dummy_http();
        let server = MockServer::start().await;
        let base = server.uri();
        mount_apple_discovery_and_jwks(&server, &base).await;
        let provider = build_provider_via_discovery(&server, &http).await;
        let now_seconds = Utc::now().timestamp();
        let begin = provider.begin(now_seconds).await.unwrap();

        let nonce = peek_stashed_nonce(&provider, begin.csrf_state.secret()).await;
        let id_token = build_id_token(&base, &nonce, None);

        // Compute the deterministic `header.payload.` prefix the JWT
        // will start with. AppleClientSecret pins the header
        // (alg=ES256, kid=KEYID45678, typ=JWT) and the payload
        // (iss=TEAM123ABC, iat=now, exp=now+3600, aud=APPLE_AUDIENCE,
        // sub=CLIENT_ID), so two parts out of three are reproducible.
        #[derive(Serialize)]
        struct ExpectedClaims<'a> {
            iss: &'a str,
            iat: i64,
            exp: i64,
            aud: &'a str,
            sub: &'a str,
        }
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some("KEYID45678".to_owned());
        // We only care about the header+payload parts (the prefix) — pick
        // any P-256 key for jsonwebtoken's encode, then split on '.'.
        let probe_pem = p8_pem();
        let probe_key = EncodingKey::from_ec_pem(probe_pem.as_bytes()).unwrap();
        let probe = jsonwebtoken::encode(
            &header,
            &ExpectedClaims {
                iss: "TEAM123ABC",
                iat: now_seconds,
                exp: now_seconds + DEFAULT_TOKEN_TTL_SECONDS,
                aud: APPLE_AUDIENCE,
                sub: CLIENT_ID,
            },
            &probe_key,
        )
        .unwrap();
        let prefix: String = probe.split('.').take(2).collect::<Vec<_>>().join(".");
        // The form-body field is `client_secret=<JWT>`. Match on
        // `client_secret=<prefix>.` so the matcher accepts any signature.
        let needle = format!("client_secret={prefix}.");

        let token_resp = CoreTokenResponse::new(
            AccessToken::new("at".to_owned()),
            CoreTokenType::Bearer,
            CoreIdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
        );
        Mock::given(method("POST"))
            .and(path("/auth/token"))
            .and(body_string_contains(&needle))
            .respond_with(ResponseTemplate::new(200).set_body_json(&token_resp))
            .expect(1)
            .mount(&server)
            .await;

        let body = format!("code=C&state={}", begin.csrf_state.secret());
        let form = AppleCallbackForm::parse(&body).unwrap();
        provider
            .finish_form_post(form, &http, now_seconds)
            .await
            .expect("token endpoint sees the JWT");
        // Mock's `.expect(1)` enforces exactly one match; if the body
        // matcher didn't catch the JWT prefix, the mock wouldn't fire and
        // the openidconnect client would surface an http error above.
    }
}
