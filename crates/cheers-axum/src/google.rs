//! Google OIDC routes — `GET /auth/login/google` + `GET /auth/callback/google`.
//!
//! The login handler stashes a flow, sets a CSRF cookie, and redirects the
//! browser to Google. The callback handler verifies the cookie, finishes the
//! flow against Google's `/token` endpoint, maps the resulting `id_token` to a
//! `cheers_core::User` via the [`UserStore`](cheers_server::UserStore), mints
//! a session through the [`SessionAuthority`](cheers_server::SessionAuthority),
//! and returns a [`SessionBody`].
//!
//! # Wiring
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use axum::Router;
//! # use cheers::providers::google::GoogleProvider;
//! # use cheers::providers::oidc_generic::MemoryOidcFlowStore;
//! # use cheers_axum::CsrfCookieConfig;
//! # use cheers_axum::google::{router, GoogleAuthState};
//! # use cheers_server::SessionAuthority;
//! # async fn run<M, R, U, W>(
//! #     google: Arc<GoogleProvider<MemoryOidcFlowStore>>,
//! #     authority: Arc<SessionAuthority<M, R, U, W>>,
//! # ) -> Result<(), Box<dyn std::error::Error>>
//! # where
//! #     M: cheers_core::TokenMinter + Send + Sync + 'static,
//! #     R: cheers_server::RefreshStore + 'static,
//! #     U: cheers_server::UserStore + 'static,
//! #     W: cheers_server::RevocationWriter + 'static,
//! # {
//! let http = openidconnect::reqwest::ClientBuilder::new()
//!     .redirect(openidconnect::reqwest::redirect::Policy::none())
//!     .build()?;
//!
//! let state = GoogleAuthState {
//!     provider: google,
//!     authority,
//!     http,
//!     cookie: CsrfCookieConfig::new("cheers_csrf_google"),
//! };
//!
//! let app: Router = Router::new().nest("/auth", router(Arc::new(state)));
//! # Ok(()) }
//! ```

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;

use cheers::providers::google::GoogleProvider;
use cheers::providers::oidc_generic::{OidcCallback, OidcFlowStore, VerifiedIdToken};
use cheers_core::{DeviceBinding, DeviceId, TokenMinter};
use cheers_server::{
    NewUser, ProviderKey, RefreshStore, RevocationWriter, SessionAuthority, UserStore,
};
use openidconnect::CsrfToken;

use crate::cookie::{CsrfCookieConfig, read_cookie};
use crate::error::RouteError;
use crate::session::SessionBody;

/// State bundle held by the Google handlers. `Arc<Self>` is what `with_state`
/// receives; cheap to clone per request.
pub struct GoogleAuthState<S, M, R, U, W> {
    pub provider: Arc<GoogleProvider<S>>,
    pub authority: Arc<SessionAuthority<M, R, U, W>>,
    pub http: openidconnect::reqwest::Client,
    pub cookie: CsrfCookieConfig,
}

impl<S, M, R, U, W> std::fmt::Debug for GoogleAuthState<S, M, R, U, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GoogleAuthState")
            .field("cookie", &self.cookie)
            .finish_non_exhaustive()
    }
}

/// Build a router mounting `GET /login/google` + `GET /callback/google`. The
/// product mounts it under whatever base path it chose (`/auth`, `/api/auth`,
/// …).
pub fn router<S, M, R, U, W>(state: Arc<GoogleAuthState<S, M, R, U, W>>) -> Router
where
    S: OidcFlowStore + Send + Sync + 'static,
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
{
    Router::new()
        .route("/login/google", get(login::<S, M, R, U, W>))
        .route("/callback/google", get(callback::<S, M, R, U, W>))
        .with_state(state)
}

/// `?code=...&state=...&...` — the query string Google appends to the
/// redirect URI.
#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    /// Google sets `error` instead of `code` when the user cancels at the
    /// consent screen.
    pub error: Option<String>,
}

/// `GET /login/google` — 302 to Google's authorization endpoint, with a
/// freshly stashed flow and the CSRF binding cookie set.
pub async fn login<S, M, R, U, W>(
    State(state): State<Arc<GoogleAuthState<S, M, R, U, W>>>,
) -> Result<Response, RouteError>
where
    S: OidcFlowStore + Send + Sync + 'static,
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
{
    let now = now_unix();
    let begin = state.provider.begin(now).await?;
    let csrf = begin.csrf_state.secret().to_owned();

    let mut headers = HeaderMap::new();
    let cookie_value = state.cookie.set_cookie(&csrf);
    let cookie_header = HeaderValue::from_str(&cookie_value)
        .map_err(|e| RouteError::Config(format!("cookie header value: {e}")))?;
    headers.insert(header::SET_COOKIE, cookie_header);

    let location = HeaderValue::from_str(begin.authorize_url.as_str())
        .map_err(|e| RouteError::Config(format!("location header value: {e}")))?;
    headers.insert(header::LOCATION, location);

    Ok((StatusCode::FOUND, headers).into_response())
}

/// `GET /callback/google` — verify CSRF, finish the flow, mint a session,
/// return `SessionBody` as JSON. The CSRF cookie is cleared on success.
pub async fn callback<S, M, R, U, W>(
    State(state): State<Arc<GoogleAuthState<S, M, R, U, W>>>,
    headers_in: HeaderMap,
    Query(params): Query<CallbackQuery>,
) -> Result<Response, RouteError>
where
    S: OidcFlowStore + Send + Sync + 'static,
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
{
    if let Some(err) = params.error {
        return Err(RouteError::Provider(err));
    }
    let code = params
        .code
        .ok_or_else(|| RouteError::MalformedCallback("missing `code`".into()))?;
    let state_param = params
        .state
        .ok_or_else(|| RouteError::MalformedCallback("missing `state`".into()))?;

    // CSRF binding: the cookie set at begin() must match the IdP-echoed state.
    let cookie_value = headers_in
        .get(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|raw| read_cookie(raw, &state.cookie.name).map(str::to_owned))
        .ok_or(RouteError::MissingCsrfCookie)?;
    if cookie_value != state_param {
        return Err(RouteError::CsrfStateMismatch);
    }

    let callback = OidcCallback::new(
        openidconnect::AuthorizationCode::new(code),
        CsrfToken::new(state_param),
    );
    let now = now_unix();
    let verified = state.provider.finish(callback, &state.http, now).await?;

    let session = resolve_user_and_establish(&state.authority, verified, now).await?;
    let body = SessionBody::from_new_session(session);

    let mut headers_out = HeaderMap::new();
    let clear = state.cookie.clear_cookie();
    if let Ok(v) = HeaderValue::from_str(&clear) {
        headers_out.insert(header::SET_COOKIE, v);
    }
    Ok((StatusCode::OK, headers_out, Json(body)).into_response())
}

/// Take the verified id_token, find-or-create a User keyed on
/// `(OidcGoogle, sub)`, mint a session for a fresh device. The `device_id` is
/// generated per login attempt — one OIDC sign-in = one device row. Products
/// that want a stickier device identity (e.g. browser-fingerprint-binding)
/// can layer that on top by overriding the SessionAuthority + UserStore.
async fn resolve_user_and_establish<M, R, U, W>(
    authority: &Arc<SessionAuthority<M, R, U, W>>,
    verified: VerifiedIdToken,
    now: i64,
) -> Result<cheers_server::NewSession, RouteError>
where
    M: TokenMinter + Send + Sync,
    R: RefreshStore,
    U: UserStore,
    W: RevocationWriter,
{
    let provider_key = ProviderKey::OidcGoogle;
    let users = authority.users();
    let user = match users.find_by_provider(&provider_key, &verified.subject).await? {
        Some(u) => u,
        None => {
            let new_user = NewUser::new();
            let new_user = match verified.email.as_deref() {
                Some(e) => new_user.with_email(e),
                None => new_user,
            };
            let new_user = match verified.name.as_deref() {
                Some(n) => new_user.with_name(n),
                None => new_user,
            };
            let u = users.create(new_user).await?;
            users
                .link_provider(&u.id, &provider_key, &verified.subject)
                .await?;
            u
        }
    };

    let device_id = DeviceId::new(generate_device_id());
    let session = authority
        .establish(
            user.id.clone(),
            device_id,
            DeviceBinding::OidcGoogle,
            now,
        )
        .await?;
    Ok(session)
}

/// 128-bit random device id, base64url-no-pad. Same generation pattern the
/// SessionAuthority uses for `jti` — uniqueness only, not a secret.
fn generate_device_id() -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("OS CSPRNG must be available");
    URL_SAFE_NO_PAD.encode(bytes)
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_device_id_produces_unique_b64url() {
        let a = generate_device_id();
        let b = generate_device_id();
        assert_ne!(a, b);
        // 16 bytes -> 22 chars b64url no-pad.
        assert_eq!(a.len(), 22);
        // No padding.
        assert!(!a.contains('='));
    }
}
