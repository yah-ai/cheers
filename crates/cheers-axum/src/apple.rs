//! Apple Sign-In routes — `GET /auth/login/apple` + `POST /auth/callback/apple`.
//!
//! Apple deviates from generic OIDC in three ways the handlers paper over for
//! the consumer:
//!
//! 1. **Form-post callback.** Apple POSTs `application/x-www-form-urlencoded`
//!    instead of using GET-with-query. The callback handler accepts the body
//!    as raw `String` (not [`axum::Form`]) so the underlying [`AppleCallbackForm::parse`]
//!    can apply Apple's own decoding rules — `axum::Form` would silently
//!    coerce `user=<JSON>` into a typed struct and lose the user payload.
//! 2. **Cross-site cookie.** Because the callback POST is cross-site, the
//!    CSRF binding cookie MUST be `SameSite=None; Secure`. [`AppleAuthState`]
//!    defaults to [`CsrfCookieConfig::for_apple`] which sets that.
//! 3. **One-shot first-login name.** Apple sends the user's real name in the
//!    `user` form field **only on first auth**. The handler routes that into
//!    [`UserStore::create`](cheers_server::UserStore::create) via
//!    [`NewUser::with_name`](cheers_server::NewUser::with_name); subsequent
//!    callbacks for the same user arrive without a `user` field and the
//!    stored name stays.
//!
//! See [`cheers::providers::apple`] for the underlying provider mechanics.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;

use cheers::providers::apple::{
    AppleCallbackForm, AppleRedirectProvider, AppleVerified, FirstLoginName,
};
use cheers::providers::oidc_generic::{OidcFlowStore, VerifiedIdToken};
use cheers_core::{DeviceBinding, DeviceId, TokenMinter};
use cheers_server::{
    NewUser, ProviderKey, RefreshStore, RevocationWriter, SessionAuthority, UserStore,
};

use crate::cookie::{CsrfCookieConfig, read_cookie};
use crate::error::RouteError;
use crate::session::SessionBody;

/// State bundle held by the Apple handlers.
pub struct AppleAuthState<S, M, R, U, W> {
    pub provider: Arc<AppleRedirectProvider<S>>,
    pub authority: Arc<SessionAuthority<M, R, U, W>>,
    pub http: openidconnect::reqwest::Client,
    pub cookie: CsrfCookieConfig,
}

impl<S, M, R, U, W> std::fmt::Debug for AppleAuthState<S, M, R, U, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppleAuthState")
            .field("cookie", &self.cookie)
            .finish_non_exhaustive()
    }
}

/// Build a router mounting `GET /login/apple` + `POST /callback/apple`.
pub fn router<S, M, R, U, W>(state: Arc<AppleAuthState<S, M, R, U, W>>) -> Router
where
    S: OidcFlowStore + Send + Sync + 'static,
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
{
    Router::new()
        .route("/login/apple", get(login::<S, M, R, U, W>))
        .route("/callback/apple", post(callback::<S, M, R, U, W>))
        .with_state(state)
}

/// `GET /login/apple` — 302 to Apple's `/auth/authorize`, with CSRF cookie set.
pub async fn login<S, M, R, U, W>(
    State(state): State<Arc<AppleAuthState<S, M, R, U, W>>>,
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

/// `POST /callback/apple` — parse the form-post body, verify CSRF, finish the
/// flow, persist the one-shot first-login name, mint a session.
///
/// The body is taken as raw `String` rather than `axum::Form<...>` so we hand
/// it to [`AppleCallbackForm::parse`] verbatim — Apple's `user` field is a
/// JSON blob inside a urlencoded body, and axum's typed-form extractor would
/// lose it.
pub async fn callback<S, M, R, U, W>(
    State(state): State<Arc<AppleAuthState<S, M, R, U, W>>>,
    headers_in: HeaderMap,
    body: String,
) -> Result<Response, RouteError>
where
    S: OidcFlowStore + Send + Sync + 'static,
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
{
    let form = AppleCallbackForm::parse(&body)?;
    let state_param = form.state.secret().to_owned();

    // CSRF binding — same shape as Google, but the cookie was set with
    // SameSite=None so it actually arrives on this cross-site POST.
    let cookie_value = headers_in
        .get(header::COOKIE)
        .and_then(|h| h.to_str().ok())
        .and_then(|raw| read_cookie(raw, &state.cookie.name).map(str::to_owned))
        .ok_or(RouteError::MissingCsrfCookie)?;
    if cookie_value != state_param {
        return Err(RouteError::CsrfStateMismatch);
    }

    let now = now_unix();
    let verified: AppleVerified = state
        .provider
        .finish_form_post(form, &state.http, now)
        .await?;

    let session = resolve_user_and_establish(
        &state.authority,
        verified.id_token,
        verified.first_login,
        now,
    )
    .await?;
    let body_out = SessionBody::from_new_session(session);

    let mut headers_out = HeaderMap::new();
    let clear = state.cookie.clear_cookie();
    if let Ok(v) = HeaderValue::from_str(&clear) {
        headers_out.insert(header::SET_COOKIE, v);
    }
    Ok((StatusCode::OK, headers_out, Json(body_out)).into_response())
}

/// Map Apple's verified id_token + first-login name into a User and start a
/// session. The `first_login` arrives only on the user's first auth; on
/// subsequent logins it's empty and the stored name is unchanged.
async fn resolve_user_and_establish<M, R, U, W>(
    authority: &Arc<SessionAuthority<M, R, U, W>>,
    verified: VerifiedIdToken,
    first_login: FirstLoginName,
    now: i64,
) -> Result<cheers_server::NewSession, RouteError>
where
    M: TokenMinter + Send + Sync,
    R: RefreshStore,
    U: UserStore,
    W: RevocationWriter,
{
    let provider_key = ProviderKey::OidcApple;
    let users = authority.users();
    let user = match users.find_by_provider(&provider_key, &verified.subject).await? {
        Some(u) => u,
        None => {
            let mut new_user = NewUser::new();
            if let Some(e) = verified.email.as_deref() {
                new_user = new_user.with_email(e);
            }
            // Apple's name comes from the one-shot `user` form field; the
            // id_token doesn't carry `name`. If first_login is empty, we leave
            // name unset — products can prompt for it.
            if let Some(n) = first_login.as_str() {
                new_user = new_user.with_name(n);
            }
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
            DeviceBinding::OidcApple,
            now,
        )
        .await?;
    Ok(session)
}

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
