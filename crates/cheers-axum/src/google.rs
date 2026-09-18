//! Google OIDC routes — two ways in, one user row out.
//!
//! **Browser redirect** — `GET /auth/login/google` + `GET
//! /auth/callback/google`. The login handler stashes a flow, sets a CSRF
//! cookie, and redirects the browser to Google. The callback handler verifies
//! the cookie, finishes the flow against Google's `/token` endpoint, maps the
//! resulting `id_token` to a `cheers_core::User` via the
//! [`UserStore`](cheers_server::UserStore), mints a session through the
//! [`SessionAuthority`](cheers_server::SessionAuthority), and returns a
//! [`SessionBody`].
//!
//! **Native sign-in** — `GET /auth/google/id-token/nonce` + `POST
//! /auth/google/id-token`. Android's Credential Manager (`GetGoogleIdOption`)
//! and Sign in with Apple on iOS hand the *app* a signed `id_token`; there is
//! no browser, no redirect URI, and no code to redeem. The app takes a nonce
//! from the first route, feeds it to the platform API, and posts the resulting
//! token back to the second. Both routes end at the same
//! `(ProviderKey::OidcGoogle, sub)` lookup, so a human who signs in on the web
//! and then on their phone is one user, not two.
//!
//! The nonce is not optional. Google's `exp` is an hour wide, so a token
//! captured off a compromised client is replayable for that long; the
//! server-minted, single-use nonce narrows that to one exchange. The flow store
//! does the narrowing — the same store the redirect flow uses.
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
//!
//! @yah:ticket(R726-F1, "cheers: POST /auth/google/id-token — exchange a Credential Manager Google ID token for a session")
//! @yah:status(review)
//! @yah:at(2026-09-12T08:40:40Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R726)
//! @yah:gotcha("THE MISSING PRIMITIVE IS ONE LEVEL DOWN, IN cheers NOT cheers-axum. OidcProvider exposes begin() and finish() and NOTHING that verifies a bare id_token — checked the full pub fn list of oss/cheers/crates/cheers/src/providers/oidc_generic.rs and providers/google.rs. GoogleProvider derefs to OidcProvider and exposes only from_provider_metadata / discover / into_inner, so the inner openidconnect CoreClient (which does have id_token_verifier()) is not reachable from outside. So this ticket is TWO pieces: (1) a verify_id_token(&self, raw) -> Result<VerifiedIdToken, OidcError> on OidcProvider, reusing the same VerifiedIdToken mapping finish() already produces (issuer/subject/email/email_verified/name); (2) the axum route over it. Note the NONCE problem: finish() binds a nonce it minted, and a Credential Manager token carries a nonce chosen by GetGoogleIdOption.setNonce — so the route has to either require and check a client-supplied nonce or document why it does not, and audience must be checked against the same server client id the Android side sent.")
//! @yah:handoff("SERVER SIDE LANDED. Two pieces as the gotcha specified, plus a third the gotcha's NONCE problem forced. (1) cheers: OidcProvider::verify_id_token(raw, &Nonce) at oss/cheers/crates/cheers/src/providers/oidc_generic.rs — parses a bare compact-JWS id_token and runs the SAME verifier finish() runs (JWKS signature, iss, aud vs the configured client_id, exp) plus a constant-time nonce match, no network I/O since the JWKS came with the provider metadata. Nonce is MANDATORY, not Option: a client-chosen nonce proves nothing. (2) The store-backed pair begin_id_token(now) -> Nonce / finish_id_token(raw, nonce_secret, now), which mint-and-stash and atomically take from the SAME OidcFlowStore the redirect flow uses — so replay is bounded by one exchange rather than by Google's hour-wide exp. (3) Axum: GET /auth/google/id-token/nonce + POST /auth/google/id-token {id_token, nonce} in crates/cheers-axum/src/google.rs, both reusing resolve_user_and_establish so the browser callback and the native exchange land on ONE (ProviderKey::OidcGoogle, sub) row.")
//! @yah:handoff("CLIENT SIDE LANDED TOO — the ticket's next bullet, done in the same pass rather than filed. app/yah/mobile/src/auth.rs authenticate() now runs the three-leg exchange: GET <base>/auth/google/id-token/nonce BEFORE the sheet (Credential Manager takes the nonce as an INPUT, so there is no fetching it afterwards) -> sheet with google_nonce -> POST <base>/auth/google/id-token. google_filter_by_authorized_accounts flipped true -> false, since the server exchange creates the user row on first sight of a sub, so a first-ever Google sign-in is now a supported path. If the nonce leg fails the Google option is simply NOT OFFERED (google_server_client_id is dropped) — a chooser whose token cannot be exchanged is worse than no chooser, and a cheers outage must not cost the user their passkey.")
//! @yah:verify("cargo test --manifest-path oss/cheers/crates/cheers/Cargo.toml --all-features = 169 passed / 0 failed + 12 doctests. The 7 new provider tests (providers::google::tests::id_token_*) cover: happy round-trip, nonce single-use replay -> UnknownFlow, client-chosen nonce -> IdToken, foreign audience -> IdToken, expired token -> IdToken, expired stash -> FlowExpired, and a nonce-only flow walked into finish() -> NotACodeFlow.")
//! @yah:verify("cargo test --manifest-path oss/cheers/crates/cheers-axum/Cargo.toml --all-features = 69 + 60 + 12 passed / 0 failed. New tests/google_id_token.rs (6, registered in tests/main.rs which is the single integration root): exchange creates user + mints session, replay -> 400 unknown_flow, foreign/absent nonce -> 401 id_token_invalid, foreign audience -> 401, empty fields -> 400, and browser_callback_and_native_exchange_share_one_user — the same Google sub arriving through GET /callback/google and POST /google/id-token yields ONE user_id and two device_ids.")
//! @yah:verify("Client side: cargo test -p mobile --lib = 50 passed / 0 failed; cargo test -p tauri-plugin-yah-credentials = 9 passed / 0 failed. The one a host-only run silently skips, and I did NOT skip it: cargo check -p mobile --target aarch64-linux-android --lib = Finished, exit 0 — that is the only build that compiles the cfg(target_os=\"android\") persist() where the new Binding -> DeviceBinding mapping lives. It needs the NDK on PATH, which is not there by default: PATH=$HOME/Library/Android/sdk/ndk/AndroidNDK13676358.app/Contents/NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin:$PATH with CC_aarch64_linux_android=aarch64-linux-android24-clang, AR_aarch64_linux_android=llvm-ar, CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=aarch64-linux-android24-clang.")
//! @yah:verify("NOT VERIFIED, and it is the ticket's original acceptance test: the on-device leg. It needs a real Google OAuth web client id, a deployed cheers configured with that SAME id as its audience, and the shared emulator — none of which I hold. Everything below the sheet is exercised by the tests above against a wiremock IdP minting real RS256 tokens; what remains unproven is that Google's Credential Manager echoes setNonce verbatim into the nonce claim (see @yah:assumes) and that the sheet renders the Google row. Run: configure google_server_client_id in /data/user/0/dev.yah.mobile/camp.json, invoke auth_authenticate, expect AuthReport::SignedIn.")
//! @yah:assumes("Google echoes GetGoogleIdOption.setNonce VERBATIM into the id_token's nonce claim — i.e. it does not hash it the way Sign in with Apple hashes ASAuthorizationOpenIDRequest.nonce. Read off Google's documented behaviour, NOT verified against a live token here (no device, no real client id). If it turns out Google hashes, the symptom is that every exchange answers 401 id_token_invalid with a nonce mismatch, and the fix is one line in cheers-axum google.rs id_token(): compare against sha256(nonce) instead of the raw secret. Firebase's own Credential Manager sample hashes the nonce on the CLIENT and passes the digest to setNonce, which is consistent with verbatim echo.")
//! @yah:gotcha("BREAKING CHANGE INSIDE cheers, pre-1.0 per the root CLAUDE.md's break-it-don't-tape-it rule: OidcFlowState.pkce_verifier is now Option<PkceCodeVerifier>. A native id_token flow has no authorization code, so there is genuinely no verifier to stash, and storing a throwaway one in a security crate would read as intentional to the next person. from_parts() takes Option, pkce_verifier() returns Option<&_>, into_parts() returns Option, and there is a new nonce_only() constructor. finish() (and apple::redirect's own finish) answer the new OidcError::NotACodeFlow on None. Call sites fixed in the same pass: cheers/src/providers/apple/redirect.rs (3) and the oidc_generic test fixtures (4). Any out-of-tree OidcFlowStore impl that serializes OidcFlowState needs the same widening.")
//! @yah:gotcha("DISCOVERED WORK, beyond the ticket title, all of it in this pass. (1) app/yah/mobile/src/auth.rs persist() hardcoded DeviceBinding::Passkey, so a Google session would have been recorded in the Keystore vault as a passkey one. finish() now takes a local Binding enum (cheers-core is an Android-ONLY dep of that crate, so cheers_core::DeviceBinding cannot appear in host-compiled code) and persist() maps it at the one point both are in scope. (2) The AuthReport code googleIdExchangeMissing is GONE — authenticate() intercepts GoogleId before non_passkey() sees it, so a GoogleId reaching non_passkey() can only have come from register(), whose ceremony is create_passkey and cannot enrol an OAuth account; it now reports googleIdNotAPasskey. Its test was renamed and still pins that the token never reaches the report. (3) tauri-plugin-yah-credentials gained GetCredentialArgs.google_nonce + Kotlin `var googleNonce`, plus a new test the_kotlin_args_class_carries_every_serialized_field that walks the serialized JSON keys and asserts each has a `var <field>` in the .kt — a field added on only one side is silently dropped by Jackson, which for a nonce means a token with no nonce claim and a server 401 with no visible cause. (4) R726-F20's gotcha in crates/yah/rpc/src/lib.rs:585 was disproven by this work; a supersession gotcha was appended there rather than rewriting another ticket's text.")
//! @yah:handoff("MOBILE LEG LANDED TOO (the @yah:next bullet, done in-session). app/yah/mobile/src/auth.rs authenticate() now: GETs /auth/google/id-token/nonce BEFORE raising the sheet (Credential Manager takes the nonce as an INPUT — there is no fetching it afterwards), passes it through the new GetCredentialArgs.google_nonce -> Kotlin GetGoogleIdOption.setNonce, intercepts CredentialOutcome::GoogleId before non_passkey() and POSTs {id_token, nonce} to /auth/google/id-token, then finishes on the same SessionBody path the passkey route uses. google_filter_by_authorized_accounts flipped true->false so a first-ever sign-in sees every account. If the nonce GET fails the Google option is simply not offered (a chooser whose token cannot be exchanged is worse than no chooser, and a down auth server must not cost the user their passkey). Plugin surface: crates/yah/tauri-plugin-yah-credentials/src/models.rs + android/src/main/java/YahCredentialsPlugin.kt.")
//! @yah:verify("cargo test --manifest-path oss/cheers/Cargo.toml --workspace: 0 failures. 13 new tests — 7 unit in crates/cheers/src/providers/google.rs (round trip, single-use nonce, client-chosen nonce refused, foreign audience refused, expired token refused, expired stash refused, nonce-only flow refused as a code flow) and 6 HTTP-level in the new crates/cheers-axum/tests/google_id_token.rs (200 + user row, replay -> 400 unknown_flow, foreign/absent nonce -> 401 id_token_invalid, foreign aud -> 401, empty fields -> 400, and browser_callback_and_native_exchange_share_one_user which pins that both doors reach ONE user row with two device rows).")
//! @yah:verify("cargo test -p mobile -p tauri-plugin-yah-credentials: 50 + 9 pass, including a new the_kotlin_args_class_carries_every_serialized_field that walks GetCredentialArgs' serialized keys and asserts each has a matching `var <field>` in the Kotlin data class — a field Jackson cannot see is silently dropped, which for googleNonce would mean a nonce-less token and a server refusal with no visible cause. Android target compiled too (source scripts/android-env.sh; cargo check -p mobile --target aarch64-linux-android --lib), which is the only build that type-checks the cfg(android) persist() path where the new Binding enum maps onto cheers_core::DeviceBinding.")
//! @yah:assumes("GOOGLE ECHOES setNonce VERBATIM into the id_token's `nonce` claim — not hashed. This is the one link in the chain not verified here: Apple's convention is SHA-256 of the raw nonce and Firebase's Google sample hashes it client-side, so if Google turns out to hash too, every on-device exchange will fail with id_token_invalid and the fix is one line in OidcProvider::finish_id_token (hash the stashed secret before comparing). The on-device verify below settles it.")
//! @yah:gotcha("GET /auth/google/id-token/nonce is unauthenticated and stashes one flow-store entry per call — the same exposure GET /auth/login/google already has, not a new class. MemoryOidcFlowStore::gc is caller-driven (no background timer), so a product on the memory store should tick it; a shared backend (redis/sqlx) expires its own. Also: the deployment's GoogleProvider MUST be constructed with the WEB client id — the same string the phone sends as google_server_client_id — because that is what the token's `aud` carries. Point it at the Android client id and every exchange answers 401 id_token_invalid; azp (which does carry the Android client id) is not checked, openidconnect 4.0.1 leaves that verification commented out.")
//! @yah:gotcha("BREAKING (pre-1.0, per CLAUDE.md 'break it, don't tape it'): OidcFlowState::pkce_verifier is now Option<PkceCodeVerifier>, so from_parts takes Option, pkce_verifier() returns Option<&_>, into_parts returns Option. A native id_token flow genuinely has no code leg, and storing a throwaway verifier beside it would have read as intentional to the next person. Call sites fixed in providers/apple/redirect.rs (3); finish() answers the new OidcError::NotACodeFlow when handed a nonce-only stash, and a test pins that. Also stale-doc sweep: crates/yah/rpc/src/lib.rs:585 (R726-F20's gotcha, ticket in review) still says 'cheers has no route that verifies a bare id_token'. Left intact — it is another ticket's record and peers were editing that file mid-session — but a reviewer should read it as history, not status. app/yah/mobile/README.md and the auth.rs module docs, which said the same thing as documentation, were corrected.")

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};

use cheers::providers::google::GoogleProvider;
use cheers::providers::oidc_generic::{OidcCallback, OidcFlowStore, VerifiedIdToken};
use cheers_core::{DeviceBinding, DeviceId, TokenMinter};
use cheers_server::{
    NewUser, ProviderKey, RefreshStore, RevocationWriter, SessionAuthority, UserStore,
};
use openidconnect::CsrfToken;
use subtle::ConstantTimeEq;

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

/// Build a router mounting the browser redirect pair (`GET /login/google` +
/// `GET /callback/google`) and the native ID-token pair (`GET
/// /google/id-token/nonce` + `POST /google/id-token`). The product mounts it
/// under whatever base path it chose (`/auth`, `/api/auth`, …).
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
        .route("/google/id-token/nonce", get(id_token_nonce::<S, M, R, U, W>))
        .route("/google/id-token", post(id_token::<S, M, R, U, W>))
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
    // Constant-time compare so a timing side-channel can't recover the CSRF
    // secret one byte at a time. A length mismatch short-circuits to non-equal.
    if cookie_value
        .as_bytes()
        .ct_eq(state_param.as_bytes())
        .unwrap_u8()
        != 1
    {
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

// ---------------------------------------------------------------------------
// Native ID-token exchange (Android Credential Manager / iOS)
// ---------------------------------------------------------------------------

/// `GET /google/id-token/nonce` response — the nonce the app must feed into
/// `GetGoogleIdOption.Builder().setNonce(..)`.
#[derive(Debug, Serialize)]
pub struct IdTokenNonceBody {
    /// Opaque secret. Single-use: the exchange consumes it.
    pub nonce: String,
    /// Seconds the nonce stays takeable. Mirrors the provider's
    /// `flow_ttl_seconds`.
    pub expires_in_seconds: i64,
}

/// `POST /google/id-token` request body.
#[derive(Debug, Deserialize)]
pub struct IdTokenRequest {
    /// The raw compact-JWS `id_token` Credential Manager handed the app.
    pub id_token: String,
    /// The nonce from a prior `GET /google/id-token/nonce`, echoed unchanged.
    pub nonce: String,
}

/// `GET /google/id-token/nonce` — mint and stash a single-use nonce.
///
/// The app calls this *before* raising the system credential sheet, passes the
/// returned `nonce` to `GetGoogleIdOption.Builder().setNonce(..)`, and posts it
/// back alongside the token. Without it a captured token could be replayed for
/// the whole hour Google's `exp` allows; with it, the window is one exchange.
pub async fn id_token_nonce<S, M, R, U, W>(
    State(state): State<Arc<GoogleAuthState<S, M, R, U, W>>>,
) -> Result<Response, RouteError>
where
    S: OidcFlowStore + Send + Sync + 'static,
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
{
    let nonce = state.provider.begin_id_token(now_unix()).await?;
    let body = IdTokenNonceBody {
        nonce: nonce.secret().to_owned(),
        expires_in_seconds: state.provider.flow_ttl_seconds(),
    };
    Ok((StatusCode::OK, Json(body)).into_response())
}

/// `POST /google/id-token` — exchange a native Google ID token for a session.
///
/// This is the Credential Manager counterpart to `GET /callback/google`: the
/// browser flow's redirect + code exchange collapses into one signed JWT the
/// IdP already handed the app, so the only things left to check are the ones
/// [`OidcProvider::verify_id_token`] does — signature against Google's JWKS,
/// `iss`, `aud` against the configured **server** (web) client id, `exp`, and
/// the server-minted nonce, taken single-use from the flow store.
///
/// On success the user is resolved through the exact same
/// `(ProviderKey::OidcGoogle, sub)` path the browser callback uses, so one
/// human signing in both ways is one row, not two.
///
/// [`OidcProvider::verify_id_token`]: cheers::providers::oidc_generic::OidcProvider::verify_id_token
pub async fn id_token<S, M, R, U, W>(
    State(state): State<Arc<GoogleAuthState<S, M, R, U, W>>>,
    Json(body): Json<IdTokenRequest>,
) -> Result<Response, RouteError>
where
    S: OidcFlowStore + Send + Sync + 'static,
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
{
    if body.id_token.is_empty() {
        return Err(RouteError::MalformedCallback("empty `id_token`".into()));
    }
    if body.nonce.is_empty() {
        return Err(RouteError::MalformedCallback("empty `nonce`".into()));
    }

    let now = now_unix();
    let verified = state
        .provider
        .finish_id_token(&body.id_token, &body.nonce, now)
        .await?;

    let session = resolve_user_and_establish(&state.authority, verified, now).await?;
    let body = SessionBody::from_new_session(session);
    Ok((StatusCode::OK, Json(body)).into_response())
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
            // Only persist the email when the IdP asserted it's verified — an
            // unverified `email` claim is attacker-controllable and must not
            // seed the account. `email_verified: None` counts as unverified.
            let new_user = match verified.email.as_deref() {
                Some(e) if verified.email_verified == Some(true) => new_user.with_email(e),
                _ => new_user,
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
