//! Magic-link routes — `POST /magic-link/request`, `POST /magic-link/redeem`,
//! and the legacy `GET /magic-link/verify`.
//!
//! The `request` handler mints one grant for the supplied email (optionally
//! bound to an S256 `challenge`, CHE-R961), builds its URLs via
//! [`MagicLinkProvider`], renders them through a [`MagicLinkEmail`] template,
//! and hands the message to a [`Mailer`]. `redeem` takes a JSON body —
//! `{token}`, `{token, verifier}` or `{code, verifier}` (noisetable W275 §5) —
//! so nothing secret rides a query string; it burns the whole grant
//! (replay → [`RouteError::AlreadyUsed`]), finds-or-creates a `User` keyed on
//! `ProviderKey::Email`, and establishes a session with
//! `DeviceBinding::EmailMagicLink`. Its only uncollapsed refusal is
//! [`RouteError::BoundElsewhere`].
//!
//! `verify` is `redeem`'s `{token}` row read off the query string. It stays
//! until noisetable deletes `/account`'s `?token=` read, then goes.
//!
//! ## Token confidentiality vs response shape
//!
//! `request` returns an *empty acknowledgement* (`{ok: true}`) — never the
//! token. The token lives in the email body only; an attacker who can read
//! `request`'s response cannot use it to log in as the requested address.
//!
//! ## Email is *inside* the token
//!
//! [`MagicLinkProvider`] pins the email into the signed token claims and
//! `verify` reads it from the verified claims (not from a query param). An
//! attacker who steals one valid token cannot re-aim it at another address
//! by editing the URL. See [`cheers::email::magic_link`] for the upstream
//! contract this leans on.
//!
//! ## Wiring
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use axum::Router;
//! # use cheers::email::magic_link::{MagicLinkCodec, MagicLinkProvider, MagicLinkUrlBuilder, MemoryMagicLinkCodeStore, MemoryUsedJtiStore};
//! # use cheers::email::{CapturingMailer, MagicLinkEmail};
//! # use cheers_axum::magic_link::{router, MagicLinkAuthState};
//! # use cheers_axum::me::NoSessionRecorder;
//! # use cheers_server::SessionAuthority;
//! # async fn run<M, R, U, W>(
//! #     authority: Arc<SessionAuthority<M, R, U, W>>,
//! # ) -> Result<(), Box<dyn std::error::Error>>
//! # where
//! #     M: cheers_core::TokenMinter + Send + Sync + 'static,
//! #     R: cheers_server::RefreshStore + 'static,
//! #     U: cheers_server::UserStore + 'static,
//! #     W: cheers_server::RevocationWriter + 'static,
//! # {
//! let provider = Arc::new(
//!     MagicLinkProvider::new(
//!         MagicLinkCodec::new(&[7u8; 32], 900)?,
//!         MagicLinkUrlBuilder::new("https://app.example/auth/sign-in").in_fragment(),
//!         MemoryUsedJtiStore::new(),
//!         MemoryMagicLinkCodeStore::new(),
//!     )
//!     .with_app_urls(MagicLinkUrlBuilder::new("https://link.app.example/sign-in").in_fragment()),
//! );
//! let mailer = Arc::new(CapturingMailer::new());
//! let template = MagicLinkEmail::new("Acme", "Acme <noreply@acme.example>");
//!
//! let state = MagicLinkAuthState {
//!     provider,
//!     mailer,
//!     authority,
//!     template,
//!     // Swap in your own `SessionRecorder` to power `GET /me/sessions`.
//!     recorder: Arc::new(NoSessionRecorder),
//! };
//!
//! let app: Router = Router::new().nest("/auth", router(Arc::new(state)));
//! # Ok(()) }
//! ```

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Query, State};
use axum::routing::{get, post};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use cheers::email::magic_link::{
    MagicLinkClaims, MagicLinkCodeStore, MagicLinkProvider, MagicLinkRedemption, UsedJtiStore,
};
use cheers::email::{MagicLinkEmail, Mailer};
use cheers_core::{DeviceBinding, DeviceId, TokenMinter};
use cheers_server::{
    NewUser, ProviderKey, RefreshStore, RevocationWriter, SessionAuthority, UserStore,
};

use crate::error::RouteError;
use crate::me::SessionRecorder;
use crate::session::SessionBody;

/// State bundle held by the magic-link handlers.
pub struct MagicLinkAuthState<M, R, U, W, S, C, MA> {
    pub provider: Arc<MagicLinkProvider<S, C>>,
    pub mailer: Arc<MA>,
    pub authority: Arc<SessionAuthority<M, R, U, W>>,
    pub template: MagicLinkEmail,
    /// Where a freshly established session is handed to the product, so it
    /// can answer `GET /me/sessions` later. Required rather than optional:
    /// this ceremony is one of only three places a [`DeviceBinding`] exists,
    /// and a product that silently skipped it would show the user a device
    /// list missing the device they just signed in on. Wire
    /// [`NoSessionRecorder`](crate::me::NoSessionRecorder) to opt out on
    /// purpose.
    pub recorder: Arc<dyn SessionRecorder>,
}

impl<M, R, U, W, S, C, MA> std::fmt::Debug for MagicLinkAuthState<M, R, U, W, S, C, MA> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MagicLinkAuthState")
            .field("template", &self.template)
            .finish_non_exhaustive()
    }
}

/// Build a router mounting `POST /magic-link/request`, `POST /magic-link/redeem`
/// and `GET /magic-link/verify`.
pub fn router<M, R, U, W, S, C, MA>(state: Arc<MagicLinkAuthState<M, R, U, W, S, C, MA>>) -> Router
where
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
    S: UsedJtiStore + 'static,
    C: MagicLinkCodeStore + 'static,
    MA: Mailer + 'static,
{
    Router::new()
        .route("/magic-link/request", post(request::<M, R, U, W, S, C, MA>))
        .route("/magic-link/redeem", post(redeem::<M, R, U, W, S, C, MA>))
        .route("/magic-link/verify", get(verify::<M, R, U, W, S, C, MA>))
        .with_state(state)
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequestBody {
    pub email: String,
    /// `base64url(SHA-256(verifier))`. An app always sends one; a browser
    /// form never does. Present, the grant's app token is bound to it and a
    /// sign-in code is minted (W275 §4).
    #[serde(default)]
    pub challenge: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct RequestAck {
    pub ok: bool,
}

/// `POST /magic-link/request` — mint a token for `email`, mail the URL,
/// return an empty acknowledgement.
///
/// Returns `RouteError::InvalidEmail` if the address fails the cheap shape
/// check ([`MagicLinkProvider::request`]). Note that this leaks *which*
/// addresses are well-formed; products that want to also hide that from
/// untrusted callers should swap this handler for one that always returns
/// `{ok: true}` and queues the actual mailer call.
pub async fn request<M, R, U, W, S, C, MA>(
    State(state): State<Arc<MagicLinkAuthState<M, R, U, W, S, C, MA>>>,
    Json(body): Json<RequestBody>,
) -> Result<Json<RequestAck>, RouteError>
where
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
    S: UsedJtiStore + 'static,
    C: MagicLinkCodeStore + 'static,
    MA: Mailer + 'static,
{
    let now = now_unix();
    let req = state
        .provider
        .request(&body.email, body.challenge.as_deref(), now)
        .await?;
    let msg = state.template.render(&body.email, &req);
    state.mailer.send(&msg).await?;
    Ok(Json(RequestAck { ok: true }))
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerifyQuery {
    pub token: String,
}

/// Body of `POST /magic-link/redeem` — exactly one of `token` / `code`;
/// `verifier` is required beside `code` and optional beside `token`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedeemBody {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub verifier: Option<String>,
}

/// `POST /magic-link/redeem` — redeem a token or a code, burn the grant,
/// resolve / create the user, mint a session.
pub async fn redeem<M, R, U, W, S, C, MA>(
    State(state): State<Arc<MagicLinkAuthState<M, R, U, W, S, C, MA>>>,
    Json(body): Json<RedeemBody>,
) -> Result<Json<SessionBody>, RouteError>
where
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
    S: UsedJtiStore + 'static,
    C: MagicLinkCodeStore + 'static,
    MA: Mailer + 'static,
{
    let now = now_unix();
    let redemption = match (&body.token, &body.code, &body.verifier) {
        (Some(token), None, verifier) => MagicLinkRedemption::Token {
            token,
            verifier: verifier.as_deref(),
        },
        (None, Some(code), Some(verifier)) => MagicLinkRedemption::Code { code, verifier },
        _ => return Err(RouteError::MagicLinkToken("malformed redeem body".into())),
    };
    let claims = state.provider.redeem(redemption, now).await?;
    sign_in(&state, &claims, now).await
}

/// `GET /magic-link/verify?token=...` — `redeem`'s `{token}` row off the
/// query string. Kept until noisetable's `/account` stops reading `?token=`.
pub async fn verify<M, R, U, W, S, C, MA>(
    State(state): State<Arc<MagicLinkAuthState<M, R, U, W, S, C, MA>>>,
    Query(q): Query<VerifyQuery>,
) -> Result<Json<SessionBody>, RouteError>
where
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
    S: UsedJtiStore + 'static,
    C: MagicLinkCodeStore + 'static,
    MA: Mailer + 'static,
{
    let now = now_unix();
    let redemption = MagicLinkRedemption::Token {
        token: &q.token,
        verifier: None,
    };
    let claims = state.provider.redeem(redemption, now).await?;
    sign_in(&state, &claims, now).await
}

/// Find-or-create the claims' email user and establish an
/// `EmailMagicLink` session for it.
async fn sign_in<M, R, U, W, S, C, MA>(
    state: &MagicLinkAuthState<M, R, U, W, S, C, MA>,
    claims: &MagicLinkClaims,
    now: i64,
) -> Result<Json<SessionBody>, RouteError>
where
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
{
    let users = state.authority.users();
    let provider_key = ProviderKey::Email;

    let user = match users.find_by_provider(&provider_key, &claims.email).await? {
        Some(u) => u,
        None => {
            let u = users
                .create(NewUser::new().with_email(&claims.email))
                .await?;
            users
                .link_provider(&u.id, &provider_key, &claims.email)
                .await?;
            u
        }
    };

    let device_id = DeviceId::new(generate_device_id());
    let session = state
        .authority
        .establish(
            user.id.clone(),
            device_id,
            DeviceBinding::EmailMagicLink,
            now,
        )
        .await?;
    state.recorder.record_new_session(&session).await?;
    Ok(Json(SessionBody::from_new_session(session)))
}

/// 128-bit random device id, base64url-no-pad. Same shape the OIDC routes
/// generate — one verify call = one device row.
fn generate_device_id() -> String {
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
        assert_eq!(a.len(), 22);
        assert!(!a.contains('='));
    }
}
