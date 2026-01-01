//! Magic-link routes — `POST /magic-link/request` + `GET /magic-link/verify`.
//!
//! The `request` handler mints a PASETO v4.local token bound to the supplied
//! email, builds a click-through URL via [`MagicLinkProvider`], renders it
//! through a [`MagicLinkEmail`] template, and hands the message to a
//! [`Mailer`]. The `verify` handler reads the token out of the query string,
//! atomically marks its `jti` as used (replay → [`RouteError::AlreadyUsed`]),
//! finds-or-creates a `User` keyed on `ProviderKey::Email`, and establishes a
//! session with `DeviceBinding::EmailMagicLink`.
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
//! # use cheers::email::magic_link::{MagicLinkCodec, MagicLinkProvider, MagicLinkUrlBuilder, MemoryUsedJtiStore};
//! # use cheers::email::{CapturingMailer, MagicLinkEmail};
//! # use cheers_axum::magic_link::{router, MagicLinkAuthState};
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
//! let provider = Arc::new(MagicLinkProvider::new(
//!     MagicLinkCodec::new(&[7u8; 32], 900)?,
//!     MagicLinkUrlBuilder::new("https://app.example/auth/magic-link/verify"),
//!     MemoryUsedJtiStore::new(),
//! ));
//! let mailer = Arc::new(CapturingMailer::new());
//! let template = MagicLinkEmail::new("Acme", "Acme <noreply@acme.example>");
//!
//! let state = MagicLinkAuthState {
//!     provider,
//!     mailer,
//!     authority,
//!     template,
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

use cheers::email::magic_link::{MagicLinkProvider, UsedJtiStore};
use cheers::email::{MagicLinkEmail, Mailer};
use cheers_core::{DeviceBinding, DeviceId, TokenMinter};
use cheers_server::{
    NewUser, ProviderKey, RefreshStore, RevocationWriter, SessionAuthority, UserStore,
};

use crate::error::RouteError;
use crate::session::SessionBody;

/// State bundle held by the magic-link handlers.
pub struct MagicLinkAuthState<M, R, U, W, S, MA> {
    pub provider: Arc<MagicLinkProvider<S>>,
    pub mailer: Arc<MA>,
    pub authority: Arc<SessionAuthority<M, R, U, W>>,
    pub template: MagicLinkEmail,
}

impl<M, R, U, W, S, MA> std::fmt::Debug for MagicLinkAuthState<M, R, U, W, S, MA> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MagicLinkAuthState")
            .field("template", &self.template)
            .finish_non_exhaustive()
    }
}

/// Build a router mounting `POST /magic-link/request` + `GET /magic-link/verify`.
pub fn router<M, R, U, W, S, MA>(state: Arc<MagicLinkAuthState<M, R, U, W, S, MA>>) -> Router
where
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
    S: UsedJtiStore + 'static,
    MA: Mailer + 'static,
{
    Router::new()
        .route("/magic-link/request", post(request::<M, R, U, W, S, MA>))
        .route("/magic-link/verify", get(verify::<M, R, U, W, S, MA>))
        .with_state(state)
}

#[derive(Debug, Clone, Deserialize)]
pub struct RequestBody {
    pub email: String,
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
pub async fn request<M, R, U, W, S, MA>(
    State(state): State<Arc<MagicLinkAuthState<M, R, U, W, S, MA>>>,
    Json(body): Json<RequestBody>,
) -> Result<Json<RequestAck>, RouteError>
where
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
    S: UsedJtiStore + 'static,
    MA: Mailer + 'static,
{
    let now = now_unix();
    let req = state.provider.request(&body.email, now).await?;
    let msg = state.template.render(&body.email, &req);
    state.mailer.send(&msg).await?;
    Ok(Json(RequestAck { ok: true }))
}

#[derive(Debug, Clone, Deserialize)]
pub struct VerifyQuery {
    pub token: String,
}

/// `GET /magic-link/verify?token=...` — consume the token, resolve / create
/// the user, mint a session.
pub async fn verify<M, R, U, W, S, MA>(
    State(state): State<Arc<MagicLinkAuthState<M, R, U, W, S, MA>>>,
    Query(q): Query<VerifyQuery>,
) -> Result<Json<SessionBody>, RouteError>
where
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
    S: UsedJtiStore + 'static,
    MA: Mailer + 'static,
{
    let now = now_unix();
    let claims = state.provider.consume(&q.token, now).await?;
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
