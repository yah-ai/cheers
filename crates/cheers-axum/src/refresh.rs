//! Refresh route — `POST /refresh` (R730).
//!
//! The RFC 6749 §6 `refresh_token` grant over
//! [`SessionAuthority::rotate`]: spend the presented refresh token, hand back
//! a fresh access token plus its rotated successor as the same [`SessionBody`]
//! every sign-in ceremony returns. Rotation + reuse detection are
//! cheers-server's ([`RefreshRotator`](cheers_server::RefreshRotator)): a
//! replayed token revokes its whole chain, so the newer token dies with it.
//!
//! ## Request / response
//!
//! `POST /refresh` with `{"refresh_token": "<opaque secret>"}` →
//! `200` [`SessionBody`]. A spent, revoked, expired or unknown token — or one
//! whose device has no recorded binding — is a `401 unauthorized`, one answer
//! for all of them so the door is not an oracle for which one it was.
//!
//! ## Where the binding comes from
//!
//! The refresh record carries no [`DeviceBinding`](cheers_core::DeviceBinding)
//! (R018, guide by omission), so this door asks the state's
//! [`BindingResolver`] for the binding of the chain's `(user, device)`.
//! [`DirectoryBindings`] adapts the product's
//! [`SessionDirectory`] — the rows its [`SessionRecorder`] wrote at sign-in —
//! which is the intended wiring. No binding → refused before the token is
//! spent; cheers never guesses a binding or mints an unbound token.
//!
//! On success the rotated session is re-recorded through the
//! [`SessionRecorder`], so `GET /me/sessions` reports the extended chain
//! expiry.
//!
//! ## Rate limiting
//!
//! Like `magic_link::router`, this router ships no limiter of its
//! own: cheers-axum is framework glue, and the right key (client IP, proxy
//! header, …) is deployment knowledge. Layer the product's limiter onto the
//! router this returns, exactly as for the magic-link router.
//!
//! ## Wiring
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use axum::Router;
//! # use cheers_axum::me::SessionDirectory;
//! # use cheers_axum::me::SessionRecorder;
//! # use cheers_axum::refresh::{router, DirectoryBindings, RefreshAuthState};
//! # use cheers_server::SessionAuthority;
//! # fn run<M, R, U, W, D>(authority: Arc<SessionAuthority<M, R, U, W>>, sessions: Arc<D>)
//! # where
//! #     M: cheers_core::TokenMinter + Send + Sync + 'static,
//! #     R: cheers_server::RefreshStore + 'static,
//! #     U: cheers_server::UserStore + 'static,
//! #     W: cheers_server::RevocationWriter + 'static,
//! #     D: SessionDirectory + SessionRecorder + 'static,
//! # {
//! let state = RefreshAuthState {
//!     authority,
//!     // The same rows the sign-in ceremonies record into.
//!     bindings: Arc::new(DirectoryBindings(sessions.clone())),
//!     recorder: sessions,
//! };
//! let app: Router = Router::new().nest("/auth", router(Arc::new(state)));
//! # }
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::routing::post;
use serde::Deserialize;

use cheers_core::{DeviceBinding, DeviceId, Error, RefreshError, StoreError, TokenMinter, UserId};
use cheers_server::{
    BindingResolver, RefreshStore, RevocationWriter, SessionAuthority, UserStore,
};

use crate::error::RouteError;
use crate::me::{SessionDirectory, SessionRecorder};
use crate::session::SessionBody;

/// State bundle held by the refresh handler.
pub struct RefreshAuthState<M, R, U, W> {
    pub authority: Arc<SessionAuthority<M, R, U, W>>,
    /// Supplies the binding the successor access token is minted with. Wire
    /// [`DirectoryBindings`] over the product's session rows; a resolver that
    /// answers `None` refuses the refresh (401) without spending the token.
    pub bindings: Arc<dyn BindingResolver>,
    /// Re-records the rotated session so `GET /me/sessions` shows the
    /// extended expiry. Usually the same object the sign-in ceremonies hold.
    pub recorder: Arc<dyn SessionRecorder>,
}

impl<M, R, U, W> std::fmt::Debug for RefreshAuthState<M, R, U, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RefreshAuthState").finish_non_exhaustive()
    }
}

/// [`BindingResolver`] over a product's [`SessionDirectory`]: the binding of
/// `(user, device)` is the one on that device's live session row.
///
/// The directory filters revoked + expired rows, so a device revoked from
/// `DELETE /me/sessions/{device_id}` stops resolving and its refresh token
/// stops rotating here even before the chain itself is revoked.
pub struct DirectoryBindings<D: ?Sized>(pub Arc<D>);

impl<D: ?Sized> std::fmt::Debug for DirectoryBindings<D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirectoryBindings").finish_non_exhaustive()
    }
}

#[async_trait]
impl<D: SessionDirectory + ?Sized> BindingResolver for DirectoryBindings<D> {
    async fn resolve_binding(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        now: i64,
    ) -> Result<Option<DeviceBinding>, StoreError> {
        Ok(self
            .0
            .list_sessions(user_id, now)
            .await?
            .into_iter()
            .find(|row| &row.device_id == device_id)
            .map(|row| row.binding))
    }
}

/// Build a router mounting `POST /refresh`. The product nests it beside the
/// sign-in routers (conventionally under `/auth`).
pub fn router<M, R, U, W>(state: Arc<RefreshAuthState<M, R, U, W>>) -> Router
where
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
{
    Router::new()
        .route("/refresh", post(refresh::<M, R, U, W>))
        .with_state(state)
}

/// `POST /refresh` request body.
#[derive(Debug, Clone, Deserialize)]
pub struct RefreshBody {
    pub refresh_token: String,
}

/// `POST /refresh` — rotate the presented refresh token into a fresh session.
pub async fn refresh<M, R, U, W>(
    State(state): State<Arc<RefreshAuthState<M, R, U, W>>>,
    Json(body): Json<RefreshBody>,
) -> Result<Json<SessionBody>, RouteError>
where
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
{
    let now = now_unix();
    let session = state
        .authority
        .rotate(&body.refresh_token, state.bindings.as_ref(), now)
        .await
        .map_err(map_rotate_error)?;
    // Unlike a sign-in, a recorder failure here does NOT fail the request.
    // The token is already spent: withholding its successor would turn the
    // client's retry into a replay and revoke the chain. The device row this
    // extends already exists (its binding is what we just minted with), so
    // the cost of a missed write is a stale expiry on /me/sessions until the
    // next rotation — not an invisible session.
    if let Err(e) = state.recorder.record_new_session(&session).await {
        tracing::warn!(error = %e, "cheers-axum refresh: re-recording rotated session failed");
    }
    Ok(Json(SessionBody::from_new_session(session)))
}

/// Every refusal of the refresh grant is one `401`: which of spent / revoked
/// / expired / unknown / unbound it was stays server-side. Store failures
/// remain 500s — they are ours, not the client's.
fn map_rotate_error(err: Error) -> RouteError {
    match err {
        Error::Refresh(RefreshError::Store(e)) => RouteError::Store(e.to_string()),
        Error::Refresh(_) => RouteError::Unauthorized,
        other => other.into(),
    }
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}
