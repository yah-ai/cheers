//! `/me/sessions` routes — list and revoke the live sessions on the
//! authenticated user's account.
//!
//! These two endpoints close the loop on the bearer/PASETO response shape the
//! provider modules return: `SessionBody::access_token` is the bearer token a
//! client hands back here as `Authorization: Bearer <paseto>`. The
//! [`EdgeVerifier`] in [`MeAuthState`] checks the signature *and* the
//! revocation set — the same verifier shape a CF Worker would hold — so the
//! origin and the edge agree on what "still valid" means.
//!
//! ## What you list, and where the binding comes from
//!
//! The refresh-token row in [`RefreshStore`] does **not** carry a
//! `DeviceBinding` (the cheers refresh chain is about *which session*, not
//! *how it authenticated*). To surface
//! `[{device_id, binding, issued_at, expires_at, is_current}]` per the ticket
//! spec, the join lives in product code: the product implements
//! [`SessionDirectory`] over its own data (a SQL query joining
//! `refresh_tokens` with whatever table records the last-known binding, or a
//! `last_binding` column on the refresh row itself). This trait stays in
//! `cheers-axum` rather than `cheers-server` so the cheers-server trait
//! surface remains minimal — no new `SessionStore` trait, per the R018
//! design call.
//!
//! ## Revoke semantics
//!
//! `DELETE /me/sessions/{device_id}` calls
//! [`SessionAuthority::revoke_device`](cheers_server::SessionAuthority::revoke_device),
//! which the `UserStore` impl is expected to extend to "also revoke refresh
//! chains for that device" (cheers-sqlx's `PgUserStore` does). That blocks
//! *new* sessions immediately. If the targeted device is the *current*
//! device, the route additionally revokes the current access token's `jti`
//! via [`SessionAuthority::revoke_session`] so the edge stops accepting it
//! within the propagation window. For non-current devices the in-flight
//! access token expires naturally inside the (minutes-scale) access TTL —
//! that bound is documented on [`SessionPolicy`](cheers_server::SessionPolicy).
//!
//! ## Wiring
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use axum::Router;
//! # use cheers_axum::me::{router, MeAuthState, SessionDirectory};
//! # use cheers_server::{EdgeVerifier, SessionAuthority};
//! # async fn run<V, Rd, M, R, U, W, D>(
//! #     edge: Arc<EdgeVerifier<V, Rd>>,
//! #     authority: Arc<SessionAuthority<M, R, U, W>>,
//! #     directory: Arc<D>,
//! # ) -> Result<(), Box<dyn std::error::Error>>
//! # where
//! #     V: cheers_core::TokenVerifier + Send + Sync + 'static,
//! #     Rd: cheers_server::RevocationReader + 'static,
//! #     M: cheers_core::TokenMinter + Send + Sync + 'static,
//! #     R: cheers_server::RefreshStore + 'static,
//! #     U: cheers_server::UserStore + 'static,
//! #     W: cheers_server::RevocationWriter + 'static,
//! #     D: SessionDirectory + 'static,
//! # {
//! let state = MeAuthState { edge, authority, directory };
//! let app: Router = Router::new().nest("/api", router(Arc::new(state)));
//! # Ok(()) }
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{delete, get};
use serde::{Deserialize, Serialize};

use cheers_core::{
    Claims, DeviceBinding, DeviceId, Error, StoreError, TokenMinter, TokenVerifier, UserId,
};
use cheers_server::{
    EdgeVerifier, RefreshStore, RevocationReader, RevocationWriter, SessionAuthority, UserStore,
};

use crate::error::RouteError;

/// Per-device active-session row a [`SessionDirectory`] returns.
///
/// One row per `(user, device)` pair — the directory is responsible for
/// collapsing rotation chains so a device with many historical refresh
/// tokens still shows up once. `binding` is the authentication that minted
/// the session; the directory stores it (the cheers refresh row doesn't).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SessionDescriptor {
    pub device_id: DeviceId,
    pub binding: DeviceBinding,
    /// Unix-seconds when this session was first established (the root
    /// refresh token's `issued_at`, NOT the latest rotation).
    pub issued_at: i64,
    /// Unix-seconds expiry of the active refresh row — when this device
    /// will be forced to re-authenticate.
    pub expires_at: i64,
}

impl SessionDescriptor {
    pub fn new(
        device_id: DeviceId,
        binding: DeviceBinding,
        issued_at: i64,
        expires_at: i64,
    ) -> Self {
        Self {
            device_id,
            binding,
            issued_at,
            expires_at,
        }
    }
}

/// Per-row JSON shape returned by `GET /me/sessions`.
///
/// `is_current` is derived from the bearer token used on the request: the
/// row whose `device_id` matches the verified [`Claims::device`] flips to
/// `true`. Exactly zero or one row is current; clients can switch on it to
/// label "this device" in a sessions UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct SessionListEntry {
    pub device_id: String,
    pub binding: DeviceBinding,
    pub issued_at: i64,
    pub expires_at: i64,
    pub is_current: bool,
}

/// Product-side enumeration of a user's active sessions.
///
/// One row per `(user, device)` — the impl is responsible for filtering out
/// revoked + expired entries and for sourcing `binding` (which the cheers
/// refresh-token row doesn't carry; see the module docs). Order is
/// unspecified.
#[async_trait]
pub trait SessionDirectory: Send + Sync {
    async fn list_sessions(
        &self,
        user_id: &UserId,
        now: i64,
    ) -> Result<Vec<SessionDescriptor>, StoreError>;
}

/// State bundle held by the `/me/sessions` handlers.
///
/// `edge` is the same [`EdgeVerifier`] a CF Worker would hold; an integrated
/// origin can construct one from the symmetric codec it already mints with
/// (any [`cheers_core::Codec`] is both a [`TokenMinter`] and a
/// [`TokenVerifier`]), or from the asymmetric pair
/// (`PasetoV4SecretMinter::verifier()` ⇒ a `PasetoV4PublicVerifier`).
pub struct MeAuthState<V, Rd, M, R, U, W, D> {
    pub edge: Arc<EdgeVerifier<V, Rd>>,
    pub authority: Arc<SessionAuthority<M, R, U, W>>,
    pub directory: Arc<D>,
}

impl<V, Rd, M, R, U, W, D> std::fmt::Debug for MeAuthState<V, Rd, M, R, U, W, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeAuthState").finish_non_exhaustive()
    }
}

/// Build a router mounting `GET /me/sessions` + `DELETE /me/sessions/{device_id}`.
/// The product nests it under whatever base path it chose (`/api`, …).
pub fn router<V, Rd, M, R, U, W, D>(state: Arc<MeAuthState<V, Rd, M, R, U, W, D>>) -> Router
where
    V: TokenVerifier + Send + Sync + 'static,
    Rd: RevocationReader + Send + Sync + 'static,
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
    D: SessionDirectory + Send + Sync + 'static,
{
    Router::new()
        .route("/me/sessions", get(list::<V, Rd, M, R, U, W, D>))
        .route(
            "/me/sessions/{device_id}",
            delete(revoke::<V, Rd, M, R, U, W, D>),
        )
        .with_state(state)
}

/// `GET /me/sessions` — list the authenticated user's active sessions.
pub async fn list<V, Rd, M, R, U, W, D>(
    State(state): State<Arc<MeAuthState<V, Rd, M, R, U, W, D>>>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionListEntry>>, RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    D: SessionDirectory,
{
    let now = now_unix();
    let claims = authenticate(&headers, &state.edge, now).await?;
    let descriptors = state.directory.list_sessions(&claims.sub, now).await?;
    let current = claims.device.clone();
    let entries = descriptors
        .into_iter()
        .map(|d| {
            let is_current = d.device_id == current;
            SessionListEntry {
                device_id: d.device_id.into_inner(),
                binding: d.binding,
                issued_at: d.issued_at,
                expires_at: d.expires_at,
                is_current,
            }
        })
        .collect();
    Ok(Json(entries))
}

/// `DELETE /me/sessions/{device_id}` — revoke a device for the authenticated
/// user. Returns `204 No Content` on success. If the targeted device is the
/// current one, the in-flight access token's `jti` is also revoked so the
/// edge stops accepting it immediately.
pub async fn revoke<V, Rd, M, R, U, W, D>(
    State(state): State<Arc<MeAuthState<V, Rd, M, R, U, W, D>>>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Result<StatusCode, RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    M: TokenMinter + Send + Sync,
    R: RefreshStore,
    U: UserStore,
    W: RevocationWriter,
{
    let now = now_unix();
    let claims = authenticate(&headers, &state.edge, now).await?;
    let target = DeviceId::new(device_id);
    state
        .authority
        .revoke_device(&claims.sub, &target)
        .await
        .map_err(map_authority_error)?;
    if target == claims.device {
        state
            .authority
            .revoke_session(&claims.jti)
            .await
            .map_err(map_authority_error)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Extract the raw token from `Authorization: Bearer <token>`. Returns
/// [`RouteError::MissingBearer`] / [`RouteError::MalformedBearer`] for the
/// two distinct failure modes so a client can tell "didn't send a header"
/// from "sent a header in the wrong shape".
pub fn bearer_from_headers(headers: &HeaderMap) -> Result<&str, RouteError> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .ok_or(RouteError::MissingBearer)?
        .to_str()
        .map_err(|_| RouteError::MalformedBearer)?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .ok_or(RouteError::MalformedBearer)?;
    if token.is_empty() {
        return Err(RouteError::MalformedBearer);
    }
    Ok(token)
}

/// Pull the bearer header and run the [`EdgeVerifier`] over the token at
/// `now`. Maps verification failures to [`RouteError::Unauthorized`].
pub async fn authenticate<V, Rd>(
    headers: &HeaderMap,
    edge: &EdgeVerifier<V, Rd>,
    now: i64,
) -> Result<Claims, RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
{
    let token = bearer_from_headers(headers)?;
    edge.verify_at(token, now).await.map_err(map_verify_error)
}

fn map_verify_error(err: Error) -> RouteError {
    match err {
        // A token that failed the codec layer (bad signature, expired,
        // malformed) is the same outcome from the caller's POV: 401.
        Error::Codec(_) => RouteError::Unauthorized,
        Error::Revoked => RouteError::Unauthorized,
        Error::Store(e) => RouteError::Store(e.to_string()),
        // Refresh / InvalidInput don't surface from EdgeVerifier::verify_at
        // in practice — keep them mapped to the existing buckets rather than
        // letting them silently turn into 401.
        Error::Refresh(e) => RouteError::Store(e.to_string()),
        Error::InvalidInput(msg) => RouteError::Config(msg),
        // cheers_core::Error is #[non_exhaustive] — any future variant gets
        // a generic 500 bridge until a dedicated mapping lands.
        other => RouteError::Store(other.to_string()),
    }
}

fn map_authority_error(err: Error) -> RouteError {
    match err {
        Error::Store(StoreError::NotFound) => RouteError::UnknownDevice,
        other => RouteError::from(other),
    }
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
    fn bearer_from_headers_accepts_canonical_form() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            "Bearer abc123".parse().unwrap(),
        );
        assert_eq!(bearer_from_headers(&h).unwrap(), "abc123");
    }

    #[test]
    fn bearer_from_headers_accepts_lowercase_scheme() {
        // RFC 7235 says the scheme is case-insensitive; some clients lowercase.
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            "bearer abc123".parse().unwrap(),
        );
        assert_eq!(bearer_from_headers(&h).unwrap(), "abc123");
    }

    #[test]
    fn bearer_from_headers_distinguishes_missing_from_malformed() {
        let empty = HeaderMap::new();
        assert!(matches!(
            bearer_from_headers(&empty).unwrap_err(),
            RouteError::MissingBearer,
        ));

        let mut wrong_scheme = HeaderMap::new();
        wrong_scheme.insert(header::AUTHORIZATION, "Basic abc123".parse().unwrap());
        assert!(matches!(
            bearer_from_headers(&wrong_scheme).unwrap_err(),
            RouteError::MalformedBearer,
        ));

        let mut empty_token = HeaderMap::new();
        empty_token.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
        assert!(matches!(
            bearer_from_headers(&empty_token).unwrap_err(),
            RouteError::MalformedBearer,
        ));
    }
}
