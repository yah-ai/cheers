//! Knock routes (`knock.md`; R734-F4) over [`KnockAuthority`].
//!
//! | Route | Caller | Does |
//! |---|---|---|
//! | `POST /knock` `{knock}` | anyone holding a key (rate-limited) | verifies the signed `Knock`, queues it; a second from the same key replaces the first |
//! | `GET /knock?resource_kind=&resource_id=` | bearer with the admit ability | lists pending knocks |
//! | `POST /knock/{id}/admit` `{confirmation?, lease_seconds?}` | bearer with the admit ability | writes the tuple, `granted_by` = caller |
//! | `POST /offer` `{resource_kind, resource_id, relation, max_uses}` | bearer with the admit ability | mints an issuer-signed `Offer` |
//! | `POST /offer/redeem` `{offer, knock}` | anyone holding a key | redeems the offer for the knock's key |
//! | `POST /admit` `{admit}` | anyone (the artifact authenticates itself) | reconciles an offline `Admit` |
//!
//! Bearers are the access tokens [`EdgeVerifier`] accepts; the caller is the
//! token's user. `POST /knock` is limited per source (the connection's peer
//! address from axum's `ConnectInfo`; without one every request shares a
//! single bucket, which fails tight) and per resource, by the in-memory
//! [`RateLimiter`] at the [`KnockConfig`] rates.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use cheers_core::{Confirmation, Knock, PrincipalId, TokenVerifier};
use cheers_server::{
    Admitted, EdgeVerifier, KnockAuthority, KnockFlowError, OwnershipRow, PendingKnock, Queued, Reconciled, RevocationReader,
};
use cheers_verify::verify_device_artifact;

use crate::error::RouteError;
use crate::me::bearer_from_headers;

/// A fixed-window counter per key: at most `limit` hits per 60-second window.
/// In memory, per process; a multi-node deployment limits per node.
#[derive(Debug, Default)]
pub struct RateLimiter {
    windows: Mutex<HashMap<String, (i64, u32)>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one hit on `key` at `now`; `false` once the window is full.
    pub fn allow(&self, key: &str, limit: u32, now: i64) -> bool {
        let window = now.div_euclid(60);
        let mut w = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        if w.len() > 10_000 {
            w.retain(|_, (at, _)| *at == window);
        }
        let slot = w.entry(key.to_owned()).or_insert((window, 0));
        if slot.0 != window {
            *slot = (window, 0);
        }
        if slot.1 >= limit {
            return false;
        }
        slot.1 += 1;
        true
    }
}

pub struct KnockState<V, Rd, S> {
    /// Verifies the bearer access tokens of approvers.
    pub edge: Arc<EdgeVerifier<V, Rd>>,
    pub authority: Arc<KnockAuthority<S>>,
    pub limiter: Arc<RateLimiter>,
}

impl<V, Rd, S> std::fmt::Debug for KnockState<V, Rd, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KnockState").finish_non_exhaustive()
    }
}

/// A knock route's failure.
#[derive(Debug, thiserror::Error)]
pub enum KnockRouteError {
    #[error(transparent)]
    Route(#[from] RouteError),
    #[error(transparent)]
    Flow(#[from] KnockFlowError),
    #[error("too many knocks; slow down")]
    RateLimited,
    #[error("bad request body: {0}")]
    BadBody(String),
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    message: String,
}

impl IntoResponse for KnockRouteError {
    fn into_response(self) -> Response {
        use KnockFlowError as F;
        let flow = match self {
            KnockRouteError::Route(e) => return e.into_response(),
            other => other,
        };
        let (status, code) = match &flow {
            KnockRouteError::Route(_) => unreachable!("returned above"),
            KnockRouteError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            KnockRouteError::BadBody(_) => (StatusCode::BAD_REQUEST, "bad_body"),
            KnockRouteError::Flow(f) => match f {
                F::Artifact(_) | F::Invalid(_) | F::Standing(_) | F::WrongAuthority { .. } | F::OfferMismatch(_) => {
                    (StatusCode::BAD_REQUEST, "bad_artifact")
                }
                F::Expired { .. } => (StatusCode::GONE, "expired"),
                F::NotAnApprover(_) => (StatusCode::FORBIDDEN, "not_an_approver"),
                F::Refused(_) => (StatusCode::FORBIDDEN, "admission_refused"),
                F::PendingFull => (StatusCode::TOO_MANY_REQUESTS, "pending_full"),
                F::UnknownKnock => (StatusCode::NOT_FOUND, "unknown_knock"),
                F::UnknownOffer => (StatusCode::NOT_FOUND, "unknown_offer"),
                F::OfferExhausted => (StatusCode::GONE, "offer_exhausted"),
                F::OfferExpired => (StatusCode::GONE, "offer_expired"),
                F::Store(_) => (StatusCode::INTERNAL_SERVER_ERROR, "store"),
            },
        };
        (status, Json(ErrorBody { error: code, message: flow.to_string() })).into_response()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct KnockBody {
    /// The signed `Knock`.
    pub knock: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnockQueued {
    pub id: String,
    pub expires_at: i64,
    /// The key's earlier pending knock on this resource was replaced.
    pub replaced: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PendingQuery {
    pub resource_kind: String,
    pub resource_id: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmitKnockBody {
    /// Defaults to `accept`.
    #[serde(default)]
    pub confirmation: Option<Confirmation>,
    /// Lease length; the path default when absent.
    #[serde(default)]
    pub lease_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmittedBody {
    pub jti: String,
    pub ownership: OwnershipRow,
}

impl From<Admitted> for AdmittedBody {
    fn from(a: Admitted) -> Self {
        Self { jti: a.jti, ownership: a.row }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateOfferBody {
    pub resource_kind: String,
    pub resource_id: String,
    pub relation: String,
    pub max_uses: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OfferCreated {
    pub offer: cheers_core::Offer,
    pub token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedeemBody {
    pub offer: String,
    pub knock: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AdmitUploadBody {
    pub admit: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum AdmitUploadOutcome {
    Accepted { jti: String, ownership: OwnershipRow },
    Refused { jti: String, refusal: String },
}

async fn caller<V, Rd, S>(headers: &HeaderMap, state: &KnockState<V, Rd, S>, now: i64) -> Result<PrincipalId, RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
{
    let token = bearer_from_headers(headers)?;
    match state.edge.verify_at(token, now).await {
        Ok(claims) => Ok(PrincipalId::user(claims.sub.as_str())),
        Err(cheers_core::Error::Store(e)) => Err(RouteError::Store(e.to_string())),
        Err(_) => Err(RouteError::Unauthorized),
    }
}

async fn post_knock<V, Rd, S>(
    State(state): State<Arc<KnockState<V, Rd, S>>>,
    request: Request,
) -> Result<(StatusCode, Json<KnockQueued>), KnockRouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    S: RevocationReader + Send + Sync,
{
    let now = now_unix();
    let config = *state.authority.config();
    let source = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_string())
        .unwrap_or_else(|| "unknown".into());
    if !state.limiter.allow(&format!("source:{source}"), config.knocks_per_source_per_minute, now) {
        return Err(KnockRouteError::RateLimited);
    }
    let bytes = axum::body::to_bytes(request.into_body(), 64 * 1024)
        .await
        .map_err(|e| KnockRouteError::BadBody(e.to_string()))?;
    let body: KnockBody = serde_json::from_slice(&bytes).map_err(|e| KnockRouteError::BadBody(e.to_string()))?;
    let knock: Knock = verify_device_artifact(&body.knock).map_err(KnockFlowError::from)?;
    let resource = format!("resource:{}/{}", knock.kind, knock.id);
    if !state.limiter.allow(&resource, config.knocks_per_resource_per_minute, now) {
        return Err(KnockRouteError::RateLimited);
    }
    let (pending, queued) = state.authority.knock(&body.knock, now).await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(KnockQueued { id: pending.id, expires_at: pending.expires_at, replaced: queued == Queued::Replaced }),
    ))
}

async fn list_knocks<V, Rd, S>(
    State(state): State<Arc<KnockState<V, Rd, S>>>,
    headers: HeaderMap,
    Query(q): Query<PendingQuery>,
) -> Result<Json<Vec<PendingKnock>>, KnockRouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    S: RevocationReader + Send + Sync,
{
    let now = now_unix();
    let who = caller(&headers, &state, now).await?;
    Ok(Json(state.authority.pending(&who, &q.resource_kind, &q.resource_id, now).await?))
}

async fn admit_knock<V, Rd, S>(
    State(state): State<Arc<KnockState<V, Rd, S>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<AdmitKnockBody>>,
) -> Result<(StatusCode, Json<AdmittedBody>), KnockRouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    S: RevocationReader + Send + Sync,
{
    let now = now_unix();
    let who = caller(&headers, &state, now).await?;
    let body = body.map(|Json(b)| b).unwrap_or_default();
    let confirmation = body.confirmation.unwrap_or(Confirmation::Accept);
    let admitted = state.authority.admit_knock(&who, &id, confirmation, body.lease_seconds, now).await?;
    Ok((StatusCode::CREATED, Json(admitted.into())))
}

async fn create_offer<V, Rd, S>(
    State(state): State<Arc<KnockState<V, Rd, S>>>,
    headers: HeaderMap,
    Json(body): Json<CreateOfferBody>,
) -> Result<(StatusCode, Json<OfferCreated>), KnockRouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    S: RevocationReader + Send + Sync,
{
    let now = now_unix();
    let who = caller(&headers, &state, now).await?;
    let (offer, token) = state
        .authority
        .offer(&who, &body.resource_kind, &body.resource_id, &body.relation, body.max_uses, now)
        .await?;
    Ok((StatusCode::CREATED, Json(OfferCreated { offer, token })))
}

async fn redeem_offer<V, Rd, S>(
    State(state): State<Arc<KnockState<V, Rd, S>>>,
    Json(body): Json<RedeemBody>,
) -> Result<(StatusCode, Json<AdmittedBody>), KnockRouteError>
where
    S: RevocationReader + Send + Sync,
{
    let admitted = state.authority.redeem_offer(&body.offer, &body.knock, now_unix()).await?;
    Ok((StatusCode::CREATED, Json(admitted.into())))
}

async fn upload_admit<V, Rd, S>(
    State(state): State<Arc<KnockState<V, Rd, S>>>,
    Json(body): Json<AdmitUploadBody>,
) -> Result<(StatusCode, Json<AdmitUploadOutcome>), KnockRouteError>
where
    S: RevocationReader + Send + Sync,
{
    Ok(match state.authority.reconcile(&body.admit, now_unix()).await? {
        Reconciled::Accepted(a) => (StatusCode::OK, Json(AdmitUploadOutcome::Accepted { jti: a.jti, ownership: a.row })),
        Reconciled::Refused { jti, refusal } => (StatusCode::FORBIDDEN, Json(AdmitUploadOutcome::Refused { jti, refusal })),
    })
}

/// The knock routes (module table). Serve under `ConnectInfo` (e.g.
/// `into_make_service_with_connect_info::<SocketAddr>()`) so `POST /knock`
/// is limited per client address.
pub fn router<V, Rd, S>(state: Arc<KnockState<V, Rd, S>>) -> Router
where
    V: TokenVerifier + Send + Sync + 'static,
    Rd: RevocationReader + Send + Sync + 'static,
    S: RevocationReader + Send + Sync + 'static,
{
    Router::new()
        .route("/knock", post(post_knock::<V, Rd, S>).get(list_knocks::<V, Rd, S>))
        .route("/knock/{id}/admit", post(admit_knock::<V, Rd, S>))
        .route("/offer", post(create_offer::<V, Rd, S>))
        .route("/offer/redeem", post(redeem_offer::<V, Rd, S>))
        .route("/admit", post(upload_admit::<V, Rd, S>))
        .with_state(state)
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limiter_counts_per_key_per_minute() {
        let l = RateLimiter::new();
        assert!(l.allow("a", 2, 600));
        assert!(l.allow("a", 2, 610));
        assert!(!l.allow("a", 2, 619));
        assert!(l.allow("b", 2, 619));
        assert!(l.allow("a", 2, 660), "a new window resets");
    }
}
