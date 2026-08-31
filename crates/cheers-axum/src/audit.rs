//! The centralized audit table's HTTP surface — `POST /audit/ingest` (write)
//! and `GET /audit/by-on-behalf-of/{user}` (read).
//!
//! The producer contract is in `.yah/docs/working/mcp-auth-and-ownership.md`
//! §Audit ingest: kamaji retains a local JSONL as the source of truth
//! and forwards batches here with bounded backoff. Cheers's responsibility
//! ends at "accepted and durable on cheers's side" — a 2xx means the batch
//! is committed; a 4xx means the records are malformed (do not retry as-is);
//! a 5xx means transient (retry with backoff).
//!
//! ## Authorization — ingest
//!
//! Requires an MCP-token bearer with [`Scope::AuditWrite`]. Composition
//! rule (4) constrains `audit:write` to service principals at grant time
//! (enforced by [`cheers_core::validate_grant`]) — the handler is the
//! defense-in-depth mint-side check. A user-principal token requesting
//! `audit:write` at grant time is rejected before it can ever be minted,
//! so the only well-formed token reaching here is a service-kind one.
//!
//! ## Authorization — read
//!
//! `audit:read` is user-grantable (unlike `audit:write`), so holding the
//! scope is necessary but NOT sufficient: it says "this principal may read
//! audit", not "this principal may read *anyone's* audit". The subject check
//! in [`authorize_audit_subject`] supplies the missing half — a service
//! principal (W127's dashboard) may query any user; a user principal may
//! query only itself. Without that second gate, any user holding
//! `audit:read` for their own dashboard could read every other user's
//! history.
//!
//! ## Wiring
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use axum::Router;
//! # use cheers_axum::mcp::McpAuthState;
//! # use cheers_axum::audit::{router, AuditState};
//! # use cheers_server::{AuditStore, PasetoV4SecretMinter};
//! # async fn run<A: AuditStore + 'static>(store: Arc<A>) -> Result<(), Box<dyn std::error::Error>> {
//! let (_minter, verifier) = PasetoV4SecretMinter::generate()?;
//! let mcp = Arc::new(McpAuthState::new(
//!     verifier,
//!     "platform-kid-1",
//!     "https://cheers.example",
//!     "https://cheers.example",
//! ));
//! let state = Arc::new(AuditState { mcp, store });
//! let app: Router = Router::new().merge(router(state));
//! # Ok(()) }
//! ```

use std::str::FromStr;
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};

use cheers_core::{PrincipalId, PrincipalKind, Scope};
use cheers_server::{AuditCursor, AuditQuery, AuditRecord, AuditRow, AuditStore};

use crate::error::RouteError;
use crate::mcp::{McpAuthState, McpClaimsExt, authenticate_mcp};

/// State bundle held by the `/audit/ingest` handler. Verify-only MCP state
/// + the durable audit store.
pub struct AuditState<A> {
    pub mcp: Arc<McpAuthState>,
    pub store: Arc<A>,
}

impl<A> std::fmt::Debug for AuditState<A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditState").finish_non_exhaustive()
    }
}

/// JSON body for `POST /audit/ingest`. A bare array of audit records — the
/// same wire shape W159's §Audit journal calls out (each record is the
/// full [`AuditRecord`] verbatim, no envelope).
#[derive(Debug, Clone, Deserialize)]
#[serde(transparent)]
pub struct AuditIngestBody(pub Vec<AuditRecord>);

/// JSON response for a successful ingest — the persisted rows in the same
/// order as the request, each carrying the cheers-assigned `id` and
/// `ingested_at` timestamp.
#[derive(Debug, Clone, Serialize)]
pub struct AuditIngestResponse {
    pub rows: Vec<AuditRow>,
}

/// Query parameters for `GET /audit/by-on-behalf-of/{user}`.
///
/// `method-prefix` is spelled with a hyphen because that is the spelling the
/// design doc publishes (`?since=...&method-prefix=...`); the underscore
/// spelling is accepted as an alias so a client generated from the Rust
/// field name still works.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuditReadQuery {
    /// Inclusive lower bound on the record's `at` (unix seconds).
    #[serde(default)]
    pub since: Option<i64>,
    /// Literal prefix the record's `method` must start with.
    #[serde(default, rename = "method-prefix", alias = "method_prefix")]
    pub method_prefix: Option<String>,
    /// Opaque `next_cursor` from the previous page.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Page size. Clamped server-side to `1..=MAX_AUDIT_PAGE_LIMIT`.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// JSON response for `GET /audit/by-on-behalf-of/{user}` — one page of rows,
/// newest first, plus the opaque cursor for the next page (absent on the
/// last page).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditPageResponse {
    pub rows: Vec<AuditRow>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

/// Mount `POST /audit/ingest` + `GET /audit/by-on-behalf-of/{user}` at the
/// conventional paths. Nest under whatever base the product chooses —
/// typically nothing, since these are already absolute paths verbatim with
/// the discovery doc and W159.
pub fn router<A>(state: Arc<AuditState<A>>) -> Router
where
    A: AuditStore + 'static,
{
    Router::new()
        .route("/audit/ingest", post(ingest::<A>))
        .route(
            "/audit/by-on-behalf-of/{user}",
            get(by_on_behalf_of::<A>),
        )
        .with_state(state)
}

/// Handler — verify bearer, require `audit:write`, validate every record,
/// then atomically append the batch.
pub async fn ingest<A>(
    State(state): State<Arc<AuditState<A>>>,
    headers: HeaderMap,
    Json(AuditIngestBody(records)): Json<AuditIngestBody>,
) -> Result<(StatusCode, Json<AuditIngestResponse>), RouteError>
where
    A: AuditStore,
{
    let now = now_unix();
    let claims = authenticate_mcp(&headers, &state.mcp, now)?;
    claims.require_scope(Scope::AuditWrite)?;
    // Validate the whole batch first — atomic semantics mean we don't
    // start writing until every record passes. Kamaji retries the
    // corrected batch on 4xx; a partial commit would defeat that.
    for rec in &records {
        rec.validate()?;
    }
    let rows = state.store.insert_batch(&records, now).await?;
    Ok((StatusCode::CREATED, Json(AuditIngestResponse { rows })))
}

/// `GET /audit/by-on-behalf-of/{user}` — one page of the audit rows
/// attributable to `{user}`, newest first (W127's "who deployed what").
///
/// `{user}` is the full wire principal, `user:<id>` — the same spelling the
/// `sub` claim and the ownership table's `on_behalf_of` column use, parsed by
/// the one [`PrincipalId`] parser rather than a second, laxer one. (The colon
/// is a legal path character; a client that percent-encodes it as `%3A` works
/// too, since axum decodes the segment first.) Naming a non-user principal is
/// a `400`, not a `403`: the `on_behalf_of` lane is user-only by construction,
/// so `camp:x` is a malformed request rather than a denied one.
///
/// Paging is keyset, not offset — see [`AuditCursor`]. Echo `next_cursor`
/// back as `?cursor=` until it comes back absent.
pub async fn by_on_behalf_of<A>(
    State(state): State<Arc<AuditState<A>>>,
    headers: HeaderMap,
    Path(user): Path<String>,
    Query(params): Query<AuditReadQuery>,
) -> Result<Json<AuditPageResponse>, RouteError>
where
    A: AuditStore,
{
    let now = now_unix();
    let claims = authenticate_mcp(&headers, &state.mcp, now)?;
    claims.require_scope(Scope::AuditRead)?;

    let target = PrincipalId::from_str(&user)
        .map_err(|e| RouteError::InvalidAuditQuery(format!("path principal: {e}")))?;
    authorize_audit_subject(&claims.sub, &target)?;

    let mut query = AuditQuery::new(target)
        .map_err(|e| RouteError::InvalidAuditQuery(e.to_string()))?;
    if let Some(since) = params.since {
        query = query.with_since(since);
    }
    if let Some(prefix) = params.method_prefix {
        query = query.with_method_prefix(prefix);
    }
    if let Some(cursor) = params.cursor.as_deref() {
        let cursor = AuditCursor::from_wire(cursor)
            .map_err(|e| RouteError::InvalidAuditQuery(e.to_string()))?;
        query = query.with_cursor(cursor);
    }
    if let Some(limit) = params.limit {
        query = query.with_limit(limit);
    }

    let page = state.store.query_by_on_behalf_of(&query).await?;
    Ok(Json(AuditPageResponse {
        rows: page.rows,
        next_cursor: page.next_cursor.as_ref().map(AuditCursor::to_wire),
    }))
}

/// May `caller` read `target`'s audit history?
///
/// - **Service** — yes, for any user. This is W127's dashboard principal;
///   `audit:read` on a service is already an operator-granted capability.
/// - **User** — only its own rows. This is the gate the ticket's second
///   verify line pins: user A asking for user B's audit is a `403`, even
///   holding a perfectly valid `audit:read` token.
/// - **Camp** (and any principal kind added later) — no. A camp is bound to
///   a user, but resolving that binding needs the camp principal store this
///   handler deliberately does not hold, and the design doc requires camp and
///   user audit trails to stay distinguishable rather than collapsed. Denying
///   is the reversible direction: a future ticket can widen this once a camp
///   genuinely needs its owner's history.
///
/// The rejection is `403`, not `404`: the caller is authenticated and the
/// path is well-formed, and unlike the ownership routes there is no
/// existence to hide — every `user:<id>` "exists" as an audit query, it just
/// may return nothing.
pub fn authorize_audit_subject(
    caller: &PrincipalId,
    target: &PrincipalId,
) -> Result<(), RouteError> {
    match caller.kind {
        PrincipalKind::Service => Ok(()),
        PrincipalKind::User if caller == target => Ok(()),
        _ => Err(RouteError::AuditSubjectForbidden),
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
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use cheers_server::AuditValidationError;
    use serde_urlencoded;

    #[test]
    fn audit_invalid_responds_400_with_stable_code() {
        let err: RouteError = AuditValidationError::EmptyAud.into();
        let (status, code) = err.status_and_code();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(code, "audit_invalid");
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn audit_subject_forbidden_responds_403_with_stable_code() {
        let err = RouteError::AuditSubjectForbidden;
        let (status, code) = err.status_and_code();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(code, "audit_subject_forbidden");
        assert_eq!(err.into_response().status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn invalid_audit_query_responds_400_with_stable_code() {
        let err = RouteError::InvalidAuditQuery("bad cursor".into());
        let (status, code) = err.status_and_code();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(code, "invalid_audit_query");
        assert_eq!(err.into_response().status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn service_principals_may_read_any_users_audit() {
        let dashboard = PrincipalId::service("w127-dashboard");
        authorize_audit_subject(&dashboard, &PrincipalId::user("alice"))
            .expect("the dashboard service reads any user");
        authorize_audit_subject(&dashboard, &PrincipalId::user("bob"))
            .expect("including a second user");
    }

    #[test]
    fn users_may_read_only_their_own_audit() {
        let alice = PrincipalId::user("alice");
        authorize_audit_subject(&alice, &alice).expect("self-query is allowed");
        assert!(matches!(
            authorize_audit_subject(&alice, &PrincipalId::user("bob")),
            Err(RouteError::AuditSubjectForbidden),
        ));
        // Same id, different kind — the kind is part of the identity, so a
        // service named "alice" is not the user named "alice".
        assert!(matches!(
            authorize_audit_subject(&alice, &PrincipalId::service("alice")),
            Err(RouteError::AuditSubjectForbidden),
        ));
    }

    #[test]
    fn camp_principals_are_denied_rather_than_resolved_to_their_bound_user() {
        assert!(matches!(
            authorize_audit_subject(&PrincipalId::camp("camp-a"), &PrincipalId::user("alice")),
            Err(RouteError::AuditSubjectForbidden),
        ));
    }

    #[test]
    fn read_query_accepts_both_method_prefix_spellings() {
        let hyphen: AuditReadQuery =
            serde_urlencoded::from_str("since=5&method-prefix=cloud.deploy&limit=3")
                .expect("hyphen spelling parses");
        assert_eq!(hyphen.since, Some(5));
        assert_eq!(hyphen.method_prefix.as_deref(), Some("cloud.deploy"));
        assert_eq!(hyphen.limit, Some(3));

        let underscore: AuditReadQuery =
            serde_urlencoded::from_str("method_prefix=cloud.deploy")
                .expect("underscore alias parses");
        assert_eq!(underscore.method_prefix.as_deref(), Some("cloud.deploy"));

        let empty: AuditReadQuery = serde_urlencoded::from_str("").expect("no params is valid");
        assert!(empty.since.is_none() && empty.method_prefix.is_none());
        assert!(empty.cursor.is_none() && empty.limit.is_none());
    }
}
