//! `POST /audit/ingest` — accept a batch of audit records from constable
//! and durably append them to cheers's centralized audit table.
//!
//! The producer contract is in `.yah/docs/working/mcp-auth-and-ownership.md`
//! §Audit ingest: constable retains a local JSONL as the source of truth
//! and forwards batches here with bounded backoff. Cheers's responsibility
//! ends at "accepted and durable on cheers's side" — a 2xx means the batch
//! is committed; a 4xx means the records are malformed (do not retry as-is);
//! a 5xx means transient (retry with backoff).
//!
//! ## Authorization
//!
//! Requires an MCP-token bearer with [`Scope::AuditWrite`]. Composition
//! rule (4) constrains `audit:write` to service principals at grant time
//! (enforced by [`cheers_core::validate_grant`]) — the handler is the
//! defense-in-depth mint-side check. A user-principal token requesting
//! `audit:write` at grant time is rejected before it can ever be minted,
//! so the only well-formed token reaching here is a service-kind one.
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
//! let mcp = Arc::new(McpAuthState::new(verifier));
//! let state = Arc::new(AuditState { mcp, store });
//! let app: Router = Router::new().merge(router(state));
//! # Ok(()) }
//! ```

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use serde::{Deserialize, Serialize};

use cheers_core::Scope;
use cheers_server::{AuditRecord, AuditRow, AuditStore};

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

/// Mount the `POST /audit/ingest` route at the conventional path. Nest under
/// whatever base the product chooses — typically nothing, since `/audit/ingest`
/// is already an absolute path verbatim with the discovery doc and W159.
pub fn router<A>(state: Arc<AuditState<A>>) -> Router
where
    A: AuditStore + 'static,
{
    Router::new()
        .route("/audit/ingest", post(ingest::<A>))
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
    let claims = authenticate_mcp(&headers, &state.mcp.verifier, now)?;
    claims.require_scope(Scope::AuditWrite)?;
    // Validate the whole batch first — atomic semantics mean we don't
    // start writing until every record passes. Constable retries the
    // corrected batch on 4xx; a partial commit would defeat that.
    for rec in &records {
        rec.validate()?;
    }
    let rows = state.store.insert_batch(&records, now).await?;
    Ok((StatusCode::CREATED, Json(AuditIngestResponse { rows })))
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

    #[test]
    fn audit_invalid_responds_400_with_stable_code() {
        let err: RouteError = AuditValidationError::EmptyAud.into();
        let (status, code) = err.status_and_code();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(code, "audit_invalid");
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
