//! `POST /ownership` + `DELETE /ownership/{id}` — the write side of cheers's
//! embedded-ownership table.
//!
//! These two routes are the only path into the ownership table writes per
//! `.yah/docs/working/mcp-auth-and-ownership.md` §Ownership table. Both
//! require an MCP token bearing [`Scope::OwnershipWrite`] — granted to
//! service principals only by composition rule (4) (the grant API rejects
//! `(kind=user, scope=ownership:write)` at write time via
//! [`cheers_core::validate_grant`]; this handler is the defense-in-depth
//! mint-side check). [`NewOwnership::new`] additionally guards the row
//! invariants (`granted_by` is a service, `on_behalf_of` is a user when
//! set), so a misconfigured insert short-circuits at parse time instead
//! of round-tripping to the database.
//!
//! ## Wiring
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use axum::Router;
//! # use cheers_axum::mcp::McpAuthState;
//! # use cheers_axum::ownership::{router, OwnershipState};
//! # use cheers_server::{OwnershipStore, PasetoV4SecretMinter};
//! # async fn run<O: OwnershipStore + 'static>(store: Arc<O>) -> Result<(), Box<dyn std::error::Error>> {
//! let (_minter, verifier) = PasetoV4SecretMinter::generate()?;
//! let mcp = Arc::new(McpAuthState::new(verifier));
//! let state = Arc::new(OwnershipState { mcp, store });
//! let app: Router = Router::new().nest("/api", router(state));
//! # Ok(()) }
//! ```

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, post};
use serde::Deserialize;

use cheers_core::{PrincipalId, Scope, StoreError};
use cheers_server::{NewOwnership, OwnershipRow, OwnershipStore};

use crate::error::RouteError;
use crate::mcp::{McpAuthState, McpClaimsExt, authenticate_mcp};

/// State bundle held by the `/ownership` handlers.
///
/// Holds the verify-only [`McpAuthState`] (no minter) and an `Arc` over a
/// product-supplied [`OwnershipStore`] impl. Mounting this router cannot
/// mint MCP tokens — same edge-verify-only property the rest of the MCP
/// surface holds.
pub struct OwnershipState<O> {
    pub mcp: Arc<McpAuthState>,
    pub store: Arc<O>,
}

impl<O> std::fmt::Debug for OwnershipState<O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnershipState").finish_non_exhaustive()
    }
}

/// JSON body for `POST /ownership`.
///
/// `granted_by` is intentionally absent — it's filled from the verified
/// bearer's `sub` so a caller cannot impersonate another service principal
/// even with a valid `ownership:write` token. `on_behalf_of` is optional
/// (self-grants leave it `None`); when set, [`NewOwnership::new`] rejects
/// any non-user principal at parse time.
#[derive(Debug, Clone, Deserialize)]
pub struct CreateOwnershipBody {
    pub principal_id: PrincipalId,
    pub resource_kind: String,
    pub resource_id: String,
    pub relationship: String,
    #[serde(default)]
    pub on_behalf_of: Option<PrincipalId>,
}

/// Build a router mounting `POST /ownership` + `DELETE /ownership/{id}`. The
/// product nests it under whatever base path it chose (`/api`, …).
pub fn router<O>(state: Arc<OwnershipState<O>>) -> Router
where
    O: OwnershipStore + 'static,
{
    Router::new()
        .route("/ownership", post(create::<O>))
        .route("/ownership/{id}", delete(revoke::<O>))
        .with_state(state)
}

/// `POST /ownership` — record the row, idempotently. The caller's verified
/// `sub` becomes `granted_by`; the body supplies the rest.
///
/// **Idempotent create**: ownership rows are set-membership — a duplicate
/// `(principal, kind, id, relationship)` row carries no meaning anywhere
/// (the `owns[]` claim is a set, revocation targets the membership). When an
/// identical LIVE row already exists, this handler returns it with `200 OK`
/// instead of inserting a second one; a fresh insert returns `201 Created` +
/// the materialised [`OwnershipRow`] (carrying the store-minted `id` +
/// `granted_at`). Writers that re-POST by design (cloud-init re-runs, daemon
/// restarts that forgot their row id) therefore converge on one live row and
/// get its `id` back for a later `DELETE`.
///
/// The existence check is a handler-level pre-query over
/// [`OwnershipStore::list_for_principal`] (live rows only), not a store
/// uniqueness constraint — it works uniformly across every store impl with
/// no schema migration. Two exactly-concurrent identical POSTs can still
/// race past it and land two rows; that residual duplicate is harmless
/// (set-membership) and mint-time dedup covers the `owns[]` claim shape.
pub async fn create<O>(
    State(state): State<Arc<OwnershipState<O>>>,
    headers: HeaderMap,
    Json(body): Json<CreateOwnershipBody>,
) -> Result<(StatusCode, Json<OwnershipRow>), RouteError>
where
    O: OwnershipStore,
{
    let now = now_unix();
    let claims = authenticate_mcp(&headers, &state.mcp.verifier, now)?;
    claims.require_scope(Scope::OwnershipWrite)?;
    let new = NewOwnership::new(
        body.principal_id,
        body.resource_kind,
        body.resource_id,
        body.relationship,
        claims.sub.clone(),
        body.on_behalf_of,
    )?;
    // Idempotency pre-query: an identical live row satisfies this request.
    // Runs AFTER NewOwnership::new so an invalid body is still a 400 even
    // when a matching row exists. list_for_principal returns live rows only;
    // is_revoked() is a belt-and-braces re-check mirroring rows_to_owns.
    let existing = state.store.list_for_principal(&new.principal_id).await?;
    if let Some(row) = existing.into_iter().find(|r| {
        !r.is_revoked()
            && r.resource_kind == new.resource_kind
            && r.resource_id == new.resource_id
            && r.relationship == new.relationship
    }) {
        return Ok((StatusCode::OK, Json(row)));
    }
    let row = state.store.insert(&new, now).await?;
    Ok((StatusCode::CREATED, Json(row)))
}

/// `DELETE /ownership/{id}` — soft-delete by id. Returns `204 No Content`
/// on success, `404 Not Found` ([`RouteError::UnknownOwnership`]) when the
/// id does not exist. Re-revoking an already-revoked row is a no-op (the
/// underlying store treats it as idempotent).
pub async fn revoke<O>(
    State(state): State<Arc<OwnershipState<O>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, RouteError>
where
    O: OwnershipStore,
{
    let now = now_unix();
    let claims = authenticate_mcp(&headers, &state.mcp.verifier, now)?;
    claims.require_scope(Scope::OwnershipWrite)?;
    state
        .store
        .revoke_by_id(&id, now)
        .await
        .map_err(map_store_error)?;
    Ok(StatusCode::NO_CONTENT)
}

fn map_store_error(err: StoreError) -> RouteError {
    match err {
        StoreError::NotFound => RouteError::UnknownOwnership,
        other => RouteError::Store(other.to_string()),
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
    use cheers_core::PrincipalKind;
    use cheers_server::OwnershipValidationError;

    #[test]
    fn map_store_error_collapses_not_found_to_unknown_ownership() {
        let mapped = map_store_error(StoreError::NotFound);
        assert!(matches!(mapped, RouteError::UnknownOwnership));
        let (status, code) = mapped.status_and_code();
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(code, "unknown_ownership");
    }

    #[test]
    fn map_store_error_bridges_other_variants_as_500() {
        let mapped = map_store_error(StoreError::Conflict);
        match mapped {
            RouteError::Store(_) => {}
            other => panic!("expected Store, got {other:?}"),
        }
    }

    #[test]
    fn ownership_invalid_responds_400_with_stable_code() {
        let err: RouteError =
            OwnershipValidationError::OnBehalfOfNotUser(PrincipalKind::Service).into();
        let (status, code) = err.status_and_code();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(code, "ownership_invalid");
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
