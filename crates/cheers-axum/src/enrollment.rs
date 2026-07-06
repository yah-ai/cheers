//! `POST /enrollment/node` — the server-mediated, user-session-authenticated
//! writer for the LAN-pair enrollment row (R593-F9, W268 §"The binding:
//! enrollment is an ownership row").
//!
//! ## Why this route exists (not another `POST /ownership` caller)
//!
//! `POST /ownership` (see [`crate::ownership`]) requires an MCP token bearing
//! [`Scope::OwnershipWrite`], and that scope is grantable to `Service`
//! principals only ([`cheers_core::validate_grant`], composition rule (4)) —
//! by construction, no `User` principal can ever hold a token that would let
//! it call that route. R593-F5's original (reverted) design worked around
//! this by shipping a *static* `ownership:write` service-principal secret
//! baked into the LAN-pair accepter (an end-user phone/Mac) so the device
//! could mint its own token locally. Adversarial review (2026-07-02) found
//! that secret, combined with `POST /ownership` not checking the body's
//! `principal_id` against the token's `sub` and accepting an unrestricted
//! `resource_kind` string, let a single extracted secret forge *arbitrary*
//! ownership rows — a full ledger compromise, not scoped node-enrollment.
//!
//! This route is the safe replacement: **the end-user device authenticates
//! with the session bearer it already legitimately holds from its own login**
//! (passkey / OIDC / magic-link — the same [`Claims`]-shaped token
//! [`crate::me`] verifies), and the server performs the ownership write
//! itself, under its own fixed internal service identity
//! ([`ENROLLMENT_GRANTED_BY`]). Three structural properties close the F5/F9
//! gaps:
//!
//! 1. **No client secret at all.** The bearer is the user's own short-TTL,
//!    revocable session token (`SessionPolicy::DEFAULT_ACCESS_TTL_SECONDS`,
//!    minutes-scale) — not a static, distributed, ledger-wide credential.
//!    Extracting it from one device compromises that one session until it
//!    expires or is revoked, not the whole ownership table.
//! 2. **`principal_id` is never caller-supplied.** It is derived entirely
//!    from the verified session's `claims.sub` — there is no body field to
//!    mismatch against a token subject, because there is no such field.
//! 3. **`resource_kind` / `relationship` are hardcoded**
//!    ([`NODE_RESOURCE_KIND`] / [`OWNS_RELATIONSHIP`], verbatim with F4's
//!    fleet-path and F5's seam constants) — the only caller-supplied datum is
//!    the `node_id` hex string itself. A caller cannot request any other
//!    resource kind or relationship through this route.
//!
//! `granted_by` on the inserted row is [`ENROLLMENT_GRANTED_BY`] (a fixed
//! `svc:` principal identifying "the enrollment route wrote this," not any
//! externally-presentable credential — [`NewOwnership::new`] requires
//! `granted_by` to be a service principal, and this route satisfies that
//! in-process rather than by verifying a service-held token). `on_behalf_of`
//! is set to the same authenticated user so `OwnershipStore::
//! revoke_by_on_behalf_of`'s user-deletion cascade sweeps the row.
//!
//! Idempotent create, mirroring [`crate::ownership::create`]: repairing the
//! same device converges on one live row (200), not a stack of duplicates.
//!
//! ## Wiring
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use axum::Router;
//! # use cheers_axum::enrollment::{router, EnrollmentState};
//! # use cheers_server::{EdgeVerifier, OwnershipStore};
//! # async fn run<V, Rd, O>(edge: Arc<EdgeVerifier<V, Rd>>, store: Arc<O>)
//! # -> Result<(), Box<dyn std::error::Error>>
//! # where
//! #     V: cheers_core::TokenVerifier + Send + Sync + 'static,
//! #     Rd: cheers_server::RevocationReader + Send + Sync + 'static,
//! #     O: OwnershipStore + 'static,
//! # {
//! let state = Arc::new(EnrollmentState { edge, store });
//! let app: Router = Router::new().nest("/api", router(state));
//! # Ok(()) }
//! ```

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use serde::Deserialize;

use cheers_core::{PrincipalId, TokenVerifier};
use cheers_server::{EdgeVerifier, NewOwnership, OwnershipRow, OwnershipStore, RevocationReader};

use crate::error::RouteError;
use crate::me::authenticate;

/// Canonical `resource_kind` for node-enrollment ownership rows — verbatim
/// with `cheers::lan_pair::enroll::NODE_RESOURCE_KIND` (R593-F5) and yubaba's
/// fleet-path `cheers_client::NODE_RESOURCE_KIND` (R593-F4). All three
/// enrollment writers must land the same literal so the `owns[].node` claim
/// vocabulary can't fork.
pub const NODE_RESOURCE_KIND: &str = "node";

/// Relationship string for enrollment rows — verbatim with F4/F5's constant.
pub const OWNS_RELATIONSHIP: &str = "owns";

/// Fixed internal service principal this route writes `granted_by` as.
///
/// Not a credential — never presented on the wire, never verified as a
/// bearer. It exists purely to satisfy [`NewOwnership::new`]'s invariant
/// that `granted_by` is always a service principal; the actual authorization
/// decision is "did the caller present a valid, unexpired, unrevoked user
/// session bearer" (checked by [`authenticate`] before this constant is ever
/// touched).
pub const ENROLLMENT_GRANTED_BY: &str = "cheers-enrollment";

/// JSON body for `POST /enrollment/node`.
///
/// Deliberately minimal: `node_id` is the ONLY caller-supplied datum. There
/// is no `principal_id` field (derived from the authenticated session) and
/// no `resource_kind` field (hardcoded to [`NODE_RESOURCE_KIND`]) — see the
/// module doc for why that's the load-bearing difference from `POST
/// /ownership`.
#[derive(Debug, Clone, Deserialize)]
pub struct EnrollNodeBody {
    /// Hex-encoded mshr `NodeId` of the paired device — same lowercase-hex
    /// encoding yubaba's `/identity` route and `mshr::NodeId::to_string()`
    /// produce. Not validated for shape here (the store treats
    /// `resource_id` as an opaque string); a garbled hex string just fails
    /// to match any real NodeId later, same failure mode as any other
    /// malformed enrollment input.
    pub node_id: String,
}

/// State bundle held by the `/enrollment/node` handler.
///
/// `edge` verifies the caller's own **session** bearer ([`Claims`], not an
/// MCP token) — the same [`EdgeVerifier`] [`crate::me`] holds. `store` is
/// the product-supplied [`OwnershipStore`] this route writes to directly,
/// with no MCP scope check in between (there is no bearer-presented
/// capability to check — the server's own write authority is implicit in
/// running this handler at all).
pub struct EnrollmentState<V, Rd, O> {
    pub edge: Arc<EdgeVerifier<V, Rd>>,
    pub store: Arc<O>,
}

impl<V, Rd, O> std::fmt::Debug for EnrollmentState<V, Rd, O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollmentState").finish_non_exhaustive()
    }
}

/// Build a router mounting `POST /enrollment/node`. The product nests it
/// under whatever base path it chose (`/api`, …).
pub fn router<V, Rd, O>(state: Arc<EnrollmentState<V, Rd, O>>) -> Router
where
    V: TokenVerifier + Send + Sync + 'static,
    Rd: RevocationReader + Send + Sync + 'static,
    O: OwnershipStore + 'static,
{
    Router::new()
        .route("/enrollment/node", post(enroll_node::<V, Rd, O>))
        .with_state(state)
}

/// `POST /enrollment/node` — record `user:<authenticated sub> owns
/// node:<node_id>`. Authenticates the caller's session bearer (never an MCP
/// token), then writes idempotently: an identical live row returns `200`,
/// a fresh one `201` (mirrors `POST /ownership`'s idempotency contract so a
/// re-pair of the same device converges on one row).
pub async fn enroll_node<V, Rd, O>(
    State(state): State<Arc<EnrollmentState<V, Rd, O>>>,
    headers: HeaderMap,
    Json(body): Json<EnrollNodeBody>,
) -> Result<(StatusCode, Json<OwnershipRow>), RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    O: OwnershipStore,
{
    let now = now_unix();
    let claims = authenticate(&headers, &state.edge, now).await?;
    let principal = PrincipalId::user(claims.sub.into_inner());
    let granted_by = PrincipalId::service(ENROLLMENT_GRANTED_BY);
    let new = NewOwnership::new(
        principal.clone(),
        NODE_RESOURCE_KIND,
        body.node_id,
        OWNS_RELATIONSHIP,
        granted_by,
        Some(principal),
    )?;

    // Idempotency pre-query, same pattern as ownership::create: an
    // identical live row already recording this (user, node) binding
    // satisfies the request without stacking a duplicate.
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
    fn constants_match_f4_f5_row_shape() {
        // These must never drift from cheers::lan_pair::enroll's constants
        // or yubaba's cheers_client — pinned here as a literal-string
        // tripwire since the three crates can't share a Rust const (yubaba
        // and cheers-axum don't depend on each other).
        assert_eq!(NODE_RESOURCE_KIND, "node");
        assert_eq!(OWNS_RELATIONSHIP, "owns");
    }
}
