//! `POST /ownership` + `DELETE /ownership/{id}` + `GET /ownership` (by resource,
//! by subject, or by principal within a resource kind, [`ListOwnershipQuery`]) — the grant door into cheers's
//! ownership table (D4, `.yah/docs/working/product-scopes-and-authorization.md`
//! §D4). A row's holder is a principal or a subject set (R732-F1).
//!
//! ## Who may write
//!
//! Authority is a relationship, not a scope. A caller may write or revoke
//! relation `r` on resource `R` only if it holds, on `R` (or on `R`'s kind
//! via a kind-level row), a live relation whose grants include `r` —
//! [`SchemaRegistry::may_grant`] over the table, so a right held through a
//! subject set counts like a direct one (R732-F2). Listing a
//! resource's rows needs the right to grant at least one relation on it
//! ([`SchemaRegistry::may_grant_any`]); listing a set subject's rows needs the
//! same right on the set's resource; a caller may always list its own rows,
//! and may list another principal's rows within kind `K` only with that
//! right on the kind-level row `kind/K`. Anything else is a 403
//! ([`RouteError::GrantForbidden`]). There is no `ownership:write` scope any
//! more and no per-writer scoping: a granter manages the rows on resources it
//! has grant rights over, whoever wrote them.
//!
//! ## Credentials
//!
//! Either shape, like the `/me/tokens` maintenance routes: a session bearer
//! (verified at the edge) or a cheers-minted MCP bearer (verified against
//! [`McpAuthState`], audience included, and checked against the same
//! revocation set). The verified `sub` is the actor whose rows are consulted.
//!
//! `granted_by` is never caller-supplied. `on_behalf_of` is never
//! caller-supplied either: it is set only from a verified RFC 8693 `act`
//! claim on an MCP bearer — then the agent in `act` is `granted_by` and the
//! token's `sub` (the user whose authority is exercised) is `on_behalf_of`.
//! A session bearer has no `act`, so `on_behalf_of` is `None`. Unknown body
//! fields (including a stray `on_behalf_of`) are rejected.
//!
//! ## Revocation reaches the offline edge
//!
//! `DELETE` revokes through [`cheers_server::revoke_ownership`], the same call
//! in-process writers use: when the row was a user's last live direct tuple on
//! its resource, it records `Revoked::Membership` at the ownership version the
//! revoke produced, so edges holding an older membership snapshot drop the
//! user (R732-F4). That is why [`OwnershipState`] carries the issuer's
//! revocation writer.
//!
//! ## Bootstrap
//!
//! The first grant-holder of a resource cannot come through this door.
//! Deployments seed it at startup with [`cheers_server::seed_ownership`],
//! which is deliberately not reachable from any route.
//!
//! ## Wiring
//!
//! ```ignore
//! let state = Arc::new(OwnershipState { edge, mcp, schema, store, revocations });
//! let app: Router = Router::new().nest("/api", router(state));
//! ```
//!
//! @yah:ticket(R731-F8, "One grant door — the ownership router authorizes by schema grant rights and accepts a session or MCP bearer (D4)")
//! @yah:status(review)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:at(2026-10-06T23:45:21Z)
//! @yah:phase(P3)
//! @yah:parent(R731)
//! @yah:next("Doc D4. Accept either credential shape, as the /me/tokens maintenance routes do. A caller may write or revoke relation r on R only if it holds on R a relation whose grants include r. Replaces per-writer scoping and the ownership:write scope.")
//! @yah:next("on_behalf_of comes only from a verified act claim or delegation; today the router copies it from the request body (ownership.rs:164).")
//! @yah:next("Delete Scope::OwnershipWrite and fix call sites, including yah app/yah/cli/src/cloud_cheers.rs:471 and yubaba cheers_client.rs.")
//! @yah:next("Bootstrap: a config seed tuple gives each resource its first grant-holder; never the general grant path.")
//! @yah:next("Open, non-blocking: should a grant require a passkey ceremony within N minutes? Nothing enforces session age today.")
//! @yah:depends_on(R731-F3)
//! @yah:depends_on(R731-F7)
//! @yah:tier(Warrior)
//! @yah:next("F8 DECIDED (leader, 2026-10-06). (1) The router accepts a session bearer OR a cheers-minted MCP bearer, mirroring the /me/tokens maintenance routes' extractor. Actor = the verified sub of either. (2) Write: load the caller's live rows (list_for_principal) and allow only if SchemaRegistry::may_grant(rows, kind, id, relation) (R731-F3); else 403. Revoke: fetch the row by id and apply the same check against row.(kind,id,relationship). List a resource's rows: allowed iff the caller may grant at least one relation on it. Per-writer scoping goes. (3) granted_by = actor. on_behalf_of comes ONLY from a verified act claim on an MCP bearer (token exchange) and is None for a session bearer. Delete the request-body field (ownership.rs ~164). (4) Delete yah_scopes::OWNERSHIP_WRITE and its composition-rule-(4) entry, and fix every call site, including yah app/yah/cli/src/cloud_cheers.rs (~471) and oss/yubaba cheers_client.rs (~204) at compile level only. yubaba's real move to /token plus a relationship is yah-side R426 work, so append it there. (5) Bootstrap: an idempotent `seed_ownership(store, &[SeedTuple], granted_by)` that the deployment calls at startup, where granted_by is the service's own svc: identity and a row is inserted only when no live identical one exists. It is never reachable from the router. (6) Update spec mcp-auth-and-ownership.md §Ownership table and composition rule (4) as superseded by D4. (7) The passkey-recency question stays open and unbuilt; leave it noted.")
//! @yah:handoff("LANDED (uncommitted, git policy defer). cheers-axum/src/ownership.rs rewritten: OwnershipState<V,Rd,O>{edge,mcp,schema,store}; private authenticate_caller accepts a session bearer (EdgeVerifier) or an MCP bearer (McpAuthState, aud enforced, jti checked against edge.revocations()); store errors are 500. create: may_grant(caller live rows, kind,id,rel) else 403 RouteError::GrantForbidden (new variant, code grant_forbidden); idempotent pre-query kept. revoke: get row (404 unknown) then may_grant on row's (kind,id,relationship) else 403. GET /ownership now takes resource_kind+resource_id (was principal_id), uses list_for_resource, allowed iff SchemaRegistry::may_grant_any. Per-writer scoping removed.")
//! @yah:handoff("Attribution (picked default, flag if wrong): with no act claim granted_by = verified sub, on_behalf_of = None; with a verified act claim (RFC 8693) granted_by = act.sub (the agent actually acting) and on_behalf_of = sub, while authority is still the sub's rows. CreateOwnershipBody has no on_behalf_of and is deny_unknown_fields, so a body on_behalf_of is a 4xx.")
//! @yah:handoff("cheers-core/src/schema.rs: may_grant refactored onto a private grant_sets iterator; new may_grant_any. cheers-server/src/ownership.rs: SeedTuple + seed_ownership(store, &[SeedTuple], granted_by, now) -> usize inserted, idempotent against live identical rows, re-exported from cheers_server; not referenced by any route.")
//! @yah:handoff("yah_scopes::OWNERSHIP_WRITE deleted along with the 'ownership' namespace (it was the namespace's only scope) and its service_only entry; registry is now 16 yah scopes. Test call sites in cheers-core/mcp.rs, cheers-axum/{mcp.rs,jwks.rs,discovery.rs (count 18->17),tests/enrollment_basic.rs}, cheers-server/{mcp_authority.rs,service_principal.rs} swapped to AUDIT_WRITE (minimal hunks in F4's files: identifier + 3 comments only). yah app/yah/cli/src/cloud_cheers.rs:478 swapped to AUDIT_WRITE. yubaba cheers_client.rs has no compile-level reference (it sends the wire string 'ownership:write' and lists by principal_id) so it was NOT edited; it will now be refused at runtime until R426 moves it to /token + a relationship.")
//! @yah:handoff("Spec mcp-auth-and-ownership.md: composition rule (4) and §Ownership table marked superseded by D4. Passkey-recency question left open (noted in the spec banner). Frozen signed fixture cheers-test-support/fixtures/valid_svc.* still carries the 'ownership:write' wire string; left as-is since decode accepts any syntactically valid scope and re-signing a fixture is out of scope.")
//! @yah:verify("cheers: cargo test --workspace --no-fail-fast -> 696 passed / 0 failed / 4 ignored (baseline measured 686/0/3 before edits; delta includes peer R731-F4/F5 tests landing concurrently).")
//! @yah:verify("cheers-axum tests/ownership_basic.rs: 12 tests (admin session grants triager, admin MCP grants, out-of-grants 403, reader 403 with no write, body on_behalf_of rejected, act claim sets on_behalf_of, revoked MCP 401, revoke without rights 403 / unknown 404 / admin revoke 204, list gated by may_grant_any, kind-level admin, seed idempotent, missing bearer 401) all pass.")
//! @yah:verify("yah: cargo test -p yah-cloud-admin 60/0/0; cargo check -p yah EXIT=0 (not blocked this time; check does not compile the cfg(test) cloud_cheers edit); oss/yubaba cargo test -p yubaba --lib cheers_client 11/0/0. Skew warnings were from peer edits to token_endpoint/discovery; discovery count fix re-confirmed after.")
//! @yah:verify("Leader final re-verify 2026-10-06 (quiet tree, no skew): cheers workspace 702 pass / 0 fail / 4 ignored; cheers-sqlx pg 17/17 + libsql 7/7; yah-cloud-admin 60/0; cargo test -p yah --lib cloud_cheers 6/0, which compiles the test-only cloud_cheers.rs edit that `cargo check -p yah` skips.")
//! @yah:gotcha("Runtime break until yah-side R426 lands: oss/yubaba cheers_client.rs still self-signs an ownership:write token. It compiles (11/0), but the reworked router refuses it, since ownership:write no longer exists and grant rights now come from relationships. Any yubaba roll that exercises cheers ownership writes will fail until R426 moves it onto POST /token plus a provisioner relationship.")
//!
//! @yah:ticket(R732-F8, "Ownership door: list rows held by a principal on resources of one kind (GET /ownership?principal_id=P&resource_kind=K), authorized by may_grant_any on (kind, K)")
//! @yah:status(review)
//! @yah:at(2026-10-07T07:09:24Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R732)
//! @yah:next("Tier: Warrior — small, well-specified door addition, but it is authorization code on a live security boundary and needs negative tests.")
//! @yah:next("Consumer: noisetable R800-F1 (noisetable camp, separate ID space). noisetable-scopes `list` (all reservations = rows held by svc:noisetable-account over kind publish-scope) and `list PRINCIPAL` for a principal other than the caller have no GET /ownership form today: ?principal_id= alone is caller-own-sub only, and no subject set holds these rows. Both modes currently get the door's 403.")
//! @yah:next("Add a fourth exactly-one form to GET /ownership: `?principal_id=<kind>:<id>&resource_kind=<K>`, which returns rows held directly by that principal on resources of kind K. Authorize it with may_grant_any on the kind-level row (kind, K): an admin of a kind may enumerate who holds what within it. Keep the existing rule that a bare ?principal_id= is caller-own-sub only. A partial or mixed form stays 400 invalid_ownership_query.")
//! @yah:next("Tests: allowed for a kind-level admin; 403 for a non-admin and for an admin of a different kind; 400 for each malformed combination; the result is limited to rows of kind K.")
//! @yah:next("When it lands, ping the noisetable R800 leader. The noisetable-side client change is small: admin_client.rs list_for_principal gains the kind-scoped query, and bin/scopes.rs `list` uses it.")
//! @yah:gotcha("Sequenced by the R732 leader: R732-F3 → R732-F8 → R732-F4, because all three edit cheers-axum/src/ownership.rs (F3 the DELETE rule, this the GET list forms, F4 the revoke path's membership recording). When it lands, ping session:6d3128e8 (noisetable R800 leader) with one line.")
//! @yah:depends_on(R732-F3)
//! @yah:handoff("LANDED (uncommitted, git policy defer). cheers-axum/src/ownership.rs: new ListTarget::PrincipalInKind{principal,kind}. ListOwnershipQuery::target() picks it when principal_id + resource_kind are set and resource_id and every subject_* field are absent. The parse is nested if/if-let because cheers-axum is edition 2021. list(): may_grant_any(caller, KIND_RESOURCE, K), else 403 grant_forbidden. Rows come from store.list_for_principal (live rows, direct holders only), kept where resource_kind == K. No migration. A bare ?principal_id= is still caller-own-sub only. Every other partial or mixed form still falls through to the existing 400 invalid_ownership_query arms. The module doc, the ListOwnershipQuery doc and the list() doc now name the fourth form.")
//! @yah:handoff("Tests: new crates/cheers-axum/tests/ownership_kind_list.rs (5 tests), registered with one mod line in tests/main.rs. They cover: a kind admin gets only kind-K rows of that principal (2 of bob's 3); a resource-level admin is 403, and so is the principal itself on the kind form; a board-kind admin is 403 on doc but 200 on board; 8 malformed query combinations each return 400 invalid_ownership_query; a bare principal_id is 403 cross-principal even for a kind admin and 200 for one's own rows (3).")
//! @yah:verify("cheers: cargo test -p cheers-axum -> 165 passed / 0 failed / 3 ignored (baseline 160/0/3; +5 new). Re-run on a skew-free closure confirmed it. cargo check --workspace --all-targets EXIT=0. Earlier red builds came from peer R732-T7's half-landed Revoked reshape (cheers-verify/cheers-server), not from this change.")

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, post};
use serde::Deserialize;

use cheers_core::{PrincipalId, SchemaRegistry, StoreError, Subject, TokenVerifier};
use cheers_server::{
    revoke_ownership, EdgeVerifier, NewOwnership, OwnershipRow, OwnershipStore, OwnershipTuples,
    OwnershipValidationError, RevocationReader, RevocationWriter,
};

use crate::error::RouteError;
use crate::mcp::{McpAuthState, authenticate_mcp};
use crate::me::bearer_from_headers;

/// State bundle held by the `/ownership` handlers.
///
/// Verify-only on both credential shapes: nothing here can mint.
pub struct OwnershipState<V, Rd, O> {
    /// Session-bearer verifier; its revocation set is consulted for MCP
    /// bearers too, so one revoke kills a token at both doors.
    pub edge: Arc<EdgeVerifier<V, Rd>>,
    pub mcp: Arc<McpAuthState>,
    /// The deployment's relationship schema — the source of grant rights.
    pub schema: Arc<SchemaRegistry>,
    pub store: Arc<O>,
    /// The issuer's revocation log: `DELETE` records a membership entry here
    /// when it removes a user's last direct tuple on a resource (module docs).
    pub revocations: Arc<dyn RevocationWriter>,
}

impl<V, Rd, O> std::fmt::Debug for OwnershipState<V, Rd, O> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnershipState").finish_non_exhaustive()
    }
}

/// JSON body for `POST /ownership`. `granted_by` and `on_behalf_of` are
/// absent by design (module doc); unknown fields are a 4xx, not ignored.
///
/// The holder is `principal_id`, or a subject set given as all three
/// `subject_*` fields (R732-F1) — exactly one form, else 400
/// `ownership_invalid`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateOwnershipBody {
    pub principal_id: Option<PrincipalId>,
    pub subject_kind: Option<String>,
    pub subject_id: Option<String>,
    pub subject_relation: Option<String>,
    pub resource_kind: String,
    pub resource_id: String,
    pub relationship: String,
}

/// Query parameters for `GET /ownership` — exactly one form; there is no
/// unfiltered table dump.
///
/// - **By resource:** `resource_kind` + `resource_id` — the live rows on that
///   resource, whatever their subject.
/// - **By subject:** `principal_id`, or `subject_kind` + `subject_id` +
///   `subject_relation` — the live rows held by exactly that subject.
/// - **By principal within a kind:** `principal_id` + `resource_kind` — the
///   live rows held directly by that principal on resources of that kind
///   (R732-F8).
///
/// A partial form, no form, or a mix of forms is 400
/// `invalid_ownership_query`.
#[derive(Debug, Clone, Deserialize)]
pub struct ListOwnershipQuery {
    pub resource_kind: Option<String>,
    pub resource_id: Option<String>,
    pub principal_id: Option<PrincipalId>,
    pub subject_kind: Option<String>,
    pub subject_id: Option<String>,
    pub subject_relation: Option<String>,
}

/// What a [`ListOwnershipQuery`] asks for.
enum ListTarget {
    Resource { kind: String, id: String },
    Subject(Subject),
    PrincipalInKind { principal: PrincipalId, kind: String },
}

impl ListOwnershipQuery {
    fn target(self) -> Result<ListTarget, RouteError> {
        if self.resource_id.is_none()
            && self.subject_kind.is_none()
            && self.subject_id.is_none()
            && self.subject_relation.is_none()
        {
            if let (Some(principal), Some(kind)) = (&self.principal_id, &self.resource_kind) {
                return Ok(ListTarget::PrincipalInKind {
                    principal: principal.clone(),
                    kind: kind.clone(),
                });
            }
        }
        let any_subject = self.principal_id.is_some()
            || self.subject_kind.is_some()
            || self.subject_id.is_some()
            || self.subject_relation.is_some();
        let bad = |msg: &str| Err(RouteError::InvalidOwnershipQuery(msg.to_owned()));
        match ((self.resource_kind, self.resource_id), any_subject) {
            ((Some(kind), Some(id)), false) => Ok(ListTarget::Resource { kind, id }),
            ((None, None), true) => Subject::from_parts(
                self.principal_id,
                self.subject_kind,
                self.subject_id,
                self.subject_relation,
            )
            .map(ListTarget::Subject)
            .map_err(|e| RouteError::InvalidOwnershipQuery(e.to_string())),
            ((None, None), false) => bad(
                "name a resource (resource_kind, resource_id) or a subject (principal_id, or \
                 subject_kind, subject_id, subject_relation)",
            ),
            (_, false) => bad("resource_kind and resource_id go together"),
            (_, true) => bad("a resource and a subject are separate queries; send one"),
        }
    }
}

/// A verified caller of the grant door.
#[derive(Debug, Clone)]
struct GrantCaller {
    /// The verified `sub` — whose live rows carry the authority.
    sub: PrincipalId,
    /// The verified `act.sub`, when an agent acts on `sub`'s behalf.
    act: Option<PrincipalId>,
}

impl GrantCaller {
    /// `(granted_by, on_behalf_of)` for a row this caller writes.
    fn attribution(&self) -> (PrincipalId, Option<PrincipalId>) {
        match &self.act {
            Some(agent) => (agent.clone(), Some(self.sub.clone())),
            None => (self.sub.clone(), None),
        }
    }
}

/// Authenticate a session bearer or an MCP bearer. Session first, as
/// [`tokens::authenticate_any`](crate::tokens::authenticate_any) does; a
/// store failure on either path is a 500, never a 401.
async fn authenticate_caller<V, Rd, O>(
    headers: &HeaderMap,
    state: &OwnershipState<V, Rd, O>,
    now: i64,
) -> Result<GrantCaller, RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
{
    let token = bearer_from_headers(headers)?;
    match state.edge.verify_at(token, now).await {
        Ok(claims) => {
            return Ok(GrantCaller {
                sub: PrincipalId::user(claims.sub.as_str()),
                act: None,
            });
        }
        Err(cheers_core::Error::Store(e)) => return Err(RouteError::Store(e.to_string())),
        Err(_) => {}
    }
    let claims = authenticate_mcp(headers, &state.mcp, now).await?;
    if state
        .edge
        .revocations()
        .is_revoked(&claims.jti)
        .await
        .map_err(|e| RouteError::Store(e.to_string()))?
    {
        return Err(RouteError::Unauthorized);
    }
    Ok(GrantCaller {
        sub: claims.sub,
        act: claims.act.map(|a| a.sub),
    })
}

/// Build a router mounting `POST /ownership` + `GET /ownership` +
/// `DELETE /ownership/{id}`. The product nests it under its base path.
pub fn router<V, Rd, O>(state: Arc<OwnershipState<V, Rd, O>>) -> Router
where
    V: TokenVerifier + Send + Sync + 'static,
    Rd: RevocationReader + Send + Sync + 'static,
    O: OwnershipStore + 'static,
{
    Router::new()
        .route("/ownership", post(create::<V, Rd, O>).get(list::<V, Rd, O>))
        .route("/ownership/{id}", delete(revoke::<V, Rd, O>))
        .with_state(state)
}

/// `POST /ownership` — write a row if the caller may grant its relation on
/// its resource. Idempotent: an identical live row comes back `200 OK`; a
/// fresh insert is `201 Created`. (The pre-query is handler-level, so two
/// exactly-concurrent identical POSTs can still land two rows — harmless,
/// ownership is set-membership.)
pub async fn create<V, Rd, O>(
    State(state): State<Arc<OwnershipState<V, Rd, O>>>,
    headers: HeaderMap,
    Json(body): Json<CreateOwnershipBody>,
) -> Result<(StatusCode, Json<OwnershipRow>), RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    O: OwnershipStore,
{
    let now = now_unix();
    let caller = authenticate_caller(&headers, &state, now).await?;
    if !state
        .schema
        .may_grant(
            &OwnershipTuples::at(&*state.store, now),
            &caller.sub,
            &body.resource_kind,
            &body.resource_id,
            &body.relationship,
        )
        .await?
    {
        return Err(RouteError::GrantForbidden);
    }
    let (granted_by, on_behalf_of) = caller.attribution();
    let subject = Subject::from_parts(
        body.principal_id,
        body.subject_kind,
        body.subject_id,
        body.subject_relation,
    )
    .map_err(OwnershipValidationError::from)?;
    let new = NewOwnership::new(
        subject,
        body.resource_kind,
        body.resource_id,
        body.relationship,
        granted_by,
        on_behalf_of,
    )?;
    let existing = match &new.subject {
        Subject::Principal(p) => state.store.list_for_principal(p).await?,
        Subject::Set { kind, id, .. } => state.store.list_for_subject_set(kind, id).await?,
    };
    if let Some(row) = existing.into_iter().find(|r| {
        !r.is_revoked()
            && r.subject == new.subject
            && r.resource_kind == new.resource_kind
            && r.resource_id == new.resource_id
            && r.relationship == new.relationship
    }) {
        return Ok((StatusCode::OK, Json(row)));
    }
    let row = state.store.insert(&new, now).await?.row;
    Ok((StatusCode::CREATED, Json(row)))
}

/// `GET /ownership` — live rows by resource or by subject
/// ([`ListOwnershipQuery`]).
///
/// - By resource: allowed iff the caller may grant at least one relation on
///   that resource.
/// - By principal subject: only the caller's own (`principal_id` = the
///   verified `sub`). A principal names no resource to hold grant rights on,
///   so anyone else's is 403.
/// - By set subject `kind/id#relation`: allowed iff the caller may grant at
///   least one relation on the set's resource `(kind, id)` — the same right
///   the per-resource list asks for, checked where the set lives.
/// - By principal within kind `K`: allowed iff the caller may grant at least
///   one relation on the kind-level row `kind/K` — an admin of a kind may
///   enumerate who holds what within it.
pub async fn list<V, Rd, O>(
    State(state): State<Arc<OwnershipState<V, Rd, O>>>,
    headers: HeaderMap,
    Query(query): Query<ListOwnershipQuery>,
) -> Result<Json<Vec<OwnershipRow>>, RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    O: OwnershipStore,
{
    let now = now_unix();
    let caller = authenticate_caller(&headers, &state, now).await?;
    let target = query.target()?;
    let tuples = OwnershipTuples::at(&*state.store, now);
    let rows = match target {
        ListTarget::Resource { kind, id } => {
            if !state.schema.may_grant_any(&tuples, &caller.sub, &kind, &id).await? {
                return Err(RouteError::GrantForbidden);
            }
            state.store.list_for_resource(&kind, &id).await?
        }
        ListTarget::Subject(Subject::Principal(p)) => {
            if p != caller.sub {
                return Err(RouteError::GrantForbidden);
            }
            state.store.list_for_principal(&p).await?
        }
        ListTarget::Subject(Subject::Set { kind, id, relation }) => {
            if !state.schema.may_grant_any(&tuples, &caller.sub, &kind, &id).await? {
                return Err(RouteError::GrantForbidden);
            }
            let mut rows = state.store.list_for_subject_set(&kind, &id).await?;
            rows.retain(|r| r.subject.as_set().is_some_and(|(_, _, rel)| rel == relation));
            rows
        }
        ListTarget::PrincipalInKind { principal, kind } => {
            if !state
                .schema
                .may_grant_any(&tuples, &caller.sub, cheers_core::KIND_RESOURCE, &kind)
                .await?
            {
                return Err(RouteError::GrantForbidden);
            }
            // list_for_principal is live-only and direct-holder-only.
            let mut rows = state.store.list_for_principal(&principal).await?;
            rows.retain(|r| r.resource_kind == kind);
            rows
        }
    };
    Ok(Json(rows))
}

/// `DELETE /ownership/{id}` — soft-delete a row if the caller holds it (the
/// subject is the caller itself) or may grant its relation on its resource,
/// through [`revoke_ownership`] (module docs). `204` on success (re-revoking is
/// a no-op), `404` for an unknown id, `403` without grant rights, `500` if
/// the membership entry could not be recorded — the row is revoked by then,
/// and repeating the `DELETE` records it.
pub async fn revoke<V, Rd, O>(
    State(state): State<Arc<OwnershipState<V, Rd, O>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    O: OwnershipStore,
{
    let now = now_unix();
    let caller = authenticate_caller(&headers, &state, now).await?;
    let row = state
        .store
        .get(&id)
        .await
        .map_err(map_store_error)?
        .ok_or(RouteError::UnknownOwnership)?;
    if !state
        .schema
        .may_revoke(&OwnershipTuples::at(&*state.store, now), &caller.sub, &row)
        .await?
    {
        return Err(RouteError::GrantForbidden);
    }
    revoke_ownership(&*state.store, &*state.revocations, &id, now)
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
