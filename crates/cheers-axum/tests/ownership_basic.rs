//! Integration tests for the `POST /ownership` + `DELETE /ownership/{id}`
//! routes — round-trip via `tower::Service::call` (no TCP listener).
//!
//! Covers the three verify clauses on R020-T17:
//!
//! 1. Round-trip: mint a `v4.public` token bearing `ownership:write`, POST a
//!    row, observe `OwnershipStore::get` shows it, DELETE, observe
//!    `revoked_at` is now set.
//! 2. Negative scope: a token without `ownership:write` is rejected with 403
//!    BEFORE any store side-effect (asserted by `insert_call_count == 0`).
//! 3. Negative invariant: a body whose `on_behalf_of` names a non-user
//!    principal surfaces as a 4xx via `NewOwnership::new()`, not a 500.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use cheers_core::{AuthStrength, McpClaims, PrincipalId, Scope};
use cheers_server::{OwnershipStore, PasetoV4SecretMinter};
use tower::ServiceExt;

use cheers_axum::mcp::McpAuthState;
use cheers_axum::ownership::{OwnershipState, router as ownership_router};

use crate::common::{MemOwnershipStore, body_to_string};

fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .expect("clock past epoch")
}

/// Build the full /ownership router. Returns the router, the minter (so
/// tests can forge bearer tokens), and the underlying store (so tests can
/// observe row state directly).
/// `kid` [`rig`]'s [`McpAuthState`] expects — every token minted for these
/// tests must carry it in the PASETO footer (R592-B7).
const TEST_KID: &str = "ownership-basic-test-kid";

fn rig() -> (Router, PasetoV4SecretMinter, Arc<MemOwnershipStore>) {
    let (minter, verifier) = PasetoV4SecretMinter::generate().expect("paseto v4 keypair");
    let store = Arc::new(MemOwnershipStore::default());
    let mcp = Arc::new(McpAuthState::new(
        verifier,
        TEST_KID,
        "https://cheers.example",
        "https://cheers.example",
    ));
    let state = Arc::new(OwnershipState {
        mcp,
        store: store.clone(),
    });
    let app = Router::new().nest("/api", ownership_router(state));
    (app, minter, store)
}

/// Mint a token with the given scope list, `sub = svc:yubaba`.
fn mint_token(
    minter: &PasetoV4SecretMinter,
    now: i64,
    scopes: Vec<Scope>,
    jti: &str,
) -> String {
    let claims = McpClaims::new(
        "https://cheers.example",
        "https://cheers.example",
        PrincipalId::service("yubaba"),
        now,
        now + 60,
        jti,
        scopes,
    )
    .with_auth_strength(AuthStrength::Bootstrap);
    minter.mint_mcp(&claims, TEST_KID).expect("mint")
}

/// Mint a token whose `sub` is the user-shape — used in the defense-in-depth
/// test: even if a `User` principal somehow held `ownership:write`,
/// `NewOwnership::new()` rejects `granted_by` not being a service.
fn mint_user_token(
    minter: &PasetoV4SecretMinter,
    now: i64,
    scopes: Vec<Scope>,
    jti: &str,
) -> String {
    let claims = McpClaims::new(
        "https://cheers.example",
        "https://cheers.example",
        PrincipalId::user("alice"),
        now,
        now + 60,
        jti,
        scopes,
    )
    .with_auth_strength(AuthStrength::UserFresh);
    minter.mint_mcp(&claims, TEST_KID).expect("mint")
}

fn auth(token: &str) -> String {
    format!("Bearer {token}")
}

#[tokio::test]
async fn round_trip_post_then_delete_marks_row_revoked() {
    let (app, minter, store) = rig();
    let now = now();
    let token = mint_token(&minter, now, vec![Scope::OwnershipWrite], "jti-rt");

    let body = serde_json::json!({
        "principal_id": "camp:camp-xyz",
        "resource_kind": "service",
        "resource_id": "svc-abc",
        "relationship": "owns",
        "on_behalf_of": "user:alice",
    });

    // POST /api/ownership.
    let req = Request::builder()
        .method("POST")
        .uri("/api/ownership")
        .header(header::AUTHORIZATION, auth(&token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_text = body_to_string(resp.into_body()).await;
    let returned: serde_json::Value = serde_json::from_str(&body_text).expect("json body");

    let id = returned
        .get("id")
        .and_then(|v| v.as_str())
        .expect("id field")
        .to_owned();
    // The handler must overwrite granted_by with the bearer's sub regardless
    // of body content — and bake in the auth'd principal.
    assert_eq!(
        returned.get("granted_by").and_then(|v| v.as_str()),
        Some("svc:yubaba"),
    );
    assert_eq!(
        returned.get("on_behalf_of").and_then(|v| v.as_str()),
        Some("user:alice"),
    );
    assert_eq!(
        returned.get("principal_id").and_then(|v| v.as_str()),
        Some("camp:camp-xyz"),
    );
    assert!(returned.get("revoked_at").map(|v| v.is_null()).unwrap_or(true));

    // The store really has the row.
    let row = store.get(&id).await.unwrap().expect("row present");
    assert_eq!(row.id, id);
    assert!(row.revoked_at.is_none(), "freshly inserted row is live");

    // DELETE /api/ownership/{id}.
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/ownership/{id}"))
        .header(header::AUTHORIZATION, auth(&token))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // The store row is soft-revoked.
    let row = store.get(&id).await.unwrap().expect("row still present");
    assert!(row.revoked_at.is_some(), "DELETE sets revoked_at");
}

#[tokio::test]
async fn delete_unknown_id_returns_404() {
    let (app, minter, _store) = rig();
    let now = now();
    let token = mint_token(&minter, now, vec![Scope::OwnershipWrite], "jti-404");

    let req = Request::builder()
        .method("DELETE")
        .uri("/api/ownership/no-such-row")
        .header(header::AUTHORIZATION, auth(&token))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = body_to_string(resp.into_body()).await;
    assert!(
        body.contains("unknown_ownership"),
        "expected unknown_ownership: {body}"
    );
}

#[tokio::test]
async fn post_without_ownership_write_returns_403_before_any_store_call() {
    let (app, minter, store) = rig();
    let now = now();
    // CloudRead is held; OwnershipWrite is not.
    let token = mint_token(&minter, now, vec![Scope::CloudRead], "jti-noscope");

    let body = serde_json::json!({
        "principal_id": "camp:camp-xyz",
        "resource_kind": "service",
        "resource_id": "svc-abc",
        "relationship": "owns",
        "on_behalf_of": "user:alice",
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/ownership")
        .header(header::AUTHORIZATION, auth(&token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_to_string(resp.into_body()).await;
    assert!(
        body.contains("insufficient_scope"),
        "expected insufficient_scope: {body}"
    );
    // The scope guard runs before any store call — defense-in-depth check
    // that the store was never touched.
    assert_eq!(
        store.insert_call_count(),
        0,
        "OwnershipStore::insert must not be called on auth failure"
    );
}

#[tokio::test]
async fn post_missing_bearer_returns_401_before_any_store_call() {
    let (app, _minter, store) = rig();
    let body = serde_json::json!({
        "principal_id": "camp:camp-xyz",
        "resource_kind": "service",
        "resource_id": "svc-abc",
        "relationship": "owns",
        "on_behalf_of": "user:alice",
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/ownership")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_to_string(resp.into_body()).await;
    assert!(body.contains("missing_bearer"), "expected missing_bearer: {body}");
    assert_eq!(store.insert_call_count(), 0);
}

#[tokio::test]
async fn post_with_service_on_behalf_of_is_400_ownership_invalid() {
    let (app, minter, store) = rig();
    let now = now();
    let token = mint_token(&minter, now, vec![Scope::OwnershipWrite], "jti-bad-obo");

    // `on_behalf_of` MUST be a `user:` principal when set. A `svc:` here is
    // well-formed JSON and a valid PrincipalId, but NewOwnership::new()
    // rejects it — surfaces as 400 ownership_invalid, NOT a 500 Store error.
    let body = serde_json::json!({
        "principal_id": "camp:camp-xyz",
        "resource_kind": "service",
        "resource_id": "svc-abc",
        "relationship": "owns",
        "on_behalf_of": "svc:other-yubaba",
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/ownership")
        .header(header::AUTHORIZATION, auth(&token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_to_string(resp.into_body()).await;
    assert!(
        body.contains("ownership_invalid"),
        "expected ownership_invalid: {body}"
    );
    // The store is reached only after NewOwnership::new validates — the
    // invariant guard short-circuits at the handler, no insert is attempted.
    assert_eq!(store.insert_call_count(), 0);
}

#[tokio::test]
async fn post_with_user_sub_is_rejected_by_defense_in_depth() {
    // The grant API rejects (kind=User, scope=ownership:write) at write time
    // (R020-F3 validate_grant). But if a User-sub token somehow carried that
    // scope (defense-in-depth scenario), the mint-side guard is
    // NewOwnership::new() refusing `granted_by` that isn't a Service. Result
    // is the same 400 ownership_invalid path.
    let (app, minter, store) = rig();
    let now = now();
    let token = mint_user_token(&minter, now, vec![Scope::OwnershipWrite], "jti-user");

    let body = serde_json::json!({
        "principal_id": "camp:camp-xyz",
        "resource_kind": "service",
        "resource_id": "svc-abc",
        "relationship": "owns",
        "on_behalf_of": "user:alice",
    });

    let req = Request::builder()
        .method("POST")
        .uri("/api/ownership")
        .header(header::AUTHORIZATION, auth(&token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_to_string(resp.into_body()).await;
    assert!(
        body.contains("ownership_invalid"),
        "expected ownership_invalid: {body}"
    );
    assert_eq!(store.insert_call_count(), 0);
}

#[tokio::test]
async fn delete_without_ownership_write_returns_403_before_any_store_call() {
    let (app, minter, store) = rig();
    let now = now();
    // Seed a row directly through the store so the DELETE has something to
    // target, then attempt removal with a token lacking the scope.
    let new = cheers_server::NewOwnership::new(
        PrincipalId::camp("camp-xyz"),
        "service",
        "svc-abc",
        "owns",
        PrincipalId::service("yubaba"),
        Some(PrincipalId::user("alice")),
    )
    .unwrap();
    let row = store.insert(&new, now).await.unwrap();
    // Reset the insert counter — the direct seed shouldn't count against the
    // "no store side-effect on auth failure" assertion below.
    store
        .insert_calls
        .store(0, std::sync::atomic::Ordering::SeqCst);

    let token = mint_token(&minter, now, vec![Scope::CloudRead], "jti-del-noscope");
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/ownership/{}", row.id))
        .header(header::AUTHORIZATION, auth(&token))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Row must still be live — scope guard ran before revoke_by_id.
    let row = store.get(&row.id).await.unwrap().unwrap();
    assert!(
        row.revoked_at.is_none(),
        "DELETE on auth failure must not mark the row revoked"
    );
}

#[tokio::test]
async fn duplicate_post_returns_existing_live_row_not_a_second_insert() {
    // Idempotent create: ownership rows are set-membership. A second POST
    // with the same (principal, kind, id, relationship) — cloud-init re-runs
    // and daemon restarts re-POST by design — must return the EXISTING live
    // row (200), not stack a duplicate (201). Otherwise revoking "the" row
    // leaves older live duplicates keeping the grant alive.
    let (app, minter, store) = rig();
    let now = now();
    let token = mint_token(&minter, now, vec![Scope::OwnershipWrite], "jti-dup");

    let body = serde_json::json!({
        "principal_id": "svc:yubaba",
        "resource_kind": "node",
        "resource_id": "aa11bb22",
        "relationship": "owns",
    });
    let post = |b: String, tok: String| {
        Request::builder()
            .method("POST")
            .uri("/api/ownership")
            .header(header::AUTHORIZATION, auth(&tok))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(b))
            .unwrap()
    };

    // First POST inserts — 201.
    let resp = app
        .clone()
        .oneshot(post(body.to_string(), token.clone()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let first: serde_json::Value =
        serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    let first_id = first["id"].as_str().unwrap().to_owned();

    // Identical second POST — 200 with the SAME row, no second insert.
    let resp = app
        .clone()
        .oneshot(post(body.to_string(), token.clone()))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "identical live row → 200, not 201");
    let second: serde_json::Value =
        serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    assert_eq!(second["id"].as_str().unwrap(), first_id);
    assert_eq!(store.insert_call_count(), 1, "no duplicate insert reached the store");

    // Exactly one live row for the principal.
    let live = store
        .list_for_principal(&PrincipalId::service("yubaba"))
        .await
        .unwrap();
    assert_eq!(live.len(), 1, "duplicate POST must not stack rows: {live:?}");

    // After revoking that row, an identical POST inserts a FRESH row (201):
    // revoked rows do not satisfy the idempotency match — re-enrollment
    // after eviction is a new membership, not a resurrection.
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/ownership/{first_id}"))
        .header(header::AUTHORIZATION, auth(&token))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    let resp = app
        .clone()
        .oneshot(post(body.to_string(), token))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED, "post-revoke re-POST is a fresh insert");
    let third: serde_json::Value =
        serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    assert_ne!(third["id"].as_str().unwrap(), first_id);
}

#[tokio::test]
async fn list_returns_live_rows_for_principal_and_requires_write_scope() {
    // GET /ownership?principal_id= — the writer's management read
    // (R593-F4): lets yubaba rediscover its enrollment row(s) after a
    // restart lost the in-memory row id, so eviction can still revoke.
    let (app, minter, store) = rig();
    let now = now();
    let token = mint_token(&minter, now, vec![Scope::OwnershipWrite], "jti-list");

    // Seed three rows directly through the store, then revoke one — the
    // revoked row must not appear in the listing.
    let svc = PrincipalId::service("yubaba");
    for (kind, rid) in [("node", "aa11"), ("service", "svc-x"), ("node", "bb22")] {
        let new = cheers_server::NewOwnership::new(
            svc.clone(),
            kind,
            rid,
            "owns",
            PrincipalId::service("yubaba"),
            None,
        )
        .unwrap();
        store.insert(&new, now).await.unwrap();
    }
    let bb22_id = store
        .list_for_principal(&svc)
        .await
        .unwrap()
        .iter()
        .find(|r| r.resource_id == "bb22")
        .map(|r| r.id.clone())
        .unwrap();
    store.revoke_by_id(&bb22_id, now).await.unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/api/ownership?principal_id=svc:yubaba")
        .header(header::AUTHORIZATION, auth(&token))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rows: serde_json::Value =
        serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 2, "live rows only: {rows:?}");
    let ids: Vec<&str> = rows.iter().map(|r| r["resource_id"].as_str().unwrap()).collect();
    assert!(ids.contains(&"aa11") && ids.contains(&"svc-x"), "got {ids:?}");

    // A different principal's filter sees none of svc:yubaba's rows.
    let req = Request::builder()
        .method("GET")
        .uri("/api/ownership?principal_id=svc:other")
        .header(header::AUTHORIZATION, auth(&token))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rows: serde_json::Value =
        serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 0);

    // The read is gated on ownership:write like the writes — a token
    // without the scope is 403.
    let noscope = mint_token(&minter, now, vec![Scope::CloudRead], "jti-list-noscope");
    let req = Request::builder()
        .method("GET")
        .uri("/api/ownership?principal_id=svc:yubaba")
        .header(header::AUTHORIZATION, auth(&noscope))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_only_returns_rows_granted_by_the_caller_r593_f9_tightening() {
    // Two different services (svc:yubaba, svc:other-writer) each grant a row
    // to the SAME principal (camp:shared). A caller authenticated as
    // svc:yubaba must see only its own row through GET /ownership, even
    // though both rows match the requested principal_id — closes the
    // cross-writer enumeration gap the R593-F8 adversarial review flagged.
    let (app, minter, store) = rig();
    let now = now();

    let shared = PrincipalId::camp("shared");
    let mine = cheers_server::NewOwnership::new(
        shared.clone(),
        "service",
        "svc-mine",
        "owns",
        PrincipalId::service("yubaba"),
        None,
    )
    .unwrap();
    store.insert(&mine, now).await.unwrap();
    let theirs = cheers_server::NewOwnership::new(
        shared.clone(),
        "service",
        "svc-theirs",
        "owns",
        PrincipalId::service("other-writer"),
        None,
    )
    .unwrap();
    store.insert(&theirs, now).await.unwrap();

    let token = mint_token(&minter, now, vec![Scope::OwnershipWrite], "jti-scoped-list");
    let req = Request::builder()
        .method("GET")
        .uri("/api/ownership?principal_id=camp:shared")
        .header(header::AUTHORIZATION, auth(&token))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rows: serde_json::Value =
        serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 1, "must see only its own row: {rows:?}");
    assert_eq!(
        rows[0].get("resource_id").and_then(|v| v.as_str()),
        Some("svc-mine")
    );
}

#[tokio::test]
async fn delete_returns_404_for_a_row_granted_by_a_different_writer_r593_f9_tightening() {
    // A row written by svc:other-writer must not be revocable by a caller
    // authenticated as svc:yubaba even though both hold ownership:write —
    // closes the cross-writer revoke gap. 404 (not 403) so the response
    // can't be used as an existence oracle distinguishing "not yours" from
    // "doesn't exist".
    let (app, minter, store) = rig();
    let now = now();

    let new = cheers_server::NewOwnership::new(
        PrincipalId::camp("camp-xyz"),
        "service",
        "svc-abc",
        "owns",
        PrincipalId::service("other-writer"),
        None,
    )
    .unwrap();
    let row = store.insert(&new, now).await.unwrap();

    let token = mint_token(&minter, now, vec![Scope::OwnershipWrite], "jti-del-notmine");
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/ownership/{}", row.id))
        .header(header::AUTHORIZATION, auth(&token))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = body_to_string(resp.into_body()).await;
    assert!(
        body.contains("unknown_ownership"),
        "expected unknown_ownership: {body}"
    );

    // The row is untouched — still live.
    let row = store.get(&row.id).await.unwrap().unwrap();
    assert!(
        row.revoked_at.is_none(),
        "a different writer's row must not be revoked"
    );
}
