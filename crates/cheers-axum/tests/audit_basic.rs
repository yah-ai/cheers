//! Integration tests for the `/audit` surface.
//!
//! `POST /audit/ingest` — R020-F13 verify clauses:
//!
//! 1. Batch POST 100 records: every record is present in the audit store
//!    after a single call.
//! 2. A record with a forbidden shape (empty `aud`) returns 4xx + does not
//!    commit the batch; kamaji's retry of the corrected batch succeeds.
//! 3. Negative auth: a token without `audit:write` is rejected 403 BEFORE
//!    the store is touched.
//!
//! The "user-principal token requesting audit:write at grant time is
//! rejected" verify item is covered by cheers-core's
//! `validate_grant_rejects_service_only_for_user` test against
//! `Scope::AuditWrite` — that's the canonical enforcement point per
//! composition rule (4); this surface is defense in depth.
//!
//! `GET /audit/by-on-behalf-of/{user}` — R020-F14 verify clauses:
//!
//! 1. The W127 dashboard service principal queries another user's audit —
//!    succeeds (`dashboard_service_reads_another_users_audit`).
//! 2. Random user A queries user B's audit — 403
//!    (`user_a_querying_user_b_audit_is_403`).

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use cheers_core::{AuthStrength, McpClaims, PrincipalId, Scope};
use cheers_server::{AuditRecord, AuditStore, MemoryAuditStore, PasetoV4SecretMinter};
use tower::ServiceExt;

use cheers_axum::audit::{AuditState, router as audit_router};
use cheers_axum::mcp::McpAuthState;

use crate::common::body_to_string;

fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .expect("clock past epoch")
}

/// `kid` [`rig`]'s [`McpAuthState`] expects — every token minted for these
/// tests must carry it in the PASETO footer (R592-B7).
const TEST_KID: &str = "audit-basic-test-kid";

fn rig() -> (Router, PasetoV4SecretMinter, Arc<MemoryAuditStore>) {
    let (minter, verifier) = PasetoV4SecretMinter::generate().expect("paseto v4 keypair");
    let store = Arc::new(MemoryAuditStore::new());
    let mcp = Arc::new(McpAuthState::new(
        verifier,
        TEST_KID,
        "https://cheers.example",
        "https://cheers.example",
    ));
    let state = Arc::new(AuditState {
        mcp,
        store: store.clone(),
    });
    let app = Router::new().merge(audit_router(state));
    (app, minter, store)
}

fn mint_token_for(
    minter: &PasetoV4SecretMinter,
    now: i64,
    sub: PrincipalId,
    scopes: Vec<Scope>,
    jti: &str,
) -> String {
    let claims = McpClaims::new(
        "https://cheers.example",
        "https://cheers.example",
        sub,
        now,
        now + 60,
        jti,
        scopes,
    )
    .with_auth_strength(AuthStrength::Bootstrap);
    minter.mint_mcp(&claims, TEST_KID).expect("mint")
}

fn mint_service_token(
    minter: &PasetoV4SecretMinter,
    now: i64,
    scopes: Vec<Scope>,
    jti: &str,
) -> String {
    mint_token_for(minter, now, PrincipalId::service("kamaji"), scopes, jti)
}

fn auth(token: &str) -> String {
    format!("Bearer {token}")
}

fn record_json(method: &str, request_id: &str, aud: &str) -> serde_json::Value {
    serde_json::json!({
        "at": 1_700_000_000,
        "sub": "user:alice",
        "camp_id": "camp-a",
        "aud": aud,
        "method": method,
        "scope": ["cloud:deploy"],
        "result": "allow",
        "request_id": request_id,
    })
}

#[tokio::test]
async fn batch_post_100_records_all_landed() {
    let (app, minter, store) = rig();
    let now = now();
    let token = mint_service_token(&minter, now, vec![Scope::AuditWrite], "jti-100");

    let batch: Vec<serde_json::Value> = (0..100)
        .map(|i| record_json("POST /cloud/deploy", &format!("rid-{i}"), "https://kamaji.example"))
        .collect();
    let body = serde_json::Value::Array(batch);

    let req = Request::builder()
        .method("POST")
        .uri("/audit/ingest")
        .header(header::AUTHORIZATION, auth(&token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    let body_text = body_to_string(resp.into_body()).await;
    let returned: serde_json::Value = serde_json::from_str(&body_text).expect("json body");
    let rows = returned
        .get("rows")
        .and_then(|v| v.as_array())
        .expect("rows array");
    assert_eq!(rows.len(), 100);
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(
            row.get("record")
                .and_then(|r| r.get("request_id"))
                .and_then(|v| v.as_str()),
            Some(format!("rid-{i}").as_str()),
        );
    }

    // The store has every record durably appended.
    assert_eq!(store.snapshot().len(), 100);
}

#[tokio::test]
async fn forbidden_shape_returns_400_and_backed_off_retry_succeeds() {
    let (app, minter, store) = rig();
    let now = now();
    let token = mint_service_token(&minter, now, vec![Scope::AuditWrite], "jti-bad");

    // First call: one record has an empty `aud` — atomic batch rejection.
    let mut bad_batch: Vec<serde_json::Value> = (0..3)
        .map(|i| record_json("POST /x", &format!("rid-{i}"), "https://kamaji.example"))
        .collect();
    bad_batch[1] = record_json("POST /x", "rid-1", ""); // empty aud — forbidden shape

    let req = Request::builder()
        .method("POST")
        .uri("/audit/ingest")
        .header(header::AUTHORIZATION, auth(&token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::Value::Array(bad_batch).to_string()))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    let body = body_to_string(resp.into_body()).await;
    assert!(body.contains("audit_invalid"), "expected audit_invalid: {body}");
    assert!(
        store.snapshot().is_empty(),
        "no records may be committed on a 4xx batch — atomic semantics",
    );

    // Backed-off retry with the corrected batch (same call shape, fixed aud).
    let good_batch: Vec<serde_json::Value> = (0..3)
        .map(|i| record_json("POST /x", &format!("rid-{i}"), "https://kamaji.example"))
        .collect();
    let req = Request::builder()
        .method("POST")
        .uri("/audit/ingest")
        .header(header::AUTHORIZATION, auth(&token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::Value::Array(good_batch).to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CREATED);
    assert_eq!(store.snapshot().len(), 3);
}

#[tokio::test]
async fn missing_audit_write_returns_403_before_any_store_call() {
    let (app, minter, store) = rig();
    let now = now();
    // CloudDeploy is held; AuditWrite is not.
    let token = mint_service_token(&minter, now, vec![Scope::CloudDeploy], "jti-noscope");

    let batch = serde_json::Value::Array(vec![record_json(
        "POST /x",
        "rid-1",
        "https://kamaji.example",
    )]);

    let req = Request::builder()
        .method("POST")
        .uri("/audit/ingest")
        .header(header::AUTHORIZATION, auth(&token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(batch.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    let body = body_to_string(resp.into_body()).await;
    assert!(
        body.contains("insufficient_scope"),
        "expected insufficient_scope: {body}"
    );
    assert!(
        store.snapshot().is_empty(),
        "AuditStore::insert_batch must not be called on scope failure"
    );
}

// ---------------------------------------------------------------------------
// GET /audit/by-on-behalf-of/{user} — R020-F14
// ---------------------------------------------------------------------------

/// Seed `store` with a small, deterministic history: `count` deploys for
/// `sub` plus one non-deploy row, so the prefix filter has something to
/// exclude.
async fn seed_for(store: &MemoryAuditStore, sub: &PrincipalId, count: i64, tag: &str) {
    let mut batch: Vec<AuditRecord> = (0..count)
        .map(|i| {
            AuditRecord::new(
                1_700_000_000 + i,
                sub.clone(),
                None,
                Some("camp-a".into()),
                "https://kamaji.example",
                "cloud.deploy",
                vec![Scope::CloudDeploy],
                "allow",
                format!("{tag}-deploy-{i}"),
            )
            .expect("fixture validates")
        })
        .collect();
    batch.push(
        AuditRecord::new(
            1_700_000_900,
            sub.clone(),
            None,
            None,
            "https://kamaji.example",
            "board.write",
            vec![],
            "allow",
            format!("{tag}-board"),
        )
        .expect("fixture validates"),
    );
    store.insert_batch(&batch, 1_800_000_000).await.unwrap();
}

async fn get_audit(app: &Router, token: &str, uri: &str) -> (StatusCode, String) {
    let req = Request::builder()
        .method("GET")
        .uri(uri)
        .header(header::AUTHORIZATION, auth(token))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    (status, body_to_string(resp.into_body()).await)
}

fn request_ids(body: &str) -> Vec<String> {
    let v: serde_json::Value = serde_json::from_str(body).expect("json body");
    v.get("rows")
        .and_then(|r| r.as_array())
        .expect("rows array")
        .iter()
        .map(|row| {
            row.get("record")
                .and_then(|r| r.get("request_id"))
                .and_then(|s| s.as_str())
                .expect("request_id")
                .to_owned()
        })
        .collect()
}

fn next_cursor(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).expect("json body");
    v.get("next_cursor")
        .and_then(|c| c.as_str())
        .map(|s| s.to_owned())
}

/// Verify line #1 — the W127 dashboard service principal queries a user's
/// audit and gets it.
#[tokio::test]
async fn dashboard_service_reads_another_users_audit() {
    let (app, minter, store) = rig();
    let now = now();
    let alice = PrincipalId::user("alice");
    seed_for(&store, &alice, 3, "alice").await;
    seed_for(&store, &PrincipalId::user("bob"), 2, "bob").await;

    let token = mint_token_for(
        &minter,
        now,
        PrincipalId::service("w127-dashboard"),
        vec![Scope::AuditRead],
        "jti-dash",
    );
    let (status, body) =
        get_audit(&app, &token, "/audit/by-on-behalf-of/user:alice").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let ids = request_ids(&body);
    assert_eq!(ids.len(), 4, "3 deploys + 1 board row: {ids:?}");
    assert!(
        ids.iter().all(|id| id.starts_with("alice-")),
        "bob's rows must not appear in alice's page: {ids:?}",
    );
    // Newest first.
    assert_eq!(ids[0], "alice-board");
    assert_eq!(next_cursor(&body), None, "one page covers 4 rows");
}

/// Verify line #2 — random user A asking for user B's audit is 403, even
/// holding a valid `audit:read` token.
#[tokio::test]
async fn user_a_querying_user_b_audit_is_403() {
    let (app, minter, store) = rig();
    let now = now();
    seed_for(&store, &PrincipalId::user("bob"), 2, "bob").await;

    let token = mint_token_for(
        &minter,
        now,
        PrincipalId::user("alice"),
        vec![Scope::AuditRead],
        "jti-a-reads-b",
    );
    let (status, body) = get_audit(&app, &token, "/audit/by-on-behalf-of/user:bob").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body.contains("audit_subject_forbidden"),
        "expected audit_subject_forbidden: {body}",
    );
    assert!(
        !body.contains("bob-deploy"),
        "a denied read must not leak any row: {body}",
    );
}

#[tokio::test]
async fn user_reads_their_own_audit() {
    let (app, minter, store) = rig();
    let now = now();
    let alice = PrincipalId::user("alice");
    seed_for(&store, &alice, 2, "alice").await;

    let token = mint_token_for(&minter, now, alice, vec![Scope::AuditRead], "jti-self");
    let (status, body) =
        get_audit(&app, &token, "/audit/by-on-behalf-of/user:alice").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(request_ids(&body).len(), 3);
}

#[tokio::test]
async fn read_without_audit_read_scope_is_403_insufficient_scope() {
    let (app, minter, store) = rig();
    let now = now();
    seed_for(&store, &PrincipalId::user("alice"), 2, "alice").await;

    // A kamaji-shaped token: it can WRITE audit but was never granted read.
    let token = mint_token_for(
        &minter,
        now,
        PrincipalId::service("kamaji"),
        vec![Scope::AuditWrite],
        "jti-noread",
    );
    let (status, body) =
        get_audit(&app, &token, "/audit/by-on-behalf-of/user:alice").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        body.contains("insufficient_scope"),
        "expected insufficient_scope: {body}",
    );
}

#[tokio::test]
async fn read_without_bearer_is_401() {
    let (app, _minter, _store) = rig();
    let req = Request::builder()
        .method("GET")
        .uri("/audit/by-on-behalf-of/user:alice")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn since_and_method_prefix_narrow_the_page() {
    let (app, minter, store) = rig();
    let now = now();
    let alice = PrincipalId::user("alice");
    seed_for(&store, &alice, 5, "alice").await;

    let token = mint_token_for(
        &minter,
        now,
        PrincipalId::service("w127-dashboard"),
        vec![Scope::AuditRead],
        "jti-filters",
    );

    // method-prefix drops the board.write row.
    let (status, body) = get_audit(
        &app,
        &token,
        "/audit/by-on-behalf-of/user:alice?method-prefix=cloud.deploy",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ids = request_ids(&body);
    assert_eq!(ids.len(), 5, "{ids:?}");
    assert!(ids.iter().all(|id| id.contains("deploy")), "{ids:?}");

    // since is an inclusive lower bound on `at`; deploys run at ..000–..004
    // and the board row at ..900.
    let (status, body) = get_audit(
        &app,
        &token,
        "/audit/by-on-behalf-of/user:alice?since=1700000003",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let ids = request_ids(&body);
    assert_eq!(ids, ["alice-board", "alice-deploy-4", "alice-deploy-3"]);

    // Both filters compose.
    let (status, body) = get_audit(
        &app,
        &token,
        "/audit/by-on-behalf-of/user:alice?since=1700000003&method-prefix=cloud.deploy",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(request_ids(&body), ["alice-deploy-4", "alice-deploy-3"]);
}

#[tokio::test]
async fn cursor_paging_walks_the_whole_history_exactly_once() {
    let (app, minter, store) = rig();
    let now = now();
    let alice = PrincipalId::user("alice");
    seed_for(&store, &alice, 9, "alice").await; // 9 deploys + 1 board = 10 rows

    let token = mint_token_for(
        &minter,
        now,
        PrincipalId::service("w127-dashboard"),
        vec![Scope::AuditRead],
        "jti-paging",
    );

    let mut seen: Vec<String> = Vec::new();
    let mut uri = "/audit/by-on-behalf-of/user:alice?limit=4".to_string();
    let mut pages = 0;
    loop {
        let (status, body) = get_audit(&app, &token, &uri).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        pages += 1;
        assert!(pages <= 5, "paging failed to terminate");
        seen.extend(request_ids(&body));
        match next_cursor(&body) {
            Some(cursor) => {
                uri = format!("/audit/by-on-behalf-of/user:alice?limit=4&cursor={cursor}");
            }
            None => break,
        }
    }
    assert_eq!(pages, 3, "10 rows at limit=4 → 4 + 4 + 2");
    assert_eq!(seen.len(), 10);
    let unique: std::collections::HashSet<_> = seen.iter().collect();
    assert_eq!(unique.len(), 10, "no row repeated across pages: {seen:?}");
}

#[tokio::test]
async fn malformed_cursor_is_400_not_a_silent_first_page() {
    let (app, minter, store) = rig();
    let now = now();
    seed_for(&store, &PrincipalId::user("alice"), 2, "alice").await;

    let token = mint_token_for(
        &minter,
        now,
        PrincipalId::service("w127-dashboard"),
        vec![Scope::AuditRead],
        "jti-badcursor",
    );
    let (status, body) = get_audit(
        &app,
        &token,
        "/audit/by-on-behalf-of/user:alice?cursor=not-a-cursor",
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body.contains("invalid_audit_query"),
        "expected invalid_audit_query: {body}",
    );
}

#[tokio::test]
async fn non_user_path_principal_is_400() {
    let (app, minter, _store) = rig();
    let now = now();
    let token = mint_token_for(
        &minter,
        now,
        PrincipalId::service("w127-dashboard"),
        vec![Scope::AuditRead],
        "jti-badpath",
    );

    // A camp principal in the path: the on_behalf_of lane is user-only.
    let (status, body) =
        get_audit(&app, &token, "/audit/by-on-behalf-of/camp:camp-a").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("invalid_audit_query"), "{body}");

    // An unprefixed segment is rejected too — cheers never guesses that a
    // bare id means `user:`.
    let (status, body) = get_audit(&app, &token, "/audit/by-on-behalf-of/alice").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("invalid_audit_query"), "{body}");
}

#[tokio::test]
async fn ingested_rows_are_readable_back_through_the_read_route() {
    // The end-to-end shape kamaji + W127 actually exercise: ingest over HTTP,
    // then read back over HTTP.
    let (app, minter, _store) = rig();
    let now = now();
    let write_token = mint_service_token(&minter, now, vec![Scope::AuditWrite], "jti-e2e-w");
    let batch = serde_json::Value::Array(vec![record_json(
        "cloud.deploy",
        "rid-e2e",
        "https://kamaji.example",
    )]);
    let req = Request::builder()
        .method("POST")
        .uri("/audit/ingest")
        .header(header::AUTHORIZATION, auth(&write_token))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(batch.to_string()))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::CREATED
    );

    // `record_json` writes sub = user:alice, so alice can read it back.
    let read_token = mint_token_for(
        &minter,
        now,
        PrincipalId::user("alice"),
        vec![Scope::AuditRead],
        "jti-e2e-r",
    );
    let (status, body) =
        get_audit(&app, &read_token, "/audit/by-on-behalf-of/user:alice").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(request_ids(&body), ["rid-e2e"]);
}

#[tokio::test]
async fn missing_bearer_returns_401() {
    let (app, _minter, store) = rig();
    let batch = serde_json::Value::Array(vec![record_json(
        "POST /x",
        "rid-1",
        "https://kamaji.example",
    )]);

    let req = Request::builder()
        .method("POST")
        .uri("/audit/ingest")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(batch.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(store.snapshot().is_empty());
}
