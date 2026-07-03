//! Integration tests for `POST /audit/ingest` — R020-F13 verify clauses:
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

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use cheers_core::{AuthStrength, McpClaims, PrincipalId, Scope};
use cheers_server::{MemoryAuditStore, PasetoV4SecretMinter};
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

fn mint_service_token(
    minter: &PasetoV4SecretMinter,
    now: i64,
    scopes: Vec<Scope>,
    jti: &str,
) -> String {
    let claims = McpClaims::new(
        "https://cheers.example",
        "https://cheers.example",
        PrincipalId::service("kamaji"),
        now,
        now + 60,
        jti,
        scopes,
    )
    .with_auth_strength(AuthStrength::Bootstrap);
    minter.mint_mcp(&claims, TEST_KID).expect("mint")
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
