//! Integration tests for the `POST /auth/refresh` door (R730).
//!
//! Always-on route (no provider feature), so this suite runs in every
//! `--features …` combo. Sessions are minted straight through the authority
//! and recorded through the same `SessionRecorder` call the ceremonies make,
//! so the binding the door resolves comes from real recorder rows.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use cheers_core::{DeviceBinding, DeviceId, UserId};
use cheers_server::{NewSession, SessionAuthority, SessionPolicy};
use tower::ServiceExt;

use cheers_axum::me::{MeAuthState, SessionRecorder, router as me_router};
use cheers_axum::refresh::{DirectoryBindings, RefreshAuthState, router as refresh_router};

use crate::common::{
    MemRevocations, MemSessionDirectory, TestAuthority, body_to_string, test_edge, test_minter,
};

fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .expect("clock past epoch")
}

struct Rig {
    app: Router,
    authority: Arc<TestAuthority>,
    directory: Arc<MemSessionDirectory>,
}

/// `/auth/refresh` + `/api/me/sessions` over one authority and one session
/// table — the shape a product mounts.
fn rig(policy: SessionPolicy) -> Rig {
    let revocations = MemRevocations::default();
    let authority = Arc::new(
        SessionAuthority::new(
            test_minter(),
            crate::common::MemRefreshStore::default(),
            crate::common::MemUserStore::default(),
            revocations.clone(),
        )
        .with_policy(policy),
    );
    let directory = Arc::new(MemSessionDirectory::default());
    let refresh = Arc::new(RefreshAuthState {
        authority: authority.clone(),
        bindings: Arc::new(DirectoryBindings(directory.clone())),
        recorder: directory.clone(),
    });
    let me = Arc::new(MeAuthState {
        edge: Arc::new(test_edge(revocations)),
        authority: authority.clone(),
        directory: directory.clone(),
    });
    let app = Router::new()
        .nest("/auth", refresh_router(refresh))
        .nest("/api", me_router(me));
    Rig {
        app,
        authority,
        directory,
    }
}

/// Establish a session for `(u1, d1)` at `at`; record it iff `record`.
async fn sign_in(rig: &Rig, at: i64, record: bool) -> NewSession {
    let session = rig
        .authority
        .establish(
            UserId::new("u1"),
            DeviceId::new("d1"),
            DeviceBinding::EmailMagicLink,
            at,
        )
        .await
        .expect("establish");
    if record {
        rig.directory
            .record_new_session(&session)
            .await
            .expect("record");
    }
    session
}

async fn post_refresh(app: &Router, token: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .method("POST")
        .uri("/auth/refresh")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::json!({ "refresh_token": token }).to_string(),
        ))
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = body_to_string(resp.into_body()).await;
    (status, serde_json::from_str(&body).expect("json body"))
}

fn str_field<'a>(body: &'a serde_json::Value, key: &str) -> &'a str {
    body[key].as_str().unwrap_or_else(|| panic!("{key} in {body}"))
}

#[tokio::test]
async fn refresh_returns_a_new_pair_and_spends_the_old_token() {
    let rig = rig(SessionPolicy::default());
    let first = sign_in(&rig, now(), true).await;
    let old = first.refresh.token.as_str().to_owned();

    let (status, body) = post_refresh(&rig.app, &old).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(str_field(&body, "token_type"), "Bearer");
    assert_eq!(str_field(&body, "user_id"), "u1");
    assert_eq!(str_field(&body, "device_id"), "d1");
    assert_ne!(str_field(&body, "refresh_token"), old);
    assert_ne!(str_field(&body, "access_token"), first.access_token);
    assert_ne!(str_field(&body, "jti"), first.claims.jti);
    assert!(body["access_expires_at"].as_i64().unwrap() > 0);
    assert!(body["refresh_expires_at"].as_i64().unwrap() >= first.refresh.record.expires_at);

    // The minted access token carries the binding the recorder rows hold.
    let claims = test_edge(MemRevocations::default())
        .verify_at(str_field(&body, "access_token"), now())
        .await
        .expect("new access token verifies");
    assert_eq!(claims.binding, DeviceBinding::EmailMagicLink);

    // The successor is live and keeps the chain going.
    let (status, _) = post_refresh(&rig.app, str_field(&body, "refresh_token")).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn replaying_a_spent_token_is_401_and_revokes_the_chain() {
    let rig = rig(SessionPolicy::default());
    let first = sign_in(&rig, now(), true).await;
    let old = first.refresh.token.as_str().to_owned();

    let (status, body) = post_refresh(&rig.app, &old).await;
    assert_eq!(status, StatusCode::OK);
    let newer = str_field(&body, "refresh_token").to_owned();

    // Reuse of the spent token.
    let (status, body) = post_refresh(&rig.app, &old).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(str_field(&body, "error"), "unauthorized");

    // Reuse detection severed the chain: the legitimate successor dies too.
    let (status, _) = post_refresh(&rig.app, &newer).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_token_is_401() {
    // Zero-second refresh TTL: the root expires at its own issue time.
    let rig = rig(SessionPolicy::default().with_refresh_ttl(0));
    let first = sign_in(&rig, now(), true).await;
    let (status, body) = post_refresh(&rig.app, first.refresh.token.as_str()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn unknown_token_is_401() {
    let rig = rig(SessionPolicy::default());
    let (status, body) = post_refresh(&rig.app, "never-issued").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn no_recorded_binding_is_401_mints_nothing_and_spends_nothing() {
    let rig = rig(SessionPolicy::default());
    // Minted, but never recorded: the directory knows no binding for d1.
    let first = sign_in(&rig, now(), false).await;
    let token = first.refresh.token.as_str().to_owned();

    let (status, body) = post_refresh(&rig.app, &token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(body.get("access_token").is_none(), "{body}");
    assert!(body.get("refresh_token").is_none(), "{body}");

    // Refused before commit: once the row exists the same token rotates
    // (a spent token would have been a replay, and revoked the chain).
    rig.directory
        .record_new_session(&first)
        .await
        .expect("record");
    let (status, body) = post_refresh(&rig.app, &token).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn me_sessions_reports_the_extended_chain_expiry() {
    let rig = rig(SessionPolicy::default());
    let signed_in_at = now() - 1_000;
    let first = sign_in(&rig, signed_in_at, true).await;

    let (status, body) = post_refresh(&rig.app, first.refresh.token.as_str()).await;
    assert_eq!(status, StatusCode::OK);
    let new_expiry = body["refresh_expires_at"].as_i64().unwrap();
    assert!(new_expiry > first.refresh.record.expires_at);

    let req = Request::builder()
        .uri("/api/me/sessions")
        .header(
            header::AUTHORIZATION,
            format!("Bearer {}", str_field(&body, "access_token")),
        )
        .body(Body::empty())
        .unwrap();
    let resp = rig.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let rows: serde_json::Value =
        serde_json::from_str(&body_to_string(resp.into_body()).await).unwrap();
    let rows = rows.as_array().unwrap();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["device_id"], "d1");
    assert_eq!(rows[0]["is_current"], true);
    assert_eq!(rows[0]["expires_at"].as_i64().unwrap(), new_expiry);
    // A rotation extends the session; it does not re-date the sign-in.
    assert_eq!(rows[0]["issued_at"].as_i64().unwrap(), signed_in_at);
}
