//! Magic-link route smoke + round-trip tests. Drives the two routes through
//! a CapturingMailer so the integration test can recover the click-through
//! URL from the rendered email body — the same shape the upstream
//! cheers/src/email/template.rs integration test uses.

#![cfg(feature = "email")]

use crate::common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

use cheers::email::magic_link::{
    MagicLinkCodec, MagicLinkProvider, MagicLinkUrlBuilder, MemoryUsedJtiStore,
};
use cheers::email::{CapturingMailer, MagicLinkEmail};
use cheers_axum::magic_link::{MagicLinkAuthState, router};
use cheers_axum::me::SessionDirectory;
use cheers_core::{DeviceBinding, UserId};
use cheers_server::UserStore;

use common::{MemSessionDirectory, TestAuthority, body_to_string, test_authority};

type RouterState = MagicLinkAuthState<
    cheers_server::HmacBlobCodec,
    common::MemRefreshStore,
    common::MemUserStore,
    common::MemRevocations,
    MemoryUsedJtiStore,
    CapturingMailer,
>;

const VERIFY_BASE: &str = "/auth/magic-link/verify";

/// Wall-clock seconds, matching the `now_unix()` the route handlers use.
fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .expect("clock past epoch")
}

fn build_app() -> (
    Router,
    Arc<RouterState>,
    Arc<TestAuthority>,
    Arc<MemSessionDirectory>,
) {
    let codec = MagicLinkCodec::new(&[7u8; 32], 900).unwrap();
    let urls = MagicLinkUrlBuilder::new(format!("https://app.example{VERIFY_BASE}"));
    let provider = Arc::new(MagicLinkProvider::new(codec, urls, MemoryUsedJtiStore::new()));
    let mailer = Arc::new(CapturingMailer::new());
    let authority = Arc::new(test_authority());
    let template = MagicLinkEmail::new("Acme", "Acme <noreply@acme.example>");

    let sessions = Arc::new(MemSessionDirectory::default());

    let state = Arc::new(MagicLinkAuthState {
        provider,
        mailer,
        authority: authority.clone(),
        template,
        recorder: sessions.clone(),
    });
    let app = Router::new().nest("/auth", router(state.clone()));
    (app, state, authority, sessions)
}

async fn json_post(app: &Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(uri)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let raw = body_to_string(resp.into_body()).await;
    let value = if raw.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&raw).unwrap_or(Value::String(raw))
    };
    (status, value)
}

async fn http_get(app: &Router, uri: &str) -> (StatusCode, Value) {
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let raw = body_to_string(resp.into_body()).await;
    let value = if raw.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&raw).unwrap_or(Value::String(raw))
    };
    (status, value)
}

/// Pull the `token` query param out of a `https://app.example/auth/...?token=...`
/// URL captured from the mailer.
fn extract_token(url: &str) -> String {
    let q = url.split_once('?').expect("url has query").1;
    for pair in q.split('&') {
        if let Some(v) = pair.strip_prefix("token=") {
            return v.to_owned();
        }
    }
    panic!("token param missing in {url}");
}

#[tokio::test]
async fn request_then_verify_creates_user_and_mints_session() {
    let (app, state, authority, sessions) = build_app();

    let (status, body) = json_post(
        &app,
        "/auth/magic-link/request",
        json!({ "email": "alice@example.com" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["ok"], true);

    let captured = state.mailer.last().expect("mailer captured a send");
    assert_eq!(captured.to, "alice@example.com");
    assert_eq!(captured.from, "Acme <noreply@acme.example>");
    assert!(captured.text.contains("https://app.example/auth/magic-link/verify?token="));

    // Walk the URL out of the email body and feed it to verify.
    let url_start = captured
        .text
        .find("https://app.example/auth/magic-link/verify?token=")
        .unwrap();
    let url = captured.text[url_start..].split_whitespace().next().unwrap();
    let token = extract_token(url);

    let (status, verify_body) =
        http_get(&app, &format!("{VERIFY_BASE}?token={token}")).await;
    assert_eq!(status, StatusCode::OK, "got {verify_body}");
    assert_eq!(verify_body["token_type"], "Bearer");
    assert!(!verify_body["access_token"].as_str().unwrap().is_empty());
    assert!(!verify_body["refresh_token"].as_str().unwrap().is_empty());
    let user_id = verify_body["user_id"].as_str().unwrap();
    assert!(user_id.starts_with("u-"));

    // The user landed in the store, and the id the route handed back is the
    // one that resolves to it — the by-id accessor is the path a service takes
    // when all it holds is a verified bearer, whose `sub` is this same id.
    let stored = authority
        .users()
        .get(&UserId::new(user_id))
        .await
        .expect("get by id")
        .expect("user persisted under the id the route returned");
    assert_eq!(stored.email.as_deref(), Some("alice@example.com"));

    // The ceremony reported the session to the recorder — this row is what a
    // product's SessionDirectory later serves from GET /me/sessions, and the
    // binding is the one only this ceremony knows.
    let recorded = sessions
        .list_sessions(&UserId::new(user_id.to_owned()), now())
        .await
        .expect("directory read");
    assert_eq!(recorded.len(), 1, "one device recorded: {recorded:?}");
    assert_eq!(recorded[0].binding, DeviceBinding::EmailMagicLink);
    assert_eq!(
        recorded[0].device_id.clone().into_inner(),
        verify_body["device_id"].as_str().unwrap(),
        "recorded device is the one the client was handed"
    );
    // The recorded lifetime is the refresh chain's, not the minutes-long
    // access TTL — that is the window a sessions UI reports.
    assert!(
        recorded[0].expires_at - recorded[0].issued_at > 3600,
        "refresh-chain lifetime, got {}s",
        recorded[0].expires_at - recorded[0].issued_at
    );

    // Replay of the same token is rejected (single-use).
    let (status, body) = http_get(&app, &format!("{VERIFY_BASE}?token={token}")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "already_used");
}

#[tokio::test]
async fn request_rejects_invalid_email() {
    let (app, _state, _authority, _sessions) = build_app();
    let (status, body) = json_post(
        &app,
        "/auth/magic-link/request",
        json!({ "email": "not-an-email" }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "invalid_email");
}

#[tokio::test]
async fn verify_rejects_malformed_token() {
    let (app, _state, _authority, _sessions) = build_app();
    let (status, body) = http_get(&app, &format!("{VERIFY_BASE}?token=not-a-real-token")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "magic_link_token");
}

#[tokio::test]
async fn verify_returns_same_user_on_repeated_logins() {
    let (app, state, authority, sessions) = build_app();

    // First request → first user row created.
    let _ = json_post(
        &app,
        "/auth/magic-link/request",
        json!({ "email": "bob@example.com" }),
    )
    .await;
    let url = state.mailer.last().unwrap().text;
    let url_start = url
        .find("https://app.example/auth/magic-link/verify?token=")
        .unwrap();
    let token = extract_token(url[url_start..].split_whitespace().next().unwrap());
    let (_status, first) =
        http_get(&app, &format!("{VERIFY_BASE}?token={token}")).await;

    // Second request → user already exists, link_provider is idempotent.
    let _ = json_post(
        &app,
        "/auth/magic-link/request",
        json!({ "email": "bob@example.com" }),
    )
    .await;
    let url = state.mailer.last().unwrap().text;
    let url_start = url
        .find("https://app.example/auth/magic-link/verify?token=")
        .unwrap();
    let token = extract_token(url[url_start..].split_whitespace().next().unwrap());
    let (status, second) =
        http_get(&app, &format!("{VERIFY_BASE}?token={token}")).await;
    assert_eq!(status, StatusCode::OK, "got {second}");
    assert_eq!(first["user_id"], second["user_id"]);
    assert_eq!(authority.users().user_count(), 1);

    // One user, two sign-ins, two device rows: verify mints a fresh device id
    // per click, so the recorder's `(user, device)` key does not collapse them
    // and the user can see (and revoke) each one separately.
    let recorded = sessions
        .list_sessions(&UserId::new(second["user_id"].as_str().unwrap().to_owned()), now())
        .await
        .expect("directory read");
    assert_eq!(recorded.len(), 2, "one row per sign-in: {recorded:?}");
    assert!(recorded
        .iter()
        .all(|r| r.binding == DeviceBinding::EmailMagicLink));
}
