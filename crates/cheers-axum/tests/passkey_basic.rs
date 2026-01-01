//! Passkey route smoke + round-trip tests. Drives the four routes against an
//! in-process SoftPasskey authenticator — same trick `cheers/src/passkey/`
//! tests use for the underlying ceremonies.

#![cfg(feature = "passkey")]

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;
use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softpasskey::SoftPasskey;

use cheers::passkey::{
    PasskeyRelyingParty, PublicKeyCredential, RegisterPublicKeyCredential, Url,
};
use cheers_axum::passkey::{MemoryPasskeyFlowStore, PasskeyAuthState, router};
use cheers_server::PasskeyCredentialStore;

use common::{MemPasskeyStore, TestAuthority, body_to_string, test_authority};

const RP_ID: &str = "example.com";
const ORIGIN: &str = "https://example.com";

type RouterState =
    PasskeyAuthState<
        cheers_server::HmacBlobCodec,
        common::MemRefreshStore,
        common::MemUserStore,
        common::MemRevocations,
        MemPasskeyStore,
        MemoryPasskeyFlowStore,
    >;

fn build_app() -> (Router, Arc<RouterState>, Arc<TestAuthority>) {
    let rp = PasskeyRelyingParty::new(RP_ID, Url::parse(ORIGIN).unwrap())
        .expect("valid relying-party config");
    let authority = Arc::new(test_authority());
    let state = Arc::new(PasskeyAuthState {
        relying_party: Arc::new(rp),
        authority: authority.clone(),
        credentials: Arc::new(MemPasskeyStore::default()),
        flows: Arc::new(MemoryPasskeyFlowStore::new()),
    });
    let app = Router::new().nest("/auth", router(state.clone()));
    (app, state, authority)
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

#[tokio::test]
async fn register_then_authenticate_round_trip_mints_a_session() {
    let (app, state, _authority) = build_app();
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    // 1) register/start — returns flow_id + challenge.
    let (status, start_body) = json_post(
        &app,
        "/auth/passkey/register/start",
        json!({
            "user_id": "u-1",
            "device_id": "phone",
            "user_name": "alice@example.com",
            "user_display_name": "Alice",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {start_body}");
    let reg_flow_id = start_body["flow_id"].as_str().unwrap().to_owned();
    assert!(!reg_flow_id.is_empty());
    let ccr_value = start_body["challenge"].clone();
    let ccr: cheers::passkey::CreationChallengeResponse =
        serde_json::from_value(ccr_value).expect("CreationChallengeResponse decodes");

    // 2) SoftPasskey signs the challenge.
    let credential: RegisterPublicKeyCredential = authenticator
        .do_registration(Url::parse(ORIGIN).unwrap(), ccr)
        .expect("software authenticator registers");

    // 3) register/finish — persists the credential + mints a session.
    let (status, finish_body) = json_post(
        &app,
        "/auth/passkey/register/finish",
        json!({
            "flow_id": reg_flow_id,
            "credential": credential,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {finish_body}");
    assert_eq!(finish_body["token_type"], "Bearer");
    assert_eq!(finish_body["user_id"].as_str().unwrap(), "u-1");
    assert!(!finish_body["access_token"].as_str().unwrap().is_empty());
    assert!(!finish_body["refresh_token"].as_str().unwrap().is_empty());
    assert_eq!(finish_body["device_id"].as_str().unwrap(), "phone");

    // Credential landed in the store.
    let stored = state
        .credentials
        .list_for_user(&cheers_core::UserId::new("u-1"))
        .await
        .unwrap();
    assert_eq!(stored.len(), 1);

    // 4) authenticate/start — returns a challenge over the registered cred.
    let (status, auth_start) = json_post(
        &app,
        "/auth/passkey/authenticate/start",
        json!({ "user_id": "u-1" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {auth_start}");
    let auth_flow_id = auth_start["flow_id"].as_str().unwrap().to_owned();
    let rcr_value = auth_start["challenge"].clone();
    let rcr: cheers::passkey::RequestChallengeResponse =
        serde_json::from_value(rcr_value).expect("RequestChallengeResponse decodes");

    // 5) SoftPasskey signs the assertion.
    let assertion: PublicKeyCredential = authenticator
        .do_authentication(Url::parse(ORIGIN).unwrap(), rcr)
        .expect("software authenticator authenticates");

    // 6) authenticate/finish — verifies + mints a fresh session.
    let (status, auth_finish) = json_post(
        &app,
        "/auth/passkey/authenticate/finish",
        json!({
            "flow_id": auth_flow_id,
            "credential": assertion,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {auth_finish}");
    assert_eq!(auth_finish["device_id"].as_str().unwrap(), "phone");
    assert_eq!(auth_finish["user_id"].as_str().unwrap(), "u-1");
    // Each establish() mints a fresh jti.
    assert_ne!(
        auth_finish["jti"].as_str().unwrap(),
        finish_body["jti"].as_str().unwrap()
    );
}

#[tokio::test]
async fn register_finish_rejects_unknown_flow_id() {
    let (app, _state, _authority) = build_app();
    let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));

    // Drive a real start_registration so we have a credential to send.
    let (_status, start_body) = json_post(
        &app,
        "/auth/passkey/register/start",
        json!({
            "user_id": "u-1",
            "device_id": "phone",
            "user_name": "alice@example.com",
            "user_display_name": "Alice",
        }),
    )
    .await;
    let ccr: cheers::passkey::CreationChallengeResponse =
        serde_json::from_value(start_body["challenge"].clone()).unwrap();
    let credential: RegisterPublicKeyCredential = authenticator
        .do_registration(Url::parse(ORIGIN).unwrap(), ccr)
        .unwrap();

    let (status, body) = json_post(
        &app,
        "/auth/passkey/register/finish",
        json!({
            "flow_id": "made-up-flow-id-not-stashed",
            "credential": credential,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "unknown_flow");
}

#[tokio::test]
async fn authenticate_start_rejects_user_with_no_passkeys() {
    let (app, _state, _authority) = build_app();
    let (status, body) = json_post(
        &app,
        "/auth/passkey/authenticate/start",
        json!({ "user_id": "u-with-no-credentials" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "unknown_credential");
}
