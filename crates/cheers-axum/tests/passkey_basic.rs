//! Passkey route smoke + round-trip tests. Drives the four routes against an
//! in-process SoftPasskey authenticator — same trick `cheers/src/passkey/`
//! tests use for the underlying ceremonies.

#![cfg(feature = "passkey")]

use crate::common;

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
use cheers_axum::passkey::{
    MemoryPasskeyFlowStore, NoPasskeyRegistrationObserver, PasskeyAuthState, router,
};
use cheers_server::PasskeyCredentialStore;

use cheers_axum::me::SessionDirectory;
use cheers_core::{DeviceBinding, UserId};

use common::{MemPasskeyStore, MemSessionDirectory, TestAuthority, body_to_string, test_authority};

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
    let rp = PasskeyRelyingParty::new(RP_ID, Url::parse(ORIGIN).unwrap())
        .expect("valid relying-party config");
    let authority = Arc::new(test_authority());
    let sessions = Arc::new(MemSessionDirectory::default());
    let state = Arc::new(PasskeyAuthState {
        relying_party: Arc::new(rp),
        authority: authority.clone(),
        credentials: Arc::new(MemPasskeyStore::default()),
        flows: Arc::new(MemoryPasskeyFlowStore::new()),
        recorder: sessions.clone(),
        registration_observer: Arc::new(NoPasskeyRegistrationObserver),
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

#[tokio::test]
async fn register_then_authenticate_round_trip_mints_a_session() {
    let (app, state, _authority, sessions) = build_app();
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

    // Registration established a session, so the recorder holds the row the
    // product's SessionDirectory will serve.
    let recorded = sessions
        .list_sessions(&UserId::new("u-1"), now())
        .await
        .expect("directory read");
    assert_eq!(recorded.len(), 1, "one device recorded: {recorded:?}");
    assert_eq!(recorded[0].binding, DeviceBinding::Passkey);
    assert_eq!(recorded[0].device_id.clone().into_inner(), "phone");

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

    // Both ceremonies reported to the recorder, and re-authenticating on a
    // device the user already has upserts on `(user, device)` rather than
    // adding a second row — otherwise a sessions UI would grow one entry per
    // sign-in on the same phone.
    let recorded = sessions
        .list_sessions(&UserId::new("u-1"), now())
        .await
        .expect("directory read");
    assert_eq!(
        recorded.len(),
        1,
        "re-auth on a known device stays one row: {recorded:?}"
    );
    assert_eq!(recorded[0].binding, DeviceBinding::Passkey);
}

#[tokio::test]
async fn register_finish_rejects_unknown_flow_id() {
    let (app, _state, _authority, _sessions) = build_app();
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
    let (app, _state, _authority, _sessions) = build_app();
    let (status, body) = json_post(
        &app,
        "/auth/passkey/authenticate/start",
        json!({ "user_id": "u-with-no-credentials" }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "unknown_credential");
}

/// Captures every `record_registered` call, in order.
#[derive(Default)]
struct CapturingObserver(std::sync::Mutex<Vec<(String, usize, usize)>>);

#[async_trait::async_trait]
impl cheers_axum::passkey::PasskeyRegistrationObserver for CapturingObserver {
    async fn record_registered(&self, user_id: &UserId, cred_id_len: usize, credential_count: usize) {
        self.0
            .lock()
            .unwrap()
            .push((user_id.as_str().to_owned(), cred_id_len, credential_count));
    }
}

#[tokio::test]
async fn registering_two_credentials_reports_widths_and_a_running_account_count() {
    let rp = PasskeyRelyingParty::new(RP_ID, Url::parse(ORIGIN).unwrap())
        .expect("valid relying-party config");
    let authority = Arc::new(test_authority());
    let sessions = Arc::new(MemSessionDirectory::default());
    let observer = Arc::new(CapturingObserver::default());
    let state = Arc::new(RouterState {
        relying_party: Arc::new(rp),
        authority: authority.clone(),
        credentials: Arc::new(MemPasskeyStore::default()),
        flows: Arc::new(MemoryPasskeyFlowStore::new()),
        recorder: sessions.clone(),
        registration_observer: observer.clone(),
    });
    let app = Router::new().nest("/auth", router(state.clone()));

    for device_id in ["phone", "laptop"] {
        let mut authenticator = WebauthnAuthenticator::new(SoftPasskey::new(true));
        let (_status, start_body) = json_post(
            &app,
            "/auth/passkey/register/start",
            json!({
                "user_id": "u-1",
                "device_id": device_id,
                "user_name": "alice@example.com",
                "user_display_name": "Alice",
            }),
        )
        .await;
        let flow_id = start_body["flow_id"].as_str().unwrap().to_owned();
        let ccr: cheers::passkey::CreationChallengeResponse =
            serde_json::from_value(start_body["challenge"].clone()).unwrap();
        let credential: RegisterPublicKeyCredential = authenticator
            .do_registration(Url::parse(ORIGIN).unwrap(), ccr)
            .expect("software authenticator registers");
        let (status, finish_body) = json_post(
            &app,
            "/auth/passkey/register/finish",
            json!({ "flow_id": flow_id, "credential": credential }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "got {finish_body}");
    }

    let observed = observer.0.lock().unwrap().clone();
    assert_eq!(observed.len(), 2, "one call per registration: {observed:?}");
    assert_eq!(observed[0].0, "u-1");
    assert_eq!(observed[1].0, "u-1");
    // A RUNNING count, not a final tally: 1 after the first credential, 2
    // after the second — the shape a per-account histogram needs (see
    // `PasskeyRegistrationObserver`'s doc comment on why).
    assert_eq!(observed[0].2, 1);
    assert_eq!(observed[1].2, 2);

    // The observed width is the actual persisted credential's, not a
    // stand-in: decode both stored credentials back to their webauthn Passkey
    // and compare cred_id() byte lengths directly.
    let stored = state
        .credentials
        .list_for_user(&UserId::new("u-1"))
        .await
        .expect("stored credentials");
    assert_eq!(stored.len(), 2);
    let mut stored_widths: Vec<usize> = stored
        .iter()
        .map(|c| {
            cheers::passkey::passkey_from_credential(c)
                .unwrap()
                .cred_id()
                .len()
        })
        .collect();
    let mut observed_widths: Vec<usize> = observed.iter().map(|(_, w, _)| *w).collect();
    stored_widths.sort_unstable();
    observed_widths.sort_unstable();
    assert_eq!(observed_widths, stored_widths);
}

// ---------------------------------------------------------------------------
// Username-less (discoverable) sign-in — R962.
//
// SoftPasskey cannot answer an empty `allowCredentials` and never returns a
// `userHandle`, so these tests hand it the discoverable challenge with the
// registered credential id filled in, then attach the `userHandle` a
// discoverable authenticator would have returned. Neither field is covered by
// the assertion signature (that covers authenticatorData + the clientData
// hash, which carries the challenge), so the server sees exactly what a real
// discoverable assertion would carry.
// ---------------------------------------------------------------------------

/// The WebAuthn user handle `register_start` has always used: a v5 UUID of
/// the `UserId`. Spelled out here rather than imported so a change to the
/// derivation — which would strand every credential already on a device —
/// fails these tests.
fn legacy_handle(user_id: &str) -> uuid::Uuid {
    uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_OID, user_id.as_bytes())
}

/// Register one credential through the routes; returns its raw credential id.
async fn register_via_routes(
    app: &Router,
    state: &RouterState,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
    user_id: &str,
    device_id: &str,
) -> Vec<u8> {
    let (status, start_body) = json_post(
        app,
        "/auth/passkey/register/start",
        json!({
            "user_id": user_id,
            "device_id": device_id,
            "user_name": format!("{user_id}@example.com"),
            "user_display_name": user_id,
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {start_body}");
    // Registration asks for a discoverable credential (R962).
    assert_eq!(
        start_body["challenge"]["publicKey"]["authenticatorSelection"]["residentKey"],
        "preferred"
    );
    let ccr: cheers::passkey::CreationChallengeResponse =
        serde_json::from_value(start_body["challenge"].clone()).unwrap();
    let credential = authenticator
        .do_registration(Url::parse(ORIGIN).unwrap(), ccr)
        .expect("software authenticator registers");
    let (status, body) = json_post(
        app,
        "/auth/passkey/register/finish",
        json!({ "flow_id": start_body["flow_id"], "credential": credential }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");

    let stored = state
        .credentials
        .list_for_user(&UserId::new(user_id))
        .await
        .unwrap();
    let row = stored
        .iter()
        .find(|c| c.device_id.as_str() == device_id)
        .expect("registered row");
    let passkey = cheers::passkey::passkey_from_credential(row).unwrap();
    // Pin the material shape cheers-server indexes by: the store-side reader
    // must land on the same key as the raw credential id.
    assert_eq!(
        cheers_server::passkey_material_credential_id(&row.material).unwrap(),
        cheers_server::passkey_credential_id_key(passkey.cred_id().as_ref()),
    );
    passkey.cred_id().as_ref().to_vec()
}

/// `discoverable/start`, then have SoftPasskey answer it for `cred_id` and
/// attach `user_handle` (or none). Returns `(flow_id, assertion JSON)`.
async fn discoverable_assertion(
    app: &Router,
    authenticator: &mut WebauthnAuthenticator<SoftPasskey>,
    cred_id: &[u8],
    user_handle: Option<uuid::Uuid>,
) -> (String, Value) {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    let (status, start) =
        json_post(app, "/auth/passkey/authenticate/discoverable/start", json!({})).await;
    assert_eq!(status, StatusCode::OK, "got {start}");
    let flow_id = start["flow_id"].as_str().unwrap().to_owned();
    let mut challenge = start["challenge"].clone();
    let allow = &challenge["publicKey"]["allowCredentials"];
    assert!(
        allow.is_null() || allow.as_array().is_some_and(|a| a.is_empty()),
        "username-less start names no credential: {allow}"
    );
    assert!(
        challenge["mediation"].is_null(),
        "cheers clears webauthn-rs's conditional mediation: {}",
        challenge["mediation"]
    );

    challenge["publicKey"]["allowCredentials"] =
        json!([{ "type": "public-key", "id": URL_SAFE_NO_PAD.encode(cred_id) }]);
    let rcr: cheers::passkey::RequestChallengeResponse =
        serde_json::from_value(challenge).unwrap();
    let assertion: PublicKeyCredential = authenticator
        .do_authentication(Url::parse(ORIGIN).unwrap(), rcr)
        .expect("software authenticator authenticates");
    let mut assertion = serde_json::to_value(&assertion).unwrap();
    assertion["response"]["userHandle"] = match user_handle {
        Some(h) => json!(URL_SAFE_NO_PAD.encode(h.as_bytes())),
        None => Value::Null,
    };
    (flow_id, assertion)
}

#[tokio::test]
async fn discoverable_start_touches_no_account() {
    // Empty credential store: a typed-username start would refuse, the
    // username-less start still issues a challenge.
    let (app, _state, _authority, _sessions) = build_app();
    let (status, body) =
        json_post(&app, "/auth/passkey/authenticate/discoverable/start", json!({})).await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert!(!body["flow_id"].as_str().unwrap().is_empty());
    assert!(!body["challenge"]["publicKey"]["challenge"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn discoverable_sign_in_resolves_the_account_from_the_credential() {
    let (app, state, _authority, sessions) = build_app();
    let mut alice_key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let mut bob_key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let alice_cred = register_via_routes(&app, &state, &mut alice_key, "u-alice", "phone").await;
    let _bob_cred = register_via_routes(&app, &state, &mut bob_key, "u-bob", "laptop").await;

    // The store finds the row by credential id alone.
    let row = state
        .credentials
        .find_by_credential_id(&alice_cred)
        .await
        .unwrap()
        .expect("found by credential id");
    assert_eq!(row.user_id.as_str(), "u-alice");

    let (flow_id, assertion) = discoverable_assertion(
        &app,
        &mut alice_key,
        &alice_cred,
        Some(legacy_handle("u-alice")),
    )
    .await;
    let (status, body) = json_post(
        &app,
        "/auth/passkey/authenticate/discoverable/finish",
        json!({ "flow_id": flow_id, "credential": assertion }),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "got {body}");
    assert_eq!(body["user_id"], "u-alice");
    assert_eq!(body["device_id"], "phone");
    assert_eq!(body["token_type"], "Bearer");
    let recorded = sessions
        .list_sessions(&UserId::new("u-alice"), now())
        .await
        .unwrap();
    assert_eq!(recorded.len(), 1, "{recorded:?}");

    // The flow is single-use.
    let (status, body) = json_post(
        &app,
        "/auth/passkey/authenticate/discoverable/finish",
        json!({ "flow_id": flow_id, "credential": assertion }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "got {body}");
    assert_eq!(body["error"], "unknown_flow");
}

#[tokio::test]
async fn discoverable_finish_refuses_a_handle_that_is_not_the_owners() {
    let (app, state, _authority, _sessions) = build_app();
    let mut alice_key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let alice_cred = register_via_routes(&app, &state, &mut alice_key, "u-alice", "phone").await;

    // Alice's credential presented under Bob's handle.
    let (flow_id, assertion) =
        discoverable_assertion(&app, &mut alice_key, &alice_cred, Some(legacy_handle("u-bob")))
            .await;
    let (status, body) = json_post(
        &app,
        "/auth/passkey/authenticate/discoverable/finish",
        json!({ "flow_id": flow_id, "credential": assertion }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "got {body}");
    assert_eq!(body["error"], "unknown_credential");
}

#[tokio::test]
async fn discoverable_finish_refuses_an_unknown_credential_id() {
    let (app, state, _authority, _sessions) = build_app();
    let mut alice_key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let alice_cred = register_via_routes(&app, &state, &mut alice_key, "u-alice", "phone").await;
    state
        .credentials
        .delete(&UserId::new("u-alice"), &cheers_core::DeviceId::new("phone"))
        .await
        .unwrap();

    let (flow_id, assertion) = discoverable_assertion(
        &app,
        &mut alice_key,
        &alice_cred,
        Some(legacy_handle("u-alice")),
    )
    .await;
    let (status, body) = json_post(
        &app,
        "/auth/passkey/authenticate/discoverable/finish",
        json!({ "flow_id": flow_id, "credential": assertion }),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "got {body}");
    assert_eq!(body["error"], "unknown_credential");
}

#[tokio::test]
async fn discoverable_finish_refuses_an_assertion_without_a_user_handle() {
    let (app, state, _authority, _sessions) = build_app();
    let mut alice_key = WebauthnAuthenticator::new(SoftPasskey::new(true));
    let alice_cred = register_via_routes(&app, &state, &mut alice_key, "u-alice", "phone").await;

    let (flow_id, assertion) =
        discoverable_assertion(&app, &mut alice_key, &alice_cred, None).await;
    let (status, body) = json_post(
        &app,
        "/auth/passkey/authenticate/discoverable/finish",
        json!({ "flow_id": flow_id, "credential": assertion }),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "got {body}");
    assert!(body["access_token"].is_null(), "no session minted: {body}");
}
