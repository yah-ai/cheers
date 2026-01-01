//! Integration tests for the `/me/sessions` routes.
//!
//! The route module is always-on (no provider feature gate), so this suite
//! runs in every `--features …` combo. It exercises:
//!
//! 1. The bearer extractor — missing header / wrong scheme / valid token
//!    paths return 401 / 401 / 200.
//! 2. `GET /me/sessions` — joins SessionDirectory rows against the verified
//!    claims and flips `is_current` on the matching device.
//! 3. `DELETE /me/sessions/{device_id}` — revoking a non-current device
//!    leaves the caller's token alive; revoking the current device flips
//!    the in-flight `jti` into the revocation set so the next request 401s.

mod common;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use cheers_core::{DeviceBinding, DeviceId, UserId};
use cheers_server::{SessionAuthority, SessionPolicy};
use tower::ServiceExt;

use cheers_axum::me::{MeAuthState, router as me_router};

use crate::common::{
    body_to_string, MemRefreshStore, MemRevocations, MemSessionDirectory, MemUserStore,
    test_edge, test_minter,
};

/// Wall-clock seconds, matching the `now_unix()` the route handlers use.
fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .expect("clock past epoch")
}

/// Wire the full /me router on top of memory stores. Returns the router, the
/// authority (so the test can directly mint sessions for fixtures), and the
/// directory (so the test can seed + observe rows).
fn rig() -> (
    Router,
    Arc<SessionAuthority<cheers_server::HmacBlobCodec, MemRefreshStore, MemUserStore, MemRevocations>>,
    Arc<MemSessionDirectory>,
    MemRevocations,
) {
    let revocations = MemRevocations::default();
    let authority = Arc::new(
        SessionAuthority::new(
            test_minter(),
            MemRefreshStore::default(),
            MemUserStore::default(),
            revocations.clone(),
        )
        // Shorter access TTL than the 15-minute default so expiry tests
        // don't have to advance time by 15 minutes.
        .with_policy(SessionPolicy::default().with_access_ttl(60)),
    );
    let directory = Arc::new(MemSessionDirectory::default());
    let edge = Arc::new(test_edge(revocations.clone()));

    let state = Arc::new(MeAuthState {
        edge,
        authority: authority.clone(),
        directory: directory.clone(),
    });
    let app = Router::new().nest("/api", me_router(state));
    (app, authority, directory, revocations)
}

/// Mint a session through the authority, mirror its `(user, device, binding,
/// issued, expires)` into the directory, and return the access token + the
/// claims it carries.
async fn seed_session(
    authority: &SessionAuthority<
        cheers_server::HmacBlobCodec,
        MemRefreshStore,
        MemUserStore,
        MemRevocations,
    >,
    directory: &MemSessionDirectory,
    user_id: &UserId,
    device_id: &DeviceId,
    binding: DeviceBinding,
    now: i64,
) -> (String, cheers_core::Claims) {
    let session = authority
        .establish(user_id.clone(), device_id.clone(), binding.clone(), now)
        .await
        .expect("establish session");
    directory.record(
        user_id.clone(),
        device_id.clone(),
        binding,
        session.refresh.record.issued_at,
        session.refresh.record.expires_at,
    );
    (session.access_token, session.claims)
}

fn auth_header(token: &str) -> String {
    format!("Bearer {token}")
}

#[tokio::test]
async fn list_returns_two_entries_with_is_current_on_caller_device() {
    let (app, authority, directory, _) = rig();
    let user = UserId::new("u-1");
    let d_phone = DeviceId::new("phone");
    let d_laptop = DeviceId::new("laptop");

    let now = now();
    let (phone_token, _) = seed_session(
        &authority,
        &directory,
        &user,
        &d_phone,
        DeviceBinding::Passkey,
        now,
    )
    .await;
    let (_, _) = seed_session(
        &authority,
        &directory,
        &user,
        &d_laptop,
        DeviceBinding::OidcGoogle,
        now,
    )
    .await;

    let req = Request::builder()
        .uri("/api/me/sessions")
        .header(header::AUTHORIZATION, auth_header(&phone_token))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).expect("json body");
    let arr = json.as_array().expect("array body");
    assert_eq!(arr.len(), 2, "two devices seeded: {body}");

    // Find rows by device_id; order is unspecified.
    let phone_row = arr
        .iter()
        .find(|v| v.get("device_id").and_then(|s| s.as_str()) == Some("phone"))
        .expect("phone row");
    let laptop_row = arr
        .iter()
        .find(|v| v.get("device_id").and_then(|s| s.as_str()) == Some("laptop"))
        .expect("laptop row");

    assert_eq!(phone_row.get("is_current"), Some(&serde_json::Value::Bool(true)));
    assert_eq!(laptop_row.get("is_current"), Some(&serde_json::Value::Bool(false)));
    assert_eq!(
        phone_row.get("binding").and_then(|b| b.get("kind")).and_then(|k| k.as_str()),
        Some("passkey"),
    );
    assert_eq!(
        laptop_row.get("binding").and_then(|b| b.get("kind")).and_then(|k| k.as_str()),
        Some("oidc_google"),
    );
}

#[tokio::test]
async fn list_rejects_missing_bearer() {
    let (app, _, _, _) = rig();
    let req = Request::builder()
        .uri("/api/me/sessions")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_to_string(resp.into_body()).await;
    assert!(body.contains("missing_bearer"), "expected missing_bearer: {body}");
}

#[tokio::test]
async fn list_rejects_wrong_scheme() {
    let (app, _, _, _) = rig();
    let req = Request::builder()
        .uri("/api/me/sessions")
        .header(header::AUTHORIZATION, "Basic abc")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_to_string(resp.into_body()).await;
    assert!(body.contains("malformed_bearer"), "expected malformed_bearer: {body}");
}

#[tokio::test]
async fn list_rejects_garbage_token() {
    let (app, _, _, _) = rig();
    let req = Request::builder()
        .uri("/api/me/sessions")
        .header(header::AUTHORIZATION, "Bearer not.a.token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body = body_to_string(resp.into_body()).await;
    assert!(body.contains("unauthorized"), "expected unauthorized: {body}");
}

#[tokio::test]
async fn revoke_other_device_returns_204_and_drops_it_from_list() {
    let (app, authority, directory, _) = rig();
    let user = UserId::new("u-2");
    let d_phone = DeviceId::new("phone");
    let d_laptop = DeviceId::new("laptop");

    let now = now();
    let (phone_token, _) = seed_session(
        &authority,
        &directory,
        &user,
        &d_phone,
        DeviceBinding::Passkey,
        now,
    )
    .await;
    seed_session(
        &authority,
        &directory,
        &user,
        &d_laptop,
        DeviceBinding::OidcGoogle,
        now,
    )
    .await;

    // The MemUserStore needs the (user, device) link recorded so its
    // revoke_device finds it. A real PgUserStore would have written this row
    // when the refresh chain was first put().
    authority.users().seed_device(&user, &d_phone);
    authority.users().seed_device(&user, &d_laptop);

    // DELETE /api/me/sessions/laptop with phone's token.
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/me/sessions/laptop")
        .header(header::AUTHORIZATION, auth_header(&phone_token))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Mirror what cheers-sqlx's PgUserStore::revoke_device would do — the
    // MemSessionDirectory and MemUserStore are decoupled in this test rig,
    // so the test forgets the row explicitly here. (A production product
    // builds SessionDirectory on the same data the UserStore writes, so a
    // single revoke flips both sides.)
    directory.forget(&user, &d_laptop);

    // The caller's bearer still works; only the laptop row should be gone.
    let req = Request::builder()
        .uri("/api/me/sessions")
        .header(header::AUTHORIZATION, auth_header(&phone_token))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_to_string(resp.into_body()).await;
    let json: serde_json::Value = serde_json::from_str(&body).unwrap();
    let arr = json.as_array().unwrap();
    assert_eq!(arr.len(), 1, "laptop should be gone: {body}");
    assert_eq!(
        arr[0].get("device_id").and_then(|s| s.as_str()),
        Some("phone"),
    );
    assert_eq!(arr[0].get("is_current"), Some(&serde_json::Value::Bool(true)));
}

#[tokio::test]
async fn revoke_current_device_kills_the_in_flight_access_token() {
    let (app, authority, directory, revocations) = rig();
    let user = UserId::new("u-3");
    let device = DeviceId::new("phone");

    let now = now();
    let (phone_token, claims) = seed_session(
        &authority,
        &directory,
        &user,
        &device,
        DeviceBinding::EmailMagicLink,
        now,
    )
    .await;
    authority.users().seed_device(&user, &device);

    // Sanity check: token verifies before we revoke.
    assert!(
        cheers_server::EdgeVerifier::new(test_minter_for_assert(), revocations.clone())
            .verify_at(&phone_token, now)
            .await
            .is_ok()
    );

    // DELETE /api/me/sessions/phone with phone's own token. Revokes the
    // device AND the in-flight jti.
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/me/sessions/phone")
        .header(header::AUTHORIZATION, auth_header(&phone_token))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // The jti landed in the revocation set; the next request with the same
    // bearer must 401.
    let req = Request::builder()
        .uri("/api/me/sessions")
        .header(header::AUTHORIZATION, auth_header(&phone_token))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // And confirm via the writer's read-side that the jti is in fact present.
    use cheers_server::RevocationReader;
    assert!(revocations.is_revoked(&claims.jti).await.unwrap());
}

/// HmacBlobCodec lacks Clone, so we build a fresh instance from the same key
/// for the sanity-verify in `revoke_current_device_*`.
fn test_minter_for_assert() -> cheers_server::HmacBlobCodec {
    cheers_server::HmacBlobCodec::new(common::TEST_HMAC_KEY)
}

#[tokio::test]
async fn revoke_unknown_device_returns_404() {
    let (app, authority, directory, _) = rig();
    let user = UserId::new("u-4");
    let device = DeviceId::new("phone");

    let now = now();
    let (phone_token, _) = seed_session(
        &authority,
        &directory,
        &user,
        &device,
        DeviceBinding::Passkey,
        now,
    )
    .await;
    authority.users().seed_device(&user, &device);

    let req = Request::builder()
        .method("DELETE")
        .uri("/api/me/sessions/ghost")
        .header(header::AUTHORIZATION, auth_header(&phone_token))
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body = body_to_string(resp.into_body()).await;
    assert!(body.contains("unknown_device"), "expected unknown_device: {body}");
}

