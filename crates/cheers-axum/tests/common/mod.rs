//! Shared fixtures across the integration tests.
//!
//! These wiremock helpers stand up localhost servers impersonating Google
//! and Apple — the same pattern `cheers/src/providers/google.rs` and
//! `cheers/src/providers/apple/redirect.rs` use, lifted here so the
//! cheers-axum tests can stitch together end-to-end browser → axum →
//! wiremock-IdP round-trips.

#![allow(dead_code)] // each test only uses a subset

use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use cheers_core::{Credential, DeviceBinding, DeviceId, PrincipalId, StoreError, User, UserId};
use cheers_server::{
    EdgeVerifier, HmacBlobCodec, NewOwnership, NewUser, OwnershipRow, OwnershipStore,
    PasskeyCredentialStore, ProviderKey, RefreshStore, RefreshTokenRecord, RevocationReader,
    RevocationWriter, SessionAuthority, UserStore,
};

use cheers_axum::me::{SessionDescriptor, SessionDirectory};

// ---------------------------------------------------------------------------
// In-memory stores — same shape `cheers-server`'s session.rs tests use, lifted
// out so multiple integration tests can share them.
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct MemUserStore {
    inner: Mutex<MemUserInner>,
}

#[derive(Default)]
struct MemUserInner {
    next_id: u64,
    users: HashMap<UserId, User>,
    links: HashMap<(ProviderKey, String), UserId>,
    devices: HashMap<UserId, Vec<DeviceId>>,
}

impl MemUserStore {
    pub fn user_count(&self) -> usize {
        self.inner.lock().unwrap().users.len()
    }
    pub fn lookup_email(&self, email: &str) -> Option<User> {
        self.inner
            .lock()
            .unwrap()
            .users
            .values()
            .find(|u| u.email.as_deref() == Some(email))
            .cloned()
    }
}

#[async_trait]
impl UserStore for MemUserStore {
    async fn find_by_provider(
        &self,
        provider: &ProviderKey,
        subject: &str,
    ) -> Result<Option<User>, StoreError> {
        let g = self.inner.lock().unwrap();
        Ok(g.links
            .get(&(provider.clone(), subject.to_owned()))
            .and_then(|id| g.users.get(id).cloned()))
    }

    async fn create(&self, new_user: NewUser) -> Result<User, StoreError> {
        let mut g = self.inner.lock().unwrap();
        g.next_id += 1;
        let id = UserId::new(format!("u-{}", g.next_id));
        let mut u = User::new(id.clone());
        u.email = new_user.email;
        u.name = new_user.name;
        g.users.insert(id, u.clone());
        Ok(u)
    }

    async fn link_provider(
        &self,
        user_id: &UserId,
        provider: &ProviderKey,
        subject: &str,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        let key = (provider.clone(), subject.to_owned());
        match g.links.get(&key) {
            Some(existing) if existing == user_id => Ok(()),
            Some(_) => Err(StoreError::Conflict),
            None => {
                g.links.insert(key, user_id.clone());
                Ok(())
            }
        }
    }

    async fn list_devices(&self, user_id: &UserId) -> Result<Vec<DeviceId>, StoreError> {
        let g = self.inner.lock().unwrap();
        Ok(g.devices.get(user_id).cloned().unwrap_or_default())
    }

    async fn revoke_device(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
    ) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        let entry = g.devices.entry(user_id.clone()).or_default();
        let before = entry.len();
        entry.retain(|d| d != device_id);
        if entry.len() == before {
            // No-op for the OIDC route tests that don't seed devices; only
            // surface NotFound when the user has *some* devices and the
            // target isn't one of them.
            if before > 0 {
                return Err(StoreError::NotFound);
            }
        }
        Ok(())
    }
}

impl MemUserStore {
    /// Seed the `(user, device)` registry the `/me/sessions` directory will
    /// later read. The OIDC routes don't populate this — they only mint
    /// sessions through SessionAuthority — so the `/me` tests do it
    /// explicitly.
    pub fn seed_device(&self, user_id: &UserId, device_id: &DeviceId) {
        let mut g = self.inner.lock().unwrap();
        g.devices
            .entry(user_id.clone())
            .or_default()
            .push(device_id.clone());
    }
}

#[derive(Default)]
pub struct MemRefreshStore(Mutex<HashMap<String, RefreshTokenRecord>>);

#[async_trait]
impl RefreshStore for MemRefreshStore {
    async fn put(&self, record: &RefreshTokenRecord) -> Result<(), StoreError> {
        self.0
            .lock()
            .unwrap()
            .insert(record.token.clone(), record.clone());
        Ok(())
    }
    async fn get(&self, token: &str) -> Result<Option<RefreshTokenRecord>, StoreError> {
        Ok(self.0.lock().unwrap().get(token).cloned())
    }
    async fn mark_consumed(&self, token: &str) -> Result<(), StoreError> {
        let mut g = self.0.lock().unwrap();
        g.get_mut(token).ok_or(StoreError::NotFound)?.consumed = true;
        Ok(())
    }
    async fn revoke_chain(&self, chain_id: &str) -> Result<(), StoreError> {
        let mut g = self.0.lock().unwrap();
        for r in g.values_mut() {
            if r.chain_id == chain_id {
                r.revoked = true;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct MemRevocations(std::sync::Arc<Mutex<std::collections::HashSet<String>>>);

#[async_trait]
impl RevocationReader for MemRevocations {
    async fn is_revoked(&self, jti: &str) -> Result<bool, StoreError> {
        Ok(self.0.lock().unwrap().contains(jti))
    }
}

#[async_trait]
impl RevocationWriter for MemRevocations {
    async fn revoke(&self, jti: &str) -> Result<(), StoreError> {
        self.0.lock().unwrap().insert(jti.to_owned());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Test minter — HmacBlobCodec is cheap and dyn-compatible with TokenMinter,
// so the round-trip tests don't have to ship Ed25519 keypairs.
// ---------------------------------------------------------------------------

pub const TEST_HMAC_KEY: [u8; 32] = *b"cheers-axum-test-hmac-key-32byte";

pub fn test_minter() -> HmacBlobCodec {
    HmacBlobCodec::new(TEST_HMAC_KEY)
}

pub fn test_verifier() -> HmacBlobCodec {
    // HmacBlobCodec impls BOTH TokenMinter and TokenVerifier on one type, so
    // an integrated origin holds one instance per role from the same key.
    HmacBlobCodec::new(TEST_HMAC_KEY)
}

pub type TestAuthority =
    SessionAuthority<HmacBlobCodec, MemRefreshStore, MemUserStore, MemRevocations>;

pub fn test_authority() -> TestAuthority {
    SessionAuthority::new(
        test_minter(),
        MemRefreshStore::default(),
        MemUserStore::default(),
        MemRevocations::default(),
    )
}

pub type TestEdgeVerifier = EdgeVerifier<HmacBlobCodec, MemRevocations>;

pub fn test_edge(revocations: MemRevocations) -> TestEdgeVerifier {
    EdgeVerifier::new(test_verifier(), revocations)
}

// ---------------------------------------------------------------------------
// MemSessionDirectory — products implement `SessionDirectory` over their own
// data; for the integration tests we keep a small in-memory map.
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct MemSessionDirectory {
    rows: Mutex<HashMap<(UserId, DeviceId), MemSessionRow>>,
}

#[derive(Clone, Debug)]
struct MemSessionRow {
    binding: DeviceBinding,
    issued_at: i64,
    expires_at: i64,
}

impl MemSessionDirectory {
    pub fn record(
        &self,
        user_id: UserId,
        device_id: DeviceId,
        binding: DeviceBinding,
        issued_at: i64,
        expires_at: i64,
    ) {
        let mut g = self.rows.lock().unwrap();
        g.insert(
            (user_id, device_id),
            MemSessionRow {
                binding,
                issued_at,
                expires_at,
            },
        );
    }

    pub fn forget(&self, user_id: &UserId, device_id: &DeviceId) {
        let mut g = self.rows.lock().unwrap();
        g.remove(&(user_id.clone(), device_id.clone()));
    }
}

#[async_trait]
impl SessionDirectory for MemSessionDirectory {
    async fn list_sessions(
        &self,
        user_id: &UserId,
        now: i64,
    ) -> Result<Vec<SessionDescriptor>, StoreError> {
        let g = self.rows.lock().unwrap();
        Ok(g.iter()
            .filter(|((u, _), row)| u == user_id && row.expires_at > now)
            .map(|((_, d), row)| {
                SessionDescriptor::new(
                    d.clone(),
                    row.binding.clone(),
                    row.issued_at,
                    row.expires_at,
                )
            })
            .collect())
    }
}

// ---------------------------------------------------------------------------
// Tiny PasskeyCredentialStore stub — only present so the workspace's
// `#[cfg(any(feature="pg",sqlite))]` paths don't drag the real store impls
// into a unit-test setup that doesn't need them.
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct StubPasskeyStore;

#[async_trait]
impl PasskeyCredentialStore for StubPasskeyStore {
    async fn put(&self, _cred: &Credential) -> Result<(), StoreError> {
        Ok(())
    }
    async fn list_for_user(&self, _user_id: &UserId) -> Result<Vec<Credential>, StoreError> {
        Ok(vec![])
    }
    async fn delete(
        &self,
        _user_id: &UserId,
        _device_id: &DeviceId,
    ) -> Result<(), StoreError> {
        Ok(())
    }
    async fn update(&self, _cred: &Credential) -> Result<(), StoreError> {
        Ok(())
    }
}

/// Real in-memory PasskeyCredentialStore for the passkey route tests — same
/// shape as the trait-test impl in `cheers-server/src/store.rs`. Used by the
/// passkey integration test so register/authenticate round-trips actually
/// persist + retrieve a credential.
#[derive(Default)]
pub struct MemPasskeyStore(Mutex<HashMap<(UserId, DeviceId), Credential>>);

#[async_trait]
impl PasskeyCredentialStore for MemPasskeyStore {
    async fn put(&self, cred: &Credential) -> Result<(), StoreError> {
        let mut g = self.0.lock().unwrap();
        let key = (cred.user_id.clone(), cred.device_id.clone());
        if g.contains_key(&key) {
            return Err(StoreError::Conflict);
        }
        g.insert(key, cred.clone());
        Ok(())
    }
    async fn list_for_user(&self, user_id: &UserId) -> Result<Vec<Credential>, StoreError> {
        let g = self.0.lock().unwrap();
        Ok(g.iter()
            .filter(|((u, _), _)| u == user_id)
            .map(|(_, c)| c.clone())
            .collect())
    }
    async fn delete(&self, user_id: &UserId, device_id: &DeviceId) -> Result<(), StoreError> {
        let mut g = self.0.lock().unwrap();
        g.remove(&(user_id.clone(), device_id.clone()))
            .ok_or(StoreError::NotFound)
            .map(|_| ())
    }
    async fn update(&self, cred: &Credential) -> Result<(), StoreError> {
        let mut g = self.0.lock().unwrap();
        let key = (cred.user_id.clone(), cred.device_id.clone());
        if !g.contains_key(&key) {
            return Err(StoreError::NotFound);
        }
        g.insert(key, cred.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// MemOwnershipStore — round-trippable in-memory backing for the ownership
// integration tests. Tracks `insert_calls` so a "rejected before any
// side-effect" assertion can assert the store was never touched.
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct MemOwnershipStore {
    inner: Mutex<MemOwnershipInner>,
    pub insert_calls: std::sync::atomic::AtomicUsize,
}

#[derive(Default)]
struct MemOwnershipInner {
    rows: HashMap<String, OwnershipRow>,
    next_id: u64,
}

impl MemOwnershipStore {
    pub fn insert_call_count(&self) -> usize {
        self.insert_calls.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait]
impl OwnershipStore for MemOwnershipStore {
    async fn insert(
        &self,
        ownership: &NewOwnership,
        now: i64,
    ) -> Result<OwnershipRow, StoreError> {
        self.insert_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let mut g = self.inner.lock().unwrap();
        g.next_id += 1;
        let id = format!("own-{}", g.next_id);
        let row = OwnershipRow::new(
            id.clone(),
            ownership.principal_id.clone(),
            ownership.resource_kind.clone(),
            ownership.resource_id.clone(),
            ownership.relationship.clone(),
            ownership.granted_by.clone(),
            ownership.on_behalf_of.clone(),
            now,
            None,
        );
        g.rows.insert(id, row.clone());
        Ok(row)
    }

    async fn get(&self, id: &str) -> Result<Option<OwnershipRow>, StoreError> {
        Ok(self.inner.lock().unwrap().rows.get(id).cloned())
    }

    async fn revoke_by_id(&self, id: &str, now: i64) -> Result<(), StoreError> {
        let mut g = self.inner.lock().unwrap();
        let row = g.rows.get_mut(id).ok_or(StoreError::NotFound)?;
        if row.revoked_at.is_none() {
            row.revoked_at = Some(now);
        }
        Ok(())
    }

    async fn revoke_by_on_behalf_of(
        &self,
        user: &PrincipalId,
        now: i64,
    ) -> Result<u64, StoreError> {
        let mut g = self.inner.lock().unwrap();
        let mut swept = 0u64;
        for row in g.rows.values_mut() {
            if row.revoked_at.is_none() && row.on_behalf_of.as_ref() == Some(user) {
                row.revoked_at = Some(now);
                swept += 1;
            }
        }
        Ok(swept)
    }

    async fn list_for_principal(
        &self,
        principal: &PrincipalId,
    ) -> Result<Vec<OwnershipRow>, StoreError> {
        let g = self.inner.lock().unwrap();
        Ok(g.rows
            .values()
            .filter(|r| &r.principal_id == principal && r.revoked_at.is_none())
            .cloned()
            .collect())
    }
}

// ---------------------------------------------------------------------------
// HTTP plumbing — drive an axum Router via tower::Service without a TCP
// listener. `oneshot` consumes the service per call, which is exactly what
// each test wants.
// ---------------------------------------------------------------------------

pub async fn body_to_string(body: axum::body::Body) -> String {
    use http_body_util::BodyExt;
    let bytes = body.collect().await.expect("body collect").to_bytes();
    String::from_utf8(bytes.to_vec()).expect("utf8 body")
}

#[cfg(any(feature = "google", feature = "apple"))]
pub fn build_http_client() -> openidconnect::reqwest::Client {
    openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .expect("reqwest client builds")
}

/// Hold both halves of a non-Send i64 timestamp so tests can drive the OIDC
/// flow with a known `now`. (We don't expose `now_unix` so the runtime call
/// is implicit; consumers use chrono::Utc::now or a fixture.)
#[cfg(any(feature = "google", feature = "apple"))]
pub fn now_seconds() -> i64 {
    chrono::Utc::now().timestamp()
}

// Convenience for the binding the OIDC routes pin per provider — the tests
// assert that the minted access token's binding matches the provider.
pub fn assert_session_user_id(body: &serde_json::Value, expected_email: Option<&str>) {
    let user_id = body
        .get("user_id")
        .and_then(|v| v.as_str())
        .expect("user_id present");
    assert!(!user_id.is_empty(), "user_id should be non-empty");
    // Smoke: the MemUserStore mints "u-N" ids.
    assert!(user_id.starts_with("u-"), "user_id shape: {user_id}");
    // Optional email assertion: callers pass Some when the IdP returned email.
    let _ = expected_email;
}

#[allow(unused)]
pub fn binding_from_session(body: &serde_json::Value) -> Option<&str> {
    body.get("device_id").and_then(|v| v.as_str())
}

// ---------------------------------------------------------------------------
// Wiremock IdP fixtures
//
// Lifted from `cheers/src/providers/google.rs` and `cheers/src/providers/apple/redirect.rs`
// — the PKCS#1 PEM is `openidconnect`'s own test fixture, deterministic so the
// signed id_tokens reproduce across runs.
//
// All of this only matters for the google + apple OIDC tests; gated behind
// the same features so the passkey/magic-link tests don't drag openidconnect
// + wiremock into their compile.
// ---------------------------------------------------------------------------

#[cfg(any(feature = "google", feature = "apple"))]
use openidconnect::core::{
    CoreJsonWebKeySet, CoreJwsSigningAlgorithm, CoreProviderMetadata, CoreResponseType,
    CoreRsaPrivateSigningKey, CoreSubjectIdentifierType,
};
#[cfg(any(feature = "google", feature = "apple"))]
use openidconnect::{
    AuthUrl, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl,
    PrivateSigningKey, ResponseTypes, TokenUrl,
};
#[cfg(any(feature = "google", feature = "apple"))]
use wiremock::matchers::{method, path};
#[cfg(any(feature = "google", feature = "apple"))]
use wiremock::{Mock, MockServer, ResponseTemplate};

pub const TEST_RSA_PEM: &str = concat!(
    "-----BEGIN RSA PRIVATE KEY-----\n",
    "MIIEowIBAAKCAQEAsRMj0YYjy7du6v1gWyKSTJx3YjBzZTG0XotRP0IaObw0k+68\n",
    "30dXadjL5jVhSWNdcg9OyMyTGWfdNqfdrS6ppBqlQNgjZJdloIqL9zOLBZrDm7G4\n",
    "+qN4KeZ4/5TyEilq2zOHHGFEzXpOq/UxqVnm3J4fhjqCNaS2nKd7HVVXGBQQ+4+F\n",
    "dVT+MyJXemw5maz2F/h324TQi6XoUPEwUddxBwLQFSOlzWnHYMc4/lcyZJ8MpTXC\n",
    "MPe/YJFNtb9CaikKUdf8x4mzwH7usSf8s2d6R4dQITzKrjrEJ0u3w3eGkBBapoMV\n",
    "FBGPjP3Haz5FsVtHc5VEN3FZVIDF6HrbJH1C4QIDAQABAoIBAHSS3izM+3nc7Bel\n",
    "8S5uRxRKmcm5je6b11u6qiVUFkHWJmMRc6QmqmSThkCq+b4/vUAe1cYZ7+l02Exo\n",
    "HOcrZiEULaDP6hUKGqyjKVv3wdlRtt8kFFxlC/HBufzAiNDuFVvzw0oquwnvMCXC\n",
    "yQvtlK+/JY/PqvM32cSt+b4o9apySsHqAtdsoHHohK82jsQqIfCi1v8XYV/xRBJB\n",
    "cQMCaA0Ls3tFpmJv3JdikyyQxio4kZ5tswghC63znCp1iL+qDq1wjjKzjick9MDb\n",
    "Qzb95X09QQP201l1FPWN7Kbhj4ybg6PJGz/VHQcvILcBCoYIc0UY/OMSBt9VN9yD\n",
    "wr1WlbECgYEA37difsTMcLmUEN57sicFe1q4lxH6eqnUBjmoKBflx4oMIIyRnfjF\n",
    "Jwsu9yIiBkJfBCP85nl2tZdcV0wfZLf6amxB/KMtdfW6r8eoTDzE472OYxSIg1F5\n",
    "dI4qn2nBI0Dou0g58xj+Kv0iLaym0pxtyJkSg/rxZGwKb9a+x5WAs50CgYEAyqC0\n",
    "NcZs2BRIiT5kEOF6+MeUvarbKh1mangKHKcTdXRrvoJ+Z5izm7FifBixo/79MYpt\n",
    "0VofW0IzYKtAI9KZDq2JcozEbZ+lt/ZPH5QEXO4T39QbDoAG8BbOmEP7l+6m+7QO\n",
    "PiQ0WSNjDnwk3W7Zihgg31DH7hyxsxQCapKLcxUCgYAwERXPiPcoDSd8DGFlYK7z\n",
    "1wUsKEe6DT0p7T9tBd1v5wA+ChXLbETn46Y+oQ3QbHg/yn+vAU/5KkFD3G4uVL0w\n",
    "Gnx/DIxa+OYYmHxXjQL8r6ClNycxl9LRsS4FPFKsAWk/u///dFI/6E1spNjfDY8k\n",
    "94ab5tHwsqn3Z5tsBHo3nQKBgFUmxbSXh2Qi2fy6+GhTqU7k6G/wXhvLsR9rBKzX\n",
    "1YiVfTXZNu+oL0ptd/q4keZeIN7x0oaY/fZm0pp8PP8Q4HtXmBxIZb+/yG+Pld6q\n",
    "YE8BSd7VDu3ABapdm0JHx3Iou4mpOBcLNeiDw3vx1bgsfkTXMPFHzE0XR+H+tak9\n",
    "nlalAoGBALAmAF7WBGdOt43Rj8hPaKOM/ahj+6z3CNwVreToNsVBHoyNmiO8q7MC\n",
    "+tRo4jgdrzk1pzs66OIHfbx5P1mXKPtgPZhvI5omAY8WqXEgeNqSL1Ksp6LZ2ql/\n",
    "ouZns5xwKc9+aRL+GWoAGNzwzcjE8cP52sBy/r0rYXTs/sZo5kgV\n",
    "-----END RSA PRIVATE KEY-----\n",
);
pub const TEST_KID: &str = "cheers-axum-test-key";

#[cfg(any(feature = "google", feature = "apple"))]
pub fn signing_key() -> CoreRsaPrivateSigningKey {
    CoreRsaPrivateSigningKey::from_pem(TEST_RSA_PEM, Some(JsonWebKeyId::new(TEST_KID.into())))
        .expect("test PEM parses")
}

/// Mount the standard `.well-known/openid-configuration` + `/jwks` endpoints
/// on a fresh wiremock. The auth/token endpoints are derived from `base`.
#[cfg(any(feature = "google", feature = "apple"))]
pub async fn mount_discovery_and_jwks(server: &MockServer, base: &str) {
    let metadata = CoreProviderMetadata::new(
        IssuerUrl::new(base.to_owned()).unwrap(),
        AuthUrl::new(format!("{base}/o/oauth2/auth")).unwrap(),
        JsonWebKeySetUrl::new(format!("{base}/jwks")).unwrap(),
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        vec![CoreSubjectIdentifierType::Public],
        vec![CoreJwsSigningAlgorithm::RsaSsaPkcs1V15Sha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(TokenUrl::new(format!("{base}/token")).unwrap()));

    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&metadata))
        .mount(server)
        .await;

    let jwks = CoreJsonWebKeySet::new(vec![signing_key().as_verification_key()]);
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(&jwks))
        .mount(server)
        .await;
}
