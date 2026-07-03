//! `GET /.well-known/jwks.json` — JSON Web Key Set publication.
//!
//! Publishes the Ed25519 public halves of every key cheers signs against:
//!
//! - **Platform signing keys** — cheers's own session-token signing key(s),
//!   supplied by the product at startup (current + outgoing during rotation).
//! - **Service-principal signing keys** — every `Active` key plus every
//!   `Retiring` key still inside its overlap window, sourced from
//!   [`ServicePrincipalAuthority::published_signing_keys`](cheers_server::ServicePrincipalAuthority::published_signing_keys).
//!   The authority already filters retiring-and-due rows out; the handler just
//!   walks the returned list.
//!
//! ## Wire shape
//!
//! Per RFC 8037 (CFRG curves) and RFC 7517 (JWKS): each entry is
//! `{ kty: "OKP", crv: "Ed25519", x: <base64url-no-pad pubkey>, kid, use: "sig" }`
//! wrapped in `{ "keys": [...] }`. The handler sorts by `kid` before serializing
//! so the body is deterministic across calls — a precondition for a stable
//! `ETag`.
//!
//! ## Caching
//!
//! `Cache-Control: public, max-age=300` plus a strong `ETag` over the serialized
//! body. A conditional GET (`If-None-Match: "<etag>"`) returns `304 Not Modified`
//! with the same `Cache-Control` / `ETag` headers and an empty body.
//!
//! ## Kamaji kid coordination
//!
//! Kamaji matches incoming MCP tokens by `kid` and falls back to a one-shot,
//! rate-limited refresh of this endpoint on unknown values. The `kid` format is
//! the rotation handle and MUST stay stable: service-principal kids come from
//! cheers-server's `mint_kid` (a 128-bit opaque value, base64url-no-pad
//! encoded). Platform kids should follow the same shape. Don't introduce
//! structured prefixes / numeric generations without coordinating with the
//! kamaji refresh path (R020-F11 §gotcha).
//!
//! ## Wiring
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use axum::Router;
//! # use cheers_axum::jwks::{router, JwksState, PlatformSigningKey};
//! # use cheers_server::{ServicePrincipalAuthority, ServicePrincipalStore};
//! # async fn run<S>(
//! #     authority: Arc<ServicePrincipalAuthority<S>>,
//! #     platform_pubkey: [u8; 32],
//! # ) -> Result<(), Box<dyn std::error::Error>>
//! # where
//! #     S: ServicePrincipalStore + 'static,
//! # {
//! let state = Arc::new(JwksState {
//!     platform_keys: vec![PlatformSigningKey::new("platform-kid-1", platform_pubkey)],
//!     authority,
//! });
//! let app: Router = Router::new().merge(router(state));
//! # Ok(()) }
//! ```

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use cheers_server::{ServicePrincipalAuthority, ServicePrincipalStore, SigningKey};

use crate::error::RouteError;

/// `max-age` value embedded in the `Cache-Control` header.
///
/// 300 seconds matches the doc's recommendation and the bound the short MCP
/// access-token TTL is sized against — a freshly-rotated kid propagates within
/// one cache window without per-call cheers lookups.
pub const DEFAULT_JWKS_MAX_AGE_SECONDS: u32 = 300;

const CACHE_CONTROL_VALUE: &str = "public, max-age=300";

/// One of cheers's own session-token signing keys.
///
/// Distinct from [`SigningKey`] (which is service-principal-scoped and carries
/// a `principal_id`): platform keys are owned by cheers itself, not by any
/// service principal. The product supplies the list at startup — today there
/// is no platform-key rotation infrastructure, so a snapshot is the right
/// shape; when rotation lands, this becomes the input to the same publication
/// path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PlatformSigningKey {
    /// JWKS rotation handle. Must be globally unique across the JWKS — kids
    /// collide service-principal kids in the same `keys` array, so don't reuse
    /// `mint_kid()`-shaped values that the authority might also emit.
    pub kid: String,
    /// Raw Ed25519 public key (32 bytes). PASETO v4.public's
    /// `AsymmetricPublicKey::<V4>::as_bytes()` shape.
    pub public_key: [u8; 32],
}

impl PlatformSigningKey {
    pub fn new(kid: impl Into<String>, public_key: [u8; 32]) -> Self {
        Self {
            kid: kid.into(),
            public_key,
        }
    }
}

/// State bundle held by the JWKS handler.
///
/// `platform_keys` is the snapshot of cheers's own signing keys to publish;
/// `authority` is the live source for service-principal keys (`Active` +
/// `Retiring`-in-window).
pub struct JwksState<S> {
    pub platform_keys: Vec<PlatformSigningKey>,
    pub authority: Arc<ServicePrincipalAuthority<S>>,
}

impl<S> std::fmt::Debug for JwksState<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JwksState")
            .field("platform_keys_len", &self.platform_keys.len())
            .finish_non_exhaustive()
    }
}

/// One Ed25519 JWK entry on the wire.
///
/// `kty` / `crv` / `use` are conceptually constants for this codepath (cheers
/// only mints Ed25519 sig-use keys), but the fields are `String` so the type
/// also round-trips through `serde_json::from_slice` — handy for tests and
/// for consumers (kamaji, products) that want to parse a fetched JWKS into
/// this same struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    /// base64url-no-pad of the raw 32-byte public key.
    pub x: String,
    pub kid: String,
    #[serde(rename = "use")]
    pub r#use: String,
}

/// The wrapper shape returned by `GET /.well-known/jwks.json` — `{ "keys": [...] }`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct JwkSet {
    pub keys: Vec<Jwk>,
}

/// Mount `GET /.well-known/jwks.json`. The product nests this at the root of
/// its server (cheers's issuer URI is the prefix everything well-known sits
/// under).
pub fn router<S>(state: Arc<JwksState<S>>) -> Router
where
    S: ServicePrincipalStore + 'static,
{
    Router::new()
        .route("/.well-known/jwks.json", get(jwks::<S>))
        .with_state(state)
}

/// `GET /.well-known/jwks.json` — emit the live JWK Set.
pub async fn jwks<S>(
    State(state): State<Arc<JwksState<S>>>,
    headers: HeaderMap,
) -> Result<Response, RouteError>
where
    S: ServicePrincipalStore,
{
    let now = now_unix();
    let published = state.authority.published_signing_keys(now).await?;
    let set = build_jwk_set(&state.platform_keys, &published);
    let body = serde_json::to_vec(&set).map_err(|e| RouteError::Store(e.to_string()))?;
    let etag = strong_etag(&body);

    if let Some(inm) = headers.get(header::IF_NONE_MATCH) {
        if inm.as_bytes() == etag.as_bytes() {
            return Ok(not_modified_response(&etag));
        }
    }

    let response = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/jwk-set+json")
        .header(
            header::CACHE_CONTROL,
            HeaderValue::from_static(CACHE_CONTROL_VALUE),
        )
        .header(
            header::ETAG,
            HeaderValue::from_str(&etag).expect("etag bytes are ascii"),
        )
        .body(axum::body::Body::from(body))
        .expect("JWKS response builds with static headers");
    Ok(response)
}

/// Build the JWK Set from cheers's platform keys + the live service-principal
/// keys. Sorts deterministically by `kid` so the same logical set hashes to
/// the same ETag across calls.
fn build_jwk_set(platform: &[PlatformSigningKey], service: &[SigningKey]) -> JwkSet {
    let mut keys: Vec<Jwk> = Vec::with_capacity(platform.len() + service.len());
    for pk in platform {
        keys.push(Jwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: URL_SAFE_NO_PAD.encode(pk.public_key),
            kid: pk.kid.clone(),
            r#use: "sig".to_string(),
        });
    }
    for sk in service {
        keys.push(Jwk {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: URL_SAFE_NO_PAD.encode(sk.public_key),
            kid: sk.kid.clone(),
            r#use: "sig".to_string(),
        });
    }
    keys.sort_by(|a, b| a.kid.cmp(&b.kid));
    JwkSet { keys }
}

/// Strong ETag: `"<hex(sha256(body))>"`. Quoted per RFC 7232 §2.3.
fn strong_etag(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let mut out = String::with_capacity(2 + digest.len() * 2);
    out.push('"');
    for b in digest.iter() {
        out.push(hex_nibble(b >> 4));
        out.push(hex_nibble(b & 0x0f));
    }
    out.push('"');
    out
}

fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => unreachable!("nibble out of range"),
    }
}

fn not_modified_response(etag: &str) -> Response {
    Response::builder()
        .status(StatusCode::NOT_MODIFIED)
        .header(
            header::CACHE_CONTROL,
            HeaderValue::from_static(CACHE_CONTROL_VALUE),
        )
        .header(
            header::ETAG,
            HeaderValue::from_str(etag).expect("etag bytes are ascii"),
        )
        .body(axum::body::Body::empty())
        .expect("304 response builds with static headers")
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

    use axum::body::{Body, to_bytes};
    use axum::http::{Request, header};
    use cheers_server::{
        MemoryServicePrincipalStore, NewServicePrincipal, OverlapPolicy, PasetoV4PublicVerifier,
        PasetoV4SecretMinter, ServicePrincipalAuthority,
    };
    use tower::ServiceExt;

    fn now() -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .expect("clock past epoch")
    }

    fn rig(
        platform: Vec<PlatformSigningKey>,
        overlap_seconds: i64,
    ) -> (
        Router,
        Arc<ServicePrincipalAuthority<MemoryServicePrincipalStore>>,
    ) {
        let authority = Arc::new(
            ServicePrincipalAuthority::new(MemoryServicePrincipalStore::new())
                .with_policy(OverlapPolicy::new(overlap_seconds)),
        );
        let state = Arc::new(JwksState {
            platform_keys: platform,
            authority: authority.clone(),
        });
        let app = Router::new().merge(router(state));
        (app, authority)
    }

    async fn body_json<T: for<'de> serde::Deserialize<'de>>(body: Body) -> T {
        let bytes = to_bytes(body, 64 * 1024).await.expect("body bytes");
        serde_json::from_slice(&bytes).expect("json decode")
    }

    async fn body_bytes(body: Body) -> Vec<u8> {
        let bytes = to_bytes(body, 64 * 1024).await.expect("body bytes");
        bytes.to_vec()
    }

    fn fresh_platform_pubkey() -> [u8; 32] {
        let (_, verifier) = PasetoV4SecretMinter::generate().expect("paseto v4 keypair");
        verifier
            .public_key()
            .as_bytes()
            .try_into()
            .expect("v4.public key is 32 bytes")
    }

    #[tokio::test]
    async fn empty_jwks_returns_just_platform_keys_with_stable_shape() {
        let platform = vec![PlatformSigningKey::new("platform-1", fresh_platform_pubkey())];
        let (app, _authority) = rig(platform.clone(), OverlapPolicy::DEFAULT_OVERLAP_SECONDS);

        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/jwks.json")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp.headers().get(header::CONTENT_TYPE).expect("content-type set");
        assert_eq!(ct, "application/jwk-set+json");
        let cc = resp.headers().get(header::CACHE_CONTROL).expect("cache-control set");
        assert_eq!(cc, CACHE_CONTROL_VALUE);
        assert!(resp.headers().get(header::ETAG).is_some(), "ETag must be present");

        let set: JwkSet = body_json(resp.into_body()).await;
        assert_eq!(set.keys.len(), 1);
        let entry = &set.keys[0];
        assert_eq!(entry.kty, "OKP");
        assert_eq!(entry.crv, "Ed25519");
        assert_eq!(entry.r#use, "sig");
        assert_eq!(entry.kid, "platform-1");
        let decoded = URL_SAFE_NO_PAD.decode(entry.x.as_bytes()).unwrap();
        assert_eq!(decoded, &platform[0].public_key);
    }

    #[tokio::test]
    async fn jwks_includes_service_principal_pubkey_with_its_kid_after_provision() {
        let (app, authority) = rig(vec![], OverlapPolicy::DEFAULT_OVERLAP_SECONDS);

        let provisioned = authority
            .provision(NewServicePrincipal::new("yubaba-1"), now())
            .await
            .unwrap();

        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/jwks.json")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let set: JwkSet = body_json(resp.into_body()).await;
        assert_eq!(set.keys.len(), 1);
        let entry = &set.keys[0];
        assert_eq!(entry.kid, provisioned.signing_key.kid);
        let decoded = URL_SAFE_NO_PAD.decode(entry.x.as_bytes()).unwrap();
        assert_eq!(
            decoded.as_slice(),
            &provisioned.signing_key.public_key[..],
            "published pubkey must match the persisted record"
        );
    }

    #[tokio::test]
    async fn rotate_publishes_both_kids_during_overlap_then_drops_old() {
        // 24h overlap so the window covers the test runtime comfortably.
        let (app, authority) = rig(vec![], 24 * 60 * 60);
        let now0 = now();
        let first = authority
            .provision(NewServicePrincipal::new("yubaba-r"), now0)
            .await
            .unwrap();
        let second = authority.rotate(&first.principal.id, now0).await.unwrap();
        assert_ne!(first.signing_key.kid, second.signing_key.kid);

        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/jwks.json")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let set: JwkSet = body_json(resp.into_body()).await;
        let mut kids: Vec<_> = set.keys.iter().map(|k| k.kid.clone()).collect();
        kids.sort();
        let mut expected = vec![first.signing_key.kid.clone(), second.signing_key.kid.clone()];
        expected.sort();
        assert_eq!(kids, expected, "both kids must publish during overlap");

        // 0-second overlap: retire_at = now0, so a wall-clock read >= now0
        // filters the old kid out of `published_signing_keys`.
        let (app2, authority2) = rig(vec![], 0);
        let now1 = now();
        let one = authority2
            .provision(NewServicePrincipal::new("yubaba-rd"), now1)
            .await
            .unwrap();
        let two = authority2.rotate(&one.principal.id, now1).await.unwrap();
        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/jwks.json")
            .body(Body::empty())
            .unwrap();
        let resp = app2.oneshot(req).await.unwrap();
        let set: JwkSet = body_json(resp.into_body()).await;
        let kids: Vec<_> = set.keys.iter().map(|k| k.kid.clone()).collect();
        assert_eq!(
            kids,
            vec![two.signing_key.kid.clone()],
            "old kid must drop after retire_at <= now",
        );
        assert!(!kids.contains(&one.signing_key.kid));
    }

    #[tokio::test]
    async fn jwks_publishes_platform_and_service_keys_together_sorted_by_kid() {
        let platform = vec![
            PlatformSigningKey::new("aaa-platform", fresh_platform_pubkey()),
            PlatformSigningKey::new("zzz-platform", fresh_platform_pubkey()),
        ];
        let (app, authority) = rig(platform.clone(), OverlapPolicy::DEFAULT_OVERLAP_SECONDS);

        let svc = authority
            .provision(NewServicePrincipal::new("yubaba-mix"), now())
            .await
            .unwrap();

        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/jwks.json")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let set: JwkSet = body_json(resp.into_body()).await;
        assert_eq!(set.keys.len(), 3);
        let kids: Vec<_> = set.keys.iter().map(|k| k.kid.clone()).collect();
        let mut sorted = kids.clone();
        sorted.sort();
        assert_eq!(kids, sorted, "JWKS keys must be sorted by kid");
        assert!(kids.contains(&"aaa-platform".to_string()));
        assert!(kids.contains(&"zzz-platform".to_string()));
        assert!(kids.contains(&svc.signing_key.kid));
    }

    #[tokio::test]
    async fn etag_is_stable_for_unchanged_jwks_and_changes_on_rotation() {
        let (app, authority) = rig(vec![], OverlapPolicy::DEFAULT_OVERLAP_SECONDS);

        authority
            .provision(NewServicePrincipal::new("yubaba-et"), now())
            .await
            .unwrap();

        let etag1 = {
            let req = Request::builder()
                .method("GET")
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            resp.headers().get(header::ETAG).cloned().expect("etag")
        };

        let etag2 = {
            let req = Request::builder()
                .method("GET")
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            resp.headers().get(header::ETAG).cloned().expect("etag")
        };
        assert_eq!(etag1, etag2, "ETag must be stable for the same JWKS body");

        authority
            .provision(NewServicePrincipal::new("yubaba-et-2"), now())
            .await
            .unwrap();
        let etag3 = {
            let req = Request::builder()
                .method("GET")
                .uri("/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            resp.headers().get(header::ETAG).cloned().expect("etag")
        };
        assert_ne!(etag1, etag3, "ETag must change when the JWKS changes");
    }

    #[tokio::test]
    async fn conditional_get_returns_304_on_matching_if_none_match() {
        let (app, authority) = rig(vec![], OverlapPolicy::DEFAULT_OVERLAP_SECONDS);
        authority
            .provision(NewServicePrincipal::new("yubaba-cg"), now())
            .await
            .unwrap();

        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/jwks.json")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let etag = resp.headers().get(header::ETAG).expect("etag").clone();

        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/jwks.json")
            .header(header::IF_NONE_MATCH, etag.clone())
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(
            resp.headers().get(header::ETAG).unwrap(),
            &etag,
            "304 must echo the same ETag"
        );
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            CACHE_CONTROL_VALUE,
            "304 must keep Cache-Control",
        );
        let body = body_bytes(resp.into_body()).await;
        assert!(body.is_empty(), "304 must have an empty body");

        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/jwks.json")
            .header(header::IF_NONE_MATCH, "\"00000000\"")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn jwks_published_pubkey_verifies_an_off_cheers_minted_mcp_token() {
        use cheers_core::{
            Actor, AuthStrength, McpClaims, Owns, PrincipalId, Scope,
        };

        let (app, authority) = rig(vec![], OverlapPolicy::DEFAULT_OVERLAP_SECONDS);
        let provisioned = authority
            .provision(NewServicePrincipal::new("yubaba-e2e"), now())
            .await
            .unwrap();
        let target_kid = provisioned.signing_key.kid.clone();

        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/jwks.json")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let set: JwkSet = body_json(resp.into_body()).await;

        let jwk = set
            .keys
            .iter()
            .find(|k| k.kid == target_kid)
            .expect("kid present in JWKS");
        let pub_bytes: [u8; 32] = URL_SAFE_NO_PAD
            .decode(jwk.x.as_bytes())
            .unwrap()
            .try_into()
            .expect("v4.public key is 32 bytes");
        let verifier = PasetoV4PublicVerifier::from_public_key(&pub_bytes).unwrap();

        let minter = PasetoV4SecretMinter::from_secret_key(&provisioned.secret_key).unwrap();
        let mut owns = Owns::default();
        owns.service = vec!["svc-prod".into()];
        let claims = McpClaims::new(
            "https://cheers.example",
            "https://kamaji.example",
            PrincipalId::service("yubaba-e2e"),
            1_000,
            1_600,
            "jti-jwks-e2e",
            vec![Scope::OwnershipWrite],
        )
        .with_act(Actor::new(PrincipalId::service("yubaba-e2e")))
        .with_owns(owns)
        .with_auth_strength(AuthStrength::Bootstrap);
        let token = minter.mint_mcp(&claims, &target_kid).unwrap();
        let back = verifier.verify_mcp_at(&token, 1_100, &target_kid).unwrap();
        assert_eq!(back, claims);
    }
}
