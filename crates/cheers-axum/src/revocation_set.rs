//! `GET /.well-known/revocation-set.json` — the issuer's current signed
//! revocation set (R732-F6; noisetable W235 §5.1, C6).
//!
//! Offline peers fetch this whenever they are online, adopt it into a
//! `cheers_verify::ReplicatedRevocations` (which re-verifies the signature and
//! refuses an older epoch), persist the token, and gossip it to peers that have
//! not been online since. The route is unauthenticated, like the JWKS: the
//! token is the trust, not the transport.
//!
//! Body:
//!
//! ```json
//! {"issuer":"https://cheers.example","epoch":1791234567,"set":"v4.public.…"}
//! ```
//!
//! `issuer` and `epoch` are copies of what the signed `set` carries, there so a
//! poller can skip a set it already holds without verifying it. A fetcher must
//! never adopt on them — only on the verified token. A strong `ETag` makes an
//! unchanged poll a `304`; `Cache-Control: no-cache` keeps every cache
//! revalidating, because a stale set is a revocation that has not arrived.

use std::sync::Arc;

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::get;
use serde::{Deserialize, Serialize};

use cheers_server::{RevocationPublisher, RevocationWriter};

use crate::error::RouteError;
use crate::jwks::strong_etag;

/// Where [`router`] mounts the publish route.
pub const REVOCATION_SET_PATH: &str = "/.well-known/revocation-set.json";

const CACHE_CONTROL_VALUE: &str = "no-cache";

/// The JSON body of [`REVOCATION_SET_PATH`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RevocationSetBody {
    pub issuer: String,
    pub epoch: u64,
    /// The signed `RevocationSet` — PASETO v4.public under the issuer key.
    pub set: String,
}

/// Mount `GET` [`REVOCATION_SET_PATH`] over `publisher`.
pub fn router<W>(publisher: Arc<RevocationPublisher<W>>) -> Router
where
    W: RevocationWriter + 'static,
{
    Router::new()
        .route(REVOCATION_SET_PATH, get(revocation_set::<W>))
        .with_state(publisher)
}

/// `GET` [`REVOCATION_SET_PATH`].
pub async fn revocation_set<W>(
    State(publisher): State<Arc<RevocationPublisher<W>>>,
    headers: HeaderMap,
) -> Result<Response, RouteError>
where
    W: RevocationWriter,
{
    let signed = publisher.current(now_unix()).await?;
    let body = RevocationSetBody {
        issuer: publisher.issuer().to_owned(),
        epoch: signed.epoch,
        set: signed.token,
    };
    let body = serde_json::to_vec(&body).map_err(|e| RouteError::Store(e.to_string()))?;
    let etag = strong_etag(&body);
    let etag_value = HeaderValue::from_str(&etag).expect("etag bytes are ascii");
    let cache_control = HeaderValue::from_static(CACHE_CONTROL_VALUE);

    if headers
        .get(header::IF_NONE_MATCH)
        .is_some_and(|inm| inm.as_bytes() == etag.as_bytes())
    {
        return Ok(Response::builder()
            .status(StatusCode::NOT_MODIFIED)
            .header(header::CACHE_CONTROL, cache_control)
            .header(header::ETAG, etag_value)
            .body(axum::body::Body::empty())
            .expect("304 response builds with static headers"));
    }

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, cache_control)
        .header(header::ETAG, etag_value)
        .body(axum::body::Body::from(body))
        .expect("revocation-set response builds with static headers"))
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
    use axum::body::Body;
    use axum::http::Request;
    use cheers_core::{DeviceId, PrincipalId, Revoked};
    use cheers_server::{MemoryOwnershipStore, MemoryRevocationStore, OwnershipStore, PasetoV4SecretMinter};
    use cheers_verify::{AdoptError, IssuerTrust, KeySetVerifier, ReplicatedRevocations, RevocationReader};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    const ISS: &str = "https://cheers.test";
    const KID: &str = "platform-1";

    fn rig() -> (Router, MemoryRevocationStore, MemoryOwnershipStore, KeySetVerifier) {
        let (minter, verifier) = PasetoV4SecretMinter::generate().unwrap();
        let public: [u8; 32] = verifier.public_key().as_bytes().try_into().unwrap();
        let store = MemoryRevocationStore::default();
        let ownership = MemoryOwnershipStore::new();
        let publisher = RevocationPublisher::new(store.clone(), Arc::new(ownership.clone()), minter, ISS, KID);
        (
            router(Arc::new(publisher)),
            store,
            ownership,
            KeySetVerifier::from_issuer_key(KID, &public, ISS),
        )
    }

    async fn get(app: &Router, if_none_match: Option<&str>) -> Response {
        let mut req = Request::builder().method("GET").uri(REVOCATION_SET_PATH);
        if let Some(etag) = if_none_match {
            req = req.header(header::IF_NONE_MATCH, etag);
        }
        app.clone().oneshot(req.body(Body::empty()).unwrap()).await.unwrap()
    }

    async fn body(resp: Response) -> RevocationSetBody {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn publishes_a_set_a_replica_adopts_and_queries() {
        let (app, store, ownership, keys) = rig();
        store.revoke(&Revoked::jti("j1", None)).await.unwrap();
        store.revoke(&Revoked::device("phone", 10)).await.unwrap();
        store
            .revoke(&Revoked::membership("namespace", "ns-1", PrincipalId::user("alice"), 3))
            .await
            .unwrap();

        let resp = get(&app, None).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(resp.headers()[header::CACHE_CONTROL], CACHE_CONTROL_VALUE);
        assert!(resp.headers().contains_key(header::ETAG));
        let published = body(resp).await;
        assert_eq!(published.issuer, ISS);
        assert_eq!(published.epoch, store.snapshot().await.unwrap().epoch);

        let replica = ReplicatedRevocations::new(IssuerTrust::key_set(ISS, keys));
        replica.adopt(&published.set).await.unwrap();
        assert_eq!(replica.epoch(), Some(published.epoch));
        assert!(replica.is_revoked("j1").await.unwrap());
        assert!(replica.is_device_revoked(&DeviceId::new("phone"), 9).await.unwrap());
        // The public set names the membership only by its tag (R732-T10).
        let key = ownership.revocation_key("namespace", "ns-1").await.unwrap();
        assert!(replica
            .is_membership_revoked(&key, "namespace", "ns-1", &PrincipalId::user("alice"), 2)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn unchanged_set_revalidates_to_304_and_a_revoke_moves_the_etag() {
        let (app, store, _, keys) = rig();
        let first = get(&app, None).await;
        let etag = first.headers()[header::ETAG].to_str().unwrap().to_owned();
        let first = body(first).await;

        let again = get(&app, Some(&etag)).await;
        assert_eq!(again.status(), StatusCode::NOT_MODIFIED);
        assert_eq!(again.headers()[header::ETAG], etag.as_str());

        store.revoke(&Revoked::device("phone", 1)).await.unwrap();
        let moved = get(&app, Some(&etag)).await;
        assert_eq!(moved.status(), StatusCode::OK);
        assert_ne!(moved.headers()[header::ETAG], etag.as_str());
        let second = body(moved).await;
        assert!(second.epoch > first.epoch);

        // A replica that took the newer set refuses the older one replayed.
        let replica = ReplicatedRevocations::new(IssuerTrust::key_set(ISS, keys));
        replica.adopt(&second.set).await.unwrap();
        assert!(matches!(replica.adopt(&first.set).await, Err(AdoptError::Stale { .. })));
    }
}
