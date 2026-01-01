//! Redis-backed integration tests. Off by default — enable with `--features
//! redis-integration` (Docker required, runs against a testcontainers redis).

#![cfg(feature = "redis-integration")]

use cheers_core::{DeviceId, StoreError, UserId};
use cheers_redis::{RedisRefreshStore, RedisRevocationStore};
use cheers_server::store::{RefreshStore, RefreshTokenRecord};
use cheers_server::RevocationWriter;
use cheers_verify::RevocationReader;
use redis::aio::ConnectionManager;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::redis::Redis;

struct RedisFixture {
    conn: ConnectionManager,
    // Keep the container alive for the test's duration.
    _container: ContainerAsync<Redis>,
}

async fn fresh_redis() -> RedisFixture {
    let container = Redis::default()
        .start()
        .await
        .expect("start redis container");
    let host = container.get_host().await.expect("container host");
    let port = container
        .get_host_port_ipv4(6379)
        .await
        .expect("container redis port");
    let url = format!("redis://{host}:{port}");
    let client = redis::Client::open(url).expect("redis client");
    let conn = ConnectionManager::new(client)
        .await
        .expect("connection manager");
    RedisFixture {
        conn,
        _container: container,
    }
}

fn fixture_refresh(
    token: &str,
    chain_id: &str,
    parent: Option<&str>,
    user: &UserId,
    device: &DeviceId,
    issued_at: i64,
    expires_at: i64,
) -> RefreshTokenRecord {
    RefreshTokenRecord::new(
        token.into(),
        chain_id.into(),
        parent.map(str::to_owned),
        user.clone(),
        device.clone(),
        issued_at,
        expires_at,
        false,
        false,
    )
}

#[tokio::test]
async fn refresh_store_put_get_consume_revoke() {
    let fx = fresh_redis().await;
    let refresh = RedisRefreshStore::new(fx.conn.clone());
    let user = UserId::new("u1");
    let device = DeviceId::new("d1");

    // Use generous expires_at — way past now() so TTL is large.
    let far = 9_999_999_999_i64;

    let r1 = fixture_refresh("tok-1", "chain-A", None, &user, &device, 100, far);
    refresh.put(&r1).await.expect("put root");

    let back = refresh.get("tok-1").await.expect("get").expect("present");
    assert_eq!(back, r1);
    assert!(refresh.get("missing").await.unwrap().is_none());

    refresh.mark_consumed("tok-1").await.expect("consume");
    let back = refresh.get("tok-1").await.unwrap().unwrap();
    assert!(back.consumed);
    assert!(!back.revoked);

    // Idempotent re-consume.
    refresh.mark_consumed("tok-1").await.expect("idempotent");

    // Successor in same chain.
    let r2 = fixture_refresh(
        "tok-2",
        "chain-A",
        Some("tok-1"),
        &user,
        &device,
        110,
        far,
    );
    refresh.put(&r2).await.expect("put successor");

    // Revoke chain flips both records via the chain set.
    refresh.revoke_chain("chain-A").await.expect("revoke");
    let t1 = refresh.get("tok-1").await.unwrap().unwrap();
    let t2 = refresh.get("tok-2").await.unwrap().unwrap();
    assert!(t1.revoked, "tok-1 should be revoked");
    assert!(t2.revoked, "tok-2 should be revoked");

    // Re-revoke is idempotent.
    refresh.revoke_chain("chain-A").await.expect("idempotent");

    // mark_consumed on a missing token => NotFound.
    match refresh.mark_consumed("never-existed").await {
        Err(StoreError::NotFound) => {}
        other => panic!("expected NotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn refresh_store_other_chain_unaffected() {
    let fx = fresh_redis().await;
    let refresh = RedisRefreshStore::new(fx.conn.clone());
    let user = UserId::new("u1");
    let device = DeviceId::new("d1");
    let far = 9_999_999_999_i64;

    refresh
        .put(&fixture_refresh(
            "ca-1", "chain-CA", None, &user, &device, 200, far,
        ))
        .await
        .unwrap();
    refresh
        .put(&fixture_refresh(
            "cb-1", "chain-CB", None, &user, &device, 200, far,
        ))
        .await
        .unwrap();
    refresh.revoke_chain("chain-CA").await.unwrap();
    assert!(refresh.get("ca-1").await.unwrap().unwrap().revoked);
    assert!(!refresh.get("cb-1").await.unwrap().unwrap().revoked);
}

#[tokio::test]
async fn refresh_store_prefix_isolation() {
    let fx = fresh_redis().await;
    let alpha = RedisRefreshStore::new(fx.conn.clone()).with_prefix("alpha");
    let beta = RedisRefreshStore::new(fx.conn.clone()).with_prefix("beta");
    let user = UserId::new("u");
    let device = DeviceId::new("d");
    let far = 9_999_999_999_i64;
    alpha
        .put(&fixture_refresh(
            "shared-tok", "c", None, &user, &device, 0, far,
        ))
        .await
        .unwrap();
    // beta's view doesn't see alpha's token.
    assert!(beta.get("shared-tok").await.unwrap().is_none());
    assert!(alpha.get("shared-tok").await.unwrap().is_some());
}

#[tokio::test]
async fn revocation_writer_and_reader() {
    let fx = fresh_redis().await;
    let revoke = RedisRevocationStore::new(fx.conn.clone());

    assert!(!revoke.is_revoked("tok-x").await.unwrap());
    revoke.revoke("tok-x").await.unwrap();
    assert!(revoke.is_revoked("tok-x").await.unwrap());
    // Idempotent.
    revoke.revoke("tok-x").await.unwrap();
    assert!(revoke.is_revoked("tok-x").await.unwrap());
    // Independence.
    assert!(!revoke.is_revoked("tok-y").await.unwrap());
}

#[tokio::test]
async fn revocation_ttl_expires_entries() {
    let fx = fresh_redis().await;
    let revoke = RedisRevocationStore::new(fx.conn.clone()).with_revoke_ttl_seconds(1);
    revoke.revoke("tok-short").await.unwrap();
    assert!(revoke.is_revoked("tok-short").await.unwrap());
    // Wait past the TTL — redis returns false once the key expires.
    tokio::time::sleep(std::time::Duration::from_millis(1_200)).await;
    assert!(!revoke.is_revoked("tok-short").await.unwrap());
}
