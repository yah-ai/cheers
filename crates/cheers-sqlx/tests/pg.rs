//! Postgres-backed tests. Off by default — enable with `--features
//! pg-integration` (Docker required, the test stands up a real Postgres
//! container via testcontainers).
//!
//! On OrbStack hosts, testcontainers looks for the Docker socket in
//! /var/run/docker.sock, but OrbStack stores it in ~/.orbstack/run/docker.sock;
//! the DOCKER_HOST env var steers testcontainers to the right location.
//!
//! @yah:ticket(R732-T11, "pg-integration tests fail on OrbStack hosts: testcontainers only finds /var/run/docker.sock")
//! @yah:status(review)
//! @yah:at(2026-10-07T17:20:22Z)
//! @yah:assignee(agent:bundle-anthropic-quill)
//! @yah:parent(R732)
//! @yah:next("Tier: Thief. Without DOCKER_HOST=unix://$HOME/.orbstack/run/docker.sock all 23 pg tests fail at container start (found on R732-T10's verification pass), so agents wrongly conclude Postgres is unavailable. Fix: in the pg test setup, if DOCKER_HOST is unset and /var/run/docker.sock is missing but ~/.orbstack/run/docker.sock exists, set DOCKER_HOST before the testcontainers client starts. Also add one line to the crate's test doc naming the variable. Verify: cargo test -p cheers-sqlx --features pg-integration with DOCKER_HOST unset passes 23/23.")
//! @yah:handoff("Added init_docker_host() function using std::sync::Once to safely set DOCKER_HOST environment variable. Function checks if DOCKER_HOST is unset, /var/run/docker.sock doesn't exist, and ~/.orbstack/run/docker.sock does exist, then configures the OrbStack socket path for testcontainers. Added documentation to module header explaining the DOCKER_HOST variable and OrbStack socket location. Called initialization at start of fresh_pg() before container startup.")
//! @yah:verify("cargo test -p cheers-sqlx --features pg-integration --test pg with DOCKER_HOST unset: all 23 tests pass.")

#![cfg(feature = "pg-integration")]

mod common;

use cheers_core::{DeviceId, UserId};
use cheers_server::store::{NewUser, UserStore};
use cheers_sqlx::{
    PgAuditStore, PgOwnershipStore, PgRefreshStore, PgRevocationStore, PgServicePrincipalStore,
    PgUserStore, PgUserTokenStore, PgBindingSequenceStore,
    PG_MIGRATIONS,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::postgres::Postgres;
use std::sync::Once;
use std::path::Path;

fn init_docker_host() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        if std::env::var("DOCKER_HOST").is_err() {
            let standard_socket = Path::new("/var/run/docker.sock");
            if !standard_socket.exists() {
                if let Ok(home) = std::env::var("HOME") {
                    let orbstack_socket = Path::new(&home).join(".orbstack/run/docker.sock");
                    if orbstack_socket.exists() {
                        let docker_host = format!("unix://{}", orbstack_socket.display());
                        unsafe {
                            std::env::set_var("DOCKER_HOST", docker_host);
                        }
                    }
                }
            }
        }
    });
}

struct PgFixture {
    pool: PgPool,
    // Held to keep the container alive for the duration of the test; dropping
    // it tears the container down.
    _container: ContainerAsync<Postgres>,
}

async fn fresh_pg() -> PgFixture {
    fresh_pg_sized(4).await
}

async fn fresh_pg_sized(max_connections: u32) -> PgFixture {
    init_docker_host();
    let container = Postgres::default()
        .start()
        .await
        .expect("start postgres container");
    let host = container.get_host().await.expect("container host");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("container pg port");
    let opts = PgConnectOptions::new()
        .host(&host.to_string())
        .port(port)
        .username("postgres")
        .password("postgres")
        .database("postgres");
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect_with(opts)
        .await
        .expect("pg connect");
    PG_MIGRATIONS.run(&pool).await.expect("migrate");
    PgFixture {
        pool,
        _container: container,
    }
}

async fn seeded_user(users: &PgUserStore) -> UserId {
    users
        .create(NewUser::new().with_email("u@example.com"))
        .await
        .expect("seed user")
        .id
}

#[tokio::test]
async fn user_store_lifecycle() {
    let fx = fresh_pg().await;
    let users = PgUserStore::new(fx.pool.clone());
    common::user_store_lifecycle(&users).await;
}

#[tokio::test]
async fn user_store_get_by_id() {
    let fx = fresh_pg().await;
    let users = PgUserStore::new(fx.pool.clone());
    common::user_store_get_by_id(&users).await;
}

#[tokio::test]
async fn refresh_store_put_get_consume_revoke() {
    let fx = fresh_pg().await;
    let users = PgUserStore::new(fx.pool.clone());
    let user = seeded_user(&users).await;
    let refresh = PgRefreshStore::new(fx.pool.clone());
    let device = DeviceId::new("d1");
    common::refresh_store_put_get_consume_revoke(&refresh, &user, &device).await;
}

#[tokio::test]
async fn refresh_store_other_chain_unaffected() {
    let fx = fresh_pg().await;
    let users = PgUserStore::new(fx.pool.clone());
    let user = seeded_user(&users).await;
    let refresh = PgRefreshStore::new(fx.pool.clone());
    let device = DeviceId::new("d1");
    common::refresh_store_other_chain_unaffected(&refresh, &user, &device).await;
}

#[tokio::test]
async fn user_store_list_devices_reflects_refresh_chains() {
    let fx = fresh_pg().await;
    let users = PgUserStore::new(fx.pool.clone());
    let user = seeded_user(&users).await;
    let refresh = PgRefreshStore::new(fx.pool.clone());

    assert!(users.list_devices(&user).await.unwrap().is_empty());

    use cheers_server::store::RefreshStore;
    refresh
        .put(&common::fixture_refresh(
            "t1",
            "c1",
            None,
            &user,
            &DeviceId::new("d1"),
            100,
            1_000,
        ))
        .await
        .unwrap();
    refresh
        .put(&common::fixture_refresh(
            "t2",
            "c2",
            None,
            &user,
            &DeviceId::new("d2"),
            100,
            1_000,
        ))
        .await
        .unwrap();

    let mut devs = users.list_devices(&user).await.unwrap();
    devs.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    assert_eq!(devs, vec![DeviceId::new("d1"), DeviceId::new("d2")]);

    users
        .revoke_device(&user, &DeviceId::new("d1"))
        .await
        .unwrap();
    let devs = users.list_devices(&user).await.unwrap();
    assert_eq!(devs, vec![DeviceId::new("d2")]);
}

#[tokio::test]
async fn revocation_writer_and_reader() {
    let fx = fresh_pg().await;
    let revoke = PgRevocationStore::new(fx.pool.clone());
    common::revocation_writer_and_reader(&revoke).await;
}

#[tokio::test]
async fn binding_sequence_store() {
    let fx = fresh_pg().await;
    common::binding_sequence_store(&PgBindingSequenceStore::new(fx.pool.clone())).await;
}

#[tokio::test]
async fn ownership_store_lifecycle() {
    let fx = fresh_pg().await;
    let store = PgOwnershipStore::new(fx.pool.clone());
    common::ownership_store_lifecycle(&store).await;
}

#[tokio::test]
async fn ownership_store_check_constraints_reject_bad_rows() {
    let fx = fresh_pg().await;
    let store = PgOwnershipStore::new(fx.pool.clone());
    common::ownership_store_check_constraints_reject_bad_rows(&store).await;
}

#[tokio::test]
async fn ownership_store_revoke_follows_holder() {
    let fx = fresh_pg().await;
    let store = PgOwnershipStore::new(fx.pool.clone());
    common::ownership_store_revoke_follows_holder(&store).await;
}

#[tokio::test]
async fn ownership_store_subject_sets() {
    let fx = fresh_pg().await;
    let store = PgOwnershipStore::new(fx.pool.clone());
    common::ownership_store_subject_sets(&store).await;
}

#[tokio::test]
async fn ownership_store_list_for_kind() {
    let fx = fresh_pg().await;
    let store = PgOwnershipStore::new(fx.pool.clone());
    common::ownership_store_list_for_kind(&store).await;
}

#[tokio::test]
async fn ownership_store_version() {
    let fx = fresh_pg().await;
    let store = PgOwnershipStore::new(fx.pool.clone());
    common::ownership_store_version(&store).await;
}

#[tokio::test]
async fn ownership_store_revocation_key() {
    let fx = fresh_pg().await;
    let store = PgOwnershipStore::new(fx.pool.clone());
    common::ownership_store_revocation_key(&store).await;
}

#[tokio::test]
async fn ownership_store_admission_policy() {
    let fx = fresh_pg().await;
    let store = PgOwnershipStore::new(fx.pool.clone());
    common::ownership_store_admission_policy(&store).await;
}

#[tokio::test]
async fn ownership_store_lease() {
    let fx = fresh_pg().await;
    common::ownership_store_lease(&PgOwnershipStore::new(fx.pool.clone())).await;
}

#[tokio::test]
async fn knock_store_lifecycle() {
    let fx = fresh_pg().await;
    common::knock_store_lifecycle(&cheers_sqlx::PgKnockStore::new(fx.pool.clone())).await;
}

/// Fires `n` store calls at once through a pool wide enough that each holds
/// its own connection; the barrier lines their transactions up.
async fn race<T, F, Fut>(n: usize, f: F) -> Vec<T>
where
    T: Send + 'static,
    F: Fn(usize) -> Fut,
    Fut: std::future::Future<Output = T> + Send + 'static,
{
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(n));
    let tasks: Vec<_> = (0..n)
        .map(|i| {
            let barrier = barrier.clone();
            let call = f(i);
            tokio::spawn(async move {
                barrier.wait().await;
                call.await
            })
        })
        .collect();
    let mut out = Vec::with_capacity(n);
    for t in tasks {
        out.push(t.await.expect("race task"));
    }
    out
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn knock_store_offer_max_uses_holds_under_concurrent_redemption() {
    use cheers_core::PrincipalId;
    use cheers_server::{KnockStore, Redeemed, StoredOffer};
    let fx = fresh_pg_sized(20).await;
    let store = cheers_sqlx::PgKnockStore::new(fx.pool.clone());
    for (jti, max_uses) in [("race-1", 1u32), ("race-3", 3)] {
        store
            .put_offer(&StoredOffer {
                jti: jti.into(),
                resource_kind: "namespace".into(),
                resource_id: "race".into(),
                relation: "guest".into(),
                created_by: PrincipalId::user("race-owner"),
                max_uses,
                created_at: 10,
                exp: 1_000,
            })
            .await
            .unwrap();
        let outcomes = race(16, |i| {
            let store = store.clone();
            async move { store.redeem_offer(jti, &PrincipalId::from_public_key(&[i as u8 + 1; 32]), 20).await.unwrap() }
        })
        .await;
        let fresh = outcomes.iter().filter(|r| matches!(r, Redeemed::Fresh(_))).count();
        let exhausted = outcomes.iter().filter(|r| matches!(r, Redeemed::Exhausted)).count();
        assert_eq!((fresh, exhausted), (max_uses as usize, 16 - max_uses as usize), "{jti}: {outcomes:?}");
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM offer_redemptions WHERE offer_jti = $1")
            .bind(jti)
            .fetch_one(&fx.pool)
            .await
            .unwrap();
        assert_eq!(rows, i64::from(max_uses), "{jti}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn knock_store_pending_cap_holds_under_concurrent_knocks() {
    use cheers_core::PrincipalId;
    use cheers_server::{KnockStore, PendingKnock, Queued};
    const CAP: usize = 3;
    let fx = fresh_pg_sized(20).await;
    let store = cheers_sqlx::PgKnockStore::new(fx.pool.clone());
    let outcomes = race(16, |i| {
        let store = store.clone();
        async move {
            let k = PendingKnock {
                id: format!("race-{i}"),
                resource_kind: "namespace".into(),
                resource_id: "race".into(),
                requester: PrincipalId::from_public_key(&[i as u8 + 1; 32]),
                relation: "guest".into(),
                label: format!("phone {i}"),
                requester_user: None,
                renews: None,
                token: format!("token-{i}"),
                created_at: 10,
                expires_at: 1_000,
            };
            store.queue_knock(&k, CAP, 10).await.unwrap()
        }
    })
    .await;
    let queued = outcomes.iter().filter(|q| **q == Queued::Queued).count();
    assert_eq!(queued, CAP, "{outcomes:?}");
    assert_eq!(store.pending_knocks("namespace", "race", 10).await.unwrap().len(), CAP);
}

#[tokio::test]
async fn ownership_subject_check_rejects_bad_forms() {
    let fx = fresh_pg().await;
    common::ownership_subject_check_rejects_bad_forms(|sql| {
        let pool = fx.pool.clone();
        async move {
            sqlx::query(&sql)
                .execute(&pool)
                .await
                .map(|_| ())
                .map_err(|e| cheers_core::StoreError::Backend(e.to_string()))
        }
    })
    .await;
}

#[tokio::test]
async fn service_principal_lifecycle() {
    let fx = fresh_pg().await;
    let store = PgServicePrincipalStore::new(fx.pool.clone());
    common::service_principal_lifecycle(&store).await;
}

#[tokio::test]
async fn service_principal_rejects_non_service_kind() {
    let fx = fresh_pg().await;
    let store = PgServicePrincipalStore::new(fx.pool.clone());
    common::service_principal_rejects_non_service_kind(&store).await;
}

#[tokio::test]
async fn service_principal_check_constraint_rejects_bad_status() {
    let fx = fresh_pg().await;
    let pool = fx.pool.clone();
    common::service_principal_check_constraint_rejects_bad_status_directly(async move {
        sqlx::query(
            "INSERT INTO service_principals (id, status, created_at) VALUES ($1, $2, $3)",
        )
        .bind("svc:bogus")
        .bind("emerging")
        .bind(1_000_i64)
        .execute(&pool)
        .await
        .map(|_| ())
        .map_err(|e| cheers_core::StoreError::Backend(e.to_string()))
    })
    .await;
    let pool = fx.pool.clone();
    common::service_principal_check_constraint_rejects_bad_status_directly(async move {
        sqlx::query(
            "INSERT INTO service_principals (id, status, created_at) VALUES ($1, $2, $3)",
        )
        .bind("user:alice")
        .bind("active")
        .bind(1_000_i64)
        .execute(&pool)
        .await
        .map(|_| ())
        .map_err(|e| cheers_core::StoreError::Backend(e.to_string()))
    })
    .await;
}

#[tokio::test]
async fn audit_store_batch_insert_round_trip() {
    let fx = fresh_pg().await;
    let store = PgAuditStore::new(fx.pool.clone());
    common::audit_store_batch_insert_round_trip(&store).await;
}

#[tokio::test]
async fn audit_store_query_by_on_behalf_of() {
    let fx = fresh_pg().await;
    let store = PgAuditStore::new(fx.pool.clone());
    common::audit_store_query_by_on_behalf_of(&store).await;
}

#[cfg(feature = "passkey")]
mod passkey {
    use super::*;
    use cheers_sqlx::PgPasskeyCredentialStore;

    #[tokio::test]
    async fn passkey_store_round_trip() {
        let fx = fresh_pg().await;
        let users = PgUserStore::new(fx.pool.clone());
        let user = seeded_user(&users).await;
        let passkeys = PgPasskeyCredentialStore::new(fx.pool.clone());
        super::common::passkey_store_round_trip(&passkeys, &user).await;
    }
}

// ---------------------------------------------------------------------------
// UserTokenStore (R728-F1) — user_tokens.user_id carries a FK to users, so
// every scenario seeds a real user first.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn user_token_store_insert_and_scoped_list() {
    let fx = fresh_pg().await;
    let users = PgUserStore::new(fx.pool.clone());
    let user = seeded_user(&users).await;
    let other = users
        .create(NewUser::new().with_email("other@example.com"))
        .await
        .expect("seed second user")
        .id;
    let tokens = PgUserTokenStore::new(fx.pool.clone());
    common::user_token_store_insert_and_scoped_list(&tokens, &user, &other).await;
}

#[tokio::test]
async fn user_token_store_revoked_and_expired_leave_the_live_list() {
    let fx = fresh_pg().await;
    let user = seeded_user(&PgUserStore::new(fx.pool.clone())).await;
    let tokens = PgUserTokenStore::new(fx.pool.clone());
    common::user_token_store_revoked_and_expired_leave_the_live_list(&tokens, &user).await;
}

#[tokio::test]
async fn user_token_store_revoke_is_idempotent_and_touch_stamps() {
    let fx = fresh_pg().await;
    let user = seeded_user(&PgUserStore::new(fx.pool.clone())).await;
    let tokens = PgUserTokenStore::new(fx.pool.clone());
    common::user_token_store_revoke_is_idempotent_and_touch_stamps(&tokens, &user).await;
}
