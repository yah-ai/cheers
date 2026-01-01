//! Postgres-backed tests. Off by default — enable with `--features
//! pg-integration` (Docker required, the test stands up a real Postgres
//! container via testcontainers).

#![cfg(feature = "pg-integration")]

mod common;

use cheers_core::{DeviceId, UserId};
use cheers_server::store::{NewUser, UserStore};
use cheers_sqlx::{
    PgOwnershipStore, PgRefreshStore, PgRevocationStore, PgServicePrincipalStore, PgUserStore,
    PG_MIGRATIONS,
};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::PgPool;
use testcontainers::runners::AsyncRunner;
use testcontainers::ContainerAsync;
use testcontainers_modules::postgres::Postgres;

struct PgFixture {
    pool: PgPool,
    // Held to keep the container alive for the duration of the test; dropping
    // it tears the container down.
    _container: ContainerAsync<Postgres>,
}

async fn fresh_pg() -> PgFixture {
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
        .max_connections(4)
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
