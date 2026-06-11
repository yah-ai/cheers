//! SQLite-backed tests. Always-on (no Docker required) — runs against an
//! in-memory `sqlite::memory:` pool freshly migrated per test.
//!
//! @yah:ticket(R020-T19, "cheers-sqlx libsql-integration test path — Turso/libSQL migration smoke")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-07T01:40:26Z)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R020)
//! @yah:gotcha("The cheers-sqlx 'sqlite' feature uses sqlx's sqlite driver (vanilla SQLite via rusqlite) — NOT libSQL. Until sqlx grows a libsql driver, the libsql-integration path runs the raw `libsql` HTTP/Hrana client against a real libsql-server container; it doesn't exercise the typed Sqlite*Store impls (they're sqlx-bound).")
//! @yah:handoff("LANDED. Cargo.toml: added `libsql-integration` feature (gates the test module, no public-API impact) and dev-dep `libsql = 0.6` with default-features = false, features = [\"remote\", \"tls\"] (rustls connector — matches workspace's no-native-tls stance per deny.toml).")
//! @yah:handoff("tests/libsql.rs (new): boots ghcr.io/tursodatabase/libsql-server:latest via testcontainers GenericImage; honors CHEERS_LIBSQL_URL to bypass the container. Connects via `libsql::Builder::new_remote(url, \"\")` (no auth — SQLD_NODE=primary), applies migrations/sqlite/0001..0003 statement-by-statement (libsql remote `execute` is one-stmt-at-a-time; naive `;`-split is fine because the migration SQL has no string literals containing `;`).")
//! @yah:handoff("Coverage (7 tests, all passing against the live container): migrations_apply_clean; email partial-UNIQUE allows multiple NULLs + rejects dup non-null; FK CASCADE wipes oauth_identities + refresh_tokens when the user is deleted; ownership CHECK rejects non-svc granted_by and non-user on_behalf_of; service_principals CHECK rejects non-svc id and bogus status; service_principal_keys CHECK enforces (active⇒retire_at NULL) ∧ (retiring⇒NOT NULL) plus FK CASCADE; ix_spk_principal_active partial-index syntax accepted (verified via sqlite_master).")
//! @yah:handoff("R020-T18's @yah:assumes about libSQL compat is now a verified property — promote/retire that assumption on next touch. Parent-relay verify still green: cargo test -p cheers-core (61) + -p cheers-server (116 + 9 proptests) + -p cheers-verify (4) pass; sqlite-feature tests (10) unaffected.")
//! @yah:verify("cargo test -p cheers-sqlx --features libsql-integration --test libsql — 7/7 pass (Docker required, ~2s after image pull).")
//! @yah:verify("cargo test -p cheers-sqlx --features sqlite — 10/10 pass (no regression).")
//! @yah:verify("cargo test -p cheers-core && cargo test -p cheers-server && cargo test -p cheers-verify — all green.")
//! @yah:assumes("libSQL accepts the same SQLite-flavor DDL we ship for sqlx::sqlite. Verified for migrations 0001+0002+0003; future migrations should re-run this harness as part of their own verify step.")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)

#![cfg(feature = "sqlite")]

mod common;

use cheers_core::{DeviceId, UserId};
use cheers_server::store::{NewUser, UserStore};
use cheers_sqlx::{
    SqliteAuditStore, SqliteOwnershipStore, SqliteRefreshStore, SqliteRevocationStore,
    SqliteServicePrincipalStore, SqliteUserStore, SQLITE_MIGRATIONS,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;
use std::str::FromStr;

async fn fresh_pool() -> SqlitePool {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .unwrap()
        .create_if_missing(true)
        // Foreign-key enforcement is off by default in sqlite.
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        // One connection — :memory: databases are per-connection, so a pool
        // with N connections gives you N independent databases. Keep the
        // schema visible across the test by capping at 1.
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("sqlite connect");
    SQLITE_MIGRATIONS.run(&pool).await.expect("migrate");
    pool
}

async fn seeded_user(users: &SqliteUserStore) -> UserId {
    users
        .create(NewUser::new().with_email("u@example.com"))
        .await
        .expect("seed user")
        .id
}

#[tokio::test]
async fn user_store_lifecycle() {
    let pool = fresh_pool().await;
    let users = SqliteUserStore::new(pool);
    common::user_store_lifecycle(&users).await;
}

#[tokio::test]
async fn refresh_store_put_get_consume_revoke() {
    let pool = fresh_pool().await;
    let users = SqliteUserStore::new(pool.clone());
    let user = seeded_user(&users).await;
    let refresh = SqliteRefreshStore::new(pool);
    let device = DeviceId::new("d1");
    common::refresh_store_put_get_consume_revoke(&refresh, &user, &device).await;
}

#[tokio::test]
async fn refresh_store_other_chain_unaffected() {
    let pool = fresh_pool().await;
    let users = SqliteUserStore::new(pool.clone());
    let user = seeded_user(&users).await;
    let refresh = SqliteRefreshStore::new(pool);
    let device = DeviceId::new("d1");
    common::refresh_store_other_chain_unaffected(&refresh, &user, &device).await;
}

#[tokio::test]
async fn user_store_list_devices_reflects_refresh_chains() {
    let pool = fresh_pool().await;
    let users = SqliteUserStore::new(pool.clone());
    let user = seeded_user(&users).await;
    let refresh = SqliteRefreshStore::new(pool);

    assert!(users.list_devices(&user).await.unwrap().is_empty());

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

    use cheers_server::store::RefreshStore;
    let mut devs = users.list_devices(&user).await.unwrap();
    devs.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    assert_eq!(devs, vec![DeviceId::new("d1"), DeviceId::new("d2")]);

    // Revoke d1 — list_devices drops it.
    users
        .revoke_device(&user, &DeviceId::new("d1"))
        .await
        .unwrap();
    let devs = users.list_devices(&user).await.unwrap();
    assert_eq!(devs, vec![DeviceId::new("d2")]);

    // Second revoke -> NotFound (no active chains for d1).
    match users.revoke_device(&user, &DeviceId::new("d1")).await {
        Err(cheers_core::StoreError::NotFound) => {}
        other => panic!("expected NotFound, got {other:?}"),
    }

    // Sanity: the refresh row IS marked revoked, get still returns it.
    let row = refresh.get("t1").await.unwrap().unwrap();
    assert!(row.revoked);
}

#[tokio::test]
async fn revocation_writer_and_reader() {
    let pool = fresh_pool().await;
    let revoke = SqliteRevocationStore::new(pool);
    common::revocation_writer_and_reader(&revoke).await;
}

#[tokio::test]
async fn ownership_store_lifecycle() {
    let pool = fresh_pool().await;
    let store = SqliteOwnershipStore::new(pool);
    common::ownership_store_lifecycle(&store).await;
}

#[tokio::test]
async fn ownership_store_check_constraints_reject_bad_rows() {
    let pool = fresh_pool().await;
    let store = SqliteOwnershipStore::new(pool);
    common::ownership_store_check_constraints_reject_bad_rows(&store).await;
}

#[tokio::test]
async fn service_principal_lifecycle() {
    let pool = fresh_pool().await;
    let store = SqliteServicePrincipalStore::new(pool);
    common::service_principal_lifecycle(&store).await;
}

#[tokio::test]
async fn service_principal_rejects_non_service_kind() {
    let pool = fresh_pool().await;
    let store = SqliteServicePrincipalStore::new(pool);
    common::service_principal_rejects_non_service_kind(&store).await;
}

#[tokio::test]
async fn service_principal_check_constraint_rejects_bad_status() {
    // Bypass the trait: raw INSERT with an out-of-vocab status — schema CHECK
    // catches it before the row lands. Belt-and-suspenders coverage that the
    // Rust-side rejection in service_principal_rejects_non_service_kind doesn't
    // exercise.
    let pool = fresh_pool().await;
    let pool_for_closure = pool.clone();
    common::service_principal_check_constraint_rejects_bad_status_directly(async move {
        sqlx::query(
            "INSERT INTO service_principals (id, status, created_at) VALUES (?, ?, ?)",
        )
        .bind("svc:bogus")
        .bind("emerging")
        .bind(1_000)
        .execute(&pool_for_closure)
        .await
        .map(|_| ())
        .map_err(|e| cheers_core::StoreError::Backend(e.to_string()))
    })
    .await;
    // Also: id without svc: prefix is rejected even with a valid status.
    let pool_for_closure = pool.clone();
    common::service_principal_check_constraint_rejects_bad_status_directly(async move {
        sqlx::query(
            "INSERT INTO service_principals (id, status, created_at) VALUES (?, ?, ?)",
        )
        .bind("user:alice")
        .bind("active")
        .bind(1_000)
        .execute(&pool_for_closure)
        .await
        .map(|_| ())
        .map_err(|e| cheers_core::StoreError::Backend(e.to_string()))
    })
    .await;
}

#[tokio::test]
async fn audit_store_batch_insert_round_trip() {
    let pool = fresh_pool().await;
    let store = SqliteAuditStore::new(pool);
    common::audit_store_batch_insert_round_trip(&store).await;
}

#[cfg(feature = "passkey")]
mod passkey {
    use super::*;
    use cheers_sqlx::SqlitePasskeyCredentialStore;

    #[tokio::test]
    async fn passkey_store_round_trip() {
        let pool = fresh_pool().await;
        let users = SqliteUserStore::new(pool.clone());
        let user = seeded_user(&users).await;
        let passkeys = SqlitePasskeyCredentialStore::new(pool);
        super::common::passkey_store_round_trip(&passkeys, &user).await;
    }
}
