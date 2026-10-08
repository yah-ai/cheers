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

use cheers_core::{DeviceId, PrincipalId, UserId};
use cheers_server::ownership::OwnershipStore;
use cheers_server::store::{NewUser, UserStore};
use cheers_sqlx::{
    SqliteAuditStore, SqliteOwnershipStore, SqliteRefreshStore, SqliteRevocationStore,
    SqliteServicePrincipalStore, SqliteUserStore, SqliteUserTokenStore, SQLITE_MIGRATIONS,
    SqliteBindingSequenceStore,
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
async fn user_store_get_by_id() {
    let pool = fresh_pool().await;
    let users = SqliteUserStore::new(pool);
    common::user_store_get_by_id(&users).await;
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
async fn binding_sequence_store() {
    let pool = fresh_pool().await;
    common::binding_sequence_store(&SqliteBindingSequenceStore::new(pool)).await;
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
async fn ownership_store_revoke_follows_holder() {
    let pool = fresh_pool().await;
    let store = SqliteOwnershipStore::new(pool);
    common::ownership_store_revoke_follows_holder(&store).await;
}

#[tokio::test]
async fn ownership_store_subject_sets() {
    let pool = fresh_pool().await;
    let store = SqliteOwnershipStore::new(pool);
    common::ownership_store_subject_sets(&store).await;
}

#[tokio::test]
async fn ownership_store_list_for_kind() {
    let pool = fresh_pool().await;
    let store = SqliteOwnershipStore::new(pool);
    common::ownership_store_list_for_kind(&store).await;
}

#[tokio::test]
async fn ownership_store_version() {
    let pool = fresh_pool().await;
    let store = SqliteOwnershipStore::new(pool);
    common::ownership_store_version(&store).await;
}

#[tokio::test]
async fn ownership_store_revocation_key() {
    let pool = fresh_pool().await;
    let store = SqliteOwnershipStore::new(pool);
    common::ownership_store_revocation_key(&store).await;
}

#[tokio::test]
async fn ownership_store_admission_policy() {
    let store = SqliteOwnershipStore::new(fresh_pool().await);
    common::ownership_store_admission_policy(&store).await;
}

#[tokio::test]
async fn ownership_store_lease() {
    common::ownership_store_lease(&SqliteOwnershipStore::new(fresh_pool().await)).await;
}

#[tokio::test]
async fn knock_store_lifecycle() {
    common::knock_store_lifecycle(&cheers_sqlx::SqliteKnockStore::new(fresh_pool().await)).await;
}

#[tokio::test]
async fn ownership_subject_check_rejects_bad_forms() {
    let pool = fresh_pool().await;
    common::ownership_subject_check_rejects_bad_forms(|sql| {
        let pool = pool.clone();
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

/// 0009 rebuilds the ownership table; a row written under 0008's schema must
/// come through it intact, as a principal-subject row.
#[tokio::test]
async fn ownership_0009_rebuild_preserves_existing_rows() {
    // One connection: each :memory: connection is its own database.
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .expect("open :memory:");
    let dir =std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations/sqlite");
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("read migrations dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "sql"))
        .collect();
    files.sort();
    let (before, after): (Vec<_>, Vec<_>) = files.into_iter().partition(|p| {
        p.file_name().unwrap().to_string_lossy().as_ref() < "0009"
    });
    let run = |path: &std::path::Path| std::fs::read_to_string(path).expect("read migration");
    for p in &before {
        sqlx::raw_sql(&run(p)).execute(&pool).await.expect("pre-0009 migration");
    }
    sqlx::query(
        "INSERT INTO ownership (id, principal_id, resource_kind, resource_id, relationship, \
         granted_by, on_behalf_of, granted_at, revoked_at) \
         VALUES ('old-1', 'user:alice', 'doc', 'd1', 'owner', 'svc:cheers', 'user:bob', 10, NULL)",
    )
    .execute(&pool)
    .await
    .expect("row under 0008");
    for p in &after {
        sqlx::raw_sql(&run(p)).execute(&pool).await.expect("0009+ migration");
    }

    let store = SqliteOwnershipStore::new(pool);
    let row = store.get("old-1").await.unwrap().expect("row survives the rebuild");
    assert_eq!(row.subject, cheers_core::Subject::Principal(PrincipalId::user("alice")));
    assert_eq!(row.on_behalf_of, Some(PrincipalId::user("bob")));
    assert_eq!(row.granted_at, 10);
    assert_eq!(store.list_for_principal(&PrincipalId::user("alice")).await.unwrap(), vec![row]);
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

#[tokio::test]
async fn audit_store_query_by_on_behalf_of() {
    let pool = fresh_pool().await;
    let store = SqliteAuditStore::new(pool);
    common::audit_store_query_by_on_behalf_of(&store).await;
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

// ---------------------------------------------------------------------------
// UserTokenStore (R728-F1) — user_tokens.user_id carries a FK to users, so
// every scenario seeds a real user first.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn user_token_store_insert_and_scoped_list() {
    let pool = fresh_pool().await;
    let users = SqliteUserStore::new(pool.clone());
    let user = seeded_user(&users).await;
    let other = users
        .create(NewUser::new().with_email("other@example.com"))
        .await
        .expect("seed second user")
        .id;
    let tokens = SqliteUserTokenStore::new(pool);
    common::user_token_store_insert_and_scoped_list(&tokens, &user, &other).await;
}

#[tokio::test]
async fn user_token_store_revoked_and_expired_leave_the_live_list() {
    let pool = fresh_pool().await;
    let user = seeded_user(&SqliteUserStore::new(pool.clone())).await;
    let tokens = SqliteUserTokenStore::new(pool);
    common::user_token_store_revoked_and_expired_leave_the_live_list(&tokens, &user).await;
}

#[tokio::test]
async fn user_token_store_revoke_is_idempotent_and_touch_stamps() {
    let pool = fresh_pool().await;
    let user = seeded_user(&SqliteUserStore::new(pool.clone())).await;
    let tokens = SqliteUserTokenStore::new(pool);
    common::user_token_store_revoke_is_idempotent_and_touch_stamps(&tokens, &user).await;
}

/// An empty in-memory pool, schema not yet applied.
async fn bare_pool() -> SqlitePool {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:").unwrap().create_if_missing(true);
    SqlitePoolOptions::new().max_connections(1).connect_with(opts).await.unwrap()
}

/// Apply the migrations with `lo <= version < hi`, raw (outside sqlx's ledger).
async fn apply_raw(pool: &SqlitePool, lo: i64, hi: i64) {
    for m in cheers_sqlx::SQLITE_MIGRATIONS.iter().filter(|m| (lo..hi).contains(&m.version)) {
        sqlx::raw_sql(&m.sql).execute(pool).await.unwrap();
    }
}

/// R734-F1: 0015 rewrites a legacy membership subject (a bare user id) into
/// the principal wire form and leaves device subjects alone.
#[tokio::test]
async fn migration_0015_prefixes_legacy_membership_subjects() {
    use cheers_core::{PrincipalId, Revoked};
    use cheers_server::RevocationWriter;
    use cheers_verify::RevocationReader;

    let pool = bare_pool().await;
    apply_raw(&pool, 0, 15).await;
    sqlx::raw_sql(
        "INSERT INTO revocations (kind, subject, revoked_at, bound) VALUES ('device', 'phone', 1, 3);
         INSERT INTO revocations (kind, subject, resource_kind, resource_id, revoked_at, bound)
             VALUES ('membership', 'alice', 'namespace', 'ns-1', 1, 7);",
    )
    .execute(&pool)
    .await
    .unwrap();
    apply_raw(&pool, 15, i64::MAX).await;

    let store = SqliteRevocationStore::new(pool);
    let mut got = store.snapshot().await.unwrap().revoked;
    got.sort_by(|a, b| a.identity().cmp(&b.identity()));
    assert_eq!(
        got,
        vec![Revoked::device("phone", 3), Revoked::membership("namespace", "ns-1", PrincipalId::user("alice"), 7)]
    );
    let k = cheers_verify::test_revocation_key("namespace", "ns-1");
    assert!(store.is_membership_revoked(&k, "namespace", "ns-1", &PrincipalId::user("alice"), 6).await.unwrap());
}

/// R732-T7: 0012 gives legacy device / membership rows (which meant "masks
/// everything") bound = i64::MAX — fail-closed — and leaves legacy jtis with
/// expires_at NULL, so they never lapse.
#[tokio::test]
async fn migration_0012_makes_legacy_revocations_fail_closed() {
    use cheers_core::Revoked;
    use cheers_server::RevocationWriter;
    use cheers_verify::RevocationReader;

    let pool = bare_pool().await;
    apply_raw(&pool, 0, 12).await;
    sqlx::raw_sql(
        "INSERT INTO revocations (kind, subject, revoked_at) VALUES ('jti', 'old-jti', 1);
         INSERT INTO revocations (kind, subject, revoked_at) VALUES ('device', 'phone', 1);
         INSERT INTO revocations (kind, subject, resource_kind, resource_id, revoked_at)
             VALUES ('membership', 'alice', 'namespace', 'ns-1', 1);",
    )
    .execute(&pool)
    .await
    .unwrap();
    apply_raw(&pool, 12, i64::MAX).await;

    let store = SqliteRevocationStore::new(pool);
    assert!(store.is_revoked("old-jti").await.unwrap());
    assert!(store.is_device_revoked(&DeviceId::new("phone"), i64::MAX as u64 - 1).await.unwrap());
    assert!(store
        .is_membership_revoked(&cheers_verify::test_revocation_key("namespace", "ns-1"), "namespace", "ns-1", &cheers_core::PrincipalId::user("alice"), 1 << 62)
        .await
        .unwrap());
    assert_eq!(store.gc(i64::MAX).await.unwrap(), 0, "a legacy jti never lapses");
    let max = i64::MAX as u64;
    let mut got = store.snapshot().await.unwrap().revoked;
    got.sort_by(|a, b| a.identity().cmp(&b.identity()));
    assert_eq!(
        got,
        vec![
            Revoked::jti("old-jti", None),
            Revoked::device("phone", max),
            Revoked::membership("namespace", "ns-1", cheers_core::PrincipalId::user("alice"), max),
        ]
    );
    // A re-revoke below the legacy bound is a no-op.
    let epoch = store.snapshot().await.unwrap().epoch;
    store.revoke(&Revoked::device("phone", 5)).await.unwrap();
    assert_eq!(store.snapshot().await.unwrap().epoch, epoch);
}

/// R732-T7: gc drops jtis whose exp passed, keeps exp-None jtis and devices,
/// and advances the epoch iff it deleted anything.
#[tokio::test]
async fn revocation_gc_lapses_jtis_by_exp() {
    use cheers_core::Revoked;
    use cheers_server::RevocationWriter;
    use cheers_verify::RevocationReader;

    let store = SqliteRevocationStore::new(fresh_pool().await);
    store.revoke(&Revoked::jti("short", Some(50))).await.unwrap();
    store.revoke(&Revoked::jti("forever", None)).await.unwrap();
    store.revoke(&Revoked::device("phone", 1)).await.unwrap();
    let before = store.snapshot().await.unwrap().epoch;
    assert_eq!(store.gc(49).await.unwrap(), 0);
    assert_eq!(store.snapshot().await.unwrap().epoch, before);
    assert_eq!(store.gc(50).await.unwrap(), 1);
    let after = store.snapshot().await.unwrap();
    assert!(after.epoch > before);
    assert_eq!(after.revoked.len(), 2);
    assert!(!store.is_revoked("short").await.unwrap());
    assert!(store.is_revoked("forever").await.unwrap());
}
