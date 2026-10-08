//! The in-process Turso backend against the shared store-contract suite.
//!
//! Every scenario here is the *same function* `cheers-sqlx`'s `sqlite.rs` and
//! `pg.rs` call — `cheers_test_support::store_scenarios`. That is what makes
//! "the account database can move into a cell without a rewrite" a checked
//! property rather than a design intention.
//!
//! Tests default to `:memory:`, which takes no file lock, so the suite runs in
//! parallel like any other. The handful of tests that need real on-disk
//! behavior (persistence, the lock) say so and use a `tempfile` directory.

use std::sync::Arc;

use cheers_core::{DeviceId, UserId};
use cheers_server::store::{NewUser, RefreshStore, UserStore};
use cheers_test_support::store_scenarios as common;
use cheers_turso::{
    migrate, AccountStores, TursoAuditStore, TursoConn, TursoOwnershipStore,
    TursoPasskeyCredentialStore, TursoRefreshStore, TursoRevocationStore,
    TursoServicePrincipalStore, TursoUserStore, TursoUserTokenStore, MIGRATIONS,
    TursoBindingSequenceStore,
};

/// A freshly migrated in-memory database. Each call gets its own.
async fn fresh() -> Arc<TursoConn> {
    let conn = Arc::new(TursoConn::open_in_memory().await.expect("open :memory:"));
    migrate::run(&conn).await.expect("migrate");
    conn
}

/// The refresh / passkey tables carry a foreign key to `users`, so those
/// scenarios need a real user first.
async fn seeded_user(users: &TursoUserStore) -> UserId {
    users
        .create(NewUser::new().with_email("u@example.com"))
        .await
        .expect("seed user")
        .id
}

// ---------------------------------------------------------------------------
// The shared contract suite
// ---------------------------------------------------------------------------

#[tokio::test]
async fn user_store_lifecycle() {
    let users = TursoUserStore::new(fresh().await);
    common::user_store_lifecycle(&users).await;
}

#[tokio::test]
async fn user_store_get_by_id() {
    let users = TursoUserStore::new(fresh().await);
    common::user_store_get_by_id(&users).await;
}

#[tokio::test]
async fn refresh_store_put_get_consume_revoke() {
    let conn = fresh().await;
    let user = seeded_user(&TursoUserStore::new(conn.clone())).await;
    let refresh = TursoRefreshStore::new(conn);
    common::refresh_store_put_get_consume_revoke(&refresh, &user, &DeviceId::new("d1")).await;
}

#[tokio::test]
async fn refresh_store_other_chain_unaffected() {
    let conn = fresh().await;
    let user = seeded_user(&TursoUserStore::new(conn.clone())).await;
    let refresh = TursoRefreshStore::new(conn);
    common::refresh_store_other_chain_unaffected(&refresh, &user, &DeviceId::new("d1")).await;
}

#[tokio::test]
async fn revocation_writer_and_reader() {
    let revoke = TursoRevocationStore::new(fresh().await);
    common::revocation_writer_and_reader(&revoke).await;
}

#[tokio::test]
async fn binding_sequence_store() {
    common::binding_sequence_store(&TursoBindingSequenceStore::new(fresh().await)).await;
}

#[tokio::test]
async fn ownership_store_lifecycle() {
    let store = TursoOwnershipStore::new(fresh().await);
    common::ownership_store_lifecycle(&store).await;
}

#[tokio::test]
async fn ownership_store_check_constraints_reject_bad_rows() {
    let store = TursoOwnershipStore::new(fresh().await);
    common::ownership_store_check_constraints_reject_bad_rows(&store).await;
}

#[tokio::test]
async fn ownership_store_revoke_follows_holder() {
    let store = TursoOwnershipStore::new(fresh().await);
    common::ownership_store_revoke_follows_holder(&store).await;
}

#[tokio::test]
async fn ownership_store_subject_sets() {
    let store = TursoOwnershipStore::new(fresh().await);
    common::ownership_store_subject_sets(&store).await;
}

#[tokio::test]
async fn ownership_store_list_for_kind() {
    let store = TursoOwnershipStore::new(fresh().await);
    common::ownership_store_list_for_kind(&store).await;
}

#[tokio::test]
async fn ownership_store_version() {
    let store = TursoOwnershipStore::new(fresh().await);
    common::ownership_store_version(&store).await;
}

#[tokio::test]
async fn ownership_store_revocation_key() {
    let store = TursoOwnershipStore::new(fresh().await);
    common::ownership_store_revocation_key(&store).await;
}

#[tokio::test]
async fn ownership_store_admission_policy() {
    let store = TursoOwnershipStore::new(fresh().await);
    common::ownership_store_admission_policy(&store).await;
}

#[tokio::test]
async fn ownership_store_lease() {
    common::ownership_store_lease(&TursoOwnershipStore::new(fresh().await)).await;
}

#[tokio::test]
async fn knock_store_lifecycle() {
    common::knock_store_lifecycle(&cheers_turso::TursoKnockStore::new(fresh().await)).await;
}

#[tokio::test]
async fn ownership_subject_check_rejects_bad_forms() {
    // Raw INSERTs: proves the engine enforces the one-form CHECK, not just
    // that the Rust types cannot express a bad subject.
    let conn = fresh().await;
    common::ownership_subject_check_rejects_bad_forms(|sql| {
        let c = conn.clone();
        async move {
            c.execute(&sql, vec![])
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
    use cheers_core::{PrincipalId, Subject};
    use cheers_server::ownership::OwnershipStore;

    let conn = Arc::new(TursoConn::open_in_memory().await.expect("open :memory:"));
    let (before, after): (Vec<&migrate::Migration>, Vec<_>) =
        MIGRATIONS.iter().partition(|m| m.version < 9);
    for m in before {
        conn.execute_batch(m.sql).await.expect("pre-0009 migration");
    }
    conn.execute(
        "INSERT INTO ownership (id, principal_id, resource_kind, resource_id, relationship, \
         granted_by, on_behalf_of, granted_at, revoked_at) \
         VALUES ('old-1', 'user:alice', 'doc', 'd1', 'owner', 'svc:cheers', 'user:bob', 10, NULL)",
        vec![],
    )
    .await
    .expect("row under 0008");
    for m in after {
        conn.execute_batch(m.sql).await.expect("0009+ migration");
    }

    let store = TursoOwnershipStore::new(conn);
    let row = store.get("old-1").await.unwrap().expect("row survives the rebuild");
    assert_eq!(row.subject, Subject::Principal(PrincipalId::user("alice")));
    assert_eq!(row.on_behalf_of, Some(PrincipalId::user("bob")));
    assert_eq!(row.granted_at, 10);
    assert_eq!(store.list_for_principal(&PrincipalId::user("alice")).await.unwrap(), vec![row]);
}

#[tokio::test]
async fn service_principal_lifecycle() {
    let store = TursoServicePrincipalStore::new(fresh().await);
    common::service_principal_lifecycle(&store).await;
}

#[tokio::test]
async fn service_principal_rejects_non_service_kind() {
    let store = TursoServicePrincipalStore::new(fresh().await);
    common::service_principal_rejects_non_service_kind(&store).await;
}

#[tokio::test]
async fn service_principal_check_constraint_rejects_bad_status() {
    // Bypass the trait entirely: a raw INSERT with an out-of-vocabulary status
    // must be stopped by the schema CHECK. This is the half the Rust-side
    // rejection can't cover, and it is the half that proves the engine
    // actually enforces CHECK constraints rather than parsing and ignoring
    // them.
    let conn = fresh().await;

    let c = conn.clone();
    common::service_principal_check_constraint_rejects_bad_status_directly(async move {
        c.execute(
            "INSERT INTO service_principals (id, status, created_at) VALUES (?, ?, ?)",
            vec!["svc:bogus".into(), "emerging".into(), 1_000i64.into()],
        )
        .await
        .map(|_| ())
    })
    .await;

    // And an id without the `svc:` prefix is rejected even with a valid status.
    let c = conn.clone();
    common::service_principal_check_constraint_rejects_bad_status_directly(async move {
        c.execute(
            "INSERT INTO service_principals (id, status, created_at) VALUES (?, ?, ?)",
            vec!["user:alice".into(), "active".into(), 1_000i64.into()],
        )
        .await
        .map(|_| ())
    })
    .await;
}

#[tokio::test]
async fn audit_store_batch_insert_round_trip() {
    let store = TursoAuditStore::new(fresh().await);
    common::audit_store_batch_insert_round_trip(&store).await;
}

#[tokio::test]
async fn audit_store_query_by_on_behalf_of() {
    let store = TursoAuditStore::new(fresh().await);
    common::audit_store_query_by_on_behalf_of(&store).await;
}

// ---------------------------------------------------------------------------
// UserTokenStore (R728-F1) — user_tokens.user_id carries a FK to users, so
// every scenario seeds a real user first.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn user_token_store_insert_and_scoped_list() {
    let conn = fresh().await;
    let users = TursoUserStore::new(conn.clone());
    let user = seeded_user(&users).await;
    let other = users
        .create(NewUser::new().with_email("other@example.com"))
        .await
        .expect("seed second user")
        .id;
    let tokens = TursoUserTokenStore::new(conn);
    common::user_token_store_insert_and_scoped_list(&tokens, &user, &other).await;
}

#[tokio::test]
async fn user_token_store_revoked_and_expired_leave_the_live_list() {
    let conn = fresh().await;
    let user = seeded_user(&TursoUserStore::new(conn.clone())).await;
    let tokens = TursoUserTokenStore::new(conn);
    common::user_token_store_revoked_and_expired_leave_the_live_list(&tokens, &user).await;
}

#[tokio::test]
async fn user_token_store_revoke_is_idempotent_and_touch_stamps() {
    let conn = fresh().await;
    let user = seeded_user(&TursoUserStore::new(conn.clone())).await;
    let tokens = TursoUserTokenStore::new(conn);
    common::user_token_store_revoke_is_idempotent_and_touch_stamps(&tokens, &user).await;
}

#[tokio::test]
async fn passkey_store_round_trip() {
    let conn = fresh().await;
    let user = seeded_user(&TursoUserStore::new(conn.clone())).await;
    let passkeys = TursoPasskeyCredentialStore::new(conn);
    common::passkey_store_round_trip(&passkeys, &user).await;
}

/// `list_devices` is derived from live refresh chains rather than stored
/// directly, so it needs the two stores wired together — the same scenario
/// `cheers-sqlx`'s `sqlite.rs` spells out inline.
#[tokio::test]
async fn user_store_list_devices_reflects_refresh_chains() {
    let conn = fresh().await;
    let users = TursoUserStore::new(conn.clone());
    let user = seeded_user(&users).await;
    let refresh = TursoRefreshStore::new(conn);

    assert!(users.list_devices(&user).await.unwrap().is_empty());

    for (token, chain, device) in [("t1", "c1", "d1"), ("t2", "c2", "d2")] {
        refresh
            .put(&common::fixture_refresh(
                token,
                chain,
                None,
                &user,
                &DeviceId::new(device),
                100,
                1_000,
            ))
            .await
            .unwrap();
    }

    let mut devs = users.list_devices(&user).await.unwrap();
    devs.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    assert_eq!(devs, vec![DeviceId::new("d1"), DeviceId::new("d2")]);

    // Revoking a device drops it from the list.
    users
        .revoke_device(&user, &DeviceId::new("d1"))
        .await
        .unwrap();
    assert_eq!(
        users.list_devices(&user).await.unwrap(),
        vec![DeviceId::new("d2")]
    );

    // A second revoke finds no live chains -> NotFound.
    match users.revoke_device(&user, &DeviceId::new("d1")).await {
        Err(cheers_core::StoreError::NotFound) => {}
        other => panic!("expected NotFound, got {other:?}"),
    }

    // The row itself survives, marked revoked — revocation is not deletion.
    assert!(refresh.get("t1").await.unwrap().unwrap().revoked);
}

// ---------------------------------------------------------------------------
// Schema drift guard
// ---------------------------------------------------------------------------

/// The migrations here must stay byte-identical to `cheers-sqlx`'s.
///
/// They are a copy rather than a cross-crate `include_str!` so this crate
/// packages standalone; this test is what makes the copy safe. It compares
/// against the sibling crate's directory when that path exists — always in the
/// monorepo, never in a published tarball, where it skips.
#[test]
fn migrations_match_cheers_sqlx() {
    let sibling = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../cheers-sqlx/migrations/sqlite");
    if !sibling.is_dir() {
        eprintln!("skipping drift guard: {} not present", sibling.display());
        return;
    }

    // Every file cheers-sqlx ships must be embedded here, byte for byte.
    let mut sibling_files: Vec<_> = std::fs::read_dir(&sibling)
        .expect("read cheers-sqlx migrations")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".sql"))
        .collect();
    sibling_files.sort();

    let mut ours: Vec<_> = MIGRATIONS.iter().map(|m| m.filename.to_owned()).collect();
    ours.sort();

    assert_eq!(
        ours, sibling_files,
        "cheers-turso and cheers-sqlx ship different migration files; \
         add the new file to both, and to MIGRATIONS"
    );

    for m in MIGRATIONS {
        let theirs = std::fs::read_to_string(sibling.join(m.filename))
            .unwrap_or_else(|e| panic!("read {}: {e}", m.filename));
        assert_eq!(
            m.sql, theirs,
            "{} differs between cheers-turso and cheers-sqlx; the two families \
             must migrate to the identical schema or the account-DB flip breaks",
            m.filename
        );
    }
}

// ---------------------------------------------------------------------------
// On-disk behavior: persistence and the engine's exclusive lock
// ---------------------------------------------------------------------------

/// A file-backed database survives being closed and reopened, and re-running
/// the migrator against it applies nothing.
#[tokio::test]
async fn file_backed_database_persists_across_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("accounts.db");

    let user_id = {
        let conn = Arc::new(TursoConn::open(&path).await.unwrap());
        migrate::run(&conn).await.unwrap();
        let stores = AccountStores::new(conn);
        stores
            .users()
            .create(NewUser::new().with_email("persist@example.com"))
            .await
            .unwrap()
            .id
        // Both the stores and the connection drop here, releasing the lock.
    };

    let conn = Arc::new(TursoConn::open(&path).await.unwrap());
    // Idempotent against a database this same runner migrated.
    migrate::run(&conn).await.unwrap();

    let rows = conn
        .query(
            "SELECT email FROM users WHERE user_id = ?",
            vec![user_id.as_str().into()],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 1, "the user must survive the reopen");
}

/// Pins the lock semantics this crate is designed around.
///
/// The cross-process half — a second OS process is refused at open time — can't
/// be exercised from inside one test binary, but its consequence is what the
/// design encodes: `TursoConn` holds the `Database` alive, because dropping
/// only the `Connection` does not release the lock. What *is* checkable here is
/// the in-process half, and it is worth pinning because it contradicts the
/// simpler reading of the constraint: within a single process the engine does
/// permit a second handle on the same file, and the two see each other's
/// writes. Code must not rely on "opening twice fails" as an in-process
/// mutual-exclusion mechanism — it isn't one.
#[tokio::test]
async fn second_in_process_handle_is_permitted_and_coherent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("accounts.db");

    let first = Arc::new(TursoConn::open(&path).await.unwrap());
    migrate::run(&first).await.unwrap();

    let second = Arc::new(TursoConn::open(&path).await.unwrap());
    let user = TursoUserStore::new(second.clone())
        .create(NewUser::new().with_email("via-second@example.com"))
        .await
        .unwrap();

    // The write went through the second handle; the first must see it.
    let rows = first
        .query(
            "SELECT user_id FROM users WHERE user_id = ?",
            vec![user.id.as_str().into()],
        )
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "two in-process handles on one file must share state"
    );
}
