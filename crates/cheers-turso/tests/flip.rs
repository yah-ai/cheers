//! The noisetable-account flip, exercised end to end.
//!
//! The claim this crate makes is not "cheers-turso works" but "the account
//! database can move from vanilla sqlite to a Turso cell by pointing a
//! different binary at the same file". Those are different claims, and only
//! the second one is what R131-S1's flip-trigger 4 is waiting on.
//!
//! So these tests drive **both families against one file**: `cheers-sqlx`
//! (sqlx, vanilla SQLite — today's P2 path) and `cheers-turso` (the in-process
//! engine — the cell-hosted future), in both orders. What must hold:
//!
//! 1. A database migrated by either family is seen as fully migrated by the
//!    other. Neither re-runs the other's migrations; neither trips the other's
//!    checksum guard.
//! 2. Rows written by one family read back correctly through the other's
//!    typed stores.
//!
//! Both families are dev-dependencies here purely for this file. Note the
//! ordering constraint the engine imposes: its exclusive lock means the two
//! families can never hold the file *at the same time*, so every test hands
//! the file over explicitly by dropping one side before opening the other.
//! That is exactly the shape a real flip takes — stop the old binary, start
//! the new one.

use std::sync::Arc;

use cheers_core::{DeviceId, UserId};
use cheers_server::store::{
    NewUser, ProviderKey, RefreshStore, RefreshTokenRecord, UserStore,
};
use cheers_sqlx::{SqliteRefreshStore, SqliteUserStore, SQLITE_MIGRATIONS};
use cheers_turso::{migrate, TursoConn, TursoRefreshStore, TursoUserStore};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::SqlitePool;

/// A sqlx pool over a real file, with the same pragmas the sqlite backend uses
/// in production.
async fn sqlx_pool(path: &std::path::Path) -> SqlitePool {
    let opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .foreign_keys(true);
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .expect("sqlx connect")
}

/// Close a sqlx pool and wait for it, so the file is genuinely released before
/// the engine tries to take its exclusive lock.
async fn hand_over(pool: SqlitePool) {
    pool.close().await;
}

fn record(token: &str, chain: &str, user: &UserId, device: &str) -> RefreshTokenRecord {
    RefreshTokenRecord::new(
        token.to_owned(),
        chain.to_owned(),
        None,
        user.clone(),
        DeviceId::new(device),
        1_000,
        9_000,
        false,
        false,
    )
}

/// sqlx migrates, turso takes over: the direction the real flip runs.
#[tokio::test]
async fn sqlx_migrated_database_is_already_migrated_for_turso() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("accounts.db");

    // --- the P2 path: vanilla sqlite via sqlx
    let pool = sqlx_pool(&path).await;
    SQLITE_MIGRATIONS.run(&pool).await.expect("sqlx migrate");

    let user = SqliteUserStore::new(pool.clone())
        .create(NewUser::new().with_email("before@example.com").with_name("Before"))
        .await
        .expect("create via sqlx");
    SqliteUserStore::new(pool.clone())
        .link_provider(&user.id, &ProviderKey::OidcGoogle, "google-sub-flip")
        .await
        .expect("link via sqlx");
    SqliteRefreshStore::new(pool.clone())
        .put(&record("tok-sqlx", "chain-sqlx", &user.id, "d1"))
        .await
        .expect("refresh via sqlx");

    let applied_before = migration_rows(&pool).await;
    hand_over(pool).await;

    // --- the flip: same file, engine binary
    let conn = Arc::new(TursoConn::open(&path).await.expect("turso open"));
    migrate::run(&conn).await.expect("turso migrate is a no-op here");

    // 1. Nothing was re-applied: the bookkeeping table is untouched.
    let applied_after = turso_migration_rows(&conn).await;
    assert_eq!(
        applied_before, applied_after,
        "cheers-turso must not re-run or rewrite migrations cheers-sqlx applied"
    );

    // 2. The sqlx-written rows read back through the turso stores.
    let found = TursoUserStore::new(conn.clone())
        .find_by_provider(&ProviderKey::OidcGoogle, "google-sub-flip")
        .await
        .expect("lookup via turso")
        .expect("the sqlx-created user must be visible");
    assert_eq!(found.id, user.id);
    assert_eq!(found.email.as_deref(), Some("before@example.com"));
    assert_eq!(found.name.as_deref(), Some("Before"));

    let refresh = TursoRefreshStore::new(conn.clone());
    let row = refresh
        .get("tok-sqlx")
        .await
        .expect("refresh lookup via turso")
        .expect("the sqlx-written refresh row must be visible");
    assert_eq!(row.chain_id, "chain-sqlx");
    assert!(!row.consumed && !row.revoked);

    // 3. And the rotation gate still works across the boundary: a token
    //    written by sqlx is consumable exactly once by turso.
    assert!(refresh.mark_consumed("tok-sqlx").await.unwrap());
    assert!(!refresh.mark_consumed("tok-sqlx").await.unwrap());

    // 4. New writes land alongside the old ones.
    TursoUserStore::new(conn.clone())
        .create(NewUser::new().with_email("after@example.com"))
        .await
        .expect("create via turso");
    let count = conn
        .query("SELECT user_id FROM users", vec![])
        .await
        .unwrap()
        .len();
    assert_eq!(count, 2);
}

/// The reverse direction — a rollback of the flip must be just as boring.
#[tokio::test]
async fn turso_migrated_database_is_already_migrated_for_sqlx() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("accounts.db");

    let user_id = {
        let conn = Arc::new(TursoConn::open(&path).await.expect("turso open"));
        migrate::run(&conn).await.expect("turso migrate");
        let user = TursoUserStore::new(conn.clone())
            .create(NewUser::new().with_email("from-turso@example.com"))
            .await
            .expect("create via turso");
        TursoUserStore::new(conn.clone())
            .link_provider(&user.id, &ProviderKey::OidcApple, "apple-sub-flip")
            .await
            .expect("link via turso");
        user.id
        // Dropping the last Arc releases the engine's exclusive lock.
    };

    let pool = sqlx_pool(&path).await;
    // sqlx's own migrator must agree the database is current. This is the
    // strongest single assertion in the file: sqlx re-derives every checksum
    // from its own migration tree and compares against the rows cheers-turso
    // wrote, so it fails if the version, the description, or a single byte of
    // the checksum disagrees.
    SQLITE_MIGRATIONS
        .run(&pool)
        .await
        .expect("sqlx must accept a turso-migrated database as current");

    let found = SqliteUserStore::new(pool.clone())
        .find_by_provider(&ProviderKey::OidcApple, "apple-sub-flip")
        .await
        .expect("lookup via sqlx")
        .expect("the turso-created user must be visible");
    assert_eq!(found.id, user_id);
    assert_eq!(found.email.as_deref(), Some("from-turso@example.com"));

    hand_over(pool).await;
}

/// The likelier real-world flip: the old binary was a version behind, so the
/// file arrives partly migrated and the new binary must finish the job.
///
/// This is the path a fully-migrated fixture can't reach — it exercises
/// "apply the remainder on top of another family's work", where a checksum or
/// version-derivation mismatch would show up as a re-run or a hard error
/// rather than as a clean no-op.
#[tokio::test]
async fn turso_applies_the_remainder_of_a_partially_migrated_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("accounts.db");

    // Stand up a database carrying only the first two migrations, recorded the
    // way sqlx records them, then let cheers-turso finish it.
    let pool = sqlx_pool(&path).await;
    let partial = sqlx::migrate::Migrator {
        migrations: SQLITE_MIGRATIONS
            .migrations
            .iter()
            .filter(|m| m.version <= 2)
            .cloned()
            .collect::<Vec<_>>()
            .into(),
        ignore_missing: SQLITE_MIGRATIONS.ignore_missing,
        locking: SQLITE_MIGRATIONS.locking,
        no_tx: SQLITE_MIGRATIONS.no_tx,
    };
    partial.run(&pool).await.expect("partial sqlx migrate");

    let before = migration_rows(&pool).await;
    assert_eq!(before.len(), 2, "fixture must really be partial");
    hand_over(pool).await;

    // cheers-turso applies 3..=N and leaves 1..=2 exactly as sqlx wrote them.
    let conn = Arc::new(TursoConn::open(&path).await.expect("turso open"));
    migrate::run(&conn).await.expect("turso finishes the migration");

    let after = turso_migration_rows(&conn).await;
    assert!(after.len() > before.len(), "the remainder must be applied");
    assert_eq!(
        &after[..2],
        &before[..],
        "cheers-turso must not rewrite the rows cheers-sqlx already wrote"
    );

    // The tables from the migrations turso applied are really there, and the
    // stores work end to end on the result.
    let user = TursoUserStore::new(conn.clone())
        .create(NewUser::new().with_email("partial@example.com"))
        .await
        .expect("create after partial migration");
    TursoRefreshStore::new(conn.clone())
        .put(&record("tok-partial", "chain-partial", &user.id, "d1"))
        .await
        .expect("refresh store works on the completed schema");

    // And handing back to sqlx, its migrator agrees the file is now current.
    drop(conn);
    let pool = sqlx_pool(&path).await;
    SQLITE_MIGRATIONS
        .run(&pool)
        .await
        .expect("sqlx accepts the finished database");
    hand_over(pool).await;
}

/// The migration bookkeeping rows must be identical, not merely compatible —
/// same versions, same descriptions, same checksums.
#[tokio::test]
async fn both_families_write_the_same_bookkeeping_rows() {
    let dir = tempfile::tempdir().unwrap();

    let by_sqlx = {
        let pool = sqlx_pool(&dir.path().join("a.db")).await;
        SQLITE_MIGRATIONS.run(&pool).await.unwrap();
        let rows = migration_rows(&pool).await;
        hand_over(pool).await;
        rows
    };

    let by_turso = {
        let conn = Arc::new(TursoConn::open(dir.path().join("b.db")).await.unwrap());
        migrate::run(&conn).await.unwrap();
        turso_migration_rows(&conn).await
    };

    assert_eq!(
        by_sqlx, by_turso,
        "the two families must write byte-identical _sqlx_migrations rows; \
         a difference here means one of them would re-migrate the other's database"
    );
    assert!(!by_sqlx.is_empty(), "the comparison must not be vacuous");
}

/// `(version, description, checksum)` for every applied migration, ascending.
async fn migration_rows(pool: &SqlitePool) -> Vec<(i64, String, Vec<u8>)> {
    use sqlx::Row as _;
    sqlx::query(
        "SELECT version, description, checksum FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(pool)
    .await
    .expect("read _sqlx_migrations via sqlx")
    .into_iter()
    .map(|r| (r.get("version"), r.get("description"), r.get("checksum")))
    .collect()
}

/// The same, read through the engine.
async fn turso_migration_rows(conn: &TursoConn) -> Vec<(i64, String, Vec<u8>)> {
    conn.query(
        "SELECT version, description, checksum FROM _sqlx_migrations ORDER BY version",
        vec![],
    )
    .await
    .expect("read _sqlx_migrations via turso")
    .iter()
    .map(|r| {
        (
            r.get::<i64>(0).unwrap(),
            r.get::<String>(1).unwrap(),
            r.get::<Vec<u8>>(2).unwrap(),
        )
    })
    .collect()
}
