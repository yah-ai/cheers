//! Migration runner for the in-process engine.
//!
//! # Why this is bit-compatible with sqlx, not merely equivalent
//!
//! `cheers-sqlx` applies the same SQLite-flavor migrations through
//! `sqlx::migrate!`, which records them in a table called `_sqlx_migrations`.
//! This runner writes **that exact table, with that exact checksum
//! algorithm** (SHA-384 of the migration's SQL bytes) and the same version and
//! description derivation.
//!
//! That is the property the noisetable-account flip rests on. The account
//! database moves from vanilla sqlite + litestream to a Turso cell by pointing
//! a different binary at the same file — so the file must not be able to tell
//! which family last touched it. A DB migrated by `cheers-sqlx` is seen as
//! fully migrated here, a DB migrated here is seen as fully migrated by
//! `cheers-sqlx`, and neither re-runs the other's work or trips the other's
//! checksum guard. Had this runner invented its own `_cheers_migrations`
//! table, the two families would each think the schema was unmigrated and the
//! flip would need a hand-written reconciliation step.
//!
//! The migration SQL itself is a byte-identical copy of
//! `cheers-sqlx/migrations/sqlite/`. It is copied rather than `include_str!`'d
//! across the crate boundary so this crate stays self-contained when packaged;
//! `migrations_match_cheers_sqlx` in `tests/turso.rs` fails the build if the
//! two ever drift.
//!
//! # What is deliberately not implemented
//!
//! Down-migrations. `cheers-sqlx` doesn't ship any either — the migration tree
//! is forward-only, and a reversible pair would have to be authored in both
//! places to stay compatible.

use cheers_core::StoreError;
use sha2::{Digest, Sha384};

use crate::conn::{TursoConn, Unit};

/// One embedded migration, in the shape sqlx's resolver derives from a
/// filename: `<version>_<description>.sql`, with `_` in the description
/// rendered as a space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    /// The integer prefix of the filename.
    pub version: i64,
    /// The filename's remainder, `.sql` trimmed and `_` replaced with ` `.
    pub description: &'static str,
    /// The file's contents, verbatim. The checksum is taken over these bytes.
    pub sql: &'static str,
    /// The source filename, for error messages and the drift guard.
    pub filename: &'static str,
}

impl Migration {
    /// SHA-384 over the SQL bytes — the value sqlx stores in
    /// `_sqlx_migrations.checksum`.
    pub fn checksum(&self) -> Vec<u8> {
        Sha384::digest(self.sql.as_bytes()).to_vec()
    }
}

/// Every migration this crate ships, in ascending version order.
///
/// Adding one here means adding the identical file to
/// `cheers-sqlx/migrations/sqlite/` in the same commit — the drift guard
/// enforces it in both directions.
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        description: "initial",
        sql: include_str!("../migrations/sqlite/0001_initial.sql"),
        filename: "0001_initial.sql",
    },
    Migration {
        version: 2,
        description: "ownership",
        sql: include_str!("../migrations/sqlite/0002_ownership.sql"),
        filename: "0002_ownership.sql",
    },
    Migration {
        version: 3,
        description: "service principals",
        sql: include_str!("../migrations/sqlite/0003_service_principals.sql"),
        filename: "0003_service_principals.sql",
    },
    Migration {
        version: 4,
        description: "audit",
        sql: include_str!("../migrations/sqlite/0004_audit.sql"),
        filename: "0004_audit.sql",
    },
    Migration {
        version: 5,
        description: "hash refresh tokens",
        sql: include_str!("../migrations/sqlite/0005_hash_refresh_tokens.sql"),
        filename: "0005_hash_refresh_tokens.sql",
    },
];

/// The bookkeeping table, verbatim from `sqlx-sqlite`'s
/// `Migrate::ensure_migrations_table`. Do not "tidy" the types: they are what
/// makes a database written by one family readable by the other.
const ENSURE_TABLE: &str = "\
CREATE TABLE IF NOT EXISTS _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    success BOOLEAN NOT NULL,
    checksum BLOB NOT NULL,
    execution_time BIGINT NOT NULL
);";

/// Why a migration run stopped.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MigrateError {
    /// The engine refused a statement.
    #[error("migration backend error: {0}")]
    Store(#[from] StoreError),

    /// A migration was applied to this database with different SQL than this
    /// binary ships. Re-running it would produce a schema neither side
    /// describes, so the run stops instead.
    #[error(
        "migration {version} ({description}) was applied with different SQL than this binary \
         ships; the database and the binary disagree about the schema"
    )]
    ChecksumMismatch {
        version: i64,
        description: &'static str,
    },

    /// The database has a migration this binary doesn't know about — almost
    /// always an older binary pointed at a newer database.
    #[error(
        "database has migration {version} applied, which this binary does not ship; \
         it is newer than this build"
    )]
    UnknownApplied { version: i64 },

    /// A previous run recorded a failed migration. sqlx writes the bookkeeping
    /// row inside the same transaction as the migration, so this should be
    /// unreachable — it means the row was written by something else.
    #[error("migration {version} is recorded as failed; the database needs manual repair")]
    Dirty { version: i64 },
}

/// Apply every outstanding migration, in order.
///
/// Idempotent: a fully migrated database is a no-op, whether it was migrated
/// by this runner or by `cheers-sqlx`. Each migration's DDL and its
/// bookkeeping row commit together, so an interrupted run leaves the database
/// on a migration boundary rather than half-way through one.
pub async fn run(conn: &TursoConn) -> Result<(), MigrateError> {
    conn.execute_batch(ENSURE_TABLE).await?;

    let applied = applied_migrations(conn).await?;

    // Guard before mutating anything: report a disagreement about migrations
    // already applied rather than stacking new ones on top of a schema we
    // can't account for.
    for (version, checksum) in &applied {
        match MIGRATIONS.iter().find(|m| m.version == *version) {
            None => return Err(MigrateError::UnknownApplied { version: *version }),
            Some(m) if m.checksum() != *checksum => {
                return Err(MigrateError::ChecksumMismatch {
                    version: m.version,
                    description: m.description,
                })
            }
            Some(_) => {}
        }
    }

    for migration in MIGRATIONS {
        if applied.iter().any(|(v, _)| *v == migration.version) {
            continue;
        }
        apply(conn, migration).await?;
    }
    Ok(())
}

/// `(version, checksum)` for every migration already recorded, ascending.
async fn applied_migrations(conn: &TursoConn) -> Result<Vec<(i64, Vec<u8>)>, MigrateError> {
    // `success = 0` rather than sqlx's `success = false`: SQLite stores the
    // boolean as an integer either way, and the comparison against 0 does not
    // depend on the engine recognising a `false` keyword.
    if let Some(row) = conn
        .query_one(
            "SELECT version FROM _sqlx_migrations WHERE success = 0 ORDER BY version LIMIT 1",
            vec![],
        )
        .await?
    {
        let version: i64 = row
            .get(0)
            .map_err(|e| crate::error::decode_error("version", e))?;
        return Err(MigrateError::Dirty { version });
    }

    let rows = conn
        .query(
            "SELECT version, checksum FROM _sqlx_migrations ORDER BY version",
            vec![],
        )
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let version: i64 = row
            .get(0)
            .map_err(|e| crate::error::decode_error("version", e))?;
        let checksum: Vec<u8> = row
            .get(1)
            .map_err(|e| crate::error::decode_error("checksum", e))?;
        out.push((version, checksum));
    }
    Ok(out)
}

/// Apply one migration: its DDL and its bookkeeping row, atomically.
async fn apply(conn: &TursoConn, migration: &Migration) -> Result<(), MigrateError> {
    let started = std::time::Instant::now();

    conn.transaction(vec![
        Unit::Script(migration.sql.to_owned()),
        // `TRUE` and `-1` are literals in sqlx's own INSERT; keeping them
        // literal keeps the written row identical.
        Unit::stmt(
            "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
             VALUES (?, ?, TRUE, ?, -1)",
            vec![
                migration.version.into(),
                migration.description.into(),
                migration.checksum().into(),
            ],
        ),
    ])
    .await?;

    // Backfill the timing sqlx records for `migrate info`. Outside the
    // transaction, exactly as sqlx does it: losing this value to a crash costs
    // nothing, and paying for it inside the transaction would extend the lock.
    let elapsed = i64::try_from(started.elapsed().as_nanos()).unwrap_or(i64::MAX);
    conn.execute(
        "UPDATE _sqlx_migrations SET execution_time = ? WHERE version = ?",
        vec![elapsed.into(), migration.version.into()],
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_ascending_and_uniquely_versioned() {
        let mut seen = Vec::new();
        for m in MIGRATIONS {
            assert!(
                !seen.contains(&m.version),
                "duplicate migration version {}",
                m.version
            );
            if let Some(prev) = seen.last() {
                assert!(m.version > *prev, "migrations must ascend: {:?}", m.filename);
            }
            seen.push(m.version);
        }
    }

    #[test]
    fn descriptions_follow_sqlx_filename_derivation() {
        // sqlx derives `description` from the filename: everything after the
        // first `_`, with `.sql` trimmed and `_` replaced by a space. Getting
        // this wrong writes a row that differs from sqlx's for the same file.
        for m in MIGRATIONS {
            let (_version, rest) = m.filename.split_once('_').expect("versioned filename");
            let expected = rest.trim_end_matches(".sql").replace('_', " ");
            assert_eq!(m.description, expected, "for {}", m.filename);
        }
    }

    #[test]
    fn checksum_is_sha384_of_the_sql_bytes() {
        // Pin the algorithm itself, not just its use: a swap to SHA-256 would
        // still "work" here but would silently break interop with cheers-sqlx.
        let m = &MIGRATIONS[0];
        assert_eq!(m.checksum().len(), 48, "SHA-384 digests are 48 bytes");
        assert_eq!(m.checksum(), Sha384::digest(m.sql.as_bytes()).to_vec());
    }

    #[tokio::test]
    async fn run_is_idempotent() {
        let conn = TursoConn::open_in_memory().await.unwrap();
        run(&conn).await.unwrap();
        let first = conn
            .query("SELECT version FROM _sqlx_migrations", vec![])
            .await
            .unwrap()
            .len();
        assert_eq!(first, MIGRATIONS.len());

        // Second run applies nothing and disturbs nothing.
        run(&conn).await.unwrap();
        let second = conn
            .query("SELECT version FROM _sqlx_migrations", vec![])
            .await
            .unwrap()
            .len();
        assert_eq!(second, first);
    }

    #[tokio::test]
    async fn run_refuses_a_database_whose_checksum_disagrees() {
        let conn = TursoConn::open_in_memory().await.unwrap();
        run(&conn).await.unwrap();

        // Simulate a binary whose 0002 differs from the one that was applied.
        conn.execute(
            "UPDATE _sqlx_migrations SET checksum = ? WHERE version = 2",
            vec![vec![0u8; 48].into()],
        )
        .await
        .unwrap();

        match run(&conn).await {
            Err(MigrateError::ChecksumMismatch { version: 2, .. }) => {}
            other => panic!("expected ChecksumMismatch for version 2, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn run_refuses_a_database_from_a_newer_binary() {
        let conn = TursoConn::open_in_memory().await.unwrap();
        run(&conn).await.unwrap();
        conn.execute(
            "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
             VALUES (?, ?, TRUE, ?, -1)",
            vec![9_999i64.into(), "from the future".into(), vec![0u8; 48].into()],
        )
        .await
        .unwrap();

        match run(&conn).await {
            Err(MigrateError::UnknownApplied { version: 9_999 }) => {}
            other => panic!("expected UnknownApplied, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_failed_migration_leaves_no_bookkeeping_row() {
        // The atomicity that makes an interrupted run safe: if the DDL fails,
        // the version must not be recorded, or the next run would skip it.
        let conn = TursoConn::open_in_memory().await.unwrap();
        conn.execute_batch(ENSURE_TABLE).await.unwrap();

        let bad = Migration {
            version: 1,
            description: "bad",
            sql: "CREATE TABLE ok (a INTEGER); CREATE TABLE ok (a INTEGER);",
            filename: "0001_bad.sql",
        };
        assert!(apply(&conn, &bad).await.is_err());

        let rows = conn
            .query("SELECT version FROM _sqlx_migrations", vec![])
            .await
            .unwrap();
        assert!(rows.is_empty(), "a failed migration must not be recorded");

        // And the DDL itself rolled back: the engine honours CREATE TABLE
        // inside a transaction. If it did not, `ok` would survive the failed
        // migration and the retry would fail forever on "table already
        // exists" — a half-applied migration that no longer knows it is half
        // applied.
        let tables = conn
            .query(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'ok'",
                vec![],
            )
            .await
            .unwrap();
        assert!(
            tables.is_empty(),
            "a failed migration must roll back its DDL, not just its bookkeeping"
        );
    }
}
