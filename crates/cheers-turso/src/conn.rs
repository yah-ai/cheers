//! The engine handle every store in this crate is built on.
//!
//! [`TursoConn`] owns one in-process Turso database and one connection to it.
//! Two properties of the engine drive the whole shape of this type; both were
//! re-verified against `turso` 0.6.1 while this crate was written (see the
//! `lock_semantics` notes in `tests/turso.rs`).
//!
//! # 1. The lock lives on the `Database`, not the `Connection`
//!
//! The engine takes a **process-wide exclusive lock on `<path>` and
//! `<path>-wal`**. A second OS process is refused at open time — not at first
//! write — with `Locking error: … File is locked by another process`. That is
//! the one-opener-per-cell constraint W179 documents, and it is why there is
//! no `open_read_only`-from-another-process path and no sidecar story: a
//! litestream-style tailer cannot open the file at all.
//!
//! The subtlety that costs a debugging session if you don't know it: dropping
//! the [`Connection`] does **not** release the lock; dropping the
//! [`Database`] does. So [`TursoConn`] holds the `Database` alive for its own
//! lifetime. If it held only the `Connection`, the `Database` temporary would
//! drop at the end of [`TursoConn::open`] and the ownership of the lock would
//! become an accident of refcounting rather than a stated invariant.
//!
//! # 2. One connection, serialized
//!
//! Every operation takes the same [`Mutex`]. That is a deliberate throughput
//! ceiling bought for a correctness guarantee: [`TursoConn::transaction`]
//! issues a bare `BEGIN IMMEDIATE` … `COMMIT` on the connection, so any
//! statement that interleaved from another task would silently join that
//! transaction. Serializing removes the hazard outright.
//!
//! Multiple connections from a single `Database` *are* supported by the engine
//! (they see each other's writes), so this can become a small pool if the
//! account workload ever justifies one — note that `PRAGMA foreign_keys` is
//! per-connection and would have to be re-applied on each. It does not justify
//! one today: an account database serves login and refresh, not a hot read
//! path, and it sits behind one cell by construction.

use std::path::Path;

use cheers_core::StoreError;
use tokio::sync::Mutex;
use turso::{Builder, Connection, Database, Row, Value};

use crate::error::map_turso_error;

/// One unit of work inside a [`TursoConn::transaction`].
///
/// The transaction primitive is deliberately a *fixed list* rather than a
/// borrowed handle: every atomic sequence cheers needs (a migration's DDL plus
/// its bookkeeping row; an audit batch) is known in full before the
/// transaction opens, and none of them branches on an intermediate result.
/// Taking the list by value keeps the primitive dyn-safe and lifetime-free,
/// and keeps the connection mutex held for a bounded, obvious span.
#[derive(Debug, Clone)]
pub enum Unit {
    /// One parameterized statement.
    Stmt {
        sql: String,
        params: Vec<Value>,
    },
    /// A multi-statement script with no parameters — migration DDL.
    Script(String),
}

impl Unit {
    /// Convenience constructor for a parameterized statement.
    pub fn stmt(sql: impl Into<String>, params: Vec<Value>) -> Self {
        Self::Stmt {
            sql: sql.into(),
            params,
        }
    }
}

/// A handle to one in-process Turso database.
///
/// Construct once per process and share it — `Arc<TursoConn>` is what every
/// store in this crate takes. Opening the same path twice in one process is
/// permitted by the engine but pointless here, and opening it from a second
/// process is refused outright; see the module docs.
pub struct TursoConn {
    /// Load-bearing: the exclusive lock on `.db` + `.db-wal` is held for as
    /// long as this value lives. Never replace this with `_: ()` "because it
    /// is unused" — it is the lock.
    _db: Database,
    conn: Mutex<Connection>,
    path: String,
}

impl std::fmt::Debug for TursoConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TursoConn")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl TursoConn {
    /// Open (or create) the database at `path` and take the engine's
    /// process-wide exclusive lock on it.
    ///
    /// Fails with [`StoreError::Backend`] if another process already holds the
    /// file. That is not a transient condition to retry — it means two openers
    /// were configured where the model allows one.
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_string_lossy().into_owned();
        Self::open_str(&path).await
    }

    /// Open a private in-memory database.
    ///
    /// Each call gets its own independent database, and no file lock is taken —
    /// which is what makes the test suite runnable in parallel.
    pub async fn open_in_memory() -> Result<Self, StoreError> {
        Self::open_str(":memory:").await
    }

    async fn open_str(path: &str) -> Result<Self, StoreError> {
        let db = Builder::new_local(path)
            .build()
            .await
            .map_err(map_turso_error)?;
        let conn = db.connect().map_err(map_turso_error)?;
        // Foreign-key enforcement is off by default, exactly as in vanilla
        // SQLite, and the schema leans on `ON DELETE CASCADE` (deleting a user
        // must sweep their oauth_identities / refresh_tokens / passkeys). This
        // pragma is per-connection, so it belongs here rather than in a
        // migration.
        conn.execute("PRAGMA foreign_keys = ON", ())
            .await
            .map_err(map_turso_error)?;
        Ok(Self {
            _db: db,
            conn: Mutex::new(conn),
            path: path.to_owned(),
        })
    }

    /// The path this handle was opened with (`:memory:` for in-memory).
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Run one statement, returning the number of rows it changed.
    ///
    /// The count is the load-bearing half of several store contracts — the
    /// refresh rotator's consume gate and every `NotFound`-on-zero-rows path
    /// read it — so callers should treat it as a result, not telemetry.
    pub async fn execute(&self, sql: &str, params: Vec<Value>) -> Result<u64, StoreError> {
        let conn = self.conn.lock().await;
        conn.execute(sql, params).await.map_err(map_turso_error)
    }

    /// Run a multi-statement script with no parameters. Not atomic — use
    /// [`transaction`](Self::transaction) when it needs to be.
    pub async fn execute_batch(&self, sql: &str) -> Result<(), StoreError> {
        let conn = self.conn.lock().await;
        conn.execute_batch(sql).await.map_err(map_turso_error)
    }

    /// Run one query and collect every row.
    ///
    /// Collecting is safe here because every query in this crate is bounded:
    /// by a primary key, by a user's device count, or by an explicit `LIMIT`.
    /// Streaming would mean holding the connection mutex across the caller's
    /// row processing, which is a worse trade.
    pub async fn query(&self, sql: &str, params: Vec<Value>) -> Result<Vec<Row>, StoreError> {
        let conn = self.conn.lock().await;
        let mut rows = conn.query(sql, params).await.map_err(map_turso_error)?;
        let mut out = Vec::new();
        while let Some(row) = rows.next().await.map_err(map_turso_error)? {
            out.push(row);
        }
        Ok(out)
    }

    /// Run one query and take the first row, if any.
    pub async fn query_one(&self, sql: &str, params: Vec<Value>) -> Result<Option<Row>, StoreError> {
        let conn = self.conn.lock().await;
        let mut rows = conn.query(sql, params).await.map_err(map_turso_error)?;
        rows.next().await.map_err(map_turso_error)
    }

    /// Run `units` inside a single transaction. All of them commit, or none do.
    ///
    /// `BEGIN IMMEDIATE` rather than a bare `BEGIN`: the write lock is taken up
    /// front, so a transaction that is going to conflict fails at the start
    /// instead of at `COMMIT` with its work already done.
    ///
    /// On any failure the transaction is rolled back before the error is
    /// returned. If the rollback *itself* fails the original error still wins —
    /// it is the one that describes what the caller did.
    pub async fn transaction(&self, units: Vec<Unit>) -> Result<(), StoreError> {
        if units.is_empty() {
            return Ok(());
        }
        let conn = self.conn.lock().await;
        conn.execute("BEGIN IMMEDIATE", ())
            .await
            .map_err(map_turso_error)?;

        let mut result = Ok(());
        for unit in units {
            let step = match unit {
                Unit::Stmt { sql, params } => conn.execute(&sql, params).await.map(|_| ()),
                Unit::Script(sql) => conn.execute_batch(&sql).await,
            };
            if let Err(e) = step {
                result = Err(map_turso_error(e));
                break;
            }
        }

        match result {
            Ok(()) => conn.execute("COMMIT", ()).await.map_err(map_turso_error).map(|_| ()),
            Err(e) => {
                if let Err(rollback_err) = conn.execute("ROLLBACK", ()).await {
                    // The caller gets the error that explains their request;
                    // the rollback failure is an operational fact for the log.
                    tracing::error!(error = %rollback_err, "rollback failed after transaction error");
                }
                Err(e)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Read-only capability handle
// ---------------------------------------------------------------------------

/// A handle that can read the account database and structurally cannot write it.
///
/// This is the in-process half of roadcase's two-gate read-only pattern.
/// Roadcase's other gate — opening the file itself with
/// `OpenFlags::ReadOnly` — is **not reachable through the `turso` 0.6.1
/// wrapper**: `Builder` exposes no flags, and `TursoDatabaseConfig` has no
/// read-only field, so that gate needs `turso_core` directly. Equally, it
/// would have nothing to open: the exclusive lock means a read-only *second*
/// opener of the same file cannot exist in the first place.
///
/// So the capability this type actually confers is in-process confinement:
/// hand a component a `ReadOnlyConn` and it cannot mutate the account
/// database, no matter what SQL it composes. The check is on the statement's
/// leading keyword — the same thing `Statement::is_readonly()` reports, done at
/// the layer where it is available.
#[derive(Debug, Clone)]
pub struct ReadOnlyConn {
    inner: std::sync::Arc<TursoConn>,
}

impl ReadOnlyConn {
    /// Narrow a read-write handle to a read-only one. There is deliberately no
    /// way back — widening is done by holding onto the original `Arc`.
    pub fn new(inner: std::sync::Arc<TursoConn>) -> Self {
        Self { inner }
    }

    /// Run a read-only query. A statement that is not a read is refused before
    /// it reaches the engine.
    pub async fn query(&self, sql: &str, params: Vec<Value>) -> Result<Vec<Row>, StoreError> {
        require_readonly(sql)?;
        self.inner.query(sql, params).await
    }

    /// Run a read-only query and take the first row, if any.
    pub async fn query_one(&self, sql: &str, params: Vec<Value>) -> Result<Option<Row>, StoreError> {
        require_readonly(sql)?;
        self.inner.query_one(sql, params).await
    }
}

/// Reject anything that isn't a read.
///
/// Allow-list, not deny-list: an unrecognized leading keyword is refused. A
/// deny-list would have to enumerate every mutating verb the engine grows,
/// and would fail open on the one it hadn't heard of yet.
fn require_readonly(sql: &str) -> Result<(), StoreError> {
    let verb = sql
        .trim_start()
        .split(|c: char| c.is_whitespace() || c == '(')
        .find(|s| !s.is_empty())
        .unwrap_or_default()
        .to_ascii_uppercase();
    if matches!(verb.as_str(), "SELECT" | "WITH" | "EXPLAIN") {
        return Ok(());
    }
    Err(StoreError::Backend(format!(
        "read-only handle refused a `{verb}` statement"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readonly_gate_admits_reads() {
        for sql in [
            "SELECT 1",
            "  select jti from revocations where jti = ?",
            "WITH x AS (SELECT 1) SELECT * FROM x",
            "EXPLAIN QUERY PLAN SELECT 1",
            "(SELECT 1)",
        ] {
            assert!(require_readonly(sql).is_ok(), "should admit: {sql}");
        }
    }

    #[test]
    fn readonly_gate_refuses_writes_and_ddl() {
        for sql in [
            "INSERT INTO users (user_id) VALUES (?)",
            "update refresh_tokens set revoked = 1",
            "DELETE FROM revocations",
            "DROP TABLE users",
            "CREATE TABLE t (a)",
            "PRAGMA foreign_keys = OFF",
            "BEGIN",
            "VACUUM",
            "REPLACE INTO users VALUES (?)",
            "",
        ] {
            assert!(require_readonly(sql).is_err(), "should refuse: {sql}");
        }
    }

    #[tokio::test]
    async fn readonly_conn_refuses_a_write_against_a_live_database() {
        let conn = std::sync::Arc::new(TursoConn::open_in_memory().await.unwrap());
        conn.execute_batch("CREATE TABLE t (a INTEGER);").await.unwrap();
        let ro = ReadOnlyConn::new(conn.clone());

        // Reads work.
        assert!(ro.query("SELECT a FROM t", vec![]).await.is_ok());

        // Writes are refused at the gate, and the table really is untouched.
        assert!(ro.query("INSERT INTO t (a) VALUES (1)", vec![]).await.is_err());
        let rows = conn.query("SELECT a FROM t", vec![]).await.unwrap();
        assert!(rows.is_empty(), "the refused write must not have landed");
    }

    #[tokio::test]
    async fn transaction_is_all_or_nothing() {
        let conn = TursoConn::open_in_memory().await.unwrap();
        conn.execute_batch("CREATE TABLE t (k TEXT PRIMARY KEY);")
            .await
            .unwrap();

        // A batch whose last statement violates the primary key must leave the
        // table exactly as it found it — this is the property the audit store's
        // atomic-ingest contract rests on.
        let err = conn
            .transaction(vec![
                Unit::stmt("INSERT INTO t (k) VALUES (?)", vec!["a".into()]),
                Unit::stmt("INSERT INTO t (k) VALUES (?)", vec!["b".into()]),
                Unit::stmt("INSERT INTO t (k) VALUES (?)", vec!["a".into()]),
            ])
            .await
            .unwrap_err();
        assert!(matches!(err, StoreError::Conflict), "got {err:?}");

        let rows = conn.query("SELECT k FROM t", vec![]).await.unwrap();
        assert!(rows.is_empty(), "a failed transaction must not commit rows");

        // And the connection is still usable afterwards — the rollback left no
        // dangling transaction behind.
        conn.execute("INSERT INTO t (k) VALUES (?)", vec!["c".into()])
            .await
            .unwrap();
        assert_eq!(conn.query("SELECT k FROM t", vec![]).await.unwrap().len(), 1);
    }
}
