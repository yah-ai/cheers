//! Map `sqlx::Error` into [`cheers_core::StoreError`].
//!
//! Three buckets:
//! - `RowNotFound` → [`StoreError::NotFound`]
//! - UNIQUE/PK violation → [`StoreError::Conflict`]
//! - Everything else → [`StoreError::Backend`] with a short message
//!
//! Conflict detection is backend-specific (Postgres `23505`, SQLite
//! `UNIQUE constraint failed`); we pattern-match both shapes so the same
//! mapper covers pg + sqlite.

use cheers_core::StoreError;
use sqlx::Error as SqlxError;

/// Translate a `sqlx::Error` into our typed [`StoreError`].
pub fn map_sqlx_error(err: SqlxError) -> StoreError {
    match err {
        SqlxError::RowNotFound => StoreError::NotFound,
        SqlxError::Database(db_err) if is_unique_violation(db_err.as_ref()) => StoreError::Conflict,
        other => StoreError::Backend(other.to_string()),
    }
}

fn is_unique_violation(db_err: &dyn sqlx::error::DatabaseError) -> bool {
    // Postgres uses SQLSTATE 23505 for unique_violation. SQLite has no
    // SQLSTATE; we sniff the message instead.
    if let Some(code) = db_err.code() {
        if code == "23505" {
            return true;
        }
    }
    let msg = db_err.message();
    msg.contains("UNIQUE constraint failed") || msg.contains("PRIMARY KEY constraint failed")
}
