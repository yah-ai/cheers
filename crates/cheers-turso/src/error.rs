//! Map [`turso::Error`] into [`cheers_core::StoreError`].
//!
//! Same three buckets `cheers-sqlx`'s mapper uses, so the two store families
//! are indistinguishable to callers:
//!
//! - UNIQUE / PRIMARY KEY violation → [`StoreError::Conflict`]
//! - everything else → [`StoreError::Backend`] with a generic opaque message
//!   (the raw engine error is logged server-side, never handed to the caller —
//!   it can carry SQL fragments, table names, or filesystem paths)
//!
//! There is no `RowNotFound` bucket: the engine reports "no rows" by yielding
//! `None` from the cursor, not by erroring, so `NotFound` is synthesized by
//! the individual stores from a zero row count — exactly as the sqlx impls do
//! for `rows_affected() == 0`.
//!
//! # Why the message is sniffed
//!
//! The engine collapses every constraint failure into one variant,
//! [`turso::Error::Constraint`], whose payload is the SQLite-compatible
//! message: `UNIQUE constraint failed: users.email (19)` /
//! `CHECK constraint failed: status IN ('active', 'revoked') (19)`. Only the
//! uniqueness family is a [`StoreError::Conflict`] — a CHECK failure means the
//! caller tried to write a row the schema forbids, which is a bug on the write
//! path, not a losable race, and it maps to `Backend` (matching
//! `cheers_sqlx::map_sqlx_error`, whose `is_unique_violation` is likewise
//! false for CHECK).

use cheers_core::StoreError;

/// Translate a [`turso::Error`] into our typed [`StoreError`].
pub fn map_turso_error(err: turso::Error) -> StoreError {
    if let turso::Error::Constraint(msg) = &err {
        if is_unique_violation(msg) {
            return StoreError::Conflict;
        }
    }
    // Don't surface the raw engine error to the caller — it can leak SQL
    // fragments, table/column names, or the database path. Log the full error
    // server-side and hand back an opaque message.
    tracing::debug!(error = %err, "turso backend error");
    StoreError::Backend("database error".to_owned())
}

/// The engine emits SQLite's own constraint wording, so the same two needles
/// `cheers-sqlx` looks for on the SQLite side apply verbatim.
fn is_unique_violation(msg: &str) -> bool {
    msg.contains("UNIQUE constraint failed") || msg.contains("PRIMARY KEY constraint failed")
}

/// A decode failure on a column we just selected is a data-integrity problem,
/// not a normal miss — surface it named rather than silently defaulting.
pub(crate) fn decode_error(column: &str, err: turso::Error) -> StoreError {
    tracing::debug!(error = %err, column, "turso column decode error");
    StoreError::Backend(format!("could not decode column `{column}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_and_primary_key_violations_are_conflicts() {
        assert!(matches!(
            map_turso_error(turso::Error::Constraint(
                "UNIQUE constraint failed: users.email (19)".into()
            )),
            StoreError::Conflict
        ));
        assert!(matches!(
            map_turso_error(turso::Error::Constraint(
                "PRIMARY KEY constraint failed: users.user_id (19)".into()
            )),
            StoreError::Conflict
        ));
    }

    #[test]
    fn check_violations_are_backend_not_conflict() {
        // A CHECK failure is a forbidden-shape write, not a lost race. The
        // ownership / service-principal stores rely on this: their scenarios
        // assert a bad row does NOT come back as Conflict.
        assert!(matches!(
            map_turso_error(turso::Error::Constraint(
                "CHECK constraint failed: granted_by LIKE 'svc:%' (19)".into()
            )),
            StoreError::Backend(_)
        ));
    }

    #[test]
    fn other_errors_are_opaque() {
        // No SQL fragment, table name, or path may reach the caller.
        let mapped = map_turso_error(turso::Error::Error(
            "near \"INSRT\": syntax error in /var/secrets/accounts.db".into(),
        ));
        match mapped {
            StoreError::Backend(msg) => {
                assert_eq!(msg, "database error");
                assert!(!msg.contains("INSRT"));
                assert!(!msg.contains("/var/secrets"));
            }
            other => panic!("expected Backend, got {other:?}"),
        }
    }
}
