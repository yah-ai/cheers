//! Small shared helpers: id minting, the clock, parameter and column plumbing.

use cheers_core::StoreError;
use turso::{Row, Value};

use crate::error::decode_error;

/// Mint a fresh opaque row id — UUIDv4 as a hyphenated string.
///
/// Identical in shape to `cheers-sqlx`'s `mint_user_id` / `mint_row_id`, and
/// for the same reason: the load-bearing property is "crypto-random 128 bits",
/// and matching the encoding means rows written by either store family are
/// indistinguishable after the noisetable-account flip.
pub(crate) fn mint_id() -> String {
    // Avoid a direct `uuid` dependency — 16 random bytes with the v4 version
    // and variant bits forced, in the canonical 8-4-4-4-12 hex layout.
    let mut buf = [0u8; 16];
    getrandom::fill(&mut buf).expect("OS CSPRNG must be available");
    buf[6] = (buf[6] & 0x0f) | 0x40;
    buf[8] = (buf[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        buf[0], buf[1], buf[2], buf[3],
        buf[4], buf[5],
        buf[6], buf[7],
        buf[8], buf[9],
        buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
    )
}

/// Current unix-seconds clock, for the `created_at` / `linked_at` columns the
/// store fills in itself. Methods that take a `now: i64` from the caller use
/// that instead — the caller's clock is the authority wherever the trait
/// offers one.
pub(crate) fn now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Bind an optional string, mapping `None` to SQL `NULL`.
///
/// Without this the natural `Option<String>::into()` would be reached for and
/// would not compile; writing `Value::Null` inline at every call site is where
/// a `Some("")`-for-`None` bug creeps in.
pub(crate) fn opt_text(v: Option<&str>) -> Value {
    match v {
        Some(s) => Value::Text(s.to_owned()),
        None => Value::Null,
    }
}

/// Bind an optional integer, mapping `None` to SQL `NULL`.
pub(crate) fn opt_int(v: Option<i64>) -> Value {
    match v {
        Some(i) => Value::Integer(i),
        None => Value::Null,
    }
}

/// Read column `idx` out of `row`, naming it if the decode fails.
///
/// Every column this crate reads was named in the query's own `SELECT` list,
/// so a decode failure is a schema/data-integrity problem rather than a normal
/// miss — it surfaces as [`StoreError::Backend`] with the column name, never
/// as a silent default.
pub(crate) fn col<T>(row: &Row, idx: usize, column: &'static str) -> Result<T, StoreError>
where
    T: turso::core::types::FromValue,
{
    row.get::<T>(idx).map_err(|e| decode_error(column, e))
}

/// Read an INTEGER column as a bool, SQLite-style: any non-zero value is true.
///
/// The schema stores `consumed` / `revoked` as `INTEGER NOT NULL DEFAULT 0`,
/// and rows written by `cheers-sqlx` bind Rust bools, which land as 0/1. Going
/// through `i64` rather than asking the engine for a `bool` keeps both
/// spellings readable.
pub(crate) fn col_bool(row: &Row, idx: usize, column: &'static str) -> Result<bool, StoreError> {
    Ok(col::<i64>(row, idx, column)? != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_ids_are_uuid_v4_shaped_and_distinct() {
        let a = mint_id();
        let b = mint_id();
        assert_ne!(a, b);
        assert_eq!(a.len(), 36);
        let parts: Vec<&str> = a.split('-').collect();
        assert_eq!(
            parts.iter().map(|p| p.len()).collect::<Vec<_>>(),
            vec![8, 4, 4, 4, 12]
        );
        // Version nibble and variant bits — the two things that make it a v4.
        assert_eq!(&parts[2][0..1], "4");
        assert!(matches!(&parts[3][0..1], "8" | "9" | "a" | "b"));
        assert!(a.chars().all(|c| c.is_ascii_hexdigit() || c == '-'));
    }

    #[test]
    fn optional_binders_distinguish_none_from_empty() {
        assert!(matches!(opt_text(None), Value::Null));
        assert!(matches!(opt_text(Some("")), Value::Text(s) if s.is_empty()));
        assert!(matches!(opt_int(None), Value::Null));
        assert!(matches!(opt_int(Some(0)), Value::Integer(0)));
    }
}
