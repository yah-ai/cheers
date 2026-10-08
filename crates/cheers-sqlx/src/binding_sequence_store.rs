//! [`BindingSequenceStore`](cheers_server::BindingSequenceStore) over `sqlx`
//! (R732-F5).
//!
//! Schema (migration 0011): `binding_sequences(device_id PRIMARY KEY, seq)`.
//! One upsert advances a device's sequence to
//! [`next_binding_seq`](cheers_server::next_binding_seq) — `max(seq + 1, now)`,
//! or `max(1, now)` for a device's first binding — and returns it, so two
//! concurrent mints for one device never share a value.

#[cfg(feature = "pg")]
pub use pg::PgBindingSequenceStore;
#[cfg(feature = "sqlite")]
pub use sqlite::SqliteBindingSequenceStore;

#[cfg(any(feature = "pg", feature = "sqlite"))]
fn seq_from_sql(seq: i64) -> Result<u64, cheers_core::StoreError> {
    u64::try_from(seq).map_err(|_| cheers_core::StoreError::Backend(format!("negative binding sequence {seq}")))
}

#[cfg(feature = "pg")]
mod pg {
    use async_trait::async_trait;
    use cheers_core::{DeviceId, StoreError};
    use cheers_server::BindingSequenceStore;
    use sqlx::{PgPool, Row};

    use crate::error::map_sqlx_error;

    /// Binding sequences over Postgres.
    pub struct PgBindingSequenceStore {
        pool: PgPool,
    }

    impl PgBindingSequenceStore {
        pub fn new(pool: PgPool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &PgPool {
            &self.pool
        }
    }

    #[async_trait]
    impl BindingSequenceStore for PgBindingSequenceStore {
        async fn next_binding_seq(&self, device: &DeviceId, now: i64) -> Result<u64, StoreError> {
            let row = sqlx::query(
                "INSERT INTO binding_sequences (device_id, seq) VALUES ($1, GREATEST($2, 1))
                 ON CONFLICT (device_id) DO UPDATE
                     SET seq = GREATEST(binding_sequences.seq + 1, EXCLUDED.seq)
                 RETURNING seq",
            )
            .bind(device.as_str())
            .bind(now)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            super::seq_from_sql(row.try_get::<i64, _>(0).map_err(map_sqlx_error)?)
        }
    }
}

#[cfg(feature = "sqlite")]
mod sqlite {
    use async_trait::async_trait;
    use cheers_core::{DeviceId, StoreError};
    use cheers_server::BindingSequenceStore;
    use sqlx::{Row, SqlitePool};

    use crate::error::map_sqlx_error;

    /// Binding sequences over SQLite.
    pub struct SqliteBindingSequenceStore {
        pool: SqlitePool,
    }

    impl SqliteBindingSequenceStore {
        pub fn new(pool: SqlitePool) -> Self {
            Self { pool }
        }

        pub fn pool(&self) -> &SqlitePool {
            &self.pool
        }
    }

    #[async_trait]
    impl BindingSequenceStore for SqliteBindingSequenceStore {
        async fn next_binding_seq(&self, device: &DeviceId, now: i64) -> Result<u64, StoreError> {
            let row = sqlx::query(
                "INSERT INTO binding_sequences (device_id, seq) VALUES (?, MAX(?, 1))
                 ON CONFLICT (device_id) DO UPDATE
                     SET seq = MAX(binding_sequences.seq + 1, excluded.seq)
                 RETURNING seq",
            )
            .bind(device.as_str())
            .bind(now)
            .fetch_one(&self.pool)
            .await
            .map_err(map_sqlx_error)?;
            super::seq_from_sql(row.try_get::<i64, _>(0).map_err(map_sqlx_error)?)
        }
    }
}
