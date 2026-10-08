//! [`BindingSequenceStore`] over the in-process engine (R732-F5).
//!
//! Schema (migration 0011): `binding_sequences(device_id PRIMARY KEY, seq)`.
//! One upsert advances a device's sequence to
//! [`next_binding_seq`](cheers_server::next_binding_seq) — `max(seq + 1, now)`,
//! or `max(1, now)` for a device's first binding — and returns it. It is one
//! statement under the connection mutex, so two concurrent mints for one
//! device never share a value.

use std::sync::Arc;

use async_trait::async_trait;
use cheers_core::{DeviceId, StoreError};
use cheers_server::BindingSequenceStore;

use crate::conn::TursoConn;
use crate::util::col;

/// The issuer's per-device binding sequences.
pub struct TursoBindingSequenceStore {
    conn: Arc<TursoConn>,
}

impl TursoBindingSequenceStore {
    pub fn new(conn: Arc<TursoConn>) -> Self {
        Self { conn }
    }

    pub fn conn(&self) -> &Arc<TursoConn> {
        &self.conn
    }
}

impl std::fmt::Debug for TursoBindingSequenceStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TursoBindingSequenceStore").finish_non_exhaustive()
    }
}

#[async_trait]
impl BindingSequenceStore for TursoBindingSequenceStore {
    async fn next_binding_seq(&self, device: &DeviceId, now: i64) -> Result<u64, StoreError> {
        // `query`, not `query_one`: it steps the statement to completion, so
        // the write is done before the connection is released.
        let rows = self
            .conn
            .query(
                "INSERT INTO binding_sequences (device_id, seq) VALUES (?, MAX(?, 1))
                 ON CONFLICT (device_id) DO UPDATE
                     SET seq = MAX(binding_sequences.seq + 1, excluded.seq)
                 RETURNING seq",
                vec![device.as_str().into(), now.into()],
            )
            .await?;
        let row = rows
            .first()
            .ok_or_else(|| StoreError::Backend("binding sequence upsert returned no row".into()))?;
        let seq = col::<i64>(row, 0, "seq")?;
        u64::try_from(seq).map_err(|_| StoreError::Backend(format!("negative binding sequence {seq}")))
    }
}
