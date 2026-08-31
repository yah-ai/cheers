//! # cheers-turso — the cell-hosted account store
//!
//! Implementations of cheers's persistence traits over the **in-process,
//! rust-native Turso engine** (`turso` 0.6.1 — the same engine roadcase cells
//! and turso-backup run).
//!
//! ## Why this is a second store family, not a config flag
//!
//! `cheers-sqlx` builds every store on `sqlx::SqlitePool`. `sqlx` has no
//! driver for anything in the Turso lineage and is unlikely to grow one, so
//! "point cheers-sqlx at Turso" was never an option — the driver boundary is
//! below the store impls, not above them. This crate reimplements the same
//! seven stores against the engine's own async API.
//!
//! The two families deliberately share everything a database can observe:
//!
//! | | `cheers-sqlx` (`sqlite`) | `cheers-turso` |
//! |---|---|---|
//! | Schema | `migrations/sqlite/*.sql` | byte-identical copy, drift-guarded |
//! | Migration bookkeeping | `_sqlx_migrations` | `_sqlx_migrations`, same checksums |
//! | Row ids | UUIDv4 hyphenated | UUIDv4 hyphenated |
//! | Provider vocabulary | `oidc_google`, … | same strings |
//! | Store contract | shared scenario suite | **the same suite** |
//!
//! That last row is the point. `cheers_test_support::store_scenarios` is one
//! set of contract tests, and both families run it. "The turso family behaves
//! like the sqlx family" is a checked property, not a claim.
//!
//! ## Interchangeability, and why `noisetable-account` starts here
//!
//! The original plan was for `noisetable-account` to run on vanilla sqlite +
//! litestream and flip to this crate later. That plan is retired: there are no
//! noisetable accounts and no noisetable site yet, so the litestream path
//! would have been built solely to be deleted — and the two are a package
//! deal anyway, since the engine's exclusive lock and WAL auto-checkpointing
//! make a litestream sidecar impossible rather than merely worse. Durability
//! is `turso-backup`'s WAL→object-store stream tier, which unlike litestream
//! carries hard fencing epochs (W245) instead of a staleness bound.
//!
//! `noisetable-account` therefore starts on this crate directly. The
//! interchangeability below is no longer a migration plan — it is the **exit
//! route**: if the engine doesn't live up to the promise, stop the binary and
//! start a `cheers-sqlx` one on the same file. No schema change, no data
//! migration, no dual-write window; the file cannot tell which family last
//! wrote it, and each family's migrator sees the other's work as already
//! applied. `tests/flip.rs` keeps that route open in both directions,
//! including the partially-migrated case.
//!
//! Keeping the exit route open is the reason the schema, ids, provider
//! vocabulary and migration bookkeeping in this crate must never drift from
//! `cheers-sqlx` — an unreviewed divergence quietly spends the insurance that
//! made adopting a young engine reasonable.
//!
//! ## Engine constraints this crate is built around
//!
//! Verified against `turso` 0.6.1 while writing this crate, not inherited on
//! faith — see [`conn`] and `tests/turso.rs`:
//!
//! - **One opener per file, process-wide.** The engine takes an exclusive lock
//!   on `<path>` *and* `<path>-wal`. A second OS process is refused at open
//!   time. This is a feature under one-cell-per-database and fatal to anything
//!   sidecar-shaped.
//! - **The lock belongs to the `Database`, not the `Connection`.** Dropping the
//!   connection does not release it. [`TursoConn`] holds the database alive
//!   deliberately.
//! - **No external WAL tailing.** The WAL auto-checkpoints, so litestream-style
//!   replication does not apply. Replication is the WAL→object-store streamer
//!   family (yubaba-tenant-streamer / turso-backup), which is in-process with
//!   the engine rather than beside it.
//!
//! ## Usage
//!
//! ```no_run
//! use std::sync::Arc;
//! use cheers_turso::{migrate, AccountStores, TursoConn};
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let conn = Arc::new(TursoConn::open("/var/lib/noisetable/accounts.db").await?);
//! migrate::run(&conn).await?;
//! let stores = AccountStores::new(conn);
//!
//! let users = stores.users();      // impl cheers_server::UserStore
//! let refresh = stores.refresh();  // impl cheers_server::RefreshStore
//! # Ok(())
//! # }
//! ```

pub mod conn;
pub mod error;
pub mod migrate;

mod util;

pub mod audit_store;
pub mod ownership_store;
pub mod passkey_store;
pub mod refresh_store;
pub mod revocation;
pub mod service_principal_store;
pub mod user_store;

pub use conn::{ReadOnlyConn, TursoConn, Unit};
pub use error::map_turso_error;
pub use migrate::{MigrateError, Migration, MIGRATIONS};

pub use audit_store::TursoAuditStore;
pub use ownership_store::TursoOwnershipStore;
pub use passkey_store::TursoPasskeyCredentialStore;
pub use refresh_store::TursoRefreshStore;
pub use revocation::{TursoRevocationReader, TursoRevocationStore};
pub use service_principal_store::TursoServicePrincipalStore;
pub use user_store::TursoUserStore;

use std::sync::Arc;

/// Every account store, over one engine handle.
///
/// The stores are cheap value types over a shared `Arc<TursoConn>`, so this is
/// a convenience for assembling them, not a resource pool — construct as many
/// as you like. It exists because the alternative at every call site is seven
/// near-identical `::new(conn.clone())` lines, which is exactly the shape
/// where one of them ends up pointed at a different connection.
///
/// Unlike `cheers-sqlx`, the passkey store is not behind a feature flag here:
/// the table is in the schema either way, and gating it would add a build
/// dimension the shared contract suite would then have to be run across.
#[derive(Debug, Clone)]
pub struct AccountStores {
    conn: Arc<TursoConn>,
}

impl AccountStores {
    pub fn new(conn: Arc<TursoConn>) -> Self {
        Self { conn }
    }

    /// The underlying handle, for the migration runner or a raw query.
    pub fn conn(&self) -> &Arc<TursoConn> {
        &self.conn
    }

    pub fn users(&self) -> TursoUserStore {
        TursoUserStore::new(self.conn.clone())
    }

    pub fn refresh(&self) -> TursoRefreshStore {
        TursoRefreshStore::new(self.conn.clone())
    }

    pub fn revocations(&self) -> TursoRevocationStore {
        TursoRevocationStore::new(self.conn.clone())
    }

    pub fn ownership(&self) -> TursoOwnershipStore {
        TursoOwnershipStore::new(self.conn.clone())
    }

    pub fn service_principals(&self) -> TursoServicePrincipalStore {
        TursoServicePrincipalStore::new(self.conn.clone())
    }

    pub fn audit(&self) -> TursoAuditStore {
        TursoAuditStore::new(self.conn.clone())
    }

    pub fn passkeys(&self) -> TursoPasskeyCredentialStore {
        TursoPasskeyCredentialStore::new(self.conn.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_server::store::{PasskeyCredentialStore, RefreshStore, UserStore};
    use cheers_server::{AuditStore, OwnershipStore, RevocationWriter, ServicePrincipalStore};
    use cheers_verify::RevocationReader;

    /// Every store must stay usable behind a trait object — the products wire
    /// them as `Arc<dyn UserStore>` and friends.
    #[test]
    fn stores_are_dyn_compatible() {
        fn _u(_: &dyn UserStore) {}
        fn _r(_: &dyn RefreshStore) {}
        fn _p(_: &dyn PasskeyCredentialStore) {}
        fn _o(_: &dyn OwnershipStore) {}
        fn _s(_: &dyn ServicePrincipalStore) {}
        fn _a(_: &dyn AuditStore) {}
        fn _rw(_: &dyn RevocationWriter) {}
        fn _rr(_: &dyn RevocationReader) {}
    }

    #[tokio::test]
    async fn account_stores_share_one_database() {
        // The bundle must hand out stores over the *same* connection — a user
        // created through one has to be visible to the next.
        let conn = Arc::new(TursoConn::open_in_memory().await.unwrap());
        migrate::run(&conn).await.unwrap();
        let stores = AccountStores::new(conn);

        let user = stores
            .users()
            .create(cheers_server::store::NewUser::new().with_email("a@b.c"))
            .await
            .unwrap();

        stores
            .users()
            .link_provider(
                &user.id,
                &cheers_server::store::ProviderKey::OidcGoogle,
                "sub-1",
            )
            .await
            .unwrap();

        let found = stores
            .users()
            .find_by_provider(&cheers_server::store::ProviderKey::OidcGoogle, "sub-1")
            .await
            .unwrap()
            .expect("user is visible through a second store handle");
        assert_eq!(found.id, user.id);
    }
}
