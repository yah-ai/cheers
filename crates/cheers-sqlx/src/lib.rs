//! # cheers-sqlx — relational-DB store impls for cheers
//!
//! Postgres- and SQLite-backed implementations of cheers's persistence traits.
//! This crate is the **long-lived-data** home: identity, OIDC links, passkey
//! credentials — anything that lives across restarts and wants secondary
//! indexes. The SQL store is also a fine *single-engine* home for refresh
//! chains + the revocation set when a deployment doesn't want a separate KV
//! tier; for production-grade hot-path TTL state, swap in `cheers-redis`.
//!
//! ## What's in here
//!
//! | Trait | Backend | Module |
//! |---|---|---|
//! | [`UserStore`](cheers_server::UserStore) | pg + sqlite | [`user_store`] |
//! | [`PasskeyCredentialStore`](cheers_server::PasskeyCredentialStore) | pg + sqlite (`passkey` feature) | [`passkey_store`] |
//! | [`RefreshStore`](cheers_server::RefreshStore) | pg + sqlite | [`refresh_store`] |
//! | [`RevocationWriter`](cheers_server::RevocationWriter) + [`RevocationReader`](cheers_verify::RevocationReader) | pg + sqlite | [`revocation`] |
//!
//! ## Feature flags
//!
//! - `pg` — compile the Postgres impls (`PgUserStore`, `PgRefreshStore`, …).
//! - `sqlite` — compile the SQLite impls (`SqliteUserStore`, …).
//! - `passkey` — compile the passkey-credential impls (gated separately because
//!   passkey rows are large `JSONB`/`TEXT` blobs not every deployment needs).
//! - `pg-integration` — opt-in test feature: enables the Docker-backed pg
//!   integration tests. Off by default so the crate's plain `cargo test` works
//!   in sandboxed environments without Docker.
//!
//! At least one of `pg` or `sqlite` should be enabled; with neither, the crate
//! exports only the migration runners.
//!
//! ## Migrations
//!
//! Each backend has its own migration tree under `migrations/{pg,sqlite}/` and
//! its own [`Migrator`](sqlx::migrate::Migrator):
//! [`PG_MIGRATIONS`] / [`SQLITE_MIGRATIONS`]. Apply on startup:
//!
//! ```ignore
//! # #[cfg(feature = "pg")]
//! # async fn run(pool: &sqlx::PgPool) -> Result<(), sqlx::migrate::MigrateError> {
//! cheers_sqlx::PG_MIGRATIONS.run(pool).await
//! # }
//! ```
//!
//! ## Why the SQL store also serves TTL data
//!
//! Refresh chains and the revocation kill-list are *short-lived, hot-path*
//! reads — a KV store like redis is the natural fit and ships in
//! `cheers-redis`. The sqlx impls of those traits are here because:
//!
//! 1. Solo-engine dev / first-cut prod deployments don't want a redis box.
//! 2. The same SQL DB that holds identity can emulate the TTL contract with
//!    a `revoked_at` column + a periodic `DELETE … WHERE expires_at < now()`
//!    cron — fine for low/medium load.
//!
//! "Redis is only ever an optimization on top of sqlite/pg if needed" — start
//! on `cheers-sqlx` for everything, peel off to `cheers-redis` once the
//! per-request validation latency or revocation-set fan-out demands it.
//!
//! @yah:ticket(R020-T18, "cheers-sqlx ServicePrincipalStore impl + 0003_service_principals migration")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-05T02:27:14Z)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R020)
//! @yah:next("Add migrations/{pg,sqlite}/0003_service_principals.sql: two tables — service_principals (id PK = 'svc:<x>' string, status, created_at), service_principal_keys (kid PK, principal_id FK, public_key BYTEA/BLOB, status enum-ish text, created_at, retire_at). CHECK constraints: id LIKE 'svc:%', status IN ('active','revoked'), key status IN ('active','retiring'), retire_at NULL iff status=active.")
//! @yah:next("Partial index: ix_spk_principal_active ON service_principal_keys (principal_id) WHERE status = 'active'.")
//! @yah:next("Add cheers-sqlx/src/service_principal_store.rs: PgServicePrincipalStore + SqliteServicePrincipalStore implementing the trait. Match the cheers-sqlx pattern from ownership_store.rs.")
//! @yah:next("Tests in tests/common/: service_principal_lifecycle scenario — provision, rotate, prune; check_constraints reject malformed rows.")
//! @yah:verify("cargo test -p cheers-sqlx --features sqlite passes (new service_principal tests).")
//! @yah:verify("cargo test -p cheers-server (regression: trait + memory impl still pass).")
//! @yah:gotcha("public_key is a 32-byte BYTEA (pg) / BLOB (sqlite). Don't encode it as base64 at the SQL layer — keep raw bytes; only the wire shape (JWKS publication, R020-F11) encodes base64.")
//! @yah:gotcha("Pruning is an UPDATE-then-delete OR a single DELETE: prefer a single DELETE FROM service_principal_keys WHERE status='retiring' AND retire_at<=$1 RETURNING count, idempotent and atomic.")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @yah:handoff("LANDED. migrations/{pg,sqlite}/0003_service_principals.sql adds service_principals (id LIKE 'svc:%', status active|revoked) + service_principal_keys (kid PK, principal_id FK CASCADE, public_key BYTEA/BLOB 32 bytes, status active|retiring, retire_at NULL iff active) with the ix_spk_principal_active partial index and CHECK belts the doc calls for.")
//! @yah:handoff("cheers-sqlx/src/service_principal_store.rs adds PgServicePrincipalStore + SqliteServicePrincipalStore implementing ServicePrincipalStore — mirrors ownership_store.rs structure. Retire is a single UPDATE; prune is a single atomic DELETE … RETURNING count (per the gotcha). Public key bound as raw &[u8].slice both directions (no base64 at the SQL layer, per the gotcha).")
//! @yah:handoff("cheers-server gained pub fn SigningKey::new(...) constructor — needed because the struct is #[non_exhaustive] and external store impls cannot use the struct-expression form. No other cheers-server change.")
//! @yah:handoff("Tests: tests/common/mod.rs gained service_principal_lifecycle, service_principal_rejects_non_service_kind, and service_principal_check_constraint_rejects_bad_status_directly (closure-shaped so each backend supplies its raw bad-row INSERT). sqlite.rs wires all three; pg.rs wires all three behind pg-integration.")
//! @yah:verify("cargo test -p cheers-sqlx --features sqlite — 10/10 pass (3 new service-principal scenarios + 7 existing).")
//! @yah:verify("cargo test -p cheers-core — 61/61 pass.")
//! @yah:verify("cargo test -p cheers-server — all pass (incl. service_principal_signing_key_new round-trip via existing tests).")
//! @yah:verify("cargo test -p cheers-verify — 4/4 pass.")
//! @yah:verify("cargo check --workspace --all-features — clean.")
//! @yah:assumes("libSQL compat for 0001+0002+0003 verified one-shot against ghcr.io/tursodatabase/libsql-server: all CREATE/CHECK/FK CASCADE/partial-index statements apply cleanly; CHECK constraints reject bad rows; ON DELETE CASCADE sweeps signing keys. Standing harness for libSQL is filed as R020-T19.")
//! @yah:assumes("Pg-integration tests added in tests/pg.rs are correct but unverified locally (no Docker test pass against pg in this session). Run cargo test -p cheers-sqlx --features pg-integration to exercise.")

/// Postgres migrations — apply with `PG_MIGRATIONS.run(&pool).await`.
#[cfg(feature = "pg")]
pub static PG_MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/pg");

/// SQLite migrations — apply with `SQLITE_MIGRATIONS.run(&pool).await`.
#[cfg(feature = "sqlite")]
pub static SQLITE_MIGRATIONS: sqlx::migrate::Migrator = sqlx::migrate!("./migrations/sqlite");

mod error;
pub use error::map_sqlx_error;

#[cfg(any(feature = "pg", feature = "sqlite"))]
pub mod user_store;
#[cfg(any(feature = "pg", feature = "sqlite"))]
pub mod refresh_store;
#[cfg(any(feature = "pg", feature = "sqlite"))]
pub mod revocation;
#[cfg(any(feature = "pg", feature = "sqlite"))]
pub mod ownership_store;
#[cfg(any(feature = "pg", feature = "sqlite"))]
pub mod service_principal_store;
#[cfg(any(feature = "pg", feature = "sqlite"))]
pub mod audit_store;
#[cfg(all(feature = "passkey", any(feature = "pg", feature = "sqlite")))]
pub mod passkey_store;

#[cfg(feature = "pg")]
pub use user_store::PgUserStore;
#[cfg(feature = "sqlite")]
pub use user_store::SqliteUserStore;
#[cfg(feature = "pg")]
pub use refresh_store::PgRefreshStore;
#[cfg(feature = "sqlite")]
pub use refresh_store::SqliteRefreshStore;
#[cfg(feature = "pg")]
pub use revocation::PgRevocationStore;
#[cfg(feature = "sqlite")]
pub use revocation::SqliteRevocationStore;
#[cfg(feature = "pg")]
pub use ownership_store::PgOwnershipStore;
#[cfg(feature = "sqlite")]
pub use ownership_store::SqliteOwnershipStore;
#[cfg(feature = "pg")]
pub use service_principal_store::PgServicePrincipalStore;
#[cfg(feature = "sqlite")]
pub use service_principal_store::SqliteServicePrincipalStore;
#[cfg(feature = "pg")]
pub use audit_store::PgAuditStore;
#[cfg(feature = "sqlite")]
pub use audit_store::SqliteAuditStore;
#[cfg(all(feature = "passkey", feature = "pg"))]
pub use passkey_store::PgPasskeyCredentialStore;
#[cfg(all(feature = "passkey", feature = "sqlite"))]
pub use passkey_store::SqlitePasskeyCredentialStore;
