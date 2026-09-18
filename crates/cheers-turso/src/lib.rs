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
//!
//! @yah:relay(R727, "Persistent single-use magic-link jti storage: a UsedJtiStore impl that survives process restart")
//! @yah:at(2026-09-11T20:49:54Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:next("Umbrella for the persistent UsedJtiStore work. The defect, the layering question, the ordering constraint that must not break, and the acceptance test are all on the child bug. Downstream consumer: noisetable camp ticket R131-B26.")
//!
//! @yah:ticket(R727-B1, "Magic-link jti burn is in-process only: MemoryUsedJtiStore is the sole UsedJtiStore impl, so a restart makes an already-consumed link redeemable for the rest of its TTL")
//! @yah:status(review)
//! @yah:at(2026-09-11T20:49:57Z)
//! @yah:assignee(agent:bundle-anthropic-miravel)
//! @yah:parent(R727)
//! @yah:severity(high)
//! @yah:next("THE DEFECT. UsedJtiStore (crates/cheers/src/email/magic_link.rs:284, `#[async_trait] pub trait UsedJtiStore: Send + Sync`, single method `async fn try_mark_used(&self, jti: &str, expires_at: i64) -> Result<bool, String>`) has exactly ONE impl in the whole cheers workspace: MemoryUsedJtiStore, a `Mutex<HashMap<String, i64>>` declared at magic_link.rs:295 with its impl at :321. Its own doc comment states the limit - \"For tests, dev, and single-replica deployments. Production multi-replica deployments want a shared backend (Redis, Postgres, ...)\". There is no persistent impl to reach for, so every production consumer of the magic-link flow is on the in-memory one by default, and process death forgets which links were redeemed. A consumed magic-link URL is therefore redeemable a second time for the remainder of its TTL.")
//! @yah:next("THE STORAGE SHAPE: (jti, expires_at), PRUNED ON EXPIRY. The trait already hands the impl `expires_at` for exactly this reason - the trait doc at magic_link.rs:277-282 says implementors should hold each jti until at least expires_at, after which the entry can be GC'd because the codec's own expiry check rejects any token whose record is missing. MemoryUsedJtiStore already models it: `gc(&self, now)` retains only entries with `exp > now`. A persistent impl MUST prune, or the table grows without bound for the life of the deployment - this is a row per magic link ever requested, and every unclicked link is its own jti (MagicLinkCodec::mint allocates a fresh random jti and touches no prior state, so requesting a new link does not invalidate outstanding ones).")
//! @yah:next("WHERE IT LIVES, AND THE ONE LAYERING DECISION TO MAKE FIRST. cheers-turso is the natural home - it already carries seven store impls over the in-process rust-native turso engine (user_store / refresh_store / passkey_store / ownership_store / audit_store / service_principal_store / revocation, per lib.rs:88-100), plus migrate.rs for the shared schema bookkeeping, and it is the substrate noisetable-account already runs on. BUT: UsedJtiStore is declared in the top-level `cheers` crate (email/magic_link.rs), while cheers-turso's Cargo.toml depends only on cheers-core, cheers-server and cheers-verify - NOT on `cheers`. Two ways out, both open (there is no cycle either way: `cheers` itself depends only on cheers-core + optional mshr): (a) add a `cheers` dependency to cheers-turso, or (b) move UsedJtiStore down into cheers-core alongside CredentialStore (cheers-core/src/store.rs:59) and re-export it from cheers::email::magic_link so existing paths keep resolving. (b) is the structurally consistent one - every other store trait these families implement is declared below them, not above - and it is cheap on a pre-1.0 crate. Decide this before writing the impl; it determines whether cheers-sqlx gets a parallel impl for free.")
//! @yah:next("Tier: Cleric - a small amount of code on a live public auth route, where the ordering and the error-mapping constraints below matter more than the volume. Judgement, not volume.")
//! @yah:gotcha("DO NOT BREAK THE VERIFY-BEFORE-BURN ORDERING. MagicLinkProvider::consume (crates/cheers/src/email/magic_link.rs:376-390) calls `self.codec.verify_at(token, now)?` FIRST and only then `self.used.try_mark_used(&claims.jti, claims.expires_at)`. That order is what stops an attacker pre-burning a legitimate jti by submitting stale or forged tokens. It is pinned by the test `provider_consume_expired_token_does_not_burn_jti` in the same file at line 561, which asserts the error is `MagicLinkError::Codec(CodecError::Expired)` and that no replay-burn happened. Any reshuffle of consume() while wiring a persistent store - including moving the store call earlier to batch a round trip - must keep that test green: `cargo test -p cheers provider_consume_expired_token_does_not_burn_jti`.")
//! @yah:gotcha("THE REFUSAL MUST REUSE THE EXISTING `already_used` CODE - DO NOT ADD A NEW CLIENT-VISIBLE ONE. A replay already maps to MagicLinkError::AlreadyUsed -> the client code `already_used` at crates/cheers-axum/src/error.rs:218. A persistent store changes WHEN that fires, never WHAT the client sees. Adding a per-cause code (`replayed_after_restart`, `expired`, `bad_signature`, ...) on this route is the vulnerability noisetable R131-B24 exists to prevent: per-cause client codes on an unauthenticated auth route are an account-enumeration oracle. That ticket verified the current collapse is deliberate and safe - all seven CodecError variants (cheers-core/src/codec.rs:105-128) Display distinctly, so the cause is already preserved server-side in the `cheers-axum route error` warn line at error.rs:262, while the client sees one opaque `magic_link_token`. Keep that property. A backend failure in the new store maps to the EXISTING MagicLinkError::Store -> `store_error` (error.rs:211), which is already distinct from replay - do not collapse those two, and do not let a store outage read as `already_used` (that would lock users out) or as success (that would defeat the fix).")
//! @yah:gotcha("THE DOWNSTREAM TICKET SAYS THERE IS A SECOND, TEST-ONLY IMPL BESIDES MemoryUsedJtiStore. THERE IS NOT - verified 2026-09-11. `rg 'impl .*UsedJtiStore for'` across crates/ returns exactly one hit, magic_link.rs:321. Every other UsedJtiStore reference is either a generic bound (cheers-axum/src/magic_link.rs:116, :153, :179) or a USE of MemoryUsedJtiStore (cheers/src/email/template.rs:232, cheers-test-identity/src/lib.rs:190, cheers-axum/tests/magic_link_basic.rs:57, cheers-axum/tests/me_basic.rs:404). Do not go hunting for a second impl to model the new one on; MemoryUsedJtiStore is the only reference, and those five call sites are what a trait move or signature change would have to be swept through.")
//! @yah:verify("THE ACCEPTANCE TEST, and it must FAIL today and PASS after the fix: request a magic link, consume it once (expect success), RESTART THE PROCESS, then replay the SAME URL. Today the replay succeeds and mints a second session. After the fix it must be refused with the existing `already_used` code (cheers-axum/src/error.rs:218), not a new one. In-crate this is expressible without a real restart by dropping the store handle and constructing a fresh one against the same database file - cheers-turso's existing file-backed tests already use tempfile for exactly this (a throwaway on-disk database per test, because the engine takes a process-wide exclusive lock).")
//! @yah:verify("cargo test -p cheers provider_consume_expired_token_does_not_burn_jti  # the verify-before-burn ordering must stay green through any consume() reshuffle")
//! @yah:verify("cargo test --workspace  # from the cheers checkout; includes tests/flip.rs, which proves the sqlx and turso families stay schema-interchangeable - a new table added on only one side breaks it")
//! @yah:verify("Downstream acceptance, run from the noisetable camp once this lands: `cd web/services && cargo test -p noisetable-account` - baseline 243 pass / 0 fail, measured 2026-09-11. The noisetable-side change is swapping MemoryUsedJtiStore for the persistent impl at web/services/account/src/auth.rs:272, tracked on noisetable R131-B26.")
//! @yah:next("DOWNSTREAM CONSUMER AND WHY THE SEVERITY IS HIGH: noisetable camp ticket R131-B26 (source anchor web/services/account/src/auth.rs:138), which owns the one-line swap at auth.rs:272 once this impl exists. It is not theoretical there. On 2026-09-11 a real magic-link URL for a real signed-in production user landed in a chat transcript; the jti was burned only in the in-process store, and the service had been redeployed minutes earlier, so a restart inside the TTL re-arms that exact URL. The window is not the 900s code default either - that deployment sets NOISETABLE_ACCOUNT_MAGIC_LINK_TTL_SECS=3600, read live out of /proc on us-east-001 - so a restart re-arms every link minted in the preceding hour, not just the most recent. A magic-link URL is a bearer credential with no second factor: it is forwarded, logged by mail gateways, and retained in transcripts, and every one of those copies is live again the moment the process restarts.")
//! @yah:handoff("Took option (b): UsedJtiStore + MemoryUsedJtiStore moved from cheers::email::magic_link into cheers-core::store (alongside CredentialStore), re-exported as `pub use cheers_core::{MemoryUsedJtiStore, UsedJtiStore};` from cheers::email::magic_link so all five existing call sites (cheers-axum/src/magic_link.rs:116,153,179; cheers/src/email/template.rs:232; cheers-test-identity/src/lib.rs:190; cheers-axum/tests/magic_link_basic.rs:57; cheers-axum/tests/me_basic.rs:404) resolve unchanged. consume() ordering untouched (verify_at first, try_mark_used second); provider_consume_expired_token_does_not_burn_jti still green.")
//! @yah:handoff("Implemented BOTH families per the gotcha: TursoUsedJtiStore (crates/cheers-turso/src/used_jti_store.rs) and SqliteUsedJtiStore (crates/cheers-sqlx/src/used_jti_store.rs, feature='sqlite'), both over a new `used_jti (jti TEXT PRIMARY KEY, expires_at INTEGER NOT NULL)` table with an index on expires_at for GC. try_mark_used is a single `INSERT ... ON CONFLICT (jti) DO NOTHING`, returning true iff the affected-row count is 1 (the insert claimed it) — atomic insert-if-absent, no transaction needed. Both ship a gc(now) method mirroring TursoRevocationStore/PgRevocationStore's pattern.")
//! @yah:handoff("Migration 0006_used_jti.sql is byte-identical in crates/cheers-turso/migrations/sqlite/ and crates/cheers-sqlx/migrations/sqlite/ (verified with `diff`), registered in cheers-turso's MIGRATIONS const at version 6 — migrations_match_cheers_sqlx (tests/turso.rs) passes.")
//! @yah:handoff("DECISION FLAGGED, not asked: no PgUsedJtiStore / no pg/0006 migration. Reasoning: noisetable-account (the only production consumer) runs on cheers-turso or cheers-sqlx sqlite (the flip.rs pair); there is no pg consumer of the magic-link flow anywhere in the workspace, so a pg impl would ship with no caller and no test, violating this codebase's 'wired to a consumer and a test, or not at all' rule. Add PgUsedJtiStore + migrations/pg/0006 alongside the first real pg consumer.")
//! @yah:handoff("Acceptance test: crates/cheers-turso/tests/magic_link_replay.rs. magic_link_replay_is_refused_after_reopening_turso_store drives the REAL MagicLinkProvider (request+consume, unmodified) against TursoUsedJtiStore, drops the store/conn (releases the engine's exclusive lock), reopens a fresh TursoUsedJtiStore against the SAME file, replays the same token, and asserts MagicLinkError::AlreadyUsed (maps to the existing already_used client code, error.rs:218 — untouched). Negative control magic_link_replay_succeeds_across_restart_with_memory_store runs the IDENTICAL scenario against MemoryUsedJtiStore (the pre-fix sole impl) and asserts the replay SUCCEEDS — proving the harness would have caught the defect pre-fix. Added cheers-turso dev-dep on cheers-providers (path, default-features=false, features=['email']) for MagicLinkProvider/MagicLinkCodec.")
//! @yah:handoff("Verified: cargo test -p cheers-providers provider_consume_expired_token_does_not_burn_jti green (unaffected by the trait move). cargo test --workspace from external/yah/oss/cheers: 566 passed, 0 failed, 0 ignored-as-failure across every crate (unit+integration+doctests) — up from a 564-pass baseline (the two new magic_link_replay.rs tests), no regressions.")
//! @yah:handoff("GIT: staged the exact 13 changed/added files (cheers-core/{lib,store}.rs, cheers-sqlx/{lib.rs,used_jti_store.rs,migrations/sqlite/0006_used_jti.sql}, cheers-turso/{Cargo.toml,lib.rs,migrate.rs,used_jti_store.rs,migrations/sqlite/0006_used_jti.sql,tests/magic_link_replay.rs}, cheers/src/email/magic_link.rs, Cargo.lock) with `git add`, verified via `git status` that no peer's in-flight files were swept in. `git commit` was denied by this session's tool policy — commit is NOT yet made; the camp's git flow (or the next agent with commit rights) needs to create it. Nothing else in the shared yah monorepo tree was touched.")
//! @yah:verify("cargo test -p cheers-providers provider_consume_expired_token_does_not_burn_jti — green, ordering-pinned test unaffected by the trait move")
//! @yah:verify("cargo test --workspace (from external/yah/oss/cheers) — 566 passed / 0 failed, includes tests/flip.rs (sqlx<->turso interchangeability, unaffected) and the new tests/magic_link_replay.rs")
//! @yah:verify("diff crates/cheers-turso/migrations/sqlite/0006_used_jti.sql crates/cheers-sqlx/migrations/sqlite/0006_used_jti.sql — byte-identical")
//! @yah:verify("Downstream: noisetable camp ticket R131-B26 can now swap MemoryUsedJtiStore for AccountStores::used_jti() (TursoUsedJtiStore) at web/services/account/src/auth.rs:272 — not run from this session, out of scope for R727-B1")
//! @yah:next("IT CANNOT BE FIXED DOWNSTREAM, AND THE OBVIOUS SHORTCUT IS FORBIDDEN BY CONTRACT. The first consumer to hit this is noisetable-account (noisetable camp ticket R131-B26), which wires MemoryUsedJtiStore at web/services/account/src/auth.rs:272. It cannot just add a used_jti table to its own account database: that file's module header at auth.rs:21-26 records the constraint and section 3 of the noisetable doc .yah/docs/working/W148-societies-fleets-and-where-publishing-happens.md is its source - the account schema is byte-identical to cheers-sqlx's BY CONTRACT, and cheers-turso's own lib.rs header (crates/cheers-turso/src/lib.rs:17-30) makes the same promise from this side, with `cheers_test_support::store_scenarios` and tests/flip.rs mechanically checking it. A downstream-owned table forks that schema and breaks the flip test's premise. So the store has to be a cheers-side impl.")
//! @yah:verify("INDEPENDENT VERIFICATION (courier, outer gate) 2026-09-11: `cargo test --workspace` from the cheers checkout = 566 passed / 0 failed / 0 ignored-as-failure (summed all 34 test-result lines myself), matching the claimed baseline+2. Confirmed `provider_consume_expired_token_does_not_burn_jti` and both `magic_link_replay.rs` tests ran and passed. `diff`+`cmp` of crates/cheers-turso/migrations/sqlite/0006_used_jti.sql vs crates/cheers-sqlx/migrations/sqlite/0006_used_jti.sql: byte-identical (exit 0 both). Read magic_link_replay_is_refused_after_reopening_turso_store: it genuinely drops the Arc<TursoConn> (and store) then opens a fresh TursoConn::open against the same on-disk path before replaying — not a shared handle — and asserts MagicLinkError::AlreadyUsed, the existing client-visible code. NEGATIVE CONTROL re-run independently: copied the cheers crate to /tmp/oss_scratch/cheers (with a read-only symlink to oss/mshr for the path dep — real tree never touched), edited only the scratch copy's acceptance test to swap TursoUsedJtiStore::new(...) for MemoryUsedJtiStore::new() (neutralising persistence while keeping the drop/reopen shape), and reran: it FAILED exactly as expected (panic: \"a replay after reopening the store must be refused\" — consume() returned Ok instead of AlreadyUsed). Confirms the test is sensitive to the actual fix, not vacuously green. Scratch copy deleted after. PG DECISION: verified cheers-sqlx's `pg` feature is real (sqlx/postgres, migrations/pg/0001-0005, and pg-capable UserStore/RefreshStore/AuditStore/OwnershipStore/Revocation/ServicePrincipalStore impls) — so this is not a moot flag, postgres is a genuine backend in this crate family. UsedJtiStore is sqlite-only (used_jti_store.rs doc comment + no migrations/pg/0006). The deferral is still correctly reasoned (no pg consumer of magic-link exists anywhere in the workspace today, so a PgUsedJtiStore would be untested/uncalled) but it is a real gap to track, not a non-issue — flagging it stays open rather than closed. Verdict: JOB 1 GREEN, ticket correctly stays at review.")

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
pub mod used_jti_store;
pub mod user_store;
pub mod user_token_store;

pub use conn::{ReadOnlyConn, TursoConn, Unit};
pub use error::map_turso_error;
pub use migrate::{MigrateError, Migration, MIGRATIONS};

pub use audit_store::TursoAuditStore;
pub use ownership_store::TursoOwnershipStore;
pub use passkey_store::TursoPasskeyCredentialStore;
pub use refresh_store::TursoRefreshStore;
pub use revocation::{TursoRevocationReader, TursoRevocationStore};
pub use service_principal_store::TursoServicePrincipalStore;
pub use used_jti_store::TursoUsedJtiStore;
pub use user_store::TursoUserStore;
pub use user_token_store::TursoUserTokenStore;

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

    pub fn used_jti(&self) -> TursoUsedJtiStore {
        TursoUsedJtiStore::new(self.conn.clone())
    }

    pub fn user_tokens(&self) -> TursoUserTokenStore {
        TursoUserTokenStore::new(self.conn.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cheers_server::store::{PasskeyCredentialStore, RefreshStore, UserStore};
    use cheers_server::{
        AuditStore, OwnershipStore, RevocationWriter, ServicePrincipalStore, UserTokenStore,
    };
    use cheers_verify::RevocationReader;

    /// Every store must stay usable behind a trait object — the products wire
    /// them as `Arc<dyn UserStore>` and friends. `UserTokenStore` in
    /// particular: `cheers-axum`'s `MeTokensState` holds it as
    /// `Arc<dyn UserTokenStore>`, so losing dyn-compatibility here breaks the
    /// `/me/tokens` router outright.
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
        fn _ut(_: &dyn UserTokenStore) {}
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
