# cheers

Identity, session, and credential primitives for yah-family products.

## Crates

The layout is **capability-tiered**: which crate you link decides what you are
able to do, so "the edge cannot mint a session" is a fact about the dependency
graph rather than a convention someone has to enforce in review.

| crate | tier | holds |
|---|---|---|
| [`cheers-core`](crates/cheers-core/) | contract | `Claims`, `Principal`, `Scope` / `McpClaims`, `CredentialStore`, and the **keyless** `TokenMinter` / `TokenVerifier` traits. No crypto, no I/O. The crate mesofact depends on. |
| [`cheers-verify`](crates/cheers-verify/) | edge | `PasetoV4PublicVerifier` (Ed25519 **public** key), `RevocationReader`, and the `EdgeVerifier` facade. **Depends on no minter**, so anything built on it is physically unable to forge a session. |
| [`cheers-server`](crates/cheers-server/) | origin | the secret-key minter, the symmetric codecs, `UserStore` / `RefreshStore`, refresh rotation, `RevocationWriter`, service principals, MCP authority, and the `SessionAuthority` facade. |
| [`cheers`](crates/cheers/) | providers | OIDC (Google, Apple, generic), passkey, email magic-link, password, LAN-pair. Each behind a feature flag. |
| [`cheers-axum`](crates/cheers-axum/) | routes | axum 0.8 routers composing the above — login/callback, passkey, magic-link, JWKS, camps, ownership, audit, `/me`. |
| [`cheers-store`](crates/cheers-store/) | client | device-tier credential storage (OS keyring, encrypted file). No token crypto. |
| [`cheers-sqlx`](crates/cheers-sqlx/) · [`cheers-turso`](crates/cheers-turso/) · [`cheers-redis`](crates/cheers-redis/) | storage | store impls — Postgres/SQLite, in-process Turso, and the Redis TTL hot path. |
| [`cheers-test-support`](crates/cheers-test-support/) · [`cheers-test-identity`](crates/cheers-test-identity/) | dev | in-memory fixtures, golden token fixtures, and a deterministic magic-link server for E2E harnesses. **Never ship either.** |

**`cheers-server` depends on `cheers-verify`, never the reverse.** That single
direction is the whole guarantee: a verify-only consumer — a CF Worker, or a
capability gateway like `oss/roadcase` — has no path to a minter in its
dependency graph, however it is wired.

## Design

See `.yah/docs/architecture/cheers.md` for the design doc,
`.yah/docs/working/edge-verifiable-auth.md` for the verify/mint split (R019),
and `.yah/docs/working/mcp-auth-and-ownership.md` for principals, scopes and
ownership (R020).

## Status

Version `0.8.x`, in use. Landed and exercised by tests: the asymmetric
verify/mint split, principal kinds (user / service / camp), the closed scope
vocabulary with composition rules, service principals, JWKS publication
(current + outgoing kids — the *automated* platform-key rotation behind it is
not landed; see `cheers-axum/src/jwks.rs`), camps and ownership scoping, an
audit trail, and the provider set above.

Not 1.0: the public types are `#[non_exhaustive]` and the wire shapes are
allowed to move, but the mesofact ↔ cheers `Claims` contract is treated as
fixed and changes to it need a coordinated migration.

> This README claimed "pre-0.1, phase P0 only" until 2026-08-29, long after
> that stopped being true. If you are reading it to decide what cheers can do,
> prefer the crate docs and the tests — those are the ones that fail when they
> go stale.

## License

Dual-licensed under MIT or Apache-2.0, your choice. Some transitive deps
(`webauthn-rs`, `authenticator`) are MPL-2.0; see `deny.toml`.
