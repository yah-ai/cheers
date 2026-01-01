# cheers

Identity, session, and credential primitives for yah-family products.

Two crates:

- [`cheers-core`](crates/cheers-core/) — contract surface (`Claims`, `Codec`,
  `UserStore`, …). Pure types, no I/O. The crate mesofact depends on.
- [`cheers`](crates/cheers/) — identity providers (OIDC, Apple Sign In,
  passkey, email magic-link, password, LAN-pair) and native credential
  stores. Each provider behind a feature flag.

The crate layout is being refined into capability-tiered crates (a
verify-only `cheers-verify` split from a minter-bearing `cheers-server`,
plus client `cheers-store` / `cheers-apple` / `cheers-android`) so the
deployment tiers — edge, server, client — are enforced by the dependency
graph rather than a shared symmetric key. See
`.yah/docs/working/edge-verifiable-auth.md` §"Crate topology" (R019).

## Design

See `.yah/docs/architecture/cheers.md` for the design doc and
`.yah/docs/working/cheers-plan.md` for the phase-by-phase build sequence.

## Status

Pre-0.1, every crate at `0.0.x`, breaking changes welcome. Phase P0
(workspace bootstrap) is the only thing landed today.

## License

Dual-licensed under MIT or Apache-2.0, your choice. Some transitive deps
(`webauthn-rs`, `authenticator`) are MPL-2.0; see `deny.toml`.
