<!-- @yah:covered-by(Q002, status=open, 2026-05-14) -->
<!-- @yah:covered-by(Q003, status=open, 2026-05-14) -->
<!-- @yah:covered-by(Q004, status=open, 2026-05-14) -->
<!-- @yah:covered-by(Q005, status=open, 2026-05-14) -->

# cheers — implementation plan

> **Companion:** [`cheers.md`](cheers.md) is the design doc; this is
> the build sequence. Structured so `/refine` can lift each phase into
> a relay with sub-tickets when the cheers board opens.
>
> **Workspace target:** `external/cheers/` (sibling of `external/xlb/`,
> `external/mesofact/`). Doesn't exist yet — Phase 0 creates it.

## Sequencing summary

```
P0 workspace setup
   │
   └─→ P1 cheers-core (foundation; gates mesofact integration)
          │
          ├─→ P2 token mint/verify + refresh rotation
          │
          ├─→ P3 email magic-link   ─┐
          │                          │
          ├─→ P4 email + password   ─┤
          │                          │
          ├─→ P5 OIDC infra + Google ┤   parallel after P1
          │       │                  │
          │       └─→ P6 Apple Sign In
          │                          │
          ├─→ P7 passkey (WebAuthn) ─┤
          │                          │
          ├─→ P8 CredentialStore impls ─┘
          │       │
          │       └─→ P9 native Apple passkey UI (needs P7+P8)
          │
          └─→ P10 LAN-pair (needs xlb-net stable + P1)

P11 mesofact resolver swap  (needs P1 only — earliest integration win)
P12 yah-platform integration (needs P5 + P6 + P7 + P11)
```

Critical path: P0 → P1 → P11 (visible win: mesofact decodes a cheers
token). Everything between P1 and P12 is parallelizable.

---

## P0 — Workspace setup

**Goal:** `external/cheers/` exists as a Cargo workspace with two
member crates, license files, CI, and lint config. Nothing
functional yet.

**Deliverables (→ tickets):**
- `external/cheers/Cargo.toml` workspace manifest, members `crates/cheers-core` + `crates/cheers`
- `external/cheers/crates/cheers-core/Cargo.toml` (empty `lib.rs`)
- `external/cheers/crates/cheers/Cargo.toml` (empty `lib.rs`, feature gates declared but inert)
- `LICENSE-MIT` + `LICENSE-APACHE` (match `external/xlb/` exactly)
- `deny.toml` with allow-list of permissive licenses + MPL exception for `webauthn-rs`, `authenticator`
- `release-plz.toml` (match xlb pattern)
- `.gitignore`
- `README.md` stub pointing at `cheers.md` design doc

**Verify:**
```bash
cd external/cheers && cargo check --workspace
cd external/cheers && cargo deny check
```

**Depends on:** nothing.

**Anchor for ticket annotation:** `external/cheers/crates/cheers-core/src/lib.rs` (module-level `//!`).

---

## P1 — cheers-core foundation

**Goal:** The contract surface that mesofact + every product depends
on. Pure types and traits, no I/O, no platform code. This is the
crate that lets P11 happen.

**Deliverables (→ tickets):**
- `claims.rs`: `Claims`, `Credential`, `DeviceBinding` enum (variants: `Passkey`, `OidcGoogle`, `OidcApple`, `OidcGeneric { issuer }`, `EmailPassword`, `EmailMagicLink`, `LanPair`), `UserId` newtype, `DeviceId` newtype, `User`
- `codec.rs`: `Codec` trait (mint + verify), `PasetoV4Codec` impl, `HmacBlobCodec` impl as fallback. Decision per design doc §"Open decisions" #1 — ship both, let consumers pick.
- `store.rs`: `UserStore` trait (find by provider+subject, create, link provider, list devices, revoke device), `CredentialStore` trait (put/get/delete), `RefreshStore` trait
- `error.rs`: typed error hierarchy, `thiserror`
- Doctests for `Codec` roundtrip
- Property tests: `Codec::verify(Codec::mint(c)) == Ok(c)` for arbitrary Claims, plus tamper-detection negative cases

**Verify:**
```bash
cd external/cheers && cargo test -p cheers-core
cd external/cheers && cargo test -p cheers-core --doc
```

**Depends on:** P0.

**Parallel-safe with:** nothing (everything else depends on this).

**Anchor:** `crates/cheers-core/src/lib.rs`.

**Gotcha to surface in ticket:** the `Claims` shape is the mesofact
↔ cheers contract. Any change after P11 ships requires a coordinated
migration. Lock the shape with a `#[non_exhaustive]` attr and explicit
versioning before tagging 0.1.

---

## P2 — Refresh token rotation

**Goal:** The stateful half of session management. Opaque refresh
tokens stored in `RefreshStore`, rotated on every use, replay-detected.

**Deliverables (→ tickets):**
- `cheers-core/src/refresh.rs`: `RefreshToken` (opaque 32-byte secret), `RefreshChain` (links token → user → device → parent), rotation logic
- `RefreshStore` impl notes (in-memory for tests; real impls live in product code per design doc)
- Replay detection: if a refresh token is presented after rotation, revoke the entire chain for that device
- Tests covering: happy-path rotate, replay → chain revoked, expired token rejection

**Verify:**
```bash
cargo test -p cheers-core refresh
```

**Depends on:** P1.

**Parallel-safe with:** P3, P4, P5, P7, P8.

**Anchor:** `crates/cheers-core/src/refresh.rs`.

**Reference (read, don't lift):** Rauthy `src/data/src/entity/sessions.rs`
— audited rotation pattern.

---

## P3 — Email magic-link provider

**Goal:** Simplest end-to-end provider. Proves the `UserStore` +
`Codec` integration without OIDC complexity. Email arrives, click,
session minted.

**Deliverables (→ tickets):**
- `cheers/src/email/magic_link.rs`: token signing (paseto with `purpose: magic-link`, 15-min exp, email claim), URL builder, verifier
- `cheers/src/email/mailer.rs`: `Mailer` trait + `LettreMailer` impl
- HTML + plaintext template structs (caller supplies actual copy)
- Single-use enforcement via `RefreshStore`-adjacent tracking (one-time-use blacklist)
- Integration test using a mock `Mailer` capturing the URL

**Verify:**
```bash
cargo test -p cheers --features email
```

**Depends on:** P1.

**Parallel-safe with:** P2, P4, P5, P7, P8.

**Anchor:** `crates/cheers/src/email/magic_link.rs`.

**Gotcha:** verify URL must include the user's email in the token
claim, not as a query param — otherwise an attacker who learns the
token can replay it for any email.

---

## P4 — Email + password (optional)

**Goal:** Argon2id password hashing + breached-password check. Gated
behind feature flag because not every product wants to enable
passwords.

**Deliverables (→ tickets):**
- `cheers/src/email/password.rs`: hash, verify, rehash-on-login if params changed
- HIBP-style breached-password prefix check (k-anonymity: SHA-1 first 5 chars → API → match suffix locally). Configurable endpoint URL for self-hosted equivalents.
- Constant-time comparison
- Default Argon2id params: m=19456, t=2, p=1 (current OWASP recommendation as of 2026)
- Tests with known-good and known-bad password hashes

**Verify:**
```bash
cargo test -p cheers --features email,password
```

**Depends on:** P1.

**Parallel-safe with:** P2, P3, P5, P7, P8.

**Anchor:** `crates/cheers/src/email/password.rs`.

**Cleanup note:** the HIBP HTTP client should be injectable so
tests don't hit the network and air-gapped deployments can skip the
check entirely.

---

## P5 — OIDC infrastructure + Google

**Goal:** Standard OIDC consumer flow — discovery, authorization code +
PKCE, state+nonce, ID token verification. Google provider is the first
concrete impl.

**Deliverables (→ tickets):**
- `cheers/src/providers/oidc_generic.rs`: `OidcProvider` struct wrapping `openidconnect::Client`, PKCE state, nonce storage trait
- `cheers/src/providers/google.rs`: `GoogleProvider` newtype wrapping `OidcProvider` with Google's discovery URL pre-baked
- Authorization URL builder
- Callback handler: code → tokens → claims → user resolution via `UserStore`
- State storage trait + in-memory impl (real impls in product code)
- Tests with `wiremock` mocking Google's OIDC endpoints

**Verify:**
```bash
cargo test -p cheers --features google
```

**Depends on:** P1.

**Parallel-safe with:** P2, P3, P4, P7, P8.

**Anchor:** `crates/cheers/src/providers/oidc_generic.rs`.

**Gotcha:** state + nonce must be bound to the session attempting
login, not just stored globally — otherwise CSRF.

---

## P6 — Apple Sign In

**Goal:** The special provider. ES256 JWT `client_secret`, two entry
points (redirect callback + native iOS token handoff), one-shot name
capture.

**Deliverables (→ tickets):**
- `cheers/src/providers/apple/client_secret.rs`: ES256 JWT generator over `jsonwebtoken` + `p256`. Reads `.p8` developer key, caches signed JWT until 5 min before expiry.
- `cheers/src/providers/apple/redirect.rs`: standard OIDC callback flow with Apple's quirks (form-post response mode, no userinfo endpoint, name only in first response)
- `cheers/src/providers/apple/native.rs`: `verify_native_token(jwt) -> Result<User, _>` — validates against Apple's JWKS, no code exchange needed
- `cheers/src/providers/apple/jwks_cache.rs`: cached JWKS with weekly refresh + on-verify-failure refresh
- `FirstLoginName` newtype wrapping `Option<String>` with doc-comment shouting about persistence requirement
- Tests with real Apple JWKS fixtures (committed) + mocked discovery
- Integration test: full redirect flow against a wiremock'd Apple

**Verify:**
```bash
cargo test -p cheers --features apple
```

**Depends on:** P5 (uses OIDC infra primitives).

**Parallel-safe with:** P7, P8.

**Anchor:** `crates/cheers/src/providers/apple/mod.rs`.

**Gotchas (must surface in ticket):**
- Apple sends user's name *only on first auth response*. If you don't
  persist it then, it's gone forever. The trait return type enforces this.
- `client_secret` JWT expires; cache invalidation on token refresh
  failure must regenerate, not just retry.
- Apple's `email` may be `@privaterelay.appleid.com`; treat as opaque.
- Apple's discovery doesn't follow OIDC spec strictly — some fields
  missing. `openidconnect` may need a custom `ProviderMetadata`.

---

## P7 — Passkey (WebAuthn server-side)

**Goal:** Registration + authentication ceremonies via `webauthn-rs`.
Server-side only — client UI per-platform comes in P9.

**Deliverables (→ tickets):**
- `cheers/src/passkey/mod.rs`: `PasskeyRelyingParty` struct wrapping `Webauthn`
- `cheers/src/passkey/register.rs`: start_registration → finish_registration, persists `CredentialID` + public key to `UserStore`
- `cheers/src/passkey/authenticate.rs`: start_authentication → finish_authentication
- Discoverable-credential flag (default off per design doc)
- Multi-credential per user (a user can have multiple passkeys: phone, laptop, security key)
- Tests against `webauthn-rs` test vectors

**Verify:**
```bash
cargo test -p cheers --features passkey
```

**Depends on:** P1.

**Parallel-safe with:** P2, P3, P4, P5, P6, P8.

**Anchor:** `crates/cheers/src/passkey/mod.rs`.

**License flag (must surface):** `webauthn-rs` is MPL-2.0. Recorded in
`deny.toml` exception list (P0). Don't modify the crate's files in
place — if patching is ever needed, isolate the patched files and
keep them MPL.

---

## P8 — CredentialStore implementations

**Goal:** Per-platform credential storage behind feature flags. None
of these are needed by the server side of cheers — they're for native
apps that hold credentials locally.

**Deliverables (→ tickets):**
- `cheers/src/store/keyring.rs`: `KeyringStore` over `keyring` crate. Compiles on macOS/iOS/Linux/Windows; tested on whatever the dev machine is.
- `cheers/src/store/encrypted_file.rs`: `EncryptedFileStore` using `age` for encryption. Key from TPM if `/dev/tpm0` exists, else generated on first run and stored in a separate file.
- `cheers/src/store/memory.rs`: `MemoryStore` for tests
- Round-trip tests per impl (gated by `#[cfg]` for platform-specific)

**Verify:**
```bash
cargo test -p cheers --features keyring
cargo test -p cheers --features headless
```

**Depends on:** P1.

**Parallel-safe with:** P2, P3, P4, P5, P6, P7.

**Anchor:** `crates/cheers/src/store/mod.rs`.

**Gotcha:** the `keyring` crate's behavior on headless Linux (no
gnome-keyring running) is "fails at runtime, not compile time." Tests
need to skip cleanly when the backing service is unavailable.

---

## P9 — Native Apple passkey UI

**Goal:** macOS and iOS get native passkey prompts via
`AuthenticationServices`, not webview WebAuthn. This is the load-bearing
UX win for yah-desktop on Mac and noisetable on iOS.

**Deliverables (→ tickets):**
- `cheers/src/native/apple/mod.rs`: feature-gated behind `macos` / `ios`
- `cheers/src/native/apple/passkey.rs`: `objc2-authentication-services` wrapper. Calls `ASAuthorizationController` with `ASAuthorizationPlatformPublicKeyCredentialProvider`.
- Bridge: native UI returns assertion bytes → cheers verifies server-side via P7's `PasskeyRelyingParty`
- Bridge in the other direction: server emits registration challenge → native UI shows passkey prompt → returns attestation
- Sample integration in `examples/` showing a Tauri command that exercises the full flow

**Verify:**
```bash
cargo build -p cheers --features macos,passkey
cargo build -p cheers --features ios --target aarch64-apple-ios   # ios feature alone — passkey pulls openssl which can't cross-compile
```

**Depends on:** P7 + P8.

**Parallel-safe with:** P10.

**Anchor:** `crates/cheers/src/native/apple/passkey.rs`.

**Cleanup:** `objc2-authentication-services` is fast-moving; pin to a
specific version and re-audit on bumps.

---

## P10 — LAN-pair

**Goal:** The rpi case. Already-authed device vouches for a fresh
headless device over LAN, using xlb-net as transport.

**Deliverables (→ tickets):**
- Wire format: `PairOffer { node_id, capabilities }`, `PairAccept { user_id, device_id, attrs, expires_at }`, both serde-encoded
- `cheers/src/lan_pair/offerer.rs`: rpi side, discovers peers via xlb-net, broadcasts `PairOffer`
- `cheers/src/lan_pair/accepter.rs`: phone/Mac side, listens for offers, prompts user (callback trait), sends `PairAccept`
- Confirmation UX hooks: `ConfirmationStrategy` trait with impls for `SixDigitCode`, `DisplayCode` (rpi shows code), `AutoTrust` (LAN-trusted opt-in)
- Resulting `Credential` minted into the rpi's `EncryptedFileStore`
- Integration test using two xlb-net `Endpoint`s in-process

**Verify:**
```bash
cargo test -p cheers --features lan-pair
```

**Depends on:** P1, plus xlb-net stable enough that we can take a dep
on a tagged version. Coordinate with xlb track.

**Parallel-safe with:** P9.

**Anchor:** `crates/cheers/src/lan_pair/mod.rs`.

**Open question (must surface as `@yah:assumes`):** Default UX is
"(b) six-digit code on rpi first-boot console output" per design doc
§"Open decisions" #4. Confirm with user before implementing — alt is
display-detection auto-switch.

---

## P11 — mesofact resolver swap

**Goal:** The first integration. mesofact's `CookieSessionResolver`
stops using its placeholder HMAC codec and depends on `cheers-core`
directly.

**Deliverables (→ tickets):**
- `external/mesofact/crates/mesofact/Cargo.toml`: add `cheers-core` path dep
- `external/mesofact/crates/mesofact/src/auth.rs` (or wherever the resolver lives): replace placeholder codec with `cheers_core::Codec`
- Update mesofact's `CookieSessionResolver` to return cheers's `User` directly (or a thin newtype)
- Update mesofact test fixtures to use cheers-minted tokens
- Backward-compat: support both old and new cookie formats for one release if any tokens exist in the wild (probably not — pre-launch)

**Verify:**
```bash
cd external/mesofact && cargo test
cd external/mesofact && cargo test --test integration  # if exists
```

**Depends on:** P1 (only).

**Parallel-safe with:** P2-P10 (this is the earliest visible win and
can ship before any provider exists, because at this point mesofact
isn't yet serving auth-gated routes — it just needs the codec to
match).

**Anchor:** wherever mesofact's `CookieSessionResolver` lives.

---

## P12 — yah-platform integration

**Goal:** First product that actually mints cheers tokens. yah-platform
plugs in all the provider features it needs and wires the HTTP routes.

**Deliverables (→ tickets):**
- yah-platform `Cargo.toml`: add `cheers` with `google, apple, passkey, email`
- yah-platform `UserStore` impl over `pg` (users, oauth_identities, refresh_tokens, passkey_credentials tables)
- `/auth/login/google`, `/auth/login/apple`, `/auth/callback/google`, `/auth/callback/apple` routes
- `/auth/passkey/register/start`, `/auth/passkey/register/finish`, `/auth/passkey/authenticate/start`, `/auth/passkey/authenticate/finish`
- `/auth/magic-link/request`, `/auth/magic-link/verify`
- `/api/me/sessions` list + `/api/me/sessions/{device_id}` revoke
- Bearer PASETO response: every callback returns `SessionBody`
  (`access_token` + `refresh_token` JSON) — **no cookies on .yah.dev** per
  R347. SPA holds the access token in JS heap or `sessionStorage`;
  native/CLI clients use the OS keyring.
- Smoke tests: full login flow per provider, mocking OIDC providers

**Verify:**
```bash
cd yah-platform && cargo test
# manual: open https://auth.yah.dev/login, click Google, complete flow, see
# the SessionBody JSON arrive and the token stash in the SPA / keyring.
```

**Depends on:** P5, P6, P7, P11.

**Parallel-safe with:** nothing it doesn't already block.

**Anchor:** yah-platform's auth module (path TBD when yah-platform exists).

---

## Cross-cutting concerns

These don't slot into a single phase — they're worked alongside whatever
phase needs them.

### Documentation
- Each provider gets a usage example in its module doc-comment
- `examples/` directory with one runnable example per consumer shape (web, native-desktop, headless)
- `cheers.md` (the design doc) stays in `mesofact/.yah/docs/working/`; per-crate `README.md` files cross-link to it

### Observability
- `tracing` spans on every public entry point: provider name, user_id (or `_pre_auth`), outcome
- Metrics hooks via callable trait (no `metrics` crate dep in cheers — caller's choice)

### Security review checkpoints
- After P2: refresh rotation pattern review (cite Rauthy audit as priorartwork)
- After P6: Apple integration review (the JWT cache + JWKS validation are the failure modes)
- After P7: WebAuthn parameter review (challenge size, RP ID, attestation requirements)
- Before P12 tag: full pass

### Versioning
- `cheers-core` tags 0.1 only after P11 (the contract is locked by mesofact integration)
- `cheers` tags 0.1 only after at least P3 + one OIDC provider land (otherwise the API surface is incomplete)
- Pre-0.1: every crate is `0.0.x`, breaking changes welcome

---

## Suggested relay layout

When the cheers board opens and `/refine` runs, the natural quest +
relay split is:

- **Quest: cheers foundation** (P0 + P1 + P2 + P11) — the contract
  surface and the mesofact integration win. Highest priority, smallest
  scope.
- **Quest: cheers providers** (P3 + P4 + P5 + P6 + P7) — all the
  identity inputs. P6 is the riskiest leaf.
- **Quest: cheers client surface** (P8 + P9 + P10) — credential storage
  + native UX + LAN-pair. Can run in parallel with the providers quest.
- **Quest: cheers in yah-platform** (P12) — final integration; blocked
  by the first two quests.

Each phase above maps to one relay under the appropriate quest.
Sub-deliverables map to compound sub-tickets (`R001-T1`, `R001-T2`, …)
under each relay.

---

## What this plan does not cover

- TOTP / authenticator-app 2FA — design doc §"Out of MVP"
- Account recovery beyond magic-link — design doc §"Out of MVP"
- Hardware-attested device identity (Apple Device Check / Play
  Integrity) — design doc §"Out of MVP"
- noisetable-specific provider configuration — happens in noisetable's
  own board after P12 demonstrates the integration shape
- yah-desktop integration — happens in yah's main camp after P9 lands
  the native passkey UI
