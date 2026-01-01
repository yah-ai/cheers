# cheers

> **Status:** working draft — naming locked; the original two-crate split is
> being refined into capability-tiered crates (verify-only `cheers-verify`
> split from a minter-bearing `cheers-server`, plus client crates) so
> deployment tiers are enforced by the dependency graph. Full DAG + rationale:
> [`edge-verifiable-auth.md`](../working/edge-verifiable-auth.md) §"Crate
> topology" (R019). Open decisions inline (§"Open decisions").
>
> **Companion docs:**
> [`mesofact.md`](mesofact.md) §"Auth & session contract" defines the
> server-side `SessionResolver` trait this crate implements.
> [`mesofact-yah-case-study.md`](mesofact-yah-case-study.md) §"yah-platform"
> assumes a single IdP at `auth.yah.dev`; cheers is what runs there
> (and on every other product binary).

## What it is

A pair of Rust crates that handles **end-user identity** for the
mesofact / warden / yah / noisetable family: prove who the user is
(Google, Apple, passkey, email), mint a credential, store it on the
appropriate platform, verify it on the server side. Pure library — no
service, no admin UI, no separate process to run.

```
external/cheers/                 ← sibling of external/xlb/
  Cargo.toml                        (workspace)
  crates/
    cheers-core/                 (no I/O, no platform)
    cheers/                      (batteries; depends on -core)
```

The name is a reference to *Cheers* — the bar where everybody knows
your name. That's exactly the contract: a user walks up, the system
recognizes them. Pairs naturally as a verb ("the desktop cheers the
user in") and a noun ("present your cheers token"). It sits alongside
mesofact in `external/` without being prefix-coupled to it — mesofact's
`CookieSessionResolver` depends on `cheers-core` directly.

## What it is not (axiomatic)

These are firm boundaries — not "later" features, not "open questions."
They define the crate.

- **Not an OIDC/OAuth provider.** No third-party app ever signs in
  *with yah / mesofact / noisetable*. We are always the *consumer*.
  This is the single decision that lets cheers stay a small library
  instead of a Rauthy-shaped service.
- **No admin UI.** Each product owns its own `/account` page; cheers
  exposes the operations (rename, link/unlink provider, revoke session,
  delete account), the product wires the HTTP routes and UI.
- **No user database.** `UserStore` is a trait; yah-platform plugs in
  Postgres, noisetable plugs in its T1/T3 store
  ([`noisetable-data-tiers.md`](noisetable-data-tiers.md)), an embedded
  binary can use SQLite. The crate ships no schema.
- **No SAML, no SCIM, no enterprise org/group/RBAC.** Single user with
  free-form `attrs` is the model. If we ever sell to an org that needs
  SAML, that's a wrapper layer at the product level — not cheers's
  job.
- **No multi-tenancy primitives.** Tenant scoping lives in product
  code (and in mesofact's `requires: ["project"]` resolution).
  cheers knows about users, not orgs.

If a feature request needs us to violate one of these, it doesn't go
in cheers — it goes in the product layer or in a sibling crate.

## The four ingress shapes

Different products see different identity inputs and store credentials
differently. The point of cheers is one library that covers all four
shapes without forcing them into one ingress.

| Shape | Where it runs | Identity in | Credential lives | Verified by |
|---|---|---|---|---|
| **mesofact web** | `*.yah.dev`, `*.noisetable.com` | OIDC redirect (Google/Apple) or email-magic-link | `yah_session` cookie on parent domain | mesofact's `CookieSessionResolver` |
| **yah-desktop** | Tauri on Mac/Linux/Windows | Native passkey via OS, or embedded webview OIDC, or password manager | OS keychain → Bearer header | warden's HTTP bridge over Tailscale, or any cheers-aware backend |
| **noisetable native** | iOS / macOS / Linux desktop, fully Rust | Apple passkey (preferred on Apple), Google passkey, or email | iOS/macOS Keychain → Bearer | noisetable's API peer |
| **noisetable rpi** | Headless Linux on Raspberry Pi | LAN-pair from an already-authed phone/Mac | age-encrypted file → device credential | LAN peer or upstream via xlb-net |

All four sit on the **same token mint/verify primitive** in
`cheers-core`. The differences are entirely in (a) which provider
talks to the user and (b) where the resulting credential gets stored.
Both axes are pluggable via traits.

### Composing the shapes

A single human can have multiple devices, each with its own credential,
all bound to one user identity:

```
User
 ├── Credential (device=phone,    binding=Apple passkey,  store=iOS Keychain)
 ├── Credential (device=laptop,   binding=passkey,        store=macOS Keychain)
 ├── Credential (device=rpi-01,   binding=LAN-pair,       store=encrypted file)
 └── Credential (browser session, binding=cookie,         store=mesofact cookie)
```

Each `Credential` carries `{user_id, device_id, exp, attrs}` in its
claims. Device binding makes revocation tractable (revoke one stolen
laptop without forcing the phone to re-login) and makes the LAN-pair
flow expressible (the rpi's device credential is just another row).

## Crate split

> **Being refined (R019).** The two-crate split below was the original design.
> It's evolving into a capability-tiered DAG — `cheers-verify` (verify-only,
> edge-safe) split out from a `cheers-server` that holds the minter, plus client
> crates (`cheers-store`, `cheers-apple`, `cheers-android`) — so that "the edge
> cannot mint" is enforced by the dependency graph rather than a shared
> symmetric key. Full DAG + rationale in
> [`edge-verifiable-auth.md`](../working/edge-verifiable-auth.md) §"Crate
> topology". The structure below stays accurate for the *current* tree.

```
external/cheers/
  Cargo.toml
  crates/
    cheers-core/                 # ~800 LOC target
      src/
        lib.rs
        claims.rs                   # Credential, Claims, DeviceBinding, User
        codec.rs                    # paseto v4 mint/verify; HMAC fallback
        store.rs                    # UserStore, CredentialStore traits
        error.rs
    cheers/                      # ~4-5k LOC target
      Cargo.toml                    # features = [google, apple, passkey,
      src/                          #             email, lan-pair,
        lib.rs                      #             keyring, headless,
        providers/                  #             ios, macos, linux, windows]
          google.rs                 # ~100 LOC over openidconnect
          apple.rs                  # ~400 LOC — the special case
          oidc_generic.rs           # custom OIDC provider config
        passkey/
          register.rs               # webauthn-rs wrapping
          authenticate.rs
        email/
          magic_link.rs             # signed single-use URL token
          password.rs               # argon2id helpers + HIBP prefix lookup
        lan_pair.rs                 # composes with xlb-net for device pairing
        store/
          keyring.rs                # cross-platform via keyring crate
          encrypted_file.rs         # age-encrypted, TPM-sealed key if available
        native/
          apple.rs                  # objc2-authentication-services
```

### Feature gates → who depends on what

| Consumer | Features enabled |
|---|---|
| **mesofact** | (only `cheers-core` — for the resolver) |
| **yah-platform binary** | `google, apple, passkey, email` |
| **yah-desktop (Tauri Mac)** | `passkey, keyring, macos` (+ webview-OIDC handled by `mesofact`) |
| **yah-desktop (Tauri Linux)** | `passkey, keyring, linux` |
| **noisetable iOS** | `apple, passkey, keyring, ios` |
| **noisetable Mac** | `apple, google, passkey, keyring, macos` |
| **noisetable rpi** | `lan-pair, headless` |

No consumer needs all of it. The OIDC stack alone is ~2 MB of compiled
code — products that don't need OIDC (rpi headless) shouldn't pay for
it.

## Token mint / verify (the core primitive)

The same primitive serves all four ingress shapes — the only thing that
varies is how the credential is *transported* (cookie, Bearer header,
file on disk) and *stored* on the client side.

### Token format

**Decision: paseto v4 local** (symmetric, authenticated encryption) for
the session token. See §"Open decisions" #1 — alternatives are HMAC-of-CBOR
or JWT.

- Versioned: future format changes don't break existing tokens because
  v4 carries `v4.local.` in the payload.
- Algorithm-agile but not algorithm-confused: paseto v4 fixes the
  category of bugs JWT historically had around `alg: none` and
  RS256-vs-HS256 confusion.
- Symmetric key — fine because the *issuer and verifier are the same
  process* (the product binary) for native flows, and the same key
  (warden-injected) across `*.yah.dev` mesofact instances for web.

### Claims shape

```rust
struct Claims {
    sub: UserId,                // stable user id
    dev: DeviceId,              // which device minted this credential
    exp: u64,                   // unix seconds
    iat: u64,
    bind: DeviceBinding,        // passkey, oidc-google, oidc-apple,
                                // email-password, email-magic-link,
                                // lan-pair
    attrs: BTreeMap<String, Value>,  // product-specific (camp_ids, etc.)
}
```

Mesofact's `CookieSessionResolver`
([`mesofact.md`](mesofact.md#auth--session-contract)) decodes this
directly — no extra layer.

### Refresh

Short-lived access token (15 min default), long-lived opaque refresh
token (90 day default) stored server-side in the `UserStore`. Refresh
rotates on every use; replay of an old refresh = revoke the whole
session chain.

This is one of two places ([§"Apple Sign In"](#apple-sign-in)) where
the crate has nontrivial state. Patterns lifted in spirit (not source)
from Rauthy's `src/data/src/entity/sessions.rs` — they were audited,
the pattern is sound, we re-implement against our `UserStore`.

## Identity providers

### Google

Standard OIDC discovery + authorization code + PKCE. ~100 LOC on top of
[`openidconnect`](https://docs.rs/openidconnect). No surprises.

### Apple Sign In

The hard provider — gets its own ~400 LOC module because it deviates
from OIDC in three ways and the crate's job is to hide that from the
product.

1. **`client_secret` is an ES256 JWT**, not a static string. Must be
   signed with your Apple developer key (`.p8` file), with `iss` =
   your Team ID, `sub` = your Service ID, `exp` ≤ 6 months out. The
   crate regenerates it on demand (cached in-memory until 5 min before
   expiry) using `jsonwebtoken` + `p256`.
2. **Two entry points, one verifier.**
   - Web/Tauri-webview: standard `authorize → callback(code) → token`
     redirect dance. `cheers::providers::apple::callback(code)`.
   - **iOS/macOS native:** the device calls
     `ASAuthorizationAppleIDProvider` directly via
     `cheers/src/native/apple.rs` (objc2 bindings), gets an
     `identity_token` JWT *without ever round-tripping through our
     server's OAuth dance*, then POSTs it to our server.
     `cheers::providers::apple::verify_native_token(jwt)` validates
     it against Apple's JWKS (cached, rotated weekly).
   - Both paths exit through the same `User` resolution.
3. **First-login name capture is one-shot.** Apple sends the user's
   name *only* on the very first auth response. The trait's success
   variant carries an `Option<DisplayName>` and the doc-comment shouts
   about persisting it immediately. Easy to get wrong — easy to make
   hard to get wrong with types.

Apple's private-relay email (`@privaterelay.appleid.com`) is treated
as opaque — same as any other email — and the user can change their
share preference in their Apple account, which we discover on next
auth.

### Passkey (WebAuthn)

`webauthn-rs` 0.5 handles the protocol. The crate wraps it with our
`UserStore` / `CredentialStore` traits.

- **Server side**: registration ceremony + authentication ceremony,
  storing the credential ID + public key on the user record.
- **Client side**: web → handled by the browser's WebAuthn API,
  mesofact passes the challenge through. Native (iOS/macOS) → the
  `native/apple.rs` module wraps `ASAuthorizationController` with
  `ASAuthorizationPlatformPublicKeyCredentialProvider`. Linux/Windows
  desktop → embedded webview does WebAuthn and the OS routes to the
  platform credential (this is also how 1Password/Bitwarden hook in —
  they implement the OS-level WebAuthn provider API, so password
  managers "just work").
- **Username-less / discoverable creds:** supported as a config flag,
  default off (Rauthy's posture: discoverable credentials eat device
  storage faster, opt-in not default).

**License note:** `webauthn-rs` is **MPL-2.0**. As a dependency this
is fine — file-level copyleft only triggers if we *modify* its files
in place. If we ever need to patch it, we keep the patched files MPL
and isolate them. Flagged against [[feedback_permissive_licenses]] in
the [`Cargo.toml` deny list](#license-audit) — exception, with rationale.

### Email + magic link

Server signs a single-use token (paseto v4 with `purpose: magic-link`,
exp 15 min, claims include the email being verified), embeds it in a
URL, sends via `lettre`. Click → server verifies token → mints session.
~150 LOC.

### Email + password (optional)

Argon2id for hashing (`argon2` crate, RustCrypto), with a HIBP-style
breached-password prefix check at registration and password-change
time (the SHA-1 prefix protocol — no plaintext leaves the client).
~200 LOC.

Default-off per product: yah-platform may enable it for accounts
created before passkeys are universal; noisetable native should
*probably* never enable it; mesofact-only products can pick.

### LAN-pair (the rpi case)

The rpi case is genuinely different and deserves its own provider type:
the user is not interacting with the rpi directly — they're using a
phone/Mac that's already authenticated, and that already-authed device
*vouches for* the rpi over LAN.

Composes with `xlb-net` ([`xlb-net.md`](../../../../../.yah/docs/architecture/xlb-net.md)):

```
already-authed device                rpi (booting)
  cheers Credential                 xlb-net NodeId (fresh)
        │                                     │
        │     1. xlb-net discovery (mDNS,     │
        │        LAN swarm)                   │
        │ ←─────────────────────────────────  │
        │                                     │
        │     2. PairOffer { node_id }        │
        │ ────────────────────────────────→   │
        │                                     │
        │     3. user confirms on phone       │
        │                                     │
        │     4. PairAccept {                 │
        │          DeviceBinding::LanPair,    │
        │          attrs (camp scope)         │
        │        }                            │
        │ ────────────────────────────────→   │
        │                                     │
        │                                     5. rpi: cheers-core
        │                                        mints local Credential,
        │                                        stores age-encrypted
```

The phone's existing cheers Credential is what authorizes step 4 —
the rpi gets a *device-scoped* Credential bound to the same `UserId`,
its own `DeviceId`, and `attrs` carrying whatever camp/scope the user
selected.

See §"Open decisions" #4 for the UX of step 3 (six-digit code shown
where? QR? auto-accept on shared LAN?).

## Credential storage (client side)

```rust
trait CredentialStore: Send + Sync {
    fn put(&self, key: &str, cred: &Credential) -> Result<(), StoreError>;
    fn get(&self, key: &str) -> Result<Option<Credential>, StoreError>;
    fn delete(&self, key: &str) -> Result<(), StoreError>;
}
```

| Platform | Impl | Crate | Notes |
|---|---|---|---|
| macOS | `KeyringStore` | [`keyring`](https://docs.rs/keyring) | Wraps Keychain via `security-framework`. Standard Keychain access. |
| iOS | `KeyringStore` | `keyring` | Same crate, different access groups via config. |
| Linux desktop | `KeyringStore` | `keyring` | Routes to libsecret / gnome-keyring / KWallet. |
| Windows | `KeyringStore` | `keyring` | Credential Manager. |
| Headless (rpi, server) | `EncryptedFileStore` | `age` | File at `$XDG_CONFIG_HOME/cheers/cred.age`. Key sealed with TPM if `/dev/tpm0` exists, otherwise a passphrase set at first run (LAN-pair flow auto-generates and stores it). |
| Web (mesofact) | n/a | n/a | Credential lives in the HTTP cookie; mesofact's resolver does the work. |

The `keyring` crate is doing the cross-platform heavy lifting — without
it we'd be writing per-OS code three times. Its `Send + Sync` story is
clean, no surprises.

## Composition points

### With mesofact

`cheers-core::Codec` is the canonical encoder/decoder for the cookie
payload. mesofact's `CookieSessionResolver` depends on `cheers-core`
(not `cheers`) and just calls `Codec::verify(cookie_value, &key)`.
No HTTP, no providers, no I/O — pure crypto + parsing.

This is why the split is `-core` vs. main: mesofact gets the tiny
verifier; product binaries that actually *mint* tokens get the full
crate.

> **Refined (R019):** with the asymmetric codec, the edge (CF Worker) gets
> `cheers-verify` (public key, no minting power) and the SSR origin gets
> `cheers-server` (secret key + stores). The "tiny verifier" becomes a
> *public-key* verifier that physically cannot mint — the symmetric
> `cheers-core::Codec` described here both mints and verifies, which is exactly
> why it can't be shipped to an edge. See
> [`edge-verifiable-auth.md`](../working/edge-verifiable-auth.md).

### With xlb-net

LAN-pair is the only direct composition. `cheers::lan_pair::Pairer`
takes an `xlb_net::Endpoint` and uses it as the transport for
`PairOffer` / `PairAccept` messages over the LAN swarm. xlb-net's
`NodeId` becomes part of the new device's `DeviceId` (concretely:
`DeviceId = blake3(NodeId || install_uuid)`).

No other cheers feature requires xlb-net. Web-only consumers don't
pull it in.

### With warden

When a cheers-using product runs as a warden workload, warden
injects:
- The paseto v4 symmetric key (rotated weekly, all `*.yah.dev`
  instances get the same one — that's what gives mesofact-yah's
  cross-instance SSO its mechanism).
- OIDC client credentials (Google client ID/secret, Apple Team ID +
  Service ID + signing key file).
- The `UserStore` connection config (pg URL for yah-platform, etc.).

The crate has no warden dependency — it just reads its config from a
caller-supplied struct. Warden is one possible caller.

## Open decisions

These are explicit TBDs to resolve before MVP coding starts. None
block doc adoption.

### 1. Token format: paseto v4 local vs HMAC-of-CBOR

**Current lean:** paseto v4 local.

- **paseto v4 local** — `pasetors` crate (MIT). No `alg`-confusion
  footguns. Authenticated encryption (XChaCha20-Poly1305). 200ms older
  ecosystem than JWT but mature.
- **HMAC-of-CBOR** — boring, zero crypto-library dependency beyond
  `hmac` + `sha2` + `serde_cbor`. We own every byte. Slightly more
  work to do nonce/key-rotation right.

**Decision driver:** if `cheers-core` ought to be a zero-extra-dep
crate (so mesofact's resolver pulls in nothing scary), HMAC-of-CBOR
wins. If we want forward-compat with public-key tokens later (paseto
v4 public for cross-product trust without shared symmetric keys),
paseto wins.

### 2. Refresh strategy: opaque DB-tracked vs rotated stateless

**Current lean:** opaque DB-tracked in `UserStore`.

Stateless JWT refresh tokens are appealing (no DB hit) but their
revocation story is essentially "wait for them to expire." Opaque
refresh tokens stored in `UserStore` cost a DB read on every refresh
(~15 min cadence per active session — not hot path), but a `DELETE
FROM sessions WHERE user_id = ?` is the entire revocation story.

For "lose my phone, log out everywhere" UX, opaque wins. For
ultra-high-scale (>10k req/sec on auth specifically), stateless wins.
We are nowhere near the latter and likely never will be.

### 3. Device binding granularity

`DeviceId = blake3(NodeId || install_uuid)` vs `DeviceId = uuid::v7()
generated on first run, stored client-side`.

The first ties device identity to xlb-net cleanly. The second is
simpler and doesn't force xlb-net on web-only consumers. Probably the
second; xlb-net can adopt the cheers `DeviceId` as one of its
NodeId derivation inputs if it wants to.

### 4. LAN-pair UX for rpi

How does the user confirm "yes, this is my rpi" on their phone? Four
options:

- **(a) Six-digit code on the rpi's local display.** Best when the rpi
  has a screen.
- **(b) Six-digit code on the rpi's first-boot console output / WiFi
  AP captive portal.** Best when the rpi is headless from day one.
- **(c) QR code from the phone, scanned by an rpi camera.** Most
  consumer products do this; we have no camera on a generic rpi.
- **(d) Auto-pair to any cheers-holding peer in the same xlb-net
  swarm.** Magical but assumes physical-LAN trust; fine for "I plugged
  this in at home" hostile for "I deployed this at a co-working space."

**Current lean:** (b) as default, fall back to (a) if a display is
detected, never (c) or (d) without explicit user opt-in.

## Out of MVP

Documented here so they're not rediscovered as gaps later:

- **TOTP / authenticator-app 2FA.** Passkeys cover MFA; if a product
  needs TOTP specifically (compliance), add as a separate provider
  later. No protocol blockers.
- **WebAuthn discoverable credentials by default.** Off; opt-in.
- **Account recovery flows.** Magic-link to the verified email is the
  recovery story for MVP. "Lost my passkey *and* lost my email" is
  out of scope — product layer decides whether to offer a support
  channel.
- **Federation between products as IdPs.** Already covered by
  axiom: not an IdP. If yah-platform and noisetable users converge,
  they share a `UserStore`, not an OIDC link.
- **Hardware-attested device identity** (Apple Device Check, Play
  Integrity). Possible later; not MVP. The `DeviceBinding` enum can
  grow variants.

## License audit

All proposed deps audited against [[feedback_permissive_licenses]]:

| Crate | License | Notes |
|---|---|---|
| `oauth2`, `openidconnect` | MIT / Apache-2.0 | Clean |
| `webauthn-rs` | **MPL-2.0** | Exception — used as unmodified dep only. Documented. |
| `pasetors` | MIT | Clean |
| `jsonwebtoken` | MIT | Clean (Apple ES256 secret only) |
| `argon2`, `hmac`, `sha2`, `p256` | MIT / Apache-2.0 (RustCrypto) | Clean |
| `lettre` | MIT / Apache-2.0 | Clean |
| `keyring` | MIT / Apache-2.0 | Clean |
| `security-framework` | MIT / Apache-2.0 | macOS/iOS Keychain bindings |
| `objc2`, `objc2-authentication-services` | MIT | Apple native passkey UI |
| `age` | MIT / Apache-2.0 | Encrypted-file credential store |
| `ctap2` / `authenticator` | **MPL-2.0** | USB security keys (Mozilla). Defer — only Linux fallback. |

Two MPL-2.0 exceptions, both file-level copyleft only (no copyleft
spreads to cheers's own code). Recorded in `deny.toml` with
rationale.

## Why this isn't a fork of Rauthy

Diligence summarized in conversation 2026-05-14:
[Rauthy](https://github.com/sebadob/rauthy) is ~73k LOC of Rust + 10k
LOC SvelteKit, mostly server-shaped (admin UI, OIDC *provider*,
hiqlite/Raft HA, clients table, sessions table, scopes). Forking it
to use as a library means deleting ~80% and reshaping the rest from
`&self` axum-service to `&self` library calls. Net negative vs.
composing primitives.

What we **lift in spirit, not source**:
- Session/refresh rotation pattern (their `sessions.rs` was audited by
  Radically Open Security 2025; the pattern is sound).
- PKCE handling defaults.
- Brute-force / rate-limiting categories (we don't implement these in
  cheers — they belong in the HTTP layer — but we name them in
  product-level docs as "things that need to exist alongside this").

Total cheers surface estimate: ~5-6k LOC, of which ~400 is Apple
Sign In, ~800 is passkey wrapping, ~1500 is the core token codec +
traits + tests, the rest is providers and storage impls.

## References

- [`mesofact.md`](mesofact.md) §"Auth & session contract" — the
  `SessionResolver` trait this crate plugs into.
- [`mesofact-yah-case-study.md`](mesofact-yah-case-study.md) §"Cross-instance
  SSO via cookie domain" — the multi-instance use case.
- [`noisetable-data-tiers.md`](noisetable-data-tiers.md) — defines the
  T0–T4 tiers; cheers's `UserStore` for noisetable lives in T0
  (global ACID) for the user table, T3 for per-user private data.
- `external/xlb/.yah/docs/...` — xlb-net is the LAN-pair transport.
