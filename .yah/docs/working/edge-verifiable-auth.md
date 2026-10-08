# Edge-verifiable session auth

**Status:** proposal (2026-05-26). Not yet scheduled into a phase.

**Driver:** yah/mesofact deploys behind a Cloudflare Worker edge in front of
Yubaba-hosted origins (mesofact axum SSR + per-user data). We want the edge to
do cheap, stateless session checks *near the user* — without holding any key
that can mint sessions, and without reaching back to a single origin store on
every request.

## Why the current codec can't be edge-verified

`cheers_core::Codec` today (codec.rs) ships two impls, **both symmetric**:

- `PasetoV4Codec` — v4.local (XChaCha20-Poly1305), encrypted + authenticated.
- `HmacBlobCodec` — HMAC-SHA256, cleartext payload.

A symmetric key both *mints* and *verifies*. So verifying a token at the edge
means shipping the minting key to a CF Worker — turning the edge into a
session-minting authority. If the edge is ever compromised, the blast radius
is "forge any user's session." That is the property we design out.

## The locality contract

Auth has **no cross-session OLTP transaction** — every hot-path check validates
*one* session. That absence of coordination is the license to globalize auth.
It splits into three tiers, distinct from the per-user project DB:

| State | Hot-path op | Locality | Backing |
|---|---|---|---|
| Access token | signature verify (no read) | global / edge — with the **user** | none (stateless token) |
| Revocation set | point membership check, read-mostly | globally replicated, eventually consistent | CF KV cache / Yubaba gossip |
| Refresh chain | rotate + replay-detect (rare, needs consistency) | **homed** — origin/Yubaba, region-pinnable | `RefreshStore` |
| _(Project DB)_ | OLTP, single-writer | regional **home** — with the **data** | per-user SQLite + Litestream |

The one consistency-sensitive auth op (refresh replay detection) is the rare
cold path, so it's homed like the data and never pollutes the global hot path.
Short access-token TTL bounds the revocation propagation window.

## Design — make capabilities physical in the types

### 1. Split mint from verify
Split `Codec` into `TokenVerifier { verify_at(token, now) -> Claims }` (what the
edge depends on) and `TokenMinter { mint(claims) -> token }` (origin only).
Asymmetric impls are **separate types**: `PasetoV4PublicVerifier` (public key)
and `PasetoV4SecretMinter` (secret key). The symmetric codecs impl *both* on one
type — so the signature itself surfaces that a symmetric codec at the edge
carries minting power. The edge can only satisfy `TokenVerifier` with
verify-but-can't-mint via the asymmetric public verifier.

### 2. Asymmetric access-token codec (v4.public / Ed25519)
Add `PasetoV4Public{Minter,Verifier}` over pasetors' `public` module (V4 =
Ed25519). Origin mints with the secret key; edge verifies with the public key.
Tradeoff: v4.public is *signed, not encrypted*, so claims are client-readable —
keep only non-secret claims in the access token (identity + expiry + jti).
Reposition v4.local in the docs as "encrypted claims, origin-only verification."

### 3. Access/refresh as the assembled deployment shape
Two facades, each holding only its tier's capabilities:

- `SessionAuthority` (origin/axum): `{ minter, refresh: RefreshStore, users:
  UserStore, revoke: RevocationWriter }`. Login → short-TTL access token + homed
  refresh token; rotate; revoke.
- `EdgeVerifier` (Worker): `{ verifier: TokenVerifier, revoked: RevocationReader }`.
  Verify + revocation check. **Cannot mint** — it takes a `TokenVerifier`, full stop.

A `SessionPolicy` carries sane TTL defaults (access ≈ minutes, refresh ≈ days).
Add `jti` to `Claims` (`#[non_exhaustive]`, additive) so revocation has a key.

### 4. Revocation as a read/write-split abstraction
Promote store.rs's "the product wires up the check" note into:

- `RevocationWriter { revoke(jti | chain) }` — origin (Yubaba Redis/gossip).
- `RevocationReader { is_revoked(jti) }` — edge (local replica / CF KV).

Eventually-consistent by documented contract; short access TTL is the bound.
`EdgeVerifier` checks the reader; `SessionAuthority` writes on logout/device-revoke.

> **Superseded in part by R732-F6 (2026-10-06).** Entries are now
> `Revoked::{Jti, Device, Membership{kind,id,user}}`; the writer is
> `revoke(&Revoked)` + `snapshot()` over a per-store, strictly monotonic epoch;
> the reader adds `is_device_revoked` / `is_membership_revoked`. The issuer
> signs the current set (`RevocationPublisher`, PASETO v4.public with implicit
> assertion `urn:cheers:artifact:revocation-set:v1`), publishes it at
> `GET /.well-known/revocation-set.json`, and offline peers replicate it with
> `cheers_verify::ReplicatedRevocations`. For standing credentials (noisetable
> W235 §5.1) revocation, not TTL, is the only bound.

### 5. Guide by omission — routing stays out of the identity token
Do **not** add a shard/routing field to `Claims`. Routing metadata (which Yubaba
shard holds a user's data) travels as a separate plaintext hint (cookie /
subdomain) the edge routes on; the origin authoritatively validates entitlement.
Keeping the identity token about identity is the guidance.

### 6. Peer-key binding — the token names the key, not the connection (R515)

§5 says routing metadata stays out of the identity token. A **peer public key**
is the one addition that is *not* metadata-creep, and the distinction is worth
stating because it looks like a counterexample: routing is a hint about where
data lives, while a peer key is a statement about *who holds this token*. It
belongs to identity.

`Claims` carries an optional `peer_key: Option<PeerKey>` — raw bytes plus an
algorithm discriminant (`{"alg": "ed25519", "key": "<base64url-no-pad>"}`),
`skip_serializing_if` so an unbound token is byte-identical to a pre-R515 one.
Not an `ed25519-dalek` type: consumers straddle a real version split (iroh
resolves 3.0.0-pre, other trust crates 2.2), and cheers only ever *compares*
these bytes — it never verifies a signature under them, so it needs no crypto
to hold one.

What it buys: a verifier that has already authenticated the connecting peer
under that key — which a QUIC/TLS handshake does by construction — can prove
**token holder == connecting peer**. Without it a stolen token replays under
the thief's own node key and they become the victim user. Binding *at
presentation* (client signs a challenge with the node key) was rejected: it
needs a live round-trip and a challenge cache, which is exactly the coordination
the locality contract above buys freedom from. Verification stays offline —
`PasetoV4PublicVerifier` against a pinned issuer pubkey plus a byte compare — so
a LAN peer with no internet still checks a week-old token.

Surface:

- mint — `SessionAuthority::establish_bound` / `rotate_bound` (peer key supplied
  by the caller, like `binding`: the refresh chain is about *which session*, so
  a plain `rotate` yields an unbound token rather than a stale binding).
- door — `EdgeVerifier::verify_bound_at(token, presented, now)`: signature,
  then binding, then the revocation read. An **unbound** token fails it; a
  deployment that also admits unbound tokens calls `verify_at` and branches on
  `peer_key` itself, so that choice is visible at the call site.

Not in cheers: the **enrollment ceremony** that populates the field. None of
cheers's HTTP ceremonies can — a browser passkey or magic-link sign-in has no
node key, because the key lives in a different process (a desktop app, a
headless appliance). The flow is "app proves possession of key `N`, presents
the user's existing session, receives a token binding `U` to `N`", and it lives
in the consuming service. cheers ships the field and both sides of the wire.

Layering, for the consumer that drove this (noisetable society rooms): the
Ed25519 roster is layer 1 and remains the *only* admission door. A bound user
token is layer 2 — it may only ADD a claim about which human a machine key
belongs to. It must never become a second way in.

> **Amended by R732-F5 (2026-10-06).** "Still checks a week-old token" above
> was false: a bound access token carries the 15-minute `exp` and the edge
> refuses it after that. The LAN credential is now the standing binding (§7).

### 7. Standing node binding — offline admission lasts until revoked (R732-F5)

Noisetable W235 §0.1: no credential expiry may refuse a working setup when no
fresher credential is reachable. This amends the short-TTL rule (§3) for
**standing edge credentials only**; browser and API access tokens keep 15
minutes.

- **Wire.** `cheers_core::StandingBinding { issuer, sub, device, peer_key, seq,
  iat, jti, <lease> }` — the [Lease](#lease-r734-f5) flattened in, with no
  `exp` today. A `SignedArtifact` with implicit
  assertion `urn:cheers:artifact:standing-binding:v1`, so it never verifies as
  an access token and no access token verifies as it.
- **Mint.** `SessionAuthority::establish_bound` / `rotate_bound` with
  `DeviceBinding::LanPair` return it in `NewSession::standing`, minted by the
  configured `StandingBinder` (issuer key + kid + `BindingSequenceStore`). An
  authority without a binder refuses a bound LanPair session
  (`Error::NoStandingBinder`) instead of handing out only a 15-minute token.
- **Ordering.** `seq` is a per-device sequence on the issuer, advanced by
  `max(prev + 1, now)` in one upsert (`binding_sequences`, migration 0011).
  The clock floor keeps a restored-from-backup issuer above what edges hold.
  Nothing orders bindings by `iat`.
- **Door.** `cheers_verify::StandingVerifier::verify_standing_at(token,
  presented, now)`: issuer signature (pinned key or JWKS issuer-role key), peer
  key equals `presented`, not superseded (`BindingLedger`: highest `seq` seen
  per device, only ever raised), `jti` and device not revoked
  (`ReplicatedRevocations` offline). The lease only sets
  `VerifiedStanding::lease`; see [Lease](#lease-r734-f5).
- **Offline restart.** The edge persists `IssuerTrust::export()`,
  `BindingLedger::export()` and `ReplicatedRevocations::export()` beside its
  bindings and rebuilds from them at boot, never from a fetch it cannot make.
- **Key rotation.** Pre-publish a new issuer kid before it signs; keep a
  retired kid published (verify-only) until every binding it signed is
  superseded or revoked. Removing a kid means compromise and invalidates its
  bindings. Under that rule a fetched JWKS never lacks a kid a held credential
  needs, so retiring a kid never strands a working offline edge.

### 8. Membership snapshot — who holds what on a resource, offline (R732-F4)

The second standing credential of W235 §5.1, under the same §7 rules: no `exp`,
lease advisory ([Lease](#lease-r734-f5)), same offline-restart and
key-rotation rules.

- **Wire.** `cheers_core::SetSnapshot { issuer, kind, id, epoch, members, iat,
  <lease> }`, with `SnapshotMember { user, relation, via }`. Implicit
  assertion `urn:cheers:artifact:set-snapshot:v1`. Members are user
  principals only, closure-expanded (one entry per relation held, so an edge
  checks `member` by exact lookup) and sets flattened, and list only
  relations the schema marks `RelationDef::membership` (R734-B6). `via` lists the
  resources where the user's own direct tuples sit that the relation derives
  from.
- **Epoch.** The issuer's store-wide `ownership_version` (migration 0013),
  advanced to `max(v + 1, now)` in the transaction of every row change.
  `SnapshotIssuer::mint` brackets the closure walk with two reads of it and
  retries on a mismatch, so equal epochs mean equal members.
- **Revocation.** `cheers_server::revoke_ownership` records
  `Revoked::Membership { kind, id, user, at_epoch }` when a user's last
  direct tuple on `(kind, id)` goes; `revoke_principal_ownership` does the
  same for every resource of a deleted user. An edge drops a member entry only when
  every `via` resource is revoked for that user above the snapshot's epoch.
  A demotion or a removed set tuple reaches the edge only in a newer snapshot.
- **Door.** `cheers_verify::SnapshotVerifier::verify_snapshot_at(token, now)`
  checks the issuer signature, then supersession (`SnapshotLedger`: the
  highest epoch seen per resource, only ever raised), then masks members.
  `VerifiedSnapshot::holds(user, relation)` answers admission questions.

### Lease (R734-F5)

One standard for "this credential should be renewed, and maybe lapses".
`cheers_core::Lease { refresh_after, exp: Option }` is flattened into the
artifact, so the wire is `"refresh_after": N` and, only when set, `"exp": N`.
`Lease::new(iat, refresh_after, exp)` builds it; `Lease::state_at(now)` reads
it as `LeaseState`:

| `now` | State |
|---|---|
| `< refresh_after` | `Current` |
| `refresh_after <= now < exp` | `Warning { exp }` |
| `>= exp` | `Expired` (never, when `exp` is `None`) |

A due lease with no `exp` reads `Warning { exp: None }`. When `exp` is set,
`iat < refresh_after <= iat + (exp - iat) / 2`: the holder gets at least half
the lease as warning. Construction (`LeaseError`) and verification
(`StandingError::Lease`, `SnapshotError::Lease`) both refuse a lease that
breaks it; with no `exp` there is no constraint. `VerifiedStanding` and
`VerifiedSnapshot` expose `lease: LeaseState`.

cheers only computes the state; it never notifies anyone. Consumers monitor
`lease` and surface the warning. Standing bindings and snapshots carry no
`exp`. The `Admit` of knock.md (R734-F2, not built yet) is the first artifact
with `exp` set.

## Consumer mapping (yah side)

- mesofact CF Worker (yah **R327**) = `EdgeVerifier` (public key + revocation reader).
- mesofact axum SSR origin = `SessionAuthority` (secret key + stores).
- Yubaba backs `RefreshStore` + `RevocationWriter`; CF KV (or Yubaba gossip) is
  the global `RevocationReader` replica.

## Crate topology

The capability split above (verify vs. mint) is enforced **structurally** — by
the crate dependency DAG, not by feature flags. A feature is additive and can be
set wrong; a missing dependency edge is a compile error. "The edge cannot mint"
is therefore realized as "the edge's crate has no path to a minter type."

### Principle: name crates by capability, not deployment location

`cheers-verify`, not `cheers-edge`. The capability (verify-only) is the invariant
the security model cares about, and it holds wherever the crate is linked;
"edge" is a deployment fact that can drift. The edge is then *defined* as "the
deployment that depends on `cheers-verify` and nothing heavier."

### The DAG (target — R019)

```
cheers-core           identity types (Claims, UserId, DeviceId, Credential),
                      errors, CredentialStore trait, and the TokenMinter /
                      TokenVerifier *traits* (trait defs are keyless → safe to
                      share). No crypto keys, no I/O.
                      ← depended on by: everything

cheers-verify         PasetoV4PublicVerifier (public key), RevocationReader,
  (edge-safe)         EdgeVerifier facade. Verify + revocation-read only.
                      → cheers-core
                      ← edge consumers, cheers-server

cheers-server         PasetoV4SecretMinter (secret key), PasetoV4Codec +
  (origin)            HmacBlobCodec (symmetric — impl BOTH traits, so they MUST
                      live here, never in -verify), UserStore, RefreshStore,
                      RefreshRotator, RevocationWriter, SessionAuthority facade.
                      → cheers-verify → cheers-core
                      ← origin/server consumers

cheers (providers)    OIDC (google / apple / oidc_generic), passkey, email
                      magic-link, password, lan-pair. Resolves *external*
                      identity → User; feature-gated per provider. Does not mint
                      sessions itself.
                      → cheers-core
                      ← origin/server consumers

cheers-store          CredentialStore impls: keyring (cross-platform),
  (client storage)    encrypted-file (headless), in-memory.
                      → cheers-core
                      ← native client consumers

cheers-apple          ASAuthorizationController native UX: Apple Sign In +
  (client native UX)  platform passkey. #[cfg(target_os = "macos" | "ios")].
                      → cheers-core (+ cheers-store)
                      ← mac / ios client consumers

cheers-android        Credential Manager / platform passkey native UX.
  (client native UX)   → cheers-core (+ cheers-store)
                      ← android client consumers.  NOTE: slated as the FIRST
                      dogfood consumer (Android → authenticate into a yah camp),
                      so this is near-term, not "later".
```

The one load-bearing arrow: **`cheers-server` → `cheers-verify`, never the
reverse.** That single direction is what guarantees a verify-only consumer has
no minter in its dependency graph. The symmetric codecs (`PasetoV4Codec`,
`HmacBlobCodec`) impl *both* `TokenMinter` and `TokenVerifier` on one type, so
they live in `cheers-server` — putting them in `cheers-verify` would re-grant
mint to the edge through the back door.

### Consumer → crate mapping (yah side)

| Consumer | Crates |
|---|---|
| **Android (first dogfood)** | `cheers-store` + `cheers-android` |
| mesofact CF Worker (edge) | `cheers-verify` |
| mesofact axum SSR (origin) | `cheers-server` + `cheers` (providers, à la carte) |
| yah-desktop (Tauri Mac) | `cheers-store` + `cheers-apple` (+ `cheers` passkey for the ceremony) |
| noisetable iOS | `cheers-store` + `cheers-apple` |
| noisetable rpi (headless) | `cheers-store` (encrypted-file) + `cheers` (lan-pair) |

### Client tier is a small family, not a leaf

"Client" fans out by **concern** (storage vs. native UX) and **platform family**
(not per-OS):

- **Storage is mostly cross-platform** — the `keyring`-backed `CredentialStore`
  compiles on mac/ios/linux/windows from one `cheers-store`. (Android storage is
  the Keystore/EncryptedSharedPreferences — check whether `keyring` covers it or
  `cheers-android` carries its own backend.) Not a crate per OS.
- **mac + iOS collapse into one `cheers-apple`** — both drive Keychain +
  AuthenticationServices; one crate cross-compiled to two targets under
  `cfg(target_os)`. **Android is its own family** (`cheers-android`, Credential
  Manager) — it shares the `CredentialStore` trait but not the Apple UX.
- **Browser is (probably) not a crate.** Pure-auth browser flows are JS (OAuth
  redirect / `navigator.credentials`) and the session is an httpOnly cookie the
  page can't read — zero Rust, storage is the cookie. Add a browser-Rust crate
  only if a wasm SPA takes custody of a non-httpOnly token (a thin `web-sys`
  storage shim, no auth logic).

### Platform selection: target_os over features

Same principle as capability-by-crate: drive platform code with
`#[cfg(target_os = …)]` (a fact the compiler knows, can't be set wrong), not
`macos`/`ios`/`android` *features* (a convention you can enable on the wrong
target). Keep a feature only for the genuine opt-in — "do I want the heavy
native-UX dep at all" — then e.g.
`cfg(all(feature = "native-passkey", target_os = "android"))`.

### wasm / getrandom (edge build)

`cheers-core` does not build for `wasm32-unknown-unknown` today: `getrandom`
(both 0.3 and 0.4 in the tree, pulled by `pasetors` directly and via
`ed25519-compact`) hard-errors without the `wasm_js` backend. This is **not**
fixed by the verify/mint split — `pasetors` sits in `cheers-verify` too, and the
Ed25519 *verify* path pulls `getrandom` via `ed25519-compact` even though
verification needs no entropy. The fix is to enable `getrandom`'s `wasm_js`
feature (target-gated) for both major versions; the crate split is orthogonal to
wasm-buildability.

### Status

Target topology for R019: **R019-F5** (no-crypto client surface) and
**R019-F6** (verify/server crate split). Today the tree is still the original
two crates (`cheers-core` + `cheers`); F1/F2 landed the asymmetric
verifier/minter *types* inside `cheers-core`, which is the prerequisite for
splitting them into separate crates. `cheers-android` is now near-term (first
dogfood), ahead of the originally-later `cheers-apple`.

## Notes

- Mostly additive to cheers-core; the one refactor is the `Codec` →
  `TokenMinter`/`TokenVerifier` split (cheers is pre-launch, so a breaking trait
  change is fine — a blanket impl keeps the symmetric codecs working).
- Relates to existing work: R007 (codec), R008 (refresh rotation), and the
  platform session work R018 (`yah_session` cookie + `/account/sessions`).
- Suggested quest placement: foundation (Q002) owns the core codec/claims/store
  changes; the driver is the yah-platform edge deployment (Q005). Filed as a
  standalone relay to avoid presuming — slot it where it fits.
