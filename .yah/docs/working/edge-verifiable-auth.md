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

### 5. Guide by omission — routing stays out of the identity token
Do **not** add a shard/routing field to `Claims`. Routing metadata (which Yubaba
shard holds a user's data) travels as a separate plaintext hint (cookie /
subdomain) the edge routes on; the origin authoritatively validates entitlement.
Keeping the identity token about identity is the guidance.

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
