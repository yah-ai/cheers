## KG slice

### `<work-item>`
- relay `relay:R020` — line 0
- ticket `ticket:R019-F5` — line 0
- ticket `ticket:R019-F3` — line 0
- relay `relay:R019` — line 0

### `crates/cheers-core/src/lib.rs`
- file `crates/cheers-core/src/lib.rs` — line 1
- mod `crates/cheers-core/src/lib.rs::store` — line 72
- mod `crates/cheers-core/src/lib.rs::principal` — line 71
- mod `crates/cheers-core/src/lib.rs::mcp` — line 70
- mod `crates/cheers-core/src/lib.rs::error` — line 69
- mod `crates/cheers-core/src/lib.rs::delegation` — line 68
- mod `crates/cheers-core/src/lib.rs::codec` — line 67
- mod `crates/cheers-core/src/lib.rs::claims` — line 66

### Cross-references

- anchors: 3
- contains: 7
- parent_item: 2

## Arch doc: .yah/docs/working/mcp-auth-and-ownership.md

_Reference only — read `.yah/docs/working/mcp-auth-and-ownership.md` for full content (over inline budget)._

## Arch doc: .yah/docs/working/edge-verifiable-auth.md

# Edge-verifiable session auth

**Status:** proposal (2026-05-26). Not yet scheduled into a phase.

**Driver:** yah/mesofact deploys behind a Cloudflare Worker edge in front of
Warden-hosted origins (mesofact axum SSR + per-user data). We want the edge to
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
| Revocation set | point membership check, read-mostly | globally replicated, eventually consistent | CF KV cache / Warden gossip |
| Refresh chain | rotate + replay-detect (rare, needs consistency) | **homed** — origin/Warden, region-pinnable | `RefreshStore` |
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

- `RevocationWriter { revoke(jti | chain) }` — origin (Warden Redis/gossip).
- `RevocationReader { is_revoked(jti) }` — edge (local replica / CF KV).

Eventually-consistent by documented contract; short access TTL is the bound.
`EdgeVerifier` checks the reader; `SessionAuthority` writes on logout/device-revoke.

### 5. Guide by omission — routing stays out of the identity token
Do **not** add a shard/routing field to `Claims`. Routing metadata (which Warden
shard holds a user's data) travels as a separate plaintext hint (cookie /
subdomain) the edge routes on; the origin authoritatively validates entitlement.
Keeping the identity token about identity is the guidance.

## Consumer mapping (yah side)

- mesofact CF Worker (yah **R327**) = `EdgeVerifier` (public key + revocation reader).
- mesofact axum SSR origin = `SessionAuthority` (secret key + stores).
- Warden backs `RefreshStore` + `RevocationWriter`; CF KV (or Warden gossip) is
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

## yah SDLC — source-embedded tickets

Work items live as `@yah:` doc-comment annotations in source. There is **no
separate issue tracker**. Launch the kanban UI with `yah board serve` (it
auto-picks a port from the workspace path).

### Lifecycle

| Column | `@yah:status(...)` | Meaning |
|---|---|---|
| **Quests** | (derived) | Coordination relays that own child relays — see below |
| **Open** | `open` | Unclaimed — also holds `.yah/todo.md` entries (pre-ticket inbox) |
| **Active** | `claimed` or `in-progress` | Someone's working on it |
| **Handoff** | `handoff` | Ready for next agent — use `/handoff` |
| **Review** | `review` or `done` | Awaiting sign-off |

Tickets move between columns by editing their `@yah:status(...)` line in
source *or* by drag-and-drop on the UI (the server rewrites the status
line for you under the same transition matrix). Allowed transitions:

- `open → active`
- `active → open | handoff | review`   (`active → open` is the admin undo)
- `handoff → active | review`
- `review → handoff`

Anything else is refused (UI dims the target column; server returns 409).

### SDLC rules

Run `yah board rules` (or the `board.rules` MCP tool) for the canonical
ruleset (Rule01–Rule12 + Col01). Narrow to a situation with
`--context pickup | finishing | new-work | archive | refactor` — or use
`--format terse` for one-line rules. For a planning-agent snapshot
(counts, active owners, handoff queue, smell), run `yah board status`.

High-leverage rules to remember without looking:

- **Rule01** — first edit on pickup is `@yah:status(in-progress)` on the ticket
- **Rule03** — finishing a phase updates the *existing* relay in place (same R-number);
  new R-numbers only for parallel/independent tracks
- **Col01** — three end-states: more work → **Handoff** (same relay, Rule03);
  tasks met but unverified → **Review** + ping user; human signed off →
  archive. Never self-archive on the same turn you set review, and never
  drop finished work back into Active.
- **Rule04** — `status(done)` is staging; archive is the terminal action

### Quests

A quest is a coordination point, not a unit of work. Declare one with
`@yah:kind(quest)` on a relay (`yah board open --kind quest …` allocates a
`Q<n>` ID, e.g. `Q005`); the board also *infers* quest-ness from any relay
that has **bare-R or bare-Q child relays** pointing at it via
`@yah:parent(...)`. Compound sub-tickets (`R007-T1`) never promote their
parent to a quest. The legacy `@yah:kind(epic)` is accepted as an alias.

Tasks/features/bugs **cannot be parented directly to a Q-id quest** —
quests own relays, not leaf tickets. Open a child relay under the quest
first, then attach sub-tickets to that relay.

R-relays and Q-quests share one counter, so a quest can't reuse a number
already taken by a relay (or vice versa) — the prefix shows intent
(work vs. coordination), not a parallel ID space.

Quests get a computed status:

- **active** — at least one child relay is still live (not in `review`)
- **closed** — all children reached `review`/`done` (or have been archived)

Quests live in their own leftmost column. Their own `@yah:status(...)` is
ignored once they qualify as a quest. Archiving a quest while it still has
live children returns a 409 — archive the children first.

### First action on pickup

When an agent claims a ticket, the **first edit** is setting
`@yah:status(in-progress)` on that ticket and saving. That is the claim
signal. Don't start modifying other code until the status line is updated.

### Archiving (not "done")

Tickets don't stay on the board after they ship. Click the `archive` button
on the ticket card — that strips the `@yah:…` annotation lines from source
and appends an audit record to `.yah/events.jsonl`. Treat `status(done)` as
a short-lived staging state, not a resting place.

### The event log

`.yah/events.jsonl` is a derivative audit log (not the source of truth):
`created`, `modified`, `archived`, `disappeared`. The server replays it on
startup and diffs against current source, so tickets that get accidentally
deleted ("clobbered") surface as `disappeared` events and can be restored
from the last-known snapshot.

### Slash commands

- `/comment` — log a progress summary to `.yah/summaries/`
- `/handoff` — write a structured relay for the next agent (`@yah:relay(...)`)
- `/refine` — turn a multi-phase plan into a relay + tickets

If the slash commands aren't available in your harness, each prompt is
also reachable as `yah board prompt <name>` — same content, no install
required.

### Never pick IDs yourself

Two agents running in parallel will race and both pick the same R-number.
Use `yah board open` (file for later) or `yah board claim` (start now) —
both take a file lock, scan source for the next unused ID, and write the
annotation atomically:

```bash
# File for later (Open column, no assignee):
yah board open --kind bug --parent R065 \
  --file packages/yah/ui/src/foo.tsx --title "Short title" \
  --next "First concrete step"

# Start now (Active column, assigned to claude):
yah board claim --kind relay \
  --file src/module.rs --title "Short title" \
  --assignee agent:claude \
  --next "First concrete step"
```

Stdout is the new ID. Two shapes:

- **Bare relay** (`--kind relay` without `--parent`) → `R008`
- **Compound sub-ticket** (`--kind task|feature|bug|spike` with `--parent R007`) →
  suffix mirrors kind: `-T` task, `-F` feature, `-B` bug, `-S` spike. All four
  share one per-relay counter — numbers stay monotonic across kinds.

`--parent` is required for `--kind task|feature|bug|spike` *(when used as
sub-ticket)*. `--kind spike` *without* `--parent` is the exception — it opens
a top-level R-prefixed relay flagged as exploratory. Orphan bare IDs
(`T01`, `F01`, `B01`, `S01`) are rejected: they collide with compound
sub-ticket numbering. For one-off work, `board open --kind relay …` first
and attach the task under it.

**Open or claim a sub-ticket inside the current relay**, don't spin up a
new relay for every chunk. The relay is the baton; sub-tickets are the
incremental checkpoints.

### Card actions

Each ticket card has two small buttons in the top-right:

- **prompt** (or **review** when the card is in the Review column) — copies
  a continuation prompt to the clipboard. For review-column cards the
  prompt is review-mode (verify + approve-or-send-back); for open/handoff
  it's a pickup prompt (`board tickets --prompt <ID>` output).
- **archive** — click once to arm (surfaces `@yah:verify(...)` commands if
  any), click again to commit.

### Where annotations go

The scanner parses Rust with `syn` and only reads doc comments attached to:

- **Module-level** (`//!` at file top, or inside `mod foo { //! … }`)
- **Top-level items** via `///` — `struct`, `enum`, `fn`, `impl` blocks, `mod`

It does **not** read `///` on enum variants, struct fields, methods inside
`impl` blocks, consts, statics, type aliases, or trait items. An annotation
placed there is invisible to the board.

**Default to `//!` at the top of the file.** Use item-level `///` only when
the ticket genuinely tracks one specific top-level item.

### Key annotations

- `@yah:ticket(ID, "title")` / `@yah:relay(ID, "title")` — define the item
- `@yah:kind(feature|bug|task|spike|quest|epic)` — override kind
- `@yah:status(open|claimed|in-progress|handoff|review|done)` — column
- `@yah:assignee(agent:name)` — who's working on it
- `@yah:phase(P1)` / `@yah:parent(R001)` — ordering / hierarchy
- `@yah:handoff("…")` — message for the next agent
- `@yah:next("…")` — concrete next step (repeatable)
- `@yah:verify("…")` — how to confirm done (repeatable; rendered as fenced bash + `&&` smoke test)
- `@yah:gotcha("…")` — pre-existing breakage / traps for the next agent (repeatable)
- `@yah:assumes("…")` — unverified claim baked into the handoff (repeatable)
- `@yah:cleanup("…")` — deferred tech debt (repeatable)
- `@yah:depends_on(ID)` — declare a dependency (cycle detection surfaces as a smell)
- `@arch:see(path/to/doc.md)` — link to architecture docs

## Output conventions

When you reference a file, function, or symbol the user might want to jump to, prefer markdown links with the `yah://` scheme over bare paths:

- `[path/to/file.rs:42](yah://file/path/to/file.rs#L42)` — opens the file in the Architecture tab rooted at that line.
- `[Foo](yah://arch/symbol/Foo)` — re-roots the arch graph on the named symbol.

The renderer turns these into clickable affordances; bare backticked `path:line` chips also work but yah:// links are preferred for prose.

## Board tools

Board MCP tools are namespaced `board.*` (dots, not underscores) — call them directly when present in your tool list; fall back to `yah board …` via Bash otherwise. The tool schemas describe their own arguments — trust those over any table.

Two semantic rules the schemas can't tell you:

- **Move into `handoff`:** update `@yah:handoff(...)` and `@yah:next(...)` annotations in source *first*, then call `board.move {"id": "<ID>", "to_bucket": "handoff"}`. The baton moves with the source, not the card.
- **Read tools** (`board.show`, `board.list_tickets`, `board.list_relays`, `board.ticket_prompt`, `board.validate`, `board.status`, `board.rules`, `board.summary`) auto-pass the approval gate. **Write tools** (`board.claim`, `board.open`, `board.move`, `board.archive`, `board.update`, `board.promote_next`, `board.promote`, `board.comment`) route through it.

## Environment quirks

- **`mcp__yah__ask_user`** is the canonical user-choice affordance: use it for structured multiple-choice prompts (multi-option, multi-select, or multi-question forms). Do NOT use it for single free-form questions — just print those into chat. `AskUserQuestion` is not wired up in this host.
- **Tool-use approvals** (Bash, Write, etc.) route through the AnswerQueue UI via `--permission-prompt-tool mcp__yah__approve_tool`; a Continue/Revise modal will appear in the desktop panel. To minimize Revise round-trips: name the target in the call's `description` ("Read app/yah/cli/src/main.rs" beats "Read file" — the user pattern-matches on description before clicking Continue); scope paths narrowly (`rg "foo" crates/yah/board/` is approvable, unbounded `rg "foo"` is a Revise); don't pre-stage destructive shapes (`rm -rf`, `git reset --hard`, `find … -delete`, `--no-verify`) unless the user has authorized that exact operation — they escalate to a hard review even when the target is harmless.
- **Grep `type: "tsx"` returns zero results silently.** claude-cli's Grep wraps ripgrep, which only knows `ts` (covers `.ts` and `.tsx`). Use `type: "ts"` or `glob: "**/*.tsx"`. If a Grep you expect to match returns nothing, recheck the type field before concluding the pattern is absent.

## Character dispatch

When the user writes **`@<Name>`** (any capitalized token after `@`), it is a **character reference**. Don't grep the source tree, don't ToolSearch — dispatch directly:

1. *(optional, only when you suspect a typo)* call `mcp__yah__camp_roster` once. **One call max.** It returns the live character list.
2. call `mcp__yah__party_dispatch` with `target: {character: "<Name>"}, prompt: "..."`. Use `mcp__yah__party_assist` instead if the user said "help me with X" (it blocks for the child's first turn); same target shape.

If `<Name>` isn't provisioned in this camp, the tool returns an error listing the available characters plus a "did you mean…" suggestion. **Trust the tool's error** — surface it to the user with the suggestion. The roster is the source of truth; do not open files looking for the character.

### `#subclass` (capability tag) — when the user didn't name anyone

When delegating by capability (search, analysis, exploration) and the user did not name a person, pass `target: {subclass: "<id>"}` instead. Built-ins:

- `subclass: "explorer"` — Read/Grep/Glob; cheap; file discovery.
- `subclass: "searcher"` — Grep/Glob only; cheapest; single-pass search.
- `subclass: "analyst"` — Read/Grep/Glob; mid tier; synthesis across many files.

For auto-dispatch (yah picks), omit `target` and add `hints`: `["cheap"]` (soft rank lowest cost), `["reasoning"]` (require extended thinking — hard filter), `["large_context"]` (require ≥32K window — hard filter).

### Rules

- **Never pass a sigil** (e.g. `yah-quill-0`). yah allocates slots; agents must not name them.
- The dispatch receipt returns `{ session_id, slot_slug }` — use `session_id` for all follow-up calls.
- `mcp__yah__subagent_spawn` is **deprecated** — prefer `party.dispatch` / `party.assist`. The legacy verb still works but the schema and error shapes are unmaintained.

The dispatched character runs as a separate yah session — the user sees it in their party and can follow along.

After the child finishes, read its structured findings with `mcp__yah__subagent_corpus_shape { session_id }` (substrate inventory) and `mcp__yah__subagent_query { session_id, substrate: "markdown", query: "<pattern>" }` (substring search across notes).

**If you are a child** (dispatched to serve another agent): write your findings as `.md` files to `.yah/subagents/<session_id>/notes/` using `write_arch_doc` or `edit_file` before your final turn. Your session id is in the `YAH_SESSION_ID` environment variable.

# Ticket: R020 — MCP auth and ownership — principal kinds, ownership table, mint paths, audit

- **id**: `R020`
- **status**: handoff
- **source**: `crates/cheers-core/src/lib.rs:1`
- **slot**: slot:bundle-anthropic-ashguard:2

## Gotchas (read first)

- This relay PRODUCES the wire contract that yah's constable consumes. Any wire-shape change here is a coordinated change with yah's R426/R427/R428 — flag the yah-side relay in any handoff.
- ownership:write and audit:write are kind=service ONLY. The grant API must reject (principal_kind=user, scope=ownership:write|audit:write) at write time, not just at mint.

## Next steps

- Resolve wire-envelope open question (PASETO v4.public vs JWT/Ed25519) in the -S1 spike before any mint-path ticket starts.
- Land foundation tickets (principal kinds, scope vocab, ownership table) in cheers-core/cheers-server before mint paths.
- Mint paths, admin endpoints, JWKS, audit can ship in parallel once the foundation is in.

## Verify

- cargo test -p cheers-core && cargo test -p cheers-server && cargo test -p cheers-verify

## Assumptions (challenge if wrong)

- R019-F5/F6 crate split is effectively landed (in review) — MCP-token mint paths bolt onto cheers-server's signer; cheers-verify verifies them unchanged.
- yah-side consumer spec (W159) keeps the wire claim shapes verbatim with this doc (act, owns, camp_id, auth_strength).
