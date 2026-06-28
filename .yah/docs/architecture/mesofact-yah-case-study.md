# mesofact — yah case study

> **Status**: design draft, 2026-05-14. Three different yah services
> — yah-marketing, yah-platform, and yah-remote-camp — deploying as
> three mesofact instances on a shared substrate
> (yubaba + mesofact + appliances). Companion to
> [mesofact-noisetable-case-study.md](./mesofact-noisetable-case-study.md).
>
> **The framing**: these are *separate services*, not facets of one
> app. They have different teams' worth of concerns, different
> lifecycles, different blast radii. The interesting design question
> is what they *share* — and how much of that sharing falls out of
> the substrate vs. requires per-service work.

## The three services

| Service | Hostname | Modes | Primary sources | Substrate stress |
|---|---|---|---|---|
| **yah-marketing** | `yah.dev` | Mode 1 only | `r2` (marketing assets) | publisher → R2 → CDN baseline |
| **yah-platform** | `yah.com` | Mode 1 + 2 + 3 | `pg` (account_db) + `r2` | session auth, pg tag invalidation, Mode 3 shell |
| **yah-remote-camp** | `camp.yah.dev` | Mode 2 + 3 | `r2` (camp roster) + `rpc` (per-camp data) + `pg` (membership) | `rpc` adapter, R2-as-roster, post-hydration mesh handoff |

Each runs as its own mesofact instance: own `manifest.json`, own
`mesofact.config.toml`, own R2 publish target, own yubaba-managed
deployment. They are not collapsed into one process and not
collapsed into one route table.

## What the substrate gives them for free

The shared substrate — yubaba (orchestration), mesofact (the
rendering binary + `@mesofact/runtime` adapters that wrap
**appliances** — the backend-service tier: sqlite, pg, R2, …),
and the **release** packaging convention layered above — means a
new yah service costs work proportional to its render contract,
not to its operational shape.

1. **One mesofact binary, three instances.** Same Rust proxy, same
   Bun worker pool image, same `@mesofact/runtime` adapter set
   compiled in. A new service is a new manifest + source config, not
   a new build of mesofact.

2. **Yubaba deploys all three identically.** Each service is a
   yubaba workload of the same kind (`mesofact-instance`): build →
   upload to R2 → SIGHUP the proxy. yah-marketing's pipeline and
   yah-remote-camp's pipeline differ only in their input artifacts.

3. **Cross-instance SSO via cookie domain.** All three instances'
   `CookieSessionResolver` reads `yah_session` from `.yah.dev` with
   the yubaba-injected HMAC key. yah-platform mints the cookie at
   OAuth callback; yah-remote-camp (and any future `*.yah.dev`
   service) decodes it without coordination. See
   [§"Auth & session contract"](./mesofact.md#auth--session-contract)
   in the main doc.

4. **One publisher pipeline, three artifact streams.** The Mode 1
   tag-invalidation pipeline (PG `LISTEN/NOTIFY` + R2 events +
   SQLite WAL tail → rerender → CDN purge by tag) runs once per
   instance with the same code. yah-marketing is the thinnest
   exercise; yah-platform's billing pages and yah-remote-camp's
   lobby cards reuse it without per-service plumbing.

5. **Release packaging.** Each service is published as a versioned
   **release** — manifest + source config + yubaba workload spec
   bundled — so deploying yah.com staging is the same gesture as
   deploying yah.dev. The release format sits above mesofact's
   manifest schema; mesofact doesn't need to know how releases are
   bundled. (Spec-only today; see §"What's spec-only".)

## What's per-service

These cannot be shared:

| Thing | Why per-service |
|---|---|
| Manifest (route table) | Different routes, different modes |
| `mesofact.config.toml` (source config) | Different sources, different scopes |
| R2 publish target (bucket + path prefix) | Tag namespaces must not collide; CDN purge by tag is per-bucket |
| Hostname + CDN config | One DNS record, one tunnel per service |
| HMAC signing key for any service-specific artifacts | yah-remote-camp's roster signing key ≠ yah-platform's session-cookie key |

The "single-tenant per instance" rule from
[§"Multi-tenancy posture"](./mesofact.md#multi-tenancy-posture)
applies *per service*, not *per company*. yah runs three instances;
each instance is single-tenant within itself.

## Three services, three load-bearing points

Each service stress-tests a different part of the substrate. The
case study is structured around what each one *teaches us about
mesofact*, not what each one *does* product-wise.

### yah-marketing — the publisher pipeline baseline

Pure Mode 1: `/`, `/docs/*`, `/blog/*`. Source: `r2` for assets. The
build emits HTML keyed by route, the publisher uploads to R2, the
Rust proxy is in the request path only as a fallback (CDN serves
~100% of traffic). No auth, no pg, no scoped sources.

**What it proves**: the entire publisher → R2 → CDN path end-to-end,
without any of the dynamic shapes confusing the test. First service
to ship; first dogfood listed in the main doc as the "first dogfood:
yah.dev marketing page" target.

If yah-marketing is hard to ship, the substrate is broken.

### yah-platform — the SaaS auth + invalidation pipeline

Routes split across all three modes:

- Mode 1: `/`, `/pricing`, `/docs/*` — same shape as yah-marketing.
- Mode 2: `/account`, `/billing`, `/billing/invoices` — auth-gated,
  per-user cache key, short TTL.
- Mode 3: `/fleet`, `/fleet/*` — SPA shell, initial state is the
  fleet snapshot, post-hydration talks to a yah-platform API.

Sources: `pg` (account_db: users, invoices, camp_ownership) + `r2`
(marketing assets).

**Three things this exercises that the others don't**:

1. **yah-platform is the identity provider for the family.** OAuth
   handler is a yubaba endpoint (not a mesofact route). On
   successful login, yubaba mints `yah_session` on `.yah.dev`.
   Every other `*.yah.dev` mesofact instance decodes that cookie
   with the same HMAC key. mesofact stays out of the OAuth
   handshake — the right boundary.

2. **The fleet dashboard inverts the camp roster.** yah-remote-camp
   reads `camp_id → home_warden_url` from R2; yah-platform's `/fleet`
   needs `user_id → [camp_ids]`. Two ways:
   - **(a)** walk the R2 roster filtering by owner — O(camps), no
   - **(b)** a `camp_ownership(user_id, camp_id)` table in `pg`
   yah-platform lands on (b). The R2 roster is a *denormalized
   projection* of pg — yah-platform writes pg, then emits per-camp
   signed manifests to R2 for yah-remote-camp to read. Same data,
   two adapters, picked by access pattern.

3. **Stripe → pg → tag invalidation runs the main doc's spec
   verbatim.** Webhook handler (yubaba-hosted) writes to pg, pg
   `LISTEN/NOTIFY` emits `pg:account_db:invoices:<user>`, mesofact
   publisher subscribes per
   [§"Publisher tag-subscription"](./mesofact.md#publisher-tag-subscription),
   the affected cached Mode 2 entry purges. No yah-specific code.

### yah-remote-camp — the single-host scoped-data case

Routes:

- Mode 2: `/c/:camp` — lobby card, OG image, public-ish preview.
- Mode 3: `/c/:camp/app/*` — the actual dashboard SPA shell.

Sources: `r2` (camp roster) + `rpc` (per-camp data) + `pg`
(membership, read from yah-platform's pg).

`<camp-id>` is the existing `CampId` slug
(`camp:XXXXXXX`, blake3-12 of canonical workspace path —
[`crates/yah/agent-tools/src/camp_id.rs`](../../../../crates/yah/agent-tools/src/camp_id.rs)).
The id is content-addressed, stable across moves, globally unique
without a coordinator. That's the URL.

**Three things this exercises that the others don't**:

1. **A camp's data plane lives on the camp, not in regional
   replicas.** Tickets, sessions, party roster, mesh state all live
   in `.yah/` on the camp's own yubaba node, served today by
   `yah-camp` over a Unix-domain JSON-RPC socket
   ([`app/yah/cli/src/bin/yah-camp.rs`](../../../../app/yah/cli/src/bin/yah-camp.rs)).
   No replica. One node. The mesofact `sqlite` adapter doesn't fit
   (no local file); `pg` doesn't fit (not Postgres). This is what
   motivated adding the **`rpc` adapter** to the main doc — HTTPS
   to a specific host, with the generation token sourced from a
   *paired* roster source.

2. **Mode 3 hydration punches out over Tailscale.** Browser →
   mesofact shell from R2 → hydrate → `https://<camp-host>.<yubaba-tailnet>/api/...`
   over Tailscale-userspace WireGuard (or yubaba's public tunnel).
   mesofact is **out** after hydration. The shell-vs-live split
   from the main doc's Mode 3 spec, demonstrated against a private
   mesh rather than a public API.

3. **The slug → home-yubaba lookup is the only T0-shape need.**
   noisetable needs Cockroach for T0 because billing + org + routing
   share an ACID surface. yah doesn't. The roster is small,
   append-mostly, read-heavy, 30s staleness fine — an R2-stored
   signed manifest satisfies it. This is what motivated the
   `generation_from = "<source>"` config field: the `rpc` adapter's
   per-camp generation token comes from the paired `r2` roster
   source, not from the camp itself. **R2 manifests as T0
   substitute.**

## Fourth surface: yah-rig-dashboard (system service)

The three services above are user-facing products. There's also a
**fourth yah mesofact consumer** that runs as a *system service*
alongside yubaba / Headscale / cloudflared — bundled with the yah
install, deployed per-rig, reachable only on the mesh by default:

- **yah-rig-dashboard** — the "kubernetes-dashboard / Headlamp"
  equivalent for yubaba-managed rigs. One mesofact instance,
  multi-rig fan-out via the `rpc` adapter and a rig roster.
  Modes 1+2+3. Routes parameterized on `(rig?, camp?)`; watchtower
  is the cell view at the rig × camp intersection.

Full design lives at
[`yah/.yah/docs/working/yah-rig-dashboard.md`](../../../../.yah/docs/working/yah-rig-dashboard.md)
— it's primarily a yah-architecture doc (yubaba integration,
system-service deployment taxonomy, bootstrap/CLI fallback) rather
than a mesofact-substrate doc, so it lives in yah's tree.

**Why it matters for this case study set**: it's the **second
`rpc`-adapter consumer** (yah-remote-camp was first), which is what
the main doc said we needed — proof that the adapter abstraction
holds at a second real backend (yubaba's HTTP API, vs. yah-camp's).
Same `generation_from = "<roster>"` pattern; same paired-roster
shape. The adapter is right.

**It's the SPA flavor of mesofact.** Most dashboard routes are
Mode 3 — auth-gated, interactive, per-user data where SSR cache
value is low. Mesofact serves one shell per route with route-
specific initial state; the SPA's client-side router takes over
after hydration. Mode 1 covers static help; Mode 2 isn't used. The
case study is therefore a strong exercise of Mode 3 + the rpc
adapter together.

**Out of scope for mesofact**: yah-desktop loads the **same SPA
bundle** into Tauri's WebView for inline camp-centric panels —
host-agnostic SPA, two delivery mediums (HTTP via mesofact in a
browser; local-file-load via Tauri in desktop). Mesofact's job is
the HTTP side; the Tauri-load path is yah-desktop's own
architecture. Desktop is a hard delivery boundary (download +
launch), not a per-route escalation, so it's not a fourth mesofact
mode. See
[`yah/.yah/docs/working/yah-rig-dashboard.md`](../../../../.yah/docs/working/yah-rig-dashboard.md)
§"yah-desktop surface (same SPA, different delivery)" for the
dashboard-side framing.

## Cross-service interactions

| Direction | What flows | How |
|---|---|---|
| yah-platform → yah-remote-camp | New camp written to `camp_ownership` pg → projected manifest pushed to R2 | yah-platform's publisher emits per-camp `camps/<id>.json` |
| yah-platform → yah-remote-camp | Logged-in user → camp.yah.dev page sees session | shared `yah_session` cookie on `.yah.dev` |
| yah-remote-camp → camp host | SPA fetches live data | direct over yubaba's tailnet, mesofact not in path |
| yah-platform → yah-remote-camp | Per-user attestation tokens for camp auth gates | minted by yah-platform, embedded in `__MESOFACT_STATE__`, presented by SPA to camp's HTTP bridge |

None of these are in the mesofact request path. yah-platform writes
pg + R2; yubaba runs the publisher; yah-remote-camp reads what's
there. The substrate doesn't need a service-to-service protocol —
the protocol is "share the storage tier."

## Adapter mapping across all three

| Logical source | Adapter | Scope | Used by | Notes |
|---|---|---|---|---|
| Marketing assets | `r2` | global | marketing, platform | shared bucket fine; tag namespaces still per-service |
| Account / billing | `pg` | global | platform | per-region read replica fine |
| Camp ownership index | `pg` | global | platform | same `pg` source as account |
| Camp roster | `r2` | global | remote-camp | signed JSON, CDN-cached 30s |
| Camp data (live) | `rpc` | project | remote-camp | `generation_from = "camp_roster"` |
| Stripe webhooks | n/a (yubaba) | n/a | (out of mesofact) | mutates pg → triggers tag invalidation |
| OAuth provider | n/a (yubaba) | n/a | (out of mesofact) | sets `yah_session` cookie |

yah-platform's `pg` adapter and yah-remote-camp's `rpc` adapter both
talk to data that ultimately originates from yah-platform's database
— but mesofact never sees that fanout. yah-platform writes pg;
yah-platform's publisher projects pg→R2; yah-remote-camp reads R2
and live-RPCs the camp host. Three mesofact instances, one logical
data flow.

## What's spec-only today

The case study assumes infrastructure that isn't built. Surfacing the
gaps honestly:

1. **yah-platform doesn't exist as a service.** yah.com is a static
   placeholder. The pg schema, OAuth handler, billing integration,
   fleet API, and camp-ownership table all need to land.

2. **`yah-camp` HTTP bridge.** Today's daemon is Unix-socket
   JSON-RPC only. The recommended shape is yubaba hosts a
   HTTP → unix-socket proxy (TLS termination, rate limiting, and
   attestation verification at the right layer); `yah-camp` stays
   transport-agnostic.

3. **The camp roster writer.** Nothing today emits the per-camp
   R2 manifests. yah-platform is the natural owner.

4. **Per-user yubaba attestations.** Minted by yah-platform,
   verified by yubaba at the camp's HTTP bridge. Phase 2.

5. **The release format itself.** Current yubaba takes a
   `WorkloadSpec`
   ([`crates/yah/yubaba/`](../../../../crates/yah/yubaba/)). A
   release bundle that combines manifest + source-config + workload
   spec is informal today; this case study is the first place it's
   described as a shared convention. Worth elevating to its own
   spec doc once the second release kind appears.

## MVP slice

The minimum to validate "three services, one substrate":

1. **yah-marketing first.** Pure Mode 1 dogfood; identical to the
   main doc's first-dogfood target.
2. **yah-platform Mode 1 next.** `yah.com/pricing`, `yah.com/docs/*`
   — essentially a second yah-marketing on a different hostname.
   Proves multi-instance posture *before* any auth work.
3. **yah-remote-camp Mode 2 lobby with stub `rpc` adapter.** Returns
   mocked camp data while the yubaba HTTP bridge is being built.
   Proves the `rpc` adapter + R2 roster + paired-generation
   pipeline end-to-end.

Three instances running, each yubaba-deployed identically, each
single-tenant, sharing only the cookie domain and the mesofact
binary. **That is the dogfood**: the substrate works because three
genuinely-different services share it without convergence.

After this slice ships, the auth-gated halves (yah-platform Mode 2/3,
yah-remote-camp Mode 3) wait on yah-platform-as-service.

## Things this case study pushed back into the main doc

Already landed in `mesofact.md` on 2026-05-14:

1. **`rpc` adapter** in §"Adapter inventory (MVP)" + Decisions.
2. **`generation_from = "<source>"`** in §"Cache-key composition" —
   the paired roster source pattern that makes R2-as-T0 work.
3. **Single-host caveat** in §"Render axis × source axis" — when the
   data has no replicas, both cross-region options collapse to RPC.
4. **Cross-instance identity** in §"Auth & session contract" —
   shared cookie domain + HMAC key, no SSO protocol needed.

One small refinement remains: §"Multi-tenancy posture" reads as if
"single-tenant per instance" means "one instance per company."
yah runs three. Worth a sentence clarifying that single-tenant is
*per service*, and a single org commonly operates several instances
on one substrate. (Landed alongside this case study.)
