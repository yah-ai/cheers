# mesofact — noisetable case study

> **Status**: design draft, 2026-05-14. How noisetable's T0–T4 data
> tier model (see [noisetable-data-tiers.md](./noisetable-data-tiers.md))
> maps onto mesofact's render modes + source adapters.
>
> **Why separate**: noisetable is *a* customer of mesofact, not its
> shape. mesofact itself knows only about render modes, sources, and
> tags. T0–T4 is application-tier vocabulary; mapping happens in
> noisetable's own deployment config.

## The two axes

mesofact's render axis (static / SSR / SPA) is orthogonal to
noisetable's data-tier axis (T0–T4), but cells aren't equal.

| | **T0** ACID global | **T1** signed broadcast | **T2** user-published, cache-first | **T3** private, home-region | **T4** telemetry |
|---|---|---|---|---|---|
| **Mode 1**<br/>static, push to R2 | rare (public org listings) | **native fit** — T1 *is* push-to-CDN | **strong fit** — patches/profile pages, rebuild on publish | **forbidden** — private + routed | aggregated daily roll-ups |
| **Mode 2**<br/>SSR, pull, short TTL | login shells, routing pages | redundant — already cached | freshness window < rebuild cadence | **the hard case** — see below | status pages, "live" dashboards |
| **Mode 3**<br/>SPA, direct API | usually no — front via API | direct manifest fetch | direct read | **the app's home** | live via WS/SSE |

## Three things fall out

### 1. T1 and Mode 1 share substrate

Both are "render → signed bytes → CDN → invalidate by tag." The
Mode 1 publisher and a T1 manifest emitter are structurally
identical. **Build them as one thing**: a publisher that emits
versioned signed artifacts to R2, treating "HTML for a marketing
page" and "package-registry index" as two artifact kinds with the
same delivery contract.

In mesofact terms: T1 manifests are an `r2`-adapter output of the
same publisher pipeline that emits Mode 1 HTML. No tier label needed
in the substrate — same publisher, two artifact kinds.

### 2. Mode 2 × T3 is the load-bearing constraint

T3 reads are routed to the project's home region. Any SSR route
that touches T3 either:

- **(a)** runs the Bun pool in every region the proxy serves, and
  the proxy routes to the home-region pool (Bun follows the data), or
- **(b)** runs the pool centrally and pays cross-region RPC on every
  T3 read inside the render (data follows Bun — slow but simpler).

For MVP, **(b) is acceptable** if launch is single-region. The
mesofact seam needed for (a) is already in the contract: sources
have a `scope: "project"` declaration in adapter config, so the
proxy can refuse cross-region during a migration and route to the
right pool when (a) ships.

### 3. Cache keys must include T3 generation

T3 carries `(home_region, generation)` in T0. SSR responses that
read T3 must include that generation in the cache key, or a project
migration leaves stale-from-defunct-region HTML in the Rust LRU.

mesofact's source-generation cache-key input already covers this —
the `sqlite` adapter exposes its generation (file mtime, LSN, or
project-generation token from T0) and the proxy folds it in. Nothing
T-specific in the substrate.

## Noisetable → mesofact source config

Each noisetable tier maps to one or more mesofact source adapters
configured in `mesofact.config.toml`:

| Tier | Adapter kind | `scope` | Notes |
|---|---|---|---|
| T0 (project routing) | not a mesofact source — Rust proxy reads via a separate handle, populates `req.project.home_region` | n/a | T0 is *resolution*, not *data*. Proxy reads it before invoking render. |
| T1 (signed manifests) | `r2` | `global` | Mode 1 publisher emits *as well as* reads from this. |
| T2 (mutable rows, immutable bytes) | `pg` + `r2` | `global` | per-region; LSN feeds source-generation. |
| T3 (project-private routed) | `sqlite` (file or LiteFS replica) or `pg` (RLS-scoped) | `project` | template `{project_id}` in `path` / `schema`. |
| T4 (telemetry) | not a mesofact source — dashboards either Mode 2 (5s TTL via `pg` query of rolled-up rows) or Mode 3 (SPA + WS). | varies | raw telemetry never enters render. |

## MVP implications for noisetable

- **Publisher unification** — one tool, two artifact kinds (Mode 1
  HTML + T1 manifests). Defer the T1 side if scope-pressed, but
  don't build them with incompatible contracts.
- **Bun pool is single-region in MVP** — explicit non-goal to ship
  multi-region (a). Cross-region T3 reads are slow-but-correct.
- **No Mode 1 route reads a `scope: "project"` source** — enforced
  at build time by mesofact, independent of noisetable's tier
  labels.
- **T0 stays behind resolution, not in render** — neither SSR nor
  static reads T0 directly; routing/auth middleware in the Rust
  proxy consults T0 (with a 30 s cached `project → home_region`
  lookup) and hands the result to render via `req.project`.
