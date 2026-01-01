# noisetable — data tier model

> **Status**: design draft, 2026-04-28. Captures the data tier model
> (T0–T4) that organizes noisetable's data flows: hardware nodes on a
> user's LAN, the cloud project that coordinates them, published
> patches/profile, and the global identity/billing layer.
>
> **Substrate**: noisetable runs on top of yah-managed rigs.
> Provisioning, ingress, mesh identity, and object-storage are yah's
> concern (see [`yah/architecture/yah-managed-rigs-topology.md`](../../../yah/architecture/yah-managed-rigs-topology.md);
> path becomes `ss/yah/architecture/...` after the rs-hack→yah rename).
> This document is strictly noisetable's *application* architecture:
> what data lives where and what its consistency contract is.
>
> **Diagram**: [`.yah/arch/authored/noisetable-data-tiers.mmd`](../.yah/arch/authored/noisetable-data-tiers.mmd)
>
> **Why this is separate from yah's arch**: noisetable is the *first
> customer of yah*, not yah itself. Hardware nodes on a LAN, project
> migration following an org, published patches — these are
> noisetable-app concerns. yah is the substrate that makes the rig
> reachable, identified, and backed up; what runs on the rig is
> application territory.

## Goals

1. **Geo-sharded by default**: most user activity stays in their home
   region. Cross-region calls are rare, explicit, and accepted to be
   slow — *pay in UX, not correctness*.
2. **Hardware nodes on a LAN coordinate via cloud**: the user's actual
   instruments/synths/whatever live on their LAN. The cloud project is
   the trust broker, identity issuer, and durable store; runtime LAN
   traffic does *not* round-trip through cloud once bootstrapped.
3. **Project-as-migration-unit**: a project (`user/default`,
   `user/named`, or `organization/install`) lives in one home region
   at a time. Migration is a deliberate operation, not a runtime
   invariant.
4. **Scale envelope**: 10–20 K projects at GTM, 2–10 M peak. App code
   that works at GTM still works at peak; the storage layout
   underneath is an ops decision.
5. **Bug blast-radius containment** at three layers (compile, network,
   data) — not adversarial security, but defense against typos and
   bad deploys.

## Non-goals

- Strong consistency on the hot path. The only ACID surface is T0
  (billing/identity/routing), and that set is kept tiny.
- Adversarial multi-tenancy. High-trust environment; mTLS via global
  broker is sufficient.
- Cross-project queries at T3. T3 is project-scoped by contract;
  cross-project analytics live at T2 (public) or T4 (aggregated).

## Data tier model (T0–T4)

Five consistency tiers, each maps cleanly to a substrate. Tier is
encoded as both a Headscale tag *and* a Rust phantom-type parameter on
data handles, so cross-tier mistakes are caught at compile time and at
the network.

| Tier | Contract | Substrate | Examples (noisetable) |
|------|----------|-----------|----------|
| **T0** | ACID, globally consistent. Low write, low read. **Keep this set tiny — every item is global write-latency cost.** | One CockroachDB or FoundationDB cluster, 3-region quorum | billing, organization membership, registration status, **project → (home_region, generation)** |
| **T1** | System-published broadcast. Hub-and-spoke. Low write, high read. Doesn't need consensus — needs *signed manifests + CDN*. | NATS JetStream + mirror streams **or** versioned object-storage manifests + signed pull | noisetable app version / OTA, package-registry index (community patches), revocation bloom filters |
| **T2** | User-published, eventually consistent across regions, cache-first read. Low write, high read. | Per-region Postgres + logical replication (mutable rows); per-region object storage + cross-region replication (immutable bytes) | published profile (mutable, per-field LWW), published patches (append-only, no LWW needed), large audio assets |
| **T3** | User-private, single source of truth, **routed to home region**. Stale not OK. Low write, low read. **Source of truth migrates to follow the project.** | Per-region Postgres (schema-per-project at low scale, multi-tenant table + RLS + sharding at high scale) **or** SQLite-per-project via [Turso](https://turso.tech) + [turso-backup](../../../yah/architecture/W195-stateful-service-pattern.md) to object storage | project hardware-node roster, project config, project trust roster (peer pubkeys) |
| **T4** | Telemetry. Stale OK, gossip OK. High write, low read. **Don't actually gossip raw events** — local TSDB, federate at query time. Gossip is for control plane, not data. | VictoriaMetrics / Mimir / Loki per region | hardware-node heartbeat, latency/glitch metrics, CRDT-aggregated LAN-mesh telemetry |

### T2 — metadata and bytes propagate on different paths

"Same tier" does not mean "same path." A profile change is a small
mutable row → replicate via logical replication + per-field LWW.
A new published patch is an append-only manifest pointing at an
immutable byte blob (audio sample / patch file) → replicate the
manifest, replicate-or-pull-on-demand the bytes. Plan for both paths
from day one.

### T3 deep dive — project as the migration unit

The unit of migration is a **project**, not a user. Identifier:
`(scope, project_id)` where
`scope ∈ {user/default, user/named, organization/install}`.

This is the single most important refinement in the design. It means:

- A user with `user/default` in EU and `user/us-experiment` pinned to
  US is normal. Per-project home region, not per-user.
- **Org installs are independently migratable**, which gives GDPR /
  data-residency compliance for free: "this org's install lives in EU,
  we never store its data elsewhere." Checkbox during enterprise
  sales; *rewrite* if not designed for at the start.
- "Pay in UX, not correctness" is the cleanest contract: a hardware
  node in US hitting a project whose home is in EU sees latency, not
  a stale read. The operator decides whether to migrate or to live
  with the cross-region cost.

#### Routing layer

T0 stores `project → (home_region, generation)`. Routing flow:

1. T3 op arrives at any node with `(scope, project_id)` in scope.
2. Node consults locally cached `project → home_region` map (TTL ~30s);
   on miss, reads T0.
3. If local node is in the home region → fast path (local Postgres
   schema or SQLite file).
4. Else → cross-region RPC to home-region replica. Slow but correct.

#### Migration protocol (the one real distributed-systems primitive)

1. Caller initiates `migrate(project_id, from=EU, to=US)`.
2. EU replica drains in-flight ops (timeout if necessary).
3. EU replica copies state to US replica.
4. T0 bumps `(home_region, generation)` from `(EU, n)` to `(US, n+1)`.
   **Generation increment is the linearization point.**
5. EU replica refuses subsequent writes (presents new generation;
   client retries against US).
6. US replica accepts.

Without the generation fence, a stale-cached node could route a write
to the now-defunct EU replica during the propagation window. The fence
makes that case fail loudly, not silently. We are not reinventing the
consensus primitive (Cockroach has range rebalancing, etcd has lease
epochs); we are applying it at project granularity.

### T3 — LAN-mesh as data plane, T3 as control plane

T3 holds the **trusted hardware-node roster** for a project. Once
nodes have read the roster (and received their own short-lived
attestation), they communicate **directly over LAN** without going
back through T3. T3 is *not in the hot path after bootstrap*.

This matters more for noisetable than for typical SaaS: the hardware
nodes are real instruments coordinating in real time. Audio-rate or
near-audio-rate coordination cannot tolerate cloud round-trips. The
cloud project's role is to bootstrap trust, then get out of the way.

This is "lightweight SPIFFE-per-project":

- Each peer presents a short-lived attestation (~5 min) signed by T3.
- Peers verify attestations directly, no per-message T3 round-trip.
- Revocation degrades gracefully: even if push-revocation fails, an
  evicted node is out within the attestation TTL.

Three propagation patterns for revocation, layered:

1. **Short-lived attestations** (always-on floor, 5 min TTL). Same
   trick SPIFFE and Tailscale use.
2. **Push** (T3 emits roster-change events to a fan-out — NATS or
   gossip). Optimization for fast revocation.
3. **Pull** (peers re-check T3 every N min). Fallback for offline.

**Implementation pointer**: `iroh` is purpose-built for this shape —
p2p with discovery via a central directory, QUIC transport,
X25519/Noise auth. T3 plays the directory role. Falling back to
`quinn` directly is fine if iroh's hosted-directory assumptions get in
the way.

### T4 — CRDT-aggregated mesh telemetry

The LAN-mesh produces telemetry as a side effect: nodes don't ship
raw events to T4 sinks; the mesh CRDT-merges locally first
(Yjs/Automerge, `automerge-rs`, `loro`, or hand-rolled per-counter),
then a designated emitter (or all of them, idempotently) pushes the
merged view. Saves bandwidth, kills duplicate-event noise, and the
project_id tag is already on every record so per-tenant T4 queries
trivially filter back through T0 org→project mapping.

For noisetable specifically, this is how audio-glitch detection
reports, end-to-end latency stats, and node uptime aggregate across a
project's hardware mesh without overwhelming the T4 sink.

### T3 storage — scale progression

App code stays project-scoped (every query carries `project_id`,
either via `search_path=schema` or via RLS policy). The storage
layout swaps underneath as scale demands:

| Scale (projects) | Layout | Migration mechanism |
|------------------|--------|---------------------|
| 0 – 50 K (GTM range) | Schema-per-project in a per-region PG cluster | `pg_dump --schema=p_xyz \| psql` |
| 50 K – 1 M | Multi-tenant tables + Postgres RLS + hash partitioning by `project_id` | Selective row export by `project_id` |
| 1 M+ (peak target) | Sharded multi-tenant: `project_id` → shard → PG cluster (Citus or app-layer routing) | Shard-aware export |

**Wildcard option for high scale**: SQLite-per-project via Turso
(embedded `turso_core`, backed by `turso-backup` to object storage)
to object storage. Each project = one `.turso` file. Migration =
`cp` + flip the T0 generation pointer. T3's low-write-per-project
profile never pressures SQLite's single-writer limit. Cross-project
joins don't work, which fits T3's isolation contract *exactly*. The
yah W195 stateful-service pattern documents the backup / restore
protocol; the operational story at 10 M files is appealing.

The decision between PG-with-shards and SQLite-per-project at peak
scale is deferred. Both are reachable from the GTM-scale
schema-per-project starting point with reasonable migration effort.

## Defense in depth — bug blast-radius containment

Three layers, each catches what the layer above missed. Framing: not
adversarial security, but containment of bugs/typos/bad deploys.

1. **Compile time** — Rust phantom types: `Db<Tier::T3, Region::EU>`
   won't unify with `Db<Tier::T0, Region::Global>`. A refactor that
   smears tiers becomes `error[E0308]` instead of an incident.
   Unique-to-Rust win; unusually effective against typo-class bugs.
   Build this layer first — it pays back every refactor.
2. **Network time** — Headscale tag ACLs scoped by
   `(region, tier, service)`. EU service literally cannot open a
   socket to US-billing or to a T0 admin endpoint. Enforced at the
   WireGuard layer, before a packet arrives. (Headscale itself is
   provisioned by yah; the *tag scheme* is noisetable's.)
3. **Data time** — Postgres row-level security + per-tenant DB roles.
   Even if a query somehow runs in the wrong scope, the database
   refuses out-of-tenant rows.

These are cheap (RLS is one `CREATE POLICY` per table; ACLs are
config; phantom types are zero-cost) and each catches a failure mode
the others can't.

## Open questions

- **T0 self-host vs CockroachDB Serverless**: the small ACID set
  fits Serverless free tier comfortably at GTM scale; self-host is a
  future cost optimization, not a day-one decision.
- **CRDT library for T2 profile / T4 mesh-merge**: `automerge-rs`
  has the largest ecosystem; `loro` has the cleanest Rust ergonomics;
  `diamond-types` is fastest. No clear winner.
- **`iroh` vs hand-rolled QUIC mesh**: iroh ships with a hosted
  directory we'd need to bypass (T3 *is* the directory). Either
  configure iroh to use a custom directory, or use `quinn` directly.
- **T3 substrate at peak scale**: schema-per-project is the GTM
  starting point; the schema-vs-row-vs-SQLite decision at 1 M+
  projects is deferred until traffic patterns are real.
- **LAN-side coordination protocol**: is the runtime LAN traffic
  audio-rate (ultra-low-latency, hand-rolled UDP) or
  control-rate-only (fine via QUIC)? Affects whether iroh covers
  everything or only the control plane.
