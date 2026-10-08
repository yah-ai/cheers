<!--
@yah:ticket(R732-T10, "Revocation set privacy: membership entries in the public GET /.well-known/revocation-set.json are plaintext (kind, id, user)")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-ashguard)
@yah:at(2026-10-07T16:48:31Z)
@yah:parent(R732)
@yah:next("Tier: Warrior. Touches the Revoked::Membership and SetSnapshot wire, adds a per-resource key store with a migration, and reshapes the membership reader API.")
@yah:next("OPERATOR DECISION (2026-10-07): A2, a KEYED hash. Rejected: A1, a plain H(kind,id,user). Its inputs are low-entropy, so anyone with a room id and a list of candidate users can confirm removals offline. B (keep plaintext) leaves removals readable. C (put the route behind auth) breaks offline edges, which cannot authenticate, and society gossip redistributes the set anyway.")
@yah:next("Design: the server stores stay plaintext. Each (kind,id) resource gets a random 32-byte revocation key, held server-side and created on first use (get-or-create on snapshot mint or membership revoke). The published entry becomes {\"membership\":{\"tag\":b64(HMAC-SHA256(key, ctx || len-prefixed kind,id,user)),\"at_epoch\":..}}; hmac and sha2 are already deps of cheers-server. at_epoch stays in clear. Jti and Device entries are unchanged.")
@yah:next("SetSnapshot carries the key for its own resource AND for every resource named in any member's via. Masks inherit from parent namespaces (crate::snapshot), so without the parent's key an edge cannot test a derived member. ReplicatedRevocations indexes membership entries by tag. is_membership_revoked takes the resource key (or the precomputed tag) instead of plaintext kind/id, and cheers-verify snapshot.rs is_masked supplies it from the snapshot.")
@yah:next("Migration: 0014 is the next free number after 0013_ownership_version; re-check before landing. Use sqlite + pg + a byte-identical turso copy + a version bump in cheers-turso migrate.rs, as T7 did.")
@yah:gotcha("Insiders are not protected. Anyone holding a room's snapshot holds its key and can read that room's removals, and a removed member keeps the key. Accepted: insiders see the roster change through snapshot epochs anyway. Key rotation is out of scope. Because the server holds plaintext, a rotation would only re-tag entries on the next publish.")
@yah:gotcha("If a resource's key changes, revocation fails OPEN without any error. Snapshots never expire, so an edge keeps testing with the old key and no new tag will match. Make the key immutable once created. Get-or-create must be insert-or-ignore followed by a reread, so two concurrent creators converge on one key. Store the keys in the same database as the ownership rows, so a restore cannot separate the two. A restore is already fatal on its own terms, since edges reject the regressed epoch as Stale. Operator gate (2026-10-07): if this design turns out to cost correctness or performance, fall back to A1, a plain hash; A1's weakness is acceptable.")
@yah:gotcha("A key must never reach the public revocation-set route or any unauthenticated route. As of 2026-10-07, cheers-axum has no public snapshot route; keep it that way.")
@yah:gotcha("Breaking for noisetable R803: SetSnapshot gains the keys, and RevocationReader::is_membership_revoked changes signature. Tell the R803 leader when this lands.")
@yah:handoff("A2 landed. cheers-core: new RevocationKey, MembershipTag and wire RevocationEntry (membership = {tag, at_epoch}). Revoked stays the plaintext store-side row, and RevocationSet.revoked is now Vec<RevocationEntry>. SetSnapshot gains revocation_keys: Vec<ResourceRevocationKey> (sorted, plus revocation_key(kind,id)), and SetSnapshot::new takes the keys before iat.")
@yah:handoff("cheers-verify: membership_tag() is HMAC-SHA256(key, urn:cheers:revocation:membership-tag:v1 || u64-BE len-prefixed kind,id,user), and revocation_entry() converts a store row to its wire form. ReplicatedRevocations indexes memberships by tag. RevocationReader::is_membership_revoked(key, kind, id, user, epoch) gained a leading &RevocationKey: plaintext origin stores ignore it and the replica tags with it. SnapshotVerifier::is_masked takes each via key from the snapshot. A via with no key is refused with SnapshotError::MissingRevocationKey; it is never admitted, which would fail open.")
@yah:handoff("cheers-server: OwnershipStore::revocation_key(kind,id) does get-or-create via insert-or-ignore plus reread. It is immutable and does not advance the ownership version. new_revocation_key() uses getrandom. It is implemented for memory, sqlx pg+sqlite, turso, and the Arc/axum/Racing delegates. RevocationPublisher::new(store, keys: Arc<dyn OwnershipStore>, minter, issuer, kid) tags memberships on publish. SnapshotIssuer::mint embeds keys for the resource and every via resource.")
@yah:handoff("Migration 0014_revocation_keys: (resource_kind, resource_id) PK, key BLOB/BYTEA CHECK len=32. It is in sqlx sqlite + pg, has a byte-identical turso copy, and is registered as version 14 in cheers-turso migrate.rs. Departure from the ticket text: is_membership_revoked keeps kind/id/user beside the key, because the tag is computed over them and origin stores hold plaintext. The key is never on any unauthenticated route; cheers-axum still has no snapshot route.")
@yah:handoff("BREAKING for noisetable R803: (1) SetSnapshot has a new revocation_keys field and the SetSnapshot::new arity changed. (2) RevocationReader::is_membership_revoked takes &RevocationKey first. (3) RevocationSet.revoked is Vec<RevocationEntry>, and membership entries carry a tag, not plaintext. (4) RevocationPublisher::new takes an ownership store. (5) OwnershipStore has a new required method, revocation_key. Tell the R803 leader.")
@yah:verify("cd oss/cheers && cargo test --workspace: 825 passed, 0 failed, 4 ignored (doctests). This includes the new revocation_key scenario on memory, turso and sqlite, publisher tag privacy, the replica tag lookup, MissingRevocationKey refusal, and tag length-prefix collision tests.")
@yah:verify("The pg suite (cheers-sqlx tests/pg.rs ownership_store_revocation_key) did not run here, since it needs a live Postgres. Run it against PG before archiving.")
@yah:verify("PG SUITE EXECUTED 2026-10-07 against real Postgres (testcontainers, throwaway container, local OrbStack docker): `DOCKER_HOST=unix://$HOME/.orbstack/run/docker.sock cargo test -p cheers-sqlx --features pg-integration --test pg` = 23 passed / 0 failed (incl. ownership_store_revocation_key from migration 0014). Log /tmp/r732t10_pg_run2.log. Without DOCKER_HOST all 23 fail at container start (no /var/run/docker.sock; OrbStack socket is ~/.orbstack/run/docker.sock). No source edits.")
@yah:gotcha("Turso pgwire: NOT available at pinned turso 0.7.2 — turso_core-0.7.2 source has no pgwire/wire-protocol server (grep clean; only SQL-level 'postgres' mentions), no tursodb binary installed, no repo script/doc starts one. Moot anyway: tests/pg.rs hard-codes testcontainers Postgres (no DATABASE_URL/env override), gated by feature pg-integration. Hosts with OrbStack need DOCKER_HOST set to run it.")
-->

<!--
@yah:ticket(R732-T7, "C6 followup: jti revocation entries carry the access token's exp so gc prunes them and the published revocation set stays bounded")
@yah:status(review)
@yah:at(2026-10-07T07:15:43Z)
@yah:assignee(agent:bundle-anthropic-ashguard)
@yah:parent(R732)
@yah:next("Tier: Warrior — leader made every design call below; the work is a signature change threaded through every revocation store, plus one migration")
@yah:next("SCOPE WIDENED BY THE R732 LEADER (2026-10-06): one pass gives every Revoked variant its bound, because all three share one row codec and one migration. (1) Jti { jti, exp: Option<i64> }: Some(exp) for access tokens and user tokens with an expiry, gc drops the row once exp <= now (the F6 UNBOUNDED GROWTH gotcha). None for credentials with no exp (standing bindings, non-expiring user tokens), which never lapse. (2) Device { device, at_seq: u64 } masks only standing bindings with seq < at_seq, so re-enrolling the same machine mints seq > at_seq and is admitted again. This is the F5 DEVICE REVOKE vs RE-ENROLL gotcha. (3) Membership { kind, id, user, at_epoch: u64 } masks only snapshots of (kind,id) with epoch < at_epoch, which is F4's leader decision moved here. Nothing records Membership entries until F4.")
@yah:next("Identity vs bound: a row is keyed by (kind, subject, resource_kind, resource_id) exactly as today, and holds ONE bound. Re-revoking the same identity upserts bound = MAX(old, new); the epoch advances only when a row was inserted or its bound rose. Redis must key by identity, not by the full Revoked JSON (today contains() matches the exact zset member, which breaks once the bound is in the JSON). Use a hash of identity -> bound beside the lapse zset, or equivalent, Lua-atomic as now.")
@yah:next("Reader API (cheers-verify revocation.rs:60-71 + Arc blanket + every impl): is_device_revoked(device, seq: u64) = an entry exists with seq < at_seq. is_membership_revoked(kind, id, user, snapshot_epoch: u64) = an entry exists with snapshot_epoch < at_epoch. is_revoked(jti) unchanged, except a lapsed jti (exp <= now) may read as unrevoked. StandingVerifier (cheers-verify standing.rs:254) passes binding.seq. ReplicatedRevocations indexes by identity -> bound.")
@yah:next("Writer side: SessionAuthority::revoke_device (cheers-server session.rs:520) takes at_seq from the binder's BindingSequenceStore::next_binding_seq(device, now). That CONSUMES a sequence number, so every earlier binding sits below it and every later one above it, with no read-then-write race. With no binder configured, the authority has minted no standing bindings and so has none to end: record no Device entry, and say so in the doc comment. revoke_session(jti) becomes revoke_session(jti, exp: i64) for access tokens (me.rs:436 has claims.exp). Add a way to revoke a standing binding by jti with exp None (session.rs:1339's test revokes b.binding.jti). cheers-axum tokens.rs:628 and :778 pass the user-token row's expiry (None if it has none).")
@yah:next("Migration 0012 (sqlx sqlite + pg + turso byte-identical copy + cheers-turso migrate.rs version 12): add the bound column to revocations, then write the jti exp into the existing expires_at column. LEGACY ROWS: existing device/membership rows meant 'masks everything', so migrate them to bound = i64::MAX (fail-closed) and document it; legacy jti rows keep expires_at NULL (never lapse). Re-check that 0012 is free at finish, because F4 takes 0013 after you.")
@yah:next("gc + publish: gc drops jti rows with expires_at <= now and advances the epoch iff it deleted anything (as today). RevocationSet / snapshot omits jtis lapsed at mint time (give snapshot or the publisher a now). Wire shape: {\"jti\":{\"jti\":..,\"exp\":..|null}}, {\"device\":{\"device\":..,\"at_seq\":..}}, {\"membership\":{\"kind\",\"id\",\"user\",\"at_epoch\"}}. Update cheers-core revocation.rs tests and the RevocationSet sort/dedup (dedup by identity keeping the max bound).")
@yah:next("Tests to add: device revoked at S refuses a binding at seq < S and admits a re-enrolled binding > S, at both the server-store and StandingVerifier levels; re-revoke raises the bound and advances the epoch while an equal or lower re-revoke does not; membership masks below at_epoch only; jti with exp lapses from gc and from the published set while exp None never lapses; the 0012 legacy-row migration on sqlite and turso; store_scenarios revocation scenario extended for all four engines (pg/redis --no-run).")
@yah:gotcha("Fenced from R732-F8, which runs concurrently: F8 edits cheers-axum ownership.rs and adds a NEW test module. This ticket must not edit cheers-axum/src/ownership.rs or tests/main.rs. The one revoke() call in tests/ownership_basic.rs is yours to update. While your reshape is half-landed the workspace will be red for F8. Land the type change and its call-site fixes in one push rather than leaving it red across turns.")
@yah:gotcha("R732-F4 runs after this ticket and consumes the Membership at_epoch and is_membership_revoked(.., snapshot_epoch). Keep those signatures exactly as specified in next so F4 needs no reshape.")
@yah:depends_on(R732-F5)
@yah:depends_on(R732-F6)
@yah:handoff("WIRE (cheers-core revocation.rs): Revoked = Jti{jti, exp: Option<i64>} | Device{device, at_seq: u64} | Membership{kind,id,user,at_epoch: u64}; externally tagged snake_case, e.g. {\"jti\":{\"jti\":..,\"exp\":..|null}}. Constructors jti(j, exp), device(d, at_seq), membership(k, id, u, at_epoch). New Revoked::identity() (variant + subject fields, no bound), cmp_bound() (for a jti, None ranks above any exp), is_lapsed_at(now). RevocationSet::new sorts by identity and dedups keeping the max bound.")
@yah:handoff("READER (cheers-verify): is_device_revoked(device, seq) is true iff an entry has seq < at_seq. is_membership_revoked(kind,id,user,snapshot_epoch) is true iff snapshot_epoch < at_epoch. is_revoked(jti) keeps its signature. Updated the Arc blanket impl. ReplicatedRevocations now indexes HashMaps of identity -> bound. StandingVerifier passes binding.seq.")
@yah:handoff("WRITER (cheers-server): RevokedColumns{kind,subject,resource_kind,resource_id,bound,expires_at} is the shared codec, exported from lib.rs. revoked_from_columns takes (.., bound, expires_at), and a device or membership row with a NULL bound is an error. RevocationWriter::revoke keeps the max bound and advances the epoch only on insert or a bound raise. RevocationPublisher::current(now) omits jtis lapsed at now. MemoryRevocationStore is keyed by identity and gained gc(now). StandingBinder::revocation_seq(device, now) consumes next_binding_seq. SessionAuthority::revoke_device(user, device, now) records Device{at_seq} only when a binder is configured and is a documented no-op entry otherwise. revoke_session(jti, exp: i64) writes Some(exp). The new revoke_standing_binding(jti) writes exp None.")
@yah:handoff("STORES: sqlx pg and sqlite use an upsert ON CONFLICT DO UPDATE ... WHERE <raises> (bound > old, or for a jti old expires_at NOT NULL and new is NULL or larger), and rows_affected gates advance_epoch in the same tx. Readers fetch (bound, expires_at). Turso reads the held bound, decides raises, then runs a transaction of the same upsert plus the epoch. Readers go through a private HeldQuery trait over TursoConn/ReadOnlyConn. Redis is re-keyed by identity: hash {p}:revocations identity -> entry JSON, hash {p}:revocations:rank identity -> rank ('inf' for jti None), zset {p}:revocations:lapse identity -> exp (jtis with exp only), plus epoch. REVOKE_LUA and GC_LUA stay atomic. with_revoke_ttl_seconds and DEFAULT_REVOKE_TTL_SECONDS are DELETED because a jti now carries its own exp.")
@yah:handoff("MIGRATION 0012_revocation_bounds.sql: sqlite (bound INTEGER), pg (bound BIGINT), and a turso copy byte-identical to sqlite (checked with cmp), registered as version 12 in cheers-turso migrate.rs. Legacy device and membership rows get bound = i64::MAX (fail-closed, documented in the SQL). Legacy jtis keep expires_at NULL. 0012 is ours and 0013 is still free for R732-F4.")
@yah:handoff("CALL SITES: cheers-axum me.rs passes now and claims.expires_at. tokens.rs:628/778 pass Some(row.expires_at); UserTokenRecord.expires_at is non-optional, so None never arises there. revocation_set.rs passes current(now_unix()). admin.rs NoopRevoked updated. The tests updated are tokens_basic.rs, ownership_basic.rs (the one revoke call only), test-support lib.rs:261, and session.rs tests. cheers-redis gained cheers-test-support as a dev-dep so redis runs the shared scenario. Did NOT touch cheers-axum ownership.rs or tests/main.rs (F8).")
@yah:handoff("TESTS ADDED/EXTENDED: core wire shape, dedup-by-identity-max, lapse. verify: replica masks below bound only; StandingVerifier refuses seq < at_seq and admits a re-enrolled seq. server: bound-raise/epoch rule, memory gc, published set omits lapsed jtis. session: revoke_device without a binder writes no entry; with a binder at_seq > the old binding.seq, the old binding is refused offline, re-enroll is admitted, and the server store agrees seq-for-seq. store_scenarios::revocation_writer_and_reader is rewritten for bounds and runs on sqlite, turso, pg and redis. 0012 legacy migration on sqlite (tests/sqlite.rs) and turso (src/revocation.rs). gc lapse on sqlite, turso, memory and redis.")
@yah:verify("cargo check --workspace --all-targets: clean (one pre-existing unused `policy` warning in cheers-test-support lib.rs:223, not ours)")
@yah:verify("cargo test --workspace --no-fail-fast: 793 pass / 0 fail / 4 ignored vs baseline 777/0/4 (+16; includes new T7 tests and possibly F8's concurrent additions)")
@yah:verify("cargo test -p cheers-sqlx --features pg,sqlite --no-run: ok; cargo test -p cheers-redis --features redis-integration --no-run: ok (pg/redis not executed, Docker)")
-->

<!--
@yah:ticket(R732-F6, "C6: revocation set — an issuer-signed, epoch-ordered list of revoked jtis, devices and (resource, user) memberships that offline peers replicate by gossip; cheers-verify ships a replica RevocationReader that adopts the highest epoch")
@yah:status(review)
@yah:at(2026-10-07T06:10:36Z)
@yah:assignee(agent:bundle-anthropic-glimmerstone)
@yah:parent(R732)
@yah:next("Tier: Wizard — the one way standing credentials end; ordering and domain separation matter")
@yah:next("Shape: RevocationSet { issuer, epoch, revoked: [Jti | Device | Membership(kind,id,user)] }, PASETO v4.public under the issuer key with its own implicit assertion; cheers-server publishes the current set (a route); cheers-verify adds ReplicatedRevocations: adopt(set) refuses lower epochs, implements RevocationReader (revocation.rs:40) for jti/device and answers membership revocations for C4.")
@yah:next("Replaces noisetable's NoRevocationReplica (society user_token.rs:244), whose doc says the bound on a revoked token is its expiry; with standing credentials (C4, C5) revocation becomes the only bound. Consumer: noisetable W235 N13 (gossip on the edge). The accepted cost: a removed member keeps a fully offline LAN until a set naming them reaches it.")
@yah:handoff("WIRE SHAPE (cheers-core/src/revocation.rs): RevocationSet { issuer: String, epoch: u64, revoked: Vec<Revoked> }, Revoked = Jti(String) | Device(DeviceId) | Membership { kind, id, user: UserId } (user spelled like Claims.sub). Serde externally tagged snake_case: {\"jti\":\"..\"} / {\"device\":\"..\"} / {\"membership\":{\"kind\":..,\"id\":..,\"user\":..}}. RevocationSet::new sorts+dedups so a set's bytes are a function of its contents. Signed as PASETO v4.public, flat JSON payload, footer {\"kid\":..} (same envelope as mint_mcp).")
@yah:handoff("DOMAIN SEPARATION (new house pattern, cheers-core/src/artifact.rs): trait SignedArtifact { const IMPLICIT_ASSERTION; fn issuer() }. Every existing token (Claims, McpClaims, ceilings, client assertions) signs with the EMPTY implicit assertion; an artifact binds its own non-empty one, so it fails signature verification on every access-token path and vice versa. RevocationSet's assertion = b\"urn:cheers:artifact:revocation-set:v1\". F4/F5 should impl SignedArtifact with urn:cheers:artifact:<kind>:v1. Mint: PasetoV4SecretMinter::mint_artifact(&T, kid) (cheers-server/src/codec.rs). Verify: KeySetVerifier::verify_artifact::<T> (issuer-role key only, payload issuer == key owner, no clock) / PasetoV4PublicVerifier::verify_artifact::<T> (pinned), both wrapped by cheers_verify::IssuerTrust { pinned(issuer, key) | key_set(issuer, KeySetVerifier) }::verify::<T>() which also checks issuer == trusted issuer.")
@yah:handoff("SERVER (cheers-server/src/revocation.rs): RevocationWriter is now { revoke(&Revoked), snapshot() -> RevocationSnapshot{epoch, revoked} }. Extended the existing jti store rather than a parallel one: every store (MemoryRevocationStore NEW in cheers-server, sqlx pg+sqlite, turso, redis) holds all three kinds plus one epoch. Epoch = per store (a store is one issuer's log), advanced by next_epoch = max(epoch+1, now_unix) in the SAME transaction as an insert that actually added a row (idempotent re-revoke leaves it); gc advances it only when it deleted something. Clock floor is deliberate: a store restored from an older backup still issues epochs above what replicas hold (a plain counter would restart below them and every replica would refuse every new set). snapshot() is ONE statement (revocation_epoch LEFT JOIN revocations ON 1=1) so epoch and contents agree under PG READ COMMITTED too. RevocationPublisher::new(store, PasetoV4SecretMinter, issuer, kid).current() -> SignedRevocationSet{epoch, token}. SessionAuthority::revoke_session -> Revoked::Jti; revoke_device now ALSO records Revoked::Device (session.rs). Shared SQL row codec: revoked_columns / revoked_from_columns / epoch_from_sql.")
@yah:handoff("MIGRATIONS 0010_revocation_set.sql (F1 took 0009): sqlx sqlite + turso sqlite rebuild revocations as (kind CHECK in jti/device/membership, subject, resource_kind '', resource_id '', revoked_at, expires_at) PK(kind,subject,resource_kind,resource_id), legacy rows copied as kind='jti'; pg renames jti->subject, adds columns, swaps revocations_pkey; all add revocation_epoch(singleton=1, epoch) seeded 0. Turso entry appended as version 10 in cheers-turso/src/migrate.rs. Redis: zset {prefix}:revocations (member = Revoked JSON, score = lapse time: now+revoke_ttl for jtis, +inf for devices/memberships) + {prefix}:revocations:epoch; revoke and gc are Lua-atomic; is_* treat a lapsed jti as unrevoked; snapshot is MULTI GET+ZRANGE; new RedisRevocationStore::gc(now).")
@yah:handoff("VERIFY SIDE (cheers-verify/src/revocation.rs): RevocationReader gained is_device_revoked(&DeviceId) and is_membership_revoked(kind, id, &UserId) as required trait methods (every implementor fixed: sqlx, turso store+reader, redis, MemoryRevocationStore, ReplicatedRevocations, axum admin.rs NoopRevoked) plus blanket impl for Arc<T>. ReplicatedRevocations::new(IssuerTrust); adopt(token) -> Ok(Advanced{from,to}) | Ok(Unchanged{epoch}) on equal epoch | Err(Stale{held,offered}) on lower | Err(Verify(VerifyError)); verify runs outside the lock, epoch compare+Arc swap under a short std RwLock, so concurrent adopts linearise on epoch and readers never block on crypto. Persistence: export() -> Option<String> (the signed token itself); import = adopt(bytes), which re-verifies. epoch() accessor.")
@yah:handoff("PUBLISH ROUTE (cheers-axum/src/revocation_set.rs, exported as revocation_set_router / REVOCATION_SET_PATH / RevocationSetBody): GET /.well-known/revocation-set.json -> {issuer, epoch, set: <token>}, strong ETag (jwks::strong_etag made pub(crate)), If-None-Match -> 304, Cache-Control: no-cache, unauthenticated like JWKS. Placed in cheers-axum because cheers-server has no HTTP layer; signing lives in cheers-server's RevocationPublisher.")
@yah:handoff("API FOR F4/F5: F5 verify_standing_at -> reader.is_device_revoked(&device) + reader.is_revoked(jti) on any RevocationReader (ReplicatedRevocations at the edge); binding type impls SignedArtifact, minted with mint_artifact, verified with IssuerTrust::verify. F4 -> reader.is_membership_revoked(kind, id, &user) per member; server side records RevocationWriter::revoke(&Revoked::membership(kind, id, user)).")
@yah:handoff("NOISETABLE SWAP POINT (not edited, separate camp; noisetable pins crates.io cheers 0.8.32/0.8.43-pre.1 with no [patch], so nothing breaks until it bumps): society crates/society/core/src/net/user_token.rs:256 `impl cheers_verify::RevocationReader for NoRevocationReplica` -> replace with Arc<ReplicatedRevocations> (IssuerTrust::pinned or key_set over the account issuer), fed by GET /.well-known/revocation-set.json + N13 gossip, persisted via export()/adopt(). Also web/services/issues/src/auth.rs:101 has its own NoRevocationReplica: on bump it must implement is_device_revoked/is_membership_revoked or swap the same way. The account service (web/services/account) mounts cheers_axum::revocation_set_router(Arc<RevocationPublisher<TursoRevocationStore>>).")
@yah:handoff("TESTS vs BASELINE (measured before editing): cheers-server unit 175 -> 180, proptest 9, golden 5, doctests 2 (all pass); cheers-verify unit 24 -> 33, golden 10 (all pass); 0 failures before and after. Also green: cheers-core 100 unit + 2 doctests; cheers-axum lib 70 (2 new route tests) + tests/main 78 + doctests 10/3 ignored; cheers-sqlx --features sqlite tests/sqlite 20 (extended revocation scenario on real SQLite); cheers-turso --lib 22 (2 new: 0010 legacy-jti migration + gc epoch); cheers-sqlx --features pg,sqlite and cheers-redis --features redis-integration compile (--no-run; need Docker to run). Coverage: signature + domain separation both directions, lower/equal epoch, jti/device/membership queries, non-issuer-role keys (assertion, self-signer) refused, foreign issuer refused, pinned + JWKS trust, export/import round trip incl. tampered bytes, concurrent adopt/read, publish route incl. 304 and stale replay.")
@yah:handoff("EXTRA WORK OUTSIDE THE TITLE: test-support mem.rs MemRevocations deleted (MemoryRevocationStore replaces it; test-support lib.rs rig updated); cheers-server session.rs test MemRevocations deleted; axum tests/common/mod.rs MemRevocations is now `pub use cheers_server::MemoryRevocationStore as MemRevocations` (test-local name kept so the nine *_basic.rs files a live peer may be editing need no rename); one-line revoke() call edits in axum tests ownership_basic.rs:260 and tokens_basic.rs:688 and src/tokens.rs (2 sites); store_scenarios.rs revocation scenario extended; edge-verifiable-auth.md section 4 annotated as superseded in part.")
@yah:verify("cd oss/cheers && cargo test -p cheers-core -p cheers-verify -p cheers-server   # expect server unit 180, verify unit 33, 0 failed")
@yah:verify("cd oss/cheers && cargo test -p cheers-axum   # lib includes revocation_set::tests (publish route)")
@yah:verify("cd oss/cheers && cargo test -p cheers-sqlx --features sqlite --test sqlite && cargo test -p cheers-turso   # store_scenarios::revocation_writer_and_reader on both SQL engines")
@yah:verify("cd oss/cheers && cargo test -p cheers-sqlx --features pg,sqlite --no-run && cargo test -p cheers-redis --features redis-integration --no-run   # pg/redis need Docker to actually run")
@yah:gotcha("MEMBERSHIP RE-GRANT (F4 must decide): a Revoked::Membership entry has no epoch bound, so if a removed user is later re-added to the same (kind, id) the set keeps naming them and an F4 replica would drop them from every later snapshot. Either the grant door deletes the entry on re-grant (needs a writer `lift`, which would advance the epoch), or the entry carries the resource epoch it was revoked at (snapshots above it re-admit). Same question for a DeviceId if device ids are ever reused. Nothing records Membership entries yet: the D4 door (cheers-axum ownership router / F3 self-revocation) should record one when a user's LAST tuple on a resource goes, not on every tuple revoke. Not wired here because that router is F1/F3 territory.")
@yah:gotcha("PUBLIC SET LEAKS MEMBERSHIP REMOVALS: GET /.well-known/revocation-set.json is unauthenticated like the JWKS, and Membership entries carry plaintext user ids and resource ids. If that is unacceptable it is an operator call: mount it behind auth, or publish H(kind,id,user) and have replicas hash their query.")
@yah:gotcha("UNBOUNDED GROWTH: SQL stores record jtis with expires_at NULL (RevocationWriter::revoke takes no expiry), so gc never prunes them and the signed set grows forever. Fix: carry the access token's exp into the jti entry so gc can drop it (redis already lapses jtis by revoke_ttl).")
@yah:gotcha("KEY ROTATION vs OFFLINE RESTART: import = adopt re-verifies, so an edge that restarts offline after the issuer retired the kid that signed its persisted set comes back with an empty replica (fail-open on revocations) until it fetches a newer set. Keep retired issuer keys in the JWKS longer than the set propagation window.")
@yah:handoff("\"FINAL CHECK (after @Glimmerstone:dove landed their turso.rs:127 fix): `cargo check --workspace --all-targets` green. `cargo test -p cheers-turso` green: lib 22, tests/turso.rs 24 (the shared revocation_writer_and_reader scenario passes on turso too), plus 5/2/1 in the other targets. Clippy on the crates I touched shows nothing in my files. The only remaining warning, unused `policy` at cheers-test-support/src/lib.rs:223, was there before this ticket. No git writes made: git policy is defer.\"")
@yah:handoff("Courier @Glimmerstone:coffee (session:5ec71e48): a signed RevocationSet with its own implicit assertion (urn:cheers:artifact:revocation-set:v1), the SignedArtifact domain-separation pattern, a per-store epoch that only moves up across memory/sqlx/turso/redis with migration 0010, RevocationPublisher plus GET /.well-known/revocation-set.json, and ReplicatedRevocations + IssuerTrust in cheers-verify. RevocationReader gained is_device_revoked and is_membership_revoked. Leader dispositions of the four gotchas: MEMBERSHIP RE-GRANT is decided and routed to R732-F4 (a Membership entry carries the ownership_version its removal produced and masks only snapshots below it; F4 also makes the door record the entry when a user's last tuple on a resource goes). UNBOUNDED GROWTH is filed as R732-F7. KEY ROTATION vs OFFLINE RESTART is routed to R732-F5 (the edge persists its key set with its standing credentials). The PUBLIC SET PRIVACY call is held for the operator at relay end; the route stays public like JWKS until then.")
@yah:verify("Leader re-run on the shared tree (with R732-F2 in flight): cargo test for cheers-core, cheers-verify, cheers-server, cheers-axum and cheers-turso gives 553 pass / 0 fail / 3 ignored, exit 0; cheers-sqlx --features sqlite --test sqlite gives 20/0, exit 0.")
-->

<!--
@yah:ticket(R732-F5, "C5: standing node binding — a LanPair binding attestation (user to node key) distinct from the 15-min access token, with no edge-enforced expiry, superseded by a newer binding for the same device and ended only by revocation")
@yah:status(review)
@yah:at(2026-10-07T06:43:33Z)
@yah:assignee(agent:bundle-anthropic-glimmerstone)
@yah:parent(R732)
@yah:next("Tier: Wizard — changes the validity semantics of a credential the offline edge trusts")
@yah:next("Today establish_bound mints a 15-min session token for DeviceBinding::LanPair (cheers-server/src/session.rs:473; default policy :173) and the edge rejects it once exp <= now (cheers-verify public_verifier.rs:151, :174; key_set.rs:164). Add a standing binding: claims {sub, device, peer_key, iat, jti, refresh_after}, its own implicit assertion, minted by establish_bound for LanPair alongside or instead of the access token; cheers-verify gains verify_standing_at = signature + peer-key binding + not revoked (C6) + not superseded, treating refresh_after as advisory.")
@yah:next("Noisetable consumers: account node-token route (web/services/account/src/node_token.rs mint_at) returns it; society R792-B18 presents last-known-good; R792-B19 stops lapsing proofs at exp. Spec: noisetable W235 §0.1, §5.")
@yah:gotcha("Sequenced after R732-F6 by the R732 leader: verify_standing_at's 'not revoked' check consumes F6's device/jti revocation surface in cheers-verify (revocation.rs), and both tickets edit cheers-verify's verifier modules — build on F6's ReplicatedRevocations rather than racing it.")
@yah:depends_on(R732-F6)
@yah:handoff("WIRE SHAPE (cheers-core/src/standing.rs, exported as cheers_core::StandingBinding): { issuer: String, sub: UserId (spelled like Claims.sub), device: DeviceId, peer_key: PeerKey ({alg,key} same as Claims.peer_key), seq: u64, iat: i64, jti: String, refresh_after: i64 } and NO exp. issuer is required by SignedArtifact (payload issuer == key owner == trusted issuer); seq carries supersession. Helpers is_bound_to(&PeerKey), is_refresh_due_at(now). SignedArtifact with IMPLICIT_ASSERTION = urn:cheers:artifact:standing-binding:v1; minted via PasetoV4SecretMinter::mint_artifact, flat JSON payload + {kid} footer.")
@yah:handoff("ISSUER (cheers-server/src/standing.rs): trait BindingSequenceStore { next_binding_seq(&DeviceId, now) -> u64 } atomic, keyed by device ALONE (a node re-bound to another user still supersedes). pub fn next_binding_seq(prev, now) = max(prev.unwrap_or(0)+1, now) - the F6 clock-floored rule, so a restored-from-backup issuer mints above what edges hold. MemoryBindingSequenceStore (cheers-server), SqliteBindingSequenceStore + PgBindingSequenceStore (cheers-sqlx/src/binding_sequence_store.rs), TursoBindingSequenceStore (cheers-turso, also AccountStores::binding_sequences()). Each is ONE upsert ... ON CONFLICT(device_id) DO UPDATE SET seq = MAX/GREATEST(seq+1, excluded.seq) RETURNING seq (turso 0.7.2 supports both; verified by test). StandingBinder::new(seq_store, PasetoV4SecretMinter, issuer, kid).with_refresh_after(secs) (default 7 days) .mint(sub, device, peer_key, now) -> SignedStandingBinding { binding, token }.")
@yah:handoff("MIGRATION 0011_binding_sequences.sql (sqlx sqlite, sqlx pg, turso byte-identical copy + migrate.rs version 11): CREATE TABLE binding_sequences (device_id TEXT PRIMARY KEY, seq INTEGER/BIGINT NOT NULL). 0011 re-checked free at finish (no other 0011 in any of the three dirs). Assumes noisetable W124 section 8 (no new tables in the account DB) covers product tables, not cheers-owned migrations - F6's 0010 added revocation_epoch the same way.")
@yah:handoff("SESSION (cheers-server/src/session.rs): SessionAuthority gains Option<StandingBinder> via with_standing_binder(binder) (no new generic, so every axum handler type and construction site is untouched). NewSession gains `standing: Option<SignedStandingBinding>`, Some exactly for peer-key-bound DeviceBinding::LanPair (establish_bound AND rotate_bound - a rotation that re-keys the node gets a successor binding with a higher seq). Access token unchanged (still 15 min). A bound LanPair request on an authority with no binder refuses with new cheers_core::Error::NoStandingBinder BEFORE anything is written (establish: no refresh root; rotate_bound: token unspent) - decided over silently degrading to a 15-min token, which is the bug this ticket removes. Plain establish/rotate (no peer key) and non-LanPair bindings get None.")
@yah:handoff("EDGE (cheers-verify/src/standing.rs): StandingVerifier<Rd: RevocationReader>::new(IssuerTrust, Rd) with verify_standing_at(token, presented: &PeerKey, now) -> Result<VerifiedStanding{binding, refresh_due}, StandingError>. Order: IssuerTrust::verify::<StandingBinding> (pinned or JWKS issuer-role only, issuer match) -> ledger.observe(seq) -> peer key == presented (PeerKeyMismatch) -> not superseded (Superseded{device,newest,offered}) -> RevocationReader::is_revoked(jti) (Revoked) -> is_device_revoked(device) (DeviceRevoked). refresh_after only sets refresh_due, never refuses; now is used for nothing else. adopt(token) = verify signature + record seq, for bindings heard by gossip. BindingLedger: highest seq per device, every update a max (lower seq after higher, or an older import, cannot un-supersede); export() -> LedgerDoc {issuer, newest: {device: seq}}, import(&doc) merges by max and refuses a foreign issuer (ForeignLedger). The ledger holds no tokens, so a key rotation cannot erase supersession knowledge.")
@yah:handoff("KEY SET PERSISTENCE: KeySetVerifier::key_set() -> Arc<KeySet> (static set or the JwksCache's current one; KeySet::doc() already existed). IssuerTrust::export() -> TrustDoc {issuer, anchor: AnchorDoc::Pinned(b64url) | AnchorDoc::KeySet(JwksDoc)} and IssuerTrust::from_doc(TrustDoc) -> static trust that never fetches. EDGE RULE FOR KEY ROTATION: (1) pre-publish a new issuer kid in the JWKS before it signs anything; (2) keep a retired kid published, verify-only, until every standing binding it signed is superseded or revoked - removing a kid means compromise and deliberately invalidates its bindings; (3) the edge persists IssuerTrust::export() + BindingLedger::export() + ReplicatedRevocations::export() beside its binding tokens and at boot rebuilds from them (IssuerTrust::from_doc, ledger import, re-adopt the set), never from a fetch it cannot make. Under (2) a fetched JWKS never lacks a kid a held credential needs, so replacing the persisted trust with a fetched one is always safe and retiring a kid never strands a working offline edge. refresh_after (7d) bounds how long an online fleet keeps bindings under a kid that stopped signing. This also answers F6's KEY ROTATION gotcha for the revocation set.")
@yah:handoff("FILES: new cheers-core/src/standing.rs, cheers-verify/src/standing.rs, cheers-server/src/standing.rs, cheers-sqlx/src/binding_sequence_store.rs, cheers-turso/src/binding_sequence_store.rs, 3x migrations 0011. Edited: cheers-core lib.rs (mod+export), error.rs (NoStandingBinder); cheers-verify lib.rs, artifact.rs (TrustDoc/AnchorDoc, export/from_doc), key_set.rs (key_set()); cheers-server lib.rs, session.rs (binder field, NewSession.standing, mint_standing, rig + 6 tests); cheers-sqlx lib.rs, tests/sqlite.rs, tests/pg.rs; cheers-turso lib.rs, migrate.rs, tests/turso.rs; cheers-test-support store_scenarios.rs (binding_sequence_store scenario); .yah/docs/working/edge-verifiable-auth.md (new section 7 + amendment note on section 6, whose 'still checks a week-old token' line was false). Stayed out of schema.rs, grants.rs, mcp_authority.rs and the axum ownership router. No git writes (policy defer).")
@yah:handoff("TESTS vs BASELINE (both measured on this tree): cargo check --workspace --all-targets exit 0 before and after (only warning both times: pre-existing unused `policy` at cheers-test-support/src/lib.rs:223). cargo test --workspace 736 pass / 0 fail / 4 ignored -> 777 / 0 / 4. Mine = 28: cheers-core +3 (wire shape, refresh advisory, assertion distinct), cheers-verify 33 -> 47 (+14), cheers-server +9 (3 standing.rs + 6 session.rs), sqlx sqlite +1, turso.rs +1 (migrations_match_cheers_sqlx drift guard green with 0011). The other +13 (core +10, axum tests/main +2, server +1) are the concurrent R732-F2 courier's. cargo test -p cheers-sqlx --features pg,sqlite --no-run exit 0 (pg scenario needs Docker to run).")
@yah:handoff("COVERAGE MAP: years later = verify a_binding_verifies_years_after_any_access_window + server a_lan_pair_session_carries_a_standing_binding_that_outlives_its_access_token (iat 1000, now +10y; same session's access token refused Expired at that time); refresh_after past = refresh_after_in_the_past_still_verifies; wrong peer key = a_wrong_peer_key_is_refused (+ server); revoked jti / device = a_revoked_jti_is_refused, a_revoked_device_is_refused, server revocation_is_what_ends_a_standing_binding_at_an_offline_edge (revoke_device / revoke_session -> RevocationPublisher -> ReplicatedRevocations); superseded + successor = a_superseded_binding_is_refused_and_its_successor_accepted, a_successor_heard_by_gossip_supersedes_without_being_presented, server re_enrolling_a_device_supersedes..., rotate_bound_mints_a_successor_binding; lower seq does not un-supersede = a_lower_sequence_adopted_after_a_higher_one_does_not_unsupersede (adopt + stale ledger import); domain separation both ways = a_binding_is_refused_as_an_access_token (KeySetVerifier::verify, verify_mcp_at, verify_at) + an_access_token_or_other_artifact_is_refused_as_a_binding (empty assertion, McpClaims, cheers-claim session payload, revocation-set assertion); non-issuer role = a_non_issuer_role_key_is_refused (assertion, self-signer, foreign issuer); ledger round trip = ledger_export_import_round_trips; offline restart = an_offline_restart_verifies_against_the_persisted_key_set (persist trust+ledger+set, rotated JWKS refuses UnknownKid, rebuilt-from-doc edge admits, supersession and role rules survive) + a_pinned_trust_round_trips_through_its_document; misconfig = lan_pair_without_a_binder_refuses_before_anything_is_written; sequences = next_seq_is_clock_floored_and_strictly_monotonic, memory_store_advances_per_device, store scenario binding_sequence_store on sqlite/turso/pg.")
@yah:handoff("NOISETABLE SWAP POINTS (not edited, separate camp): (a) web/services/account: AppState's SessionAuthority must call .with_standing_binder(StandingBinder::new(AccountStores::binding_sequences(), <issuer-key minter>, <issuer>, <issuer-role kid>)) or every node-token mint fails NoStandingBinder after the bump; node_token.rs mint_at returns session.standing (token + seq + refresh_after) in NodeTokenBody beside the access token. (b) society R792-B18: the node persists its last-known-good binding token and presents it (Hello::user_claim or a new field); the peer side swaps EdgeVerifier::verify_bound_at for StandingVerifier::verify_standing_at with IssuerTrust over the account issuer and its ReplicatedRevocations replica, gossiping bindings into StandingVerifier::adopt. (c) R792-B19: stop lapsing proofs at exp - a standing binding has none; persist IssuerTrust::export / BindingLedger::export / ReplicatedRevocations::export and rebuild at boot per the key-rotation rule above.")
@yah:verify("cd oss/cheers && cargo test -p cheers-core -p cheers-verify -p cheers-server --lib   # standing::tests in all three + session::tests R732-F5 block; expect verify lib 47, 0 failed")
@yah:verify("cd oss/cheers && cargo test -p cheers-turso && cargo test -p cheers-sqlx --features sqlite --test sqlite   # binding_sequence_store scenario + migrations_match_cheers_sqlx with 0011")
@yah:verify("cd oss/cheers && cargo test -p cheers-sqlx --features pg,sqlite --no-run   # pg binding_sequence_store compiles; needs Docker to run")
@yah:verify("cd oss/cheers && cargo check --workspace --all-targets && cargo test --workspace   # courier run: 777 pass / 0 fail / 4 ignored (baseline 736/0/4), exit 0")
@yah:gotcha("DEVICE REVOKE vs RE-ENROLL (leader/operator call, mirrors F4's membership re-grant): Revoked::Device carries no bound, and noisetable derives the device id from the node key (node:<hex>). So once a node's device is revoked, re-enrolling the SAME machine mints a binding the edge refuses forever (DeviceRevoked) - and the revocation set never shrinks it. Suggested fix, same shape as F4's decision: Revoked::Device carries the binding seq current at revocation (BindingSequenceStore can report it) and masks only bindings at or below it; a higher-seq binding re-admits. Not done here: it changes F6's wire shape and all four revocation stores (+ a migration) while F6 is in review.")
@yah:gotcha("Two concurrent issuers sharing one device id but separate sequence stores (e.g. two account cells) could mint equal seqs; the ledger treats equal seq as not superseded. One issuer = one sequence store, same as one revocation log per issuer.")
@yah:handoff("Leader sign-off request: StandingBinding, StandingBinder with migration 0011 binding_sequences, StandingVerifier with its BindingLedger, and IssuerTrust export/from_doc have all landed (see the courier handoff above). DEVICE REVOKE vs RE-ENROLL is decided, not dropped. It moved into R732-T7, which now reshapes every Revoked variant to carry its bound: Device {device, at_seq} masks only bindings with seq < at_seq, and revoke_device consumes at_seq from the binder's BindingSequenceStore, so re-enrolling the same machine re-admits it. It is the same store codec and migration as T7's jti exp and F4's membership at_epoch, so a single pass makes a single migration.")
@yah:verify("Leader re-run 2026-10-06: cargo check --workspace --all-targets EXIT=0; cargo test --workspace 777 pass / 0 fail / 4 ignored EXIT=0, matching the courier's 777/0/4. That includes session::tests::a_lan_pair_session_carries_a_standing_binding_that_outlives_its_access_token and standing::tests::a_revoked_device_is_refused.")
-->

<!--
@yah:ticket(R732-F4, "C4: SetSnapshot — an issuer-signed membership snapshot with no edge-enforced expiry: store-wide ownership_version epoch, advisory refresh_after, superseded only by a higher epoch, mint from live tuples and offline verify")
@yah:status(review)
@yah:at(2026-10-07T07:40:53Z)
@yah:assignee(agent:bundle-anthropic-glimmerstone)
@yah:parent(R732)
@yah:next("Tier: Wizard — new signed artifact under the issuer key; domain separation and validity semantics matter")
@yah:next("Shape: SetSnapshot { resource:(kind,id), epoch, members:[(UserId, relation)], iat, refresh_after }. NO exp: a verifier never refuses it for age. It stops counting only when the verifier has seen a higher epoch for the same resource or a revocation set (C6) that names it. refresh_after only tells holders when to fetch a fresher one if reachable. PASETO v4.public with its own implicit assertion; members spelled like Claims.sub.")
@yah:next("epoch needs the per-resource monotonic ownership_version D2 deferred (product-scopes...md:165); timestamps are not a safe epoch. cheers-server mints closure-expanded with sets flattened; cheers-verify verifies against the pinned key or JWKS (D5). Spec: noisetable W235 §5.")
@yah:gotcha("Sequenced after R732-F3 by the R732 leader: this ticket must also make the D4 door (cheers-axum ownership router, or a cheers-server service it calls) record Revoked::Membership{kind, id, user, at_epoch} when a user's LAST live tuple on a resource is revoked, by admin revoke or by F3's holder self-revoke. Nothing records membership entries today (R732-F6 handoff). F3 edits the same router hunks, so it lands first.")
@yah:next("Also land R732-F2's deferred index in the same ownership migration: `ix_ownership_resource ON ownership(resource_kind, resource_id) WHERE revoked_at IS NULL` on sqlx sqlite + pg and turso, registered in cheers-turso migrate.rs. The door's holds/may_grant down-walk calls list_for_resource once per node and full-scans without it. Mint the snapshot through `SchemaRegistry::members(&OwnershipTuples(&*store), kind, id)` (R732-F2 handoff), which already flattens sets and folds the closure.")
@yah:next("The Revoked reshape moved to R732-T7, which lands first and gives Revoked::Membership { kind, id, user, at_epoch } and is_membership_revoked(kind, id, user, snapshot_epoch). This ticket only RECORDS the entry: the door writes Revoked::membership(kind, id, user, at_epoch) with at_epoch = the ownership_version the removal produced. A snapshot verifier drops a member iff is_membership_revoked(kind, id, user, snapshot.epoch). Take migration 0013 (T7 takes 0012) for ownership_version + ix_ownership_resource.")
@yah:depends_on(R732-F3)
@yah:depends_on(R732-F8)
@yah:depends_on(R732-T7)
@yah:handoff("WIRE (cheers-core/src/snapshot.rs, exported SetSnapshot + SnapshotMember): SetSnapshot { issuer, kind, id, epoch: u64, members: Vec<SnapshotMember>, iat, refresh_after } with NO exp; SnapshotMember { user: UserId (spelled like Claims.sub), relation, via: Vec<(kind, id)> } (JSON via = [[kind,id],..]). SetSnapshot::new sorts members by (user, relation) and sorts+dedups each via, so equal memberships encode to equal bytes. Helpers lists(user, rel), is_refresh_due_at(now). SignedArtifact with IMPLICIT_ASSERTION urn:cheers:artifact:set-snapshot:v1; minted with PasetoV4SecretMinter::mint_artifact. Module doc states the accepted mask rule: only a user's LAST direct tuple on a resource is recorded; demotions and removed set tuples reach edges only through a newer snapshot.")
@yah:handoff("SCHEMA (cheers-core/src/schema.rs): SchemaRegistry::members now returns Vec<Member { principal, relation, via: BTreeSet<(kind,id)> }> (Member exported); no parallel fn. via = every resource where one of P's direct tuples sits that the walk reached for that relation (the resource itself for a direct holder, the set's resource for an inherited one). credit() takes the row's resource. New test via_is_exactly_the_direct_tuples_whose_loss_ends_a_member cross-checks over the 300 seeded random graphs that revoking P's direct tuples on all of via ends (P, r) and sparing any single one keeps it (asserts >20 multi-via members). The random-graph generator was extracted to random_graphs() and is shared with up_and_down_walks_agree_on_random_graphs.")
@yah:handoff("VERSION SEMANTICS (cheers-server/src/ownership.rs): ONE store-wide ownership_version; pub fn next_ownership_version(prev, now) = max(prev+1, now). OwnershipStore::insert -> Result<Inserted { row, version }>; revoke_by_id -> Result<u64> = the version this revoke produced, or the CURRENT version when the row was already revoked (a no-op that advances nothing); new current_version(). revoke_by_principal ALSO advances once when it sweeps anything (discovered: without it the account-deletion cascade would change contents at an equal epoch). Every advance is in the same transaction as the row change: sqlx pg/sqlite begin a tx, UPDATE ownership_version SET version = GREATEST/MAX(version + 1, now) RETURNING version; turso uses a new TursoConn::transaction_rows with a new Unit::Query (the bump is conditioned WHERE EXISTS(live row) so a no-op advances nothing; the sweep count is read inside the tx). `now` is the caller's clock, as for granted_at. New pub MemoryOwnershipStore (one lock per write), exported with Inserted and next_ownership_version.")
@yah:handoff("MIGRATION 0013_ownership_version.sql (sqlx sqlite, sqlx pg, turso copy byte-identical by cmp, registered as version 13 in cheers-turso migrate.rs): singleton ownership_version(singleton=1, version) seeded 0, plus R732-F2's ix_ownership_resource ON ownership(resource_kind, resource_id) WHERE revoked_at IS NULL. turso 0.7.2 ACCEPTS the partial index (0009 already used one; the turso suite and migrations_match_cheers_sqlx are green with 0013), so it is partial in all three. F2's PERF residual is struck; that entry also carried an optional 'batch list_for_subject_sets' note, dropped with it.")
@yah:handoff("RECORDING (cheers-server/src/snapshot.rs, exported revoke_ownership): revoke_ownership(store, revocations, id, now) -> version. get row (NotFound), revoke_by_id -> V, then iff the subject is a USER principal and that user holds no other live direct tuple on (kind, id), RevocationWriter::revoke(Revoked::membership(kind, id, user, V)). Tuple first, then the entry; an entry failure returns the error (tuple already gone: online sees it at once, offline edges keep the user until a fresher snapshot), and re-running the call heals it (no-op revoke returns the current version, entry recorded there, which is safe because any snapshot below it listing the user through this resource predates the removal). The axum DELETE door (cheers-axum ownership.rs revoke) now calls it after may_revoke; OwnershipState gained `revocations: Arc<dyn RevocationWriter>`. Direct revoke_by_id callers (enrollment.rs node rows) and revoke_by_principal record nothing, by design and documented.")
@yah:handoff("SERVER MINT (cheers-server/src/snapshot.rs): SnapshotIssuer::new(store: impl OwnershipStore, Arc<SchemaRegistry>, PasetoV4SecretMinter, issuer, kid).with_refresh_after(secs) (default 7 days) .mint(kind, id, now) -> SignedSetSnapshot { snapshot, token }. v1 = current_version, members(OwnershipTuples), v2 = current_version; v1 != v2 retries up to MINT_ATTEMPTS = 5, then new cheers_core::Error::SnapshotContended { kind, id, attempts }. epoch = v1. Filters to PrincipalKind::User. No HTTP route (N7 owns it).")
@yah:handoff("EDGE (cheers-verify/src/snapshot.rs, exported SnapshotVerifier, SnapshotLedger, SnapshotLedgerDoc, SnapshotError, VerifiedSnapshot): SnapshotVerifier<Rd: RevocationReader>::new(IssuerTrust, Rd). verify_snapshot_at(token, now) = IssuerTrust::verify::<SetSnapshot> -> ledger.observe -> Superseded { kind, id, newest, offered } if a higher epoch was seen -> per member, dropped iff EVERY via has is_membership_revoked(k, i, user, snapshot.epoch) (an empty via is dropped: nothing could revoke it). Returns VerifiedSnapshot { snapshot (as signed), admitted, refresh_due }; now only sets refresh_due. holds(user, relation). adopt(token) = signature + observe, for gossip. SnapshotLedger: highest epoch per (kind,id), every update a max; export() -> { issuer, newest: {kind: {id: epoch}} }, import merges by max and refuses a foreign issuer with the existing ForeignLedger, whose message is generalised from 'binding ledger' to 'ledger'.")
@yah:handoff("COVERAGE: domain separation both ways = verify a_snapshot_is_refused_as_every_other_credential (KeySetVerifier::verify, verify_mcp_at, verify_at, StandingVerifier, ReplicatedRevocations::adopt) + every_other_credential_is_refused_as_a_snapshot (empty/binding/revocation-set assertions over a snapshot payload; real binding, revocation set, MCP and session tokens; assertion-role key; foreign issuer) + core implicit_assertion_is_its_own. Years later + refresh_after past = a_snapshot_verifies_years_after_iat_and_past_refresh_after. Supersession, lower adopt and stale import = a_higher_epoch_supersedes_and_nothing_lower_unsupersedes. Mask below V only = a_membership_revoked_at_v_masks_below_v_only; via rule = an_entry_is_dropped_only_when_every_via_is_revoked + server removal_from_the_parent_drops_an_inherited_member_and_keeps_a_direct_one (also the re-added user admitted at a later epoch, end-to-end through MemoryRevocationStore -> RevocationPublisher -> ReplicatedRevocations). Recording = server recording_fires_only_when_the_last_direct_tuple_goes (demotion, set tuple and service rows record nothing) + axum delete_records_a_membership_entry_only_for_the_last_direct_tuple (two relations, revoke one then the other through the HTTP door). Version per engine = store_scenarios::ownership_store_version on memory, sqlite, turso and pg. Mint retry = a_write_under_the_walk_retries_and_mints_the_later_state + a_walk_that_never_settles_is_refused. Plus mint_lists_users_closure_expanded_with_via_at_the_store_version, core wire shape and sort tests, ledger round trip, schema members_carry_the_direct_tuples_they_derive_from.")
@yah:handoff("FILES (uncommitted, git policy defer). New: cheers-core/src/snapshot.rs, cheers-server/src/snapshot.rs, cheers-verify/src/snapshot.rs, 3x 0013_ownership_version.sql. Edited: cheers-core lib.rs, schema.rs, error.rs, revocation.rs (Membership docs now say it masks by via); cheers-server lib.rs, ownership.rs, grants.rs and mcp_authority.rs (their test-only ownership mocks replaced by MemoryOwnershipStore); cheers-verify lib.rs, standing.rs (ForeignLedger text); cheers-sqlx ownership_store.rs, tests/sqlite.rs, tests/pg.rs; cheers-turso conn.rs, ownership_store.rs, migrate.rs, tests/turso.rs; cheers-axum ownership.rs, enrollment.rs (.row), camps.rs (InlineOwn mock replaced), tests/common/mod.rs (MemOwnershipStore delegates to MemoryOwnershipStore, keeps insert_calls), tests/ownership_basic.rs, tests/ownership_kind_list.rs; cheers-test-support store_scenarios.rs (.row at 12 sites + new scenario), lib.rs; docs product-scopes-and-authorization.md (D2: ownership_version no longer deferred, store-wide amends W235 C4) and edge-verifiable-auth.md (new §8). Nothing in noisetable edited; Ashguard's R733 file untouched.")
@yah:handoff("NOISETABLE SWAP POINTS (separate camp, not edited; it pins cheers 0.8.43-pre.1 from the registry, so all of this lands on the next bump). BREAKING: OwnershipStore::insert returns Inserted (use .row: projects/scopes.rs:932/1123, projects/mod.rs:630, lib.rs:1400/1575 etc.); revoke_by_id returns u64 (ledger.rs:79-80's Ledger blanket impl must map it); custom OwnershipStore impls need current_version; cheers_axum OwnershipState needs revocations: the account service's revocation store, the one its RevocationPublisher signs. In-process namespace revokes (projects/namespace.rs:227 and every membership revoke under svc:noisetable-account) must call cheers_server::revoke_ownership(&*ownership, &*revocations, &row.id, now), or offline edges never drop removed members. N7 (R803-F6): build SnapshotIssuer::new(<Arc<TursoOwnershipStore>>, <SchemaRegistry with the W235 namespace schema>, <issuer-key minter>, <issuer>, <issuer-role kid>) and serve mint(\"namespace\", N, now); map Error::SnapshotContended to a retryable 503; the node persists the token as last-known-good. N8 (R803-F8): admission = StandingVerifier (node binding, sub) + SnapshotVerifier::verify_snapshot_at then VerifiedSnapshot::holds(sub, \"member\"); persist SnapshotLedger::export beside IssuerTrust/BindingLedger/ReplicatedRevocations exports. N13 (R803-F7): gossip snapshot tokens into SnapshotVerifier::adopt and revocation sets into ReplicatedRevocations::adopt. W235 §5.2's C4 row still says per-resource ownership_version and needs the store-wide amendment. Migration 0013 runs through cheers-turso migrate on the account DB (same W124 §8 assumption as 0010-0012).")
@yah:verify("cd oss/cheers && cargo check --workspace --all-targets: EXIT=0. The only warning is the pre-existing unused `policy` at cheers-test-support/src/lib.rs:223.")
@yah:verify("cd oss/cheers && cargo test --workspace --no-fail-fast: 815 pass / 0 fail / 4 ignored, EXIT=0, vs the leader's baseline 793/0/4. The +22 are exactly this ticket's new tests: core 6, server 5, verify 7, test-support memory 1, sqlite 1, turso 1, axum 1. migrations_match_cheers_sqlx passes with 0013.")
@yah:verify("cargo test -p cheers-sqlx --features pg,sqlite --no-run: exit 0. cargo test -p cheers-redis --features redis-integration --no-run: exit 0.")
@yah:verify("Beyond --no-run, the pg suite ran against live Postgres (OrbStack: DOCKER_HOST=unix:///Users/leif/.orbstack/run/docker.sock TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=same): cargo test -p cheers-sqlx --features pg-integration --test pg passed 22/0, including ownership_store_version. So 0013 and the GREATEST ... RETURNING bump apply on a real pg.")
@yah:verify("cargo doc --no-deps -p cheers-core -p cheers-server -p cheers-verify: no rustdoc warnings in any file this ticket touched.")
@yah:handoff("LEADER FOLLOW-UP 1 (residual landed): OwnershipStore::revoke_by_principal now returns the ownership version: the one the sweep produced, or current_version when nothing was live. It used to return a row count; the scenarios now check the version and the history instead. New trait read list_history_for_principal(principal): every direct row, live AND revoked, implemented on memory, sqlx pg+sqlite, turso, the Arc blanket and both test mocks. New cheers_server::revoke_principal_ownership(store, revocations, principal, now) -> version, beside revoke_ownership and exported. It sweeps first. Then, for a USER principal, it records Revoked::membership(kind, id, user, V) for every resource in the history that the user holds no live direct tuple on after the sweep. Camps and services record nothing. DEVIATION from the brief, deliberate: the resources come from the history read AFTER the sweep, not from the live rows before it. Listing before the sweep cannot heal: a re-run finds nothing live, so entries a failed run missed would be lost for good. With the history read every run records the same set, so re-running heals exactly as revoke_ownership does. The cost is an entry (or a raised bound) for resources the user left long ago, which is safe because the user holds nothing live there at V.")
@yah:handoff("CALLERS: no production caller of revoke_by_principal exists in oss/cheers, yah app/crates or oss/yubaba. The remaining callers are store-contract scenarios (they must exercise the trait method itself), the mock delegations, and cheers-axum tests/tokens_basic.rs:863, a grant-shrink fixture rather than a deletion, so it stays on the raw method. Docs: revoke_ownership's doc, the snapshot module doc, product-scopes D2 and edge-verifiable-auth §8 now name revoke_principal_ownership. Title fixed to 'store-wide ownership_version epoch' (product-scopes-and-authorization.md:95, title string only). Both residuals are struck.")
@yah:handoff("TESTS ADDED: cheers-server snapshot::tests::deleting_a_user_drops_them_from_every_held_snapshot. dana holds direct tuples on band and museum, and through ed#guest <- museum#member she is also a guest of ed. Pre-deletion snapshots of band and ed are minted; the cascade records band and museum at V; after gossip the offline SnapshotVerifier drops dana from both held snapshots and keeps erin. A service principal's cascade records nothing. snapshot::tests::a_failed_cascade_recording_is_healed_by_re_running_it uses a revocation log that fails its first write: the first run errors with the rows already gone, and the re-run records both resources at the current version. store_scenarios: ownership_store_lifecycle checks the sweep advances the version, an idempotent re-sweep returns the same version, and history keeps both revoked rows with their own revoked_at; ownership_store_version checks history after the sweep; revoke_follows_holder and subject_sets were adapted. All of this runs on memory, sqlite, turso and live pg.")
@yah:handoff("NOISETABLE SWAP POINT (account_deletion.rs, not edited): the cascade does not call revoke_by_principal at all. It runs raw SQL, `DELETE FROM ownership WHERE principal_id = ?1 OR on_behalf_of = ?1` (account_deletion.rs:348-350). That hard delete skips BOTH the ownership_version bump, which breaks 'equal epoch implies equal members' for snapshots minted around it, AND the membership entries, so offline edges keep the deleted user. Fix there: call cheers_server::revoke_principal_ownership(&*ownership, &*revocations, &PrincipalId::user(uid), now) BEFORE the hard DELETE. It needs the history the DELETE then erases, and the DELETE itself is then a post-revocation purge. Also note the `ownership_version` row it already lists as NoUserData at :145-146.")
@yah:verify("Follow-up re-run on this tree: cargo check --workspace --all-targets EXIT=0; the only warning is the pre-existing unused `policy`, now at cheers-test-support/src/lib.rs:230. cargo test --workspace --no-fail-fast: 817 pass / 0 fail / 4 ignored, EXIT=0, vs 815/0/4; the +2 are deleting_a_user_drops_them_from_every_held_snapshot and a_failed_cascade_recording_is_healed_by_re_running_it.")
@yah:verify("Follow-up: cargo test -p cheers-sqlx --features pg,sqlite --no-run exit 0. cargo test -p cheers-redis --features redis-integration --no-run exit 0. Live pg (OrbStack DOCKER_HOST): cargo test -p cheers-sqlx --features pg-integration --test pg passed 22/0, covering the version-returning sweep and list_history_for_principal on real Postgres.")
-->

<!--
@yah:ticket(R732-F3, "C3: a holder may always revoke a tuple it holds (leaving), whatever its grant rights — an addition to D4's door rule")
@yah:status(review)
@yah:at(2026-10-07T06:43:29Z)
@yah:assignee(agent:bundle-anthropic-miravel)
@yah:parent(R732)
@yah:next("Tier: Cleric — one rule plus tests at the reworked door")
@yah:next("At the D4 ownership router (R731-F8) and schema.rs. Noisetable's leave route (W235 N4) is the first consumer.")
@yah:gotcha("Sequenced after R732-F2 by the R732 leader: F1 changes NewOwnership/RelationTuple used at the router, F2 rewires may_grant (schema.rs) and its router call sites, and this ticket edits both the router and schema.rs — running them concurrently on one tree collides.")
@yah:depends_on(R731-F8)
@yah:depends_on(R732-F2)
@yah:handoff("LANDED (uncommitted, git policy defer). cheers-core/src/schema.rs: new SchemaRegistry::may_revoke(source, principal, tuple: &impl RelationTuple) beside may_grant. True iff tuple.subject() is Subject::Principal equal to the caller (a holder may always revoke what it holds); otherwise falls back to may_grant on the tuple's (resource_kind, resource_id, relation). Only a direct principal subject counts: a set-subject tuple (team/T#member) is not revocable by a member of T on that basis; leaving a set means revoking your own direct tuple on T.")
@yah:handoff("cheers-axum/src/ownership.rs: the DELETE /ownership/{id} handler (revoke) now calls may_revoke(&OwnershipTuples(&*state.store), &caller.sub, &row) in place of may_grant; the doc comment is updated. The revoke path is still a straight get -> authorise -> revoke_by_id sequence, with no membership-revocation recording, so R732-F4 can add that after the authorise step.")
@yah:handoff("Last-owner rule: W235 DOES state one (section 2.4 floors, and Guards: 'A namespace's last owner cannot be removed (a noisetable route rule)'), but it assigns it to noisetable's route layer (N4 / R803-F3), not to cheers. So the cheers door does NOT enforce it; may_revoke lets the last owner revoke its own tuple. Noisetable's leave route must check it before calling DELETE.")
@yah:handoff("Out-of-scope note: the workspace was red for a while from the concurrent R732-F5 session.rs/standing work (unresolved crate::standing, missing NewSession.standing). I did not touch those files and waited for it to compile.")
@yah:verify("cargo check --workspace --all-targets: EXIT=0. cargo test --workspace: EXIT=0, 769 passed / 0 failed / 4 ignored (baseline was 750/0/4; the delta includes the peer's F5 tests as well as my 2).")
@yah:verify("New tests: cheers-core schema::tests::may_revoke_rules (holder revokes with no grant rights; non-holder without rights refused; grant rights still authorise revoking another's tuple; set-subject tuple not self-revocable by a set member). cheers-axum tests/ownership_basic.rs a_holder_may_revoke_its_own_tuple_but_not_anothers (bob, a plain reader, DELETEs own tuple -> 204 and revoked_at set; DELETEs carol's tuple -> 403 and row stays live). Both pass.")
@yah:verify("Caveat: the camp's skew detector flagged the final test run as suspect because peers edited session.rs and ownership.rs mid-run. My may_revoke call is still present in ownership.rs, and the result was green.")
@yah:handoff("Leader sign-off request: may_revoke (schema.rs:404) and its call at the DELETE door (cheers-axum ownership.rs:404) are present on the tree, and both named tests pass. The last-owner rule stays with noisetable's leave route (W235 Guards); cheers does not enforce it.")
@yah:verify("Leader re-run 2026-10-06 on the shared tree (F3 + F5 landed): cargo check --workspace --all-targets EXIT=0; cargo test --workspace 777 pass / 0 fail / 4 ignored EXIT=0, including schema::tests::may_revoke_rules and ownership_basic::a_holder_may_revoke_its_own_tuple_but_not_anothers.")
-->

<!--
@yah:ticket(R732-F2, "C2: SchemaRegistry::holds(store, principal, kind, id, relation) through the implies-closure and subject sets, depth-bounded and cycle-safe; may_grant and SchemaGrantStore's derived grants use it")
@yah:status(review)
@yah:at(2026-10-07T06:19:11Z)
@yah:assignee(agent:bundle-anthropic-glimmerstone)
@yah:parent(R732)
@yah:next("Tier: Wizard — the core authorization check")
@yah:next("Depth <= 4 with a visited set. may_grant is schema.rs:152; derived grants cheers-server/src/grants.rs:57. Spec: noisetable W235 §3 effective(P, resource, rel).")
@yah:depends_on(R732-F1)
@yah:handoff("API (cheers-core/src/schema.rs, re-exported from cheers_core): `pub const MAX_SET_HOPS: usize = 4`; `#[async_trait] pub trait TupleSource: Send + Sync { type Tuple: RelationTuple + Send + Sync; list_for_principal(&PrincipalId); list_for_resource(kind, id); list_for_subject_set(kind, id) }` all -> Result<Vec<Tuple>, StoreError>; `pub struct Holdings` (contains(kind,id,rel), iter() -> (kind,id,rel) sorted, is_empty()); `ResolvedRelation.relations: BTreeSet<&'static str>` = the relation plus its implies-closure (new field, computed in resolve_list). SchemaRegistry gains async `holds(source, principal, kind, id, relation) -> Result<bool, StoreError>`, `held_by(source, principal) -> Result<Holdings, StoreError>`, `members(source, kind, id) -> Result<Vec<(PrincipalId, String)>, StoreError>`. `may_grant` / `may_grant_any` are now async and take `(source, principal, kind, id[, relation])` -> Result<bool, StoreError>; the old row-slice forms and private grant_sets are deleted (no shim). A store error is an error, never 'not held'.")
@yah:handoff("SEMANTICS: a tuple `R#rel <- Set{k,i,srel}` confers `closure(rel)` on R to everyone holding srel on k/i through the closure. Hops count set edges only (direct tuple = hop 0; implies is the precomputed closure, never a hop). Hitting the bound = not held, never an error. A relation the schema does not resolve (kind without schema, or undeclared) implies only itself, so no-schema kinds like node#owns still work by exact name. Kind-level tuples (kind/<K>#r) can be held through sets too; they still confer grants, not per-resource relations, and are not members of their kind's resources. Walks re-check RelationTuple::is_live even though sources return live rows.")
@yah:handoff("DOWN WALK (private `reaches(source, P, roots)`): BFS from root nodes (kind,id,rel), one level per hop, list_for_resource per node (memoised per (kind,id) per check). A live row whose relation's closure contains the wanted rel either IS P (true) or is a set whose node is queued if hop < MAX and unvisited. BFS + one global visited set is exact under the bound, because each node is first reached at its fewest hops. holds = reaches([(k,i,rel)]). may_grant = reaches(every relation on (k,i) whose resolved grants contain rel, plus every kind relation on (kind/k) whose grants do); may_grant_any is the same with non-empty grants. On a kind-level resource itself (kind == KIND_RESOURCE) the roots are id's kind relations, which matches the old grant_sets behaviour.")
@yah:handoff("UP WALK (`held_by`): seed from list_for_principal (closure-expanded), then per hop list_for_subject_set(k,i) for each newly held (k,i,rel), and keep rows whose set subject is exactly (k,i,rel). Because holdings are closure-expanded, that equals 'set relation implied by what P holds'. Each new holding is expanded once, holdings at hop MAX are not expanded. Agreement: held_by(P).contains(k,i,r) == holds(P,k,i,r) == members(k,i) contains (P,r). Test up_and_down_walks_agree_on_random_graphs cross-checks all three over 300 seeded random graphs (8 resources incl. a no-schema kind, 3 users, cycles, 10% revoked rows, chains past the bound) and asserts more than 100 set-derived positives, so it cannot pass vacuously.")
@yah:handoff("R732-F4 SHOULD CALL `SchemaRegistry::members(&OwnershipTuples(&*store), kind, id)`, e.g. members(.., \"namespace\", N). It returns every (PrincipalId, relation) on the resource with sets flattened and the closure folded in (an owner is listed as owner, admin, publisher, member and guest), sorted by (principal string, relation) and deduped, under the same 4-hop bound, and agrees with holds. It returns every principal kind, so F4 filters to users and, if the snapshot wants one relation per member, reduces to the strongest itself.")
@yah:handoff("cheers-server: `pub struct OwnershipTuples<'a, O: ?Sized>(pub &'a O)` in ownership.rs implements TupleSource for any OwnershipStore (re-exported from cheers_server). It is a newtype because the orphan rule forbids a blanket impl of cheers-core's trait. SchemaGrantStore::list_for (grants.rs) now derives scopes from `schema.held_by(&OwnershipTuples(&self.ownership), principal)`, so set tuples confer derived grants at mint. The UnknownRelation warning now names principal/kind/id/relation (holdings carry no row id).")
@yah:handoff("CALL SITES: cheers-axum/src/ownership.rs create (POST) and revoke (DELETE) call `may_grant(&OwnershipTuples(&*state.store), &caller.sub, ...).await?`; list (GET) by resource and by set subject call may_grant_any likewise; the `?principal_id=<self>` form reads list_for_principal itself (direct rows only, unchanged behaviour). Module doc updated. mcp_authority.rs needed NO change: it never called may_grant, its mints read grants through SchemaGrantStore (now set-aware), its MemOwnershipStore mock already implemented list_for_subject_set (R732-F1), and its camp `owns` claim deliberately stays direct camp rows via list_for_principal. No caller of may_grant/ResolvedRelation exists in noisetable, yah app/crates or oss/yubaba (grepped), so nothing outside oss/cheers breaks.")
@yah:handoff("FILES TOUCHED (uncommitted, git policy defer): cheers-core/src/schema.rs (module doc, consts/trait/Holdings, walks, tests), cheers-core/src/lib.rs (re-export line only); cheers-server/src/ownership.rs (import + OwnershipTuples after the Arc impl), cheers-server/src/lib.rs (re-export), cheers-server/src/grants.rs (doc, list_for, test mock list_for_resource/list_for_subject_set were unimplemented!(), +1 test); cheers-axum/src/ownership.rs (imports, doc, create/list/revoke); cheers-axum/tests/ownership_basic.rs (imports + 1 test); .yah/docs/working/product-scopes-and-authorization.md (D2 subject-sets bullet, D4 one sentence). No migration and no store change.")
@yah:verify("Baseline BEFORE edits (oss/cheers): cargo check --workspace --all-targets exit 0; cargo test --workspace --no-fail-fast 736 passed / 0 failed / 4 ignored, exit 0.")
@yah:verify("AFTER, run 1: check exit 0 (only pre-existing warning: cheers-test-support/src/lib.rs:223 unused `policy`). Tests 747 / 0 / 4, exit 0. The +11 are exactly the new tests. Run 2, re-run on the current shared tree: check exit 0 and tests 750 / 0 / 4, exit 0. Its +3 are R732-F6's concurrent tests, and the camp flagged skew from a peer edit to cheers-verify/src/artifact.rs during that run. Its 3 unused-import warnings in cheers-verify/src/artifact.rs belong to the peer and are not from this ticket.")
@yah:verify("New tests, all passing. cheers-core schema::tests: holds_a_direct_tuple_and_nothing_else, holds_through_the_implies_closure, holds_through_a_one_hop_set, holds_through_a_multi_hop_set, a_set_cycle_terminates (A#member ⊇ B#member ⊇ A#member, empty and populated), the_depth_bound_holds_hop_four_and_refuses_hop_five (holds/held_by/members all refuse hop 5 with no error), may_grant_honours_set_derived_rights (incl. kind-level via a set), held_by_and_members_flatten_sets_and_fold_the_closure, up_and_down_walks_agree_on_random_graphs. may_grant_rules, may_grant_kind_level and implied_relations_carry_their_grants were ported to the async signature. cheers-server grants::tests::set_tuples_confer_derived_grants_at_mint (2-hop set yields the scopes and loses them when the set row is revoked). cheers-axum ownership_basic::a_set_derived_right_is_honoured_at_the_door (a set-derived admin may POST, GET and DELETE; a non-member and another resource get 403; after the membership is revoked, DELETE and POST get 403).")
@yah:handoff("Courier @Glimmerstone:hydra (session:7138fe94) landed TupleSource, async SchemaRegistry::holds / held_by / members and async may_grant / may_grant_any (4 set hops, cycle-safe, the bound means not-held). SchemaGrantStore derives grants through held_by, the router's call sites are switched over, and a 300-graph cross-check pins up/down agreement. The deferred ownership(resource_kind, resource_id) index is routed to R732-F4, which already adds an ownership migration.")
@yah:verify("Leader re-run on the shared tree with R732-F5 in flight: cargo check --workspace --all-targets exit 0; cargo test --workspace 750 pass / 0 fail / 4 ignored, exit 0.")
-->

<!--
@yah:ticket(R732-F1, "C1: subject sets in the ownership tuple (Subject = Principal | Set{kind, id, relation}, nullable subject columns with a one-form CHECK, list_for_subject_set + index, three-schema migrations)")
@yah:status(review)
@yah:at(2026-10-07T06:01:03Z)
@yah:assignee(agent:bundle-anthropic-glimmerstone)
@yah:parent(R732)
@yah:next("Tier: Wizard — schema change to the authorization tuple store on every backend")
@yah:next("NewOwnership/OwnershipRow (cheers-server/src/ownership.rs:80, :124) gain subject_kind/subject_id/subject_relation; RelationTuple::subject() (cheers-core/src/schema.rs:70); OwnershipStore::list_for_subject_set(kind, id). Migrations for sqlx sqlite/pg and turso; SQLite needs a table rebuild as in R731-F7's 0008. Spec: noisetable W235 §2.1, §5 table C1.")
@yah:gotcha("Consumer waiting: noisetable R800-F1 (@Glimmerstone:libra, session:6d3128e8) builds against this tree through a devcrate burst. When F1 lands and `cargo check --workspace` in oss/cheers is green, send that session one line saying so, and name the new list-by-subject door endpoint's query shape. Scope added mid-flight by the R732 leader: a list-by-subject form on GET /ownership, and fixing the cheers-axum principal_id call sites.")
@yah:handoff("TYPE: cheers-core/src/schema.rs adds `pub enum Subject { Principal(PrincipalId), Set { kind, id, relation } }` (+ Subject::set, principal(), as_set(), from_parts(principal_id, kind, id, relation) -> Result<_, SubjectFormError>, From<PrincipalId>, Display `kind/id#relation`), re-exported from cheers_core with SubjectFormError. RelationTuple gains `fn subject(&self) -> &Subject`. Serde is FLAT in column names via a private SubjectWire (try_from/into): a principal subject serializes as {\"principal_id\": \"user:alice\"} exactly as before, a set as {\"subject_kind\",\"subject_id\",\"subject_relation\"}; both/neither/partial is a deserialize error. So principal rows keep their wire shape (yubaba cheers_client, cheers lan_pair fixtures unaffected).")
@yah:handoff("ROW TYPES: cheers-server/src/ownership.rs NewOwnership.principal_id and OwnershipRow.principal_id are REPLACED by `#[serde(flatten)] pub subject: Subject` (no compat field). NewOwnership::new now takes `subject: impl Into<Subject>`, so every existing NewOwnership::new(PrincipalId, ...) call compiles unchanged. OwnershipRow::new takes `subject: Subject`. OwnershipValidationError gains SubjectForm(#[from] SubjectFormError). SeedTuple stays principal-only (bootstrap is a principal by design).")
@yah:handoff("STORE: OwnershipStore::list_for_subject_set(kind, id) -> live rows whose subject is a set on (kind, id), any subject_relation (caller filters by relation/closure). Implemented on PgOwnershipStore, SqliteOwnershipStore (cheers-sqlx/src/ownership_store.rs, now one shared COLUMNS const + parse_subject), TursoOwnershipStore (cheers-turso/src/ownership_store.rs, column indices shifted), the Arc<T> blanket impl, and every mock (cheers-server grants.rs + mcp_authority.rs tests, cheers-axum camps.rs test + tests/common/mod.rs). list_for_principal / revoke_by_principal are unchanged SQL (principal_id = ?) so they naturally exclude set rows; list_for_resource returns both forms.")
@yah:handoff("MIGRATION 0009_ownership_subject_sets.sql (number 0009 is mine; next free is 0010). sqlite (cheers-sqlx/migrations/sqlite and byte-identical cheers-turso/migrations/sqlite, registered as version 9 'ownership subject sets' in cheers-turso/src/migrate.rs): table rebuild as 0008 did -- principal_id nullable, subject_kind/subject_id/subject_relation TEXT added, CHECK one-form `(principal_id NOT NULL AND all subject_* NULL) OR (principal_id NULL AND all subject_* NOT NULL)`, on_behalf_of CHECK kept, ix_ownership_principal recreated, NEW partial index ix_ownership_subject_set ON (subject_kind, subject_id) WHERE revoked_at IS NULL AND subject_kind IS NOT NULL. pg: ALTER principal_id DROP NOT NULL, ADD the three columns, ADD CONSTRAINT ownership_subject_one_form CHECK (same predicate), same partial index.")
@yah:handoff("BEHAVIOUR KEPT for principal tuples: SchemaGrantStore derived grants (grants.rs) and may_grant read list_for_principal, so set rows confer nothing until R732-F2. Enrollment (cheers-axum/src/enrollment.rs) eviction sweep now compares subjects and DELIBERATELY only evicts principal-held rows -- a set-subject row on a node is not swept by a re-pair (picked default; product call for W235 device ownership if wrong).")
@yah:handoff("ROUTER (cheers-axum/src/ownership.rs), incl. the leader's scope addition. POST /ownership body: `principal_id` OR all of `subject_kind`,`subject_id`,`subject_relation` (+ resource_kind, resource_id, relationship); both/neither/partial -> 400 ownership_invalid; authority check unchanged (may_grant on the TARGET resource; no rights over the set's resource needed to name it, Zanzibar-style); idempotency looks up via list_for_principal or list_for_subject_set. GET /ownership takes exactly one form: (a) `?resource_kind=K&resource_id=I` (unchanged, needs may_grant_any on K/I); (b) `?principal_id=<kind>:<id>` -> live rows held directly by that principal, allowed ONLY when it is the caller's own verified sub, any other principal is 403 grant_forbidden (a principal names no resource to hold rights on); (c) `?subject_kind=K&subject_id=I&subject_relation=R` -> live rows whose subject is exactly K/I#R, allowed iff caller may_grant_any on (K, I). Mixed resource+subject, partial form, or empty -> 400 `invalid_ownership_query` (new RouteError::InvalidOwnershipQuery in cheers-axum/src/error.rs). Side effect: yubaba cheers_client's `GET /ownership?principal_id=svc:<self>` list call works again (R731-F8 had made it a 400).")
@yah:handoff("NOISETABLE (not edited): web/services/account breaks at compile on OwnershipRow.principal_id reads -- src/issues_admin.rs:138 and :187; src/projects/scopes.rs:408, :416, :421, :447, :835, :916. Fix shape: `r.subject.principal()` (Option<&PrincipalId>) or compare `r.subject == Subject::Principal(p)`. Its NewOwnership::new calls compile unchanged; raw SQL in account_deletion.rs:328/:730 (principal_id = ?1) stays valid. Rows from list_for_resource may now carry set subjects, so code assuming every row has a principal must decide what a set row means.")
@yah:verify("Baseline BEFORE edits: cargo test --workspace --no-fail-fast (oss/cheers) = 702 passed / 0 failed / 4 ignored, exit 0; cheers-sqlx --features pg-integration,libsql-integration --test pg --test libsql (OrbStack DOCKER_HOST) = pg 17/17, libsql 7/7.")
@yah:verify("AFTER: cargo check --workspace --all-targets --features cheers-sqlx/pg-integration,cheers-sqlx/libsql-integration = exit 0 (only warning: unused `policy` at cheers-test-support/src/lib.rs:223, not from this ticket). cargo test --workspace --no-fail-fast = 736 passed / 0 failed / 4 ignored, exit 0 (delta includes R732-F6's concurrent tests). pg 19/19, libsql 7/7.")
@yah:verify("New tests, all passing: cheers-core schema::tests::{subject_serializes_flat_in_column_names, subject_requires_exactly_one_form}; cheers-server ownership::tests::ownership_row_wire_keeps_principal_id_and_flattens_sets; store_scenarios::ownership_store_subject_sets (list_for_subject_set filters kind/id + liveness, set rows absent from list_for_principal and untouched by revoke_by_principal, present in list_for_resource) and store_scenarios::ownership_subject_check_rejects_bad_forms (raw SQL: both forms / neither / partial set / principal+kind rejected by the CHECK, both valid forms accepted) wired on sqlx-sqlite, turso AND pg; ownership_0009_rebuild_preserves_existing_rows on sqlx-sqlite and turso (row written under 0008 reads back as a principal subject after 0009); libsql.rs ownership_check_constraints_reject_bad_rows extended with set/both/neither rows; cheers-axum ownership_basic::{a_caller_lists_rows_held_by_its_own_subject, another_principals_subject_is_refused_even_to_a_resource_admin, a_set_subject_is_granted_and_listed_by_a_caller_with_rights_on_its_resource, a_body_naming_both_subject_forms_is_400, mixed_or_partial_list_forms_are_400}.")
@yah:handoff("FILES TOUCHED (all uncommitted, git policy defer): cheers-core/src/{schema.rs,lib.rs}; cheers-server/src/{ownership.rs,grants.rs,mcp_authority.rs (test mock + one test ctor only)}; cheers-sqlx/src/ownership_store.rs; cheers-sqlx/migrations/{sqlite,pg}/0009_ownership_subject_sets.sql; cheers-sqlx/tests/{sqlite.rs,pg.rs,libsql.rs}; cheers-turso/src/{ownership_store.rs,migrate.rs}; cheers-turso/migrations/sqlite/0009_ownership_subject_sets.sql; cheers-turso/tests/turso.rs; cheers-test-support/src/store_scenarios.rs (ownership section only); cheers-axum/src/{ownership.rs,enrollment.rs,error.rs,camps.rs (test mock)}; cheers-axum/tests/{common/mod.rs (MemOwnershipStore only),ownership_basic.rs,enrollment_basic.rs:274}. Shared-tree note: R732-F6 (@Glimmerstone:coffee) took migration 0010 after mine and edited other hunks of store_scenarios.rs, tests/common/mod.rs, ownership_basic.rs:260 concurrently; no collision.")
@yah:handoff("NOT DONE (scope): no holds()/closure walking (R732-F2). may_grant/grant_sets still treat every caller row as held; that is safe because callers pass list_for_principal rows, which never contain set rows. No index added for list_for_resource (it full-scans; pre-existing).")
@yah:handoff("Courier @Glimmerstone:dove (session:3bd7b6e0): Subject = Principal | Set{kind,id,relation} in cheers-core, a flat serde wire (principal rows keep the principal_id key), migration 0009 on sqlx sqlite/pg and turso with the one-form CHECK and the ix_ownership_subject_set index, list_for_subject_set on every store and mock, and the leader-added by-subject GET /ownership forms (?principal_id=self, ?subject_kind&subject_id&subject_relation). Details are in the handoff entries above.")
@yah:verify("Leader re-run on the shared tree (with R732-F6 in flight): cargo check --workspace --all-targets exits 0; cargo test --workspace gives 736 pass / 0 fail / 4 ignored (courier baseline 702/0/4; the delta includes F6's tests).")
-->

<!--
@yah:relay(R732, "Offline-durable authorization for namespaces (noisetable W235): subject sets, membership snapshots, standing node bindings and revocation sets")
@yah:at(2026-10-07T00:01:39Z)
@yah:status(open)
@yah:assignee(agent:bundle-anthropic-glimmerstone)
@yah:next("Consumer: noisetable W235 (namespaces and organizations), camp /Users/leif/ss/noisetable, doc .yah/docs/working/W235-namespaces-and-organizations.md §5 and §8. Its invariant: offline admission by membership lasts until revoked; no credential expiry may refuse or tear down a working setup when no fresher credential is reachable.")
@yah:next("This amends D2's 'tokens stay short-lived ... ownership_version stays deferred' for standing edge credentials only: browser/API access tokens keep the 15-min TTL. ownership_version is now needed (snapshot epoch).")
@yah:next("Order: C1 -> C2 -> C4; C5 and C6 independent; C3 after R731-F8's door. Noisetable's R792-B18 and W235 N7/N8/N13 wait on C4/C5/C6.")
@arch:see(.yah/docs/working/product-scopes-and-authorization.md)
-->

<!-- @yah:diligence(status=passed, by=agent:claude, date=2026-10-06) -->
<!-- @yah:covered-by(R731, status=open, 2026-10-06) -->
# Product scopes and authorization — cheers as a product's auth service

**Status:** Draft, 2026-10-06. Diligence pass the same day corrected the
"exists today" table and reworked D3, D4, D5 and the phasing. Not refined into
board work yet.
**Origin:** noisetable R795-T8. Granting the noisetable-issue skill its
issues-admin row needed the account service stopped, and the operator stopped
to look at the whole picture before another pattern got copied.
**First consumer:** noisetable's account service (`web/services/account`).
**Builds on:** `mcp-auth-and-ownership.md` (the MCP producer spec), and most of
what that spec planned is already built. This doc covers the one thing it never
covered: a product with its own permissions.

---

## Why this doc exists

cheers was specified for yah. Its scopes, principal kinds and ownership table
describe yah's camps, clouds and boards. Noisetable is the first product built
on cheers, and it hits three gaps that yah does not:

1. A product has permissions of its own ("may triage the issue desk", "may
   publish a pack"), and cheers has no place to put them.
2. A product's machine principals (a triage skill, an operator script) have to
   authenticate without a person present.
3. A product's operator has to grant and revoke on a live service.

Noisetable worked around each gap locally, and the workaround has now been
copied across four token types. This doc proposes closing the gaps in cheers,
then moving noisetable onto the result.

## What exists today (verified 2026-10-06)

### In cheers

| Piece | Where | State |
|---|---|---|
| Closed `Scope` enum, 17 yah verbs (`board:write`, `cloud:deploy`, …) | `cheers-core/src/mcp.rs:35` | built; unknown strings fail to parse |
| `PrincipalKind` `user` / `svc` / `camp` | `cheers-core/src/principal.rs:33` | built |
| Ownership table as relation tuples `(principal, resource_kind, resource_id, relationship)` | `cheers-server/src/ownership.rs` | built |
| `POST/DELETE/GET /ownership`, gated on service-only `ownership:write`, `granted_by` forced to the caller, per-writer scoping | `cheers-axum/src/ownership.rs` | built |
| `GrantStore` `(principal, aud) → [scope or bundle]`, bundles expanded at mint | `cheers-server/src/grants.rs` | trait (`list_for` only) plus `MemoryGrantStore`; no durable impl in `cheers-sqlx` / `cheers-turso` and no write API, so products hand-code one (`PublishGrants` below) |
| `ServicePrincipalAuthority`: Ed25519 keypair per service principal, rotation overlap, JWKS publication | `cheers-server/src/service_principal.rs` | built |
| `POST /admin/service-principals` + `/{id}/rotate`: operator **session** bearer + `OperatorPolicy`, secret returned once, body `{desired_id}` only (no grants) | `cheers-axum/src/admin.rs` (R020-T17, in review) | built |
| `/.well-known/jwks.json`, OIDC discovery, `/admin/camps/bootstrap` | `cheers-axum` | built |
| Mint paths: `mint_user_fresh`, `mint_api_token` (user PATs, served by `/me/tokens`), `mint_bootstrap` (camp), `mint_token_exchange` (user + camp, RFC 8693) | `cheers-server/src/mcp_authority.rs` | built. **None accepts a `svc:` principal**: per the spec, a service signs its own tokens with its own key |
| `POST /token` HTTP route | spec §Mint flows 3 | not built. Discovery already advertises it: `token_endpoint` = `/token` and the token-exchange grant type (`cheers-axum/src/discovery.rs:60,69`) |
| MCP-bearer verification (`McpAuthState`, `PasetoV4PublicVerifier`) | `cheers-axum/src/mcp.rs`, `cheers-verify` | one pinned `(kid, key)` pair. cheers-verify has no JWKS client; W159's kid-miss JWKS cache exists only in kamaji (`oss/kamaji/crates/kamaji-bin/src/auth/`) |
| JWKS key roles | `cheers-axum/src/jwks.rs:178`, kamaji `auth/verifier.rs:159-213` | **none.** cheers publishes platform keys and every service principal's key in one flat set (`Jwk` has no principal field). kamaji accepts any key in the set and checks only `iss`, `aud` and `exp`, so a service principal's key can sign a token with any `sub` and any scope that kamaji accepts |
| Session-authenticated ownership write: the user's own session bearer, the row written in-process under a fixed `svc:cheers-enrollment` `granted_by`, `on_behalf_of` taken from the verified session | `cheers-axum/src/enrollment.rs` | built; the precedent for D4's verified attribution |

### In noisetable's account service

Five audiences, each with its own mint door, borrowing yah scopes:

| Token | `aud` | Scope it borrows | What it really means |
|---|---|---|---|
| publish API token | `urn:noisetable:account:publish` | `cloud:deploy`, `cloud:read` | may publish packs |
| diagnostics operator token | `urn:noisetable:account:diagnostics` | `audit:read` | may read service diagnostics |
| issues bearer (1 h) | `urn:noisetable:issues` | `board:write` | may triage the issue desk |
| camp credential (90 d) | `urn:noisetable:account:issues-mint` | `camp:admin` | names an `svc:` caller of the issues mint door |
| assist token | `urn:noisetable:inference` | none referenced in `assist_token.rs` | may call inference |

How the rest is wired:

- `PublishGrants` (`api_token.rs:286`) is a hard-coded `GrantStore`: every user
  holds the publish scopes.
- Issues-admin is an ownership row `(issues, noisetable, admin)`, checked when
  the issues bearer is minted (`issues_admin.rs`).
- The camp credential is minted offline with the account's own issuer key and
  lasts 90 days. Whoever holds it *is* the principal until the row is revoked.
- The diagnostics token is minted offline by `noisetable-account
  --mint-diagnostics-token` (1 h TTL) with the issuer key.
- Ownership rows are written by `noisetable-scopes`, a CLI that opens the
  database file directly. turso's lock is process-exclusive, so every grant,
  and even every `show` or `list`, needs the service stopped
  (`bin/scopes.rs:41`). R132-F5 chose a CLI over an HTTP route on purpose: an
  authenticated internet-facing admin surface was judged more attack surface
  than the toil it removed (`bin/scopes.rs:4`).
- The account service mounts none of cheers' `ownership`, `jwks` or
  `discovery` routers. It binds one listener, `NOISETABLE_ACCOUNT_ADDR`
  (default `127.0.0.1:4332`). There is no mesh-only listener.
- The issues and inference services each verify against one pinned public
  key (`NOISETABLE_ISSUER_PUBLIC_KEY`, `NOISETABLE_INFERENCE_ISSUER_PUBLIC_KEY`),
  so rotating the issuer key means redeploying both.

## The gaps, stated as defects

1. **Scope punning.** `board:write` means "triage issues" at one audience and
   "write the yah board" in yah, so the audience does all the real locking. A
   token no longer says what it permits, and each new product permission is
   either another pun or an edit to a yah crate's closed enum.
2. **Self-issued long-lived bearers for machines.** These contradict this
   crate's own spec (`mcp-auth-and-ownership.md` §Service principal
   bootstrap), and the machinery the spec chose, `ServicePrincipalAuthority`,
   is already built.
3. **No live admin API.** The ownership write API exists in cheers, but no
   product mounts it, so grants fall back to editing the database file, and a
   process-exclusive store turns each one into downtime.
4. **Relationships have no schema.** Nothing says which relationships exist
   for a resource kind or what each implies: `admin` does not imply `read`. So
   each consumer hand-codes what a relationship means at the point of use.
5. **Two stores answering one question.** `GrantStore` ("which scopes may P
   hold at aud") and the ownership table ("what relationship P has to R") both
   decide authorization, with nothing tying them together.

## Proposed model

The shape is the one mainstream OAuth 2.1 / relationship-based (ReBAC)
deployments use, sized for cheers. No external engine (OpenFGA, SpiceDB) is
proposed; the ownership table is already the tuple store such engines are
built on.

### D1. Each resource server owns its scope vocabulary

- A scope is `<namespace>:<verb>`. Each audience (resource server) declares
  its namespace and verbs, for example `issues:triage`, `issues:read-full`,
  `packs:publish`, `diagnostics:read`.
- cheers-core keeps yah's 17 scopes as one built-in namespace set, not as the
  whole universe.
- The wire type becomes a validated string checked against a **scope
  registry** the deployment builds at startup. Each entry carries metadata:
  `service_only`, a description, and the audiences it is valid at.
- Discovery's `scopes_supported` reads the registry instead of `Scope::ALL`.
- The composition rules carry over unchanged: no wildcards, `:admin` distinct
  from `:read` / `:write`, service-only scopes refused at grant, and `aud`
  mandatory.
- Products declare scopes as typed constants, so a typo is a compile error,
  not a string mismatch. Open question: a macro, or a trait each product
  implements.
- Blast radius: `McpClaims.scope` is `Vec<Scope>` in cheers-core, so the wire
  change reaches every verifier, not only the mint. That means cheers-verify,
  noisetable's issues and inference services, and at least 14 files in yah's
  tree that name `Scope` beside cheers (kamaji, cloud-admin, …; grep,
  2026-10-06). Change the type and fix those call sites. Do not parse both
  shapes.

### D2. Scopes say what a token may attempt; relationships say what a principal holds

- A **relationship** answers "may P do this to R": `issues/noisetable#admin`.
  Grants and revokes write relationships.
- A **scope** is what a minted token carries, the capability the bearer may
  exercise at one audience. It is the intersection of what the client asked
  for and what P's relationships allow.
- Each resource kind gets a small **relationship schema**, declared in code by
  the product. It lists the relationships that exist, what each implies, the
  scopes each unlocks, and which relationships a holder may grant and revoke
  on the same resource (D4):

  ```text
  resource issues
    relation admin    implies triager   scopes issues:admin                        grants admin, triager, reader
    relation triager  implies reader    scopes issues:triage, issues:read-full
    relation reader                     scopes issues:read
  ```

- The mint path walks P's live tuples through the schema to get grantable
  scopes, then intersects with the request. That makes `GrantStore` a
  **derived view** of the ownership table, not a second source of truth
  (gap 5). Rows that grant a scope directly, for subjects with no
  relationship, survive only as an escape hatch, if at all (open question).
- **Subject sets (R732, noisetable W235 §2.1).** A tuple's holder may be a
  set, `issues/x#reader ← namespace/n#member`: everyone holding `member` on
  `namespace/n` through the implies-closure holds `reader` on `issues/x`.
  "P holds r on R" is `SchemaRegistry::holds`, which follows sets for at
  most `MAX_SET_HOPS` = 4 hops with a visited set; past the bound is "not
  held", never an error. The mint path's walk is `SchemaRegistry::held_by`
  (up from P's direct tuples) and a resource's flattened membership is
  `SchemaRegistry::members`. Both agree with `holds` by construction.
- Tokens stay short-lived. Revoking a tuple stops new mints and the TTL bounds
  the tokens already out, as today.
- **`ownership_version` (R732-F4, migration 0013).** One store-wide counter,
  advanced to `max(v + 1, now)` in the same transaction as every write that
  changes a row (`OwnershipStore::insert`, a revoking `revoke_by_id`, a
  sweeping `revoke_by_principal`), and read by `current_version`. It is the
  epoch of a membership snapshot (`SetSnapshot`, noisetable W235 §5 C4), the
  standing credential that carries membership to the offline edge. It is
  store-wide rather than per resource, which amends W235's C4 row: subject
  sets make a child namespace's flattened members depend on the parent's
  rows, so a per-resource counter on the child would not move when someone
  left the parent. The issuer mints between two reads of the version and
  retries if they differ, so equal epochs mean equal members. Removing a
  user's last direct tuple on a resource records `Revoked::Membership` at the
  version the removal produced (`cheers_server::revoke_ownership`, used by
  the D4 door and by in-process writers alike). A deletion cascade goes
  through `cheers_server::revoke_principal_ownership`, which sweeps the
  holder's tuples and records one entry per resource it ever held directly.

### D3. Machine principals authenticate with keys, never with stored bearers

- **Service principals** (`svc:`) use the keypair lifecycle cheers already
  has. Provisioning (`POST /admin/service-principals`, built in R020-T17)
  returns the secret half once. The principal signs a short-lived client
  assertion (the RFC 7523 shape, PASETO-wrapped), and the token endpoint
  exchanges it for an audience-bound access token. Nothing long-lived is a
  bearer.
- **This reverses a decision in the spec.** `mcp-auth-and-ownership.md`
  §Service principal bootstrap has the service sign its *own* access tokens
  with its key, and it explicitly preferred that over a client-credentials
  fetch: the service keeps minting while cheers is unreachable, and verifiers
  keep one public-key path. The reason to reverse it is that a self-minted
  token's `scope` is whatever the holder wrote. A signature proves who signed
  the token, not what they were granted, so cheers' grants, and D2's derived
  grants, are never consulted. The exchange puts cheers back on the mint
  path for every machine token. The cost is that machine principals cannot
  mint while cheers is down, and the access TTL (≤ 1 h) bounds that cost.
  **Decided (operator, 2026-10-06): exchange.** Self-signing is deferred, not
  ruled out. Verification already scales without cheers, through JWKS (D5).
  Minting costs cheers about one call per principal, audience and TTL window.
  Bring self-signing back for a specific service only if that mint load
  becomes measurable. D5's key roles keep the cost of doing that to one key's
  role plus a cheers-issued ceiling.
- New work this needs: an `McpAuthority::mint_service` (no mint path accepts
  `svc:` today), assertion verification against the principal's published
  keys plus `UsedJtiStore`, and the `POST /token` route (D6). The provisioning
  body needs no `grants` field: under D2, a service principal's scopes come
  from relationships written through D4.
- **Camps**: a later phase could have a product trust yah's camp issuer, a
  federation on the GitHub-OIDC-to-cloud pattern, so a camp needs no stored
  product secret at all. Out of scope for v1. Record it so D3 does not foreclose
  it.

### D4. Grants are live, authenticated and audited

**Decided (operator, 2026-10-06): the right to grant is a relationship.** A
grant is the same tuple whether the caller is a user, a service or a camp, so
the caller's kind does not decide who may write one.

- **One write door: cheers' `ownership` router, reworked.** It accepts either
  credential shape, a session bearer or a cheers-minted MCP bearer, as the
  `/me/tokens` maintenance routes already do. The caller's verified `sub` is
  the actor, whatever its kind.
- **Authorization is a schema lookup against live tuples, not a scope.** A
  caller may write or revoke relationship `r` on resource `R` only if it
  holds, on `R`, a relation whose `grants` list includes `r` (D2). "Holds"
  includes through a subject set (`SchemaRegistry::may_grant`, R732-F2). The
  check runs at write time against the table, so there is no token scope to
  go stale. `ownership:write` is deleted as a scope, along with its entry in
  composition rule (4). Revocation follows the same rule. That replaces
  today's per-writer scoping, where a writer could list and delete only the
  rows it wrote.
- **Attribution and lifecycle become separate columns.**
  - `granted_by` is the caller's verified `sub`, of any kind. The
    `CHECK (granted_by LIKE 'svc:%')` constraint and
    `OwnershipValidationError::GrantedByNotService` go.
  - `on_behalf_of` is attribution only: the user an agent or service acted
    for. It comes from a verified `act` claim or delegation, never from the
    request body. Today's router copies it from the body unverified
    (`cheers-axum/src/ownership.rs:164`).
  - A row is revoked when its holder (`principal_id`) is deleted, never
    because its granter was. Today `revoke_by_on_behalf_of` sweeps by
    `on_behalf_of`, so deleting an operator's account would revoke every grant
    they ever made. If a row must die with someone other than its holder,
    that is an explicit nullable `bound_to` column. Phase 1 checks whether any
    current `on_behalf_of` cascade needs one.
- **The service process is the only writer of the table.** That settles the
  exclusive-lock problem: the service owns the file, so grants go through it.
  In-process writes by product code (enrollment, project claims) stay, under
  the service's own `svc:` identity.
- **Bootstrap:** a seed tuple in config gives each resource its first
  grant-holder (`issues/noisetable#admin` for the operator) before anyone can
  call the door. Seed tuples never become the general grant path.
- **Mount on a mesh-only listener** for noisetable v1, not the public door.
  That answers R132-F5's objection to an internet-facing admin surface.
  noisetable binds one listener today, so the second bind is new work.
- `noisetable-scopes` becomes an HTTP client. It presents the operator's
  session, obtained through the existing browser passkey handoff
  (`handback.rs`, R131-F30).

Blast radius. Each item is a call site to fix, not a shim to keep:

- **cheers:**
  - a new migration in each of the three ownership schemas (`cheers-sqlx`
    sqlite and pg, `cheers-turso` sqlite `0002_ownership.sql`). In SQLite,
    dropping a CHECK means rebuilding the table;
  - `Scope::OwnershipWrite`;
  - the kind check in `NewOwnership::new`;
  - the `ownership` router;
  - every `revoke_by_on_behalf_of` caller.
- **yubaba:** `cheers_client.rs:204` self-signs an `ownership:write` token.
  It moves to `/token` (D3) and to a relationship.
- **yah:** `app/yah/cli/src/cloud_cheers.rs:471` asserts the old service-only
  rule.
- **Spec:** `mcp-auth-and-ownership.md` §Ownership table and composition
  rule (4) are superseded. Update them when the code lands.

### D5. Resource servers verify through JWKS

Resource servers fetch `/.well-known/jwks.json` and match on `kid`, with the
refresh-on-unknown-`kid` rule from W159, instead of pinning one key in an env
var. Rotating the issuer or a service principal's key then needs no redeploy.

This is new code in cheers, not configuration. cheers-verify holds exactly one
`(kid, key)` pair, and `McpAuthState` is built on it. The W159 cache (first
fetch, atomic refresh, rate-limited kid-miss refetch, restart from disk) is
implemented only in kamaji (`oss/kamaji/crates/kamaji-bin/src/auth/`). Lift it
into cheers-verify and let `McpAuthState` hold a key set. Then noisetable's
issues and inference services, and kamaji itself, share one implementation.

**Every published key carries a role, and verifiers enforce it.** Today's
flat set is a live hole: kamaji treats a service principal's key as the
issuer's (see the table above). Each JWK gains the principal it belongs to
and a role:

| Role | Key belongs to | May sign |
|---|---|---|
| `issuer` | cheers | access tokens for any `sub` |
| `assertion` | `svc:<id>` | only D3 client assertions, presented to `/token` and never to a resource server. Every service principal's key starts here |
| `self-signer` | `svc:<id>` | access tokens whose `sub` is exactly `svc:<id>`, within a ceiling cheers issued |

A self-signer's ceiling is a cheers-signed delegation listing the audiences and
scopes the service may self-issue. It is derived from its relationships when
issued and refreshed through `/token`. It has the same shape as the existing
`UserDelegation` (`cheers-core/src/delegation.rs`). The verifier checks that
the token's scopes fall within the ceiling.

Build the role field and its enforcement now, even with zero self-signers.
Then admitting one hot service later means flipping its key's role and adding
the delegation type, with no change to any resource server. If D5 ships as a
flat `kid → key` map instead, admitting a self-signer means retrofitting
every verifier.

### D6. One token endpoint instead of a mint door per feature

`POST /token` covers both flows, taking `audience` + `scope`:

- token exchange (RFC 8693): the mint side is built as
  `McpAuthority::mint_token_exchange`, for user + camp only; the route is not;
- client assertion (D3): needs `mint_service`.

It replaces per-feature doors such as noisetable's `POST /api/v1/issues/token`
and the diagnostics and assist mints. Each door shrinks to a scope
declaration plus a relationship schema entry. Until the route lands,
discovery advertises an endpoint nothing serves. Either land the route or drop
`token_endpoint` and the exchange grant type from discovery in the meantime.

## Noisetable migration (first consumer)

| Today | After |
|---|---|
| publish token: `cloud:deploy` + `cloud:read`, every user via `PublishGrants` | `packs:publish` / `packs:read` from a `publisher` relationship (or an account-level default, decided in diligence) |
| diagnostics token: `audit:read` | `diagnostics:read` from `account/noisetable#operator` |
| issues bearer: `board:write` | `issues:triage` / `issues:read-full` from the issues schema |
| camp credential, 90 d bearer, `camp:admin` | retired; `svc:noisetable-issue-skill` gets a keypair (D3) |
| assist token, audience only | `inference:assist`, its scope made explicit |
| `noisetable-scopes` opens the DB file | HTTP client of the mesh-mounted `ownership` router, presenting the operator's session (D4) |
| issues and inference services pin issuer keys in env | JWKS through cheers-verify (D5) |

The vaulted `noisetable-issue-skill-camp-credential` (minted 2026-10-06)
grants nothing on its own: no ownership row exists for it. It is deleted when
the skill moves to a keypair.

## Phasing

1. **cheers: scope registry** (D1) and the relationship schema with
   derived grants (D2). These are the API decisions every later phase depends
   on.
2. **cheers: machine plane.** Add `McpAuthority::mint_service`, client
   assertion verification, and `POST /token` (assertion + exchange, D3/D6),
   plus the JWKS-backed verifier in cheers-verify (D5). Provisioning is already
   built (R020-T17).
3. **Admin plane.**
   - In cheers, rework the `ownership` router (D4): it accepts either
     credential, checks grant rights against the schema, splits attribution
     from lifecycle, and ships the three schema migrations.
   - In noisetable, mount the router on a new mesh-only listener, seed the
     first admin tuples, turn `noisetable-scopes` into an HTTP client, and
     retire the direct-DB path.
4. **noisetable: token migration.** Move the five audiences onto product
   scopes and `/token`, and switch the issues and inference services to JWKS.
5. **noisetable R795-T8 resumes.** Grant `svc:noisetable-issue-skill` through
   the admin plane, give the skill a keypair, run the authenticated smoke
   test, and delete the vaulted bearer.

Phases 1 and 2 can overlap once D1's wire type is settled. Phase 3 needs
phase 1's relationship schema, because the door's authorization is a schema
lookup. It does not need phase 2: an operator calls the door with a session
bearer. Phase 1 followed by phase 3 is the shortest path to live grants
without downtime. Neither unblocks R795-T8 by itself, because the skill still
needs a credential, which is phase 2.

## Open questions

- **D1 typing.** A `scopes!` macro that emits constants plus a registry entry,
  or a `ProductScopes` trait? It has to work for crates that only verify,
  which never link `cheers-server`.
- **D2 escape hatch.** Keep direct scope grants (no relationship) at all? Lean
  no, until a consumer needs one.
- **D2 where the check runs.** Embedded at mint (today) versus checked by the
  resource server against a decision endpoint. Lean mint-only while TTLs stay
  at an hour or less.
- **D3 assertion format.** A PASETO v4.public assertion, mirroring RFC 7523's
  claims (`iss = sub = svc:<id>`, `aud = token endpoint`, `jti`, `exp`
  ≤ 5 min), reusing `UsedJtiStore` for replay.
- **D2/D4 machine writers on new resources.** A provisioner such as yubaba
  writes `owns` on a resource that did not exist a moment earlier, so it
  holds no relation on that resource yet. There are two options:
  - a kind-level relation: `provisioner` on kind `service` grants `owns` on
    any `service`;
  - parent relations, Zanzibar's tuple-to-userset: `service:S#parent =
    cloud:C`, and `cloud:C#provisioner` grants on its children.

  Lean kind-level for v1. This blocks yubaba's move onto the door, not
  noisetable's phase 3.
- **D4 recency.** Must a grant follow a passkey ceremony within N minutes?
  Nothing enforces session age today.
- **Publish default.** Does every account hold `packs:publish` (today's
  behaviour, modelled as an account-level default relationship), or does
  publishing become a granted relationship?

## Related

- `mcp-auth-and-ownership.md`: the producer spec this extends.
- `edge-verifiable-auth.md`: session tokens and verify semantics.
- yah `.yah/docs/working/W159-camp-trust-boundaries-and-mcp-auth.md`: the
  consumer-side spec on the yah side.
- noisetable `.yah/docs/working/W231-user-bug-reports.md` §3.1: the issues-admin
  design this generalises.
- noisetable `web/services/account/src/issues_admin.rs`,
  `bin/scopes.rs`, `api_token.rs`: the code that migrates.
