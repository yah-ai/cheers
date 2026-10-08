<!--
@yah:ticket(R734-F7, "Generic offline-Admit verification: Approval carries the policy and epoch instead of a VerifiedSnapshot, and the verify chain becomes a free function over &dyn AdmitAuthority, so a non-issuer root (noisetable's room roster) can implement it")
@yah:status(review)
@yah:at(2026-10-08T16:48:45Z)
@yah:assignee(agent:bundle-anthropic-glimmerstone)
@yah:parent(R734)
@yah:next("Tier: Wizard. Consumer: noisetable R803-F15 (offline Admit for rooms, rooted in the creator-signed room roster, admit ability = Role::Enroll). Found by noisetable R803-F13 phase 1.")
@yah:next("DEFECT: AdmitAuthority cannot be implemented by any root other than the issuer. crates/cheers-verify/src/admit.rs:120 Approval carries `snapshot: VerifiedSnapshot`, which only the cheers issuer can produce. The whole chain (device signature, validate, authority, expiry, jti revocation, approval, requester binding, evaluate_admit) lives in the inherent IssuerAdmitAuthority::verify_admit_at (admit.rs:217), so it is not generic over the trait at admit.rs:135.")
@yah:next("PROPOSED: Approval { user, relation, policy: Option<AdmissionPolicy>, epoch: u64 } replaces the snapshot field. A free `verify_admit_with(authority: &dyn AdmitAuthority, trusted_authority: &str, revocations: &dyn RevocationReader, token, now) -> Result<VerifiedAdmit, AdmitError>` runs the chain; IssuerAdmitAuthority::verify_admit_at becomes a thin call into it. Keep the same check order and error variants. Only the OFFLINE Admit path needs this. The online knock does not.")
@yah:next("SEQUENCING: land this AFTER the 0.8.43 publish (the operator is cutting 0.8.43 from the current working copy). It is a breaking change to Approval, so it goes in the next cheers bump.")
@yah:handoff("BUILT (2026-10-08), crates/cheers-verify/src/admit.rs: Approval is now { user: Option<UserId>, relation: String, policy: Option<AdmissionPolicy>, epoch: u64 }. The snapshot field is gone; IssuerAdmitAuthority fills policy from snapshot.admission_policy().cloned() and epoch from the held snapshot's epoch. New free fn `pub async fn verify_admit_with(authority: &dyn AdmitAuthority, trusted_authority: &str, revocations: &dyn RevocationReader, token: &str, now: i64) -> Result<VerifiedAdmit, AdmitError>`, re-exported from cheers_verify. It runs the chain in the old order with the old variants: device signature, validate, WrongAuthority (vs trusted_authority), Expired, Revoked (vs revocations), approval_at, requester binding, evaluate_admit(approval.policy). IssuerAdmitAuthority::verify_admit_at is now a one-line call: verify_admit_with(self, snapshots.trust().issuer(), snapshots.revocations(), token, now). The online knock path is untouched.")
@yah:handoff("DESIGN CONSEQUENCE, decided here rather than in the ticket: the chain's requester-binding step called the issuer's StandingVerifier, and the decided signature carries no standing verifier. So AdmitAuthority gained a REQUIRED method `async fn requester_user_at(&self, requester: &PeerKey, binding: &str, now: i64) -> Result<UserId, AdmitError>`. It is asked only when the Admit carries requester_binding. The issuer impl calls standing.verify_standing_at(...).binding.sub. The NotAKey check on the requester stays in verify_admit_with, in its old position. Consequence for noisetable R803-F15: its roster impl must implement both approval_at and requester_user_at. A roster that binds no users can refuse there.")
@yah:handoff("CALLERS: a grep across the yah monorepo for AdmitAuthority|IssuerAdmitAuthority|VerifiedAdmit|verify_admit_at|verify_admit_with|approval_at (comment lines stripped, piped to `| wc -l`) hits 3 files, all in cheers: cheers-verify admit.rs and lib.rs, plus cheers-server src/knock.rs. knock.rs uses only approval_at().relation/.user in tests, so it needed no change. mesofact, passway, roadcase, kamaji and the root members have zero references. A read-only grep of ~/ss/noisetable also has zero references. knock.md's library-seam prose gained one sentence on verify_admit_with. The cheers version is NOT bumped; the next release is the operator's.")
@yah:handoff("TESTS ADDED (admit.rs): refusals_keep_the_chain_order. One issuer-path admit breaks every link at once (rogue authority, expired, revoked jti, demoted approver, requester binding for another key, lease over the path max), and the test repairs one link at a time. It asserts WrongAuthority -> Expired -> Revoked -> NotAnApprover -> Standing(PeerKeyMismatch) -> PolicyRefused(LeaseOverMax) -> Ok (approval.epoch == 12). a_non_issuer_root_verifies_an_offline_admit: a test Roster AdmitAuthority rooted in its own Ed25519 root key (authority `room:<root b64>`), plus a test Jtis RevocationReader. It verifies an offline Admit through verify_admit_with (Approval{user None, relation enroll, policy, epoch 3}) and refuses WrongAuthority (an admit naming the cheers ISS), NotAnApprover (a roster key without enroll), Revoked (the root's own jti set) and PolicyRefused (the roster's policy switched to users). The revocation-check helper was extracted into revoke(&Rig, jti).")
@yah:handoff("MUTATION CHECK: with verify_admit_with's revocation link disabled (`if false && revocations.is_revoked(..)`), `cargo test -p cheers-verify --lib admit::` gave 14 passed and 3 FAILED: a_revoked_admit_jti_is_refused, a_non_issuer_root_verifies_an_offline_admit and refusals_keep_the_chain_order. The link was then restored (grep -c 'if false' admit.rs = 0) and all tests rerun green.")
@yah:handoff("SUGGESTED COMMIT (git policy defer, not run): git add oss/cheers/crates/cheers-verify/src/admit.rs oss/cheers/crates/cheers-verify/src/lib.rs oss/cheers/.yah/docs/working/knock.md && git commit -m 'cheers R734-F7: generic offline-Admit verification via verify_admit_with over &dyn AdmitAuthority' -m 'Approval carries policy + epoch instead of VerifiedSnapshot; AdmitAuthority gains requester_user_at; IssuerAdmitAuthority::verify_admit_at delegates. Breaking for the next cheers bump.' -m 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'")
@yah:verify("cd oss/cheers && cargo test -p cheers-verify. Baseline before the edit: lib 80 passed, 10 passed, 0 passed, all ok. After: lib 82 passed (+2 new), 10 passed, 0 passed, 0 failed, EXIT=0, no warnings.")
@yah:verify("cd oss/cheers && cargo test -p cheers-server. Baseline: 214 + 9 + 5 + 2 passed. After: 214 + 9 + 5 + 2 passed, 0 failed, EXIT=0. No change was needed there.")
@yah:verify("cd oss/cheers && cargo check --workspace --all-targets: EXIT=0, 0 warnings, 0 errors.")
@yah:verify("Mutation: disable the revocation link in verify_admit_with, then run cargo test -p cheers-verify --lib admit::. Expect 3 failures, including a_non_issuer_root_verifies_an_offline_admit and refusals_keep_the_chain_order. Observed 14 passed, 3 failed, EXIT=101; the link was then restored.")
-->

<!--
@yah:ticket(R734-F5, "Lease warning as one cheers standard: Lease and LeaseState, shared by Admit, StandingBinding and SetSnapshot")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-glimmerstone)
@yah:at(2026-10-07T17:32:41Z)
@yah:parent(R734)
@yah:next("Operator (2026-10-07): cheers standardizes the lease warning, and consumers monitor it and surface it. cheers exposes the state and never notifies anyone itself.")
@yah:next("Today the concept exists twice: refresh_after + is_refresh_due_at on StandingBinding (cheers-core standing.rs:67,78) and SetSnapshot (snapshot.rs:135,188), and refresh_due: bool on VerifiedStanding (cheers-verify standing.rs:93) and VerifiedSnapshot (snapshot.rs:86). Replace both copies with one cheers-core Lease { refresh_after, exp: Option<i64> } and Lease::state_at(now) -> LeaseState { Current, Warning { exp }, Expired }. Verified* results expose lease: LeaseState instead of refresh_due.")
@yah:next("Invariant (knock.md, Posted lease): when exp is Some, iat < refresh_after <= iat + (exp - iat) / 2. Construction and verification both refuse a lease that breaks it. Serde-flatten the Lease so the StandingBinding and SetSnapshot wire stays {refresh_after}, with exp omitted when None. Admit (R734-F2) is the first user with exp set.")
@yah:next("Document it once, in edge-verifiable-auth.md as a short section that §7, §8 and knock.md point to.")
@yah:verify("state_at at each boundary: before refresh_after, at it, and at exp. A lease with refresh_after past the midpoint is refused. Existing StandingBinding and SetSnapshot tokens round-trip byte-identical.")
@yah:tier(Warrior)
@yah:handoff("LANDED: new cheers-core/src/lease.rs (Lease{refresh_after,exp} with private fields, Lease::new(iat,refresh_after,exp)->Result<_,LeaseError>, validate(iat), state_at(now)->LeaseState{Current,Warning{exp},Expired}); re-exported in cheers-core lib.rs. state_at: exp<=now Expired, else now>=refresh_after Warning, else Current; the >= boundary matches the old is_refresh_due_at (it was `now >= refresh_after`, checked).")
@yah:handoff("StandingBinding (core standing.rs) and SetSnapshot (core snapshot.rs) now hold `#[serde(flatten)] pub lease: Lease`; refresh_after field and is_refresh_due_at deleted outright, SetSnapshot::new takes `lease: Lease` in place of refresh_after. Added Error::Lease (core error.rs), StandingError::Lease and SnapshotError::Lease (verify), checked via lease.validate(iat) right after signature verify, before the ledger observes the seq/epoch. cheers-server minters (standing.rs mint, snapshot.rs mint) build Lease::new(now, now+secs, None)?.")
@yah:handoff("SERDE: #[serde(flatten)] won, no hand-written serde needed. Lease is the LAST field in both structs so declaration order is preserved; bytes are identical and exp is omitted when None. No deny_unknown_fields on either type.")
@yah:handoff("API BREAK for noisetable R803: VerifiedStanding.refresh_due / VerifiedSnapshot.refresh_due (bool) -> `.lease: LeaseState` (match Warning{exp}); StandingBinding.refresh_after / SetSnapshot.refresh_after (field) -> `.lease.refresh_after()`; is_refresh_due_at -> `.lease.state_at(now)`; SetSnapshot::new last arg i64 -> Lease. No aliases kept.")
@yah:handoff("DOCS: edge-verifiable-auth.md gained a 'Lease (R734-F5)' section after section 8; sections 7 and 8 point at it. knock.md Posted-lease text now points at it. Framing kept: cheers computes state, consumers monitor and surface the warning, cheers never notifies. Admit (R734-F2) named as first user with exp set; not built. Historic @yah annotation text in knock.md / product-scopes-and-authorization.md still mentions refresh_due; left alone as ticket history.")
@yah:verify("Baseline cargo test --workspace: 825 pass / 0 fail (confirmed before edits). After: 842 pass / 0 fail, EXIT=0 (log /tmp/r734f5_ws6_2.log). The count also includes whatever F1 added in parallel.")
@yah:verify("New tests: lease.rs (state_without_exp_never_expires, state_at_each_boundary_with_exp covering before refresh_after / at it / at exp, refresh_after_is_bounded_by_the_midpoint, wire_omits_exp_when_none); core standing.rs and snapshot.rs flattened_lease_is_byte_identical_to_the_old_wire (golden string built from the pre-edit field order, asserts serialize equality and that old bytes deserialize) and exp_rides_the_flattened_lease; verify standing.rs and snapshot.rs a_lease_past_its_midpoint_is_refused (forged via deserialize, refused at verify with ::Lease), plus an at-midpoint accept in standing.")
@yah:verify("Caveat: the golden strings were written from the pre-edit struct declaration order rather than captured by running the old binary; members/revocation_keys are empty in the snapshot golden so F1's principal widening does not touch it.")
@yah:handoff("Leader re-verified (Glimmerstone, session:ead31b87): cargo test --workspace 842 pass / 0 fail / 4 ignored. All 10 new lease, golden and midpoint tests appear as ok in /tmp/r734lead_f1v1.log. Golden caveat checked: at anchor 9ddca7b5, refresh_after was the last field of StandingBinding, so putting the flattened Lease last keeps declaration order. SetSnapshot is entirely uncommitted R732 work. Uncommitted (git policy defer).")
@yah:verify("cd oss/cheers && cargo test --workspace --no-fail-fast: 842/0, re-run by the leader on 2026-10-07. Field order compared with git show 9ddca7b5:oss/cheers/crates/cheers-core/src/standing.rs.")
-->

<!--
@yah:ticket(R734-F4, "Knock online routes and offline-Admit reconciliation (cheers-axum + cheers-server)")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-glimmerstone)
@yah:at(2026-10-07T18:17:01Z)
@yah:parent(R734)
@yah:next("Routes: POST /knock (a signed Knock, queued as a pending row); GET pending knocks for a resource (callers with the admit ability only); POST /knock/{id}/admit (writes the tuple with granted_by set to the approver); POST /offer and POST /offer/redeem; POST /admit (upload an offline Admit).")
@yah:next("Reconciliation (knock.md): accept an uploaded Admit iff its approver holds the admit ability NOW, and write the tuple. Otherwise record Revoked::Jti(admit.jti, admit.exp) so edges drop it. Uploads are idempotent per jti.")
@yah:next("Sybil bounds: one pending knock per key per resource, pending knocks lapse (TTL), a per-resource pending cap, and POST /knock rate-limited per resource and per source.")
@yah:verify("Tests: an online knock-to-admit run writes the same tuple an offline Admit reconciles to. An Admit from a since-demoted approver is refused and appears in the next revocation set. A second pending knock from the same key replaces the first. The pending cap is enforced.")
@yah:depends_on(R734-F2)
@yah:depends_on(R734-F3)
@yah:tier(Warrior)
@yah:next("C1 (operator, 2026-10-07, revised): a reconciled tuple keeps its Admit's lease (exp, refresh_after), so the ownership tuple and SnapshotMember both gain an optional lease, and edges report refresh_due on reconciled guests too. Renewal: POST /knock may name a prior Admit jti, and the approver re-admits with one tap and a fresh lease.")
@yah:verify("An uploaded week-long Admit reconciles to a tuple that lapses at the same exp and reports refresh_due after the same refresh_after.")
@yah:handoff("LANDED (courier Ashguard, uncommitted, git policy defer). Migration 0017_knock: one file, byte-identical in cheers-sqlx migrations/sqlite and pg and in cheers-turso migrations/sqlite (BIGINT/TEXT only); turso migrate.rs is bumped to version 17. It adds ownership.lease_iat/lease_refresh_after/lease_exp plus four tables: pending_knocks (UNIQUE kind,id,requester), offers, offer_redemptions (PK offer_jti,redeemer) and admissions (jti PK; ownership_id XOR refusal).")
@yah:handoff("ADMITTERS MOVE (decision 0): AdmissionPolicy.admitters: BTreeSet<String> (core admission.rs:187), omitted from the wire when empty, which fails closed; builder with_admitters (admission.rs:211). IssuerAdmitAuthority::new(standing, snapshots) dropped its admit_relations arg (verify admit.rs:176) and now reads admitters from the held snapshot's policy. The server checks the same field over live tuples with SchemaRegistry::holds in KnockAuthority::admit_relation (server knock.rs:410). Edge and server agree on an implied admitter: snapshot members are closure-expanded at mint, so there was nothing to paper over. Test: edge_and_server_agree_on_an_admitter_by_implication (owner implies admin, admitters={admin}).")
@yah:handoff("TUPLE LEASE: server ownership.rs has TupleLease{iat, #[flatten] lease} at :133, with from_columns that validates on read. NewOwnership.lease and OwnershipRow.lease are Option, serde-omitted when None, with builders with_lease. OwnershipRow::is_live_at(now) is at :258. OwnershipTuples is now a struct built with OwnershipTuples::at(&store, now) (:819) and drops lapsed rows, so holds/held_by/members and the mint stop counting a tuple at exp. All 5 call sites were updated (axum ownership.rs x3, server snapshot.rs; grants.rs uses the wall clock because GrantStore::list_for has no now). Engines: Memory, sqlx sqlite+pg, and turso insert/read the three lease columns.")
@yah:handoff("SNAPSHOT: SnapshotMember.lease: Option<Lease> (core snapshot.rs:121), omitted when None; golden test a_member_lease_rides_the_wire_only_when_present. The mint (server snapshot.rs member_leases :212) sets it only when the entry's via is exactly this resource and every live direct tuple the principal holds here is leased (the latest exp wins). Edge: verify_snapshot_at drops a member whose lease reads Expired (verify snapshot.rs:268), and VerifiedSnapshot::member_lease(principal, relation, now) -> Option<LeaseState> (:105) surfaces Warning.")
@yah:handoff("SERVER (new cheers-server/src/knock.rs): KnockConfig (:50) defaults are pending_ttl 24h, pending_cap 64, knocks_per_source_per_minute 10, knocks_per_resource_per_minute 60, offer_ttl 1h. trait KnockStore (:141), with impls for MemoryKnockStore (:200), Arc, SqliteKnockStore/PgKnockStore (new cheers-sqlx knock_store.rs, one SQL text numbered for pg) and TursoKnockStore (new cheers-turso knock_store.rs). KnockAuthority<Rd> (:339) is built by ::new(schema, ownership, knocks, revocations, StandingVerifier, minter, issuer, kid) and exposes knock :463, pending :490, admit_knock :498, offer :527, redeem_offer :568 and reconcile :617. reconcile accepts iff approver_of (the key's own admitter tuple, or its standing binding's user) holds an admitter relation now AND evaluate_admit passes on the live policy; on refusal it records the outcome and calls Revoked::jti(jti, exp). Idempotent per jti.")
@yah:handoff("ROUTES (new cheers-axum/src/knock.rs, router :334; KnockState{edge, authority, limiter} :69): POST /knock {knock} -> 202 {id, expires_at, replaced}; GET /knock?resource_kind&resource_id (bearer, admitter) -> pending list; POST /knock/{id}/admit {confirmation?, lease_seconds?} (bearer, admitter) -> 201 {jti, ownership}; POST /offer {resource_kind, resource_id, relation, max_uses} (bearer, admitter) -> 201 {offer, token}; POST /offer/redeem {offer, knock} -> 201 {jti, ownership}; POST /admit {admit} -> 200 accepted or 403 refused {outcome, jti, ...}. Status codes: 429 for rate_limited and pending_full, 403 for not_an_approver and admission_refused, 404 for an unknown knock or offer, 410 for an exhausted or expired offer, 400 for a bad artifact. RateLimiter (:41) is a fixed 60s window in memory, with no new crate. The per-source key is the ConnectInfo<SocketAddr> ip; without ConnectInfo every request shares one bucket, which fails tight.")
@yah:handoff("My defaults (one line each): online paths also run evaluate_admit, so closed stops online knocks (test closed_stops_online_knocks_too). Renewal is keyed by grant: a fresh admission revokes the requester's live LEASED tuple for the same relation and resource and never touches a standing one; Knock.renews is informational. Online jtis are knock:<id> and offer:<jti>:<key>. An offer redemption runs on the Offer path at confirmation Accept and requires the offer's creator to still be an admitter. Offers are issuer-signed and verified with the issuer's own key (derived from the minter). knock.md Reconciliation gained a short 'Settled by R734-F4' list.")
@yah:handoff("Drive-by: removed the unused `let policy = SessionPolicy::default().with_access_ttl(300);` from cheers-test-support lib.rs and the now-unused SessionPolicy import. I checked before deleting: it had no other use in that test.")
@yah:handoff("NOISETABLE R803 BREAK LIST: (1) IssuerAdmitAuthority::new lost its 3rd arg; the admit relations now come from AdmissionPolicy.admitters in the snapshot policy, so a policy without admitters admits nobody. (2) OwnershipTuples(&store) became OwnershipTuples::at(&store, now). (3) OwnershipStore impls must persist NewOwnership.lease, and OwnershipRow carries a .lease field (non_exhaustive structs, built through new()+with_lease). (4) SnapshotMember gained lease: Option<Lease>, so struct literals need `lease: None`; the wire is unchanged when None. (5) Migration 0017 alters ownership. (6) Edges drop expired leased members.")
@yah:verify("cargo test --workspace --no-fail-fast: 896 pass / 0 fail / 4 ignored, EXIT=0 (/tmp/r734f4_ws1.log), against a 875/0 baseline. PG (orbstack, --features pg-integration --test pg): 26 pass / 0 fail, EXIT=0, against a 24/0 baseline (adds ownership_store_lease and knock_store_lifecycle).")
@yah:verify("Ticket verifies, server knock::tests: an_online_knock_and_an_offline_admit_write_the_same_tuple (same subject/resource/relation/granted_by/on_behalf_of/lease, and a re-upload is idempotent); an_admit_from_a_since_demoted_approver_is_refused_and_revoked (Revoked::Jti(admit-2, exp) is in the revocation writer's set); a_second_pending_knock_replaces_the_first_and_the_cap_holds (also: a non-admitter gets NotAnApprover on the list, and pending knocks lapse at the TTL); a_week_long_admit_reconciles_to_a_tuple_that_warns_and_lapses_with_it (holds true until exp, false at exp; the mint carries the lease; the edge reports Current then Warning{exp} from the same refresh_after and drops the guest at exp; the post-exp mint omits it); edge_and_server_agree_on_an_admitter_by_implication; a_renewing_knock_replaces_the_lease; an_offer_is_redeemed_once_per_key_up_to_max_uses; closed_stops_online_knocks_too.")
@yah:verify("Routes, cheers-axum tests/knock_basic.rs: knock_then_admit_writes_the_tuple_and_a_second_knock_replaces_the_first (401/403/201/404); post_knock_is_rate_limited_per_source_and_capped_per_resource (pending_full, rate_limited, 400 on a forged knock); an_uploaded_admit_and_an_offer_reconcile_through_the_routes. Unit test knock::tests::the_limiter_counts_per_key_per_minute. Core: a_member_lease_rides_the_wire_only_when_present (golden) and wire_round_trips with admitters. Verify: a_leased_guest_warns_then_drops_at_exp and the_admit_ability_comes_from_the_held_policy. store_scenarios ownership_store_lease and knock_store_lifecycle run on memory, sqlite, turso and pg.")
@yah:gotcha("The workspace build emits 3 deprecation warnings from oss/mshr endpoint.rs (iroh CaRootsConfig), which is outside cheers and was being edited by someone else during this run. cheers itself now builds warning-free.")
@yah:handoff("PG RACE FIXED (courier Ashguard): cheers-sqlx knock_store.rs now serializes both bounded writes on Postgres only. redeem_offer first runs PG_LOCK_OFFER (SELECT 1 FROM offers WHERE jti = $1 FOR UPDATE). queue_knock first runs PG_LOCK_RESOURCE (pg_advisory_xact_lock(hashtextextended(kind || ':' || id, 0))) before the lapse, the replace-own (DROP_OWN) and the conditional insert, so the replace path takes the same lock. The macro gained two Option lock args; sqlite passes None, so SQLite and turso are unchanged, and no schema change was needed (migration 0017 untouched). The module doc now states the guarantee. tests/pg.rs gained fresh_pg_sized(n) and a barrier-driven race() helper; cheers-sqlx dev-dep tokio gained the sync feature.")
@yah:verify("PG race tests knock_store_offer_max_uses_holds_under_concurrent_redemption (16 distinct keys against max_uses=1 and max_uses=3) and knock_store_pending_cap_holds_under_concurrent_knocks (16 keys, cap 3) caught the race before the fix: 16 of 16 succeeded in both (/tmp/r734f4_race_pre2.log). After the fix the PG suite passes 28/0, EXIT=0 (/tmp/r734f4_pg_post1.log), and cargo test --workspace --no-fail-fast passes 896/0, EXIT=0 (/tmp/r734f4_ws_post1.log). Two pg-feature unused-import warnings come from cheers-sqlx used_jti_store.rs:10-11, which is outside this change.")
@yah:gotcha("The knock RateLimiter is per process, so a multi-node deployment limits per node.")
@yah:handoff("Leader re-verified (Glimmerstone, session:ead31b87) after the PG race fix by courier session:abf9e810. cargo test --workspace: 896 pass / 0 fail / 4 ignored. cheers-sqlx PG: 28 pass / 0 fail, including knock_store_offer_max_uses_holds_under_concurrent_redemption and knock_store_pending_cap_holds_under_concurrent_knocks. Per the courier, both failed before the fix (16/16 succeeded). The fix is PG-only: FOR UPDATE on the offer row and pg_advisory_xact_lock per resource, with no schema change. The two unused-import warnings at cheers-sqlx used_jti_store.rs:10-11 under the pg feature predate R734; the file is unchanged since 9ddca7b5. Everything is uncommitted (git policy defer).")
@yah:verify("cd oss/cheers && cargo test --workspace --no-fail-fast (896/0), then DOCKER_HOST=unix://$HOME/.orbstack/run/docker.sock cargo test -p cheers-sqlx --features pg-integration --test pg (28/0). Both were re-run by the leader on 2026-10-07 (/tmp/r734lead_f4v2.log, /tmp/r734lead_f4pg2.log).")
-->

<!--
@yah:ticket(R734-F3, "Admission policy as signed resource data: mode (open, knock, users, closed) plus minimum confirmation level per relation, carried in SetSnapshot")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-glimmerstone)
@yah:at(2026-10-07T17:42:59Z)
@yah:parent(R734)
@yah:next("Store the policy as rows on a resource, so a change advances ownership_version like any other row change. Add the migration (next free number after 0013, re-checked when you land, since R732-T10 takes one too) across sqlite, pg and turso, plus the cheers-turso migrate.rs version.")
@yah:next("SetSnapshot carries the policy. An edge evaluates every held Admit against the policy it holds NOW (knock.md, The dial), which makes tightening a class revocation with no per-key entries. Defaults for a resource with no policy row: closed for offline admits, which keeps current behaviour.")
@yah:verify("Tests: open admits any key at the floor relation. knock requires an Admit. users makes key-only admits inert. closed makes every offline admit inert. Moving the dial back restores them. An older-epoch snapshot with a looser mode is refused by the ledger.")
@yah:depends_on(R734-F1)
@yah:tier(Warrior)
@yah:next("C1 (operator, 2026-10-07, revised): posted leases (knock.md, Posted lease). For each admission path (knock, offer, scan), the policy carries a default lease, a maximum lease, and the default notice point. The seed is knock = a week (a day allowed) and everything else = 30 days. No purge floor.")
@yah:verify("An Admit whose lease exceeds the policy maximum for its path is refused. Policy defaults are applied when the approver picks no lease.")
@yah:handoff("LANDED (courier Ashguard, uncommitted, git policy defer). No stray draft from the earlier courier existed (no admission.rs, no 0016). New cheers-core/src/admission.rs, re-exported from lib.rs: AdmissionMode{Open,Knock,Users,Closed}, Confirmation{Accept,Compare,Scan} (Ord, weakest first), AdmissionPath{Knock,Offer,Scan}, PostedLease{default,max,notice secs} (new() refuses default<=0, default>max, notice<=0 or notice>default/2; serde try_from re-validates on read), PathLeases::seed() (knock 7d/7d/notice 1d; offer+scan 30d/30d/notice 7d; no purge floor), AdmissionPolicy{mode, floor: String, min_confirmation: BTreeMap<relation,Confirmation>, leases} (admission.rs:172) with new(mode, floor), with_min_confirmation, with_leases.")
@yah:handoff("F2 EVALUATION API (admission.rs:251): `pub fn evaluate_admit(policy: Option<&AdmissionPolicy>, admit: &AdmitFacts<'_>, iat: i64, lease: Option<LeaseRequest>) -> Result<Lease, AdmissionRefusal>`. AdmitFacts{relation:&str, path:AdmissionPath, confirmation:Option<Confirmation> (None = bare key, no Admit), requester_is_user:bool} (admission.rs:204). LeaseRequest{Length(i64) (approver pick), Exact(Lease) (the Admit's signed lease, edge side)} (admission.rs:216). None policy = closed. Rules: closed refuses all; users refuses !requester_is_user; knock/users/closed refuse confirmation None; open admits a bare key only at policy.floor; an Admit below min_confirmation[relation] is refused; lease None = path default; Length/Exact over path max refused (LeaseOverMax); Exact without exp refused (LeaseUnbounded). Refusals: AdmissionRefusal{Mode,NotFloor,BelowConfirmation,LeaseOverMax,LeaseUnbounded,Lease}. Resolved refresh_after = iat + min(path notice, length/2).")
@yah:handoff("Wire: SetSnapshot gains `policy: Option<AdmissionPolicy>` (core snapshot.rs:145, serde default + skip_serializing_if none, placed before the flattened lease) and with_policy() (snapshot.rs:186); SetSnapshot::new signature unchanged. VerifiedSnapshot::admission_policy() (verify snapshot.rs:105). Policy JSON: {mode, floor, min_confirmation (omitted when empty), leases:{knock,offer,scan:{default,max,notice}}}.")
@yah:handoff("Storage: migration 0016_admission_policies (table admission_policies(resource_kind, resource_id, policy TEXT JSON, PK kind+id)), byte-identical in cheers-sqlx migrations/sqlite + pg and cheers-turso migrations/sqlite; turso migrate.rs version 16. OwnershipStore gains admission_policy(kind,id)->Option and set_admission_policy(kind,id,Option<&AdmissionPolicy>,now)->u64 version (server ownership.rs:407,417; Some upserts, None deletes, always advances ownership_version in the same transaction). Helpers encode_/decode_admission_policy (ownership.rs:427,434; malformed row = StoreError::Backend). Implemented on Memory, Arc delegate, sqlx sqlite+pg, turso, Racing (server snapshot.rs tests), cheers-axum tests MemOwnershipStore. Mint (server snapshot.rs) reads the policy inside the version bracket and embeds it.")
@yah:handoff("Docs: knock.md 'The dial' + 'Posted lease' gained short notes on no-policy=closed/omitted field, open floor relation, knock max=default, notice capped at midpoint for shorter leases.")
@yah:handoff("NOISETABLE R803: no wire break. SetSnapshot without policy is byte-identical (golden test). Only additive: new optional `policy` field, new OwnershipStore trait methods (any out-of-tree OwnershipStore impl must add two methods).")
@yah:verify("Baseline cargo test --workspace: 842 pass / 0 fail. After: 872 pass / 0 fail, EXIT=0 (/tmp/r734f3a_ws4.log; count includes F2's concurrent tests). PG (orbstack, --features pg-integration --test pg): 24 pass / 0 fail incl. ownership_store_admission_policy.")
@yah:verify("New tests: core admission.rs (open_admits_any_key_at_the_floor_relation, knock_requires_an_admit, users_makes_key_only_admits_inert, closed_and_no_policy_make_every_offline_admit_inert, moving_the_dial_back_restores_admits, an_admit_below_the_minimum_confirmation_is_refused, defaults_apply_when_no_lease_is_picked, a_lease_over_the_path_maximum_is_refused, a_notice_past_the_midpoint_is_refused_on_build_and_on_read, wire_round_trips); core snapshot policy_rides_the_wire_only_when_present; verify snapshot an_older_epoch_with_a_looser_policy_is_refused (existing ledger, no new code; also no-policy snapshot verifies and reads closed); server snapshot the_policy_row_is_minted_and_its_change_advances_the_epoch; store_scenarios ownership_store_admission_policy run on memory, sqlite, turso, pg.")
@yah:gotcha("F2 (session f235e69f) was editing cheers-verify admit.rs and core knock.rs concurrently and already imports admission::{AdmissionPath, Confirmation}; mid-run its admit.rs test module briefly failed to compile (ConfirmationLevel / requester_binding), settled on its own. I touched none of its files.")
@yah:handoff("Leader re-verified (Glimmerstone, session:ead31b87): cargo test --workspace 875 pass / 0 fail / 4 ignored. cheers-sqlx PG integration 24 pass / 0 fail, including ownership_store_admission_policy (migration 0016). The one workspace warning (unused `policy` at cheers-test-support lib.rs:240) predates R734; it is at anchor 9ddca7b5 line 223, and F4 removes it. Uncommitted (git policy defer).")
@yah:verify("cd oss/cheers && cargo test --workspace --no-fail-fast (875/0), then DOCKER_HOST=unix://$HOME/.orbstack/run/docker.sock cargo test -p cheers-sqlx --features pg-integration --test pg (24/0). Both re-run by the leader on 2026-10-07.")
-->

<!--
@yah:ticket(R734-F2, "Knock artifacts (Knock, Offer, Admit), the AdmitAuthority trait, and its issuer-rooted implementation")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-glimmerstone)
@yah:at(2026-10-07T17:42:56Z)
@yah:parent(R734)
@yah:next("cheers-core: Knock, Offer and Admit as SignedArtifact types, each with its own implicit assertion (urn:cheers:artifact:{knock,offer,admit}:v1). Their fields are in the knock.md Artifacts table. Knock and Admit are signed by device keys, not by the issuer, so they need a verify path keyed by the embedded public key.")
@yah:next("cheers-verify: the AdmitAuthority trait. It answers whether key A holds the admit ability on R under the held policy. Implement it over StandingVerifier (A's binding proves which user A belongs to) and SnapshotVerifier (that user holds a relation with the admit ability). verify_admit_at(admit, now) re-checks the whole chain against the CURRENTLY held snapshot, so an approver's lost right drops their admits that were never uploaded.")
@yah:next("Enforce one-hop delegation: an Admit whose approver key was itself admitted offline, and has no issuer tuple yet, does not verify.")
@yah:verify("Tests: a valid chain admits. An approver demoted in a newer snapshot loses their unreconciled admits. A chain two hops deep is refused. An Admit below the policy's minimum confirmation level is refused (needs F3; stub the policy until then).")
@yah:tier(Wizard)
@yah:next("C1 (operator, 2026-10-07, revised): every Admit carries exp and refresh_after with iat < refresh_after <= iat + (exp - iat) / 2. verify_admit_at refuses an Admit that breaks this and reports refresh_due once now >= refresh_after (the same field as on StandingBinding and SetSnapshot). A Knock may name a prior Admit's jti to renew it.")
@yah:verify("An Admit with refresh_after past its lease midpoint is refused. refresh_due is false before refresh_after and true from it until exp. Past exp the Admit is refused.")
@yah:depends_on(R734-F1)
@yah:depends_on(R734-F5)
@yah:handoff("LANDED (courier Ashguard session:f235e69f, uncommitted, git policy defer). NEW cheers-core/src/knock.rs: Knock{requester:PrincipalId(key),kind,id,relation,nonce,label,standing:Option<binding token>,renews:Option<admit jti>,iat}; Offer{issuer,signer:Option<PrincipalId>,kind,id,relation,max_uses,jti,iat,exp}; Admit{approver(key),approver_binding:Option<token>,authority(issuer URL),requester(key),requester_binding:Option<token>,kind,id,relation,source:AdmitSource{Knock(hash)|Offer(hash)},confirmation:Confirmation,epoch,jti,iat,#[serde(flatten)] lease:Lease}. Assertions urn:cheers:artifact:{knock,offer,admit}:v1. Admit::validate() requires key principals, exp Some and the Lease midpoint; Admit::path() = Scan if confirmation Scan else the source kind. trait DeviceSigned: SignedArtifact { fn signer() } on Knock and Admit; SignedArtifact::issuer() of a device-signed artifact is the signer key id. KnockError{NotAKey,MissingExp,Lease}. Re-exported from cheers-core lib.rs.")
@yah:handoff("NEW cheers-verify/src/admit.rs: verify_device_artifact<T: DeviceSigned>(token)->Result<T,CodecError> (reads the signer from the untrusted payload, then verifies under exactly that Ed25519 key via PasetoV4PublicVerifier::verify_artifact, same envelope); artifact_hash(token) = b64url SHA-256 for AdmitSource. #[async_trait] trait AdmitAuthority { async fn approval_at(&self, approver:&PrincipalId, approver_binding:Option<&str>, kind, id, now) -> Result<Approval{user:Option<UserId>,relation,snapshot:VerifiedSnapshot}, AdmitError> }. IssuerAdmitAuthority<Rd>::new(StandingVerifier, SnapshotVerifier, admit_relations) + hold_snapshot(token) (keeps newest epoch per resource) + pub async fn verify_admit_at(&self, token:&str, now:i64) -> Result<VerifiedAdmit{admit,approval,lease:LeaseState}, AdmitError>. Re-exported from cheers-verify lib.rs.")
@yah:handoff("Chain: device sig -> Admit::validate -> authority==trusted issuer -> Expired refused -> admit jti vs revocation set -> approval_at re-verifies the HELD snapshot at now (so a newer demoting snapshot drops un-uploaded admits) -> approver is issuer-rooted iff the key itself holds an admit relation in the snapshot, OR its standing binding (peer_key == approver key) names a user who does -> requester_binding verified against the requester key gives requester_is_user -> policy. One-hop falls out: the authority never consults other Admits, so an offline-admitted key has no path (NotAnApprover).")
@yah:handoff("POLICY: uses F3's API directly (landed mid-run): cheers_core::evaluate_admit(snapshot.admission_policy(), AdmitFacts{relation,path:admit.path(),confirmation:Some(..),requester_is_user}, admit.iat, Some(LeaseRequest::Exact(admit.lease))); refusal -> AdmitError::PolicyRefused{jti,reason:AdmissionRefusal}. No seam, no stub left. I dropped my own ConfirmationLevel enum in favour of F3's cheers_core::Confirmation. Which relations carry the admit ability is a constructor list on IssuerAdmitAuthority (no ability concept exists in the schema); F3's policy could own it later.")
@yah:handoff("API for noisetable R803: additive only (new types/trait/fns); no existing signature changed by F2. noisetable implements AdmitAuthority over RoomRoster. Device clients sign Knock/Admit themselves with pasetors (flat JSON payload, kind assertion); cheers-verify carries no minter by design.")
@yah:verify("cargo test --workspace --no-fail-fast: 872 pass / 0 fail / 4 ignored, EXIT=0 (baseline 842/0; delta includes F3's tests landing in parallel). Mine (14): knock::tests admit_requires_exp_and_the_midpoint, wire_flattens_the_lease_and_spells_levels_lowercase, each_kind_has_its_own_assertion; admit::tests a_valid_chain_admits, a_key_with_its_own_issuer_tuple_admits_without_a_binding, a_demoted_approver_loses_unreconciled_admits, a_two_hop_chain_is_refused (also a borrowed binding -> PeerKeyMismatch), the_policy_held_now_decides (BelowConfirmation, no policy=closed, users inert, dial back restores), a_lease_past_the_path_maximum_is_refused, a_lease_past_its_midpoint_is_refused, lease_state_through_exp_then_refused (Current/Warning/Expired refused), tampered_and_wrong_assertion_artifacts_are_refused (wrong key, flipped byte, Knock assertion), a_revoked_admit_jti_is_refused, a_knock_verifies_under_its_requester_key.")
@yah:handoff("Users-mode follow-up (leader request): VerifiedAdmit gained `requester_user: Option<UserId>`, the sub of the requester's verified standing binding, which feeds AdmitFacts.requester_is_user (cheers-verify/src/admit.rs). This is an additive field. Neither cheers-test-support nor cheers-server exposes a StandingBinding minter that cheers-verify tests can reach, so the bindings are signed with the test issuer key through a new Rig::bind(by, user, peer) helper.")
@yah:verify("Users-mode tests added (admit::tests): users_mode_admits_a_requester_with_its_own_binding (requester_user == bob), a_requester_binding_for_another_key_is_refused (Standing PeerKeyMismatch), a_requester_binding_from_an_untrusted_issuer_is_refused (Standing Verify). cargo test --workspace --no-fail-fast: 875 pass / 0 fail / 4 ignored, EXIT=0 (log /tmp/r734f2_ws3_users.log).")
@yah:handoff("Leader re-verified (Glimmerstone, session:ead31b87): cargo test --workspace 875 pass / 0 fail / 4 ignored, which includes the users-mode positive test plus the requester_binding refusal tests landed on the warm continue. The policy check calls F3's evaluate_admit directly, so no seam remains. Uncommitted (git policy defer).")
@yah:verify("cd oss/cheers && cargo test --workspace --no-fail-fast: 875/0, re-run by the leader on 2026-10-07 (/tmp/r734lead_f23v1.log).")
-->

<!--
@yah:ticket(R734-F1, "Knock wire: PrincipalKind::Key, and membership widened from user to principal")
@yah:status(review)
@yah:assignee(agent:bundle-anthropic-glimmerstone)
@yah:at(2026-10-07T17:30:54Z)
@yah:parent(R734)
@yah:next("cheers-core principal.rs: add PrincipalKind::Key, whose id is the Ed25519 public key in a fixed wire spelling. Give it a prefix in from_prefix and a constructor beside user/service/camp.")
@yah:next("Widen SnapshotMember.user: UserId to principal: PrincipalId, and widen Revoked::Membership.user the same way. Thread the change through the snapshot mint (cheers-server snapshot.rs), the mask and VerifiedSnapshot::holds (cheers-verify snapshot.rs), the revocation stores of all four engines, and store_scenarios. Every subject in an ownership tuple must accept a Key principal.")
@yah:gotcha("R732-T10 (keyed hash of membership entries) tags (kind, id, user). If T10 lands first, the tag input becomes the principal's wire form. Coordinate with whoever holds T10 instead of reshaping it underneath them.")
@yah:gotcha("Breaking for noisetable: the SetSnapshot member wire changes, and so does is_membership_revoked's subject type. Tell the noisetable R803 leader when this lands.")
@yah:tier(Warrior)
@yah:handoff("Landed (courier Ashguard, uncommitted, git policy defer). cheers-core principal.rs: PrincipalKind::Key with prefix 'key'. The id is base64url-no-pad of the 32-byte Ed25519 key, the same spelling as the JWKS x member (cheers-axum jwks.rs). PrincipalId::key(id) -> Result refuses anything that does not decode to exactly 32 bytes (new PrincipalIdParseError::InvalidKey), and FromStr routes key: through it. PrincipalId::from_public_key(&[u8;32]). From<UserId>/From<&UserId> for PrincipalId (a user kind). PrincipalKind::is_member_kind() = User|Key. PrincipalKind and PrincipalId now derive Ord. A Key with bound_to is refused (NonCampHasBoundTo).")
@yah:handoff("Membership widened: SnapshotMember.principal: PrincipalId (wire {\"principal\":\"user:alice\"}), SetSnapshot::lists(&PrincipalId); Revoked::Membership{principal}; Revoked::membership takes impl Into<PrincipalId>; Revoked::identity() now returns Cow for the 4th part (the principal's wire form).")
@yah:handoff("cheers-verify: membership_tag(key, kind, id, &PrincipalId) hashes the principal's kind-prefixed wire form under ctx urn:cheers:revocation:membership-tag:v2. RevocationReader::is_membership_revoked(key, kind, id, principal: &PrincipalId, epoch) changed across the trait, the Arc delegate, ReplicatedRevocations, memory/sqlx sqlite+pg/turso/redis stores and the cheers-axum admin test stub. VerifiedSnapshot::holds(&PrincipalId) and the mask key on member.principal.")
@yah:handoff("cheers-server: RevokedColumns.subject is now Cow, and membership rows store principal.to_string() and parse it back strictly. The snapshot mint lists User+Key principals. revoke_ownership and revoke_principal_ownership record membership entries for Key principals too.")
@yah:handoff("Migration 0015_membership_principals: UPDATE revocations SET subject='user:'||subject WHERE kind='membership'. Byte-identical in cheers-sqlx migrations/sqlite and pg and cheers-turso migrations/sqlite; turso migrate.rs gains version 15. No ownership CHECK restricted the principal kind, so the tuple subject needed no schema change.")
@yah:handoff("Extra scope: R734-F5 landed Lease in the same files mid-run. I adapted only my own new tests to SetSnapshot::new(.., Lease) and touched none of F5's hunks.")
@yah:verify("Baseline cargo test --workspace: 825 pass / 0 fail. After: 842 pass / 0 fail (--no-fail-fast, EXIT=0). PG (DOCKER_HOST orbstack, --features pg-integration --test pg): 23 pass / 0 fail, EXIT=0.")
@yah:verify("New tests: principal key_principal_round_trips_and_refuses_non_32_byte_ids; core snapshot key_principal_is_a_member_in_wire_form; verify revocation a_user_and_a_key_with_one_id_string_tag_differently; verify snapshot a_key_principal_is_held_and_masked_like_a_user; server snapshot a_key_principal_is_minted_held_and_revoked_like_a_user (memory stores); migration_0015_prefixes_legacy_membership_subjects (sqlite + turso). store_scenarios revocation_writer_and_reader now revokes a Key membership and checks that user:<same id> is distinct, which runs on sqlite, pg and turso (redis too when its test harness runs).")
@yah:gotcha("NOISETABLE BREAK (R803, accepted, not shimmed): (1) SetSnapshot member wire 'user':'alice' -> 'principal':'user:alice'. (2) SnapshotMember.user -> .principal: PrincipalId. (3) RevocationReader::is_membership_revoked takes &PrincipalId. (4) VerifiedSnapshot::holds and SetSnapshot::lists take &PrincipalId. (5) Revoked::Membership.user -> principal, and Revoked::identity() returns Cow. (6) membership_tag ctx is v2 and its input is the prefixed principal, so v1 tags in held sets no longer match: edges must re-adopt a fresh revocation set. (7) RevokedColumns.subject is Cow and no longer Copy. Tell the noisetable R803 leader.")
@yah:gotcha("The memory revocation store is not run through store_scenarios (cheers-server tests it directly). Its Key path is covered by the server snapshot Key test.")
@yah:handoff("Leader re-verified (Glimmerstone, session:ead31b87) with tree anchor 9ddca7b5 plus uncommitted F1/F5 edits (git policy defer, no commit_sha). cargo test --workspace: 842 pass / 0 fail / 4 ignored. cheers-sqlx PG integration: 23 pass / 0 fail. The courier's full account is in the handoff entries above.")
@yah:verify("cd oss/cheers && cargo test --workspace --no-fail-fast (842/0), then DOCKER_HOST=unix://$HOME/.orbstack/run/docker.sock cargo test -p cheers-sqlx --features pg-integration --test pg (23/0). Both re-run by the leader on 2026-10-07.")
-->

<!--
@yah:relay(R734, "Knock: consent-based admission for principals that hold nothing, online and offline (cheers primitive; noisetable rooms specialize it)")
@yah:at(2026-10-07T16:42:44Z)
@yah:next("Library seam (operator, 2026-10-07): cheers is general purpose, and noisetable rooms are one specialization. cheers owns the artifacts, the verifier, the policy model, the online routes, and the AdmitAuthority trait. Consumers own transport and UI. noisetable's side is noisetable R803-F13 (W235-namespaces-and-organizations.md). It is a cross-camp dependency, so it is not a board edge.")
@yah:next("Children run in order. F1 wire: Key principals and principal-shaped membership. Then, in parallel: F2 artifacts plus AdmitAuthority, and F3 admission policy (the dial plus confirmation minimums) carried in the snapshot. Then F4: online routes plus reconciliation.")
@yah:next("Operator approved knock.md on 2026-10-07, with C1 = posted leases. R734-F1 and R734-F5 can start now and in parallel. F2 waits on both.")
-->

# Knock — consent-based admission, online and offline

Status: approved by the operator, 2026-10-07. It was driven by noisetable society rooms (W235).
cheers ships the general primitive, and rooms are one specialization of it.

## Why

Auth frameworks ship *invite*, where an insider names an outsider. Almost none
ship *knock*, where an outsider who holds nothing asks to come in and an
insider consents. Products fake knock with account-first signup, which is the
wrong shape for demos, onboarding and casual rooms. None of them can do it
offline.

What makes a general knock possible here is that cheers treats cloud and
offline as one model. `edge-verifiable-auth.md` §7 and §8 already let an edge
with no issuer in reach verify that a device key belongs to a user and that
the user holds a relation on a resource. That is exactly the authority an
approver needs to show.

## Invariants

1. **A requester needs only a key.** A user account is optional, and it can
   only add to what the key holds.
2. **One model, two paths.** An offline admission and an online one end in
   the same tuple.
3. **The authority root is pluggable.** The cheers issuer is one root, proven
   by a snapshot. A noisetable room's creator-signed roster is another.
4. **Delegation is one hop.** A principal admitted offline cannot admit
   anyone else until the issuer has recorded it.
5. **Admission policy is signed resource data, evaluated at verify time.**
   Tightening the policy drops every admission it no longer permits, without
   naming any of them.
6. **Expiry is posted, never sprung.** Anything that expires announces it by
   its lease's midpoint, and the announcement travels inside the artifact, so
   an offline holder sees it too. cheers standardizes it as one type,
   `Lease` / `LeaseState` (R734-F5), on every standing credential. Consumers
   monitor that state and surface it. cheers never notifies anyone itself.

## A non-user is its key

`PrincipalKind::Key`, whose id is the Ed25519 public key. A non-user is not
identified by its MAC, IP or Bluetooth address:

- MAC addresses are randomized per network.
- Bluetooth LE addresses rotate.
- IP addresses are shared behind NAT.
- All three can be spoofed.

A key is also free to mint. No device identifier resists Sybil attacks, so
resistance has to come from what admission costs (below), never from the
identifier.

Two fields widen from users to any principal: `SnapshotMember.user: UserId`
becomes `principal: PrincipalId`, and so does `Revoked::Membership.user`. Both
are breaking changes, which is fine before 1.0.

## Artifacts

| Artifact | Signed by | Says | Lifetime |
|---|---|---|---|
| `Knock` | the requester's key | Key K asks for relation ρ on R. It may also carry a standing binding naming user U. Includes a nonce and a display label. | pending, minutes |
| `Offer` | an approver's device key, or the issuer | Whoever redeems this with a key may hold ρ on R. Includes max uses. | short `exp` |
| `Admit` | the approver's device key (offline only) | K holds ρ on R. Includes the Knock or Offer hash, the confirmation level, the epoch of the authority it was checked under, a `jti`, and a lease: `exp` plus `refresh_after`. | a posted lease (C1) |

An `Offer` is the invite direction and a `Knock` is the knock direction; both
end in an `Admit`. A QR code can carry either one. noisetable's
`namespace_invite` (consent-based and online) is an online `Offer`.

An online admission needs no artifact, because the tuple it writes is the
record.

## Confirmation levels

| Level | Mechanism | What it defeats |
|---|---|---|
| `accept` | The approver taps accept on the label and key fingerprint. | Nothing beyond "someone asked". |
| `compare` | Both screens show a short code derived from the knock and an approver nonce, the way Bluetooth numeric comparison and Signal safety numbers work. | A nearby device racing a copied label. |
| `scan` | The approver scans a QR code from the requester (key and nonce), or the requester scans the approver's `Offer`. | Anyone not physically present. |

Resource policy sets the minimum level for each relation, and each `Admit`
records the level used. An edge refuses an `Admit` below the minimum in the
policy it currently holds.

## The dial (admission mode)

| Mode | How a new principal gets in | Key-only admits already held |
|---|---|---|
| `open` | Any key, at the floor relation, with no approval. | valid |
| `knock` | An `Admit`. | valid |
| `users` | An `Admit` whose requester presented a standing binding. | inert |
| `closed` | Issuer tuples only. | inert, and so is every other offline admit |

The mode is a row, so changing it advances the epoch and the change ships in
the next snapshot. An edge evaluates every `Admit` it holds against the policy
it holds *now*. Moving the dial is therefore the class revocation: nobody has
to list the spam keys. Moving the dial back restores every admit it made
inert whose lease is still running, spam included. A flood is over once its
knock leases lapse.

A resource with no policy row reads as `closed`, and its snapshot omits the
`policy` field entirely, so snapshots minted before policies existed verify
unchanged. In `open` mode a bare key (no `Admit`) enters only at the policy's
`floor` relation. The policy model and its single evaluation entry point,
`evaluate_admit`, live in cheers-core `admission.rs` (R734-F3).

The snapshot ledger refuses a rollback, because the highest epoch wins. A peer
withholding a newer snapshot is the remaining exposure, the same one the
revocation set has.

## Offline verification (issuer-rooted)

An edge accepts an `Admit` from three artifacts, all of which verify offline:

1. The approver's standing binding (§7).
2. A snapshot of R (§8) showing that the approver's user holds a relation with
   the `admit` ability, under a mode that permits the admission.
3. The `Admit` itself, signed by the approver's bound device key.

The chain is re-checked against the snapshot held now. An approver who loses
the right takes their not-yet-uploaded admits with them.

## Reconciliation

Any device that reaches cheers can upload an `Admit`, including the guest's
own, because the artifact authenticates itself. The issuer then does one of
two things:

- If the approver holds the right now, it writes the tuple with
  `granted_by` set to the approver. From then on the tuple stands on its own
  and survives the approver's removal.
- Otherwise it records `Revoked::Jti` for the admit's `jti`, so edges drop it.

An online knock skips the artifact entirely. `POST /knock` queues a pending
row, and an approver's `POST /knock/{id}/admit` writes the tuple.

Settled by R734-F4 (cheers-server `knock.rs`, cheers-axum `knock.rs`):

- **The admit ability is `AdmissionPolicy::admitters`**, a signed field of the
  policy. The edge reads it off the snapshot, whose members are already
  closure-expanded. The issuer checks it with `SchemaRegistry::holds` over
  live tuples. Both answer the same for a relation held only by implication.
  An empty set means nobody may admit.
- **Every path obeys the live dial.** Online knocks, offer redemptions and
  uploaded `Admit`s all go through `evaluate_admit`, so `closed` stops online
  admission too. An operator can still write tuples directly.
- **Renewal is keyed by the grant.** Admitting a key that already holds a
  *leased* tuple for the same relation on the same resource revokes the old
  tuple and writes one with the fresh lease. A standing tuple is never
  replaced. The `Knock.renews` jti is shown to the approver as information.
- **Every admission has a jti, and the outcome is recorded once per jti**:
  the `Admit`'s own jti, `knock:<pending id>`, or `offer:<jti>:<key>`.
- An online offer is issuer-signed, and redeeming it takes a signed `Knock`
  from the redeeming key. It is evaluated on the `offer` path at confirmation
  `accept`, and its creator must still hold the admit ability.

## Sybil controls

- **Admission cost, chosen by the dial:** a human tap (`knock`), an account
  (`users`), or physical presence (`scan`).
- **Bounded queues:** one pending knock per key per resource, pending knocks
  lapse, and each resource has a cap. Online `POST /knock` is rate-limited.
- **One-hop delegation** (invariant 4): an admitted spam key cannot admit
  more.
- **The dial as class revocation.** It is reversible, and it hides spam keys
  without removing them.
- **Leases.** A flood lapses with its knock leases (a week at most by
  default), with nobody having to act. The dial hides it until then.
- **Rejected: proof-of-work.** It costs a phone more than it costs an
  attacker's GPU.
- **Rejected: device identifiers.** They are free and spoofable.

## The library seam

cheers ships the artifacts, the verifier, the policy model, the online routes
(`cheers-axum`), and an `AdmitAuthority` trait. The trait answers one
question: does key A hold the admit ability on R, under policy P, according to
what this edge holds? cheers implements it over §7 and §8, rooted in the
issuer. `verify_admit_with` runs the offline Admit chain over any
implementation: its `Approval` carries the policy and epoch the root holds
now, and the root also verifies a requester's standing binding. Transport
belongs to the consumer: HTTP on the web, and society LAN/BLE for noisetable.

## noisetable rooms as the specialization

| cheers | noisetable room |
|---|---|
| resource `(kind, id)` | `room:<creator key>` |
| authority root: an issuer snapshot | the creator-signed roster (`AdmitAuthority` over `RoomRoster`) |
| the `admit` ability | `Role::Enroll` |
| a key-principal tuple | a roster `Member { key, label, roles }` |
| the dial | `Admission::OpenRoom` / `Room`, plus `knock` and `users` |
| transport | society presence, BLE, QR |

Today, `OpenRoom → Room` is one-way (`crates/society/core/src/net/admission.rs:669`
in noisetable). A dial makes it two-way.

## Decisions

- **C1 (operator, 2026-10-07, revised the same day): every `Admit` holds a
  posted lease.** The operator first chose "stands until revoked" and then
  reversed it. "How long?" has no right answer, so the design makes the
  answer survivable: whatever lease is chosen, nobody is surprised by its
  end. Rejected: standing until revoked, which needed the purge floor (since
  dropped) to end a flood.

## Posted lease

An `Admit` carries a `Lease` with `exp` set, the standard defined once in
`edge-verifiable-auth.md` ("Lease", shared with §7 and §8). Its invariant,
`iat < refresh_after <= iat + (exp - iat) / 2`, means the holder always gets
at least half the lease as warning, and the verifier refuses an `Admit` that
breaks it, so no client can mint an expiry that comes as a surprise. From
`refresh_after` it reports `LeaseState::Warning`, and `Expired` at `exp`.

The notice is computed from the artifact itself, so an offline device sees it
without anyone pushing it. The holder is told "renew or upgrade", and the
resource's approvers are told "these guests are expiring".

| Lease | Typical use | Notice begins |
|---|---|---|
| a day | a knock for the evening | at the midpoint |
| a week | a knock (default) | after day 1 |
| 30 days | the default for everything else (`Offer`, `scan`) | after week 1 |

Policy sets the default and the maximum per admission path. The approver picks
within them. The seeded knock maximum equals its default (a week), so a day is
a pick below it. The notice point is a fixed offset from `iat` per path; for a
lease shorter than the default it is capped at that lease's midpoint, which is
why a day-long knock warns at its midpoint. A policy whose notice point passes
its own default lease's midpoint is refused at construction and on read.

There are two ways to keep a guest during the notice window:

- **Renew.** A new `Knock` names the old `Admit`'s `jti`, and an approver
  re-admits it with one tap.
- **Upgrade.** The guest gets a longer lease, or becomes a user principal.

A reconciled tuple keeps its `Admit`'s lease, so uploading an `Admit` never
turns a week-long lease into a permanent one.
