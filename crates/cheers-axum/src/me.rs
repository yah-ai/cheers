//! `/me/sessions` routes — list and revoke the live sessions on the
//! authenticated user's account.
//!
//! These two endpoints close the loop on the bearer/PASETO response shape the
//! provider modules return: `SessionBody::access_token` is the bearer token a
//! client hands back here as `Authorization: Bearer <paseto>`. The
//! [`EdgeVerifier`] in [`MeAuthState`] checks the signature *and* the
//! revocation set — the same verifier shape a CF Worker would hold — so the
//! origin and the edge agree on what "still valid" means.
//!
//! ## What you list, and where the binding comes from
//!
//! The refresh-token row in [`RefreshStore`] does **not** carry a
//! `DeviceBinding` (the cheers refresh chain is about *which session*, not
//! *how it authenticated*). To surface
//! `[{device_id, binding, issued_at, expires_at, is_current}]` per the ticket
//! spec, the row lives in product code: the product implements
//! [`SessionDirectory`] over its own table. Both halves of that table are
//! product-owned — [`SessionRecorder`] is how the rows get written, and it is
//! the reason this is implementable at all. The binding is known in exactly
//! three places (magic-link verify, passkey register, passkey authenticate),
//! all of them inside this crate, so a product that merely *mounts* those
//! routers is never on the stack when a session is established; the recorder
//! is the seam that hands it out. Both traits stay in `cheers-axum` rather
//! than `cheers-server` so the cheers-server trait surface remains minimal —
//! no new `SessionStore` trait, per the R018 design call, and the refresh
//! chain goes on saying nothing about how a session authenticated.
//!
//! A service that wants no session list wires [`NoSessionRecorder`] and skips
//! [`router`].
//!
//! ## Revoke semantics
//!
//! `DELETE /me/sessions/{device_id}` calls
//! [`SessionAuthority::revoke_device`](cheers_server::SessionAuthority::revoke_device),
//! which the `UserStore` impl is expected to extend to "also revoke refresh
//! chains for that device" (cheers-sqlx's `PgUserStore` does). That blocks
//! *new* sessions immediately. If the targeted device is the *current*
//! device, the route additionally revokes the current access token's `jti`
//! via [`SessionAuthority::revoke_session`] so the edge stops accepting it
//! within the propagation window. For non-current devices the in-flight
//! access token expires naturally inside the (minutes-scale) access TTL —
//! that bound is documented on [`SessionPolicy`](cheers_server::SessionPolicy).
//!
//! ## Wiring
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use axum::Router;
//! # use cheers_axum::me::{router, MeAuthState, SessionDirectory};
//! # use cheers_server::{EdgeVerifier, SessionAuthority};
//! # async fn run<V, Rd, M, R, U, W, D>(
//! #     edge: Arc<EdgeVerifier<V, Rd>>,
//! #     authority: Arc<SessionAuthority<M, R, U, W>>,
//! #     directory: Arc<D>,
//! # ) -> Result<(), Box<dyn std::error::Error>>
//! # where
//! #     V: cheers_core::TokenVerifier + Send + Sync + 'static,
//! #     Rd: cheers_server::RevocationReader + 'static,
//! #     M: cheers_core::TokenMinter + Send + Sync + 'static,
//! #     R: cheers_server::RefreshStore + 'static,
//! #     U: cheers_server::UserStore + 'static,
//! #     W: cheers_server::RevocationWriter + 'static,
//! #     D: SessionDirectory + 'static,
//! # {
//! let state = MeAuthState { edge, authority, directory };
//! let app: Router = Router::new().nest("/api", router(Arc::new(state)));
//! # Ok(()) }
//! ```
//!
//! @yah:relay(R516, "SessionRecorder seam in cheers-axum so a product can populate SessionDirectory")
//! @yah:at(2026-09-09T06:03:22Z)
//! @yah:assignee(agent:claude)
//! @yah:parent(Q003)
//! @yah:gotcha("The three establish call sites are all INSIDE cheers-axum, so no product code is ever on the stack when a binding is known: crates/cheers-axum/src/magic_link.rs:189 (DeviceBinding::EmailMagicLink, device id freshly minted there by generate_device_id), crates/cheers-axum/src/passkey.rs:341 (register, Passkey) and passkey.rs:461 (authenticate, Passkey). This is the whole gap — not a missing store impl, a missing observation point. The only SessionDirectory impl in the tree today is the test one at crates/cheers-axum/tests/common/mod.rs.")
//! @yah:next("ALTERNATIVE CONSIDERED AND NOT RECOMMENDED — put binding on RefreshTokenRecord plus a binding column on refresh_tokens. It is the more faithful data model but it contradicts the guide-by-omission call stated twice in crates/cheers-server/src/session.rs (rotate and establish_bound both argue the chain is about which session, not how this token authenticated), and its blast radius is cheers-server, cheers/src/store/memory.rs, cheers-sqlx, cheers-redis, cheers-turso, the shared crates/cheers-test-support/src/store_scenarios.rs suite, plus a migration that must land byte-identically in crates/cheers-turso/migrations/sqlite/ and crates/cheers-sqlx/migrations/{sqlite,pg}/ — enforced by migrations_match_cheers_sqlx at crates/cheers-turso/tests/turso.rs:211. The recorder shape touches one crate and no migrations.")
//! @yah:next("FIRST CONSUMER, and why this is filed from outside: noisetable's account service (noisetable camp R131-F7) merges both provider routers at web/services/account/src/auth.rs:258-259 and wants GET /me/sessions for an account-UI device list. It consumes the cheers family as plain crates.io deps at 0.8.32 (web/services/account/Cargo.toml:47-52, no [patch.crates-io] since the R131-T11 graduation), so this landing needs a published release before noisetable can move. Note establish_bound needs no seam: noisetable's node-enrollment route calls it from product code (web/services/account/src/node_token.rs), so the product already holds the binding there.")
//! @yah:verify("cargo test -p cheers-axum — the /me tests at crates/cheers-axum/tests/me_basic.rs must go on passing against a real recorder-backed directory rather than only the hand-rolled one in tests/common/mod.rs")
//! @yah:next("The shape is settled in R516-F1: a SessionRecorder trait in cheers-axum plus a required recorder field on the two provider states. This relay holds the why and the rejected alternative; the work unit is the child.")
//! @yah:gotcha("WHY THIS EXISTS (verified 2026-09-08 against the working tree). SessionDirectory at crates/cheers-axum/src/me.rs was unimplementable by a product that only mounts the provider routers. SessionListEntry requires a binding, but SessionAuthority::establish_inner in crates/cheers-server/src/session.rs hands the binding to mint_access and then writes the root refresh row without it; RefreshTokenRecord in crates/cheers-server/src/store.rs has no binding field, deliberately — 'guide by omission, the refresh chain is about which session, not how it authenticated', per rotate's doc comment. UserStore::list_devices returns bare device ids with no binding either. Hence a recorder rather than a store change.")
//!
//! @yah:ticket(R516-F1, "Add SessionRecorder trait + required state field, call it from the three establish sites")
//! @yah:status(review)
//! @yah:at(2026-09-09T06:21:45Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R516)
//! @yah:next("Declare `#[async_trait] pub trait SessionRecorder: Send + Sync { async fn record_established(&self, user_id: &UserId, device_id: &DeviceId, binding: &DeviceBinding, issued_at: i64, expires_at: i64) -> Result<(), StoreError>; }` in crates/cheers-axum/src/me.rs beside SessionDirectory (me.rs:141) and re-export it from crates/cheers-axum/src/lib.rs where SessionDirectory is already re-exported. Same crate for the same reason me.rs:21-24 gives — the cheers-server trait surface stays minimal, no new SessionStore, per the R018 design call.")
//! @yah:next("Add the recorder as a REQUIRED field (not Option) on MagicLinkAuthState (crates/cheers-axum/src/magic_link.rs:82) and PasskeyAuthState (crates/cheers-axum/src/passkey.rs:188), and call it after establish() returns Ok at magic_link.rs:189, passkey.rs:341 and passkey.rs:461. Ship a no-op impl for services that do not list sessions. Both structs are plain pub-field bundles, so a required field is a compile error at every construction site rather than a silent None — and a missed recorder means a device the user can neither see nor revoke. Breaking for yubaba/passway/cloud-admin, but mechanical: one field, one NoRecorder.")
//! @yah:next("Decide and document the failure policy for record_established. Recommend propagating the error so the sign-in request fails: a session that was minted but not recorded is one the user can neither see on /me/sessions nor revoke from it, which is worse than a failed sign-in the client can retry. The alternative (log and continue) trades a silent security hole for availability and should be an explicit product choice, not the default. Whichever wins, say so in the trait's doc comment — this is the kind of call me.rs already documents rather than leaves to the reader.")
//! @yah:verify("cargo test -p cheers-axum — extend crates/cheers-axum/tests/me_basic.rs so the SessionDirectory under test is fed by a SessionRecorder wired into the magic-link and passkey routers, rather than the hand-populated one in tests/common/mod.rs. That end-to-end path (sign in, then list) is the thing this ticket exists to make possible, so it is the test that proves it.")
//! @yah:handoff("LANDED. `SessionRecorder` + `NoSessionRecorder` in crates/cheers-axum/src/me.rs, re-exported from lib.rs beside SessionDirectory. Required `recorder: Arc<dyn SessionRecorder>` field on MagicLinkAuthState and PasskeyAuthState — `Arc<dyn …>` rather than a seventh generic, matching AdminAuthState's `Arc<dyn OperatorPolicy>` precedent in admin.rs. Called at all three establish sites (magic_link.rs verify, passkey.rs register/finish, passkey.rs authenticate/finish) via the trait's provided `record_new_session(&NewSession)`, which reads the refresh chain's issued_at/expires_at so no caller can pick the access token's minutes-long TTL by mistake. Errors propagate through `From<StoreError> for RouteError`, so a failed record fails the sign-in — documented on the trait with the reasoning and the opt-out.")
//! @yah:handoff("TESTS. crates/cheers-axum/tests/common/mod.rs: MemSessionDirectory now impls SessionRecorder over the same map, which is the product shape — one table, written at establish, read at list. me_basic.rs: seed_session switched to record_new_session (the fixture stopped duplicating the timestamp mapping), plus a new end-to-end magic_link_sign_in_then_list_sessions_round_trip that mounts the magic-link router and the /me router over one authority and one directory, signs in for real, and asserts GET /me/sessions returns that device with binding kind email_magic_link and is_current true — nothing seeded by hand. magic_link_basic.rs asserts one row per sign-in with the refresh-chain lifetime (not the access TTL); passkey_basic.rs asserts register records the device and re-authenticating on it upserts rather than adding a second row. cheers-test-identity mounts NoSessionRecorder — it has no /me surface.")
//! @yah:verify("cargo test --workspace --all-features: cheers-axum 69 unit + 54 integration + 12 doctests green, cheers-server 161 green, whole workspace green except cheers-redis's 5 tests, which fail on SocketNotFoundError(\"/var/run/docker.sock\") — testcontainers with no docker on this host, pre-existing and untouched by this change (no store crate was modified). cargo clippy -p cheers-axum -p cheers-test-identity --all-features --all-targets: no new warnings (the 12 'very complex type' ones are the pre-existing 6-generic handlers; the borrowed-expression one is camps.rs:238). cargo doc: 53 pre-existing warnings crate-wide, none in me.rs / magic_link.rs / passkey.rs. cargo fmt deliberately not run — lib.rs:298 records that the crate is already fmt-dirty tree-wide.")
//! @yah:gotcha("BREAKING for anyone constructing MagicLinkAuthState or PasskeyAuthState — that is the design (a forgotten recorder would be a device the user can neither see nor revoke, so the compiler asks). The only construction sites in the yah monorepo were inside this repo: the two module doctests, the two integration-test rigs, and cheers-test-identity. Grepped /Users/leif/ss/yah for both type names and found nothing else — yubaba, passway and cloud-admin do not construct them, contrary to the guess recorded on the parent relay. Outside the monorepo, noisetable's account service does (web/services/account/src/auth.rs), and it needs a published release to pick this up.")
//!
//! @yah:relay(R728, "User API tokens: a non-interactive credential that IS the user, not a service principal standing next to one")
//! @yah:at(2026-09-12T19:47:16Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:gotcha("Do NOT reach for the session-signing key to work around the absence of this. That is what happened on noisetable R700-T5: with no non-interactive path to a user identity, an agent read the production session-signing key out of the vault into a 0600 file, minted a session directly, and deleted the file. It was careful and it worked, and it is precisely the operation this relay exists to make unnecessary.")
//!
//! @yah:ticket(R728-F1, "Mint, list and revoke user API tokens — /me/tokens beside /me/sessions")
//! @yah:status(review)
//! @yah:at(2026-09-12T19:47:21Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R728)
//! @yah:next("Tier: Wizard — a new credential type with its own TTL, scope and revocation semantics; getting it wrong is a security defect, not a bug.")
//! @yah:next("SHAPE: `POST /me/tokens` (name + requested scopes + optional expiry) returns the secret EXACTLY ONCE; `GET /me/tokens` lists metadata only; `DELETE /me/tokens/{id}` revokes. Mirror the /me/sessions pair at me.rs:303 — same authenticated-caller posture, same revocation row, same uniform 401 for missing/garbage/expired/revoked.")
//! @yah:next("MINT NARROWER THAN THE SESSION THAT CREATED IT — attenuation is the whole point. Requested scopes are INTERSECTED with the caller's own grants, never taken verbatim, so a PAT can never widen its holder. Run validate_grant over each expanded scope the way mint_user_fresh already does (cheers-server/src/session.rs), so a scope smuggled through a bundle is caught BEFORE signing.")
//! @yah:next("GIVE IT AN auth_strength THAT IS NOT `user-fresh` (cheers-core/src/mcp.rs carries the vocabulary). A route guarding a destructive verb must be able to demand a real ceremony and refuse a PAT, and that has to be a claims fact rather than a convention.")
//! @yah:next("BUILD ON THE EXISTING PARTS, DO NOT FORK A PARALLEL STACK: grants keyed (principal, aud) with empty-rejects (grants.rs), bundles expanded at mint (bundles::expand_scopes), RevocationWriter/Reader already consulted by the edge, the audit trail. What is genuinely new is the token record (name, created_at, last_used_at, expiry) and a TTL policy that is not session-shaped.")
//! @yah:next("FOR RIGS, PREFER BINDING OVER A BARE STRING. noisetable already has the ceremony: web/services/account/src/node_token.rs trades a signed nonce for a session token whose claims embed cheers_core::PeerKey, so the result is non-transferable — a stolen token replays under the thief's own node key and is worthless. A bare PAT replays anywhere. If a token is for a machine that holds a key, bind it.")
//! @yah:gotcha("A revoked PAT must 401 INDISTINGUISHABLY from a garbage one — same status and same body. noisetable's account service already pins that equality for sessions (web/services/account/src/lib.rs, me_rejects_revoked_token_indistinguishably) and the same oracle-free posture has to hold here, or the list endpoint plus a 401 variant tells an attacker which stolen strings are still live.")
//! @yah:assumes("That a long-lived user-subject token is acceptable at all, rather than requiring a refresh-style rotation. The operator asked for API tokens explicitly (2026-09-12) on the grounds that end users will want them for metadata edits and for driving rigs from another app.")
//! @yah:handoff("LANDED. POST/GET/DELETE /me/tokens in a NEW module crates/cheers-axum/src/tokens.rs (MeTokensState<V,Rd,B,G,O,W> + tokens_router), deliberately NOT bolted onto MeAuthState: minting needs an McpAuthority (minter+bundles+grants+ownership) and a product that only wants a device list must not be forced to assemble one. Mount both routers under the same base path. Re-exported from cheers_axum as tokens_router / MeTokensState / SharedTokensState / CreateTokenBody / CreatedToken / TokenListEntry.")
//! @yah:handoff("MINT PATH: McpAuthority::mint_api_token(user, aud, requested, ttl_seconds, now) at crates/cheers-server/src/mcp_authority.rs — a third mint path beside mint_user_fresh/mint_bootstrap, same signing key, same generate_jti, same envelope. NOT a second verification stack: the returned token is an ordinary v4.public MCP token and the test verifies it with PasetoV4PublicVerifier::verify_mcp_at, the exact call a resource server makes. TTL policy lives on McpPolicy (api_token_default_ttl_seconds = 90d, api_token_max_ttl_seconds = 365d, with_api_token_ttls builder); out-of-range is REJECTED (McpMintError::TtlOutOfRange -> 400), never clamped.")
//! @yah:handoff("ATTENUATION: grants.list_for(principal, aud) -> empty rejects as AudNotEntitled (403 aud_not_entitled) BEFORE signing; expand_scopes; validate_grant over every expanded scope BEFORE signing (composition rule (4) defence, pinned by mint_api_token_rejects_service_only_scope_smuggled_via_bundle). Empty/omitted scopes = everything held for that aud, frozen at mint. A requested scope outside the effective set is McpMintError::UnentitledScopes naming EVERY offender -> 400 unentitled_scopes with all of them in the message. Never a silent drop.")
//! @yah:handoff("AuthStrength::ApiToken added to cheers-core/src/mcp.rs, serializes \"api-token\". No fallback shim: the enum is #[non_exhaustive] and nothing in this workspace matches it exhaustively, so no call site needed fixing (verified by grep across all 11 cheers crates + the yah monorepo). Doc on the variant states the consumer contract explicitly: these are NOT ranked, a consumer writes matches!(s, UserFresh) rather than 'at least X'.")
//! @yah:handoff("STORAGE: migration 0007_user_tokens.sql in all three dirs — crates/cheers-sqlx/migrations/sqlite/, crates/cheers-turso/migrations/sqlite/ (byte-identical, `diff` clean, registered at version 7 in crates/cheers-turso/src/migrate.rs, migrations_match_cheers_sqlx passes) and crates/cheers-sqlx/migrations/pg/ (BIGINT/BOOLEAN flavor; note pg was at 0005 not 0006 — used_jti is sqlite-only per the R748 deferral, so the pg tree has a deliberate gap at 6). Table + index exactly as specified. NO secret and NO secret_hash column, with the reasoning written into the migration itself: verification is by signature so a hash would have no reader, and a protected column with no reader only widens what a DB leak is worth.")
//! @yah:handoff("UserTokenStore trait + UserTokenRecord + MemoryUserTokenStore in crates/cheers-server/src/user_tokens.rs, exported from cheers_server. Mirrors the MemoryGrantStore/MemoryBundleStore pattern. list_live_for_user filters revoked+expired (same contract SessionDirectory carries); get() returns dead rows too, which is what lets revoke distinguish 'not yours' (404) from 'already dead' (204).")
//! @yah:handoff("REVOKE does both halves in the order that fails safe: RevocationWriter::revoke(jti) FIRST (that is what the edge reads — if the metadata flip then fails the token is still dead), then UserTokenStore::mark_revoked. Foreign jti and unknown jti are the SAME 404 unknown_token, matching /me/sessions' unknown_device shape and reasoning (no id enumeration); the test asserts the two response bodies are byte-equal. Re-revoking your own token is 204, not 404.")
//! @yah:handoff("AUDIT: an AuditRecord is written for both mint and revoke via AuditStore::insert_batch, request_id = the token's jti so an operator can match a mint to its revoke with no join table. A failed audit write FAILS the request (500) — fail-closed; documented on the create handler along with why the already-signed token is not handed back in that case.")
//! @yah:gotcha("DECISION 3 IMPLEMENTED STRUCTURALLY RATHER THAN AS A CHECK, and the difference is worth knowing. All three /me/tokens routes authenticate with a SESSION bearer through me::authenticate (EdgeVerifier::verify_at -> cheers_core::Claims). A session Claims carries no auth_strength and no scope field, so there was no auth_strength == UserFresh predicate to write. What the requirement wanted — 'a PAT cannot mint a PAT' — is instead guaranteed by the claim-shape split: a PAT is McpClaims-shaped, so it fails verify_at outright and collapses into the identical 401 as a garbage string. Pinned by a_pat_cannot_mint_a_pat, which first asserts the PAT IS valid via verify_mcp_at so it is not a broken-token test. Stronger than a branch, because a branch can be forgotten.")
//! @yah:gotcha("THE COST OF THAT, stated rather than buried: GET and DELETE /me/tokens also require a session, so a caller holding ONLY a PAT cannot list or revoke their tokens. Decision 3 wanted those two open to 'any authenticated caller'. Revocation is still reachable from any browser sign-in including a fresh magic link on a new device, which is the locked-out case that mattered. Admitting McpClaims here too needs a second verifier on the state plus an expected_kid/iss/aud trust policy (the shape McpAuthState carries) and an unanswered aud-portability question — a PAT minted for aud https://kamaji is not obviously entitled to manage tokens at cheers's own aud. Filed as the followup below rather than half-wired.")
//! @yah:gotcha("DECISION 9 (PeerKey binding) DELIBERATELY SKIPPED, per its own escape clause. McpClaims has no peer_key field and its absence is an explicit prior decision, not an oversight: R515-F1's gotcha at crates/cheers-core/src/claims.rs says so verbatim ('McpClaims did NOT get a peer_key... If an MCP-call token ever needs the same holder==peer proof, it is a separate additive field'). Adding the field is easy; making it MEAN anything is not — there is no verify_bound_mcp_at, EdgeVerifier::verify_bound_at takes the session Claims shape only, and no edge in this tree reads an MCP peer key. Embedding a binding nothing enforces is exactly the half-wire the ticket told me to avoid.")
//! @yah:gotcha("DECISION 10 (last_used_at) LEFT NULL, per its own escape clause. The column exists, is returned by GET /me/tokens, and UserTokenStore::touch_last_used is on the trait — but cheers never calls it, and there is no cheap hook to add. The only place a use is observable is the verify edge, and EdgeVerifier deliberately holds a RevocationReader and NO writer at all; giving it a store write would undo the property that a compromised edge cannot mutate origin state. The intended writer is a resource server, which is already doing per-call work and already holds writable state. Documented at the trait method and in the migration.")
//! @yah:gotcha("CROSS-CAMP SEAM — kamaji will REJECT a PAT until it adds the variant. oss/kamaji/crates/kamaji-bin/src/auth/claims.rs:81 keeps its OWN copy of AuthStrength { Bootstrap, UserFresh } with #[serde(rename_all = \"kebab-case\")] and no #[serde(other)] fallback, so auth_strength: \"api-token\" fails to deserialize and takes the WHOLE McpClaims with it — the token is refused as malformed. That is fail-closed, so nothing is unsafe, but PATs do not work against kamaji until that enum gains ApiToken. oss/kamaji is a separate cargo workspace and was out of this ticket's blast radius, so it was NOT edited. cheers-core's own consumers are fine: nothing anywhere matches AuthStrength exhaustively (grepped all 11 cheers crates and the yah monorepo).")
//! @yah:gotcha("aud IS A REQUIRED FIELD on POST /me/tokens, which the ticket did not name. Grants are keyed (principal, aud), so the audience is what decides which scopes the caller even has; pinning one aud per deployment would make this surface unable to express a grant table the rest of cheers already models, and defaulting it would silently mint for the wrong resource. Reasoning is on CreateTokenBody.")
//! @yah:verify("BASELINES BEATEN, all measured from the cheers workspace at anchor 16995dbe. cargo test -p cheers-axum --lib: 68 passed / 0 failed (baseline 65, +3 unit tests in tokens.rs). cargo test -p cheers-axum --test \"*\": 50 passed / 0 failed (baseline 38, +12 integration tests in tests/tokens_basic.rs). cargo test -p cheers-server --lib: 152 passed / 0 failed (baseline 140, +4 user_tokens store tests, +8 mint_api_token tests). Also cargo test -p cheers-core --lib 71/0, cargo test -p cheers-axum --doc 10 passed / 2 ignored (the new module doctest compiles), cargo test -p cheers-turso all five binaries green including migrations_match_cheers_sqlx.")
//! @yah:verify("cargo test --workspace from oss/cheers: every test binary reports ok, zero FAILED lines, zero panics, zero error lines. cheers-redis's docker-socket tests did not surface as failures in this run.")
//! @yah:verify("cargo clippy -p cheers-axum -p cheers-server --all-targets: ZERO new warnings. The six that remain are all pre-existing and unrelated — type_complexity at cheers-server/src/grants.rs:43, cheers-axum/src/me.rs:332 and :365, cheers-axum/tests/me_basic.rs:44; needless_borrow at cheers-server/src/camp.rs:1031 and cheers-axum/src/camps.rs:238. My three handlers initially tripped the same type_complexity lint the me.rs handlers carry; fixed properly with a `pub type SharedTokensState<V,Rd,B,G,O,W>` alias rather than an allow attribute.")
//! @yah:verify("diff crates/cheers-sqlx/migrations/sqlite/0007_user_tokens.sql crates/cheers-turso/migrations/sqlite/0007_user_tokens.sql — byte-identical (exit 0), and the drift guard test agrees.")
//! @yah:verify("THE SECURITY PROPERTIES ARE PINNED, not just the plumbing. every_authentication_failure_is_byte_identical drives three doors — a REVOKED session bearer, a garbage string, and a genuinely valid PAT — and asserts all three return 401 with the SAME response body bytes ({\"error\":\"unauthorized\",\"message\":\"unauthorized\"}), so 'revoked' never leaks that a stolen token was real. revoking_a_foreign_or_unknown_token_is_an_identical_404 asserts the two 404 bodies are byte-equal. a_minted_pat_is_frozen_and_does_not_track_later_grant_edits empties the grant table, shows a fresh mint now 403s, shows the already-signed token STILL verifies with its old scopes, and then kills it by revocation — pinning that a signed token does not un-sign itself and that revocation is the answer, so nobody 'fixes' it by re-reading grants on the verify path.")
//! @yah:next("OPEN QUESTION for whoever takes R728 forward: should GET/DELETE /me/tokens also accept a PAT? See the gotcha — it needs an McpClaims verifier on MeTokensState with its own expected_kid/iss/aud, plus a call on whether a PAT minted for aud X may manage tokens at cheers's own aud. That is a product/security decision, not a mechanical one.")
//! @yah:handoff("WAVE 2 — THE PERSISTENT STORES LANDED, closing the gap flagged at the end of wave 1. PgUserTokenStore + SqliteUserTokenStore in crates/cheers-sqlx/src/user_token_store.rs (module + both re-exports registered in cheers-sqlx/src/lib.rs behind the same #[cfg(feature)] gates its siblings use) and TursoUserTokenStore in crates/cheers-turso/src/user_token_store.rs (module + re-export + an AccountStores::user_tokens() accessor beside the other seven). Migration 0007's table is no longer a table nothing writes.")
//! @yah:handoff("ONE SCOPE CODEC, SHARED, NOT COPIED: cheers_server::encode_scopes / decode_scopes in crates/cheers-server/src/user_tokens.rs — the space-joined wire strings, per Scope's Display/FromStr. Both backend families call those same two functions rather than each rolling its own split/join, because a row written by one family must be readable by the other and two copies would agree on the day they were written and drift after. decode_scopes rejects an unparseable token with StoreError::Backend rather than skipping it: a scope cheers cannot parse in a row cheers wrote means the table has drifted from the code, and a silently shorter list would show the user a token weaker than the one they hold.")
//! @yah:handoff("CONTRACT SUITE, NOT PER-BACKEND COPIES: three scenarios added to crates/cheers-test-support/src/store_scenarios.rs (user_token_store_insert_and_scoped_list, _revoked_and_expired_leave_the_live_list, _revoke_is_idempotent_and_touch_stamps) plus a fixture_user_token helper, and all three are called by cheers-turso/tests/turso.rs, cheers-sqlx/tests/sqlite.rs and cheers-sqlx/tests/pg.rs. Same function, three engines — the shape that module's own header argues for. Every scenario seeds a real user first because user_tokens.user_id carries the FK to users.")
//! @yah:handoff("WHAT THE SCENARIOS PIN, beyond round-tripping: list_live_for_user is scoped to one user AND filters revoked+expired AND orders newest-first (matching the (user_id, created_at DESC) index the migration ships); the expiry boundary is exclusive, so expires_at == now is already dead; get() still returns revoked and expired rows, which is the asymmetry DELETE /me/tokens/{id} leans on to tell 'not yours' (404) from 'already dead' (204) — a store that deleted on revoke would turn every second revoke of your own token into a 404; mark_revoked is idempotent and NotFound on an unknown jti; touch_last_used stamps, latest-wins, and is NotFound on an unknown jti; and an empty scope list survives as an empty vec rather than decoding as [\"\"].")
//! @yah:handoff("DISCOVERED WORK DONE IN PASS — crates/cheers-turso/tests/flip.rs gained user_token_rows_survive_the_flip_in_both_directions. flip.rs exists to prove an account DB can move between the sqlx and engine families on one file, and user_tokens is the only table whose column format is not a primitive, so it is exactly the table that could break that claim. The test writes a token through sqlx, hands the file over, reads it through the engine (asserting the scopes vector decodes identically), revokes it there, writes a second row through the engine, hands back, and asserts sqlx sees the revoke and decodes the engine's row. That is what makes 'sharing encode_scopes was sufficient' checked rather than asserted.")
//! @yah:handoff("kamaji TAUGHT THE VARIANT (operator-authorized cross-workspace edit): AuthStrength::ApiToken added at oss/kamaji/crates/kamaji-bin/src/auth/claims.rs, kebab-case to match, with a doc comment on the enum stating that it is a deliberate copy of cheers_core::AuthStrength joined only by the wire strings and that a missing variant fails the WHOLE McpClaims deserialization rather than degrading. No exhaustive match anywhere in kamaji needed fixing — the enum is only constructed and compared. New test api_token_strength_deserializes_and_is_not_user_fresh pins the wire string round trip and that a PAT is not UserFresh, so the seam is proven closed rather than merely compiling.")
//! @yah:handoff("TursoUserTokenStore added to cheers-turso's stores_are_dyn_compatible test — cheers-axum's MeTokensState holds Arc<dyn UserTokenStore>, so losing dyn-compatibility would break the /me/tokens router outright and that is worth a compile-time guard rather than a discovery at wiring time.")
//! @yah:verify("WAVE 2 RE-VERIFICATION, all three baselines still beaten. cargo test -p cheers-axum --lib: 68 passed / 0 failed (baseline 65). cargo test -p cheers-axum --test \"*\": 50 passed / 0 failed (baseline 38). cargo test -p cheers-server --lib: 154 passed / 0 failed (baseline 140 — 152 after wave 1, +2 for the encode_scopes/decode_scopes round-trip and unknown-token tests). cargo test -p cheers-core --lib: 71 passed / 0 failed.")
//! @yah:verify("THE NEW STORE SUITES, actually executed. cargo test -p cheers-sqlx --features sqlite: the sqlite target goes 13 -> 16 passed / 0 failed (the three shared UserTokenStore scenarios against a real migrated in-memory SQLite pool). cargo test -p cheers-turso: turso.rs goes 17 -> 20 passed / 0 failed (same three scenarios against the in-process engine), flip.rs goes 4 -> 5 passed / 0 failed (the new cross-family user_tokens interchange test, driving both store families against one real on-disk file), lib unit tests 20 passed / 0 failed.")
//! @yah:verify("POSTGRES IS COMPILE-VERIFIED, NOT RUN — stated plainly rather than implied. cheers-sqlx/tests/pg.rs is #![cfg(feature = \"pg-integration\")] and stands up a real Postgres container via testcontainers, and this host has no docker socket. `cargo check -p cheers-sqlx --features pg,pg-integration --all-targets` is clean (exit 0, no errors), so PgUserTokenStore and its three gated tests typecheck against the real sqlx Postgres driver — but no Postgres query in this module has been executed. Run `cargo test -p cheers-sqlx --features pg-integration --test pg` on a host with docker before trusting the pg backend in production.")
//! @yah:verify("cargo test --workspace from oss/cheers: zero FAILED lines, zero panics, zero error lines across every test binary.")
//! @yah:verify("kamaji: `cargo test --workspace` from oss/kamaji is fully green (kamaji-bin lib 219 -> 220 passed / 0 failed with the new claims test, kamaji lib 162, kamaji-proto 18, all integration targets ok, zero failures anywhere). `cargo clippy -p kamaji-bin --all-targets` adds no warning in claims.rs — every warning it reports is pre-existing and elsewhere (server.rs x3, pidfd.rs, kamaji-proto/messages.rs, cheers-mock/env.rs).")
//! @yah:verify("CLIPPY CLEAN, ZERO NEW WARNINGS, across everything this ticket touched: `cargo clippy -p cheers-axum -p cheers-server -p cheers-core -p cheers-turso -p cheers-test-support --all-targets` and `cargo clippy -p cheers-sqlx --features pg,sqlite,pg-integration --all-targets` both report no errors, and every warning location is a file this ticket did not create — cheers-server/src/{camp.rs:1031, grants.rs:43}, cheers-axum/src/{camps.rs:238, me.rs:354, me.rs:387}, cheers-axum/tests/me_basic.rs:44, cheers-test-support/src/lib.rs:222, cheers/src/email/template.rs:127. Nothing in either user_token_store.rs, user_tokens.rs, tokens.rs, store_scenarios.rs or kamaji's claims.rs. (The me.rs line numbers moved from 332/365 because this ticket's own annotation block grew in that file's header; they are the same two pre-existing handlers.)")
//! @yah:gotcha("THE POSTGRES BACKEND HAS NEVER BEEN EXECUTED. PgUserTokenStore typechecks against the real sqlx Postgres driver and its three gated tests compile, but cheers-sqlx/tests/pg.rs needs a docker socket this host does not have, so not one of its SQL statements has run. The SQL is the same shape as the SQLite half with $N placeholders and TRUE/FALSE literals against the BOOLEAN column the pg migration declares, which is the difference most likely to bite. Run `cargo test -p cheers-sqlx --features pg-integration --test pg` on a docker host before relying on it.")
//! @yah:gotcha("MIGRATION 0007 IS AT A DIFFERENT INDEX IN THE PG TREE. crates/cheers-sqlx/migrations/pg/ jumps 0005 -> 0007 because used_jti (0006) is deliberately SQLite-only per the R748 deferral. That gap is intentional and sqlx's migrator is fine with it, but anyone diffing the three directories file-by-file will see it and should not 'fix' it by inventing a pg/0006.")
//! @yah:gotcha("last_used_at IS STILL NEVER WRITTEN BY CHEERS — wave 2 changed nothing about that, it only made the column persistent. touch_last_used now has four real implementations and a contract test in the shared suite, but every caller of it is a test: the intended writer is the resource server that consumes PATs, because the only place a use is observable is the verify edge and an EdgeVerifier deliberately holds a revocation READER and no writer. A live deployment will show null in that field until a resource server calls it.")
//! @yah:next("Run the Postgres backend for real: `cargo test -p cheers-sqlx --features pg-integration --test pg` on a host with a docker socket. PgUserTokenStore is compile-verified only — see the gotcha. This is the one remaining unexecuted path in R728-F1.")
//! @yah:handoff("LEADER SIGN-OFF (Ashguard:polaris, relay R728). Scope was widened mid-flight on purpose and the widening is the part worth reading. The dispatch originally scoped storage to \"trait + memory impl for tests\"; the courier landed that, then correctly flagged that migration 0007 created a table nothing wrote. That cut was wrong for the relay's unit of done — R728 is \"a non-interactive credential that IS the user\", and a credential whose list dies with the process is not one — so the same warm courier was sent back for the persistent impls rather than the gap being filed as a followup. It also took the kamaji AuthStrength variant, which was outside the original blast radius and was authorized explicitly because the seam was one this ticket created.")
//! @yah:verify("INDEPENDENTLY RE-VERIFIED by the leader via a separate read-only session, not taken from the implementer's self-report. Confirmed by direct observation: all seven new files present (tokens.rs 483L, tokens_basic.rs 695L, user_tokens.rs 352L, cheers-sqlx/src/user_token_store.rs 311L, cheers-turso/src/user_token_store.rs, three 0007 migrations at 45L each); sqlite-vs-turso migration diff exits 0; both AuthStrength enums (cheers-core/src/mcp.rs:285 and kamaji-bin/src/auth/claims.rs:91) carry ApiToken; TokenListEntry has NO token/secret field, so the secret is mint-only by construction.")
//! @yah:next("STILL NOT MINE, still open for R728: whether GET/DELETE /me/tokens should also accept a PAT rather than only a session bearer. Needs an McpClaims verifier on MeTokensState with its own expected_kid/iss/aud plus a call on whether a PAT minted for aud X may manage tokens at cheers's own aud — an operator decision, being taken to them as a separate ticket.")
//! @yah:verify("LEADER'S OWN TEST RUN, every summary line read rather than a total trusted: cheers-axum --lib 68/0 (baseline 65), cheers-axum --test \"*\" 50/0 (baseline 38), cheers-server --lib 154/0 (baseline 140), cheers-turso 20/0, cheers-sqlx sqlite.rs 16/0 + lib 2/0, kamaji-bin lib 220/0 (+2 mock_issuer_boot, +2 sibling_wire_e2e, +1 uds_skeleton). Zero failures anywhere in either workspace. THE ONE HONEST GAP, restated so nobody reads the green as wider than it is: cheers-sqlx/tests/pg.rs reports 0 passed — it is gated behind the pg-integration feature and a docker socket this host does not have, so PgUserTokenStore is COMPILE-VERIFIED ONLY and not one Postgres statement in it has ever executed. Same class as the pre-existing cheers-redis docker skip. Anyone deploying on Postgres should run that suite against a real instance first.")

use std::sync::Arc;

use async_trait::async_trait;
use axum::Json;
use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{delete, get};
use serde::{Deserialize, Serialize};

use cheers_core::{
    Claims, DeviceBinding, DeviceId, Error, StoreError, TokenMinter, TokenVerifier, UserId,
};
use cheers_server::{
    EdgeVerifier, NewSession, RefreshStore, RevocationReader, RevocationWriter, SessionAuthority,
    UserStore,
};

use crate::error::RouteError;

/// Per-device active-session row a [`SessionDirectory`] returns.
///
/// One row per `(user, device)` pair — the directory is responsible for
/// collapsing rotation chains so a device with many historical refresh
/// tokens still shows up once. `binding` is the authentication that minted
/// the session; the directory stores it (the cheers refresh row doesn't).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SessionDescriptor {
    pub device_id: DeviceId,
    pub binding: DeviceBinding,
    /// Unix-seconds when this session was first established (the root
    /// refresh token's `issued_at`, NOT the latest rotation).
    pub issued_at: i64,
    /// Unix-seconds expiry of the active refresh row — when this device
    /// will be forced to re-authenticate.
    pub expires_at: i64,
}

impl SessionDescriptor {
    pub fn new(
        device_id: DeviceId,
        binding: DeviceBinding,
        issued_at: i64,
        expires_at: i64,
    ) -> Self {
        Self {
            device_id,
            binding,
            issued_at,
            expires_at,
        }
    }
}

/// Per-row JSON shape returned by `GET /me/sessions`.
///
/// `is_current` is derived from the bearer token used on the request: the
/// row whose `device_id` matches the verified [`Claims::device`] flips to
/// `true`. Exactly zero or one row is current; clients can switch on it to
/// label "this device" in a sessions UI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct SessionListEntry {
    pub device_id: String,
    pub binding: DeviceBinding,
    pub issued_at: i64,
    pub expires_at: i64,
    pub is_current: bool,
}

/// Product-side enumeration of a user's active sessions.
///
/// One row per `(user, device)` — the impl is responsible for filtering out
/// revoked + expired entries and for sourcing `binding` (which the cheers
/// refresh-token row doesn't carry; see the module docs). Order is
/// unspecified.
#[async_trait]
pub trait SessionDirectory: Send + Sync {
    async fn list_sessions(
        &self,
        user_id: &UserId,
        now: i64,
    ) -> Result<Vec<SessionDescriptor>, StoreError>;
}

/// Product-side observation of a session at the moment it is established.
///
/// The counterpart to [`SessionDirectory`]: the directory reads a device list
/// back, and this is where the rows come from. cheers calls it from the
/// provider ceremonies (magic-link verify, passkey register/authenticate) —
/// the only points at which a [`DeviceBinding`] is known, and points the
/// product has no call site inside, since it mounts those routers rather than
/// writing them. Without it a product literally cannot implement
/// `SessionDirectory`: the refresh row carries no binding
/// ([`RefreshTokenRecord`](cheers_server::RefreshTokenRecord)), and
/// [`UserStore::list_devices`] hands back bare
/// [`DeviceId`]s.
///
/// `issued_at` / `expires_at` are the refresh chain's, not the access token's
/// — they are the lifetime `SessionDescriptor` reports, and the access TTL is
/// minutes.
///
/// **Called on every establish, including a re-authentication on a device the
/// user already has.** Impls should upsert on `(user_id, device_id)` rather
/// than insert, and are free to overwrite `binding` — the latest ceremony is
/// the honest answer to "how is this device signed in".
///
/// **Also called on every refresh rotation** (`refresh::router`, R730), with
/// the same `(user_id, device_id)` and binding, the extended `expires_at`, and
/// the *rotation* time as `issued_at`. An impl that reports first-sign-in time
/// (as [`SessionDescriptor::issued_at`] documents) keeps its stored
/// `issued_at` on conflict and takes the new `expires_at`. On that path an
/// error is logged rather than failing the request — the token is already
/// spent, so refusing would make the client's retry a replay.
///
/// **An error fails the sign-in.** That is deliberate: a session that minted
/// but did not record is one the user can neither see on `GET /me/sessions`
/// nor revoke from it, which is a worse outcome than a failed sign-in the
/// client can retry. A product that would rather trade that away can swallow
/// the error inside its own impl and return `Ok(())` — but it makes that call
/// explicitly, in its own code.
///
/// Services that surface no session list wire [`NoSessionRecorder`].
#[async_trait]
pub trait SessionRecorder: Send + Sync {
    async fn record_established(
        &self,
        user_id: &UserId,
        device_id: &DeviceId,
        binding: &DeviceBinding,
        issued_at: i64,
        expires_at: i64,
    ) -> Result<(), StoreError>;

    /// Record a [`NewSession`] straight off
    /// [`SessionAuthority::establish`](cheers_server::SessionAuthority::establish).
    ///
    /// Provided, not implemented by products: it exists so the caller cannot
    /// pick the wrong timestamps. The lifetime recorded is the refresh
    /// chain's (minted alongside the access token, and what
    /// [`SessionDescriptor`] reports), never the access token's minutes-long
    /// TTL. The provider ceremonies in this crate call this; a product that
    /// runs its own ceremony over `establish` / `establish_bound` should call
    /// it too.
    async fn record_new_session(&self, session: &NewSession) -> Result<(), StoreError> {
        self.record_established(
            &session.refresh.record.user_id,
            &session.refresh.record.device_id,
            &session.claims.binding,
            session.refresh.record.issued_at,
            session.refresh.record.expires_at,
        )
        .await
    }
}

/// A [`SessionRecorder`] that records nothing, for services with no
/// `/me/sessions` surface.
///
/// The recorder field on the provider states is deliberately required rather
/// than `Option`, so a product that wants a session list cannot forget to
/// wire one — the compiler asks. This is the explicit way to answer "I don't
/// want one", and pairing it with [`me::router`](router) is a contradiction:
/// the directory will stay empty.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoSessionRecorder;

#[async_trait]
impl SessionRecorder for NoSessionRecorder {
    async fn record_established(
        &self,
        _user_id: &UserId,
        _device_id: &DeviceId,
        _binding: &DeviceBinding,
        _issued_at: i64,
        _expires_at: i64,
    ) -> Result<(), StoreError> {
        Ok(())
    }
}

/// State bundle held by the `/me/sessions` handlers.
///
/// `edge` is the same [`EdgeVerifier`] a CF Worker would hold; an integrated
/// origin can construct one from the symmetric codec it already mints with
/// (any [`cheers_core::Codec`] is both a [`TokenMinter`] and a
/// [`TokenVerifier`]), or from the asymmetric pair
/// (`PasetoV4SecretMinter::verifier()` ⇒ a `PasetoV4PublicVerifier`).
pub struct MeAuthState<V, Rd, M, R, U, W, D> {
    pub edge: Arc<EdgeVerifier<V, Rd>>,
    pub authority: Arc<SessionAuthority<M, R, U, W>>,
    pub directory: Arc<D>,
}

impl<V, Rd, M, R, U, W, D> std::fmt::Debug for MeAuthState<V, Rd, M, R, U, W, D> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeAuthState").finish_non_exhaustive()
    }
}

/// Build a router mounting `GET /me/sessions` + `DELETE /me/sessions/{device_id}`.
/// The product nests it under whatever base path it chose (`/api`, …).
pub fn router<V, Rd, M, R, U, W, D>(state: Arc<MeAuthState<V, Rd, M, R, U, W, D>>) -> Router
where
    V: TokenVerifier + Send + Sync + 'static,
    Rd: RevocationReader + Send + Sync + 'static,
    M: TokenMinter + Send + Sync + 'static,
    R: RefreshStore + Send + Sync + 'static,
    U: UserStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
    D: SessionDirectory + Send + Sync + 'static,
{
    Router::new()
        .route("/me/sessions", get(list::<V, Rd, M, R, U, W, D>))
        .route(
            "/me/sessions/{device_id}",
            delete(revoke::<V, Rd, M, R, U, W, D>),
        )
        .with_state(state)
}

/// `GET /me/sessions` — list the authenticated user's active sessions.
pub async fn list<V, Rd, M, R, U, W, D>(
    State(state): State<Arc<MeAuthState<V, Rd, M, R, U, W, D>>>,
    headers: HeaderMap,
) -> Result<Json<Vec<SessionListEntry>>, RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    D: SessionDirectory,
{
    let now = now_unix();
    let claims = authenticate(&headers, &state.edge, now).await?;
    let descriptors = state.directory.list_sessions(&claims.sub, now).await?;
    let current = claims.device.clone();
    let entries = descriptors
        .into_iter()
        .map(|d| {
            let is_current = d.device_id == current;
            SessionListEntry {
                device_id: d.device_id.into_inner(),
                binding: d.binding,
                issued_at: d.issued_at,
                expires_at: d.expires_at,
                is_current,
            }
        })
        .collect();
    Ok(Json(entries))
}

/// `DELETE /me/sessions/{device_id}` — revoke a device for the authenticated
/// user. Returns `204 No Content` on success. If the targeted device is the
/// current one, the in-flight access token's `jti` is also revoked so the
/// edge stops accepting it immediately.
pub async fn revoke<V, Rd, M, R, U, W, D>(
    State(state): State<Arc<MeAuthState<V, Rd, M, R, U, W, D>>>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> Result<StatusCode, RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    M: TokenMinter + Send + Sync,
    R: RefreshStore,
    U: UserStore,
    W: RevocationWriter,
{
    let now = now_unix();
    let claims = authenticate(&headers, &state.edge, now).await?;
    let target = DeviceId::new(device_id);
    state
        .authority
        .revoke_device(&claims.sub, &target, now)
        .await
        .map_err(map_authority_error)?;
    if target == claims.device {
        state
            .authority
            .revoke_session(&claims.jti, claims.expires_at)
            .await
            .map_err(map_authority_error)?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Extract the raw token from `Authorization: Bearer <token>`. Returns
/// [`RouteError::MissingBearer`] / [`RouteError::MalformedBearer`] for the
/// two distinct failure modes so a client can tell "didn't send a header"
/// from "sent a header in the wrong shape".
pub fn bearer_from_headers(headers: &HeaderMap) -> Result<&str, RouteError> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .ok_or(RouteError::MissingBearer)?
        .to_str()
        .map_err(|_| RouteError::MalformedBearer)?;
    let token = raw
        .strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .ok_or(RouteError::MalformedBearer)?;
    if token.is_empty() {
        return Err(RouteError::MalformedBearer);
    }
    Ok(token)
}

/// Pull the bearer header and run the [`EdgeVerifier`] over the token at
/// `now`. Maps verification failures to [`RouteError::Unauthorized`].
pub async fn authenticate<V, Rd>(
    headers: &HeaderMap,
    edge: &EdgeVerifier<V, Rd>,
    now: i64,
) -> Result<Claims, RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
{
    let token = bearer_from_headers(headers)?;
    edge.verify_at(token, now).await.map_err(map_verify_error)
}

fn map_verify_error(err: Error) -> RouteError {
    match err {
        // A token that failed the codec layer (bad signature, expired,
        // malformed) is the same outcome from the caller's POV: 401.
        Error::Codec(_) => RouteError::Unauthorized,
        Error::Revoked => RouteError::Unauthorized,
        Error::Store(e) => RouteError::Store(e.to_string()),
        // Refresh / InvalidInput don't surface from EdgeVerifier::verify_at
        // in practice — keep them mapped to the existing buckets rather than
        // letting them silently turn into 401.
        Error::Refresh(e) => RouteError::Store(e.to_string()),
        Error::InvalidInput(msg) => RouteError::Config(msg),
        // cheers_core::Error is #[non_exhaustive] — any future variant gets
        // a generic 500 bridge until a dedicated mapping lands.
        other => RouteError::Store(other.to_string()),
    }
}

fn map_authority_error(err: Error) -> RouteError {
    match err {
        Error::Store(StoreError::NotFound) => RouteError::UnknownDevice,
        other => RouteError::from(other),
    }
}

fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_from_headers_accepts_canonical_form() {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            "Bearer abc123".parse().unwrap(),
        );
        assert_eq!(bearer_from_headers(&h).unwrap(), "abc123");
    }

    #[test]
    fn bearer_from_headers_accepts_lowercase_scheme() {
        // RFC 7235 says the scheme is case-insensitive; some clients lowercase.
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            "bearer abc123".parse().unwrap(),
        );
        assert_eq!(bearer_from_headers(&h).unwrap(), "abc123");
    }

    #[test]
    fn bearer_from_headers_distinguishes_missing_from_malformed() {
        let empty = HeaderMap::new();
        assert!(matches!(
            bearer_from_headers(&empty).unwrap_err(),
            RouteError::MissingBearer,
        ));

        let mut wrong_scheme = HeaderMap::new();
        wrong_scheme.insert(header::AUTHORIZATION, "Basic abc123".parse().unwrap());
        assert!(matches!(
            bearer_from_headers(&wrong_scheme).unwrap_err(),
            RouteError::MalformedBearer,
        ));

        let mut empty_token = HeaderMap::new();
        empty_token.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
        assert!(matches!(
            bearer_from_headers(&empty_token).unwrap_err(),
            RouteError::MalformedBearer,
        ));
    }
}
