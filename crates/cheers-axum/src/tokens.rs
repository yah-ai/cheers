//! `/me/tokens` routes — mint, list, revoke and rotate the authenticated
//! user's API tokens (PATs).
//!
//! The sibling of [`me`](crate::me): same authenticated-caller posture, same
//! bearer extractor, same uniform 401, same "revocation is not deletion" shape
//! — for a credential that is *not* a browser session.
//!
//! ## What a PAT is, in one sentence
//!
//! An ordinary `v4.public` MCP token, minted by
//! [`McpAuthority::mint_api_token`], signed with the same key, carrying the
//! same `jti`, checked against the same revocation set — differing only in
//! `auth_strength: "api-token"`, a long caller-chosen expiry, and a scope list
//! that is a subset of the minter's entitlement.
//!
//! There is deliberately **no opaque-secret verification path**: cheers never
//! looks up presented bytes, so there is no secret and no secret hash in the
//! database (see [`cheers_server::user_tokens`]). The only genuinely new
//! persistence is the metadata row, keyed by `jti`, which exists so the user
//! can *see* and *name* what they have issued.
//!
//! ## Why this is a separate state and router from `/me/sessions`
//!
//! Minting needs an [`McpAuthority`] — a minter, a bundle store, a grant store
//! and an ownership store. A product that wants a device list has no business
//! being forced to assemble a mint authority to get one, so
//! [`MeAuthState`](crate::me::MeAuthState) is left alone and this ships its
//! own [`MeTokensState`]. Mount both, or either.
//!
//! ## Authentication: four routes, two doors, and which is which is the design
//!
//! There are two credential shapes: a **session** bearer
//! (`cheers_core::Claims`, what `/me/sessions` takes) and a **PAT**
//! (`McpClaims`). They are distinct PASETO payload shapes, so neither verifier
//! can be fooled by the other's token — the split is structural, not a check
//! that could be forgotten.
//!
//! | Route | Session | PAT | Why |
//! |---|---|---|---|
//! | `POST /me/tokens` | yes | **no** | Mints from the *grant table*. The one really protected door. |
//! | `GET /me/tokens` | yes | yes | Returns only the caller's own metadata. Widens nobody. |
//! | `DELETE /me/tokens/{id}` | yes | yes | Only ever removes authority. Widens nobody. |
//! | `POST /me/tokens/{id}/rotate` | yes | yes (its own id only) | Mints from the *presented token's* scopes. Can narrow, never widen. |
//!
//! `POST /me/tokens` staying session-only is what keeps "a PAT cannot mint a
//! PAT" true: a PAT presented there fails `EdgeVerifier::verify_at` outright
//! and collapses into the same 401 as a garbage string, so the grant table is
//! only ever read on behalf of a real interactive ceremony.
//!
//! The other three admit either shape, because **credential maintenance must
//! not be a PITA** (operator, 2026-09-12) — a credential a script holds has to
//! be able to see itself, kill itself, and roll itself without a human opening
//! a browser. R728-F1 shipped these three session-only and this is the ticket
//! that opened them.
//!
//! ### The PAT's `aud` is deliberately NOT checked
//!
//! [`ApiTokenTrust`] carries an `expected_kid` and an `expected_iss` but no
//! `expected_aud` — unlike [`McpAuthState`](crate::mcp::McpAuthState), which a
//! resource server uses and which must reject a token minted for someone
//! else's resource. Grants are keyed `(principal, aud)`, so requiring the
//! PAT's `aud` to be cheers's own would narrow this feature to tokens a user
//! minted *specifically* for credential management — which is likely nobody,
//! and every rig token would be unable to roll itself.
//!
//! It is safe on its own terms, and the reason is that none of the three verbs
//! grants authority at an audience: listing returns the caller's own metadata,
//! revoking only subtracts, and rotating is bounded by the presented token's
//! own scopes (see [`rotate`]). What the `aud` claim protects — "this token
//! may act on that resource" — is not a thing any of them do.
//!
//! ### One revocation set, one uniform 401
//!
//! Both doors read the *same* revocation set: the PAT path calls
//! `EdgeVerifier::revocations()` rather than being handed a second reader that
//! could disagree about what is dead. And every failure on either path — no
//! bearer, garbage, wrong `kid`, wrong `iss`, bad signature, expired, revoked,
//! a non-user principal — returns the identical 401 body. That is what keeps a
//! revoked token from telling an attacker it was ever real, and
//! `every_authentication_failure_is_byte_identical` in
//! `tests/tokens_basic.rs` drives both verifiers to prove it.
//!
//! ## Attenuation
//!
//! Requested scopes are intersected with a ceiling, never taken verbatim, and
//! an unheld scope is a 400 naming it rather than a silent drop. The two mint
//! paths differ only in where that ceiling comes from, and the difference is
//! the security boundary between them:
//!
//! - [`create`] → [`McpAuthority::mint_api_token`]: the caller's grants for
//!   the requested `aud`, bundle-expanded.
//! - [`rotate`] → [`McpAuthority::rotate_api_token`]: the **presented
//!   token's own scopes**. It never reads the grant table, so a frozen
//!   credential cannot re-widen itself by rolling over.
//!
//! See those two methods for the full rule set.
//!
//! ## Wiring
//!
//! ```no_run
//! # use std::sync::Arc;
//! # use axum::Router;
//! # use cheers_axum::tokens::{router, ApiTokenTrust, MeTokensState};
//! # use cheers_server::{AuditStore, EdgeVerifier, McpAuthority, PasetoV4PublicVerifier, RevocationWriter, UserTokenStore};
//! # async fn run<V, Rd, B, G, O, W>(
//! #     edge: Arc<EdgeVerifier<V, Rd>>,
//! #     mcp: Arc<McpAuthority<B, G, O>>,
//! #     tokens: Arc<dyn UserTokenStore>,
//! #     revocations: Arc<W>,
//! #     audit: Arc<dyn AuditStore>,
//! #     verifier: PasetoV4PublicVerifier,
//! # ) -> Result<(), Box<dyn std::error::Error>>
//! # where
//! #     V: cheers_core::TokenVerifier + Send + Sync + 'static,
//! #     Rd: cheers_server::RevocationReader + 'static,
//! #     B: cheers_server::BundleStore + 'static,
//! #     G: cheers_server::GrantStore + 'static,
//! #     O: cheers_server::OwnershipStore + 'static,
//! #     W: RevocationWriter + 'static,
//! # {
//! // The PAT half: the published key this surface trusts, and the issuer it
//! // trusts it to speak for. No `aud` — see the module docs.
//! let pat = ApiTokenTrust::new(verifier, "platform-kid-1", "https://cheers.example");
//! let state = MeTokensState { edge, mcp, tokens, revocations, audit, pat };
//! let app: Router = Router::new().nest("/api", router(Arc::new(state)));
//! # Ok(()) }
//! ```
//!
//! @yah:ticket(R728-F2, "Can a PAT manage PATs? Admit McpClaims on GET/DELETE /me/tokens, or don't")
//! @yah:status(review)
//! @yah:at(2026-09-12T20:48:31Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R728)
//! @yah:next("THE ARGUMENT FOR NO (leave as landed): revocation is already reachable from any browser sign-in including a fresh magic link on a new device, which is the locked-out case that actually mattered. Credential management being ceremony-gated is a feature, not a gap.")
//! @yah:gotcha("Do NOT open this up by adding a second verifier and calling it done. Admitting McpClaims on MeTokensState means giving that state its own expected_kid/iss/aud trust policy, and the uniform-401 property (every_authentication_failure_is_byte_identical in cheers-axum/tests/tokens_basic.rs) must still hold across BOTH claim shapes afterwards — a second verifier is a second place for a distinguishable failure to leak out.")
//! @arch:see(crates/cheers-axum/src/tokens.rs)
//! @yah:next("Tier: Wizard — it is an authentication-surface decision with a uniform-401 invariant to preserve, not a handler edit.")
//! @yah:gotcha("THE HARD SUB-QUESTION, and the reason this is an operator call rather than a default: a PAT is minted for a specific aud, because grants are keyed (principal, aud). Is a PAT minted for `aud https://kamaji` entitled to manage credentials at cheers's OWN aud? The conservative answer — admit a PAT only when its aud IS cheers's own aud — is defensible but narrows the feature to tokens a user minted specifically for credential management, which may be nobody. The permissive answer makes any rig token a credential-management token. That is a product/security tradeoff with no obviously-correct default.")
//! @yah:next("THE QUESTION: as landed in R728-F1, all three /me/tokens routes authenticate with a SESSION bearer via me::authenticate (EdgeVerifier::verify_at -> cheers_core::Claims). A caller holding ONLY a PAT therefore cannot list or revoke their own tokens — a PAT is McpClaims-shaped, fails verify_at, and collapses into the uniform 401. That was deliberate, not an oversight: R728-F1's dispatch asked for GET/DELETE to accept any authenticated caller, and the courier correctly declined to half-wire it.")
//! @yah:next("THE WORK, if the answer is yes: give MeTokensState an McpClaims verifier alongside the EdgeVerifier, with its own expected_kid/iss/aud trust policy (the shape McpAuthState already carries), accept EITHER claim shape on GET and DELETE only, and keep POST session-only so a PAT still cannot mint a PAT. Then extend every_authentication_failure_is_byte_identical to drive both verifiers' failure paths and assert the bodies stay byte-equal.")
//! @yah:gotcha("OPERATOR ANSWERED 2026-09-12, verbatim: \"list and revoke, seems like wider than create. right? we DO as much as possible want a credential to be able to roll itsself except for really protected sections of the app. credential maintenance is NOT something we want to be a PITA\". Two instructions in that, and the second is bigger than the question asked. (1) YES — admit a PAT on GET and DELETE, and they explicitly endorse that list+revoke is a wider door than create. (2) A credential must be able to ROLL ITSELF, which list+revoke alone does not deliver: rolling needs a mint, and create stayed session-only. So this ticket grew a rotate endpoint. Read the next entries for the shape.")
//! @yah:next("SHAPE AS DECIDED (leader, off the operator's answer). Three doors, three postures. (a) GET /me/tokens and DELETE /me/tokens/{id} accept EITHER claim shape — session bearer or PAT — and the PAT's aud is NOT checked, because the permissive read is what \"credential maintenance must not be a PITA\" asks for and neither verb can widen anyone: listing returns only the caller's own metadata, and revoking only ever removes authority. (b) NEW POST /me/tokens/{id}/rotate — authenticated by the PAT ITSELF, mints a replacement whose scopes are a subset of the PRESENTING token's scopes (never re-read from the grant table, or a rotate would silently re-widen a frozen token back up to current grants), then revokes the old jti. Returns the new secret exactly once, same shape as create. A session bearer may rotate too. (c) POST /me/tokens is unchanged and stays session-only — that is the \"really protected section\", and it is the door where scopes are drawn from grants rather than from an existing token.")
//! @yah:next("THE INVARIANT THAT MUST SURVIVE ALL OF IT: a PAT can never widen its holder. Rotate is the new place that could break it — scopes come from the presenting token's own claims, intersected with nothing else, never from grants.list_for. A rotate must also not extend authority indefinitely without bound: give the replacement its own fresh TTL under the same McpPolicy ceiling (api_token_max_ttl_seconds), and requesting more than the presenting token's remaining life is allowed only up to that ceiling, not beyond it. The second invariant is the uniform 401: with a second verifier on MeTokensState there are now two failure paths, so every_authentication_failure_is_byte_identical must be extended to drive BOTH and assert the bodies stay byte-equal — that test is the reason a revoked token does not tell an attacker it was ever real.")
//! @yah:handoff("LANDED, all three doors as the leader specified. (a) GET /me/tokens and DELETE /me/tokens/{id} now take EITHER claim shape. (b) NEW POST /me/tokens/{id}/rotate. (c) POST /me/tokens unchanged and still session-only — a_pat_cannot_mint_a_pat still passes untouched. The admitting helper is tokens::authenticate_any (crates/cheers-axum/src/tokens.rs), which returns a Caller { user: UserId, credential: Credential::{Session,ApiToken} }; list/revoke/rotate all go through it and me::authenticate is now used by create alone. No authenticate_v2 beside the old one — the three handlers were reshaped onto the new return type and their call sites fixed.")
//! @yah:handoff("ROTATE, the half list+revoke does not deliver. POST /me/tokens/{id}/rotate mints a replacement, persists its row, revokes the old jti in BOTH halves (RevocationWriter first, then mark_revoked), writes two audit rows (one per jti, both method 'POST /me/tokens/rotate' so the rotation is findable from either id), and returns 201 with the same CreatedToken shape create uses — the new secret exactly once. Body is OPTIONAL (Option<Json<RotateTokenBody>>, axum 0.8's OptionalFromRequest): a bare `curl -X POST .../rotate` with no body means 'same again', because requiring a body to say nothing is exactly the PITA the operator named. RotateTokenBody carries name/scopes/expires_in_secs and deliberately NO aud — changing audience means reading the grant table, which makes it a mint, not a roll.")
//! @yah:handoff("THE MINT PATH THAT DOES NOT READ GRANTS: McpAuthority::rotate_api_token in crates/cheers-server/src/mcp_authority.rs, mint path 3b beside mint_api_token. It is deliberately NOT async — it performs zero store I/O, and that absence IS the property: the scope ceiling is the `held` slice the caller passes (the presented token's own claims), so no grants.list_for can creep back in. Shared with the create path rather than copied: api_token_ttl() (policy default, ceiling, reject-never-clamp) and the free fn attenuate() (requested-vs-ceiling intersection, UnentitledScopes naming every offender) and sign_api_token() (claims + AuthStrength::ApiToken + mint_mcp) are now used by BOTH, so the two paths cannot drift on the rules they share while differing only where they must. validate_grant still runs over the resulting scopes so a service-only scope cannot be laundered forward by a re-sign.")
//! @yah:handoff("TWO SUPPORTING RESHAPES, both chosen over a parallel copy. (1) cheers-verify: EdgeVerifier gained `pub fn revocations(&self) -> &Rd` (crates/cheers-verify/src/edge.rs) so the PAT path reads the SAME revocation set the session path does — McpClaims is verified by an inherent method rather than through TokenVerifier, so it cannot ride verify_at, and handing this surface its own second reader would let two halves of one route disagree about what is dead. Returning a RevocationReader widens nobody: it can ask, never revoke. (2) cheers-axum/src/mcp.rs: authenticate_mcp's body was lifted into pub fn verify_mcp_bearer(headers, verifier, kid, iss, expected_aud: Option<&str>, now) and authenticate_mcp now calls it with Some(aud). One verification body, two audience postures, chosen at the call site — so the aud-blind door cannot drift from the resource-server door.")
//! @yah:gotcha("THE {id} RULE, decided and written down as the ticket asked. A PAT may rotate ONLY ITSELF ({id} == its own jti); a session may rotate any of that user's tokens. Reason for the PAT half: rolling a SIBLING is lateral movement — a narrow credential minting a replacement for authority it does not itself hold — and the operator's requirement was that a credential roll ITSELF. Reason the session half is unrestricted: a session could mint a wider token outright at POST /me/tokens, so restricting it at rotate would protect nothing. The refusal for a wrong {id} is the same 404 unknown_token a nonexistent id gets (pinned byte-equal by a_pat_cannot_rotate_a_token_that_is_not_its_own), and it is checked BEFORE the store read so a stolen token cannot probe which sibling ids are real. NOTE the asymmetry with DELETE, which is deliberate: a PAT may revoke ANY of the user's tokens, because revoking only ever subtracts authority and a holder locked out of everything else should be able to kill the lot from whatever they still have.")
//! @yah:gotcha("WHERE A SESSION'S ROTATE GETS ITS CEILING, since 'the presenting token's own claims' has no answer for a session (a session Claims carries no scope field). A session rotating token X mints from X's OWN metadata row scopes — the authority actually being rolled — never from grants.list_for. Pinned by a_session_may_rotate_any_of_the_users_tokens_bounded_by_that_token: the session holds cloud:deploy in the grant table, the target token does not, and the rotation asking for cloud:deploy is a 400. For a PAT the ceiling and the aud both come from the SIGNED claims rather than the row, because the row is metadata and the claims are the authority. A dead target (revoked OR expires_at <= now) is 404 unknown_token, not a fresh token: rotating a revoked credential would resurrect authority its owner already ended, and the 404 is the same body a foreign id gets.")
//! @yah:gotcha("ORDER OF OPERATIONS IN ROTATE, and why it is not the obvious one. Mint -> insert the new row -> revoke the old jti (RevocationWriter first, then mark_revoked) -> audit. Revoking FIRST and failing afterwards would leave the caller holding NOTHING: old credential dead, replacement never received. Failing before the revoke leaves them holding their old still-working token plus an orphan jti nobody has, which expires on its own. Same fail-closed reasoning as create's 'a failed metadata write fails the request even though the token is already signed'. Anyone tempted to 'clean up' by revoking early should read this first.")
//! @yah:gotcha("KAMAJI WAS NOT BUILT, and here is the grounds rather than an assumption. This ticket did not touch AuthStrength or McpClaims (cheers-core is unmodified — verified by the diff), and no crate under oss/kamaji/crates/*/Cargo.toml depends on cheers-core, cheers-verify or cheers-server (grepped). The R728-F1 seam is a deliberate copy of the enum joined only by wire strings, and no wire string changed here, so there is nothing for kamaji to re-learn. If a future change to this surface moves an McpClaims field, that build is back on the hook.")
//! @yah:verify("EVERY BASELINE BEATEN, each summary line read rather than a total trusted. cargo test -p cheers-axum --lib 68/0 (baseline 68, unchanged — the new work is integration-shaped). cargo test -p cheers-axum --test main 60 passed / 0 failed (baseline 50, +10). cargo test -p cheers-server --lib 159/0 (baseline 154, +5 rotate_api_token unit tests). cargo test -p cheers-turso 20/0 plus flip 5/0, magic_link_replay 2/0, lib 20/0, doc 1/0. cargo test -p cheers-sqlx --features sqlite: sqlite.rs 16/0, lib 2/0. cargo test -p cheers-verify green. cargo test -p cheers-axum --doc 10 passed / 2 ignored (the reshaped wiring doctest compiles with the new `pat` field). cargo test --workspace from oss/cheers: 34 'test result: ok' lines, zero FAILED, zero failures:, zero error lines.")
//! @yah:verify("THE UNIFORM 401 NOW SPANS BOTH VERIFIERS — every_authentication_failure_is_byte_identical went from 3 arms to 7 and asserts every body is byte-equal to the first: (1) a revoked session bearer, (2) a garbage string, (3) a REVOKED PAT, (4) an EXPIRED PAT (minted with a past `now` so its exp is already gone — same key, same kid, same iss), (5) a PAT signed by a FOREIGN KEY, (6) a PAT signed by OUR key with OUR kid and a foreign `iss` (the subtlest arm: valid signature, valid kid, only the trust policy can catch it), (7) a valid camp-subject token (mint_bootstrap) whose principal is not a user. All seven return 401 with {\"error\":\"unauthorized\",\"message\":\"unauthorized\"}. Arms 4-6 are built by a new foreign_authority(secret, iss) helper and the rig now keeps the mint key's raw secret so arm 6 can sign identically to the rig.")
//! @yah:verify("ROTATE'S OWN PROPERTIES, all pinned as the dispatch listed them. rotate_replaces_the_token_and_kills_the_one_it_replaces (new jti != old, the replacement verifies with verify_mcp_at and carries auth_strength api-token, the old bytes 401 on the very next request, both revocation halves flipped, list shows exactly one live row, three audit rows covering both ids). rotate_scopes_come_from_the_presented_token_not_from_current_grants (grants WIDENED after mint; asking for the new scope is a 400 naming cloud:destroy, a plain roll carries cloud:read over unchanged). rotate_can_narrow_and_rename (+ blank rename is 400). a_pat_cannot_rotate_a_token_that_is_not_its_own (sibling id byte-equal to a nonexistent id, nothing minted, sibling not revoked). rotating_a_revoked_token_is_refused_rather_than_resurrected. rotating_a_foreign_users_token_is_an_identical_404. rotate_gets_a_fresh_ttl_and_is_still_bounded_by_the_policy_ceiling (over-ceiling rejected not clamped; the default roll is a full 90d, longer than the hour the replaced token had left). a_pat_can_list_and_revoke_with_no_session_at_all and a_pat_minted_for_another_audience_still_manages_credentials cover the list/revoke half and the aud-blind call. At the unit level: rotate_api_token_mints_from_the_presented_scopes_without_reading_grants asserts the contrast directly — an EMPTY grant table still rolls a token, while the same inputs through mint_api_token are AudNotEntitled.")
//! @yah:verify("CLIPPY: cargo clippy -p cheers-axum -p cheers-server -p cheers-verify --all-targets — ZERO new warnings. Every warning it reports is pre-existing and in a file this ticket did not create or edit: type_complexity at cheers-server/src/grants.rs:43, cheers-axum/src/me.rs:374 and :387 (the same two pre-existing /me/sessions handlers R728-F1 noted; the line numbers moved again only because annotation blocks in that file's header grew) and cheers-axum/tests/me_basic.rs:44; needless_borrows_for_generic_args at cheers-axum/src/camps.rs:238 and cheers-server/src/camp.rs:1031. Nothing in tokens.rs, mcp.rs, mcp_authority.rs, cheers-verify/src/edge.rs or tokens_basic.rs. The new six-generic rotate handler avoids the type_complexity lint by using the existing SharedTokensState alias rather than an allow attribute.")
//! @yah:handoff("LEADER SIGN-OFF (Ashguard:polaris, relay R728). This ticket was filed as a yes/no question about GET/DELETE and came back from the operator as something larger: \"we DO as much as possible want a credential to be able to roll itsself\". List+revoke alone does not deliver that — rolling needs a mint — so the ticket grew POST /me/tokens/{id}/rotate. Reviewers should read it as the operator's answer implemented, not as scope drift: the second sentence of that answer is the rotate endpoint.")
//! @yah:verify("INDEPENDENTLY RE-VERIFIED by the leader in a separate read-only session, by quoted source rather than the implementer's word. THE INVARIANT THAT MATTERED: no grant read happens anywhere on the rotate path. rotate_api_token (cheers-server/src/mcp_authority.rs:472) is non-async and its body contains no `grants`, no `list_for`, no `expand_scopes` and no `.await` at all — it takes `held: &[Scope]` and uses it as the only attenuation ceiling. The handler (cheers-axum/src/tokens.rs:685) sources `held` from `Credential::ApiToken(claims) => claims.scope` for a PAT and from the metadata row for a session — never from the grant table. So a frozen token cannot re-widen itself by rotating, which is the single way this feature could have leaked authority.")
//! @yah:handoff("NOT COMMITTED by this session (shared tree, git writes are the camp's call). Files touched: cheers-axum/src/{tokens.rs, mcp.rs, lib.rs}, cheers-axum/tests/tokens_basic.rs, cheers-server/src/mcp_authority.rs, cheers-verify/src/edge.rs. cheers-core is NOT among them — no claim shape or wire string moved. New public surface re-exported from cheers_axum: ApiTokenTrust, Caller, Credential, RotateTokenBody, authenticate_any, verify_mcp_bearer. BREAKING (intentional, pre-1.0): MeTokensState gained a required `pat: ApiTokenTrust` field, so every construction site must supply the PAT trust policy; the only one in-tree is the test rig, and it was fixed rather than given a default.")
//! @yah:verify("UNIFORM 401 HELD ACROSS THE SECOND VERIFIER — the other thing that could have gone wrong. every_authentication_failure_is_byte_identical (cheers-axum/tests/tokens_basic.rs:616) now drives SEVEN arms, not the original three: revoked session, garbage, revoked PAT, expired PAT, foreign-KEY PAT, foreign-ISS PAT (our key, our kid, valid signature, untrusted issuer — only the trust policy catches that one), and a valid camp token whose subject is not a user. It asserts every body byte-equal to the first, not merely equal status codes. create is still session-only (tokens.rs:493 calls me::authenticate) and a_pat_cannot_mint_a_pat still passes.")
//! @yah:verify("LEADER'S OWN TEST RUN, every binary's summary line read rather than a total trusted: cheers-axum --lib 68/0, cheers-axum --test \"*\" 60/0 (baseline 50 — 10 new tests in tokens_basic.rs, 12 to 22), cheers-server --lib 159/0 (baseline 154), cheers-turso 28/0, cheers-sqlx --features sqlite 18/0 + 1 ignored (sqlite.rs 16, lib 2), kamaji-bin 225/0 (lib 220). 558 tests, zero failures across both workspaces. The implementer SKIPPED the kamaji build on the grounds that cheers-core was untouched; I ran it anyway rather than accept the inference, and checked the grounds separately — AuthStrength is still exactly {Bootstrap, UserFresh, ApiToken} and McpClaims gained no field. The claim was true, but it was observed, not taken. cheers-sqlx/tests/pg.rs remains compile-only on this host (no docker socket) — carried over from R728-F1, not introduced here.")

use std::str::FromStr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use cheers_core::{
    Claims, McpClaims, PrincipalId, PrincipalKind, Revoked, Scope, ScopeRegistry, TokenVerifier,
    UserId,
};
use cheers_server::{
    AuditRecord, AuditStore, BundleStore, EdgeVerifier, GrantStore, McpAuthority, McpMintError,
    OwnershipStore, PasetoV4PublicVerifier, RevocationReader, RevocationWriter, UserTokenRecord,
    UserTokenStore,
};

use crate::error::RouteError;
use crate::mcp::verify_mcp_bearer;
use crate::me::{authenticate, bearer_from_headers};

/// `POST /me/tokens` request body.
///
/// `aud` is **required**. Grants are keyed `(principal, aud)`, so the audience
/// is what decides which scopes the caller even has — pinning one per
/// deployment would make this surface unable to express a grant table the rest
/// of cheers already models, and defaulting it would silently mint for the
/// wrong resource.
#[derive(Debug, Clone, Deserialize)]
#[non_exhaustive]
pub struct CreateTokenBody {
    /// Human label. Opaque to cheers; must be non-empty so a token list is
    /// actually readable.
    pub name: String,
    /// Target resource URI the token is minted for.
    pub aud: String,
    /// Wire-form scope strings (`"cloud:read"`). Empty or omitted means
    /// "everything I currently hold for `aud`".
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Lifetime in seconds. Omitted ⇒ the policy default (90 days). Out of
    /// range ⇒ 400; never clamped.
    #[serde(default)]
    pub expires_in_secs: Option<i64>,
}

/// `POST /me/tokens` response — **the only time `token` is ever returned**.
///
/// Nothing in cheers can reproduce it: no secret and no hash of one is stored,
/// because verification is by signature. A client that loses this value mints
/// a new token and revokes this one.
#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
pub struct CreatedToken {
    /// The secret. Once.
    pub token: String,
    /// The token's `jti` — the id for `DELETE /me/tokens/{id}`.
    pub id: String,
    pub name: String,
    pub aud: String,
    pub scopes: Vec<Scope>,
    pub created_at: i64,
    pub expires_at: i64,
}

/// Per-row JSON shape returned by `GET /me/tokens` — metadata only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct TokenListEntry {
    pub id: String,
    pub name: String,
    pub aud: String,
    pub scopes: Vec<Scope>,
    pub created_at: i64,
    /// `None` unless a resource server reported a use — cheers never writes
    /// it. See [`cheers_server::user_tokens`].
    pub last_used_at: Option<i64>,
    pub expires_at: i64,
}

impl From<UserTokenRecord> for TokenListEntry {
    fn from(r: UserTokenRecord) -> Self {
        Self {
            id: r.jti,
            name: r.name,
            aud: r.aud,
            scopes: r.scopes,
            created_at: r.created_at,
            last_used_at: r.last_used_at,
            expires_at: r.expires_at,
        }
    }
}

/// `POST /me/tokens/{id}/rotate` request body — every field optional, and an
/// absent body is fine (`None` for all three).
///
/// There is deliberately **no `aud`**: a rotation keeps the audience of the
/// token it replaces. Changing audience means reading the grant table for the
/// new one, which is a mint — [`create`] — not a roll.
#[derive(Debug, Clone, Default, Deserialize)]
#[non_exhaustive]
pub struct RotateTokenBody {
    /// Rename while rolling. Omitted ⇒ the replaced token's name is kept;
    /// present but blank ⇒ 400, same as [`create`].
    #[serde(default)]
    pub name: Option<String>,
    /// Narrow while rolling. Empty or omitted ⇒ the replaced authority is
    /// carried over verbatim. A scope the presented credential does not hold
    /// is a 400 naming it — a rotation can never widen.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Lifetime of the replacement in seconds. Omitted ⇒ the policy default.
    /// Out of range ⇒ 400; never clamped.
    #[serde(default)]
    pub expires_in_secs: Option<i64>,
}

/// The trust policy the PAT door is held to — which published key this
/// surface trusts (`kid`, R592-B7's footer requirement) and which issuer it
/// trusts to have signed for a user.
///
/// **No `expected_aud`, on purpose.** See the module docs: requiring the PAT's
/// audience to be cheers's own would mean only a token minted specifically for
/// credential management could manage credentials, and none of the verbs this
/// gates grants authority at an audience.
pub struct ApiTokenTrust {
    pub verifier: Arc<cheers_verify::KeySetVerifier>,
    pub expected_iss: String,
}

impl ApiTokenTrust {
    /// Static key set: `verifier`'s key as the one issuer-role key under `kid`
    /// (R731-F6 — same key-set path as [`McpAuthState`](crate::McpAuthState)).
    pub fn new(
        verifier: PasetoV4PublicVerifier,
        kid: impl Into<String>,
        expected_iss: impl Into<String>,
    ) -> Self {
        let expected_iss = expected_iss.into();
        let key: [u8; 32] = verifier
            .public_key()
            .as_bytes()
            .try_into()
            .expect("Ed25519 public key is 32 bytes");
        Self {
            verifier: Arc::new(cheers_verify::KeySetVerifier::from_issuer_key(
                kid,
                &key,
                expected_iss.clone(),
            )),
            expected_iss,
        }
    }
}

impl std::fmt::Debug for ApiTokenTrust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiTokenTrust")
            .field("expected_iss", &self.expected_iss)
            .finish_non_exhaustive()
    }
}

/// Which credential shape authenticated a request, for the routes that take
/// either. Carries the verified claims because [`rotate`] attenuates from
/// them.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Credential {
    /// A browser-shaped session bearer. Holds no scopes of its own — the
    /// user's full authority, gated by a real ceremony.
    Session(Box<Claims>),
    /// A PAT (or any user-subject `McpClaims` token). `scope` here is the
    /// ceiling a rotation may mint under.
    ApiToken(Box<McpClaims>),
}

/// An authenticated caller of the `/me/tokens` routes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Caller {
    /// The user both shapes resolve to. Every store read is scoped by it, so
    /// a `jti` alone is never enough to act on a row.
    pub user: UserId,
    pub credential: Credential,
}

/// State bundle held by the `/me/tokens` handlers.
pub struct MeTokensState<V, Rd, B, G, O, W> {
    /// Authenticates a *session* caller — and, via
    /// [`EdgeVerifier::revocations`], supplies the single revocation set both
    /// doors read.
    pub edge: Arc<EdgeVerifier<V, Rd>>,
    /// Mints the PAT. Also the source of the TTL policy and the grant lookup
    /// that bounds attenuation.
    pub mcp: Arc<McpAuthority<B, G, O>>,
    /// The metadata rows. Not on the token's trust path.
    pub tokens: Arc<dyn UserTokenStore>,
    /// The half of revoke that actually kills the token at the edge.
    pub revocations: Arc<W>,
    /// Mint and revoke are both recorded. A failed audit write fails the
    /// request — see [`create`].
    pub audit: Arc<dyn AuditStore>,
    /// The second door: what a PAT presented to list / revoke / rotate is
    /// verified against (R728-F2).
    pub pat: ApiTokenTrust,
}

impl<V, Rd, B, G, O, W> std::fmt::Debug for MeTokensState<V, Rd, B, G, O, W> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MeTokensState").finish_non_exhaustive()
    }
}

/// The handlers' shared state, aliased so the six-generic `Arc<..>` appears
/// once rather than in every signature.
pub type SharedTokensState<V, Rd, B, G, O, W> = Arc<MeTokensState<V, Rd, B, G, O, W>>;

/// Build a router mounting `POST /me/tokens`, `GET /me/tokens`,
/// `DELETE /me/tokens/{id}` and `POST /me/tokens/{id}/rotate`. The product
/// nests it under whatever base path it chose (`/api`, …) — the same one it
/// nests [`me::router`](crate::me::router) under.
pub fn router<V, Rd, B, G, O, W>(state: SharedTokensState<V, Rd, B, G, O, W>) -> Router
where
    V: TokenVerifier + Send + Sync + 'static,
    Rd: RevocationReader + Send + Sync + 'static,
    B: BundleStore + Send + Sync + 'static,
    G: GrantStore + Send + Sync + 'static,
    O: OwnershipStore + Send + Sync + 'static,
    W: RevocationWriter + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/me/tokens",
            post(create::<V, Rd, B, G, O, W>).get(list::<V, Rd, B, G, O, W>),
        )
        .route("/me/tokens/{id}", delete(revoke::<V, Rd, B, G, O, W>))
        .route(
            "/me/tokens/{id}/rotate",
            post(rotate::<V, Rd, B, G, O, W>),
        )
        .with_state(state)
}

/// Authenticate a caller presenting **either** credential shape — the door
/// [`list`], [`revoke`] and [`rotate`] stand behind.
///
/// Session shape first (it is the common case and the cheaper check), then the
/// PAT shape. The order is not security-relevant: the two PASETO payloads are
/// structurally distinct, so exactly one of the two verifiers can ever succeed
/// for a given string.
///
/// Three things every rejection has in common, and all three are load-bearing:
///
/// 1. **One body.** Missing bearer aside, every failure is
///    [`RouteError::Unauthorized`] — bad signature, expired, wrong `kid`,
///    wrong `iss`, revoked, or a valid token whose subject is not a user. A
///    caller cannot learn which.
/// 2. **One revocation set.** The PAT path reads
///    [`EdgeVerifier::revocations`], the very set the session path consults,
///    so `DELETE /me/tokens/{id}` kills a token for both doors at once.
/// 3. **A store failure is never a 401.** If the revocation read itself fails
///    the caller gets a 500, because answering "unauthorized" on a flaky read
///    would turn an outage into a silent mass logout.
///
/// A non-user principal (`svc:`, `camp:`) is refused: these routes act on *a
/// user's* credentials, and a camp token is not a user even though it is a
/// perfectly valid `McpClaims`.
pub async fn authenticate_any<V, Rd, B, G, O, W>(
    headers: &HeaderMap,
    state: &MeTokensState<V, Rd, B, G, O, W>,
    now: i64,
) -> Result<Caller, RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
{
    let token = bearer_from_headers(headers)?;

    match state.edge.verify_at(token, now).await {
        Ok(claims) => {
            return Ok(Caller {
                user: claims.sub.clone(),
                credential: Credential::Session(Box::new(claims)),
            })
        }
        // Ours, not the caller's — see (3) above.
        Err(cheers_core::Error::Store(e)) => return Err(RouteError::Store(e.to_string())),
        Err(_) => {}
    }

    let claims = verify_mcp_bearer(
        headers,
        &state.pat.verifier,
        &state.pat.expected_iss,
        // No audience policy — deliberate, see the module docs.
        None,
        now,
    )
    .await?;
    if claims.sub.kind != PrincipalKind::User {
        return Err(RouteError::Unauthorized);
    }
    if state
        .edge
        .revocations()
        .is_revoked(&claims.jti)
        .await
        .map_err(|e| RouteError::Store(e.to_string()))?
    {
        return Err(RouteError::Unauthorized);
    }

    Ok(Caller {
        user: UserId::new(claims.sub.id.clone()),
        credential: Credential::ApiToken(Box::new(claims)),
    })
}

/// `POST /me/tokens` — mint a user API token.
///
/// Returns `201 Created` with [`CreatedToken`]; the secret is in the body and
/// is never retrievable again.
///
/// Order of operations is deliberate: mint (which is where every
/// authorization rule lives and where a rejection must happen *before*
/// signing), then persist the metadata row, then audit. A failed metadata
/// write or a failed audit write **fails the request with a 500** even though
/// the token is already signed. That is the fail-closed direction: the caller
/// sees an error and does not deploy a credential cheers has no record of. The
/// signed token is not handed back, so the worst case is an orphan `jti` that
/// nobody holds and that expires on its own.
pub async fn create<V, Rd, B, G, O, W>(
    State(state): State<SharedTokensState<V, Rd, B, G, O, W>>,
    headers: HeaderMap,
    Json(body): Json<CreateTokenBody>,
) -> Result<(StatusCode, Json<CreatedToken>), RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    B: BundleStore,
    G: GrantStore,
    O: OwnershipStore,
{
    let now = now_unix();
    let claims = authenticate(&headers, &state.edge, now).await?;

    let name = body.name.trim();
    if name.is_empty() {
        return Err(RouteError::InvalidTokenRequest("name must not be empty".into()));
    }
    if body.aud.trim().is_empty() {
        return Err(RouteError::InvalidTokenRequest("aud must not be empty".into()));
    }
    let requested = parse_scopes(state.mcp.scopes(), &body.scopes)?;

    let principal = PrincipalId::user(claims.sub.as_str());
    let minted = state
        .mcp
        .mint_api_token(
            principal.clone(),
            body.aud.clone(),
            &requested,
            body.expires_in_secs,
            now,
        )
        .await
        .map_err(map_mint_error)?;

    let record = UserTokenRecord::new(
        minted.claims.jti.clone(),
        claims.sub.clone(),
        name,
        minted.claims.scope.clone(),
        body.aud.clone(),
        now,
        minted.claims.exp,
    );
    state.tokens.insert(&record).await?;

    write_audit(
        &state.audit,
        now,
        principal,
        &body.aud,
        "POST /me/tokens",
        minted.claims.scope.clone(),
        &minted.claims.jti,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreatedToken {
            token: minted.token,
            id: record.jti,
            name: record.name,
            aud: record.aud,
            scopes: record.scopes,
            created_at: record.created_at,
            expires_at: record.expires_at,
        }),
    ))
}

/// `GET /me/tokens` — list the caller's live API tokens. Metadata only; the
/// secrets are not recoverable from here or anywhere else.
///
/// Takes **either** credential shape ([`authenticate_any`]): a token that can
/// be revoked should be able to see itself. The rows are scoped to the
/// caller's own `user_id`, so admitting a PAT here shows it nothing a session
/// would not have shown, and shows it nothing about anyone else.
pub async fn list<V, Rd, B, G, O, W>(
    State(state): State<SharedTokensState<V, Rd, B, G, O, W>>,
    headers: HeaderMap,
) -> Result<Json<Vec<TokenListEntry>>, RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
{
    let now = now_unix();
    let caller = authenticate_any(&headers, &state, now).await?;
    let rows = state.tokens.list_live_for_user(&caller.user, now).await?;
    Ok(Json(rows.into_iter().map(TokenListEntry::from).collect()))
}

/// `DELETE /me/tokens/{id}` — revoke one API token. `204 No Content`.
///
/// **Both halves, in this order.** The [`RevocationWriter`] entry is what the
/// edge actually reads, so it goes first: if the metadata flip fails
/// afterwards the token is still dead, which is the failure direction to
/// prefer. The metadata flip is what makes the kill visible on
/// `GET /me/tokens`.
///
/// A `{id}` that is unknown *or* belongs to another user is `404 unknown_token`
/// — the same shape (and the same reasoning) as `DELETE /me/sessions`'s
/// `unknown_device`: distinguishing the two would let a probe enumerate other
/// users' token ids. Revoking an already-revoked token of your own is `204`,
/// not 404: the row is still yours and the outcome is the one you asked for.
///
/// Takes **either** credential shape ([`authenticate_any`]), including a PAT
/// killing itself, and a PAT here is *not* restricted to its own `jti`: a
/// leaked credential's holder should be able to kill every token they hold
/// from whatever they still have, and the verb can only ever subtract
/// authority from the caller's own rows.
pub async fn revoke<V, Rd, B, G, O, W>(
    State(state): State<SharedTokensState<V, Rd, B, G, O, W>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    W: RevocationWriter,
{
    let now = now_unix();
    let caller = authenticate_any(&headers, &state, now).await?;

    let row = state.tokens.get(&id).await?.ok_or(RouteError::UnknownToken)?;
    if row.user_id != caller.user {
        return Err(RouteError::UnknownToken);
    }

    state.revocations.revoke(&Revoked::jti(&row.jti, Some(row.expires_at))).await?;
    state.tokens.mark_revoked(&row.jti).await?;

    write_audit(
        &state.audit,
        now,
        PrincipalId::user(caller.user.as_str()),
        &row.aud,
        "DELETE /me/tokens",
        row.scopes.clone(),
        &row.jti,
    )
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// `POST /me/tokens/{id}/rotate` — replace a token with a fresh one and kill
/// the old `jti`. `201 Created` with [`CreatedToken`]; the new secret is in
/// the body and, as with [`create`], is never retrievable again.
///
/// This is the half that makes a credential able to *roll itself*. List and
/// revoke let a PAT see and end its own life; only a mint lets it continue
/// one, and [`create`] is session-only by design. So this door exists, and its
/// entire job is to mint a replacement **without ever reading the grant
/// table**.
///
/// ## Who may rotate what
///
/// - A **session** bearer may rotate any of that user's tokens. It is the full
///   interactive authority; it could mint a wider token outright at
///   [`create`], so restricting it here would protect nothing.
/// - A **PAT** may rotate **only itself** — `{id}` must equal its own `jti`,
///   and anything else is the same `404 unknown_token` an id that does not
///   exist gets, so a stolen token cannot probe which of the user's other
///   token ids are real. Rolling *itself* is the need the operator named;
///   rolling a *sibling* is lateral movement, and it would let a narrow
///   credential mint replacements for tokens whose authority it does not hold.
///
/// ## Where the replacement's scopes come from — and where they do not
///
/// From the **presented credential**, never from `grants.list_for`. For a PAT
/// that is its own signed `scope` list; for a session it is the replaced row's
/// scopes (a session carries no scopes of its own, and the row is the
/// authority actually being rolled). Re-reading grants would mean a token
/// minted when the user held `cloud:read` could come back holding
/// `cloud:destroy` — a frozen credential silently re-widening itself, which is
/// exactly what `a_minted_pat_is_frozen_and_does_not_track_later_grant_edits`
/// pins against. Requested scopes are intersected with that ceiling and an
/// unheld one is a 400 naming it, matching [`create`]'s `UnentitledScopes`.
///
/// The audience carries over for the same reason: a different `aud` would have
/// to be authorized out of the grant table, which makes it a mint.
///
/// The replacement gets a fresh TTL under the same [`McpPolicy`] ceiling
/// (`api_token_max_ttl_seconds`) — bounded rotation, not indefinite extension.
///
/// ## A dead token cannot be rolled
///
/// Revoked or expired ⇒ `404 unknown_token`, not a fresh token. Rotating a
/// dead credential would resurrect authority its owner already ended, and the
/// 404 is the same body a foreign id gets so the two stay indistinguishable.
///
/// ## Order of operations
///
/// Mint, persist the new row, *then* revoke the old one, then audit — and the
/// sequence is chosen for what a failure leaves behind. Revoking first and
/// failing afterwards would leave the caller holding **nothing**: their old
/// credential dead and a replacement they never received. Failing before the
/// revoke leaves them holding their old, still-working token plus an orphan
/// `jti` nobody has, which expires on its own. Both halves of the revoke run
/// in the same fail-safe order [`revoke`] uses.
///
/// [`McpPolicy`]: cheers_server::McpPolicy
pub async fn rotate<V, Rd, B, G, O, W>(
    State(state): State<SharedTokensState<V, Rd, B, G, O, W>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Option<Json<RotateTokenBody>>,
) -> Result<(StatusCode, Json<CreatedToken>), RouteError>
where
    V: TokenVerifier + Send + Sync,
    Rd: RevocationReader,
    B: BundleStore,
    G: GrantStore,
    O: OwnershipStore,
    W: RevocationWriter,
{
    let now = now_unix();
    let caller = authenticate_any(&headers, &state, now).await?;
    let body = body.map(|Json(b)| b).unwrap_or_default();

    // A PAT rolls itself and nothing else. Checked before the store read so a
    // foreign id and a nonexistent one are indistinguishable even in timing
    // shape.
    if let Credential::ApiToken(claims) = &caller.credential {
        if claims.jti != id {
            return Err(RouteError::UnknownToken);
        }
    }

    let row = state.tokens.get(&id).await?.ok_or(RouteError::UnknownToken)?;
    if row.user_id != caller.user {
        return Err(RouteError::UnknownToken);
    }
    if row.revoked || row.expires_at <= now {
        return Err(RouteError::UnknownToken);
    }

    let name = match body.name.as_deref() {
        Some(n) if n.trim().is_empty() => {
            return Err(RouteError::InvalidTokenRequest("name must not be empty".into()))
        }
        Some(n) => n.trim().to_owned(),
        None => row.name.clone(),
    };
    let requested = parse_scopes(state.mcp.scopes(), &body.scopes)?;

    // The ceiling, and the aud, come from the credential in hand. For a PAT
    // the signed claims are the authority; the metadata row is only what the
    // user sees.
    let (held, aud) = match &caller.credential {
        Credential::ApiToken(claims) => (claims.scope.clone(), claims.aud.clone()),
        Credential::Session(_) => (row.scopes.clone(), row.aud.clone()),
    };

    let principal = PrincipalId::user(caller.user.as_str());
    let minted = state
        .mcp
        .rotate_api_token(
            principal.clone(),
            aud.clone(),
            &held,
            &requested,
            body.expires_in_secs,
            now,
        )
        .map_err(map_mint_error)?;

    let record = UserTokenRecord::new(
        minted.claims.jti.clone(),
        caller.user.clone(),
        name,
        minted.claims.scope.clone(),
        aud.clone(),
        now,
        minted.claims.exp,
    );
    state.tokens.insert(&record).await?;

    state.revocations.revoke(&Revoked::jti(&row.jti, Some(row.expires_at))).await?;
    state.tokens.mark_revoked(&row.jti).await?;

    // Two rows, one event: the rotation is findable from either id, which is
    // what an operator reconstructing a credential's lineage needs.
    write_audit(
        &state.audit,
        now,
        principal.clone(),
        &aud,
        "POST /me/tokens/rotate",
        minted.claims.scope.clone(),
        &record.jti,
    )
    .await?;
    write_audit(
        &state.audit,
        now,
        principal,
        &row.aud,
        "POST /me/tokens/rotate",
        row.scopes.clone(),
        &row.jti,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreatedToken {
            token: minted.token,
            id: record.jti,
            name: record.name,
            aud: record.aud,
            scopes: record.scopes,
            created_at: record.created_at,
            expires_at: record.expires_at,
        }),
    ))
}

/// Parse wire scope strings into the closed vocabulary. An unknown or
/// wildcard scope is a 400 naming it — [`Scope::from_str`] is where
/// composition rule (1) (no wildcards on the wire) is enforced, so this is
/// also the wildcard rejection.
/// Parse client-requested scopes and refuse any this deployment's registry
/// does not declare — an unknown scope is a malformed request, not merely an
/// unheld one.
fn parse_scopes(registry: &ScopeRegistry, raw: &[String]) -> Result<Vec<Scope>, RouteError> {
    raw.iter()
        .map(|s| {
            let scope =
                Scope::from_str(s).map_err(|e| RouteError::InvalidTokenRequest(e.to_string()))?;
            if !registry.contains(&scope) {
                return Err(RouteError::InvalidTokenRequest(format!("unknown scope '{scope}'")));
            }
            Ok(scope)
        })
        .collect()
}

/// `request_id` correlates the audit row to the token it is about, so an
/// operator reading the journal can match a mint to its revoke without a join
/// table. The `jti` is already unique per token and is not a secret.
async fn write_audit(
    audit: &Arc<dyn AuditStore>,
    now: i64,
    sub: PrincipalId,
    aud: &str,
    method: &str,
    scope: Vec<Scope>,
    jti: &str,
) -> Result<(), RouteError> {
    let record = AuditRecord::new(now, sub, None, None, aud, method, scope, "allow", jti)?;
    audit.insert_batch(std::slice::from_ref(&record), now).await?;
    Ok(())
}

/// Mint failures split three ways, and the split is the security-relevant
/// part: what the caller asked for wrongly (400), what they are not entitled
/// to (403), and what is broken on our side (500). Nothing here collapses into
/// 401 — the caller *is* authenticated; the mint is what failed.
fn map_mint_error(err: McpMintError) -> RouteError {
    match err {
        McpMintError::UnentitledScopes { .. } => RouteError::UnentitledScopes(err.to_string()),
        McpMintError::TtlOutOfRange { .. } => RouteError::InvalidTokenRequest(err.to_string()),
        McpMintError::AudNotEntitled { .. } => {
            RouteError::NotEntitledForAud(err.to_string())
        }
        McpMintError::InvalidScope { .. } => RouteError::UnentitledScopes(err.to_string()),
        // WrongPrincipalKind is unreachable here (the principal is built from
        // a verified session's `sub`, always a user); GrantMisconfigured and
        // BundleExpansion are server-side data bugs; Store/Codec are
        // infrastructure. All 500.
        other => RouteError::Store(other.to_string()),
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
    use cheers_core::yah_scopes;

    #[test]
    fn parse_scopes_maps_wire_strings_and_rejects_unknown() {
        let reg = yah_scopes::registry_at(["https://kamaji.example"]).unwrap();
        let ok = parse_scopes(&reg, &["cloud:read".into(), "board:write".into()]).unwrap();
        assert_eq!(ok, vec![yah_scopes::CLOUD_READ, yah_scopes::BOARD_WRITE]);
        assert!(parse_scopes(&reg, &["cloud:everything".into()]).is_err());
    }

    /// Composition rule (1): no wildcards on the wire. The request body is the
    /// outermost place a `cloud:*` could arrive, so it must die here.
    #[test]
    fn parse_scopes_rejects_a_wildcard() {
        let err = parse_scopes(&yah_scopes::registry_at(["https://kamaji.example"]).unwrap(), &["cloud:*".into()]).unwrap_err();
        assert!(matches!(err, RouteError::InvalidTokenRequest(_)));
    }

    #[test]
    fn list_entry_from_record_carries_no_secret_field() {
        let row = UserTokenRecord::new(
            "j1",
            cheers_core::UserId::new("alice"),
            "ci",
            vec![yah_scopes::CLOUD_READ],
            "https://kamaji.example",
            1_000,
            9_000,
        );
        let json = serde_json::to_string(&TokenListEntry::from(row)).unwrap();
        assert!(!json.contains("token"), "list rows must not carry a secret: {json}");
        assert!(json.contains("\"id\":\"j1\""));
        assert!(json.contains("\"last_used_at\":null"));
    }
}
