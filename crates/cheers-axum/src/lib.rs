//! # cheers-axum — HTTP route handlers for cheers
//!
//! axum 0.8 routers that wire cheers's identity providers into a
//! [`SessionAuthority`](cheers_server::SessionAuthority). This crate is the
//! HTTP-framework binding for cheers; a product (yah-platform, noisetable, …)
//! supplies concrete [`UserStore`](cheers_server::UserStore) +
//! [`RefreshStore`](cheers_server::RefreshStore) +
//! [`RevocationWriter`](cheers_server::RevocationWriter) impls (from
//! `cheers-sqlx` / `cheers-redis`) and a configured provider, then mounts the
//! returned [`Router`](axum::Router) at `/auth`.
//!
//! ## Modules
//!
//! - [`google`] (feature `google`) — `GET /auth/login/google` + `GET /auth/callback/google`
//!   for Google's standard OIDC Authorization Code + PKCE flow.
//! - [`apple`] (feature `apple`) — `GET /auth/login/apple` + `POST /auth/callback/apple`
//!   for Apple's form-post variant with one-shot first-login name capture.
//! - [`passkey`] (feature `passkey`) — `POST /auth/passkey/{register,authenticate}/{start,finish}`
//!   for the WebAuthn ceremonies wired to a [`SessionAuthority`].
//! - [`magic_link`] (feature `email`) — `POST /auth/magic-link/request` +
//!   `GET /auth/magic-link/verify` for the email-token sign-in flow.
//!
//! Each module exposes:
//!
//! 1. A state struct (e.g. [`google::GoogleAuthState`]) bundling the provider,
//!    the [`SessionAuthority`](cheers_server::SessionAuthority), an HTTP client,
//!    and the CSRF cookie [`config`](CsrfCookieConfig).
//! 2. Route handlers (`login`, `callback`) that consume that state.
//! 3. A `router()` constructor that mounts the handlers at the conventional
//!    paths.
//!
//! ## CSRF cookie binding
//!
//! The OIDC flow store ([`OidcFlowStore`](cheers::providers::oidc_generic::OidcFlowStore))
//! holds in-flight flows keyed by `csrf_state.secret()`. To prevent a stolen
//! `state` from being usable against a victim's session, each `login` handler
//! sets an `Http-Only` cookie carrying the same value; `callback` refuses any
//! request where the cookie is missing or doesn't match the `?state=` param.
//! Apple specifically requires `SameSite=None` on this cookie because Apple's
//! callback is a cross-site POST — see [`apple`] for the override.
//!
//! ## Session response
//!
//! On a successful callback, the handler returns JSON containing the freshly
//! minted access token, the refresh token, and the user_id — the
//! [`SessionBody`] shape every provider module reuses. The client caches the
//! `access_token` (SPAs: in JS heap or `sessionStorage`; native/CLI: OS
//! keyring) and hands it back as `Authorization: Bearer <paseto>`. See
//! [`me`] for the `/me/sessions` list+revoke routes that consume that header.
//! No cookies are written by these routes (per R347 the .yah.dev surface is
//! cookie-free); a product that wants the cookie pattern wraps the returned
//! `Json<SessionBody>` in its own middleware.
//!
//! @yah:ticket(R020-F9, "Service-principal admin endpoint + Ed25519 keypair lifecycle (POST /admin/service-principals + --rotate)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T01:36:03Z)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R020)
//! @yah:next("POST /admin/service-principals { kind: 'service', desired_id, grants: […] } authenticated by operator passkey. Allocate principal record, generate Ed25519 keypair, return secret half ONCE.")
//! @yah:next("Track pubkey in cheers for JWKS publication; the secret leaves cheers exactly once.")
//! @yah:next("Rotation: --rotate registers a fresh keypair; keep old keypair active for service_overlap_window (default 24h) before dropping from JWKS.")
//! @yah:verify("Provision a service principal, capture the returned secret, sign a token off-cheers, present it at POST /ownership — cheers verifies via JWKS without a separate fetch.")
//! @yah:verify("Rotate, observe two pubkeys in JWKS during overlap window, observe old kid drops from JWKS after window expires.")
//! @yah:gotcha("Secret half returned ONCE — cheers retains only the public key. There is no recovery path for a lost secret; rotate to issue a new one.")
//! @yah:gotcha("Yubaba uses this keypair to mint its OWN short-lived tokens (sub: svc:yubaba-<id>) signed with the Ed25519 key. Cheers verifies these on receipt at POST /ownership etc. — do not assume cheers always mints yubaba's tokens.")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @yah:depends_on(R020-F2)
//! @yah:depends_on(R020-F3)
//! @yah:depends_on(R020-F4)
//! @yah:handoff("FOUNDATION LANDED. Service-principal core lives in crates/cheers-server/src/service_principal.rs: SigningKey { kid, principal_id, public_key: [u8;32] (serde via base64url-no-pad), status: Active|Retiring, created_at, retire_at } + SigningKeyStatus + ProvisionedKey { principal, signing_key, secret_key: [u8;64] } (Debug omits the secret) + NewServicePrincipal + OverlapPolicy (default 24h) + ServicePrincipalError (typed, mapped to HTTP in the follow-on) + ServicePrincipalStore trait + MemoryServicePrincipalStore + ServicePrincipalAuthority<S>. Re-exported from cheers_server::* (lib.rs L42-46). 14 new unit tests; cargo test -p cheers-server: 96 unit + 9 proptest + 2 doctest, all green. Parent relay smoke green (cheers-core 51, cheers-verify 4, cheers-axum 22). cargo check --workspace --all-features clean.")
//! @yah:handoff("AUTHORITY API: ServicePrincipalAuthority::provision(NewServicePrincipal, now) -> ProvisionedKey (allocates Principal kind=Service via Principal::try_new, generates fresh Ed25519 keypair via PasetoV4SecretMinter::generate, persists pubkey only, returns 64-byte secret ONCE). ::rotate(&PrincipalId, now) -> ProvisionedKey (refuses non-service kind / unknown id, retires the prior Active key with retire_at = now + policy.overlap_seconds, registers + returns fresh keypair). ::published_signing_keys(now) -> Vec<SigningKey> (the JWKS filter — every Active key + every Retiring whose retire_at > now). ::prune_retired_keys(now) -> u64 (idempotent drop of Retiring-and-due rows).")
//! @yah:handoff("SECRET-EXTRACTION AFFORDANCE: PasetoV4SecretMinter::secret_key_bytes() -> &[u8] (new, in cheers-server/src/codec.rs). Documented as origin-only, single-use, service-principal-only — cheers's session signing key NEVER reaches this accessor (constructed once at startup, never extracted). The symmetric codecs don't expose it at all. This is the only extraction point; do not add another for other consumers.")
//! @yah:handoff("SCOPE SPLIT (matches F4's T1/T2/T3 split). Filed: R020-T17 (HTTP admin routes POST /admin/service-principals + /rotate in cheers-axum, with operator-passkey EdgeVerifier auth + RouteError::AlreadyExists/UnknownPrincipal mappings); R020-T18 (cheers-sqlx PgServicePrincipalStore + SqliteServicePrincipalStore + migrations/{pg,sqlite}/0003_service_principals.sql). Both depend_on R020-F9. Open them after F9 sign-off.")
//! @yah:handoff("F11 (JWKS extension) consumes ServicePrincipalAuthority::published_signing_keys(now) directly — the filter is already done, F11 just walks the returned list to build JWK entries (one JWK per SigningKey, kty=OKP, crv=Ed25519, x=base64url(public_key), kid=signing_key.kid). The depends_on(R020-F9) edge on F11 stands; no extra coupling needed.")
//! @yah:handoff("INVARIANTS DOCUMENTED IN SOURCE: (a) public_key is exactly 32 bytes (PASETO V4 raw Ed25519); serde rejects wrong-length input. (b) secret_key is the 64-byte seed||pubkey layout — round-trip test pins this: bytes[32..] == signing_key.public_key. (c) ProvisionedKey::Debug omits the secret. (d) kid is a 128-bit base64url-no-pad opaque value (same shape/entropy as session::generate_jti). (e) Retiring rows with retire_at=None (impossible via the authority, only via a misbehaving direct store write) are EXCLUDED from published_signing_keys — belt-and-braces against zombies.")
//! @yah:handoff("GRANT WIRING IS NOT IN F9. The doc step 2 says 'grants typically include ownership:write and audit:write'. GrantStore today is read-only (list_for); there is no put_grant trait method. The HTTP route (T17) takes a `grants: [...]` body field and writes it via whatever grant-write path lands separately. Don't conflate — the F9 authority cleanly returns ProvisionedKey; grant population is composable at the HTTP layer.")
//! @yah:handoff("WIRE-CONTRACT COORDINATION: this work doesn't change the W159 wire contract (claims shapes, scopes, token envelope). The JWKS shape DOES touch the kamaji consumer surface — F11 is where that coordination is needed, not here.")
//! @yah:next("Sign off F9 (this ticket) — tasks-met, awaiting human review.")
//! @yah:next("Claim R020-T17 to land the cheers-axum admin routes + operator auth.")
//! @yah:next("Claim R020-T18 to land the cheers-sqlx persistent impl + 0003 migration.")
//! @yah:next("F11 (JWKS) can now be claimed in parallel — ServicePrincipalAuthority::published_signing_keys is its consumer entry point.")
//!
//! @yah:ticket(R020-F10, "Camp bootstrap endpoint + user-delegation verification (POST /admin/camps/bootstrap)")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T01:36:11Z)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R020)
//! @yah:next("POST /admin/camps/bootstrap { bound_to: user:<U>, desired_id, initial_grants: […] } authenticated as yubaba's service principal; body carries the user U's signed delegation (per yah/W122 QR-pair flow).")
//! @yah:next("Verify yubaba's identity + verify the user-signed delegation; allocate camp principal with bound_to: user:<U>; issue long-lived refresh credential.")
//! @yah:next("Retain the delegation as the auditable 'user U authorized camp C' record.")
//! @yah:verify("Provision a camp via the endpoint; observe bound_to set in the principal record; mint via path #2 with the returned credential succeeds.")
//! @yah:verify("Revoke U; subsequent mint via path #2 for the bound camp returns principal_revoked.")
//! @yah:gotcha("Revoking U cascades to all camps bound_to: U. Revoking C alone does NOT touch U. Bake the cascade into the principal-status update path, not into clients.")
//! @yah:assumes("yah-side QR-pair / mobile-app delegation flow (W122) is the canonical way the user signs the delegation. Cheers verifies a known signature shape — W122 must converge before this lands.")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @yah:depends_on(R020-F2)
//! @yah:depends_on(R020-F4)
//! @yah:depends_on(R020-F9)
//! @yah:handoff("LANDED. NEW MODULES: (1) crates/cheers-core/src/delegation.rs — UserDelegation { bound_to, camp_id, issued_at, expires_at, user_signing_key: [u8;32], signature: [u8;64] } + DelegationError + signing_payload() (canonical bytes the W122 client signs). Wire encoding: user_signing_key + signature ride as base64url-no-pad strings. Re-exported as cheers_core::{UserDelegation, DelegationError}. base64 added as an unconditional cheers-core dep (encoding, no crypto). (2) crates/cheers-server/src/camp.rs — UserSigningKey { kid, user, public_key:[u8;32], status:Active|Revoked, created_at } + UserSigningKeyStore trait (list_active_for_user) + MemoryUserSigningKeyStore; CampBootstrapCredential { token, camp_id, created_at, expires_at, revoked }; NewCampPrincipal + ProvisionedCamp + CampPrincipalStore trait (insert/get principal + credential + delegation, revoke_camps_bound_to) + MemoryCampPrincipalStore; CampBootstrapPolicy (default 1 year credential TTL); CampAuthorityError; CampAuthority<S,K>::{ provision, revoke_user_cascade }. (3) crates/cheers-axum/src/camps.rs — CampAdminState<S,K> + CreateCampBootstrapBody + CampBootstrapResponse + POST /admin/camps/bootstrap route. Re-exports from cheers_axum::*.")
//! @yah:handoff("VERIFICATION CHAIN. CampAuthority::provision runs in fixed order — each step aborts before the next side-effect: (1) bound_to.kind == User (programmer-error gate), (2) delegation.bound_to == provision.bound_to, (3) delegation.camp_id == provision.desired_id, (4) delegation.expires_at > now (DelegationExpired), (5) lookup ACTIVE trusted keys for bound_to via UserSigningKeyStore; reject UntrustedSigningKey if delegation.user_signing_key not present (Revoked keys are filtered out by list_active_for_user), (6) Ed25519 verify_delegation_signature over signing_payload (BadSignature on miss), (7) Principal::try_new(kind=Camp, bound_to=Some(user), Active), (8) insert principal (Conflict -> AlreadyExists), insert delegation (audit retention), generate 32-byte CSPRNG credential token + insert. Pinned by 13 unit tests in camp::tests including provision_rejects_signature_from_other_keypair_in_trusted_set (smuggled-pubkey attack: trusted pubkey + forged sig caught by signature verify).")
//! @yah:handoff("CASCADE REVOKE. CampAuthority::revoke_user_cascade(user, now) -> u64 newly-revoked count. Routes through CampPrincipalStore::revoke_camps_bound_to (one sweep over principals + credentials). Memory impl flips both principal.status and credential.revoked for every match in a single mutex-held update. Rejects user.kind != User with WrongPrincipalKind (protects against accidental service/camp cascades that would silently no-op against the WHERE clause). IDEMPOTENT — second sweep returns 0. NOT YET WIRED to a user-revocation hook (no SessionAuthority MCP-awareness today); the primitive is in place for the future wiring. Same pattern OwnershipStore::revoke_by_on_behalf_of follows (F4).")
//! @yah:handoff("WIRE CONTRACT: bound_to + delegation.bound_to MUST agree at the API boundary (the duplication is on purpose — caller sees the binding at the top of the JSON without re-parsing delegation; mismatch surfaces as DelegationMismatch -> 400). Same for desired_id vs delegation.camp_id. delegation.signing_payload() is a stable byte serialization of (bound_to, camp_id, issued_at, expires_at, user_signing_key) — the canonical W122-signing target. signing_payload_starts_with_bound_to_field pins the field order so a struct reorder fails loudly.")
//! @yah:handoff("ROUTE AUTH: POST /admin/camps/bootstrap takes an MCP BEARER (yubaba's service principal, not session bearer — different in kind from F9/T17 admin routes which take SESSION bearers for operator passkey). Required scope: Scope::CampAdmin. Verified by McpAuthState::verifier + authenticate_mcp + require_scope(Scope::CampAdmin). Session bearer presented at this route -> Unauthorized (collapses with bad sig / expired — confusing-deputy guard via the verify_mcp_at vs verify_at additional-claim-key split, pinned by bootstrap_camp_rejects_session_bearer_as_unauthorized).")
//! @yah:handoff("USER PUBKEY TRUST IS PER-USER, FROM A STORE — NOT BLINDLY ACCEPTED FROM THE BODY. The delegation carries the pubkey it signs under (so the verifier doesn't need a kid lookup), but the AUTHORITY refuses unless that pubkey is registered in UserSigningKeyStore as Active for the named user. The enrollment flow (W122 / mobile QR-pair) populates the store; cheers-side stops at 'lookup + verify'. The persistent UserSigningKeyStore impl + the enrollment HTTP surface are W122-side / cheers-sqlx follow-ons — file as peers when W122 lands. For now: MemoryUserSigningKeyStore + UserSigningKey::new (cross-crate constructor since the struct is #[non_exhaustive]).")
//! @yah:handoff("HTTP ERROR MAPPING in error.rs: added From<CampAuthorityError> for RouteError + a new InvalidDelegation(String) variant -> 400 'invalid_delegation'. AlreadyExists(camp_id) -> 409 'already_exists' (reuses the F9/T17 variant). UntrustedSigningKey / BadSignature -> 401 'unauthorized' (collapsed for the same probe-blocking reason as the MCP authentication path). DelegationMismatch / DelegationExpired / InvalidDelegation -> 400 'invalid_delegation'. WrongPrincipalKind / Principal / Store -> 500 via RouteError::Store (programmer-error reaching the route).")
//! @yah:handoff("VERIFY '#2 mint succeeds' END-TO-END: bootstrap_credential_round_trips_into_mint_bootstrap_path test provisions a camp via the authority, looks up the credential via CampPrincipalStore::get_credential, then calls McpAuthority::mint_bootstrap on the resolved camp principal — token verifies under the v4.public edge verifier. Proves the integration shape with mint flow #2 without requiring the (still-unticketed) /token HTTP endpoint that exchanges credential -> camp principal.")
//! @yah:handoff("GRANT WIRING STILL NOT DONE — same intentional carve-out as F9/T17. The route body is { bound_to, desired_id, delegation }; the initial_grants field the doc names is absent. When GrantStore gains a put_grant trait method, extend CampAdminState with grants store and add an `initial_grants` body field (still required to enforce composition rule (4) — but easier alongside that landing). Until then, an operator can hit POST /grants (separate path) to populate scopes for the freshly-allocated camp principal.")
//! @yah:handoff("VERIFIED GREEN: cargo test -p cheers-core (61 unit incl. 10 new delegation tests + 1 doctest); cargo test -p cheers-server (116 unit incl. 20 new camp tests, 9 proptest, 2 doctest); cargo test -p cheers-verify (4); cargo test -p cheers-axum (43 unit incl. 12 new camps tests, 7+7 integration + 5 doctest). cargo check --workspace --all-features clean. Parent relay smoke (R020) green.")
//! @yah:next("Sign off F10 — tasks-met, awaiting human review.")
//! @yah:next("When W122 (yah-side QR-pair / mobile-app delegation) converges, file the cheers-side enrollment HTTP route (POST /admin/users/<id>/signing-keys with operator-passkey + scope check) + the cheers-sqlx PgUserSigningKeyStore + 0004_user_signing_keys migration — peer ticket to R020-T18 (service-principal store).")
//! @yah:next("File a peer cheers-sqlx ticket for PgCampPrincipalStore + SqliteCampPrincipalStore + 0005_camp_principals migration (mirrors T18's split for service principals).")
//! @yah:next("File a peer ticket for the /token endpoint that exchanges a CampBootstrapCredential for a path-#2 mint (the credential -> McpAuthority::mint_bootstrap edge the round-trip test wires by hand here). Same shape as the OAuth /token grant_type=urn:ietf:params:oauth:grant-type:token-exchange dispatch noted in T16's handoff.")
//! @yah:next("Wire CampAuthority::revoke_user_cascade into the user-revocation hook once SessionAuthority grows MCP awareness (deferred per F4's same-named carve-out).")
//! @yah:verify("cargo test -p cheers-core -p cheers-server -p cheers-verify -p cheers-axum (61 + 116 + 4 + 43 unit + integration suites all green; 20 new camp + 12 new camps + 10 new delegation tests)")
//! @yah:verify("cargo check --workspace --all-features (clean — no warnings introduced)")
//! @yah:verify("Verify line #1 (provision + bound_to set + mint via path #2 succeeds): bootstrap_credential_round_trips_into_mint_bootstrap_path")
//! @yah:verify("Verify line #2 (cascade revoke on user U): revoke_user_cascade_flips_only_camps_bound_to_that_user + revoke_user_cascade_revokes_associated_credentials")
//!
//! @yah:ticket(R020-F11, "JWKS extension: publish service-principal pubkeys alongside cheers signing keys")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T01:36:24Z)
//! @yah:status(review)
//! @yah:phase(P4)
//! @yah:parent(R020)
//! @yah:next("Extend GET /.well-known/jwks.json to include service-principal pubkeys (kid keyed) alongside cheers's signing key(s).")
//! @yah:next("Honor 24–72h overlap window per kind — both keys present during the window, only new kid mints, old kid drops after.")
//! @yah:next("Cache-Control: max-age=300; ETag for cheap conditional GET.")
//! @yah:verify("GET /.well-known/jwks.json after provisioning a service principal includes its pubkey with the expected kid.")
//! @yah:verify("After --rotate, both old and new pubkeys appear during the overlap window; old pubkey is absent after the window expires.")
//! @yah:gotcha("Kamaji matches by kid and falls back to a one-shot rate-limited (1/sec) refresh on unknown kid. Don't change the kid format without coordinating with the kamaji refresh path.")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @yah:depends_on(R020-F9)
//! @yah:handoff("LANDED crates/cheers-axum/src/jwks.rs (re-exported from cheers_axum::*): JwksState<S> { platform_keys: Vec<PlatformSigningKey>, authority: Arc<ServicePrincipalAuthority<S>> } + PlatformSigningKey { kid, public_key: [u8;32] } + Jwk { kty, crv, x, kid, use } + JwkSet { keys } + router(state) mounting GET /.well-known/jwks.json. DEFAULT_JWKS_MAX_AGE_SECONDS = 300.")
//! @yah:handoff("AUTHORITATIVE SOURCES: platform_keys is a SNAPSHOT the product supplies at startup (no platform-key rotation infra today; when it lands, this list becomes its sink, the publication path stays the same). Service-principal keys flow through ServicePrincipalAuthority::published_signing_keys(now) verbatim — F9's already-filtered output (Active + Retiring-within-window). NO new filter logic in F11.")
//! @yah:handoff("WIRE SHAPE: RFC 8037/7517 OKP+Ed25519 JWK Set. Each entry is { kty:'OKP', crv:'Ed25519', x:<base64url-no-pad 32-byte pubkey>, kid:<opaque>, use:'sig' }. Keys sorted ASC by kid before serialization → deterministic body → stable ETag across calls. Response is application/jwk-set+json.")
//! @yah:handoff("CACHING: Cache-Control: public, max-age=300 + strong ETag (\"<hex(sha256(body))>\"). Conditional GET on If-None-Match: <etag> returns 304 with empty body, same Cache-Control + ETag echoed back. Mismatch falls through to 200. Cheap conditional GET works for kamaji's local cache invalidation.")
//! @yah:handoff("KID FORMAT: respects R020-F11's gotcha — service-principal kids are F9's mint_kid() output (128-bit base64url-no-pad opaque). Platform kids are operator-supplied; the docs call out 'use the same opaque shape'. NO structured prefixes / numeric generations — would break the kamaji refresh path.")
//! @yah:handoff("Jwk/JwkSet fields are String (not &'static str) so the types ROUND-TRIP through serde — a kamaji / product fetching JWKS can deserialize the response into the same struct cheers serializes from. Tests exercise this both ways.")
//! @yah:handoff("NEW UNCONDITIONAL DEP: sha2 = '0.10' on cheers-axum (for the strong ETag). Transitively present via webauthn-rs / openidconnect already; declared unconditional so the JWKS path doesn't depend on a feature flag.")
//! @yah:handoff("PasetoV4PublicVerifier is imported via cheers_server's re-export (cheers_server::PasetoV4PublicVerifier) — cheers-axum has no direct cheers-verify dep, same pattern as mcp.rs.")
//! @yah:handoff("TESTS: 7 inline jwks::tests using tower::ServiceExt::oneshot — (1) empty JWKS returns just platform keys with kty/crv/use/kid + base64url-decoded x pin (2) service-principal pubkey + kid appear after provision (3) rotate publishes both kids during overlap then drops old after retire_at<=now — first half uses 24h policy, second half uses 0s policy as a wall-clock-independent proxy (4) platform + service keys publish together sorted by kid (5) ETag stable for unchanged body, changes when JWKS changes (6) 304 on matching If-None-Match echoes ETag + Cache-Control, mismatched → 200 (7) end-to-end: provision → GET /jwks → reconstruct verifier from JWK.x → off-cheers mint with returned secret → verify under JWKS pubkey (kamaji's contract).")
//! @yah:handoff("WIRE-CONTRACT COORDINATION: this DOES touch the kamaji consumer surface — flag yah-side W159 / R426 with the JWKS endpoint URL + shape before kamaji's verifier wiring lands. kid format unchanged from F9 (kamaji matches by kid + one-shot rate-limited refresh on unknown).")
//! @yah:handoff("VERIFIED GREEN: cargo test -p cheers-axum --lib jwks (7/7 jwks pass), cargo test -p cheers-core -p cheers-server -p cheers-verify -p cheers-axum (parent relay smoke + full suite: 50 + 61 + 116 + 9 + 4 + integration + doctests, all green), cargo check --workspace --all-features clean.")
//! @yah:next("Sign off F11 — tasks-met, awaiting human review.")
//! @yah:next("Propagate JWKS endpoint shape into yah-side W159 / R426 (kamaji verifier wiring) — endpoint is GET /.well-known/jwks.json, application/jwk-set+json, OKP+Ed25519+kid, Cache-Control: public, max-age=300, ETag-conditional. Same kid format as F9.")
//! @yah:next("F12 (OIDC discovery) now unblocked — its jwks_uri field points at this endpoint.")
//! @yah:next("File a peer ticket against cheers-sqlx for the persistent ServicePrincipalStore (R020-T18 already exists) and confirm published_signing_keys behavior matches the Memory impl under a real backend.")
//! @yah:next("Platform-key rotation infrastructure remains a deferred concern: when SessionAuthority grows kid-aware multi-key signing, the JwksState API stays the same — the product just rebuilds platform_keys after each rotation.")
//! @yah:verify("cargo test -p cheers-axum --lib jwks (7/7 inline jwks::tests pass)")
//! @yah:verify("cargo test -p cheers-axum jwks::tests::jwks_includes_service_principal_pubkey_with_its_kid_after_provision — verify line #1 of the ticket")
//! @yah:verify("cargo test -p cheers-axum jwks::tests::rotate_publishes_both_kids_during_overlap_then_drops_old — verify line #2 of the ticket (overlap+drop)")
//! @yah:verify("cargo test -p cheers-core -p cheers-server -p cheers-verify -p cheers-axum (parent relay smoke all green)")
//! @yah:verify("cargo check --workspace --all-features clean")
//!
//! @yah:ticket(R020-F12, "OIDC discovery: GET /.well-known/openid-configuration")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T01:36:29Z)
//! @yah:status(review)
//! @yah:phase(P4)
//! @yah:parent(R020)
//! @yah:next("Serve issuer, jwks_uri, token_endpoint, scopes_supported (from the Scope enum), grant_types_supported (must include urn:ietf:params:oauth:grant-type:token-exchange + passkey), subject_types_supported: ['user', 'service', 'camp'].")
//! @yah:next("scopes_supported must be derived from the typed Scope enum so it can't drift from what mint actually accepts.")
//! @yah:verify("GET the endpoint and validate the JSON shape against a known good fixture.")
//! @yah:verify("scopes_supported equals the full Scope enum at compile time (regression test that fails if the enum is extended but the discovery doc isn't).")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @yah:depends_on(R020-F3)
//! @yah:depends_on(R020-F11)
//! @yah:handoff("LANDED. NEW MODULE: crates/cheers-axum/src/discovery.rs (re-exported from cheers_axum::*): DiscoveryState { issuer } + DiscoveryState::new(issuer) + OpenIdConfiguration { issuer, jwks_uri, token_endpoint, scopes_supported, grant_types_supported, subject_types_supported } + router(state) mounting GET /.well-known/openid-configuration. Public path constants: OPENID_CONFIGURATION_PATH, JWKS_PATH, TOKEN_ENDPOINT_PATH. Public slice constants: SUBJECT_TYPES_SUPPORTED = ['user','service','camp'], GRANT_TYPES_SUPPORTED = ['urn:ietf:params:oauth:grant-type:token-exchange','passkey'].")
//! @yah:handoff("ENUM-DRIVEN SCOPES (the load-bearing invariant): scopes_supported is derived from cheers_core::Scope::ALL — a new pub const on Scope listing every variant. Discovery doc CANNOT drift from what the mint path accepts; they share a single source of truth. ALL is paired with scope_all_is_exhaustive (cheers-core/src/mcp.rs:tests), which uses an exhaustive intra-crate match (Scope is #[non_exhaustive] for external users but fully matchable in cheers-core) — adding a Scope variant without listing it in ALL is either a compile error (missing match arm) or a test failure (per-arm assert).")
//! @yah:handoff("WIRE SHAPE matches the doc §Discovery example verbatim: issuer (product-supplied), jwks_uri = <issuer>/.well-known/jwks.json (verbatim with jwks.rs's mount), token_endpoint = <issuer>/token (the multi-grant /token endpoint is still unticketed — peer of T17), scopes_supported from Scope::ALL, grant_types_supported = ['urn:ietf:params:oauth:grant-type:token-exchange','passkey'], subject_types_supported = ['user','service','camp']. Note: subject_types_supported re-uses the OIDC field NAME for cheers's principal-kind vocabulary, NOT OIDC's pseudonymity variants — consistent with the doc and called out in the module top-comment.")
//! @yah:handoff("TESTS: 4 inline discovery::tests using tower::ServiceExt::oneshot — (1) discovery_doc_matches_known_good_fixture pins the full JSON shape to a known-good OpenIdConfiguration literal, (2) scopes_supported_equals_the_full_scope_enum verifies cfg.scopes_supported == Scope::ALL.map(as_wire) exact order+contents (the regression test the ticket calls for), (3) grant_and_subject_types_include_the_required_values asserts token-exchange + passkey grants and the exact subject_types list, (4) issuer_prefixes_jwks_and_token_endpoints checks URL composition.")
//! @yah:handoff("NO NEW DEPS: discovery.rs uses only the crate's existing axum + serde + cheers-core stack — no base64, no sha2, no openidconnect. Static-ish handler, no per-call work.")
//! @yah:handoff("OpenIdConfiguration and DiscoveryState are #[non_exhaustive] — consumers (and the doctest) must use DiscoveryState::new(issuer) instead of struct-literal syntax. The doctest was updated accordingly.")
//! @yah:handoff("WIRE-CONTRACT COORDINATION: this DOES touch consumer surface via the discovery hop yah's kamaji follows from /.well-known/oauth-protected-resource → cheers's issuer → this discovery doc. Endpoint URL + shape + Scope::ALL ordering need to land in yah-side W159 / R426 before the kamaji discovery wiring is exercised. kid format unchanged; jwks_uri points at the same /.well-known/jwks.json the F11 route serves.")
//! @yah:handoff("VERIFIED GREEN: cargo test -p cheers-axum --lib discovery (4/4 pass), cargo test -p cheers-core (62 unit incl. new scope_all_is_exhaustive + 1 doctest), cargo test -p cheers-server (116 unit + 9 proptest + 2 doctest), cargo test -p cheers-verify (4), cargo test -p cheers-axum (35 unit, up from 31 — 4 new discovery tests; 7 doctests, +1 for discovery), cargo check --workspace --all-features clean.")
//! @yah:next("Sign off F12 — tasks-met, awaiting human review.")
//! @yah:next("When the /token HTTP endpoint that dispatches grant_type to mint_user_fresh / mint_bootstrap / mint_token_exchange lands (peer of T17, still unticketed), the token_endpoint URL is already advertised by this discovery doc — no further coordination needed.")
//! @yah:next("Propagate discovery endpoint shape into yah-side W159 / R426 (kamaji discovery wiring): GET /.well-known/openid-configuration, application/json, issuer/jwks_uri/token_endpoint/scopes_supported/grant_types_supported/subject_types_supported fields, scopes_supported derived from Scope::ALL ordering.")
//! @yah:verify("cargo test -p cheers-axum --lib discovery (4/4 inline discovery::tests pass)")
//! @yah:verify("cargo test -p cheers-axum discovery::tests::discovery_doc_matches_known_good_fixture — verify line #1 (JSON shape vs known-good fixture)")
//! @yah:verify("cargo test -p cheers-core mcp::tests::scope_all_is_exhaustive — verify line #2 (regression test pinning scopes_supported = full Scope enum at compile time via exhaustive intra-crate match)")
//! @yah:verify("cargo test -p cheers-axum discovery::tests::scopes_supported_equals_the_full_scope_enum — the runtime half of verify line #2 (endpoint output reflects Scope::ALL)")
//! @yah:verify("cargo test -p cheers-core && cargo test -p cheers-server && cargo test -p cheers-verify && cargo test -p cheers-axum (parent relay smoke all green)")
//! @yah:verify("cargo check --workspace --all-features clean")
//!
//! @yah:ticket(R020-F14, "Audit read endpoint: GET /audit/by-on-behalf-of/&lt;user&gt; (W127 'who deployed what')")
//! @yah:at(2026-06-04T01:36:44Z)
//! @yah:status(open)
//! @yah:phase(P4)
//! @yah:parent(R020)
//! @yah:next("GET /audit/by-on-behalf-of/<user>?since=&method-prefix= paged.")
//! @yah:next("Authorization: scope=audit:read. Granted to W127-dashboard service principal and to the user themselves for self-queries (sub == path:user).")
//! @yah:next("Cursor pagination, not offset — audit table is append-only and large.")
//! @yah:verify("W127 dashboard service principal queries another user's audit — succeeds.")
//! @yah:verify("Random user A queries user B's audit — 403.")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @yah:depends_on(R020-F13)
//!
//! @yah:ticket(R020-T16, "Bearer/McpClaims authentication middleware in cheers-axum")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-04T18:26:04Z)
//! @yah:status(review)
//! @yah:phase(P2)
//! @yah:parent(R020)
//! @yah:next("Add an McpAuthState<V> struct (verify-side state) holding an Arc<PasetoV4PublicVerifier> (or generic over a TokenVerifier-style trait once the verify_mcp_at sibling lands in T15).")
//! @yah:next("Add bearer_from_headers reuse / a fresh authenticate_mcp helper: pull Authorization: Bearer, verify_mcp_at(token, now), return McpClaims or RouteError::Unauthorized.")
//! @yah:next("Expose McpClaims as an axum Extension (or as a typed FromRequestParts extractor — pick the pattern that composes with the existing /me handlers' style).")
//! @yah:next("Add a scope-guard helper: McpClaims::require_scope(Scope::OwnershipWrite) -> Result<(), RouteError> for handlers to call before any side-effect.")
//! @yah:verify("cargo test -p cheers-axum (unit: bearer extraction reuses the existing missing/malformed mappings; verify_mcp_at success populates the Extension; expired/bad-sig → 401).")
//! @yah:verify("Negative scope test: a McpClaims without Scope::OwnershipWrite is rejected by the scope-guard helper with a typed RouteError.")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @yah:depends_on(R020-T15)
//! @yah:handoff("Landed crates/cheers-axum/src/mcp.rs (re-exported from cheers_axum::*): McpAuthState{ verifier: Arc<PasetoV4PublicVerifier> }, authenticate_mcp(headers, verifier, now) -> Result<McpClaims, RouteError>, and the McpClaimsExt extension trait with require_scope(&self, Scope) -> Result<(), RouteError>. State is non-generic for now — verify_mcp_at is an inherent method on PasetoV4PublicVerifier, no McpTokenVerifier trait exists yet. When one lands the state becomes McpAuthState<V>; documented in the module top.")
//! @yah:handoff("authenticate_mcp REUSES bearer_from_headers from me.rs (kept that helper pub for exactly this consumer). Verification failure routes to RouteError::Unauthorized (401) — expired/bad-sig/malformed all collapse, by design, so a probe can't distinguish them. MissingBearer and MalformedBearer surface their existing variants unchanged. Tested.")
//! @yah:handoff("Scope guard is a TRAIT EXTENSION on McpClaims (cheers-core), not a method on McpClaims itself — the rejection type (RouteError) lives in cheers-axum, so a method on McpClaims would invert the dependency direction. Handler code reads `claims.require_scope(Scope::OwnershipWrite)?;` — native ergonomics with crate-direction intact.")
//! @yah:handoff("Added RouteError::InsufficientScope { required: Scope } variant (403 / 'insufficient_scope'). Distinct from Unauthorized (401) by design: the principal authenticated, the call is just not authorized. Required adding `cheers_core::Scope` to error.rs imports.")
//! @yah:handoff("Confusing-deputy structural guard pinned by authenticate_mcp_rejects_session_token_as_unauthorized — a session-shape token (with 'cheers' additional claim) hitting verify_mcp_at is rejected as Unauthorized (the 'mcp' additional-claim key is absent). The two PASETO claim shapes can't be confused even when both have valid Ed25519 signatures from the same key.")
//! @yah:handoff("9 new tests in mcp::tests: authenticate_mcp_verifies_valid_token_and_returns_claims; authenticate_mcp_rejects_expired_as_unauthorized; authenticate_mcp_rejects_bad_signature_as_unauthorized; authenticate_mcp_rejects_malformed_bearer; authenticate_mcp_rejects_missing_bearer; authenticate_mcp_rejects_session_token_as_unauthorized; require_scope_accepts_held_scope; require_scope_rejects_missing_scope; insufficient_scope_responds_403_with_stable_code (pins status + 'insufficient_scope' code + IntoResponse path).")
//! @yah:handoff("PasetoV4PublicVerifier is imported via cheers_server's re-export (cheers_server::PasetoV4PublicVerifier) — cheers-axum's Cargo.toml already depends on cheers-server, no new direct cheers-verify dep needed. Same pattern as me.rs's existing EdgeVerifier import.")
//! @yah:handoff("Verified GREEN: cargo test -p cheers-axum (19 unit, up from 10 — 9 new mcp tests), cargo test -p cheers-core (51 + 1 doctest), cargo test -p cheers-server (82 + 9 proptest + 2 doctest), cargo test -p cheers-verify (4), cargo check --workspace --all-features clean.")
//! @yah:next("T17 (POST/DELETE /ownership routes) consumes this directly — OwnershipState<O> bundles McpAuthState + Arc<O: OwnershipStore>; handler extracts claims via authenticate_mcp, then `claims.require_scope(Scope::OwnershipWrite)?;` before calling OwnershipStore::insert/revoke_by_id. Set granted_by = claims.sub.to_string() (already in 'svc:<id>' shape on the wire). The InsufficientScope -> 403 mapping is already done; T17 just composes.")
//! @yah:next("When a McpTokenVerifier trait lands (probably alongside R020-F11 JWKS so the verifier can hold multiple kids), genericize McpAuthState -> McpAuthState<V: McpTokenVerifier>; authenticate_mcp becomes generic too. Will be a one-liner per call site — the inherent-method dependence is the only thing blocking it.")
//! @yah:next("The /token HTTP endpoint that dispatches grant_type to mint_user_fresh / mint_bootstrap / mint_token_exchange is still unticketed (peer of T17). It needs cheers_server's McpAuthority on the state side, NOT McpAuthState (which is verify-only). Different surfaces — don't conflate them.")
//! @yah:verify("cargo test -p cheers-axum mcp::tests::authenticate_mcp_verifies_valid_token_and_returns_claims — valid token round-trips, claims equal what was minted.")
//! @yah:verify("cargo test -p cheers-axum mcp::tests::authenticate_mcp_rejects_expired_as_unauthorized — now == exp -> RouteError::Unauthorized (401), not a leaked Expired distinction.")
//! @yah:verify("cargo test -p cheers-axum mcp::tests::authenticate_mcp_rejects_bad_signature_as_unauthorized — token signed by a different keypair -> Unauthorized.")
//! @yah:verify("cargo test -p cheers-axum mcp::tests::authenticate_mcp_rejects_session_token_as_unauthorized — confusing-deputy guard: a session-shape PASETO from the same key surfaces as Unauthorized at the MCP verify path.")
//! @yah:verify("cargo test -p cheers-axum mcp::tests::require_scope_rejects_missing_scope — InsufficientScope { required: OwnershipWrite } when the claim's scope list doesn't contain it.")
//! @yah:verify("cargo test -p cheers-axum mcp::tests::insufficient_scope_responds_403_with_stable_code — status = 403, code = 'insufficient_scope', IntoResponse path emits 403.")
//! @yah:verify("cargo test -p cheers-core && cargo test -p cheers-server && cargo test -p cheers-verify (parent relay smoke).")
//!
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//!
//! @yah:ticket(R020-T17, "Admin HTTP routes for service principals (POST /admin/service-principals + /rotate) + operator auth")
//! @yah:assignee(agent:claude)
//! @yah:at(2026-06-05T02:27:04Z)
//! @yah:status(review)
//! @yah:phase(P3)
//! @yah:parent(R020)
//! @yah:next("Add cheers-axum/src/admin.rs: AdminAuthState { edge: Arc<EdgeVerifier<V,Rd>>, authority: Arc<ServicePrincipalAuthority<S>>, operators: Arc<dyn OperatorPolicy> }. Operator gate: a small trait OperatorPolicy { fn is_operator(&self, user: &UserId) -> bool } so the product wires whatever list/role check it likes.")
//! @yah:next("POST /admin/service-principals { desired_id }: bearer-auth via EdgeVerifier (operator passkey session), assert is_operator(claims.sub), call authority.provision(NewServicePrincipal::new(desired_id), now), return 201 + { principal, signing_key, secret_key_b64 }. Secret_key returned base64url ONCE — never re-fetchable.")
//! @yah:next("POST /admin/service-principals/{id}/rotate: same operator gate; call authority.rotate(&PrincipalId::service(id), now), return 200 + { signing_key, secret_key_b64 }.")
//! @yah:next("Map ServicePrincipalError to RouteError: AlreadyExists -> 409 (new variant), UnknownPrincipal -> 404 (new variant or reuse UnknownDevice-pattern), WrongPrincipalKind/NoActiveKey/Codec -> 500, Store -> Store.")
//! @yah:next("Tests: provision returns secret once; rotate retires old + issues fresh; non-operator caller -> 403; unknown id rotate -> 404.")
//! @yah:verify("cargo test -p cheers-axum admin::tests passes.")
//! @yah:verify("cargo test -p cheers-core && cargo test -p cheers-server && cargo test -p cheers-verify (parent relay smoke).")
//! @yah:gotcha("Secret returned ONCE via the HTTP response — base64url-no-pad encode the 64-byte secret_key. Do NOT log the response body; tracing::warn at handler level must not include the response.")
//! @yah:gotcha("Operator check is DIFFERENT from MCP scope check: operator endpoints take a SESSION bearer (EdgeVerifier::verify_at -> Claims), NOT an MCP bearer (verify_mcp_at -> McpClaims). Don't confuse the two state structs.")
//! @arch:see(.yah/docs/working/mcp-auth-and-ownership.md)
//! @yah:handoff("LANDED crates/cheers-axum/src/admin.rs: AdminAuthState<V,Rd,S> { edge: Arc<EdgeVerifier<V,Rd>>, authority: Arc<ServicePrincipalAuthority<S>>, operators: Arc<dyn OperatorPolicy> } + OperatorPolicy trait (sync `fn is_operator(&self, &UserId) -> bool`) + CreateServicePrincipalBody + ProvisionResponse { principal, signing_key, secret_key_b64 } (Serialize+Deserialize so callers and tests can parse it) + router() mounting POST /admin/service-principals and POST /admin/service-principals/{id}/rotate. Re-exported from cheers_axum::* (lib.rs).")
//! @yah:handoff("ERROR MAPPINGS in cheers-axum/src/error.rs: added RouteError::AlreadyExists(String) -> 409 'already_exists', RouteError::UnknownPrincipal(String) -> 404 'unknown_principal', RouteError::NotOperator -> 403 'not_operator'. Plus From<ServicePrincipalError> impl: AlreadyExists/UnknownPrincipal map specifically, everything else (WrongPrincipalKind/NoActiveKey/Codec/Principal) collapses to 500 via Store(other.to_string()) — by design, those are programmer-error reaching the handler and shouldn't be client-distinguishable.")
//! @yah:handoff("BEARER KIND: admin endpoints take SESSION bearers (EdgeVerifier::verify_at -> Claims), not MCP bearers — reused crate::me::authenticate() verbatim. Operator check runs AFTER session auth: `if !state.operators.is_operator(&claims.sub) { return Err(NotOperator); }`. Pinned by negative test: non-operator caller gets 403 AND the principal store is empty afterwards (no side-effect leak).")
//! @yah:handoff("BASE64 IS NOW UNCONDITIONAL in cheers-axum/Cargo.toml (was optional, only on under google/apple/passkey/email features). Dropped `dep:base64` from those four feature lists. Reason: admin routes base64url-encode the 64-byte secret_key in the response body — making the dep feature-gated would mean either gating /admin routes too (wrong; admin is core) or duplicating the dep. The 17KB base64 crate is already pulled by every realistic build.")
//! @yah:handoff("TESTS: 9 inline admin::tests using tower::ServiceExt::oneshot against the full Router. Covers (1) provision returns 201 + secret-once + JWKS sees the new pubkey; (2) non-operator -> 403 with no store side-effect; (3) missing bearer -> 401; (4) duplicate desired_id -> 409; (5) rotate retires old + issues fresh + both kids in JWKS during overlap; (6) rotate unknown id -> 404; (7) rotate non-operator -> 403; (8) ProvisionResponse round-trips via real provision (the structs are #[non_exhaustive]); (9) OperatorPolicy is dyn-compatible. tokio::test runtime (NOT pollster::block_on — needed for the existing tokio-tower interop).")
//! @yah:handoff("VERIFIED: cargo test -p cheers-axum admin::tests (9/9 pass), cargo test -p cheers-axum (31/31, up from 22 — 9 new admin tests), cargo test -p cheers-axum --all-features (35 unit + all integration tests pass), cargo test -p cheers-core -p cheers-server -p cheers-verify (parent relay smoke: 51 + 96 + 9 proptest + 4 + doctests, all green), cargo check --workspace --all-features clean.")
//! @yah:handoff("GRANT WIRING STILL NOT DONE (intentional, matches F9 handoff). The route body is just { desired_id }; granting scopes to the new principal is the separate composable layer the F9 handoff calls out. When GrantStore gains a put_grant trait method, extend AdminAuthState with the grants store and add a `grants: Vec<Scope|BundleName>` body field. Don't reach for it from the rotate route — rotation is about key material, not authorization.")
//! @yah:next("Sign off T17 — tasks-met, awaiting human review.")
//! @yah:next("Claim R020-T18 (cheers-sqlx PgServicePrincipalStore + Turso path, see [[cheers-sqlx-backends]] memory). Note backend is Postgres + Turso (libSQL), not vanilla SQLite — verify libSQL-compat for any SQLite-only pragmas.")
//! @yah:next("Claim R020-F11 (JWKS extension) — depends on F9, can run in parallel with T18.")
//! @yah:next("Claim R020-F10 (camp bootstrap endpoint) — depends on F2/F4/F9, parallelizable.")

#![warn(missing_debug_implementations)]
#![warn(unreachable_pub)]

pub mod admin;
pub mod audit;
pub mod camps;
pub mod cookie;
pub mod discovery;
pub mod error;
pub mod jwks;
pub mod mcp;
pub mod me;
pub mod ownership;
pub mod session;

#[cfg(feature = "google")]
pub mod google;

#[cfg(feature = "apple")]
pub mod apple;

#[cfg(feature = "passkey")]
pub mod passkey;

#[cfg(feature = "email")]
pub mod magic_link;

pub use admin::{
    AdminAuthState, CreateServicePrincipalBody, OperatorPolicy, ProvisionResponse,
};
pub use audit::{AuditIngestBody, AuditIngestResponse, AuditState};
pub use camps::{CampAdminState, CampBootstrapResponse, CreateCampBootstrapBody};
pub use cookie::CsrfCookieConfig;
pub use discovery::{
    DiscoveryState, GRANT_TYPES_SUPPORTED, OPENID_CONFIGURATION_PATH, OpenIdConfiguration,
    SUBJECT_TYPES_SUPPORTED,
};
pub use error::RouteError;
pub use jwks::{Jwk, JwkSet, JwksState, PlatformSigningKey, DEFAULT_JWKS_MAX_AGE_SECONDS};
pub use mcp::{authenticate_mcp, McpAuthState, McpClaimsExt};
pub use me::{MeAuthState, SessionDescriptor, SessionDirectory, SessionListEntry};
pub use ownership::{CreateOwnershipBody, OwnershipState};
pub use session::SessionBody;
