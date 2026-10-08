//! Session JSON response shape returned by `callback` handlers.
//!
//! R018-T4 will refine this with /api/me/sessions list+revoke. For T2 we
//! return the minimal triple a client needs: access_token (the PASETO/HMAC
//! string), refresh_token (the opaque secret), and the user_id the IdP
//! resolved to.
//!
//! @yah:relay(R730, "cheers-axum refresh door: POST /auth/refresh over SessionAuthority::rotate (refresh_token grant), so a cheers consumer can spend the refresh token it already hands out")
//! @yah:status(review)
//! @yah:at(2026-10-03T20:10:51Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:next("WHY: every cheers ceremony returns SessionBody.refresh_token, but no cheers-axum router can spend one, and the noisetable SPA drops it for that reason (web/landing/src/account/session.ts). noisetable R743-T44 (staging account étude lane) is blocked on this: operator decision 2026-10-03 is refresh-token write-back, and api-staging.noisetable.com/api/v1/auth/refresh answers 404 today. The operator asked whether cheers-axum should own it. Answer: yes. It is the RFC 6749 section 6 refresh grant with rotation plus reuse detection (OAuth security BCP), and cheers already implements the semantics in cheers-server SessionAuthority::rotate / RefreshRotator, where a replay revokes the chain. Only the HTTP door is missing.")
//! @yah:next("DESIGN CALL BEFORE CODE (the reason this was not built in passing): rotate() mints the access token in the same call that spends the refresh token, but the refresh record carries no DeviceBinding (the R018 'guide by omission' decision, restated in cheers-axum me.rs, which rejected a binding column). A generic door therefore cannot know the binding to mint with. Recommended: add a cheers-server variant that rotates first and then asks a caller-supplied resolver for the binding of (user_id, device_id) before minting. The product resolver is its SessionDirectory/SessionRecorder rows (the noisetable account service records binding per device in sessions.rs). Re-record the session on rotation (SessionRecorder::record_new_session) so /me/sessions reflects the extended chain expiry. If no binding is recorded, refuse rather than guess.")
//! @yah:next("CONTRACT the consumer already codes against (noisetable tools/etude/src/staging.rs, REFRESH_PATH): POST <api_base>/auth/refresh with JSON {\"refresh_token\"} returns 200 SessionBody (access_token, refresh_token, access_expires_at, refresh_expires_at, user_id, device_id, jti). A spent, revoked or expired token is a 401 (400/403/410 are also treated as rejection). Rate-limit like magic-link. Mount it in web/services/account auth::router beside magic_link_routes. Then publish cheers, bump web/services, and redeploy noisetable-account-staging (operator-gated).")
//! @yah:handoff("2026-10-03 (Ashguard, courier session:dfa746e0): the refresh door is built and tested in oss/cheers. The leader still holds the claim.")
//! @yah:handoff("cheers-server: SessionAuthority::rotate and rotate_bound are generalized rather than given a _v2. The `binding` param is now `&B where B: BindingResolver + ?Sized`. The new trait BindingResolver::resolve_binding(user, device, now) -> Result<Option<DeviceBinding>, StoreError> lives in session.rs and is re-exported. A fixed DeviceBinding implements it, so existing callers just pass `&DeviceBinding::X`. Fixed call sites: session.rs tests and cheers-test-support/src/lib.rs:246.")
//! @yah:handoff("Ordering is check, then resolve, then commit. RefreshRotator::rotate is split into check() and commit(), and rotate() is now check followed by commit. check() returns an opaque LiveRefresh (exported) that only a successful check can construct. check() runs unknown, revoked, replay (which revokes the chain) and expired, and mutates nothing on success. rotate_inner resolves the binding before commit's mark_consumed. If no binding is found, the new cheers-core RefreshError::Unbound is returned with the token unspent and the chain untouched, so nothing is half-rotated and nothing is minted unbound. Replay still outranks Unbound. A resolver store error becomes Error::Store and also spends nothing. This is documented at SessionAuthority::rotate.")
//! @yah:handoff("cheers-axum: new always-on module src/refresh.rs. It has RefreshAuthState{authority, bindings: Arc<dyn BindingResolver>, recorder: Arc<dyn SessionRecorder>}, DirectoryBindings(Arc<D: SessionDirectory>) (the product resolver, built over the /me/sessions rows its recorder writes), router() mounting POST /refresh, and RefreshBody{refresh_token}. lib.rs re-exports these as refresh_router, DirectoryBindings, RefreshAuthState and RefreshBody. Every Error::Refresh(_) except Store maps to RouteError::Unauthorized (401 'unauthorized', which avoids an oracle). Successful rotations are re-recorded via record_new_session. A recorder failure on THIS path is logged with tracing::warn, not returned: the token is already spent, so a failed request would turn the client's retry into a replay that revokes the chain. SessionBody::from_new_session is no longer feature-gated.")
//! @yah:handoff("SessionRecorder contract (me.rs doc): the recorder is also called on every rotation, with the rotation time as issued_at. Upsert impls should keep their stored issued_at on conflict and take the new expires_at. The test MemSessionDirectory's record_established now does this.")
//! @yah:handoff("RATE LIMIT: cheers-axum has NO limiter on the magic-link routes. noisetable layers one (web/services/account/src/auth.rs, magic_link_send_cap, from rate_limit.rs). So refresh::router also ships unlimited, and its module doc tells the consumer to layer its own limiter the same way. Wiring that cap is a consumer step.")
//! @yah:handoff("TESTS: new cheers-axum/tests/refresh_basic.rs (6 tests): happy path with a new pair and a live successor; replay gives 401 and the newer token also gets 401; expired (refresh ttl 0) gives 401; unknown gives 401; no recorded binding gives 401 with no access_token or refresh_token in the body, and the same token rotates once the row is recorded; /me/sessions shows the extended expires_at and keeps the original issued_at. Also 4 new cheers-server unit tests in session.rs (resolver keyed by chain identity, unbound refuses without spending, resolver failure spends nothing, replay revokes before the resolver is asked).")
//! @yah:handoff("VERIFIED: `cargo test -p cheers-server`: 163+9+5+2 pass (baseline 159+9+5+2). `cargo test -p cheers-axum`: 68+66+11 pass, 2 ignored (baseline 68+60+10, 2 ignored). `cargo test -p cheers-axum --all-features`: 72+89+14 pass, 2 ignored. `cargo check --workspace --all-targets`: clean apart from a pre-existing unused `policy` warning at cheers-test-support/src/lib.rs:222, which is not from this change. Nothing is committed (git-policy=defer).")
//! @yah:handoff("2026-10-03 (Glimmerstone, leader session:67c7c3bf): the cheers-side door has landed. The courier was @Ashguard:coffee (session:dfa746e0); its full account is in the handoff entries above. Nothing is committed (git-policy=defer). The remaining steps are cross-repo or operator-gated: publishing cheers (a breaking rotate signature change) and noisetable's mount, rate cap, pin bump and staging redeploy, which is noisetable R743-T44's lane.")
//! @yah:verify("The leader re-ran `cargo test -p cheers-server -p cheers-axum` in oss/cheers: EXIT=0, 68/66/163/9/5/11(2 ignored)/2 pass, 0 fail. This matches the courier's counts (baseline: cheers-server 159, cheers-axum 60+10).")
//! @yah:next("OUT OF SCOPE for the courier, still remaining (all operator-gated or in another repo): (1) publish cheers. This is a breaking API change: SessionAuthority::rotate/rotate_bound now take `&impl BindingResolver`, and RefreshError gains Unbound (non_exhaustive). (2) In noisetable web/services/account auth::router, mount cheers_axum::refresh_router(RefreshAuthState{authority, bindings: Arc::new(DirectoryBindings(sessions)), recorder: sessions}) beside magic_link_routes under /auth, layer a refresh rate cap from rate_limit.rs, and keep issued_at on conflict in its SessionRecorder upsert (sessions.rs). (3) Bump the cheers pins in web/services. (4) Redeploy noisetable-account-staging so api-staging.noisetable.com/api/v1/auth/refresh stops returning 404 (unblocks noisetable R743-T44).")
//! @yah:handoff("2026-10-03 (Ashguard, courier session:b50c7a9a): cheers 0.8.43-pre.1 is PUBLISHED on crates.io (operator option A: cheers only, everything else stays 0.8.42). The 9 crates are cheers-core, cheers-providers, cheers-store, cheers-verify, cheers-server, cheers-axum, cheers-redis, cheers-sqlx and cheers-turso, each at 0.8.43-pre.1; every one was confirmed through the crates.io API. Pre-flight: every uncommitted hunk under oss/cheers is R730's, apart from board-only annotation lines for R729 in cheers-axum/src/passkey.rs. Published with --allow-dirty because git-policy=defer, which the operator approved via ask_user. Nothing is committed.")
//! @yah:handoff("Version edits: oss/cheers [workspace.package] version is 0.8.43-pre.1, and every intra-family path dep is version \"=0.8.43-pre.1\" (mshr stays 0.8.42). In-tree consumers were retargeted to \"0.8.43-pre.1\" so they still resolve: crates/yah/cloud-admin, crates/yah/control-plane, app/yah/cli and app/yah/mobile Cargo.toml, plus oss/mesofact/crates/mesofact-core/Cargo.toml. The root has no cheers [patch.crates-io] entry; it uses path deps. The next `cargo xtask release 0.8.43` resets all of these to 0.8.43, because retarget_table rewrites any oss-crate requirement that differs from the target.")
//! @yah:handoff("VERIFIED: `cargo test -p cheers-server -p cheers-axum` passes cheers-server 163+9+5+2 and cheers-axum 68+66+11 with 2 ignored, 0 failed, matching the baseline (log /tmp/che-r730-pre1-test-a.log). `cargo publish --workspace --dry-run` is green for all 9 crates. Root `cargo check -p yah` gives EXIT=0, and mesofact `cargo metadata` gives EXIT=0. The first real publish timed out on index lag after 4 crates; I polled index.crates.io and the rerun published the other 5.")
//! @yah:handoff("Release skill crates/yah/party/src/skill_procedures/release.md gains the section 'One-off family pre-release', which covers the standing pattern and the index-lag recovery. scripts/oss-publish.sh needed no change. Operator commit to sweep: oss/cheers, the 5 consumer Cargo.tomls listed above, and release.md. Noisetable (pin to cheers-axum \"0.8.43-pre.1\", mount, redeploy) is untouched; that is the R743-T44 follow-up.")

use serde::{Deserialize, Serialize};

use cheers_server::NewSession;

/// JSON body returned by every successful login callback.
///
/// `token_type` is `Bearer` so a frontend can drop the header in verbatim:
/// `Authorization: Bearer <access_token>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SessionBody {
    pub access_token: String,
    pub token_type: &'static str,
    /// Absolute unix-seconds expiry, mirroring the `Claims.expires_at` in the
    /// signed access token. Clients can use this without re-verifying the
    /// PASETO to decide when to rotate.
    pub access_expires_at: i64,
    pub refresh_token: String,
    pub refresh_expires_at: i64,
    pub user_id: String,
    pub device_id: String,
    /// `jti` of the access token — useful so a frontend that wants to
    /// preemptively logout can hand it back without re-decoding the token.
    pub jti: String,
}

// Unconditional since R730: the refresh door (no provider feature) returns it.
impl SessionBody {
    pub(crate) fn from_new_session(session: NewSession) -> Self {
        let NewSession {
            access_token,
            claims,
            refresh,
            ..
        } = session;
        Self {
            access_token,
            token_type: "Bearer",
            access_expires_at: claims.expires_at,
            refresh_token: refresh.token.into_inner(),
            refresh_expires_at: refresh.record.expires_at,
            user_id: claims.sub.into_inner(),
            device_id: claims.device.into_inner(),
            jti: claims.jti,
        }
    }
}
