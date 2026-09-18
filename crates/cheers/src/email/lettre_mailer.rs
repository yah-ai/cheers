//! [`Mailer`] backed by an SMTP relay via [`lettre`].
//!
//! Gated behind the `email-lettre` feature so trait-only consumers don't
//! pull lettre + tokio + rustls. The transport is rustls-only — cheers's
//! `deny.toml` rejects native-tls / openssl-sys.
//!
//! # Constructing a transport
//!
//! ```no_run
//! use cheers::email::lettre_mailer::LettreMailer;
//!
//! # async fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! let mailer = LettreMailer::starttls("smtp.example.com", "user", "secret")?;
//! # let _ = mailer; Ok(()) }
//! ```
//!
//! [`LettreMailer::implicit_tls`] covers the 465 shape, and
//! [`LettreMailer::plaintext`] covers a dev mail catcher on an arbitrary port
//! with no TLS and no auth. For anything beyond those three (pooled
//! connections, a custom TLS parameter set, …), build the underlying
//! [`AsyncSmtpTransport`] directly and wrap it with [`LettreMailer::from_transport`].
//!
//! @yah:relay(R518, "Mail transport surface: reach dev-tier and non-standard-port SMTP relays without forcing a direct lettre dep")
//! @yah:at(2026-09-11T06:15:14Z)
//! @yah:status(open)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//!
//! @yah:ticket(R518-F1, "LettreMailer::plaintext(host, port) — a third constructor beside starttls and implicit_tls")
//! @yah:status(review)
//! @yah:at(2026-09-11T06:15:16Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R518)
//! @yah:next("ADD `LettreMailer::plaintext(host: &str, port: u16) -> Result<Self, MailerError>` beside starttls and implicit_tls, over `AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host).port(port)`, with NO credentials — a local catcher accepts anonymous submission and passing Credentials it will not challenge for is noise. Everything needed already exists: `from_transport` is public and its doc comment at lettre_mailer.rs names \"dangerous-localhost / non-standard-port configurations\" as precisely the case it is there for. This is that case, given a name, so a caller does not have to reimplement it. Mirror the two existing constructor tests — `starttls_constructor_does_not_dial` / `implicit_tls_constructor_does_not_dial` — with the plaintext equivalent; constructing must not dial. Tier: Thief — one function, one test, an established local pattern to copy.")
//! @yah:verify("WHY THIS IS BEING ASKED FOR, so the constructor is not mistaken for speculative surface: yah R584-F2 adds a dev/pond-tier SMTP capability driver (mailcrab) under W265's capability/driver model, and mailcrab listens plaintext on 1025 with no auth. Neither existing constructor can dial it — starttls pins 587 + STARTTLS + PLAIN/LOGIN auth, implicit_tls pins 465. Without this, every consumer that wants the dev catcher takes a direct lettre dependency solely to build a transport, which re-forks the seam cheers owns. First consumer is noisetable-account (web/services/account/src/{config.rs,mailer.rs} in the noisetable camp), which already speaks `cheers::email::Mailer` and selects transports through an AccountMailer enum.")
//! @yah:handoff("LANDED: LettreMailer::plaintext(host: &str, port: u16) -> Result<Self, MailerError> in crates/cheers/src/email/lettre_mailer.rs, built over AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host).port(port).build() with NO credentials, exactly as the @yah:next specified. Item-level doc names it plaintext + unauthenticated, names the dev-catcher use case (mailcrab/MailHog), and states explicitly that a caller selecting transports from deploy-time config must reach it via its own distinct token rather than making a production arm port-configurable.")
//! @yah:gotcha("NAME IT SO IT CANNOT BE SELECTED BY ACCIDENT IN PRODUCTION, and leave the danger in the name or the docs — this constructor sends mail over an unencrypted, unauthenticated connection. The existing pair reads `starttls` / `implicit_tls`, so `plaintext` is the honest third member; lettre's own builder is called `builder_dangerous` for the same reason. Downstream consumers should reach it only from a transport selection that a deploy-time config value cannot land on by typo — noisetable-account's config.rs, for instance, fails closed on any NOISETABLE_ACCOUNT_MAILER value outside its known set, and will gate this behind a distinct token rather than making the production `smtp` arm port-configurable.")
//! @yah:verify("RUN IT WITH THE FEATURE ON, THE BARE FORM IS VACUOUS: `cd oss/cheers && cargo test -p cheers-providers --features email-lettre`. The package is `cheers-providers`, NOT `cheers` (`cargo test -p cheers` does not resolve to a package in this workspace and tripped the implementing courier). `email-lettre` is OFF by default, so `cargo test -p cheers-providers` with no `--features` never COMPILES lettre_mailer.rs at all: `plaintext` and its `plaintext_constructor_does_not_dial` test are absent from the binary and the run still exits 0 green. Measured 2026-09-11 on this tree: without the feature = 119 lib tests + 9 doc-tests passed, proving nothing about this ticket; with `--features email-lettre` = 123 lib tests + 10 doc-tests passed, and the +4 lib tests / +1 doc-test ARE the lettre_mailer module (the doc-test is the module header example at lettre_mailer.rs line 9). A run reporting 119/9 is a false green — re-run it with the feature.")
//!
//! @yah:ticket(R518-B2, "No CI pipeline ever builds cheers' `email-lettre` feature — every test behind it is dead in the pipeline")
//! @yah:status(review)
//! @yah:at(2026-09-13T07:27:55Z)
//! @yah:assignee(agent:bundle-anthropic-ashguard)
//! @yah:parent(R518)
//! @yah:severity(high)
//! @yah:next("MAKE SOME PIPELINE RUN `cheers-providers` WITH `email-lettre` ON. Today no pipeline in the yah camp runs cheers' tests at ALL — not with the feature, not without it. Audited 2026-09-11 across every file in external/yah/.yah/qed/: the only cheers compile in CI is `yah-dashboard-e2e-auth.toml` step `build:cheers` (line 77-83), which is `cargo build --manifest-path oss/cheers/Cargo.toml -p cheers-test-identity --bin cheers-test-identity` — a different package, a build not a test, default features. `oss-publish.toml` step `publish-cheers` (line 364) shells `scripts/oss-publish.sh oss/cheers`, which runs `cargo publish --workspace` (line 107/109) and no tests. `mesofact-musl.toml` lists `oss/cheers` only in `source_context` (lines 214, 363) so the musl image can see the path dep. `peers.toml` registers `[peer.cheers] path = \"oss/cheers\"` (line 24) but oss/cheers has NO `.yah/qed/` directory, so no peer sub-pipeline can target it, and `oss/cheers/.github/workflows/` is an empty directory. The only `--all-features` anywhere in the camp is `yah-check.toml` line 307, scoped to `-p yah-mesofact-bundle` in oss/yah-base. The shape to copy is that same `bundle-contract-matrix` step: a `--manifest-path oss/cheers/Cargo.toml` cargo step is the camp's sanctioned form for a cross-workspace test (it also keeps the step off the root `cargo-target` concurrency key). Whether that step belongs in `yah-check.toml` or in a new cheers-owned pipeline is the call to make — that is a deliberate QED change and wants an owner, which is why this is a ticket and not an edit. Tier: Thief — one step in one TOML plus the ownership call; no new infrastructure.")
//! @yah:gotcha("THE EVIDENCE, MEASURED ON THIS TREE 2026-09-11. `cd oss/cheers && cargo test -p cheers-providers` = 119 lib tests + 9 doc-tests, all green. `cargo test -p cheers-providers --features email-lettre` = 123 lib tests + 10 doc-tests, all green. The 4-test gap is the entire `email::lettre_mailer` module, including R518-F1's brand-new `plaintext_constructor_does_not_dial`; the extra doc-test is that module's header example. Because `email-lettre` is off by default, the bare command does not merely skip those tests — it never compiles the file, so a type error in `LettreMailer` would also pass. An exit-0 there is a false green.")
//! @yah:verify("After the step lands: the chosen pipeline's step list contains a cargo test invocation naming `--features email-lettre` (or `--all-features`) for `-p cheers-providers`, and a run of it reports 123 lib tests / 10 doc-tests for that step, not 119/9. 119/9 means the feature flag did not take.")
//! @yah:gotcha("WHY THE BLAST RADIUS IS PRODUCTION AND NOT JUST THIS CRATE. noisetable's independent `web/services/` workspace consumes the cheers family through a COMMITTED `[patch.crates-io]` path dep at external/yah (see noisetable .yah/docs/working/W124-noisetable-web-services.md), and `noisetable-account` — the live sign-in service — is the first consumer of `LettreMailer`, selecting its transport through an `AccountMailer` enum in web/services/account/src/{config.rs,mailer.rs}. So a regression in anything behind `email-lettre` reaches a production sign-in path while every pipeline in the yah camp stays green. noisetable's own `web-services-published` card (.yah/qed/web-services-published.toml) only COMPILES web/services against published crates — it runs no cheers tests either.")
//! @yah:handoff("LANDED: `.yah/qed/yah-check.toml` step `cheers-lettre-transport` (line 362), inserted directly after `bundle-contract-matrix` as step 3d. argv = `cargo test --manifest-path oss/cheers/Cargo.toml -p cheers-providers --features email-lettre --locked`, timeout 1800. That is the only change in this ticket — one step in one TOML, no new infrastructure, matching the filed Thief tier.")
//! @yah:handoff("THE OWNERSHIP CALL, DECIDED AND WHY: yah-check.toml, NOT a new cheers-owned pipeline. `oss/cheers` has no `.yah/qed/` at all, so the `[peer.cheers]` entry in `.yah/qed/peers.toml:24` has nothing to target — but standing one up would not by itself make anything RUN, because a peer sub-pipeline only executes when some pipeline dispatches it. The yah-check edit would have been needed either way, so the second artifact bought nothing this ticket needs. Placing it here also gets release coverage for free: `.yah/qed/yah-release-check.toml:65-66` runs `target = { path = \".yah/qed/yah-check.toml\" }` as a sub-pipeline, so every release check now compiles and runs the lettre transport.")
//! @yah:handoff("`--features email-lettre` AND NOT `--all-features`, decided on read evidence: cheers-providers' `[features]` (oss/cheers/crates/cheers/Cargo.toml) defines `macos = [passkey, dep:objc2, dep:objc2-foundation, dep:objc2-authentication-services]`, which `--all-features` would enable. That builds on this camp's Mac and cannot build on a Linux runner, so `--all-features` would have made the step platform-dependent while adding zero coverage of the transport being guarded. Default features stay on; the flag is purely additive.")
//! @yah:handoff("THE CONCURRENCY KEY NEEDED NO CHANGE, and that is load-bearing rather than lucky. yah-check holds `cargo-target#ci-dev`; the new step builds `oss/cheers/target` instead and carries no `--profile`. It is exempt from the guard by construction: `runs_cargo_locally` at app/yah/cli/tests/camp_qed_admission_lanes.rs:83-91 returns false for any argv containing `--manifest-path`, and its doc comment at :78-82 names `bundle-contract-matrix` as the live precedent for exactly this. Read directly, not inferred.")
//! @yah:handoff("STEP COMMENT CARRIES THE ASSERTION AS A DELTA, NOT AS ABSOLUTE COUNTS — see the count gotcha below for why the filed numbers had already rotted in two days.")
//! @yah:verify("STEP IS REGISTERED AND PARSES: `yah qed pipelines --verbose` line 485 renders `- cheers-lettre-transport (cargo test --manifest-path oss/cheers/Cargo.toml -p cheers-providers --features email-lettre --locked)`, immediately after bundle-contract-matrix. That is the recipe loader's own parse of the edited TOML, so a malformed table could not have produced it.")
//! @yah:verify("THE STEP'S OWN COMMAND RUN ON THIS TREE, 2026-09-13: `cd oss/cheers && cargo test -p cheers-providers --features email-lettre --locked` -> exit 0, 130 lib passed / 0 failed, 10 doc-tests passed. Doc-test list includes `crates/cheers/src/email/lettre_mailer.rs - email::lettre_mailer (line 9) - compile`, i.e. the module is genuinely compiled, which was the whole failure being fixed.")
//! @yah:verify("THE DELTA MEASURED, which is what makes the step non-vacuous: same command WITHOUT the feature -> 126 lib / 9 doc. So the flag is worth exactly 4 lib tests + 1 doc-test, and those five are the whole of `email::lettre_mailer`. If a future run of this step ever reports the same count as the bare command, the feature stopped taking.")
//! @yah:verify("NOT RUN, AND THIS IS THE ONE GAP: `cargo test -p yah --locked --profile ci-dev --test main -- camp_qed_admission_lanes` (the concurrency-key guard) cannot build on this tree — see the peer-breakage gotcha. Attempted three times, red at the same call site each time, never reaching a test. The property it would assert is established above by reading `runs_cargo_locally`; re-run it once the root workspace compiles.")
//! @yah:verify("ALSO NOT RUN: `yah qed run yah-check` end to end. Same structural wall R838 and R835-T2 both recorded on this recipe — check.toml declares no workspace mode so it defaults to `checkout`, which refuses over tracked uncommitted changes, and this shared tree has ~40 from live peers. Needs a clean tree, i.e. an operator action.")
//! @yah:gotcha("THE COUNTS IN THIS TICKET'S FILING GOTCHA ARE STALE — do not verify against them. Filed 2026-09-11 as 119/9 bare and 123/10 with the feature; re-measured 2026-09-13 as 126/9 and 130/10. The crate gained seven `providers::oidc_generic` lib tests in between, unrelated to lettre. The DELTA (4 lib + 1 doc) is the invariant and is what the step's comment asserts; absolute counts rot in days on this tree.")
//! @yah:gotcha("BLOCKED THE GUARD RUN, NOT THIS CHANGE, AND IS NOT MINE: the root workspace does not compile as of 2026-09-13. `error[E0061]: this method takes 4 arguments but 3 arguments were supplied` at app/yah/cli/src/cloud.rs:11151 — `rv_slot.to_workload_payload(env, feeds, feed_project_prefix)` is missing argument #4 of type `Vec<SecretMount>`, against the method defined at oss/yubaba/crates/cloud/src/reconciler/mesofact_bundle.rs:589. An in-flight signature change whose call site has not caught up. Attributed to R876 (@Miravel:libra, session:592a7b04) because that session was live in oss/yubaba running `cargo test -p yah-cloud --lib mesofact_bundle` with both mesofact_bundle.rs and yubaba/src/deploy/secret_mount.rs uncommitted-modified; git cannot prove authorship of a working-tree hunk, so treat that as strong inference, not fact. Notified via party.chat 2026-09-13. I did not touch either file. Every root-workspace cargo test on this tree fails at that line until it lands.")
//! @yah:gotcha("THIS STEP GATES cheers-providers ONLY, deliberately, and the rest of the cheers workspace remains untested by any pipeline in this camp — cheers-core, cheers-axum, cheers-store, cheers-sqlx, cheers-turso, cheers-redis, cheers-server, cheers-verify all still have zero CI coverage here. Widening to `--workspace` is defensible but is a different change with a different cost, and `--features` needs a `-p` to attach to. Same reasoning bundle-contract-matrix records for oss/yah-base at yah-check.toml:307-309.")
//! @yah:cleanup("`.yah/qed/oss-binaries.toml:67-73` carries a commented-out `target = { peer = { camp = \"cheers\", pipeline = \"release-build\" } }` sub-pipeline step. It is dead because `oss/cheers` has no `.yah/qed/` directory, so the peer registration at peers.toml:24 resolves to a camp with no recipes. Uncommenting it requires standing up `oss/cheers/.yah/qed/release-build.toml` first — the cross-camp interface name is fixed and documented at yah-install.toml:87. Out of scope here; this ticket needed a test gate, not a release lane.")

use async_trait::async_trait;
use lettre::message::{Mailbox, MultiPart, SinglePart, header::ContentType};
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncTransport, Message, Tokio1Executor};

use crate::email::mailer::{EmailMessage, Mailer, MailerError};

/// SMTP-backed [`Mailer`].
///
/// Holds an [`AsyncSmtpTransport`] internally; clone-cheap (the transport
/// is `Clone` and connection-pooled by lettre).
#[derive(Clone)]
pub struct LettreMailer {
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl LettreMailer {
    /// STARTTLS relay on the standard submission port (587) with PLAIN /
    /// LOGIN auth. The most common shape for managed SMTP providers.
    pub fn starttls(
        host: &str,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, MailerError> {
        let creds = Credentials::new(username.into(), password.into());
        let transport = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
            .map_err(|e| MailerError::Build(format!("starttls_relay: {e}")))?
            .credentials(creds)
            .build();
        Ok(Self { transport })
    }

    /// Implicit TLS (port 465) relay with PLAIN / LOGIN auth.
    pub fn implicit_tls(
        host: &str,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<Self, MailerError> {
        let creds = Credentials::new(username.into(), password.into());
        let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(host)
            .map_err(|e| MailerError::Build(format!("relay: {e}")))?
            .credentials(creds)
            .build();
        Ok(Self { transport })
    }

    /// **Plaintext, unauthenticated** SMTP on an arbitrary port — no TLS, no
    /// credentials, nothing on the wire is encrypted.
    ///
    /// This exists for **development mail catchers** (mailcrab, MailHog,
    /// `python -m smtpd`), which accept anonymous submission on a
    /// non-standard port and speak no TLS at all. Neither [`Self::starttls`]
    /// (587 + STARTTLS + PLAIN/LOGIN) nor [`Self::implicit_tls`] (465) can
    /// dial one.
    ///
    /// Never select this for a production relay: the message body, the
    /// envelope and every recipient address travel in the clear, and the peer
    /// is never authenticated. A caller that picks a transport from
    /// deploy-time config should reach this constructor from its own
    /// distinct, explicitly-named token — not by making a production arm
    /// port-configurable, where one typo'd value would silently downgrade a
    /// real send.
    ///
    /// Returns `Result` for symmetry with the two constructors above;
    /// lettre's `builder_dangerous` cannot fail, so this is always `Ok`.
    pub fn plaintext(host: &str, port: u16) -> Result<Self, MailerError> {
        let transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(host)
            .port(port)
            .build();
        Ok(Self { transport })
    }

    /// Wrap a caller-built transport — for pooled / dangerous-localhost /
    /// non-standard-port configurations not covered by the helpers above.
    pub fn from_transport(transport: AsyncSmtpTransport<Tokio1Executor>) -> Self {
        Self { transport }
    }

    /// Underlying transport, for tests and lettre-aware tooling.
    pub fn transport(&self) -> &AsyncSmtpTransport<Tokio1Executor> {
        &self.transport
    }
}

fn parse_mailbox(role: &str, raw: &str) -> Result<Mailbox, MailerError> {
    raw.parse::<Mailbox>()
        .map_err(|e| MailerError::Build(format!("{role}: {e} ({raw:?})")))
}

#[async_trait]
impl Mailer for LettreMailer {
    async fn send(&self, msg: &EmailMessage) -> Result<(), MailerError> {
        let from = parse_mailbox("from", &msg.from)?;
        let to = parse_mailbox("to", &msg.to)?;

        let mut builder = Message::builder().from(from).to(to).subject(&msg.subject);
        if let Some(reply) = &msg.reply_to {
            builder = builder.reply_to(parse_mailbox("reply_to", reply)?);
        }

        let email = match &msg.html {
            None => builder
                .header(ContentType::TEXT_PLAIN)
                .body(msg.text.clone()),
            Some(html) => {
                let multipart = MultiPart::alternative()
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_PLAIN)
                            .body(msg.text.clone()),
                    )
                    .singlepart(
                        SinglePart::builder()
                            .header(ContentType::TEXT_HTML)
                            .body(html.clone()),
                    );
                builder.multipart(multipart)
            }
        }
        .map_err(|e| MailerError::Build(format!("message: {e}")))?;

        self.transport
            .send(email)
            .await
            .map_err(|e| MailerError::Transport(format!("smtp: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starttls_constructor_does_not_dial() {
        // We're not connecting — just asserting the builder accepts a
        // plausible host and the helper wires credentials without panic.
        let m = LettreMailer::starttls("smtp.example.com", "u", "p").unwrap();
        let _ = m.transport();
    }

    #[test]
    fn implicit_tls_constructor_does_not_dial() {
        let m = LettreMailer::implicit_tls("smtp.example.com", "u", "p").unwrap();
        let _ = m.transport();
    }

    #[test]
    fn plaintext_constructor_does_not_dial() {
        // Nothing is listening on 1025 in CI — constructing must not try.
        let m = LettreMailer::plaintext("127.0.0.1", 1025).unwrap();
        let _ = m.transport();
    }

    #[tokio::test]
    async fn send_returns_build_error_for_invalid_mailbox() {
        let m = LettreMailer::starttls("smtp.example.com", "u", "p").unwrap();
        let bad = EmailMessage::new("not-a-mailbox", "from@x", "s", "t");
        let err = m.send(&bad).await.unwrap_err();
        assert!(matches!(err, MailerError::Build(_)));
    }
}
