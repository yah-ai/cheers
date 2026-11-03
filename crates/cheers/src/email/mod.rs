//! Email-based identity providers — magic-link (R010-T1+T2) + password (P4).
//!
//! Gated behind the `email` feature. The leaf modules are independent:
//! [`magic_link`] ships a token codec + URL builder + replay store; [`mailer`]
//! ships a transport-agnostic [`Mailer`] trait + [`CapturingMailer`];
//! [`template`] renders a [`magic_link::MagicLinkRequest`] into the
//! [`mailer::EmailMessage`] the mailer accepts. A concrete SMTP impl
//! ([`lettre_mailer::LettreMailer`]) lives behind the additional
//! `email-lettre` feature so trait-only consumers don't pay for lettre +
//! tokio + rustls.
//!
//! @yah:ticket(R961-F1, "MagicLinkProvider::request mints the code before building app_url so the app URL carries #token=<T>&code=<C> (W275 s3)")
//! @yah:status(review)
//! @yah:at(2026-10-16T23:31:17Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R961)
//! @yah:next("MagicLinkUrlBuilder::build takes only the token today, so the app URL is token-only and &code= cannot be appended by the account service. Mint the 6-digit code before building app_url and let the builder emit #token=<T>&code=<C>. Filed from noisetable R983-F3 (GAP 1); spec .yah/docs/working/W275-two-track-sign-in-email.md s3 in the noisetable repo.")
//! @yah:handoff("Landed (uncommitted, git-policy=defer). MagicLinkUrlBuilder::build(token, code: Option<&str>), a changed signature with no overload. A code always rides the fragment, whatever mode the token uses: fragment mode gives base#token=T&code=C, query mode gives base?token=T#code=C. New pub const CODE_PARAM=\"code\". MagicLinkProvider::request already minted the code before building the URLs. It now passes code.as_deref() to the app builder and None to the browser builder, so T_open's link never carries a code. Only the in-file tests called build(); noisetable's account service only constructs builders (auth.rs:518/522), so it needs no change.")
//! @yah:verify("cargo test -p cheers-providers --all-features: 190 lib passed, 0 failed (log /tmp/glim-r961-providers-a2.log). New: url_builder_puts_code_beside_token_in_fragment, url_builder_keeps_code_out_of_the_query; bound_token_redeems_only_with_matching_verifier now pins app_url == sign-in#token=<T_app>&code=<C> and a code-free browser url. template bound_request_renders_two_actions_and_the_code expects the href with & escaped as &amp;, which is correct HTML.")
//! @yah:gotcha("cheers-axum tests/magic_link_basic.rs request_grant now splits the app link on &code= and asserts that the link's code equals the mailed code line. cargo test -p cheers-axum --all-features --test main: 122/122. The only cheers-axum failure is the pre-existing discovery::tests::scopes_supported_equals_the_registry (24 vs 19), already recorded on R961/R962.")

pub mod magic_link;
pub mod mailer;
pub mod template;

#[cfg(feature = "email-lettre")]
pub mod lettre_mailer;

#[cfg(feature = "password")]
pub mod password;

pub use mailer::{CapturingMailer, EmailMessage, Mailer, MailerError};
pub use template::MagicLinkEmail;
