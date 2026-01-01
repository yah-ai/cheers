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

pub mod magic_link;
pub mod mailer;
pub mod template;

#[cfg(feature = "email-lettre")]
pub mod lettre_mailer;

#[cfg(feature = "password")]
pub mod password;

pub use mailer::{CapturingMailer, EmailMessage, Mailer, MailerError};
pub use template::MagicLinkEmail;
