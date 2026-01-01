//! Transport-agnostic mail sending.
//!
//! [`Mailer`] is the abstraction every email-shaped provider depends on
//! (today: magic-link; tomorrow: password reset, account verification, …).
//! cheers itself stays free of any SMTP transitive deps; concrete impls
//! live in their own modules behind feature flags.
//!
//! Two impls ship in this crate:
//!
//! - [`CapturingMailer`] — in-memory; collects every send for inspection.
//!   Used by the magic-link integration test (and by callers writing their
//!   own tests).
//! - [`crate::email::lettre_mailer::LettreMailer`] — gated behind the
//!   `email-lettre` feature; SMTP transport via `lettre` (rustls only).
//!
//! Callers who want a different transport (SES, Postmark, sendmail, an
//! internal RPC, …) implement [`Mailer`] directly.

use async_trait::async_trait;
use std::sync::Mutex;

/// One outbound email.
///
/// Plaintext is required (deliverability — every modern spam filter scores
/// HTML-only mail down). HTML is optional; when present, mailers send a
/// `multipart/alternative` body.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct EmailMessage {
    /// RFC 5321 mailbox or `Display Name <addr@host>`. Caller validates.
    pub to: String,
    pub from: String,
    pub reply_to: Option<String>,
    pub subject: String,
    pub text: String,
    pub html: Option<String>,
}

impl EmailMessage {
    /// Build a plaintext-only message. Use [`with_html`] to attach HTML.
    ///
    /// [`with_html`]: EmailMessage::with_html
    pub fn new(
        to: impl Into<String>,
        from: impl Into<String>,
        subject: impl Into<String>,
        text: impl Into<String>,
    ) -> Self {
        Self {
            to: to.into(),
            from: from.into(),
            reply_to: None,
            subject: subject.into(),
            text: text.into(),
            html: None,
        }
    }

    pub fn with_html(mut self, html: impl Into<String>) -> Self {
        self.html = Some(html.into());
        self
    }

    pub fn with_reply_to(mut self, reply_to: impl Into<String>) -> Self {
        self.reply_to = Some(reply_to.into());
        self
    }
}

/// Errors a mailer impl may return.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MailerError {
    /// Could not assemble the message (bad address, body encoding, …).
    /// Typically a caller bug — fix the [`EmailMessage`] before retrying.
    #[error("build: {0}")]
    Build(String),
    /// Transport-level failure (SMTP error, network error, auth refused, …).
    /// May be transient; retry policy is the caller's choice.
    #[error("transport: {0}")]
    Transport(String),
}

/// Send an [`EmailMessage`] over whatever transport this impl owns.
#[async_trait]
pub trait Mailer: Send + Sync {
    async fn send(&self, msg: &EmailMessage) -> Result<(), MailerError>;
}

/// In-memory [`Mailer`] that records every successful send.
///
/// The integration test for magic-link uses this to recover the
/// click-through URL from the rendered email body.
#[derive(Default)]
pub struct CapturingMailer {
    sent: Mutex<Vec<EmailMessage>>,
}

impl CapturingMailer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot every message captured so far (cloned).
    pub fn captured(&self) -> Vec<EmailMessage> {
        self.sent.lock().unwrap().clone()
    }

    /// Most recently captured message, if any.
    pub fn last(&self) -> Option<EmailMessage> {
        self.sent.lock().unwrap().last().cloned()
    }

    pub fn len(&self) -> usize {
        self.sent.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.sent.lock().unwrap().is_empty()
    }

    pub fn clear(&self) {
        self.sent.lock().unwrap().clear();
    }
}

#[async_trait]
impl Mailer for CapturingMailer {
    async fn send(&self, msg: &EmailMessage) -> Result<(), MailerError> {
        self.sent.lock().unwrap().push(msg.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_message_builder_sets_optional_fields() {
        let m = EmailMessage::new("to@x", "from@x", "Hi", "plain")
            .with_html("<p>html</p>")
            .with_reply_to("reply@x");
        assert_eq!(m.html.as_deref(), Some("<p>html</p>"));
        assert_eq!(m.reply_to.as_deref(), Some("reply@x"));
    }

    #[test]
    fn capturing_mailer_records_each_send() {
        pollster::block_on(async {
            let m = CapturingMailer::new();
            assert!(m.is_empty());
            let msg = EmailMessage::new("to@x", "from@x", "s", "t");
            m.send(&msg).await.unwrap();
            m.send(&msg).await.unwrap();
            assert_eq!(m.len(), 2);
            assert_eq!(m.last().unwrap(), msg);
            m.clear();
            assert!(m.is_empty());
        });
    }
}
