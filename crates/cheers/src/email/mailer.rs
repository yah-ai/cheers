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
//!
//! @yah:ticket(R961-F2, "EmailMessage grows a headers field that LettreMailer sends, so callers can set X-Mailgun-Track-Clicks: no (W275 s7)")
//! @yah:status(review)
//! @yah:at(2026-10-16T23:31:25Z)
//! @yah:assignee(agent:bundle-anthropic-glimmerstone)
//! @yah:parent(R961)
//! @yah:next("EmailMessage has to/from/reply_to/subject/text/html and no headers; LettreMailer sets none. Add a headers field and have LettreMailer emit it so the account service can attach X-Mailgun-Track-Clicks: no per message. Filed from noisetable R983-F3 (GAP 2); spec W275 s7 in the noisetable repo.")
//! @yah:handoff("Landed (uncommitted, git-policy=defer). EmailMessage gains pub headers: Vec<(String,String)> (ordered) plus with_header(name, value); new() starts it empty. EmailMessage is #[non_exhaustive], so no external struct literal breaks. LettreMailer::send now calls a free build_message(msg) that adds each header through MessageBuilder::raw_header(HeaderValue::new(..)). Three kinds of entry are refused with MailerError::Build. (a) Names the message already owns: from, to, cc, bcc, reply-to, subject, content-type, content-transfer-encoding, mime-version, matched case-insensitively. lettre's insert_raw replaces a same-named field, so letting one through would silently override a checked value. (b) Values containing CR or LF, which would allow header injection. (c) Names lettre rejects (spaces, colon, longer than 76 characters). Caller usage: MagicLinkEmail::render(..).with_header(\"X-Mailgun-Track-Clicks\", \"no\").")
//! @yah:verify("cargo test -p cheers-providers --all-features: 190 lib passed (log /tmp/glim-r961-providers-a2.log). New: lettre_mailer extra_headers_reach_the_wire (header present in Message::formatted() for both plain and multipart), extra_headers_cannot_override_modelled_fields, extra_headers_refuse_bad_names_and_line_breaks (CRLF/LF Bcc-injection attempts refused); mailer email_message_builder_sets_optional_fields asserts header order.")
//! @yah:gotcha("noisetable web/services/account/src/mailer.rs has its own Mailer impl (a file-dropping dev mailer, deliver() near line 214). It ignores EmailMessage.headers unless it is taught to write them out. That is harmless for Mailgun, which only reads the header over SMTP via LettreMailer.")

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
    /// Extra header fields, sent in order — e.g. a provider directive such as
    /// `X-Mailgun-Track-Clicks: no`, which keeps a relay from rewriting the
    /// links a magic-link email carries (W275 §7). Fields this struct already
    /// models (`From`, `Subject`, …) are not settable here; mailers refuse them.
    pub headers: Vec<(String, String)>,
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
            headers: Vec::new(),
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

    /// Append one header field. See [`EmailMessage::headers`].
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
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
            .with_reply_to("reply@x")
            .with_header("X-Mailgun-Track-Clicks", "no")
            .with_header("X-Mailgun-Track-Opens", "no");
        assert_eq!(m.html.as_deref(), Some("<p>html</p>"));
        assert_eq!(m.reply_to.as_deref(), Some("reply@x"));
        assert_eq!(
            m.headers,
            [
                ("X-Mailgun-Track-Clicks".to_owned(), "no".to_owned()),
                ("X-Mailgun-Track-Opens".to_owned(), "no".to_owned()),
            ]
        );
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
