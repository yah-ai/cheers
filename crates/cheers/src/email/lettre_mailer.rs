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
//! For more exotic configurations (custom port, no auth, implicit TLS,
//! pooled connections, …), build the underlying
//! [`AsyncSmtpTransport`] directly and wrap it with [`LettreMailer::from_transport`].

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

    #[tokio::test]
    async fn send_returns_build_error_for_invalid_mailbox() {
        let m = LettreMailer::starttls("smtp.example.com", "u", "p").unwrap();
        let bad = EmailMessage::new("not-a-mailbox", "from@x", "s", "t");
        let err = m.send(&bad).await.unwrap_err();
        assert!(matches!(err, MailerError::Build(_)));
    }
}
