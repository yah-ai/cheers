//! Render a [`MagicLinkRequest`] into the [`EmailMessage`] a [`Mailer`] sends.
//!
//! The template is intentionally minimal — caller supplies their product
//! name, sender mailbox, subject, and call-to-action copy; cheers stitches
//! those into a plaintext + HTML body with the magic-link URL embedded once
//! in each.
//!
//! # Why this is a struct, not a trait
//!
//! Most callers want the same shape with their own copy. A trait would push
//! every consumer to write boilerplate. The struct is final-stage data, so
//! callers who want a fully custom layout build [`EmailMessage`] themselves
//! and skip [`MagicLinkEmail`] entirely.
//!
//! # Example
//!
//! ```
//! use cheers::email::magic_link::{MagicLinkCodec, MagicLinkProvider, MagicLinkUrlBuilder, MemoryUsedJtiStore};
//! use cheers::email::{Mailer, MagicLinkEmail, CapturingMailer};
//!
//! # pollster::block_on(async {
//! let provider = MagicLinkProvider::new(
//!     MagicLinkCodec::new(&[7u8; 32], 900).unwrap(),
//!     MagicLinkUrlBuilder::new("https://app.example/auth/verify"),
//!     MemoryUsedJtiStore::new(),
//! );
//! let mailer = CapturingMailer::new();
//! let template = MagicLinkEmail::new("Acme", "Acme <noreply@acme.example>");
//!
//! let req = provider.request("alice@example.com", 1_700_000_000).await.unwrap();
//! let msg = template.render("alice@example.com", &req);
//! mailer.send(&msg).await.unwrap();
//!
//! let captured = mailer.last().unwrap();
//! assert!(captured.text.contains(&req.url));
//! assert!(captured.html.unwrap().contains(&req.url));
//! # });
//! ```
//!
//! @yah:relay(R733, "MagicLinkEmail: let a product supply the opening line and drop the greeting paragraph")
//! @yah:status(review)
//! @yah:at(2026-10-07T06:59:06Z)
//! @yah:assignee(bundle-anthropic-ashguard)
//! @yah:next("render() always writes the greeting paragraph first, defaulting to \"Hi,\". A product that wants the first line of the email to state the fact has nowhere to put it except the greeting slot, and with_greeting(\"\") leaves an empty first line and an empty <p>. Add an explicit seam (e.g. Option-typed greeting that renders nothing when cleared, or a with_opening(line) that replaces greeting+intro) so callers own the opening line. Keep render() as the single renderer; no pre-rendered bodies. Consumer: noisetable web/services/account/src/mailer.rs::magic_link_email (noisetable R801-F6), which currently puts its fact line in the greeting slot.")
//! @yah:handoff("Added MagicLinkEmail::without_greeting(); an empty greeting (also with_greeting(\"\")) now renders no greeting paragraph in text or HTML, so with_intro(line) becomes the opening line. render() stays the single renderer. Simplified intro defaulting. Test: without_greeting_makes_intro_the_opening_line.")
//! @yah:verify("cargo test --manifest-path oss/cheers/crates/cheers/Cargo.toml --lib email::template — 5 passed")
//! @yah:cleanup("noisetable R801-F6: switch mailer.rs::magic_link_email to .without_greeting().with_intro(fact_line)")

use crate::email::magic_link::MagicLinkRequest;
use crate::email::mailer::EmailMessage;

/// Builder + renderer for the magic-link email body.
///
/// Construct with [`new`], override copy with the `with_*` setters, then
/// call [`render`] for each recipient.
///
/// [`new`]: MagicLinkEmail::new
/// [`render`]: MagicLinkEmail::render
#[derive(Debug, Clone)]
pub struct MagicLinkEmail {
    product_name: String,
    from: String,
    subject: Option<String>,
    greeting: Option<String>,
    intro: Option<String>,
    button_label: Option<String>,
    fallback_intro: Option<String>,
    expiry_notice: Option<String>,
    footer: Option<String>,
}

impl MagicLinkEmail {
    /// Required: caller's product name (used in default subject + body) and
    /// the From mailbox lettre/SMTP will sign as.
    pub fn new(product_name: impl Into<String>, from: impl Into<String>) -> Self {
        Self {
            product_name: product_name.into(),
            from: from.into(),
            subject: None,
            greeting: None,
            intro: None,
            button_label: None,
            fallback_intro: None,
            expiry_notice: None,
            footer: None,
        }
    }

    pub fn with_subject(mut self, s: impl Into<String>) -> Self {
        self.subject = Some(s.into());
        self
    }

    pub fn with_greeting(mut self, s: impl Into<String>) -> Self {
        self.greeting = Some(s.into());
        self
    }

    /// Drop the greeting paragraph entirely, so the intro (see
    /// [`with_intro`](Self::with_intro)) is the email's opening line.
    /// `with_greeting("")` is equivalent: an empty greeting renders nothing.
    pub fn without_greeting(mut self) -> Self {
        self.greeting = Some(String::new());
        self
    }

    pub fn with_intro(mut self, s: impl Into<String>) -> Self {
        self.intro = Some(s.into());
        self
    }

    pub fn with_button_label(mut self, s: impl Into<String>) -> Self {
        self.button_label = Some(s.into());
        self
    }

    pub fn with_fallback_intro(mut self, s: impl Into<String>) -> Self {
        self.fallback_intro = Some(s.into());
        self
    }

    pub fn with_expiry_notice(mut self, s: impl Into<String>) -> Self {
        self.expiry_notice = Some(s.into());
        self
    }

    pub fn with_footer(mut self, s: impl Into<String>) -> Self {
        self.footer = Some(s.into());
        self
    }

    /// Render to an [`EmailMessage`] addressed to `to`.
    ///
    /// `req.url` is embedded verbatim in both bodies; the URL is URL-safe
    /// by construction (PASETO v4 alphabet) so no escaping is needed in
    /// the plaintext copy. The HTML body escapes the URL into the `href`
    /// for defense in depth.
    pub fn render(&self, to: impl Into<String>, req: &MagicLinkRequest) -> EmailMessage {
        let subject = self
            .subject
            .clone()
            .unwrap_or_else(|| format!("Sign in to {}", self.product_name));
        let greeting = self.greeting.as_deref().unwrap_or("Hi,");
        let intro_owned = match self.intro.as_deref() {
            Some(i) if !i.is_empty() => i.to_owned(),
            _ => format!("Click the link below to sign in to {}.", self.product_name),
        };
        let button = self.button_label.as_deref().unwrap_or("Sign in");
        let fallback = self
            .fallback_intro
            .as_deref()
            .unwrap_or("If the button doesn't work, paste this URL into your browser:");
        let expiry = self.expiry_notice.as_deref().unwrap_or(
            "This link can be used once and expires soon. If you didn't request it, ignore this email.",
        );
        let footer_line = self.footer.as_deref();

        let mut text = String::new();
        if !greeting.is_empty() {
            text.push_str(greeting);
            text.push_str("\n\n");
        }
        text.push_str(&intro_owned);
        text.push_str("\n\n");
        text.push_str(&req.url);
        text.push_str("\n\n");
        text.push_str(expiry);
        if let Some(f) = footer_line {
            text.push_str("\n\n");
            text.push_str(f);
        }
        text.push('\n');

        let mut html = String::new();
        html.push_str("<!doctype html><html><body style=\"font-family:system-ui,sans-serif;line-height:1.5\">");
        if !greeting.is_empty() {
            html.push_str("<p>");
            html.push_str(&escape_html(greeting));
            html.push_str("</p>");
        }
        html.push_str("<p>");
        html.push_str(&escape_html(&intro_owned));
        html.push_str("</p><p><a href=\"");
        html.push_str(&escape_html_attr(&req.url));
        html.push_str("\" style=\"display:inline-block;padding:10px 18px;background:#111;color:#fff;text-decoration:none;border-radius:6px\">");
        html.push_str(&escape_html(button));
        html.push_str("</a></p><p>");
        html.push_str(&escape_html(fallback));
        html.push_str("</p><p style=\"word-break:break-all\"><code>");
        html.push_str(&escape_html(&req.url));
        html.push_str("</code></p><p style=\"color:#666;font-size:0.875em\">");
        html.push_str(&escape_html(expiry));
        html.push_str("</p>");
        if let Some(f) = footer_line {
            html.push_str("<p style=\"color:#666;font-size:0.875em\">");
            html.push_str(&escape_html(f));
            html.push_str("</p>");
        }
        html.push_str("</body></html>");

        EmailMessage::new(to, &self.from, subject, text).with_html(html)
    }

    pub fn from(&self) -> &str {
        &self.from
    }

    pub fn product_name(&self) -> &str {
        &self.product_name
    }
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(ch),
        }
    }
    out
}

fn escape_html_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::email::magic_link::{
        MagicLinkCodec, MagicLinkProvider, MagicLinkUrlBuilder, MemoryUsedJtiStore,
    };
    use crate::email::mailer::{CapturingMailer, Mailer};

    fn provider() -> MagicLinkProvider<MemoryUsedJtiStore> {
        MagicLinkProvider::new(
            MagicLinkCodec::new(&[5u8; 32], 900).unwrap(),
            MagicLinkUrlBuilder::new("https://app.example/auth/verify"),
            MemoryUsedJtiStore::new(),
        )
    }

    #[test]
    fn default_render_embeds_url_in_both_bodies() {
        pollster::block_on(async {
            let p = provider();
            let req = p.request("alice@example.com", 1_000).await.unwrap();
            let t = MagicLinkEmail::new("Acme", "Acme <noreply@acme.example>");
            let msg = t.render("alice@example.com", &req);
            assert!(msg.text.contains(&req.url));
            assert!(msg.html.as_ref().unwrap().contains(&req.url));
            assert_eq!(msg.subject, "Sign in to Acme");
            assert_eq!(msg.from, "Acme <noreply@acme.example>");
            assert_eq!(msg.to, "alice@example.com");
        });
    }

    #[test]
    fn custom_copy_overrides_defaults() {
        pollster::block_on(async {
            let p = provider();
            let req = p.request("a@b.co", 1_000).await.unwrap();
            let t = MagicLinkEmail::new("Acme", "n@a.co")
                .with_subject("Your link")
                .with_greeting("Hello friend,")
                .with_intro("Tap below.")
                .with_button_label("Open Acme")
                .with_fallback_intro("Or copy:")
                .with_expiry_notice("Expires in 15 minutes.")
                .with_footer("Acme Inc.");
            let msg = t.render("a@b.co", &req);
            assert_eq!(msg.subject, "Your link");
            assert!(msg.text.contains("Hello friend,"));
            assert!(msg.text.contains("Tap below."));
            assert!(msg.text.contains("Expires in 15 minutes."));
            assert!(msg.text.contains("Acme Inc."));
            let html = msg.html.unwrap();
            assert!(html.contains("Open Acme"));
            assert!(html.contains("Acme Inc."));
        });
    }

    #[test]
    fn html_escapes_user_facing_copy() {
        pollster::block_on(async {
            let p = provider();
            let req = p.request("a@b.co", 1_000).await.unwrap();
            let t = MagicLinkEmail::new("Ac<me>", "n@a.co").with_intro("a & b < c");
            let msg = t.render("a@b.co", &req);
            let html = msg.html.unwrap();
            assert!(html.contains("a &amp; b &lt; c"));
            // product_name only flows into subject (plaintext), not html greeting.
            assert!(msg.subject.contains("Ac<me>"));
        });
    }

    #[test]
    fn without_greeting_makes_intro_the_opening_line() {
        pollster::block_on(async {
            let p = provider();
            let req = p.request("a@b.co", 1_000).await.unwrap();
            for t in [
                MagicLinkEmail::new("Acme", "n@a.co").without_greeting(),
                MagicLinkEmail::new("Acme", "n@a.co").with_greeting(""),
            ] {
                let msg = t.with_intro("Your sign-in link.").render("a@b.co", &req);
                assert!(msg.text.starts_with("Your sign-in link.\n\n"));
                let html = msg.html.unwrap();
                assert!(!html.contains("<p></p>"));
                assert!(html.contains("\"><p>Your sign-in link.</p>"));
            }
        });
    }

    /// Plan §P3 deliverable: integration test using a mock Mailer capturing
    /// the URL. Wires the full provider + template + capturing-mailer chain.
    #[test]
    fn integration_provider_template_capturing_mailer() {
        pollster::block_on(async {
            let p = provider();
            let mailer = CapturingMailer::new();
            let template = MagicLinkEmail::new("Acme", "Acme <noreply@acme.example>");

            let req = p.request("alice@example.com", 1_700_000_000).await.unwrap();
            let msg = template.render("alice@example.com", &req);
            mailer.send(&msg).await.unwrap();

            // Recover the URL the user would click.
            let captured = mailer.last().unwrap();
            assert!(captured.text.contains(&req.url));

            // The captured URL still verifies + consumes through the same provider.
            let claims = p.consume(&req.token, 1_700_000_030).await.unwrap();
            assert_eq!(claims.email, "alice@example.com");
        });
    }
}
