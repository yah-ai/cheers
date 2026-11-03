//! Render a [`MagicLinkRequest`] into the [`EmailMessage`] a [`Mailer`] sends.
//!
//! The template is intentionally minimal — caller supplies their product
//! name, sender mailbox, subject, and call-to-action copy; cheers stitches
//! those into a plaintext + HTML body with the magic-link URL embedded once
//! in each.
//!
//! # Two actions and a code (CHE-R961, noisetable W275 §7)
//!
//! A *bound* request ([`MagicLinkRequest::is_bound`]) from a provider with an
//! app URL builder renders, in order: the app action (`req.app_url`), the
//! browser action (`req.url`), then the code line. The plain-text part
//! carries each URL on its own line under its label, and the "paste this
//! URL" fallback is not rendered: with two URLs it would be two long strings,
//! and the code covers someone reading mail on another device.
//!
//! An *unbound* request renders the browser action alone, even when the
//! provider built an app URL: unbound `T_app` is a bearer token, and the app
//! track's custom-scheme step would hand it to whichever app claims the
//! scheme (W275 §4, operator form F1326).
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
//! use cheers::email::magic_link::{
//!     MagicLinkCodec, MagicLinkProvider, MagicLinkUrlBuilder, MemoryMagicLinkCodeStore,
//!     MemoryUsedJtiStore,
//! };
//! use cheers::email::{Mailer, MagicLinkEmail, CapturingMailer};
//!
//! # pollster::block_on(async {
//! let provider = MagicLinkProvider::new(
//!     MagicLinkCodec::new(&[7u8; 32], 900).unwrap(),
//!     MagicLinkUrlBuilder::new("https://app.example/auth/verify"),
//!     MemoryUsedJtiStore::new(),
//!     MemoryMagicLinkCodeStore::new(),
//! );
//! let mailer = CapturingMailer::new();
//! let template = MagicLinkEmail::new("Acme", "Acme <noreply@acme.example>");
//!
//! let req = provider.request("alice@example.com", None, 1_700_000_000).await.unwrap();
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
    app_button_label: Option<String>,
    code_intro: Option<String>,
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
            app_button_label: None,
            code_intro: None,
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

    /// Label of the app action, rendered only for a bound request.
    pub fn with_app_button_label(mut self, s: impl Into<String>) -> Self {
        self.app_button_label = Some(s.into());
        self
    }

    /// The line introducing the code: what it is for (typing into the
    /// device that asked). The code itself follows on its own line.
    pub fn with_code_intro(mut self, s: impl Into<String>) -> Self {
        self.code_intro = Some(s.into());
        self
    }

    pub fn with_fallback_intro(mut self, s: impl Into<String>) -> Self {
        self.fallback_intro = Some(s.into());
        self
    }

    /// Drop the "paste this URL" paragraph from single-action mail too.
    /// `with_fallback_intro("")` is equivalent.
    pub fn without_fallback(mut self) -> Self {
        self.fallback_intro = Some(String::new());
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
    /// URLs are embedded verbatim in the plaintext body; they are URL-safe
    /// by construction (PASETO v4 alphabet) so no escaping is needed there.
    /// The HTML body escapes them into each `href` for defense in depth.
    /// See the module docs for when the app action and code line appear.
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
        let app_button_owned = self
            .app_button_label
            .clone()
            .unwrap_or_else(|| format!("Open {}", self.product_name));
        let code_intro = self
            .code_intro
            .as_deref()
            .unwrap_or("Or enter this code on the device that asked:");
        let fallback = self
            .fallback_intro
            .as_deref()
            .unwrap_or("If the button doesn't work, paste this URL into your browser:");
        let expiry = self.expiry_notice.as_deref().unwrap_or(
            "This link can be used once and expires soon. If you didn't request it, ignore this email.",
        );
        let footer_line = self.footer.as_deref();

        // (label, url) in render order.
        let mut actions: Vec<(&str, &str)> = Vec::with_capacity(2);
        if let (true, Some(app_url)) = (req.is_bound(), req.app_url.as_deref()) {
            actions.push((&app_button_owned, app_url));
        }
        actions.push((button, &req.url));
        let two_actions = actions.len() == 2;
        let code = req.code.as_deref();

        let mut text = String::new();
        if !greeting.is_empty() {
            text.push_str(greeting);
            text.push_str("\n\n");
        }
        text.push_str(&intro_owned);
        text.push_str("\n\n");
        if two_actions {
            for (label, url) in &actions {
                text.push_str(label);
                text.push_str(":\n");
                text.push_str(url);
                text.push_str("\n\n");
            }
        } else {
            text.push_str(&req.url);
            text.push_str("\n\n");
        }
        if let Some(c) = code {
            text.push_str(code_intro);
            text.push_str("\n\n");
            text.push_str(c);
            text.push_str("\n\n");
        }
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
        html.push_str("</p>");
        for (label, url) in &actions {
            html.push_str("<p><a href=\"");
            html.push_str(&escape_html_attr(url));
            html.push_str("\" style=\"display:inline-block;padding:10px 18px;background:#111;color:#fff;text-decoration:none;border-radius:6px\">");
            html.push_str(&escape_html(label));
            html.push_str("</a></p>");
        }
        if let Some(c) = code {
            html.push_str("<p>");
            html.push_str(&escape_html(code_intro));
            html.push_str("</p><p style=\"font-size:1.5em;letter-spacing:0.2em\"><strong>");
            html.push_str(&escape_html(c));
            html.push_str("</strong></p>");
        }
        if !two_actions && !fallback.is_empty() {
            html.push_str("<p>");
            html.push_str(&escape_html(fallback));
            html.push_str("</p><p style=\"word-break:break-all\"><code>");
            html.push_str(&escape_html(&req.url));
            html.push_str("</code></p>");
        }
        html.push_str("<p style=\"color:#666;font-size:0.875em\">");
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
        MagicLinkCodec, MagicLinkProvider, MagicLinkRedemption, MagicLinkUrlBuilder,
        MemoryMagicLinkCodeStore, MemoryUsedJtiStore, s256,
    };
    use crate::email::mailer::{CapturingMailer, Mailer};

    fn provider() -> MagicLinkProvider<MemoryUsedJtiStore, MemoryMagicLinkCodeStore> {
        MagicLinkProvider::new(
            MagicLinkCodec::new(&[5u8; 32], 900).unwrap(),
            MagicLinkUrlBuilder::new("https://app.example/auth/verify"),
            MemoryUsedJtiStore::new(),
            MemoryMagicLinkCodeStore::new(),
        )
        .with_app_urls(MagicLinkUrlBuilder::new("https://link.app.example/sign-in").in_fragment())
    }

    #[test]
    fn default_render_embeds_url_in_both_bodies() {
        pollster::block_on(async {
            let p = provider();
            let req = p.request("alice@example.com", None, 1_000).await.unwrap();
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
            let req = p.request("a@b.co", None, 1_000).await.unwrap();
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
            let req = p.request("a@b.co", None, 1_000).await.unwrap();
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
            let req = p.request("a@b.co", None, 1_000).await.unwrap();
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

    #[test]
    fn bound_request_renders_two_actions_and_the_code() {
        pollster::block_on(async {
            let p = provider();
            let ch = s256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
            let req = p.request("a@b.co", Some(&ch), 1_000).await.unwrap();
            let app_url = req.app_url.clone().unwrap();
            let code = req.code.clone().unwrap();
            let msg = MagicLinkEmail::new("Acme", "n@a.co")
                .with_app_button_label("Open the app")
                .with_button_label("Sign in here")
                .with_code_intro("Type this into the app:")
                .render("a@b.co", &req);

            // Plain text: each URL on its own line under its label, app first.
            let app_at = msg.text.find(&format!("Open the app:\n{app_url}\n")).unwrap();
            let web_at = msg.text.find(&format!("Sign in here:\n{}\n", req.url)).unwrap();
            assert!(app_at < web_at);
            assert!(msg.text.contains(&format!("Type this into the app:\n\n{code}\n")));
            assert!(!msg.text.contains("paste this URL"));

            let html = msg.html.unwrap();
            assert_eq!(html.matches("<a href=").count(), 2);
            // The app URL is `#token=<T>&code=<C>`; the attribute escapes `&`.
            assert!(app_url.ends_with(&format!("&code={code}")));
            let app_href = html
                .find(&format!("<a href=\"{}\"", app_url.replace('&', "&amp;")))
                .unwrap();
            let web_href = html.find(&format!("<a href=\"{}\"", req.url)).unwrap();
            assert!(app_href < web_href);
            assert!(html.contains(&format!("<strong>{code}</strong>")));
            assert!(!html.contains("<code>"));
        });
    }

    #[test]
    fn unbound_request_renders_one_action_and_no_code() {
        pollster::block_on(async {
            let p = provider();
            let req = p.request("a@b.co", None, 1_000).await.unwrap();
            assert!(req.app_url.is_some(), "the provider still builds T_app's URL");
            let msg = MagicLinkEmail::new("Acme", "n@a.co")
                .with_code_intro("Type this into the app:")
                .render("a@b.co", &req);
            assert!(!msg.text.contains(req.app_url.as_deref().unwrap()));
            assert!(!msg.text.contains("Type this into the app:"));
            let html = msg.html.unwrap();
            assert_eq!(html.matches("<a href=").count(), 1);
            assert!(!html.contains("<strong>"));
        });
    }

    #[test]
    fn without_fallback_drops_the_paste_line() {
        pollster::block_on(async {
            let p = provider();
            let req = p.request("a@b.co", None, 1_000).await.unwrap();
            let html = MagicLinkEmail::new("Acme", "n@a.co")
                .without_fallback()
                .render("a@b.co", &req)
                .html
                .unwrap();
            assert!(!html.contains("<code>"));
            assert!(html.contains(&req.url));
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

            let req = p.request("alice@example.com", None, 1_700_000_000).await.unwrap();
            let msg = template.render("alice@example.com", &req);
            mailer.send(&msg).await.unwrap();

            // Recover the URL the user would click.
            let captured = mailer.last().unwrap();
            assert!(captured.text.contains(&req.url));

            // The captured URL still verifies + consumes through the same provider.
            let open = MagicLinkRedemption::Token {
                token: &req.token,
                verifier: None,
            };
            let claims = p.redeem(open, 1_700_000_030).await.unwrap();
            assert_eq!(claims.email, "alice@example.com");
        });
    }
}
