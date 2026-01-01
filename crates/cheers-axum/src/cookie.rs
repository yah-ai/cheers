//! CSRF cookie configuration + tiny header-level cookie helpers.
//!
//! The handlers don't reach for the `cookie` crate — the slice of cookie
//! handling we need (Set-Cookie + parsing one named value out of `Cookie:`)
//! is small enough that pulling in a parser/serializer would be overkill.

use std::fmt::Write as _;

/// Where + how to set the CSRF binding cookie.
///
/// The `csrf` cookie carries the same secret as the OIDC `?state=` parameter
/// the IdP echoes back; the callback handler refuses a request whose cookie
/// doesn't match. See the module docs on [`crate`] for why this binding
/// matters.
///
/// Defaults are conservative — `HttpOnly`, `Secure`, `SameSite=Lax`, path=`/`,
/// no `Domain` (so the cookie is host-only). Override per provider; Apple
/// needs `SameSite=None` because its callback is a cross-site POST.
#[derive(Debug, Clone)]
pub struct CsrfCookieConfig {
    /// Cookie name. Provider-specific by convention (e.g. `cheers_csrf_google`).
    pub name: String,
    /// `Path=` attribute. Default `/`.
    pub path: String,
    /// `Domain=` attribute, or `None` for host-only.
    pub domain: Option<String>,
    /// `SameSite=` attribute.
    pub same_site: SameSite,
    /// Whether to set the `Secure` flag. Set `false` only in dev/test (cookie
    /// is then sent over plain HTTP). Default `true`.
    pub secure: bool,
    /// `HttpOnly` flag. Always `true` in defaults — JS doesn't need to read
    /// this value.
    pub http_only: bool,
    /// `Max-Age` in seconds. Default 600 (10 minutes) — long enough to cover
    /// IdP login UI latency, short enough that an abandoned flow's cookie
    /// expires.
    pub max_age_seconds: i64,
}

/// `SameSite` cookie attribute values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SameSite {
    Strict,
    Lax,
    /// `SameSite=None`. The cookie is sent on cross-site requests. Browsers
    /// require `Secure` to also be set when `SameSite=None`; the handlers do
    /// NOT enforce that here so a localhost dev can override `secure=false`.
    None,
}

impl SameSite {
    fn as_str(self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

impl CsrfCookieConfig {
    /// Conservative defaults for a server-redirect OIDC flow (Google, generic
    /// OIDC).
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            path: "/".into(),
            domain: None,
            same_site: SameSite::Lax,
            secure: true,
            http_only: true,
            max_age_seconds: 600,
        }
    }

    /// Defaults tuned for Apple Sign-In's cross-site form-post callback —
    /// `SameSite=None` (the only value browsers send on a cross-site POST).
    /// `Secure` is forced on; localhost dev needs `with_secure(false)` to
    /// drop it.
    pub fn for_apple(name: impl Into<String>) -> Self {
        Self {
            same_site: SameSite::None,
            ..Self::new(name)
        }
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = path.into();
        self
    }

    pub fn with_domain(mut self, domain: impl Into<String>) -> Self {
        self.domain = Some(domain.into());
        self
    }

    pub fn with_same_site(mut self, ss: SameSite) -> Self {
        self.same_site = ss;
        self
    }

    pub fn with_secure(mut self, secure: bool) -> Self {
        self.secure = secure;
        self
    }

    pub fn with_max_age_seconds(mut self, seconds: i64) -> Self {
        self.max_age_seconds = seconds;
        self
    }

    /// Build a `Set-Cookie` header value carrying `value` for this config.
    /// Used by `login` handlers.
    pub fn set_cookie(&self, value: &str) -> String {
        let mut s = String::with_capacity(128);
        write!(&mut s, "{}={}; Path={}", self.name, value, self.path).unwrap();
        if let Some(d) = &self.domain {
            write!(&mut s, "; Domain={d}").unwrap();
        }
        write!(&mut s, "; Max-Age={}", self.max_age_seconds).unwrap();
        write!(&mut s, "; SameSite={}", self.same_site.as_str()).unwrap();
        if self.http_only {
            s.push_str("; HttpOnly");
        }
        if self.secure {
            s.push_str("; Secure");
        }
        s
    }

    /// Build a `Set-Cookie` header value that clears this cookie — emitted by
    /// `callback` handlers after successfully consuming the flow.
    pub fn clear_cookie(&self) -> String {
        let mut s = String::with_capacity(128);
        write!(&mut s, "{}=; Path={}", self.name, self.path).unwrap();
        if let Some(d) = &self.domain {
            write!(&mut s, "; Domain={d}").unwrap();
        }
        s.push_str("; Max-Age=0");
        write!(&mut s, "; SameSite={}", self.same_site.as_str()).unwrap();
        if self.http_only {
            s.push_str("; HttpOnly");
        }
        if self.secure {
            s.push_str("; Secure");
        }
        s
    }
}

/// Extract one named cookie's value from a `Cookie:` header string.
///
/// Returns the first matching value; `None` if the header has no entry for
/// `name`. Doesn't decode percent-escapes — cookie *values* are opaque, and
/// the CSRF value we set is a base64url-safe secret.
pub fn read_cookie<'a>(header_value: &'a str, name: &str) -> Option<&'a str> {
    for raw in header_value.split(';') {
        let raw = raw.trim();
        let Some((k, v)) = raw.split_once('=') else {
            continue;
        };
        if k == name {
            return Some(v);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_cookie_defaults() {
        let cfg = CsrfCookieConfig::new("x");
        let out = cfg.set_cookie("abc");
        assert!(out.contains("x=abc"));
        assert!(out.contains("Path=/"));
        assert!(out.contains("Max-Age=600"));
        assert!(out.contains("SameSite=Lax"));
        assert!(out.contains("HttpOnly"));
        assert!(out.contains("Secure"));
        assert!(!out.contains("Domain="));
    }

    #[test]
    fn set_cookie_apple_defaults_to_samesite_none() {
        let cfg = CsrfCookieConfig::for_apple("ap");
        let out = cfg.set_cookie("xyz");
        assert!(out.contains("SameSite=None"));
        assert!(out.contains("Secure"));
    }

    #[test]
    fn set_cookie_can_drop_secure_and_set_domain() {
        let cfg = CsrfCookieConfig::new("y")
            .with_secure(false)
            .with_domain("example.com")
            .with_max_age_seconds(60);
        let out = cfg.set_cookie("v");
        assert!(!out.contains("Secure"));
        assert!(out.contains("Domain=example.com"));
        assert!(out.contains("Max-Age=60"));
    }

    #[test]
    fn clear_cookie_zero_max_age() {
        let cfg = CsrfCookieConfig::new("z");
        let out = cfg.clear_cookie();
        assert!(out.contains("z="));
        assert!(out.contains("Max-Age=0"));
    }

    #[test]
    fn read_cookie_picks_named_value() {
        let h = "foo=bar; cheers_csrf_google=ABC123; baz=qux";
        assert_eq!(read_cookie(h, "cheers_csrf_google"), Some("ABC123"));
        assert_eq!(read_cookie(h, "foo"), Some("bar"));
        assert_eq!(read_cookie(h, "missing"), None);
    }

    #[test]
    fn read_cookie_tolerates_whitespace() {
        let h = "  a=1 ;   b=2";
        assert_eq!(read_cookie(h, "a"), Some("1"));
        assert_eq!(read_cookie(h, "b"), Some("2"));
    }

    #[test]
    fn read_cookie_empty_header_returns_none() {
        assert_eq!(read_cookie("", "a"), None);
    }
}
