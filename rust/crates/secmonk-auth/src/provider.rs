//! Authentication strategies (rust ADR-0014 §"Auth providers").
//!
//! An [`AuthProvider`] is one way to prove who a caller is: the API keys of `api_keys.toml` today; an OIDC
//! identity provider, a TLS client certificate (mTLS between nodes) or a reverse-proxy header later. The
//! [`crate::Authenticator`] holds an ordered chain of providers and is the only thing the HTTP layer talks to:
//!
//! - **direct requests**: each provider looks at the [`RequestContext`] (the `Authorization` header, a TLS peer
//!   certificate) and answers `None` ("not mine"), or `Some(Ok(principal))` / `Some(Err(_))` ("mine, and this is
//!   the verdict"). The first provider that answers `Some` decides; a `Bearer` session token issued by this
//!   server (a JWT whose `iss` is `secmonk`) is handled by the authenticator itself before the chain, every other
//!   `Bearer` token (an OIDC access token) goes through the chain.
//! - **logins** (`POST /auth/token`): `{"method": "<name>", ...params}`; the provider whose
//!   [`AuthProvider::login_methods`] lists the method verifies the params and returns a principal, for which the
//!   authenticator issues a session JWT carrying the provider's name (`prv` claim).
//! - **session revalidation**: a session JWT is accepted only while [`AuthProvider::revalidate`] of its issuing
//!   provider still accepts the subject (a revoked API key also kills its JWTs); the session's scopes are those of
//!   the token that the subject still has.
//!
//! Adding a strategy = implementing this trait and registering it in the chain (`Authenticator::with_providers`);
//! the HTTP layer, the session tokens, scopes, rate limits and audit stay unchanged.

use std::time::SystemTime;

use serde_json::Value;

use crate::keys::Principal;
use crate::scope::Scopes;
use crate::{AuthError, Result};

/// Read access to the request headers, without a dependency on an HTTP crate. Names are matched
/// case-insensitively; a header sent several times answers its first value (or `None`, the implementor's choice).
pub trait HeaderLookup {
    /// The value of header `name`, if present and valid text.
    fn header(&self, name: &str) -> Option<&str>;
}

/// `(name, value)` pairs (tests, simple callers): pass `&pairs` where `pairs: &[(&str, &str)]`.
impl HeaderLookup for &[(&str, &str)] {
    fn header(&self, name: &str) -> Option<&str> {
        self.iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    }
}

/// What a provider may look at to authenticate one request. Borrowed from the HTTP layer; new fields are added
/// as new strategies need them (the struct is `non_exhaustive`: build it with [`RequestContext::new`] and the
/// `with_*` methods).
#[derive(Clone, Copy, Default)]
#[non_exhaustive]
pub struct RequestContext<'a> {
    /// The raw `Authorization` header value.
    pub authorization: Option<&'a str>,
    /// The client address (logs, throttles): the peer, or the forwarded client behind a trusted proxy.
    pub client: Option<&'a str>,
    /// SHA-256 (hex) of the TLS client certificate, when the connection presented one (future mTLS provider).
    pub peer_cert_sha256: Option<&'a str>,
    /// The request method (`GET`, `POST`).
    pub method: Option<&'a str>,
    /// The request path, without the query.
    pub path: Option<&'a str>,
    /// Every request header (a reverse-proxy or OIDC provider reads its own).
    pub headers: Option<&'a dyn HeaderLookup>,
}

impl std::fmt::Debug for RequestContext<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // never the credential
        f.debug_struct("RequestContext")
            .field("authorization", &self.authorization.map(|_| "<redacted>"))
            .field("client", &self.client)
            .field("peer_cert_sha256", &self.peer_cert_sha256)
            .field("method", &self.method)
            .field("path", &self.path)
            .field("headers", &self.headers.is_some())
            .finish()
    }
}

impl<'a> RequestContext<'a> {
    /// A context with an `Authorization` header value and a client address.
    pub fn new(authorization: Option<&'a str>, client: Option<&'a str>) -> Self {
        RequestContext {
            authorization,
            client,
            ..RequestContext::default()
        }
    }

    /// The same context with a TLS peer certificate fingerprint.
    pub fn with_peer_cert(mut self, sha256_hex: Option<&'a str>) -> Self {
        self.peer_cert_sha256 = sha256_hex;
        self
    }

    /// The same context with the request method and path (audit logs, providers that care).
    pub fn with_request(mut self, method: &'a str, path: &'a str) -> Self {
        self.method = Some(method);
        self.path = Some(path);
        self
    }

    /// The same context with access to every request header.
    pub fn with_headers(mut self, headers: &'a dyn HeaderLookup) -> Self {
        self.headers = Some(headers);
        self
    }

    /// One request header (`None` without header access or when absent).
    pub fn header(&self, name: &str) -> Option<&'a str> {
        self.headers?.header(name)
    }

    /// `(scheme, credential)` of the `Authorization` header: scheme as written, credential trimmed. `None` when
    /// there is no header; `Err` when it is not `<scheme> <credential>`.
    pub fn authorization_parts(&self) -> Option<Result<(&'a str, &'a str)>> {
        let header = self.authorization?.trim();
        Some(match header.split_once(' ') {
            Some((s, c)) if !c.trim().is_empty() && !c.trim().contains(' ') => Ok((s, c.trim())),
            _ => Err(AuthError::Malformed("bad Authorization header".into())),
        })
    }
}

/// What [`AuthProvider::revalidate`] knows about a subject now: its display name and its current scopes. A
/// session keeps only the scopes its token carries **and** the subject still has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// Current display name.
    pub name: String,
    /// Current scopes.
    pub scopes: Scopes,
}

/// One authentication strategy. Implementations must be cheap to call per request and must never log secrets.
pub trait AuthProvider: Send + Sync + std::fmt::Debug {
    /// Stable name: the `prv` claim of the session tokens it backs, the `method` of its logins, logs.
    fn name(&self) -> &str;

    /// Login methods this provider accepts at `POST /auth/token` (e.g. `["api_key"]`).
    fn login_methods(&self) -> &[&str] {
        &[]
    }

    /// Authenticate a request directly (without a session token). `None`: not this provider's credential.
    fn authenticate(&self, ctx: &RequestContext<'_>, now: SystemTime) -> Option<Result<Principal>> {
        let _ = (ctx, now);
        None
    }

    /// Verify a login (`method` is one of [`AuthProvider::login_methods`], `params` the JSON body).
    fn login(&self, method: &str, params: &Value, now: SystemTime) -> Result<Principal> {
        let _ = (params, now);
        Err(AuthError::Malformed(format!(
            "unsupported login method {method:?}"
        )))
    }

    /// Whether a session token issued for `subject` by this provider is still valid; returns the subject's
    /// current name and scopes. Default: refuse (a provider that issues no sessions never sees this).
    fn revalidate(&self, subject: &str, now: SystemTime) -> Result<Subject> {
        let _ = (subject, now);
        Err(AuthError::Revoked)
    }

    /// Pick up changed backing data (a re-read key file, a refreshed JWKS). Returns true when something changed.
    fn reload(&self) -> Result<bool> {
        Ok(false)
    }
}
