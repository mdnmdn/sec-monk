//! Authentication strategies (rust ADR-0014 §"Auth providers").
//!
//! An [`AuthProvider`] is one way to prove who a caller is: the API keys of `api_keys.toml` today; an OIDC
//! identity provider, a TLS client certificate (mTLS between nodes) or a reverse-proxy header later. The
//! [`crate::Authenticator`] holds an ordered chain of providers and is the only thing the HTTP layer talks to:
//!
//! - **direct requests**: each provider looks at the [`RequestContext`] (the `Authorization` header, a TLS peer
//!   certificate) and answers `None` ("not mine"), or `Some(Ok(principal))` / `Some(Err(_))` ("mine, and this is
//!   the verdict"). The first provider that answers `Some` decides; a `Bearer` session token issued by this
//!   server is handled by the authenticator itself before the chain.
//! - **logins** (`POST /auth/token`): `{"method": "<name>", ...params}`; the provider whose
//!   [`AuthProvider::login_methods`] lists the method verifies the params and returns a principal, for which the
//!   authenticator issues a session JWT carrying the provider's name (`prv` claim).
//! - **session revalidation**: a session JWT is accepted only while [`AuthProvider::revalidate`] of its issuing
//!   provider still accepts the subject (a revoked API key also kills its JWTs).
//!
//! Adding a strategy = implementing this trait and registering it in the chain (`Authenticator::with_providers`);
//! the HTTP layer, the session tokens, scopes, rate limits and audit stay unchanged.

use std::time::SystemTime;

use serde_json::Value;

use crate::keys::Principal;
use crate::{AuthError, Result};

/// What a provider may look at to authenticate one request. Borrowed from the HTTP layer; new fields are added
/// as new strategies need them (the struct is `non_exhaustive`: build it with [`RequestContext::new`]).
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct RequestContext<'a> {
    /// The raw `Authorization` header value.
    pub authorization: Option<&'a str>,
    /// The client address (logs, throttles).
    pub client: Option<&'a str>,
    /// SHA-256 (hex) of the TLS client certificate, when the connection presented one (future mTLS provider).
    pub peer_cert_sha256: Option<&'a str>,
}

impl<'a> RequestContext<'a> {
    /// A context with an `Authorization` header value and a client address.
    pub fn new(authorization: Option<&'a str>, client: Option<&'a str>) -> Self {
        RequestContext {
            authorization,
            client,
            peer_cert_sha256: None,
        }
    }

    /// The same context with a TLS peer certificate fingerprint.
    pub fn with_peer_cert(mut self, sha256_hex: Option<&'a str>) -> Self {
        self.peer_cert_sha256 = sha256_hex;
        self
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

    /// Whether a session token issued for `subject` by this provider is still valid; returns the current display
    /// name of the subject. Default: refuse (a provider that issues no sessions never sees this).
    fn revalidate(&self, subject: &str, now: SystemTime) -> Result<String> {
        let _ = (subject, now);
        Err(AuthError::Revoked)
    }

    /// Pick up changed backing data (a re-read key file, a refreshed JWKS). Returns true when something changed.
    fn reload(&self) -> Result<bool> {
        Ok(false)
    }
}
