//! Error type of the crate.

use crate::scope::Scope;

/// Everything that can go wrong in authentication. The HTTP layer maps all credential failures to 401.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthError {
    /// No credential was presented.
    #[error("no credentials presented")]
    Missing,
    /// The credential is syntactically wrong (key format, header scheme, token structure).
    #[error("malformed credentials: {0}")]
    Malformed(String),
    /// Unknown key id (internal detail; public text is the generic one).
    #[error("unknown key id")]
    UnknownKey,
    /// Secret or signature does not match.
    #[error("invalid credentials")]
    InvalidCredentials,
    /// Key or token is past its expiry.
    #[error("credentials expired")]
    Expired,
    /// Key was revoked.
    #[error("key revoked")]
    Revoked,
    /// The principal lacks the scope.
    #[error("missing scope {0}")]
    Forbidden(Scope),
    /// Token bucket or login throttle refused the call.
    #[error("rate limited")]
    RateLimited,
    /// Unknown scope name.
    #[error("unknown scope {0:?}")]
    UnknownScope(String),
    /// A key with this name already exists.
    #[error("a key named {0:?} already exists")]
    DuplicateName(String),
    /// No key with this id or name.
    #[error("no key {0:?}")]
    NotFound(String),
    /// File I/O failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being done.
        context: String,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
    /// A file has the wrong content or permissions.
    #[error("{0}")]
    Format(String),
    /// The provider cannot decide right now (its backing data failed to load): fail closed.
    #[error("authentication unavailable: {0}")]
    Unavailable(String),
}

impl AuthError {
    pub(crate) fn io(context: impl Into<String>, source: std::io::Error) -> Self {
        AuthError::Io {
            context: context.into(),
            source,
        }
    }

    /// Text safe to show to a client: never reveals why a credential was refused.
    pub fn public_message(&self) -> &'static str {
        match self {
            AuthError::Missing => "authentication required",
            AuthError::Forbidden(_) => "forbidden",
            AuthError::RateLimited => "rate limited",
            AuthError::Unavailable(_) => "authentication unavailable",
            AuthError::Malformed(_)
            | AuthError::UnknownKey
            | AuthError::InvalidCredentials
            | AuthError::Expired
            | AuthError::Revoked => "invalid credentials",
            _ => "internal error",
        }
    }

    /// The HTTP status of the failure: 401 for credential problems (and a missing credential), 403 for a
    /// missing scope, 429 when throttled, 503 when a provider cannot decide, 500 otherwise.
    pub fn http_status(&self) -> u16 {
        match self {
            AuthError::Missing => 401,
            e if e.is_credential_failure() => 401,
            AuthError::Forbidden(_) => 403,
            AuthError::RateLimited => 429,
            AuthError::Unavailable(_) => 503,
            _ => 500,
        }
    }

    /// A short class of the failure for audit logs (never the credential, never details).
    pub fn reason_class(&self) -> &'static str {
        match self {
            AuthError::Missing => "missing",
            AuthError::Malformed(_) => "malformed",
            AuthError::UnknownKey => "unknown_key",
            AuthError::InvalidCredentials => "invalid",
            AuthError::Expired => "expired",
            AuthError::Revoked => "revoked",
            AuthError::Forbidden(_) => "forbidden",
            AuthError::RateLimited => "rate_limited",
            AuthError::Unavailable(_) => "unavailable",
            _ => "internal",
        }
    }

    /// True for the failures that count as a failed login (credential problems, not server problems).
    pub fn is_credential_failure(&self) -> bool {
        matches!(
            self,
            AuthError::Malformed(_)
                | AuthError::UnknownKey
                | AuthError::InvalidCredentials
                | AuthError::Expired
                | AuthError::Revoked
        )
    }
}
