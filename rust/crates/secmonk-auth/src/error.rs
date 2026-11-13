//! Error type of the crate.

use crate::scope::Scope;

/// Everything that can go wrong in authentication. The HTTP layer maps all credential failures to 401.
#[derive(Debug, thiserror::Error)]
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
            AuthError::Malformed(_)
            | AuthError::UnknownKey
            | AuthError::InvalidCredentials
            | AuthError::Expired
            | AuthError::Revoked => "invalid credentials",
            _ => "internal error",
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
