//! Wire error codes (`err.code`) and the error body shared with the API's `ApiError`.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// An `err.code`. Unknown codes from a newer peer are kept verbatim ([`ErrorCode::Other`]).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// Malformed frame or message; the connection closes.
    ProtocolError,
    /// The callee does not serve the method.
    UnknownMethod,
    /// Params do not validate.
    InvalidParams,
    /// No such asset.
    UnknownAsset,
    /// No such vulnerability.
    UnknownVuln,
    /// No such collector.
    UnknownCollector,
    /// No such source.
    UnknownSource,
    /// No database yet.
    NoDb,
    /// Not available on this OS.
    UnsupportedPlatform,
    /// The collector failed on the target.
    CollectError,
    /// Docker engine unreachable.
    EngineUnreachable,
    /// SSH host unreachable.
    HostUnreachable,
    /// The request was cancelled.
    Cancelled,
    /// The deadline passed.
    Timeout,
    /// The module died with the request pending.
    ModuleCrashed,
    /// The module cannot be started.
    ModuleUnavailable,
    /// Another job runs.
    Busy,
    /// A write based on an outdated read.
    Stale,
    /// Anything else.
    Internal,
    /// A code this version does not know.
    Other(String),
}

impl ErrorCode {
    /// The wire string.
    pub fn as_str(&self) -> &str {
        match self {
            ErrorCode::ProtocolError => "protocol-error",
            ErrorCode::UnknownMethod => "unknown-method",
            ErrorCode::InvalidParams => "invalid-params",
            ErrorCode::UnknownAsset => "unknown-asset",
            ErrorCode::UnknownVuln => "unknown-vuln",
            ErrorCode::UnknownCollector => "unknown-collector",
            ErrorCode::UnknownSource => "unknown-source",
            ErrorCode::NoDb => "no-db",
            ErrorCode::UnsupportedPlatform => "unsupported-platform",
            ErrorCode::CollectError => "collect-error",
            ErrorCode::EngineUnreachable => "engine-unreachable",
            ErrorCode::HostUnreachable => "host-unreachable",
            ErrorCode::Cancelled => "cancelled",
            ErrorCode::Timeout => "timeout",
            ErrorCode::ModuleCrashed => "module-crashed",
            ErrorCode::ModuleUnavailable => "module-unavailable",
            ErrorCode::Busy => "busy",
            ErrorCode::Stale => "stale",
            ErrorCode::Internal => "internal",
            ErrorCode::Other(s) => s,
        }
    }

    /// Parse a wire string (never fails: unknown codes become [`ErrorCode::Other`]).
    pub fn parse(s: &str) -> ErrorCode {
        match s {
            "protocol-error" => ErrorCode::ProtocolError,
            "unknown-method" => ErrorCode::UnknownMethod,
            "invalid-params" => ErrorCode::InvalidParams,
            "unknown-asset" => ErrorCode::UnknownAsset,
            "unknown-vuln" => ErrorCode::UnknownVuln,
            "unknown-collector" => ErrorCode::UnknownCollector,
            "unknown-source" => ErrorCode::UnknownSource,
            "no-db" => ErrorCode::NoDb,
            "unsupported-platform" => ErrorCode::UnsupportedPlatform,
            "collect-error" => ErrorCode::CollectError,
            "engine-unreachable" => ErrorCode::EngineUnreachable,
            "host-unreachable" => ErrorCode::HostUnreachable,
            "cancelled" => ErrorCode::Cancelled,
            "timeout" => ErrorCode::Timeout,
            "module-crashed" => ErrorCode::ModuleCrashed,
            "module-unavailable" => ErrorCode::ModuleUnavailable,
            "busy" => ErrorCode::Busy,
            "stale" => ErrorCode::Stale,
            "internal" => ErrorCode::Internal,
            other => ErrorCode::Other(other.to_string()),
        }
    }

    /// Every known code, for tables and tests.
    pub const KNOWN: [&'static str; 19] = [
        "protocol-error",
        "unknown-method",
        "invalid-params",
        "unknown-asset",
        "unknown-vuln",
        "unknown-collector",
        "unknown-source",
        "no-db",
        "unsupported-platform",
        "collect-error",
        "engine-unreachable",
        "host-unreachable",
        "cancelled",
        "timeout",
        "module-crashed",
        "module-unavailable",
        "busy",
        "stale",
        "internal",
    ];
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(ErrorCode::parse(&s))
    }
}

/// Maximum length of `error` text on the wire (schema `maxLength`).
pub const MAX_ERROR_LEN: usize = 4096;

/// A failure as it travels on the wire and through the domain traits: `{code, error, hint?, data?}`.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
#[error("{code}: {error}")]
pub struct WireError {
    /// Code.
    pub code: ErrorCode,
    /// Human message (never a traceback); at most [`MAX_ERROR_LEN`] chars.
    pub error: String,
    /// Optional hint for the user.
    pub hint: Option<String>,
    /// Optional structured details (boxed: keeps `WireError` at 80 bytes, below `clippy::result_large_err`).
    pub data: Option<Box<Value>>,
}

impl WireError {
    /// A new error; the message is truncated to [`MAX_ERROR_LEN`] chars.
    pub fn new(code: ErrorCode, error: impl Into<String>) -> WireError {
        let mut error = error.into();
        truncate_chars(&mut error, MAX_ERROR_LEN);
        WireError {
            code,
            error,
            hint: None,
            data: None,
        }
    }

    /// With a hint.
    pub fn with_hint(mut self, hint: impl Into<String>) -> WireError {
        self.hint = Some(hint.into());
        self
    }

    /// `internal` error in the `"<Type>: <message>"` form.
    pub fn internal(kind: &str, message: impl fmt::Display) -> WireError {
        WireError::new(ErrorCode::Internal, format!("{kind}: {message}"))
    }

    /// Shorthand for `protocol-error`.
    pub fn protocol(message: impl Into<String>) -> WireError {
        WireError::new(ErrorCode::ProtocolError, message)
    }

    /// Shorthand for `invalid-params`.
    pub fn invalid_params(message: impl Into<String>) -> WireError {
        WireError::new(ErrorCode::InvalidParams, message)
    }

    /// Shorthand for `cancelled`.
    pub fn cancelled(message: impl Into<String>) -> WireError {
        WireError::new(ErrorCode::Cancelled, message)
    }
}

/// Truncate a string to at most `max` chars (on a char boundary).
pub fn truncate_chars(s: &mut String, max: usize) {
    if let Some((idx, _)) = s.char_indices().nth(max) {
        s.truncate(idx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_round_trip() {
        for k in ErrorCode::KNOWN {
            let c = ErrorCode::parse(k);
            assert!(!matches!(c, ErrorCode::Other(_)), "{k}");
            assert_eq!(c.as_str(), k);
            let j = serde_json::to_string(&c).unwrap();
            assert_eq!(serde_json::from_str::<ErrorCode>(&j).unwrap(), c);
        }
        assert_eq!(
            ErrorCode::parse("future-code"),
            ErrorCode::Other("future-code".into())
        );
    }

    #[test]
    fn stays_small() {
        assert!(
            std::mem::size_of::<WireError>() <= 80,
            "{}",
            std::mem::size_of::<WireError>()
        );
    }

    #[test]
    fn long_errors_truncate() {
        let e = WireError::new(ErrorCode::Internal, "é".repeat(5000));
        assert_eq!(e.error.chars().count(), MAX_ERROR_LEN);
    }
}
