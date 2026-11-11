//! Errors of the engine service: the wire codes of `secmonk-wire/1` that reach the UI, plus `NotImplemented` for
//! the skeleton. `secmonk-api` maps them to HTTP statuses and the `{error, hint, code}` body
//! (`rust/_docs/tech/api-contract.md#errors`).

use std::fmt;

/// Why a call failed. One variant per wire code the API distinguishes; the HTTP status is the API's business.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    InvalidParams,
    NoDb,
    UnknownAsset,
    UnknownVuln,
    /// A job id nobody knows (404 without a code, as `JobRunner.get`).
    UnknownJob,
    Busy,
    UnsupportedPlatform,
    CollectError,
    EngineUnreachable,
    HostUnreachable,
    ModuleUnavailable,
    ModuleCrashed,
    Timeout,
    Internal,
    /// The route exists but the engine part behind it is not built yet (skeleton, wave W3).
    NotImplemented,
}

impl ErrorKind {
    /// The wire code (`secmonk-wire/1` `error.code`) or the API-level code for `NotImplemented`.
    pub fn wire_code(self) -> &'static str {
        match self {
            Self::InvalidParams => "invalid-params",
            Self::NoDb => "no-db",
            Self::UnknownAsset => "unknown-asset",
            Self::UnknownVuln => "unknown-vuln",
            Self::UnknownJob => "unknown-job",
            Self::Busy => "busy",
            Self::UnsupportedPlatform => "unsupported-platform",
            Self::CollectError => "collect-error",
            Self::EngineUnreachable => "engine-unreachable",
            Self::HostUnreachable => "host-unreachable",
            Self::ModuleUnavailable => "module-unavailable",
            Self::ModuleCrashed => "module-crashed",
            Self::Timeout => "timeout",
            Self::Internal => "internal",
            Self::NotImplemented => "not-implemented",
        }
    }
}

/// An engine failure: a kind, the user-facing message and an optional hint (both are ours, never a remote reply).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct EngineError {
    pub kind: ErrorKind,
    pub message: String,
    pub hint: Option<String>,
    /// The finer reason a module gave in `data.reason` (`kubectl-missing`, `k8s-denied`, `k8s-unreachable`).
    pub reason: Option<String>,
}

impl EngineError {
    pub fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            hint: None,
            reason: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// `DataApi.no_db`: the store is not initialized yet.
    pub fn no_db(state_path: impl fmt::Display) -> Self {
        Self::new(ErrorKind::NoDb, format!("no database at {state_path}")).with_hint(
            "Create the local vulnerability mirror first (Sources & sync, or `secmonk sync kev epss osv`), \
             then scan assets.",
        )
    }

    pub fn unknown_asset(id: &str) -> Self {
        Self::new(
            ErrorKind::UnknownAsset,
            format!("unknown asset {}", py_repr(id)),
        )
    }

    pub fn unknown_vuln(id: &str) -> Self {
        Self::new(ErrorKind::UnknownVuln, format!("unknown vulnerability id {}", py_repr(id))).with_hint(
            "Not in the local mirror: sync the source that publishes it (osv, cvelist, nvd, euvd\u{2026}).",
        )
    }

    pub fn unknown_job(id: u64) -> Self {
        Self::new(ErrorKind::UnknownJob, format!("no job {id}"))
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::InvalidParams, message)
    }

    pub fn not_implemented(route: &str) -> Self {
        Self::new(
            ErrorKind::NotImplemented,
            format!("{route} is not implemented yet"),
        )
        .with_hint("The engine behind this route is built in wave W3 of the prototype plan.")
    }
}

/// Python's `repr()` of a string as Python's `!r` prints it in messages: single quotes unless the text has a single
/// quote and no double quote.
pub fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// A failed module or trait call keeps its wire code; the API maps it to a status.
impl From<secmonk_proto::WireError> for EngineError {
    fn from(e: secmonk_proto::WireError) -> Self {
        use secmonk_proto::ErrorCode as C;
        let kind = match e.code {
            C::InvalidParams | C::UnknownCollector | C::UnknownSource => ErrorKind::InvalidParams,
            C::UnknownAsset => ErrorKind::UnknownAsset,
            C::UnknownVuln => ErrorKind::UnknownVuln,
            C::NoDb => ErrorKind::NoDb,
            C::UnsupportedPlatform => ErrorKind::UnsupportedPlatform,
            C::CollectError => ErrorKind::CollectError,
            C::EngineUnreachable => ErrorKind::EngineUnreachable,
            C::HostUnreachable => ErrorKind::HostUnreachable,
            C::Timeout => ErrorKind::Timeout,
            C::ModuleCrashed => ErrorKind::ModuleCrashed,
            C::ModuleUnavailable => ErrorKind::ModuleUnavailable,
            C::Busy | C::Stale => ErrorKind::Busy,
            C::ProtocolError | C::UnknownMethod | C::Cancelled | C::Internal | C::Other(_) => {
                ErrorKind::Internal
            }
        };
        let reason = e
            .data
            .as_deref()
            .and_then(|d| d.get("reason"))
            .and_then(|r| r.as_str())
            .map(str::to_owned);
        Self {
            kind,
            message: e.error,
            hint: e.hint,
            reason,
        }
    }
}

pub type EngineResult<T> = Result<T, EngineError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repr_matches_python() {
        assert_eq!(py_repr("abc"), "'abc'");
        assert_eq!(py_repr("it's"), "\"it's\"");
        assert_eq!(py_repr("a\nb"), "'a\\nb'");
        assert_eq!(py_repr("it's \"x\""), "'it\\'s \"x\"'");
    }

    #[test]
    fn wire_errors_keep_their_meaning() {
        use secmonk_proto::{ErrorCode, WireError};
        let e: EngineError = WireError::new(ErrorCode::ModuleCrashed, "py-engine died")
            .with_hint("see logs")
            .into();
        assert_eq!(
            (e.kind, e.message.as_str(), e.hint.as_deref()),
            (ErrorKind::ModuleCrashed, "py-engine died", Some("see logs"))
        );
        assert_eq!(
            EngineError::from(WireError::new(ErrorCode::Stale, "x")).kind,
            ErrorKind::Busy
        );
    }

    #[test]
    fn no_db_message_is_pythons() {
        let e = EngineError::no_db("/d/state.sqlite3");
        assert_eq!(e.message, "no database at /d/state.sqlite3");
        assert!(
            e.hint
                .unwrap()
                .starts_with("Create the local vulnerability mirror first")
        );
    }
}
