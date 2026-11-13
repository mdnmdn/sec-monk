//! What the server binding and the client share: the wire code <-> HTTP status table ([`status_of`],
//! [`wire_error_of_status`]: `http` only) and the query-string helpers. [`api_error_of_wire`] (an `ApiError`
//! body) exists with the `server` feature only.

use http::StatusCode;
use percent_encoding::{NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
#[cfg(feature = "server")]
use secmonk_api::ApiError;
use secmonk_traits::{ErrorCode, WireError};

/// The `code` a node answers for a request refused for lack of credentials (client side only: the server layer in
/// front of the mount answers 401 / 403 without a code).
pub const CODE_UNAUTHORIZED: &str = "unauthorized";
/// The `code` the client reports for a 403.
pub const CODE_FORBIDDEN: &str = "forbidden";
/// The `code` the client reports for a 404 without a wire code.
pub const CODE_NOT_FOUND: &str = "not-found";

/// HTTP status of a wire code (`api-contract.md#errors`, extended for the codes a node can raise).
pub fn status_of(code: &ErrorCode) -> StatusCode {
    match code {
        ErrorCode::InvalidParams | ErrorCode::ProtocolError => StatusCode::BAD_REQUEST,
        ErrorCode::UnknownAsset
        | ErrorCode::UnknownVuln
        | ErrorCode::UnknownCollector
        | ErrorCode::UnknownSource
        | ErrorCode::NoDb => StatusCode::NOT_FOUND,
        ErrorCode::Busy | ErrorCode::Stale => StatusCode::CONFLICT,
        ErrorCode::UnsupportedPlatform
        | ErrorCode::CollectError
        | ErrorCode::ModuleUnavailable
        | ErrorCode::ModuleCrashed
        | ErrorCode::Timeout
        | ErrorCode::Cancelled => StatusCode::SERVICE_UNAVAILABLE,
        ErrorCode::EngineUnreachable | ErrorCode::HostUnreachable => StatusCode::BAD_GATEWAY,
        ErrorCode::UnknownMethod => StatusCode::NOT_IMPLEMENTED,
        ErrorCode::Internal | ErrorCode::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

/// The body of a failed call. The wire `code` always travels (the client maps it back); the text of an `internal`
/// (or unknown-code) error is replaced by a generic one, the original goes to the log: internals are not for the
/// network.
#[cfg(feature = "server")]
pub fn api_error_of_wire(e: &WireError) -> ApiError {
    let status = status_of(&e.code);
    let hidden = status == StatusCode::INTERNAL_SERVER_ERROR;
    if hidden {
        tracing::warn!(code = %e.code, error = %e.error, "node call failed");
    }
    let mut a = ApiError::new(
        status,
        if hidden {
            "internal error".to_owned()
        } else {
            e.error.clone()
        },
    )
    .with_code(e.code.as_str());
    if !hidden && let Some(h) = &e.hint {
        a = a.with_hint(h.clone());
    }
    a
}

/// Most characters of a remote error text kept in a [`WireError`] (it is the remote's text, never ours).
const MAX_REMOTE_TEXT: usize = 500;

/// The [`WireError`] of an HTTP answer: the body's wire `code` when it is a known one, else the status decides
/// (400 / 413 `invalid-params`, 401 `unauthorized`, 403 `forbidden`, 404 `not-found`, 409 / 429 `busy`, 502
/// `host-unreachable`, 503 `module-unavailable`, 504 `timeout`, other 5xx `internal`).
pub fn wire_error_of_status(status: u16, body: &[u8]) -> WireError {
    let parsed: Option<serde_json::Value> = serde_json::from_slice(body).ok();
    let text = parsed
        .as_ref()
        .and_then(|v| v.get("error"))
        .and_then(|v| v.as_str())
        .map(|s| s.chars().take(MAX_REMOTE_TEXT).collect::<String>());
    let hint = parsed
        .as_ref()
        .and_then(|v| v.get("hint"))
        .and_then(|v| v.as_str())
        .map(|s| s.chars().take(MAX_REMOTE_TEXT).collect::<String>());
    let from_body = parsed
        .as_ref()
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_str())
        .map(ErrorCode::parse)
        .filter(|c| !matches!(c, ErrorCode::Other(_)));
    let code = from_body.unwrap_or_else(|| match status {
        400 | 413 | 414 | 422 => ErrorCode::InvalidParams,
        401 => ErrorCode::Other(CODE_UNAUTHORIZED.into()),
        403 => ErrorCode::Other(CODE_FORBIDDEN.into()),
        404 => ErrorCode::Other(CODE_NOT_FOUND.into()),
        409 | 429 => ErrorCode::Busy,
        502 => ErrorCode::HostUnreachable,
        503 => ErrorCode::ModuleUnavailable,
        504 => ErrorCode::Timeout,
        _ => ErrorCode::Internal,
    });
    let text = text.unwrap_or_else(|| format!("the node answered HTTP {status}"));
    let mut e = WireError::new(code, text);
    e.hint = hint;
    e
}

/// Percent-encode one query component (everything but ASCII alphanumerics).
pub fn pct(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

fn decode(s: &str) -> String {
    percent_decode_str(&s.replace('+', " "))
        .decode_utf8_lossy()
        .into_owned()
}

/// `name=value` pairs of a raw query string, decoded, in order; pairs with an empty value or no `=` are dropped.
pub fn parse_query(raw: Option<&str>) -> Vec<(String, String)> {
    raw.unwrap_or("")
        .split('&')
        .filter_map(|pair| {
            let (n, v) = pair.split_once('=')?;
            (!v.is_empty()).then(|| (decode(n), decode(v)))
        })
        .collect()
}

/// A query string (`a=1&b=2`, no leading `?`) from pairs.
pub fn encode_query(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", pct(k), pct(v)))
        .collect::<Vec<_>>()
        .join("&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_round_trip() {
        let pairs = vec![
            ("q".to_owned(), "a b&c=d+é".to_owned()),
            ("limit".to_owned(), "5".to_owned()),
        ];
        let s = encode_query(&pairs);
        assert_eq!(parse_query(Some(&s)), pairs);
        assert!(parse_query(Some("a=&b&c=1")).len() == 1);
        assert!(parse_query(None).is_empty());
    }

    #[cfg(feature = "server")]
    #[test]
    fn status_mapping_round_trips_the_wire_code() {
        for k in ErrorCode::KNOWN {
            let code = ErrorCode::parse(k);
            let a = api_error_of_wire(&WireError::new(code.clone(), "x"));
            let back = wire_error_of_status(a.status.as_u16(), &a.body());
            if status_of(&code) == StatusCode::INTERNAL_SERVER_ERROR {
                assert_eq!(a.message, "internal error");
            }
            assert_eq!(back.code, code, "{k}");
        }
        let e = wire_error_of_status(403, b"{\"error\":\"forbidden\",\"hint\":\"lacks match\"}");
        assert_eq!(e.code, ErrorCode::Other("forbidden".into()));
        assert_eq!(e.hint.as_deref(), Some("lacks match"));
        assert_eq!(
            wire_error_of_status(500, b"<html>").code,
            ErrorCode::Internal
        );
    }
}
