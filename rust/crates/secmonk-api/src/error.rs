//! `ApiError`: the `{error, hint?, code?}` body and HTTP status of `web/api.py` `ApiError`.

use http::StatusCode;
use secmonk_engine::{EngineError, ErrorKind};
use serde::Serialize;

/// An API failure. Serialized as the response body: `error` always, `hint` and `code` only when set (the key
/// order is Python's: error, hint, code).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiError {
    #[serde(skip)]
    pub status: StatusCode,
    #[serde(rename = "error")]
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
            hint: None,
            code: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn with_code(mut self, code: impl Into<String>) -> Self {
        self.code = Some(code.into());
        self
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, message)
    }

    /// The JSON body bytes.
    pub fn body(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_else(|_| br#"{"error":"internal error"}"#.to_vec())
    }
}

/// HTTP status of a wire code (`api-contract.md#errors`).
pub fn status_of(kind: ErrorKind) -> StatusCode {
    match kind {
        ErrorKind::InvalidParams => StatusCode::BAD_REQUEST,
        ErrorKind::NoDb
        | ErrorKind::UnknownAsset
        | ErrorKind::UnknownVuln
        | ErrorKind::UnknownJob => StatusCode::NOT_FOUND,
        ErrorKind::Busy => StatusCode::CONFLICT,
        ErrorKind::UnsupportedPlatform
        | ErrorKind::CollectError
        | ErrorKind::ModuleUnavailable
        | ErrorKind::ModuleCrashed
        | ErrorKind::Timeout => StatusCode::SERVICE_UNAVAILABLE,
        ErrorKind::EngineUnreachable | ErrorKind::HostUnreachable => StatusCode::BAD_GATEWAY,
        ErrorKind::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        ErrorKind::NotImplemented => StatusCode::NOT_IMPLEMENTED,
    }
}

/// Wire codes whose `code` stays in the body (the UI branches on them); the others are status-only, as in Python.
fn keeps_code(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::NoDb
            | ErrorKind::UnknownAsset
            | ErrorKind::UnknownVuln
            | ErrorKind::NotImplemented
    )
}

impl From<EngineError> for ApiError {
    fn from(e: EngineError) -> Self {
        let code = keeps_code(e.kind).then(|| e.kind.wire_code().to_owned());
        Self {
            status: status_of(e.kind),
            message: e.message,
            hint: e.hint,
            code,
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Probe failures of the host-facing routes (`web/jobs.py` `_discover_error`, `_engine_error`, `k8s_kubeconfigs`).
// The module reports *what* failed in the wire code and, for Kubernetes, *why* in `data.reason`
// (`kubectl-missing`, `k8s-denied`, `k8s-unreachable`); the route decides the HTTP shape. Remote replies are never
// echoed: messages are generic (`<Type>` only), the details stay in the module log and the CLI.
// ---------------------------------------------------------------------------------------------------------------

/// Why a Kubernetes probe call failed (`data.reason` of the module's error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum K8sReason {
    /// `kubectl` is not installed (or not on PATH) on this machine.
    KubectlMissing,
    /// The cluster refused the request (RBAC, expired credentials).
    Denied,
    /// The cluster cannot be reached (or any other kubectl failure).
    Unreachable,
}

impl K8sReason {
    /// The wire `data.reason` value.
    pub fn wire(self) -> &'static str {
        match self {
            Self::KubectlMissing => "kubectl-missing",
            Self::Denied => "k8s-denied",
            Self::Unreachable => "k8s-unreachable",
        }
    }

    /// `data.reason` -> reason.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "kubectl-missing" => Some(Self::KubectlMissing),
            "k8s-denied" => Some(Self::Denied),
            "k8s-unreachable" => Some(Self::Unreachable),
            _ => None,
        }
    }
}

/// The Kubernetes reason of an engine error: the module's `data.reason`, carried by `EngineError::reason`.
pub fn k8s_reason(e: &EngineError) -> Option<K8sReason> {
    e.reason.as_deref().and_then(K8sReason::from_wire)
}

/// The exception type name at the start of a module's `<Type>: <message>` text, else `fallback`.
pub fn type_name<'a>(message: &'a str, fallback: &'a str) -> &'a str {
    match message.split_once(": ") {
        Some((t, _))
            if !t.is_empty()
                && t.len() <= 64
                && t.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.') =>
        {
            t
        }
        _ => fallback,
    }
}

/// Failures of the host itself or of a module's state (busy, down, not built here): they keep their own status. Any
/// other failure of a probe call is a generic 502 (`_engine_error`: what the engine said is never echoed).
fn is_host_state(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::Busy
            | ErrorKind::ModuleUnavailable
            | ErrorKind::ModuleCrashed
            | ErrorKind::UnsupportedPlatform
            | ErrorKind::NotImplemented
    )
}

/// `GET /api/discover`: `JobRunner._discover_error` plus the ValueError branch of `discover`.
pub fn discover_error(e: EngineError, target: Option<&str>) -> ApiError {
    let is_k8s_target = target.is_some_and(|t| t.starts_with("k8s://"));
    let reason = k8s_reason(&e);
    if e.kind == ErrorKind::InvalidParams {
        return ApiError::bad_request(e.message)
            .with_hint("Expected nothing (this machine) or [ssh://]user@host[:port].");
    }
    if reason.is_none() && !is_k8s_target && is_host_state(e.kind) {
        return e.into();
    }
    if reason.is_some() || is_k8s_target {
        let hint_tail = "`secmonk discover k8s://<context>` shows the full error.";
        return match reason {
            Some(K8sReason::KubectlMissing) => ApiError::new(
                StatusCode::FAILED_DEPENDENCY,
                "kubectl is not installed on the machine running secmonk ui",
            )
            .with_hint("Install kubectl (on PATH), or use the CLI with -o kubectl=/path/to/kubectl.")
            .with_code(K8sReason::KubectlMissing.wire()),
            Some(K8sReason::Denied) => ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!(
                    "the cluster refused the request ({})",
                    type_name(&e.message, "KubectlError")
                ),
            )
            .with_hint(format!(
                "The kubeconfig user lacks read access (RBAC) or its credentials expired; {hint_tail}"
            ))
            .with_code(K8sReason::Denied.wire()),
            _ => ApiError::new(
                StatusCode::BAD_GATEWAY,
                format!(
                    "cannot reach the Kubernetes cluster ({})",
                    type_name(&e.message, "KubectlError")
                ),
            )
            .with_hint(format!(
                "Check the kubeconfig and context (and the VPN, if the API server needs one); {hint_tail}"
            ))
            .with_code(K8sReason::Unreachable.wire()),
        };
    }
    ApiError::new(
        StatusCode::BAD_GATEWAY,
        format!(
            "cannot explore the host ({})",
            type_name(&e.message, "SSHError")
        ),
    )
    .with_hint(
        "Is the host reachable over ssh with a key (no password prompt) from the machine running \
         secmonk ui? `secmonk discover <target>` shows the full error.",
    )
}

/// `GET /api/docker/contexts`, `/api/docker/containers`: `_engine_error`.
pub fn docker_error(e: EngineError) -> ApiError {
    match e.kind {
        ErrorKind::InvalidParams => ApiError::bad_request(e.message).with_hint(
            "Check the host (unix:// tcp:// ssh://user@host), the context name and the selector \
             (names, globs, re:<regex>, comma separated).",
        ),
        k if !is_host_state(k) => ApiError::new(
            StatusCode::BAD_GATEWAY,
            format!(
                "cannot reach the Docker engine ({})",
                type_name(&e.message, "RuntimeError")
            ),
        )
        .with_hint(
            "Is the Docker/Podman engine running and reachable from the machine running secmonk ui? For ssh:// \
             hosts the key must be usable without a prompt. `secmonk containers` with the same host / context \
             shows the engine's own error.",
        ),
        _ => e.into(),
    }
}

/// `GET /api/k8s/kubeconfigs`: any failure is a 500 with the exception type.
pub fn kubeconfigs_error(e: EngineError) -> ApiError {
    match e.kind {
        ErrorKind::Busy
        | ErrorKind::ModuleUnavailable
        | ErrorKind::ModuleCrashed
        | ErrorKind::Timeout => e.into(),
        _ => ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "cannot list kubeconfigs ({})",
                type_name(&e.message, "OSError")
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn body_shape_is_pythons() {
        let e = ApiError::not_found("no database at /x")
            .with_hint("h")
            .with_code("no-db");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&e.body()).unwrap(),
            json!({"error": "no database at /x", "hint": "h", "code": "no-db"})
        );
        let plain = ApiError::bad_request("id: required");
        assert_eq!(
            String::from_utf8(plain.body()).unwrap(),
            r#"{"error":"id: required"}"#
        );
        let full = String::from_utf8(e.body()).unwrap();
        assert!(full.find("error").unwrap() < full.find("hint").unwrap());
        assert!(full.find("hint").unwrap() < full.find("code").unwrap());
    }

    #[test]
    fn engine_errors_map_to_status_and_code() {
        let a = ApiError::from(EngineError::unknown_asset("x"));
        assert_eq!(
            (a.status.as_u16(), a.code.as_deref()),
            (404, Some("unknown-asset"))
        );
        let b = ApiError::from(EngineError::new(ErrorKind::Busy, "another job is running"));
        assert_eq!((b.status.as_u16(), b.code), (409, None));
        let m = ApiError::from(EngineError::new(ErrorKind::ModuleUnavailable, "py-engine"));
        assert_eq!((m.status.as_u16(), m.code), (503, None));
        let n = ApiError::from(EngineError::unknown_job(7));
        assert_eq!((n.status.as_u16(), n.code), (404, None));
        let u = ApiError::from(EngineError::new(ErrorKind::HostUnreachable, "x"));
        assert_eq!(u.status.as_u16(), 502);
    }

    #[test]
    fn discover_errors_follow_python() {
        let mk = |kind, msg: &str, reason: Option<&str>| {
            let mut e = EngineError::new(kind, msg);
            e.reason = reason.map(str::to_owned);
            e
        };
        let missing = discover_error(
            mk(
                ErrorKind::CollectError,
                "KubectlError: kubectl not found",
                Some("kubectl-missing"),
            ),
            Some("k8s://prod"),
        );
        assert_eq!(
            (missing.status.as_u16(), missing.code.as_deref()),
            (424, Some("kubectl-missing"))
        );
        assert!(missing.message.starts_with("kubectl is not installed"));
        let denied = discover_error(
            mk(
                ErrorKind::HostUnreachable,
                "KubectlError: forbidden",
                Some("k8s-denied"),
            ),
            Some("k8s://prod"),
        );
        assert_eq!(
            (denied.status.as_u16(), denied.code.as_deref()),
            (502, Some("k8s-denied"))
        );
        assert_eq!(
            denied.message,
            "the cluster refused the request (KubectlError)"
        );
        let down = discover_error(
            mk(
                ErrorKind::HostUnreachable,
                "KubectlError: no route to host",
                Some("k8s-unreachable"),
            ),
            Some("k8s://prod"),
        );
        assert_eq!(
            (down.status.as_u16(), down.code.as_deref()),
            (502, Some("k8s-unreachable"))
        );
        assert_eq!(
            down.message,
            "cannot reach the Kubernetes cluster (KubectlError)"
        );
        let ssh = discover_error(
            mk(ErrorKind::HostUnreachable, "SSHError: boom secret", None),
            Some("u@h"),
        );
        assert_eq!((ssh.status.as_u16(), ssh.code), (502, None));
        assert_eq!(
            ssh.message, "cannot explore the host (SSHError)",
            "the remote text is not echoed"
        );
        let bad = discover_error(
            mk(ErrorKind::InvalidParams, "ValueError: bad target", None),
            Some("x"),
        );
        assert_eq!(bad.status.as_u16(), 400);
        assert!(bad.hint.unwrap().starts_with("Expected nothing"));
        let busy = discover_error(
            mk(ErrorKind::Busy, "a discovery is already running", None),
            None,
        );
        assert_eq!(busy.status.as_u16(), 409);
        let down_mod = discover_error(
            mk(ErrorKind::ModuleUnavailable, "py-probe failed", None),
            None,
        );
        assert_eq!(down_mod.status.as_u16(), 503);
    }

    #[test]
    fn docker_and_kubeconfig_errors() {
        let e = docker_error(EngineError::new(
            ErrorKind::EngineUnreachable,
            "RuntimeError: cannot connect to tcp://u:p@h",
        ));
        assert_eq!(
            (e.status.as_u16(), e.message.as_str()),
            (502, "cannot reach the Docker engine (RuntimeError)")
        );
        assert_eq!(
            docker_error(EngineError::new(ErrorKind::InvalidParams, "ValueError: x"))
                .status
                .as_u16(),
            400
        );
        let k = kubeconfigs_error(EngineError::new(ErrorKind::CollectError, "OSError: denied"));
        assert_eq!(
            (k.status.as_u16(), k.message.as_str()),
            (500, "cannot list kubeconfigs (OSError)")
        );
        assert_eq!(type_name("no type here", "X"), "X");
    }

    /// `_engine_error` / `_discover_error`: anything that is not bad input or the state of the host or a module
    /// is a generic 502 whose message never carries what the engine said.
    #[test]
    fn internal_and_timeout_errors_are_a_generic_502() {
        for kind in [ErrorKind::Internal, ErrorKind::Timeout] {
            let d = docker_error(EngineError::new(kind, "RuntimeError: secret detail"));
            assert_eq!(
                (d.status.as_u16(), d.message.as_str(), d.code),
                (502, "cannot reach the Docker engine (RuntimeError)", None)
            );
            let h = discover_error(
                EngineError::new(kind, "OSError: secret detail"),
                Some("u@h"),
            );
            assert_eq!(
                (h.status.as_u16(), h.message.as_str()),
                (502, "cannot explore the host (OSError)")
            );
        }
        // module state keeps its own status
        let m = docker_error(EngineError::new(ErrorKind::ModuleCrashed, "py-probe died"));
        assert_eq!(m.status.as_u16(), 503);
        let b = docker_error(EngineError::new(ErrorKind::Busy, "busy"));
        assert_eq!(b.status.as_u16(), 409);
        assert_eq!(type_name("SSHError: a: b", "X"), "SSHError");
    }
}
