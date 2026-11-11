//! What the browser may ask for: the option policy of `web/jobs.py` and `ops.py`, enforced here because the
//! modules do not enforce it (they run whatever the host sends; the host decides what the UI may choose).
//!
//! * `WEB_FORBIDDEN_SCAN_OPTS`: collector options a scan started from the browser may not set (they choose what
//!   runs on this machine: a binary, a transport, an ssh config, a kubectl path);
//! * `DISCOVER_WEB_OPTS`: the only `opt` keys of `GET /api/discover`;
//! * `DOCKER_LIST_OPTS`: the only `opt` keys of `GET /api/docker/containers`.

use secmonk_engine::JsonObject;
use secmonk_engine::error::py_repr;
use secmonk_engine::splitlines;
use serde_json::Value;

use crate::error::ApiError;

/// `web/jobs.py` `WEB_FORBIDDEN_SCAN_OPTS`.
pub const WEB_FORBIDDEN_SCAN_OPTS: [&str; 5] = [
    "ssh_bin",
    "transport",
    "ssh_option",
    "kubectl",
    "ssh_config",
];

/// `ops.py` `DISCOVER_WEB_OPTS`.
pub const DISCOVER_WEB_OPTS: [&str; 14] = [
    "identity",
    "known_hosts",
    "insecure_host_key",
    "connect_timeout",
    "probe_timeout",
    "context",
    "host",
    "tls_ca",
    "tls_cert",
    "tls_key",
    "tls_verify",
    "kubeconfig",
    "namespace",
    "sudo",
];

/// `web/jobs.py` `DOCKER_LIST_OPTS` (no `socket`, no `ssh_bin`: a path to run).
pub const DOCKER_LIST_OPTS: [&str; 7] = [
    "tls_ca",
    "tls_cert",
    "tls_key",
    "tls_verify",
    "identity",
    "timeout",
    "connect_timeout",
];

/// The key of a `key=value` option (`ops.parse_opts`): `None` for an item without `=` or with an empty key.
fn option_key(item: &str) -> Option<&str> {
    let (key, _) = item.split_once('=')?;
    (!key.is_empty()).then_some(key)
}

fn sorted_joined(set: &[&str]) -> String {
    let mut v = set.to_vec();
    v.sort_unstable();
    v.join(", ")
}

/// `opt=k=v` values of a GET route: every item must be `key=value` (`parse_opts`), every key allowed.
fn check_opts(options: &[String], allowed: &[&str], hint: String) -> Result<(), ApiError> {
    let mut bad: Vec<&str> = Vec::new();
    for item in options {
        let Some(key) = option_key(item) else {
            return Err(ApiError::bad_request(format!(
                "opt: expected key=value, got {}",
                py_repr(item)
            )));
        };
        if !allowed.contains(&key) && !bad.contains(&key) {
            bad.push(key);
        }
    }
    if bad.is_empty() {
        return Ok(());
    }
    bad.sort_unstable();
    Err(
        ApiError::bad_request(format!("opt: not accepted here: {}", bad.join(", ")))
            .with_hint(hint),
    )
}

/// `GET /api/discover` options.
pub fn check_discover_opts(options: &[String]) -> Result<(), ApiError> {
    check_opts(
        options,
        &DISCOVER_WEB_OPTS,
        format!("Allowed: {}.", sorted_joined(&DISCOVER_WEB_OPTS)),
    )
}

/// `GET /api/docker/containers` options.
pub fn check_docker_opts(options: &[String]) -> Result<(), ApiError> {
    check_opts(
        options,
        &DOCKER_LIST_OPTS,
        format!(
            "Allowed: {}; use the host, context and all parameters.",
            sorted_joined(&DOCKER_LIST_OPTS)
        ),
    )
}

/// The option strings of a scan item as `ops.scan_item` reads them: a string is split into lines, a list must hold
/// only strings, blanks dropped; every item must be `key=value`. Anything else is a 400 (the policy fails closed:
/// an option list it cannot read is an option list it cannot vet).
fn item_option_keys(
    options: Option<&Value>,
    where_: &str,
    collector: Option<&str>,
) -> Result<Vec<String>, ApiError> {
    let prefix = match collector {
        Some(c) => format!("{where_}: {c}"),
        None => where_.to_owned(),
    };
    let lines: Vec<String> = match options {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::String(s)) => splitlines(s)
            .into_iter()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_owned)
            .collect(),
        Some(Value::Array(a)) => {
            let mut v = Vec::new();
            for x in a {
                let Some(s) = x.as_str() else {
                    return Err(ApiError::bad_request(format!(
                        "{prefix}: options must be a list of key=value strings"
                    )));
                };
                let s = s.trim();
                if !s.is_empty() {
                    v.push(s.to_owned());
                }
            }
            v
        }
        Some(_) => {
            return Err(ApiError::bad_request(format!(
                "{prefix}: options must be a list of key=value strings"
            )));
        }
    };
    lines
        .iter()
        .map(|l| {
            option_key(l).map(str::to_owned).ok_or_else(|| {
                ApiError::bad_request(format!("{prefix}: expected key=value, got {}", py_repr(l)))
            })
        })
        .collect()
}

fn check_scan_item(
    options: Option<&Value>,
    where_: &str,
    collector: Option<&str>,
) -> Result<(), ApiError> {
    let keys = item_option_keys(options, where_, collector)?;
    let mut bad: Vec<&str> = WEB_FORBIDDEN_SCAN_OPTS
        .iter()
        .copied()
        .filter(|f| keys.iter().any(|k| k == f))
        .collect();
    if bad.is_empty() {
        return Ok(());
    }
    bad.sort_unstable();
    Err(ApiError::bad_request(format!(
        "{where_}: option not accepted from the browser: {}",
        bad.join(", ")
    ))
    .with_hint(
        "Run scans that need a custom ssh binary, transport, ssh_option, ssh_config or kubectl with \
         the secmonk CLI.",
    ))
}

/// `POST /api/jobs` with `kind: scan`: the single item (`options`) or every one of `items` (`items[n]`) must carry
/// readable `key=value` options and none of the forbidden keys; a malformed `items` is refused too. Other kinds
/// pass (a sync has no collector options).
pub fn check_scan_body(body: &JsonObject) -> Result<(), ApiError> {
    if body.get("kind").and_then(Value::as_str) != Some("scan") {
        return Ok(());
    }
    match body.get("items") {
        None | Some(Value::Null) => check_scan_item(
            body.get("options"),
            "options",
            body.get("collector").and_then(Value::as_str),
        ),
        Some(Value::Array(items)) => {
            for (n, it) in items.iter().enumerate() {
                let where_ = format!("items[{}]", n + 1);
                let Some(o) = it.as_object() else {
                    return Err(ApiError::bad_request(format!(
                        "{where_}: expected an object {{collector, target, options}}"
                    )));
                };
                check_scan_item(
                    o.get("options"),
                    &where_,
                    o.get("collector").and_then(Value::as_str),
                )?;
            }
            Ok(())
        }
        Some(_) => Err(ApiError::bad_request(
            "items: expected a non-empty list of {collector, target, options}",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body(v: Value) -> JsonObject {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn sets_are_pythons() {
        assert_eq!(WEB_FORBIDDEN_SCAN_OPTS.len(), 5);
        assert_eq!(DISCOVER_WEB_OPTS.len(), 14);
        assert_eq!(DOCKER_LIST_OPTS.len(), 7);
        assert_eq!(
            sorted_joined(&DOCKER_LIST_OPTS),
            "connect_timeout, identity, timeout, tls_ca, tls_cert, tls_key, tls_verify"
        );
    }

    #[test]
    fn option_strings_split_like_python_splitlines() {
        assert_eq!(
            splitlines("a\r\nb\rc\x0bd\x0ce\x1cf\u{85}g\u{2028}h\u{2029}i\n"),
            ["a", "b", "c", "d", "e", "f", "g", "h", "i"]
        );
        // a forbidden option hidden behind a separator only Python's splitlines knows is still seen
        for sep in ["\u{2028}", "\x0b", "\x1c", "\u{85}", "\r"] {
            let b = body(json!({"kind": "scan", "collector": "ssh",
                                "options": format!("depth=2{sep}kubectl=/tmp/x")}));
            assert!(check_scan_body(&b).is_err(), "separator {sep:?}");
        }
    }

    #[test]
    fn single_scan_forbidden_options() {
        let b = body(
            json!({"kind": "scan", "collector": "ssh", "options": ["kubectl=/tmp/x", "ssh_bin=ssh", "depth=2"]}),
        );
        let e = check_scan_body(&b).unwrap_err();
        assert_eq!(e.status.as_u16(), 400);
        assert_eq!(
            e.message,
            "options: option not accepted from the browser: kubectl, ssh_bin"
        );
        assert!(
            e.hint
                .unwrap()
                .starts_with("Run scans that need a custom ssh binary")
        );
        // string form: one per line
        let s = body(
            json!({"kind": "scan", "collector": "fs", "options": "depth=1\n  transport=x  \n"}),
        );
        assert!(
            check_scan_body(&s)
                .unwrap_err()
                .message
                .contains("transport")
        );
        let ok = body(json!({"kind": "scan", "collector": "fs", "options": ["exclude=a,b"]}));
        assert!(check_scan_body(&ok).is_ok());
    }

    #[test]
    fn batch_items_are_checked_with_their_position() {
        let b = body(json!({"kind": "scan", "items": [
            {"collector": "fs", "options": []},
            {"collector": "k8s", "options": ["ssh_config=/x", "ssh_option=y"]}]}));
        let e = check_scan_body(&b).unwrap_err();
        assert_eq!(
            e.message,
            "items[2]: option not accepted from the browser: ssh_config, ssh_option"
        );
        // `items` wins over a top-level `options`, as in `_prepare_scan`
        let both =
            body(json!({"kind": "scan", "options": ["kubectl=x"], "items": [{"collector": "fs"}]}));
        assert!(check_scan_body(&both).is_ok());
    }

    #[test]
    fn malformed_options_are_refused_not_waved_through() {
        // M10: the policy used to fail open on anything it could not parse
        for (b, msg) in [
            (
                json!({"kind": "scan", "collector": "ssh", "options": ["kubectl"]}),
                "options: ssh: expected key=value, got 'kubectl'",
            ),
            (
                json!({"kind": "scan", "options": ["=x"]}),
                "options: expected key=value, got '=x'",
            ),
            (
                json!({"kind": "scan", "options": [1, 2]}),
                "options: options must be a list of key=value strings",
            ),
            (
                json!({"kind": "scan", "options": {"a": 1}}),
                "options: options must be a list of key=value strings",
            ),
            (
                json!({"kind": "scan", "items": "x"}),
                "items: expected a non-empty list of {collector, target, options}",
            ),
            (
                json!({"kind": "scan", "items": {"a": 1}}),
                "items: expected a non-empty list of {collector, target, options}",
            ),
            (
                json!({"kind": "scan", "items": [{"collector": "fs"}, "a"]}),
                "items[2]: expected an object {collector, target, options}",
            ),
            (
                json!({"kind": "scan", "items": [{"collector": "fs", "options": ["x"]}]}),
                "items[1]: fs: expected key=value, got 'x'",
            ),
            (
                json!({"kind": "scan", "items": [{"collector": "fs", "options": [true]}]}),
                "items[1]: fs: options must be a list of key=value strings",
            ),
        ] {
            let e = check_scan_body(&body(b.clone())).unwrap_err();
            assert_eq!((e.status.as_u16(), e.message.as_str()), (400, msg), "{b}");
        }
        // a forbidden key hidden next to a malformed item is still not let through
        let e = check_scan_body(&body(
            json!({"kind": "scan", "items": [{"collector": "k8s", "options": ["kubectl=/x"]}, 5]}),
        ))
        .unwrap_err();
        assert_eq!(e.status.as_u16(), 400);
        // sync bodies and null/absent options pass
        for b in [
            json!({"kind": "sync", "sources": ["kev"], "options": ["kubectl=x"]}),
            json!({"kind": "scan", "collector": "fs"}),
            json!({"kind": "scan", "collector": "fs", "options": null}),
        ] {
            assert!(check_scan_body(&body(b.clone())).is_ok(), "{b}");
        }
    }

    #[test]
    fn get_route_options() {
        assert!(check_discover_opts(&["identity=/k".into(), "sudo=true".into()]).is_ok());
        let e = check_discover_opts(&[
            "ssh_option=x".into(),
            "transport=y".into(),
            "ssh_option=z".into(),
        ])
        .unwrap_err();
        assert_eq!(e.message, "opt: not accepted here: ssh_option, transport");
        assert!(
            e.hint
                .unwrap()
                .starts_with("Allowed: connect_timeout, context, host, identity,")
        );
        let e = check_discover_opts(&["noequals".into()]).unwrap_err();
        assert_eq!(e.message, "opt: expected key=value, got 'noequals'");
        let e = check_docker_opts(&["socket=/var/run/docker.sock".into()]).unwrap_err();
        assert_eq!(e.message, "opt: not accepted here: socket");
        assert_eq!(
            e.hint.unwrap(),
            "Allowed: connect_timeout, identity, timeout, tls_ca, tls_cert, tls_key, tls_verify; use the host, context and all parameters."
        );
        assert!(check_docker_opts(&["tls_verify=true".into()]).is_ok());
        assert!(check_docker_opts(&[]).is_ok());
    }
}
