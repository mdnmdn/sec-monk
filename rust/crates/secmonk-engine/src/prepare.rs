//! Validation of `POST /api/jobs` bodies, in the request (ports of `web/jobs.py` `_prepare_sync`, `_prepare_scan`,
//! `_prepare_batch`, `_web_item`, `_scan_common` and `ops.scan_item`, `scan_params`, `batch_params`, titles). The
//! result is a [`Plan`]: title, redacted parameters (what is shown and stored) and the work to run.

use std::collections::BTreeSet;

use secmonk_model::JobKind;
use serde_json::{Map, Value, json};

use crate::error::{EngineError, ErrorKind, py_repr};
use crate::opts::{opt_str, parse_opts, py_repr_value, splitlines, str_list, truthy};
use crate::payload::{redact_opt_items, redact_target};

/// `ops.MAX_ITEMS`: items of one host-mode batch scan.
pub const MAX_ITEMS: usize = 20;
/// `web/jobs.WEB_FORBIDDEN_SCAN_OPTS`: collector options a browser-started scan may not set.
pub const WEB_FORBIDDEN_SCAN_OPTS: [&str; 5] = [
    "ssh_bin",
    "transport",
    "ssh_option",
    "kubectl",
    "ssh_config",
];
/// `ops.SYNC_ALL_ORDER` (used when no source module reports an order).
pub const SYNC_ALL_ORDER: [&str; 8] = [
    "kev",
    "epss",
    "osv",
    "cvelist",
    "nvd",
    "euvd",
    "msrc",
    "debian-tracker",
];

/// One collector run of a scan (`ops.ScanItem`): `options` as given (stripped `key=value` strings), `opts` parsed.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanItem {
    pub collector: String,
    pub target: Option<String>,
    pub options: Vec<String>,
    pub opts: Map<String, Value>,
    /// Host mode: the discover candidate id.
    pub id: Option<String>,
}

/// A scan run.
#[derive(Debug, Clone, PartialEq)]
pub struct ScanPlan {
    pub items: Vec<ScanItem>,
    pub save: bool,
    pub min_confidence: f64,
    /// A single-collector scan: an expansion error is the run's error.
    pub strict_expand: bool,
}

/// A sync run.
#[derive(Debug, Clone, PartialEq)]
pub struct SyncPlan {
    pub sources: Vec<String>,
    pub ecosystems: Vec<String>,
    pub since: Option<String>,
    pub full: bool,
    pub limit: Option<u64>,
    pub path: Option<String>,
}

/// What a job runs.
#[derive(Debug, Clone, PartialEq)]
pub enum Work {
    Scan(ScanPlan),
    Sync(SyncPlan),
}

/// A validated job.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    pub kind: JobKind,
    pub title: String,
    pub params: Value,
    pub work: Work,
}

/// What validation needs to know about this engine.
#[derive(Debug, Clone)]
pub struct Registry<'a> {
    /// Collector names (probe allowlist).
    pub collectors: &'a BTreeSet<String>,
    /// Source name -> in `sync all`.
    pub sources: &'a [(String, bool)],
    /// `sync all` order.
    pub sync_all_order: &'a [String],
    /// `[engine] min_confidence`.
    pub min_confidence: f64,
    /// Whether the store is initialized (a scan without saving needs a database).
    pub db_exists: bool,
    /// For the `no database at <path>` message.
    pub state_db: &'a str,
}

fn bad(msg: impl Into<String>) -> EngineError {
    EngineError::invalid(msg)
}

fn joined<'a>(names: impl IntoIterator<Item = &'a String>) -> String {
    names
        .into_iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

/// `JobRunner.start` minus the history row: validate the body into a plan.
pub fn prepare(body: &Map<String, Value>, reg: &Registry<'_>) -> Result<Plan, EngineError> {
    match body.get("kind").and_then(Value::as_str) {
        Some("sync") => prepare_sync(body, reg),
        Some("scan") if body.get("items").is_some_and(|v| !v.is_null()) => prepare_batch(body, reg),
        Some("scan") => prepare_scan(body, reg),
        _ => Err(bad("kind: expected 'sync' or 'scan'")),
    }
}

/// `ops.expand_sources`: `all` -> every source with `in_all` (`sync_all_order` first); duplicates dropped.
pub fn expand_sources(names: &[String], reg: &Registry<'_>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for n in names {
        if n == "all" {
            let known: Vec<&String> = reg.sources.iter().map(|(n, _)| n).collect();
            let mut ordered: Vec<String> = reg
                .sync_all_order
                .iter()
                .filter(|x| known.contains(x))
                .cloned()
                .collect();
            let mut rest: Vec<String> = known
                .iter()
                .filter(|x| !reg.sync_all_order.contains(x))
                .map(|x| (*x).clone())
                .collect();
            rest.sort();
            ordered.extend(rest);
            out.extend(
                ordered
                    .into_iter()
                    .filter(|x| reg.sources.iter().any(|(n, in_all)| n == x && *in_all)),
            );
        } else {
            out.push(n.clone());
        }
    }
    let mut seen = BTreeSet::new();
    out.retain(|x| seen.insert(x.clone()));
    out
}

fn prepare_sync(body: &Map<String, Value>, reg: &Registry<'_>) -> Result<Plan, EngineError> {
    let names = expand_sources(&str_list(body.get("sources"), "sources").map_err(bad)?, reg);
    if names.is_empty() {
        return Err(bad("sources: choose at least one source (or 'all')"));
    }
    let unknown: Vec<&String> = names
        .iter()
        .filter(|n| !reg.sources.iter().any(|(s, _)| s == *n))
        .collect();
    if !unknown.is_empty() {
        let mut known: Vec<&String> = reg.sources.iter().map(|(n, _)| n).collect();
        known.sort();
        return Err(bad(format!(
            "unknown source {} (known: {})",
            joined(unknown),
            joined(known)
        )));
    }
    let limit = match body.get("limit") {
        None | Some(Value::Null) => None,
        Some(v) => match v.as_u64() {
            Some(n) if n >= 1 => Some(n),
            _ => return Err(bad("limit: expected a positive integer")),
        },
    };
    let path = opt_str(body.get("path"), "path").map_err(bad)?;
    if let Some(p) = &path
        && !crate::opts::expand_user(p).exists()
    {
        return Err(bad(format!(
            "path: {p} does not exist (on the machine running secmonk ui)"
        )));
    }
    let ecosystems = str_list(body.get("ecosystems"), "ecosystems").map_err(bad)?;
    let since = opt_str(body.get("since"), "since").map_err(bad)?;
    let full = body.get("full").is_some_and(truthy);
    let params = json!({
        "sources": names, "ecosystems": ecosystems, "since": since, "full": full, "limit": limit, "path": path,
    });
    Ok(Plan {
        kind: JobKind::Sync,
        title: format!("sync {}", names.join(", ")),
        params,
        work: Work::Sync(SyncPlan {
            sources: names,
            ecosystems,
            since,
            full,
            limit,
            path,
        }),
    })
}

/// `_scan_common`: (save, min_confidence).
fn scan_common(body: &Map<String, Value>, reg: &Registry<'_>) -> Result<(bool, f64), EngineError> {
    let save = body.get("save") != Some(&Value::Bool(false));
    let mc = match body.get("min_confidence") {
        None => reg.min_confidence,
        Some(Value::Number(n)) => n.as_f64().unwrap_or(-1.0),
        Some(_) => -1.0,
    };
    if !(0.0..=1.0).contains(&mc) {
        return Err(bad("min_confidence: expected a number between 0 and 1"));
    }
    if !save && !reg.db_exists {
        return Err(EngineError::new(ErrorKind::Busy, format!("no database at {}", reg.state_db))
            .with_hint("A scan without saving needs an existing mirror: sync first, or keep 'Save' on."));
    }
    Ok((save, mc))
}

fn is_slug(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

/// `ops.scan_item`: `Err` = the `ValueError` text.
pub fn scan_item(
    collector: Option<&Value>,
    target: Option<&Value>,
    options: Option<&Value>,
    id: Option<&Value>,
    collectors: &BTreeSet<String>,
) -> Result<ScanItem, String> {
    let id = match id {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if is_slug(s) => Some(s.clone()),
        Some(other) => {
            let msg = format!(
                "id: expected a short slug (a-z, 0-9, . _ -), got {}",
                py_repr_value(other)
            );
            return Err(msg.chars().take(120).collect());
        }
    };
    let collector = match collector {
        Some(Value::String(c)) if collectors.contains(c) => c.clone(),
        other => {
            return Err(format!(
                "unknown collector {} (known: {})",
                other.map_or_else(|| "None".to_owned(), py_repr_value),
                joined(collectors)
            ));
        }
    };
    let target = match target {
        None | Some(Value::Null) => None,
        Some(Value::String(t)) => Some(t.clone()),
        Some(_) => return Err(format!("{collector}: target must be a string")),
    };
    let raw: Vec<String> = match options {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::String(s)) => splitlines(s).into_iter().map(str::to_owned).collect(),
        Some(Value::Array(a)) if a.iter().all(Value::is_string) => a
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect(),
        Some(_) => {
            return Err(format!(
                "{collector}: options must be a list of key=value strings"
            ));
        }
    };
    let options: Vec<String> = raw
        .iter()
        .map(|x| x.trim())
        .filter(|x| !x.is_empty())
        .map(str::to_owned)
        .collect();
    let opts = parse_opts(&options).map_err(|e| format!("{collector}: {e}"))?;
    let target = target
        .map(|t| t.trim().to_owned())
        .filter(|t| !t.is_empty());
    Ok(ScanItem {
        collector,
        target,
        options,
        opts,
        id,
    })
}

/// `_web_item`: `scan_item` + the browser policy; errors are 400 prefixed with `where_`.
fn web_item(
    collector: Option<&Value>,
    target: Option<&Value>,
    options: Option<&Value>,
    where_: &str,
    id: Option<&Value>,
    reg: &Registry<'_>,
) -> Result<ScanItem, EngineError> {
    let item = scan_item(collector, target, options, id, reg.collectors)
        .map_err(|e| bad(format!("{where_}: {e}")))?;
    let mut forbidden: Vec<&str> = item
        .opts
        .keys()
        .map(String::as_str)
        .filter(|k| WEB_FORBIDDEN_SCAN_OPTS.contains(k))
        .collect();
    forbidden.sort_unstable();
    if !forbidden.is_empty() {
        return Err(bad(format!(
            "{where_}: option not accepted from the browser: {}",
            forbidden.join(", ")
        ))
        .with_hint(
            "Run scans that need a custom ssh binary, transport, ssh_option, ssh_config or kubectl with \
             the secmonk CLI.",
        ));
    }
    Ok(item)
}

fn prepare_scan(body: &Map<String, Value>, reg: &Registry<'_>) -> Result<Plan, EngineError> {
    let collector = opt_str(body.get("collector"), "collector").map_err(bad)?;
    let collector = match collector {
        Some(c) if reg.collectors.contains(&c) => c,
        _ => {
            return Err(bad(format!(
                "collector: expected one of {}",
                joined(reg.collectors)
            )));
        }
    };
    let target = opt_str(body.get("target"), "target").map_err(bad)?;
    let raw_opts: Vec<String> = match body.get("options") {
        Some(v @ Value::Array(_)) => str_list(Some(v), "options").map_err(bad)?,
        other => splitlines(&opt_str(other, "options").map_err(bad)?.unwrap_or_default())
            .into_iter()
            .map(str::trim)
            .filter(|x| !x.is_empty())
            .map(str::to_owned)
            .collect(),
    };
    let item = web_item(
        Some(&Value::String(collector.clone())),
        target.as_ref().map(|t| Value::String(t.clone())).as_ref(),
        Some(&json!(raw_opts)),
        "options",
        None,
        reg,
    )?;
    let (save, mc) = scan_common(body, reg)?;
    let shown = redact_target(target.as_deref());
    let params = json!({
        "collector": collector, "target": shown, "options": redact_opt_items(&raw_opts),
        "save": save, "min_confidence": mc,
    });
    let title = match &shown {
        Some(t) if !t.is_empty() => format!("scan {collector} {t}"),
        _ => format!("scan {collector}"),
    };
    Ok(Plan {
        kind: JobKind::Scan,
        title,
        params,
        work: Work::Scan(ScanPlan {
            items: vec![item],
            save,
            min_confidence: mc,
            strict_expand: true,
        }),
    })
}

fn prepare_batch(body: &Map<String, Value>, reg: &Registry<'_>) -> Result<Plan, EngineError> {
    let raw = match body.get("items") {
        Some(Value::Array(a)) if !a.is_empty() => a,
        _ => {
            return Err(bad(
                "items: expected a non-empty list of {collector, target, options}",
            ));
        }
    };
    if raw.len() > MAX_ITEMS {
        return Err(bad(format!("items: at most {MAX_ITEMS} per scan")));
    }
    let mut items = Vec::with_capacity(raw.len());
    for (n, it) in raw.iter().enumerate() {
        let n = n + 1;
        let Some(it) = it.as_object() else {
            return Err(bad(format!(
                "items[{n}]: expected an object {{collector, target, options}}"
            )));
        };
        items.push(web_item(
            it.get("collector"),
            it.get("target"),
            it.get("options"),
            &format!("items[{n}]"),
            it.get("id"),
            reg,
        )?);
    }
    let host = opt_str(body.get("host"), "host").map_err(bad)?;
    let (save, mc) = scan_common(body, reg)?;
    let host_shown = redact_target(host.as_deref()).unwrap_or_else(|| "local".into());
    let host_shown = if host_shown.is_empty() {
        "local".into()
    } else {
        host_shown
    };
    let params = json!({
        "mode": "host", "host": host_shown,
        "items": items.iter().map(|i| json!({
            "id": i.id, "collector": i.collector, "target": redact_target(i.target.as_deref()),
            "options": redact_opt_items(&i.options),
        })).collect::<Vec<_>>(),
        "save": save, "min_confidence": mc,
    });
    let mut names: Vec<&str> = Vec::new();
    for i in &items {
        let n = i.id.as_deref().unwrap_or(&i.collector);
        if !names.contains(&n) {
            names.push(n);
        }
    }
    let title = format!("scan host {host_shown}: {}", names.join(", "));
    Ok(Plan {
        kind: JobKind::Scan,
        title,
        params,
        work: Work::Scan(ScanPlan {
            items,
            save,
            min_confidence: mc,
            strict_expand: false,
        }),
    })
}

/// `{x!r}` of an optional target in messages (`None` -> `None`).
pub fn repr_target(t: Option<&str>) -> String {
    t.map_or_else(|| "None".into(), py_repr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg<'a>(c: &'a BTreeSet<String>, s: &'a [(String, bool)], o: &'a [String]) -> Registry<'a> {
        Registry {
            collectors: c,
            sources: s,
            sync_all_order: o,
            min_confidence: 0.5,
            db_exists: false,
            state_db: "/d/state.sqlite3",
        }
    }

    fn body(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn fixtures() -> (BTreeSet<String>, Vec<(String, bool)>, Vec<String>) {
        (
            ["fs", "docker-engine", "macos"]
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
            vec![
                ("osv".into(), true),
                ("kev".into(), true),
                ("nvd".into(), false),
                ("zzz".into(), true),
            ],
            SYNC_ALL_ORDER.iter().map(|s| (*s).to_owned()).collect(),
        )
    }

    #[test]
    fn sync_bodies() {
        let (c, s, o) = fixtures();
        let r = reg(&c, &s, &o);
        let p = prepare(&body(json!({"kind": "sync", "sources": "all"})), &r).unwrap();
        assert_eq!(p.title, "sync kev, osv, zzz");
        assert_eq!(
            p.params,
            json!({"sources": ["kev", "osv", "zzz"], "ecosystems": [], "since": null, "full": false, "limit": null, "path": null})
        );
        let e = prepare(&body(json!({"kind": "sync", "sources": ["bogus"]})), &r).unwrap_err();
        assert_eq!(
            e.message,
            "unknown source bogus (known: kev, nvd, osv, zzz)"
        );
        let e = prepare(&body(json!({"kind": "sync", "sources": []})), &r).unwrap_err();
        assert_eq!(e.message, "sources: choose at least one source (or 'all')");
        let e = prepare(
            &body(json!({"kind": "sync", "sources": "kev", "limit": 1.5})),
            &r,
        )
        .unwrap_err();
        assert_eq!(e.message, "limit: expected a positive integer");
        let e = prepare(
            &body(json!({"kind": "sync", "sources": "kev", "path": "/no/such/dir/x"})),
            &r,
        )
        .unwrap_err();
        assert!(e.message.starts_with("path: /no/such/dir/x does not exist"));
        let e = prepare(&body(json!({"kind": "nope"})), &r).unwrap_err();
        assert_eq!(e.message, "kind: expected 'sync' or 'scan'");
    }

    #[test]
    fn scan_bodies() {
        let (c, s, o) = fixtures();
        let r = reg(&c, &s, &o);
        let p = prepare(
            &body(json!({"kind": "scan", "collector": "fs", "target": " ssh://u:pw@h/x ", "options": "a=1\n\n token=s3cret "})),
            &r,
        )
        .unwrap();
        assert_eq!(p.title, "scan fs ssh://u@h/x");
        assert_eq!(p.params["options"][0], "a=1");
        assert_ne!(p.params["options"][1], "token=s3cret");
        assert_eq!(p.params["min_confidence"], json!(0.5));
        let Work::Scan(plan) = &p.work else { panic!() };
        assert!(plan.strict_expand && plan.save);
        assert_eq!(
            plan.items[0].target.as_deref(),
            Some("ssh://u:pw@h/x"),
            "the run gets the real target"
        );
        let e = prepare(&body(json!({"kind": "scan", "collector": "nope"})), &r).unwrap_err();
        assert_eq!(
            e.message,
            "collector: expected one of docker-engine, fs, macos"
        );
        let e = prepare(
            &body(json!({"kind": "scan", "collector": "fs", "options": ["ssh_bin=/x"]})),
            &r,
        )
        .unwrap_err();
        assert_eq!(
            e.message,
            "options: option not accepted from the browser: ssh_bin"
        );
        let e = prepare(
            &body(json!({"kind": "scan", "collector": "fs", "options": ["novalue"]})),
            &r,
        )
        .unwrap_err();
        assert_eq!(e.message, "options: fs: expected key=value, got 'novalue'");
        let e = prepare(
            &body(json!({"kind": "scan", "collector": "fs", "min_confidence": true})),
            &r,
        )
        .unwrap_err();
        assert_eq!(
            e.message,
            "min_confidence: expected a number between 0 and 1"
        );
        let e = prepare(
            &body(json!({"kind": "scan", "collector": "fs", "save": false})),
            &r,
        )
        .unwrap_err();
        assert_eq!(
            (e.kind, e.message.as_str()),
            (ErrorKind::Busy, "no database at /d/state.sqlite3")
        );
    }

    #[test]
    fn batch_bodies() {
        let (c, s, o) = fixtures();
        let r = reg(&c, &s, &o);
        let p = prepare(
            &body(json!({"kind": "scan", "host": "me@box", "items": [
                {"id": "docker", "collector": "docker-engine", "target": "web"},
                {"id": "docker", "collector": "docker-engine", "target": "image:*"},
                {"collector": "fs", "target": "/srv", "options": ["exclude=a,b"]}]})),
            &r,
        )
        .unwrap();
        assert_eq!(p.title, "scan host me@box: docker, fs");
        assert_eq!(p.params["mode"], "host");
        assert_eq!(
            p.params["items"][2],
            json!({"id": null, "collector": "fs", "target": "/srv", "options": ["exclude=a,b"]})
        );
        let e = prepare(&body(json!({"kind": "scan", "items": []})), &r).unwrap_err();
        assert_eq!(
            e.message,
            "items: expected a non-empty list of {collector, target, options}"
        );
        let e = prepare(&body(json!({"kind": "scan", "items": [1]})), &r).unwrap_err();
        assert_eq!(
            e.message,
            "items[1]: expected an object {collector, target, options}"
        );
        let e = prepare(
            &body(json!({"kind": "scan", "items": [{"collector": "fs", "id": "Bad Id"}]})),
            &r,
        )
        .unwrap_err();
        assert_eq!(
            e.message,
            "items[1]: id: expected a short slug (a-z, 0-9, . _ -), got 'Bad Id'"
        );
        let e = prepare(
            &body(json!({"kind": "scan", "items": [{"collector": null}]})),
            &r,
        )
        .unwrap_err();
        assert_eq!(
            e.message,
            "items[1]: unknown collector None (known: docker-engine, fs, macos)"
        );
        let many: Vec<Value> = (0..21).map(|_| json!({"collector": "fs"})).collect();
        let e = prepare(&body(json!({"kind": "scan", "items": many})), &r).unwrap_err();
        assert_eq!(e.message, "items: at most 20 per scan");
    }
}
