//! Payload builders ported from `reports.py` / `ops.py` (job payloads, run summaries, scan entries and results,
//! redacted job parameters). Key order follows the Python dicts (`serde_json` `preserve_order`).

use secmonk_model::{JobKind, JobRow, JobStatus};
use secmonk_safeio::{redact_option, scrub_text, strip_url_secrets};
use serde_json::{Map, Value, json};

/// `reports.PRIORITY_KEYS`.
pub const PRIORITY_KEYS: [&str; 4] = ["P1", "P2", "P3", "P4"];
/// `ops.STORED_FINDINGS`: findings kept per target in a stored scan result (and shown per entry).
pub const STORED_FINDINGS: usize = 500;

/// `reports.priority_counts`.
pub fn priority_counts(rows: &[Value]) -> Map<String, Value> {
    let mut c: Map<String, Value> = PRIORITY_KEYS
        .iter()
        .map(|k| ((*k).to_owned(), json!(0)))
        .collect();
    c.insert("kev".into(), json!(0));
    c.insert("total".into(), json!(0));
    let bump = |c: &mut Map<String, Value>, k: &str, by: i64| {
        let n = c.get(k).and_then(Value::as_i64).unwrap_or(0);
        c.insert(k.to_owned(), json!(n + by));
    };
    for f in rows {
        if let Some(p) = f.get("priority").and_then(Value::as_str)
            && PRIORITY_KEYS.contains(&p)
        {
            bump(&mut c, p, 1);
        }
        bump(
            &mut c,
            "kev",
            i64::from(f.get("kev").is_some_and(crate::opts::truthy)),
        );
        bump(&mut c, "total", 1);
    }
    c
}

fn int_of(v: Option<&Value>) -> i64 {
    v.and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
        .unwrap_or(0)
}

/// `reports.job_summary`.
pub fn job_summary(kind: JobKind, result: Option<&Value>) -> Value {
    let Some(Value::Object(r)) = result else {
        return json!({});
    };
    match kind {
        JobKind::Scan => {
            let empty = Vec::new();
            let targets = r.get("targets").and_then(Value::as_array).unwrap_or(&empty);
            let errors = targets
                .iter()
                .filter(|t| t.get("error").is_some_and(crate::opts::truthy))
                .count();
            let mut out = Map::new();
            out.insert("targets".into(), json!(targets.len()));
            out.insert("errors".into(), json!(errors));
            out.insert(
                "components".into(),
                json!(int_of(r.get("stats").and_then(|s| s.get("components")))),
            );
            let counts = r.get("counts");
            for k in PRIORITY_KEYS.iter().copied().chain(["kev", "total"]) {
                out.insert(k.into(), json!(int_of(counts.and_then(|c| c.get(k)))));
            }
            Value::Object(out)
        }
        JobKind::Sync => {
            let empty = Vec::new();
            let sources = r.get("sources").and_then(Value::as_array).unwrap_or(&empty);
            json!({
                "sources": sources.len(),
                "errors": sources.iter().filter(|s| s.get("status").and_then(Value::as_str) == Some("error")).count(),
                "records": sources.iter().map(|s| int_of(s.get("records"))).sum::<i64>(),
            })
        }
    }
}

/// `reports.job_payload`.
#[allow(clippy::too_many_arguments)]
pub fn job_payload(
    id: i64,
    kind: JobKind,
    origin: &str,
    title: Option<&str>,
    params: Option<&Value>,
    started: Option<&str>,
    finished: Option<&str>,
    status: Option<&str>,
    error: Option<&str>,
    result: Option<&Value>,
    log: Option<&[String]>,
    include_log: bool,
    summary: Option<&Value>,
    log_lines: Option<i64>,
) -> Value {
    let params = match params {
        Some(p) if crate::opts::truthy(p) => p.clone(),
        _ => json!({}),
    };
    let mut d = json!({
        "id": id, "kind": kind.as_str(), "origin": origin, "title": title, "params": params,
        "started": started, "finished": finished, "status": status, "error": error, "result": result,
        "summary": summary.cloned().unwrap_or_else(|| job_summary(kind, result)),
        "log_lines": log_lines.unwrap_or(log.map_or(0, |l| l.len() as i64)),
    });
    if include_log {
        d["log"] = json!(log.unwrap_or(&[]));
    }
    d
}

/// `reports.job_dict`: a stored run. A `running` row whose process is gone reads as `error` / `interrupted`.
pub fn job_dict(row: &JobRow, include_log: bool) -> Value {
    let (mut status, mut error) = (row.status.map(JobStatus::as_str), row.error.as_deref());
    if row.status == Some(JobStatus::Running)
        && !secmonk_store::jobs::owner_alive(row.owner.as_ref())
    {
        status = Some("error");
        error = Some("interrupted");
    }
    job_payload(
        row.id,
        row.kind,
        row.origin.as_str(),
        row.title.as_deref(),
        row.params.as_ref(),
        row.started_at.as_deref(),
        row.finished_at.as_deref(),
        status,
        error,
        row.result.as_ref(),
        row.log.as_deref(),
        include_log && row.log.is_some(),
        row.summary.as_ref(),
        Some(row.log_lines),
    )
}

/// `ops.redact_target`: URL password, query and fragment dropped (the user name is kept).
pub fn redact_target(target: Option<&str>) -> Option<String> {
    target.map(|t| {
        if t.contains("://") {
            strip_url_secrets(t, true)
        } else {
            t.to_owned()
        }
    })
}

/// `ops.redact_opt_items`: `key=value` strings with secret values masked.
pub fn redact_opt_items(items: &[String]) -> Vec<String> {
    items
        .iter()
        .map(|item| match item.split_once('=') {
            Some((k, v)) => match redact_option(k, &Value::String(v.to_owned())) {
                Value::String(s) => format!("{k}={s}"),
                other => format!("{k}={other}"),
            },
            None => item.clone(),
        })
        .collect()
}

/// `scrub_text` of an optional text.
pub fn scrub_opt(text: Option<&str>) -> Option<String> {
    text.map(scrub_text)
}

/// `ops._blank_entry`.
pub fn blank_entry(collector: &str, target: Option<&str>) -> Map<String, Value> {
    let v = json!({
        "collector": collector, "target": target, "asset": null, "scan_id": null, "stats": {}, "warnings": [],
        "partial": false, "findings": [], "counts": priority_counts(&[]), "error": null,
        "reused": false, "reused_scan_id": null, "tags": [],
    });
    match v {
        Value::Object(m) => m,
        _ => unreachable!("json! object"),
    }
}

/// `ops._image_facts`: tags and requested refs of an image asset on its entry.
pub fn image_facts(entry: &mut Map<String, Value>, meta: &Map<String, Value>) {
    if let Some(Value::Array(tags)) = meta.get("tags") {
        entry.insert(
            "tags".into(),
            Value::Array(tags.iter().filter(|t| t.is_string()).cloned().collect()),
        );
    }
    if let Some(Value::Array(refs)) = meta.get("requested_refs")
        && !refs.is_empty()
    {
        entry.insert(
            "requested_refs".into(),
            Value::Array(refs.iter().filter(|t| t.is_string()).cloned().collect()),
        );
    }
}

/// The `say` line after a match: `"<v> <k with spaces>"` joined by ` · `.
pub fn stats_line(stats: &Value) -> String {
    stats
        .as_object()
        .map(|m| {
            m.iter()
                .map(|(k, v)| format!("{v} {}", k.replace('_', " ")))
                .collect::<Vec<_>>()
                .join(" · ")
        })
        .unwrap_or_default()
}

/// `ops.scan_result`: per-target entries -> (status, result, error).
pub fn scan_result(
    entries: Vec<Map<String, Value>>,
    saved: bool,
) -> (JobStatus, Value, Option<String>) {
    let mut stats = Map::new();
    let mut counts = priority_counts(&[]);
    let add = |m: &mut Map<String, Value>, k: &str, v: &Value| {
        let next = match (m.get(k), v) {
            (Some(prev), v) if prev.is_i64() && v.is_i64() => {
                json!(prev.as_i64().unwrap_or(0) + v.as_i64().unwrap_or(0))
            }
            (Some(prev), v) => json!(prev.as_f64().unwrap_or(0.0) + v.as_f64().unwrap_or(0.0)),
            (None, v) => v.clone(),
        };
        m.insert(k.to_owned(), next);
    };
    for e in &entries {
        if let Some(Value::Object(s)) = e.get("stats") {
            for (k, v) in s {
                if v.is_number() {
                    add(&mut stats, k, v);
                }
            }
        }
        if let Some(Value::Object(c)) = e.get("counts") {
            for (k, v) in c {
                add(&mut counts, k, v);
            }
        }
    }
    let failed: Vec<&str> = entries
        .iter()
        .filter_map(|e| {
            e.get("error")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
        })
        .collect();
    let (status, error) = if !entries.is_empty() && failed.len() == entries.len() {
        let msg = if failed.len() == 1 {
            failed[0].to_owned()
        } else {
            format!("all {} targets failed: {}", failed.len(), failed[0])
        };
        (JobStatus::Error, Some(msg))
    } else if !failed.is_empty()
        || entries
            .iter()
            .any(|e| e.get("partial").is_some_and(crate::opts::truthy))
    {
        (JobStatus::Partial, None)
    } else {
        (JobStatus::Ok, None)
    };
    let result = json!({"saved": saved, "targets": entries, "stats": stats, "counts": counts});
    (status, result, error)
}

/// `ops.sync_status`.
pub fn sync_status(entries: &[Value]) -> JobStatus {
    let has = |s: &str| {
        entries
            .iter()
            .any(|e| e.get("status").and_then(Value::as_str) == Some(s))
    };
    if has("error") {
        JobStatus::Error
    } else if has("partial") {
        JobStatus::Partial
    } else {
        JobStatus::Ok
    }
}

/// `ops.stored_result`: per-target findings capped at `STORED_FINDINGS`, target errors scrubbed.
pub fn stored_result(kind: JobKind, result: Option<&Value>) -> Option<Value> {
    let r = result?;
    let (JobKind::Scan, Value::Object(map)) = (kind, r) else {
        return Some(r.clone());
    };
    let mut out = map.clone();
    let targets: Vec<Value> = map
        .get("targets")
        .and_then(Value::as_array)
        .map(|ts| {
            ts.iter()
                .map(|t| {
                    let mut t = t.as_object().cloned().unwrap_or_default();
                    let findings: Vec<Value> = t
                        .get("findings")
                        .and_then(Value::as_array)
                        .map(|f| f.iter().take(STORED_FINDINGS).cloned().collect())
                        .unwrap_or_default();
                    t.insert("findings".into(), Value::Array(findings));
                    let err = scrub_opt(t.get("error").and_then(Value::as_str));
                    t.insert("error".into(), json!(err));
                    Value::Object(t)
                })
                .collect()
        })
        .unwrap_or_default();
    out.insert("targets".into(), Value::Array(targets));
    Some(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_and_summaries() {
        let rows = vec![
            json!({"priority": "P1", "kev": true}),
            json!({"priority": "P3", "kev": false}),
        ];
        assert_eq!(
            Value::Object(priority_counts(&rows)),
            json!({"P1": 1, "P2": 0, "P3": 1, "P4": 0, "kev": 1, "total": 2})
        );
        let mut e1 = blank_entry("fs", Some("/x"));
        e1.insert("stats".into(), json!({"components": 3, "matches": 1}));
        e1.insert("counts".into(), Value::Object(priority_counts(&rows)));
        let mut e2 = blank_entry("fs", Some("/y"));
        e2.insert("error".into(), json!("RuntimeError: boom"));
        let (status, result, error) = scan_result(vec![e1, e2], true);
        assert_eq!((status, error), (JobStatus::Partial, None));
        assert_eq!(result["stats"], json!({"components": 3, "matches": 1}));
        let s = job_summary(JobKind::Scan, Some(&result));
        assert_eq!(
            s,
            json!({"targets": 2, "errors": 1, "components": 3, "P1": 1, "P2": 0, "P3": 1, "P4": 0, "kev": 1, "total": 2})
        );
        let mut e3 = blank_entry("fs", None);
        e3.insert("error".into(), json!("x"));
        let mut e4 = e3.clone();
        e4.insert("error".into(), json!("y"));
        let (status, _, error) = scan_result(vec![e3, e4], false);
        assert_eq!(
            (status, error.as_deref()),
            (JobStatus::Error, Some("all 2 targets failed: x"))
        );
        assert_eq!(
            job_summary(
                JobKind::Sync,
                Some(
                    &json!({"sources": [{"status": "error", "records": 2}, {"status": "ok", "records": 5}]})
                )
            ),
            json!({"sources": 2, "errors": 1, "records": 7})
        );
        assert_eq!(job_summary(JobKind::Sync, None), json!({}));
    }

    #[test]
    fn redaction_of_params() {
        assert_eq!(
            redact_target(Some("ssh://me:pw@host/x?token=1")).as_deref(),
            Some("ssh://me@host/x")
        );
        assert_eq!(
            redact_opt_items(&["password=hunter2".into(), "plain".into()])[1],
            "plain"
        );
        assert_ne!(
            redact_opt_items(&["password=hunter2".into()])[0],
            "password=hunter2"
        );
    }

    #[test]
    fn stored_results_are_capped() {
        let findings: Vec<Value> = (0..600).map(|i| json!({"n": i})).collect();
        let r = json!({"saved": true, "targets": [{"findings": findings, "error": "see https://u:p@h/x"}]});
        let s = stored_result(JobKind::Scan, Some(&r)).unwrap();
        assert_eq!(s["targets"][0]["findings"].as_array().unwrap().len(), 500);
        assert!(!s["targets"][0]["error"].as_str().unwrap().contains("u:p"));
    }
}
