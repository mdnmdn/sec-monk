//! CISA Known Exploited Vulnerabilities, native (rust ADR-0011). Port of `src/secmonk/sources/kev.py` plus the
//! `source_sync` bookkeeping of `ops.sync_source` / `db.set_sync_state`; reference: `py-sources` (differential test
//! `secmonk-engine/tests/real_modules.rs`). Doc: `rust/_docs/tech/source-kev.md`.
//!
//! The feed is a small full snapshot. A sync reads it (official CISA URL, the `cisagov/kev-data` GitHub mirror on any
//! error, or `--path`), refuses a snapshot that is empty or under half of the stored rows unless `full`, and emits:
//! a `delete` for every stored `kev` row whose CVE left the feed, a `raw_record` and a `kev` upsert per entry, then the
//! `source_sync` upsert. `limit` upserts a subset and deletes nothing (`partial`). The resulting mirror equals what
//! the Python source leaves after its `DELETE FROM kev` + `INSERT OR REPLACE` (raw records of removed CVEs stay, as
//! there).

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use futures_util::StreamExt;
use secmonk_model::{JsonMap, MirrorTable, RowOp, SyncEntry};
use secmonk_traits::{
    CallCtx, ErrorCode, MirrorView, NATIVE_GENERATION, ProgressUpdate, ResultStream, RowsBatch,
    Source, SourceInfo, StepResult, StreamMsg, SyncEnd, SyncParams, WireError,
};
use serde_json::{Value, json};

use crate::batch::{self, Limits};
use crate::feed;

/// Source name.
pub const NAME: &str = "kev";
/// Description (as the Python source's).
pub const DESCRIPTION: &str = "CISA Known Exploited Vulnerabilities catalog (full snapshot)";
/// The official feed.
pub const OFFICIAL_URL: &str =
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
/// The GitHub mirror, tried when the official feed fails.
pub const MIRROR_URL: &str =
    "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json";
/// Largest feed accepted (the real one is about 1.5 MB in 2026).
pub const MAX_FEED_BYTES: u64 = 32 * 1024 * 1024;

/// Fields with a dedicated column; everything else goes to `kev.extra`.
const MAPPED: [&str; 7] = [
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "dueDate",
    "knownRansomwareCampaignUse",
];

/// The native KEV source.
pub struct KevSource {
    view: Arc<dyn MirrorView>,
    official: String,
    mirror: String,
    limits: Limits,
    max_bytes: u64,
}

impl std::fmt::Debug for KevSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KevSource")
            .field("official", &self.official)
            .field("mirror", &self.mirror)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl KevSource {
    /// The source over a read-only view of the mirror.
    pub fn new(view: Arc<dyn MirrorView>) -> KevSource {
        KevSource {
            view,
            official: OFFICIAL_URL.into(),
            mirror: MIRROR_URL.into(),
            limits: Limits::default(),
            max_bytes: MAX_FEED_BYTES,
        }
    }

    /// Other feed URLs (tests: a local server; `http://` is then allowed).
    pub fn with_urls(mut self, official: &str, mirror: &str) -> KevSource {
        self.official = official.into();
        self.mirror = mirror.into();
        self
    }

    /// Other batch limits (tests: several batches out of a small fixture).
    pub fn with_limits(mut self, limits: Limits) -> KevSource {
        self.limits = limits;
        self
    }

    /// Another size cap of the feed.
    pub fn with_max_bytes(mut self, max_bytes: u64) -> KevSource {
        self.max_bytes = max_bytes;
        self
    }

    fn allow_http(&self) -> bool {
        !(self.official.starts_with("https://") && self.mirror.starts_with("https://"))
    }

    /// `_load`: the feed document and its origin. Official feed first, the mirror on any error.
    async fn load(&self, path: Option<&str>, ctx: &CallCtx) -> Result<(Value, String), String> {
        if let Some(p) = path {
            let p = PathBuf::from(p);
            let doc = feed::read_json(&p, self.max_bytes).await?;
            return Ok((doc, format!("from file {}", feed::py_path(&p))));
        }
        let http = self.allow_http();
        match feed::download_json(&self.official, self.max_bytes, http).await {
            Ok(doc) => Ok((doc, format!("from {}", self.official))),
            Err(official_err) => {
                ctx.report(ProgressUpdate {
                    message: Some(format!(
                        "kev: official feed failed ({official_err}); trying mirror"
                    )),
                    ..Default::default()
                });
                let doc = feed::download_json(&self.mirror, self.max_bytes, http).await?;
                Ok((
                    doc,
                    format!(
                        "from mirror {} (official failed: {official_err})",
                        self.mirror
                    ),
                ))
            }
        }
    }

    /// One sync: the batches and the run's end. Infrastructure failures (the mirror view) are wire errors; feed
    /// problems are an `error` entry with its `source_sync` row, as `ops.sync_source` records them.
    async fn run(
        &self,
        params: &SyncParams,
        ctx: &CallCtx,
    ) -> StepResult<(Vec<RowsBatch>, SyncEnd)> {
        let t0 = Instant::now();
        let opts = &params.options;
        let limit = opts.limit.flatten();
        if limit == Some(0) {
            return Err(WireError::new(
                ErrorCode::InvalidParams,
                "options.limit: expected >= 1",
            ));
        }
        let path = opts.path.clone().flatten().filter(|p| !p.is_empty());
        let full = opts.full.unwrap_or(false);
        let outcome = match self.load(path.as_deref(), ctx).await {
            Ok((doc, origin)) => self.rows(&doc, &origin, limit, full, ctx).await?,
            Err(message) => Outcome::error(message),
        };
        let base = self
            .view
            .applied(NAME)
            .await?
            .filter(|a| a.generation.as_deref() == Some(NATIVE_GENERATION))
            .map_or(0, |a| a.seq);
        let now = secmonk_model::time::now_iso();
        let message = outcome.message.as_deref().map(feed::scrub);
        let mut ops = outcome.ops;
        ops.push(sync_row(
            &outcome.status,
            outcome.records,
            outcome.cursor,
            message.clone(),
            &now,
        ));
        let n_ops = ops.len() as u64;
        let batches = batch::cut(NAME, ops, base + 1, self.limits);
        let end = SyncEnd {
            entry: SyncEntry {
                source: NAME.into(),
                status: outcome.status,
                records: outcome.records,
                seconds: (t0.elapsed().as_secs_f64() * 10.0).round() / 10.0,
                message,
            },
            batches: batches.len() as u64,
            last_seq: batches.last().map_or(0, |b| b.seq),
            ops: n_ops,
        };
        Ok((batches, end))
    }

    /// `KevSource.sync` of the Python source: the rows of a loaded document (or the error entry).
    async fn rows(
        &self,
        doc: &Value,
        origin: &str,
        limit: Option<u64>,
        full: bool,
        ctx: &CallCtx,
    ) -> StepResult<Outcome> {
        let Some(all) = doc.get("vulnerabilities") else {
            return Ok(Outcome::error("'vulnerabilities'".into())); // str(KeyError) of the Python source
        };
        let Some(all) = all.as_array() else {
            return Ok(Outcome::error(
                "kev: 'vulnerabilities' is not a list".into(),
            ));
        };
        match doc.get("count") {
            None | Some(Value::Null) => {}
            Some(c) if c.as_u64() == Some(all.len() as u64) => {}
            Some(c) => ctx.report(ProgressUpdate {
                message: Some(format!(
                    "kev: feed count {} != {} entries; using entries",
                    py_str(c),
                    all.len()
                )),
                ..Default::default()
            }),
        }
        let entries: &[Value] = match limit {
            Some(n) => &all[..all.len().min(usize::try_from(n).unwrap_or(usize::MAX))],
            None => all,
        };
        let limited = limit.is_some();
        if !limited && let Some(refusal) = self.snapshot_guard(entries.len() as u64, full).await? {
            return Ok(Outcome::error(format!("kev: {refusal}")));
        }
        let now = secmonk_model::time::now_iso();
        let mut upserts: Vec<RowOp> = Vec::with_capacity(entries.len() * 2);
        let mut seen: HashSet<String> = HashSet::with_capacity(entries.len());
        for e in entries {
            match entry_rows(e, &now) {
                Ok((cve, raw, kev)) => {
                    upserts.push(raw);
                    upserts.push(kev);
                    seen.insert(cve);
                }
                Err(m) => return Ok(Outcome::error(m)),
            }
        }
        let mut ops: Vec<RowOp> = Vec::new();
        if !limited {
            // `DELETE FROM kev` + re-insert, as the difference against the stored rows
            for key in self.view.row_keys(MirrorTable::Kev, NAME).await? {
                let gone = key
                    .get("cve_id")
                    .and_then(Value::as_str)
                    .is_some_and(|c| !seen.contains(c));
                if gone {
                    ops.push(RowOp::Delete {
                        table: MirrorTable::Kev,
                        key,
                    });
                }
            }
        }
        ops.extend(upserts);
        Ok(Outcome {
            status: if limited { "partial" } else { "ok" }.into(),
            records: entries.len() as u64,
            cursor: if limited {
                None
            } else {
                doc.get("catalogVersion").and_then(cursor_text)
            },
            message: Some(format!("{} entries {origin}", entries.len())),
            ops,
        })
    }

    /// `base.snapshot_guard` on the `kev` table.
    async fn snapshot_guard(&self, new_count: u64, full: bool) -> StepResult<Option<String>> {
        if full {
            return Ok(None);
        }
        let old = self.view.count_rows(MirrorTable::Kev, NAME).await?;
        if new_count == 0 {
            return Ok(Some(
                "refusing to replace the data with an empty snapshot (use --full to force)".into(),
            ));
        }
        if old > 0 && new_count * 2 < old {
            return Ok(Some(format!(
                "refusing to replace {old} rows with a snapshot of only {new_count} (< 50%; use --full to force)"
            )));
        }
        Ok(None)
    }
}

/// What one run produced before batching.
struct Outcome {
    status: String,
    records: u64,
    cursor: Option<String>,
    message: Option<String>,
    ops: Vec<RowOp>,
}

impl Outcome {
    /// A failed run: no rows, only the `source_sync` status (`set_sync_state` keeps the last good totals).
    fn error(message: String) -> Outcome {
        Outcome {
            status: "error".into(),
            records: 0,
            cursor: None,
            message: Some(message),
            ops: Vec::new(),
        }
    }
}

fn obj(v: Value) -> JsonMap {
    match v {
        Value::Object(m) => m,
        _ => JsonMap::new(),
    }
}

/// `db.set_sync_state` as a row operation. ok/partial: `last_sync` = now, the cursor only when there is one (the
/// SQL's `COALESCE(excluded.cursor, cursor)`), records, status, message. error: status and message only (an upsert
/// updates only the given columns; a new row gets `last_sync`/`cursor` NULL and `records` 0, as there).
fn sync_row(
    status: &str,
    records: u64,
    cursor: Option<String>,
    message: Option<String>,
    now: &str,
) -> RowOp {
    let mut row = JsonMap::new();
    row.insert("source".into(), json!(NAME));
    if status != "error" {
        row.insert("last_sync".into(), json!(now));
        if let Some(c) = cursor {
            row.insert("cursor".into(), json!(c));
        }
        row.insert("records".into(), json!(records));
    }
    row.insert("status".into(), json!(status));
    row.insert("message".into(), json!(message));
    RowOp::Upsert {
        table: MirrorTable::SourceSync,
        row,
    }
}

/// `catalogVersion` as the TEXT the Python source stores (a number becomes its text, as SQLite's affinity does).
fn cursor_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// `str(value)` for the count log line.
fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// A text column of an entry: a string, or null when absent / null. Anything else refuses the feed (the Python
/// source would store numbers as text and fail on arrays; a malformed feed is an error here).
fn text(e: &JsonMap, cve: &str, field: &str) -> Result<Value, String> {
    match e.get(field) {
        None | Some(Value::Null) => Ok(Value::Null),
        Some(Value::String(s)) => Ok(json!(s)),
        Some(_) => Err(format!("kev: {cve}: {field} is not a string")),
    }
}

/// The `raw_record` and `kev` upserts of one feed entry.
fn entry_rows(e: &Value, now: &str) -> Result<(String, RowOp, RowOp), String> {
    let Some(m) = e.as_object() else {
        return Err("kev: an entry is not an object".into());
    };
    let cve = match m.get("cveID") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        None => return Err("'cveID'".into()), // str(KeyError) of the Python source
        Some(_) => return Err("kev: cveID is not a non-empty string".into()),
    };
    let date_added = text(m, &cve, "dateAdded")?;
    let raw = RowOp::Upsert {
        table: MirrorTable::RawRecord,
        row: obj(json!({
            "source": NAME, "record_id": cve, "modified": date_added, "fetched_at": now, "data": e,
        })),
    };
    let extra: JsonMap = m
        .iter()
        .filter(|(k, _)| !MAPPED.contains(&k.as_str()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let ransomware = if m.get("knownRansomwareCampaignUse").and_then(Value::as_str) == Some("Known")
    {
        "1"
    } else {
        "0"
    };
    let kev = RowOp::Upsert {
        table: MirrorTable::Kev,
        row: obj(json!({
            "cve_id": cve,
            "vendor": text(m, &cve, "vendorProject")?,
            "product": text(m, &cve, "product")?,
            "name": text(m, &cve, "vulnerabilityName")?,
            "date_added": date_added,
            "due_date": text(m, &cve, "dueDate")?,
            "ransomware": ransomware,
            "source": NAME,
            "extra": Value::Object(extra),
        })),
    };
    Ok((cve, raw, kev))
}

#[async_trait]
impl Source for KevSource {
    fn sources(&self) -> Vec<SourceInfo> {
        vec![SourceInfo {
            name: NAME.into(),
            description: DESCRIPTION.into(),
            in_all: true,
        }]
    }

    fn sync_all_order(&self) -> Vec<String> {
        Vec::new() // the order of the Python sources (or the engine's default) applies
    }

    async fn sync(
        &self,
        params: SyncParams,
        ctx: CallCtx,
    ) -> StepResult<ResultStream<RowsBatch, SyncEnd>> {
        if params.source != NAME {
            return Err(WireError::new(
                ErrorCode::UnknownSource,
                format!("unknown source {:?} (known: kev)", params.source),
            ));
        }
        let (batches, end) = self.run(&params, &ctx).await?;
        let mut msgs: Vec<StepResult<StreamMsg<RowsBatch, SyncEnd>>> = batches
            .into_iter()
            .map(|b| Ok(StreamMsg::Item(b)))
            .collect();
        msgs.push(Ok(StreamMsg::End(end)));
        Ok(futures_util::stream::iter(msgs).boxed())
    }

    async fn ack(&self, _source: &str, _through_seq: u64, _ctx: CallCtx) -> StepResult<()> {
        Ok(()) // no change log: nothing to drop
    }

    async fn export(
        &self,
        source: &str,
        _ctx: CallCtx,
    ) -> StepResult<ResultStream<RowsBatch, Value>> {
        Err(WireError::new(
            ErrorCode::UnknownMethod,
            format!(
                "{source}: native importer: no staging database, source.export is not supported; run a sync to rewrite the rows"
            ),
        ))
    }

    fn native(&self) -> bool {
        true
    }
}
