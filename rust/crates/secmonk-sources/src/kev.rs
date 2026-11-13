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
use secmonk_model::{JsonMap, MirrorTable, RowOp};
use secmonk_traits::{
    CallCtx, MirrorView, ProgressUpdate, ResultStream, RowsBatch, Source, SourceInfo, StepResult,
    SyncEnd, SyncParams,
};
use serde_json::{Value, json};

use crate::batch::Limits;
use crate::{feed, py};
use crate::native::{self, Outcome};

/// Source name.
pub const NAME: &str = "kev";
/// Registration (`crate::IMPORTERS`): rust by default since 2026-11-11 (differential test green).
pub const IMPORTER: crate::Importer = crate::Importer {
    name: NAME,
    default_rust: true,
    importer_version: "rust/1",
    new: |view| Arc::new(KevSource::new(view)),
};
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

    /// One sync: the stream of batches and the run's end. Infrastructure failures (the mirror view) are wire
    /// errors; feed problems are an `error` entry with its `source_sync` row, as `ops.sync_source` records them.
    async fn run(
        &self,
        params: &SyncParams,
        ctx: &CallCtx,
    ) -> StepResult<ResultStream<RowsBatch, SyncEnd>> {
        let t0 = Instant::now();
        let opts = &params.options;
        let limit = native::limit(opts)?;
        let path = opts.path.clone().flatten().filter(|p| !p.is_empty());
        let full = opts.full.unwrap_or(false);
        let outcome = match self.load(path.as_deref(), ctx).await {
            Ok((doc, origin)) => self.rows(&doc, &origin, limit, full, ctx).await?,
            Err(message) => Outcome::error(message),
        };
        let first = native::first_seq(self.view.as_ref(), NAME).await?;
        Ok(native::stream(NAME, outcome, first, self.limits, t0))
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
                    py::str_of(c),
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
        if !limited && !full {
            let old = self.view.count_rows(MirrorTable::Kev, NAME).await?;
            if let Some(refusal) = native::snapshot_guard(old, entries.len() as u64, full) {
                return Ok(Outcome::error(format!("kev: {refusal}")));
            }
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
            total: None,
            cursor: if limited {
                None
            } else {
                doc.get("catalogVersion").and_then(cursor_text)
            },
            message: Some(format!("{} entries {origin}", entries.len())),
            ops: native::iter_ops(ops),
        })
    }
}

fn obj(v: Value) -> JsonMap {
    match v {
        Value::Object(m) => m,
        _ => JsonMap::new(),
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
        native::check_name(NAME, &params.source)?;
        self.run(&params, &ctx).await
    }

    async fn ack(&self, _source: &str, _through_seq: u64, _ctx: CallCtx) -> StepResult<()> {
        Ok(()) // no change log: nothing to drop
    }

    async fn export(
        &self,
        source: &str,
        _ctx: CallCtx,
    ) -> StepResult<ResultStream<RowsBatch, Value>> {
        Err(native::export_refused(source))
    }

    fn native(&self) -> bool {
        true
    }
}
