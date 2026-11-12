//! NVD CVE API 2.0, native (rust ADR-0011, ADR-0012). Port of `src/secmonk/sources/nvd.py` plus the `source_sync`
//! bookkeeping of `ops.sync_source` / `db.set_sync_state`; reference: `py-sources` (differential test
//! `secmonk-engine/tests/native_nvd.rs`). Doc: `rust/_docs/tech/source-nvd.md`.
//!
//! Modes, by precedence as in Python: `--path` (an API-shaped JSON file, or a directory of them: `*.json`, sorted),
//! `ids` (one `cveId` request each), else the CVE endpoint: a delta from the stored cursor in windows of 119 days
//! (`lastModStartDate` / `lastModEndDate`), or a full paginated pull (`full`, or no stored cursor).
//!
//! Python commits every page in its own transaction, so a failure keeps the pages before it. The native importer
//! works the same way, one page at a time: a page is read, split into records without building one tree
//! (`serde_json::RawValue`), every record of the page is checked first (a failing record discards the whole page, as
//! its rolled-back transaction), then the page's operations are produced in chunks while the engine applies the
//! batches: per CVE a `raw_record` and a `vulnerability` upsert and its `affected` rows (CPE match ranges) replaced
//! against the stored ones (read through `MirrorView::rows_by_id`; nothing when they are equal). The status, records,
//! cursor and message are known only at the end, so the run's end goes through `native::stream_deferred`.
//!
//! API: the key is a call secret (`SyncParams.secrets.api_key`, from the engine's `nvd_api_key_env`), sent as the
//! `apiKey` header (marked sensitive), never in a URL, a log line or a message (redacted from every message). Redirects
//! are never followed. Requests are paced (0.6 s with a key, 6 s without) and 403 / 429 / 5xx answers and transport
//! errors are retried up to 5 times with exponential backoff (2 s base, 120 s cap) honoring `Retry-After`.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures_util::StreamExt;
use secmonk_model::{JsonMap, MirrorTable, RowOp};
use secmonk_traits::{
    CallCtx, MAX_VIEW_IDS, MirrorView, ResultStream, RowsBatch, Source, SourceInfo, StepResult,
    SyncEnd, SyncParams,
};
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;
use serde_json::{Value, json};

use crate::batch::Limits;
use crate::native::{self, Ops, Progress, Tail, TailCell};
use crate::rows::{self, DeleteKey};
use crate::{feed, py};

/// Source name.
pub const NAME: &str = "nvd";
/// Registration (`crate::IMPORTERS`): rust by default since 2026-11-12 (differential test green; faster than
/// `py-sources` at every step of the volume measurement, rust/_docs/tech/source-nvd.md).
pub const IMPORTER: crate::Importer = crate::Importer {
    name: NAME,
    default_rust: true,
    new: |view| Arc::new(NvdSource::new(view)),
};
/// Description (as the Python source's).
pub const DESCRIPTION: &str = "NVD CVE API 2.0: CVSS, CWE and CPE applicability";
/// The CVE endpoint.
pub const API_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
/// `resultsPerPage` (the API's maximum).
pub const PAGE_SIZE: u64 = 2000;
/// The internal `source_sync` row holding the end of the last completed delta window.
pub const PROGRESS_KEY: &str = "nvd:progress";
/// A delta window: 119 days, under NVD's 120-day cap (microseconds).
const WINDOW_US: i64 = 119 * 86_400 * 1_000_000;
/// CVSS metric lists, newest version first.
const METRIC_ORDER: [&str; 4] = [
    "cvssMetricV40",
    "cvssMetricV31",
    "cvssMetricV30",
    "cvssMetricV2",
];
/// Statuses retried (throttling, transient server errors).
const RETRY_STATUS: [u16; 6] = [403, 429, 500, 502, 503, 504];
/// (cpeMatch field, events key).
const BOUNDS: [(&str, &str); 4] = [
    ("versionStartIncluding", "introduced"),
    ("versionStartExcluding", "introduced_exclusive"),
    ("versionEndExcluding", "fixed"),
    ("versionEndIncluding", "last_affected"),
];

/// Input caps (the Python source has none). Worst-case memory within them: rust/_docs/tech/source-nvd.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Bytes of one `--path` file.
    pub file_bytes: u64,
    /// Bytes of one API answer.
    pub response_bytes: u64,
    /// Bytes of one record (`{"cve": {...}}`).
    pub record_bytes: usize,
    /// Records of one run.
    pub records: u64,
    /// `affected` rows of one CVE (new ones, and stored ones read back).
    pub matches: usize,
    /// API requests of one run (retries not counted).
    pub requests: u64,
    /// `*.json` files of one `--path` directory.
    pub files: usize,
    /// Directory entries visited in one `--path` directory.
    pub entries: usize,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            file_bytes: 256 * 1024 * 1024,
            response_bytes: 64 * 1024 * 1024,
            record_bytes: 8 * 1024 * 1024,
            records: 1_000_000,
            matches: 50_000,
            requests: 10_000,
            files: 10_000,
            entries: 100_000,
        }
    }
}

/// Request pacing and retries (the values of `_NvdClient`; tests shorten them).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// Least time between two requests with an API key.
    pub pause_with_key: Duration,
    /// Least time between two requests without one.
    pub pause_without_key: Duration,
    /// First backoff delay (doubled per attempt).
    pub backoff_base: Duration,
    /// Longest delay (backoff or `Retry-After`).
    pub backoff_max: Duration,
    /// Retries after the first attempt.
    pub retries: u32,
    /// Time limit of one request, connecting and reading together (httpx's 60 s is per operation only, so a slow
    /// trickle could last for ever there); running out is a transport error, retried.
    pub request_total: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            pause_with_key: Duration::from_millis(600),
            pause_without_key: Duration::from_secs(6),
            backoff_base: Duration::from_secs(2),
            backoff_max: Duration::from_secs(120),
            retries: 5,
            request_total: Duration::from_secs(600),
        }
    }
}

/// Records per chunk of the operation stream (at most `MAX_VIEW_IDS` ids are read per chunk).
const CHUNK_RECORDS: usize = MAX_VIEW_IDS;
/// Record bytes per chunk (a chunk closes once it is reached).
const CHUNK_BYTES: usize = 4 * 1024 * 1024;
/// New `affected` rows per chunk (a chunk closes once it is reached).
const CHUNK_NEW: usize = 50_000;
/// Stored `affected` rows read per chunk (a chunk closes once it is reached).
const CHUNK_STORED: usize = 50_000;
/// Records whose stored rows are read in one `rows_by_id` call.
const GROUP: usize = 5;
/// CVE ids per `rows_by_id` call of the stored-rows check of a page.
const CHECK_IDS: usize = 50;

/// The native NVD source.
pub struct NvdSource {
    view: Arc<dyn MirrorView>,
    api_url: String,
    limits: Limits,
    caps: Caps,
    timing: Timing,
    now_us: Option<i64>,
}

impl fmt::Debug for NvdSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NvdSource")
            .field("api_url", &self.api_url)
            .field("limits", &self.limits)
            .field("caps", &self.caps)
            .field("timing", &self.timing)
            .finish_non_exhaustive()
    }
}

impl NvdSource {
    /// The source over a read-only view of the mirror.
    pub fn new(view: Arc<dyn MirrorView>) -> NvdSource {
        NvdSource {
            view,
            api_url: API_URL.into(),
            limits: Limits::default(),
            caps: Caps::default(),
            timing: Timing::default(),
            now_us: None,
        }
    }

    /// Another CVE endpoint (tests: a local server; `http://` is then allowed).
    pub fn with_api_url(mut self, url: &str) -> NvdSource {
        self.api_url = url.into();
        self
    }

    /// Other batch limits (tests: several batches out of a small fixture).
    pub fn with_limits(mut self, limits: Limits) -> NvdSource {
        self.limits = limits;
        self
    }

    /// Other input caps.
    pub fn with_caps(mut self, caps: Caps) -> NvdSource {
        self.caps = caps;
        self
    }

    /// Other pacing and retries.
    pub fn with_timing(mut self, timing: Timing) -> NvdSource {
        self.timing = timing;
        self
    }

    /// A fixed "now" (ISO 8601; naive = UTC) for the end of the delta windows (tests).
    ///
    /// # Panics
    /// When `iso` is not a timestamp.
    pub fn with_now(mut self, iso: &str) -> NvdSource {
        self.now_us = Some(fromisoformat(iso).expect("a timestamp"));
        self
    }

    async fn run(
        &self,
        params: &SyncParams,
        ctx: &CallCtx,
    ) -> StepResult<ResultStream<RowsBatch, SyncEnd>> {
        let t0 = Instant::now();
        let opts = &params.options;
        let limit = native::limit(opts)?;
        let key = params
            .secrets
            .as_ref()
            .and_then(|s| s.api_key.clone())
            .filter(|k| !k.is_empty());
        let path = opts.path.clone().flatten().filter(|p| !p.is_empty());
        let ids: Vec<String> = opts.ids.clone().unwrap_or_default();
        let tail: TailCell = Arc::new(Mutex::new(None));
        let mut run = Run {
            view: self.view.clone(),
            caps: self.caps,
            now: secmonk_model::time::now_iso(),
            limit,
            count: 0,
            say: Progress::new(ctx),
            input: Input::Done,
            page: None,
            emitted: HashMap::new(),
            secret: key.clone(),
            tail: tail.clone(),
            done: false,
        };
        let client = || Client {
            url: self.api_url.clone(),
            allow_http: !self.api_url.starts_with("https://"),
            key: key.clone(),
            timing: self.timing,
            last: None,
            requests: 0,
            caps: self.caps,
            http: None,
        };
        if let Some(p) = path {
            let shown = feed::py_path(Path::new(&p));
            let (dir, label, caps) = (PathBuf::from(&p), shown.clone(), self.caps);
            let listed = tokio::task::spawn_blocking(move || list_files(&dir, &label, &caps))
                .await
                .map_err(|e| native::internal(NAME, format!("listing task failed: {e}")))?;
            match listed {
                Ok(files) => {
                    run.input = Input::Files {
                        files: files.into(),
                        origin: shown,
                    }
                }
                Err(fail) => run.fail(fail, None),
            }
        } else if !ids.is_empty() {
            run.input = Input::Ids {
                client: client(),
                n: ids.len(),
                ids: ids.into(),
            };
        } else {
            let now = self.now_us.unwrap_or_else(now_us);
            match self.api_plan(opts, now).await? {
                Ok(plan) => {
                    run.input = Input::Api {
                        client: client(),
                        plan,
                        with_key: key.is_some(),
                    }
                }
                Err(fail) => run.fail(fail, None),
            }
        }
        let first = native::first_seq(self.view.as_ref(), NAME).await?;
        Ok(native::stream_deferred(
            NAME,
            ops(run),
            tail,
            first,
            self.limits,
            t0,
        ))
    }

    /// The stored cursor of one `source_sync` row (`get_sync_cursor`), parsed; unparsable ones are skipped.
    async fn cursor_of(&self, key: &str) -> StepResult<Option<i64>> {
        let page = self
            .view
            .rows_page(MirrorTable::SourceSync, key, None, 1)
            .await?;
        Ok(page
            .rows
            .first()
            .and_then(|r| r.get("cursor"))
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty())
            .and_then(|c| fromisoformat(c).ok()))
    }

    /// `_stored_cursor`, `_delta_start`, the `--since` trust rule and the windows (`sync` before its first request).
    async fn api_plan(
        &self,
        opts: &secmonk_model::SyncOptions,
        end: i64,
    ) -> StepResult<Result<ApiPlan, Fail>> {
        let stored = match (
            self.cursor_of(NAME).await?,
            self.cursor_of(PROGRESS_KEY).await?,
        ) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        let full = opts.full.unwrap_or(false);
        let since = opts.since.clone().flatten();
        let start = if full {
            None
        } else if let Some(s) = &since {
            match parse_since(s) {
                Ok(t) => Some(t),
                Err(m) => return Ok(Err(Fail::Caught(format!("ValueError: {m}")))),
            }
        } else {
            stored
        };
        // a --since run may only move the cursor when it re-covers [since, stored]
        let trust = match (&since, full) {
            (Some(_), false) => stored.is_some_and(|s| start.is_some_and(|t| t <= s)),
            _ => true,
        };
        let mut queries = VecDeque::new();
        let mode = match start {
            None => {
                queries.push_back(Query::Full);
                "full".to_owned()
            }
            Some(s) => {
                let mut cur = s;
                while cur < end {
                    let next = (cur + WINDOW_US).min(end);
                    queries.push_back(Query::Window(cur, next));
                    cur = next;
                }
                format!("delta since {}", iso(s))
            }
        };
        Ok(Ok(ApiPlan {
            queries,
            current: None,
            end,
            trust,
            mode,
            cursor: None,
        }))
    }
}

/// Why a run stops at a page. Python's sync catches `httpx.HTTPError`, `OSError`, `ValueError` and `KeyError`
/// (status `partial` with the records so far, or `error` without any); anything else reaches `ops.sync_source`
/// (status `error`, no records). The text is `<exception class>: <message>`, as both word it; native refusals (caps,
/// types Python would store as text) are `nvd: ...` and count as caught.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Fail {
    Caught(String),
    Uncaught(String),
}

fn type_error(m: String) -> Fail {
    Fail::Uncaught(format!("TypeError: {m}"))
}

fn attribute_error(v: &Value, attr: &str) -> Fail {
    Fail::Uncaught(format!(
        "AttributeError: {}",
        py::no_attr(py::type_name(v), attr)
    ))
}

/// The `TypeError` text of `v["key"]` on a value that is not a dict.
fn subscript_error(v: &Value) -> Fail {
    type_error(match v {
        Value::Array(_) => "list indices must be integers or slices, not str".into(),
        Value::String(_) => "string indices must be integers, not 'str'".into(),
        other => format!("'{}' object is not subscriptable", py::type_name(other)),
    })
}

/// `for x in d.get(k, [])` (no `or []`): absent is empty, `null`, a bool or a number is not iterable.
fn iter_get(v: Option<&Value>) -> Result<py::Items<'_>, Fail> {
    match v {
        Some(x @ (Value::Null | Value::Bool(_) | Value::Number(_))) => Err(type_error(format!(
            "'{}' object is not iterable",
            py::type_name(x)
        ))),
        other => py::iter_items(other).map_err(type_error),
    }
}

/// `for x in (v or [])`.
fn iter_or(v: Option<&Value>) -> Result<py::Items<'_>, Fail> {
    py::iter_items(v).map_err(type_error)
}

/// An element of a list the code calls `.get` on: a dict, else Python's `AttributeError`.
fn dict_of<'a>(item: &Cow<'a, Value>) -> Result<&'a JsonMap, Fail> {
    match item {
        Cow::Borrowed(Value::Object(m)) => Ok(m),
        other => Err(attribute_error(other, "get")),
    }
}

/// A text column: a string, or NULL when absent or null; anything else refuses the run (Python stores numbers as
/// text and fails on lists only when SQLite binds them).
fn text(v: Option<&Value>, id: &str, field: &str) -> Result<Option<String>, Fail> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(Fail::Caught(format!("nvd: {id}: {field} is not a string"))),
    }
}

/// A number as Python compares and binds it (a bool is an int).
fn number(v: &Value) -> Option<f64> {
    match v {
        Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
        Value::Number(n) => n.as_f64(),
        _ => None,
    }
}

/// `_best_cvss`: (score, vector, version, severity) of the best metric: Primary before Secondary, then 4.0 > 3.1 >
/// 3.0 > 2.0 (the first of equals).
struct Cvss<'a> {
    score: Option<&'a Value>,
    vector: Option<&'a Value>,
    version: Option<&'a Value>,
    severity: Option<String>,
}

fn best_cvss(metrics: Option<&Value>) -> Result<Cvss<'_>, Fail> {
    let none = Cvss {
        score: None,
        vector: None,
        version: None,
        severity: None,
    };
    let metrics = match metrics {
        None => return Ok(none),
        Some(Value::Object(m)) => m,
        Some(v) => return Err(attribute_error(v, "get")),
    };
    let mut best: Option<((bool, usize), &JsonMap)> = None;
    for (rank, key) in METRIC_ORDER.iter().enumerate() {
        for m in iter_or(metrics.get(*key))? {
            let m = dict_of(&m)?;
            let k = (m.get("type").and_then(Value::as_str) != Some("Primary"), rank);
            if best.is_none_or(|(b, _)| k < b) {
                best = Some((k, m));
            }
        }
    }
    let Some((_, m)) = best else {
        return Ok(none);
    };
    let empty: &JsonMap = &EMPTY;
    let data = match m.get("cvssData") {
        None => empty,
        Some(Value::Object(d)) => d,
        Some(v) => return Err(attribute_error(v, "get")),
    };
    let score = data.get("baseScore");
    // `normalize_severity(data.get("baseSeverity") or m.get("baseSeverity")) or severity_from_score(score)`
    let label = match data.get("baseSeverity") {
        Some(v) if py::truthy(v) => Some(v),
        _ => m.get("baseSeverity"),
    };
    let severity = match label.and_then(Value::as_str) {
        Some(s) => rows::normalize_severity(Some(s)),
        None => None,
    };
    let severity = match severity {
        Some(s) => Some(s),
        None => match score {
            None | Some(Value::Null) => None,
            Some(v) => match number(v) {
                Some(f) => rows::severity_from_score(Some(f)).map(str::to_owned),
                None => {
                    return Err(type_error(format!(
                        "'>=' not supported between instances of '{}' and 'float'",
                        py::type_name(v)
                    )));
                }
            },
        },
    };
    Ok(Cvss {
        score,
        vector: data.get("vectorString"),
        version: data.get("version"),
        severity,
    })
}

static EMPTY: std::sync::LazyLock<JsonMap> = std::sync::LazyLock::new(JsonMap::new);

/// `_english`: the `value` of the first description whose `lang` is `en`.
fn english(descriptions: Option<&Value>) -> Result<Option<&Value>, Fail> {
    for d in iter_or(descriptions)? {
        let d = dict_of(&d)?;
        if d.get("lang").and_then(Value::as_str) == Some("en") {
            return Ok(d.get("value"));
        }
    }
    Ok(None)
}

/// `_cwes`: the `CWE-*` values of the weaknesses, Primary first, without repeats.
fn cwes(weaknesses: Option<&Value>) -> Result<Vec<String>, Fail> {
    let mut ws: Vec<&JsonMap> = Vec::new();
    for w in iter_or(weaknesses)? {
        ws.push(dict_of(&w)?);
    }
    ws.sort_by_key(|w| w.get("type").and_then(Value::as_str) != Some("Primary"));
    let mut out: Vec<String> = Vec::new();
    for w in ws {
        for d in iter_get(w.get("description"))? {
            let d = dict_of(&d)?;
            match d.get("value") {
                None => {}
                Some(Value::String(v)) => {
                    if v.starts_with("CWE-") && !out.contains(v) {
                        out.push(v.clone());
                    }
                }
                Some(v) => return Err(attribute_error(v, "startswith")),
            }
        }
    }
    Ok(out)
}

/// `base.cpe_fields`: split a CPE 2.3 string on `:` not preceded by a backslash (`(?<!\\):`), then unescape
/// `\<c>` to `<c>` (any character but a newline) in each field.
pub fn cpe_fields(criteria: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let (mut start, mut prev) = (0usize, None::<char>);
    for (i, c) in criteria.char_indices() {
        if c == ':' && prev != Some('\\') {
            parts.push(&criteria[start..i]);
            start = i + 1;
        }
        prev = Some(c);
    }
    parts.push(&criteria[start..]);
    parts
        .into_iter()
        .map(|f| {
            let mut out = String::with_capacity(f.len());
            let mut it = f.chars().peekable();
            while let Some(c) = it.next() {
                match (c, it.peek()) {
                    ('\\', Some(&n)) if n != '\n' => {
                        out.push(n);
                        it.next();
                    }
                    _ => out.push(c),
                }
            }
            out
        })
        .collect()
}

/// The `seen` key of a cpeMatch (`matchCriteriaId or json.dumps(match, sort_keys=True)`), as Python compares it:
/// numbers and bools by value (`1 == 1.0 == True`), strings by text, the dumped form in its own domain (equal to an
/// id only in Python, when an id string spells out another match's JSON).
#[derive(Debug, PartialEq, Eq, Hash)]
enum SeenKey {
    Num(u64),
    Str(String),
    Dumps(String),
}

/// JSON with object keys sorted at every level (the comparison of `json.dumps(..., sort_keys=True)`).
fn canonical(v: &Value) -> String {
    fn sorted(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort();
                Value::Object(keys.into_iter().map(|k| (k.clone(), sorted(&m[k]))).collect())
            }
            Value::Array(a) => Value::Array(a.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_string(&sorted(v)).unwrap_or_default()
}

fn seen_key(m: &JsonMap) -> Result<SeenKey, Fail> {
    match m.get("matchCriteriaId") {
        Some(v) if py::truthy(v) => match v {
            Value::String(s) => Ok(SeenKey::Str(s.clone())),
            Value::Array(_) | Value::Object(_) => Err(type_error(format!(
                "unhashable type: '{}'",
                py::type_name(v)
            ))),
            other => {
                let f = number(other).unwrap_or(f64::NAN);
                Ok(SeenKey::Num(if f == 0.0 { 0 } else { f.to_bits() }))
            }
        },
        _ => Ok(SeenKey::Dumps(canonical(&Value::Object(m.clone())))),
    }
}

/// `_add_cpe`: the `affected` row of one vulnerable cpeMatch, or `None` (not a CPE 2.3 string, or version `-` / empty
/// without bounds).
fn cpe_row(id: &str, m: &JsonMap) -> Result<Option<JsonMap>, Fail> {
    let criteria = match m.get("criteria") {
        None => "",
        Some(v) if !py::truthy(v) => "",
        Some(Value::String(s)) => s.as_str(),
        Some(v) => {
            return Err(type_error(format!(
                "expected string or bytes-like object, got '{}'",
                py::type_name(v)
            )));
        }
    };
    let fields = cpe_fields(criteria);
    if fields.len() < 6 || fields[0] != "cpe" {
        return Ok(None);
    }
    let (vendor, product, version) = (&fields[3], &fields[4], &fields[5]);
    let update = fields.get(6).map_or("*", String::as_str);
    let mut events: Vec<Value> = BOUNDS
        .iter()
        .filter_map(|(key, ev)| {
            m.get(*key).filter(|v| py::truthy(v)).map(|v| {
                let mut e = JsonMap::new();
                e.insert((*ev).to_owned(), v.clone());
                Value::Object(e)
            })
        })
        .collect();
    let mut versions: Vec<Value> = Vec::new();
    let has_start = |e: &Value| e.get("introduced").is_some() || e.get("introduced_exclusive").is_some();
    if !events.is_empty() && !events.iter().any(has_start) {
        events.insert(0, json!({"introduced": "0"})); // end-only bound: from the beginning
    }
    if events.is_empty() {
        if version == "*" {
            events.push(json!({"introduced": "0"})); // all versions
        } else if version != "-" && !version.is_empty() {
            versions.push(json!(version));
        } else {
            return Ok(None); // '-' with no bounds: no version applies
        }
    }
    let mut extra = JsonMap::new();
    extra.insert(
        "matchCriteriaId".into(),
        m.get("matchCriteriaId").cloned().unwrap_or(Value::Null),
    );
    let mut range_type = "CPE";
    if !matches!(update, "*" | "-" | "") {
        // beta / rc / pN: matching the bare version would flag the final release
        range_type = "CVE-UNPARSED";
        extra.insert("cpe_update".into(), json!(update));
    }
    Ok(Some(rows::affected(
        NAME,
        id,
        rows::Affected {
            vendor: Some(vendor.clone()),
            product: Some(product.clone()),
            cpe: m.get("criteria").and_then(Value::as_str).map(str::to_owned),
            range_type: Some(range_type.into()),
            events: (!events.is_empty()).then_some(events),
            versions,
            extra: Value::Object(extra),
            ..rows::Affected::default()
        },
    )))
}

/// What `_store_cve` writes for one CVE.
#[derive(Debug)]
struct Plan {
    id: String,
    raw: RowOp,
    vulnerability: RowOp,
    /// Empty for a rejected CVE (its rows are dropped).
    affected: Vec<JsonMap>,
}

/// `item["cve"]`.
fn cve_of(item: Value) -> Result<Value, Fail> {
    match item {
        Value::Object(mut m) => m
            .remove("cve")
            .ok_or_else(|| Fail::Caught("KeyError: 'cve'".into())),
        other => Err(subscript_error(&other)),
    }
}

/// `_store_cve(conn, cve)` as rows, with the checks that make Python raise, in its order.
fn plan(cve: Value, now: &str, caps: &Caps) -> Result<Plan, Fail> {
    let Value::Object(m) = &cve else {
        return Err(subscript_error(&cve));
    };
    let id = match m.get("id") {
        None => return Err(Fail::Caught("KeyError: 'id'".into())),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return Err(Fail::Caught("nvd: a CVE id is not a string".into())),
    };
    let rejected = m.get("vulnStatus").and_then(Value::as_str) == Some("Rejected");
    // Python's errors first, in its order (`_best_cvss`, `_english`, `_cwes`), then the native type refusals
    let cvss = best_cvss(m.get("metrics"))?;
    let summary = english(m.get("descriptions"))?;
    let weak = cwes(m.get("weaknesses"))?;
    let modified = text(m.get("lastModified"), &id, "lastModified")?;
    let summary = text(summary, &id, "descriptions[].value")?;
    let published = text(m.get("published"), &id, "published")?;
    let state = if rejected {
        Some("REJECTED".to_owned())
    } else {
        text(m.get("vulnStatus"), &id, "vulnStatus")?
    };
    let score = match cvss.score {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            number(v).ok_or_else(|| Fail::Caught(format!("nvd: {id}: baseScore is not a number")))?,
        ),
    };
    let vector = text(cvss.vector, &id, "vectorString")?;
    let version = text(cvss.version, &id, "version")?;
    let extra = json!({
        "sourceIdentifier": m.get("sourceIdentifier").cloned().unwrap_or(Value::Null),
        "cveTags": m.get("cveTags").cloned().unwrap_or_else(|| json!([])),
    });
    let mut affected = Vec::new();
    if !rejected {
        let mut seen: HashSet<SeenKey> = HashSet::new();
        for config in iter_get(m.get("configurations"))? {
            let config = dict_of(&config)?;
            for node in iter_get(config.get("nodes"))? {
                let node = dict_of(&node)?;
                for cm in iter_get(node.get("cpeMatch"))? {
                    let cm = dict_of(&cm)?;
                    if !cm.get("vulnerable").is_some_and(py::truthy) {
                        continue;
                    }
                    if !seen.insert(seen_key(cm)?) {
                        continue;
                    }
                    if let Some(row) = cpe_row(&id, cm)? {
                        if affected.len() >= caps.matches {
                            return Err(Fail::Caught(format!(
                                "nvd: {id}: more than {} CPE match rows; refusing",
                                caps.matches
                            )));
                        }
                        affected.push(row);
                    }
                }
            }
        }
    }
    let vulnerability = rows::vulnerability(
        NAME,
        &id,
        rows::Vulnerability {
            summary,
            published,
            modified: modified.clone(),
            withdrawn: if rejected { modified.clone() } else { None },
            state,
            severity: cvss.severity,
            cvss_score: score,
            cvss_vector: vector,
            cvss_version: version,
            cwes: weak,
            extra,
            ..rows::Vulnerability::default()
        },
    );
    let raw = rows::raw_record(NAME, &id, modified.as_deref(), now, cve);
    Ok(Plan {
        id,
        raw,
        vulnerability,
        affected,
    })
}

/// Parse and plan one record (`{"cve": {...}}`) of a page.
fn plan_item(text: &str, now: &str, caps: &Caps) -> Result<Plan, Fail> {
    let item: Value = serde_json::from_str(text)
        .map_err(|e| Fail::Caught(format!("invalid JSON: {e}")))?;
    plan(cve_of(item)?, now, caps)
}

// ------------------------------------------------------------------------------------------------ pages

/// One API page or `--path` document: its text and the byte ranges of its records (the members of
/// `vulnerabilities`), in order.
#[derive(Debug)]
struct Page {
    text: String,
    items: Vec<Range<usize>>,
    /// `totalResults` (the last one of a repeated key).
    total: Option<Value>,
}

/// The top level of a document.
enum Top<'a> {
    Map {
        vulns: Option<&'a RawValue>,
        total: Option<Value>,
    },
    /// Not a dict: `doc.get` fails (`AttributeError`), with the type name.
    Other(&'static str),
}

struct Envelope;

impl<'de> DeserializeSeed<'de> for Envelope {
    type Value = Top<'de>;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Top<'de>, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Envelope {
    type Value = Top<'de>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an NVD API response")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Top<'de>, A::Error> {
        let (mut vulns, mut total) = (None, None);
        while let Some(key) = map.next_key::<Cow<'de, str>>()? {
            match key.as_ref() {
                // a repeated key: the last value counts, as in `json.loads`
                "vulnerabilities" => vulns = Some(map.next_value::<&'de RawValue>()?),
                "totalResults" => total = Some(map.next_value::<Value>()?),
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Top::Map { vulns, total })
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Top<'de>, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Top::Other("list"))
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<Top<'de>, E> {
        Ok(Top::Other("str"))
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Top<'de>, E> {
        Ok(Top::Other("bool"))
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Top<'de>, E> {
        Ok(Top::Other("int"))
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Top<'de>, E> {
        Ok(Top::Other("int"))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Top<'de>, E> {
        Ok(Top::Other("float"))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Top<'de>, E> {
        Ok(Top::Other("NoneType"))
    }
}

/// The records of a `vulnerabilities` list as byte ranges (relative to the text at `base`), each at most
/// `record_bytes`.
struct Records {
    base: usize,
    record_bytes: usize,
    max_items: u64,
}

impl<'de> DeserializeSeed<'de> for Records {
    type Value = Vec<Range<usize>>;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for Records {
    type Value = Vec<Range<usize>>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a list of records")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::new();
        while let Some(raw) = seq.next_element::<&'de RawValue>()? {
            if out.len() as u64 >= self.max_items {
                return Err(de::Error::custom(format!(
                    "nvd: more than {} records in one page; refusing",
                    self.max_items
                )));
            }
            let s = raw.get();
            if s.len() > self.record_bytes {
                return Err(de::Error::custom(format!(
                    "nvd: a record is larger than {} bytes; refusing",
                    self.record_bytes
                )));
            }
            let start = s.as_ptr() as usize - self.base;
            out.push(start..start + s.len());
        }
        Ok(out)
    }
}

/// `json.loads` of a page, then `doc.get("vulnerabilities", [])` and the `for item in ...` of `_store_pages`: the
/// records of a list, nothing for an empty string or object, Python's errors for the other shapes.
fn split_page(bytes: Vec<u8>, caps: &Caps) -> Result<Page, Fail> {
    if let Err(e) = std::str::from_utf8(&bytes) {
        return Err(Fail::Caught(format!(
            "UnicodeDecodeError: {}",
            py::utf8_error(&bytes, &e)
        )));
    }
    let text = String::from_utf8(bytes).map_err(|e| Fail::Caught(e.to_string()))?;
    let message = |e: serde_json::Error| Fail::Caught(feed::json_error(&e, &["nvd: "]));
    let base = text.as_ptr() as usize;
    let (items, total) = {
        let mut de = serde_json::Deserializer::from_str(&text);
        let top = Envelope.deserialize(&mut de).map_err(message)?;
        de.end().map_err(message)?;
        let (vulns, total) = match top {
            Top::Map { vulns, total } => (vulns, total),
            Top::Other(t) => {
                return Err(Fail::Uncaught(format!(
                    "AttributeError: {}",
                    py::no_attr(t, "get")
                )));
            }
        };
        let items = match vulns.map(|r| r.get().trim_start()) {
            None => Vec::new(),
            Some(s) if s.starts_with('[') => {
                let mut de = serde_json::Deserializer::from_str(vulns.map_or("", |r| r.get()));
                Records {
                    base,
                    record_bytes: caps.record_bytes,
                    max_items: caps.records,
                }
                .deserialize(&mut de)
                .map_err(message)?
            }
            // the keys of an object, the characters of a string: `item["cve"]` on a str
            Some(s) if s.starts_with('{') && s[1..].trim_start().starts_with('}') => Vec::new(),
            Some("\"\"") => Vec::new(),
            Some(s) if s.starts_with('{') || s.starts_with('"') => {
                return Err(type_error(
                    "string indices must be integers, not 'str'".into(),
                ));
            }
            Some(s) => {
                let v: Value = serde_json::from_str(s).unwrap_or(Value::Null);
                return Err(type_error(format!(
                    "'{}' object is not iterable",
                    py::type_name(&v)
                )));
            }
        };
        (items, total)
    };
    Ok(Page { text, items, total })
}

/// Every record of the first `take` records of `page` planned in order (the page's transaction in Python): their
/// CVE ids, or the index and failure of the first that fails.
fn check_page(
    page: &Page,
    take: usize,
    now: &str,
    caps: &Caps,
) -> Result<Vec<String>, (usize, Fail)> {
    let mut ids = Vec::with_capacity(take);
    for (i, r) in page.items.iter().take(take).enumerate() {
        ids.push(plan_item(&page.text[r.clone()], now, caps).map_err(|f| (i, f))?.id);
    }
    Ok(ids)
}

/// The `--path` documents: a directory's `*.json` entries sorted by name (`sorted(path.glob("*.json"))`, not
/// recursive, hidden names and directories so named included), else the path itself.
fn list_files(path: &Path, shown: &str, caps: &Caps) -> Result<Vec<(PathBuf, String)>, Fail> {
    if !std::fs::metadata(path).is_ok_and(|m| m.is_dir()) {
        return Ok(vec![(path.to_path_buf(), shown.to_owned())]);
    }
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    let Ok(rd) = std::fs::read_dir(path) else {
        return Ok(Vec::new()); // unreadable: glob yields nothing
    };
    for (n, e) in rd.flatten().enumerate() {
        if n >= caps.entries {
            return Err(Fail::Caught(format!(
                "nvd: more than {} entries in {shown}; refusing",
                caps.entries
            )));
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".json") {
            if out.len() >= caps.files {
                return Err(Fail::Caught(format!(
                    "nvd: more than {} files in {shown}; refusing",
                    caps.files
                )));
            }
            out.push((name, e.path()));
        }
    }
    out.sort();
    let prefix = if shown.ends_with('/') {
        shown.to_owned()
    } else {
        format!("{shown}/")
    };
    Ok(out
        .into_iter()
        .map(|(name, p)| (p, format!("{prefix}{name}")))
        .collect())
}

/// Read one `--path` document (a regular file, at most `max` bytes) with Python's `OSError` texts.
fn read_file(path: &Path, shown: &str, max: u64) -> Result<Vec<u8>, Fail> {
    use std::io::Read;
    let f = feed::open_regular(path).map_err(|e| Fail::Caught(e.with_class()))?;
    let mut body = Vec::new();
    f.take(max + 1)
        .read_to_end(&mut body)
        .map_err(|e| Fail::Caught(format!("{}: {}", feed::py_exception(&e), feed::os_error(&e, path))))?;
    if body.len() as u64 > max {
        return Err(Fail::Caught(format!(
            "nvd: {shown}: larger than {max} bytes; refusing"
        )));
    }
    Ok(body)
}

// ------------------------------------------------------------------------------------------------ the API client

/// `_NvdClient`: the `apiKey` header, pacing, retries with backoff and `Retry-After`, no redirects.
struct Client {
    url: String,
    allow_http: bool,
    key: Option<String>,
    timing: Timing,
    last: Option<Instant>,
    requests: u64,
    caps: Caps,
    /// One HTTP client for every request of the run (built at the first one).
    http: Option<reqwest::Client>,
}

/// `m` with every occurrence of the API key replaced by `***` (keys shorter than 8 characters are not searched for:
/// that would mangle ordinary text, and a real key is a 36-character UUID).
fn redact(key: Option<&str>, m: String) -> String {
    match key {
        Some(k) if k.len() >= 8 => m.replace(k, "***"),
        _ => m,
    }
}

impl Client {
    /// GET `<url>?<query>`; the failure as Python's sync reports it (every HTTP failure is caught there). Log lines
    /// and failures pass [`redact`].
    async fn get(&mut self, query: &[(&str, String)], say: &Progress) -> Result<Vec<u8>, Fail> {
        let key = self.key.clone();
        let line = |m: String| say.line(redact(key.as_deref(), m));
        self.get_raw(query, &line).await.map_err(|f| match f {
            Fail::Caught(m) => Fail::Caught(redact(key.as_deref(), m)),
            Fail::Uncaught(m) => Fail::Uncaught(redact(key.as_deref(), m)),
        })
    }

    async fn get_raw(&mut self, query: &[(&str, String)], say: &(dyn Fn(String) + Sync)) -> Result<Vec<u8>, Fail> {
        self.requests += 1;
        if self.requests > self.caps.requests {
            return Err(Fail::Caught(format!(
                "nvd: more than {} API requests in one run; refusing",
                self.caps.requests
            )));
        }
        let url = format!("{}?{}", self.url, encode_query(query));
        let mut headers = Vec::new();
        if let Some(k) = &self.key {
            let mut v = reqwest::header::HeaderValue::from_str(k).map_err(|_| {
                Fail::Caught("nvd: the API key is not a valid HTTP header value".into())
            })?;
            v.set_sensitive(true);
            headers.push((reqwest::header::HeaderName::from_static("apikey"), v));
        }
        let pause = if self.key.is_some() {
            self.timing.pause_with_key
        } else {
            self.timing.pause_without_key
        };
        let g = feed::Get {
            url: &url,
            max_bytes: self.caps.response_bytes,
            allow_http: self.allow_http,
            timeout: feed::TIMEOUT,
            accept: Some("application/json"),
            too_large: None,
            same_origin_redirects: false,
        };
        if self.http.is_none() {
            self.http = Some(
                feed::fetch_client(feed::TIMEOUT, self.allow_http, true)
                    .map_err(|m| Fail::Caught(format!("nvd: {m}")))?,
            );
        }
        let Some(http) = self.http.clone() else {
            return Err(Fail::Caught("nvd: native importer: no HTTP client".into()));
        };
        let mut attempt = 0u32;
        loop {
            if let Some(last) = self.last {
                let since = last.elapsed();
                if since < pause {
                    tokio::time::sleep(pause - since).await;
                }
            }
            let got = feed::fetch(&http, &g, &headers, Some(self.timing.request_total)).await;
            self.last = Some(Instant::now());
            let backoff = self
                .timing
                .backoff_base
                .saturating_mul(2u32.saturating_pow(attempt))
                .min(self.timing.backoff_max);
            let delay = match got {
                Ok((body, _)) => return Ok(body),
                Err(feed::FetchError::Transport(m)) => {
                    if attempt >= self.timing.retries {
                        return Err(Fail::Caught(format!("TransportError: {m}")));
                    }
                    say(format!(
                        "nvd: native importer: {m}; retry {} of {} in {:.1} s",
                        attempt + 1,
                        self.timing.retries,
                        backoff.as_secs_f64()
                    ));
                    backoff
                }
                Err(feed::FetchError::Status {
                    code,
                    retry_after,
                    message,
                }) => {
                    if !RETRY_STATUS.contains(&code) || attempt >= self.timing.retries {
                        return Err(Fail::Caught(format!("HTTPStatusError: {message}")));
                    }
                    let wait = retry_after
                        .as_deref()
                        .and_then(|r| retry_after_secs(r, unix_secs()))
                        .map_or(backoff, |s| {
                            Duration::try_from_secs_f64(s)
                                .unwrap_or(self.timing.backoff_max)
                                .min(self.timing.backoff_max)
                        });
                    say(format!(
                        "nvd: native importer: {message}; retry {} of {} in {:.1} s",
                        attempt + 1,
                        self.timing.retries,
                        wait.as_secs_f64()
                    ));
                    wait
                }
                Err(feed::FetchError::Other(m)) => return Err(Fail::Caught(format!("nvd: {m}"))),
            };
            tokio::time::sleep(delay).await;
            attempt += 1;
        }
    }
}

/// A query string as httpx encodes `params`: unreserved characters kept, space as `+`, the rest `%XX`.
fn encode_query(query: &[(&str, String)]) -> String {
    let enc = |s: &str| {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                    out.push(char::from(b));
                }
                b' ' => out.push('+'),
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    };
    query
        .iter()
        .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// `_retry_after`: seconds (`float()`; at least 0), or an HTTP date with a zone (RFC 2822 / IMF-fixdate) minus now;
/// `None` for anything else. `now` is seconds since the Unix epoch.
fn retry_after_secs(raw: &str, now: f64) -> Option<f64> {
    if let Some(f) = py::float_str(raw) {
        return Some(if f.is_nan() { 0.0 } else { f.max(0.0) });
    }
    let t = http_date(raw)?;
    Some((t - now).max(0.0))
}

/// An RFC 2822 date with a zone (`Wed, 21 Oct 2015 07:28:00 GMT`, `21 Oct 2015 07:28:00 +0200`) as seconds since the
/// Unix epoch.
fn http_date(raw: &str) -> Option<f64> {
    let s = raw.trim();
    let s = match s.split_once(',') {
        Some((_, rest)) => rest.trim(),
        None => s,
    };
    let parts: Vec<&str> = s.split_whitespace().collect();
    if parts.len() != 5 {
        return None;
    }
    let day: u32 = parts[0].parse().ok()?;
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let month = MONTHS
        .iter()
        .position(|m| parts[1].eq_ignore_ascii_case(m))? as u32
        + 1;
    let year: i64 = parts[2].parse().ok()?;
    let hms: Vec<u32> = parts[3]
        .split(':')
        .map(|p| p.parse().ok())
        .collect::<Option<_>>()?;
    let (h, mi, se) = match hms.as_slice() {
        [h, m] => (*h, *m, 0),
        [h, m, s] => (*h, *m, *s),
        _ => return None,
    };
    let offset: i64 = match parts[4] {
        z if z.eq_ignore_ascii_case("GMT") || z.eq_ignore_ascii_case("UT") || z.eq_ignore_ascii_case("UTC") || z == "Z" => 0,
        z if (z.starts_with('+') || z.starts_with('-')) && z.len() == 5 => {
            let n: i64 = z[1..].parse().ok()?;
            let secs = (n / 100) * 3600 + (n % 100) * 60;
            if z.starts_with('-') { -secs } else { secs }
        }
        _ => return None,
    };
    if !(1..=12).contains(&month) || day == 0 || day > days_in_month(year, month) || h > 23 || mi > 59 || se > 60 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    Some((days * 86_400 + i64::from(h) * 3600 + i64::from(mi) * 60 + i64::from(se) - offset) as f64)
}

fn unix_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |d| d.as_secs_f64())
}

// ------------------------------------------------------------------------------------------------ timestamps

/// Now, in microseconds since the Unix epoch.
fn now_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX))
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's algorithm).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// (year, month, day) of a day number ([`days_from_civil`] reversed).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        2 if (y % 4 == 0 && y % 100 != 0) || y % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// `_iso`: UTC, milliseconds (truncated), `Z`: `2026-11-11T08:00:00.123Z`.
pub fn iso(us: i64) -> String {
    let secs = us.div_euclid(1_000_000);
    let ms = us.rem_euclid(1_000_000) / 1000;
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let rem = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// `_parse_ts`: `datetime.fromisoformat` (naive = UTC) as microseconds since the Unix epoch, or the `ValueError` text.
/// The forms of Python 3.13 except ISO week dates: `YYYY-MM-DD` / `YYYYMMDD`, then one separator character and a time
/// `HH[:MM[:SS[.f]]]` / `HHMM[SS[.f]]` (`.` or `,`, extra fraction digits dropped), then `Z` or `±HH[:MM[:SS[.f]]]` /
/// `±HHMM[SS]`.
pub fn fromisoformat(s: &str) -> Result<i64, String> {
    let invalid = || format!("Invalid isoformat string: {}", py::repr_str(s));
    let b = s.as_bytes();
    let digits = |r: Range<usize>| -> Option<u32> {
        let t = s.get(r)?;
        (!t.is_empty() && t.bytes().all(|c| c.is_ascii_digit())).then(|| t.parse().ok())?
    };
    if b.len() < 7 {
        return Err(invalid());
    }
    let (y, mo, d, rest) = if b.get(4) == Some(&b'-') {
        if b.get(7) != Some(&b'-') {
            return Err(invalid());
        }
        let (Some(y), Some(mo), Some(d)) = (digits(0..4), digits(5..7), digits(8..10)) else {
            return Err(invalid());
        };
        (y, mo, d, s.get(10..).ok_or_else(invalid)?)
    } else {
        let (Some(y), Some(mo), Some(d)) = (digits(0..4), digits(4..6), digits(6..8)) else {
            return Err(invalid());
        };
        (y, mo, d, s.get(8..).ok_or_else(invalid)?)
    };
    if y == 0 {
        return Err("year 0 is out of range".into());
    }
    if !(1..=12).contains(&mo) {
        return Err("month must be in 1..12".into());
    }
    if d == 0 || d > days_in_month(i64::from(y), mo) {
        return Err("day is out of range for month".into());
    }
    let mut us = days_from_civil(i64::from(y), mo, d) * 86_400 * 1_000_000;
    let mut chars = rest.chars();
    if chars.next().is_some() {
        let time = chars.as_str();
        if time.is_empty() {
            return Err(invalid());
        }
        let tz_at = time.find(['+', '-', 'Z']).unwrap_or(time.len());
        let (clock, tz) = time.split_at(tz_at);
        let (h, mi, se, frac) = hms(clock).ok_or_else(invalid)?;
        if h > 23 {
            return Err("hour must be in 0..23".into());
        }
        if mi > 59 {
            return Err("minute must be in 0..59".into());
        }
        if se > 59 {
            return Err("second must be in 0..59".into());
        }
        us += (i64::from(h) * 3600 + i64::from(mi) * 60 + i64::from(se)) * 1_000_000 + frac;
        if !tz.is_empty() {
            let off = if tz == "Z" {
                0
            } else {
                let sign = if tz.starts_with('-') { -1 } else { 1 };
                let (oh, om, os, of) = hms(&tz[1..]).ok_or_else(invalid)?;
                if tz.starts_with('Z') || oh > 23 || om > 59 || os > 59 {
                    return Err(invalid());
                }
                sign * ((i64::from(oh) * 3600 + i64::from(om) * 60 + i64::from(os)) * 1_000_000 + of)
            };
            us -= off;
        }
    }
    Ok(us)
}

/// `HH`, `HH:MM`, `HH:MM:SS[.f]`, `HHMM`, `HHMMSS[.f]` -> (h, m, s, microseconds).
fn hms(t: &str) -> Option<(u32, u32, u32, i64)> {
    let (main, frac) = match t.find(['.', ',']) {
        Some(i) => (&t[..i], Some(&t[i + 1..])),
        None => (t, None),
    };
    let num = |x: &str| -> Option<u32> {
        (x.len() == 2 && x.bytes().all(|c| c.is_ascii_digit())).then(|| x.parse().ok())?
    };
    if !main.is_ascii() {
        return None; // the slicing below is by byte
    }
    let parts: Vec<&str> = if main.contains(':') {
        main.split(':').collect()
    } else {
        if main.len() % 2 != 0 || main.len() > 6 {
            return None;
        }
        (0..main.len() / 2).map(|i| &main[2 * i..2 * i + 2]).collect()
    };
    let vals: Vec<u32> = parts.iter().map(|p| num(p)).collect::<Option<_>>()?;
    let (h, m, s) = match vals.as_slice() {
        [h] => (*h, 0, 0),
        [h, m] => (*h, *m, 0),
        [h, m, s] => (*h, *m, *s),
        _ => return None,
    };
    let us = match frac {
        None => 0,
        Some(_) if vals.len() < 3 => return None,
        Some(f) => {
            if !f.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            let six: String = f.chars().chain(std::iter::repeat('0')).take(6).collect();
            six.parse().ok()?
        }
    };
    Some((h, m, s, us))
}

/// `parse_since`: `2020`, `2020-05`, `2020-05-17` or a full ISO timestamp (naive = UTC). The patterns are
/// Python's `\d{4}` and `\d{4}-\d{2}` (Unicode decimal digits, matched by character), so a year in other digits is
/// padded too and then refused by `fromisoformat`, with the padded text in the message as there.
pub fn parse_since(s: &str) -> Result<i64, String> {
    let s = py::strip(s);
    let c: Vec<char> = s.chars().collect();
    let digits = |r: std::ops::Range<usize>| c[r].iter().all(|ch| py::is_decimal(*ch));
    let padded = if c.len() == 4 && digits(0..4) {
        format!("{s}-01-01")
    } else if c.len() == 7 && digits(0..4) && c[4] == '-' && digits(5..7) {
        format!("{s}-01")
    } else {
        s.to_owned()
    };
    fromisoformat(&padded)
}

// ------------------------------------------------------------------------------------------------ the run

/// One API query of a run.
#[derive(Debug, Clone, Copy)]
enum Query {
    /// A full pull (no date filter).
    Full,
    /// A delta window `[lo, hi]` (microseconds).
    Window(i64, i64),
}

/// The API part of `sync`.
struct ApiPlan {
    queries: VecDeque<Query>,
    /// The query being paged and its next `startIndex`.
    current: Option<(Query, u64)>,
    /// The end of the run's windows (`datetime.now(UTC)` before any request).
    end: i64,
    /// Whether this run may write `nvd:progress` and return a cursor (`--since` rule).
    trust: bool,
    /// `full` / `delta since <iso>`.
    mode: String,
    /// The end of the last completed window (or of the full pull).
    cursor: Option<String>,
}

enum Input {
    Files {
        files: VecDeque<(PathBuf, String)>,
        origin: String,
    },
    Ids {
        client: Client,
        ids: VecDeque<String>,
        n: usize,
    },
    Api {
        client: Client,
        plan: ApiPlan,
        with_key: bool,
    },
    Done,
}

/// A checked page whose records are being emitted.
struct Live {
    page: Page,
    take: usize,
    pos: usize,
}

/// The state of one run (the operation stream).
struct Run {
    view: Arc<dyn MirrorView>,
    caps: Caps,
    now: String,
    limit: Option<u64>,
    count: u64,
    say: Progress,
    input: Input,
    page: Option<Live>,
    /// `affected` rows emitted per CVE id in this run (an id seen again replaces those, not the stored ones).
    emitted: HashMap<String, u32>,
    /// The API key, redacted from every message.
    secret: Option<String>,
    tail: TailCell,
    done: bool,
}

/// The operations of the run, one chunk at a time.
fn ops(run: Run) -> Ops {
    futures_util::stream::unfold(Some(run), |state| async move {
        let mut r = state?;
        match r.next_ops().await {
            Ok(None) => None,
            Ok(Some(ops)) => Some((Ok(ops), Some(r))),
            Err(err) => Some((Err(err), None)),
        }
    })
    .flat_map(|r: StepResult<Vec<RowOp>>| {
        futures_util::stream::iter(match r {
            Ok(v) => v.into_iter().map(Ok).collect::<Vec<_>>(),
            Err(e) => vec![Err(e)],
        })
    })
    .boxed()
}

impl Run {
    fn redact(&self, m: String) -> String {
        redact(self.secret.as_deref(), m)
    }

    fn set_tail(&mut self, t: Tail) {
        let t = Tail {
            message: t.message.map(|m| self.redact(m)),
            ..t
        };
        if let Ok(mut g) = self.tail.lock() {
            *g = Some(t);
        }
        self.done = true;
        self.page = None;
        self.input = Input::Done;
    }

    fn cursor_now(&self) -> Option<String> {
        match &self.input {
            Input::Api { plan, .. } if plan.trust => plan.cursor.clone(),
            _ => None,
        }
    }

    /// The run stops at a failure (the `except` of `sync`, or `ops.sync_source` for an uncaught one). The
    /// `nvd:progress` rows of the windows completed before stay (written as each window completed, as Python's
    /// `set_sync_state` commits them).
    fn fail(&mut self, fail: Fail, extra: Option<u64>) {
        let tail = match fail {
            Fail::Caught(m) => {
                let records = self.count + extra.unwrap_or(0);
                Tail {
                    status: if records > 0 { "partial" } else { "error" }.into(),
                    records,
                    total: None,
                    cursor: self.cursor_now(),
                    message: Some(m),
                }
            }
            Fail::Uncaught(m) => Tail {
                status: "error".into(),
                records: 0,
                total: None,
                cursor: None,
                message: Some(m),
            },
        };
        self.set_tail(tail);
    }

    fn exhausted(&self) -> bool {
        self.limit.is_some_and(|l| self.count >= l)
    }

    /// The end of a run that did not fail (also when the limit stopped it).
    fn finish(&mut self) -> Vec<RowOp> {
        let limited = self.exhausted();
        let tail = match &self.input {
            Input::Files { origin, .. } => Tail {
                status: "ok".into(),
                records: self.count,
                message: Some(format!("from file {origin}")),
                ..Tail::default()
            },
            Input::Ids { n, .. } => Tail {
                status: "ok".into(),
                records: self.count,
                message: Some(format!("{n} ids")),
                ..Tail::default()
            },
            Input::Api { plan, with_key, .. } => Tail {
                status: if limited { "partial" } else { "ok" }.into(),
                records: self.count,
                total: None,
                cursor: self.cursor_now(),
                message: Some(format!(
                    "{}, NVD API {} key{}",
                    plan.mode,
                    if *with_key { "with" } else { "without" },
                    if limited { ", limit reached" } else { "" }
                )),
            },
            Input::Done => Tail {
                status: "ok".into(),
                records: self.count,
                ..Tail::default()
            },
        };
        self.set_tail(tail);
        Vec::new()
    }

    /// The next document, `None` when there is none left.
    async fn next_doc(&mut self) -> Result<Option<Vec<u8>>, Fail> {
        let say = &self.say;
        match &mut self.input {
            Input::Files { files, .. } => {
                let Some((p, shown)) = files.pop_front() else {
                    return Ok(None);
                };
                let max = self.caps.file_bytes;
                tokio::task::spawn_blocking(move || read_file(&p, &shown, max))
                    .await
                    .map_err(|e| Fail::Caught(format!("nvd: native importer: read task failed: {e}")))?
                    .map(Some)
            }
            Input::Ids { client, ids, .. } => {
                let Some(id) = ids.pop_front() else {
                    return Ok(None);
                };
                let id = py::strip(&id).to_uppercase();
                client.get(&[("cveId", id)], say).await.map(Some)
            }
            Input::Api { client, plan, .. } => {
                if plan.current.is_none() {
                    match plan.queries.pop_front() {
                        None => return Ok(None),
                        Some(q) => plan.current = Some((q, 0)),
                    }
                }
                let Some((q, start)) = plan.current else {
                    return Ok(None);
                };
                let mut query: Vec<(&str, String)> = Vec::new();
                if let Query::Window(lo, hi) = q {
                    query.push(("lastModStartDate", iso(lo)));
                    query.push(("lastModEndDate", iso(hi)));
                }
                query.push(("resultsPerPage", PAGE_SIZE.to_string()));
                query.push(("startIndex", start.to_string()));
                client.get(&query, say).await.map(Some)
            }
            Input::Done => Ok(None),
        }
    }

    /// After a page was written: `_cve_pages`'s paging (`start += len(items)`; done when there were none or `start >=
    /// totalResults`), then the window's cursor and its `nvd:progress` row, returned to be written at once (Python's
    /// `set_sync_state` commits it as soon as the window completes; a later failure does not undo it).
    fn after_page(&mut self, n_items: usize, total: Option<Value>) -> Result<Option<RowOp>, Fail> {
        let now = self.now.clone();
        let Input::Api { plan, .. } = &mut self.input else {
            return Ok(None);
        };
        let Some((q, start)) = plan.current else {
            return Ok(None);
        };
        let next = start + n_items as u64;
        let finished = n_items == 0 || {
            match total {
                None => true,
                Some(v) => match number(&v) {
                    Some(t) => next as f64 >= t,
                    None => {
                        return Err(type_error(format!(
                            "'>=' not supported between instances of 'int' and '{}'",
                            py::type_name(&v)
                        )));
                    }
                },
            }
        };
        if !finished {
            plan.current = Some((q, next));
            return Ok(None);
        }
        plan.current = None;
        match q {
            Query::Full => plan.cursor = Some(iso(plan.end)),
            Query::Window(_, hi) => {
                let c = iso(hi);
                plan.cursor = Some(c.clone());
                if plan.trust {
                    return Ok(Some(native::sync_row(
                        PROGRESS_KEY,
                        "ok",
                        0,
                        Some(c),
                        Some("last completed window end".into()),
                        &now,
                    )));
                }
            }
        }
        Ok(None)
    }

    /// The operations of the next step: a chunk of the live page, the `nvd:progress` row of a window that completed,
    /// or the end. `None` once the run is over.
    async fn next_ops(&mut self) -> StepResult<Option<Vec<RowOp>>> {
        loop {
            if self.done {
                return Ok(None);
            }
            if let Some(live) = &self.page {
                if live.pos < live.take {
                    return self.chunk().await.map(Some);
                }
                let Some(live) = self.page.take() else {
                    continue;
                };
                self.count += live.take as u64;
                self.say.line(format!("nvd: {} records", self.count));
                if self.exhausted() {
                    return Ok(Some(self.finish()));
                }
                // `len(items)`: the records of a list (any other shape that got here was empty)
                match self.after_page(live.page.items.len(), live.page.total) {
                    Ok(None) => {}
                    Ok(Some(progress)) => return Ok(Some(vec![progress])),
                    Err(f) => {
                        self.fail(f, None);
                        return Ok(Some(Vec::new()));
                    }
                }
                continue;
            }
            let bytes = match self.next_doc().await {
                Ok(None) => return Ok(Some(self.finish())),
                Ok(Some(b)) => b,
                Err(f) => {
                    self.fail(f, None);
                    return Ok(Some(Vec::new()));
                }
            };
            let caps = self.caps;
            let now = self.now.clone();
            let left = self.limit.map(|l| l.saturating_sub(self.count));
            let count = self.count;
            let checked = tokio::task::spawn_blocking(move || {
                let page = split_page(bytes, &caps).map_err(|f| (0, f))?;
                let take = left.map_or(page.items.len(), |l| {
                    page.items.len().min(usize::try_from(l).unwrap_or(usize::MAX))
                });
                if count + take as u64 > caps.records {
                    return Err((
                        0,
                        Fail::Caught(format!(
                            "nvd: more than {} records in one run; refusing",
                            caps.records
                        )),
                    ));
                }
                let ids = check_page(&page, take, &now, &caps)?;
                Ok((page, take, ids))
            })
            .await
            .map_err(|e| native::internal(NAME, format!("check task failed: {e}")))?;
            match checked {
                Ok((page, take, ids)) => {
                    // the stored rows are part of the check: a refusal must come before the page's first operation
                    if let Err(f) = self.check_stored(ids).await? {
                        self.fail(f, None);
                        return Ok(Some(Vec::new()));
                    }
                    self.page = Some(Live { page, take, pos: 0 });
                    continue;
                }
                Err((k, f)) => {
                    // Python counted the records before the failing one, then rolled the page back
                    self.fail(f, Some(k as u64));
                    return Ok(Some(Vec::new()));
                }
            }
        }
    }

    /// The check of a page against the stored rows, before its first operation: a CVE (not emitted yet in this run)
    /// with more stored `affected` rows than `Caps::matches` (only rows `py-sources` wrote before a switch) refuses
    /// the run at this page. Read in groups of [`CHECK_IDS`] ids, nothing kept but the counts of one group.
    async fn check_stored(&self, ids: Vec<String>) -> StepResult<Result<(), Fail>> {
        let mut seen: HashSet<&str> = HashSet::new();
        let todo: Vec<String> = ids
            .iter()
            .filter(|id| !self.emitted.contains_key(id.as_str()) && seen.insert(id.as_str()))
            .cloned()
            .collect();
        for group in todo.chunks(CHECK_IDS) {
            let rows = self.view.rows_by_id(MirrorTable::Affected, NAME, group).await?;
            if rows.len() <= self.caps.matches {
                continue;
            }
            for (id, of) in rows::group_by(&rows, "vuln_id") {
                if of.len() > self.caps.matches {
                    return Ok(Err(Fail::Caught(format!(
                        "nvd: native importer: {id}: {} stored affected rows (more than {}); refusing, sync nvd \
                         with the python implementation",
                        of.len(),
                        self.caps.matches
                    ))));
                }
            }
        }
        Ok(Ok(()))
    }

    /// The stored `affected` rows of `ids`. A CVE with more stored rows than the caps allow was refused by
    /// [`Run::check_stored`]; finding one here (the mirror changed during the run) is an internal error.
    async fn stored(&self, ids: &[String]) -> StepResult<Vec<JsonMap>> {
        let rows = self.view.rows_by_id(MirrorTable::Affected, NAME, ids).await?;
        if rows.len() > self.caps.matches {
            for (id, of) in rows::group_by(&rows, "vuln_id") {
                if of.len() > self.caps.matches {
                    return Err(native::internal(
                        NAME,
                        format!(
                            "{id}: {} stored affected rows (more than {}); refusing, sync nvd with the python \
                             implementation",
                            of.len(),
                            self.caps.matches
                        ),
                    ));
                }
            }
        }
        Ok(rows)
    }

    /// The operations of the next chunk of the live page: read in groups of at most [`GROUP`] records, closed at
    /// [`CHUNK_RECORDS`] records, [`CHUNK_BYTES`] of record text or [`CHUNK_NEW`] new rows (checked per record) or
    /// [`CHUNK_STORED`] stored rows (checked per group).
    async fn chunk(&mut self) -> StepResult<Vec<RowOp>> {
        let mut plans: Vec<Plan> = Vec::new();
        let (mut bytes, mut new) = (0usize, 0usize);
        let mut stored: Vec<JsonMap> = Vec::new();
        let mut read: HashSet<String> = HashSet::new();
        while let Some(live) = self.page.as_mut() {
            if live.pos >= live.take
                || plans.len() >= CHUNK_RECORDS
                || bytes >= CHUNK_BYTES
                || new >= CHUNK_NEW
                || stored.len() >= CHUNK_STORED
            {
                break;
            }
            let start = plans.len();
            while plans.len() - start < GROUP
                && live.pos < live.take
                && bytes < CHUNK_BYTES
                && new < CHUNK_NEW
            {
                let r = live.page.items[live.pos].clone();
                live.pos += 1;
                bytes += r.len();
                let p = plan_item(&live.page.text[r], &self.now, &self.caps).map_err(|f| {
                    native::internal(NAME, format!("a checked record failed: {f:?}"))
                })?;
                new += p.affected.len();
                plans.push(p);
            }
            let ids: Vec<String> = plans[start..]
                .iter()
                .filter(|p| !self.emitted.contains_key(&p.id))
                .filter(|p| read.insert(p.id.clone()))
                .map(|p| p.id.clone())
                .collect();
            if !ids.is_empty() {
                stored.extend(self.stored(&ids).await?);
            }
        }
        if let Some(live) = self.page.as_mut()
            && live.pos >= live.take
        {
            live.page.text = String::new(); // emitted: release the text (the ranges stay for `len(items)`)
        }
        let of = rows::group_by(&stored, "vuln_id");
        let none = Vec::new();
        let mut ops = Vec::new();
        for p in plans {
            // `store_raw`, `upsert_vulnerability`, `replace_children` + `add_affected`
            ops.push(p.raw);
            ops.push(p.vulnerability);
            let n_new = u32::try_from(p.affected.len()).unwrap_or(u32::MAX);
            match self.emitted.get(&p.id) {
                Some(&n) => {
                    // emitted earlier in this run (perhaps not applied yet): replace those rows
                    ops.extend((0..n).map(|_| RowOp::Delete {
                        table: MirrorTable::Affected,
                        key: [
                            ("source".to_owned(), json!(NAME)),
                            ("vuln_id".to_owned(), json!(p.id)),
                        ]
                        .into_iter()
                        .collect(),
                    }));
                    ops.extend(p.affected.into_iter().map(|row| RowOp::Upsert {
                        table: MirrorTable::Affected,
                        row,
                    }));
                }
                None => ops.extend(rows::replace_affected(
                    of.get(p.id.as_str()).unwrap_or(&none),
                    p.affected,
                    DeleteKey::Record,
                )),
            }
            self.emitted.insert(p.id, n_new);
        }
        Ok(ops)
    }
}

#[async_trait]
impl Source for NvdSource {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn caps() -> Caps {
        Caps::default()
    }

    fn rows_of(cve: Value) -> Plan {
        plan(cve, "now", &caps()).unwrap()
    }

    fn fail_of(cve: Value) -> Fail {
        plan(cve, "now", &caps()).unwrap_err()
    }

    #[test]
    fn cpe_strings_split_like_base_py() {
        assert_eq!(
            cpe_fields("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*").len(),
            13
        );
        // `(?<!\\):` then `\\(.)` -> `\1`: an escaped colon stays in its field
        assert_eq!(
            cpe_fields(r"cpe:2.3:a:x\:y:z"),
            vec!["cpe", "2.3", "a", "x:y", "z"]
        );
        assert_eq!(cpe_fields(r"a\\:b"), vec![r"a\:b"]); // the lookbehind sees the backslash
        assert_eq!(cpe_fields("a\\\nb:c"), vec!["a\\\nb", "c"]);
        assert_eq!(cpe_fields(""), vec![""]);
        assert_eq!(cpe_fields(r"x\"), vec![r"x\"]);
    }

    fn cve(extra: Value) -> Value {
        let mut c = json!({"id": "CVE-2099-0001", "lastModified": "2026-01-01T00:00:00.000",
                           "published": "2025-01-01T00:00:00.000", "vulnStatus": "Analyzed"});
        for (k, v) in extra.as_object().unwrap() {
            c[k] = v.clone();
        }
        c
    }

    fn vuln_row(p: &Plan) -> JsonMap {
        match &p.vulnerability {
            RowOp::Upsert { row, .. } => row.clone(),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn the_best_cvss_metric_is_chosen_like_python() {
        let m = |t: &str, v: &str, s: f64| {
            json!({"type": t, "cvssData": {"version": v, "baseScore": s, "vectorString": format!("V{v}")}})
        };
        // Primary before Secondary whatever the version; newest version within one type
        let p = rows_of(cve(json!({"metrics": {
            "cvssMetricV40": [m("Secondary", "4.0", 9.9)],
            "cvssMetricV31": [m("Primary", "3.1", 7.5), m("Primary", "3.1", 1.0)],
            "cvssMetricV2": [m("Primary", "2.0", 5.0)],
        }})));
        let r = vuln_row(&p);
        assert_eq!(r["cvss_score"], json!(7.5));
        assert_eq!(r["cvss_version"], "3.1");
        assert_eq!(r["severity"], "HIGH");
        let p = rows_of(cve(json!({"metrics": {
            "cvssMetricV40": [m("Secondary", "4.0", 9.9)],
            "cvssMetricV2": [{"type": "Secondary", "baseSeverity": "moderate", "cvssData": {"baseScore": 1.0, "version": "2.0"}}],
        }})));
        let r = vuln_row(&p);
        assert_eq!((r["cvss_version"].as_str(), r["severity"].as_str()), (Some("4.0"), Some("CRITICAL")));
        // V2's severity outside cvssData; a falsy one inside falls back to it
        let p = rows_of(cve(json!({"metrics": {"cvssMetricV2": [
            {"type": "Primary", "baseSeverity": "moderate", "cvssData": {"baseScore": 9.0, "baseSeverity": ""}}]}})));
        assert_eq!(vuln_row(&p)["severity"], "MEDIUM");
        // no metrics: NULLs
        let r = vuln_row(&rows_of(cve(json!({}))));
        assert_eq!((r["cvss_score"].clone(), r["severity"].clone()), (Value::Null, Value::Null));
        // a bool score is an int
        let p = rows_of(cve(json!({"metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": true}}]}})));
        assert_eq!((vuln_row(&p)["cvss_score"].clone(), vuln_row(&p)["severity"].clone()), (json!(1.0), json!("LOW")));
    }

    #[test]
    fn cwes_descriptions_and_rejected_records() {
        let p = rows_of(cve(json!({
            "descriptions": [{"lang": "es", "value": "x"}, {"lang": "en", "value": "English"}, 5],
            "weaknesses": [
                {"type": "Secondary", "description": [{"value": "CWE-79"}, {"value": "NVD-CWE-Other"}]},
                {"type": "Primary", "description": [{"value": "CWE-917"}, {"value": "CWE-79"}, {}]},
            ],
            "cveTags": null, "sourceIdentifier": "psirt@example.org"
        })));
        let r = vuln_row(&p);
        assert_eq!(r["summary"], "English");
        assert_eq!(r["cwes"], json!(["CWE-917", "CWE-79"]));
        assert_eq!(r["extra"], json!({"sourceIdentifier": "psirt@example.org", "cveTags": null}));
        assert_eq!(vuln_row(&rows_of(cve(json!({}))))["extra"]["cveTags"], json!([]));
        let p = rows_of(cve(json!({"vulnStatus": "Rejected", "configurations": null})));
        let r = vuln_row(&p);
        assert_eq!((r["state"].as_str(), r["withdrawn"].as_str()), (Some("REJECTED"), Some("2026-01-01T00:00:00.000")));
        assert!(p.affected.is_empty());
    }

    #[test]
    fn cpe_matches_become_rows_like_add_cpe() {
        let cm = |crit: &str, extra: Value| {
            let mut m = json!({"vulnerable": true, "criteria": crit});
            for (k, v) in extra.as_object().unwrap() {
                m[k] = v.clone();
            }
            m
        };
        let p = rows_of(cve(json!({"configurations": [{"nodes": [{"cpeMatch": [
            cm("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", json!({"versionStartIncluding": "2.0", "versionEndExcluding": "2.15.0", "matchCriteriaId": "A"})),
            cm("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", json!({"versionStartIncluding": "9", "matchCriteriaId": "A"})),
            cm("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", json!({"versionEndExcluding": "120.0.6099.109", "matchCriteriaId": "B"})),
            cm("cpe:2.3:a:Foo_Bar:Some_Product:1.2.3:*:*:*:*:*:*:*", json!({})),
            cm("cpe:2.3:a:foo:bar:1.2.3:*:*:*:*:*:*:*", json!({})),
            cm("cpe:2.3:a:foo:dash:-:*:*:*:*:*:*:*", json!({"matchCriteriaId": "D"})),
            cm("cpe:2.3:a:foo:beta:2.0:beta1:*:*:*:*:*:*", json!({"matchCriteriaId": "E"})),
            cm("cpe:2.3:a:foo:all:*:*:*:*:*:*:*:*", json!({"matchCriteriaId": 7})),
            cm("cpe:2.3:a:foo:dup:*:*:*:*:*:*:*:*", json!({"matchCriteriaId": 7.0})),
            {"vulnerable": false, "criteria": "cpe:2.3:a:no:no:*:*:*:*:*:*:*:*"},
            cm("not a cpe", json!({"matchCriteriaId": "F"})),
        ]}]}]})));
        let a = &p.affected;
        assert_eq!(a.len(), 6, "{a:#?}");
        assert_eq!(a[0]["events"], json!([{"introduced": "2.0"}, {"fixed": "2.15.0"}]));
        assert_eq!(a[0]["extra"], json!({"matchCriteriaId": "A"}));
        assert_eq!((a[0]["vendor"].as_str(), a[0]["product"].as_str()), (Some("apache"), Some("log4j")));
        assert_eq!(a[1]["events"], json!([{"introduced": "0"}, {"fixed": "120.0.6099.109"}]));
        // the same id ("" fallback: json.dumps of equal matches) once; vendor/product normalized
        assert_eq!(a[2]["versions"], json!(["1.2.3"]));
        assert_eq!((a[2]["vendor"].as_str(), a[2]["product"].as_str()), (Some("foo bar"), Some("some product")));
        assert_eq!(a[2]["events"], Value::Null);
        assert_eq!(a[2]["extra"], json!({"matchCriteriaId": null}));
        assert_eq!(a[3]["versions"], json!(["1.2.3"]));
        assert_eq!(a[4]["range_type"], "CVE-UNPARSED");
        assert_eq!(a[4]["extra"], json!({"matchCriteriaId": "E", "cpe_update": "beta1"}));
        assert_eq!(a[5]["events"], json!([{"introduced": "0"}]), "7 and 7.0 are one key");
        assert_eq!(a[5]["cpe"], "cpe:2.3:a:foo:all:*:*:*:*:*:*:*:*");
        assert_eq!(a[0]["range_type"], "CPE");
    }

    #[test]
    fn errors_read_like_python() {
        let cases: Vec<(Value, Fail)> = vec![
            (json!({"lastModified": "x"}), Fail::Caught("KeyError: 'id'".into())),
            (json!({"id": "C", "metrics": null}), attribute_error(&Value::Null, "get")),
            (json!({"id": "C", "metrics": {"cvssMetricV31": 5}}), type_error("'int' object is not iterable".into())),
            (json!({"id": "C", "metrics": {"cvssMetricV31": {"a": 1}}}), Fail::Uncaught("AttributeError: 'str' object has no attribute 'get'".into())),
            (json!({"id": "C", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": "9"}}]}}),
             type_error("'>=' not supported between instances of 'str' and 'float'".into())),
            (json!({"id": "C", "metrics": {"cvssMetricV31": [{"cvssData": null}]}}), attribute_error(&Value::Null, "get")),
            (json!({"id": "C", "descriptions": [3]}), Fail::Uncaught("AttributeError: 'int' object has no attribute 'get'".into())),
            (json!({"id": "C", "weaknesses": [{"description": null}]}), type_error("'NoneType' object is not iterable".into())),
            (json!({"id": "C", "weaknesses": [{"description": [{"value": null}]}]}),
             Fail::Uncaught("AttributeError: 'NoneType' object has no attribute 'startswith'".into())),
            (json!({"id": "C", "configurations": null}), type_error("'NoneType' object is not iterable".into())),
            (json!({"id": "C", "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": true, "matchCriteriaId": [1]}]}]}]}),
             type_error("unhashable type: 'list'".into())),
            (json!({"id": "C", "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": true, "criteria": 5}]}]}]}),
             type_error("expected string or bytes-like object, got 'int'".into())),
            (json!({"id": "C", "configurations": ["x"]}), Fail::Uncaught("AttributeError: 'str' object has no attribute 'get'".into())),
            (json!({"id": 5}), Fail::Caught("nvd: a CVE id is not a string".into())),
            (json!({"id": "C", "published": 5}), Fail::Caught("nvd: C: published is not a string".into())),
            (json!({"id": "C", "metrics": {"cvssMetricV31": [{"baseSeverity": "HIGH", "cvssData": {"baseScore": "9"}}]}}),
             Fail::Caught("nvd: C: baseScore is not a number".into())),
        ];
        for (c, want) in cases {
            assert_eq!(fail_of(c.clone()), want, "{c}");
        }
        assert_eq!(cve_of(json!({"x": 1})).unwrap_err(), Fail::Caught("KeyError: 'cve'".into()));
        assert_eq!(cve_of(json!([1])).unwrap_err(), type_error("list indices must be integers or slices, not str".into()));
        assert_eq!(cve_of(json!("s")).unwrap_err(), type_error("string indices must be integers, not 'str'".into()));
        assert_eq!(cve_of(json!(null)).unwrap_err(), type_error("'NoneType' object is not subscriptable".into()));
        assert_eq!(fail_of(json!(true)), type_error("'bool' object is not subscriptable".into()));
        let small = Caps { matches: 1, ..caps() };
        let two = cve(json!({"configurations": [{"nodes": [{"cpeMatch": [
            {"vulnerable": true, "criteria": "cpe:2.3:a:a:a:*:*:*:*:*:*:*:*", "matchCriteriaId": "1"},
            {"vulnerable": true, "criteria": "cpe:2.3:a:a:b:*:*:*:*:*:*:*:*", "matchCriteriaId": "2"}]}]}]}));
        assert_eq!(
            plan(two, "now", &small).unwrap_err(),
            Fail::Caught("nvd: CVE-2099-0001: more than 1 CPE match rows; refusing".into())
        );
    }

    #[test]
    fn pages_split_like_store_pages() {
        let page = |t: &str| split_page(t.as_bytes().to_vec(), &caps());
        let p = page(r#"{"totalResults": 2, "vulnerabilities": [{"cve": {"id": "A"}}, {"cve": {"id": "B"}}], "vulnerabilities": [{"cve": {"id": "C"}}]}"#).unwrap();
        assert_eq!(p.items.iter().map(|r| &p.text[r.clone()]).collect::<Vec<_>>(), vec![r#"{"cve": {"id": "C"}}"#]);
        assert_eq!(p.total, Some(json!(2)));
        for empty in [r#"{}"#, r#"{"vulnerabilities": []}"#, r#"{"vulnerabilities": {}}"#, r#"{"vulnerabilities": ""}"#] {
            assert!(page(empty).unwrap().items.is_empty(), "{empty}");
        }
        let err = |t: &str| page(t).unwrap_err();
        assert_eq!(err("[1]"), Fail::Uncaught("AttributeError: 'list' object has no attribute 'get'".into()));
        assert_eq!(err("null"), Fail::Uncaught("AttributeError: 'NoneType' object has no attribute 'get'".into()));
        assert_eq!(err(r#"{"vulnerabilities": null}"#), type_error("'NoneType' object is not iterable".into()));
        assert_eq!(err(r#"{"vulnerabilities": false}"#), type_error("'bool' object is not iterable".into()));
        assert_eq!(err(r#"{"vulnerabilities": 1.5}"#), type_error("'float' object is not iterable".into()));
        assert_eq!(err(r#"{"vulnerabilities": {"a": 1}}"#), type_error("string indices must be integers, not 'str'".into()));
        assert_eq!(err(r#"{"vulnerabilities": "ab"}"#), type_error("string indices must be integers, not 'str'".into()));
        assert!(matches!(err("{"), Fail::Caught(m) if m.starts_with("invalid JSON")));
        assert_eq!(
            split_page(b"{\"x\": \"caf\xe9\"}".to_vec(), &caps()).unwrap_err(),
            Fail::Caught("UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe9 in position 10: invalid continuation byte".into())
        );
        let small = Caps { record_bytes: 10, ..caps() };
        assert_eq!(
            split_page(br#"{"vulnerabilities": [{"cve": {"id": "CVE-1"}}]}"#.to_vec(), &small).unwrap_err(),
            Fail::Caught("nvd: a record is larger than 10 bytes; refusing".into())
        );
    }

    #[test]
    fn timestamps_follow_python() {
        // values checked against Python 3.13 `datetime.fromisoformat`
        let t = |s: &str| fromisoformat(s).map(iso);
        assert_eq!(t("2026-11-11T08:00:00.123Z").unwrap(), "2026-11-11T08:00:00.123Z");
        assert_eq!(t("2026-11-11T08:00:00.1239").unwrap(), "2026-11-11T08:00:00.123Z");
        assert_eq!(t("2020-01-01T10:00:00.1234567Z").unwrap(), "2020-01-01T10:00:00.123Z");
        assert_eq!(t("2020-01-01").unwrap(), "2020-01-01T00:00:00.000Z");
        assert_eq!(t("20200101").unwrap(), "2020-01-01T00:00:00.000Z");
        assert_eq!(t("2020-01-01T10").unwrap(), "2020-01-01T10:00:00.000Z");
        assert_eq!(t("2020-01-01T1000").unwrap(), "2020-01-01T10:00:00.000Z");
        assert_eq!(t("2020-01-01 10:00+0530").unwrap(), "2020-01-01T04:30:00.000Z");
        assert_eq!(t("2020-01-01T10:00:00-0130").unwrap(), "2020-01-01T11:30:00.000Z");
        assert_eq!(t("2020-01-01T10:00:00+05").unwrap(), "2020-01-01T05:00:00.000Z");
        assert_eq!(t("2020-01-01T10:00:00,5").unwrap(), "2020-01-01T10:00:00.500Z");
        assert_eq!(t("1969-12-31T23:59:59.999Z").unwrap(), "1969-12-31T23:59:59.999Z");
        assert_eq!(t("2020-13-01").unwrap_err(), "month must be in 1..12");
        assert_eq!(t("2020-02-30").unwrap_err(), "day is out of range for month");
        assert_eq!(t("2020-01-01T25:00").unwrap_err(), "hour must be in 0..23");
        assert_eq!(t("2020-01-01T10:61").unwrap_err(), "minute must be in 0..59");
        assert_eq!(t("2020-01-01T10:00:61").unwrap_err(), "second must be in 0..59");
        assert_eq!(t("0000-01-01").unwrap_err(), "year 0 is out of range");
        for bad in [
            "x",
            "2020-01-01 ",
            "2020-0101",
            "2020-01-01T",
            "2020-W01-1",
            "2020-01-01T10:0",
            // review W10.3 M1: non-ASCII text where the parser slices by byte
            "abcé12",
            "2020-01-01T1é1",
            "202é-01",
            "é",
            "2020-01-01Té",
            "2020-01-01T10:00+0é",
        ] {
            assert_eq!(t(bad).unwrap_err(), format!("Invalid isoformat string: {}", py::repr_str(bad)), "{bad}");
        }
        assert_eq!(iso(parse_since(" 2020 ").unwrap()), "2020-01-01T00:00:00.000Z");
        assert_eq!(iso(parse_since("2020-05").unwrap()), "2020-05-01T00:00:00.000Z");
        // values checked against Python 3.13 `parse_since`
        for (since, shown) in [
            ("abcé12", "'abcé12'"),
            ("2020-01-01T1é1", "'2020-01-01T1é1'"),
            ("\u{ff12}\u{ff10}\u{ff12}\u{ff10}", "'\u{ff12}\u{ff10}\u{ff12}\u{ff10}-01-01'"),
        ] {
            assert_eq!(parse_since(since).unwrap_err(), format!("Invalid isoformat string: {shown}"));
        }
        assert_eq!(iso(parse_since("2020-01-01\u{e9}10:00").unwrap()), "2020-01-01T10:00:00.000Z");
        assert_eq!(iso(parse_since("2020-05-17T10:00:00").unwrap()), "2020-05-17T10:00:00.000Z");
        for d in [-1_000_000i64, 0, 59, 18_000, 2_932_896] {
            let (y, m, dd) = civil_from_days(d);
            assert_eq!(days_from_civil(y, m, dd), d);
        }
    }

    #[test]
    fn queries_and_retry_after_like_httpx() {
        assert_eq!(
            encode_query(&[("lastModStartDate", "2026-01-01T00:00:00.000Z".into()), ("cveId", "C V&E".into())]),
            "lastModStartDate=2026-01-01T00%3A00%3A00.000Z&cveId=C+V%26E"
        );
        assert_eq!(retry_after_secs(" 7 ", 0.0), Some(7.0));
        assert_eq!(retry_after_secs("-3", 0.0), Some(0.0));
        assert_eq!(retry_after_secs("nan", 0.0), Some(0.0));
        assert_eq!(retry_after_secs("inf", 0.0), Some(f64::INFINITY));
        let t = http_date("Wed, 21 Oct 2015 07:28:00 GMT").unwrap();
        assert_eq!(t, 1_445_412_480.0);
        assert_eq!(http_date("21 Oct 2015 07:28:00 +0200"), Some(t - 7200.0));
        assert_eq!(retry_after_secs("Wed, 21 Oct 2015 07:28:00 GMT", t - 30.0), Some(30.0));
        assert_eq!(retry_after_secs("Wed, 21 Oct 2015 07:28:00", 0.0), None);
        assert_eq!(retry_after_secs("soon", 0.0), None);
    }
}
