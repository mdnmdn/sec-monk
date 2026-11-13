//! ENISA EUVD, native (rust ADR-0011, ADR-0012). Port of `src/secmonk/sources/euvd.py` plus the `source_sync`
//! bookkeeping of `ops.sync_source` / `db.set_sync_state`; reference: `py-sources` (differential test
//! `secmonk-engine/tests/native_euvd.rs`). Doc: `rust/_docs/tech/source-euvd.md`.
//!
//! A sync reads `--path` (a JSON list of records, or an object with an `items` or `content` list) or the API
//! (`/exploitedvulnerabilities?size=100`, `/lastvulnerabilities`, with `limit` also `/vulnerabilities` pages). The
//! documents are split into records without building one tree (`serde_json::RawValue`), every record is checked
//! first (Python writes all records in one transaction: one bad record fails the run and stores nothing), then the
//! operations are produced per chunk of records while the engine applies the batches: per record a `raw_record` and a
//! `vulnerability` upsert, its `alias` and `affected` rows replaced against the stored ones (read through
//! `MirrorView::rows_by_id`; nothing when they are equal), and an `epss` upsert of source `euvd` per CVE alias (the
//! store never lets it replace a FIRST row). Nothing is deleted for records that left the views: the Python source
//! only adds and refreshes.

use std::collections::HashMap;
use std::fmt;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use futures_util::StreamExt;
use secmonk_model::{JsonMap, MirrorTable, RowOp};
use secmonk_traits::{
    CallCtx, ErrorCode, MAX_VIEW_IDS, MirrorView, ResultStream, RowsBatch, Source, SourceInfo,
    StepResult, SyncEnd, SyncParams, WireError,
};
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;
use serde_json::{Value, json};

use crate::batch::Limits;
use crate::native::{self, Ops, Outcome};
use crate::rows::{self, DeleteKey};
use crate::{feed, py};

/// Source name.
pub const NAME: &str = "euvd";
/// Registration (`crate::IMPORTERS`): rust by default since 2026-11-11 (differential test green).
pub const IMPORTER: crate::Importer = crate::Importer {
    name: NAME,
    default_rust: true,
    importer_version: "rust/1",
    new: |view| Arc::new(EuvdSource::new(view)),
};
/// Description (as the Python source's).
pub const DESCRIPTION: &str =
    "ENISA EUVD: exploited and recent EU vulnerability records, with CVE aliases";
/// The API.
pub const BASE_URL: &str = "https://euvdservices.enisa.europa.eu/api";
/// Records per API page (`size`).
pub const PAGE_SIZE: usize = 100;

/// Input caps (the Python source has none). Worst-case memory within them: rust/_docs/tech/source-euvd.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Bytes of all documents of one run together (the `--path` file, or every API answer).
    pub total_bytes: u64,
    /// Bytes of one API answer.
    pub response_bytes: u64,
    /// Bytes of one record.
    pub record_bytes: usize,
    /// Records of one run.
    pub records: usize,
    /// Product objects plus CVE aliases of one record (each becomes an `affected` / `alias` / `epss` row).
    pub children: usize,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            total_bytes: 256 * 1024 * 1024,
            response_bytes: 32 * 1024 * 1024,
            record_bytes: 1024 * 1024,
            records: 1_000_000,
            children: 10_000,
        }
    }
}

/// Records per chunk of the operation stream (at most `MAX_VIEW_IDS` ids are read per chunk).
const CHUNK_RECORDS: usize = MAX_VIEW_IDS;
/// Record bytes per chunk of the operation stream (a chunk closes once it is reached).
const CHUNK_BYTES: usize = 2 * 1024 * 1024;
/// New child rows (products and CVE aliases) per chunk (a chunk closes once it is reached).
const CHUNK_CHILDREN: usize = 20_000;
/// Stored `alias` and `affected` rows read per chunk (a chunk closes once it is reached).
const CHUNK_STORED: usize = 50_000;
/// Records whose stored rows are read in one `rows_by_id` call per table: within the caps one call returns at most
/// `GROUP * Caps::children` rows of each table.
const GROUP: usize = 5;

/// The native EUVD source.
pub struct EuvdSource {
    view: Arc<dyn MirrorView>,
    base: String,
    limits: Limits,
    caps: Caps,
}

impl fmt::Debug for EuvdSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EuvdSource")
            .field("base", &self.base)
            .field("limits", &self.limits)
            .field("caps", &self.caps)
            .finish_non_exhaustive()
    }
}

impl EuvdSource {
    /// The source over a read-only view of the mirror.
    pub fn new(view: Arc<dyn MirrorView>) -> EuvdSource {
        EuvdSource {
            view,
            base: BASE_URL.into(),
            limits: Limits::default(),
            caps: Caps::default(),
        }
    }

    /// Another API base URL (tests: a local server; `http://` is then allowed).
    pub fn with_base_url(mut self, base: &str) -> EuvdSource {
        self.base = base.trim_end_matches('/').into();
        self
    }

    /// Other batch limits (tests: several batches out of a small fixture).
    pub fn with_limits(mut self, limits: Limits) -> EuvdSource {
        self.limits = limits;
        self
    }

    /// Other input caps.
    pub fn with_caps(mut self, caps: Caps) -> EuvdSource {
        self.caps = caps;
        self
    }

    async fn run(
        &self,
        params: &SyncParams,
    ) -> StepResult<ResultStream<RowsBatch, SyncEnd>> {
        let t0 = Instant::now();
        let opts = &params.options;
        let limit = native::limit(opts)?;
        let path = opts.path.clone().flatten().filter(|p| !p.is_empty());
        let loaded = match path {
            Some(p) => self.load_file(&PathBuf::from(p), limit).await,
            None => self.load_remote(limit).await,
        };
        let outcome = match loaded {
            Ok((docs, origin)) => self.outcome(docs, &origin).await?,
            Err(message) => Outcome::error(message),
        };
        let first = native::first_seq(self.view.as_ref(), NAME).await?;
        Ok(native::stream(NAME, outcome, first, self.limits, t0))
    }

    /// `--path`: one document; `limit` keeps its first records (`_items(doc)[:limit]`).
    async fn load_file(
        &self,
        path: &std::path::Path,
        limit: Option<u64>,
    ) -> Result<(Vec<Doc>, String), String> {
        let bytes = feed::read_bytes(path, self.caps.total_bytes).await?;
        let mut doc = Doc::parse(bytes, false, self.caps)?;
        if let Some(n) = limit {
            doc.records
                .truncate(usize::try_from(n).unwrap_or(usize::MAX));
        }
        Ok((vec![doc], format!("from file {}", feed::py_path(path))))
    }

    /// `_load_remote`: the exploited view, the recent view, and with `limit` pages of `/vulnerabilities` until
    /// `limit` records or an empty page (`_paged`).
    async fn load_remote(&self, limit: Option<u64>) -> Result<(Vec<Doc>, String), String> {
        let http = !self.base.starts_with("https://");
        let mut budget = Budget {
            bytes: self.caps.total_bytes,
            records: self.caps.records,
        };
        let mut docs = Vec::new();
        let exploited = self
            .get(
                &format!("{}/exploitedvulnerabilities?size={PAGE_SIZE}", self.base),
                true,
                http,
                &mut budget,
            )
            .await?;
        docs.push(exploited);
        docs.push(
            self.get(
                &format!("{}/lastvulnerabilities", self.base),
                false,
                http,
                &mut budget,
            )
            .await?,
        );
        if let Some(limit) = limit {
            let limit = usize::try_from(limit).unwrap_or(usize::MAX);
            let (mut got, mut page) = (0usize, 0u64);
            while got < limit {
                let url = format!(
                    "{}/vulnerabilities?page={page}&size={PAGE_SIZE}",
                    self.base
                );
                let mut doc = self.get(&url, false, http, &mut budget).await?;
                if doc.records.is_empty() {
                    break;
                }
                doc.records.truncate(limit - got);
                got += doc.records.len();
                docs.push(doc);
                page += 1;
            }
        }
        Ok((docs, format!("from {}", feed::scrub(&self.base))))
    }

    /// One API answer as a document, within the run's budget.
    async fn get(
        &self,
        url: &str,
        exploited: bool,
        http: bool,
        budget: &mut Budget,
    ) -> Result<Doc, String> {
        let cap = self.caps.response_bytes.min(budget.bytes);
        let body = feed::download(url, cap, http, feed::TIMEOUT).await?;
        budget.bytes -= body.len() as u64;
        let caps = Caps {
            records: budget.records,
            ..self.caps
        };
        let doc = Doc::parse(body, exploited, caps)?;
        budget.records -= doc.records.len();
        Ok(doc)
    }

    /// Check every record (in order; the first failure is the run's error), then the lazy operations.
    async fn outcome(&self, docs: Vec<Doc>, origin: &str) -> StepResult<Outcome> {
        let caps = self.caps;
        let checked = tokio::task::spawn_blocking(move || check(docs, caps))
            .await
            .map_err(|e| WireError::new(ErrorCode::Internal, format!("euvd: {e}")))?;
        let (docs, last) = match checked {
            Ok(v) => v,
            Err(message) => return Ok(Outcome::error(message)),
        };
        let records = last.len() as u64;
        Ok(Outcome {
            status: "ok".into(),
            records,
            total: None,
            cursor: None,
            message: Some(format!("{records} records {origin}")),
            ops: ops(Emit {
                docs,
                doc: 0,
                rec: 0,
                index: 0,
                last,
                view: self.view.clone(),
                now: secmonk_model::time::now_iso(),
                caps: self.caps,
            }),
        })
    }
}

/// What is left of the run's caps while the API answers come in.
struct Budget {
    bytes: u64,
    records: usize,
}

/// One document: its text and the byte ranges of its records, in order.
struct Doc {
    text: String,
    records: Vec<Range<usize>>,
    /// From the exploited view (`exploited_view` of `_store`).
    exploited: bool,
}

impl Doc {
    /// `json.loads` + `_items`: UTF-8 text (Python's `UnicodeDecodeError` text otherwise), a list of records or an
    /// object whose `items` (else `content`) is a list; `ValueError` text of `_items` for any other shape.
    fn parse(bytes: Vec<u8>, exploited: bool, caps: Caps) -> Result<Doc, String> {
        if let Err(e) = std::str::from_utf8(&bytes) {
            return Err(py::utf8_error(&bytes, &e));
        }
        let text = String::from_utf8(bytes).map_err(|e| e.to_string())?;
        let records = split(&text, caps)?;
        Ok(Doc {
            text,
            records,
            exploited,
        })
    }
}

const SHAPE: &str = "unexpected EUVD response shape (no list of records)";

/// The byte ranges of the records of a document (relative to `text`), within the caps.
fn split(text: &str, caps: Caps) -> Result<Vec<Range<usize>>, String> {
    // our own refusals come back as serde errors with a position appended; syntax errors read "invalid JSON: ..."
    let message = |e: serde_json::Error| feed::json_error(&e, &[SHAPE, "euvd: "]);
    let base = text.as_ptr() as usize;
    let mut de = serde_json::Deserializer::from_str(text);
    let top = Envelope { base, caps }
        .deserialize(&mut de)
        .map_err(message)?;
    de.end().map_err(message)?;
    match top {
        Top::List(r) => Ok(r),
        Top::Object { items, content } => {
            let list = [items, content]
                .into_iter()
                .flatten()
                .find(|raw| raw.get().trim_start().starts_with('['))
                .ok_or_else(|| SHAPE.to_owned())?;
            let mut de = serde_json::Deserializer::from_str(list.get());
            Records { base, caps }
                .deserialize(&mut de)
                .map_err(message)
        }
    }
}

/// The top level of a document: a list of records, or an object whose `items` / `content` are kept unparsed.
enum Top<'a> {
    List(Vec<Range<usize>>),
    Object {
        items: Option<&'a RawValue>,
        content: Option<&'a RawValue>,
    },
}

/// Reads the top level without keeping anything but the record ranges or the two candidate lists.
struct Envelope {
    base: usize,
    caps: Caps,
}

impl<'de> DeserializeSeed<'de> for Envelope {
    type Value = Top<'de>;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Top<'de>, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Envelope {
    type Value = Top<'de>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a list of records or an object")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<Top<'de>, A::Error> {
        Records {
            base: self.base,
            caps: self.caps,
        }
        .visit_seq(seq)
        .map(Top::List)
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Top<'de>, A::Error> {
        let (mut items, mut content) = (None, None);
        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                // a repeated key: the last value counts, as in `json.loads`
                "items" => items = Some(map.next_value::<&'de RawValue>()?),
                "content" => content = Some(map.next_value::<&'de RawValue>()?),
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Top::Object { items, content })
    }

    fn visit_str<E: de::Error>(self, _: &str) -> Result<Top<'de>, E> {
        Err(E::custom(SHAPE))
    }
    fn visit_borrowed_str<E: de::Error>(self, _: &'de str) -> Result<Top<'de>, E> {
        Err(E::custom(SHAPE))
    }
    fn visit_string<E: de::Error>(self, _: String) -> Result<Top<'de>, E> {
        Err(E::custom(SHAPE))
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<Top<'de>, E> {
        Err(E::custom(SHAPE))
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Top<'de>, E> {
        Err(E::custom(SHAPE))
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Top<'de>, E> {
        Err(E::custom(SHAPE))
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Top<'de>, E> {
        Err(E::custom(SHAPE))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Top<'de>, E> {
        Err(E::custom(SHAPE))
    }
}

/// Reads a list of records as byte ranges (relative to the text at `base`), refusing more than `caps.records` and a
/// record above `caps.record_bytes` as soon as it is read.
struct Records {
    base: usize,
    caps: Caps,
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
            if out.len() >= self.caps.records {
                return Err(de::Error::custom(format!(
                    "euvd: more than {} records; refusing",
                    self.caps.records
                )));
            }
            let s = raw.get();
            if s.len() > self.caps.record_bytes {
                return Err(de::Error::custom(format!(
                    "euvd: a record is larger than {} bytes; refusing",
                    self.caps.record_bytes
                )));
            }
            let start = s.as_ptr() as usize - self.base;
            out.push(start..start + s.len());
        }
        Ok(out)
    }
}

/// What `_store` writes for one record (`None` from [`plan`]: a record without an id, skipped).
struct Plan {
    id: String,
    /// Product objects plus CVE aliases (the record's share of [`CHUNK_CHILDREN`]).
    children: usize,
    raw: RowOp,
    vulnerability: RowOp,
    aliases: Vec<(String, String)>,
    affected: Vec<JsonMap>,
    epss: Vec<RowOp>,
}

/// `str(exception)` as `ops.sync_source` words an exception the source does not catch: `<class>: <text>`.
fn uncaught(class: &str, text: String) -> String {
    format!("{class}: {text}")
}

/// A text column of a record: a string, or null when absent / null. Anything else refuses the run (Python would
/// store numbers as text and fail on lists only when SQLite binds them).
fn text_field(rec: &JsonMap, id: &str, field: &str) -> Result<Option<String>, String> {
    match rec.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(format!("euvd: {id}: {field} is not a string")),
    }
}

/// `_store(conn, rec, exploited_view)` as rows, with the checks that make Python raise, in its order.
fn plan(rec: Value, exploited_view: bool, now: &str, caps: &Caps) -> Result<Option<Plan>, String> {
    let Value::Object(m) = &rec else {
        return Err(uncaught(
            "AttributeError",
            format!("'{}' object has no attribute 'get'", py::type_name(&rec)),
        ));
    };
    let id = match m.get("id") {
        Some(v) if !py::truthy(v) => return Ok(None),
        None => return Ok(None),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return Err("euvd: a record id is not a string".into()),
    };
    let exploited = m.get("exploited").is_some_and(py::truthy) || exploited_view;
    let epss = m.get("epss").cloned().unwrap_or(Value::Null);
    // `[p for p in rec.get("products") or [] if isinstance(p, dict)]`
    let products: Vec<&JsonMap> = match m.get("products") {
        Some(v) if !py::truthy(v) => Vec::new(),
        None => Vec::new(),
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_object).collect(),
        Some(Value::String(_) | Value::Object(_)) => Vec::new(), // iterates characters / keys: no dict
        Some(v) => {
            return Err(uncaught(
                "TypeError",
                format!("'{}' object is not iterable", py::type_name(v)),
            ));
        }
    };
    // `_SPLIT.split(rec.get("aliases") or "")`, upper-cased, CVE ids only
    let cves: Vec<String> = match m.get("aliases") {
        Some(v) if !py::truthy(v) => Vec::new(),
        None => Vec::new(),
        Some(Value::String(s)) => s
            .split(|c: char| py::is_space(c) || c == ',')
            .map(str::to_uppercase)
            .filter(|a| a.starts_with("CVE-"))
            .collect(),
        Some(v) => {
            return Err(uncaught(
                "TypeError",
                format!(
                    "expected string or bytes-like object, got '{}'",
                    py::type_name(v)
                ),
            ));
        }
    };
    if products.len() + cves.len() > caps.children {
        return Err(format!(
            "euvd: {id}: more than {} products and CVE aliases; refusing",
            caps.children
        ));
    }
    let modified = text_field(m, &id, "dateUpdated")?;
    let summary = text_field(m, &id, "description")?;
    let published = text_field(m, &id, "datePublished")?;
    let vector = text_field(m, &id, "baseScoreVector")?;
    let version = text_field(m, &id, "baseScoreVersion")?;
    // `severity_from_score(score)`: a number (a bool is an int there), else Python's comparison fails
    let score = match m.get("baseScore") {
        None | Some(Value::Null) => None,
        Some(Value::Bool(b)) => Some(if *b { 1.0 } else { 0.0 }),
        Some(Value::Number(n)) => n.as_f64(),
        Some(v) => {
            return Err(uncaught(
                "TypeError",
                format!(
                    "'>=' not supported between instances of '{}' and 'float'",
                    py::type_name(v)
                ),
            ));
        }
    };
    let mut affected = Vec::with_capacity(products.len());
    let (mut vendors, mut names): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    for p in &products {
        let field = |k: &str| -> Result<Option<String>, String> {
            match p.get(k) {
                None | Some(Value::Null) => Ok(None),
                Some(Value::String(s)) => Ok(Some(s.clone())),
                Some(_) => Err(format!("euvd: {id}: products[].{k} is not a string")),
            }
        };
        let (vendor, product) = (field("vendor")?, field("product")?);
        let versions = match p.get("version") {
            Some(v) if !py::truthy(v) => Vec::new(),
            None => Vec::new(),
            Some(v @ Value::String(_)) => vec![v.clone()],
            Some(_) => return Err(format!("euvd: {id}: products[].version is not a string")),
        };
        vendors.extend(vendor.clone().filter(|s| !s.is_empty()));
        names.extend(product.clone().filter(|s| !s.is_empty()));
        affected.push(rows::affected(
            NAME,
            &id,
            rows::Affected {
                vendor,
                product,
                range_type: Some("CVE".into()),
                version_type: Some("euvd".into()),
                versions,
                extra: Value::Object((*p).clone()),
                ..rows::Affected::default()
            },
        ));
    }
    vendors.sort();
    vendors.dedup();
    names.sort();
    names.dedup();
    // `float(epss)` per CVE alias (only reached when there is one)
    let score_epss = match (&epss, cves.is_empty()) {
        (Value::Null, _) | (_, true) => None,
        (Value::Bool(b), false) => Some(if *b { 1.0 } else { 0.0 }),
        (Value::Number(n), false) => n.as_f64(),
        (Value::String(s), false) => Some(
            py::float_str(s)
                .ok_or_else(|| format!("could not convert string to float: {}", feed::py_repr(s)))?,
        ),
        (v, false) => {
            return Err(uncaught(
                "TypeError",
                format!(
                    "float() argument must be a string or a real number, not '{}'",
                    py::type_name(v)
                ),
            ));
        }
    };
    if score_epss.is_some_and(f64::is_infinite) {
        return Err(format!("euvd: {id}: epss is not finite"));
    }
    let extra = json!({
        "exploited": exploited,
        "epss": epss,
        "assigner": m.get("assigner").cloned().unwrap_or(Value::Null),
        "vendors": vendors,
        "products": names,
    });
    let day: Option<String> = modified
        .as_deref()
        .map(|d| d.chars().take(10).collect::<String>())
        .filter(|d| !d.is_empty());
    let epss_rows = match score_epss {
        None => Vec::new(),
        Some(s) => cves
            .iter()
            .map(|cve| RowOp::Upsert {
                table: MirrorTable::Epss,
                row: obj(json!({
                    "cve_id": cve,
                    "score": serde_json::Number::from_f64(s).map_or(Value::Null, Value::Number),
                    "percentile": null,
                    "date": day,
                    "source": NAME,
                })),
            })
            .collect(),
    };
    let aliases = rows::alias_set(&id, cves.iter().map(|c| (c.as_str(), "alias")));
    let vulnerability = rows::vulnerability(
        NAME,
        &id,
        rows::Vulnerability {
            summary,
            published,
            modified: modified.clone(),
            severity: rows::severity_from_score(score).map(str::to_owned),
            cvss_score: score,
            cvss_vector: vector,
            cvss_version: version,
            extra,
            ..rows::Vulnerability::default()
        },
    );
    let raw = rows::raw_record(NAME, &id, modified.as_deref(), now, rec.clone());
    Ok(Some(Plan {
        children: products.len() + cves.len(),
        id,
        raw,
        vulnerability,
        aliases,
        affected,
        epss: epss_rows,
    }))
}

fn obj(v: Value) -> JsonMap {
    match v {
        Value::Object(m) => m,
        _ => JsonMap::new(),
    }
}

/// Parse one record of a document.
fn record(doc: &Doc, r: &Range<usize>) -> Result<Value, String> {
    serde_json::from_str(&doc.text[r.clone()]).map_err(|e| format!("invalid JSON: {e}"))
}

/// The id of the record at a global index (a record the check already accepted).
fn id_at(docs: &[Doc], mut index: usize) -> Option<String> {
    for doc in docs {
        if let Some(r) = doc.records.get(index) {
            return record(doc, r)
                .ok()?
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        index -= doc.records.len();
    }
    None
}

/// The global index of the last record of every id, without keeping the ids: a 64-bit hash (keys random per run) maps
/// to the index; a hash already taken by another id (checked by reading that record's id again) keeps the id itself
/// in `spill`. Memory: one hash entry per distinct id; `spill` stays empty unless two ids collide.
struct LastIndex {
    hasher: std::collections::hash_map::RandomState,
    by_hash: HashMap<u64, usize>,
    spill: HashMap<String, usize>,
}

impl LastIndex {
    fn new() -> LastIndex {
        LastIndex {
            hasher: std::collections::hash_map::RandomState::new(),
            by_hash: HashMap::new(),
            spill: HashMap::new(),
        }
    }

    fn hash(&self, id: &str) -> u64 {
        use std::hash::BuildHasher;
        self.hasher.hash_one(id)
    }

    /// Record `index` as the latest record of `id`.
    fn insert(&mut self, docs: &[Doc], id: String, index: usize) {
        if let Some(i) = self.spill.get_mut(&id) {
            *i = index;
            return;
        }
        let h = self.hash(&id);
        match self.by_hash.get(&h).copied() {
            Some(j) if id_at(docs, j).as_deref() != Some(id.as_str()) => {
                self.spill.insert(id, index);
            }
            _ => {
                self.by_hash.insert(h, index);
            }
        }
    }

    /// Whether `index` is the last record of `id`.
    fn is_last(&self, id: &str, index: usize) -> bool {
        match self.spill.get(id) {
            Some(i) => *i == index,
            None => self.by_hash.get(&self.hash(id)) == Some(&index),
        }
    }

    /// Distinct ids.
    fn len(&self) -> usize {
        self.by_hash.len() + self.spill.len()
    }
}

/// The first pass: every record checked in order (the first failure is the run's message), and the index of the
/// last record of every id (an earlier record of the same id is overwritten by it in Python, except its `epss` rows).
fn check(docs: Vec<Doc>, caps: Caps) -> Result<(Vec<Doc>, LastIndex), String> {
    let mut last = LastIndex::new();
    let mut index = 0usize;
    for doc in &docs {
        for r in &doc.records {
            if let Some(p) = plan(record(doc, r)?, doc.exploited, "", &caps)? {
                last.insert(&docs, p.id, index);
            }
            index += 1;
        }
    }
    Ok((docs, last))
}

/// The state of the operation stream: the next record to emit.
struct Emit {
    docs: Vec<Doc>,
    doc: usize,
    rec: usize,
    index: usize,
    last: LastIndex,
    view: Arc<dyn MirrorView>,
    now: String,
    caps: Caps,
}

/// The operations of the run, one chunk of records at a time.
fn ops(emit: Emit) -> Ops {
    futures_util::stream::unfold(Some(emit), |state| async move {
        let mut e = state?;
        match e.chunk().await {
            Ok(None) => None,
            Ok(Some(ops)) => Some((Ok(ops), Some(e))),
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

impl Emit {
    /// The plan of the next record (`None` inside for a skipped record), whether it is the last of its id, and its
    /// text length; `None` when every record was read.
    fn next_record(&mut self) -> StepResult<Option<(Option<Plan>, bool, usize)>> {
        loop {
            let Some(doc) = self.docs.get_mut(self.doc) else {
                return Ok(None);
            };
            let Some(r) = doc.records.get(self.rec).cloned() else {
                doc.text = String::new(); // emitted: release the text
                doc.records = Vec::new();
                self.doc += 1;
                self.rec = 0;
                continue;
            };
            let doc = &self.docs[self.doc];
            let p = plan(
                record(doc, &r).map_err(|m| native::internal(NAME, m))?,
                doc.exploited,
                &self.now,
                &self.caps,
            )
            .map_err(|m| native::internal(NAME, m))?;
            let full = p
                .as_ref()
                .is_some_and(|p| self.last.is_last(&p.id, self.index));
            self.rec += 1;
            self.index += 1;
            return Ok(Some((p, full, r.len())));
        }
    }

    /// The stored rows of `table` for `ids`, refusing a record with more stored rows than the caps allow (rows
    /// `py-sources` wrote from a larger record before a switch).
    async fn stored(&self, table: MirrorTable, ids: &[String]) -> StepResult<Vec<JsonMap>> {
        let rows = self.view.rows_by_id(table, NAME, ids).await?;
        if rows.len() > self.caps.children {
            for (id, of) in rows::group_by(&rows, "vuln_id") {
                if of.len() > self.caps.children {
                    return Err(WireError::new(
                        ErrorCode::Internal,
                        format!(
                            "euvd: native importer: {id}: {} stored {} rows (more than {}); refusing, sync euvd \
                             with the python implementation",
                            of.len(),
                            table.as_str(),
                            self.caps.children
                        ),
                    ));
                }
            }
        }
        Ok(rows)
    }

    /// The operations of the next chunk of records (`None` when every record was emitted). A chunk is read in groups
    /// of [`GROUP`] records and closes at [`CHUNK_RECORDS`] records, [`CHUNK_BYTES`] of record text,
    /// [`CHUNK_CHILDREN`] new child rows or [`CHUNK_STORED`] stored rows, whichever comes first.
    async fn chunk(&mut self) -> StepResult<Option<Vec<RowOp>>> {
        let mut plans: Vec<(Plan, bool)> = Vec::new();
        let (mut bytes, mut children) = (0usize, 0usize);
        let (mut stored_alias, mut stored_affected) = (Vec::new(), Vec::new());
        let mut done = false;
        while !done
            && plans.len() < CHUNK_RECORDS
            && bytes < CHUNK_BYTES
            && children < CHUNK_CHILDREN
            && stored_alias.len() + stored_affected.len() < CHUNK_STORED
        {
            let start = plans.len();
            while plans.len() - start < GROUP {
                match self.next_record()? {
                    None => {
                        done = true;
                        break;
                    }
                    Some((p, full, len)) => {
                        bytes += len;
                        if let Some(p) = p {
                            children += p.children;
                            plans.push((p, full));
                        }
                    }
                }
            }
            let ids: Vec<String> = plans[start..]
                .iter()
                .filter(|(_, full)| *full)
                .map(|(p, _)| p.id.clone())
                .collect();
            if !ids.is_empty() {
                stored_alias.extend(self.stored(MirrorTable::Alias, &ids).await?);
                stored_affected.extend(self.stored(MirrorTable::Affected, &ids).await?);
            }
        }
        if plans.is_empty() && done {
            return Ok(None);
        }
        let alias_of = rows::group_by(&stored_alias, "vuln_id");
        let affected_of = rows::group_by(&stored_affected, "vuln_id");
        let mut ops = Vec::new();
        for (p, full) in plans {
            if full {
                // `store_raw`, `upsert_vulnerability`, `replace_children` + `add_alias` / `add_affected`
                ops.push(p.raw);
                ops.push(p.vulnerability);
                let none = Vec::new();
                ops.extend(rows::replace_aliases(
                    NAME,
                    &p.id,
                    alias_of.get(p.id.as_str()).unwrap_or(&none),
                    &p.aliases,
                ));
                ops.extend(rows::replace_affected(
                    affected_of.get(p.id.as_str()).unwrap_or(&none),
                    p.affected,
                    DeleteKey::Record,
                ));
            }
            // an earlier record of an id a later one overwrites: only its epss upserts remain in Python
            ops.extend(p.epss);
        }
        Ok(Some(ops))
    }
}

#[async_trait]
impl Source for EuvdSource {
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
        _ctx: CallCtx,
    ) -> StepResult<ResultStream<RowsBatch, SyncEnd>> {
        native::check_name(NAME, &params.source)?;
        self.run(&params).await
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

    fn texts(text: &str, caps: Caps) -> Result<Vec<String>, String> {
        Ok(split(text, caps)?
            .into_iter()
            .map(|r| text[r].to_owned())
            .collect())
    }

    #[test]
    fn documents_split_into_records_like_items() {
        assert_eq!(texts(" [1, {\"a\": [2]}] ", caps()).unwrap(), vec!["1", "{\"a\": [2]}"]);
        assert_eq!(
            texts(r#"{"total": 2, "items": [{"id": "A"}, {"id": "B"}]}"#, caps()).unwrap(),
            vec![r#"{"id": "A"}"#, r#"{"id": "B"}"#]
        );
        // `items` not a list: `content`; a repeated key: the last one
        assert_eq!(
            texts(r#"{"items": {"x": 1}, "content": [3], "content": [4, 5]}"#, caps()).unwrap(),
            vec!["4", "5"]
        );
        for bad in [r#"{"items": 1}"#, "\"x\"", "3", "null", "true", "{}"] {
            assert_eq!(texts(bad, caps()).unwrap_err(), SHAPE, "{bad}");
        }
        assert!(texts("[1,", caps()).unwrap_err().starts_with("invalid JSON"));
        assert!(texts("[1] x", caps()).unwrap_err().starts_with("invalid JSON"));
        let small = Caps {
            records: 2,
            record_bytes: 8,
            ..caps()
        };
        assert_eq!(
            texts("[1, 2, 3]", small).unwrap_err(),
            "euvd: more than 2 records; refusing"
        );
        assert_eq!(
            texts(r#"{"items": ["123456789"]}"#, small).unwrap_err(),
            "euvd: a record is larger than 8 bytes; refusing"
        );
        assert_eq!(texts("[[1, 2]]", small).unwrap(), vec!["[1, 2]"]);
    }

    #[test]
    fn a_lone_surrogate_escape_refuses_the_run() {
        // json.loads accepts it (Python then fails when SQLite stores the record, or skips a record without id)
        let text = r#"[{"description": "\ud800"}]"#.to_owned();
        let records = split(&text, Caps::default()).unwrap_or_default();
        let docs = vec![Doc {
            text,
            records,
            exploited: false,
        }];
        let e = match check(docs, Caps::default()) {
            Err(e) => e,
            Ok(_) => panic!("accepted"),
        };
        assert!(e.starts_with("invalid JSON: "), "{e}");
    }

    #[test]
    fn the_last_record_index_survives_a_hash_collision() {
        let text = r#"[{"id": "A"}, {"id": "B"}, {"id": "A"}, {"id": "B"}]"#.to_owned();
        let records = split(&text, Caps::default()).unwrap();
        let docs = vec![Doc {
            text,
            records,
            exploited: false,
        }];
        let mut last = LastIndex::new();
        last.insert(&docs, "A".into(), 0);
        // B's hash taken by A's record, as a collision would: B must be kept apart, by its id
        let hb = last.hash("B");
        last.by_hash.insert(hb, 0);
        last.insert(&docs, "B".into(), 1);
        assert_eq!(last.spill.get("B"), Some(&1));
        last.insert(&docs, "A".into(), 2);
        last.insert(&docs, "B".into(), 3);
        assert!(last.is_last("B", 3) && !last.is_last("B", 1));
        assert!(last.is_last("A", 2) && !last.is_last("A", 0));
    }

    fn plan_of(v: Value) -> Result<Option<Plan>, String> {
        plan(v, false, "now", &Caps::default())
    }

    #[test]
    fn records_fail_like_the_python_source() {
        assert_eq!(
            plan_of(json!([1])).err().unwrap(),
            "AttributeError: 'list' object has no attribute 'get'"
        );
        assert!(plan_of(json!({"id": ""})).unwrap().is_none());
        assert!(plan_of(json!({"description": "x"})).unwrap().is_none());
        let rec = |extra: Value| {
            let mut r = json!({"id": "EUVD-1", "aliases": "CVE-1"});
            for (k, v) in extra.as_object().unwrap() {
                r[k] = v.clone();
            }
            plan_of(r).err()
        };
        assert_eq!(
            rec(json!({"products": 5})).unwrap(),
            "TypeError: 'int' object is not iterable"
        );
        assert_eq!(
            rec(json!({"aliases": ["CVE-1"]})).unwrap(),
            "TypeError: expected string or bytes-like object, got 'list'"
        );
        assert_eq!(
            rec(json!({"baseScore": "9"})).unwrap(),
            "TypeError: '>=' not supported between instances of 'str' and 'float'"
        );
        assert_eq!(
            rec(json!({"epss": "high"})).unwrap(),
            "could not convert string to float: 'high'"
        );
        assert_eq!(
            rec(json!({"epss": [1]})).unwrap(),
            "TypeError: float() argument must be a string or a real number, not 'list'"
        );
        assert_eq!(rec(json!({"epss": "inf"})).unwrap(), "euvd: EUVD-1: epss is not finite");
        let many: Vec<Value> = (0..10_000).map(|_| json!({"product": "p"})).collect();
        assert_eq!(
            rec(json!({"products": many})).unwrap(),
            "euvd: EUVD-1: more than 10000 products and CVE aliases; refusing"
        );
        assert_eq!(
            rec(json!({"description": 5})).unwrap(),
            "euvd: EUVD-1: description is not a string"
        );
        assert_eq!(
            rec(json!({"products": [{"vendor": 1}]})).unwrap(),
            "euvd: EUVD-1: products[].vendor is not a string"
        );
        // no CVE alias: epss is never converted
        assert!(plan_of(json!({"id": "E", "epss": [1]})).unwrap().is_some());
        // products as a string or an object hold no dict; falsy versions are no versions
        assert!(rec(json!({"products": "abc"})).is_none());
        assert!(rec(json!({"products": {"vendor": "x"}})).is_none());
        assert!(rec(json!({"products": [{"version": 0}]})).is_none());
    }

    #[test]
    fn a_record_becomes_the_rows_of_store() {
        let p = plan(
            json!({
                "id": "EUVD-2026-1", "description": "d", "datePublished": "2026-01-01T00:00:00Z",
                "dateUpdated": "2026-02-03T04:05:06Z", "baseScore": 7, "baseScoreVersion": "3.1",
                "baseScoreVector": "CVSS:3.1/X", "aliases": "cve-2026-1\n CVE-2026-2,GHSA-x, CVE-2026-1",
                "assigner": "a", "epss": "0.5", "exploited": 0,
                "products": [{"vendor": "Acme_Corp", "product": "Widget", "version": "1.0"}, "x",
                             {"vendor": "", "product": "Other"}]
            }),
            true,
            "now",
            &Caps::default(),
        )
        .unwrap()
        .unwrap();
        let RowOp::Upsert { row, .. } = &p.vulnerability else {
            panic!()
        };
        assert_eq!(row["severity"], "HIGH");
        assert_eq!(row["cvss_score"], json!(7.0));
        assert_eq!(row["cwes"], json!([]));
        assert_eq!(
            row["extra"],
            json!({"exploited": true, "epss": "0.5", "assigner": "a", "vendors": ["Acme_Corp"],
                   "products": ["Other", "Widget"]})
        );
        assert_eq!(
            p.aliases,
            vec![("CVE-2026-1".into(), "alias".into()), ("CVE-2026-2".into(), "alias".into())]
        );
        assert_eq!(p.affected.len(), 2);
        assert_eq!(p.affected[0]["vendor"], "acme corp");
        assert_eq!(p.affected[0]["versions"], json!(["1.0"]));
        assert_eq!(p.affected[1]["vendor"], Value::Null);
        assert_eq!(p.affected[1]["versions"], Value::Null);
        // one epss row per CVE alias, duplicates included, as the Python loop
        assert_eq!(p.epss.len(), 3);
        let RowOp::Upsert { row, .. } = &p.epss[0] else {
            panic!()
        };
        assert_eq!(
            row,
            &obj(json!({"cve_id": "CVE-2026-1", "score": 0.5, "percentile": null, "date": "2026-02-03",
                        "source": "euvd"}))
        );
    }
}
