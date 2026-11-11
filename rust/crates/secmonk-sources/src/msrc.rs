//! Microsoft MSRC CVRF v3, native (rust ADR-0011, ADR-0012). Port of `src/secmonk/sources/msrc.py` plus the
//! `source_sync` bookkeeping of `ops.sync_source` / `db.set_sync_state`; reference: `py-sources` (differential test
//! `secmonk-engine/tests/native_msrc.rs`). Doc: `rust/_docs/tech/source-msrc.md`.
//!
//! A sync reads CVRF JSON documents (one per month) from `--path` (a file, or every `*.json` under a directory, in
//! the order of their `CurrentReleaseDate`) or from the API (`/updates`, then one document per month). Each document
//! is checked, then kept deflated in memory; the run is computed twice over them: a first pass decides everything
//! the `source_sync` row needs (status, counts, cursor) without emitting, the second pass emits the operations per
//! chunk of vulnerabilities while the engine applies the batches. Both passes run the same steps over the same
//! state, so they take the same decisions. Per vulnerability: the `affected` rows of this CVE and this document
//! (`extra.document`) are replaced against the stored ones (read through `MirrorView::rows_by_id`, deleted row by
//! row), and the `vulnerability` / `raw_record` rows are written only when the document is not older than the stored
//! row (else only new KB numbers are merged into `extra.kbs`).

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;
use std::io::{Read, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::StreamExt;
use secmonk_model::{JsonMap, MirrorTable, RowOp};
use secmonk_traits::{
    CallCtx, MAX_VIEW_IDS, MirrorView, ResultStream, RowsBatch, Source, SourceInfo, StepResult,
    SyncEnd, SyncParams,
};
use serde::de::{self, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;
use serde_json::{Value, json};

use crate::batch::Limits;
use crate::native::{self, Ops, Outcome};
use crate::rows::{self, DeleteKey};
use crate::{feed, py};

/// Source name.
pub const NAME: &str = "msrc";
/// Registration (`crate::IMPORTERS`): rust by default since 2026-11-11 (differential test green).
pub const IMPORTER: crate::Importer = crate::Importer {
    name: NAME,
    default_rust: true,
    new: |view| Arc::new(MsrcSource::new(view)),
};
/// Description (as the Python source's).
pub const DESCRIPTION: &str = "Microsoft MSRC CVRF v3: per-product fixed builds + KBs for Windows/Office/.NET (API blocked in sandbox)";
/// The API.
pub const BASE_URL: &str = "https://api.msrc.microsoft.com/cvrf/v3.0";
/// Connect and read timeout of a download (httpx `timeout=120.0` of the Python source).
pub const TIMEOUT: Duration = Duration::from_secs(120);

/// Input caps (the Python source has none). Worst-case memory within them: rust/_docs/tech/source-msrc.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Bytes of one document (a file or an API answer).
    pub document_bytes: u64,
    /// Bytes of the `/updates` answer.
    pub updates_bytes: u64,
    /// Bytes of all documents of one run together, as read.
    pub total_bytes: u64,
    /// Bytes of all documents of one run together, as held in memory (deflated).
    pub held_bytes: u64,
    /// Documents of one run (files under `--path`, or months).
    pub documents: usize,
    /// Directory entries visited under a `--path` directory.
    pub entries: usize,
    /// Vulnerabilities of one run (all documents).
    pub vulnerabilities: usize,
    /// Bytes of one vulnerability object.
    pub vulnerability_bytes: usize,
    /// Bytes of a document's `ProductTree` (and of its `DocumentTracking`).
    pub tree_bytes: usize,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            document_bytes: 64 * 1024 * 1024,
            updates_bytes: 16 * 1024 * 1024,
            total_bytes: 4 * 1024 * 1024 * 1024,
            held_bytes: 512 * 1024 * 1024,
            documents: 2_000,
            entries: 100_000,
            vulnerabilities: 500_000,
            vulnerability_bytes: 8 * 1024 * 1024,
            tree_bytes: 4 * 1024 * 1024,
        }
    }
}

/// Vulnerabilities per chunk of a pass (one `rows_by_id` read per chunk).
const CHUNK_VULNS: usize = MAX_VIEW_IDS;
/// Vulnerability bytes per chunk of a pass.
const CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// The native MSRC source.
pub struct MsrcSource {
    view: Arc<dyn MirrorView>,
    base: String,
    limits: Limits,
    caps: Caps,
}

impl fmt::Debug for MsrcSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MsrcSource")
            .field("base", &self.base)
            .field("limits", &self.limits)
            .field("caps", &self.caps)
            .finish_non_exhaustive()
    }
}

impl MsrcSource {
    /// The source over a read-only view of the mirror.
    pub fn new(view: Arc<dyn MirrorView>) -> MsrcSource {
        MsrcSource {
            view,
            base: BASE_URL.into(),
            limits: Limits::default(),
            caps: Caps::default(),
        }
    }

    /// Another API base URL (tests: a local server; `http://` is then allowed).
    pub fn with_base_url(mut self, base: &str) -> MsrcSource {
        self.base = base.trim_end_matches('/').into();
        self
    }

    /// Other batch limits (tests: several batches out of a small fixture).
    pub fn with_limits(mut self, limits: Limits) -> MsrcSource {
        self.limits = limits;
        self
    }

    /// Other input caps.
    pub fn with_caps(mut self, caps: Caps) -> MsrcSource {
        self.caps = caps;
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
        let say = native::Progress::new(ctx);
        let path = opts.path.clone().flatten().filter(|p| !p.is_empty());
        let loaded = match path {
            Some(p) => self.load_path(&PathBuf::from(p)).await,
            None => {
                let since = opts.since.clone().flatten().filter(|s| !s.is_empty());
                let full = opts.full.unwrap_or(false);
                self.load_remote(since, full, limit, &say).await
            }
        };
        let outcome = match loaded {
            Ok(docs) => self.outcome(docs, &say).await?,
            Err(message) => Outcome::error(message),
        };
        let first = native::first_seq(self.view.as_ref(), NAME).await?;
        Ok(native::stream(NAME, outcome, first, self.limits, t0))
    }

    /// `--path`: a file, or every `*.json` under a directory (`rglob`), in `(CurrentReleaseDate, path)` order; the
    /// run stops at the first document that cannot be read or parsed (`_local_docs` raises there).
    async fn load_path(&self, path: &Path) -> Result<Vec<Loaded>, String> {
        let shown = feed::py_path(path);
        // `Path.exists()`: false for "not found"-like errors; other errors raise (`OSError`)
        let Some(meta) = feed::exists_like_python(path)? else {
            return Err(format!("path not found: {shown}"));
        };
        let files: Vec<feed::Found> = if meta.is_file() {
            let name = path
                .file_name()
                .map_or_else(String::new, |n| n.to_string_lossy().into_owned());
            vec![feed::Found {
                path: path.to_path_buf(),
                shown: shown.clone(),
                name,
            }]
        } else if meta.is_dir() {
            let (root, caps, s) = (path.to_path_buf(), self.caps, shown.clone());
            let found = tokio::task::spawn_blocking(move || {
                feed::rglob(&root, &s, ".json", caps.entries, caps.documents)
            })
            .await
            .map_err(|e| format!("msrc: {e}"))?;
            match found {
                Ok(f) => f,
                Err(feed::TooMany::Entries) => {
                    return Err(format!(
                        "msrc: more than {} entries under {shown}; refusing",
                        self.caps.entries
                    ));
                }
                Err(feed::TooMany::Files) => {
                    return Err(format!(
                        "msrc: more than {} documents under {shown}; refusing",
                        self.caps.documents
                    ));
                }
            }
        } else {
            return Err(format!("not a regular file: {}", feed::py_repr(&shown)));
        };
        let mut budget = Budget::new(&self.caps);
        let mut docs = Vec::with_capacity(files.len());
        for feed::Found {
            path: file,
            shown: display,
            name,
        } in files
        {
            let body = match feed::read_bytes(&file, self.caps.document_bytes).await {
                Err(message) => Body::Abort(message),
                Ok(bytes) => self.prepare(bytes, &name, &mut budget).await?,
            };
            let date = match &body {
                Body::Doc(h) => h.date.clone(),
                Body::Abort(_) => String::new(),
            };
            docs.push(Loaded {
                date,
                display,
                name,
                body,
            });
        }
        docs.sort_by(|a, b| (&a.date, &a.display).cmp(&(&b.date, &b.display)));
        if let Some(i) = docs.iter().position(|d| matches!(d.body, Body::Abort(_))) {
            docs.truncate(i + 1); // the documents after it are never imported
        }
        Ok(docs)
    }

    /// `_download_months`: `/updates` sorted by `CurrentReleaseDate`, filtered by `since`, by the stored cursor
    /// (unless `full`), the newest `limit`; then one document per month. A failing download stops the run there.
    async fn load_remote(
        &self,
        since: Option<String>,
        full: bool,
        limit: Option<u64>,
        say: &native::Progress,
    ) -> Result<Vec<Loaded>, String> {
        let http = !self.base.starts_with("https://");
        let cursor = if full {
            None
        } else {
            self.stored_cursor().await.map_err(|e| e.error)?
        };
        let body = download(
            &format!("{}/updates", self.base),
            self.caps.updates_bytes,
            http,
            false,
        )
        .await?;
        let updates = updates(&body)?;
        let mut picked: Vec<(String, Option<String>, String)> = Vec::new(); // (id, CvrfUrl, date)
        for (id, url, date) in updates {
            if since.as_deref().is_some_and(|s| date.as_str() < s) {
                continue;
            }
            if cursor.as_deref().is_some_and(|c| date.as_str() <= c) {
                continue; // months already imported (a revised month has a newer date)
            }
            picked.push((id, url, date));
        }
        if let Some(n) = limit {
            let keep = usize::try_from(n).unwrap_or(usize::MAX);
            let drop = picked.len().saturating_sub(keep);
            picked.drain(..drop);
        }
        if picked.len() > self.caps.documents {
            return Err(format!(
                "msrc: more than {} documents to download; refusing (use --since or --limit)",
                self.caps.documents
            ));
        }
        let home = feed::origin(&self.base)
            .unwrap_or_default()
            .to_ascii_lowercase();
        let mut budget = Budget::new(&self.caps);
        let mut docs = Vec::new();
        for (id, url, _) in picked {
            say.line(format!("msrc: {id}"));
            let url = url.unwrap_or_else(|| format!("{}/cvrf/{id}", self.base));
            let body = if !feed::same_origin(&url, &self.base) {
                Body::Abort(format!(
                    "msrc: document URL {} is not on {}; refusing",
                    feed::scrub(&url),
                    feed::scrub(&home)
                ))
            } else {
                // a redirect may not leave the origin either
                match download(&url, self.caps.document_bytes, http, true).await {
                    Err(message) => Body::Abort(message),
                    Ok(bytes) => self.prepare(bytes, &id, &mut budget).await?,
                }
            };
            let stop = matches!(body, Body::Abort(_));
            docs.push(Loaded {
                date: String::new(),
                display: id.clone(),
                name: id,
                body,
            });
            if stop {
                break;
            }
        }
        Ok(docs)
    }

    /// The stored cursor (`get_sync_cursor`).
    async fn stored_cursor(&self) -> StepResult<Option<String>> {
        let page = self
            .view
            .rows_page(MirrorTable::SourceSync, NAME, None, 1)
            .await?;
        Ok(page
            .rows
            .first()
            .and_then(|r| r.get("cursor"))
            .and_then(Value::as_str)
            .filter(|c| !c.is_empty())
            .map(str::to_owned))
    }

    /// One document as read: decoded, parsed, counted and deflated; or the error that stops the run at it (an
    /// `Err` refuses the whole run: a cap over all documents).
    async fn prepare(
        &self,
        bytes: Vec<u8>,
        name: &str,
        budget: &mut Budget,
    ) -> Result<Body, String> {
        budget.take_bytes(bytes.len() as u64, &self.caps)?;
        let (caps, name_owned, left) = (self.caps, name.to_owned(), budget.vulns);
        let prepared = tokio::task::spawn_blocking(move || prepare(bytes, &name_owned, &caps, left))
            .await
            .map_err(|e| format!("msrc: {e}"))?;
        match prepared {
            Ok(held) => {
                budget.take_held(&held, &self.caps)?;
                Ok(Body::Doc(held))
            }
            Err(Fault::Abort(message)) => Ok(Body::Abort(message)),
            Err(Fault::Refuse(message)) => Err(message),
        }
    }

    /// The first pass, then the outcome and the lazy second pass. `source_sync.records` is the number of msrc
    /// vulnerabilities after the run (`SyncResult.total`), the entry's `records` the vulnerabilities imported by this
    /// run (`SyncResult.records`).
    async fn outcome(&self, docs: Vec<Loaded>, say: &native::Progress) -> StepResult<Outcome> {
        let before = self
            .view
            .count_rows(MirrorTable::Vulnerability, NAME)
            .await?;
        let c = self.check(&docs, say).await?;
        let (status, records, message) = match &c.abort {
            Some(m) => (
                if c.total > 0 { "partial" } else { "error" },
                c.total,
                m.clone(),
            ),
            None => (
                if c.errors > 0 { "partial" } else { "ok" },
                before + c.created,
                format!("{} vulnerabilities", c.total),
            ),
        };
        let entry_records = if status == "error" { 0 } else { c.total };
        Ok(Outcome {
            status: status.into(),
            records: entry_records,
            total: Some(records),
            cursor: c.cursor,
            message: Some(message),
            ops: ops(Emit {
                docs: docs.into_iter(),
                open: None,
                hdr: None,
                state: c.initial,
                overlay: HashMap::new(),
                repeated: c.repeated,
                view: self.view.clone(),
                caps: self.caps,
                now: secmonk_model::time::now_iso(),
            }),
        })
    }

    /// The first pass: every document in order, every vulnerability through [`step`] against the stored
    /// `vulnerability` rows (read per chunk) and the state this run leaves; nothing emitted.
    async fn check(&self, docs: &[Loaded], say: &native::Progress) -> StepResult<Checked> {
        let mut c = Checked::default();
        let mut state: HashMap<String, Option<Prev>> = HashMap::new();
        let mut seen: HashSet<(String, Option<String>)> = HashSet::new();
        for doc in docs {
            let held = match &doc.body {
                Body::Abort(m) => {
                    c.abort = Some(m.clone());
                    break;
                }
                Body::Doc(h) => h,
            };
            let mut open = Some(OpenDoc::open(held, &self.caps).await?);
            let hdr = match open.as_mut().and_then(|o| o.header.take()) {
                Some(Ok(h)) => h,
                Some(Err(e)) => {
                    c.errors += 1;
                    say.line(format!("msrc: {}: {e}", doc.name));
                    continue;
                }
                None => return Err(native::internal(NAME, "document header read twice".into())),
            };
            let mut n = 0u64;
            let mut failed = None;
            'doc: loop {
                let values = OpenDoc::next_chunk(&mut open).await?;
                if values.is_empty() {
                    break;
                }
                // the stored rows of the CVEs this run has not read yet (`None`: not stored)
                let missing: Vec<String> = distinct_cves(&values)
                    .into_iter()
                    .filter(|id| !state.contains_key(id))
                    .collect();
                let mut found: HashMap<String, Prev> = HashMap::new();
                for row in self
                    .view
                    .rows_by_id(MirrorTable::Vulnerability, NAME, &missing)
                    .await?
                {
                    if let Some(id) = row.get("id").and_then(Value::as_str) {
                        found.insert(id.to_owned(), Prev::of_row(&row));
                    }
                }
                for id in missing {
                    let prev = found.remove(&id);
                    c.initial.insert(id.clone(), prev.clone());
                    state.insert(id, prev);
                }
                for v in &values {
                    match step(&mut state, v, &hdr) {
                        Err(Fail::Doc(e)) => {
                            failed = Some(e);
                            break 'doc;
                        }
                        Err(Fail::Internal(e)) => return Err(native::internal(NAME, e)),
                        Ok(None) => {}
                        Ok(Some(st)) => {
                            n += 1;
                            let key = (st.plan.cve.clone(), hdr.doc_id.clone());
                            if !seen.insert(key.clone()) {
                                c.repeated.insert(key);
                            }
                        }
                    }
                }
            }
            match failed {
                Some(e) => {
                    c.errors += 1;
                    say.line(format!("msrc: {}: {e}", doc.name));
                }
                None => {
                    c.total += n;
                    if c.errors == 0 {
                        let date = hdr.released.clone().unwrap_or_default();
                        if !date.is_empty() && c.cursor.as_deref().is_none_or(|k| date.as_str() > k)
                        {
                            c.cursor = Some(date);
                        }
                    }
                }
            }
        }
        c.created = state
            .iter()
            .filter(|(id, now)| now.is_some() && c.initial.get(*id).is_some_and(Option::is_none))
            .count() as u64;
        Ok(c)
    }
}

/// What is left of the run's caps while documents are read.
struct Budget {
    bytes: u64,
    held: u64,
    vulns: usize,
}

impl Budget {
    fn new(caps: &Caps) -> Budget {
        Budget {
            bytes: caps.total_bytes,
            held: caps.held_bytes,
            vulns: caps.vulnerabilities,
        }
    }

    fn take_bytes(&mut self, n: u64, caps: &Caps) -> Result<(), String> {
        self.bytes = self.bytes.checked_sub(n).ok_or_else(|| {
            format!(
                "msrc: documents larger than {} bytes in total; refusing",
                caps.total_bytes
            )
        })?;
        Ok(())
    }

    fn take_held(&mut self, h: &Held, caps: &Caps) -> Result<(), String> {
        self.held = self.held.checked_sub(h.data.len() as u64).ok_or_else(|| {
            format!(
                "msrc: documents larger than {} bytes in total once compressed; refusing",
                caps.held_bytes
            )
        })?;
        self.vulns -= h.vulns.min(self.vulns);
        Ok(())
    }
}

/// One document of the run, in import order.
struct Loaded {
    /// `_release_date(doc)` (sort key of local files; empty for a document that cannot be read).
    date: String,
    /// `str(path)` (sort key of local files), or the month id.
    display: String,
    /// File name or month id (log lines).
    name: String,
    body: Body,
}

enum Body {
    Doc(Held),
    /// The run stops here with this message (`OSError`, `UnicodeDecodeError`, invalid JSON, a cap of one document).
    Abort(String),
}

/// A checked document, deflated.
struct Held {
    data: Arc<Vec<u8>>,
    len: usize,
    date: String,
    vulns: usize,
}

/// Why a document is not held: it stops the run at its position, or it refuses the whole run (a cap over all).
enum Fault {
    Abort(String),
    Refuse(String),
}

/// Decode (a UTF-8 BOM dropped, as `utf-8-sig`), parse, count and deflate one document.
fn prepare(mut bytes: Vec<u8>, name: &str, caps: &Caps, vulns_left: usize) -> Result<Held, Fault> {
    if bytes.starts_with(b"\xef\xbb\xbf") {
        bytes.drain(..3);
    }
    if let Err(e) = std::str::from_utf8(&bytes) {
        return Err(Fault::Abort(py::utf8_error(&bytes, &e)));
    }
    let text = String::from_utf8(bytes).map_err(|e| Fault::Abort(e.to_string()))?;
    let parsed = parse_doc(&text, name, caps, vulns_left)?;
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
    enc.write_all(text.as_bytes())
        .map_err(|e| Fault::Abort(e.to_string()))?;
    let data = enc.finish().map_err(|e| Fault::Abort(e.to_string()))?;
    Ok(Held {
        data: Arc::new(data),
        len: text.len(),
        date: parsed.date,
        vulns: parsed.vulns.len(),
    })
}

/// Download `url` (at most `max_bytes`) with `Accept: application/json` (the MSRC API answers XML without it), within
/// the origin of `url` when `same_origin`. Errors carry no URL credentials.
async fn download(
    url: &str,
    max_bytes: u64,
    allow_http: bool,
    same_origin: bool,
) -> Result<Vec<u8>, String> {
    let g = feed::Get {
        url,
        max_bytes,
        allow_http,
        timeout: TIMEOUT,
        accept: Some("application/json"),
        too_large: None,
        same_origin_redirects: same_origin,
    };
    Ok(feed::get(&g).await?.0)
}

/// The months of the `/updates` answer, sorted by `CurrentReleaseDate` (stable): `(ID or Alias, CvrfUrl, date)`.
fn updates(body: &[u8]) -> Result<Vec<(String, Option<String>, String)>, String> {
    let doc = feed::parse(body)?;
    let Value::Object(m) = &doc else {
        return Err(format!("AttributeError: {}", no_get(&doc)));
    };
    let mut out = Vec::new();
    for u in py::iter_items(m.get("value")).map_err(|e| format!("TypeError: {e}"))? {
        let Value::Object(u) = u.as_ref() else {
            return Err(format!("AttributeError: {}", no_get(&u)));
        };
        let date = match u.get("CurrentReleaseDate") {
            Some(v) if !py::truthy(v) => String::new(),
            None => String::new(),
            Some(Value::String(s)) => s.clone(),
            Some(_) => return Err("msrc: an update's CurrentReleaseDate is not a string".into()),
        };
        let id = [u.get("ID"), u.get("Alias")]
            .into_iter()
            .flatten()
            .find(|v| py::truthy(v))
            .map_or_else(|| "None".to_owned(), py::str_of);
        let url = match u.get("CvrfUrl") {
            Some(v) if !py::truthy(v) => None,
            None => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => return Err("msrc: an update's CvrfUrl is not a string".into()),
        };
        out.push((id, url, date));
    }
    out.sort_by(|a, b| a.2.cmp(&b.2));
    Ok(out)
}

// --------------------------------------------------------------------------------------------------- documents

/// The parts of one document a pass reads.
struct Parsed {
    /// `_release_date(doc)`.
    date: String,
    /// The document-level values, or the error of the document (per document, as `import_cvrf` raises it).
    header: Result<Header, String>,
    /// Byte ranges of the vulnerability objects (empty when the header failed).
    vulns: Vec<Range<usize>>,
}

/// What `import_cvrf` computes once per document.
struct Header {
    tree: HashMap<String, Value>,
    doc_id: Option<String>,
    released: Option<String>,
    published: Option<String>,
}

/// The top level of a document: the three members read (the last of a repeated key, as `json.loads`) or the type of
/// a document that is not an object.
enum Top<'a> {
    Object {
        tree: Option<&'a RawValue>,
        tracking: Option<&'a RawValue>,
        vulns: Option<&'a RawValue>,
    },
    Other(&'static str),
}

struct TopVisitor;

impl<'de> Visitor<'de> for TopVisitor {
    type Value = Top<'de>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a CVRF document")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Top<'de>, A::Error> {
        let (mut tree, mut tracking, mut vulns) = (None, None, None);
        while let Some(key) = map.next_key::<Cow<'de, str>>()? {
            match key.as_ref() {
                "ProductTree" => tree = Some(map.next_value::<&'de RawValue>()?),
                "DocumentTracking" => tracking = Some(map.next_value::<&'de RawValue>()?),
                "Vulnerability" => vulns = Some(map.next_value::<&'de RawValue>()?),
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(Top::Object {
            tree,
            tracking,
            vulns,
        })
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

/// Reads the vulnerability list as byte ranges (relative to the text at `base`), refusing more than `max` elements
/// (`over` is set: a cap of the run) and an element above `max_bytes` (a cap of the document).
struct Elements<'c> {
    base: usize,
    max: usize,
    max_bytes: usize,
    over: &'c Cell<bool>,
}

impl<'de> Visitor<'de> for Elements<'_> {
    type Value = Vec<Range<usize>>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a list")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::new();
        while let Some(raw) = seq.next_element::<&'de RawValue>()? {
            if out.len() >= self.max {
                self.over.set(true);
                return Err(de::Error::custom(format!(
                    "msrc: more than {} vulnerabilities in total; refusing",
                    self.max
                )));
            }
            let s = raw.get();
            if s.len() > self.max_bytes {
                return Err(de::Error::custom(format!(
                    "msrc: a vulnerability is larger than {} bytes; refusing",
                    self.max_bytes
                )));
            }
            let start = s.as_ptr() as usize - self.base;
            out.push(start..start + s.len());
        }
        Ok(out)
    }
}

/// serde errors as messages: our own refusals (`msrc: ...`) without the position, syntax errors as `invalid JSON`.
fn json_message(e: &serde_json::Error) -> String {
    feed::json_error(e, &["msrc: "])
}

/// What `for vuln in doc.get("Vulnerability") or []` needs of a member that is not a list: its type and truthiness
/// (the first item of a truthy string or object is a one-character string or a key, so a `str`). Read from the
/// member's text, which the document parse has already checked: nothing is built, whatever its size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Shape {
    type_name: &'static str,
    truthy: bool,
}

impl Shape {
    fn of(raw: &RawValue) -> Result<Shape, String> {
        const WS: [char; 4] = [' ', '\t', '\n', '\r'];
        // JSON whitespace only; the text is valid JSON
        let t = raw.get().trim_matches(WS);
        let (type_name, truthy) = match t.as_bytes().first() {
            Some(b'[') => ("list", !t[1..].trim_start_matches(WS).starts_with(']')),
            Some(b'{') => ("dict", !t[1..].trim_start_matches(WS).starts_with('}')),
            Some(b'"') => ("str", t != "\"\""),
            Some(b't') => ("bool", true),
            Some(b'f') => ("bool", false),
            Some(b'n') => ("NoneType", false),
            _ => {
                let n: Value = serde_json::from_str(t).map_err(|e| json_message(&e))?;
                (py::type_name(&n), py::truthy(&n))
            }
        };
        Ok(Shape { type_name, truthy })
    }
}

/// Parse one document: the members `import_cvrf` reads, the header with Python's per-document errors, the ranges of
/// its vulnerabilities. `Err`: the run stops at this document (syntax, a cap) or is refused (`Fault::Refuse`).
fn parse_doc(text: &str, name: &str, caps: &Caps, vulns_left: usize) -> Result<Parsed, Fault> {
    let abort = |e: serde_json::Error| Fault::Abort(json_message(&e));
    let mut de = serde_json::Deserializer::from_str(text);
    let top = de::Deserializer::deserialize_any(&mut de, TopVisitor).map_err(abort)?;
    de.end().map_err(abort)?;
    let (tree_raw, tracking_raw, vulns_raw) = match top {
        Top::Other(t) => {
            return Ok(Parsed {
                date: String::new(),
                header: Err(format!("'{t}' object has no attribute 'get'")),
                vulns: Vec::new(),
            });
        }
        Top::Object {
            tree,
            tracking,
            vulns,
        } => (tree, tracking, vulns),
    };
    for (what, raw) in [("ProductTree", tree_raw), ("DocumentTracking", tracking_raw)] {
        if raw.is_some_and(|r| r.get().len() > caps.tree_bytes) {
            return Err(Fault::Abort(format!(
                "msrc: {name}: {what} larger than {} bytes; refusing",
                caps.tree_bytes
            )));
        }
    }
    // ProductTree and DocumentTracking only: each at most `tree_bytes` of text
    let value = |raw: Option<&RawValue>| -> Result<Value, Fault> {
        raw.map_or(Ok(Value::Null), |r| {
            serde_json::from_str(r.get()).map_err(|e| Fault::Abort(json_message(&e)))
        })
    };
    let tracking = value(tracking_raw)?;
    // `_release_date`: `str((doc.get("DocumentTracking") or {}).get("CurrentReleaseDate") or "")`
    let date = match &tracking {
        Value::Object(t) => t
            .get("CurrentReleaseDate")
            .filter(|v| py::truthy(v))
            .map(py::str_of)
            .unwrap_or_default(),
        _ => String::new(),
    };
    let over = Cell::new(false);
    let is_list = vulns_raw.is_some_and(|r| r.get().trim_start().starts_with('['));
    let vulns = match vulns_raw {
        Some(r) if is_list => {
            let mut de = serde_json::Deserializer::from_str(r.get());
            de::Deserializer::deserialize_seq(
                &mut de,
                Elements {
                    base: text.as_ptr() as usize,
                    max: vulns_left,
                    max_bytes: caps.vulnerability_bytes,
                    over: &over,
                },
            )
            .map_err(|e| {
                if over.get() {
                    Fault::Refuse(json_message(&e))
                } else {
                    Fault::Abort(json_message(&e))
                }
            })?
        }
        _ => Vec::new(),
    };
    // a member that is not a list: only its shape is read, never a tree of it
    let other = match vulns_raw {
        Some(r) if !is_list => Some(Shape::of(r).map_err(Fault::Abort)?),
        _ => None,
    };
    let header = header(&value(tree_raw)?, &tracking, other);
    let vulns = if header.is_ok() { vulns } else { Vec::new() };
    Ok(Parsed {
        date,
        header,
        vulns,
    })
}

/// `import_cvrf` up to its loop: the product tree, the document id, the release dates; and the error of a
/// `Vulnerability` member that is not a list (`vulns`: its shape, given only when it is not a list).
fn header(tree: &Value, tracking: &Value, vulns: Option<Shape>) -> Result<Header, String> {
    let mut out = HashMap::new();
    if py::truthy(tree) {
        walk_products(tree, &mut out);
    }
    let empty = JsonMap::new();
    let tracking = match tracking {
        v if !py::truthy(v) => &empty,
        Value::Object(m) => m,
        v => return Err(no_get(v)),
    };
    let ident = match tracking.get("Identification") {
        Some(v) if !py::truthy(v) => &empty,
        None => &empty,
        Some(Value::Object(m)) => m,
        Some(v) => return Err(no_get(v)),
    };
    let doc_id = value_of(ident.get("ID"));
    let date = |k: &str| match tracking.get(k) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(format!("msrc: DocumentTracking.{k} is not a string")),
    };
    let released = date("CurrentReleaseDate")?;
    let published = date("InitialReleaseDate")?;
    // `for vuln in doc.get("Vulnerability") or []` over something that is not a list: nothing when falsy, else a
    // number or `true` is not iterable, and the first item of a string or object (a `str`) has no `get`
    if let Some(v) = vulns.filter(|v| v.truthy && v.type_name != "list") {
        return Err(match v.type_name {
            "str" | "dict" => py::no_attr("str", "get"),
            t => format!("'{t}' object is not iterable"),
        });
    }
    Ok(Header {
        tree: out,
        doc_id,
        released,
        published,
    })
}

/// `_walk_products`: every object with a string `ProductID` and a `Value`, depth first; for a `ProductID` seen
/// again, the value found last is kept.
fn walk_products(node: &Value, out: &mut HashMap<String, Value>) {
    match node {
        Value::Object(m) => {
            if let (Some(Value::String(pid)), Some(v)) = (m.get("ProductID"), m.get("Value")) {
                out.insert(pid.clone(), v.clone());
            }
            for v in m.values() {
                walk_products(v, out);
            }
        }
        Value::Array(a) => {
            for v in a {
                walk_products(v, out);
            }
        }
        _ => {}
    }
}

/// A document opened for a pass: its text, header and the next vulnerability to read.
struct OpenDoc {
    text: String,
    header: Option<Result<Header, String>>,
    vulns: Vec<Range<usize>>,
    next: usize,
}

impl OpenDoc {
    async fn open(held: &Held, caps: &Caps) -> StepResult<OpenDoc> {
        let (data, len, caps) = (held.data.clone(), held.len, *caps);
        tokio::task::spawn_blocking(move || -> Result<OpenDoc, String> {
            let mut text = String::with_capacity(len);
            flate2::read::DeflateDecoder::new(&data[..])
                .read_to_string(&mut text)
                .map_err(|e| e.to_string())?;
            let p = parse_doc(&text, "", &caps, usize::MAX).map_err(|f| match f {
                Fault::Abort(m) | Fault::Refuse(m) => m,
            })?;
            Ok(OpenDoc {
                text,
                header: Some(p.header),
                vulns: p.vulns,
                next: 0,
            })
        })
        .await
        .map_err(|e| native::internal(NAME, e.to_string()))?
        .map_err(|m| native::internal(NAME, m))
    }

    /// [`OpenDoc::parse_chunk`] on the blocking pool (parsing up to [`CHUNK_BYTES`] plus one vulnerability of up to
    /// `Caps::vulnerability_bytes` must not hold a runtime thread); the document is moved there and back.
    async fn next_chunk(open: &mut Option<OpenDoc>) -> StepResult<Vec<Value>> {
        let Some(mut doc) = open.take() else {
            return Err(native::internal(NAME, "document read after its end".into()));
        };
        let (doc, values) = tokio::task::spawn_blocking(move || {
            let v = doc.parse_chunk();
            (doc, v)
        })
        .await
        .map_err(|e| native::internal(NAME, e.to_string()))?;
        *open = Some(doc);
        values
    }

    /// The next vulnerabilities, parsed (at most [`CHUNK_VULNS`] and about [`CHUNK_BYTES`]); empty at the end.
    fn parse_chunk(&mut self) -> StepResult<Vec<Value>> {
        let mut out = Vec::new();
        let mut bytes = 0usize;
        while out.len() < CHUNK_VULNS && bytes < CHUNK_BYTES {
            let Some(r) = self.vulns.get(self.next).cloned() else {
                break;
            };
            bytes += r.len();
            out.push(
                serde_json::from_str(&self.text[r])
                    .map_err(|e| native::internal(NAME, format!("invalid JSON: {e}")))?,
            );
            self.next += 1;
        }
        Ok(out)
    }
}

/// The CVE ids of a chunk (strings, non-empty), each once.
fn distinct_cves(values: &[Value]) -> Vec<String> {
    let mut seen = HashSet::new();
    values
        .iter()
        .filter_map(|v| v.get("CVE").and_then(Value::as_str))
        .filter(|s| !s.is_empty() && seen.insert(*s))
        .map(str::to_owned)
        .collect()
}

// --------------------------------------------------------------------------------------------------- Python semantics

/// `_value(x)`: `x.get("Value")` of an object, then `str(x)` unless it is `None` or `""`.
fn value_of(x: Option<&Value>) -> Option<String> {
    let x = match x {
        Some(Value::Object(m)) => m.get("Value"),
        other => other,
    };
    match x {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) if s.is_empty() => None,
        Some(v) => Some(py::str_of(v)),
    }
}

/// `AttributeError` text of `x.get(...)` on something that is not an object.
fn no_get(v: &Value) -> String {
    py::no_attr(py::type_name(v), "get")
}

/// `re.fullmatch(r"\d{6,8}", kb)`: six to eight Unicode decimal digits (category Nd).
fn is_kb_number(kb: &str) -> bool {
    let n = kb.chars().count();
    // one character `float()` accepts is exactly one decimal digit (signs, `.`, `_`, `e` and spaces alone are not)
    (6..=8).contains(&n)
        && kb
            .chars()
            .all(|c| py::float_str(c.encode_utf8(&mut [0u8; 4])).is_some())
}

/// The text of `s` without a case-insensitive (ASCII) suffix `pat`, if it ends with it.
fn strip_suffix_ci<'a>(s: &'a str, pat: &str) -> Option<&'a str> {
    let n = s.len().checked_sub(pat.len())?;
    s.as_bytes()[n..]
        .eq_ignore_ascii_case(pat.as_bytes())
        .then(|| &s[..n])
}

fn trim_end_ws(s: &str) -> &str {
    s.trim_end_matches(py::is_space)
}

/// `_ARCH_SUFFIX.sub("", s)`: `\s+for\s+(?:(?:x64|x86|arm64|itanium|ia-64)-based|32-bit|64-bit)\s+systems\s*$`.
fn strip_arch(s: &str) -> &str {
    const ARCHES: [&str; 7] = [
        "x64-based",
        "x86-based",
        "arm64-based",
        "itanium-based",
        "ia-64-based",
        "32-bit",
        "64-bit",
    ];
    fn one_or_more_ws(t: &str) -> Option<&str> {
        let u = trim_end_ws(t);
        (u.len() < t.len()).then_some(u)
    }
    let found = (|| {
        let rest = strip_suffix_ci(trim_end_ws(s), "systems")?;
        let rest = one_or_more_ws(rest)?;
        let rest = ARCHES.iter().find_map(|a| {
            let r = strip_suffix_ci(rest, a)?;
            one_or_more_ws(r)
        })?;
        let rest = strip_suffix_ci(rest, "for")?;
        one_or_more_ws(rest)
    })();
    found.unwrap_or(s)
}

/// `_CORE_SUFFIX.sub("", s)`: `\s*\(server core installation\)\s*$`.
fn strip_core(s: &str) -> &str {
    strip_suffix_ci(trim_end_ws(s), "(server core installation)").map_or(s, trim_end_ws)
}

/// `normalize_product_name`: MSRC FullProductName -> the product spelling of Microsoft CNA records (lowercase).
/// Case-insensitive matching is ASCII only (Python's `re.IGNORECASE` also folds `ſ` and the Kelvin sign).
pub fn normalize_product_name(full_name: &str) -> String {
    let s = py::split_ws(full_name).collect::<Vec<_>>().join(" ");
    const PREFIX: &str = "windows server, version ";
    if let Some(rest) = s
        .get(..PREFIX.len())
        .filter(|p| p.eq_ignore_ascii_case(PREFIX))
        .map(|_| &s[PREFIX.len()..])
    {
        let word: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !word.is_empty() {
            return format!(
                "windows server 2022, {} edition (server core installation)",
                word.to_lowercase()
            );
        }
    }
    py::strip(strip_arch(strip_core(strip_arch(&s)))).to_lowercase()
}

// --------------------------------------------------------------------------------------------------- one vulnerability

/// The stored state of a CVE's `vulnerability` row that `import_cvrf` reads.
#[derive(Debug, Clone, PartialEq)]
struct Prev {
    modified: Option<String>,
    extra: JsonMap,
}

impl Prev {
    fn of_row(row: &JsonMap) -> Prev {
        Prev {
            modified: row.get("modified").and_then(Value::as_str).map(str::to_owned),
            // `loads(prev["extra"], {})`
            extra: row
                .get("extra")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default(),
        }
    }

    fn kbs(&self) -> BTreeSet<String> {
        match self.extra.get("kbs") {
            Some(Value::Array(a)) => a.iter().map(py::str_of).collect(),
            _ => BTreeSet::new(),
        }
    }
}

/// One `affected` row being collected (`rows[(prod, FixedBuild)]`).
#[derive(Default)]
struct RowAcc {
    kbs: BTreeSet<String>,
    product_ids: Vec<String>,
    full_names: BTreeSet<String>,
    supersedes: BTreeSet<String>,
}

/// What `import_cvrf` computes for one vulnerability before its transaction.
struct Plan {
    cve: String,
    kbs: BTreeSet<String>,
    affected: Vec<JsonMap>,
    summary: Option<String>,
    details: Option<String>,
    score: Option<f64>,
    /// `cvss_vector` and `cvss_version`, or the error raised when they are computed (only in the branch that writes
    /// the vulnerability row).
    vector: Result<(Option<String>, Option<String>), String>,
}

/// The vulnerability's `vulnerability` / `raw_record` write.
enum Decision {
    /// The document is not older than the stored row: both rows written.
    Newest {
        extra: Value,
        vector: Option<String>,
        version: Option<String>,
    },
    /// An older document with new KB numbers: only `extra` updated.
    Kbs(JsonMap),
    /// An older document without new KB numbers.
    Keep,
}

struct Step {
    plan: Plan,
    decision: Decision,
}

/// A vulnerability that fails: the document stops there (Python's per-document `except`), or an internal error.
enum Fail {
    Doc(String),
    Internal(String),
}

impl From<String> for Fail {
    fn from(m: String) -> Fail {
        Fail::Doc(m)
    }
}

/// The loop body of `import_cvrf` up to its transaction. `None`: no `CVE` (skipped, not counted).
fn plan(vuln: &Value, hdr: &Header) -> Result<Option<Plan>, String> {
    let Value::Object(m) = vuln else {
        return Err(no_get(vuln));
    };
    let cve = match m.get("CVE") {
        None => return Ok(None),
        Some(v) if !py::truthy(v) => return Ok(None),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return Err("msrc: a CVE is not a string".into()),
    };
    // `max(scores, key=BaseScore)`: the first of the highest numeric scores (a bool is an int there)
    let mut best: Option<(f64, &JsonMap)> = None;
    for s in py::iter_items(m.get("CVSSScoreSets"))? {
        // an object is always a list element (borrowed); characters and keys are strings
        let s = match s {
            Cow::Borrowed(Value::Object(o)) => o,
            other => return Err(no_get(&other)),
        };
        let score = match s.get("BaseScore") {
            Some(Value::Number(n)) => n.as_f64(),
            Some(Value::Bool(b)) => Some(if *b { 1.0 } else { 0.0 }),
            _ => None,
        };
        if let Some(x) = score
            && best.is_none_or(|(b, _)| x > b)
        {
            best = Some((x, s));
        }
    }
    let mut details = None;
    for nt in py::iter_items(m.get("Notes"))? {
        let Value::Object(nt) = nt.as_ref() else {
            return Err(no_get(&nt));
        };
        if nt.get("Title").and_then(Value::as_str) == Some("Description") {
            details = value_of(nt.get("Value"));
            break;
        }
    }
    let mut kbs = BTreeSet::new();
    let mut acc: BTreeMap<(String, String), RowAcc> = BTreeMap::new();
    for rem in py::iter_items(m.get("Remediations"))? {
        let Value::Object(rem) = rem.as_ref() else {
            return Err(no_get(&rem));
        };
        let kb = value_of(rem.get("Description"));
        if let Some(k) = kb.as_deref().filter(|k| is_kb_number(k)) {
            kbs.insert(format!("KB{k}"));
        }
        let kind = py::str_of(rem.get("Type").unwrap_or(&Value::Null));
        if kind != "2" && kind != "Vendor Fix" {
            continue;
        }
        let Some(fixed) = rem.get("FixedBuild").filter(|v| py::truthy(v)) else {
            continue;
        };
        // per character for a string, as Python iterates it
        for pid in py::iter_items(rem.get("ProductID"))? {
            let pid = py::str_of(&pid);
            let Some(name) = hdr.tree.get(&pid).filter(|v| py::truthy(v)) else {
                continue;
            };
            let Value::String(name) = name else {
                return Err(py::no_attr(py::type_name(name), "split"));
            };
            let prod = normalize_product_name(name);
            let fixed = match fixed {
                Value::String(s) => s.clone(),
                Value::Array(_) | Value::Object(_) => {
                    return Err(format!("unhashable type: '{}'", py::type_name(fixed)));
                }
                _ => return Err(format!("msrc: {cve}: FixedBuild is not a string")),
            };
            let row = acc.entry((prod, fixed)).or_default();
            if let Some(k) = &kb {
                row.kbs.insert(format!("KB{k}"));
            }
            row.product_ids.push(pid);
            row.full_names.insert(name.clone());
            if let Some(s) = rem.get("Supercedence").filter(|v| py::truthy(v)) {
                row.supersedes.insert(py::str_of(s));
            }
        }
    }
    let vector = match best.map(|(_, b)| b.get("Vector")) {
        None | Some(None | Some(Value::Null)) => Ok((None, None)),
        Some(Some(Value::String(v))) => {
            let version = v
                .split('/')
                .next()
                .unwrap_or_default()
                .replace("CVSS:", "");
            Ok((Some(v.clone()), Some(version).filter(|s| !s.is_empty())))
        }
        Some(Some(v)) if py::truthy(v) => Err(py::no_attr(py::type_name(v), "split")),
        Some(Some(_)) => Err(format!("msrc: {cve}: Vector is not a string")),
    };
    let doc = json!(hdr.doc_id);
    let affected = acc
        .into_iter()
        .map(|((prod, fixed), r)| {
            rows::affected(
                NAME,
                &cve,
                rows::Affected {
                    vendor: Some("microsoft".into()),
                    product: Some(prod),
                    range_type: Some("CVE".into()),
                    version_type: Some("custom".into()),
                    events: Some(vec![json!({"introduced": "0"}), json!({"fixed": fixed})]),
                    extra: json!({
                        "kb": r.kbs,
                        "product_ids": r.product_ids,
                        "full_names": r.full_names,
                        "supersedes": r.supersedes,
                        "document": doc,
                    }),
                    ..rows::Affected::default()
                },
            )
        })
        .collect();
    Ok(Some(Plan {
        cve,
        kbs,
        affected,
        summary: value_of(m.get("Title")),
        details,
        score: best.map(|(s, _)| s),
        vector,
    }))
}

/// One vulnerability of `import_cvrf`: its plan and the transaction's decision against `state` (the CVE's row as
/// stored at the start of the run, then as this run left it), which is updated.
fn step(
    state: &mut HashMap<String, Option<Prev>>,
    vuln: &Value,
    hdr: &Header,
) -> Result<Option<Step>, Fail> {
    let Some(plan) = plan(vuln, hdr)? else {
        return Ok(None);
    };
    let prev = state
        .get(&plan.cve)
        .ok_or_else(|| Fail::Internal(format!("{}: stored row not read", plan.cve)))?
        .clone();
    let released = hdr.released.as_deref().filter(|r| !r.is_empty());
    let older = prev.as_ref().is_some_and(|p| {
        let m = p.modified.as_deref().unwrap_or("");
        !m.is_empty() && released.is_some_and(|r| m > r)
    });
    let prev_kbs = prev.as_ref().map(Prev::kbs).unwrap_or_default();
    let decision = if !older {
        let (vector, version) = plan.vector.clone()?;
        let all: BTreeSet<&String> = plan.kbs.iter().chain(&prev_kbs).collect();
        let extra = json!({"document": hdr.doc_id, "kbs": all});
        state.insert(
            plan.cve.clone(),
            Some(Prev {
                modified: hdr.released.clone(),
                extra: extra.as_object().cloned().unwrap_or_default(),
            }),
        );
        Decision::Newest {
            extra,
            vector,
            version,
        }
    } else if !plan.kbs.is_subset(&prev_kbs) {
        let mut p = prev.unwrap_or(Prev {
            modified: None,
            extra: JsonMap::new(),
        });
        let all: BTreeSet<&String> = plan.kbs.iter().chain(&prev_kbs).collect();
        p.extra.insert("kbs".into(), json!(all));
        let extra = p.extra.clone();
        state.insert(plan.cve.clone(), Some(p));
        Decision::Kbs(extra)
    } else {
        Decision::Keep
    };
    Ok(Some(Step { plan, decision }))
}

/// What the first pass found.
#[derive(Default)]
struct Checked {
    /// Vulnerabilities of the documents imported in full (`SyncResult.records`).
    total: u64,
    /// Documents that failed (per-document errors).
    errors: u64,
    cursor: Option<String>,
    /// The message of the document that stopped the run.
    abort: Option<String>,
    /// The stored state of every CVE the run reads, as at its start (the second pass starts from it).
    initial: HashMap<String, Option<Prev>>,
    /// CVEs the run stores that were not stored before.
    created: u64,
    /// `(CVE, document)` pairs the run writes more than once (the second pass keeps what it wrote for them).
    repeated: HashSet<(String, Option<String>)>,
}

// --------------------------------------------------------------------------------------------------- second pass

/// The state of the operation stream.
struct Emit {
    docs: std::vec::IntoIter<Loaded>,
    /// The document being emitted (`None` between documents) and its header.
    open: Option<OpenDoc>,
    hdr: Option<Header>,
    state: HashMap<String, Option<Prev>>,
    overlay: HashMap<(String, Option<String>), Vec<JsonMap>>,
    repeated: HashSet<(String, Option<String>)>,
    view: Arc<dyn MirrorView>,
    caps: Caps,
    now: String,
}

/// The operations of the run, one chunk of vulnerabilities at a time.
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
    /// The operations of the next chunk (`None` after the last document or at the one that stops the run).
    async fn chunk(&mut self) -> StepResult<Option<Vec<RowOp>>> {
        loop {
            if self.open.is_none() {
                let Some(doc) = self.docs.next() else {
                    return Ok(None);
                };
                let Body::Doc(held) = &doc.body else {
                    return Ok(None);
                };
                let mut open = OpenDoc::open(held, &self.caps).await?;
                match open.header.take() {
                    Some(Ok(h)) => {
                        self.open = Some(open);
                        self.hdr = Some(h);
                    }
                    _ => continue, // a failing document: nothing written
                }
            }
            let values = OpenDoc::next_chunk(&mut self.open).await?;
            if values.is_empty() {
                self.open = None;
                continue;
            }
            let ids = distinct_cves(&values);
            let stored = self
                .view
                .rows_by_id(MirrorTable::Affected, NAME, &ids)
                .await?;
            let by_id = rows::group_by(&stored, "vuln_id");
            let mut ops = Vec::new();
            let mut stop = false;
            if let Some(hdr) = self.hdr.as_ref() {
                for v in &values {
                    match step(&mut self.state, v, hdr) {
                        Err(Fail::Doc(_)) => {
                            stop = true; // the rest of the document is not imported
                            break;
                        }
                        Err(Fail::Internal(m)) => return Err(native::internal(NAME, m)),
                        Ok(None) => {}
                        Ok(Some(st)) => {
                            let key = (st.plan.cve.clone(), hdr.doc_id.clone());
                            let doc = json!(hdr.doc_id);
                            let stored: Vec<&JsonMap> = match self.overlay.get(&key) {
                                Some(rows) => rows.iter().collect(),
                                None => by_id
                                    .get(st.plan.cve.as_str())
                                    .map(|rs| {
                                        rs.iter()
                                            .copied()
                                            .filter(|r| document_of(r) == doc)
                                            .collect()
                                    })
                                    .unwrap_or_default(),
                            };
                            let keep = self
                                .repeated
                                .contains(&key)
                                .then(|| st.plan.affected.clone());
                            emit_step(&mut ops, st, v, hdr, &stored, &self.now);
                            if let Some(rows) = keep {
                                self.overlay.insert(key, rows);
                            }
                        }
                    }
                }
            }
            if stop {
                self.open = None;
            }
            return Ok(Some(ops));
        }
    }
}

/// `json_extract(extra, '$.document')` of a stored `affected` row (null when absent).
fn document_of(row: &JsonMap) -> Value {
    row.get("extra")
        .and_then(Value::as_object)
        .and_then(|e| e.get("document"))
        .cloned()
        .unwrap_or(Value::Null)
}

/// The row operations of one vulnerability: its `vulnerability` / `raw_record` write, then the `affected` rows of
/// this CVE and document replaced (one delete per stored row, keyed by the row; nothing when they are equal).
fn emit_step(
    ops: &mut Vec<RowOp>,
    st: Step,
    vuln: &Value,
    hdr: &Header,
    stored: &[&JsonMap],
    now: &str,
) {
    let Step { plan, decision } = st;
    match decision {
        Decision::Newest {
            extra,
            vector,
            version,
        } => {
            ops.push(rows::raw_record(
                NAME,
                &plan.cve,
                hdr.released.as_deref(),
                now,
                vuln.clone(),
            ));
            ops.push(rows::vulnerability(
                NAME,
                &plan.cve,
                rows::Vulnerability {
                    summary: plan.summary,
                    details: plan.details,
                    published: hdr.published.clone(),
                    modified: hdr.released.clone(),
                    severity: rows::severity_from_score(plan.score).map(str::to_owned),
                    cvss_score: plan.score,
                    cvss_vector: vector,
                    cvss_version: version,
                    extra,
                    ..rows::Vulnerability::default()
                },
            ));
        }
        Decision::Kbs(extra) => {
            // `UPDATE vulnerability SET extra=?`: an upsert of the key and `extra` only
            let mut row = JsonMap::new();
            row.insert("source".into(), json!(NAME));
            row.insert("id".into(), json!(plan.cve));
            row.insert("extra".into(), Value::Object(extra));
            ops.push(RowOp::Upsert {
                table: MirrorTable::Vulnerability,
                row,
            });
        }
        Decision::Keep => {}
    }
    ops.extend(rows::replace_affected(stored, plan.affected, DeleteKey::Row));
}

#[async_trait]
impl Source for MsrcSource {
    fn sources(&self) -> Vec<SourceInfo> {
        vec![SourceInfo {
            name: NAME.into(),
            description: DESCRIPTION.into(),
            in_all: true, // as the Python source (no `in_all = False`; `ops.SYNC_ALL_ORDER` lists it)
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

    #[test]
    fn product_names_normalize_like_python() {
        let n = normalize_product_name;
        assert_eq!(n("Windows 11 Version 23H2 for x64-based Systems"), "windows 11 version 23h2");
        assert_eq!(n("Windows 11 Version 23H2 for ARM64-based Systems"), "windows 11 version 23h2");
        assert_eq!(n("Windows 10 Version 22H2 for 32-bit Systems"), "windows 10 version 22h2");
        assert_eq!(n("Windows Server 2022 (Server Core installation)"), "windows server 2022");
        assert_eq!(n("Windows Server 2022"), "windows server 2022");
        assert_eq!(
            n("Windows Server, version 23H2 (Server Core installation)"),
            "windows server 2022, 23h2 edition (server core installation)"
        );
        // arch, then Server Core, then arch again; whitespace collapsed first
        assert_eq!(
            n("  Windows Server 2012 R2\tfor x64-based Systems  (Server Core installation) "),
            "windows server 2012 r2"
        );
        assert_eq!(n("Windows 7 for Itanium-based Systems"), "windows 7");
        assert_eq!(n("Windows Server 2008 for IA-64-based Systems"), "windows server 2008");
        assert_eq!(n("Office 2016 (64-bit edition)"), "office 2016 (64-bit edition)");
        // no space before `for`, or an arch that is not listed: unchanged (lower-cased)
        assert_eq!(n("Xfor x64-based Systems"), "xfor x64-based systems");
        assert_eq!(n("Windows for zx64-based Systems"), "windows for zx64-based systems");
        assert_eq!(n("for x64-based Systems"), "for x64-based systems");
        assert_eq!(n("Windows Server, version "), "windows server, version");
        assert_eq!(n("WINDOWS SERVER, VERSION 1909"), "windows server 2022, 1909 edition (server core installation)");
    }

    #[test]
    fn python_str_of_json_values() {
        // `str()` and `repr(float)` themselves: py.rs tests
        assert_eq!(py::str_of(&json!(1.5e300)), "1.5e+300");
        assert_eq!(py::str_of(&json!([1, "a", {"b": null, "c": true}])), "[1, 'a', {'b': None, 'c': True}]");
        assert_eq!(value_of(Some(&json!({"Value": ""}))), None);
        assert_eq!(value_of(Some(&json!({"Other": 1}))), None);
        assert_eq!(value_of(Some(&json!(0))), Some("0".into()));
        assert_eq!(value_of(Some(&json!(false))), Some("False".into()));
        assert!(is_kb_number("5041585"));
        assert!(is_kb_number("٥٠٤١٥٨٥"));
        assert!(!is_kb_number("50415"));
        assert!(!is_kb_number("504158512"));
        assert!(!is_kb_number("5041e85"));
        assert!(!is_kb_number("+041585"));
        assert_eq!(py::iter_items(Some(&json!(3))).unwrap_err(), "'int' object is not iterable");
        assert_eq!(py::iter_items(Some(&json!("ab"))).unwrap().count(), 2);
        assert!(py::iter_items(Some(&json!(0))).unwrap().next().is_none());
    }

    fn hdr() -> Header {
        let tree = json!({"FullProductName": [
            {"ProductID": "1", "Value": "Windows 11 Version 23H2 for x64-based Systems"},
            {"ProductID": "2", "Value": "Windows 11 Version 23H2 for ARM64-based Systems"},
            {"ProductID": "3", "Value": 7},
            {"ProductID": "4", "Value": ""}],
            "Branch": [{"Items": [{"ProductID": "5", "Value": "Windows Server 2022"}]}]});
        header(
            &tree,
            &json!({"Identification": {"ID": {"Value": "2024-Aug"}}, "CurrentReleaseDate": "2024-08-14",
                    "InitialReleaseDate": "2024-08-13"}),
            None,
        )
        .unwrap()
    }

    #[test]
    fn a_vulnerability_becomes_rows_like_import_cvrf() {
        let h = hdr();
        assert_eq!(h.tree.len(), 5, "nested branches walked");
        assert_eq!(h.doc_id.as_deref(), Some("2024-Aug"));
        let p = plan(
            &json!({"CVE": "CVE-1", "Title": {"Value": "t"},
                    "Notes": [{"Title": "FAQ", "Value": "no"}, {"Title": "Description", "Value": "d"}, 5],
                    "CVSSScoreSets": [{"BaseScore": 7.5, "Vector": "x"}, {"BaseScore": "9"},
                                      {"BaseScore": 9, "Vector": "CVSS:3.1/AV:N"}, {"BaseScore": 9.0}],
                    "Remediations": [
                        {"Type": 2, "Description": {"Value": "5041585"}, "FixedBuild": "10.0.1",
                         "ProductID": ["1", "2", "3x", "4"], "Supercedence": 5040442},
                        {"Type": "Vendor Fix", "Description": "Click to Run", "FixedBuild": "10.0.1",
                         "ProductID": [1]},
                        {"Type": 2.0, "Description": "5000001", "FixedBuild": "9", "ProductID": ["5"]},
                        {"Type": 2, "Description": "5000002", "ProductID": ["5"]}]}),
            &h,
        )
        .unwrap()
        .unwrap();
        assert_eq!(p.summary.as_deref(), Some("t"));
        assert_eq!(p.details.as_deref(), Some("d"), "the first Description note; later notes unread");
        assert_eq!(p.score, Some(9.0));
        assert_eq!(p.vector, Ok((Some("CVSS:3.1/AV:N".into()), Some("3.1".into()))));
        assert_eq!(
            p.kbs.iter().collect::<Vec<_>>(),
            vec!["KB5000001", "KB5000002", "KB5041585"]
        );
        assert_eq!(p.affected.len(), 1, "one product + fixed build");
        let r = &p.affected[0];
        assert_eq!(r["product"], "windows 11 version 23h2");
        assert_eq!(r["vendor"], "microsoft");
        assert_eq!(r["events"], json!([{"introduced": "0"}, {"fixed": "10.0.1"}]));
        assert_eq!(
            r["extra"],
            json!({"kb": ["KB5041585", "KBClick to Run"], "product_ids": ["1", "2", "1"],
                   "full_names": ["Windows 11 Version 23H2 for ARM64-based Systems",
                                  "Windows 11 Version 23H2 for x64-based Systems"],
                   "supersedes": ["5040442"], "document": "2024-Aug"})
        );
    }

    #[test]
    fn vulnerabilities_fail_like_python() {
        let h = hdr();
        let err = |v: Value| plan(&v, &h).err().unwrap();
        assert_eq!(err(json!(5)), "'int' object has no attribute 'get'");
        assert!(plan(&json!({"CVE": ""}), &h).unwrap().is_none());
        assert!(plan(&json!({"Title": "x"}), &h).unwrap().is_none());
        assert_eq!(err(json!({"CVE": 5})), "msrc: a CVE is not a string");
        assert_eq!(err(json!({"CVE": "C", "CVSSScoreSets": 3})), "'int' object is not iterable");
        assert_eq!(err(json!({"CVE": "C", "CVSSScoreSets": "ab"})), "'str' object has no attribute 'get'");
        assert_eq!(err(json!({"CVE": "C", "Notes": [1]})), "'int' object has no attribute 'get'");
        let rem = |r: Value| json!({"CVE": "C", "Remediations": [r]});
        assert_eq!(
            err(rem(json!({"Type": 2, "FixedBuild": "1", "ProductID": ["3"]}))),
            "'int' object has no attribute 'split'"
        );
        assert_eq!(
            err(rem(json!({"Type": 2, "FixedBuild": ["1"], "ProductID": ["1"]}))),
            "unhashable type: 'list'"
        );
        assert_eq!(
            err(rem(json!({"Type": 2, "FixedBuild": 10, "ProductID": ["1"]}))),
            "msrc: C: FixedBuild is not a string"
        );
        // a bad FixedBuild without a known product raises nothing (the key is never built)
        assert!(plan(&rem(json!({"Type": 2, "FixedBuild": [1], "ProductID": ["9"]})), &h).is_ok());
        // the vector error is kept for the branch that writes the vulnerability row
        let p = plan(&json!({"CVE": "C", "CVSSScoreSets": [{"BaseScore": 1, "Vector": 5}]}), &h)
            .unwrap()
            .unwrap();
        assert_eq!(p.vector, Err("'int' object has no attribute 'split'".into()));
        assert_eq!(
            header(&json!({}), &json!([1]), None).err().unwrap(),
            "'list' object has no attribute 'get'"
        );
        assert_eq!(
            header(&json!({}), &json!({"CurrentReleaseDate": 5}), None).err().unwrap(),
            "msrc: DocumentTracking.CurrentReleaseDate is not a string"
        );
        let member = |text: &str| header(&json!({}), &json!({}), Some(shape(text))).err();
        assert_eq!(member("7").unwrap(), "'int' object is not iterable");
        assert_eq!(member("1e3").unwrap(), "'float' object is not iterable");
        assert_eq!(member("true").unwrap(), "'bool' object is not iterable");
        assert_eq!(member(r#"{"a": 1}"#).unwrap(), "'str' object has no attribute 'get'");
        assert_eq!(member(r#""ab""#).unwrap(), "'str' object has no attribute 'get'");
        for falsy in [r#""""#, "0", "-0", "0.0", "0e5", "false", "null", "{}", "{ \n }"] {
            assert_eq!(member(falsy), None, "{falsy}");
        }
    }

    /// The shape of a `Vulnerability` member written as `text`.
    fn shape(text: &str) -> Shape {
        Shape::of(serde_json::from_str::<&RawValue>(text).unwrap()).unwrap()
    }

    #[test]
    fn a_vulnerability_member_that_is_not_a_list_is_never_built() {
        // M2 of the W9.6 review: only the type and truthiness are read (a member of the size of the document cap
        // would otherwise be parsed whole); the per-document error is the one Python raises on its first item
        let caps = Caps::default();
        let big = format!(r#"{{"Vulnerability": {{"{}": 1, "b": [2]}}}}"#, "k".repeat(1 << 20));
        let d = parse_doc(&big, "x", &caps, 10).ok().unwrap();
        assert_eq!(d.header.err().unwrap(), "'str' object has no attribute 'get'");
        let d = parse_doc(r#"{"Vulnerability": "\u00e9x"}"#, "x", &caps, 10).ok().unwrap();
        assert_eq!(d.header.err().unwrap(), "'str' object has no attribute 'get'");
        let d = parse_doc(r#"{"Vulnerability":  0.0 }"#, "x", &caps, 10).ok().unwrap();
        assert!(d.header.is_ok());
        assert_eq!(shape(" [ ] ").type_name, "list");
    }

    #[test]
    fn the_newest_document_writes_the_vulnerability_row() {
        let mut h = hdr();
        let v = json!({"CVE": "C", "Remediations": [{"Description": "5000001"}]});
        let mut state = HashMap::from([("C".to_owned(), None)]);
        let st = step(&mut state, &v, &h).ok().unwrap().unwrap();
        assert!(matches!(st.decision, Decision::Newest { .. }));
        // an older document: only new KBs merged, the document id kept
        h.released = Some("2024-07-01".into());
        h.doc_id = Some("2024-Jul".into());
        let v2 = json!({"CVE": "C", "Remediations": [{"Description": "5000002"}]});
        match step(&mut state, &v2, &h).ok().unwrap().unwrap().decision {
            Decision::Kbs(extra) => assert_eq!(
                Value::Object(extra),
                json!({"document": "2024-Aug", "kbs": ["KB5000001", "KB5000002"]})
            ),
            _ => panic!("expected a kbs update"),
        }
        assert!(matches!(
            step(&mut state, &v2, &h).ok().unwrap().unwrap().decision,
            Decision::Keep
        ));
        // an older document never raises the vector error; the newest does
        let bad = json!({"CVE": "C", "CVSSScoreSets": [{"BaseScore": 1, "Vector": 5}]});
        assert!(step(&mut state, &bad, &h).is_ok());
        h.released = Some("2025-01-01".into());
        assert!(matches!(step(&mut state, &bad, &h), Err(Fail::Doc(_))));
        let mut empty = HashMap::new();
        assert!(matches!(step(&mut empty, &v, &h), Err(Fail::Internal(_))));
    }

    #[test]
    fn documents_parse_with_caps() {
        let caps = Caps::default();
        let d = parse_doc(
            r#"{"Vulnerability": [{"CVE": "A"}, 2], "DocumentTracking": {"CurrentReleaseDate": "2024"},
                "Vulnerability": [{"CVE": "B"}]}"#,
            "x",
            &caps,
            10,
        )
        .ok()
        .unwrap();
        assert_eq!(d.vulns.len(), 1, "the last of a repeated key");
        assert_eq!(d.date, "2024");
        assert!(d.header.is_ok());
        let d = parse_doc("[1, 2]", "x", &caps, 10).ok().unwrap();
        assert_eq!(d.header.err().unwrap(), "'list' object has no attribute 'get'");
        let msg = |r: Result<Parsed, Fault>| match r {
            Err(Fault::Abort(m)) => format!("abort: {m}"),
            Err(Fault::Refuse(m)) => format!("refuse: {m}"),
            Ok(_) => "ok".into(),
        };
        assert!(msg(parse_doc("{", "x", &caps, 10)).starts_with("abort: invalid JSON"));
        assert_eq!(
            msg(parse_doc(r#"{"Vulnerability": [1, 2, 3]}"#, "x", &caps, 2)),
            "refuse: msrc: more than 2 vulnerabilities in total; refusing"
        );
        let small = Caps {
            vulnerability_bytes: 4,
            tree_bytes: 4,
            ..caps
        };
        assert_eq!(
            msg(parse_doc(r#"{"Vulnerability": ["12345"]}"#, "x", &small, 10)),
            "abort: msrc: a vulnerability is larger than 4 bytes; refusing"
        );
        assert_eq!(
            msg(parse_doc(r#"{"ProductTree": [1, 2]}"#, "f.json", &small, 10)),
            "abort: msrc: f.json: ProductTree larger than 4 bytes; refusing"
        );
    }

    #[test]
    fn urls_keep_to_the_api_origin() {
        assert!(feed::same_origin("https://API.msrc.microsoft.com/cvrf/x", BASE_URL));
        assert!(!feed::same_origin("https://api.msrc.microsoft.com.evil/x", BASE_URL));
        assert!(!feed::same_origin("http://api.msrc.microsoft.com/x", BASE_URL));
        let u = updates(br#"{"value": [{"ID": "2024-Feb", "CurrentReleaseDate": "2024-02-13"},
                                       {"Alias": "2024-Jan", "CurrentReleaseDate": "2024-01-09", "CvrfUrl": "u"}]}"#)
            .unwrap();
        assert_eq!(u[0], ("2024-Jan".into(), Some("u".into()), "2024-01-09".into()));
        assert_eq!(u[1].0, "2024-Feb");
        assert_eq!(updates(b"[]").unwrap_err(), "AttributeError: 'list' object has no attribute 'get'");
        assert!(updates(br#"{"value": null}"#).unwrap().is_empty());
    }
}
