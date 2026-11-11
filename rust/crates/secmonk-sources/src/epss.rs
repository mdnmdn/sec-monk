//! FIRST EPSS scores, native (rust ADR-0011). Port of `src/secmonk/sources/epss.py` plus the `source_sync`
//! bookkeeping of `ops.sync_source` / `db.set_sync_state`; reference: `py-sources` (differential test
//! `secmonk-engine/tests/real_modules.rs`). Doc: `rust/_docs/tech/source-epss.md`.
//!
//! Bulk mode (the default): the daily CSV (gzip download, or `--path` to a `.csv.gz` or plain `.csv`) is decompressed
//! with a cap on the output, split into lines of at most [`MAX_LINE`] bytes and parsed as Python does (`#` lines carry
//! `score_date`, the header and malformed lines are skipped). The parsed rows are kept in a compact list (about 60
//! bytes per row) so the snapshot guard can refuse the file before anything is emitted; the `epss` upserts are then
//! built batch by batch while the engine reads the stream. API mode (`options.ids`): the FIRST API in batches of 100
//! ids, as the Python source.
//!
//! No deletes: the Python source only runs `INSERT OR REPLACE`, so a CVE that leaves the feed keeps its last score,
//! and the EUVD-provided rows (`source = 'euvd'`) of CVEs the feed lacks stay. A FIRST row replaces a EUVD row of the
//! same CVE (the store's rule for `epss`, whose key has no `source`), never the reverse.

use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use secmonk_model::{JsonMap, MirrorTable, RowOp};
use secmonk_traits::{
    CallCtx, MirrorView, ProgressUpdate, ResultStream, RowsBatch, Source, SourceInfo, StepResult,
    SyncEnd, SyncParams,
};
use serde_json::{Value, json};

use crate::batch::Limits;
use crate::native::{self, Outcome};
use crate::{feed, py};

/// Source name.
pub const NAME: &str = "epss";
/// Registration (`crate::IMPORTERS`): rust by default since 2026-11-11 (differential test green).
pub const IMPORTER: crate::Importer = crate::Importer {
    name: NAME,
    default_rust: true,
    new: |view| Arc::new(EpssSource::new(view)),
};
/// Description (as the Python source's).
pub const DESCRIPTION: &str =
    "FIRST EPSS exploitation probability scores (daily bulk or API lookup)";
/// The daily bulk file.
pub const BULK_URL: &str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
/// The FIRST API (`options.ids`).
pub const API_URL: &str = "https://api.first.org/data/v1/epss";
/// Ids per API request (as the Python source).
pub const API_BATCH: usize = 100;
/// Decompressed bytes accepted (the Python source's `MAX_DECOMPRESSED`, here for plain files too).
pub const MAX_DECOMPRESSED: u64 = 1024 * 1024 * 1024;
/// Longest CSV line accepted (the Python source's `MAX_LINE`).
pub const MAX_LINE: usize = 64 * 1024;
/// Rows accepted from one file (the 2026 feed has about 300 000 rows). A parsed row takes 48 bytes plus its CVE id
/// on the heap; with [`MAX_CVE_BYTES`] the parsed list stays under about 250 MiB at worst (96 MiB of rows, up to half
/// of that again while the list grows, 64 MiB of ids, about 32 MiB of allocator rounding), whatever the file holds:
/// comment and date lines keep nothing.
pub const MAX_ROWS: usize = 2_000_000;
/// Bytes of CVE ids kept from one file (the 2026 feed has about 4 MiB): bounds rows with long id fields (a line may
/// be 64 KiB).
pub const MAX_CVE_BYTES: usize = 64 * 1024 * 1024;
/// Compressed bytes accepted from the bulk download (the 2026 file is a few MiB).
pub const MAX_DOWNLOAD: u64 = 128 * 1024 * 1024;
/// Bytes accepted from one API answer.
pub const MAX_API_BYTES: u64 = 16 * 1024 * 1024;
/// Connect and read timeout of the bulk download (httpx `timeout=120.0` of the Python source).
pub const BULK_TIMEOUT: Duration = Duration::from_secs(120);

/// The native EPSS source.
pub struct EpssSource {
    view: Arc<dyn MirrorView>,
    bulk_url: String,
    api_url: String,
    limits: Limits,
    caps: Caps,
}

impl std::fmt::Debug for EpssSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EpssSource")
            .field("bulk_url", &self.bulk_url)
            .field("api_url", &self.api_url)
            .field("limits", &self.limits)
            .field("caps", &self.caps)
            .finish_non_exhaustive()
    }
}

/// Size caps of one bulk file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Decompressed (or plain) bytes.
    pub decompressed: u64,
    /// Rows kept.
    pub rows: usize,
    /// Bytes of CVE ids kept.
    pub cve_bytes: usize,
    /// Compressed bytes of a download.
    pub download: u64,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            decompressed: MAX_DECOMPRESSED,
            rows: MAX_ROWS,
            cve_bytes: MAX_CVE_BYTES,
            download: MAX_DOWNLOAD,
        }
    }
}

impl EpssSource {
    /// The source over a read-only view of the mirror.
    pub fn new(view: Arc<dyn MirrorView>) -> EpssSource {
        EpssSource {
            view,
            bulk_url: BULK_URL.into(),
            api_url: API_URL.into(),
            limits: Limits::default(),
            caps: Caps::default(),
        }
    }

    /// Other URLs (tests: a local server; `http://` is then allowed).
    pub fn with_urls(mut self, bulk: &str, api: &str) -> EpssSource {
        self.bulk_url = bulk.into();
        self.api_url = api.into();
        self
    }

    /// Other batch limits (tests: several batches out of a small fixture).
    pub fn with_limits(mut self, limits: Limits) -> EpssSource {
        self.limits = limits;
        self
    }

    /// Other size caps (tests).
    pub fn with_caps(mut self, caps: Caps) -> EpssSource {
        self.caps = caps;
        self
    }

    fn allow_http(url: &str) -> bool {
        !url.starts_with("https://")
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
        let ids: Vec<String> = opts
            .ids
            .iter()
            .flatten()
            .map(|i| py::strip(i))
            .filter(|i| !i.is_empty())
            .map(str::to_uppercase)
            .collect();
        // API mode when `ids` was given at all (`if opts.ids:`), even if every id is blank
        let outcome = if opts.ids.as_ref().is_none_or(Vec::is_empty) {
            let path = opts.path.clone().flatten().filter(|p| !p.is_empty());
            self.bulk(path, limit, opts.full.unwrap_or(false)).await?
        } else {
            self.api(ids, limit, ctx).await
        };
        let first = native::first_seq(self.view.as_ref(), NAME).await?;
        Ok(native::stream(NAME, outcome, first, self.limits, t0))
    }

    /// `_bulk` of the Python source: parse the whole file, apply the guard, then the upserts (built lazily).
    async fn bulk(
        &self,
        path: Option<String>,
        limit: Option<u64>,
        full: bool,
    ) -> StepResult<Outcome> {
        let caps = self.caps;
        let parsed = match path {
            Some(p) => {
                let p = PathBuf::from(p);
                let shown = feed::py_path(&p);
                let gz = shown.ends_with(".gz");
                let job = move || -> Result<Parsed, String> {
                    let f = feed::open_regular(&p).map_err(|e| e.with_class())?;
                    parse(f, gz, limit, caps)
                };
                run_blocking(job)
                    .await
                    .map(|rows| (rows, format!("file {shown}")))
            }
            None => {
                let url = self.bulk_url.clone();
                match feed::download(&url, caps.download, Self::allow_http(&url), BULK_TIMEOUT)
                    .await
                {
                    Ok(body) => run_blocking(move || parse(body.as_slice(), true, limit, caps))
                        .await
                        .map(|rows| (rows, url)),
                    Err(e) => Err(e),
                }
            }
        };
        let (parsed, origin) = match parsed {
            Ok(x) => x,
            Err(message) => return Ok(Outcome::error(message)),
        };
        let count = parsed.rows.len() as u64;
        if limit.is_none() {
            // a plausible daily file holds about all CVEs: an empty or tiny one is a broken download
            if count == 0 {
                return Ok(Outcome::error(
                    "ValueError: EPSS file has no rows; refusing".into(),
                ));
            }
            let existing = self.view.count_rows(MirrorTable::Epss, NAME).await?;
            if !full && existing > 0 && count * 2 < existing {
                return Ok(Outcome::error(format!(
                    "ValueError: EPSS file has only {count} rows (stored: {existing}, < 50%); refusing (use --full to force)"
                )));
            }
        }
        let cursor = if limit.is_some() {
            None
        } else {
            parsed
                .rows
                .last()
                .and_then(|r| Parsed::date(r).map(str::to_owned))
        };
        Ok(Outcome {
            status: if limit.is_some() { "partial" } else { "ok" }.into(),
            records: count,
            total: None,
            cursor,
            message: Some(format!("{count} scores from {origin}")),
            ops: native::iter_ops(parsed.into_ops()),
        })
    }

    /// `_sync_api` of the Python source: the FIRST API for `ids`, in batches of [`API_BATCH`]. All answers are read
    /// before anything is emitted (the Python source rolls back on any error).
    async fn api(&self, mut ids: Vec<String>, limit: Option<u64>, ctx: &CallCtx) -> Outcome {
        if let Some(n) = limit {
            ids.truncate(usize::try_from(n).unwrap_or(usize::MAX));
        }
        let http = Self::allow_http(&self.api_url);
        let mut rows: Vec<JsonMap> = Vec::new();
        let mut cursor: Option<String> = None;
        for chunk in ids.chunks(API_BATCH) {
            let url = format!("{}?cve={}", self.api_url, query_value(&chunk.join(",")));
            let doc = match feed::download(&url, MAX_API_BYTES, http, feed::TIMEOUT).await {
                Ok(body) => match feed::parse(&body) {
                    Ok(doc) => doc,
                    Err(e) => return Outcome::error(e),
                },
                Err(e) => return Outcome::error(e),
            };
            let got = match api_rows(&doc) {
                Ok(r) => r,
                Err(e) => return Outcome::error(e),
            };
            if let Some(last) = got.last() {
                cursor = last.get("date").and_then(Value::as_str).map(str::to_owned);
            }
            rows.extend(got);
            ctx.report(ProgressUpdate {
                message: Some(format!("epss: {} scores from API", rows.len())),
                ..Default::default()
            });
        }
        let count = rows.len() as u64;
        Outcome {
            status: if limit.is_some() { "partial" } else { "ok" }.into(),
            records: count,
            total: None,
            cursor: if limit.is_some() { None } else { cursor },
            message: Some(format!("{count} scores from FIRST API ({} ids)", ids.len())),
            ops: native::iter_ops(rows.into_iter().map(|row| RowOp::Upsert {
                table: MirrorTable::Epss,
                row,
            })),
        }
    }
}

/// Run a parse on the blocking pool (decompression and parsing of a large file must not hold a runtime thread).
async fn run_blocking<T: Send + 'static>(
    job: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(job)
        .await
        .map_err(|e| format!("epss: native importer: parse task failed: {e}"))?
}

/// One parsed score. `date` is the `score_date` in force for the row, kept inline (always ten ASCII bytes), so date
/// lines allocate nothing however many there are.
struct Score {
    cve: Box<str>,
    score: f64,
    percentile: f64,
    date: Option<[u8; 10]>,
}

/// The rows of one file, in file order (duplicates kept: the later one is stored, as with `INSERT OR REPLACE`).
struct Parsed {
    rows: Vec<Score>,
}

/// A stored date as text (ASCII by construction).
fn date_text(d: &[u8; 10]) -> &str {
    std::str::from_utf8(d).unwrap_or_default()
}

impl Parsed {
    fn date(s: &Score) -> Option<&str> {
        s.date.as_ref().map(date_text)
    }

    /// The `epss` upserts, built as they are consumed.
    fn into_ops(self) -> impl Iterator<Item = RowOp> + Send {
        self.rows.into_iter().map(move |s| {
            let date = Parsed::date(&s).map_or(Value::Null, |d| Value::String(d.to_owned()));
            let mut row = JsonMap::with_capacity(5);
            row.insert("cve_id".into(), Value::String(s.cve.into()));
            row.insert("score".into(), json!(s.score));
            row.insert("percentile".into(), json!(s.percentile));
            row.insert("date".into(), date);
            row.insert("source".into(), json!(NAME));
            RowOp::Upsert {
                table: MirrorTable::Epss,
                row,
            }
        })
    }
}

/// A reader that fails once more than `cap` bytes came out of `inner` (the decompression-bomb cap).
struct Capped<R> {
    inner: R,
    left: u64,
}

/// The marker error of [`Capped`].
#[derive(Debug)]
struct OverCap;

impl std::fmt::Display for OverCap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("over the size cap")
    }
}

impl std::error::Error for OverCap {}

impl<R: Read> Read for Capped<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n as u64 > self.left {
            return Err(std::io::Error::other(OverCap));
        }
        self.left -= n as u64;
        Ok(n)
    }
}

/// Why a line could not be read.
enum LineError {
    Io(std::io::Error),
    TooLong,
}

/// The next line (without `\n`) into `line`; `false` at the end. A line longer than `max` bytes is an error before it
/// is buffered whole.
fn next_line<B: BufRead>(r: &mut B, line: &mut Vec<u8>, max: usize) -> Result<bool, LineError> {
    line.clear();
    loop {
        let buf = match r.fill_buf() {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(LineError::Io(e)),
        };
        if buf.is_empty() {
            return Ok(!line.is_empty());
        }
        match buf.iter().position(|&b| b == b'\n') {
            Some(i) => {
                if line.len() + i > max {
                    return Err(LineError::TooLong);
                }
                line.extend_from_slice(&buf[..i]);
                r.consume(i + 1);
                return Ok(true);
            }
            None => {
                let n = buf.len();
                if line.len() + n > max {
                    return Err(LineError::TooLong);
                }
                line.extend_from_slice(buf);
                r.consume(n);
            }
        }
    }
}

/// `_iter_lines` + `_parse_rows` of the Python source over `input` (gzip when `gz`), stopping after `limit` rows.
/// Errors are worded as `f"{type(e).__name__}: {e}"` of the Python source where it is cheap.
fn parse<R: Read>(input: R, gz: bool, limit: Option<u64>, caps: Caps) -> Result<Parsed, String> {
    let inner: Box<dyn Read> = if gz {
        Box::new(flate2::read::GzDecoder::new(input))
    } else {
        Box::new(input)
    };
    let mut reader = BufReader::with_capacity(
        1 << 16,
        Capped {
            inner,
            left: caps.decompressed,
        },
    );
    let io_error = |e: std::io::Error| -> String {
        if e.get_ref().is_some_and(|i| i.is::<OverCap>()) {
            if gz {
                format!(
                    "DecompressError: decompressed data exceeds the {} byte limit",
                    caps.decompressed
                )
            } else {
                format!(
                    "ValueError: EPSS file exceeds the {} byte limit",
                    caps.decompressed
                )
            }
        } else if gz && e.kind() == std::io::ErrorKind::UnexpectedEof {
            "DecompressError: truncated gz data (no end-of-stream marker)".into()
        } else if gz {
            format!("DecompressError: corrupt gz data: {e}")
        } else {
            format!("{}: {e}", feed::py_exception(&e))
        }
    };
    let limit = limit.map_or(usize::MAX, |n| usize::try_from(n).unwrap_or(usize::MAX));
    let mut out = Parsed { rows: Vec::new() };
    let mut date: Option<[u8; 10]> = None;
    let mut cve_bytes = 0usize;
    let mut line = Vec::with_capacity(256);
    while out.rows.len() < limit {
        match next_line(&mut reader, &mut line, MAX_LINE) {
            Ok(true) => {}
            Ok(false) => break,
            Err(LineError::TooLong) => {
                return Err(format!(
                    "ValueError: EPSS line longer than {MAX_LINE} bytes"
                ));
            }
            Err(LineError::Io(e)) => return Err(io_error(e)),
        }
        let text = std::str::from_utf8(&line).map_err(|e| {
            let at = e.valid_up_to();
            format!(
                "UnicodeDecodeError: 'utf-8' codec can't decode byte 0x{:02x} in position {at}",
                line[at]
            )
        })?;
        match parse_line(text) {
            Line::Skip => {}
            Line::Date(d) => {
                date = d.as_bytes().try_into().ok();
            }
            Line::Row(cve, score, percentile) => {
                if out.rows.len() >= caps.rows {
                    return Err(format!(
                        "ValueError: EPSS file has more than {} rows; refusing",
                        caps.rows
                    ));
                }
                cve_bytes += cve.len();
                if cve_bytes > caps.cve_bytes {
                    return Err(format!(
                        "ValueError: EPSS file has more than {} bytes of CVE ids; refusing",
                        caps.cve_bytes
                    ));
                }
                out.rows.push(Score {
                    cve: cve.into_boxed_str(),
                    score,
                    percentile,
                    date,
                });
            }
        }
    }
    Ok(out)
}

/// What one line holds.
enum Line<'a> {
    Skip,
    Date(&'a str),
    Row(String, f64, f64),
}

/// `_parse_rows` of the Python source for one line: blank lines skipped, `#` lines may carry
/// `score_date:YYYY-MM-DD`, the `cve,` header skipped, then `cve,epss,percentile[,...]` with both numbers parsed by
/// Python's `float` rules; anything else is skipped.
fn parse_line(raw: &str) -> Line<'_> {
    let line = py::strip(raw);
    if line.is_empty() {
        return Line::Skip;
    }
    if line.starts_with('#') {
        return score_date(line).map_or(Line::Skip, Line::Date);
    }
    if line.len() >= 4 && line.as_bytes()[..4].eq_ignore_ascii_case(b"cve,") {
        return Line::Skip;
    }
    let mut parts = line.split(',');
    let (Some(cve), Some(score), Some(pct)) = (parts.next(), parts.next(), parts.next()) else {
        return Line::Skip;
    };
    match (finite_float(score), finite_float(pct)) {
        (Some(s), Some(p)) => Line::Row(py::strip(cve).to_uppercase(), s, p),
        _ => Line::Skip,
    }
}

/// The first `score_date:(\d{4}-\d{2}-\d{2})` match (ASCII digits).
fn score_date(line: &str) -> Option<&str> {
    const KEY: &str = "score_date:";
    line.match_indices(KEY).find_map(|(i, _)| {
        let rest = line.get(i + KEY.len()..i + KEY.len() + 10)?;
        let b = rest.as_bytes();
        let ok = b.iter().enumerate().all(|(j, c)| match j {
            4 | 7 => *c == b'-',
            _ => c.is_ascii_digit(),
        });
        ok.then_some(rest)
    })
}

/// [`py::float_str`] (Python's `float(str)`) without infinities: SQLite would keep them, but they have no JSON form,
/// so `py-sources` cannot carry them either (see source-epss.md). `nan` is kept (SQLite stores a NaN as NULL, and so
/// does the row: `json!(NaN)` is null). An epss rule, not a copy of `py`.
fn finite_float(s: &str) -> Option<f64> {
    py::float_str(s).filter(|v| !v.is_infinite())
}

/// A query value as `httpx` encodes `params` (everything but the unreserved characters percent-encoded).
fn query_value(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The `epss` rows of one API answer: `data[]` of `{cve, epss, percentile, date}`, the numbers as strings (or
/// numbers), `cve` as given (the Python source does not upper-case it).
fn api_rows(doc: &Value) -> Result<Vec<JsonMap>, String> {
    let Some(obj) = doc.as_object() else {
        return Err("epss: API answer is not an object".into());
    };
    let data = match obj.get("data") {
        None => return Ok(Vec::new()),
        Some(Value::Array(a)) => a,
        Some(_) => return Err("epss: API answer: 'data' is not a list".into()),
    };
    let mut out = Vec::with_capacity(data.len());
    for d in data {
        let Some(d) = d.as_object() else {
            return Err("epss: API answer: an entry is not an object".into());
        };
        let cve = match d.get("cve") {
            None => return Err("KeyError: 'cve'".into()),
            Some(Value::String(s)) => s.clone(),
            Some(_) => return Err("epss: API answer: cve is not a string".into()),
        };
        let number = |k: &str| -> Result<f64, String> {
            let v = match d.get(k) {
                None => return Err(format!("KeyError: '{k}'")),
                Some(Value::String(s)) => finite_float(s).ok_or_else(|| {
                    format!(
                        "ValueError: could not convert string to float: {}",
                        feed::py_repr(s)
                    )
                })?,
                Some(Value::Number(n)) => n.as_f64().unwrap_or(f64::NAN),
                Some(_) => return Err(format!("epss: {cve}: {k} is not a number")),
            };
            if v.is_infinite() {
                Err(format!("epss: {cve}: {k} is infinite"))
            } else {
                Ok(v)
            }
        };
        let (score, percentile) = (number("epss")?, number("percentile")?);
        let date = match d.get("date") {
            None | Some(Value::Null) => Value::Null,
            Some(Value::String(s)) => Value::String(s.clone()),
            Some(_) => return Err(format!("epss: {cve}: date is not a string")),
        };
        let mut row = JsonMap::with_capacity(5);
        row.insert("cve_id".into(), Value::String(cve));
        row.insert("score".into(), json!(score));
        row.insert("percentile".into(), json!(percentile));
        row.insert("date".into(), date);
        row.insert("source".into(), json!(NAME));
        out.push(row);
    }
    Ok(out)
}

#[async_trait]
impl Source for EpssSource {
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

    fn gz(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn parse_all(input: &[u8], gz: bool, caps: Caps) -> Result<Parsed, String> {
        parse(input, gz, None, caps)
    }

    #[test]
    fn gzip_input_is_capped_and_truncation_or_corruption_is_an_error() {
        let csv = b"#score_date:2026-11-06\ncve,epss,percentile\nCVE-1,0.1,0.2\n".repeat(2000);
        let z = gz(&csv);
        let caps = Caps::default();
        let p = parse_all(&z, true, caps).unwrap();
        assert_eq!(p.rows.len(), 2000);
        assert_eq!(Parsed::date(&p.rows[1999]), Some("2026-11-06"));
        let truncated = "DecompressError: truncated gz data (no end-of-stream marker)";
        for (what, input) in [
            ("empty", Vec::new()),
            ("half header", z[..5].to_vec()),
            ("mid stream", z[..z.len() / 2].to_vec()),
            ("no trailer", z[..z.len() - 8].to_vec()),
        ] {
            assert_eq!(
                parse_all(&input, true, caps).err().as_deref(),
                Some(truncated),
                "{what}"
            );
        }
        let e = parse_all(b"not gzip at all", true, caps).err().unwrap();
        assert!(e.starts_with("DecompressError: corrupt gz data: "), "{e}");
        let mut bad_crc = z.clone();
        let n = bad_crc.len();
        bad_crc[n - 8] ^= 0xff;
        let e = parse_all(&bad_crc, true, caps).err().unwrap();
        assert!(e.starts_with("DecompressError: corrupt gz data: "), "{e}");
        // trailing bytes after the member are ignored (Python stops at the end of the first member)
        assert_eq!(
            parse_all(&[z.clone(), b"junk".to_vec()].concat(), true, caps)
                .unwrap()
                .rows
                .len(),
            2000
        );
        // decompression bomb: the cap holds on the output, not on the compressed size
        let bomb = gz(&b"#\n".repeat(2 << 20));
        assert!(bomb.len() < 64 << 10);
        let small = Caps {
            decompressed: 1 << 20,
            ..caps
        };
        assert_eq!(
            parse_all(&bomb, true, small).err().as_deref(),
            Some("DecompressError: decompressed data exceeds the 1048576 byte limit")
        );
        assert_eq!(
            parse_all(
                &csv,
                false,
                Caps {
                    decompressed: 1000,
                    ..caps
                }
            )
            .err()
            .as_deref(),
            Some("ValueError: EPSS file exceeds the 1000 byte limit")
        );
        // the row cap and the line cap
        assert_eq!(
            parse_all(&csv, false, Caps { rows: 10, ..caps })
                .err()
                .as_deref(),
            Some("ValueError: EPSS file has more than 10 rows; refusing")
        );
        let long = [b"CVE-1,0.1,0.2\n".to_vec(), vec![b'x'; MAX_LINE + 1]].concat();
        assert_eq!(
            parse_all(&long, false, caps).err().as_deref(),
            Some("ValueError: EPSS line longer than 65536 bytes")
        );
        let exact = [vec![b'#'; MAX_LINE], b"\nCVE-1,0.1,0.2".to_vec()].concat();
        assert_eq!(
            parse_all(&exact, false, caps).unwrap().rows.len(),
            1,
            "a line of exactly MAX_LINE bytes"
        );
        let e = parse_all(b"CVE-1,0.1,0.2\nCVE-\xff,0.1,0.2\n", false, caps)
            .err()
            .unwrap();
        assert_eq!(
            e,
            "UnicodeDecodeError: 'utf-8' codec can't decode byte 0xff in position 4"
        );
        // the limit stops reading: a truncated stream after the first rows is not seen (as Python's islice)
        let p = parse(&z[..z.len() / 2], true, Some(3), caps).unwrap();
        assert_eq!(p.rows.len(), 3);
    }

    #[test]
    fn date_lines_keep_nothing_and_cve_bytes_are_capped() {
        // review W8.3 M1: a file of date lines costs no memory per line; a row takes 48 bytes plus its id
        assert_eq!(std::mem::size_of::<Score>(), 48);
        let mut text = Vec::new();
        for i in 0..200_000u32 {
            text.extend_from_slice(format!("#score_date:2026-{:02}-01\n", 1 + i % 12).as_bytes());
        }
        text.extend_from_slice(b"CVE-1,0.1,0.2\n#score_date:2026-12-31\nCVE-2,0.3,0.4\n");
        let p = parse_all(&gz(&text), true, Caps::default()).unwrap();
        assert_eq!(p.rows.len(), 2);
        assert_eq!(
            Parsed::date(&p.rows[0]),
            Some("2026-08-01"),
            "the last date before the row"
        );
        assert_eq!(Parsed::date(&p.rows[1]), Some("2026-12-31"));
        let long = format!("{},0.1,0.2\n", "C".repeat(60_000)).repeat(3);
        let caps = Caps {
            cve_bytes: 150_000,
            ..Caps::default()
        };
        assert_eq!(
            parse_all(long.as_bytes(), false, caps).err().as_deref(),
            Some("ValueError: EPSS file has more than 150000 bytes of CVE ids; refusing")
        );
        assert_eq!(
            parse_all(&long.as_bytes()[..120_020], false, caps)
                .unwrap()
                .rows
                .len(),
            2
        );
    }

    #[test]
    fn lines_parse_like_python() {
        assert!(matches!(
            parse_line("#model_version:v2023.03.01,score_date:2026-11-06T00:00:00+0000"),
            Line::Date("2026-11-06")
        ));
        assert!(matches!(parse_line("#score_date:2026-1-06"), Line::Skip));
        assert!(matches!(
            parse_line("# score_date:x score_date:2026-01-02"),
            Line::Date("2026-01-02")
        ));
        for skip in [
            "",
            "   ",
            "cve,epss,percentile",
            "CVE,EPSS",
            "CVE-1,0.5",
            "CVE-1,x,0.5",
            "CVE-1,0.5,1__0",
        ] {
            assert!(matches!(parse_line(skip), Line::Skip), "{skip:?}");
        }
        let Line::Row(c, s, p) = parse_line("  cve-2024-0001 , 1_0e-1 ,+.5,extra\r") else {
            panic!("a row")
        };
        assert_eq!((c.as_str(), s, p), ("CVE-2024-0001", 1.0, 0.5));
        assert!(
            matches!(parse_line("CVE-1,NaN,0.5"), Line::Row(_, s, _) if s.is_nan()),
            "NaN: a row with a null score, as SQLite stores it"
        );
        assert!(
            matches!(parse_line("CVE-1,-inf,0.5"), Line::Skip),
            "infinite"
        );
        assert!(
            matches!(parse_line("CVE-1,0.5,Infinity"), Line::Skip),
            "infinite"
        );
        assert_eq!(finite_float("\t0.00043\u{a0}"), Some(0.00043));
        assert_eq!(finite_float("_1"), None);
        // Unicode decimal digits, as Python: float('０.５') == 0.5, float('٣') == 3.0, float('𝟗') == 9.0
        assert_eq!(finite_float("０.５"), Some(0.5));
        assert_eq!(finite_float("\u{663}"), Some(3.0));
        assert_eq!(finite_float("\u{1D7D7}"), Some(9.0));
        assert_eq!(finite_float("1\u{FF10}_\u{FF10}"), Some(100.0));
        assert_eq!(finite_float("½"), None, "No, not Nd");
        assert_eq!(finite_float("\u{2160}"), None, "Nl, not Nd");
        assert_eq!(query_value("CVE-1,CVE 2"), "CVE-1%2CCVE%202");
    }
}
