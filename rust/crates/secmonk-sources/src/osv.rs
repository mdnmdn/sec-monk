//! OSV.dev bulk, native (rust ADR-0011, ADR-0012). Port of `src/secmonk/sources/osv.py` plus the `source_sync`
//! bookkeeping of `ops.sync_source` / `db.set_sync_state`; reference: `py-sources` (differential test
//! `secmonk-engine/tests/native_osv.rs`). Doc: `rust/_docs/tech/source-osv.md`.
//!
//! Inputs, as in Python: `--path` (a directory of `*.json` files, a `.zip` archive or one JSON file), else one bucket
//! pass per ecosystem (`ecosystems`, default [`DEFAULT_ECOSYSTEMS`]): a delta from the ecosystem's cursor row
//! `osv:<Eco>` (`<Eco>/modified_id.csv`, then `<Eco>/<ID>.json` per changed id; at most 5000 ids) or a full import of
//! `<Eco>/all.zip`. Python commits every record on its own (a failing record is rolled back and skipped), so the native
//! importer plans every record on its own too: a record Python would skip is skipped (logged), nothing is checked
//! across records.
//!
//! Records are read and planned on the blocking pool (zip members and files) and passed to the operation stream
//! through a bounded channel: per record a `raw_record` upsert (only with `SECMONK_OSV_STORE_RAW`), a `vulnerability`
//! upsert, and its `alias` and `affected` rows replaced against the stored ones (read through
//! `MirrorView::rows_by_id` in groups; nothing when they are equal). A record id already emitted in this run (the same
//! advisory in two ecosystems) replaces what was emitted instead of reading it back. The status, records, total and
//! messages are known only at the end, so the run's end goes through `native::stream_deferred`.
//!
//! Archives are untrusted: `all.zip` is downloaded into an anonymous temporary file (never extracted), read through
//! its central directory with caps on the entry count, the declared uncompressed total, each member's size and
//! compression ratio; members with unsafe names, overlapping data or duplicate names are refused.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::StreamExt;
use secmonk_model::{JsonMap, MirrorTable, RowOp};
use secmonk_traits::{
    CallCtx, MirrorView, ResultStream, RowsBatch, Source, SourceInfo, StepResult, SyncEnd,
    SyncParams,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;

use crate::batch::Limits;
use crate::native::{self, Ops, Progress, Tail, TailCell};
use crate::rows::{self, DeleteKey};
use crate::{feed, py};

/// Source name.
pub const NAME: &str = "osv";
/// Registration (`crate::IMPORTERS`): rust by default since 2026-11-12 (differential test green; faster than
/// `py-sources` at every step of the volume measurement, rust/_docs/tech/source-osv.md).
pub const IMPORTER: crate::Importer = crate::Importer {
    name: NAME,
    default_rust: true,
    importer_version: "rust/1",
    new: |view| Arc::new(OsvSource::new(view)),
};
/// Description (as the Python source's).
pub const DESCRIPTION: &str = "OSV.dev bulk (package ecosystems + distro advisories)";
/// The public bucket.
pub const BUCKET: &str = "https://osv-vulnerabilities.storage.googleapis.com";
/// `DEFAULT_ECOSYSTEMS` of the Python source.
pub const DEFAULT_ECOSYSTEMS: [&str; 15] = [
    "PyPI",
    "npm",
    "Maven",
    "Go",
    "crates.io",
    "RubyGems",
    "NuGet",
    "Packagist",
    "Pub",
    "SwiftURL",
    "Debian",
    "Alpine",
    "Red Hat",
    "Rocky Linux",
    "AlmaLinux",
];
/// More changed ids than this since the cursor: a full import instead of a delta (`DELTA_MAX_IDS`).
pub const DELTA_MAX_IDS: usize = 5000;
/// The environment switch of raw storage (`SECMONK_OSV_STORE_RAW`, as the Python source reads it).
pub const STORE_RAW_ENV: &str = "SECMONK_OSV_STORE_RAW";
/// Progress line every this many records (`LOG_EVERY`).
const LOG_EVERY: u64 = 5000;
/// HTTP timeout per operation (`http_client(timeout=120.0)`).
const TIMEOUT: Duration = Duration::from_secs(120);
/// Records per group whose stored rows are read together (one `rows_by_id` per table).
const GROUP: usize = 25;
/// Record bytes per group (a group closes once it is reached).
const GROUP_BYTES: usize = 4 * 1024 * 1024;
/// New `affected` rows per group (a group closes once it is reached).
const GROUP_NEW: usize = 20_000;
/// Planned records in flight between the reader and the operation stream.
const CHANNEL: usize = 2;

/// Input caps (the Python source caps only the download and each zip member). Worst-case memory within them:
/// rust/_docs/tech/source-osv.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Bytes of one downloaded `all.zip` (`MAX_ZIP_BYTES`, 4 GiB).
    pub download_bytes: u64,
    /// Bytes of one `modified_id.csv`.
    pub csv_bytes: u64,
    /// Bytes of one record: a zip member, a JSON file, a delta answer (`MAX_MEMBER_SIZE`, 50 MiB).
    pub member_bytes: u64,
    /// Entries of one zip archive.
    pub zip_entries: usize,
    /// Declared uncompressed bytes of the `.json` members of one archive.
    pub zip_total: u64,
    /// Largest compression ratio of one member (uncompressed / compressed) ...
    pub zip_ratio: u64,
    /// ... above this uncompressed size.
    pub ratio_floor: u64,
    /// Distinct record ids written in one run.
    pub records: usize,
    /// `affected` rows of one record (new ones; stored ones above it refuse the run).
    pub affected: usize,
    /// `*.json` files of one `--path` directory.
    pub files: usize,
    /// Directory entries visited in one `--path` directory.
    pub entries: usize,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            download_bytes: 4 * 1024 * 1024 * 1024,
            csv_bytes: 256 * 1024 * 1024,
            member_bytes: 50 * 1024 * 1024,
            zip_entries: 2_000_000,
            zip_total: 64 * 1024 * 1024 * 1024,
            zip_ratio: 200,
            ratio_floor: 1024 * 1024,
            records: 2_000_000,
            affected: 10_000,
            files: 1_000_000,
            entries: 2_000_000,
        }
    }
}

/// The native OSV source.
pub struct OsvSource {
    view: Arc<dyn MirrorView>,
    bucket: String,
    limits: Limits,
    caps: Caps,
    store_raw: Option<bool>,
}

impl fmt::Debug for OsvSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OsvSource")
            .field("bucket", &self.bucket)
            .field("limits", &self.limits)
            .field("caps", &self.caps)
            .field("store_raw", &self.store_raw)
            .finish_non_exhaustive()
    }
}

impl OsvSource {
    /// The source over a read-only view of the mirror.
    pub fn new(view: Arc<dyn MirrorView>) -> OsvSource {
        OsvSource {
            view,
            bucket: BUCKET.into(),
            limits: Limits::default(),
            caps: Caps::default(),
            store_raw: None,
        }
    }

    /// Another bucket URL (tests: a local server; `http://` is then allowed).
    pub fn with_bucket(mut self, url: &str) -> OsvSource {
        self.bucket = url.trim_end_matches('/').into();
        self
    }

    /// Other batch limits (tests: several batches out of a small fixture).
    pub fn with_limits(mut self, limits: Limits) -> OsvSource {
        self.limits = limits;
        self
    }

    /// Other input caps.
    pub fn with_caps(mut self, caps: Caps) -> OsvSource {
        self.caps = caps;
        self
    }

    /// Raw storage on or off, whatever `SECMONK_OSV_STORE_RAW` says (default: the variable, read at each sync).
    pub fn with_store_raw(mut self, on: bool) -> OsvSource {
        self.store_raw = Some(on);
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
        let store_raw = self.store_raw.unwrap_or_else(store_raw_from_env);
        let path = opts.path.clone().flatten().filter(|p| !p.is_empty());
        let tail: TailCell = Arc::new(Mutex::new(None));
        let total0 = self
            .view
            .count_rows(MirrorTable::Vulnerability, NAME)
            .await?;
        let mut run = Run {
            view: self.view.clone(),
            caps: self.caps,
            bucket: self.bucket.clone(),
            plan: PlanOpts {
                store_raw,
                now: secmonk_model::time::now_iso(),
                affected: self.caps.affected,
            },
            limit,
            full: opts.full.unwrap_or(false),
            say: Progress::new(ctx),
            tail: tail.clone(),
            emitted: HashMap::new(),
            total0,
            new_ids: 0,
            mode: Mode::Done,
            feed: None,
            client: None,
            done: false,
        };
        if let Some(p) = path {
            run.mode = Mode::Path {
                path: PathBuf::from(&p),
                shown: feed::py_path(Path::new(&p)),
                started: false,
            };
        } else {
            let names: Vec<String> = opts
                .ecosystems
                .clone()
                .filter(|e| !e.is_empty())
                .unwrap_or_else(|| DEFAULT_ECOSYSTEMS.iter().map(|s| (*s).to_owned()).collect());
            match validate_ecosystems(&names) {
                Ok(()) => {
                    run.mode = Mode::Ecos(Box::new(Ecos {
                        n: names.len(),
                        todo: names.into(),
                        errors: Vec::new(),
                        ok: 0,
                        partial: false,
                        records: 0,
                        states: HashMap::new(),
                    }))
                }
                Err(m) => run.set_tail(Tail {
                    status: "error".into(),
                    message: Some(m),
                    ..Tail::default()
                }),
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
}

/// `_store_raw_enabled`: `SECMONK_OSV_STORE_RAW` stripped and lower-cased is `1`, `true` or `yes`.
fn store_raw_from_env() -> bool {
    std::env::var(STORE_RAW_ENV)
        .is_ok_and(|v| matches!(py::strip(&v).to_lowercase().as_str(), "1" | "true" | "yes"))
}

/// `validate_ecosystems`: a release-qualified name (`Debian:12`) is refused with Python's `ValueError` text.
fn validate_ecosystems(names: &[String]) -> Result<(), String> {
    for n in names {
        if n.contains(':') {
            let base = n.split(':').next().unwrap_or("");
            return Err(format!(
                "OSV ecosystem {} is release-qualified; use the base name ({}). Per-release zips are stale legacy \
                 dumps; the base-name zip contains all releases.",
                py::repr_str(n),
                py::repr_str(base)
            ));
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ Python rules

/// The characters for which Python's `str.isdigit()` is true but `str.isdecimal()` is not (Numeric_Type=Digit:
/// superscripts, circled digits, ...), from Python 3.13's tables.
const OTHER_DIGITS: [(u32, u32); 20] = [
    (0xB2, 0xB3),
    (0xB9, 0xB9),
    (0x1369, 0x1371),
    (0x19DA, 0x19DA),
    (0x2070, 0x2070),
    (0x2074, 0x2079),
    (0x2080, 0x2089),
    (0x2460, 0x2468),
    (0x2474, 0x247C),
    (0x2488, 0x2490),
    (0x24EA, 0x24EA),
    (0x24F5, 0x24FD),
    (0x24FF, 0x24FF),
    (0x2776, 0x277E),
    (0x2780, 0x2788),
    (0x278A, 0x2792),
    (0x10A40, 0x10A43),
    (0x10E60, 0x10E68),
    (0x11052, 0x1105A),
    (0x1F100, 0x1F10A),
];

/// Python's `str.isdigit()` for one character.
fn is_digit(c: char) -> bool {
    let u = u32::from(c);
    py::is_decimal(c) || OTHER_DIGITS.iter().any(|(a, b)| (*a..=*b).contains(&u))
}

/// `purl.normalize_ecosystem` of a non-empty string.
pub fn normalize_ecosystem(e: &str) -> String {
    if e.is_empty() {
        return String::new();
    }
    let parts: Vec<&str> = e.split(':').collect();
    let base = parts[0];
    fn rel<'a>(ps: &[&'a str]) -> Option<&'a str> {
        ps.iter()
            .find(|p| p.chars().next().is_some_and(is_digit))
            .copied()
    }
    if base == "Ubuntu" {
        return rel(&parts[1..]).map_or_else(|| "Ubuntu".into(), |r| format!("Ubuntu:{r}"));
    }
    if base == "Red Hat" && parts.len() > 1 {
        let product = parts[1];
        if product == "enterprise_linux"
            || product.starts_with("rhel_")
            || product.chars().next().is_some_and(is_digit)
        {
            return rel(&parts[1..]).map_or_else(
                || "Red Hat".into(),
                |r| format!("Red Hat:{}", r.split('.').next().unwrap_or("")),
            );
        }
        return e.into();
    }
    if (base == "Rocky Linux" || base == "AlmaLinux") && parts.len() > 1 {
        return format!("{base}:{}", parts[1].split('.').next().unwrap_or(""));
    }
    e.into()
}

/// `_ubuntu_variant`: `Ubuntu:Pro:FIPS-updates:22.04:LTS` -> `Pro:FIPS-updates` (`None` for plain releases).
pub fn ubuntu_variant(raw: Option<&Value>) -> Option<String> {
    let s = raw?.as_str()?.strip_prefix("Ubuntu:")?;
    let parts: Vec<&str> = s
        .split(':')
        .filter(|p| !p.is_empty() && !p.chars().next().is_some_and(is_digit) && *p != "LTS")
        .collect();
    (!parts.is_empty()).then(|| parts.join(":"))
}

/// `purl.normalize_name` (`ecosystem` already normalized; `""` for a falsy one).
pub fn normalize_name(ecosystem: &str, name: &str) -> String {
    let base = ecosystem.split(':').next().unwrap_or("");
    let n = py::strip(name);
    match base {
        "PyPI" => {
            let mut out = String::with_capacity(n.len());
            let mut run = false;
            for c in n.chars() {
                if matches!(c, '-' | '_' | '.') {
                    if !run {
                        out.push('-');
                    }
                    run = true;
                } else {
                    out.push(c);
                    run = false;
                }
            }
            out.to_lowercase()
        }
        "Go" | "Maven" => n.to_owned(),
        _ => n.to_lowercase(),
    }
}

/// A JSON value bound to a TEXT column by Python's `sqlite3` and read back: a string as is, `null` as NULL, an
/// integer or a bool as its decimal text (TEXT affinity; `True` is 1). `Err`: a list or an object (Python fails when
/// it binds them, so the record is skipped), an integer beyond 64 bits (`OverflowError`), and a float (SQLite's own
/// REAL-to-TEXT conversion is not ported: the record is skipped, a documented difference).
fn bind_text(v: Option<&Value>, what: &str) -> Result<Option<String>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(Value::Bool(b)) => Ok(Some(if *b { "1" } else { "0" }.into())),
        Some(Value::Number(n)) => match n.as_i64() {
            Some(i) => Ok(Some(i.to_string())),
            None if n.is_f64() => Err(format!("{what} is a float")),
            None => Err(format!(
                "{what}: Python int too large to convert to SQLite INTEGER"
            )),
        },
        Some(other) => Err(format!(
            "{what}: type '{}' is not supported",
            py::type_name(other)
        )),
    }
}

/// The character run `\.\d{6}\d+` of `parse_ts`'s `re.sub` cut to `.` and six digits (Unicode decimal digits, as
/// `re`'s `\d`).
fn cut_fraction(s: &str) -> Cow<'_, str> {
    if !s.contains('.') {
        return Cow::Borrowed(s);
    }
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '.' {
            let run = chars[i + 1..]
                .iter()
                .take_while(|c| py::is_decimal(**c))
                .count();
            if run >= 7 {
                out.push('.');
                out.extend(&chars[i + 1..i + 7]);
                i += 1 + run;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    Cow::Owned(out)
}

/// `parse_ts`: an RFC 3339 timestamp (0-9 fractional digits, `Z`, naive = UTC) as microseconds since the epoch, or
/// the `ValueError` text (`datetime.fromisoformat`, as nvd ports it).
pub fn parse_ts(s: &str) -> Result<i64, String> {
    let s = py::strip(s);
    let z = match s.strip_suffix('Z') {
        Some(x) => Cow::Owned(format!("{x}+00:00")),
        None => Cow::Borrowed(s),
    };
    crate::nvd::fromisoformat(&cut_fraction(&z))
}

/// `str.splitlines()`: the line boundaries of Python (`\n`, `\r`, `\r\n`, `\v`, `\f`, `\x1c`-`\x1e`, `\x85`,
/// ` `, ` `), no empty last line.
fn splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        let is_break = matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if is_break {
            out.push(&s[start..i]);
            let mut next = i + c.len_utf8();
            if c == '\r' && it.peek().is_some_and(|(_, n)| *n == '\n') {
                it.next();
                next += 1;
            }
            start = next;
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// The changed ids of a `modified_id.csv` (`ids_modified_since`): `(microseconds, timestamp, id)` of every
/// `<ts>,<ID>` line newer than `cursor`, at most `keep` of them kept, and how many there are.
fn ids_modified_since(text: &str, cursor: i64, keep: usize) -> (Vec<(i64, String, String)>, usize) {
    let mut out = Vec::new();
    let mut n = 0usize;
    for line in splitlines(text) {
        let line = py::strip(line);
        let Some((ts, rid)) = line.split_once(',') else {
            continue;
        };
        let Ok(t) = parse_ts(ts) else {
            continue;
        };
        if t > cursor {
            n += 1;
            if out.len() < keep {
                out.push((t, ts.to_owned(), py::strip(rid).to_owned()));
            }
        }
    }
    (out, n)
}

/// `urllib.parse.quote(s)` (safe `/`): UTF-8, everything but `A-Za-z0-9_.-~/` as `%XX`.
pub fn quote(s: &str) -> String {
    quote_safe(s, b"/")
}

fn quote_safe(s: &str, safe: &[u8]) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"_.-~".contains(&b) || safe.contains(&b) {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

// ------------------------------------------------------------------------------------------------ CVSS 3.x

fn w_av(v: &str) -> Option<f64> {
    Some(match v {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    })
}

fn w_ac(v: &str) -> Option<f64> {
    Some(match v {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    })
}

fn w_ui(v: &str) -> Option<f64> {
    Some(match v {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    })
}

fn w_cia(v: &str) -> Option<f64> {
    Some(match v {
        "H" => 0.56,
        "L" => 0.22,
        "N" => 0.0,
        _ => return None,
    })
}

/// `_roundup` of the CVSS 3.1 specification, as the Python source computes it.
fn roundup(x: f64) -> f64 {
    let i = (x * 100_000.0).round_ties_even();
    if i % 10_000.0 == 0.0 {
        i / 100_000.0
    } else {
        ((i / 10_000.0).floor() + 1.0) / 10.0
    }
}

/// `cvss3_score`: the CVSS 3.0 / 3.1 base score of a vector, `None` when it is not a valid v3 vector.
pub fn cvss3_score(vector: &str) -> Option<f64> {
    let parts: Vec<&str> = vector.split('/').collect();
    if parts[0] != "CVSS:3.0" && parts[0] != "CVSS:3.1" {
        return None;
    }
    let mut m: HashMap<&str, &str> = HashMap::new();
    for p in &parts[1..] {
        let (k, v) = p.split_once(':')?;
        m.insert(k, v);
    }
    let scope_changed = *m.get("S")? == "C";
    let pr = match *m.get("PR")? {
        "N" => 0.85,
        "L" if scope_changed => 0.68,
        "L" => 0.62,
        "H" if scope_changed => 0.5,
        "H" => 0.27,
        _ => return None,
    };
    let (c, i, a) = (
        w_cia(m.get("C")?)?,
        w_cia(m.get("I")?)?,
        w_cia(m.get("A")?)?,
    );
    let iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    let impact = if scope_changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
    } else {
        6.42 * iss
    };
    let expl = 8.22 * w_av(m.get("AV")?)? * w_ac(m.get("AC")?)? * pr * w_ui(m.get("UI")?)?;
    if impact <= 0.0 {
        return Some(0.0);
    }
    let total = if scope_changed {
        1.08 * (impact + expl)
    } else {
        impact + expl
    };
    Some(roundup(total.min(10.0)))
}

/// The conservative score of a CVSS v4-only record from its label (`DERIVED_SCORE`).
fn derived_score(label: &str) -> Option<f64> {
    Some(match label {
        "LOW" => 3.0,
        "MEDIUM" => 5.5,
        "HIGH" => 8.0,
        "CRITICAL" => 9.5,
        _ => return None,
    })
}

/// `_cvss`: (score, vector, version, label word, v4 vector when a v3 vector was chosen).
type Cvss = (
    Option<f64>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn cvss(severity: Option<&Value>) -> Result<Cvss, String> {
    let (mut v3, mut v4, mut word): (Option<String>, Option<String>, Option<String>) =
        (None, None, None);
    for s in py::iter_items(severity)? {
        let Value::Object(s) = s.as_ref() else {
            return Err(py::no_attr(py::type_name(&s), "get"));
        };
        let Some(Value::String(sc)) = s.get("score") else {
            continue;
        };
        let t = s.get("type").and_then(Value::as_str);
        if t == Some("CVSS_V3") && v3.is_none() {
            v3 = Some(sc.clone());
        } else if t == Some("CVSS_V4") && v4.is_none() {
            v4 = Some(sc.clone());
        } else if t == Some("Ubuntu") && word.is_none() {
            word = Some(sc.clone());
        }
    }
    if let Some(v) = v3.filter(|v| !v.is_empty()) {
        let version = v
            .split('/')
            .next()
            .unwrap_or("")
            .rsplit(':')
            .next()
            .unwrap_or("")
            .to_owned();
        return Ok((cvss3_score(&v), Some(v), Some(version), word, v4));
    }
    if let Some(v) = v4.filter(|v| !v.is_empty()) {
        return Ok((None, Some(v), Some("4.0".into()), word, None));
    }
    Ok((None, None, None, word, None))
}

// ------------------------------------------------------------------------------------------------ purl

/// `_strip_purl` of a string: the purl rebuilt from its type, namespace and name by `packageurl-python` 0.17
/// (`PackageURL.from_string`, then `PackageURL(type, namespace, name).to_string()`), or, when that parse raises,
/// the text before the first `?` and `#`.
pub fn strip_purl(p: &str) -> String {
    match purl::parse(p) {
        Some((t, ns, n)) => purl::rebuild(&t, ns.as_deref(), &n),
        None => {
            let a = p.split('?').next().unwrap_or("");
            a.split('#').next().unwrap_or("").to_owned()
        }
    }
}

/// A port of the parts of `packageurl-python` 0.17.6 and `urllib.parse` (Python 3.13) that `_strip_purl` reaches.
mod purl {
    use super::py;

    /// The quoting step of `normalize` (`get_quoter`).
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Coder {
        /// `quote` (percent-encode, `:` kept).
        Quote,
        /// `unquote`.
        Unquote,
        /// None.
        Keep,
    }

    /// The `qualifiers` argument `normalize_name` sees (for `mlflow` names).
    enum Quals<'a> {
        Str(&'a str),
        Map(&'a [(String, String)]),
        None,
    }

    fn code(c: Coder, s: &str) -> String {
        match c {
            Coder::Quote => super::quote(s).replace("%3A", ":"),
            Coder::Unquote => unquote(s),
            Coder::Keep => s.to_owned(),
        }
    }

    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    /// `urllib.parse.unquote`: `%XX` escapes decoded per run of ASCII characters as UTF-8 with replacement
    /// characters; other characters kept.
    pub(super) fn unquote(s: &str) -> String {
        if !s.contains('%') {
            return s.to_owned();
        }
        let mut out = String::with_capacity(s.len());
        let mut rest = s;
        while !rest.is_empty() {
            let ascii = rest.find(|c: char| !c.is_ascii()).unwrap_or(rest.len());
            let (run, tail) = rest.split_at(ascii);
            let b = run.as_bytes();
            let mut bytes = Vec::with_capacity(b.len());
            let mut i = 0;
            while i < b.len() {
                if b[i] == b'%'
                    && let (Some(h), Some(l)) = (
                        b.get(i + 1).copied().and_then(hex),
                        b.get(i + 2).copied().and_then(hex),
                    )
                {
                    bytes.push(h * 16 + l);
                    i += 3;
                    continue;
                }
                bytes.push(b[i]);
                i += 1;
            }
            out.push_str(&String::from_utf8_lossy(&bytes));
            let non = tail.find(|c: char| c.is_ascii()).unwrap_or(tail.len());
            out.push_str(&tail[..non]);
            rest = &tail[non..];
        }
        out
    }

    const LOWER_NAMESPACE: [&str; 10] = [
        "bitbucket",
        "github",
        "pypi",
        "gitlab",
        "composer",
        "luarocks",
        "qpkg",
        "alpm",
        "apk",
        "hex",
    ];
    const LOWER_NAME: [&str; 13] = [
        "bitbucket",
        "github",
        "pypi",
        "gitlab",
        "composer",
        "luarocks",
        "oci",
        "npm",
        "alpm",
        "apk",
        "bitnami",
        "hex",
        "pub",
    ];

    fn normalize_type(t: &str, c: Coder) -> Option<String> {
        if t.is_empty() {
            return None;
        }
        let s = py::strip(&code(c, t)).to_lowercase();
        (!s.is_empty()).then_some(s)
    }

    fn normalize_namespace(ns: Option<&str>, ptype: Option<&str>, c: Coder) -> Option<String> {
        let ns = ns.filter(|s| !s.is_empty())?;
        let mut s = py::strip(ns).trim_matches('/').to_owned();
        if ptype.is_some_and(|t| LOWER_NAMESPACE.contains(&t)) {
            s = s.to_lowercase();
        }
        // `ptype in ("cpan")` is a substring test
        if ptype.is_some_and(|t| !t.is_empty() && "cpan".contains(t)) {
            s = s.to_uppercase();
        }
        let segs: Vec<String> = s
            .split('/')
            .filter(|g| !py::strip(g).is_empty())
            .map(|g| code(c, g))
            .collect();
        let out = segs.join("/");
        (!out.is_empty()).then_some(out)
    }

    fn mlflow(name: String, q: &Quals<'_>) -> String {
        match q {
            Quals::Map(m) => {
                let repo = m
                    .iter()
                    .find(|(k, _)| k == "repository_url")
                    .map(|(_, v)| v.as_str())
                    .filter(|v| !v.is_empty());
                match repo {
                    Some(r) if r.to_lowercase().contains("azureml") => name,
                    Some(r) if r.to_lowercase().contains("databricks") => name.to_lowercase(),
                    _ => name,
                }
            }
            Quals::Str(s) => {
                let l = s.to_lowercase();
                if l.contains("azureml") {
                    name
                } else if l.contains("databricks") {
                    name.to_lowercase()
                } else {
                    name
                }
            }
            Quals::None => name,
        }
    }

    /// `normalize_name`; `Some("")` is possible for `mlflow` (no `or None` there).
    fn normalize_name(
        name: Option<&str>,
        q: &Quals<'_>,
        ptype: Option<&str>,
        c: Coder,
    ) -> Option<String> {
        let name = name.filter(|s| !s.is_empty())?;
        let mut s = py::strip(&code(c, name)).trim_matches('/').to_owned();
        // `ptype in ("mlflow")` is a substring test
        if ptype.is_some_and(|t| !t.is_empty() && "mlflow".contains(t)) {
            return Some(mlflow(s, q));
        }
        if ptype.is_some_and(|t| LOWER_NAME.contains(&t)) {
            s = s.to_lowercase();
        }
        match ptype {
            Some("pypi") => s = s.replace('_', "-").to_lowercase(),
            Some("hackage") => s = s.replace('_', "-"),
            Some("pub") => {
                s = s
                    .to_lowercase()
                    .chars()
                    .map(|ch| {
                        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
                            ch
                        } else {
                            '_'
                        }
                    })
                    .collect();
            }
            _ => {}
        }
        (!s.is_empty()).then_some(s)
    }

    /// `normalize_qualifiers(<str>, encode=False)`: the sorted map, or `Err` where it raises `ValueError`.
    fn qualifiers(q: &str) -> Result<Vec<(String, String)>, ()> {
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let items: Vec<&str> = q.split('&').collect();
        if items.iter().any(|kv| !kv.contains('=')) {
            return Err(());
        }
        let mut map: Vec<(String, String)> = Vec::new();
        for kv in items {
            let (k, v) = kv.split_once('=').unwrap_or((kv, ""));
            if k.is_empty() || py::strip(k).is_empty() || v.is_empty() || py::strip(v).is_empty() {
                continue;
            }
            let key = py::strip(k).to_lowercase();
            let val = unquote(v);
            match map.iter_mut().find(|(mk, _)| *mk == key) {
                Some(e) => e.1 = val,
                None => map.push((key, val)),
            }
        }
        for (key, _) in &map {
            let bad = key.contains('%')
                || key.contains(' ')
                || key
                    .chars()
                    .any(|c| !(c.is_ascii_alphanumeric() || ".-_".contains(c)))
                || key.chars().next().is_some_and(|c| c.is_ascii_digit());
            if bad {
                return Err(());
            }
        }
        map.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(map)
    }

    const C0_OR_SPACE: fn(char) -> bool = |c| c <= ' ';

    /// `_check_bracketed_netloc` (the IPv6 form checked with Rust's parser: zone ids are refused, where Python's
    /// `ipaddress` accepts them).
    fn bracketed_netloc_ok(netloc: &str) -> bool {
        let hp = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
        let host = match hp.split_once('[') {
            Some((before, bracketed)) => {
                if !before.is_empty() {
                    return false;
                }
                let (host, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
                if !port.is_empty() && !port.starts_with(':') {
                    return false;
                }
                host
            }
            None => hp.split_once(':').map_or(hp, |(h, _)| h),
        };
        if let Some(rest) = host.strip_prefix('v') {
            // \Av[a-fA-F0-9]+\..+\Z (re.ASCII)
            let Some((hexpart, tail)) = rest.split_once('.') else {
                return false;
            };
            !hexpart.is_empty()
                && hexpart.bytes().all(|b| b.is_ascii_hexdigit())
                && !tail.is_empty()
                && !tail.contains('\n')
        } else {
            host.parse::<std::net::Ipv6Addr>().is_ok()
        }
    }

    /// `urllib.parse.urlsplit(url, scheme="", allow_fragments=True)`: `(scheme, netloc, path, query, fragment)`,
    /// `Err` where it raises `ValueError`. The NFKC check of a non-ASCII netloc is not ported.
    #[allow(clippy::type_complexity)]
    fn urlsplit(url: &str) -> Result<(String, String, String, String, String), ()> {
        let url: String = url
            .trim_start_matches(C0_OR_SPACE)
            .chars()
            .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
            .collect();
        let mut rest = url.as_str();
        let mut scheme = String::new();
        if let Some(i) = rest.find(':')
            && i > 0
            && rest.as_bytes()[0].is_ascii_alphabetic()
            && rest[..i]
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
        {
            scheme = rest[..i].to_ascii_lowercase();
            rest = &rest[i + 1..];
        }
        let mut netloc = "";
        if rest.starts_with("//") {
            let after = &rest[2..];
            let end = after.find(['/', '?', '#']).unwrap_or(after.len());
            netloc = &after[..end];
            rest = &after[end..];
            let (open, close) = (netloc.contains('['), netloc.contains(']'));
            if open != close {
                return Err(());
            }
            if open && close && !bracketed_netloc_ok(netloc) {
                return Err(());
            }
        }
        let (rest, fragment) = rest.split_once('#').unwrap_or((rest, ""));
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        Ok((
            scheme,
            netloc.to_owned(),
            path.to_owned(),
            query.to_owned(),
            fragment.to_owned(),
        ))
    }

    /// `PackageURL.from_string(p)` (normalized): `(type, namespace, name)`, `None` where it raises.
    pub(super) fn parse(purl: &str) -> Option<(String, Option<String>, String)> {
        if purl.is_empty() || py::strip(purl).is_empty() {
            return None;
        }
        let (scheme, rest) = purl.split_once(':')?;
        if scheme != "pkg" {
            return None;
        }
        let rem = py::strip(rest).trim_start_matches('/');
        let (type_, remainder) = rem.split_once('/')?;
        if type_.is_empty()
            || !type_
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c))
            || type_.as_bytes()[0].is_ascii_digit()
        {
            return None;
        }
        let type_ = type_.to_ascii_lowercase();
        let (scheme, authority, mut path, quals, _subpath) = urlsplit(remainder).ok()?;
        if !authority.is_empty() {
            path = format!("{authority}:{path}");
        }
        if !scheme.is_empty() {
            let original = remainder.split(':').next().unwrap_or("");
            path = format!("{original}:{path}");
        }
        let mut path = path.trim_start_matches('/').to_owned();
        let mut namespace = String::new();
        if type_ == "npm" && path.starts_with('@') {
            let (ns, p) = match path.split_once('/') {
                Some((a, b)) => (a.to_owned(), b.to_owned()),
                None => (path.clone(), String::new()),
            };
            namespace = ns;
            path = p;
        }
        let remainder = match path.rfind('@') {
            Some(i) => &path[..i],
            None => path.as_str(),
        };
        let ns_name = py::strip(remainder).trim_matches('/');
        let parts: Vec<&str> = ns_name
            .split('/')
            .filter(|s| !s.is_empty() && !py::strip(s).is_empty())
            .collect();
        let mut name = "";
        if namespace.is_empty() && parts.len() > 1 {
            name = parts[parts.len() - 1];
            namespace = parts[..parts.len() - 1].join("/");
        } else if parts.len() == 1 {
            name = parts[0];
        }
        if name.is_empty() {
            return None;
        }
        // pass 1: normalize(..., encode=False)
        let t1 = normalize_type(&type_, Coder::Unquote);
        let ns1 = normalize_namespace(Some(&namespace), t1.as_deref(), Coder::Unquote);
        let n1 = normalize_name(
            Some(name),
            &Quals::Str(&quals),
            t1.as_deref(),
            Coder::Unquote,
        );
        let q1 = qualifiers(&quals).ok()?;
        // PackageURL.__new__: type and name required, then normalize(..., encode=None)
        let (t1, n1) = (t1?, n1.filter(|n| !n.is_empty())?);
        let t2 = normalize_type(&t1, Coder::Keep)?;
        let ns2 = normalize_namespace(ns1.as_deref(), Some(&t2), Coder::Keep);
        let n2 = normalize_name(Some(&n1), &Quals::Map(&q1), Some(&t2), Coder::Keep)?;
        Some((t2, ns2, n2))
    }

    /// `PackageURL(type=t, namespace=ns, name=n).to_string()` (`purl.build` without version and qualifiers).
    pub(super) fn rebuild(t: &str, ns: Option<&str>, n: &str) -> String {
        // PackageURL.__new__: normalize(..., encode=None)
        let t3 = normalize_type(t, Coder::Keep);
        let ns3 = normalize_namespace(ns, t3.as_deref(), Coder::Keep);
        let n3 = normalize_name(Some(n), &Quals::None, t3.as_deref(), Coder::Keep);
        // to_string: normalize(..., encode=True); qualifiers are `{}`
        let t4 = t3.as_deref().and_then(|t| normalize_type(t, Coder::Quote));
        let ns4 = normalize_namespace(ns3.as_deref(), t4.as_deref(), Coder::Quote);
        let n4 = normalize_name(n3.as_deref(), &Quals::Map(&[]), t4.as_deref(), Coder::Quote);
        let mut out = format!("pkg:{}/", t4.unwrap_or_default());
        if let Some(ns) = ns4 {
            out.push_str(&ns);
            out.push('/');
        }
        out.push_str(&n4.unwrap_or_default());
        out
    }
}

// ------------------------------------------------------------------------------------------------ one record

/// What every record plan needs.
#[derive(Debug, Clone)]
struct PlanOpts {
    store_raw: bool,
    now: String,
    affected: usize,
}

/// The rows of one record (`import_record`).
#[derive(Debug)]
struct Plan {
    id: String,
    /// Bytes of the record's text (for grouping).
    bytes: usize,
    raw: Option<RowOp>,
    vulnerability: RowOp,
    aliases: Vec<(String, String)>,
    affected: Vec<JsonMap>,
}

/// `import_record` of one value.
#[derive(Debug)]
enum Planned {
    /// Not an object, or no truthy `id`: `return False` (not counted, not logged).
    Ignored,
    /// Python raises inside the record's savepoint: rolled back, logged, not counted.
    Skipped { id: String, reason: String },
    /// The rows, and `rec["modified"]` when it is a string.
    Rows(Box<Plan>, Option<String>),
}

fn obj(v: Option<&Value>) -> Option<&JsonMap> {
    match v {
        Some(Value::Object(m)) => Some(m),
        _ => None,
    }
}

fn truthy(v: Option<&Value>) -> bool {
    v.is_some_and(py::truthy)
}

/// `import_record` (without the database): the rows of one record, or why Python would skip it.
fn plan(rec: Value, bytes: usize, o: &PlanOpts) -> Planned {
    let Some(m) = obj(Some(&rec)) else {
        return Planned::Ignored;
    };
    let Some(idv) = m.get("id").filter(|v| py::truthy(v)) else {
        return Planned::Ignored;
    };
    let id = py::str_of(idv);
    let modified = match m.get("modified") {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    };
    match rows_of(m, &id, o) {
        Ok((vulnerability, aliases, affected, modified_text)) => {
            let raw = if o.store_raw {
                Some(rows::raw_record(
                    NAME,
                    &id,
                    modified_text.as_deref(),
                    &o.now,
                    rec,
                ))
            } else {
                None
            };
            Planned::Rows(
                Box::new(Plan {
                    id,
                    bytes,
                    raw,
                    vulnerability,
                    aliases,
                    affected,
                }),
                modified,
            )
        }
        Err(reason) => Planned::Skipped { id, reason },
    }
}

type RecordRows = (RowOp, Vec<(String, String)>, Vec<JsonMap>, Option<String>);

fn rows_of(m: &JsonMap, rid: &str, o: &PlanOpts) -> Result<RecordRows, String> {
    let empty = JsonMap::new();
    let dbs = obj(m.get("database_specific")).unwrap_or(&empty);
    let details = m.get("details");
    let summary_v = m.get("summary");
    let summary = if !truthy(summary_v) && truthy(details) {
        match details {
            Some(Value::String(d)) => {
                let first: String = py::strip(d)
                    .split('\n')
                    .next()
                    .unwrap_or("")
                    .chars()
                    .take(300)
                    .collect();
                (!first.is_empty()).then_some(first)
            }
            other => {
                return Err(py::no_attr(
                    py::type_name(other.unwrap_or(&Value::Null)),
                    "strip",
                ));
            }
        }
    } else {
        bind_text(summary_v, "summary")?
    };
    let (mut score, vector, cvss_version, word, v4_vector) = cvss(m.get("severity"))?;
    let label = dbs.get("severity").and_then(Value::as_str);
    let label = rows::normalize_severity(label)
        .or_else(|| rows::normalize_severity(word.as_deref()))
        .or_else(|| rows::severity_from_score(score).map(str::to_owned));
    let mut vuln_extra = JsonMap::new();
    if score.is_none()
        && vector.is_some()
        && let Some(d) = label.as_deref().and_then(derived_score)
    {
        score = Some(d);
        vuln_extra.insert("score_derived".into(), json!(true));
    }
    if let Some(v4) = v4_vector.filter(|v| !v.is_empty()) {
        vuln_extra.insert("cvss_v4_vector".into(), json!(v4));
    }
    let cwe_ids = dbs.get("cwe_ids");
    let mut cwes: Vec<String> = Vec::new();
    for c in py::iter_items(cwe_ids)? {
        if let Value::String(s) = c.as_ref() {
            cwes.push(s.clone());
        }
    }
    if let Some(Value::String(s)) = cwe_ids {
        cwes = vec![s.clone()];
    }
    let mut refs: Vec<Value> = Vec::new();
    for r in py::iter_items(m.get("references"))? {
        if let Value::Object(r) = r.as_ref()
            && truthy(r.get("url"))
            && let Some(u) = r.get("url")
        {
            refs.push(u.clone());
        }
    }
    refs.truncate(10);
    let src_db = dbs
        .get("source")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map_or_else(
            || rid.split('-').next().unwrap_or("").to_owned(),
            str::to_owned,
        );
    let mut extra = JsonMap::new();
    extra.insert("source_db".into(), json!(src_db));
    extra.insert("references".into(), Value::Array(refs));
    extra.extend(vuln_extra);
    let modified_text = bind_text(m.get("modified"), "modified")?;
    let vulnerability = rows::vulnerability(
        NAME,
        rid,
        rows::Vulnerability {
            summary,
            details: bind_text(details, "details")?,
            published: bind_text(m.get("published"), "published")?,
            modified: modified_text.clone(),
            withdrawn: bind_text(m.get("withdrawn"), "withdrawn")?,
            state: None,
            severity: label,
            cvss_score: score,
            cvss_vector: vector,
            cvss_version,
            cwes,
            extra: Value::Object(extra),
        },
    );
    // `upstream` ids are stored with kind 'upstream', not as aliases; `related` is ignored
    let mut adds: Vec<(String, &str)> = Vec::new();
    for (key, kind) in [("aliases", "alias"), ("upstream", "upstream")] {
        for a in py::iter_items(m.get(key))? {
            if let Value::String(s) = a.as_ref() {
                adds.push((s.clone(), kind));
            }
        }
    }
    let aliases = rows::alias_set(rid, adds.iter().map(|(a, k)| (a.as_str(), *k)));
    let mut affected = Vec::new();
    if !truthy(m.get("withdrawn")) {
        for aff in py::iter_items(m.get("affected"))? {
            affected_rows(aff.as_ref(), rid, o, &mut affected)?;
        }
    }
    Ok((vulnerability, aliases, affected, modified_text))
}

/// The ECOSYSTEM / SEMVER / GIT range types.
const RANGE_TYPES: [&str; 3] = ["ECOSYSTEM", "SEMVER", "GIT"];

/// The rows of one `affected[]` entry.
fn affected_rows(
    aff: &Value,
    rid: &str,
    o: &PlanOpts,
    out: &mut Vec<JsonMap>,
) -> Result<(), String> {
    let Some(aff) = obj(Some(aff)) else {
        return Ok(());
    };
    let Some(pkg) = obj(aff.get("package")) else {
        return Ok(());
    };
    if !truthy(pkg.get("name")) {
        return Ok(());
    }
    let raw_eco = pkg.get("ecosystem");
    // normalize_ecosystem: a falsy value is returned as it is (and bound later, when a row is added); a truthy
    // non-string raises
    let eco: Result<Option<String>, String> = match raw_eco {
        Some(Value::String(s)) => Ok(Some(normalize_ecosystem(s))),
        Some(v) if py::truthy(v) => {
            return Err(py::no_attr(py::type_name(v), "split"));
        }
        other => bind_text(other, "ecosystem"),
    };
    let eco_for_name = match raw_eco {
        Some(Value::String(s)) => normalize_ecosystem(s),
        _ => String::new(),
    };
    let name = match pkg.get("name") {
        Some(Value::String(s)) => normalize_name(&eco_for_name, s),
        Some(v) => return Err(py::no_attr(py::type_name(v), "strip")),
        None => return Ok(()),
    };
    let purl = match pkg.get("purl") {
        Some(Value::String(s)) if !s.is_empty() => Some(strip_purl(s)),
        Some(v) if py::truthy(v) => return Err(py::no_attr(py::type_name(v), "split")),
        _ => None,
    };
    let mut ranges: Vec<Cow<'_, JsonMap>> = Vec::new();
    for r in py::iter_items(aff.get("ranges"))? {
        if let Cow::Borrowed(Value::Object(r)) = r {
            ranges.push(Cow::Borrowed(r));
        }
    }
    let espec = obj(aff.get("ecosystem_specific"));
    let mut binaries: Vec<Value> = Vec::new();
    let mut custom: Vec<&JsonMap> = Vec::new();
    if let Some(espec) = espec {
        for b in py::iter_items(espec.get("binaries"))? {
            if let Cow::Borrowed(Value::Object(b)) = b
                && truthy(b.get("binary_name"))
                && let Some(n) = b.get("binary_name")
            {
                binaries.push(n.clone());
            }
        }
        for r in py::iter_items(espec.get("custom_ranges"))? {
            if let Cow::Borrowed(Value::Object(r)) = r
                && truthy(r.get("events"))
            {
                custom.push(r);
            }
        }
    }
    if !custom.is_empty() {
        // Go: the SEMVER range is an open-ended `introduced: 0` placeholder; the real bounds are the custom ranges
        let placeholder = json!([{"introduced": "0"}]);
        ranges.retain(|r| {
            let t = r.get("type").and_then(Value::as_str);
            !(matches!(t, Some("ECOSYSTEM" | "SEMVER")) && r.get("events") == Some(&placeholder))
        });
        for c in custom {
            let t = c
                .get("type")
                .and_then(Value::as_str)
                .filter(|t| RANGE_TYPES.contains(t))
                .unwrap_or("ECOSYSTEM");
            let mut r = c.clone();
            r.insert("type".into(), json!(t));
            r.insert("_custom".into(), json!(true));
            ranges.push(Cow::Owned(r));
        }
    }
    let variant = ubuntu_variant(raw_eco);
    let urgency = espec
        .and_then(|e| e.get("urgency"))
        .and_then(Value::as_str)
        .map(|u| py::strip(u).to_lowercase());
    let mut has_eco_range = false;
    let row = |range_type: &str, events: Option<Value>, versions: Vec<Value>, extra: JsonMap| {
        let ecosystem = eco.clone()?;
        let mut row = rows::affected(
            NAME,
            rid,
            rows::Affected {
                ecosystem,
                package: Some(name.clone()),
                purl: purl.clone(),
                range_type: Some(range_type.to_owned()),
                versions,
                extra: if extra.is_empty() {
                    Value::Null
                } else {
                    Value::Object(extra)
                },
                ..rows::Affected::default()
            },
        );
        if let Some(e) = events {
            row.insert("events".into(), e);
        }
        Ok::<JsonMap, String>(row)
    };
    for r in &ranges {
        let Some(rt) = r
            .get("type")
            .and_then(Value::as_str)
            .filter(|t| RANGE_TYPES.contains(t))
        else {
            continue;
        };
        let mut extra = JsonMap::new();
        if truthy(r.get("_custom")) {
            extra.insert("custom_range".into(), json!(true));
        }
        if let Some(v) = &variant {
            extra.insert("ecosystem_variant".into(), json!(v));
        }
        if rt != "GIT" {
            has_eco_range = true;
            extra.insert(
                "raw_ecosystem".into(),
                raw_eco.cloned().unwrap_or(Value::Null),
            );
        }
        if truthy(r.get("database_specific"))
            && let Some(d) = r.get("database_specific")
        {
            extra.insert("database_specific".into(), d.clone());
        }
        if !binaries.is_empty() {
            extra.insert("binaries".into(), Value::Array(binaries.clone()));
        }
        if let Some(u) = &urgency {
            extra.insert("urgency".into(), json!(u));
        }
        if rt == "GIT"
            && truthy(r.get("repo"))
            && let Some(repo) = r.get("repo")
        {
            extra.insert("repo".into(), repo.clone());
        }
        let events = match r.get("events") {
            Some(e) if py::truthy(e) => e.clone(),
            _ => json!([]),
        };
        // secmonk-mirror-rows/1: `events` is a list of objects (Python stores any truthy value)
        if !events
            .as_array()
            .is_some_and(|a| a.iter().all(Value::is_object))
        {
            return Err(
                "range events are not a list of objects (secmonk-mirror-rows/1); refusing".into(),
            );
        }
        out.push(row(rt, Some(events), Vec::new(), extra)?);
        if out.len() > o.affected {
            return Err(too_many(o.affected));
        }
    }
    let mut versions: Vec<Value> = Vec::new();
    for v in py::iter_items(aff.get("versions"))? {
        if let Value::String(_) = v.as_ref() {
            versions.push(v.into_owned());
        }
    }
    if !versions.is_empty() && !has_eco_range {
        let mut extra = JsonMap::new();
        extra.insert(
            "raw_ecosystem".into(),
            raw_eco.cloned().unwrap_or(Value::Null),
        );
        if let Some(v) = &variant {
            extra.insert("ecosystem_variant".into(), json!(v));
        }
        if !binaries.is_empty() {
            extra.insert("binaries".into(), Value::Array(binaries));
        }
        let mut r = row("VERSIONS", None, versions, extra)?;
        r.insert("events".into(), Value::Null);
        out.push(r);
        if out.len() > o.affected {
            return Err(too_many(o.affected));
        }
    }
    Ok(())
}

fn too_many(cap: usize) -> String {
    format!("more than {cap} affected rows; refusing")
}

// ------------------------------------------------------------------------------------------------ JSON input

/// `json.loads(<bytes>)`: the encoding detected as `json.detect_encoding` does (UTF-8 with or without a BOM,
/// UTF-16 and UTF-32 by BOM or by the position of the zero bytes), then parsed.
fn loads_bytes(b: &[u8]) -> Result<Value, String> {
    let text: Cow<'_, str> = if b.starts_with(&[0, 0, 0xFE, 0xFF]) {
        Cow::Owned(utf32(&b[4..], true)?)
    } else if b.starts_with(&[0xFF, 0xFE, 0, 0]) {
        Cow::Owned(utf32(&b[4..], false)?)
    } else if b.starts_with(&[0xFE, 0xFF]) {
        Cow::Owned(utf16(&b[2..], true)?)
    } else if b.starts_with(&[0xFF, 0xFE]) {
        Cow::Owned(utf16(&b[2..], false)?)
    } else if let Some(rest) = b.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        Cow::Borrowed(py::decode_utf8(rest)?)
    } else if b.len() >= 4 && b[0] == 0 {
        if b[1] != 0 {
            Cow::Owned(utf16(b, true)?)
        } else {
            Cow::Owned(utf32(b, true)?)
        }
    } else if b.len() >= 4 && b[1] == 0 {
        if b[2] != 0 || b[3] != 0 {
            Cow::Owned(utf16(b, false)?)
        } else {
            Cow::Owned(utf32(b, false)?)
        }
    } else if b.len() == 2 && b[0] == 0 {
        Cow::Owned(utf16(b, true)?)
    } else if b.len() == 2 && b[1] == 0 {
        Cow::Owned(utf16(b, false)?)
    } else {
        Cow::Borrowed(py::decode_utf8(b)?)
    };
    serde_json::from_str(&text).map_err(|e| format!("invalid JSON: {e}"))
}

fn utf16(b: &[u8], be: bool) -> Result<String, String> {
    if !b.len().is_multiple_of(2) {
        return Err("'utf-16' codec can't decode: truncated data".into());
    }
    let units = b.as_chunks::<2>().0.iter().map(|c| {
        if be {
            u16::from_be_bytes([c[0], c[1]])
        } else {
            u16::from_le_bytes([c[0], c[1]])
        }
    });
    char::decode_utf16(units)
        .collect::<Result<String, _>>()
        .map_err(|e| format!("'utf-16' codec: {e}"))
}

fn utf32(b: &[u8], be: bool) -> Result<String, String> {
    if !b.len().is_multiple_of(4) {
        return Err("'utf-32' codec can't decode: truncated data".into());
    }
    b.as_chunks::<4>()
        .0
        .iter()
        .map(|c| {
            let u = if be {
                u32::from_be_bytes([c[0], c[1], c[2], c[3]])
            } else {
                u32::from_le_bytes([c[0], c[1], c[2], c[3]])
            };
            char::from_u32(u).ok_or_else(|| format!("'utf-32' codec: invalid code point {u:#x}"))
        })
        .collect()
}

// ------------------------------------------------------------------------------------------------ the importer

/// Messages of a reader (blocking pool) to the operation stream.
#[derive(Debug)]
enum Msg {
    Plan(Box<Plan>),
    Log(String),
    End(ImportEnd),
    Fail(Fail),
}

/// An error that stops one import: Python's exception class (`None` for a native refusal) and its text.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Fail {
    class: Option<&'static str>,
    msg: String,
}

impl Fail {
    fn native(msg: String) -> Fail {
        Fail { class: None, msg }
    }

    /// The text of `ops.sync_source` (`<class>: <text>`) for an import from `--path`; native refusals read
    /// `osv: <text>`.
    fn for_path(&self) -> String {
        match self.class {
            Some(c) => format!("{c}: {}", self.msg),
            None => format!("{NAME}: {}", self.msg),
        }
    }
}

/// The end of one import (`_Importer` after its records).
#[derive(Debug, Clone, Default)]
struct ImportEnd {
    count: u64,
    max_modified: Option<String>,
    /// A delta: the cursor to store (`newest or cursor`) and the failed ids.
    delta: Option<(String, u64)>,
}

/// `_Importer`: counts the records imported, keeps the largest `modified`, stops at the limit.
#[derive(Debug)]
struct Importer {
    label: String,
    count: u64,
    max: Option<(i64, String)>,
    limit: Option<u64>,
    opts: PlanOpts,
}

impl Importer {
    fn new(label: &str, limit: Option<u64>, opts: PlanOpts) -> Importer {
        Importer {
            label: label.to_owned(),
            count: 0,
            max: None,
            limit,
            opts,
        }
    }

    /// `_Importer.full`.
    fn full(&self) -> bool {
        self.limit.is_some_and(|l| self.count >= l)
    }

    /// `_Importer.add`: the plan of one record (or nothing), with its log lines in `out`.
    fn add(&mut self, rec: Value, bytes: usize, out: &mut Vec<Msg>) {
        match plan(rec, bytes, &self.opts) {
            Planned::Ignored => {}
            Planned::Skipped { id, reason } => {
                out.push(Msg::Log(format!("{NAME}: skipping {id}: {reason}")));
            }
            Planned::Rows(p, modified) => {
                self.count += 1;
                if let Some(m) = modified
                    && let Ok(t) = parse_ts(&m)
                    && self.max.as_ref().is_none_or(|(best, _)| t > *best)
                {
                    self.max = Some((t, m));
                }
                out.push(Msg::Plan(p));
                if self.count.is_multiple_of(LOG_EVERY) {
                    out.push(Msg::Log(format!(
                        "{NAME} {}: {} records",
                        self.label, self.count
                    )));
                }
            }
        }
    }

    fn end(&self) -> ImportEnd {
        ImportEnd {
            count: self.count,
            max_modified: self.max.as_ref().map(|(_, s)| s.clone()),
            delta: None,
        }
    }
}

/// The sending half of a reader: `false` once the operation stream is gone (the reader stops).
struct Sink(mpsc::Sender<Msg>);

impl Sink {
    fn send(&self, m: Msg) -> bool {
        self.0.blocking_send(m).is_ok()
    }

    fn all(&self, ms: Vec<Msg>) -> bool {
        ms.into_iter().all(|m| self.send(m))
    }
}

/// Read records on the blocking pool with `read`, which returns the end of the import or what stopped it.
fn spawn_reader(
    read: impl FnOnce(&Sink) -> Result<ImportEnd, Fail> + Send + 'static,
) -> mpsc::Receiver<Msg> {
    let (tx, rx) = mpsc::channel(CHANNEL);
    tokio::task::spawn_blocking(move || {
        let sink = Sink(tx);
        let last = match read(&sink) {
            Ok(end) => Msg::End(end),
            Err(f) => Msg::Fail(f),
        };
        sink.send(last);
    });
    rx
}

// ------------------------------------------------------------------------------------------------ zip archives

/// What the central directory says about one entry.
#[derive(Debug)]
struct Entry {
    index: usize,
    raw: Box<[u8]>,
    size: u64,
    csize: u64,
    method: zip::CompressionMethod,
    flags: u16,
    external: u32,
    /// The data's byte range in the archive, or why the local header is refused.
    data: Result<(u64, u64), String>,
    header: u64,
    /// The next header (or the central directory): the data must end before it.
    end: u64,
}

impl Entry {
    /// The name for messages (UTF-8, invalid bytes replaced).
    fn name(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(&self.raw)
    }

    fn is_json(&self) -> bool {
        !self.raw.ends_with(b"/") && self.raw.ends_with(b".json")
    }

    /// `repr(ZipInfo)` (Python 3.13), as `ZipFile.open` puts it in its messages.
    fn repr(&self) -> String {
        let method = |m: u16| -> String {
            match m {
                1 => "shrink".into(),
                2..=5 => "reduce".into(),
                6 => "implode".into(),
                8 => "deflate".into(),
                9 => "deflate64".into(),
                10 => "implode".into(),
                12 => "bzip2".into(),
                14 => "lzma".into(),
                18 => "terse".into(),
                19 => "lz77".into(),
                97 => "wavpack".into(),
                98 => "ppmd".into(),
                other => other.to_string(),
            }
        };
        let code = self.method_code();
        let mut out = format!("<ZipInfo filename={}", py::repr_str(&self.name()));
        if code != 0 {
            out.push_str(&format!(" compress_type={}", method(code)));
        }
        let (hi, lo) = (self.external >> 16, self.external & 0xFFFF);
        if hi != 0 {
            out.push_str(&format!(" filemode={}", py::repr_str(&filemode(hi))));
        }
        if lo != 0 {
            out.push_str(&format!(" external_attr={lo:#x}"));
        }
        let is_dir = self.raw.ends_with(b"/");
        if !is_dir || self.size != 0 {
            out.push_str(&format!(" file_size={}", self.size));
        }
        if (!is_dir || self.csize != 0) && (code != 0 || self.size != self.csize) {
            out.push_str(&format!(" compress_size={}", self.csize));
        }
        out.push('>');
        out
    }

    /// The method number of the central directory.
    #[allow(deprecated)]
    fn method_code(&self) -> u16 {
        match self.method {
            zip::CompressionMethod::Stored => 0,
            zip::CompressionMethod::Deflated => 8,
            zip::CompressionMethod::Unsupported(n) => n,
            _ => u16::MAX,
        }
    }
}

/// `stat.filemode` (the C version of `_stat`: `?` for an unknown file type).
fn filemode(mode: u32) -> String {
    let kind = match mode & 0o170_000 {
        0o140_000 => 's',
        0o120_000 => 'l',
        0o100_000 => '-',
        0o060_000 => 'b',
        0o040_000 => 'd',
        0o020_000 => 'c',
        0o010_000 => 'p',
        _ => '?',
    };
    let mut out = String::from(kind);
    for (r, w, x, special, set, unset) in [
        (0o400, 0o200, 0o100, 0o4000, 's', 'S'),
        (0o040, 0o020, 0o010, 0o2000, 's', 'S'),
        (0o004, 0o002, 0o001, 0o1000, 't', 'T'),
    ] {
        out.push(if mode & r != 0 { 'r' } else { '-' });
        out.push(if mode & w != 0 { 'w' } else { '-' });
        out.push(match (mode & x != 0, mode & special != 0) {
            (true, true) => set,
            (false, true) => unset,
            (true, false) => 'x',
            (false, false) => '-',
        });
    }
    out
}

/// A name that could address something outside a flat archive: an absolute path, a drive, a `..` part, a
/// backslash or a NUL byte. Never extracted anyway; refused so that no such name reaches a log line or a row.
fn unsafe_name(raw: &[u8]) -> bool {
    raw.contains(&0)
        || raw.contains(&b'\\')
        || raw.first() == Some(&b'/')
        || (raw.len() >= 2 && raw[1] == b':' && raw[0].is_ascii_alphabetic())
        || raw.split(|b| *b == b'/').any(|seg| seg == b"..")
}

/// The local header of an entry at `at` (`ZipFile.open`'s checks): its signature, its name equal to the central
/// directory's `name`; the offset where the data starts.
fn local_header(f: &mut std::fs::File, at: u64, name: &[u8]) -> Result<u64, String> {
    let mut head = [0u8; 30];
    f.seek(std::io::SeekFrom::Start(at))
        .and_then(|_| f.read_exact(&mut head))
        .map_err(|_| "Truncated file header".to_owned())?;
    if head[..4] != *b"PK\x03\x04" {
        return Err("Bad magic number for file header".into());
    }
    let n = u64::from(u16::from_le_bytes([head[26], head[27]]));
    let x = u64::from(u16::from_le_bytes([head[28], head[29]]));
    let mut local = vec![0u8; usize::from(u16::from_le_bytes([head[26], head[27]]))];
    f.read_exact(&mut local)
        .map_err(|_| "Truncated file header".to_owned())?;
    if local != name {
        return Err(format!(
            "File name in directory {} and header {} differ.",
            py::repr_str(&String::from_utf8_lossy(name)),
            py::repr_str(&String::from_utf8_lossy(&local))
        ));
    }
    Ok(at + 30 + n + x)
}

/// `_iter_zip` + `_import_iter`: the `.json` members of an archive in central-directory order. `what` names the
/// archive in messages (`PyPI/all.zip`, or the `--path`).
fn read_zip(
    file: std::fs::File,
    what: &str,
    imp: &mut Importer,
    caps: &Caps,
    sink: &Sink,
) -> Result<ImportEnd, Fail> {
    let bad_zip = || Fail {
        class: Some("BadZipFile"),
        msg: "File is not a zip file".into(),
    };
    let mut probe = file
        .try_clone()
        .map_err(|e| Fail::native(format!("{what}: {e}")))?;
    let mut za = zip::ZipArchive::new(file).map_err(|_| bad_zip())?;
    if za.has_duplicate_names() {
        return Err(Fail::native(format!(
            "{what}: duplicate member names; refusing"
        )));
    }
    if za.len() > caps.zip_entries {
        return Err(Fail::native(format!(
            "{what}: more than {} zip entries; refusing",
            caps.zip_entries
        )));
    }
    let mut entries: Vec<Entry> = Vec::with_capacity(za.len());
    let mut declared = 0u64;
    for i in 0..za.len() {
        let mut entry = {
            let e = za.by_index_data(i).map_err(|_| bad_zip())?;
            if e.version_needed() > 63 {
                return Err(Fail {
                    class: Some("NotImplementedError"),
                    msg: format!(
                        "zip file version {:.1}",
                        f64::from(e.version_needed()) / 10.0
                    ),
                });
            }
            Entry {
                index: i,
                raw: e.name_raw().into(),
                size: e.size(),
                csize: e.compressed_size(),
                method: e.compression(),
                flags: e.flags().as_u16(),
                external: e.external_attributes(),
                data: Err(String::new()),
                header: e.header_start(),
                end: 0,
            }
        };
        // the local header gives where the data starts; a bad header or another name there is a bad member (as
        // Python's BadZipFile when it opens the member)
        entry.data = local_header(&mut probe, entry.header, &entry.raw)
            .map(|s| (s, s.saturating_add(entry.csize)));
        if entry.is_json() {
            declared = declared.saturating_add(entry.size);
        }
        entries.push(entry);
    }
    if declared > caps.zip_total {
        return Err(Fail::native(format!(
            "{what}: the members hold more than {} bytes uncompressed; refusing",
            caps.zip_total
        )));
    }
    // `_end_offset`: the next local header in offset order, or the central directory
    let mut order: Vec<usize> = (0..entries.len()).collect();
    order.sort_by_key(|i| entries[*i].header);
    let mut end = za.central_directory_start();
    for i in order.into_iter().rev() {
        entries[i].end = end;
        end = entries[i].header;
    }
    for e in &entries {
        if !e.is_json() {
            continue;
        }
        if imp.full() {
            break;
        }
        let skip = |reason: String| sink.send(Msg::Log(format!("{NAME}: {reason}")));
        if unsafe_name(&e.raw) {
            if !skip(format!(
                "skipping zip member with an unsafe name {}",
                py::repr_str(&e.name())
            )) {
                break;
            }
            continue;
        }
        if e.size > caps.member_bytes {
            if !skip(format!(
                "skipping oversized zip member {} ({} B)",
                e.name(), e.size
            )) {
                break;
            }
            continue;
        }
        if e.flags & 0x20 != 0 {
            return Err(Fail {
                class: Some("NotImplementedError"),
                msg: "compressed patched data (flag bit 5)".into(),
            });
        }
        if e.flags & 0x40 != 0 {
            return Err(Fail {
                class: Some("NotImplementedError"),
                msg: "strong encryption (flag bit 6)".into(),
            });
        }
        let data_end = match &e.data {
            Ok((_, end)) => *end,
            Err(m) => {
                if !skip(format!("bad member {}: {m}", e.name())) {
                    break;
                }
                continue;
            }
        };
        // Python only warns when another entry has the same local header (`_end_offset == header_offset`)
        if data_end > e.end && e.end != e.header {
            if !skip(format!(
                "bad member {}: Overlapped entries: {} (possible zip bomb)",
                e.name(),
                py::repr_str(&e.name())
            )) {
                break;
            }
            continue;
        }
        if e.flags & 0x01 != 0 {
            return Err(Fail {
                class: Some("RuntimeError"),
                msg: format!(
                    "File {} is encrypted, password required for extraction",
                    e.repr()
                ),
            });
        }
        match e.method {
            zip::CompressionMethod::Stored | zip::CompressionMethod::Deflated => {}
            m if m == zip::CompressionMethod::BZIP2 || m == zip::CompressionMethod::LZMA => {
                // bzip2 and lzma: Python reads them, the workspace's zip crate is built without them
                if !skip(format!(
                    "skipping zip member {} (bzip2 or lzma compression is not supported by the native importer)",
                    e.name()
                )) {
                    break;
                }
                continue;
            }
            _ => {
                return Err(Fail {
                    class: Some("NotImplementedError"),
                    msg: "That compression method is not supported".into(),
                });
            }
        }
        if e.size > caps.ratio_floor && e.size / e.csize.max(1) > caps.zip_ratio {
            if !skip(format!(
                "skipping zip member {}: compression ratio above {} (possible zip bomb)",
                e.name(), caps.zip_ratio
            )) {
                break;
            }
            continue;
        }
        let data = match za.by_index(e.index) {
            Ok(f) => {
                let cap = e.size.min(caps.member_bytes);
                let mut buf = Vec::with_capacity(usize::try_from(cap).unwrap_or(0).min(1 << 20));
                f.take(cap + 1).read_to_end(&mut buf).map(|_| buf)
            }
            Err(err) => Err(std::io::Error::other(err.to_string())),
        };
        let data = match data {
            Ok(d) if d.len() as u64 > caps.member_bytes => {
                if !skip(format!("skipping oversized zip member {}", e.name())) {
                    break;
                }
                continue;
            }
            Ok(d) => d,
            Err(err) => {
                if !skip(format!(
                    "bad member {}: {}",
                    e.name(),
                    feed::scrub(&err.to_string())
                )) {
                    break;
                }
                continue;
            }
        };
        let rec = match loads_bytes(&data) {
            Ok(v) => v,
            Err(m) => {
                if !skip(format!("bad member {}: {m}", e.name())) {
                    break;
                }
                continue;
            }
        };
        let mut out = Vec::new();
        imp.add(rec, data.len(), &mut out);
        if !sink.all(out) {
            break;
        }
    }
    Ok(imp.end())
}

// ------------------------------------------------------------------------------------------------ --path

/// `Path.is_dir()` (follows symlinks; false on any error).
fn is_dir(p: &Path) -> bool {
    std::fs::metadata(p).is_ok_and(|m| m.is_dir())
}

/// `PurePath.suffix` of Python 3.13, lower-cased.
fn suffix_lower(shown: &str) -> String {
    let name = shown.rsplit('/').next().unwrap_or(shown);
    match name.rfind('.') {
        Some(i) if i > 0 && i < name.len() - 1 => name[i..].to_lowercase(),
        _ => String::new(),
    }
}

/// `sorted(p.glob("*.json"))`: the entries of `dir` (not recursive, hidden names and directories so named
/// included) whose name ends in `.json`, sorted by name, each with its `str(path)`.
fn list_json(dir: &Path, shown: &str, caps: &Caps) -> Result<Vec<(PathBuf, String)>, Fail> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut out: Vec<(PathBuf, String, String)> = Vec::new();
    for (n, e) in rd.flatten().enumerate() {
        if n >= caps.entries {
            return Err(Fail::native(format!(
                "{shown}: more than {} directory entries; refusing",
                caps.entries
            )));
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".json") {
            out.push((e.path(), format!("{shown}/{name}"), name));
            if out.len() > caps.files {
                return Err(Fail::native(format!(
                    "{shown}: more than {} .json files; refusing",
                    caps.files
                )));
            }
        }
    }
    out.sort_by(|a, b| a.2.cmp(&b.2));
    Ok(out.into_iter().map(|(p, s, _)| (p, s)).collect())
}

/// `_iter_json_files` + `_import_iter`: each file read as UTF-8 JSON, a list taken as its records.
fn read_json_files(
    files: Vec<(PathBuf, String)>,
    imp: &mut Importer,
    caps: &Caps,
    sink: &Sink,
) -> Result<ImportEnd, Fail> {
    'files: for (p, shown) in files {
        let log = |m: String| sink.send(Msg::Log(format!("{NAME}: {m}")));
        let mut f = match feed::open_regular(&p) {
            Ok(f) => f,
            Err(e) => {
                if !log(format!("bad file {shown}: {}", e.message)) {
                    break;
                }
                continue;
            }
        };
        if f.metadata().is_ok_and(|m| m.len() > caps.member_bytes) {
            if !log(format!("skipping oversized file {shown}")) {
                break;
            }
            continue;
        }
        let mut buf = Vec::new();
        if let Err(e) = (&mut f).take(caps.member_bytes + 1).read_to_end(&mut buf) {
            if !log(format!("bad file {shown}: {}", feed::os_error(&e, &p))) {
                break;
            }
            continue;
        }
        if buf.len() as u64 > caps.member_bytes {
            if !log(format!("skipping oversized file {shown}")) {
                break;
            }
            continue;
        }
        let bytes = buf.len();
        let doc = match py::decode_utf8(&buf).and_then(|t| {
            serde_json::from_str::<Value>(t).map_err(|e| format!("invalid JSON: {e}"))
        }) {
            Ok(d) => d,
            Err(m) => {
                if !log(format!("bad file {shown}: {m}")) {
                    break;
                }
                continue;
            }
        };
        drop(buf);
        let recs = match doc {
            Value::Array(a) => a,
            other => vec![other],
        };
        let per = bytes / recs.len().max(1);
        for rec in recs {
            if imp.full() {
                break 'files;
            }
            let mut out = Vec::new();
            imp.add(rec, per, &mut out);
            if !sink.all(out) {
                break 'files;
            }
        }
    }
    Ok(imp.end())
}

/// `_sync_path`'s reading: a directory of `*.json`, a `.zip` archive, or one JSON file.
fn read_path(
    path: &Path,
    shown: &str,
    imp: &mut Importer,
    caps: &Caps,
    sink: &Sink,
) -> Result<ImportEnd, Fail> {
    if is_dir(path) {
        let files = list_json(path, shown, caps)?;
        return read_json_files(files, imp, caps, sink);
    }
    if suffix_lower(shown) == ".zip" {
        let f = feed::open_regular(path).map_err(|e| Fail {
            class: Some(e.class),
            msg: e.message,
        })?;
        return read_zip(f, shown, imp, caps, sink);
    }
    read_json_files(
        vec![(path.to_path_buf(), shown.to_owned())],
        imp,
        caps,
        sink,
    )
}

// ------------------------------------------------------------------------------------------------ HTTP

/// One GET of `url` into memory (at most `max`): the body, `Ok(None)` for a 404, else the error text.
async fn get(
    client: &reqwest::Client,
    url: &str,
    max: u64,
    allow_http: bool,
) -> Result<Option<Vec<u8>>, String> {
    let g = feed::Get {
        url,
        max_bytes: max,
        allow_http,
        timeout: TIMEOUT,
        accept: None,
        too_large: None,
        same_origin_redirects: false,
    };
    match feed::fetch(client, &g, &[], None).await {
        Ok((body, _)) => Ok(Some(body)),
        Err(feed::FetchError::Status { code: 404, .. }) => Ok(None),
        Err(e) => Err(e.message().to_owned()),
    }
}

/// `_download_zip`: `<Eco>/all.zip` streamed into an anonymous temporary file (private, removed when closed), at
/// most `cap` bytes (Python's messages for the cap).
async fn download_zip(
    client: &reqwest::Client,
    url: &str,
    eco: &str,
    cap: u64,
) -> Result<std::fs::File, String> {
    use tokio::io::AsyncWriteExt;
    let shown = secmonk_safeio::strip_url_secrets(url, false);
    let mut resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| feed::scrub(&e.to_string()))?;
    if !resp.status().is_success() {
        return Err(format!("HTTP {} for {shown}", resp.status().as_u16()));
    }
    if let Some(n) = resp.content_length()
        && n > cap
    {
        return Err(format!(
            "{eco}/all.zip is {n} bytes, above the {cap} byte limit"
        ));
    }
    let file = tokio::task::spawn_blocking(tempfile::tempfile)
        .await
        .map_err(|e| format!("native importer: temporary file task failed: {e}"))?
        .map_err(|e| format!("cannot create a temporary file: {e}"))?;
    let mut out = tokio::fs::File::from_std(file);
    let mut total = 0u64;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| feed::scrub(&e.to_string()))?
    {
        total += chunk.len() as u64;
        if total > cap {
            return Err(format!(
                "{eco}/all.zip exceeds the {cap} byte download limit"
            ));
        }
        out.write_all(&chunk)
            .await
            .map_err(|e| format!("cannot write the temporary file: {e}"))?;
    }
    out.flush()
        .await
        .map_err(|e| format!("cannot write the temporary file: {e}"))?;
    let mut file = out.into_std().await;
    file.rewind()
        .map_err(|e| format!("cannot read the temporary file: {e}"))?;
    Ok(file)
}

// ------------------------------------------------------------------------------------------------ the run

/// A record id written in this run: what was emitted, to replace it when the id comes again.
#[derive(Debug)]
struct Emitted {
    aliases: Vec<(String, String)>,
    affected: u32,
    digest: [u8; 32],
}

/// SHA-256 of a multiset of rows (their JSON, sorted).
fn digest(rows: &[JsonMap]) -> [u8; 32] {
    let mut texts: Vec<String> = rows
        .iter()
        .map(|r| serde_json::to_string(r).unwrap_or_default())
        .collect();
    texts.sort();
    let mut h = Sha256::new();
    for t in texts {
        h.update(t.as_bytes());
        h.update(b"\n");
    }
    h.finalize().into()
}

/// The per-ecosystem state of a run over the bucket (`_sync_all`).
#[derive(Debug)]
struct Ecos {
    n: usize,
    todo: VecDeque<String>,
    errors: Vec<String>,
    ok: usize,
    partial: bool,
    records: u64,
    /// `osv:<Eco>` rows written in this run: (status, cursor), read instead of the view (not applied yet).
    states: HashMap<String, (String, Option<String>)>,
}

#[derive(Debug)]
enum Mode {
    Path {
        path: PathBuf,
        shown: String,
        started: bool,
    },
    Ecos(Box<Ecos>),
    Done,
}

/// How the current import ends.
#[derive(Debug)]
enum Kind {
    Path {
        shown: String,
    },
    Full {
        eco: String,
        key: String,
        /// The stored cursor before this import (kept when it imports no record: `COALESCE`).
        prev: Option<String>,
    },
    Delta {
        eco: String,
        key: String,
    },
}

/// The changed ids of a delta and where it is.
struct Delta {
    eco: String,
    changed: VecDeque<(i64, String, String)>,
    cursor: (i64, String),
    imp: Importer,
    good: Vec<(i64, String)>,
    first_fail: Option<i64>,
    failures: u64,
}

impl fmt::Debug for Delta {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Delta")
            .field("eco", &self.eco)
            .field("left", &self.changed.len())
            .finish_non_exhaustive()
    }
}

/// Where the records of the current import come from.
#[derive(Debug)]
enum Origin {
    Reader(mpsc::Receiver<Msg>),
    Delta(Box<Delta>),
}

/// The current import.
#[derive(Debug)]
struct Feed {
    kind: Kind,
    from: Origin,
}

/// The next record of an import, its end, or what stopped it.
enum Next {
    Plan(Box<Plan>),
    End(ImportEnd),
    Fail(Fail),
}

/// The state of one run (the operation stream).
struct Run {
    view: Arc<dyn MirrorView>,
    caps: Caps,
    bucket: String,
    plan: PlanOpts,
    limit: Option<u64>,
    full: bool,
    say: Progress,
    tail: TailCell,
    emitted: HashMap<String, Emitted>,
    total0: u64,
    new_ids: u64,
    mode: Mode,
    feed: Option<Feed>,
    client: Option<reqwest::Client>,
    done: bool,
}

/// The operations of the run, one group of records at a time.
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
    fn set_tail(&mut self, t: Tail) {
        if let Ok(mut g) = self.tail.lock() {
            *g = Some(t);
        }
        self.done = true;
        self.feed = None;
        self.mode = Mode::Done;
    }

    fn allow_http(&self) -> bool {
        !self.bucket.starts_with("https://")
    }

    fn client(&mut self) -> Result<reqwest::Client, String> {
        if let Some(c) = &self.client {
            return Ok(c.clone());
        }
        let c = feed::fetch_client(TIMEOUT, self.allow_http(), false)?;
        self.client = Some(c.clone());
        Ok(c)
    }

    /// The operations of the next step, `None` once the run is over.
    async fn next_ops(&mut self) -> StepResult<Option<Vec<RowOp>>> {
        loop {
            if self.done {
                return Ok(None);
            }
            if self.feed.is_some() {
                return self.group().await.map(Some);
            }
            match &mut self.mode {
                Mode::Path {
                    path,
                    shown,
                    started,
                } => {
                    if *started {
                        return Err(native::internal(NAME, "the import ended twice".into()));
                    }
                    *started = true;
                    let (path, shown) = (path.clone(), shown.clone());
                    let mut imp = Importer::new(&shown, self.limit, self.plan.clone());
                    let (caps, what) = (self.caps, shown.clone());
                    let rx =
                        spawn_reader(move |sink| read_path(&path, &what, &mut imp, &caps, sink));
                    self.feed = Some(Feed {
                        kind: Kind::Path { shown },
                        from: Origin::Reader(rx),
                    });
                }
                Mode::Ecos(e) => {
                    let Some(eco) = e.todo.pop_front() else {
                        return Ok(Some(self.finish_ecos()));
                    };
                    if let Some(op) = self.start_eco(eco).await? {
                        return Ok(Some(vec![op]));
                    }
                }
                Mode::Done => return Ok(None),
            }
        }
    }

    /// The end of a run over the bucket (`_sync_all`, then the total of `sync`).
    fn finish_ecos(&mut self) -> Vec<RowOp> {
        let Mode::Ecos(e) = &self.mode else {
            return Vec::new();
        };
        let status = if !e.errors.is_empty() && e.ok == 0 {
            "error"
        } else if !e.errors.is_empty() || e.partial {
            "partial"
        } else {
            "ok"
        };
        let message = if e.errors.is_empty() {
            format!("{} ecosystems", e.n)
        } else {
            e.errors.join("; ")
        };
        let tail = Tail {
            status: status.into(),
            records: e.records,
            total: (status != "error").then_some(self.total0 + self.new_ids),
            cursor: None,
            message: Some(message),
        };
        self.set_tail(tail);
        Vec::new()
    }

    fn eco_failed(&mut self, eco: &str, msg: &str) {
        self.say.line(format!("{NAME} {eco}: failed: {msg}"));
        if let Mode::Ecos(e) = &mut self.mode {
            e.errors.push(format!("{eco}: {msg}"));
        }
    }

    /// `_sync_ecosystem` up to its first record: the stored state, the delta or the download. An `osv:<Eco>` row to
    /// write at once never comes from here (`None`); a failure is recorded and the next ecosystem follows.
    async fn start_eco(&mut self, eco: String) -> StepResult<Option<RowOp>> {
        let key = format!("{NAME}:{eco}");
        let local = match &self.mode {
            Mode::Ecos(e) => e.states.get(&key).cloned(),
            _ => None,
        };
        let (status, stored) = match local {
            Some((s, c)) => (Some(s), c),
            None => {
                let page = self
                    .view
                    .rows_page(MirrorTable::SourceSync, &key, None, 1)
                    .await?;
                let row = page.rows.first();
                let text = |k: &str| {
                    row.and_then(|r| r.get(k))
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                };
                (text("status"), text("cursor"))
            }
        };
        // the delta path needs a trustworthy cursor: only after a complete (status ok) sync
        let cursor = if self.full || status.as_deref() != Some("ok") {
            None
        } else {
            stored.clone().filter(|c| !c.is_empty())
        };
        let client = match self.client() {
            Ok(c) => c,
            Err(m) => {
                self.eco_failed(&eco, &m);
                return Ok(None);
            }
        };
        let enc = quote(&eco);
        if let Some(cursor) = cursor {
            let url = format!("{}/{enc}/modified_id.csv", self.bucket);
            let csv = match get(&client, &url, self.caps.csv_bytes, self.allow_http()).await {
                Ok(Some(b)) => b,
                Ok(None) => {
                    let shown = secmonk_safeio::strip_url_secrets(&url, false);
                    self.eco_failed(&eco, &format!("HTTP 404 for {shown}"));
                    return Ok(None);
                }
                Err(m) => {
                    self.eco_failed(&eco, &m);
                    return Ok(None);
                }
            };
            let cur = match parse_ts(&cursor) {
                Ok(c) => c,
                Err(m) => {
                    self.eco_failed(&eco, &m);
                    return Ok(None);
                }
            };
            let text = String::from_utf8_lossy(&csv).into_owned();
            drop(csv);
            let (mut changed, n) = ids_modified_since(&text, cur, DELTA_MAX_IDS + 1);
            drop(text);
            if n <= DELTA_MAX_IDS {
                // oldest first so the cursor can advance contiguously (a stable sort, as Python's)
                changed.sort_by_key(|c| c.0);
                self.feed = Some(Feed {
                    kind: Kind::Delta {
                        eco: eco.clone(),
                        key,
                    },
                    from: Origin::Delta(Box::new(Delta {
                        eco: eco.clone(),
                        changed: changed.into(),
                        cursor: (cur, cursor),
                        imp: Importer::new(&eco, self.limit, self.plan.clone()),
                        good: Vec::new(),
                        first_fail: None,
                        failures: 0,
                    })),
                });
                return Ok(None);
            }
            self.say.line(format!(
                "{NAME} {eco}: {n} changes since cursor, falling back to full zip"
            ));
        }
        self.say
            .line(format!("{NAME} {eco}: downloading {eco}/all.zip"));
        let url = format!("{}/{enc}/all.zip", self.bucket);
        let file = match download_zip(&client, &url, &eco, self.caps.download_bytes).await {
            Ok(f) => f,
            Err(m) => {
                self.eco_failed(&eco, &m);
                return Ok(None);
            }
        };
        let mut imp = Importer::new(&eco, self.limit, self.plan.clone());
        let (caps, what) = (self.caps, format!("{eco}/all.zip"));
        let rx = spawn_reader(move |sink| read_zip(file, &what, &mut imp, &caps, sink));
        self.feed = Some(Feed {
            kind: Kind::Full {
                eco,
                key,
                prev: stored,
            },
            from: Origin::Reader(rx),
        });
        Ok(None)
    }

    /// The next record of the current import.
    async fn next_record(&mut self) -> Next {
        let say = &self.say;
        let Some(feed) = self.feed.as_mut() else {
            return Next::Fail(Fail::native("native importer: no import".into()));
        };
        match &mut feed.from {
            Origin::Reader(rx) => loop {
                match rx.recv().await {
                    Some(Msg::Log(l)) => say.line(l),
                    Some(Msg::Plan(p)) => return Next::Plan(p),
                    Some(Msg::End(e)) => return Next::End(e),
                    Some(Msg::Fail(f)) => return Next::Fail(f),
                    None => {
                        return Next::Fail(Fail::native(
                            "native importer: the reader stopped without a result".into(),
                        ));
                    }
                }
            },
            Origin::Delta(d) => {
                let client = match &self.client {
                    Some(c) => c.clone(),
                    None => return Next::Fail(Fail::native("native importer: no client".into())),
                };
                let allow_http = !self.bucket.starts_with("https://");
                delta_next(d, &client, &self.bucket, allow_http, &self.caps, say).await
            }
        }
    }

    /// One group of records of the current import: planned, compared with the stored rows, as operations; and the
    /// import's end when it came.
    async fn group(&mut self) -> StepResult<Vec<RowOp>> {
        let mut plans: Vec<Plan> = Vec::new();
        let (mut bytes, mut new) = (0usize, 0usize);
        let mut ended: Option<Result<ImportEnd, Fail>> = None;
        while plans.len() < GROUP && bytes < GROUP_BYTES && new < GROUP_NEW {
            match self.next_record().await {
                Next::Plan(p) => {
                    bytes += p.bytes;
                    new += p.affected.len();
                    plans.push(*p);
                }
                Next::End(e) => {
                    ended = Some(Ok(e));
                    break;
                }
                Next::Fail(f) => {
                    ended = Some(Err(f));
                    break;
                }
            }
        }
        let mut ops = self.emit(plans).await?;
        if let Some(end) = ended {
            let Some(feed) = self.feed.take() else {
                return Err(native::internal(NAME, "the import vanished".into()));
            };
            ops.extend(self.import_ended(feed.kind, end));
        }
        Ok(ops)
    }

    /// The bookkeeping after one import: the `osv:<Eco>` row, the counts, or the run's end for `--path`.
    fn import_ended(&mut self, kind: Kind, end: Result<ImportEnd, Fail>) -> Vec<RowOp> {
        let now = self.plan.now.clone();
        match (kind, end) {
            (Kind::Path { shown }, Ok(e)) => {
                let tail = Tail {
                    status: "ok".into(),
                    records: e.count,
                    total: Some(self.total0 + self.new_ids),
                    cursor: e.max_modified,
                    message: Some(format!("from {shown}")),
                };
                self.set_tail(tail);
                Vec::new()
            }
            (Kind::Path { .. }, Err(f)) => {
                // what `ops.sync_source` makes of an exception: error, no records
                let tail = Tail {
                    status: "error".into(),
                    message: Some(f.for_path()),
                    ..Tail::default()
                };
                self.set_tail(tail);
                Vec::new()
            }
            (Kind::Full { eco, key, prev }, Ok(e)) => {
                let truncated = self.limit.is_some_and(|l| e.count >= l);
                let status = if truncated { "partial" } else { "ok" };
                let cursor = if truncated {
                    None
                } else {
                    e.max_modified.clone()
                };
                let mut row = native::sync_row(
                    &key,
                    status,
                    e.count,
                    cursor.clone(),
                    Some("full".into()),
                    &now,
                );
                if truncated && let RowOp::Upsert { row, .. } = &mut row {
                    // a --limit run imported an arbitrary subset: no cursor, and the next run must be full
                    row.insert("cursor".into(), Value::Null);
                }
                self.say
                    .line(format!("{NAME} {eco}: imported {} records (full)", e.count));
                let partial = self.limit.is_some();
                if let Mode::Ecos(m) = &mut self.mode {
                    let kept = if truncated { None } else { cursor.or(prev) };
                    m.states.insert(key, (status.into(), kept));
                    m.ok += 1;
                    m.records += e.count;
                    m.partial |= partial;
                }
                vec![row]
            }
            (Kind::Delta { eco, key }, Ok(e)) => {
                let (cursor, failures) = e.delta.clone().unwrap_or_default();
                let message = if failures > 0 {
                    format!("delta, {failures} failed")
                } else {
                    "delta".into()
                };
                let row = native::sync_row(
                    &key,
                    "ok",
                    e.count,
                    Some(cursor.clone()),
                    Some(message),
                    &now,
                );
                self.say.line(format!(
                    "{NAME} {eco}: imported {} records (delta)",
                    e.count
                ));
                if let Mode::Ecos(m) = &mut self.mode {
                    m.states.insert(key, ("ok".into(), Some(cursor)));
                    m.ok += 1;
                    m.records += e.count;
                    m.partial |= failures > 0;
                }
                vec![row]
            }
            (Kind::Full { eco, .. } | Kind::Delta { eco, .. }, Err(f)) => {
                self.eco_failed(&eco, &f.msg);
                Vec::new()
            }
        }
    }

    /// The operations of a group of planned records: `store_raw`, `upsert_vulnerability`, `replace_children` +
    /// `add_alias` / `add_affected`, against the stored rows (read once per group for the ids not written in this
    /// run) or against what this run emitted.
    async fn emit(&mut self, plans: Vec<Plan>) -> StepResult<Vec<RowOp>> {
        if plans.is_empty() {
            return Ok(Vec::new());
        }
        let mut seen: HashSet<&str> = HashSet::new();
        let ids: Vec<String> = plans
            .iter()
            .filter(|p| !self.emitted.contains_key(&p.id) && seen.insert(p.id.as_str()))
            .map(|p| p.id.clone())
            .collect();
        let (aliases, affected, vulns) = if ids.is_empty() {
            (Vec::new(), Vec::new(), Vec::new())
        } else {
            (
                self.view.rows_by_id(MirrorTable::Alias, NAME, &ids).await?,
                self.view
                    .rows_by_id(MirrorTable::Affected, NAME, &ids)
                    .await?,
                self.view
                    .rows_by_id(MirrorTable::Vulnerability, NAME, &ids)
                    .await?,
            )
        };
        let stored_aliases = rows::group_by(&aliases, "vuln_id");
        let stored_affected = rows::group_by(&affected, "vuln_id");
        for (id, of) in &stored_affected {
            if of.len() > self.caps.affected {
                return Err(native::internal(
                    NAME,
                    format!(
                        "{id}: {} stored affected rows (more than {}); refusing, sync osv with the python implementation",
                        of.len(),
                        self.caps.affected
                    ),
                ));
            }
        }
        let exists: HashSet<&str> = vulns
            .iter()
            .filter_map(|r| r.get("id").and_then(Value::as_str))
            .collect();
        let none = Vec::new();
        let mut ops = Vec::new();
        let mut new_ids = 0u64;
        for p in plans {
            if let Some(raw) = p.raw {
                ops.push(raw);
            }
            ops.push(p.vulnerability);
            let n_new = u32::try_from(p.affected.len()).unwrap_or(u32::MAX);
            let dig = digest(&p.affected);
            match self.emitted.get(&p.id) {
                Some(prev) => {
                    // emitted earlier in this run (perhaps not applied yet): replace those rows
                    let maps: Vec<JsonMap> = prev
                        .aliases
                        .iter()
                        .map(|(a, k)| alias_row(&p.id, a, k))
                        .collect();
                    let refs: Vec<&JsonMap> = maps.iter().collect();
                    ops.extend(rows::replace_aliases(NAME, &p.id, &refs, &p.aliases));
                    if prev.digest != dig || prev.affected != n_new {
                        ops.extend((0..prev.affected).map(|_| {
                            RowOp::Delete {
                                table: MirrorTable::Affected,
                                key: [
                                    ("source".to_owned(), json!(NAME)),
                                    ("vuln_id".to_owned(), json!(p.id)),
                                ]
                                .into_iter()
                                .collect(),
                            }
                        }));
                        ops.extend(p.affected.into_iter().map(|row| RowOp::Upsert {
                            table: MirrorTable::Affected,
                            row,
                        }));
                    }
                }
                None => {
                    ops.extend(rows::replace_aliases(
                        NAME,
                        &p.id,
                        stored_aliases.get(p.id.as_str()).unwrap_or(&none),
                        &p.aliases,
                    ));
                    ops.extend(rows::replace_affected(
                        stored_affected.get(p.id.as_str()).unwrap_or(&none),
                        p.affected,
                        DeleteKey::Record,
                    ));
                    if !exists.contains(p.id.as_str()) {
                        new_ids += 1;
                    }
                }
            }
            self.emitted.insert(
                p.id,
                Emitted {
                    aliases: p.aliases,
                    affected: n_new,
                    digest: dig,
                },
            );
        }
        self.new_ids += new_ids;
        if self.emitted.len() > self.caps.records {
            return Err(native::internal(
                NAME,
                format!(
                    "more than {} records in one run; refusing",
                    self.caps.records
                ),
            ));
        }
        Ok(ops)
    }
}

fn alias_row(vuln_id: &str, alias: &str, kind: &str) -> JsonMap {
    let mut m = JsonMap::new();
    m.insert("vuln_id".into(), json!(vuln_id));
    m.insert("alias".into(), json!(alias));
    m.insert("source".into(), json!(NAME));
    m.insert("kind".into(), json!(kind));
    m
}

/// A record id that would leave `<Eco>/` in the bucket URL (a `/` or a dot segment): not fetched, logged, and
/// treated as not found (Python fetches it).
fn unsafe_id(rid: &str) -> bool {
    rid.is_empty() || rid.contains('/') || rid.contains('\\') || rid == "." || rid == ".."
}

/// `_delta`'s loop up to its next record: GET `<Eco>/<ID>.json` per changed id (oldest first), 404 skipped, a
/// failure counted (the cursor stays before the first one); the end with the cursor to store.
async fn delta_next(
    d: &mut Delta,
    client: &reqwest::Client,
    bucket: &str,
    allow_http: bool,
    caps: &Caps,
    say: &Progress,
) -> Next {
    loop {
        if d.imp.full() {
            break;
        }
        let Some((t, ts, rid)) = d.changed.pop_front() else {
            break;
        };
        let mut produced: Option<Box<Plan>> = None;
        let outcome: Result<(), String> = if unsafe_id(&rid) {
            say.line(format!(
                "{NAME} {}: {}: an id that is not a plain file name; skipped",
                d.eco,
                py::repr_str(&rid)
            ));
            Ok(())
        } else {
            let url = format!("{bucket}/{}/{}.json", quote(&d.eco), quote(&rid));
            match get(client, &url, caps.member_bytes, allow_http).await {
                Ok(None) => Ok(()),
                Ok(Some(body)) => match loads_bytes(&body) {
                    Ok(doc @ Value::Object(_)) => {
                        let mut out = Vec::new();
                        d.imp.add(doc, body.len(), &mut out);
                        for m in out {
                            match m {
                                Msg::Plan(p) => produced = Some(p),
                                Msg::Log(l) => say.line(l),
                                Msg::End(_) | Msg::Fail(_) => {}
                            }
                        }
                        Ok(())
                    }
                    Ok(_) => Err("ValueError: record is not a JSON object".into()),
                    Err(m) => Err(m),
                },
                Err(m) => Err(m),
            }
        };
        match outcome {
            Ok(()) => {
                if d.first_fail.is_none() {
                    d.good.push((t, ts));
                }
            }
            Err(m) => {
                d.failures += 1;
                say.line(format!("{NAME} {}: {rid}: {m}", d.eco));
                if d.first_fail.is_none() {
                    d.first_fail = Some(t);
                }
            }
        }
        if let Some(p) = produced {
            return Next::Plan(p);
        }
    }
    // the cursor advances only to the last success before the first failure, never backwards
    let mut newest: Option<&(i64, String)> = None;
    for g in &d.good {
        if d.first_fail.is_none_or(|f| g.0 < f) {
            newest = Some(g);
        }
    }
    let newest = newest.filter(|g| g.0 > d.cursor.0);
    let cursor = newest.map_or_else(|| d.cursor.1.clone(), |g| g.1.clone());
    let mut end = d.imp.end();
    end.delta = Some((cursor, d.failures));
    Next::End(end)
}

#[async_trait]
impl Source for OsvSource {
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

    fn opts() -> PlanOpts {
        PlanOpts {
            store_raw: false,
            now: "2026-11-12T00:00:00Z".into(),
            affected: 10_000,
        }
    }

    fn rows(rec: Value) -> Box<Plan> {
        match plan(rec, 0, &opts()) {
            Planned::Rows(p, _) => p,
            other => panic!("{other:?}"),
        }
    }

    fn skipped(rec: Value) -> String {
        match plan(rec, 0, &opts()) {
            Planned::Skipped { reason, .. } => reason,
            other => panic!("{other:?}"),
        }
    }

    fn vuln(p: &Plan) -> &JsonMap {
        match &p.vulnerability {
            RowOp::Upsert { row, .. } => row,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn purls_are_rebuilt_like_packageurl_python() {
        // expected values: `_strip_purl` of the Python source (packageurl-python 0.17.6, Python 3.13.5)
        let cases: &[(&str, &str)] = &[
            ("pkg:pypi/Foo_Bar", "pkg:pypi/foo-bar"),
            ("pkg:pypi/foo@1.0?x=1#sub", "pkg:pypi/foo"),
            (
                "pkg:maven/org.apache.logging.log4j/log4j-core",
                "pkg:maven/org.apache.logging.log4j/log4j-core",
            ),
            (
                "pkg:deb/debian/xz-utils?arch=source&distro=trixie",
                "pkg:deb/debian/xz-utils",
            ),
            (
                "pkg:deb/ubuntu/python-tornado?arch=source&distro=esm-apps%2Fbionic",
                "pkg:deb/ubuntu/python-tornado",
            ),
            ("pkg:npm/%40scope/name", "pkg:npm/%40scope/name"),
            ("pkg:npm/@scope/Name@1.0", "pkg:npm/%40scope/name"),
            (
                "pkg:golang/github.com/Foo/Bar",
                "pkg:golang/github.com/Foo/Bar",
            ),
            (
                "pkg:swift/github.com/apple/swift-nio",
                "pkg:swift/github.com/apple/swift-nio",
            ),
            ("pkg:pub/http", "pkg:pub/http"),
            ("pkg:pub/Foo-Bar.baz", "pkg:pub/foo_bar_baz"),
            ("pkg:apk/alpine/xz?arch=source", "pkg:apk/alpine/xz"),
            (
                "pkg:rpm/redhat/openssl?epoch=1&arch=src",
                "pkg:rpm/redhat/openssl",
            ),
            ("pkg:cargo/serde", "pkg:cargo/serde"),
            ("PKG:pypi/x", "PKG:pypi/x"),
            ("pkg:", "pkg:"),
            ("pkg:/", "pkg:/"),
            ("pkg:pypi", "pkg:pypi"),
            ("pkg:1abc/x", "pkg:1abc/x"),
            ("pkg:py$pi/x", "pkg:py$pi/x"),
            ("pkg:pypi/x?bad", "pkg:pypi/x"),
            ("pkg:pypi/x?1a=b", "pkg:pypi/x"),
            ("pkg:pypi/x?a%20b=c", "pkg:pypi/x"),
            ("pkg:pypi/%20", "pkg:pypi/%20"),
            ("pkg:generic/a%2Fb/c", "pkg:generic/a/b/c"),
            ("pkg:generic/ns%2Fx/n%2Fm", "pkg:generic/ns/x/n/m"),
            ("pkg:generic//a//b//", "pkg:generic/a/b"),
            ("pkg:generic/a:b/c", "pkg:generic/a:b/c"),
            (
                "pkg:generic/http://host/path/n",
                "pkg:generic/http:host:/path/n",
            ),
            ("pkg:generic///host/x", "pkg:generic/host:/x"),
            ("pkg:generic/x@y@z", "pkg:generic/x%40y"),
            ("pkg:generic/n%C3%A9", "pkg:generic/n%C3%A9"),
            ("pkg:generic/n%C3", "pkg:generic/n%EF%BF%BD"),
            ("pkg:generic/é%41", "pkg:generic/%C3%A9A"),
            ("pkg:generic/n a", "pkg:generic/n%20a"),
            (
                "pkg:mlflow/MyModel?repository_url=https://databricks.example",
                "pkg:mlflow/mymodel",
            ),
            ("pkg:m/AbC", "pkg:m/AbC"),
            ("pkg:cpan/a/B", "pkg:cpan/A/B"),
            ("pkg:c/ns/x", "pkg:c/NS/x"),
            ("pkg:hackage/a_b", "pkg:hackage/a-b"),
            ("pkg:github/Foo/Bar", "pkg:github/foo/bar"),
            ("pkg:huggingface/A/B@ABC", "pkg:huggingface/A/B"),
            ("pkg:generic/[x]/y", "pkg:generic/%5Bx%5D/y"),
            ("pkg:generic///[::1]/y", "pkg:generic/%5B::1%5D:/y"),
            ("pkg:generic///[x/y", "pkg:generic///[x/y"),
            ("pkg:generic/\tx\ny", "pkg:generic/xy"),
            ("pkg:generic/ x ", "pkg:generic/x"),
            ("pkg:generic/x#", "pkg:generic/x"),
            ("pkg:generic/x?", "pkg:generic/x"),
            ("pkg:generic/x?a=", "pkg:generic/x"),
            ("pkg:generic/x?=b", "pkg:generic/x"),
            ("pkg:generic/x?a=b&c", "pkg:generic/x"),
            ("pkg:Generic/X", "pkg:generic/X"),
            ("pkg:pypi/A.B-C_D", "pkg:pypi/a.b-c-d"),
            ("pkg:oci/Foo@sha256:ABC", "pkg:oci/foo"),
            ("pkg:npm/@/x", "pkg:npm/%40/x"),
            ("pkg:npm/@a", "pkg:npm/@a"),
            ("pkg:generic/%7E~", "pkg:generic/~~"),
            ("pkg:generic/a+b!c", "pkg:generic/a%2Bb%21c"),
            ("pkg:bitnami/Foo", "pkg:bitnami/foo"),
            ("pkg:composer/Vendor/Pkg", "pkg:composer/vendor/pkg"),
            ("pkg:alpm/Arch/Pkg", "pkg:alpm/arch/pkg"),
            ("pkg:generic/ü/x", "pkg:generic/%C3%BC/x"),
            ("pkg:generic/x?K=1", "pkg:generic/x"),
            ("pkg:generic/x?%4b=1", "pkg:generic/x"),
            ("pkg:generic/a/b/c@1.0#x/y", "pkg:generic/a/b/c"),
            (
                "pkg:deb/debian/libc6?distro=debian-12&arch=amd64",
                "pkg:deb/debian/libc6",
            ),
            ("noscheme", "noscheme"),
            ("pkg:generic/x?a=b&a=c", "pkg:generic/x"),
            ("pkg:mlflow/X?repository_url=AzureML", "pkg:mlflow/X"),
            ("pkg:low/Abc", "pkg:low/Abc"),
            ("pkg:an/ns/x", "pkg:an/NS/x"),
            ("pkg:generic/x%2", "pkg:generic/x%252"),
            ("pkg:generic/x%zz", "pkg:generic/x%25zz"),
            ("pkg:generic/%2F", "pkg:generic/%2F"),
        ];
        for (p, want) in cases {
            assert_eq!(strip_purl(p), *want, "{p:?}");
        }
    }

    #[test]
    fn ecosystems_and_names_are_normalized_like_purl_py() {
        // expected values: `purl.normalize_ecosystem` and `_ubuntu_variant` of the Python source (Python 3.13.5)
        let cases: &[(&str, &str, Option<&str>)] = &[
            ("Ubuntu:Pro:18.04:LTS", "Ubuntu:18.04", Some("Pro")),
            ("Ubuntu:22.04:LTS", "Ubuntu:22.04", None),
            ("Ubuntu", "Ubuntu", None),
            (
                "Ubuntu:Pro:FIPS-updates:22.04:LTS",
                "Ubuntu:22.04",
                Some("Pro:FIPS-updates"),
            ),
            ("Red Hat:enterprise_linux:9::appstream", "Red Hat:9", None),
            ("Red Hat:rhel_eus:9.6::baseos", "Red Hat:9", None),
            ("Red Hat:enterprise_linux:10.2", "Red Hat:10", None),
            (
                "Red Hat:openshift:4.14::el9",
                "Red Hat:openshift:4.14::el9",
                None,
            ),
            ("Red Hat:8", "Red Hat:8", None),
            ("Red Hat", "Red Hat", None),
            ("Red Hat:enterprise_linux", "Red Hat", None),
            ("Rocky Linux:8.6", "Rocky Linux:8", None),
            ("AlmaLinux:9", "AlmaLinux:9", None),
            ("AlmaLinux", "AlmaLinux", None),
            ("Debian:12", "Debian:12", None),
            ("PyPI", "PyPI", None),
            ("Ubuntu:²3", "Ubuntu:²3", None),
            ("Red Hat:①x:4.1", "Red Hat:①x", None),
            ("", "", None),
        ];
        for (raw, eco, variant) in cases {
            assert_eq!(normalize_ecosystem(raw), *eco, "{raw:?}");
            assert_eq!(
                ubuntu_variant(Some(&json!(raw))).as_deref(),
                *variant,
                "{raw:?}"
            );
        }
        assert_eq!(normalize_name("PyPI", " Foo__Bar.baz-"), "foo-bar-baz-");
        assert_eq!(normalize_name("Maven", "Org.X:Y"), "Org.X:Y");
        assert_eq!(normalize_name("Go", "github.com/A/B"), "github.com/A/B");
        assert_eq!(normalize_name("npm", "@Scope/X"), "@scope/x");
        assert_eq!(normalize_name("", "X"), "x");
    }

    #[test]
    fn cvss3_scores_follow_the_python_source() {
        // expected values: `cvss3_score` of the Python source
        let cases: &[(&str, Option<f64>)] = &[
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Some(9.8)),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", Some(10.0)),
            ("CVSS:3.0/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", Some(1.8)),
            ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", Some(6.4)),
            ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", Some(0.0)),
            ("CVSS:3.1/AV:A/AC:L/PR:H/UI:R/S:C/C:H/I:L/A:L", Some(7.1)),
            ("CVSS:3.1/AV:N", None),
            ("CVSS:2.0/AV:N", None),
            (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:H",
                Some(9.8),
            ),
            ("CVSS:3.1/AVN", None),
            (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/AV:L",
                Some(8.4),
            ),
        ];
        for (v, want) in cases {
            assert_eq!(cvss3_score(v), *want, "{v}");
        }
        // every CVSS 3.1 base vector (2592): the joined `repr` of Python's scores has this SHA-256
        let mut all = Vec::new();
        for av in ["N", "A", "L", "P"] {
            for ac in ["L", "H"] {
                for pr in ["N", "L", "H"] {
                    for ui in ["N", "R"] {
                        for s in ["U", "C"] {
                            for c in ["H", "L", "N"] {
                                for i in ["H", "L", "N"] {
                                    for a in ["H", "L", "N"] {
                                        let v = format!(
                                            "CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"
                                        );
                                        all.push(py::float_repr(cvss3_score(&v).unwrap()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        let h: [u8; 32] = Sha256::digest(all.join(",").as_bytes()).into();
        assert_eq!(
            crate::decode::hex(&h),
            "5f321f7c7911e204e55f67130ebe8a9a7b782938d907d265da46e9389cbc17c3"
        );
    }

    #[test]
    fn timestamps_and_the_csv_follow_python() {
        assert_eq!(parse_ts("2024-01-01T00:00:00Z"), Ok(1_704_067_200_000_000));
        assert_eq!(
            parse_ts("2024-01-01T00:00:00.123456789Z"),
            Ok(1_704_067_200_123_456)
        );
        assert_eq!(
            parse_ts("2024-01-01T00:00:00.1234567+01:00"),
            Ok(1_704_063_600_123_456)
        );
        assert_eq!(parse_ts(" 2024-01-01 "), Ok(1_704_067_200_000_000));
        assert_eq!(parse_ts("2024-01-01T00:00:00"), Ok(1_704_067_200_000_000));
        assert!(parse_ts("bad").is_err());
        assert_eq!(
            splitlines("a\r\nb\rc\x0bd\u{2028}e\n\nf\n"),
            vec!["a", "b", "c", "d", "e", "", "f"]
        );
        let csv = "2026-11-07T08:45:03.213207645Z,MAL-2\n\n no comma\nbad,X\n2026-11-06T00:00:00Z, GHSA-1 \r\n2026-11-01T00:00:00Z,OLD";
        let cur = parse_ts("2026-11-05T00:00:00Z").unwrap();
        let (ids, n) = ids_modified_since(csv, cur, 1);
        assert_eq!(n, 2);
        assert_eq!(ids.len(), 1, "only `keep` are kept");
        assert_eq!(ids[0].2, "MAL-2");
        let (ids, _) = ids_modified_since(csv, cur, 10);
        assert_eq!(ids[1].2, "GHSA-1");
        assert_eq!(quote("Red Hat"), "Red%20Hat");
        assert_eq!(quote("RHSA-2026:3/x~y"), "RHSA-2026%3A3/x~y");
    }

    #[test]
    fn text_columns_bind_like_sqlite() {
        assert_eq!(bind_text(Some(&json!("x")), "f"), Ok(Some("x".into())));
        assert_eq!(bind_text(Some(&json!(5)), "f"), Ok(Some("5".into())));
        assert_eq!(bind_text(Some(&json!(true)), "f"), Ok(Some("1".into())));
        assert_eq!(bind_text(Some(&Value::Null), "f"), Ok(None));
        assert!(bind_text(Some(&json!(1.5)), "f").is_err());
        assert!(bind_text(Some(&json!([1])), "f").is_err());
        assert!(bind_text(Some(&json!(u64::MAX)), "f").is_err());
    }

    #[test]
    fn json_bytes_decode_like_json_loads() {
        assert_eq!(
            loads_bytes(b"\xef\xbb\xbf{\"a\":1}").unwrap(),
            json!({"a": 1})
        );
        let utf16: Vec<u8> = "{\"a\":\"\u{e9}\"}"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(loads_bytes(&utf16).unwrap(), json!({"a": "\u{e9}"}));
        let mut bom = vec![0xFE, 0xFF];
        bom.extend("[1]".encode_utf16().flat_map(u16::to_be_bytes));
        assert_eq!(loads_bytes(&bom).unwrap(), json!([1]));
        let utf32: Vec<u8> = "[2]"
            .chars()
            .flat_map(|c| u32::from(c).to_be_bytes())
            .collect();
        assert_eq!(loads_bytes(&utf32).unwrap(), json!([2]));
        assert!(
            loads_bytes(b"{\"a\": \"caf\xe9\"}")
                .unwrap_err()
                .contains("can't decode byte 0xe9")
        );
        assert!(loads_bytes(b"{").unwrap_err().starts_with("invalid JSON"));
    }

    #[test]
    fn zip_names_and_suffixes() {
        for bad in [
            &b"../x.json"[..],
            b"/etc/x.json",
            b"a/../../x.json",
            b"C:x.json",
            b"a\\b.json",
            b"a\0.json",
        ] {
            assert!(unsafe_name(bad), "{bad:?}");
        }
        for ok in [
            &b"GHSA-1.json"[..],
            b"RHSA-2026:39976.json",
            b"dir/x.json",
            b"..x.json",
        ] {
            assert!(!unsafe_name(ok), "{ok:?}");
        }
        assert_eq!(suffix_lower("/a/b.ZIP"), ".zip");
        assert_eq!(suffix_lower(".zip"), "");
        assert_eq!(suffix_lower("a."), "");
        assert!(unsafe_id("a/b") && unsafe_id("..") && !unsafe_id("GHSA-x"));
        assert!(
            validate_ecosystems(&["Debian:12".into()])
                .unwrap_err()
                .starts_with(
                    "OSV ecosystem 'Debian:12' is release-qualified; use the base name ('Debian')."
                )
        );
    }

    #[test]
    fn records_plan_like_import_record() {
        assert!(matches!(plan(json!([1]), 0, &opts()), Planned::Ignored));
        assert!(matches!(
            plan(json!({"id": ""}), 0, &opts()),
            Planned::Ignored
        ));
        // a numeric id is stored as its text (`str(rec["id"])`)
        let p = rows(json!({"id": 5, "modified": "2024-01-01T00:00:00Z"}));
        assert_eq!(p.id, "5");
        assert_eq!(vuln(&p)["extra"]["source_db"], "5");
        // the summary from the details; v4-only severity: a score derived from the label
        let p = rows(json!({"id": "GHSA-1", "details": "  first line\nsecond",
            "database_specific": {"severity": "moderate", "cwe_ids": "CWE-79"},
            "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}],
            "references": [{"url": "u1"}, {"url": ""}, "x", {"url": 7}]}));
        let v = vuln(&p);
        assert_eq!(v["summary"], "first line");
        assert_eq!(
            (
                v["severity"].clone(),
                v["cvss_score"].clone(),
                v["cvss_version"].clone()
            ),
            (json!("MEDIUM"), json!(5.5), json!("4.0"))
        );
        assert_eq!(v["cwes"], json!(["CWE-79"]));
        assert_eq!(
            v["extra"],
            json!({"source_db": "GHSA", "references": ["u1", 7], "score_derived": true})
        );
        // the v3 vector is used, the v4 vector goes to extra; the Ubuntu word is a label
        let p = rows(
            json!({"id": "U-1", "severity": [{"type": "Ubuntu", "score": "high"},
            {"type": "CVSS_V4", "score": "CVSS:4.0/X"},
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}),
        );
        let v = vuln(&p);
        assert_eq!(
            (v["severity"].clone(), v["cvss_score"].clone()),
            (json!("HIGH"), json!(9.8))
        );
        assert_eq!(v["extra"]["cvss_v4_vector"], "CVSS:4.0/X");
        // aliases and upstream ids; withdrawn: no affected rows
        let p = rows(
            json!({"id": "A-1", "aliases": ["CVE-1", "A-1", 3], "upstream": ["CVE-1", "CVE-2"],
            "withdrawn": "2024-01-01", "affected": [{"package": {"name": "x", "ecosystem": "PyPI"}, "versions": ["1"]}]}),
        );
        assert_eq!(
            p.aliases,
            vec![
                ("CVE-1".into(), "alias".into()),
                ("CVE-2".into(), "upstream".into())
            ]
        );
        assert!(p.affected.is_empty());
        // Python raises: the record is skipped
        assert!(skipped(json!({"id": "X", "severity": "CVSS"})).contains("no attribute 'get'"));
        assert!(skipped(json!({"id": "X", "references": 5})).contains("not iterable"));
        assert!(skipped(json!({"id": "X", "details": 5})).contains("no attribute 'strip'"));
        assert!(skipped(json!({"id": "X", "published": [1]})).contains("published"));
        assert!(
            skipped(json!({"id": "X", "affected": [{"package": {"name": 5}, "versions": ["1"]}]}))
                .contains("strip")
        );
        assert!(
            skipped(json!({"id": "X", "affected": [{"package": {"name": "x", "ecosystem": 5}}]}))
                .contains("split")
        );
        assert!(
            skipped(
                json!({"id": "X", "affected": [{"package": {"name": "x", "ecosystem": []}, "versions": ["1"]}]})
            )
            .contains("ecosystem")
        );
        // a falsy non-string ecosystem with no row is not bound
        let p = rows(json!({"id": "X", "affected": [{"package": {"name": "x", "ecosystem": []}}]}));
        assert!(p.affected.is_empty());
    }

    #[test]
    fn affected_rows_follow_import_record() {
        let p = rows(json!({"id": "GO-1", "affected": [
            {"package": {"name": "Mod", "ecosystem": "Go", "purl": "pkg:golang/Mod"},
             "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]},
                        {"type": "GIT", "repo": "r", "events": [{"introduced": "a"}]}],
             "ecosystem_specific": {"custom_ranges": [{"type": "X", "events": [{"introduced": "1"}], "database_specific": {"k": 1}}],
                                    "binaries": [{"binary_name": "b1"}, {"binary_name": ""}], "urgency": " Low "}},
            {"package": {"name": "Pkg", "ecosystem": "Ubuntu:Pro:22.04:LTS"}, "versions": ["1.0", 2]},
            {"package": {"name": "", "ecosystem": "PyPI"}, "versions": ["1"]},
            "not a dict"
        ]}));
        let a = &p.affected;
        assert_eq!(a.len(), 3, "{a:#?}");
        assert_eq!(a[0]["range_type"], "GIT");
        assert_eq!(
            a[0]["extra"],
            json!({"binaries": ["b1"], "urgency": "low", "repo": "r"})
        );
        assert_eq!(a[0]["purl"], "pkg:golang/Mod");
        assert_eq!(a[1]["range_type"], "ECOSYSTEM");
        assert_eq!(a[1]["events"], json!([{"introduced": "1"}]));
        assert_eq!(
            a[1]["extra"],
            json!({"custom_range": true, "raw_ecosystem": "Go", "database_specific": {"k": 1},
                   "binaries": ["b1"], "urgency": "low"})
        );
        assert_eq!(a[2]["range_type"], "VERSIONS");
        assert_eq!(a[2]["ecosystem"], "Ubuntu:22.04");
        assert_eq!(a[2]["package"], "pkg");
        assert_eq!(a[2]["events"], Value::Null);
        assert_eq!(a[2]["versions"], json!(["1.0"]));
        assert_eq!(
            a[2]["extra"],
            json!({"raw_ecosystem": "Ubuntu:Pro:22.04:LTS", "ecosystem_variant": "Pro"})
        );
        // events kept verbatim when truthy, `[]` otherwise (a list of objects only: the row contract); `extra or None`
        let p = rows(json!({"id": "X", "affected": [{"package": {"name": "x"},
            "ranges": [{"type": "GIT", "events": [{"x": 1}]}, {"type": "GIT"}]}]}));
        assert_eq!(p.affected[0]["events"], json!([{"x": 1}]));
        assert!(skipped(json!({"id": "X", "affected": [{"package": {"name": "x"}, "ranges": [{"type": "GIT", "events": "str"}]}]})).contains("list of objects"));
        assert!(skipped(json!({"id": "X", "affected": [{"package": {"name": "x"}, "ranges": [{"type": "GIT", "events": ["s"]}]}]})).contains("list of objects"));
        assert_eq!(p.affected[1]["events"], json!([]));
        assert_eq!(p.affected[1]["extra"], Value::Null);
        assert_eq!(p.affected[1]["ecosystem"], Value::Null);
        // the per-record cap
        let many: Vec<Value> = (0..3)
            .map(|i| json!({"package": {"name": format!("p{i}")}, "versions": ["1"]}))
            .collect();
        let o = PlanOpts {
            affected: 2,
            ..opts()
        };
        assert!(matches!(
            plan(json!({"id": "X", "affected": many}), 0, &o),
            Planned::Skipped { reason, .. } if reason.contains("more than 2")
        ));
    }
}
