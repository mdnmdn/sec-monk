//! Debian Security Tracker, native (rust ADR-0011, ADR-0012). Port of `src/secmonk/sources/debian_tracker.py` plus
//! the `source_sync` bookkeeping of `ops.sync_source` / `db.set_sync_state`; reference: `py-sources` (differential
//! test `secmonk-engine/tests/native_debian_tracker.rs`). Doc: `rust/_docs/tech/source-debian-tracker.md`.
//!
//! Two inputs, as the Python source: the tracker JSON (download, or `--path` to a plain or gzip file) and a checkout of
//! the security-tracker repository (`--path` to a directory: `data/CVE/list`, `data/DSA/list`, `data/DLA/list`). The
//! JSON is parsed as it is read (no document tree, no copy of the download in memory): each package's entries are
//! reduced to the fields the Python code reads and turned into compact rows (strings interned, 36 bytes per row).
//! Every row is built and checked before anything is emitted (Python builds the whole list inside its transaction).
//!
//! The tracker is a snapshot: Python deletes every `distro_triage` row of the source and inserts the new ones. Here the
//! stored rows are read page by page (`MirrorView::rows_page`) and compared with the new rows (sorted, last row of a key
//! kept, as `INSERT OR REPLACE`): a delete per stored row whose key left, an upsert per new or changed row, nothing for
//! an equal row. All pages are read before the first operation is emitted. `--limit` upserts its subset without
//! reading or deleting anything (status `partial`), as Python.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::io::{BufRead, BufReader, Read};
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use regex::Regex;
use secmonk_model::{JsonMap, MirrorTable, RowOp};
use secmonk_traits::{
    CallCtx, MAX_VIEW_PAGE, MirrorView, ResultStream, RowsBatch, Source, SourceInfo, StepResult,
    SyncEnd, SyncParams,
};
use serde::de::{self, DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::batch::Limits;
use crate::native::{self, Outcome};
use crate::{decode, feed, py};

/// Source name.
pub const NAME: &str = "debian-tracker";
/// Registration (`crate::IMPORTERS`): rust by default since 2026-11-11 (differential test green).
pub const IMPORTER: crate::Importer = crate::Importer {
    name: NAME,
    default_rust: true,
    new: |view| Arc::new(DebianTrackerSource::new(view)),
};
/// Description (as the Python source's).
pub const DESCRIPTION: &str =
    "Debian Security Tracker: per-release status, urgency, no-dsa and DSA/DLA ids";
/// The tracker JSON.
pub const TRACKER_URL: &str = "https://security-tracker.debian.org/tracker/data/json";
/// Connect and read timeout of the download (httpx `timeout=300.0` of the Python source).
pub const TIMEOUT: Duration = Duration::from_secs(300);

/// Input caps. Worst-case memory within them: rust/_docs/tech/source-debian-tracker.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Downloaded bytes (the Python source's `MAX_DOWNLOAD`).
    pub download: u64,
    /// Decompressed (or plain) JSON bytes (Python: 2 GiB for compressed input, none for plain).
    pub decompressed: u64,
    /// Bytes of one repository list file.
    pub file_bytes: u64,
    /// Bytes of one line of a repository list file.
    pub line_bytes: usize,
    /// Bytes kept for one package of the JSON or one CVE block of `CVE/list` while it is read.
    pub entry_bytes: usize,
    /// Packages of the JSON.
    pub packages: usize,
    /// Rows built.
    pub rows: usize,
    /// Distinct strings kept (packages, CVE ids, versions, notes, ...).
    pub strings: usize,
    /// Bytes of the distinct strings kept.
    pub string_bytes: usize,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            download: 512 * 1024 * 1024,
            decompressed: 1024 * 1024 * 1024,
            file_bytes: 512 * 1024 * 1024,
            line_bytes: 1024 * 1024,
            entry_bytes: 64 * 1024 * 1024,
            packages: 1_000_000,
            rows: 3_000_000,
            strings: 2_000_000,
            string_bytes: 128 * 1024 * 1024,
        }
    }
}

/// The native Debian tracker source.
pub struct DebianTrackerSource {
    view: Arc<dyn MirrorView>,
    url: String,
    limits: Limits,
    caps: Caps,
}

impl fmt::Debug for DebianTrackerSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DebianTrackerSource")
            .field("url", &self.url)
            .field("limits", &self.limits)
            .field("caps", &self.caps)
            .finish_non_exhaustive()
    }
}

// ------------------------------------------------------------------------------------------------ vocabulary

/// codename -> OSV Debian release (`CODENAME_TO_RELEASE`); index = the row's `eco`.
const CODENAMES: [&str; 9] = [
    "wheezy", "jessie", "stretch", "buster", "bullseye", "bookworm", "trixie", "forky", "duke",
];
const ECOSYSTEMS: [&str; 9] = [
    "Debian:7",
    "Debian:8",
    "Debian:9",
    "Debian:10",
    "Debian:11",
    "Debian:12",
    "Debian:13",
    "Debian:14",
    "Debian:15",
];
/// Releases an unbracketed (sid) text line without a fixed version is propagated to.
const IMPLICIT_RELEASES: [&str; 4] = ["bullseye", "bookworm", "trixie", "forky"];
const URGENCIES: [&str; 6] = [
    "unimportant",
    "low",
    "medium",
    "high",
    "not yet assigned",
    "end-of-life",
];
const DEFAULT_URGENCY: &str = "not yet assigned";
const STAR_NOTE: &str = "urgency marked '*' by tracker";

fn release_index(codename: &str) -> Option<u8> {
    CODENAMES.iter().position(|c| *c == codename).map(|i| i as u8)
}

fn is_urgency(u: &str) -> bool {
    URGENCIES.contains(&u)
}

/// `_NODSA_ARGS`.
fn nodsa_arg(arg: &str) -> Option<&'static str> {
    match arg {
        "<no-dsa>" => Some("no-dsa"),
        "<postponed>" => Some("postponed"),
        "<ignored>" | "<end-of-life>" => Some("ignored"),
        _ => None,
    }
}

/// The counters of the sync message (`Stats`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Stats {
    temp: u64,
    sid: u64,
    unknown_release: u64,
    orphan_advisories: u64,
}

impl Stats {
    fn add(&mut self, o: &Stats) {
        self.temp += o.temp;
        self.sid += o.sid;
        self.unknown_release += o.unknown_release;
        self.orphan_advisories += o.orphan_advisories;
    }
}

/// `_release_of`.
fn release_of(codename: &str, stats: &mut Stats) -> Option<u8> {
    let c = py::strip(codename).to_lowercase();
    if c == "sid" || c == "unstable" {
        stats.sid += 1;
        return None;
    }
    let r = release_index(&c);
    if r.is_none() {
        stats.unknown_release += 1;
    }
    r
}

/// `_urgency`: (`'low*'` -> `('low', true)`); lower-cased, `None` for empty.
fn urgency(raw: &str) -> (Option<String>, bool) {
    if raw.is_empty() {
        return (None, false);
    }
    let u = py::strip(raw).to_lowercase();
    let star = u.ends_with('*');
    let u = py::strip(u.trim_end_matches('*'));
    ((!u.is_empty()).then(|| u.to_owned()), star)
}

/// `_join`: the non-empty parts joined with `; `, `None` when nothing is left.
fn join<'a>(parts: impl IntoIterator<Item = Option<&'a str>>) -> Option<String> {
    let s = parts
        .into_iter()
        .flatten()
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    (!s.is_empty()).then_some(s)
}

/// The triage columns of one row before interning.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Triage {
    status: Option<String>,
    urgency: Option<String>,
    fixed: Option<String>,
    nodsa: Option<String>,
    note: Option<String>,
}

// ------------------------------------------------------------------------------------------------ compact rows

/// No string (NULL).
const NONE: u32 = u32::MAX;

/// Distinct strings, each kept once; rows refer to them by index.
#[derive(Debug, Default)]
struct Syms {
    list: Vec<Arc<str>>,
    map: HashMap<Arc<str>, u32>,
    bytes: usize,
    max_strings: usize,
    max_bytes: usize,
}

impl Syms {
    fn new(caps: &Caps) -> Syms {
        Syms {
            max_strings: caps.strings,
            max_bytes: caps.string_bytes,
            ..Syms::default()
        }
    }

    fn id(&mut self, s: &str) -> Result<u32, String> {
        if let Some(&i) = self.map.get(s) {
            return Ok(i);
        }
        if self.list.len() >= self.max_strings {
            return Err(format!(
                "debian-tracker: native importer: more than {} distinct strings; refusing",
                self.max_strings
            ));
        }
        if self.bytes + s.len() > self.max_bytes {
            return Err(format!(
                "debian-tracker: native importer: more than {} bytes of distinct strings; refusing",
                self.max_bytes
            ));
        }
        let a: Arc<str> = Arc::from(s);
        let i = self.list.len() as u32;
        self.bytes += s.len();
        self.list.push(a.clone());
        self.map.insert(a, i);
        Ok(i)
    }

    fn opt(&mut self, s: Option<&str>) -> Result<u32, String> {
        s.map_or(Ok(NONE), |s| self.id(s))
    }

    fn lookup(&self, s: &str) -> Option<u32> {
        self.map.get(s).copied()
    }

    fn get(&self, i: u32) -> Option<&str> {
        if i == NONE {
            None
        } else {
            self.list.get(i as usize).map(|s| &**s)
        }
    }

    fn text(&self, i: u32) -> &str {
        self.get(i).unwrap_or_default()
    }
}

/// One `distro_triage` row: the release index and the string ids of its columns (`source` is always this source).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Row {
    eco: u8,
    pkg: u32,
    cve: u32,
    status: u32,
    urgency: u32,
    fixed: u32,
    nodsa: u32,
    note: u32,
    advisory: u32,
}

impl Row {
    fn new(eco: u8, pkg: u32, cve: u32, t: &Triage, syms: &mut Syms) -> Result<Row, String> {
        Ok(Row {
            eco,
            pkg,
            cve,
            status: syms.opt(t.status.as_deref())?,
            urgency: syms.opt(t.urgency.as_deref())?,
            fixed: syms.opt(t.fixed.as_deref())?,
            nodsa: syms.opt(t.nodsa.as_deref())?,
            note: syms.opt(t.note.as_deref())?,
            advisory: NONE,
        })
    }

    fn key<'a>(&self, s: &'a Syms) -> (&'static str, &'a str, &'a str) {
        (ECOSYSTEMS[self.eco as usize], s.text(self.pkg), s.text(self.cve))
    }

    /// The other columns, in the mirror's order.
    fn values(&self) -> [(&'static str, u32); 6] {
        [
            ("status", self.status),
            ("urgency", self.urgency),
            ("fixed_version", self.fixed),
            ("nodsa", self.nodsa),
            ("note", self.note),
            ("advisory", self.advisory),
        ]
    }

    fn upsert(&self, s: &Syms) -> RowOp {
        let (eco, pkg, cve) = self.key(s);
        let mut row = JsonMap::with_capacity(10);
        row.insert("ecosystem".into(), json!(eco));
        row.insert("package".into(), json!(pkg));
        row.insert("cve_id".into(), json!(cve));
        for (col, v) in self.values() {
            row.insert(col.into(), json!(s.get(v)));
        }
        row.insert("source".into(), json!(NAME));
        RowOp::Upsert {
            table: MirrorTable::DistroTriage,
            row,
        }
    }

    /// Equal to a stored row on every column but the key.
    fn same_as(&self, stored: &JsonMap, s: &Syms) -> bool {
        self.values().iter().all(|(col, v)| match (stored.get(*col), s.get(*v)) {
            (None | Some(Value::Null), None) => true,
            (Some(Value::String(a)), Some(b)) => a == b,
            _ => false,
        })
    }
}

fn row_limit(rows: usize, caps: &Caps) -> Result<(), String> {
    if rows >= caps.rows {
        return Err(format!(
            "debian-tracker: native importer: more than {} rows; refusing",
            caps.rows
        ));
    }
    Ok(())
}

/// What a load produced: the rows in Python's order (duplicate keys possible from the JSON), the strings, counters.
struct Loaded {
    rows: Vec<Row>,
    syms: Syms,
    stats: Stats,
    origin: String,
    /// The JSON's validator or content digest; `None` for a repository checkout (computed from the rows).
    cursor: Option<String>,
}

// ------------------------------------------------------------------------------------------------ JSON input

/// A JSON value as far as the Python code looks at it (type, truthiness, text).
#[derive(Debug, Clone, Default, PartialEq)]
enum Field {
    #[default]
    Absent,
    Null,
    Bool(bool),
    Int(String),
    Float(f64),
    Str(String),
    /// A list; `true` when not empty.
    List(bool),
    /// An object; `true` when not empty.
    Dict(bool),
}

impl Field {
    fn truthy(&self) -> bool {
        match self {
            Field::Absent | Field::Null => false,
            Field::Bool(b) | Field::List(b) | Field::Dict(b) => *b,
            Field::Int(t) => t != "0",
            Field::Float(f) => *f != 0.0,
            Field::Str(s) => !s.is_empty(),
        }
    }

    fn type_name(&self) -> &'static str {
        match self {
            Field::Absent | Field::Null => "NoneType",
            Field::Bool(_) => "bool",
            Field::Int(_) => "int",
            Field::Float(_) => "float",
            Field::Str(_) => "str",
            Field::List(_) => "list",
            Field::Dict(_) => "dict",
        }
    }

    /// Heap bytes held (the text of an int or a string).
    fn heap(&self) -> usize {
        match self {
            Field::Int(s) | Field::Str(s) => s.capacity(),
            _ => 0,
        }
    }
}

/// The visitor methods of every value that is not an object: each builds a [`Field`] and returns `self.other(field)`
/// (a string: `self.text(v)`).
macro_rules! non_objects {
    () => {
        fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
            Ok(self.other(Field::Bool(v)))
        }
        fn visit_i64<E: de::Error>(self, v: i64) -> Result<Self::Value, E> {
            Ok(self.other(Field::Int(v.to_string())))
        }
        fn visit_u64<E: de::Error>(self, v: u64) -> Result<Self::Value, E> {
            Ok(self.other(Field::Int(v.to_string())))
        }
        fn visit_f64<E: de::Error>(self, v: f64) -> Result<Self::Value, E> {
            Ok(self.other(Field::Float(v)))
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
            Ok(self.text(v))
        }
        fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(self.other(Field::Null))
        }
        fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
            Ok(self.other(Field::Null))
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut any = false;
            while seq.next_element::<IgnoredAny>()?.is_some() {
                any = true;
            }
            Ok(self.other(Field::List(any)))
        }
    };
}

/// The shape of a string only (its text is not needed).
fn str_shape(v: &str) -> Field {
    Field::Str(if v.is_empty() { String::new() } else { "x".into() })
}

struct FieldVisitor;

impl FieldVisitor {
    fn other(self, f: Field) -> Field {
        f
    }
    fn text(self, v: &str) -> Field {
        Field::Str(v.to_owned())
    }
}

impl<'de> Visitor<'de> for FieldVisitor {
    type Value = Field;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    non_objects!();

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Field, A::Error> {
        let mut any = false;
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            any = true;
        }
        Ok(Field::Dict(any))
    }
}

impl<'de> serde::Deserialize<'de> for Field {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Field, D::Error> {
        d.deserialize_any(FieldVisitor)
    }
}

/// One release of a CVE entry: the five fields `_json_row` reads, or not an object (skipped).
#[derive(Debug, Clone, Default, PartialEq)]
struct Rel {
    dict: bool,
    status: Field,
    fixed: Field,
    urgency: Field,
    nodsa: Field,
    reason: Field,
}

impl Rel {
    /// Bytes held: the struct and the text of its fields.
    fn size(&self) -> usize {
        size_of::<Rel>()
            + self.status.heap()
            + self.fixed.heap()
            + self.urgency.heap()
            + self.nodsa.heap()
            + self.reason.heap()
    }
}

struct RelVisitor;

impl RelVisitor {
    fn other(self, _: Field) -> Rel {
        Rel::default()
    }
    fn text(self, _: &str) -> Rel {
        Rel::default()
    }
}

impl<'de> Visitor<'de> for RelVisitor {
    type Value = Rel;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a release object")
    }

    non_objects!();

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Rel, A::Error> {
        let mut r = Rel {
            dict: true,
            ..Rel::default()
        };
        while let Some(k) = map.next_key::<String>()? {
            // a repeated key: the last value counts, as in `json.loads`
            match k.as_str() {
                "status" => r.status = map.next_value()?,
                "fixed_version" => r.fixed = map.next_value()?,
                "urgency" => r.urgency = map.next_value()?,
                "nodsa" => r.nodsa = map.next_value()?,
                "nodsa_reason" => r.reason = map.next_value()?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(r)
    }
}

impl<'de> serde::Deserialize<'de> for Rel {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Rel, D::Error> {
        d.deserialize_any(RelVisitor)
    }
}

/// `entry.get("releases") or {}`: nothing (falsy), the releases in dict order (a repeated key keeps its first place
/// and its last value, as a Python dict), or a truthy value that is not an object (its type name).
#[derive(Debug, Clone, Default, PartialEq)]
enum Releases {
    #[default]
    Falsy,
    Dict(Vec<(String, Rel)>),
    Bad(&'static str),
}

struct ReleasesVisitor;

impl ReleasesVisitor {
    fn other(self, f: Field) -> Releases {
        if f.truthy() {
            Releases::Bad(f.type_name())
        } else {
            Releases::Falsy
        }
    }
    fn text(self, v: &str) -> Releases {
        self.other(str_shape(v))
    }
}

impl<'de> Visitor<'de> for ReleasesVisitor {
    type Value = Releases;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("the releases of an entry")
    }

    non_objects!();

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Releases, A::Error> {
        let mut out: Vec<(String, Rel)> = Vec::new();
        let mut at: HashMap<String, usize> = HashMap::new();
        while let Some(k) = map.next_key::<String>()? {
            let v: Rel = map.next_value()?;
            match at.get(&k) {
                Some(&i) => out[i].1 = v,
                None => {
                    at.insert(k.clone(), out.len());
                    out.push((k, v));
                }
            }
        }
        Ok(if out.is_empty() {
            Releases::Falsy
        } else {
            Releases::Dict(out)
        })
    }
}

impl<'de> serde::Deserialize<'de> for Releases {
    fn deserialize<D: de::Deserializer<'de>>(d: D) -> Result<Releases, D::Error> {
        d.deserialize_any(ReleasesVisitor)
    }
}

/// One CVE entry of a package: its releases, or not an object (`None`, skipped).
struct EntryVisitor;

impl EntryVisitor {
    fn other(self, _: Field) -> Option<Releases> {
        None
    }
    fn text(self, _: &str) -> Option<Releases> {
        None
    }
}

impl<'de> Visitor<'de> for EntryVisitor {
    type Value = Option<Releases>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a CVE entry")
    }

    non_objects!();

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut releases = Releases::Falsy;
        while let Some(k) = map.next_key::<String>()? {
            if k == "releases" {
                releases = map.next_value()?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(Some(releases))
    }
}

struct EntrySeed;

impl<'de> DeserializeSeed<'de> for EntrySeed {
    type Value = Option<Releases>;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(EntryVisitor)
    }
}

/// Bytes the releases of an entry hold while their package is read: per release its slot in the list, its slot in the
/// key map of [`ReleasesVisitor`], the key twice (list and map) and the [`Rel`].
fn releases_size(r: &Option<Releases>) -> usize {
    match r {
        Some(Releases::Dict(v)) => v
            .iter()
            .map(|(k, r)| {
                size_of::<(String, Rel)>() + size_of::<(String, usize)>() + 2 * k.capacity() + r.size()
            })
            .sum(),
        _ => 0,
    }
}

/// What one package of the JSON produced: its rows and counters, or the error Python would raise on it.
#[derive(Debug, Default)]
struct PkgOut {
    rows: Vec<Row>,
    stats: Stats,
    error: Option<String>,
}

/// The state of a JSON parse.
struct JsonCtx {
    caps: Caps,
    syms: Syms,
    rows: usize,
    packages: BTreeMap<String, PkgOut>,
}

/// A refusal of the parse (a cap): passes through serde as a custom error.
fn refusal<E: de::Error>(m: String) -> E {
    E::custom(m)
}

/// `str(fixed)` of a `fixed_version` that is not `None` / `""`.
fn fixed_text(f: &Field, where_: &dyn Fn() -> String) -> Result<Option<String>, String> {
    Ok(match f {
        Field::Absent | Field::Null => None,
        Field::Str(s) if s.is_empty() => None,
        Field::Str(s) | Field::Int(s) => Some(s.clone()),
        Field::Bool(b) => Some(if *b { "True" } else { "False" }.into()),
        Field::Float(x) => Some(py::float_repr(*x)),
        Field::List(_) | Field::Dict(_) => {
            return Err(format!(
                "debian-tracker: {}: fixed_version is a {}; refusing",
                where_(),
                f.type_name()
            ));
        }
    })
}

fn no_attribute(f: &Field, attr: &str) -> String {
    format!("AttributeError: {}", py::no_attr(f.type_name(), attr))
}

/// `_json_row` without the key: the triage columns of one release, or Python's exception text.
fn json_row(rel: &Rel, where_: &dyn Fn() -> String) -> Result<Triage, String> {
    // `(rel.get("status") or "").lower() or None`
    let mut status = match &rel.status {
        f if !f.truthy() => None,
        Field::Str(s) => Some(s.to_lowercase()).filter(|s| !s.is_empty()),
        f => return Err(no_attribute(f, "lower")),
    };
    let fixed = fixed_text(&rel.fixed, where_)?;
    if status.as_deref() == Some("resolved") && fixed.as_deref() == Some("0") {
        status = Some("not-affected".into());
    }
    let (urg, star) = match &rel.urgency {
        f if !f.truthy() => (None, false),
        Field::Str(s) => urgency(s),
        f => return Err(no_attribute(f, "strip")),
    };
    let nodsa_text = &rel.nodsa;
    let reason = match &rel.reason {
        f if !f.truthy() => String::new(),
        Field::Str(s) => py::strip(s).to_lowercase(),
        f => return Err(no_attribute(f, "strip")),
    };
    let known = reason == "postponed" || reason == "ignored";
    let nodsa = (!matches!(nodsa_text, Field::Absent | Field::Null) || known)
        .then(|| if known { reason.clone() } else { "no-dsa".into() });
    let text = match nodsa_text {
        Field::Str(s) => Some(py::strip(s)),
        _ => None,
    };
    Ok(Triage {
        status,
        urgency: urg,
        fixed,
        nodsa,
        note: join([text, star.then_some(STAR_NOTE)]),
    })
}

/// The rows of one package (`rows_from_json` for one `pkg`), entries in dict order.
fn package_rows(
    pkg: &str,
    entries: &[(String, Option<Releases>)],
    ctx: &mut JsonCtx,
) -> Result<PkgOut, String> {
    let mut out = PkgOut::default();
    let pkg_l = pkg.to_lowercase();
    let mut pkg_id = None;
    for (cve, entry) in entries {
        let Some(releases) = entry else { continue };
        if !cve.starts_with("CVE-") {
            out.stats.temp += 1; // TEMP-* (no stable id, cannot match advisories)
            continue;
        }
        let list = match releases {
            Releases::Falsy => continue,
            Releases::Bad(t) => {
                out.error = Some(format!("AttributeError: {}", py::no_attr(t, "items")));
                return Ok(out);
            }
            Releases::Dict(l) => l,
        };
        for (codename, rel) in list {
            if !rel.dict {
                continue;
            }
            let Some(eco) = release_of(codename, &mut out.stats) else {
                continue;
            };
            let where_ = || format!("{pkg} {cve} {codename}");
            let t = match json_row(rel, &where_) {
                Ok(t) => t,
                Err(e) => {
                    out.error = Some(e);
                    return Ok(out);
                }
            };
            row_limit(ctx.rows, &ctx.caps)?;
            let p = match pkg_id {
                Some(p) => p,
                None => *pkg_id.insert(ctx.syms.id(&pkg_l)?),
            };
            let c = ctx.syms.id(cve)?;
            out.rows.push(Row::new(eco, p, c, &t, &mut ctx.syms)?);
            ctx.rows += 1;
        }
    }
    Ok(out)
}

/// One package value: its CVE entries (a repeated key keeps its first place and its last value), then its rows.
struct PackageSeed<'a> {
    ctx: &'a mut JsonCtx,
    name: &'a str,
}

impl<'de> DeserializeSeed<'de> for PackageSeed<'_> {
    type Value = PkgOut;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<PkgOut, D::Error> {
        d.deserialize_any(self)
    }
}

impl PackageSeed<'_> {
    fn other(self, _: Field) -> PkgOut {
        PkgOut::default() // `if not isinstance(cves, dict): continue`
    }
    fn text(self, _: &str) -> PkgOut {
        PkgOut::default()
    }
}

impl<'de> Visitor<'de> for PackageSeed<'_> {
    type Value = PkgOut;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a package object")
    }

    non_objects!();

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<PkgOut, A::Error> {
        let mut entries: Vec<(String, Option<Releases>)> = Vec::new();
        let mut at: HashMap<String, usize> = HashMap::new();
        let mut bytes = 0usize;
        while let Some(k) = map.next_key::<String>()? {
            let v = map.next_value_seed(EntrySeed)?;
            // the entry's slot in `entries` and in `at`, its key twice, its releases
            bytes += size_of::<(String, Option<Releases>)>()
                + size_of::<(String, usize)>()
                + 2 * k.capacity()
                + releases_size(&v);
            if bytes > self.ctx.caps.entry_bytes {
                return Err(refusal(format!(
                    "debian-tracker: native importer: package {} holds more than {} bytes of release data; refusing",
                    short(self.name),
                    self.ctx.caps.entry_bytes
                )));
            }
            match at.get(&k) {
                Some(&i) => entries[i].1 = v,
                None => {
                    at.insert(k.clone(), entries.len());
                    entries.push((k, v));
                }
            }
        }
        package_rows(self.name, &entries, self.ctx).map_err(refusal)
    }
}

/// A name in a message: at most 80 characters.
fn short(s: &str) -> String {
    let mut out: String = s.chars().take(80).collect();
    if out.len() < s.len() {
        out.push_str("...");
    }
    out
}

/// The top level: `true` for an object (its packages collected in `ctx`), `false` for anything else (consumed).
struct TopVisitor<'a> {
    ctx: &'a mut JsonCtx,
}

impl TopVisitor<'_> {
    fn other(self, _: Field) -> bool {
        false
    }
    fn text(self, _: &str) -> bool {
        false
    }
}

impl<'de> Visitor<'de> for TopVisitor<'_> {
    type Value = bool;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    non_objects!();

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<bool, A::Error> {
        while let Some(name) = map.next_key::<String>()? {
            let out = map.next_value_seed(PackageSeed {
                ctx: &mut *self.ctx,
                name: &name,
            })?;
            // a repeated package: the last value counts, as in `json.loads`
            self.ctx.packages.insert(name, out);
            if self.ctx.packages.len() > self.ctx.caps.packages {
                return Err(refusal(format!(
                    "debian-tracker: native importer: more than {} packages; refusing",
                    self.ctx.caps.packages
                )));
            }
        }
        Ok(true)
    }
}

impl<'de> DeserializeSeed<'de> for TopVisitor<'_> {
    type Value = bool;

    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<bool, D::Error> {
        d.deserialize_any(self)
    }
}

/// `load_json_bytes` + `rows_from_json`: the rows of the tracker JSON read from `r`, the first `limit` packages
/// (sorted by name) when given, and the SHA-256 of the decompressed content.
fn parse_json<R: Read>(r: R, caps: Caps, limit: Option<u64>) -> Result<(Loaded, String), String> {
    let messages = decode::Messages {
        source: NAME,
        too_large: format!(
            "debian-tracker: native importer: the document is larger than {} bytes; refusing",
            caps.decompressed
        ),
        too_large_gzip: format!(
            "DecompressError: decompressed data exceeds the {} byte limit",
            caps.decompressed
        ),
    };
    let mut input = decode::open_decoded(r, caps.decompressed, &messages)?;
    let mut ctx = JsonCtx {
        caps,
        syms: Syms::new(&caps),
        rows: 0,
        packages: BTreeMap::new(),
    };
    let parsed = {
        let mut de = serde_json::Deserializer::from_reader(BufReader::with_capacity(
            64 * 1024,
            &mut input,
        ));
        TopVisitor { ctx: &mut ctx }
            .deserialize(&mut de)
            .and_then(|object| de.end().map(|()| object))
    };
    let object = match parsed {
        Ok(o) => o,
        Err(e) => {
            // an I/O error under the parser (a cap, the download) is the message, not serde's text of it
            if let Some(m) = input.take_error() {
                return Err(m);
            }
            return Err(feed::json_error(&e, &["debian-tracker: "]));
        }
    };
    // the rest of the input (nothing but what `end` saw): hashed, and a gzip trailer checked
    if let Err(e) = std::io::copy(&mut input, &mut std::io::sink()) {
        return Err(input.message(&e));
    }
    if !object {
        return Err("TypeError: tracker JSON: top level is not an object".into());
    }
    let digest = input.sha256();
    let mut rows = Vec::new();
    let mut stats = Stats::default();
    let n = limit.map_or(usize::MAX, |l| usize::try_from(l).unwrap_or(usize::MAX));
    for (_, out) in ctx.packages.into_iter().take(n) {
        if let Some(e) = out.error {
            return Err(e);
        }
        stats.add(&out.stats);
        rows.extend(out.rows);
    }
    Ok((
        Loaded {
            rows,
            syms: ctx.syms,
            stats,
            origin: String::new(),
            cursor: None,
        },
        digest,
    ))
}

// ------------------------------------------------------------------------------------------------ text input

/// `\s` of Python's `re` (`str.isspace`): Unicode White_Space plus `\x1c`-`\x1f`.
macro_rules! ws {
    () => {
        r"[\s\x1c-\x1f]"
    };
}
macro_rules! nws {
    () => {
        r"[^\s\x1c-\x1f]"
    };
}

static CVE_HEAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(CVE-\d{4}-\d{4,}|TEMP-",
        nws!(),
        r"+)(?:",
        ws!(),
        r"|$)"
    ))
    .expect("CVE_HEAD")
});
static PKG_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^\t(?:\[(?P<rel>[A-Za-z0-9._-]+)\]",
        ws!(),
        r"+)?-",
        ws!(),
        r"+(?P<pkg>[^\s\x1c-\x1f<>]+)(?:",
        ws!(),
        r"+(?P<arg>",
        nws!(),
        r"+))?(?:",
        ws!(),
        r"+\((?P<paren>.*)\))?",
        ws!(),
        r"*$"
    ))
    .expect("PKG_LINE")
});
static ADV_HEAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"^(?:\[[^\]]*\]",
        ws!(),
        r"+)?((?:DSA|DLA|DTSA)-\d+(?:-\d+)?)",
        ws!()
    ))
    .expect("ADV_HEAD")
});
static CVE_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"CVE-\d{4}-\d{4,}").expect("CVE_ID"));

/// A package line: `(release, package lower-cased, arg, parenthesis)`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PkgLine {
    rel: Option<String>,
    pkg: String,
    arg: Option<String>,
    paren: Option<String>,
}

fn pkg_line(line: &str) -> Option<PkgLine> {
    let m = PKG_LINE.captures(line)?;
    let s = |n: &str| m.name(n).map(|x| x.as_str().to_owned());
    Some(PkgLine {
        rel: s("rel"),
        pkg: m.name("pkg")?.as_str().to_lowercase(),
        arg: s("arg"),
        paren: s("paren"),
    })
}

/// `_split_paren`: (urgency, note) from the parenthesized suffix of a package line.
fn split_paren(paren: Option<&str>, whole_is_note: bool) -> (Option<String>, Option<String>) {
    let Some(paren) = paren.filter(|p| !p.is_empty()) else {
        return (None, None);
    };
    let p = py::strip(paren);
    let (u, _) = urgency(p);
    if u.as_deref().is_some_and(is_urgency) {
        return (u, None);
    }
    if whole_is_note {
        return (None, Some(p.to_owned()));
    }
    let mut urg = None;
    let mut notes = Vec::new();
    for tok in p.split(';').map(py::strip) {
        let (tu, _) = urgency(tok);
        if tu.as_deref().is_some_and(is_urgency) {
            urg = tu;
        } else if !tok.is_empty() && !tok.to_lowercase().starts_with("bug #") {
            notes.push(Some(tok));
        }
    }
    (urg, join(notes))
}

fn note_only(arg: Option<&str>) -> bool {
    arg.is_some_and(|a| nodsa_arg(a).is_some() || a == "<not-affected>")
}

/// `_text_row` without the key: `None` for forms that carry no triage (`<itp>`, `<removed>`, a bare package).
fn text_row(arg: Option<&str>, paren: Option<&str>, inherited: Option<&str>) -> Option<Triage> {
    let arg = arg?;
    let (mut urg, note) = split_paren(paren, note_only(Some(arg)));
    let (status, fixed, nodsa) = match arg {
        "<unfixed>" => ("open", None, None),
        "<undetermined>" => ("undetermined", None, None),
        "<not-affected>" => ("not-affected", Some("0"), None),
        a => match nodsa_arg(a) {
            Some(n) => {
                if a == "<end-of-life>" {
                    urg = urg.or_else(|| Some("end-of-life".into()));
                }
                ("open", None, Some(n))
            }
            None if a.starts_with('<') => return None,
            None => ("resolved", Some(a), None),
        },
    };
    Some(Triage {
        status: Some(status.into()),
        urgency: Some(
            urg.or_else(|| inherited.map(str::to_owned))
                .unwrap_or_else(|| DEFAULT_URGENCY.into()),
        ),
        fixed: fixed.map(str::to_owned),
        nodsa: nodsa.map(str::to_owned),
        note,
    })
}

/// The rows of a repository checkout, keyed `(release, package, CVE)`: a later row of a key replaces the earlier one
/// in place (the `out` dict of `rows_from_cve_list`).
struct RepoRows {
    caps: Caps,
    syms: Syms,
    rows: Vec<Row>,
    at: HashMap<(u8, u32, u32), usize>,
    stats: Stats,
}

impl RepoRows {
    fn put(&mut self, eco: u8, pkg: &str, cve: &str, t: &Triage) -> Result<(), String> {
        let p = self.syms.id(pkg)?;
        let c = self.syms.id(cve)?;
        let row = Row::new(eco, p, c, t, &mut self.syms)?;
        match self.at.get(&(eco, p, c)) {
            Some(&i) => self.rows[i] = row,
            None => {
                row_limit(self.rows.len(), &self.caps)?;
                self.at.insert((eco, p, c), self.rows.len());
                self.rows.push(row);
            }
        }
        Ok(())
    }
}

/// `rows_from_cve_list`, one line at a time.
struct CveList {
    cve: Option<String>,
    block: Vec<PkgLine>,
    bytes: usize,
}

impl CveList {
    fn new() -> CveList {
        CveList {
            cve: None,
            block: Vec::new(),
            bytes: 0,
        }
    }

    fn line(&mut self, line: &str, out: &mut RepoRows) -> Result<(), String> {
        if line.is_empty() || line.starts_with("\t\t") {
            return Ok(());
        }
        if !line.starts_with('\t') {
            self.flush(out)?;
            self.block.clear();
            self.bytes = 0;
            self.cve = match CVE_HEAD.captures(line) {
                Some(c) if c[1].starts_with("CVE-") => Some(c[1].to_owned()),
                Some(_) => {
                    out.stats.temp += 1;
                    None
                }
                None => None,
            };
            return Ok(());
        }
        if self.cve.is_none() {
            return Ok(());
        }
        if let Some(p) = pkg_line(line) {
            self.bytes += size_of::<PkgLine>() + line.len();
            if self.bytes > out.caps.entry_bytes {
                return Err(format!(
                    "debian-tracker: native importer: an entry of CVE/list holds more than {} bytes; refusing",
                    out.caps.entry_bytes
                ));
            }
            self.block.push(p);
        }
        Ok(())
    }

    /// `flush` of `rows_from_cve_list`.
    fn flush(&mut self, out: &mut RepoRows) -> Result<(), String> {
        let Some(cve) = self.cve.as_deref() else {
            return Ok(());
        };
        // first pass: urgency from the sid lines
        let mut sid_urg: HashMap<&str, Option<String>> = HashMap::new();
        for l in self.block.iter().filter(|l| l.rel.is_none()) {
            sid_urg.insert(
                &l.pkg,
                split_paren(l.paren.as_deref(), note_only(l.arg.as_deref())).0,
            );
        }
        let mut explicit: HashSet<(u8, &str)> = HashSet::new();
        for l in &self.block {
            let Some(rel) = &l.rel else { continue };
            let Some(eco) = release_of(rel, &mut out.stats) else {
                continue;
            };
            explicit.insert((eco, &l.pkg));
            let inherited = sid_urg.get(l.pkg.as_str()).cloned().flatten();
            if let Some(t) = text_row(l.arg.as_deref(), l.paren.as_deref(), inherited.as_deref()) {
                out.put(eco, &l.pkg, cve, &t)?;
            }
        }
        // sid lines: skipped, but open / not-affected states propagate to unlisted releases
        for l in self.block.iter().filter(|l| l.rel.is_none()) {
            out.stats.sid += 1;
            if !matches!(
                l.arg.as_deref(),
                Some("<unfixed>" | "<undetermined>" | "<not-affected>")
            ) {
                continue;
            }
            for codename in IMPLICIT_RELEASES {
                let Some(eco) = release_index(codename) else {
                    continue;
                };
                if explicit.contains(&(eco, l.pkg.as_str())) {
                    continue;
                }
                if let Some(t) = text_row(l.arg.as_deref(), l.paren.as_deref(), None) {
                    out.put(eco, &l.pkg, cve, &t)?;
                }
            }
        }
        Ok(())
    }
}

/// `parse_advisory_list` + `attach_advisories`, one line at a time: each advisory is matched against the rows when
/// its block ends (the rows are complete by then). `chosen` holds per row the first advisory that names it, replaced
/// once by the first advisory whose version equals the row's fixed version.
struct AdvList {
    adv: Option<String>,
    cves: Vec<String>,
    rels: Vec<(String, String, String)>,
    bytes: usize,
}

impl AdvList {
    fn new() -> AdvList {
        AdvList {
            adv: None,
            cves: Vec::new(),
            rels: Vec::new(),
            bytes: 0,
        }
    }

    fn line(
        &mut self,
        line: &str,
        out: &mut RepoRows,
        chosen: &mut HashMap<usize, (String, bool)>,
    ) -> Result<(), String> {
        if py::strip(line).is_empty() {
            return Ok(());
        }
        if !line.starts_with('\t') {
            self.flush(out, chosen);
            self.adv = ADV_HEAD.captures(line).map(|c| c[1].to_owned());
            self.cves.clear();
            self.rels.clear();
            self.bytes = 0;
            return Ok(());
        }
        // a kept line: its CVE ids or its `(release, package, version)` (at most the line's text), plus a slot
        self.bytes += size_of::<(String, String, String)>() + line.len();
        if self.bytes > out.caps.entry_bytes {
            return Err(format!(
                "debian-tracker: native importer: an entry of an advisory list holds more than {} bytes; refusing",
                out.caps.entry_bytes
            ));
        }
        let s = py::strip(line);
        if s.starts_with('{') {
            self.cves
                .extend(CVE_ID.find_iter(s).map(|m| m.as_str().to_owned()));
            return Ok(());
        }
        if let Some(p) = pkg_line(line)
            && let (Some(rel), Some(arg)) = (p.rel, p.arg)
            && !arg.starts_with('<')
        {
            self.rels.push((rel.to_lowercase(), p.pkg, arg));
        }
        Ok(())
    }

    fn flush(&mut self, out: &mut RepoRows, chosen: &mut HashMap<usize, (String, bool)>) {
        let Some(adv) = &self.adv else { return };
        for (codename, pkg, ver) in &self.rels {
            let Some(eco) = release_index(codename) else {
                continue;
            };
            for cve in &self.cves {
                let row = match (out.syms.lookup(pkg), out.syms.lookup(cve)) {
                    (Some(p), Some(c)) => out.at.get(&(eco, p, c)).copied(),
                    _ => None,
                };
                let Some(i) = row else {
                    out.stats.orphan_advisories += 1;
                    continue;
                };
                let exact = out.syms.get(out.rows[i].fixed) == Some(ver.as_str());
                match chosen.get(&i) {
                    Some((_, true)) => {}
                    Some((_, false)) if !exact => {}
                    _ => {
                        chosen.insert(i, (adv.clone(), exact));
                    }
                }
            }
        }
    }
}

/// Read a text file line by line as Python's text mode does (`errors="replace"`, universal newlines: `\n`, `\r\n`
/// and `\r` end a line). Not a regular file (or missing): nothing, as `_read_text`.
fn read_lines(
    path: &Path,
    caps: &Caps,
    mut f: impl FnMut(&str) -> Result<(), String>,
) -> Result<(), String> {
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => {}
        _ => return Ok(()),
    }
    let file = feed::open_regular(path).map_err(|e| e.with_class())?;
    let shown = feed::py_path(path);
    let len = file.metadata().map(|m| m.len()).unwrap_or(0);
    if len > caps.file_bytes {
        return Err(format!(
            "debian-tracker: native importer: {shown} is larger than {} bytes; refusing",
            caps.file_bytes
        ));
    }
    let mut r = BufReader::with_capacity(64 * 1024, file.take(caps.file_bytes));
    let mut buf = Vec::new();
    loop {
        buf.clear();
        // at most one line (and its `\n`) past the cap: refused before it is buffered whole
        let n = (&mut r)
            .take(caps.line_bytes as u64 + 1)
            .read_until(b'\n', &mut buf)
            .map_err(|e| format!("{}: {}", feed::py_exception(&e), feed::os_error(&e, path)))?;
        if n == 0 {
            return Ok(());
        }
        let ended = buf.last() == Some(&b'\n');
        if ended {
            buf.pop();
        } else if buf.len() > caps.line_bytes {
            return Err(format!(
                "debian-tracker: native importer: {shown}: a line is longer than {} bytes; refusing",
                caps.line_bytes
            ));
        }
        for piece in buf.split(|b| *b == b'\r') {
            f(&String::from_utf8_lossy(piece))?;
        }
    }
}

/// `load_repo`: `CVE/list`, then the advisories of `DSA/list` and `DLA/list`; `limit` keeps the rows of the first
/// `limit` package names (sorted).
fn load_repo(root: &Path, caps: Caps, limit: Option<u64>) -> Result<Loaded, String> {
    let data = if root.join("data").is_dir() {
        root.join("data")
    } else {
        root.to_path_buf()
    };
    let mut out = RepoRows {
        caps,
        syms: Syms::new(&caps),
        rows: Vec::new(),
        at: HashMap::new(),
        stats: Stats::default(),
    };
    let mut list = CveList::new();
    read_lines(&data.join("CVE").join("list"), &caps, |l| list.line(l, &mut out))?;
    list.flush(&mut out)?;
    let mut chosen: HashMap<usize, (String, bool)> = HashMap::new();
    for name in ["DSA", "DLA"] {
        let mut adv = AdvList::new();
        read_lines(&data.join(name).join("list"), &caps, |l| {
            adv.line(l, &mut out, &mut chosen)
        })?;
        adv.flush(&mut out, &mut chosen);
    }
    for (i, (adv, _)) in chosen {
        out.rows[i].advisory = out.syms.id(&adv)?;
    }
    let RepoRows {
        mut rows, syms, stats, ..
    } = out;
    if let Some(n) = limit {
        let names: std::collections::BTreeSet<&str> =
            rows.iter().map(|r| syms.text(r.pkg)).collect();
        let keep: HashSet<&str> = names
            .into_iter()
            .take(usize::try_from(n).unwrap_or(usize::MAX))
            .collect();
        rows.retain(|r| keep.contains(syms.text(r.pkg)));
    }
    Ok(Loaded {
        rows,
        syms,
        stats,
        origin: format!("repo checkout {}", feed::py_path(root)),
        cursor: None,
    })
}

// ------------------------------------------------------------------------------------------------ cursor of a checkout

/// `sha256(repr(sorted(rows)))` of a checkout's rows (`rows` sorted by key, keys distinct).
fn repo_cursor(rows: &[Row], s: &Syms) -> String {
    let mut h = Sha256::new();
    let mut piece = String::new();
    h.update(b"[");
    for (i, r) in rows.iter().enumerate() {
        piece.clear();
        if i > 0 {
            piece.push_str(", ");
        }
        piece.push('(');
        let (eco, pkg, cve) = r.key(s);
        let cols = [Some(eco), Some(pkg), Some(cve)]
            .into_iter()
            .chain(r.values().into_iter().map(|(_, v)| s.get(v)));
        for (j, v) in cols.enumerate() {
            if j > 0 {
                piece.push_str(", ");
            }
            match v {
                Some(t) => py::repr_str_into(t, &mut piece),
                None => piece.push_str("None"),
            }
        }
        piece.push(')');
        h.update(piece.as_bytes());
    }
    h.update(b"]");
    decode::hex(&h.finalize())
}

/// The rows sorted by key, the last row of each key kept (`INSERT OR REPLACE` in Python's order).
fn sorted_unique(mut rows: Vec<Row>, s: &Syms) -> Vec<Row> {
    rows.sort_by(|a, b| a.key(s).cmp(&b.key(s))); // stable: equal keys keep Python's order
    let mut out: Vec<Row> = Vec::with_capacity(rows.len());
    for r in rows {
        match out.last_mut() {
            Some(last) if last.key(s) == r.key(s) => *last = r,
            _ => out.push(r),
        }
    }
    out.shrink_to_fit();
    out
}

// ------------------------------------------------------------------------------------------------ the source

async fn blocking<T: Send + 'static>(
    job: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    tokio::task::spawn_blocking(job)
        .await
        .map_err(|e| format!("debian-tracker: native importer: parse task failed: {e}"))?
}

impl DebianTrackerSource {
    /// The source over a read-only view of the mirror.
    pub fn new(view: Arc<dyn MirrorView>) -> DebianTrackerSource {
        DebianTrackerSource {
            view,
            url: TRACKER_URL.into(),
            limits: Limits::default(),
            caps: Caps::default(),
        }
    }

    /// Another tracker URL (tests: a local server; `http://` is then allowed).
    pub fn with_url(mut self, url: &str) -> DebianTrackerSource {
        self.url = url.into();
        self
    }

    /// Other batch limits (tests: several batches out of a small fixture).
    pub fn with_limits(mut self, limits: Limits) -> DebianTrackerSource {
        self.limits = limits;
        self
    }

    /// Other input caps.
    pub fn with_caps(mut self, caps: Caps) -> DebianTrackerSource {
        self.caps = caps;
        self
    }

    async fn run(&self, params: &SyncParams) -> StepResult<ResultStream<RowsBatch, SyncEnd>> {
        let t0 = Instant::now();
        let opts = &params.options;
        let limit = native::limit(opts)?;
        let full = opts.full.unwrap_or(false);
        let path = opts.path.clone().flatten().filter(|p| !p.is_empty());
        let caps = self.caps;
        let loaded = match path.map(PathBuf::from) {
            Some(p) if tokio::fs::metadata(&p).await.is_ok_and(|m| m.is_dir()) => {
                blocking(move || load_repo(&p, caps, limit)).await
            }
            Some(p) => {
                blocking(move || {
                    let f = feed::open_regular(&p).map_err(|e| e.with_class())?;
                    let (mut l, digest) = parse_json(f, caps, limit)?;
                    l.origin = format!("file {}", feed::py_path(&p));
                    l.cursor = Some(digest);
                    Ok(l)
                })
                .await
            }
            None => self.load_remote(limit).await,
        };
        let outcome = match loaded {
            Ok(l) => self.outcome(l, limit, full).await?,
            Err(message) => Outcome::error(message),
        };
        let first = native::first_seq(self.view.as_ref(), NAME).await?;
        Ok(native::stream(NAME, outcome, first, self.limits, t0))
    }

    /// `_download` + `load_json_bytes`, the body parsed as it arrives. Cursor: `ETag`, else `Last-Modified`, else the
    /// SHA-256 of the decompressed content.
    async fn load_remote(&self, limit: Option<u64>) -> Result<Loaded, String> {
        let shown = secmonk_safeio::strip_url_secrets(&self.url, false);
        let caps = self.caps;
        let get = feed::Get {
            url: &self.url,
            max_bytes: caps.download,
            allow_http: !self.url.starts_with("https://"),
            timeout: TIMEOUT,
            accept: None,
            too_large: Some(format!(
                "ValueError: tracker download exceeds {} bytes",
                caps.download
            )),
            same_origin_redirects: false,
        };
        let ((mut l, digest), v) =
            feed::get_streamed(&get, move |r| parse_json(r, caps, limit)).await?;
        l.origin = feed::scrub(&shown);
        l.cursor = Some(v.etag.or(v.last_modified).unwrap_or(digest));
        Ok(l)
    }

    /// The guard, then the operations: with `limit` an upsert per row; else the stored rows compared page by page.
    async fn outcome(&self, l: Loaded, limit: Option<u64>, full: bool) -> StepResult<Outcome> {
        let Loaded {
            rows,
            syms,
            stats,
            origin,
            cursor,
        } = l;
        let n = rows.len() as u64;
        let limited = limit.is_some();
        if !limited && !full {
            let old = self
                .view
                .count_rows(MirrorTable::DistroTriage, NAME)
                .await?;
            if let Some(refusal) = native::snapshot_guard(old, n, full) {
                return Ok(Outcome::error(format!("debian-tracker: {refusal}")));
            }
        }
        let job = tokio::task::spawn_blocking(move || {
            let rows = sorted_unique(rows, &syms);
            let cursor = match cursor {
                Some(c) => Some(c),
                None if !limited => Some(repo_cursor(&rows, &syms)),
                None => None,
            };
            (rows, syms, cursor)
        });
        let (rows, mut syms, cursor) = job
            .await
            .map_err(|e| native::internal(NAME, format!("sort task failed: {e}")))?;
        let mut message = format!(
            "{n} triage rows from {origin}; skipped {} TEMP ids, {} sid entries, {} unknown-release entries",
            stats.temp, stats.sid, stats.unknown_release
        );
        if stats.orphan_advisories > 0 {
            message.push_str(&format!(
                "; {} advisory refs without a matching row",
                stats.orphan_advisories
            ));
        }
        if limited {
            // a debug subset: upserted without reading or deleting anything
            let syms = Arc::new(syms);
            return Ok(Outcome {
                status: "partial".into(),
                records: n,
                total: None,
                cursor: None,
                message: Some(message),
                ops: native::iter_ops(rows.into_iter().map(move |r| r.upsert(&syms))),
            });
        }
        // the stored rows, page by page: unchanged ones skipped, keys that left deleted (every page is read before the
        // first operation is emitted, so the pages never see this run's own writes)
        syms.max_strings = usize::MAX;
        syms.max_bytes = usize::MAX;
        let mut unchanged = vec![false; rows.len()];
        let mut deletes: Vec<(u8, u32, u32)> = Vec::new();
        let mut odd: Vec<JsonMap> = Vec::new();
        let mut after = None;
        loop {
            let page = self
                .view
                .rows_page(MirrorTable::DistroTriage, NAME, after, MAX_VIEW_PAGE)
                .await?;
            for r in &page.rows {
                let text = |c: &str| r.get(c).and_then(Value::as_str);
                let (Some(e), Some(p), Some(c)) =
                    (text("ecosystem"), text("package"), text("cve_id"))
                else {
                    // a key that is not text (not written by this source): deleted by its stored values
                    odd.push(
                        ["ecosystem", "package", "cve_id", "source"]
                            .iter()
                            .map(|k| ((*k).to_owned(), r.get(*k).cloned().unwrap_or(Value::Null)))
                            .collect(),
                    );
                    continue;
                };
                match rows.binary_search_by(|x| x.key(&syms).cmp(&(e, p, c))) {
                    Ok(i) => unchanged[i] = rows[i].same_as(r, &syms),
                    Err(_) => {
                        let eco = ECOSYSTEMS.iter().position(|x| *x == e);
                        match eco {
                            Some(eco) => deletes.push((
                                eco as u8,
                                syms.id(p).map_err(|m| native::internal(NAME, m))?,
                                syms.id(c).map_err(|m| native::internal(NAME, m))?,
                            )),
                            None => odd.push(delete_key(json!(e), json!(p), json!(c))),
                        }
                    }
                }
            }
            match page.next {
                Some(next) => after = Some(next),
                None => break,
            }
        }
        let syms = Arc::new(syms);
        let s2 = syms.clone();
        let deletes = odd.into_iter().chain(deletes.into_iter().map(move |(e, p, c)| {
            delete_key(
                json!(ECOSYSTEMS[e as usize]),
                json!(s2.text(p)),
                json!(s2.text(c)),
            )
        }));
        let upserts = rows
            .into_iter()
            .zip(unchanged)
            .filter(|(_, same)| !same)
            .map(move |(r, _)| r.upsert(&syms));
        Ok(Outcome {
            status: "ok".into(),
            records: n,
            total: None,
            cursor,
            message: Some(message),
            ops: native::iter_ops(
                deletes
                    .map(|key| RowOp::Delete {
                        table: MirrorTable::DistroTriage,
                        key,
                    })
                    .chain(upserts),
            ),
        })
    }
}

fn delete_key(e: Value, p: Value, c: Value) -> JsonMap {
    let mut key = JsonMap::with_capacity(4);
    key.insert("ecosystem".into(), e);
    key.insert("package".into(), p);
    key.insert("cve_id".into(), c);
    key.insert("source".into(), json!(NAME));
    key
}

#[async_trait]
impl Source for DebianTrackerSource {
    fn sources(&self) -> Vec<SourceInfo> {
        vec![SourceInfo {
            name: NAME.into(),
            description: DESCRIPTION.into(),
            in_all: true, // as `py-sources` (the Python source sets no `in_all = False`)
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

    /// Rows as their column values (`None` = NULL).
    type Dumped = Vec<Vec<Option<String>>>;

    fn json_rows(doc: &str, limit: Option<u64>) -> Result<(Dumped, Stats), String> {
        let (l, _) = parse_json(doc.as_bytes(), caps(), limit)?;
        Ok((dump(&l.rows, &l.syms), l.stats))
    }

    fn dump(rows: &[Row], s: &Syms) -> Dumped {
        rows.iter()
            .map(|r| {
                let (e, p, c) = r.key(s);
                [Some(e.to_owned()), Some(p.to_owned()), Some(c.to_owned())]
                    .into_iter()
                    .chain(r.values().into_iter().map(|(_, v)| s.get(v).map(str::to_owned)))
                    .collect()
            })
            .collect()
    }

    fn o(s: &str) -> Option<String> {
        Some(s.to_owned())
    }

    #[test]
    fn json_rows_follow_rows_from_json() {
        let doc = r#"{
          "Zlib": {"CVE-2024-1": {"releases": {
              "bookworm": {"status": "Resolved", "fixed_version": "0", "urgency": " Low* "},
              "sid": {"status": "open"}, "etch": {"status": "open"}, "bad": 5,
              "bullseye": {"status": "open", "nodsa": " Minor ", "nodsa_reason": "Postponed"},
              "trixie": {"status": "open", "nodsa": 3},
              "forky": {"fixed_version": 1.0, "nodsa_reason": "other"}}},
            "TEMP-1": {"releases": {"bookworm": {}}}, "CVE-2024-2": 5, "CVE-2024-3": {"releases": []}},
          "apt": [1], "b": {"CVE-2024-9": {"releases": {"Bookworm": {"status": "open"}, " bookworm ": {"status": "x"}}}}
        }"#;
        let (rows, stats) = json_rows(doc, None).unwrap();
        assert_eq!(
            stats,
            Stats {
                temp: 1,
                sid: 1,
                unknown_release: 1,
                orphan_advisories: 0
            }
        );
        let n = None;
        assert_eq!(
            rows,
            vec![
                vec![o("Debian:12"), o("zlib"), o("CVE-2024-1"), o("not-affected"), o("low"), o("0"), n.clone(), o(STAR_NOTE), n.clone()],
                vec![o("Debian:11"), o("zlib"), o("CVE-2024-1"), o("open"), n.clone(), n.clone(), o("postponed"), o("Minor"), n.clone()],
                vec![o("Debian:13"), o("zlib"), o("CVE-2024-1"), o("open"), n.clone(), n.clone(), o("no-dsa"), n.clone(), n.clone()],
                vec![o("Debian:14"), o("zlib"), o("CVE-2024-1"), n.clone(), n.clone(), o("1.0"), n.clone(), n.clone(), n.clone()],
                vec![o("Debian:12"), o("b"), o("CVE-2024-9"), o("open"), n.clone(), n.clone(), n.clone(), n.clone(), n.clone()],
                vec![o("Debian:12"), o("b"), o("CVE-2024-9"), o("x"), n.clone(), n.clone(), n.clone(), n.clone(), n],
            ]
            .into_iter()
            // sorted packages: "Zlib" < "apt" < "b"
            .collect::<Vec<_>>()
        );
        // limit: the first packages by name, non-objects included
        let (rows, _) = json_rows(doc, Some(2)).unwrap();
        assert_eq!(rows.len(), 4);
        let (rows, _) = json_rows(doc, Some(1)).unwrap();
        assert_eq!(rows.len(), 4);
    }

    #[test]
    fn json_errors_read_like_python() {
        let err = |d: &str| json_rows(d, None).unwrap_err();
        assert_eq!(err("[1]"), "TypeError: tracker JSON: top level is not an object");
        assert_eq!(err("3"), "TypeError: tracker JSON: top level is not an object");
        assert!(err("[1").starts_with("invalid JSON"));
        assert!(err("{} x").starts_with("invalid JSON"));
        assert!(err("").starts_with("invalid JSON"));
        assert_eq!(
            err(r#"{"p": {"CVE-1": {"releases": [1]}}}"#),
            "AttributeError: 'list' object has no attribute 'items'"
        );
        assert_eq!(
            err(r#"{"p": {"CVE-1": {"releases": {"bookworm": {"status": 1}}}}}"#),
            "AttributeError: 'int' object has no attribute 'lower'"
        );
        assert_eq!(
            err(r#"{"p": {"CVE-1": {"releases": {"bookworm": {"urgency": true}}}}}"#),
            "AttributeError: 'bool' object has no attribute 'strip'"
        );
        assert_eq!(
            err(r#"{"p": {"CVE-1": {"releases": {"bookworm": {"nodsa_reason": {"a": 1}}}}}}"#),
            "AttributeError: 'dict' object has no attribute 'strip'"
        );
        assert_eq!(
            err(r#"{"p": {"CVE-1": {"releases": {"bookworm": {"fixed_version": [1]}}}}}"#),
            "debian-tracker: p CVE-1 bookworm: fixed_version is a list; refusing"
        );
        // falsy values are nothing; an error outside the limit does not count; TEMP and sid never fail
        assert!(json_rows(r#"{"p": {"CVE-1": {"releases": 0}, "TEMP-1": {"releases": 5}}}"#, None).is_ok());
        assert!(json_rows(r#"{"a": {}, "z": {"CVE-1": {"releases": [1]}}}"#, Some(1)).is_ok());
        // a repeated CVE key keeps its first place and its last value
        let (rows, _) = json_rows(
            r#"{"p": {"CVE-1": {"releases": {"bookworm": {"status": "a"}}}, "CVE-1": {"releases": {"bookworm": {"status": "b"}}}}}"#,
            None,
        )
        .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][3], o("b"));
    }

    #[test]
    fn json_input_variants_and_caps() {
        let doc = br#"{"p": {"CVE-1": {"releases": {"bookworm": {"status": "open"}}}}}"#;
        let mut bom = b"\xef\xbb\xbf".to_vec();
        bom.extend_from_slice(doc);
        let (_, d1) = parse_json(&doc[..], caps(), None).unwrap();
        let (l, d2) = parse_json(bom.as_slice(), caps(), None).unwrap();
        assert_eq!(l.rows.len(), 1);
        assert_ne!(d1, d2, "the digest covers the BOM, as the Python source's");
        let gz = {
            use std::io::Write;
            let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
            e.write_all(doc).unwrap();
            e.finish().unwrap()
        };
        let (l, d3) = parse_json(gz.as_slice(), caps(), None).unwrap();
        assert_eq!((l.rows.len(), d3), (1, d1));
        assert_eq!(
            parse_json(&gz[..gz.len() - 12], caps(), None).err().unwrap(),
            "DecompressError: truncated gz data (no end-of-stream marker)"
        );
        let small = Caps {
            decompressed: 10,
            ..caps()
        };
        assert_eq!(
            parse_json(gz.as_slice(), small, None).err().unwrap(),
            "DecompressError: decompressed data exceeds the 10 byte limit"
        );
        assert_eq!(
            parse_json(&doc[..], small, None).err().unwrap(),
            "debian-tracker: native importer: the document is larger than 10 bytes; refusing"
        );
        assert!(
            parse_json(&b"BZh91AY"[..], caps(), None)
                .err()
                .unwrap()
                .contains("bzip2 input is not supported")
        );
        let rows1 = Caps { rows: 1, ..caps() };
        let two = br#"{"p": {"CVE-1": {"releases": {"bookworm": {}, "trixie": {}}}}}"#;
        assert_eq!(
            parse_json(&two[..], rows1, None).err().unwrap(),
            "debian-tracker: native importer: more than 1 rows; refusing"
        );
        let entry = Caps {
            entry_bytes: 100,
            ..caps()
        };
        assert!(
            parse_json(&two[..], entry, None)
                .err()
                .unwrap()
                .contains("package p holds more than 100 bytes")
        );
        // review W9.6: a release counts what it holds (the `Rel` itself and its slots), not 64 bytes: two empty
        // releases are above twice the size of the struct
        let rel = Caps {
            entry_bytes: 2 * size_of::<Rel>(),
            ..caps()
        };
        assert!(
            parse_json(&two[..], rel, None)
                .err()
                .unwrap()
                .contains("package p holds more than")
        );
        let pk = Caps { packages: 1, ..caps() };
        assert_eq!(
            parse_json(&br#"{"a": 1, "b": 2}"#[..], pk, None).err().unwrap(),
            "debian-tracker: native importer: more than 1 packages; refusing"
        );
    }

    #[test]
    fn package_lines_match_the_python_pattern() {
        let p = |l: &str| pkg_line(l).map(|p| (p.rel, p.pkg, p.arg, p.paren));
        assert_eq!(
            p("\t[bookworm] - OpenSSH 1:9.2p1-2 (high; bug #1)"),
            Some((o("bookworm"), "openssh".into(), o("1:9.2p1-2"), o("high; bug #1")))
        );
        assert_eq!(p("\t- foo (low)"), Some((None, "foo".into(), o("(low)"), None)));
        assert_eq!(p("\t- foo"), Some((None, "foo".into(), None, None)));
        assert_eq!(
            p("\t- foo <unfixed> (a (b) c)  "),
            Some((None, "foo".into(), o("<unfixed>"), o("a (b) c")))
        );
        assert_eq!(p("\t-foo"), None);
        assert_eq!(p("\t[sid]\x1c- foo\u{a0}1.0"), Some((o("sid"), "foo".into(), o("1.0"), None)));
        assert_eq!(p("\t- foo 1.0 trailing"), None);
        assert!(CVE_HEAD.is_match("CVE-2024-12345 (x)"));
        assert!(CVE_HEAD.is_match("CVE-٢٠٢٤-1234"));
        assert!(!CVE_HEAD.is_match("CVE-2024-123x"));
        assert_eq!(&ADV_HEAD.captures("[1 Jan] DSA-1-2 x").unwrap()[1], "DSA-1-2");
        assert!(ADV_HEAD.captures("DLA-1").is_none());
    }

    #[test]
    fn parentheses_and_text_rows() {
        assert_eq!(split_paren(Some("low; bug #1; Note "), false), (o("low"), o("Note")));
        assert_eq!(split_paren(Some(" medium* "), true), (o("medium"), None));
        assert_eq!(split_paren(Some("  "), true), (None, o("")));
        assert_eq!(split_paren(Some("bug #1"), false), (None, None));
        let t = text_row(Some("<end-of-life>"), Some("gone"), Some("low")).unwrap();
        assert_eq!(
            (t.status, t.urgency, t.nodsa, t.note),
            (o("open"), o("end-of-life"), o("ignored"), o("gone"))
        );
        let t = text_row(Some("1.2"), Some("bug #3"), Some("high")).unwrap();
        assert_eq!((t.status, t.fixed, t.urgency), (o("resolved"), o("1.2"), o("high")));
        assert!(text_row(Some("<itp>"), None, None).is_none());
        assert!(text_row(None, None, None).is_none());
    }

    #[test]
    fn a_checkout_follows_load_repo() {
        let d = tempfile::tempdir().unwrap();
        let data = d.path().join("data");
        for n in ["CVE", "DSA", "DLA"] {
            std::fs::create_dir_all(data.join(n)).unwrap();
        }
        std::fs::write(
            data.join("CVE/list"),
            b"CVE-2024-0001 (x)\r\n\t- Foo <unfixed> (low)\r\t[bookworm] - foo 1.0-1\n\t\t[x] - bad 1\n\
             CVE-2024-0001 (again)\n\t[trixie] - foo <not-affected> (code \xff absent)\n\
             TEMP-1 (t)\n\t- foo <unfixed>\nNOTE x\n\t- bar <unfixed>\n",
        )
        .unwrap();
        std::fs::write(
            data.join("DSA/list"),
            "[1 Jan 2024] DSA-2-1 foo\n\t{CVE-2024-0001 CVE-2024-0404}\n\t[bookworm] - foo 0.9\n\
             DSA-1-1 foo\n\t{CVE-2024-0001}\n\t[bookworm] - foo 1.0-1\n\t[bullseye] - foo 1.0\n",
        )
        .unwrap();
        let l = load_repo(d.path(), caps(), None).unwrap();
        let rows = dump(&sorted_unique(l.rows, &l.syms), &l.syms);
        assert_eq!(rows.len(), 4, "{rows:?}");
        let bookworm = rows.iter().find(|r| r[0] == o("Debian:12")).unwrap();
        assert_eq!(bookworm[3..], [o("resolved"), o("low"), o("1.0-1"), None, None, o("DSA-1-1")]);
        let trixie = rows.iter().find(|r| r[0] == o("Debian:13")).unwrap();
        assert_eq!(trixie[7], o("code \u{fffd} absent"));
        assert_eq!(l.stats.temp, 1);
        assert_eq!(l.stats.sid, 1);
        assert_eq!(l.stats.orphan_advisories, 1, "CVE-2024-0404");
        let bullseye = rows.iter().find(|r| r[0] == o("Debian:11")).unwrap();
        assert_eq!(bullseye[8], o("DSA-1-1"));
        let long = Caps {
            line_bytes: 8,
            ..caps()
        };
        assert!(load_repo(d.path(), long, None).err().unwrap().contains("a line is longer than 8 bytes"));
        // no data/: the directory itself; missing lists: no rows
        let empty = load_repo(&data.join("DLA"), caps(), None).unwrap();
        assert!(empty.rows.is_empty());
    }
}
