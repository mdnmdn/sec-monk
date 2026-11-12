//! CVE List v5 (CVEProject/cvelistV5) with CISA Vulnrichment ADP data, native (rust ADR-0011, ADR-0012). Port of
//! `src/secmonk/sources/cvelist.py` plus the `source_sync` bookkeeping of `ops.sync_source` / `db.set_sync_state`;
//! reference: `py-sources` (differential test `secmonk-engine/tests/native_cvelist.rs`). Doc:
//! `rust/_docs/tech/source-cvelist.md`.
//!
//! Modes, by precedence as in Python: `--path` (one CVE JSON file, or a directory walked for `CVE-*.json`), `ids`
//! (one raw GitHub request per id), else the git mode: a sparse partial clone of the CVE List repository in a cache
//! directory, brought to upstream HEAD with the same hardened `git` subprocess as Python (fixed arguments, no shell,
//! an environment cleared down to what git needs, a time limit and an output cap per call). The internal rows
//! `cvelist:git` (last fully imported commit) and `cvelist:years` (oldest synced year) are mirror rows, so both
//! implementations continue each other's state.
//!
//! Python imports file by file, each record in its own SAVEPOINT: a record that raises is rolled back alone and counted
//! as an error. The native importer does the same: every record is planned completely (every check Python would make
//! while writing it) before any of its operations is emitted; a failing record emits nothing and counts as an error.
//! Records are taken in groups; the stored `vulnerability` rows (`dateUpdated` comparison) and `affected` rows
//! (`replace_children`) of a group are read through `MirrorView::rows_by_id`. The status and counts are known only at
//! the end, so the run's end goes through `native::stream_deferred`.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
use std::ffi::OsString;
use std::fmt;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::StreamExt;
use regex::Regex;
use secmonk_model::{JsonMap, MirrorTable, RowOp};
use secmonk_traits::{
    CallCtx, MirrorView, ResultStream, RowsBatch, Source, SourceInfo, StepResult, SyncEnd,
    SyncParams,
};
use serde_json::{Value, json};

use crate::batch::Limits;
use crate::native::{self, Ops, Progress, Tail, TailCell};
use crate::rows::{self, DeleteKey};
use crate::{feed, py};

/// Source name.
pub const NAME: &str = "cvelist";
/// Registration (`crate::IMPORTERS`).
pub const IMPORTER: crate::Importer = crate::Importer {
    name: NAME,
    default_rust: false,
    new: |view| Arc::new(CvelistSource::new(view)),
};
/// Description (as the Python source's).
pub const DESCRIPTION: &str =
    "CVE List v5 (CVEProject/cvelistV5) with CISA Vulnrichment ADP data";
/// The upstream repository (git mode).
pub const REPO_URL: &str = "https://github.com/CVEProject/cvelistV5";
/// The raw file base (ids mode).
pub const RAW_BASE: &str = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/";
/// The internal `source_sync` row of the last fully imported commit.
pub const GIT_KEY: &str = "cvelist:git";
/// The internal `source_sync` row of the oldest synced year.
pub const YEARS_KEY: &str = "cvelist:years";
/// `ids` value that asks for the CVE ids referenced by other sources (not served natively).
pub const REFERENCED: &str = "@referenced";
/// The cache subdirectory of the native clone (below the per-user cache directory, see [`default_cache_dir`]).
pub const CACHE_SUBDIR: &str = "cvelist-native";

/// The hardening flags of every git call (`_GIT_HARDEN`).
const GIT_HARDEN: [&str; 10] = [
    "-c",
    "core.fsmonitor=",
    "-c",
    "core.hooksPath=/dev/null",
    "-c",
    "core.pager=cat",
    "-c",
    "core.sshCommand=ssh",
    "-c",
    "protocol.ext.allow=never",
];
/// The only variables of the host's environment a git call gets (proxies, CA files, the program search path and
/// what Windows needs); everything else, `HOME` and every `GIT_*` included, is cleared.
const GIT_PASS_ENV: [&str; 17] = [
    "PATH",
    "SYSTEMROOT",
    "SystemRoot",
    "WINDIR",
    "TMPDIR",
    "TEMP",
    "TMP",
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
];

/// Input caps (the Python source has none). Worst-case memory within them: rust/_docs/tech/source-cvelist.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caps {
    /// Bytes of one record file (`--path`, the clone) or one raw answer (ids).
    pub file_bytes: u64,
    /// Files of one run (a `--path` walk, or the clone's walks and changed files together).
    pub files: usize,
    /// Directory entries visited by one walk.
    pub entries: usize,
    /// `affected` rows of one record (new ones, and stored ones read back).
    pub rows: usize,
    /// Bytes of the standard output of one git call (`git diff --name-only` of a full year is about 4 MiB).
    pub git_output: usize,
    /// Time limit of one git call (Python's `timeout=3600`).
    pub git_timeout: Duration,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            file_bytes: 4 * 1024 * 1024,
            files: 1_000_000,
            entries: 4_000_000,
            rows: 10_000,
            git_output: 64 * 1024 * 1024,
            git_timeout: Duration::from_secs(3600),
        }
    }
}

/// Files read per group (one `rows_by_id` read per table).
const GROUP: usize = 50;
/// Record bytes per group (a group closes once it is reached).
const GROUP_BYTES: u64 = 8 * 1024 * 1024;
/// Files read at once (one thread each) within a group.
const READERS: usize = 8;
/// Bytes of a git call's standard error kept for the message.
const GIT_STDERR: usize = 64 * 1024;
/// Timeout of one raw request (`http_client(timeout=30.0)`).
const RAW_TIMEOUT: Duration = Duration::from_secs(30);

/// The native CVE List source.
pub struct CvelistSource {
    view: Arc<dyn MirrorView>,
    limits: Limits,
    caps: Caps,
    repo_url: String,
    raw_base: String,
    cache_dir: Option<PathBuf>,
    git: OsString,
}

impl fmt::Debug for CvelistSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CvelistSource")
            .field("limits", &self.limits)
            .field("caps", &self.caps)
            .field("repo_url", &self.repo_url)
            .field("raw_base", &self.raw_base)
            .field("cache_dir", &self.cache_dir)
            .finish_non_exhaustive()
    }
}

impl CvelistSource {
    /// The source over a read-only view of the mirror; the clone lives in [`default_cache_dir`].
    pub fn new(view: Arc<dyn MirrorView>) -> CvelistSource {
        CvelistSource {
            view,
            limits: Limits::default(),
            caps: Caps::default(),
            repo_url: REPO_URL.into(),
            raw_base: RAW_BASE.into(),
            cache_dir: default_cache_dir(),
            git: "git".into(),
        }
    }

    /// Other batch limits (tests: several batches out of a small fixture).
    pub fn with_limits(mut self, limits: Limits) -> CvelistSource {
        self.limits = limits;
        self
    }

    /// Other input caps.
    pub fn with_caps(mut self, caps: Caps) -> CvelistSource {
        self.caps = caps;
        self
    }

    /// Another repository URL (tests: a local `file://` repository).
    pub fn with_repo_url(mut self, url: &str) -> CvelistSource {
        self.repo_url = url.into();
        self
    }

    /// Another raw file base (tests: a local server; `http://` is then allowed).
    pub fn with_raw_base(mut self, url: &str) -> CvelistSource {
        self.raw_base = url.into();
        self
    }

    /// The directory of the clone (it is created 0700; a symlink is refused; another origin is re-cloned).
    pub fn with_cache_dir(mut self, dir: &Path) -> CvelistSource {
        self.cache_dir = Some(dir.to_path_buf());
        self
    }

    /// Another git program (tests: a missing one).
    pub fn with_git(mut self, program: &str) -> CvelistSource {
        self.git = program.into();
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
        let path = opts.path.clone().flatten().filter(|p| !p.is_empty());
        let ids: Vec<String> = opts.ids.clone().unwrap_or_default();
        let full = opts.full.unwrap_or(false);
        let tail: TailCell = Arc::new(Mutex::new(None));
        let base_total = self
            .view
            .count_rows(MirrorTable::Vulnerability, NAME)
            .await?;
        let mut run = Run {
            view: self.view.clone(),
            caps: self.caps,
            now: secmonk_model::time::now_iso(),
            limit,
            full,
            count: 0,
            errors: 0,
            index: 0,
            hit_limit: false,
            base_total,
            new_ids: 0,
            emitted: HashMap::new(),
            say: Progress::new(ctx),
            ctx: ctx.clone(),
            input: Input::Done,
            mode: Mode::Path(String::new()),
            tail: tail.clone(),
            done: false,
        };
        if let Some(p) = path {
            run.mode = Mode::Path(feed::py_path(Path::new(&p)));
            run.input = Input::PathPending(PathBuf::from(p));
        } else if ids.len() == 1 && ids[0] == REFERENCED {
            run.set_tail(Tail {
                status: "error".into(),
                message: Some(format!(
                    "{NAME}: native importer: ids [{REFERENCED}] reads the alias and kev rows of every source, which \
                     the mirror view does not list; sync cvelist with the python implementation for it"
                )),
                ..Tail::default()
            });
        } else if !ids.is_empty() {
            run.mode = Mode::Ids;
            let allow_http = !self.raw_base.starts_with("https://");
            match feed::fetch_client(RAW_TIMEOUT, allow_http, false) {
                Ok(client) => {
                    run.input = Input::Ids {
                        client,
                        base: self.raw_base.clone(),
                        allow_http,
                        ids: ids.iter().map(|i| py::strip(i).to_uppercase()).collect(),
                    };
                }
                Err(e) => run.fail_run(format!("{NAME}: native importer: {e}")),
            }
        } else {
            run.mode = Mode::Git(GitDone::default());
            match &self.cache_dir {
                Some(dir) => {
                    run.input = Input::GitPending(GitCfg {
                        program: self.git.clone(),
                        url: self.repo_url.clone(),
                        repo: dir.clone(),
                        timeout: self.caps.git_timeout,
                        out_cap: self.caps.git_output,
                        since: opts.since.clone().flatten(),
                        full,
                    });
                }
                None => run.fail_run(format!(
                    "{NAME}: native importer: no cache directory for the clone (no SECMONK_CACHE, XDG_CACHE_HOME or \
                     home directory)"
                )),
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

/// The per-user cache directory of the native clone: `$SECMONK_CACHE`, else `$XDG_CACHE_HOME/secmonk`, else
/// `~/.cache/secmonk` (Windows: `%LOCALAPPDATA%\secmonk\cache`), as `secmonk/paths.cache_dir()`, then
/// [`CACHE_SUBDIR`]. Never relative to the working directory (a relative variable is ignored). `None` without any.
pub fn default_cache_dir() -> Option<PathBuf> {
    let abs = |v: OsString| Some(PathBuf::from(v)).filter(|p| p.is_absolute());
    let var = |k: &str| std::env::var_os(k).filter(|v| !v.is_empty());
    let home = || {
        var("HOME")
            .or_else(|| var("USERPROFILE"))
            .and_then(abs)
    };
    let root = if let Some(c) = var("SECMONK_CACHE") {
        match c.to_str().and_then(|s| s.strip_prefix("~/")) {
            Some(rest) => home().map(|h| h.join(rest)),
            None => abs(c),
        }
    } else if cfg!(windows) {
        var("LOCALAPPDATA")
            .and_then(abs)
            .or_else(|| home().map(|h| h.join("AppData").join("Local")))
            .map(|p| p.join("secmonk").join("cache"))
    } else {
        var("XDG_CACHE_HOME")
            .and_then(abs)
            .map(|x| x.join("secmonk"))
            .or_else(|| home().map(|h| h.join(".cache").join("secmonk")))
    };
    root.map(|r| r.join(CACHE_SUBDIR))
}

// ------------------------------------------------------------------------------------------------ paths and urls

static ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\ACVE-(\d{4})-(\d{4,})\n?\z").unwrap());

/// The value of a Unicode decimal digit (`int()` reads them as `0`-`9`).
fn digit_value(c: char) -> Option<u32> {
    if let Some(d) = c.to_digit(10) {
        return Some(d);
    }
    if !py::is_decimal(c) {
        return None;
    }
    py::float_str(&c.to_string()).map(|f| f as u32)
}

/// Decimal digits (ASCII or Unicode) as a plain ASCII number without leading zeros (`"0"` for zero).
fn ascii_number(digits: &str) -> String {
    let s: String = digits
        .chars()
        .filter_map(digit_value)
        .map(|d| char::from(b'0' + d as u8))
        .collect();
    let t = s.trim_start_matches('0');
    if t.is_empty() { "0".into() } else { t.into() }
}

/// Python's limit on `int(str)` (`sys.get_int_max_str_digits()`).
const INT_MAX_STR_DIGITS: usize = 4300;

fn int_limit_error(n: usize) -> String {
    format!(
        "ValueError: Exceeds the limit ({INT_MAX_STR_DIGITS} digits) for integer string conversion: value has {n} \
         digits; use sys.set_int_max_str_digits() to increase the limit"
    )
}

/// `cve_path`: the repository path of a CVE id (`CVE-2021-44228` -> `cves/2021/44xxx/CVE-2021-44228.json`); the file
/// name keeps the id's digits verbatim, the folder is the numeric value divided by 1000. `Err`: Python's `ValueError`.
pub fn cve_path(cve_id: &str) -> Result<String, String> {
    let Some(c) = ID_RE.captures(py::strip(cve_id)) else {
        return Err(format!(
            "ValueError: not a CVE id: {}",
            py::repr_str(cve_id)
        ));
    };
    let (year, digits) = (&c[1], &c[2]);
    let n = digits.chars().count();
    if n > INT_MAX_STR_DIGITS {
        return Err(int_limit_error(n));
    }
    let num = ascii_number(digits);
    let folder = if num.len() <= 3 {
        "0".to_owned()
    } else {
        num[..num.len() - 3].to_owned()
    };
    Ok(format!("cves/{year}/{folder}xxx/CVE-{year}-{digits}.json"))
}

const REGISTRY_HOSTS: [(&str, &str); 20] = [
    ("registry.npmjs.org", "npm"),
    ("npmjs.com", "npm"),
    ("www.npmjs.com", "npm"),
    ("npmjs.org", "npm"),
    ("pypi.org", "PyPI"),
    ("pypi.python.org", "PyPI"),
    ("files.pythonhosted.org", "PyPI"),
    ("repo.maven.apache.org", "Maven"),
    ("repo1.maven.org", "Maven"),
    ("search.maven.org", "Maven"),
    ("mvnrepository.com", "Maven"),
    ("rubygems.org", "RubyGems"),
    ("crates.io", "crates.io"),
    ("packagist.org", "Packagist"),
    ("repo.packagist.org", "Packagist"),
    ("nuget.org", "NuGet"),
    ("www.nuget.org", "NuGet"),
    ("api.nuget.org", "NuGet"),
    ("pkg.go.dev", "Go"),
    ("proxy.golang.org", "Go"),
];

/// `urlparse(u).hostname` of Python 3.13 (`urlsplit`: tab and newlines removed, leading C0 controls and spaces
/// stripped, the scheme only when it starts with an ASCII letter, the netloc only after `//`, the host after the last
/// `@`, before a `:` or inside `[...]`, lower-cased). `None`: no host (or one Python refuses with `ValueError`, which
/// `ecosystem_from_url` treats the same).
fn url_hostname(url: &str) -> Option<String> {
    let cleaned: String = url
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut rest = cleaned.trim_start_matches(|c: char| c <= ' ');
    if let Some(i) = rest.find(':') {
        let scheme = &rest[..i];
        if i > 0
            && scheme.as_bytes()[0].is_ascii_alphabetic()
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        {
            rest = &rest[i + 1..];
        }
    }
    let after = rest.strip_prefix("//")?;
    let end = after.find(['/', '?', '#']).unwrap_or(after.len());
    let netloc = &after[..end];
    if netloc.contains('[') != netloc.contains(']') {
        return None; // ValueError: Invalid IPv6 URL
    }
    let hostinfo = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
    let host = match hostinfo.split_once('[') {
        Some((_, b)) => b.split_once(']').map_or(b, |(h, _)| h),
        None => hostinfo.split_once(':').map_or(hostinfo, |(h, _)| h),
    };
    let host = host.to_lowercase();
    (!host.is_empty()).then_some(host)
}

/// `ecosystem_from_url`: the OSV ecosystem of a package registry URL (`collectionURL`), or `None`.
pub fn ecosystem_from_url(url: Option<&Value>) -> Option<&'static str> {
    let Some(Value::String(u)) = url else {
        return None;
    };
    if u.is_empty() {
        return None;
    }
    let u = py::strip(u);
    let full = if u.contains("://") {
        u.to_owned()
    } else {
        format!("https://{u}")
    };
    let host = url_hostname(&full)?;
    REGISTRY_HOSTS
        .iter()
        .find(|(h, _)| *h == host)
        .map(|(_, e)| *e)
}

static PYPI_SEP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[-_.]+").unwrap());

/// `purl.normalize_name`: the lookup key of a package name in an ecosystem.
pub fn normalize_name(ecosystem: Option<&str>, name: &str) -> String {
    let base = ecosystem.unwrap_or("").split(':').next().unwrap_or("");
    let n = py::strip(name);
    match base {
        "PyPI" => PYPI_SEP.replace_all(n, "-").to_lowercase(),
        "Go" | "Maven" => n.to_owned(),
        _ => n.to_lowercase(),
    }
}

// ------------------------------------------------------------------------------------------------ versions

/// Python's `\s` for `str` patterns: Unicode whitespace plus the separators `\x1c`-`\x1f` (`str.isspace()`).
macro_rules! ws {
    () => {
        r"\s\x1c-\x1f"
    };
}

static VERSION_LIKE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[vV]?\d[0-9A-Za-z.+~_:\-]*\n?\z").unwrap());
static HEX_HASH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[0-9a-fA-F]{7,64}\n?\z").unwrap());
static CMP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"\A(?P<op><=|>=|<|>|=)[",
        ws!(),
        r"]*(?P<v>[^",
        ws!(),
        r",;]+)"
    ))
    .unwrap()
});
static SEP_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(r"(?i)\A(?:[", ws!(), r",;]+|\band\b|&&|&)")).unwrap()
});
static RANGE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\A(?P<a>[^",
        ws!(),
        r"]+)[",
        ws!(),
        r"]+(?:-|to|through|thru)[",
        ws!(),
        r"]+(?P<b>[^",
        ws!(),
        r"]+)\n?\z"
    ))
    .unwrap()
});
static OLDER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\A(?:up to and including|up to|through|thru)[",
        ws!(),
        r"]+(?P<v>[^",
        ws!(),
        r"]+)\n?\z|\A(?P<v2>[^",
        ws!(),
        r"]+)[",
        ws!(),
        r"]+(?:and|or)[",
        ws!(),
        r"]+(?:earlier|older|prior|below|before|lower)(?:[",
        ws!(),
        r"]+versions?)?\n?\z"
    ))
    .unwrap()
});
static BEFORE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\A(?:prior to|before|earlier than|below|older than)[",
        ws!(),
        r"]+(?P<v>[^",
        ws!(),
        r"]+)\n?\z"
    ))
    .unwrap()
});
static LATER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?i)\A(?P<v>[^",
        ws!(),
        r"]+)[",
        ws!(),
        r"]+(?:and|or)[",
        ws!(),
        r"]+(?:later|newer|above|higher)(?:[",
        ws!(),
        r"]+versions?)?\n?\z"
    ))
    .unwrap()
});

/// `is_version_like` of a string: `2.0-beta9`, `1.2.3`, `v4`; not `128.*`, `log4j-core*`, URLs, free text.
pub fn version_like(s: &str) -> bool {
    VERSION_LIKE.is_match(py::strip(s))
}

/// `is_version_like` of any value (only a string can be one).
fn is_version_like(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::String(s)) if version_like(s))
}

/// `looks_like_commit`: a hex string of 7 to 64 characters with a letter, and 12 or more characters or a digit.
pub fn looks_like_commit(s: &str) -> bool {
    let s = py::strip(s);
    if !HEX_HASH.is_match(s) {
        return false;
    }
    s.chars().any(|c| c.is_ascii_alphabetic())
        && s.chars().count() >= 7
        && (s.chars().count() >= 12 || s.chars().any(|c| c.is_ascii_digit()))
}

fn ev(key: &str, v: &str) -> Value {
    let mut m = JsonMap::new();
    m.insert(key.to_owned(), Value::String(v.to_owned()));
    Value::Object(m)
}

/// `parse_version_expression`: a free-text version expression as OSV-style events, or `None` when not understood (a
/// plain version is not an expression).
pub fn parse_version_expression(s: &str) -> Option<Vec<Value>> {
    let s = py::strip(s).trim_end_matches(['.', ',', ';']);
    if s.is_empty() || s.chars().count() > 120 || version_like(s) {
        return None;
    }
    if let Some(m) = OLDER_RE.captures(s) {
        let v = m.name("v").or_else(|| m.name("v2"))?.as_str();
        return version_like(v).then(|| vec![ev("introduced", "0"), ev("last_affected", v)]);
    }
    if let Some(m) = BEFORE_RE.captures(s) {
        let v = m.name("v")?.as_str();
        return version_like(v).then(|| vec![ev("introduced", "0"), ev("fixed", v)]);
    }
    if let Some(m) = LATER_RE.captures(s) {
        let v = m.name("v")?.as_str();
        return version_like(v).then(|| vec![ev("introduced", v)]);
    }
    if let Some(m) = RANGE_RE.captures(s) {
        let (a, b) = (m.name("a")?.as_str(), m.name("b")?.as_str());
        if version_like(a) && version_like(b) {
            return Some(vec![ev("introduced", a), ev("last_affected", b)]);
        }
    }
    // comparison operators; everything must be consumed
    let mut pos = 0usize;
    let mut parts: Vec<(&str, &str)> = Vec::new();
    while pos < s.len() {
        let rest = &s[pos..];
        if let Some(sep) = SEP_RE.find(rest)
            && sep.end() > 0
        {
            pos += sep.end();
            continue;
        }
        let cm = CMP_RE.captures(rest)?;
        parts.push((cm.name("op")?.as_str(), cm.name("v")?.as_str()));
        pos += cm.get(0)?.end();
    }
    if parts.is_empty() || parts.len() > 2 || !parts.iter().all(|(_, v)| version_like(v)) {
        return None;
    }
    let (mut intro, mut fixed, mut last): (Option<&str>, Option<&str>, Option<&str>) =
        (None, None, None);
    for (op, v) in parts {
        match op {
            ">=" | ">" => intro = Some(v),
            "<" => fixed = Some(v),
            "<=" => last = Some(v),
            _ => (intro, last) = (Some(v), Some(v)), // "="
        }
    }
    if intro.is_none() && fixed.is_none() && last.is_none() {
        return None;
    }
    let mut out = vec![ev("introduced", intro.unwrap_or("0"))];
    if let Some(f) = fixed {
        out.push(ev("fixed", f));
    } else if let Some(l) = last {
        out.push(ev("last_affected", l));
    }
    Some(out)
}

/// One token of the tolerant comparator's key: (rank, number, word), compared in that order.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Tok {
    rank: u8,
    /// A non-negative integer as ASCII digits without leading zeros (`"0"` for zero).
    num: String,
    word: String,
}

impl Ord for Tok {
    fn cmp(&self, o: &Tok) -> Ordering {
        self.rank
            .cmp(&o.rank)
            .then_with(|| self.num.len().cmp(&o.num.len()))
            .then_with(|| self.num.cmp(&o.num))
            .then_with(|| self.word.cmp(&o.word))
    }
}

impl PartialOrd for Tok {
    fn partial_cmp(&self, o: &Tok) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

const R_PRE: u8 = 1;
const R_FINAL: u8 = 2;
const R_POST: u8 = 3;
const R_NUM: u8 = 4;

fn pad() -> Tok {
    Tok {
        rank: R_FINAL,
        num: "0".into(),
        word: String::new(),
    }
}

static TOKEN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d+|[a-zA-Z]+").unwrap());

/// `versions._generic_key`: `1.0-rc1` < `1.0` == `1.0.0` == `1.0.Final` < `1.0p1` < `1.0a` < `1.0.1`. `Err`: Python's
/// `ValueError` for a number of more than 4300 digits.
fn generic_key(v: &str) -> Result<Vec<Tok>, String> {
    let mut v = py::strip(v);
    let mut cs = v.chars();
    if matches!(cs.next(), Some('v' | 'V')) && cs.next().is_some_and(py::is_decimal) {
        v = &v[1..];
    }
    let mut out: Vec<Tok> = Vec::new();
    for m in TOKEN.find_iter(v) {
        let tok = m.as_str();
        if tok.chars().next().is_some_and(py::is_decimal) {
            let n = tok.chars().count();
            if n > INT_MAX_STR_DIGITS {
                return Err(int_limit_error(n));
            }
            out.push(Tok {
                rank: R_NUM,
                num: ascii_number(tok),
                word: String::new(),
            });
            continue;
        }
        let tok = tok.to_ascii_lowercase();
        // `prev in "-.~"`, where the empty string (the token starts the version) is in every string
        let prev = v[..m.start()].chars().next_back();
        let pre = match tok.as_str() {
            "dev" | "snapshot" => Some(0),
            "alpha" | "a" => Some(1),
            "beta" | "b" => Some(2),
            "m" | "milestone" => Some(3),
            "preview" | "pre" => Some(4),
            "rc" | "cr" => Some(5),
            _ => None,
        };
        if matches!(tok.as_str(), "final" | "ga" | "release" | "rel" | "stable") {
            out.push(pad());
        } else if let Some(p) = pre
            && (tok.len() > 1 || prev.is_none_or(|c| matches!(c, '-' | '.' | '~')))
        {
            out.push(Tok {
                rank: R_PRE,
                num: p.to_string(),
                word: String::new(),
            });
        } else {
            let word = match tok.as_str() {
                "pl" | "patch" | "post" | "patchlevel" => "p".to_owned(),
                _ => tok,
            };
            out.push(Tok {
                rank: R_POST,
                num: "0".into(),
                word,
            });
        }
    }
    // drop zero numbers / final markers that end a numeric group
    let zero = Tok {
        rank: R_NUM,
        num: "0".into(),
        word: String::new(),
    };
    let mut i = out.len() as isize - 1;
    while i >= 0 {
        let u = i as usize;
        if (out[u] == zero || out[u] == pad()) && (u == out.len() - 1 || out[u + 1].rank != R_NUM) {
            out.remove(u);
        }
        i -= 1;
    }
    Ok(out)
}

/// `versions.compare(a, b)` of the generic scheme: equal strings are equal, else the tolerant keys padded to the same
/// length. `Err`: Python's `ValueError` (a number of more than 4300 digits).
pub fn compare_versions(a: &str, b: &str) -> Result<Ordering, String> {
    if a == b {
        return Ok(Ordering::Equal);
    }
    let (mut ka, mut kb) = (generic_key(a)?, generic_key(b)?);
    let n = ka.len().max(kb.len());
    ka.resize(n, pad());
    kb.resize(n, pad());
    Ok(ka.cmp(&kb))
}

/// What one `versions[]` entry becomes (`convert_version_entry`).
#[derive(Debug, Clone, PartialEq)]
pub enum Converted {
    /// `range_type` CVE with events.
    Events(Vec<Value>),
    /// An exact version, `range_type` CVE.
    Versions(Vec<Value>),
    /// Commit-based events, `range_type` GIT.
    Git(Vec<Value>),
    /// Not understood: `range_type` CVE-UNPARSED, the raw entry in `extra`.
    Unparsed,
    /// Nothing usable.
    Skip,
}

const NO_VERSION: [&str; 7] = ["", "n/a", "na", "unspecified", "unknown", "none", "-"];

fn no_version(v: &str) -> bool {
    NO_VERSION.contains(&v.to_lowercase().as_str())
}

/// `x or ""`, then `str(x)`.
fn str_or_empty(v: Option<&Value>) -> String {
    match v {
        Some(x) if py::truthy(x) => py::str_of(x),
        _ => String::new(),
    }
}

/// `str(x).strip()` of a value that is not `None`.
fn stripped(v: Option<&Value>) -> Option<String> {
    match v {
        None | Some(Value::Null) => None,
        Some(x) => Some(py::strip(&py::str_of(x)).to_owned()),
    }
}

/// `_events_from_changes`: events from `changes[]` (`unaffected at X` closes, `affected at X` opens); `None` when an
/// `at` is not version-like or nothing came out.
fn events_from_changes(start: Option<&str>, changes: &[&JsonMap]) -> Option<Vec<Value>> {
    let mut events = Vec::new();
    let mut open = false;
    if let Some(s) = start {
        events.push(ev("introduced", s));
        open = true;
    }
    for ch in changes {
        let at = ch.get("at");
        let st = change_status(ch);
        if !is_version_like(at) {
            return None;
        }
        let at = at.and_then(Value::as_str).unwrap_or_default();
        if st == "unaffected" {
            if open {
                events.push(ev("fixed", at));
                open = false;
            }
        } else if st == "affected" && !open {
            events.push(ev("introduced", at));
            open = true;
        }
    }
    (!events.is_empty()).then_some(events)
}

/// `str(ch.get("status", "")).lower()`.
fn change_status(ch: &JsonMap) -> String {
    match ch.get("status") {
        None => String::new(),
        Some(v) => py::str_of(v).to_lowercase(),
    }
}

/// `convert_version_entry`: one `versions[]` entry (status affected) as a storable shape. `Err`: Python's exceptions
/// (`changes` not iterable, a version number Python cannot convert).
pub fn convert_version_entry(entry: &JsonMap) -> Result<Converted, String> {
    let version = stripped(entry.get("version")).unwrap_or_default();
    let lt = stripped(entry.get("lessThan"));
    let lte = stripped(entry.get("lessThanOrEqual"));
    let vtype = py::strip(&str_or_empty(entry.get("versionType"))).to_lowercase();
    let changes: Vec<&JsonMap> = items(entry.get("changes"))?
        .filter_map(|c| dict_item(&c))
        .collect();

    // commit-based data is not an installed-software version
    if matches!(vtype.as_str(), "git" | "original_commit_for_fix")
        || looks_like_commit(&version)
        || lt.as_deref().is_some_and(looks_like_commit)
        || lte.as_deref().is_some_and(looks_like_commit)
    {
        let mut out = Vec::new();
        if !version.is_empty() && !no_version(&version) && version != "0" {
            out.push(ev("introduced", &version));
        }
        match (&lt, &lte) {
            (Some(l), _) if !l.is_empty() => out.push(ev("fixed", l)),
            (_, Some(l)) if !l.is_empty() => out.push(ev("last_affected", l)),
            _ => {}
        }
        return Ok(Converted::Git(out));
    }

    let open = |v: &str| matches!(v, "0" | "*" | "");
    if lt.is_none() && lte.is_none() {
        if no_version(&version) && !version.is_empty() {
            return Ok(Converted::Skip);
        }
        if open(&version) {
            return Ok(Converted::Events(vec![ev("introduced", "0")]));
        }
        if version_like(&version) {
            if !changes.is_empty() {
                return Ok(match events_from_changes(Some(&version), &changes) {
                    Some(e) => Converted::Events(e),
                    None => Converted::Unparsed,
                });
            }
            return Ok(Converted::Versions(vec![Value::String(version)]));
        }
        return Ok(match parse_version_expression(&version) {
            Some(e) => Converted::Events(e),
            None => Converted::Unparsed,
        });
    }

    // bounded entry
    let version = if no_version(&version) && !version.is_empty() {
        "0".to_owned()
    } else {
        version
    };
    let mut start: Option<String> = if open(&version) {
        Some("0".into())
    } else if version_like(&version) {
        Some(version.clone())
    } else {
        None // free text lower bound
    };
    let (bound_kind, bound) = match (&lt, &lte) {
        (Some(l), _) => ("fixed", l.clone()),
        (None, Some(l)) => ("last_affected", l.clone()),
        (None, None) => unreachable!("checked above"),
    };
    let open_ended = bound == "*";
    let bound_ok = open_ended || version_like(&bound);

    if let Some(s) = start.as_mut()
        && bound_ok
    {
        if bound_kind == "fixed" && !open_ended && bound == *s {
            *s = "0".into(); // Chrome style: version == lessThan means "below this version"
        }
        let mut events = vec![ev("introduced", s)];
        let mut is_open = true;
        let mut valid: Vec<(&JsonMap, &str)> = changes
            .iter()
            .filter(|c| is_version_like(c.get("at")))
            .map(|c| (*c, c.get("at").and_then(Value::as_str).unwrap_or_default()))
            .collect();
        sort_by_version(&mut valid)?;
        for (ch, at) in valid {
            let st = change_status(ch);
            if !open_ended && compare_versions(at, &bound)? != Ordering::Less {
                continue; // changes at/after the bound are moot
            }
            if st == "unaffected" && is_open {
                events.push(ev("fixed", at));
                is_open = false;
            } else if st == "affected" && !is_open {
                events.push(ev("introduced", at));
                is_open = true;
            }
        }
        if is_open && !open_ended {
            events.push(ev(bound_kind, &bound));
        }
        return Ok(Converted::Events(events));
    }

    // invalid bound or lower bound: try changes[]
    if !changes.is_empty()
        && let Some(e) = events_from_changes(start.as_deref(), &changes)
    {
        return Ok(Converted::Events(e));
    }
    Ok(Converted::Unparsed)
}

/// `list.sort(key=cmp_to_key(compare))` (stable); the first comparator error is returned, as the sort raises it.
fn sort_by_version(v: &mut [(&JsonMap, &str)]) -> Result<(), String> {
    let mut err: Option<String> = None;
    v.sort_by(|a, b| match compare_versions(a.1, b.1) {
        Ok(o) => o,
        Err(e) => {
            err.get_or_insert(e);
            Ordering::Equal
        }
    });
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

// ------------------------------------------------------------------------------------------------ Python helpers

/// `for x in (v or [])`, with Python's `TypeError` for a truthy number.
fn items(v: Option<&Value>) -> Result<py::Items<'_>, String> {
    py::iter_items(v).map_err(|m| format!("TypeError: {m}"))
}

/// An element that is a dict (`isinstance(x, dict)`), borrowed from the record.
fn dict_item<'a>(item: &Cow<'a, Value>) -> Option<&'a JsonMap> {
    match item {
        Cow::Borrowed(Value::Object(m)) => Some(m),
        _ => None,
    }
}

/// An element the code calls `.get` on: a dict, else Python's `AttributeError`.
fn dict_of<'a>(item: &Cow<'a, Value>) -> Result<&'a JsonMap, String> {
    match item {
        Cow::Borrowed(Value::Object(m)) => Ok(m),
        other => Err(attr_error(other, "get")),
    }
}

fn attr_error(v: &Value, attr: &str) -> String {
    format!(
        "AttributeError: {}",
        py::no_attr(py::type_name(v), attr)
    )
}

/// `d.get(key)` where `None` and JSON `null` are the same.
fn get<'a>(d: &'a JsonMap, key: &str) -> Option<&'a Value> {
    d.get(key).filter(|v| !v.is_null())
}

/// `x or {}` of a value the code then calls `.get` on: a dict, an empty one for a falsy value, else Python's
/// `AttributeError`.
fn dict_or_empty<'a>(v: Option<&'a Value>, empty: &'a JsonMap) -> Result<&'a JsonMap, String> {
    match v {
        Some(Value::Object(m)) => Ok(m),
        Some(x) if py::truthy(x) => Err(attr_error(x, "get")),
        _ => Ok(empty),
    }
}

/// Python's `==` between two JSON values (`1 == 1.0 == True`; lists and dicts element by element).
fn py_eq(a: &Value, b: &Value) -> bool {
    let num = |v: &Value| match v {
        Value::Bool(x) => Some(if *x { 1.0 } else { 0.0 }),
        Value::Number(n) => n.as_f64(),
        _ => None,
    };
    match (a, b) {
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| py_eq(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| py_eq(v, w)))
        }
        _ => match (num(a), num(b)) {
            (Some(p), Some(q)) => p == q,
            _ => a == b,
        },
    }
}

/// A text column as Python binds it: `None` for absent / `null`, a string; a list or dict fails the binding
/// (`sqlite3.ProgrammingError`); a number or bool, which Python stores as text, refuses the record natively.
fn text(v: Option<&Value>, id: &str, field: &str) -> Result<Option<String>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(x @ (Value::Array(_) | Value::Object(_))) => Err(format!(
            "ProgrammingError: Error binding parameter: type '{}' is not supported",
            py::type_name(x)
        )),
        Some(_) => Err(format!("{NAME}: {id}: {field} is not a string")),
    }
}

/// `norm_vendor_product` of a value: `None`, a normalized string, or Python's `AttributeError` (`.strip()`).
fn norm_checked(v: Option<&Value>) -> Result<Option<String>, String> {
    match v {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(rows::norm_vendor_product(Some(s))),
        Some(x) => Err(attr_error(x, "strip")),
    }
}

/// `float(x)` of a JSON value.
fn py_float(v: &Value) -> Result<f64, String> {
    match v {
        Value::Bool(b) => Ok(if *b { 1.0 } else { 0.0 }),
        Value::Number(n) => Ok(n.as_f64().unwrap_or(f64::NAN)),
        Value::String(s) => py::float_str(s).ok_or_else(|| {
            format!(
                "ValueError: could not convert string to float: {}",
                py::repr_str(s)
            )
        }),
        other => Err(format!(
            "TypeError: float() argument must be a string or a real number, not '{}'",
            py::type_name(other)
        )),
    }
}

// ------------------------------------------------------------------------------------------------ one record

/// What `import_record` writes for one record (without its `raw_record`, which takes the record itself).
#[derive(Debug)]
struct Planned {
    id: String,
    modified: Option<String>,
    vulnerability: RowOp,
    affected: Vec<JsonMap>,
}

/// `_english`: the `value` of the first description whose `lang` starts with `en` (`None` when none).
fn english(descs: Option<&Value>) -> Result<Option<Value>, String> {
    for d in items(descs)? {
        let d = dict_of(&d)?;
        let lang = match d.get("lang") {
            None => String::new(),
            Some(v) => py::str_of(v),
        };
        if lang.to_lowercase().starts_with("en")
            && let Some(v) = d.get("value").filter(|v| py::truthy(v))
        {
            return Ok(Some(v.clone()));
        }
    }
    Ok(None)
}

/// `a.get("providerMetadata", {}).get("shortName", default)` as `str()`.
fn adp_short(a: &JsonMap, default: &str) -> Result<String, String> {
    let pm = match a.get("providerMetadata") {
        None => return Ok(default.to_owned()),
        Some(Value::Object(m)) => m,
        Some(x) => return Err(attr_error(x, "get")),
    };
    Ok(pm.get("shortName").map_or(default.to_owned(), py::str_of))
}

const CVSS_ORDER: [&str; 4] = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"];

/// `_metric_candidates`: (order index, metric) of every metric with a `baseScore`.
fn metric_candidates(c: &JsonMap) -> Result<Vec<(usize, &JsonMap)>, String> {
    let mut out = Vec::new();
    for m in items(c.get("metrics"))? {
        let m = dict_of(&m)?;
        for (i, key) in CVSS_ORDER.iter().enumerate() {
            if let Some(Value::Object(x)) = m.get(*key)
                && get(x, "baseScore").is_some()
            {
                out.push((i, x));
            }
        }
    }
    Ok(out)
}

/// `_best_cvss`: the CNA's best metric (4.0 > 3.1 > 3.0 > 2.0, the first of equals), else the first ADP with one;
/// with its provenance (`cna` / `adp:<shortName>`).
fn best_cvss<'a>(
    cna: &'a JsonMap,
    adps: &[&'a JsonMap],
) -> Result<Option<(&'a JsonMap, String)>, String> {
    let mut containers: Vec<(String, &JsonMap)> = vec![("cna".into(), cna)];
    for a in adps {
        containers.push((format!("adp:{}", adp_short(a, "?")?), a));
    }
    for (prov, c) in containers {
        let cands = metric_candidates(c)?;
        if let Some(best) = cands.iter().map(|(i, _)| *i).min() {
            let m = cands.iter().find(|(i, _)| *i == best).map(|(_, m)| *m);
            return Ok(m.map(|m| (m, prov)));
        }
    }
    Ok(None)
}

/// `_cwes`: the `cweId`s of the problem types, without repeats (Python equality).
fn cwes_of(c: &JsonMap) -> Result<Vec<Value>, String> {
    let mut out: Vec<Value> = Vec::new();
    for pt in items(c.get("problemTypes"))? {
        let pt = dict_of(&pt)?;
        for d in items(pt.get("descriptions"))? {
            let d = dict_of(&d)?;
            if let Some(cwe) = d.get("cweId").filter(|v| py::truthy(v))
                && !out.iter().any(|x| py_eq(x, cwe))
            {
                out.push(cwe.clone());
            }
        }
    }
    Ok(out)
}

/// `_adp_other`: the `content` of the first ADP `metrics[].other` of type `typ`.
fn adp_other<'a>(adps: &[&'a JsonMap], typ: &str) -> Result<Option<&'a JsonMap>, String> {
    for a in adps {
        for m in items(a.get("metrics"))? {
            let m = dict_of(&m)?;
            if let Some(Value::Object(o)) = m.get("other")
                && o.get("type").and_then(Value::as_str) == Some(typ)
                && let Some(Value::Object(c)) = o.get("content")
            {
                return Ok(Some(c));
            }
        }
    }
    Ok(None)
}

/// `_ssvc`: the SSVC decision points flattened, plus `version`, `timestamp`, `role`.
fn ssvc(adps: &[&JsonMap]) -> Result<Option<JsonMap>, String> {
    let Some(c) = adp_other(adps, "ssvc")? else {
        return Ok(None);
    };
    if c.is_empty() {
        return Ok(None);
    }
    let mut out = JsonMap::new();
    for opt in items(c.get("options"))? {
        if let Some(o) = dict_item(&opt) {
            for (k, v) in o {
                out.insert(k.clone(), v.clone());
            }
        }
    }
    for k in ["version", "timestamp", "role"] {
        if let Some(v) = c.get(k).filter(|v| py::truthy(v)) {
            out.insert(k.to_owned(), v.clone());
        }
    }
    Ok((!out.is_empty()).then_some(out))
}

/// The rows of one record, with the per-record cap.
struct Rows<'c> {
    id: String,
    out: Vec<JsonMap>,
    caps: &'c Caps,
}

impl Rows<'_> {
    fn push(&mut self, row: JsonMap) -> Result<(), String> {
        if self.out.len() >= self.caps.rows {
            return Err(format!(
                "{NAME}: {}: more than {} affected rows; refusing",
                self.id, self.caps.rows
            ));
        }
        self.out.push(row);
        Ok(())
    }
}

/// `_import_affected_entry`: the rows of one `affected[]` entry of a container.
fn affected_entry(aff: &JsonMap, container: &str, rows_out: &mut Rows<'_>) -> Result<(), String> {
    let vendor = aff.get("vendor");
    let product = aff.get("product");
    let pkg = aff.get("packageName");
    let pkg_raw = match pkg {
        Some(Value::String(s)) if !py::strip(s).is_empty() => Some(py::strip(s).to_owned()),
        _ => None,
    };
    if pkg_raw.is_none() && norm_checked(vendor)?.is_none() && norm_checked(product)?.is_none() {
        return Ok(());
    }
    let coll = aff.get("collectionURL");
    let ecosystem = if pkg_raw.is_some() {
        ecosystem_from_url(coll)
    } else {
        None
    };
    let package = pkg_raw.as_deref().map(|p| normalize_name(ecosystem, p));
    let mut base_extra = JsonMap::new();
    base_extra.insert("container".into(), json!(container));
    for (k, v) in [
        ("package_name", pkg),
        ("collection_url", coll),
        ("platforms", aff.get("platforms")),
        ("default_status", aff.get("defaultStatus")),
        ("cpes", aff.get("cpes")),
    ] {
        if let Some(v) = v.filter(|v| py::truthy(v)) {
            base_extra.insert(k.into(), v.clone());
        }
    }
    let row = |rows_out: &mut Rows<'_>,
               range_type: &str,
               vtype: Option<&str>,
               status: &str,
               events: Option<Vec<Value>>,
               versions: Vec<Value>,
               extra: JsonMap|
     -> Result<(), String> {
        // add_affected normalizes vendor and product (`.strip()` on a non-string raises)
        let (v, p) = (norm_checked(vendor)?, norm_checked(product)?);
        let mut x = base_extra.clone();
        for (k, val) in extra {
            x.insert(k, val);
        }
        let r = rows::affected(
            NAME,
            &rows_out.id,
            rows::Affected {
                ecosystem: ecosystem.map(str::to_owned),
                package: package.clone(),
                vendor: v,
                product: p,
                range_type: Some(range_type.into()),
                version_type: vtype.map(str::to_owned),
                events,
                versions,
                status: status.into(),
                extra: Value::Object(x),
                ..rows::Affected::default()
            },
        );
        rows_out.push(r)
    };

    let mut n = 0usize;
    let mut unaffected: Vec<Value> = Vec::new();
    for v in items(aff.get("versions"))? {
        let Some(v) = dict_item(&v) else {
            continue;
        };
        let status = {
            let s = [v.get("status"), aff.get("defaultStatus")]
                .into_iter()
                .flatten()
                .find(|x| py::truthy(x));
            s.map_or(String::new(), py::str_of).to_lowercase()
        };
        let vtype = py::strip(&str_or_empty(v.get("versionType"))).to_lowercase();
        let vtype = (!vtype.is_empty()).then_some(vtype);
        if status == "unaffected" {
            unaffected.push(Value::Object(v.clone()));
            continue;
        }
        if status != "affected" && !status.is_empty() {
            continue; // 'unknown'
        }
        let vt = vtype.as_deref();
        match convert_version_entry(v)? {
            Converted::Events(e) => {
                row(rows_out, "CVE", vt, "affected", Some(e), Vec::new(), JsonMap::new())?
            }
            Converted::Versions(vs) => {
                row(rows_out, "CVE", vt, "affected", None, vs, JsonMap::new())?
            }
            Converted::Git(e) => {
                row(rows_out, "GIT", vt, "affected", Some(e), Vec::new(), JsonMap::new())?
            }
            Converted::Unparsed => {
                let mut x = JsonMap::new();
                x.insert("raw".into(), Value::Object(v.clone()));
                row(rows_out, "CVE-UNPARSED", vt, "affected", None, Vec::new(), x)?;
            }
            Converted::Skip => continue,
        }
        n += 1;
    }
    // unaffected-only entries (Mozilla style) are kept as one status="unaffected" row
    if n == 0 && !unaffected.is_empty() {
        let mut x = JsonMap::new();
        x.insert("unaffected_versions".into(), Value::Array(unaffected));
        row(rows_out, "CVE", None, "unaffected", None, Vec::new(), x)?;
        n += 1;
    }
    // defaultStatus "affected" with no usable versions: keep the statement
    if n == 0 && str_or_empty(aff.get("defaultStatus")).to_lowercase() == "affected" {
        let mut x = JsonMap::new();
        x.insert("default_status".into(), json!("affected"));
        row(rows_out, "CVE-UNPARSED", None, "affected", None, Vec::new(), x)?;
    }
    Ok(())
}

/// The `seen` key of a cpeMatch (`matchCriteriaId or json.dumps(match, sort_keys=True)`), as Python compares it:
/// numbers and bools by value, strings by text, the dumped form in its own domain.
#[derive(Debug, PartialEq, Eq, Hash)]
enum SeenKey {
    Num(u64),
    Str(String),
    Dumps(String),
}

fn sorted_json(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .map(|k| (k.clone(), sorted_json(&m[k])))
                    .collect(),
            )
        }
        Value::Array(a) => Value::Array(a.iter().map(sorted_json).collect()),
        other => other.clone(),
    }
}

fn seen_key(m: &JsonMap) -> Result<SeenKey, String> {
    match m.get("matchCriteriaId") {
        Some(v) if py::truthy(v) => match v {
            Value::String(s) => Ok(SeenKey::Str(s.clone())),
            Value::Array(_) | Value::Object(_) => Err(format!(
                "TypeError: unhashable type: '{}'",
                py::type_name(v)
            )),
            other => {
                let f = py_float(other).unwrap_or(f64::NAN);
                Ok(SeenKey::Num(if f == 0.0 { 0 } else { f.to_bits() }))
            }
        },
        _ => Ok(SeenKey::Dumps(
            serde_json::to_string(&sorted_json(&Value::Object(m.clone()))).unwrap_or_default(),
        )),
    }
}

/// `_import_cpe_applicability`: one row per vulnerable cpeMatch of every node (breadth first), de-duplicated.
fn cpe_applicability(apps: Option<&Value>, rows_out: &mut Rows<'_>) -> Result<(), String> {
    let mut stack: VecDeque<Cow<'_, Value>> = VecDeque::new();
    for app in items(apps)? {
        let app = dict_of(&app)?;
        stack.extend(items(app.get("nodes"))?);
    }
    let mut seen: HashSet<SeenKey> = HashSet::new();
    while let Some(node) = stack.pop_front() {
        let node = dict_of(&node)?;
        stack.extend(items(node.get("children"))?);
        for m in items(node.get("cpeMatch"))? {
            let m = dict_of(&m)?;
            if m.get("vulnerable") == Some(&Value::Bool(false)) {
                continue;
            }
            let Some(crit) = m.get("criteria").filter(|v| py::truthy(v)) else {
                continue;
            };
            let key = seen_key(m)?;
            if seen.contains(&key) {
                continue;
            }
            seen.insert(key);
            let Value::String(crit) = crit else {
                return Err(format!(
                    "TypeError: expected string or bytes-like object, got '{}'",
                    py::type_name(crit)
                ));
            };
            let fields = crate::nvd::cpe_fields(crit);
            if fields.len() < 6 || fields[0] != "cpe" {
                continue;
            }
            let (vendor, product, raw_ver) = (&fields[3], &fields[4], fields[5].as_str());
            let update = fields.get(6).map_or("*", String::as_str);
            let exact = (!matches!(raw_ver, "*" | "-" | "")).then_some(raw_ver);
            let mut events: Vec<Value> = Vec::new();
            let mut dropped = JsonMap::new();
            let mut start: Option<(&str, &Value)> = None;
            for (field, key) in [
                ("versionStartIncluding", "introduced"),
                ("versionStartExcluding", "introduced_exclusive"),
            ] {
                if let Some(val) = m.get(field).filter(|v| py::truthy(v)) {
                    if is_version_like(Some(val)) {
                        start.get_or_insert((key, val));
                    } else {
                        dropped.insert(field.into(), val.clone());
                    }
                }
            }
            let mut end: Option<(&str, &Value)> = None;
            for (field, key) in [
                ("versionEndExcluding", "fixed"),
                ("versionEndIncluding", "last_affected"),
            ] {
                if let Some(val) = m.get(field).filter(|v| py::truthy(v)) {
                    if is_version_like(Some(val)) {
                        end = Some((key, val));
                    } else {
                        dropped.insert(field.into(), val.clone());
                    }
                }
            }
            let obj = |k: &str, v: &Value| {
                let mut e = JsonMap::new();
                e.insert(k.to_owned(), v.clone());
                Value::Object(e)
            };
            if start.is_some() || end.is_some() {
                events.push(match start {
                    Some((k, v)) => obj(k, v),
                    None => ev("introduced", "0"),
                });
                if let Some((k, v)) = end {
                    events.push(obj(k, v));
                }
            } else if exact.is_none() && raw_ver == "*" && dropped.is_empty() {
                events.push(ev("introduced", "0")); // wildcard, no bounds: all versions
            }
            let versions: Vec<Value> = match exact {
                Some(x) if events.is_empty() && version_like(x) => vec![json!(x)],
                _ => Vec::new(),
            };
            let mut extra = JsonMap::new();
            extra.insert("container".into(), json!("cna"));
            let dropped_update = !matches!(update, "*" | "-" | "");
            if dropped_update {
                extra.insert("cpe_update".into(), json!(update));
            }
            let has_dropped = !dropped.is_empty();
            if has_dropped {
                extra.insert("dropped_bounds".into(), Value::Object(dropped));
            }
            let range_type = if has_dropped || dropped_update {
                "CVE-UNPARSED"
            } else {
                "CPE"
            };
            let r = rows::affected(
                NAME,
                &rows_out.id,
                rows::Affected {
                    vendor: Some(vendor.clone()),
                    product: Some(product.clone()),
                    cpe: Some(crit.clone()),
                    range_type: Some(range_type.into()),
                    events: (!events.is_empty()).then_some(events),
                    versions,
                    extra: Value::Object(extra),
                    ..rows::Affected::default()
                },
            );
            rows_out.push(r)?;
        }
    }
    Ok(())
}

/// `import_record`: the rows of one parsed record. `Ok(None)`: not a CVE record (no `cveMetadata.cveId`), nothing
/// written; `Err`: what Python raises inside the record's SAVEPOINT (the record is then left as it was).
fn plan_record(rec: &Value, caps: &Caps) -> Result<Option<Planned>, String> {
    let empty = JsonMap::new();
    let Value::Object(r) = rec else {
        return Ok(None);
    };
    let Some(Value::Object(meta)) = r.get("cveMetadata") else {
        return Ok(None);
    };
    let Some(id_v) = meta.get("cveId").filter(|v| py::truthy(v)) else {
        return Ok(None);
    };
    let id = match text(Some(id_v), "?", "cveId")? {
        Some(s) => s,
        None => return Ok(None),
    };
    let state = meta.get("state");
    let rejected = state.and_then(Value::as_str) == Some("REJECTED");
    let modified = text(meta.get("dateUpdated"), &id, "dateUpdated")?;
    let containers = dict_or_empty(r.get("containers"), &empty)?;
    let cna = dict_or_empty(containers.get("cna"), &empty)?;
    let adps: Vec<&JsonMap> = items(containers.get("adp"))?
        .filter_map(|a| dict_item(&a))
        .collect();

    let mut summary = if rejected {
        english(cna.get("rejectedReasons"))?
    } else {
        None
    };
    if summary.is_none() {
        summary = english(cna.get("descriptions"))?;
        if summary.is_none() {
            summary = get(cna, "title").cloned();
        }
    }

    let mut extra = JsonMap::new();
    let mut vuln = rows::Vulnerability::default();
    if let Some((metric, prov)) = best_cvss(cna, &adps)? {
        let score = py_float(get(metric, "baseScore").unwrap_or(&Value::Null))?;
        vuln.cvss_score = Some(score);
        vuln.cvss_vector = text(metric.get("vectorString"), &id, "vectorString")?;
        vuln.cvss_version = get(metric, "version").map(py::str_of);
        vuln.severity = match metric.get("baseSeverity").filter(|v| py::truthy(v)) {
            Some(sev) => rows::normalize_severity(Some(&py::str_of(sev))),
            None => rows::severity_from_score(Some(score)).map(str::to_owned),
        };
        extra.insert("cvss_source".into(), json!(prov));
    }
    let mut cwes = cwes_of(cna)?;
    if cwes.is_empty() {
        for a in &adps {
            cwes = cwes_of(a)?;
            if !cwes.is_empty() {
                break;
            }
        }
    }
    if let Some(s) = ssvc(&adps)? {
        extra.insert("ssvc".into(), Value::Object(s));
    }
    if let Some(k) = adp_other(&adps, "kev")?.filter(|k| !k.is_empty()) {
        extra.insert("adp_kev".into(), Value::Object(k.clone()));
    }
    if let Some(a) = meta.get("assignerShortName").filter(|v| py::truthy(v)) {
        extra.insert("assigner".into(), a.clone());
    }
    if let Some(t) = cna.get("title").filter(|v| py::truthy(v)) {
        extra.insert("title".into(), t.clone());
    }
    let mut refs: Vec<Value> = Vec::new();
    for c in std::iter::once(cna).chain(adps.iter().copied()) {
        for rf in items(c.get("references"))? {
            let rf = dict_of(&rf)?;
            if let Some(u) = rf.get("url").filter(|v| py::truthy(v))
                && !refs.iter().any(|x| py_eq(x, u))
            {
                refs.push(u.clone());
            }
        }
    }
    if !refs.is_empty() {
        refs.truncate(20);
        extra.insert("references".into(), Value::Array(refs));
    }

    vuln.summary = text(summary.as_ref(), &id, "summary")?;
    vuln.published = text(meta.get("datePublished"), &id, "datePublished")?;
    vuln.modified = modified.clone();
    vuln.withdrawn = if rejected {
        text(meta.get("dateRejected"), &id, "dateRejected")?
    } else {
        None
    };
    vuln.state = text(state, &id, "state")?;
    vuln.extra = if extra.is_empty() {
        Value::Null
    } else {
        Value::Object(extra)
    };
    let mut vulnerability = rows::vulnerability(NAME, &id, vuln);
    if let RowOp::Upsert { row, .. } = &mut vulnerability {
        row.insert("cwes".into(), Value::Array(cwes)); // any JSON value Python keeps, not only strings
    }

    let mut out = Rows {
        id: id.clone(),
        out: Vec::new(),
        caps,
    };
    if !rejected {
        for aff in items(cna.get("affected"))? {
            if let Some(aff) = dict_item(&aff) {
                affected_entry(aff, "cna", &mut out)?;
            }
        }
        for a in &adps {
            let container = format!("adp:{}", adp_short(a, "adp")?);
            for aff in items(a.get("affected"))? {
                if let Some(aff) = dict_item(&aff) {
                    affected_entry(aff, &container, &mut out)?;
                }
            }
        }
        cpe_applicability(cna.get("cpeApplicability"), &mut out)?;
    }
    Ok(Some(Planned {
        id,
        modified,
        vulnerability,
        affected: out.out,
    }))
}

/// The CVE id the stored rows of a record are read for (`cveMetadata.cveId` when it is a non-empty string).
fn record_id(rec: &Value) -> Option<&str> {
    rec.get("cveMetadata")?
        .get("cveId")?
        .as_str()
        .filter(|s| !s.is_empty())
}

// ------------------------------------------------------------------------------------------------ git

/// The git mode's fixed configuration for one run.
#[derive(Debug, Clone)]
struct GitCfg {
    program: OsString,
    url: String,
    repo: PathBuf,
    timeout: Duration,
    out_cap: usize,
    since: Option<String>,
    full: bool,
}

/// A failed git call: `Failed` is Python's `CalledProcessError` (a non-zero exit), `Other` a timeout, a program
/// that could not run, or an output over the cap (`TimeoutExpired`, `OSError`).
#[derive(Debug)]
enum GitErr {
    Failed(String),
    Other(String),
}

impl GitErr {
    fn detail(&self) -> &str {
        match self {
            GitErr::Failed(m) | GitErr::Other(m) => m,
        }
    }
}

/// Read a pipe to its end, keeping at most `cap` bytes (`true` when more came).
fn drain(mut r: impl Read, cap: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    let mut over = false;
    loop {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if out.len() + n > cap {
                    over = true;
                    out.extend_from_slice(&buf[..cap.saturating_sub(out.len())]);
                } else if !over {
                    out.extend_from_slice(&buf[..n]);
                }
            }
        }
    }
    (out, over)
}

impl GitCfg {
    /// One git call (`_git`): `git <harden> <args>` in `cwd`, no shell, stdin empty, the environment cleared down to
    /// [`GIT_PASS_ENV`] plus `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=<null device>`, `GIT_TERMINAL_PROMPT=0`,
    /// `LC_ALL=C`; at most `timeout` (then killed), standard output at most `out_cap` bytes. The output, stripped.
    fn git(&self, args: &[&str], cwd: Option<&Path>) -> Result<String, GitErr> {
        use std::process::{Command, Stdio};
        let shown = format!("git {}", args.first().copied().unwrap_or(""));
        let mut c = Command::new(&self.program);
        c.args(GIT_HARDEN).args(args).env_clear();
        for k in GIT_PASS_ENV {
            if let Some(v) = std::env::var_os(k) {
                c.env(k, v);
            }
        }
        c.env("GIT_CONFIG_NOSYSTEM", "1")
            .env(
                "GIT_CONFIG_GLOBAL",
                if cfg!(windows) { "NUL" } else { "/dev/null" },
            )
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(d) = cwd {
            c.current_dir(d);
        }
        let mut child = c
            .spawn()
            .map_err(|e| GitErr::Other(feed::os_error(&e, Path::new(&self.program))))?;
        let (out, err) = (child.stdout.take(), child.stderr.take());
        let cap = self.out_cap;
        let t_out = std::thread::spawn(move || out.map(|o| drain(o, cap)).unwrap_or_default());
        let t_err =
            std::thread::spawn(move || err.map(|e| drain(e, GIT_STDERR)).unwrap_or_default());
        let deadline = Instant::now() + self.timeout;
        let mut pause = Duration::from_millis(2);
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if Instant::now() >= deadline => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = (t_out.join(), t_err.join());
                    return Err(GitErr::Other(format!(
                        "Command '{shown}' timed out after {} seconds",
                        self.timeout.as_secs()
                    )));
                }
                Ok(None) => {
                    std::thread::sleep(pause);
                    pause = (pause * 2).min(Duration::from_millis(50));
                }
                Err(e) => return Err(GitErr::Other(e.to_string())),
            }
        };
        let (stdout, over) = t_out.join().unwrap_or_default();
        let (stderr, _) = t_err.join().unwrap_or_default();
        if over {
            return Err(GitErr::Other(format!(
                "{shown}: output larger than {cap} bytes"
            )));
        }
        if !status.success() {
            let e = String::from_utf8_lossy(&stderr).into_owned();
            return Err(GitErr::Failed(if py::strip(&e).is_empty() {
                format!(
                    "Command '{shown}' returned non-zero exit status {}.",
                    status.code().unwrap_or(-1)
                )
            } else {
                e
            }));
        }
        Ok(py::strip(&String::from_utf8_lossy(&stdout)).to_owned())
    }

    /// `_origin_matches`: the clone's `remote.origin.url` is the configured URL (a failing `git config` is `false`).
    fn origin_matches(&self) -> Result<bool, GitErr> {
        if !self.repo.join(".git").is_dir() {
            return Ok(false);
        }
        match self.git(
            &["config", "--local", "--get", "remote.origin.url"],
            Some(&self.repo),
        ) {
            Ok(u) => Ok(u == self.url),
            Err(GitErr::Failed(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }
}

/// What the git phase leaves for the walk.
#[derive(Debug, Default, Clone)]
struct GitDone {
    head: String,
    years: Vec<String>,
}

/// The files of the git phase: the changed ones first, then the walked years.
#[derive(Debug)]
struct GitPrep {
    done: GitDone,
    changed: Vec<PathBuf>,
    dirs: Vec<PathBuf>,
}

/// `_SHA_RE` (`$` also before a final newline).
fn sha_like(s: &str) -> bool {
    let s = s.strip_suffix('\n').unwrap_or(s);
    (s.len() == 40 || s.len() == 64) && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `_years`: the previous and current year, widened by `--since` (`\d{4}` at its start) and the oldest year synced.
fn years_of(since: Option<&str>, oldest: Option<i64>, cur: i64) -> Vec<String> {
    let mut start = cur - 1;
    if let Some(s) = since {
        let four: Vec<u32> = s.chars().take(4).map_while(digit_value).collect();
        if four.len() == 4 && s.chars().take(4).all(py::is_decimal) {
            let y = four.iter().fold(0i64, |a, d| a * 10 + i64::from(*d));
            start = start.min(y).min(cur);
        }
    }
    if let Some(o) = oldest {
        start = start.min(o);
    }
    (start..=cur).map(|y| y.to_string()).collect()
}

/// `cache_subdir`: the clone directory created 0700, a symlink refused, group/other permissions removed.
fn private_dir(path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut b = std::fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(path)?;
    let meta = std::fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} is a symlink; refusing to use it",
                feed::py_path(path)
            ),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o077 != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

/// The git phase of `_sync_git` (blocking): the clone brought to upstream HEAD, the changed files and the years to
/// walk. `Err`: the detail of `git failed: <detail>`.
fn git_phase(
    cfg: &GitCfg,
    stored_years: Option<String>,
    stored_cursor: Option<String>,
    cur_year: i64,
    say: &Progress,
) -> Result<GitPrep, String> {
    let oldest = stored_years
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .map(|s| s.parse::<i64>().unwrap_or(i64::MAX));
    let years = years_of(cfg.since.as_deref(), oldest, cur_year);
    let sparse: Vec<String> = years.iter().map(|y| format!("cves/{y}")).collect();
    let mut old = stored_cursor.filter(|s| sha_like(s) && !cfg.full);
    let mut changed: Option<Vec<PathBuf>> = None;
    let repo = &cfg.repo;
    let io = |e: std::io::Error| e.to_string();
    let g = |e: GitErr| e.detail().to_owned();

    if std::fs::symlink_metadata(repo).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(format!(
            "{} is a symlink; refusing to use it",
            feed::py_path(repo)
        ));
    }
    private_dir(repo).map_err(io)?;
    if repo.join(".git").exists() && !cfg.origin_matches().map_err(g)? {
        say.line(format!(
            "{NAME}: cache has a foreign/unknown origin; re-cloning"
        ));
        std::fs::remove_dir_all(repo).map_err(io)?;
    }
    let fresh = !repo.join(".git").exists();
    if fresh {
        private_dir(repo).map_err(io)?;
        say.line(format!("{NAME}: cloning (partial, sparse)"));
        let target = repo.to_string_lossy().into_owned();
        cfg.git(
            &[
                "clone",
                "--depth",
                "1",
                "--filter=blob:none",
                "--sparse",
                "--",
                &cfg.url,
                &target,
            ],
            None,
        )
        .map_err(g)?;
        old = None;
    }
    let new_years: Vec<String> = years
        .iter()
        .filter(|y| !repo.join("cves").join(y).exists())
        .cloned()
        .collect();
    let mut add: Vec<&str> = vec!["sparse-checkout", "add"];
    add.extend(sparse.iter().map(String::as_str));
    cfg.git(&add, Some(repo)).map_err(g)?;

    let walk_years: Vec<String> = if fresh {
        years.clone()
    } else {
        // always bring the cache to upstream HEAD; the cursor only picks diff vs full walk
        cfg.git(&["fetch", "--depth", "1", "origin", "main"], Some(repo))
            .map_err(g)?;
        let new_sha = cfg.git(&["rev-parse", "FETCH_HEAD"], Some(repo)).map_err(g)?;
        let mut walk = years.clone();
        if let Some(o) = &old {
            walk = new_years;
            if new_sha != *o {
                match cfg.git(
                    &[
                        "diff",
                        "--name-only",
                        "--no-renames",
                        "--end-of-options",
                        o,
                        &new_sha,
                        "--",
                        "cves",
                    ],
                    Some(repo),
                ) {
                    Ok(names) => {
                        changed = Some(
                            names
                                .lines()
                                .filter(|n| n.ends_with(".json"))
                                .map(|n| repo.join(n))
                                .collect(),
                        );
                    }
                    Err(GitErr::Failed(_)) => {
                        // shallow history: old commit not available -> rely on dateUpdated comparison
                        say.line(format!(
                            "{NAME}: diff unavailable, falling back to dateUpdated comparison"
                        ));
                        walk = years.clone();
                    }
                    Err(e) => return Err(g(e)),
                }
            } else {
                changed = Some(Vec::new());
            }
        }
        cfg.git(&["reset", "--hard", "FETCH_HEAD"], Some(repo))
            .map_err(g)?;
        cfg.git(&["sparse-checkout", "reapply"], Some(repo))
            .map_err(g)?;
        walk
    };
    let head = cfg.git(&["rev-parse", "HEAD"], Some(repo)).map_err(g)?;
    Ok(GitPrep {
        done: GitDone { head, years },
        changed: changed.unwrap_or_default(),
        dirs: walk_years
            .iter()
            .map(|y| repo.join("cves").join(y))
            .collect(),
    })
}

// ------------------------------------------------------------------------------------------------ files

/// The files of a run, produced lazily: the changed files of the git diff first (only those that exist), then each
/// directory's `CVE-*.json` files sorted as Python sorts paths (by component); repeats skipped in git mode.
#[derive(Debug, Default)]
struct Walk {
    changed: VecDeque<PathBuf>,
    dirs: VecDeque<PathBuf>,
    cur: VecDeque<(PathBuf, String)>,
    seen: Option<HashSet<PathBuf>>,
    /// Git mode: files are read only below the clone (`read_within`).
    boundary: Option<PathBuf>,
    /// Files handed out so far (all walks of the run).
    files: usize,
}

/// One file read and parsed.
#[derive(Debug)]
struct Loaded {
    shown: String,
    rec: Result<Value, String>,
}

/// A run-level failure of a walk (a cap).
#[derive(Debug)]
struct WalkFail(String);

fn list_dir(dir: &Path, shown: &str, caps: &Caps) -> Result<Vec<(PathBuf, String)>, WalkFail> {
    let found = feed::rglob(dir, shown, ".json", caps.entries, caps.files).map_err(|t| {
        WalkFail(match t {
            feed::TooMany::Entries => format!(
                "{NAME}: more than {} directory entries under {shown}; refusing",
                caps.entries
            ),
            feed::TooMany::Files => format!(
                "{NAME}: more than {} files under {shown}; refusing",
                caps.files
            ),
        })
    })?;
    let mut out: Vec<(PathBuf, String)> = found
        .into_iter()
        .filter(|f| f.name.starts_with("CVE-"))
        .map(|f| (f.path, f.shown))
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

impl Walk {
    /// The next file, or `None` at the end.
    fn next_file(&mut self, caps: &Caps) -> Result<Option<(PathBuf, String)>, WalkFail> {
        loop {
            let next = if let Some(p) = self.changed.pop_front() {
                if !p.exists() {
                    continue;
                }
                let s = p.to_string_lossy().into_owned();
                (p, s)
            } else if let Some(f) = self.cur.pop_front() {
                f
            } else if let Some(d) = self.dirs.pop_front() {
                let is_dir = std::fs::metadata(&d).is_ok_and(|m| m.is_dir());
                if !is_dir {
                    continue; // `_walk(d) if d.exists() else []`
                }
                let shown = d.to_string_lossy().into_owned();
                self.cur = list_dir(&d, &shown, caps)?.into();
                continue;
            } else {
                return Ok(None);
            };
            if let Some(seen) = self.seen.as_mut()
                && !seen.insert(next.0.clone())
            {
                continue;
            }
            self.files += 1;
            if self.files > caps.files {
                return Err(WalkFail(format!(
                    "{NAME}: more than {} files in one run; refusing",
                    caps.files
                )));
            }
            return Ok(Some(next));
        }
    }

    /// Read one file: below the clone through `read_within` (no symlink out of it, a regular file), else a regular
    /// file (symlinks followed); at most `cap` bytes; strict UTF-8; JSON.
    fn read(&self, path: &Path, shown: &str, cap: u64) -> (Result<Value, String>, u64) {
        match self.read_bytes(path, shown, cap) {
            Err(e) => (Err(e), 0),
            Ok(body) => {
                let rec = py::decode_utf8(&body)
                    .map_err(|m| format!("UnicodeDecodeError: {m}"))
                    .and_then(|t| {
                        serde_json::from_str(t).map_err(|e| format!("JSONDecodeError: {e}"))
                    });
                (rec, body.len() as u64)
            }
        }
    }

    fn read_bytes(&self, path: &Path, shown: &str, cap: u64) -> Result<Vec<u8>, String> {
        let too_large = || format!("{NAME}: {shown}: larger than {cap} bytes; refusing");
        match &self.boundary {
            Some(b) => secmonk_safeio::read_within(path, b, cap).map_err(|e| match e {
                secmonk_safeio::WithinError::Io(io) => {
                    format!("{}: {}", feed::py_exception(&io), feed::os_error(&io, path))
                }
                secmonk_safeio::WithinError::TooLarge(..) => too_large(),
                other => format!("{NAME}: {other}"),
            }),
            None => {
                let f = feed::open_regular(path).map_err(|e| e.with_class())?;
                let mut body = Vec::new();
                f.take(cap + 1).read_to_end(&mut body).map_err(|e| {
                    format!("{}: {}", feed::py_exception(&e), feed::os_error(&e, path))
                })?;
                if body.len() as u64 > cap {
                    return Err(too_large());
                }
                Ok(body)
            }
        }
    }

    /// The next group of files, read and parsed (blocking): at most [`GROUP`] files, taken in rounds of [`READERS`]
    /// files read on as many threads (opening a file dominates the cost), until [`GROUP_BYTES`] of text.
    fn next_group(&mut self, caps: &Caps) -> Result<Vec<Loaded>, WalkFail> {
        let mut out: Vec<Loaded> = Vec::new();
        let mut bytes = 0u64;
        while out.len() < GROUP && bytes < GROUP_BYTES {
            let mut round: Vec<(PathBuf, String)> = Vec::new();
            while round.len() < READERS && out.len() + round.len() < GROUP {
                match self.next_file(caps)? {
                    Some(f) => round.push(f),
                    None => break,
                }
            }
            if round.is_empty() {
                break;
            }
            let me: &Walk = self;
            let read: Vec<(Loaded, u64)> = std::thread::scope(|s| {
                let handles: Vec<_> = round
                    .into_iter()
                    .map(|(path, shown)| {
                        s.spawn(move || {
                            let (rec, n) = me.read(&path, &shown, caps.file_bytes);
                            (Loaded { shown, rec }, n)
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| {
                        h.join().unwrap_or_else(|_| {
                            (
                                Loaded {
                                    shown: String::new(),
                                    rec: Err(format!("{NAME}: native importer: a reading thread failed")),
                                },
                                0,
                            )
                        })
                    })
                    .collect()
            });
            for (l, n) in read {
                bytes += n;
                out.push(l);
            }
        }
        Ok(out)
    }
}

// ------------------------------------------------------------------------------------------------ the run

/// The mode of a run (its end message).
#[derive(Debug)]
enum Mode {
    /// `--path`, shown as Python's `str(path)`.
    Path(String),
    Ids,
    Git(GitDone),
}

/// Where the next operations come from.
enum Input {
    /// `--path` before its listing.
    PathPending(PathBuf),
    /// Git mode before its git phase.
    GitPending(GitCfg),
    Files(Box<Walk>),
    Ids {
        client: reqwest::Client,
        base: String,
        allow_http: bool,
        ids: VecDeque<String>,
    },
    Done,
}

/// What this run emitted for one CVE id (an id seen again replaces those rows, not the stored ones).
#[derive(Debug, Clone)]
struct Emitted {
    rows: u32,
    modified: Option<String>,
}

/// The state of one run (the operation stream).
struct Run {
    view: Arc<dyn MirrorView>,
    caps: Caps,
    now: String,
    limit: Option<u64>,
    full: bool,
    count: u64,
    errors: u64,
    /// Files taken so far (`enumerate(files)`).
    index: u64,
    hit_limit: bool,
    base_total: u64,
    new_ids: u64,
    emitted: HashMap<String, Emitted>,
    say: Progress,
    /// The call's context (a second progress handle for the git phase on the blocking pool).
    ctx: CallCtx,
    input: Input,
    mode: Mode,
    tail: TailCell,
    done: bool,
}

/// The operations of the run, one group at a time.
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

/// The stored rows of a group of records.
struct Stored {
    modified: HashMap<String, Value>,
    affected: Vec<JsonMap>,
    /// The ids whose `affected` rows were read.
    read: HashSet<String>,
}

/// A record whose stored row is at least as new (`_is_newer` false for certain, whatever else the group holds).
fn surely_not_newer(rec: &Value, stored_modified: Option<&Value>) -> bool {
    let updated = rec
        .get("cveMetadata")
        .and_then(|m| m.get("dateUpdated"))
        .and_then(Value::as_str);
    match (stored_modified.and_then(Value::as_str), updated) {
        (Some(m), Some(u)) => !m.is_empty() && !u.is_empty() && m >= u,
        _ => false,
    }
}

impl Run {
    fn set_tail(&mut self, t: Tail) {
        if let Ok(mut g) = self.tail.lock() {
            *g = Some(t);
        }
        self.done = true;
        self.input = Input::Done;
    }

    /// A run that fails before or outside its records (`git failed: ...`, a missing path, a cap): status `error`.
    fn fail_run(&mut self, message: String) {
        self.set_tail(Tail {
            status: "error".into(),
            message: Some(message),
            ..Tail::default()
        });
    }

    fn total(&self) -> u64 {
        self.base_total + self.new_ids
    }

    /// The end of a run that went through its input (also when the limit stopped it); the internal git rows.
    fn finish(&mut self) -> Vec<RowOp> {
        let (count, errors) = (self.count, self.errors);
        let partial = if errors > 0 { "partial" } else { "ok" };
        let mut ops = Vec::new();
        let tail = match &self.mode {
            Mode::Path(shown) => Tail {
                status: partial.into(),
                records: count,
                total: Some(self.total()),
                cursor: None,
                message: Some(format!("imported {count} from {shown}")),
            },
            Mode::Ids => Tail {
                status: partial.into(),
                records: count,
                total: Some(self.total()),
                cursor: None,
                message: Some(format!("fetched {count} ids")),
            },
            Mode::Git(g) => {
                let complete = !self.hit_limit && errors == 0;
                let short: String = g.head.chars().take(10).collect();
                if complete {
                    // only a fully imported run may advance the internal cursor / widen the synced year range
                    ops.push(native::sync_row(
                        GIT_KEY,
                        "ok",
                        0,
                        Some(g.head.clone()),
                        Some(format!("git {short}")),
                        &self.now,
                    ));
                    ops.push(native::sync_row(
                        YEARS_KEY,
                        "ok",
                        0,
                        g.years.first().cloned(),
                        Some("oldest synced year".into()),
                        &self.now,
                    ));
                }
                let mut message = format!(
                    "git {short}, years {}..{}",
                    g.years.first().map_or("", String::as_str),
                    g.years.last().map_or("", String::as_str)
                );
                if self.hit_limit {
                    message.push_str(", limit reached");
                }
                if errors > 0 {
                    message.push_str(&format!(", {errors} record errors"));
                }
                Tail {
                    status: if complete { "ok" } else { "partial" }.into(),
                    records: count,
                    total: Some(self.total()),
                    cursor: complete.then(|| g.head.clone()),
                    message: Some(message),
                }
            }
        };
        self.set_tail(tail);
        ops
    }

    /// The next operations, or `None` once the tail is set.
    async fn next_ops(&mut self) -> StepResult<Option<Vec<RowOp>>> {
        if self.done {
            return Ok(None);
        }
        match std::mem::replace(&mut self.input, Input::Done) {
            Input::Done => Ok(Some(self.finish())),
            Input::PathPending(p) => {
                self.start_path(p).await?;
                Ok(Some(Vec::new()))
            }
            Input::GitPending(cfg) => {
                self.start_git(cfg).await?;
                Ok(Some(Vec::new()))
            }
            Input::Files(walk) => self.next_files(walk).await.map(Some),
            Input::Ids {
                client,
                base,
                allow_http,
                mut ids,
            } => {
                let ops = self.next_id(&client, &base, allow_http, &mut ids).await?;
                if !self.done && !ids.is_empty() {
                    self.input = Input::Ids {
                        client,
                        base,
                        allow_http,
                        ids,
                    };
                }
                Ok(Some(ops))
            }
        }
    }

    /// `--path`: `path.exists()`, then the file itself or the sorted `CVE-*.json` files below the directory.
    async fn start_path(&mut self, p: PathBuf) -> StepResult<()> {
        let shown = feed::py_path(&p);
        let caps = self.caps;
        let listed = tokio::task::spawn_blocking(move || -> Result<Walk, String> {
            let meta = match feed::exists_like_python(&p) {
                Ok(Some(m)) => m,
                Ok(None) => return Err(format!("path not found: {shown}")),
                Err(e) => return Err(format!("git failed: {}", first_300(&e))),
            };
            let mut walk = Walk::default();
            if meta.is_file() {
                walk.cur.push_back((p.clone(), shown));
            } else if meta.is_dir() {
                walk.cur = list_dir(&p, &shown, &caps).map_err(|f| f.0)?.into();
            } else {
                return Err(format!(
                    "{NAME}: not a regular file or a directory: {}",
                    feed::py_repr(&shown)
                ));
            }
            Ok(walk)
        })
        .await
        .map_err(|e| native::internal(NAME, format!("listing task failed: {e}")))?;
        match listed {
            Ok(walk) => self.input = Input::Files(Box::new(walk)),
            Err(m) => self.fail_run(m),
        }
        Ok(())
    }

    /// The stored cursor of an internal `source_sync` row (`get_sync_cursor`).
    async fn cursor_of(&self, key: &str) -> StepResult<Option<String>> {
        let page = self
            .view
            .rows_page(MirrorTable::SourceSync, key, None, 1)
            .await?;
        Ok(page
            .rows
            .first()
            .and_then(|r| r.get("cursor"))
            .and_then(Value::as_str)
            .map(str::to_owned))
    }

    /// Git mode: the git phase on the blocking pool, then the walk.
    async fn start_git(&mut self, cfg: GitCfg) -> StepResult<()> {
        let stored_years = self.cursor_of(YEARS_KEY).await?;
        let stored_cursor = self.cursor_of(GIT_KEY).await?;
        let cur_year: i64 = self.now.get(..4).and_then(|y| y.parse().ok()).unwrap_or(1970);
        let say = Progress::new(&self.ctx);
        let repo = cfg.repo.clone();
        let prep = tokio::task::spawn_blocking(move || {
            git_phase(&cfg, stored_years, stored_cursor, cur_year, &say)
        })
        .await
        .map_err(|e| native::internal(NAME, format!("git task failed: {e}")))?;
        match prep {
            Ok(p) => {
                let boundary = repo.canonicalize().unwrap_or(repo);
                self.mode = Mode::Git(p.done);
                self.input = Input::Files(Box::new(Walk {
                    changed: p.changed.into(),
                    dirs: p.dirs.into(),
                    seen: Some(HashSet::new()),
                    boundary: Some(boundary),
                    ..Walk::default()
                }));
            }
            Err(detail) => self.fail_run(format!("git failed: {}", first_300(&detail))),
        }
        Ok(())
    }

    /// The next group of files (`_import_files`).
    async fn next_files(&mut self, walk: Box<Walk>) -> StepResult<Vec<RowOp>> {
        let caps = self.caps;
        let (walk, group) = tokio::task::spawn_blocking(move || {
            let mut walk = walk;
            let g = walk.next_group(&caps);
            (walk, g)
        })
        .await
        .map_err(|e| native::internal(NAME, format!("reading task failed: {e}")))?;
        let group = match group {
            Ok(g) => g,
            Err(WalkFail(m)) => {
                self.fail_run(m);
                return Ok(Vec::new());
            }
        };
        if group.is_empty() {
            return Ok(self.finish());
        }
        self.input = Input::Files(walk);
        let stored = self.stored(&group).await?;
        let mut ops = Vec::new();
        for item in group {
            if self.limit.is_some_and(|l| self.count >= l) {
                self.hit_limit = true;
                return Ok({
                    let mut o = ops;
                    o.extend(self.finish());
                    o
                });
            }
            self.index += 1;
            match item.rec {
                Err(e) => self.record_error(&item.shown, &e),
                Ok(rec) => {
                    let is_record = rec.as_object().is_some_and(|m| m.contains_key("cveMetadata"));
                    if is_record {
                        let newer = if self.full {
                            Ok(true)
                        } else {
                            self.is_newer(&rec, &stored)
                        };
                        match newer {
                            Err(e) => self.record_error(&item.shown, &e),
                            Ok(false) => {}
                            Ok(true) => self.import(rec, &stored, &item.shown, &mut ops),
                        }
                    }
                }
            }
            if self.index.is_multiple_of(500) {
                self.say.line(format!("{NAME}: {} records", self.count));
            }
        }
        Ok(ops)
    }

    /// A record that failed: counted; logged as Python logs it (`skipping <file>` / `<id>` in the ids mode).
    fn record_error(&mut self, shown: &str, e: &str) {
        self.errors += 1;
        self.say.line(match self.mode {
            Mode::Ids => format!("{NAME}: {shown}: {e}"),
            _ => format!("{NAME}: skipping {shown}: {e}"),
        });
    }

    /// The stored `vulnerability.modified` and `affected` rows of the records of a group not emitted yet.
    async fn stored(&self, group: &[Loaded]) -> StepResult<Stored> {
        let mut ids: Vec<String> = Vec::new();
        for l in group {
            if let Ok(rec) = &l.rec
                && let Some(id) = record_id(rec)
                && !self.emitted.contains_key(id)
                && !ids.iter().any(|i| i == id)
            {
                ids.push(id.to_owned());
            }
        }
        let mut out = Stored {
            modified: HashMap::new(),
            affected: Vec::new(),
            read: HashSet::new(),
        };
        if ids.is_empty() {
            return Ok(out);
        }
        for r in self
            .view
            .rows_by_id(MirrorTable::Vulnerability, NAME, &ids)
            .await?
        {
            if let Some(id) = r.get("id").and_then(Value::as_str) {
                out.modified.insert(
                    id.to_owned(),
                    r.get("modified").cloned().unwrap_or(Value::Null),
                );
            }
        }
        // the affected rows only of the ids a record of the group may be imported for: an unchanged re-sync reads none
        let check = matches!(self.mode, Mode::Path(_) | Mode::Git(_)) && !self.full;
        let need: Vec<String> = ids
            .into_iter()
            .filter(|id| {
                !check
                    || group.iter().any(|l| match &l.rec {
                        Ok(rec) if record_id(rec) == Some(id.as_str()) => {
                            !surely_not_newer(rec, out.modified.get(id.as_str()))
                        }
                        _ => false,
                    })
            })
            .collect();
        if !need.is_empty() {
            out.affected = self
                .view
                .rows_by_id(MirrorTable::Affected, NAME, &need)
                .await?;
        }
        out.read = need.into_iter().collect();
        Ok(out)
    }

    /// `_is_newer`: no stored row, or a stored `modified` older than `dateUpdated` (either missing: newer).
    fn is_newer(&self, rec: &Value, stored: &Stored) -> Result<bool, String> {
        let empty = JsonMap::new();
        let meta = dict_or_empty(rec.get("cveMetadata"), &empty)?;
        let id = match meta.get("cveId") {
            None | Some(Value::Null) => return Ok(true),
            Some(Value::String(s)) => s.as_str(),
            Some(x @ (Value::Array(_) | Value::Object(_))) => {
                return Err(format!(
                    "ProgrammingError: Error binding parameter 1: type '{}' is not supported",
                    py::type_name(x)
                ));
            }
            Some(_) => return Ok(true), // a non-string id never matches a stored one (refused when imported)
        };
        let row_modified: Option<Value> = match self.emitted.get(id) {
            Some(e) => Some(e.modified.clone().map_or(Value::Null, Value::String)),
            None => stored.modified.get(id).cloned(),
        };
        let Some(row_modified) = row_modified else {
            return Ok(true);
        };
        let updated = meta.get("dateUpdated");
        match (&row_modified, updated) {
            (Value::String(m), Some(u)) if !m.is_empty() && py::truthy(u) => match u {
                Value::String(u) => Ok(m.as_str() < u.as_str()),
                other => Err(format!(
                    "TypeError: '>=' not supported between instances of 'str' and '{}'",
                    py::type_name(other)
                )),
            },
            _ => Ok(true),
        }
    }

    /// `_import_guarded`: plan the record; emit its rows, or count the error and emit nothing.
    fn import(&mut self, rec: Value, stored: &Stored, shown: &str, ops: &mut Vec<RowOp>) {
        let planned = match plan_record(&rec, &self.caps) {
            Ok(Some(p)) => p,
            Ok(None) => return,
            Err(e) => return self.record_error(shown, &e),
        };
        let prior = self.emitted.get(&planned.id).cloned();
        if prior.is_none() && !stored.read.contains(&planned.id) {
            let e = format!("{NAME}: native importer: the stored rows of {} were not read", planned.id);
            return self.record_error(shown, &e);
        }
        let stored_rows: Vec<&JsonMap> = if prior.is_none() {
            stored
                .affected
                .iter()
                .filter(|r| r.get("vuln_id").and_then(Value::as_str) == Some(planned.id.as_str()))
                .collect()
        } else {
            Vec::new()
        };
        if stored_rows.len() > self.caps.rows {
            let e = format!(
                "{NAME}: {}: {} stored affected rows (more than {}); refusing, sync cvelist with the python \
                 implementation",
                planned.id,
                stored_rows.len(),
                self.caps.rows
            );
            return self.record_error(shown, &e);
        }
        if prior.is_none() && !stored.modified.contains_key(&planned.id) {
            self.new_ids += 1;
        }
        ops.push(rows::raw_record(
            NAME,
            &planned.id,
            planned.modified.as_deref(),
            &self.now,
            rec,
        ));
        ops.push(planned.vulnerability);
        let n_new = u32::try_from(planned.affected.len()).unwrap_or(u32::MAX);
        match &prior {
            Some(e) => {
                // emitted earlier in this run (perhaps not applied yet): replace those rows
                ops.extend((0..e.rows).map(|_| RowOp::Delete {
                    table: MirrorTable::Affected,
                    key: [
                        ("source".to_owned(), json!(NAME)),
                        ("vuln_id".to_owned(), json!(planned.id)),
                    ]
                    .into_iter()
                    .collect(),
                }));
                ops.extend(planned.affected.into_iter().map(|row| RowOp::Upsert {
                    table: MirrorTable::Affected,
                    row,
                }));
            }
            None => ops.extend(rows::replace_affected(
                &stored_rows,
                planned.affected,
                DeleteKey::Record,
            )),
        }
        self.emitted.insert(
            planned.id,
            Emitted {
                rows: n_new,
                modified: planned.modified,
            },
        );
        self.count += 1;
    }

    /// One id of the ids mode (`_fetch_ids`): the limit, the raw request (404: not an error), the record.
    async fn next_id(
        &mut self,
        client: &reqwest::Client,
        base: &str,
        allow_http: bool,
        ids: &mut VecDeque<String>,
    ) -> StepResult<Vec<RowOp>> {
        let Some(cid) = ids.pop_front() else {
            return Ok(self.finish());
        };
        if self.limit.is_some_and(|l| self.count >= l) {
            return Ok(self.finish());
        }
        let fail = |run: &mut Run, e: String| run.record_error(&cid, &e);
        let url = match cve_path(&cid) {
            Ok(p) => format!("{base}{p}"),
            Err(e) => {
                fail(self, e);
                return Ok(Vec::new());
            }
        };
        let g = feed::Get {
            url: &url,
            max_bytes: self.caps.file_bytes,
            allow_http,
            timeout: RAW_TIMEOUT,
            accept: None,
            too_large: Some(format!(
                "{NAME}: {}: larger than {} bytes; refusing",
                secmonk_safeio::strip_url_secrets(&url, false),
                self.caps.file_bytes
            )),
            same_origin_redirects: false,
        };
        let body = match feed::fetch(client, &g, &[], None).await {
            Ok((b, _)) => b,
            Err(feed::FetchError::Status { code: 404, .. }) => {
                self.say.line(format!("{NAME}: {cid} not found"));
                return Ok(Vec::new());
            }
            Err(feed::FetchError::Status { message, .. }) => {
                fail(self, format!("HTTPStatusError: {message}"));
                return Ok(Vec::new());
            }
            Err(feed::FetchError::Transport(m)) => {
                fail(self, format!("TransportError: {m}"));
                return Ok(Vec::new());
            }
            Err(feed::FetchError::Other(m)) => {
                fail(self, m);
                return Ok(Vec::new());
            }
        };
        let rec: Value = match py::decode_utf8(&body)
            .map_err(|m| format!("UnicodeDecodeError: {m}"))
            .and_then(|t| serde_json::from_str(t).map_err(|e| format!("JSONDecodeError: {e}")))
        {
            Ok(v) => v,
            Err(e) => {
                fail(self, e);
                return Ok(Vec::new());
            }
        };
        let group = [Loaded {
            shown: cid.clone(),
            rec: Ok(rec),
        }];
        let stored = self.stored(&group).await?;
        let [Loaded { rec: Ok(rec), .. }] = group else {
            return Ok(Vec::new());
        };
        let mut ops = Vec::new();
        self.import(rec, &stored, &cid, &mut ops);
        Ok(ops)
    }
}

/// `detail.strip()[:300]`.
fn first_300(detail: &str) -> String {
    py::strip(detail).chars().take(300).collect()
}

#[async_trait]
impl Source for CvelistSource {
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

    fn events(v: Value) -> Vec<Value> {
        v.as_array().unwrap().clone()
    }

    #[test]
    fn version_expressions_follow_the_python_parser() {
        // tests/sources/test_cvelist.py::test_parse_version_expression
        let cases: Vec<(&str, Option<Value>)> = vec![
            ("< 2.5.4", Some(json!([{"introduced": "0"}, {"fixed": "2.5.4"}]))),
            ("<= 1.2", Some(json!([{"introduced": "0"}, {"last_affected": "1.2"}]))),
            (">= 1.0, <= 1.2", Some(json!([{"introduced": "1.0"}, {"last_affected": "1.2"}]))),
            (">=1.0 <1.2", Some(json!([{"introduced": "1.0"}, {"fixed": "1.2"}]))),
            ("3.0.0 - 3.0.3", Some(json!([{"introduced": "3.0.0"}, {"last_affected": "3.0.3"}]))),
            ("2.3 and earlier", Some(json!([{"introduced": "0"}, {"last_affected": "2.3"}]))),
            (
                "7.3.3-7015 and older versions",
                Some(json!([{"introduced": "0"}, {"last_affected": "7.3.3-7015"}])),
            ),
            ("prior to 4.5", Some(json!([{"introduced": "0"}, {"fixed": "4.5"}]))),
            ("1.0 or later", Some(json!([{"introduced": "1.0"}]))),
            ("1.2.3", None),
            ("log4j-core*", None),
            ("some random text", None),
            ("< foo*", None),
            // more shapes
            ("= 1.2", Some(json!([{"introduced": "1.2"}, {"last_affected": "1.2"}]))),
            (">= 1.0 and < 2.0.", Some(json!([{"introduced": "1.0"}, {"fixed": "2.0"}]))),
            (">=1 && <2", Some(json!([{"introduced": "1"}, {"fixed": "2"}]))),
            ("UP TO 2.0", Some(json!([{"introduced": "0"}, {"last_affected": "2.0"}]))),
            ("before 3", Some(json!([{"introduced": "0"}, {"fixed": "3"}]))),
            ("1.0 to 2.0", Some(json!([{"introduced": "1.0"}, {"last_affected": "2.0"}]))),
            ("< 1 < 2 < 3", None),
            (">", None),
            ("", None),
        ];
        for (expr, want) in cases {
            assert_eq!(
                parse_version_expression(expr),
                want.map(events),
                "{expr:?}"
            );
        }
        assert_eq!(parse_version_expression(&format!("< {}", "1".repeat(119))), None);
    }

    fn entry(v: Value) -> JsonMap {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn version_entries_convert_like_python() {
        // tests/sources/test_cvelist.py::test_convert_edge_cases and test_review_fixes.py
        let conv = |v: Value| convert_version_entry(&entry(v)).unwrap();
        assert_eq!(
            conv(json!({"version": "0", "lessThan": "*", "status": "affected"})),
            Converted::Events(events(json!([{"introduced": "0"}])))
        );
        assert_eq!(
            conv(json!({"version": "1.0", "lessThan": "2.0"})),
            Converted::Events(events(json!([{"introduced": "1.0"}, {"fixed": "2.0"}])))
        );
        assert_eq!(
            conv(json!({"version": "1.4"})),
            Converted::Versions(vec![json!("1.4")])
        );
        assert_eq!(conv(json!({"version": "n/a"})), Converted::Skip);
        assert_eq!(
            conv(json!({"version": "1.0", "lessThan": "2.*"})),
            Converted::Unparsed
        );
        assert_eq!(
            conv(json!({"version": "a".repeat(40), "lessThan": "b".repeat(40), "versionType": "git"})),
            Converted::Git(events(json!([{"introduced": "a".repeat(40)}, {"fixed": "b".repeat(40)}])))
        );
        for (e, want) in [
            (
                json!({"version": "2.4.0", "lessThan": "*", "changes": [{"at": "2.4.58", "status": "unaffected"}]}),
                json!([{"introduced": "2.4.0"}, {"fixed": "2.4.58"}]),
            ),
            (
                json!({"version": "1.0", "lessThan": "2.0", "changes": [{"at": "1.5", "status": "unaffected"}]}),
                json!([{"introduced": "1.0"}, {"fixed": "1.5"}]),
            ),
            (
                json!({"version": "1.0", "lessThan": "2.0", "changes": [{"at": "1.7", "status": "affected"},
                                                                     {"at": "1.5", "status": "unaffected"}]}),
                json!([{"introduced": "1.0"}, {"fixed": "1.5"}, {"introduced": "1.7"}, {"fixed": "2.0"}]),
            ),
            (
                json!({"version": "1.0", "lessThan": "2.0", "changes": [{"at": "3.0", "status": "unaffected"}]}),
                json!([{"introduced": "1.0"}, {"fixed": "2.0"}]),
            ),
            // Chrome: version == lessThan
            (
                json!({"version": "134.0.6998.35", "lessThan": "134.0.6998.35"}),
                json!([{"introduced": "0"}, {"fixed": "134.0.6998.35"}]),
            ),
            // Log4Shell: a bound that is not a version, changes[] decide
            (
                json!({"version": "2.0-beta9", "lessThan": "log4j-core*", "changes": [
                    {"at": "2.3.1", "status": "unaffected"}, {"at": "2.4", "status": "affected"},
                    {"at": "2.12.2", "status": "unaffected"}]}),
                json!([{"introduced": "2.0-beta9"}, {"fixed": "2.3.1"}, {"introduced": "2.4"}, {"fixed": "2.12.2"}]),
            ),
        ] {
            assert_eq!(conv(e.clone()), Converted::Events(events(want)), "{e}");
        }
        // a number that Python cannot convert raises inside the comparison
        let big = format!("1.{}", "9".repeat(4301));
        assert!(
            convert_version_entry(&entry(json!({"version": "1.0", "lessThan": "2.0",
                "changes": [{"at": big, "status": "unaffected"}]})))
            .unwrap_err()
            .starts_with("ValueError: Exceeds the limit")
        );
        assert!(
            convert_version_entry(&entry(json!({"version": "1.0", "changes": 5})))
                .unwrap_err()
                .starts_with("TypeError")
        );
    }

    #[test]
    fn the_generic_comparator_orders_like_python() {
        // expected values from `secmonk.engine.versions.compare` (Python 3.13, 2026-11-12)
        use Ordering::*;
        for (a, b, want) in [
            ("1.0-rc1", "1.0", Less),
            ("1.0", "1.0.0", Equal),
            ("1.0.Final", "1.0", Equal),
            ("1.0", "1.0p1", Less),
            ("1.0p1", "1.0a", Greater),
            ("1.0a", "1.0.1", Less),
            ("1.1.1w", "1.1.1t", Greater),
            ("1.0-b2", "1.0", Less),
            ("v2.0", "2.0", Equal),
            ("2.10", "2.9", Greater),
            ("1.0.patch1", "1.0.p1", Equal),
            ("a1", "1", Less),
            ("0010", "9", Greater),
            ("1.0-dev", "1.0-alpha", Less),
            ("1.0.0.0", "1", Equal),
            ("1.0a", "1.0b", Less),
            ("1-0", "1", Equal),
            ("1.final.0", "1", Equal),
            ("b", "a", Greater),
            ("2.0~beta", "2.0", Less),
            ("1.0m1", "1.0", Greater),
            ("1.0.m1", "1.0", Less),
            ("\u{663}.1", "3.1", Equal),
            ("3.1", "\u{663}.2", Less),
        ] {
            assert_eq!(compare_versions(a, b).unwrap(), want, "{a} vs {b}");
        }
    }

    #[test]
    fn paths_urls_and_names_follow_python() {
        assert_eq!(
            cve_path("CVE-2021-44228").unwrap(),
            "cves/2021/44xxx/CVE-2021-44228.json"
        );
        assert_eq!(
            cve_path("CVE-2014-0160").unwrap(),
            "cves/2014/0xxx/CVE-2014-0160.json"
        );
        assert_eq!(
            cve_path("CVE-2019-1010022").unwrap(),
            "cves/2019/1010xxx/CVE-2019-1010022.json"
        );
        assert_eq!(
            cve_path("CVE-2026-119977").unwrap(),
            "cves/2026/119xxx/CVE-2026-119977.json"
        );
        assert_eq!(
            cve_path(" cve-2023-0001\n").unwrap(),
            "cves/2023/0xxx/CVE-2023-0001.json"
        );
        assert_eq!(
            cve_path("GHSA-xxxx").unwrap_err(),
            "ValueError: not a CVE id: 'GHSA-xxxx'"
        );
        let eco = |u: &str| ecosystem_from_url(Some(&json!(u)));
        assert_eq!(eco("https://npmjs.com/form-data"), Some("npm"));
        assert_eq!(eco("pypi.org/project/x"), Some("PyPI"));
        assert_eq!(eco("HTTPS://User:pw@REPO1.maven.org:443/maven2"), Some("Maven"));
        assert_eq!(eco("https://github.com/x/y"), None);
        assert_eq!(eco("https://[pypi.org/x"), None);
        assert_eq!(eco("npmjs.com/x://y"), None, "no scheme, no netloc");
        assert_eq!(ecosystem_from_url(Some(&json!(5))), None);
        assert_eq!(normalize_name(Some("PyPI"), " Zope.Interface "), "zope-interface");
        assert_eq!(normalize_name(Some("Maven"), "Org.X:Y"), "Org.X:Y");
        assert_eq!(normalize_name(None, "Form-Data"), "form-data");
        assert!(version_like("2.0-beta9") && version_like(" v4 ") && !version_like("128.*"));
        assert!(looks_like_commit("deadbeef1") && !looks_like_commit("deadbeef") && !looks_like_commit("1234567"));
        assert!(looks_like_commit("abcdefabcdef"));
        assert_eq!(years_of(None, None, 2026), vec!["2025", "2026"]);
        assert_eq!(years_of(Some("2021-05-01"), None, 2026).len(), 6);
        assert_eq!(years_of(Some("2030"), Some(2024), 2026), vec!["2024", "2025", "2026"]);
        assert_eq!(years_of(Some("abcd"), None, 2026), vec!["2025", "2026"]);
        assert!(sha_like(&"a".repeat(40)) && sha_like(&format!("{}\n", "b".repeat(64))));
        assert!(!sha_like("--output=/tmp/x") && !sha_like(&"A".repeat(40)));
    }

    fn crec(cna: Value, adp: Value) -> Value {
        let mut c = json!({"descriptions": [{"lang": "en", "value": "d"}]});
        for (k, v) in cna.as_object().unwrap() {
            c[k] = v.clone();
        }
        json!({"cveMetadata": {"cveId": "CVE-2026-0001", "state": "PUBLISHED",
                               "dateUpdated": "2026-01-01T00:00:00.000Z"},
               "containers": {"cna": c, "adp": adp}})
    }

    fn plan(rec: Value) -> Result<Option<Planned>, String> {
        plan_record(&rec, &Caps::default())
    }

    fn vrow(p: &Planned) -> &JsonMap {
        match &p.vulnerability {
            RowOp::Upsert { row, .. } => row,
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn records_become_the_rows_python_writes() {
        let p = plan(crec(
            json!({"metrics": [{"cvssV3_1": {"baseScore": 5.0, "version": "3.1", "baseSeverity": "Moderate",
                                              "vectorString": "CVSS:3.1/AV:N"}}],
                   "problemTypes": [{"descriptions": [{"cweId": "CWE-79"}, {"cweId": "CWE-79"}]}],
                   "affected": [{"packageName": "Zope.Interface",
                                 "collectionURL": "https://pypi.org/project/zope.interface",
                                 "versions": [{"version": "1.0", "status": "affected"}]},
                                {"vendor": "acme", "product": "widget", "defaultStatus": "affected"},
                                {"vendor": "n/a", "product": "n/a", "versions": [{"version": "1"}]}]}),
            json!([{"providerMetadata": {"shortName": "CISA-ADP"},
                    "metrics": [{"other": {"type": "ssvc", "content": {"options": [{"Exploitation": "none"},
                                 {"Automatable": "no"}], "version": "2.0.3", "role": "CISA Coordinator"}}}]}]),
        ))
        .unwrap()
        .unwrap();
        let v = vrow(&p);
        assert_eq!(v["severity"], "MEDIUM");
        assert_eq!(v["cvss_score"], json!(5.0));
        assert_eq!(v["cwes"], json!(["CWE-79"]));
        assert_eq!(
            v["extra"],
            json!({"cvss_source": "cna", "ssvc": {"Exploitation": "none", "Automatable": "no",
                   "version": "2.0.3", "role": "CISA Coordinator"}})
        );
        assert_eq!(p.affected.len(), 2);
        assert_eq!(p.affected[0]["ecosystem"], "PyPI");
        assert_eq!(p.affected[0]["package"], "zope-interface");
        assert_eq!(p.affected[1]["range_type"], "CVE-UNPARSED");
        assert_eq!(p.affected[1]["extra"]["default_status"], "affected");

        // the CPE applicability rows (tests/sources/test_review_fixes.py)
        let cpe = |m: Value| {
            plan(crec(
                json!({"cpeApplicability": [{"nodes": [{"operator": "OR", "cpeMatch": [m]}]}]}),
                json!([]),
            ))
            .unwrap()
            .unwrap()
            .affected
        };
        let base = "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*";
        let r = cpe(json!({"vulnerable": true, "criteria": base, "versionStartExcluding": "1.0",
                           "versionEndExcluding": "2.0"}));
        assert_eq!(r[0]["events"], json!([{"introduced_exclusive": "1.0"}, {"fixed": "2.0"}]));
        assert_eq!(r[0]["range_type"], "CPE");
        let r = cpe(json!({"vulnerable": true, "criteria": base}));
        assert_eq!(r[0]["events"], json!([{"introduced": "0"}]));
        let r = cpe(json!({"vulnerable": true, "criteria": base, "versionStartExcluding": "see advisory",
                           "versionEndExcluding": "2.0"}));
        assert_eq!(r[0]["range_type"], "CVE-UNPARSED");
        let r = cpe(json!({"vulnerable": true, "criteria": "cpe:2.3:a:Vendor_Co:prod\\:name:*:*:*:*:*:*:*:*"}));
        assert_eq!((&r[0]["vendor"], &r[0]["product"]), (&json!("vendor co"), &json!("prod:name")));
        let r = cpe(json!({"vulnerable": true, "criteria": "cpe:2.3:a:g:chrome:1.0:beta:*:*:*:*:*:*"}));
        assert_eq!(r[0]["extra"]["cpe_update"], "beta");
        assert_eq!(r[0]["versions"], json!(["1.0"]));
    }

    #[test]
    fn record_errors_are_what_python_raises() {
        let err = |rec: Value| plan(rec).unwrap_err();
        assert!(err(crec(json!({"metrics": ["junk"]}), json!([]))).starts_with("AttributeError"));
        assert!(err(crec(json!({"metrics": [{"cvssV3_1": {"baseScore": "n/a"}}]}), json!([])))
            .starts_with("ValueError: could not convert string to float"));
        assert!(err(crec(json!({"affected": [{"vendor": 5, "product": "x"}]}), json!([])))
            .starts_with("AttributeError: 'int' object has no attribute 'strip'"));
        assert!(err(crec(json!({"affected": 3}), json!([]))).starts_with("TypeError"));
        assert!(err(crec(json!({"title": ["x"], "descriptions": []}), json!([]))).starts_with("ProgrammingError"));
        assert!(err(crec(json!({}), json!([{"providerMetadata": null}]))).starts_with("AttributeError"));
        // not records: nothing, no error
        assert!(plan(json!([1])).unwrap().is_none());
        assert!(plan(json!({"cveMetadata": {"cveId": ""}})).unwrap().is_none());
        assert!(plan(json!({"cveMetadata": "x"})).unwrap().is_none());
        // a rejected record: no affected rows, the reason as summary, withdrawn
        let p = plan(json!({"cveMetadata": {"cveId": "CVE-2026-9", "state": "REJECTED", "dateRejected": "d"},
                            "containers": {"cna": {"rejectedReasons": [{"lang": "en", "value": "dup"}],
                                                   "affected": [{"vendor": "a", "product": "b"}]}}}))
        .unwrap()
        .unwrap();
        assert!(p.affected.is_empty());
        assert_eq!(vrow(&p)["summary"], "dup");
        assert_eq!(vrow(&p)["withdrawn"], "d");
        // the per-record cap
        let many: Vec<Value> = (0..5).map(|i| json!({"version": format!("1.{i}")})).collect();
        let caps = Caps {
            rows: 3,
            ..Caps::default()
        };
        assert!(
            plan_record(
                &crec(json!({"affected": [{"vendor": "a", "versions": many}]}), json!([])),
                &caps
            )
            .unwrap_err()
            .contains("more than 3 affected rows")
        );
    }
}
