//! Reading a feed document: a download over the workspace's `reqwest` client (rustls) or a local file (`--path`),
//! both size-capped, then parsed as JSON (kev), returned as bytes or an open file (epss, euvd, msrc), or parsed while
//! it arrives ([`get_streamed`], debian-tracker). Feeds are untrusted input: the cap is checked while reading (and
//! against `Content-Length` first), JSON nesting is bounded by `serde_json`'s recursion limit, and every message that
//! leaves here is free of URL credentials. Also the file-system helpers with Python's semantics the `--path` loaders
//! share ([`exists_like_python`], [`rglob`], [`os_error`]) and [`json_error`].

use std::path::{Path, PathBuf};
use std::time::Duration;

use futures_util::StreamExt;
use serde_json::Value;
use tokio::io::AsyncReadExt;

/// `User-Agent` of every download (the Python sources send `secmonk/<version> (+vulnerability-scanner-prototype)`).
pub const USER_AGENT: &str = concat!(
    "secmonk-desktop/",
    env!("CARGO_PKG_VERSION"),
    " (+vulnerability-scanner-prototype)"
);

/// Connect and read timeout of a download (httpx `timeout=60.0` of the Python source: per operation, not total).
pub const TIMEOUT: Duration = Duration::from_secs(60);

/// Download `url` (at most `max_bytes`) and parse it as JSON. Plain `http://` is refused unless `allow_http` (tests
/// against a local server). Proxies come from the environment (`HTTPS_PROXY`, as `httpx` with `trust_env`).
pub async fn download_json(url: &str, max_bytes: u64, allow_http: bool) -> Result<Value, String> {
    parse(&download(url, max_bytes, allow_http, TIMEOUT).await?)
}

/// Download `url` into memory: at most `max_bytes` (checked against `Content-Length` first, then while the body
/// streams), connect and read timeout `timeout`. Errors carry no URL credentials. [`get`] without its options.
pub async fn download(
    url: &str,
    max_bytes: u64,
    allow_http: bool,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let g = Get {
        url,
        max_bytes,
        allow_http,
        timeout,
        accept: None,
        too_large: None,
        same_origin_redirects: false,
    };
    Ok(get(&g).await?.0)
}

/// One GET of a feed document.
#[derive(Debug, Clone)]
pub struct Get<'a> {
    /// The URL (credentials in it never reach a message).
    pub url: &'a str,
    /// Body bytes accepted (`Content-Length` checked first, then the body as it arrives).
    pub max_bytes: u64,
    /// Plain `http://` allowed (tests against a local server); else `https_only`.
    pub allow_http: bool,
    /// Connect and read timeout (per operation, as httpx's `timeout`).
    pub timeout: Duration,
    /// An `Accept` header (none by default; the MSRC API answers XML without `application/json`).
    pub accept: Option<&'static str>,
    /// The message of a body over `max_bytes`; default `<url>: larger than <max_bytes> bytes`.
    pub too_large: Option<String>,
    /// Follow redirects only to the origin of `url` (else up to 10 redirects to any origin, as httpx). A redirect
    /// elsewhere fails: `<url>: redirect to <target> is not on <origin>; refusing`.
    pub same_origin_redirects: bool,
}

impl Get<'_> {
    fn too_large(&self, shown: &str) -> String {
        self.too_large
            .clone()
            .unwrap_or_else(|| format!("{shown}: larger than {} bytes", self.max_bytes))
    }
}

/// The cache validators of an answer (`ETag`, `Last-Modified`); empty or non-ASCII values are dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Validators {
    /// `ETag`.
    pub etag: Option<String>,
    /// `Last-Modified`.
    pub last_modified: Option<String>,
}

impl Validators {
    fn of(resp: &reqwest::Response) -> Validators {
        let header = |h: reqwest::header::HeaderName| {
            resp.headers()
                .get(h)
                .and_then(|v| v.to_str().ok())
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
        };
        Validators {
            etag: header(reqwest::header::ETAG),
            last_modified: header(reqwest::header::LAST_MODIFIED),
        }
    }
}

/// A redirect refused by the same-origin policy (its text is the message).
#[derive(Debug)]
struct OffOrigin(String);

impl std::fmt::Display for OffOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OffOrigin {}

/// The workspace's `reqwest` client for one download: `User-Agent`, `https_only` unless `allow_http`, connect and
/// read timeout; redirects only within `origin` when given (else reqwest's default: up to 10).
fn client(
    timeout: Duration,
    allow_http: bool,
    origin: Option<String>,
) -> Result<reqwest::Client, String> {
    client_with(timeout, allow_http, origin, false)
}

/// [`client`], or with `no_redirects` a client that follows no redirect (a 3xx answer is returned as it is).
fn client_with(
    timeout: Duration,
    allow_http: bool,
    origin: Option<String>,
    no_redirects: bool,
) -> Result<reqwest::Client, String> {
    let mut b = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .https_only(!allow_http)
        .connect_timeout(timeout)
        .read_timeout(timeout);
    if no_redirects {
        b = b.redirect(reqwest::redirect::Policy::none());
    } else if let Some(home) = origin {
        b = b.redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= 10 {
                return attempt.error("too many redirects");
            }
            if same_origin(attempt.url().as_str(), &home) {
                attempt.follow()
            } else {
                let to = scrub(attempt.url().as_str());
                attempt.error(OffOrigin(format!(
                    "redirect to {to} is not on {}; refusing",
                    scrub(&home)
                )))
            }
        }));
    }
    b.build().map_err(|e| scrub(&e.to_string()))
}

/// The text of a request error: scrubbed; a redirect the same-origin policy refused as `<url>: <refusal>`.
fn request_error(e: &reqwest::Error, shown: &str) -> String {
    let mut src: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(e);
    while let Some(s) = src {
        if let Some(o) = s.downcast_ref::<OffOrigin>() {
            return scrub(&format!("{shown}: {o}"));
        }
        src = s.source();
    }
    scrub(&e.to_string())
}

/// Send the request of `g` and check the status and `Content-Length`.
async fn send(g: &Get<'_>, shown: &str) -> Result<reqwest::Response, String> {
    let origin = if g.same_origin_redirects {
        Some(origin(g.url).unwrap_or_default().to_owned())
    } else {
        None
    };
    let client = client(g.timeout, g.allow_http, origin)?;
    let mut req = client.get(g.url);
    if let Some(a) = g.accept {
        req = req.header(reqwest::header::ACCEPT, a);
    }
    let resp = req.send().await.map_err(|e| request_error(&e, shown))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {} for {shown}", status.as_u16()));
    }
    if resp.content_length().is_some_and(|n| n > g.max_bytes) {
        return Err(g.too_large(shown));
    }
    Ok(resp)
}

/// Download `g.url` into memory with its validators. Proxies come from the environment (`HTTPS_PROXY`, as `httpx`
/// with `trust_env`). Errors carry no URL credentials.
pub async fn get(g: &Get<'_>) -> Result<(Vec<u8>, Validators), String> {
    let shown = secmonk_safeio::strip_url_secrets(g.url, false);
    let resp = send(g, &shown).await?;
    let validators = Validators::of(&resp);
    let mut body: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| scrub(&e.to_string()))?;
        if body.len() as u64 + chunk.len() as u64 > g.max_bytes {
            return Err(g.too_large(&shown));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, validators))
}

/// Why [`fetch`] failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchError {
    /// No complete answer (connect, timeout, a body cut short): the request may be sent again.
    Transport(String),
    /// An answer whose status is not 2xx (a redirect too, with `no_redirects`): the code, the `Retry-After` header
    /// (ASCII text, if any) and the message `HTTP <code> for <url>`.
    Status {
        /// The HTTP status code.
        code: u16,
        /// The `Retry-After` header as sent.
        retry_after: Option<String>,
        /// `HTTP <code> for <url>` (no URL credentials).
        message: String,
    },
    /// Anything else: the size cap, a client that could not be built.
    Other(String),
}

impl FetchError {
    /// The message.
    pub fn message(&self) -> &str {
        match self {
            FetchError::Transport(m)
            | FetchError::Other(m)
            | FetchError::Status { message: m, .. } => m,
        }
    }
}

/// A client for [`fetch`], to reuse for every request of a run: `User-Agent`, `https_only` unless `allow_http`,
/// connect and read timeout `timeout`; no redirect followed when `no_redirects` (a 3xx answer is returned as it is),
/// else reqwest's default (up to 10).
pub fn fetch_client(
    timeout: Duration,
    allow_http: bool,
    no_redirects: bool,
) -> Result<reqwest::Client, String> {
    client_with(timeout, allow_http, None, no_redirects)
}

/// One GET of `g.url` with `client` ([`fetch_client`]; its redirect policy applies, `g.same_origin_redirects`,
/// `g.allow_http` and `g.timeout` are the client's) and extra request `headers` (mark secret values with
/// `HeaderValue::set_sensitive`), within `total` when given (connecting, waiting and reading together; a transport
/// error when it runs out). Unlike [`get`], the failure says whether a retry makes sense ([`FetchError`]); retries
/// and pacing are the caller's. Messages carry no URL credentials and no header values.
pub async fn fetch(
    client: &reqwest::Client,
    g: &Get<'_>,
    headers: &[(reqwest::header::HeaderName, reqwest::header::HeaderValue)],
    total: Option<Duration>,
) -> Result<(Vec<u8>, Validators), FetchError> {
    let shown = secmonk_safeio::strip_url_secrets(g.url, false);
    let mut req = client.get(g.url);
    if let Some(a) = g.accept {
        req = req.header(reqwest::header::ACCEPT, a);
    }
    for (k, v) in headers {
        req = req.header(k, v.clone());
    }
    if let Some(t) = total {
        req = req.timeout(t);
    }
    let resp = req.send().await.map_err(|e| {
        if e.is_builder() {
            FetchError::Other(request_error(&e, &shown))
        } else {
            FetchError::Transport(request_error(&e, &shown))
        }
    })?;
    let status = resp.status();
    if !status.is_success() {
        let retry_after = resp
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        return Err(FetchError::Status {
            code: status.as_u16(),
            retry_after,
            message: format!("HTTP {} for {shown}", status.as_u16()),
        });
    }
    if resp.content_length().is_some_and(|n| n > g.max_bytes) {
        return Err(FetchError::Other(g.too_large(&shown)));
    }
    let validators = Validators::of(&resp);
    let mut body: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| FetchError::Transport(scrub(&e.to_string())))?;
        if body.len() as u64 + chunk.len() as u64 > g.max_bytes {
            return Err(FetchError::Other(g.too_large(&shown)));
        }
        body.extend_from_slice(&chunk);
    }
    Ok((body, validators))
}

/// The reading half of a streamed download ([`get_streamed`]): the body as it arrives. A failed download or a body
/// over the cap is a read error whose text is the message ([`crate::decode::io_message`] returns it as is).
#[derive(Debug)]
pub struct BodyReader {
    rx: tokio::sync::mpsc::Receiver<Result<Vec<u8>, String>>,
    cur: Vec<u8>,
    pos: usize,
}

impl std::io::Read for BodyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        while self.pos >= self.cur.len() {
            match self.rx.blocking_recv() {
                Some(Ok(b)) => {
                    self.cur = b;
                    self.pos = 0;
                }
                Some(Err(m)) => return Err(crate::decode::msg_error(m)),
                None => return Ok(0),
            }
        }
        let n = (self.cur.len() - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.cur[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// Download `g.url` and parse the body while it arrives: `parse` runs on the blocking pool over a [`BodyReader`]
/// fed through a bounded channel of 16 chunks, so the body is never held whole. The cap and the download errors
/// reach the parser as read errors (scrubbed); when the parser stops early the download stops too, and the
/// parser's result is the answer.
pub async fn get_streamed<T: Send + 'static>(
    g: &Get<'_>,
    parse: impl FnOnce(BodyReader) -> Result<T, String> + Send + 'static,
) -> Result<(T, Validators), String> {
    let shown = secmonk_safeio::strip_url_secrets(g.url, false);
    let resp = send(g, &shown).await?;
    let validators = Validators::of(&resp);
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, String>>(16);
    let parser = tokio::task::spawn_blocking(move || {
        parse(BodyReader {
            rx,
            cur: Vec::new(),
            pos: 0,
        })
    });
    let mut body = resp.bytes_stream();
    let mut total = 0u64;
    while let Some(chunk) = body.next().await {
        let item = match chunk {
            Ok(c) => {
                total += c.len() as u64;
                if total > g.max_bytes {
                    Err(g.too_large(&shown))
                } else {
                    Ok(c.to_vec())
                }
            }
            Err(e) => Err(scrub(&e.to_string())),
        };
        let stop = item.is_err();
        if tx.send(item).await.is_err() || stop {
            break; // the parser stopped (its result is the answer), or this was the error
        }
    }
    drop(tx);
    let out = parser
        .await
        .map_err(|e| format!("native importer: parse task failed: {e}"))??;
    Ok((out, validators))
}

/// `scheme://authority` of a URL (as written: no case folding, no default port removed).
pub fn origin(url: &str) -> Option<&str> {
    let start = url.find("://")? + 3;
    let end = url[start..]
        .find(['/', '?', '#'])
        .map_or(url.len(), |i| start + i);
    Some(&url[..end])
}

/// Whether `url` is on the origin of `base` (`scheme://authority`, ASCII case-insensitive).
pub fn same_origin(url: &str, base: &str) -> bool {
    match (origin(url), origin(base)) {
        (Some(a), Some(b)) => a.eq_ignore_ascii_case(b),
        _ => false,
    }
}

/// `Path.exists()` of Python 3.13 with the metadata: `Ok(None)` for the errors it treats as "does not exist"
/// (`ENOENT`, `ENOTDIR`, `EBADF`, `ELOOP`; on Windows also `ERROR_PATH_NOT_FOUND`, `ERROR_NOT_READY`,
/// `ERROR_INVALID_NAME`, `ERROR_CANT_RESOLVE_FILENAME`), `Err` with the `OSError` text for any other error (raised
/// there).
pub fn exists_like_python(path: &Path) -> Result<Option<std::fs::Metadata>, String> {
    match std::fs::metadata(path) {
        Ok(m) => Ok(Some(m)),
        Err(e) if not_found_like(&e) => Ok(None),
        Err(e) => Err(os_error(&e, path)),
    }
}

/// The errors `pathlib`'s `_ignore_error` ignores (`_IGNORED_ERRNOS`, `_IGNORED_WINERRORS`).
fn not_found_like(e: &std::io::Error) -> bool {
    let Some(code) = e.raw_os_error() else {
        return false;
    };
    if cfg!(windows) {
        // Win32 codes: FILE_NOT_FOUND and PATH_NOT_FOUND (errno ENOENT there), NOT_READY, INVALID_NAME,
        // CANT_RESOLVE_FILENAME (`_IGNORED_WINERRORS`)
        matches!(code, 2 | 3 | 21 | 123 | 1921)
    } else {
        // ENOENT, ENOTDIR, EBADF, ELOOP (40 on Linux, 62 on macOS and the BSDs)
        let eloop = if cfg!(target_os = "linux") { 40 } else { 62 };
        matches!(code, 2 | 20 | 9) || code == eloop
    }
}

/// One file [`rglob`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The path to open.
    pub path: PathBuf,
    /// `str(path)` as Python shows it (the root as given, then the names).
    pub shown: String,
    /// The file name.
    pub name: String,
}

/// Which cap of [`rglob`] was passed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TooMany {
    /// More than `max_entries` directory entries visited.
    Entries,
    /// More than `max_files` matches.
    Files,
}

/// The entries whose name ends in `suffix` under `root` (`Path.rglob("*<suffix>")` of Python 3.13: hidden names
/// included, directories so named included, symlinked directories matched but not entered), each with its
/// `str(path)` (from `shown`, the root's) and name; unreadable directories are skipped. At most `max_entries`
/// entries visited and `max_files` matches.
pub fn rglob(
    root: &Path,
    shown: &str,
    suffix: &str,
    max_entries: usize,
    max_files: usize,
) -> Result<Vec<Found>, TooMany> {
    let prefix = match shown {
        "." => String::new(),
        s if s.ends_with('/') => s.to_owned(),
        s => format!("{s}/"),
    };
    let mut out = Vec::new();
    let mut entries = 0usize;
    let mut stack = vec![(root.to_path_buf(), prefix)];
    while let Some((dir, disp)) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in rd.flatten() {
            entries += 1;
            if entries > max_entries {
                return Err(TooMany::Entries);
            }
            let name = e.file_name().to_string_lossy().into_owned();
            let d = format!("{disp}{name}");
            if name.ends_with(suffix) {
                out.push(Found {
                    path: e.path(),
                    shown: d.clone(),
                    name,
                });
                if out.len() > max_files {
                    return Err(TooMany::Files);
                }
            }
            if e.file_type().is_ok_and(|t| t.is_dir()) {
                stack.push((e.path(), format!("{d}/")));
            }
        }
    }
    Ok(out)
}

/// A `serde_json` error as a message: an importer's own refusal (a custom error starting with one of `own`, raised
/// by its visitors) without the position serde appends, anything else as `invalid JSON: <serde_json text>`.
pub fn json_error(e: &serde_json::Error, own: &[&str]) -> String {
    let m = e.to_string();
    let head = m.split(" at line ").next().unwrap_or(&m);
    if own.iter().any(|p| head.starts_with(p)) {
        head.to_owned()
    } else {
        format!("invalid JSON: {e}")
    }
}

/// Read a local feed file (at most `max_bytes`) and parse it as JSON. I/O errors read like Python's `OSError`
/// (`[Errno 2] No such file or directory: '<path>'`), so a failing `--path` gives the same message in both versions.
///
/// Only a regular file is opened (symlinks followed): a directory answers Python's `[Errno 21] Is a directory`, anything
/// else (a FIFO, a device, a socket) is refused before `open`, which would block on a FIFO with no writer.
pub async fn read_json(path: &Path, max_bytes: u64) -> Result<Value, String> {
    parse(&read_bytes(path, max_bytes).await?)
}

/// Read a local feed file into memory (at most `max_bytes`), with the checks and messages of [`read_json`].
pub async fn read_bytes(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let owned = path.to_path_buf();
    let f = tokio::task::spawn_blocking(move || open_regular(&owned))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.message)?;
    let mut body = Vec::new();
    tokio::fs::File::from_std(f)
        .take(max_bytes + 1)
        .read_to_end(&mut body)
        .await
        .map_err(|e| os_error(&e, path))?;
    if body.len() as u64 > max_bytes {
        return Err(format!("{}: larger than {max_bytes} bytes", py_path(path)));
    }
    Ok(body)
}

/// A local file that could not be opened: Python's exception class and `str(exception)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileError {
    /// `FileNotFoundError`, `IsADirectoryError`, `PermissionError`, `OSError`, ...
    pub class: &'static str,
    /// `[Errno 2] No such file or directory: '<path>'`, or `not a regular file: '<path>'`.
    pub message: String,
}

impl FileError {
    /// `f"{type(e).__name__}: {e}"`, as the Python sources that report the class (epss) word it.
    pub fn with_class(&self) -> String {
        format!("{}: {}", self.class, self.message)
    }
}

/// Open a local feed file for reading: a regular file only (symlinks followed). A directory answers Python's
/// `[Errno 21] Is a directory`; anything else (a FIFO, a device, a socket) is refused before `open`, which would block
/// on a FIFO with no writer. The kind is checked again on the opened file (replaced between the check and the open).
pub fn open_regular(path: &Path) -> Result<std::fs::File, FileError> {
    let io = |e: &std::io::Error| FileError {
        class: py_exception(e),
        message: os_error(e, path),
    };
    let kind = |meta: &std::fs::Metadata| -> Result<(), FileError> {
        if meta.is_dir() {
            Err(io(&std::io::Error::from_raw_os_error(21)))
        } else if !meta.is_file() {
            Err(FileError {
                class: "OSError",
                message: format!("not a regular file: {}", py_repr(&py_path(path))),
            })
        } else {
            Ok(())
        }
    };
    kind(&std::fs::metadata(path).map_err(|e| io(&e))?)?;
    let f = std::fs::File::open(path).map_err(|e| io(&e))?;
    kind(&f.metadata().map_err(|e| io(&e))?)?;
    Ok(f)
}

/// The `OSError` subclass Python raises for an errno (POSIX numbers; others are `OSError`).
pub fn py_exception(e: &std::io::Error) -> &'static str {
    match e.raw_os_error() {
        Some(2) => "FileNotFoundError",
        Some(1 | 13) => "PermissionError",
        Some(20) => "NotADirectoryError",
        Some(21) => "IsADirectoryError",
        Some(4) => "InterruptedError",
        _ => "OSError",
    }
}

/// JSON text -> value. Python's `json.loads` errors read differently (`Expecting value: line 1 column 1 (char 0)`);
/// the status is the same.
pub fn parse(body: &[u8]) -> Result<Value, String> {
    serde_json::from_slice(body).map_err(|e| format!("invalid JSON: {e}"))
}

/// URL credentials and token-like strings out of a message.
pub fn scrub(text: &str) -> String {
    secmonk_safeio::scrub_text(text)
}

/// Python's `str(OSError)`: `[Errno N] <strerror>: '<path>'`.
pub fn os_error(e: &std::io::Error, path: &Path) -> String {
    let text = e.to_string();
    match e.raw_os_error() {
        Some(code) => {
            let strerror = text
                .strip_suffix(&format!(" (os error {code})"))
                .unwrap_or(&text);
            format!("[Errno {code}] {strerror}: {}", py_repr(&py_path(path)))
        }
        None => format!("{text}: {}", py_repr(&py_path(path))),
    }
}

/// Python's `repr(str)` ([`crate::py::repr_str`]).
pub fn py_repr(s: &str) -> String {
    crate::py::repr_str(s)
}

/// `str(pathlib.Path(p))` on POSIX: repeated and trailing slashes and `.` components removed (two leading slashes
/// are kept, as POSIX allows). Elsewhere the path as displayed.
pub fn py_path(path: &Path) -> String {
    let s = path.to_string_lossy();
    if cfg!(windows) {
        return s.into_owned();
    }
    let lead = if s.starts_with("//") && !s.starts_with("///") {
        "//"
    } else if s.starts_with('/') {
        "/"
    } else {
        ""
    };
    let parts: Vec<&str> = s
        .split('/')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    let out = format!("{lead}{}", parts.join("/"));
    if out.is_empty() { ".".into() } else { out }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_and_errors_read_like_python() {
        assert_eq!(py_path(Path::new("/a//b/./c/")), "/a/b/c");
        assert_eq!(py_path(Path::new("./x.json")), "x.json");
        assert_eq!(py_path(Path::new("//net/x")), "//net/x");
        assert_eq!(py_repr("it's"), "\"it's\"");
        assert_eq!(py_repr("/tmp/x"), "'/tmp/x'");
    }

    #[tokio::test]
    async fn local_files_are_capped_and_errors_read_like_oserror() {
        let d = tempfile::tempdir().unwrap();
        let missing = d.path().join("missing.json");
        let e = read_json(&missing, 100).await.unwrap_err();
        assert_eq!(
            e,
            format!(
                "[Errno 2] No such file or directory: '{}'",
                missing.display()
            )
        );
        let big = d.path().join("big.json");
        std::fs::write(&big, format!("\"{}\"", "x".repeat(200))).unwrap();
        assert!(
            read_json(&big, 100)
                .await
                .unwrap_err()
                .contains("larger than 100 bytes")
        );
        assert_eq!(
            read_json(&big, 1000).await.unwrap().as_str().unwrap().len(),
            200
        );
        let bad = d.path().join("bad.json");
        std::fs::write(&bad, "{").unwrap();
        assert!(
            read_json(&bad, 100)
                .await
                .unwrap_err()
                .starts_with("invalid JSON")
        );
        assert!(
            read_json(d.path(), 100)
                .await
                .unwrap_err()
                .starts_with("[Errno 21] ")
        );
        let e = read_json(&d.path().join(".//big.json"), 100)
            .await
            .unwrap_err();
        assert_eq!(
            e,
            format!("{}/big.json: larger than 100 bytes", py_path(d.path()))
        );
    }

    #[test]
    fn origins_and_json_errors() {
        assert_eq!(
            origin("https://api.msrc.microsoft.com/cvrf/v3.0"),
            Some("https://api.msrc.microsoft.com")
        );
        assert_eq!(
            origin("http://127.0.0.1:8080"),
            Some("http://127.0.0.1:8080")
        );
        assert_eq!(origin("https://a@b/x?y"), Some("https://a@b"));
        assert_eq!(origin("nope"), None);
        assert!(same_origin("HTTPS://Example.org/a", "https://example.org"));
        assert!(!same_origin(
            "https://example.org:8443/a",
            "https://example.org"
        ));
        assert!(!same_origin("nope", "nope"));
        let e = serde_json::from_str::<Value>("{").unwrap_err();
        assert!(json_error(&e, &["x: "]).starts_with("invalid JSON: EOF while parsing"));
        let e: serde_json::Error = serde::de::Error::custom("x: too many; refusing");
        assert_eq!(json_error(&e, &["y: ", "x: "]), "x: too many; refusing");
    }

    #[test]
    fn paths_exist_and_walk_like_python() {
        let d = tempfile::tempdir().unwrap();
        assert!(
            exists_like_python(&d.path().join("missing"))
                .unwrap()
                .is_none()
        );
        let f = d.path().join("f.json");
        std::fs::write(&f, "{}").unwrap();
        // ENOTDIR: a path below a file does not exist for `Path.exists()`
        assert!(exists_like_python(&f.join("x")).unwrap().is_none());
        assert!(exists_like_python(&f).unwrap().is_some_and(|m| m.is_file()));
        std::fs::create_dir_all(d.path().join("sub/.hidden.json")).unwrap();
        std::fs::write(d.path().join("sub/b.json"), "{}").unwrap();
        std::fs::write(d.path().join("sub/c.txt"), "").unwrap();
        let shown = py_path(d.path());
        let mut found = rglob(d.path(), &shown, ".json", 100, 100).unwrap();
        found.sort_by(|a, b| a.shown.cmp(&b.shown));
        let names: Vec<&str> = found.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["f.json", ".hidden.json", "b.json"]);
        assert_eq!(found[2].shown, format!("{shown}/sub/b.json"));
        assert_eq!(
            rglob(d.path(), &shown, ".json", 2, 100),
            Err(TooMany::Entries)
        );
        assert_eq!(
            rglob(d.path(), &shown, ".json", 100, 2),
            Err(TooMany::Files)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_fifo_is_refused_without_blocking() {
        // review W6.5 L6: `open` of a FIFO with no writer would block the sync forever
        let d = tempfile::tempdir().unwrap();
        let fifo = d.path().join("feed.json");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(made.success());
        let e = tokio::time::timeout(std::time::Duration::from_secs(5), read_json(&fifo, 100))
            .await
            .expect("no hang")
            .unwrap_err();
        assert_eq!(e, format!("not a regular file: '{}'", fifo.display()));
    }
}
