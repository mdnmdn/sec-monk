//! Reading a feed document: a download over the workspace's `reqwest` client (rustls) or a local file (`--path`),
//! both size-capped, then parsed as JSON. Feeds are untrusted input: the cap is checked while reading (and against
//! `Content-Length` first), JSON nesting is bounded by `serde_json`'s recursion limit, and every message that leaves
//! here is free of URL credentials.

use std::path::Path;
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
    let shown = secmonk_safeio::strip_url_secrets(url, false);
    let client = reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .https_only(!allow_http)
        .connect_timeout(TIMEOUT)
        .read_timeout(TIMEOUT)
        .build()
        .map_err(|e| scrub(&e.to_string()))?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| scrub(&e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("HTTP {} for {shown}", status.as_u16()));
    }
    if resp.content_length().is_some_and(|n| n > max_bytes) {
        return Err(format!("{shown}: larger than {max_bytes} bytes"));
    }
    let mut body: Vec<u8> = Vec::new();
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| scrub(&e.to_string()))?;
        if body.len() as u64 + chunk.len() as u64 > max_bytes {
            return Err(format!("{shown}: larger than {max_bytes} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    parse(&body)
}

/// Read a local feed file (at most `max_bytes`) and parse it as JSON. I/O errors read like Python's `OSError`
/// (`[Errno 2] No such file or directory: '<path>'`), so a failing `--path` gives the same message in both versions.
///
/// Only a regular file is opened (symlinks followed): a directory answers Python's `[Errno 21] Is a directory`, anything
/// else (a FIFO, a device, a socket) is refused before `open`, which would block on a FIFO with no writer.
pub async fn read_json(path: &Path, max_bytes: u64) -> Result<Value, String> {
    let kind = |meta: &std::fs::Metadata| -> Result<(), String> {
        if meta.is_dir() {
            Err(os_error(&std::io::Error::from_raw_os_error(21), path))
        } else if !meta.is_file() {
            Err(format!("not a regular file: {}", py_repr(&py_path(path))))
        } else {
            Ok(())
        }
    };
    kind(
        &tokio::fs::metadata(path)
            .await
            .map_err(|e| os_error(&e, path))?,
    )?;
    let f = tokio::fs::File::open(path)
        .await
        .map_err(|e| os_error(&e, path))?;
    kind(&f.metadata().await.map_err(|e| os_error(&e, path))?)?; // replaced between the check and the open
    let mut body = Vec::new();
    f.take(max_bytes + 1)
        .read_to_end(&mut body)
        .await
        .map_err(|e| os_error(&e, path))?;
    if body.len() as u64 > max_bytes {
        return Err(format!("{}: larger than {max_bytes} bytes", py_path(path)));
    }
    parse(&body)
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
fn os_error(e: &std::io::Error, path: &Path) -> String {
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

/// Python's `repr(str)` for the common case (single quotes unless the text has one and no double quote).
fn py_repr(s: &str) -> String {
    let body: String = s
        .chars()
        .flat_map(|c| match c {
            '\\' => vec!['\\', '\\'],
            '\n' => vec!['\\', 'n'],
            '\t' => vec!['\\', 't'],
            '\r' => vec!['\\', 'r'],
            c => vec![c],
        })
        .collect();
    if body.contains('\'') && !body.contains('"') {
        format!("\"{body}\"")
    } else {
        format!("'{}'", body.replace('\'', "\\'"))
    }
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
