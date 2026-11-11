//! Static files of the UI, resolved inside one directory and nowhere else.

use std::path::{Component, Path, PathBuf};

use percent_encoding::percent_decode_str;

/// A loaded static file.
#[derive(Debug)]
pub struct StaticFile {
    pub content_type: &'static str,
    pub body: Vec<u8>,
}

/// Why a path is not served. The router answers 404 `not found` for all of them; the variants are for tests and
/// logs.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// `..`, an absolute path, a drive prefix, a NUL: never leaves the directory.
    Traversal,
    /// Not a regular file inside the directory (missing, a directory, a symlink pointing out).
    NotFound,
    Unreadable,
}

/// MIME type by extension, `charset=utf-8` for text, JavaScript and SVG (as `web/server.py` `_static`).
pub fn content_type(path: &Path) -> &'static str {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase);
    match ext.as_deref() {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("js" | "mjs") => "text/javascript; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("txt" | "md") => "text/plain; charset=utf-8",
        Some("json" | "map") => "application/json",
        Some("svg") => "image/svg+xml; charset=utf-8",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("ico") => "image/vnd.microsoft.icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("wasm") => "application/wasm",
        _ => "application/octet-stream",
    }
}

/// The directory the UI is served from.
#[derive(Debug, Clone)]
pub struct StaticDir {
    root: PathBuf,
}

impl StaticDir {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Serve `rel` (a raw, possibly percent-encoded path below the root, no leading `/static/`).
    pub fn read(&self, rel: &str) -> Result<StaticFile, Refused> {
        let decoded = percent_decode_str(rel)
            .decode_utf8()
            .map_err(|_| Refused::Traversal)?;
        if decoded.contains('\0') || decoded.contains('\\') {
            return Err(Refused::Traversal);
        }
        let rel = Path::new(decoded.as_ref());
        if rel.as_os_str().is_empty()
            || !rel.components().all(|c| matches!(c, Component::Normal(_)))
        {
            return Err(Refused::Traversal);
        }
        let root = self.root.canonicalize().map_err(|_| Refused::NotFound)?;
        let file = root
            .join(rel)
            .canonicalize()
            .map_err(|_| Refused::NotFound)?;
        if !file.starts_with(&root) || !file.is_file() {
            return Err(Refused::NotFound);
        }
        let body = std::fs::read(&file).map_err(|_| Refused::Unreadable)?;
        Ok(StaticFile {
            content_type: content_type(&file),
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree() -> (PathBuf, PathBuf) {
        let base = std::env::temp_dir().join(format!(
            "secmonk-api-static-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("static");
        std::fs::create_dir_all(root.join("js")).unwrap();
        std::fs::write(root.join("index.html"), "<html></html>").unwrap();
        std::fs::write(root.join("js/app.js"), "1").unwrap();
        std::fs::write(root.join("a b.css"), "x").unwrap();
        std::fs::write(base.join("secret.txt"), "secret").unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(base.join("secret.txt"), root.join("link.txt")).unwrap();
            std::os::unix::fs::symlink(&base, root.join("up")).unwrap();
        }
        (base, root)
    }

    #[test]
    fn serves_files_inside_and_refuses_everything_else() {
        let (base, root) = tree();
        let d = StaticDir::new(&root);
        assert_eq!(
            d.read("index.html").unwrap().content_type,
            "text/html; charset=utf-8"
        );
        assert_eq!(
            d.read("js/app.js").unwrap().content_type,
            "text/javascript; charset=utf-8"
        );
        assert_eq!(d.read("a%20b.css").unwrap().body, b"x");
        for bad in [
            "../secret.txt",
            "%2e%2e/secret.txt",
            "js/../../secret.txt",
            "/etc/passwd",
            "..%2fsecret.txt",
            "js%5c..%5c..%5csecret.txt",
            "a\0b",
            "",
            "%ff",
        ] {
            assert_eq!(d.read(bad).unwrap_err(), Refused::Traversal, "{bad:?}");
        }
        assert_eq!(
            d.read("js").unwrap_err(),
            Refused::NotFound,
            "directories are not files"
        );
        assert_eq!(d.read("nope.js").unwrap_err(), Refused::NotFound);
        #[cfg(unix)]
        {
            assert_eq!(
                d.read("link.txt").unwrap_err(),
                Refused::NotFound,
                "symlink out of the dir"
            );
            assert_eq!(
                d.read("up/secret.txt").unwrap_err(),
                Refused::NotFound,
                "directory symlink out"
            );
        }
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn missing_root_is_not_found() {
        assert_eq!(
            StaticDir::new("/nonexistent/secmonk-ui")
                .read("index.html")
                .unwrap_err(),
            Refused::NotFound
        );
    }
}
