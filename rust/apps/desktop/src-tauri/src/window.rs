//! The main window: its origin, its data directory and what it may navigate to.

#[cfg(not(target_os = "macos"))]
use std::path::Path;

use tauri::{App, Url, WebviewUrl, WebviewWindowBuilder};

use secmonk_config::Config;

/// Windows (WebView2) and Android rewrite custom schemes to `http://<scheme>.localhost`.
pub fn tauri_scheme_authority(scheme: &str, windows: bool) -> String {
    if windows {
        format!("{scheme}.localhost")
    } else {
        "localhost".to_owned()
    }
}

/// The URL the window opens: `secmonk://localhost/`, `http://secmonk.localhost/` on Windows.
pub fn origin_url(scheme: &str, windows: bool) -> String {
    let authority = tauri_scheme_authority(scheme, windows);
    if windows {
        format!("http://{authority}/")
    } else {
        format!("{scheme}://{authority}/")
    }
}

/// Developer tools: only in a debug build and only when `[ui] devtools` asks for them. A release build never opens
/// them, whatever the config file says (they can read and change everything the page holds).
pub fn devtools_enabled(configured: bool, debug_build: bool) -> bool {
    configured && debug_build
}

/// What to do with a navigation request of the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Navigation {
    /// Our own origin.
    Allow,
    /// An `http(s)` link: refused in the window, opened in the system browser.
    OpenExternal,
    /// Anything else (`file:`, `javascript:`, `data:`, other schemes): refused.
    Deny,
}

pub fn classify_navigation(url: &Url, scheme: &str, windows: bool) -> Navigation {
    let own_host = tauri_scheme_authority(scheme, windows);
    let own = if windows {
        url.scheme() == "http"
    } else {
        url.scheme() == scheme
    };
    if own && url.host_str() == Some(own_host.as_str()) && url.port().is_none() {
        return Navigation::Allow;
    }
    match url.scheme() {
        "http" | "https" => Navigation::OpenExternal,
        _ => Navigation::Deny,
    }
}

fn open_in_browser(url: &Url) {
    if let Err(e) = opener::open_browser(url.as_str()) {
        eprintln!(
            "secmonk-desktop: cannot open {} in the browser: {e}",
            url.host_str().unwrap_or("link")
        );
    }
}

/// Private directory (0700 on POSIX) for the webview's own state.
#[cfg(not(target_os = "macos"))]
fn private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
    }
}

pub fn open_main(app: &App, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let windows = cfg!(windows);
    let scheme = config.ui_scheme.clone();
    let url: Url = origin_url(&scheme, windows).parse()?;
    let nav_scheme = scheme.clone();
    let new_scheme = scheme;
    let builder = WebviewWindowBuilder::new(app, "main", WebviewUrl::External(url))
        .title("sec-monk")
        .inner_size(1280.0, 860.0)
        .min_inner_size(900.0, 600.0)
        .devtools(devtools_enabled(config.ui_devtools, cfg!(debug_assertions)))
        .on_navigation(
            move |u| match classify_navigation(u, &nav_scheme, windows) {
                Navigation::Allow => true,
                Navigation::OpenExternal => {
                    open_in_browser(u);
                    false
                }
                Navigation::Deny => false,
            },
        )
        .on_new_window(move |u, _features| {
            if classify_navigation(&u, &new_scheme, windows) == Navigation::OpenExternal {
                open_in_browser(&u);
            }
            tauri::webview::NewWindowResponse::Deny
        });
    // WebView2 and WebKitGTK keep their state where we say; WKWebView (macOS) has no such option and writes
    // ~/Library/WebKit/<id> and ~/Library/Caches/<id> (documented exception, plans/on-macos.md).
    #[cfg(not(target_os = "macos"))]
    let builder = {
        let dir = config.layout().webview();
        private_dir(&dir)?;
        builder.data_directory(dir)
    };
    builder.build()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nav(url: &str, windows: bool) -> Navigation {
        classify_navigation(&url.parse().unwrap(), "secmonk", windows)
    }

    #[test]
    fn devtools_are_off_in_release_builds() {
        assert!(devtools_enabled(true, true));
        assert!(!devtools_enabled(false, true));
        assert!(
            !devtools_enabled(true, false),
            "a config file cannot turn them on in a release build"
        );
        assert!(!devtools_enabled(false, false));
    }

    #[test]
    fn origin_per_platform() {
        assert_eq!(origin_url("secmonk", false), "secmonk://localhost/");
        assert_eq!(origin_url("secmonk", true), "http://secmonk.localhost/");
    }

    #[test]
    fn navigation_rules() {
        assert_eq!(nav("secmonk://localhost/", false), Navigation::Allow);
        assert_eq!(
            nav("secmonk://localhost/index.html#/assets", false),
            Navigation::Allow
        );
        assert_eq!(nav("http://secmonk.localhost/", true), Navigation::Allow);
        assert_eq!(
            nav("https://nvd.nist.gov/vuln/detail/CVE-1", false),
            Navigation::OpenExternal
        );
        assert_eq!(
            nav("http://localhost/", false),
            Navigation::OpenExternal,
            "another origin, not ours"
        );
        assert_eq!(
            nav("http://secmonk.localhost/", false),
            Navigation::OpenExternal,
            "http form is Windows-only"
        );
        assert_eq!(nav("secmonk://evil.example/", false), Navigation::Deny);
        assert_eq!(nav("file:///etc/passwd", false), Navigation::Deny);
        assert_eq!(nav("javascript:alert(1)", false), Navigation::Deny);
        assert_eq!(nav("data:text/html,x", false), Navigation::Deny);
    }
}
