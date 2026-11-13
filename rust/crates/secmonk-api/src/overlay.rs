//! The UI overlay of `rust/ui`, embedded: the page and the scripts that change how the unchanged web UI reaches
//! the API (Tauri IPC in the window, HTTPS + Bearer token in a browser). Served by the router at `/`,
//! `/index.html` and `/rust-ui/<file>`; the rest of the UI comes from `static_dir` (`/static/*`).

/// `/` and `/index.html`.
pub const INDEX_HTML: &str = include_str!("../../../ui/index.html");
const TRANSPORT_JS: &str = include_str!("../../../ui/transport.js");
const LOGIN_JS: &str = include_str!("../../../ui/login.js");
const BOOT_JS: &str = include_str!("../../../ui/boot.js");
const RUST_UI_CSS: &str = include_str!("../../../ui/rust-ui.css");

/// `(content type, body)` of an overlay file by its name below `/rust-ui/`; `None` for any other name.
pub fn file(name: &str) -> Option<(&'static str, &'static str)> {
    const JS: &str = "text/javascript; charset=utf-8";
    Some(match name {
        "transport.js" => (JS, TRANSPORT_JS),
        "login.js" => (JS, LOGIN_JS),
        "boot.js" => (JS, BOOT_JS),
        "rust-ui.css" => ("text/css; charset=utf-8", RUST_UI_CSS),
        _ => return None,
    })
}
