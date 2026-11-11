//! Where the UI files come from. Dev: config or `$SECMONK_STATIC`. Release: the bundled resource only, because the
//! webview runs whatever it finds there (a config file or an environment variable must not be able to swap it).

use std::path::{Path, PathBuf};

/// Pure resolution, testable without Tauri.
///
/// * `dev`: a debug build. Order: `env` (`SECMONK_STATIC`), then the configured `ui.static_dir`, then the bundle.
/// * release: `resource_dir/static` only.
pub fn resolve(
    dev: bool,
    env: Option<PathBuf>,
    configured: Option<PathBuf>,
    resource_dir: Option<&Path>,
) -> Option<PathBuf> {
    let bundled = resource_dir.map(|r| r.join("static"));
    if dev {
        env.filter(|p| !p.as_os_str().is_empty())
            .or(configured)
            .or(bundled)
    } else {
        bundled
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Option<PathBuf> {
        Some(PathBuf::from(s))
    }

    #[test]
    fn dev_prefers_env_then_config_then_bundle() {
        let res = Path::new("/app/Resources");
        assert_eq!(resolve(true, p("/env"), p("/cfg"), Some(res)), p("/env"));
        assert_eq!(resolve(true, None, p("/cfg"), Some(res)), p("/cfg"));
        assert_eq!(
            resolve(true, p(""), p("/cfg"), Some(res)),
            p("/cfg"),
            "an empty variable is unset"
        );
        assert_eq!(
            resolve(true, None, None, Some(res)),
            p("/app/Resources/static")
        );
    }

    #[test]
    fn release_ignores_env_and_config() {
        let res = Path::new("/app/Resources");
        assert_eq!(
            resolve(false, p("/env"), p("/cfg"), Some(res)),
            p("/app/Resources/static")
        );
        assert_eq!(resolve(false, p("/env"), p("/cfg"), None), None);
    }
}
