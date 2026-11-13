//! Defaults of an installed (bundled) app: where its own copy of the Python project and of the UI live.
//!
//! A release bundle (`tauri.bundle.conf.json`, rust/_docs/tech/release.md) carries two resources next to the
//! executable's resource directory (on Windows the install directory itself):
//!
//! ```text
//! <resource_dir>/static/                     the UI (src/secmonk/web/static)
//! <resource_dir>/python-project/             staged by rust/scripts/stage_python_project.py:
//!     pyproject.toml, README.md, uv.lock, src/secmonk/, rust/python/
//! ```
//!
//! Without a config file a bundled app would look for `./python` relative to the current directory and never start
//! its modules. [`app_defaults`] turns the resources into `--set`-style defaults that sit **below** the config file
//! (`secmonk_config::LoadOptions::app_defaults`): a user's `sec-monk.toml` or `--set` still wins. The project is
//! installed non-editable (`modules.editable = false`): the install directory (`Program Files` on Windows) is
//! read-only and must not end up on the venv's import path.

use std::path::Path;

use secmonk_config::path_setting;

/// Relative path of the bundled modules project below the resource directory.
pub const PYTHON_PROJECT: &str = "python-project/rust/python";

/// Relative path of the bundled UI below the resource directory.
pub const STATIC_DIR: &str = "static";

/// The application defaults for a resource directory: only for the resources that are really there (a dev build
/// run from `target/` has none of them and keeps the repository's dev configuration).
pub fn app_defaults(resource_dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let project = resource_dir.join(PYTHON_PROJECT);
    if project.join("pyproject.toml").is_file() {
        out.push(path_setting("modules.python_project", &project));
        out.push("modules.editable=false".to_owned());
    }
    let static_dir = resource_dir.join(STATIC_DIR);
    if static_dir.join("index.html").is_file() {
        out.push(path_setting("ui.static_dir", &static_dir));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_only_for_resources_that_exist() {
        let d = tempfile::tempdir().unwrap();
        let res = d.path();
        assert!(app_defaults(res).is_empty(), "a dev build has no bundle");

        std::fs::create_dir_all(res.join(PYTHON_PROJECT)).unwrap();
        std::fs::write(res.join(PYTHON_PROJECT).join("pyproject.toml"), "").unwrap();
        std::fs::create_dir_all(res.join(STATIC_DIR)).unwrap();
        std::fs::write(res.join(STATIC_DIR).join("index.html"), "").unwrap();
        let got = app_defaults(res);
        assert_eq!(got.len(), 3);
        assert!(got[0].starts_with("modules.python_project="));
        assert_eq!(got[1], "modules.editable=false");
        assert!(got[2].starts_with("ui.static_dir="));
    }

    #[test]
    fn defaults_load_below_the_config_file() {
        let d = tempfile::tempdir().unwrap();
        let res = d.path().join("Program Files").join("sec-monk");
        std::fs::create_dir_all(res.join(PYTHON_PROJECT)).unwrap();
        std::fs::write(res.join(PYTHON_PROJECT).join("pyproject.toml"), "").unwrap();
        let cwd = d.path().join("cwd");
        std::fs::create_dir_all(&cwd).unwrap();
        let opts = |cwd: &Path| secmonk_config::LoadOptions {
            cwd: cwd.to_path_buf(),
            home: Some(d.path().join("home")),
            user_config_root: Some(d.path().join("cfg")),
            user_data_root: Some(d.path().join("data")),
            app_defaults: app_defaults(&res),
            ..Default::default()
        };
        let c = secmonk_config::load(&opts(&cwd)).unwrap();
        assert_eq!(c.python_project, res.join(PYTHON_PROJECT));
        assert!(!c.modules_editable);
        // a config file of the user still decides
        std::fs::write(
            cwd.join("sec-monk.toml"),
            "[modules]\npython_project = \"elsewhere\"\neditable = true\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                cwd.join("sec-monk.toml"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let c = secmonk_config::load(&opts(&cwd)).unwrap();
        assert_eq!(c.python_project, cwd.join("elsewhere"));
        assert!(c.modules_editable);
    }
}
