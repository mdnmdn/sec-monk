//! The versions a node serves that are not data versions: the **matcher version** (proposal §3.2 rule 6: a change
//! invalidates every match a client stored) and the importer version recorded for a module source.
//!
//! The matcher version is `py-engine/<secmonk version>+keys/<KEYS_VERSION>`: the matching rules are the Python
//! reference matcher's (`py-engine` runs `src/secmonk/engine/match.py`), so its package version stands for them, and
//! the lookup keys a client stores come from [`component_lookup_keys`](super::component_lookup_keys), versioned by
//! [`KEYS_VERSION`](super::KEYS_VERSION). The `py-engine` hello carries only the version of the module wrapper
//! (`secmonk_modules.__version__`), not the `secmonk` package's, and the engine never sees the hello (it receives
//! trait objects); so the version is read **at build time** from the root `pyproject.toml` (the `secmonk`
//! package) through `include_str!` (a change of the file rebuilds the crate). A release that changes the Python
//! matcher bumps that version, and with it every client's cache.

use std::sync::LazyLock;

use super::keys::KEYS_VERSION;

/// The root `pyproject.toml` (the `secmonk` reference package that `py-engine` runs).
const SECMONK_PYPROJECT: &str = include_str!("../../../../../pyproject.toml");

/// `version = "..."` of the `[project]` table of a `pyproject.toml` (`"0"` when absent: a build without it still
/// works, with a version that never matches a real one).
fn project_version(toml: &str) -> String {
    let mut in_project = false;
    for line in toml.lines() {
        let l = line.trim();
        if l.starts_with('[') {
            in_project = l == "[project]";
            continue;
        }
        if in_project
            && let Some(rest) = l.strip_prefix("version")
            && let Some(v) = rest.trim_start().strip_prefix('=')
        {
            return v.trim().trim_matches('"').to_owned();
        }
    }
    "0".to_owned()
}

static SECMONK_VERSION: LazyLock<String> = LazyLock::new(|| project_version(SECMONK_PYPROJECT));
static MATCHER: LazyLock<String> =
    LazyLock::new(|| format!("py-engine/{}+keys/{KEYS_VERSION}", *SECMONK_VERSION));
static IMPORTER_MODULE: LazyLock<String> = LazyLock::new(|| format!("python/{}", *SECMONK_VERSION));

/// The version of the `secmonk` Python package this build runs (root `pyproject.toml`).
pub fn secmonk_version() -> &'static str {
    &SECMONK_VERSION
}

/// The matcher version of this build: `py-engine/<secmonk version>+keys/<KEYS_VERSION>`.
pub fn matcher_version() -> &'static str {
    &MATCHER
}

/// The importer version recorded for a module source (`py-sources`) that declares none: `python/<secmonk
/// version>` (the Python sources are part of the `secmonk` package).
pub fn default_importer_module() -> &'static str {
    &IMPORTER_MODULE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_come_from_the_pyproject() {
        assert_eq!(
            project_version(
                "[tool.x]\nversion = \"9\"\n[project]\nname = \"a\"\nversion = \"1.2.3\"\n"
            ),
            "1.2.3"
        );
        assert_eq!(project_version("[project]\nname = \"a\"\n"), "0");
        assert_ne!(secmonk_version(), "0", "the root pyproject has a version");
        assert_eq!(
            matcher_version(),
            format!("py-engine/{}+keys/{KEYS_VERSION}", secmonk_version())
        );
        assert!(!matcher_version().contains('#'), "the epoch separator");
        assert!(
            !default_importer_module().contains('@'),
            "the since-token separator"
        );
        assert!(default_importer_module().starts_with("python/"));
    }
}
