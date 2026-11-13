//! Helpers of the unit tests.

use std::path::Path;

use secmonk_config::{Config, LoadOptions, load};

/// A configuration whose directories are all below `root`, with `--set` overrides.
pub(crate) fn temp_config(root: &Path, overrides: &[&str]) -> Config {
    std::fs::create_dir_all(root.join("cwd")).unwrap();
    load(&LoadOptions {
        cwd: root.join("cwd"),
        home: Some(root.join("home")),
        user_config_root: Some(root.join("cfgroot")),
        user_data_root: Some(root.join("dataroot")),
        cli_overrides: overrides.iter().map(|s| (*s).to_owned()).collect(),
        ..Default::default()
    })
    .unwrap()
}

/// A configuration from TOML text (every directory below a fresh temporary root, kept for the process).
pub(crate) fn config_from_toml(toml: &str) -> Config {
    let root = tempfile::tempdir().unwrap().keep();
    std::fs::create_dir_all(root.join("cwd")).unwrap();
    let raw = secmonk_config::parse(toml, Path::new("x.toml")).unwrap();
    secmonk_config::resolve(
        raw,
        secmonk_config::ConfigOrigin::Flag,
        None,
        &LoadOptions {
            cwd: root.join("cwd"),
            home: Some(root.join("home")),
            user_config_root: Some(root.join("cfgroot")),
            user_data_root: Some(root.join("dataroot")),
            ..Default::default()
        },
    )
    .unwrap()
}
