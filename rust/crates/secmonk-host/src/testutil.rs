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
