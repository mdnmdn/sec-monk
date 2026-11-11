//! Command line and configuration of the app: `--config FILE`, then the lookup order of `secmonk-config`
//! (`SECMONK_CONFIG`, `./sec-monk.toml`, the per-user file, defaults). Everything else comes from the file.

use std::path::PathBuf;
use std::sync::Arc;

use secmonk_config::{Config, LoadOptions, load};

/// `--config FILE` / `--config=FILE` from the arguments (without the program name). Unknown arguments are an
/// error: the file decides what runs, a typo must not be ignored.
pub fn parse_args(args: &[String]) -> Result<Option<PathBuf>, String> {
    let mut config = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--config" => {
                let v = it.next().ok_or("--config needs a file")?;
                config = Some(PathBuf::from(v));
            }
            s if s.starts_with("--config=") => {
                config = Some(PathBuf::from(&s["--config=".len()..]))
            }
            "-h" | "--help" => return Err("usage: secmonk-desktop [--config FILE]".into()),
            other => {
                return Err(format!(
                    "unknown argument {other:?} (usage: secmonk-desktop [--config FILE])"
                ));
            }
        }
    }
    Ok(config)
}

/// Load the configuration; the process environment is read here and nowhere else.
pub fn load_config(args: &[String]) -> Result<Arc<Config>, String> {
    let cli = parse_args(args)?;
    load(&LoadOptions::from_env(cli))
        .map(Arc::new)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn config_flag_forms() {
        assert_eq!(parse_args(&a(&[])).unwrap(), None);
        assert_eq!(
            parse_args(&a(&["--config", "x.toml"])).unwrap(),
            Some("x.toml".into())
        );
        assert_eq!(
            parse_args(&a(&["--config=y.toml"])).unwrap(),
            Some("y.toml".into())
        );
        assert!(parse_args(&a(&["--config"])).is_err());
        assert!(
            parse_args(&a(&["--nope"]))
                .unwrap_err()
                .contains("unknown argument")
        );
    }
}
