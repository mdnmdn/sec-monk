//! The `apikey` commands over `Config.auth_keys_file`: create, list, revoke. They touch the keys file only (no
//! engine, no uv, no Python); a running server picks changes up on its next request.

use std::path::Path;
use std::time::{Duration, SystemTime};

use secmonk_auth::{KeyRecord, KeyStore, Scopes};
use secmonk_config::Config;
use secmonk_config::layout::ensure_private_dir;

/// Create the private directories the keys file lives in (the layout's `auth/`, and its own parent when moved).
pub(crate) fn ensure_auth_dirs(config: &Config) -> Result<(), String> {
    ensure_private_dir(&config.layout().auth()).map_err(|e| e.to_string())?;
    if let Some(parent) = config.auth_keys_file.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        ensure_private_dir(parent).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn open(config: &Config) -> Result<KeyStore, String> {
    ensure_auth_dirs(config)?;
    KeyStore::load(&config.auth_keys_file).map_err(|e| e.to_string())
}

/// Create a key, save the file (0600) and return the plaintext key, to be shown once.
pub fn create(
    config: &Config,
    name: &str,
    scopes: &[String],
    expires_days: Option<u64>,
) -> Result<String, String> {
    let scopes = Scopes::parse(scopes.iter().map(String::as_str)).map_err(|e| e.to_string())?;
    let expires =
        expires_days.map(|d| SystemTime::now() + Duration::from_secs(d.saturating_mul(86_400)));
    let mut store = open(config)?;
    let key = store
        .create(name, scopes, expires)
        .map_err(|e| e.to_string())?;
    store.save().map_err(|e| e.to_string())?;
    Ok(key)
}

/// The key table: id, name, scopes, created, expires, revoked. Never a key or a hash.
pub fn list(config: &Config) -> Result<String, String> {
    let store = open(config)?;
    Ok(format_table(store.list()))
}

/// Revoke by id or name and save; returns the id.
pub fn revoke(config: &Config, id_or_name: &str) -> Result<String, String> {
    let mut store = open(config)?;
    let id = store.revoke(id_or_name).map_err(|e| e.to_string())?;
    store.save().map_err(|e| e.to_string())?;
    Ok(id)
}

/// The path of the keys file (for messages).
pub fn keys_path(config: &Config) -> &Path {
    &config.auth_keys_file
}

/// Render the records as aligned columns (one line per key, a header first; a note when there is none).
pub fn format_table(keys: &[KeyRecord]) -> String {
    let rows: Vec<[String; 6]> = keys
        .iter()
        .map(|k| {
            [
                k.id.clone(),
                k.name.clone(),
                k.scopes
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(","),
                k.created.clone(),
                k.expires.clone().unwrap_or_else(|| "-".into()),
                if k.revoked { "yes" } else { "no" }.into(),
            ]
        })
        .collect();
    let head = ["ID", "NAME", "SCOPES", "CREATED", "EXPIRES", "REVOKED"].map(String::from);
    let mut widths = [0usize; 6];
    for r in std::iter::once(&head).chain(rows.iter()) {
        for (w, c) in widths.iter_mut().zip(r) {
            *w = (*w).max(c.chars().count());
        }
    }
    let mut out = String::new();
    for r in std::iter::once(&head).chain(rows.iter()) {
        let line: Vec<String> = r
            .iter()
            .zip(widths)
            .map(|(c, w)| format!("{c:<w$}"))
            .collect();
        out.push_str(line.join("  ").trim_end());
        out.push('\n');
    }
    if rows.is_empty() {
        out.push_str("(no API keys)\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::temp_config;

    #[test]
    fn create_list_revoke_roundtrip_without_leaking_secrets() {
        let d = tempfile::tempdir().unwrap();
        let config = temp_config(d.path(), &[]);
        let key = create(&config, "admin", &["admin".into()], None).unwrap();
        assert!(key.starts_with("smk_"));
        let key2 = create(&config, "ci", &["ui:read".into(), "match".into()], Some(7)).unwrap();
        assert!(
            create(&config, "ci", &["match".into()], None).is_err(),
            "duplicate name"
        );
        assert!(create(&config, "x", &["bogus".into()], None).is_err());

        let table = list(&config).unwrap();
        assert!(table.starts_with("ID"), "{table}");
        assert!(
            table.contains("admin") && table.contains("match,ui:read")
                || table.contains("ui:read,match")
        );
        let hash = std::fs::read_to_string(keys_path(&config)).unwrap();
        for secret in [&key, &key2] {
            assert!(!table.contains(secret.as_str()));
            let tail = secret.rsplit('_').next().unwrap();
            assert!(
                !table.contains(tail) && !hash.contains(tail),
                "the secret is never stored"
            );
        }
        for line in hash.lines().filter(|l| l.starts_with("hash")) {
            let h = line.split('"').nth(1).unwrap();
            assert!(!table.contains(h), "hashes are not listed");
        }

        let id = revoke(&config, "ci").unwrap();
        assert_eq!(id.len(), 8);
        let table = list(&config).unwrap();
        let ci = table.lines().find(|l| l.contains(" ci ")).unwrap();
        assert!(ci.trim_end().ends_with("yes"), "{ci}");
        assert!(revoke(&config, "nobody").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(keys_path(&config)), 0o600);
            assert_eq!(mode(&config.layout().auth()), 0o700);
        }
    }

    #[test]
    fn empty_table_says_so() {
        assert!(format_table(&[]).contains("(no API keys)"));
    }
}
