//! The `apikey` commands over `Config.auth_keys_file`: create, list, revoke. They touch the keys file only (no
//! engine, no uv, no Python); a running server picks changes up on its next request.

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

/// Run `f` on the loaded store while holding an exclusive lock on `<keys_file>.lock`, so concurrent CLI
/// invocations cannot lose each other's updates (load, modify, save is one critical section).
fn locked<T>(
    config: &Config,
    f: impl FnOnce(&mut KeyStore) -> Result<T, String>,
) -> Result<T, String> {
    ensure_auth_dirs(config)?;
    let mut lock_name = config.auth_keys_file.clone().into_os_string();
    lock_name.push(".lock");
    let lock_path = std::path::PathBuf::from(lock_name);
    let mut open = std::fs::OpenOptions::new();
    open.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let lock = open
        .open(&lock_path)
        .map_err(|e| format!("{}: {e}", lock_path.display()))?;
    lock.lock()
        .map_err(|e| format!("lock {}: {e}", lock_path.display()))?;
    let mut store = KeyStore::load(&config.auth_keys_file).map_err(|e| e.to_string())?;
    let out = f(&mut store);
    let _ = lock.unlock();
    out
}

/// The longest key lifetime accepted (100 years), in days.
pub const MAX_EXPIRES_DAYS: u64 = 36_500;

/// Create a key, save the file (0600) and return the plaintext key, to be shown once. `expires_days` is 1..=36500.
pub fn create(
    config: &Config,
    name: &str,
    scopes: &[String],
    expires_days: Option<u64>,
) -> Result<String, String> {
    let scopes = Scopes::parse(scopes.iter().map(String::as_str)).map_err(|e| e.to_string())?;
    let expires = match expires_days {
        None => None,
        Some(d) if (1..=MAX_EXPIRES_DAYS).contains(&d) => Some(
            SystemTime::now()
                .checked_add(Duration::from_secs(d * 86_400))
                .ok_or("the expiry is out of range")?,
        ),
        Some(d) => {
            return Err(format!(
                "expires-days {d} is out of range (1..={MAX_EXPIRES_DAYS})"
            ));
        }
    };
    locked(config, |store| {
        let key = store
            .create(name, scopes, expires)
            .map_err(|e| e.to_string())?;
        store.save().map_err(|e| e.to_string())?;
        Ok(key)
    })
}

/// The key table: id, name, scopes, created, expires, revoked. Never a key or a hash.
pub fn list(config: &Config) -> Result<String, String> {
    let store = locked(config, |s| Ok(s.list().to_vec()))?;
    Ok(format_table(&store))
}

/// Revoke by id or name and save; returns the id.
pub fn revoke(config: &Config, id_or_name: &str) -> Result<String, String> {
    locked(config, |store| {
        let id = store.revoke(id_or_name).map_err(|e| e.to_string())?;
        store.save().map_err(|e| e.to_string())?;
        Ok(id)
    })
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
        let hash = std::fs::read_to_string(&config.auth_keys_file).unwrap();
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
            let mode =
                |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&config.auth_keys_file), 0o600);
            assert_eq!(mode(&config.layout().auth()), 0o700);
        }
    }

    #[test]
    fn expires_days_is_validated() {
        let d = tempfile::tempdir().unwrap();
        let config = temp_config(d.path(), &[]);
        for bad in [0, 36_501, u64::MAX] {
            assert!(create(&config, "k", &["match".into()], Some(bad)).is_err());
        }
        assert!(create(&config, "k", &["match".into()], Some(36_500)).is_ok());
    }

    #[test]
    fn concurrent_creates_lose_no_key() {
        let d = tempfile::tempdir().unwrap();
        let config = std::sync::Arc::new(temp_config(d.path(), &[]));
        let hs: Vec<_> = (0..8)
            .map(|i| {
                let c = config.clone();
                std::thread::spawn(move || {
                    create(&c, &format!("k{i}"), &["match".into()], None).unwrap()
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        let table = list(&config).unwrap();
        assert_eq!(table.lines().count(), 9, "{table}");
    }

    #[test]
    fn empty_table_says_so() {
        assert!(format_table(&[]).contains("(no API keys)"));
    }
}
