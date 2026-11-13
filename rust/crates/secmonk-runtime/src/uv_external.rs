//! An external uv: `[uv] path` (a file or `"auto"` = `uv` on `PATH`), instead of the managed, sha256-verified download.
//!
//! Trust model: a managed uv is verified against a pinned sha256. An external uv is trusted by *where it lives*
//! and by its `--version` string only (no checksum): it must report the configured version (unless
//! `[uv] any_version`), and on unix its file and its directory must be owned by the current user or root and not
//! writable by group or others. The first successful check is cached for the life of the runtime (no
//! `uv --version` spawn per `ensure_uv`); a binary replaced afterwards is not noticed until restart.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use secmonk_config::UvPath;

use crate::uv::{UvRuntime, UvSource, exe_name};
use crate::{RuntimeError, RuntimeResult};

impl UvRuntime {
    /// `<uv> --version` must report the configured version (unless `any_version`). Returns the version.
    pub(crate) async fn check_external(&self, uv: &Path) -> RuntimeResult<String> {
        if !uv.is_file() {
            return Err(RuntimeError::io(
                uv,
                std::io::Error::new(std::io::ErrorKind::NotFound, "no such uv binary"),
            ));
        }
        check_trusted_location(uv)?;
        let out = tokio::time::timeout(
            Duration::from_secs(30),
            tokio::process::Command::new(uv)
                .arg("--version")
                .env_clear()
                .env("UV_NO_CONFIG", "1")
                .stdin(Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| RuntimeError::Step {
            step: "uv --version".into(),
            code: None,
            stderr: "timed out".into(),
        })?
        .map_err(|e| RuntimeError::io(uv, e))?;
        if !out.status.success() {
            return Err(RuntimeError::Step {
                step: "uv --version".into(),
                code: out.status.code(),
                stderr: secmonk_safeio::scrub_text(&String::from_utf8_lossy(&out.stderr)),
            });
        }
        let found = parse_uv_version(&String::from_utf8_lossy(&out.stdout));
        let expected = &self.settings.uv_version;
        if !self.settings.uv_any_version && found.as_deref() != Some(expected.as_str()) {
            return Err(RuntimeError::UvVersion {
                path: uv.to_path_buf(),
                found: found.unwrap_or_else(|| "unknown".into()),
                expected: expected.clone(),
            });
        }
        Ok(found.unwrap_or_else(|| "unknown".into()))
    }

    /// `[uv] path`: the configured binary, or `uv` on `PATH` (`auto`, falling back to the managed download when
    /// absent or of another version). `Ok(None)`: use the managed download.
    pub(crate) async fn external_uv(&self) -> RuntimeResult<Option<PathBuf>> {
        // the first successful check stands: no `uv --version` per call
        if let Some(u) = self.uv_in_use()
            && matches!(u.source, UvSource::Configured | UvSource::Path)
        {
            return Ok(Some(u.path));
        }
        match &self.settings.uv_path {
            None => Ok(None),
            Some(UvPath::File(f)) => {
                let v = self.check_external(f).await?;
                self.record(f, &v, UvSource::Configured);
                Ok(Some(f.clone()))
            }
            Some(UvPath::Auto) => {
                let path = (self.host_env)("PATH");
                let Some(f) = path
                    .as_deref()
                    .and_then(|p| find_on_path(&exe_name("uv"), p))
                else {
                    tracing::info!("uv.path = auto: no uv on PATH, using the managed download");
                    return Ok(None);
                };
                match self.check_external(&f).await {
                    Ok(v) => {
                        self.record(&f, &v, UvSource::Path);
                        Ok(Some(f))
                    }
                    Err(e) => {
                        tracing::info!(uv = %f.display(), error = %e, "uv on PATH not usable, using the managed download");
                        Ok(None)
                    }
                }
            }
        }
    }
}

/// Refuse a uv whose file or directory could have been replaced by someone else (unix): both must be owned by the
/// current user or root and not writable by group or others. Symlinks are resolved first (a Homebrew `bin/uv` link
/// is judged by its target). No-op elsewhere.
fn check_trusted_location(uv: &Path) -> RuntimeResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let real = std::fs::canonicalize(uv).map_err(|e| RuntimeError::io(uv, e))?;
        let me = rustix::process::getuid().as_raw();
        let untrusted = |reason: String| RuntimeError::UntrustedUv {
            path: uv.to_path_buf(),
            reason,
        };
        let mut checked = vec![real.clone()];
        if let Some(parent) = real.parent() {
            checked.push(parent.to_path_buf());
        }
        for p in checked {
            let md = std::fs::metadata(&p).map_err(|e| RuntimeError::io(&p, e))?;
            if md.mode() & 0o022 != 0 {
                return Err(untrusted(format!(
                    "{} is writable by group or others (mode {:o})",
                    p.display(),
                    md.mode() & 0o7777
                )));
            }
            if md.uid() != me && md.uid() != 0 {
                return Err(untrusted(format!(
                    "{} is owned by uid {}, not by you or root",
                    p.display(),
                    md.uid()
                )));
            }
        }
    }
    #[cfg(not(unix))]
    let _ = uv;
    Ok(())
}

/// `uv 0.13.7 (abc123 2026-11-01)` -> `0.13.7`.
fn parse_uv_version(out: &str) -> Option<String> {
    let mut it = out.split_whitespace();
    (it.next()? == "uv").then(|| it.next().map(str::to_string))?
}

/// The first executable regular file called `name` in the directories of `path` (a `PATH` value). Relative
/// directories are skipped: a `PATH` entry that depends on the working directory is not trusted.
pub fn find_on_path(name: &str, path: &std::ffi::OsStr) -> Option<PathBuf> {
    std::env::split_paths(path)
        .filter(|d| d.is_absolute())
        .map(|d| d.join(name))
        .find(|f| is_executable(f))
}

fn is_executable(f: &Path) -> bool {
    let Ok(md) = std::fs::metadata(f) else {
        return false;
    };
    if !md.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    true
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let tmp = dir.join(format!(".{name}.tmp"));
        std::fs::write(&tmp, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
        let f = dir.join(name);
        std::fs::rename(&tmp, &f).unwrap();
        f
    }

    fn fake_uv(dir: &Path, version: &str) -> PathBuf {
        script(
            dir,
            "uv",
            &format!(
                "if [ \"$1\" = \"--version\" ]; then echo 'uv {version} (abc 2026-01-01)'; else exit 1; fi"
            ),
        )
    }

    #[test]
    fn path_lookup_skips_relative_and_non_executable_entries() {
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a"), d.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::write(a.join("uv"), b"#!/bin/sh\n").unwrap(); // not executable
        let good = fake_uv(&b, "1.0.0");
        let joined =
            std::env::join_paths([PathBuf::from("relative/dir"), a.clone(), b.clone()]).unwrap();
        assert_eq!(find_on_path("uv", &joined), Some(good));
        assert_eq!(find_on_path("uvx", &joined), None);
        assert_eq!(find_on_path("uv", std::ffi::OsStr::new("")), None);
    }

    #[test]
    fn uv_version_output_is_parsed() {
        assert_eq!(
            parse_uv_version("uv 0.13.7 (abc 2026-11-01)\n").as_deref(),
            Some("0.13.7")
        );
        assert_eq!(parse_uv_version("uv 0.13.7").as_deref(), Some("0.13.7"));
        assert_eq!(parse_uv_version("pip 24.0"), None);
        assert_eq!(parse_uv_version(""), None);
    }

    #[test]
    fn a_writable_uv_or_directory_is_not_trusted() {
        let d = tempfile::tempdir().unwrap();
        let uv = fake_uv(&d.path().join("bin"), "1.0.0");
        assert!(check_trusted_location(&uv).is_ok());
        let mode =
            |p: &Path, m| std::fs::set_permissions(p, std::fs::Permissions::from_mode(m)).unwrap();
        mode(&uv, 0o775);
        let e = check_trusted_location(&uv).unwrap_err();
        assert!(matches!(e, RuntimeError::UntrustedUv { .. }), "{e}");
        mode(&uv, 0o755);
        mode(uv.parent().unwrap(), 0o757);
        assert!(matches!(
            check_trusted_location(&uv),
            Err(RuntimeError::UntrustedUv { .. })
        ));
        mode(uv.parent().unwrap(), 0o755);
        // a symlink is judged by its target
        let link_dir = d.path().join("links");
        std::fs::create_dir_all(&link_dir).unwrap();
        std::os::unix::fs::symlink(&uv, link_dir.join("uv")).unwrap();
        assert!(check_trusted_location(&link_dir.join("uv")).is_ok());
        mode(&uv, 0o777);
        assert!(check_trusted_location(&link_dir.join("uv")).is_err());
    }
}
