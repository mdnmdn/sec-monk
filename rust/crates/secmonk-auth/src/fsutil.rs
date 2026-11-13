//! Private-file helpers: random bytes, permission checks, atomic 0600 writes.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::AuthError;

pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], AuthError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf)
        .map_err(|e| AuthError::io("random source", std::io::Error::other(e.to_string())))?;
    Ok(buf)
}

/// Fail if the file is writable by group/other (`mask = 0o022`) or accessible at all by them (`0o077`).
#[cfg(unix)]
pub(crate) fn check_mode(path: &Path, mask: u32) -> Result<(), AuthError> {
    let meta =
        fs::metadata(path).map_err(|e| AuthError::io(format!("stat {}", path.display()), e))?;
    check_meta_mode(path, &meta, mask)
}

/// [`check_mode`] on metadata already taken (from an open handle); `path` is for the message.
#[cfg(unix)]
pub(crate) fn check_meta_mode(
    path: &Path,
    meta: &fs::Metadata,
    mask: u32,
) -> Result<(), AuthError> {
    use std::os::unix::fs::PermissionsExt;
    let mode = meta.permissions().mode() & 0o777;
    if mode & mask != 0 {
        return Err(AuthError::Format(format!(
            "{} has mode {mode:03o}; refusing a file accessible to group/other (chmod 600)",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn check_mode(_path: &Path, _mask: u32) -> Result<(), AuthError> {
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn check_meta_mode(
    _path: &Path,
    _meta: &fs::Metadata,
    _mask: u32,
) -> Result<(), AuthError> {
    Ok(())
}

fn temp_sibling(path: &Path) -> Result<PathBuf, AuthError> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "file".into());
    let rnd = hex::encode(random_bytes::<6>()?);
    Ok(path.with_file_name(format!(".{name}.tmp-{rnd}")))
}

fn write_temp(path: &Path, data: &[u8]) -> Result<PathBuf, AuthError> {
    let tmp = temp_sibling(path)?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let res = opts.open(&tmp).and_then(|mut f| {
        f.write_all(data)?;
        f.sync_all()
    });
    if let Err(e) = res {
        let _ = fs::remove_file(&tmp);
        return Err(AuthError::io(format!("write {}", tmp.display()), e));
    }
    Ok(tmp)
}

/// Atomically replace `path` with `data` (temp file in the same directory, mode 0600, rename).
pub(crate) fn write_private(path: &Path, data: &[u8]) -> Result<(), AuthError> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)
            .map_err(|e| AuthError::io(format!("create {}", dir.display()), e))?;
    }
    let tmp = write_temp(path, data)?;
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        AuthError::io(format!("rename to {}", path.display()), e)
    })
}

/// Create `path` with `data` only if it does not exist. Returns false when it already existed.
pub(crate) fn create_private_new(path: &Path, data: &[u8]) -> Result<bool, AuthError> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        fs::create_dir_all(dir)
            .map_err(|e| AuthError::io(format!("create {}", dir.display()), e))?;
    }
    let tmp = write_temp(path, data)?;
    let res = fs::hard_link(&tmp, path);
    let _ = fs::remove_file(&tmp);
    match res {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(e) => Err(AuthError::io(format!("create {}", path.display()), e)),
    }
}
