//! Config lookup order, the ownership check and the checked read.
//!
//! A config file decides which code runs (modules, uv URL) and where state goes, so a file found by the lookup
//! (steps 2-4) is opened **once** without following a final symlink, checked on the open handle (`fstat`: regular
//! file, owned by the current user, not group/other-writable; its directory not group/other-writable) and read
//! from that same handle: there is no window between the check and the read.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use crate::{APP_DIR, CONFIG_FILE, ConfigError, LoadOptions};

/// Largest config file read.
pub const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Where the config came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigOrigin {
    /// `--config`.
    Flag,
    /// `SECMONK_CONFIG`.
    Env,
    /// `./sec-monk.toml` (every build).
    Cwd,
    /// The per-user config file.
    User,
    /// No file: built-in defaults.
    Defaults,
}

impl ConfigOrigin {
    /// Whether a file of this origin must pass the ownership check (every step but `--config`).
    pub fn checked(self) -> bool {
        matches!(
            self,
            ConfigOrigin::Env | ConfigOrigin::Cwd | ConfigOrigin::User
        )
    }
}

/// A located config file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Located {
    /// Absolute path.
    pub path: PathBuf,
    /// Lookup step.
    pub origin: ConfigOrigin,
}

/// Find the config file. An explicit file (`--config`, `SECMONK_CONFIG`) must exist; files from steps 2-4
/// must pass [`check_owner`].
/// `Ok(None)` means built-in defaults.
pub fn locate(opts: &LoadOptions) -> Result<Option<Located>, ConfigError> {
    let abs = |p: PathBuf| if p.is_absolute() { p } else { opts.cwd.join(p) };
    if let Some(p) = &opts.cli_config {
        let p = abs(p.clone());
        if !p.is_file() {
            return Err(ConfigError::NotFound(p));
        }
        return Ok(Some(Located {
            path: p,
            origin: ConfigOrigin::Flag,
        }));
    }
    if let Some(p) = &opts.env_config {
        let p = abs(PathBuf::from(p));
        if std::fs::symlink_metadata(&p).is_err() {
            return Err(ConfigError::NotFound(p));
        }
        check_owner(&p)?;
        return Ok(Some(Located {
            path: p,
            origin: ConfigOrigin::Env,
        }));
    }
    let cwd_file = opts.cwd.join(CONFIG_FILE);
    if std::fs::symlink_metadata(&cwd_file).is_ok() {
        check_owner(&cwd_file)?;
        return Ok(Some(Located {
            path: cwd_file,
            origin: ConfigOrigin::Cwd,
        }));
    }
    if let Some(root) = &opts.user_config_root {
        let f = root.join(APP_DIR).join(CONFIG_FILE);
        if std::fs::symlink_metadata(&f).is_ok() {
            check_owner(&f)?;
            return Ok(Some(Located {
                path: f,
                origin: ConfigOrigin::User,
            }));
        }
    }
    Ok(None)
}

/// Refuse a config file that is a symlink, not a regular file, not owned by the current user, or writable by
/// group/others, or whose directory is writable by group/others without the sticky bit (POSIX). The checks run
/// on the open handle. On Windows: a regular file that is not a reparse point (symlink, junction); ownership and
/// ACLs are **not** checked (documented limitation, configuration.md § Lookup order).
pub fn check_owner(path: &Path) -> Result<(), ConfigError> {
    open_checked(path).map(|_| ())
}

/// Read the located file: for checked origins through [`check_owner`]'s open handle, `--config` with a plain
/// open (the user named it explicitly; symlinks allowed). At most [`MAX_CONFIG_BYTES`].
pub fn read_config(l: &Located) -> Result<String, ConfigError> {
    let f = if l.origin.checked() {
        open_checked(&l.path)?
    } else {
        File::open(&l.path).map_err(|e| ConfigError::io(&l.path, e))?
    };
    let md = f.metadata().map_err(|e| ConfigError::io(&l.path, e))?;
    if !md.is_file() {
        return Err(untrusted(&l.path, "not a regular file"));
    }
    if md.len() > MAX_CONFIG_BYTES {
        return Err(untrusted(&l.path, "larger than 1 MiB"));
    }
    let mut text = String::new();
    f.take(MAX_CONFIG_BYTES)
        .read_to_string(&mut text)
        .map_err(|e| ConfigError::io(&l.path, e))?;
    Ok(text)
}

fn untrusted(path: &Path, reason: &str) -> ConfigError {
    ConfigError::Untrusted {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

/// Open without following a final symlink and without blocking (a FIFO), then check the handle.
fn open_checked(path: &Path) -> Result<File, ConfigError> {
    let lmd = std::fs::symlink_metadata(path).map_err(|e| ConfigError::io(path, e))?;
    if lmd.file_type().is_symlink() {
        return Err(untrusted(path, "is a symlink"));
    }
    if !lmd.is_file() {
        return Err(untrusted(path, "not a regular file"));
    }
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let flags = rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK;
        o.custom_flags(flags.bits() as i32);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_FLAG_OPEN_REPARSE_POINT: open a symlink / junction itself, never its target.
        o.custom_flags(0x0020_0000);
    }
    let f = o.open(path).map_err(|e| {
        #[cfg(unix)]
        if e.raw_os_error() == Some(rustix::io::Errno::LOOP.raw_os_error()) {
            return untrusted(path, "is a symlink");
        }
        ConfigError::io(path, e)
    })?;
    let md = f.metadata().map_err(|e| ConfigError::io(path, e))?;
    if md.file_type().is_symlink() {
        return Err(untrusted(path, "is a symlink"));
    }
    if !md.is_file() {
        return Err(untrusted(path, "not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if md.dev() != lmd.dev() || md.ino() != lmd.ino() {
            return Err(untrusted(path, "replaced while it was opened"));
        }
        if md.uid() != rustix::process::getuid().as_raw() {
            return Err(untrusted(path, "not owned by the current user"));
        }
        if md.mode() & 0o022 != 0 {
            return Err(untrusted(path, "writable by group or others"));
        }
        check_parent(path)?;
    }
    Ok(f)
}

/// The directory of the file must not let others replace it: not group/other-writable, unless sticky (`/tmp`:
/// others cannot rename or delete a file they do not own, and the file itself is checked to be ours).
#[cfg(unix)]
fn check_parent(path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let md = std::fs::metadata(parent).map_err(|e| ConfigError::io(parent, e))?;
    let sticky = md.mode() & 0o1000 != 0;
    if md.mode() & 0o022 != 0 && !sticky {
        return Err(untrusted(
            path,
            "its directory is writable by group or others",
        ));
    }
    Ok(())
}
