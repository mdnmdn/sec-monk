//! The `data_dir` layout (`rust/_docs/tech/configuration.md` § data_dir layout). Directories are created
//! 0700 and checked (owned by the current user, not a symlink), as `secmonk/paths.py` `ensure_private_dir`.

use std::path::{Path, PathBuf};

use crate::ConfigError;

/// Every path below `data_dir` the host, uv and the modules use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// The data directory (absolute).
    pub root: PathBuf,
}

macro_rules! sub {
    ($($(#[$m:meta])* $name:ident => $rel:expr;)*) => {
        impl Layout {
            $( $(#[$m])* pub fn $name(&self) -> PathBuf { self.root.join($rel) } )*
        }
    };
}

sub! {
    /// `db/`: state and mirror databases.
    db => "db";
    /// `tools/`: uv releases.
    tools => "tools";
    /// `tools/downloads/`: partial downloads.
    downloads => "tools/downloads";
    /// `python/`: `UV_PYTHON_INSTALL_DIR`.
    python => "python";
    /// `python/bin/`: `UV_PYTHON_BIN_DIR`.
    python_bin => "python/bin";
    /// `pycache/`: bytecode.
    pycache => "pycache";
    /// `webview/`: webview data (Linux, Windows).
    webview => "webview";
    /// `uv-cache/`: `UV_CACHE_DIR`.
    uv_cache => "uv-cache";
    /// `uv-tools/`: `UV_TOOL_DIR`.
    uv_tools => "uv-tools";
    /// `uv-tools/bin/`: `UV_TOOL_BIN_DIR`.
    uv_tools_bin => "uv-tools/bin";
    /// `uv-home/`: sentinel HOME/XDG/APPDATA of uv steps; must stay empty.
    uv_home => "uv-home";
    /// `venvs/`: module environments.
    venvs => "venvs";
    /// `modules/`: module-owned files.
    modules => "modules";
    /// `python-home/`: `SECMONK_HOME` of modules.
    python_home => "python-home";
    /// `cache/secmonk/`: `SECMONK_CACHE` of modules.
    secmonk_cache => "cache/secmonk";
    /// `logs/`.
    logs => "logs";
    /// `logs/modules/`.
    module_logs => "logs/modules";
    /// `jobs/`: per-job scratch.
    jobs => "jobs";
    /// `tmp/`: `TMPDIR` of children.
    tmp => "tmp";
    /// `run/`: instance lock.
    run => "run";
}

impl Layout {
    /// The layout of `root` (should be the canonical `Config::data_dir`).
    pub fn new(root: &Path) -> Layout {
        Layout {
            root: root.to_path_buf(),
        }
    }

    /// `tools/uv-<version>/`.
    pub fn uv_dir(&self, version: &str) -> PathBuf {
        self.tools().join(format!("uv-{version}"))
    }

    /// `venvs/<env>/`.
    pub fn venv(&self, env: &str) -> PathBuf {
        self.venvs().join(env)
    }

    /// `modules/<name>/`.
    pub fn module_dir(&self, name: &str) -> PathBuf {
        self.modules().join(name)
    }

    /// `run/instance.lock`.
    pub fn instance_lock(&self) -> PathBuf {
        self.run().join("instance.lock")
    }

    /// Directories created at start.
    pub fn dirs(&self) -> Vec<PathBuf> {
        vec![
            self.root.clone(),
            self.db(),
            self.tools(),
            self.downloads(),
            self.python(),
            self.python_bin(),
            self.pycache(),
            self.uv_cache(),
            self.uv_tools(),
            self.uv_tools_bin(),
            self.uv_home(),
            self.venvs(),
            self.modules(),
            self.python_home(),
            self.root.join("cache"),
            self.secmonk_cache(),
            self.logs(),
            self.module_logs(),
            self.jobs(),
            self.tmp(),
            self.run(),
        ]
    }

    /// Create every directory of the layout (0700, checked).
    pub fn create(&self) -> Result<(), ConfigError> {
        for d in self.dirs() {
            ensure_private_dir(&d)?;
        }
        Ok(())
    }
}

/// Create `path` (0700) if missing; refuse a symlink or a directory owned by someone else; tighten group/other
/// permissions (`paths.ensure_private_dir`).
pub fn ensure_private_dir(path: &Path) -> Result<(), ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|e| ConfigError::io(path, e))?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(path).map_err(|e| ConfigError::io(path, e))?;
    let md = std::fs::symlink_metadata(path).map_err(|e| ConfigError::io(path, e))?;
    let refuse = |reason: &str| ConfigError::Untrusted {
        path: path.to_path_buf(),
        reason: reason.into(),
    };
    if md.file_type().is_symlink() {
        return Err(refuse("is a symlink"));
    }
    if !md.is_dir() {
        return Err(refuse("is not a directory"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if md.uid() != rustix::process::getuid().as_raw() {
            return Err(refuse("is not owned by the current user"));
        }
        if md.mode() & 0o077 != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| ConfigError::io(path, e))?;
        }
    }
    Ok(())
}
