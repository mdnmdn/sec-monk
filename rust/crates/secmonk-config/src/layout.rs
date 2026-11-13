//! The `data_dir` layout (`rust/_docs/tech/configuration.md` § data_dir layout). Directories are created
//! 0700 and checked (owned by the current user, not a symlink), as `secmonk/paths.py` `ensure_private_dir`.

use std::path::{Path, PathBuf};

use crate::ConfigError;

/// Every path below `data_dir` the host, uv and the modules use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    /// The data directory (absolute).
    pub root: PathBuf,
    /// `[paths]`: directories moved out of `root` (absolute).
    pub moved: MovedDirs,
}

/// `[paths]` as resolved: a directory that lives elsewhere than its default below `data_dir`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MovedDirs {
    /// `tools/` (uv releases, `downloads/`).
    pub tools: Option<PathBuf>,
    /// `python/` (`UV_PYTHON_INSTALL_DIR`, `bin/`).
    pub python: Option<PathBuf>,
    /// `venvs/`.
    pub venvs: Option<PathBuf>,
    /// `uv-cache/`.
    pub uv_cache: Option<PathBuf>,
    /// `cache/secmonk/` (`SECMONK_CACHE`).
    pub cache: Option<PathBuf>,
    /// `logs/` (`modules/`).
    pub logs: Option<PathBuf>,
    /// `db/`.
    pub db: Option<PathBuf>,
    /// `auth/`.
    pub auth: Option<PathBuf>,
}

macro_rules! sub {
    ($($(#[$m:meta])* $name:ident => $rel:expr;)*) => {
        impl Layout {
            $( $(#[$m])* pub fn $name(&self) -> PathBuf { self.root.join($rel) } )*
        }
    };
}

sub! {
    /// `pycache/`: bytecode.
    pycache => "pycache";
    /// `webview/`: webview data (Linux, Windows).
    webview => "webview";
    /// `uv-tools/`: `UV_TOOL_DIR`.
    uv_tools => "uv-tools";
    /// `uv-tools/bin/`: `UV_TOOL_BIN_DIR`.
    uv_tools_bin => "uv-tools/bin";
    /// `uv-home/`: sentinel HOME/XDG/APPDATA of uv steps; must stay empty.
    uv_home => "uv-home";
    /// `modules/`: module-owned files.
    modules => "modules";
    /// `python-home/`: `SECMONK_HOME` of modules.
    python_home => "python-home";
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
            moved: MovedDirs::default(),
        }
    }

    /// The layout of `root` with the `[paths]` directories moved.
    pub fn with_moved(root: &Path, moved: MovedDirs) -> Layout {
        Layout {
            root: root.to_path_buf(),
            moved,
        }
    }

    fn pick(&self, moved: &Option<PathBuf>, rel: &str) -> PathBuf {
        moved.clone().unwrap_or_else(|| self.root.join(rel))
    }

    /// `db/` (`[paths] db`): state and mirror databases.
    pub fn db(&self) -> PathBuf {
        self.pick(&self.moved.db, "db")
    }

    /// `tools/` (`[paths] tools`): uv releases.
    pub fn tools(&self) -> PathBuf {
        self.pick(&self.moved.tools, "tools")
    }

    /// `tools/downloads/`: partial downloads.
    pub fn downloads(&self) -> PathBuf {
        self.tools().join("downloads")
    }

    /// `python/` (`[paths] python`): `UV_PYTHON_INSTALL_DIR`.
    pub fn python(&self) -> PathBuf {
        self.pick(&self.moved.python, "python")
    }

    /// `python/bin/`: `UV_PYTHON_BIN_DIR`.
    pub fn python_bin(&self) -> PathBuf {
        self.python().join("bin")
    }

    /// `uv-cache/` (`[paths] uv_cache`): `UV_CACHE_DIR`.
    pub fn uv_cache(&self) -> PathBuf {
        self.pick(&self.moved.uv_cache, "uv-cache")
    }

    /// `venvs/` (`[paths] venvs`): module environments.
    pub fn venvs(&self) -> PathBuf {
        self.pick(&self.moved.venvs, "venvs")
    }

    /// `cache/secmonk/` (`[paths] cache`): `SECMONK_CACHE` of modules.
    pub fn secmonk_cache(&self) -> PathBuf {
        self.pick(&self.moved.cache, "cache/secmonk")
    }

    /// `logs/` (`[paths] logs`).
    pub fn logs(&self) -> PathBuf {
        self.pick(&self.moved.logs, "logs")
    }

    /// `logs/modules/`.
    pub fn module_logs(&self) -> PathBuf {
        self.logs().join("modules")
    }

    /// `auth/` (`[paths] auth`): API keys file and JWT secret.
    pub fn auth(&self) -> PathBuf {
        self.pick(&self.moved.auth, "auth")
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
            self.auth(),
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
