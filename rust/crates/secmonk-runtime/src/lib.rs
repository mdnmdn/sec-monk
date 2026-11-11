//! Python runtime (`secmonk-runtime`): the [`PythonRuntime`] trait and [`UvRuntime`], a pinned uv release
//! downloaded into `data_dir`, checksum-verified, extracted safely, then used to install the interpreter and the
//! module venv with an environment that keeps every uv write inside `data_dir`. Modules are launched from the
//! venv interpreter directly (never `uv run`, which would stay as a parent process).
//!
//! Spec: `rust/_docs/tech/configuration.md` § uv, rust ADR-0004.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use async_trait::async_trait;

pub mod env;
pub mod extract;
pub mod fetch;
pub mod pins;
pub mod platform;
pub mod tree;
mod uv;

pub use tree::{TreeDigest, module_digest, verify_module_tree, verify_project_pins};
pub use uv::{UvRuntime, UvSettings};

/// Runtime errors.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// No uv release for this OS/arch/libc.
    #[error("unsupported platform for uv: {0}")]
    UnsupportedPlatform(String),
    /// No checksum for the target (fail closed).
    #[error("no sha256 pin for {0}; set [uv.sha256] in sec-monk.toml")]
    NoChecksum(String),
    /// The archive does not match its pin.
    #[error("sha256 mismatch for {asset}: expected {expected}, got {actual}")]
    ChecksumMismatch {
        /// Asset name.
        asset: String,
        /// Pinned digest.
        expected: String,
        /// Digest of the received bytes.
        actual: String,
    },
    /// Download failed.
    #[error("download of {url} failed: {message}")]
    Download {
        /// URL (no credentials: release URLs carry none).
        url: String,
        /// Message.
        message: String,
    },
    /// Offline mode without the needed artifact.
    #[error("offline: {0}")]
    Offline(String),
    /// The archive is not what we expect.
    #[error("bad uv archive: {0}")]
    BadArchive(String),
    /// A uv step failed.
    #[error("{step} failed (exit {code:?}): {stderr}")]
    Step {
        /// Step name.
        step: String,
        /// Exit code.
        code: Option<i32>,
        /// Last lines of stderr (scrubbed).
        stderr: String,
    },
    /// The module project cannot be hashed (symlink, special file, too large).
    #[error("module tree: {0}")]
    Integrity(String),
    /// `trust = "pinned"` and the project on disk does not match `[modules.pins]`.
    #[error("module {module}: {what} does not match the pin (expected {expected}, got {actual})")]
    PinMismatch {
        /// Module name (`*` when no pin exists at all).
        module: String,
        /// `lock_sha256`, `tree_sha256` or `[modules.pins]`.
        what: String,
        /// Pinned value (`(no pin)` when absent).
        expected: String,
        /// Value on disk.
        actual: String,
    },
    /// Filesystem error.
    #[error("{path}: {source}")]
    Io {
        /// Path.
        path: PathBuf,
        /// Error.
        source: std::io::Error,
    },
}

impl RuntimeError {
    pub(crate) fn io(path: &Path, source: std::io::Error) -> RuntimeError {
        RuntimeError::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

/// Result type.
pub type RuntimeResult<T> = Result<T, RuntimeError>;

/// What [`PythonRuntime::ensure`] set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeInfo {
    /// uv version.
    pub uv_version: String,
    /// uv binary.
    pub uv: PathBuf,
    /// Python version requested (`3.13`).
    pub python_version: String,
}

/// What [`PythonRuntime::ensure_env`] set up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvInfo {
    /// venv name.
    pub env: String,
    /// venv directory.
    pub venv: PathBuf,
    /// Interpreter inside it.
    pub python: PathBuf,
    /// sha256 of the project's `uv.lock`.
    pub lock_sha256: String,
    /// `secmonk-tree/1` hash of the module sources ([`tree`]).
    pub tree_sha256: String,
    /// Whether `uv sync` ran (false: the install marker matched).
    pub synced: bool,
}

/// A process to start: program, args, the complete environment (applied after `env_clear`), working dir.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    /// Executable.
    pub program: PathBuf,
    /// Arguments.
    pub args: Vec<OsString>,
    /// The whole environment of the child.
    pub env: BTreeMap<String, OsString>,
    /// Working directory.
    pub cwd: PathBuf,
}

/// `CREATE_NO_WINDOW`: no console window for children on Windows.
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

impl LaunchSpec {
    /// A tokio command: `env_clear()` + exactly [`LaunchSpec::env`], `CREATE_NO_WINDOW` on Windows,
    /// `kill_on_drop`. Stdio is left to the caller.
    pub fn to_command(&self) -> tokio::process::Command {
        let mut c = tokio::process::Command::new(&self.program);
        c.args(&self.args)
            .env_clear()
            .envs(&self.env)
            .current_dir(&self.cwd)
            .kill_on_drop(true);
        #[cfg(windows)]
        c.creation_flags(CREATE_NO_WINDOW);
        c
    }
}

/// Installs and launches Python environments.
#[async_trait]
pub trait PythonRuntime: Send + Sync {
    /// uv present and verified, the interpreter installed.
    async fn ensure(&self) -> RuntimeResult<RuntimeInfo>;

    /// The venv `env` of the uv project `project` in sync with its lock (`uv sync --frozen`).
    async fn ensure_env(&self, project: &Path, env: &str) -> RuntimeResult<EnvInfo>;

    /// The launch command of a module: the venv interpreter with `entry` (`-I -m secmonk_modules ...`), the
    /// module environment, `-X pycache_prefix=<data_dir>/pycache` (works under `-I`).
    fn command(&self, env: &str, entry: &[String]) -> RuntimeResult<LaunchSpec>;

    /// [`PythonRuntime::command`] with the environment scoped by the manifest `capabilities` (wire strings:
    /// `read-target`, `network`, ...; [`env::module_env_for`]). Use this one to start a module; the default
    /// implementation (test runtimes) ignores the capabilities.
    fn command_for(
        &self,
        env: &str,
        entry: &[String],
        capabilities: &[&str],
    ) -> RuntimeResult<LaunchSpec> {
        let _ = capabilities;
        self.command(env, entry)
    }
}
