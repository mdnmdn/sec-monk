//! `sec-monk.toml` (`secmonk-config`): lookup order, ownership check, path resolution, `data_dir` layout.
//!
//! Spec: `rust/_docs/tech/configuration.md`, rust ADR-0008. The first file found wins (no merging):
//! `--config`, `SECMONK_CONFIG`, `./sec-monk.toml` (every build), the per-user config
//! file, else built-in defaults.
//! Relative paths resolve against the config file's directory; `data_dir` is canonicalized to an absolute
//! path before anything uses it.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use serde::Deserialize;

pub mod layout;
mod lookup;

pub use layout::{Layout, MovedDirs};
pub use lookup::{ConfigOrigin, Located, MAX_CONFIG_BYTES, check_owner, locate, read_config};

/// File name looked up in the current directory and the per-user config directory.
pub const CONFIG_FILE: &str = "sec-monk.toml";
/// Directory name under the per-user data/config roots.
pub const APP_DIR: &str = "sec-monk";
/// Supported `config_version`.
pub const CONFIG_VERSION: u32 = 1;

/// Configuration errors.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// A config file named explicitly does not exist.
    #[error("config file {0} not found")]
    NotFound(PathBuf),
    /// A config file failed the ownership/permission check.
    #[error("refusing config file {path}: {reason}")]
    Untrusted {
        /// The file.
        path: PathBuf,
        /// Why.
        reason: String,
    },
    /// TOML syntax or schema error.
    #[error("invalid config {path}: {message}")]
    Parse {
        /// The file.
        path: PathBuf,
        /// Message.
        message: String,
    },
    /// A value is not acceptable.
    #[error("invalid config value: {0}")]
    Invalid(String),
    /// No home / data directory could be determined.
    #[error("cannot determine the per-user {0} directory")]
    NoUserDir(&'static str),
    /// Filesystem error.
    #[error("{path}: {source}")]
    Io {
        /// The path.
        path: PathBuf,
        /// The error.
        source: std::io::Error,
    },
}

impl ConfigError {
    /// An I/O error on `path`.
    pub fn io(path: &Path, source: std::io::Error) -> ConfigError {
        ConfigError::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

/// The file as written (`sec-monk.toml`), before path resolution. Unknown keys are refused: the file decides
/// which code runs, a silently ignored typo is worse than an error.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    /// Format version (1).
    pub config_version: Option<u32>,
    /// Data directory.
    pub data_dir: Option<String>,
    /// `[database]`.
    #[serde(default)]
    pub database: DatabaseSection,
    /// `[python]`.
    #[serde(default)]
    pub python: PythonSection,
    /// `[uv]`.
    #[serde(default)]
    pub uv: UvSection,
    /// `[modules]`.
    #[serde(default)]
    pub modules: ModulesSection,
    /// `[ui]`.
    #[serde(default)]
    pub ui: UiSection,
    /// `[engine]`.
    #[serde(default)]
    pub engine: EngineSection,
    /// `[sources]`.
    #[serde(default)]
    pub sources: SourcesSection,
    /// `[log]`.
    #[serde(default)]
    pub log: LogSection,
    /// `[paths]`.
    #[serde(default)]
    pub paths: PathsSection,
    /// `[server]`.
    #[serde(default)]
    pub server: ServerSection,
    /// `[auth]`.
    #[serde(default)]
    pub auth: AuthSection,
    /// `[node]`.
    #[serde(default)]
    pub node: NodeSection,
}

/// `[paths]`: directories below `data_dir` that can live elsewhere (unset = `data_dir/<default>`).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathsSection {
    /// uv releases (`tools/`).
    pub tools: Option<String>,
    /// uv-managed interpreters (`python/`).
    pub python: Option<String>,
    /// Module environments (`venvs/`).
    pub venvs: Option<String>,
    /// `UV_CACHE_DIR` (`uv-cache/`).
    pub uv_cache: Option<String>,
    /// `SECMONK_CACHE` of modules (`cache/secmonk/`).
    pub cache: Option<String>,
    /// Log files (`logs/`).
    pub logs: Option<String>,
    /// Database files (`db/`; `{db_dir}`).
    pub db: Option<String>,
    /// API keys and JWT secret (`auth/`).
    pub auth: Option<String>,
}

/// `[server] auth`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// Required on a non-loopback address, off on loopback.
    #[default]
    Auto,
    /// Always required.
    Required,
    /// Never required (loopback only).
    Off,
}

impl AuthMode {
    /// The config spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthMode::Auto => "auto",
            AuthMode::Required => "required",
            AuthMode::Off => "off",
        }
    }
}

/// `[server]`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerSection {
    /// `host:port` of the HTTP(S) listener.
    pub listen: Option<String>,
    /// PEM certificate chain.
    pub tls_cert: Option<String>,
    /// PEM private key.
    pub tls_key: Option<String>,
    /// Extra accepted `Host` names.
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    /// Plain HTTP on a non-loopback address.
    pub insecure_http: Option<bool>,
    /// Scans and syncs through the API.
    pub allow_actions: Option<bool>,
    /// Authentication mode.
    pub auth: Option<AuthMode>,
    /// Serve the UI files.
    pub serve_ui: Option<bool>,
}

/// `[auth]`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSection {
    /// API keys file.
    pub keys_file: Option<String>,
    /// JWT lifetime in seconds.
    pub jwt_ttl_s: Option<u64>,
    /// JWT secret file.
    pub jwt_secret_file: Option<String>,
    /// Calls per minute per key.
    pub rate_per_minute: Option<u32>,
}

/// A node API service (`[node] serve`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeService {
    /// Source feed.
    Feed,
    /// Component matching.
    Match,
    /// Vulnerability summaries.
    Vulninfo,
}

impl NodeService {
    /// The config spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            NodeService::Feed => "feed",
            NodeService::Match => "match",
            NodeService::Vulninfo => "vulninfo",
        }
    }
}

/// `[node] matcher`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatcherMode {
    /// Match against the local mirror.
    #[default]
    Local,
    /// Match through `node.upstream`.
    Remote,
}

impl MatcherMode {
    /// The config spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            MatcherMode::Local => "local",
            MatcherMode::Remote => "remote",
        }
    }
}

/// `[node]`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    /// This node has a mirror part.
    pub mirror: Option<bool>,
    /// Node API services offered.
    #[serde(default)]
    pub serve: Vec<NodeService>,
    /// Where matching runs.
    pub matcher: Option<MatcherMode>,
    /// `[node.upstream]`.
    #[serde(default)]
    pub upstream: UpstreamSection,
}

/// `[node.upstream]`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamSection {
    /// Base URL of the upstream node.
    pub url: Option<String>,
    /// Environment variable holding the upstream API key.
    pub api_key_env: Option<String>,
    /// PEM to trust.
    pub ca_cert: Option<String>,
    /// Sources followed from the upstream feed.
    #[serde(default)]
    pub sources: Vec<String>,
}

/// `[database]`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseSection {
    /// `sqlite` (later `postgres`, `mysql`).
    pub backend: Option<String>,
    /// State database URL (`{data_dir}` and `{db_dir}` substituted).
    pub state: Option<String>,
    /// Mirror database URL.
    pub mirror: Option<String>,
}

/// `[python]`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PythonSection {
    /// Interpreter version (`3.13`).
    pub version: Option<String>,
    /// No downloads of any kind.
    pub offline: Option<bool>,
    /// Wheel directory for offline installs.
    pub find_links: Option<String>,
    /// Package index URL.
    pub index_url: Option<String>,
}

/// `[uv]`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UvSection {
    /// Pinned uv version (overrides the compiled-in pin).
    pub version: Option<String>,
    /// URL template with `{version}` and `{asset}`.
    pub url: Option<String>,
    /// Local copy of the release archive.
    pub archive: Option<String>,
    /// A uv binary to use instead of the managed download (`"auto"`: `uv` on `PATH`).
    pub path: Option<String>,
    /// Accept any version of `[uv] path` (default: it must report `[uv] version`).
    pub any_version: Option<bool>,
    /// target triple -> sha256 of the release archive.
    #[serde(default)]
    pub sha256: BTreeMap<String, String>,
}

/// The modules enabled when `[modules] enabled` is absent (no config file, or a file without the key): the four
/// shipped ones. A module whose manifest does not list the running platform stays registered as unavailable
/// (`ModuleEntry::available`), so the default is the same on every OS. `enabled = []` means none.
pub const DEFAULT_MODULES: [&str; 4] = ["py-engine", "py-procmon", "py-probe", "py-sources"];

/// `[modules]`; tables other than `pins` are per-module overrides (`[modules.py-sources]`). Not
/// `deny_unknown_fields` (serde cannot combine it with `flatten`): an unknown key must still deserialize as a
/// [`ModuleOverride`] table, which denies unknown fields, so typos are refused all the same.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct ModulesSection {
    /// uv project of the Python modules.
    pub python_project: Option<String>,
    /// Modules that may run.
    pub enabled: Option<Vec<String>>,
    /// `dev` or `pinned`.
    pub trust: Option<TrustMode>,
    /// Integrity pins (pinned mode).
    #[serde(default)]
    pub pins: BTreeMap<String, ModulePin>,
    /// Per-module limit / lifecycle overrides.
    #[serde(flatten)]
    pub overrides: BTreeMap<String, ModuleOverride>,
}

/// Trust mode of module code.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustMode {
    /// Editable install from the repo, no tree hash.
    #[default]
    Dev,
    /// Pins must match before install.
    Pinned,
}

/// `[modules.pins] <name> = {lock_sha256, tree_sha256}`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModulePin {
    /// sha256 of `uv.lock`.
    pub lock_sha256: Option<String>,
    /// sha256 of the module sources.
    pub tree_sha256: Option<String>,
}

/// `[modules.<name>]`: overrides of manifest `limits` / `lifecycle` (never capabilities).
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleOverride {
    /// `lazy` / `eager`.
    pub start: Option<String>,
    /// Idle timeout.
    pub idle_timeout_s: Option<u64>,
    /// Restarts per window.
    pub max_restarts: Option<u32>,
    /// Restart window.
    pub restart_window_s: Option<u64>,
    /// `hello` timeout.
    pub hello_timeout_s: Option<u64>,
    /// Request deadline.
    pub request_timeout_s: Option<u64>,
    /// Grace after cancel.
    pub cancel_grace_s: Option<u64>,
    /// Frame limit.
    pub max_frame: Option<u64>,
    /// Concurrent requests.
    pub max_inflight: Option<u32>,
    /// Memory limit.
    pub memory_mb: Option<u64>,
}

/// `[ui]`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UiSection {
    /// The current UI, served in place.
    pub static_dir: Option<String>,
    /// Custom scheme name.
    pub scheme: Option<String>,
    /// Process monitor on a snapshot file.
    pub snapshot: Option<String>,
    /// Optional dev HTTP binding.
    pub http_listen: Option<String>,
    /// Webview developer tools.
    pub devtools: Option<bool>,
}

/// `[engine]`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineSection {
    /// Minimum match confidence.
    pub min_confidence: Option<f64>,
}

/// `[sources]`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcesSection {
    /// Environment variable holding the NVD API key.
    pub nvd_api_key_env: Option<String>,
    /// `[sources.implementation]`: source name -> `rust` | `python` (rust ADR-0011).
    #[serde(default)]
    pub implementation: BTreeMap<String, SourceImpl>,
}

/// Which implementation syncs a source (`[sources.implementation]`, rust ADR-0011).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceImpl {
    /// The native Rust source (`secmonk-sources`), in-process.
    Rust,
    /// The Python source of `py-sources` (staging adapter, rust ADR-0010).
    Python,
}

/// `[log]`.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSection {
    /// `tracing` filter.
    pub level: Option<String>,
    /// Log files kept.
    pub keep_days: Option<u32>,
}

/// The resolved configuration: absolute paths, defaults filled, `{data_dir}` substituted.
#[derive(Debug, Clone, PartialEq)]
pub struct Config {
    /// Which file was used.
    pub origin: ConfigOrigin,
    /// The file (absent for built-in defaults).
    pub file: Option<PathBuf>,
    /// Absolute, canonical data directory (created).
    pub data_dir: PathBuf,
    /// Database backend (`sqlite`).
    pub database_backend: String,
    /// State database URL.
    pub state_url: String,
    /// Mirror database URL.
    pub mirror_url: String,
    /// Python version for module venvs.
    pub python_version: String,
    /// Offline mode.
    pub offline: bool,
    /// Wheel directory.
    pub find_links: Option<PathBuf>,
    /// Package index.
    pub index_url: Option<String>,
    /// uv version override (`None` = compiled-in pin).
    pub uv_version: Option<String>,
    /// uv URL template.
    pub uv_url: Option<String>,
    /// Local uv archive.
    pub uv_archive: Option<PathBuf>,
    /// sha256 overrides per target.
    pub uv_sha256: BTreeMap<String, String>,
    /// uv project of the Python modules (absolute).
    pub python_project: PathBuf,
    /// Enabled modules.
    pub modules_enabled: Vec<String>,
    /// Trust mode.
    pub trust: TrustMode,
    /// Integrity pins.
    pub module_pins: BTreeMap<String, ModulePin>,
    /// Per-module overrides.
    pub module_overrides: BTreeMap<String, ModuleOverride>,
    /// UI static directory (absolute; not required to exist).
    pub ui_static_dir: PathBuf,
    /// Custom scheme.
    pub ui_scheme: String,
    /// Snapshot file.
    pub ui_snapshot: Option<PathBuf>,
    /// Dev HTTP binding.
    pub ui_http_listen: Option<String>,
    /// Devtools.
    pub ui_devtools: bool,
    /// Minimum confidence.
    pub min_confidence: f64,
    /// NVD key variable name.
    pub nvd_api_key_env: String,
    /// `[sources.implementation]` as written (defaults: [`Config::source_impl`]).
    pub source_impls: BTreeMap<String, SourceImpl>,
    /// Log filter.
    pub log_level: String,
    /// Log files kept.
    pub log_keep_days: u32,
    /// `[paths]`: moved directories (absolute).
    pub paths: MovedDirs,
    /// `[uv] path`.
    pub uv_path: Option<UvPath>,
    /// `[uv] any_version`.
    pub uv_any_version: bool,
    /// `[server] listen` (`None`: the host falls back to `ui.http_listen`, then `127.0.0.1:8765`).
    pub server_listen: Option<String>,
    /// `[server] tls_cert`.
    pub server_tls_cert: Option<PathBuf>,
    /// `[server] tls_key`.
    pub server_tls_key: Option<PathBuf>,
    /// `[server] allow_hosts`.
    pub server_allow_hosts: Vec<String>,
    /// `[server] insecure_http`.
    pub server_insecure_http: bool,
    /// `[server] allow_actions`.
    pub server_allow_actions: bool,
    /// `[server] auth`.
    pub server_auth: AuthMode,
    /// `[server] serve_ui`.
    pub server_serve_ui: bool,
    /// `[auth] keys_file` (default `<auth dir>/api_keys.toml`).
    pub auth_keys_file: PathBuf,
    /// `[auth] jwt_ttl_s`.
    pub auth_jwt_ttl_s: u64,
    /// `[auth] jwt_secret_file` (default `<auth dir>/jwt.key`).
    pub auth_jwt_secret_file: PathBuf,
    /// `[auth] rate_per_minute`.
    pub auth_rate_per_minute: u32,
    /// `[node] mirror`.
    pub node_mirror: bool,
    /// `[node] serve` (sorted, no duplicates).
    pub node_serve: Vec<NodeService>,
    /// `[node] matcher`.
    pub node_matcher: MatcherMode,
    /// `[node.upstream] url`.
    pub node_upstream_url: Option<String>,
    /// `[node.upstream] api_key_env`.
    pub node_upstream_api_key_env: String,
    /// `[node.upstream] ca_cert`.
    pub node_upstream_ca_cert: Option<PathBuf>,
    /// `[node.upstream] sources`.
    pub node_upstream_sources: Vec<String>,
}

/// `[uv] path`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UvPath {
    /// `"auto"`: `uv` (`uv.exe`) on `PATH` when its version matches, else the managed download.
    Auto,
    /// A uv binary.
    File(PathBuf),
}

/// Inputs of [`load`]: everything the process environment contributes, so tests stay hermetic.
#[derive(Debug, Clone, Default)]
pub struct LoadOptions {
    /// `--config`.
    pub cli_config: Option<PathBuf>,
    /// `SECMONK_CONFIG`.
    pub env_config: Option<OsString>,
    /// `SECMONK_STATIC` (dev override of `ui.static_dir`).
    pub env_static: Option<OsString>,
    /// Current directory.
    pub cwd: PathBuf,
    /// User home.
    pub home: Option<PathBuf>,
    /// Per-user config root (`~/Library/Application Support`, `$XDG_CONFIG_HOME`, `%APPDATA%`).
    pub user_config_root: Option<PathBuf>,
    /// Per-user data root (`~/Library/Application Support`, `$XDG_DATA_HOME`, `%LOCALAPPDATA%`).
    pub user_data_root: Option<PathBuf>,
    /// `SECMONK_*` variables (name, value) other than the reserved ones ([`RESERVED_ENV`]); see
    /// [`env_key`]. Override the file.
    pub env_overrides: Vec<(String, String)>,
    /// `--set section.key=value` ([`parse_set`]). Override the environment.
    pub cli_overrides: Vec<String>,
}

impl LoadOptions {
    /// From the real process environment, with `--config` from the command line.
    pub fn from_env(cli_config: Option<PathBuf>) -> LoadOptions {
        LoadOptions {
            cli_config,
            env_config: std::env::var_os("SECMONK_CONFIG").filter(|v| !v.is_empty()),
            env_static: std::env::var_os("SECMONK_STATIC").filter(|v| !v.is_empty()),
            cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
            home: dirs::home_dir(),
            user_config_root: dirs::config_dir(),
            user_data_root: dirs::data_local_dir(),
            env_overrides: std::env::vars_os()
                .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)))
                .filter(|(k, v)| {
                    k.starts_with(ENV_PREFIX)
                        && !RESERVED_ENV.contains(&k.as_str())
                        && !v.is_empty()
                })
                .collect(),
            cli_overrides: Vec::new(),
        }
    }
}

/// Locate, check, parse and resolve the configuration (file, then `SECMONK_*`, then `--set` overrides); create
/// and check `data_dir`. Logs which file is used.
pub fn load(opts: &LoadOptions) -> Result<Config, ConfigError> {
    let located = locate(opts)?;
    let (table, path, origin, file) = match located {
        Some(l) => {
            let text = read_config(&l)?;
            let table = parse_table(&text, &l.path)?;
            tracing::info!(file = %l.path.display(), origin = ?l.origin, "using config file");
            (table, l.path.clone(), l.origin, Some(l.path))
        }
        None => {
            tracing::info!("no config file found; using built-in defaults");
            (
                toml::Table::new(),
                PathBuf::from(CONFIG_FILE),
                ConfigOrigin::Defaults,
                None,
            )
        }
    };
    let table = apply_overrides(table, opts)?;
    let raw = raw_from_table(table, &path)?;
    resolve(raw, origin, file, opts)
}

/// Parse the TOML text of a config file.
pub fn parse(text: &str, path: &Path) -> Result<RawConfig, ConfigError> {
    raw_from_table(parse_table(text, path)?, path)
}

fn parse_table(text: &str, path: &Path) -> Result<toml::Table, ConfigError> {
    toml::from_str(text).map_err(|e| ConfigError::Parse {
        path: path.to_path_buf(),
        message: e.to_string(),
    })
}

fn raw_from_table(table: toml::Table, path: &Path) -> Result<RawConfig, ConfigError> {
    let raw: RawConfig = toml::Value::Table(table)
        .try_into()
        .map_err(|e: toml::de::Error| ConfigError::Parse {
            path: path.to_path_buf(),
            message: e.to_string(),
        })?;
    if let Some(v) = raw.config_version
        && v != CONFIG_VERSION
    {
        return Err(ConfigError::Parse {
            path: path.to_path_buf(),
            message: format!("config_version {v} is not supported (expected {CONFIG_VERSION})"),
        });
    }
    Ok(raw)
}

/// Prefix of the environment overrides.
pub const ENV_PREFIX: &str = "SECMONK_";

/// `SECMONK_*` variables that are not config overrides (read elsewhere).
pub const RESERVED_ENV: [&str; 6] = [
    "SECMONK_CONFIG",
    "SECMONK_STATIC",
    "SECMONK_API_KEY",
    "SECMONK_UPSTREAM_API_KEY",
    "SECMONK_JWT_SECRET",
    "SECMONK_LOG",
];

/// Keys holding a path: a relative value given by an override resolves against the current directory.
const OVERRIDE_PATH_KEYS: &[&str] = &[
    "data_dir",
    "paths.tools",
    "paths.python",
    "paths.venvs",
    "paths.uv_cache",
    "paths.cache",
    "paths.logs",
    "paths.db",
    "paths.auth",
    "python.find_links",
    "uv.archive",
    "uv.path",
    "modules.python_project",
    "ui.static_dir",
    "ui.snapshot",
    "server.tls_cert",
    "server.tls_key",
    "auth.keys_file",
    "auth.jwt_secret_file",
    "node.upstream.ca_cert",
];

/// Top-level keys that a `SECMONK_<KEY>` variable (no `__`) may override.
const TOP_LEVEL_ENV_KEYS: &[&str] = &["data_dir", "config_version"];

/// The dotted config key of an environment variable: `SECMONK_DATA_DIR` -> `data_dir`,
/// `SECMONK_SERVER__LISTEN` -> `server.listen`. `None` for names without the prefix, the reserved ones, and
/// `SECMONK_<NAME>` variables without `__` that are not a top-level key: those belong to other tools (the Python
/// project's `SECMONK_HOME`, `SECMONK_DB`, `SECMONK_SSH_PASSWORD`, test hooks) and are ignored, never refused.
/// A variable with `__` is always an override, so a typo in one (`SECMONK_SERVR__LISTEN`) is refused.
pub fn env_key(name: &str) -> Option<String> {
    let rest = name.strip_prefix(ENV_PREFIX)?;
    if RESERVED_ENV.contains(&name) || rest.is_empty() {
        return None;
    }
    let key = rest.to_ascii_lowercase();
    if !key.contains("__") && !TOP_LEVEL_ENV_KEYS.contains(&key.as_str()) {
        return None;
    }
    Some(key.replace("__", "."))
}

/// Split a `--set key=value` argument.
pub fn parse_set(s: &str) -> Result<(String, String), ConfigError> {
    let bad = || ConfigError::Invalid(format!("--set {s:?}: expected section.key=value"));
    let (k, v) = s.split_once('=').ok_or_else(bad)?;
    let k = k.trim();
    if k.is_empty()
        || !k
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Err(bad());
    }
    Ok((k.to_string(), v.to_string()))
}

/// Merge the environment and `--set` overrides into the parsed file (CLI last, so it wins). Every override is
/// checked against the schema on its own, so an unknown key or a wrongly typed value is refused with the name of
/// the variable or flag that carries it.
fn apply_overrides(mut doc: toml::Table, opts: &LoadOptions) -> Result<toml::Table, ConfigError> {
    let mut env: Vec<&(String, String)> = opts.env_overrides.iter().collect();
    env.sort();
    for (name, value) in env {
        if RESERVED_ENV.contains(&name.as_str()) {
            continue;
        }
        let Some(key) = env_key(name) else {
            return Err(ConfigError::Invalid(format!(
                "environment variable {name}: not a {ENV_PREFIX}* override"
            )));
        };
        set_override(
            &mut doc,
            &key,
            value,
            &format!("environment variable {name}"),
            opts,
        )?;
    }
    for arg in &opts.cli_overrides {
        let (key, value) = parse_set(arg)?;
        set_override(&mut doc, &key, &value, &format!("--set {key}"), opts)?;
    }
    Ok(doc)
}

fn nested(parts: &[&str], value: toml::Value) -> toml::Table {
    let mut t = toml::Table::new();
    match parts {
        [last] => {
            t.insert((*last).to_string(), value);
        }
        [first, rest @ ..] => {
            t.insert(
                (*first).to_string(),
                toml::Value::Table(nested(rest, value)),
            );
        }
        [] => {}
    }
    t
}

fn set_override(
    doc: &mut toml::Table,
    key: &str,
    value: &str,
    what: &str,
    opts: &LoadOptions,
) -> Result<(), ConfigError> {
    let parts: Vec<&str> = key.split('.').collect();
    if parts.iter().any(|p| p.is_empty()) {
        return Err(ConfigError::Invalid(format!(
            "{what}: empty key segment in {key:?}"
        )));
    }
    // TOML value if `v = <value>` parses, else the text; a typed value the schema refuses (`3.13` for a string
    // key) falls back to the text.
    let mut candidates = Vec::new();
    if let Ok(t) = toml::from_str::<toml::Table>(&format!("v = {value}"))
        && let Some(v) = t.get("v")
    {
        candidates.push(v.clone());
    }
    if !matches!(candidates.first(), Some(toml::Value::String(_))) {
        candidates.push(toml::Value::String(value.to_string()));
    }
    let is_path = OVERRIDE_PATH_KEYS.contains(&key);
    let mut first_err = None;
    for mut cand in candidates {
        if is_path
            && let toml::Value::String(s) = &cand
            && !s.is_empty()
            && !(key == "uv.path" && s == "auto")
        {
            let abs = resolve_path(s, &opts.cwd, opts.home.as_deref())?;
            cand = toml::Value::String(abs.to_string_lossy().into_owned());
        }
        let probe = toml::Value::Table(nested(&parts, cand.clone()));
        match probe.try_into::<RawConfig>() {
            Ok(_) => {
                insert_nested(doc, &parts, cand, what)?;
                return Ok(());
            }
            Err(e) => {
                first_err.get_or_insert(e.to_string());
            }
        }
    }
    Err(ConfigError::Invalid(format!(
        "{what}: {}",
        first_err.unwrap_or_default().trim()
    )))
}

fn insert_nested(
    doc: &mut toml::Table,
    parts: &[&str],
    value: toml::Value,
    what: &str,
) -> Result<(), ConfigError> {
    let (last, parents) = parts.split_last().expect("non-empty key");
    let mut cur = doc;
    for p in parents {
        let entry = cur
            .entry((*p).to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        cur = entry.as_table_mut().ok_or_else(|| {
            ConfigError::Invalid(format!("{what}: {p} is not a table in the file"))
        })?;
    }
    cur.insert((*last).to_string(), value);
    Ok(())
}

/// Resolve a parsed file: paths against the file's directory, defaults, `data_dir` creation and
/// canonicalization, `{data_dir}` substitution.
pub fn resolve(
    raw: RawConfig,
    origin: ConfigOrigin,
    file: Option<PathBuf>,
    opts: &LoadOptions,
) -> Result<Config, ConfigError> {
    let base = match &file {
        Some(f) => f
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| opts.cwd.clone()),
        None => opts.cwd.clone(),
    };
    let base = if base.is_absolute() {
        base
    } else {
        opts.cwd.join(base)
    };
    let home = opts.home.as_deref();
    let path = |s: &str| resolve_path(s, &base, home);

    let data_dir = match raw.data_dir.as_deref() {
        Some(d) if !d.trim().is_empty() => path(d)?,
        _ => opts
            .user_data_root
            .clone()
            .ok_or(ConfigError::NoUserDir("data"))?
            .join(APP_DIR),
    };
    layout::ensure_private_dir(&data_dir)?;
    let data_dir = canonical(&data_dir)?;
    let opt_path = |v: &Option<String>| v.as_deref().map(path).transpose();
    let moved = MovedDirs {
        tools: opt_path(&raw.paths.tools)?,
        python: opt_path(&raw.paths.python)?,
        venvs: opt_path(&raw.paths.venvs)?,
        uv_cache: opt_path(&raw.paths.uv_cache)?,
        cache: opt_path(&raw.paths.cache)?,
        logs: opt_path(&raw.paths.logs)?,
        db: opt_path(&raw.paths.db)?,
        auth: opt_path(&raw.paths.auth)?,
    };
    let layout = Layout::with_moved(&data_dir, moved.clone());
    let url_text = |p: &Path| strip_verbatim(&p.to_string_lossy()).replace('\\', "/");
    let dd = url_text(&data_dir);
    let db_dir = url_text(&layout.db());
    let subst = |s: &str| s.replace("{data_dir}", &dd).replace("{db_dir}", &db_dir);

    let backend = raw.database.backend.unwrap_or_else(|| "sqlite".into());
    if backend != "sqlite" {
        return Err(ConfigError::Invalid(format!(
            "database backend {backend:?} is not supported yet"
        )));
    }
    let state_url = subst(
        raw.database
            .state
            .as_deref()
            .unwrap_or("sqlite://{db_dir}/state.sqlite3"),
    );
    let mirror_url = subst(
        raw.database
            .mirror
            .as_deref()
            .unwrap_or("sqlite://{db_dir}/mirror.sqlite3"),
    );

    let min_confidence = raw.engine.min_confidence.unwrap_or(0.5);
    if !(0.0..=1.0).contains(&min_confidence) {
        return Err(ConfigError::Invalid(format!(
            "engine.min_confidence {min_confidence} not in 0..1"
        )));
    }
    if let Some(enabled) = &raw.modules.enabled
        && let Some(bad) = enabled.iter().find(|n| !is_slug(n))
    {
        return Err(ConfigError::Invalid(format!(
            "modules.enabled: invalid module name {bad:?}"
        )));
    }
    if let Some(bad) = raw.sources.implementation.keys().find(|n| !is_slug(n)) {
        return Err(ConfigError::Invalid(format!(
            "sources.implementation: invalid source name {bad:?}"
        )));
    }
    for (target, sum) in &raw.uv.sha256 {
        if sum.len() != 64 || !sum.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ConfigError::Invalid(format!(
                "uv.sha256.{target}: not a sha256 hex digest"
            )));
        }
    }
    let uv_path = match raw.uv.path.as_deref() {
        None => None,
        Some("auto") => Some(UvPath::Auto),
        Some(p) if p.trim().is_empty() => {
            return Err(ConfigError::Invalid("uv.path is empty".into()));
        }
        Some(p) => Some(UvPath::File(path(p)?)),
    };
    let server_tls_cert = opt_path(&raw.server.tls_cert)?;
    let server_tls_key = opt_path(&raw.server.tls_key)?;
    if server_tls_cert.is_some() != server_tls_key.is_some() {
        return Err(ConfigError::Invalid(
            "server.tls_cert and server.tls_key must be set together".into(),
        ));
    }
    let server_auth = raw.server.auth.unwrap_or_default();
    if let Some(l) = raw.server.listen.as_deref() {
        if l.trim().is_empty() || !l.contains(':') {
            return Err(ConfigError::Invalid(format!(
                "server.listen {l:?}: expected host:port"
            )));
        }
        if server_auth == AuthMode::Off && !is_loopback_listen(l) {
            return Err(ConfigError::Invalid(format!(
                "server.auth = \"off\" is only allowed on a loopback address, not {l:?}"
            )));
        }
    }
    if let Some(bad) = raw.server.allow_hosts.iter().find(|h| h.trim().is_empty()) {
        return Err(ConfigError::Invalid(format!(
            "server.allow_hosts: invalid host name {bad:?}"
        )));
    }
    let jwt_ttl = raw.auth.jwt_ttl_s.unwrap_or(3600);
    if jwt_ttl == 0 {
        return Err(ConfigError::Invalid("auth.jwt_ttl_s must be > 0".into()));
    }
    let rate = raw.auth.rate_per_minute.unwrap_or(600);
    if rate == 0 {
        return Err(ConfigError::Invalid(
            "auth.rate_per_minute must be > 0".into(),
        ));
    }
    let auth_dir = layout.auth();
    let auth_keys_file = match opt_path(&raw.auth.keys_file)? {
        Some(p) => p,
        None => auth_dir.join("api_keys.toml"),
    };
    let auth_jwt_secret_file = match opt_path(&raw.auth.jwt_secret_file)? {
        Some(p) => p,
        None => auth_dir.join("jwt.key"),
    };
    let node_matcher = raw.node.matcher.unwrap_or_default();
    let upstream_url = raw
        .node
        .upstream
        .url
        .clone()
        .filter(|u| !u.trim().is_empty());
    if let Some(u) = &upstream_url
        && !(u.starts_with("https://") || u.starts_with("http://"))
    {
        return Err(ConfigError::Invalid(format!(
            "node.upstream.url {u:?}: expected an http(s) URL"
        )));
    }
    if upstream_url.is_none() {
        if node_matcher == MatcherMode::Remote {
            return Err(ConfigError::Invalid(
                "node.matcher = \"remote\" requires node.upstream.url".into(),
            ));
        }
        if !raw.node.upstream.sources.is_empty() {
            return Err(ConfigError::Invalid(
                "node.upstream.sources requires node.upstream.url".into(),
            ));
        }
    }
    if let Some(bad) = raw.node.upstream.sources.iter().find(|n| !is_slug(n)) {
        return Err(ConfigError::Invalid(format!(
            "node.upstream.sources: invalid source name {bad:?}"
        )));
    }
    let mut node_serve = raw.node.serve.clone();
    node_serve.sort();
    node_serve.dedup();
    let static_dir = match &opts.env_static {
        Some(s) => path(&s.to_string_lossy())?,
        None => path(
            raw.ui
                .static_dir
                .as_deref()
                .unwrap_or("../src/secmonk/web/static"),
        )?,
    };

    Ok(Config {
        origin,
        file,
        data_dir: data_dir.clone(),
        database_backend: backend,
        state_url,
        mirror_url,
        python_version: raw.python.version.unwrap_or_else(|| "3.13".into()),
        offline: raw.python.offline.unwrap_or(false),
        find_links: raw.python.find_links.as_deref().map(path).transpose()?,
        index_url: raw.python.index_url,
        uv_version: raw.uv.version,
        uv_url: raw.uv.url,
        uv_archive: raw.uv.archive.as_deref().map(path).transpose()?,
        uv_sha256: raw
            .uv
            .sha256
            .into_iter()
            .map(|(k, v)| (k, v.to_ascii_lowercase()))
            .collect(),
        python_project: path(raw.modules.python_project.as_deref().unwrap_or("python"))?,
        modules_enabled: raw
            .modules
            .enabled
            .unwrap_or_else(|| DEFAULT_MODULES.iter().map(|m| (*m).to_owned()).collect()),
        trust: raw.modules.trust.unwrap_or_default(),
        module_pins: raw.modules.pins,
        module_overrides: raw.modules.overrides,
        ui_static_dir: static_dir,
        ui_scheme: raw.ui.scheme.unwrap_or_else(|| "secmonk".into()),
        ui_snapshot: raw.ui.snapshot.as_deref().map(path).transpose()?,
        ui_http_listen: raw.ui.http_listen,
        ui_devtools: raw.ui.devtools.unwrap_or(false),
        min_confidence,
        nvd_api_key_env: raw
            .sources
            .nvd_api_key_env
            .unwrap_or_else(|| "NVD_API_KEY".into()),
        source_impls: raw.sources.implementation,
        log_level: raw.log.level.unwrap_or_else(|| "info".into()),
        log_keep_days: raw.log.keep_days.unwrap_or(7),
        paths: moved,
        uv_path,
        uv_any_version: raw.uv.any_version.unwrap_or(false),
        server_listen: raw.server.listen,
        server_tls_cert,
        server_tls_key,
        server_allow_hosts: raw.server.allow_hosts,
        server_insecure_http: raw.server.insecure_http.unwrap_or(false),
        server_allow_actions: raw.server.allow_actions.unwrap_or(true),
        server_auth,
        server_serve_ui: raw.server.serve_ui.unwrap_or(true),
        auth_keys_file,
        auth_jwt_ttl_s: jwt_ttl,
        auth_jwt_secret_file,
        auth_rate_per_minute: rate,
        node_mirror: raw.node.mirror.unwrap_or(true),
        node_serve,
        node_matcher,
        node_upstream_url: upstream_url,
        node_upstream_api_key_env: raw
            .node
            .upstream
            .api_key_env
            .unwrap_or_else(|| "SECMONK_UPSTREAM_API_KEY".into()),
        node_upstream_ca_cert: opt_path(&raw.node.upstream.ca_cert)?,
        node_upstream_sources: raw.node.upstream.sources,
    })
}

/// Whether a `host:port` listen address is a loopback one (`localhost`, `127.0.0.0/8`, `::1`).
pub fn is_loopback_listen(listen: &str) -> bool {
    let host = listen.rsplit_once(':').map_or(listen, |(h, _)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

impl Config {
    /// The `data_dir` layout.
    pub fn layout(&self) -> Layout {
        Layout::with_moved(&self.data_dir, self.paths.clone())
    }

    /// The implementation chosen for `source`: the `[sources.implementation]` entry, else `default`. The default of
    /// a source with a native importer is that importer's `default_rust` (`secmonk_sources::IMPORTERS`, rust
    /// ADR-0012), `python` otherwise; whether a Rust implementation exists is the host's check.
    pub fn source_impl(&self, source: &str, default: SourceImpl) -> SourceImpl {
        self.source_impls.get(source).copied().unwrap_or(default)
    }

    /// File path of a `sqlite://` URL (`None` for other schemes).
    pub fn sqlite_path(url: &str) -> Option<PathBuf> {
        url.strip_prefix("sqlite://").map(PathBuf::from)
    }
}

/// Canonical absolute path without the Windows extended-length prefix (`\\?\C:\...` from
/// `std::fs::canonicalize`), which breaks `sqlite:` / `file:` URIs and leaks into child environments and working
/// directories; `dunce` keeps the prefix only where a plain path cannot express the path. A no-op elsewhere.
pub fn canonical(p: &Path) -> Result<PathBuf, ConfigError> {
    dunce::canonicalize(p).map_err(|e| ConfigError::io(p, e))
}

/// A path as text without the Windows verbatim prefix (`\\?\C:\x` -> `C:\x`, `\\?\UNC\s\sh` ->
/// `\\s\sh`); other strings are returned unchanged. For paths built elsewhere that reach a URI.
pub fn strip_verbatim(s: &str) -> std::borrow::Cow<'_, str> {
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        std::borrow::Cow::Owned(format!(r"\\{rest}"))
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        std::borrow::Cow::Borrowed(rest)
    } else {
        std::borrow::Cow::Borrowed(s)
    }
}

/// `~` expansion, then relative paths against `base`. The result is absolute, not canonicalized.
pub fn resolve_path(s: &str, base: &Path, home: Option<&Path>) -> Result<PathBuf, ConfigError> {
    let p = if s == "~" || s.starts_with("~/") || s.starts_with("~\\") {
        let home = home.ok_or(ConfigError::NoUserDir("home"))?;
        if s.len() > 2 {
            home.join(&s[2..])
        } else {
            home.to_path_buf()
        }
    } else {
        PathBuf::from(s)
    };
    Ok(if p.is_absolute() { p } else { base.join(p) })
}

fn is_slug(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && matches!(b[0], b'a'..=b'z' | b'0'..=b'9')
        && b.iter()
            .all(|c| matches!(c, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b'-'))
}

/// TOML rendering of the resolved configuration (`config show`): every key with its effective value, paths
/// absolute. Holds no secret: `Config` carries environment variable *names* only.
pub fn effective_toml(c: &Config) -> String {
    use toml::Value as V;
    type T = toml::Table;
    fn put(t: &mut T, k: &str, v: V) {
        t.insert(k.to_string(), v);
    }
    fn s(v: &str) -> V {
        V::String(v.to_string())
    }
    fn p(v: &Path) -> V {
        V::String(v.to_string_lossy().into_owned())
    }
    fn opt(t: &mut T, k: &str, v: Option<V>) {
        if let Some(v) = v {
            t.insert(k.to_string(), v);
        }
    }
    fn list<I: IntoIterator<Item = String>>(it: I) -> V {
        V::Array(it.into_iter().map(V::String).collect())
    }
    fn int(v: u64) -> V {
        V::Integer(i64::try_from(v).unwrap_or(i64::MAX))
    }

    let mut root = T::new();
    put(
        &mut root,
        "config_version",
        V::Integer(i64::from(CONFIG_VERSION)),
    );
    put(&mut root, "data_dir", p(&c.data_dir));

    let mut t = T::new();
    put(&mut t, "backend", s(&c.database_backend));
    put(&mut t, "state", s(&c.state_url));
    put(&mut t, "mirror", s(&c.mirror_url));
    put(&mut root, "database", V::Table(t));

    let mut t = T::new();
    put(&mut t, "version", s(&c.python_version));
    put(&mut t, "offline", V::Boolean(c.offline));
    opt(&mut t, "find_links", c.find_links.as_deref().map(p));
    opt(&mut t, "index_url", c.index_url.as_deref().map(s));
    put(&mut root, "python", V::Table(t));

    let mut t = T::new();
    opt(&mut t, "version", c.uv_version.as_deref().map(s));
    opt(&mut t, "url", c.uv_url.as_deref().map(s));
    opt(&mut t, "archive", c.uv_archive.as_deref().map(p));
    opt(
        &mut t,
        "path",
        c.uv_path.as_ref().map(|u| match u {
            UvPath::Auto => s("auto"),
            UvPath::File(f) => p(f),
        }),
    );
    put(&mut t, "any_version", V::Boolean(c.uv_any_version));
    if !c.uv_sha256.is_empty() {
        let sums: T = c.uv_sha256.iter().map(|(k, v)| (k.clone(), s(v))).collect();
        put(&mut t, "sha256", V::Table(sums));
    }
    put(&mut root, "uv", V::Table(t));

    let mut t = T::new();
    put(&mut t, "python_project", p(&c.python_project));
    put(&mut t, "enabled", list(c.modules_enabled.iter().cloned()));
    put(
        &mut t,
        "trust",
        s(match c.trust {
            TrustMode::Dev => "dev",
            TrustMode::Pinned => "pinned",
        }),
    );
    if !c.module_pins.is_empty() {
        let mut pins = T::new();
        for (name, pin) in &c.module_pins {
            let mut e = T::new();
            opt(&mut e, "lock_sha256", pin.lock_sha256.as_deref().map(s));
            opt(&mut e, "tree_sha256", pin.tree_sha256.as_deref().map(s));
            put(&mut pins, name, V::Table(e));
        }
        put(&mut t, "pins", V::Table(pins));
    }
    for (name, o) in &c.module_overrides {
        let mut e = T::new();
        opt(&mut e, "start", o.start.as_deref().map(s));
        opt(&mut e, "idle_timeout_s", o.idle_timeout_s.map(int));
        opt(
            &mut e,
            "max_restarts",
            o.max_restarts.map(|v| int(v.into())),
        );
        opt(&mut e, "restart_window_s", o.restart_window_s.map(int));
        opt(&mut e, "hello_timeout_s", o.hello_timeout_s.map(int));
        opt(&mut e, "request_timeout_s", o.request_timeout_s.map(int));
        opt(&mut e, "cancel_grace_s", o.cancel_grace_s.map(int));
        opt(&mut e, "max_frame", o.max_frame.map(int));
        opt(
            &mut e,
            "max_inflight",
            o.max_inflight.map(|v| int(v.into())),
        );
        opt(&mut e, "memory_mb", o.memory_mb.map(int));
        put(&mut t, name, V::Table(e));
    }
    put(&mut root, "modules", V::Table(t));

    let mut t = T::new();
    put(&mut t, "static_dir", p(&c.ui_static_dir));
    put(&mut t, "scheme", s(&c.ui_scheme));
    opt(&mut t, "snapshot", c.ui_snapshot.as_deref().map(p));
    opt(&mut t, "http_listen", c.ui_http_listen.as_deref().map(s));
    put(&mut t, "devtools", V::Boolean(c.ui_devtools));
    put(&mut root, "ui", V::Table(t));

    let mut t = T::new();
    put(&mut t, "min_confidence", V::Float(c.min_confidence));
    put(&mut root, "engine", V::Table(t));

    let mut t = T::new();
    put(&mut t, "nvd_api_key_env", s(&c.nvd_api_key_env));
    if !c.source_impls.is_empty() {
        let imp: T = c
            .source_impls
            .iter()
            .map(|(k, v)| {
                let v = match v {
                    SourceImpl::Rust => "rust",
                    SourceImpl::Python => "python",
                };
                (k.clone(), s(v))
            })
            .collect();
        put(&mut t, "implementation", V::Table(imp));
    }
    put(&mut root, "sources", V::Table(t));

    let mut t = T::new();
    put(&mut t, "level", s(&c.log_level));
    put(&mut t, "keep_days", int(c.log_keep_days.into()));
    put(&mut root, "log", V::Table(t));

    let l = c.layout();
    let mut t = T::new();
    put(&mut t, "tools", p(&l.tools()));
    put(&mut t, "python", p(&l.python()));
    put(&mut t, "venvs", p(&l.venvs()));
    put(&mut t, "uv_cache", p(&l.uv_cache()));
    put(&mut t, "cache", p(&l.secmonk_cache()));
    put(&mut t, "logs", p(&l.logs()));
    put(&mut t, "db", p(&l.db()));
    put(&mut t, "auth", p(&l.auth()));
    put(&mut root, "paths", V::Table(t));

    let mut t = T::new();
    opt(&mut t, "listen", c.server_listen.as_deref().map(s));
    opt(&mut t, "tls_cert", c.server_tls_cert.as_deref().map(p));
    opt(&mut t, "tls_key", c.server_tls_key.as_deref().map(p));
    put(
        &mut t,
        "allow_hosts",
        list(c.server_allow_hosts.iter().cloned()),
    );
    put(&mut t, "insecure_http", V::Boolean(c.server_insecure_http));
    put(&mut t, "allow_actions", V::Boolean(c.server_allow_actions));
    put(&mut t, "auth", s(c.server_auth.as_str()));
    put(&mut t, "serve_ui", V::Boolean(c.server_serve_ui));
    put(&mut root, "server", V::Table(t));

    let mut t = T::new();
    put(&mut t, "keys_file", p(&c.auth_keys_file));
    put(&mut t, "jwt_ttl_s", int(c.auth_jwt_ttl_s));
    put(&mut t, "jwt_secret_file", p(&c.auth_jwt_secret_file));
    put(
        &mut t,
        "rate_per_minute",
        int(c.auth_rate_per_minute.into()),
    );
    put(&mut root, "auth", V::Table(t));

    let mut t = T::new();
    put(&mut t, "mirror", V::Boolean(c.node_mirror));
    put(
        &mut t,
        "serve",
        list(c.node_serve.iter().map(|x| x.as_str().to_string())),
    );
    put(&mut t, "matcher", s(c.node_matcher.as_str()));
    let mut u = T::new();
    opt(&mut u, "url", c.node_upstream_url.as_deref().map(s));
    put(&mut u, "api_key_env", s(&c.node_upstream_api_key_env));
    opt(&mut u, "ca_cert", c.node_upstream_ca_cert.as_deref().map(p));
    put(
        &mut u,
        "sources",
        list(c.node_upstream_sources.iter().cloned()),
    );
    put(&mut t, "upstream", V::Table(u));
    put(&mut root, "node", V::Table(t));

    let header = format!(
        "# effective configuration (origin: {:?}{})\n",
        c.origin,
        c.file
            .as_ref()
            .map(|f| format!(", file: {}", f.display()))
            .unwrap_or_default()
    );
    header + &toml::to_string(&root).unwrap_or_default()
}
