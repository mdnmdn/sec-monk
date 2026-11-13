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
mod overrides;
mod sections;

pub use layout::{Layout, MovedDirs};
pub use lookup::{ConfigOrigin, Located, MAX_CONFIG_BYTES, check_owner, locate, read_config};
pub use overrides::{ENV_PREFIX, RESERVED_ENV, effective_toml, env_key, parse_set, path_setting};
pub use sections::{
    AuthMode, AuthSection, MatcherMode, NodeSection, NodeService, PathsSection, ServerSection,
    UpstreamSection,
};

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
    /// Install the modules project editable (dev mode only; default true). A bundled app sets it false: its
    /// project lives in the read-only install directory and is copied into the venv instead.
    pub editable: Option<bool>,
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
    /// `[modules] editable` (default true): with `trust = "dev"`, install the project editable.
    pub modules_editable: bool,
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
    /// `[server] trusted_proxies` (IPs or CIDRs, validated syntactically; as written, trimmed).
    pub server_trusted_proxies: Vec<String>,
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
    /// Defaults of the running application (`section.key=value`, same syntax as `--set`), applied **below** the
    /// file: a key the file (or an override) sets wins. The desktop app's release build uses it to point
    /// `[modules] python_project` at its bundled copy. Empty for `from_env`.
    pub app_defaults: Vec<String>,
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
            app_defaults: Vec::new(),
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
    let table = overrides::apply_overrides(table, opts)?;
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
    let server_trusted_proxies: Vec<String> = raw
        .server
        .trusted_proxies
        .iter()
        .map(|p| p.trim().to_owned())
        .collect();
    if let Some(bad) = server_trusted_proxies.iter().find(|p| !is_ip_or_cidr(p)) {
        return Err(ConfigError::Invalid(format!(
            "server.trusted_proxies: {bad:?} is not an IP address or CIDR (e.g. \"10.0.0.1\", \"10.0.0.0/8\")"
        )));
    }
    if !raw.node.serve.is_empty() && server_auth == AuthMode::Off {
        return Err(ConfigError::Invalid(
            "server.auth = \"off\" cannot be combined with node.serve: the node API always needs authentication \
             (use \"auto\" or \"required\")"
                .into(),
        ));
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
        modules_editable: raw.modules.editable.unwrap_or(true),
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
        server_trusted_proxies,
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

/// Whether a socket address is a loopback one (`127.0.0.0/8`, `::1`, and IPv4-mapped IPv6 such as
/// `::ffff:127.0.0.1`). The one definition of "loopback" for the exposure rules.
pub fn is_loopback_addr(addr: &std::net::SocketAddr) -> bool {
    is_loopback_ip(addr.ip())
}

/// [`is_loopback_addr`] for a bare IP address.
pub fn is_loopback_ip(ip: std::net::IpAddr) -> bool {
    ip.to_canonical().is_loopback()
}

/// Whether a `host:port` listen address is a loopback one (`localhost`, or an address per [`is_loopback_addr`]).
pub fn is_loopback_listen(listen: &str) -> bool {
    let host = listen.rsplit_once(':').map_or(listen, |(h, _)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<std::net::IpAddr>().is_ok_and(is_loopback_ip)
}

/// An IP address or `IP/prefix` (prefix within the address family's width).
pub fn is_ip_or_cidr(s: &str) -> bool {
    match s.split_once('/') {
        None => s.parse::<std::net::IpAddr>().is_ok(),
        Some((ip, prefix)) => match (ip.parse::<std::net::IpAddr>(), prefix.parse::<u8>()) {
            (Ok(std::net::IpAddr::V4(_)), Ok(p)) => p <= 32,
            (Ok(std::net::IpAddr::V6(_)), Ok(p)) => p <= 128,
            _ => false,
        },
    }
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
