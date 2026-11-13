//! The `[paths]`, `[server]`, `[auth]` and `[node]` sections of the file as written (before resolution).

use serde::Deserialize;

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
    /// Reverse proxies (IPs or CIDRs) whose `X-Forwarded-For` is trusted for the client address.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
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
