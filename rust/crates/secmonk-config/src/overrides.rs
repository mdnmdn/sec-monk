//! Environment and `--set` overrides merged into the parsed file, and the `config show` rendering.

use std::path::Path;

use crate::{
    CONFIG_VERSION, Config, ConfigError, LoadOptions, RawConfig, SourceImpl, TrustMode, UvPath,
    resolve_path,
};

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
pub(crate) fn apply_overrides(
    mut doc: toml::Table,
    opts: &LoadOptions,
) -> Result<toml::Table, ConfigError> {
    // application defaults first, only where the file left the key unset (the file and the overrides win)
    for arg in &opts.app_defaults {
        let (key, value) = parse_set(arg)?;
        if !has_key(&doc, &key) {
            set_override(&mut doc, &key, &value, &format!("app default {key}"), opts)?;
        }
    }
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

/// A `section.key=value` entry (for `--set` or [`crate::LoadOptions::app_defaults`]) whose value is `path` as a
/// TOML string: quoted and escaped, so Windows backslashes and non-ASCII names survive the TOML parse.
pub fn path_setting(key: &str, path: &std::path::Path) -> String {
    let value = toml::Value::String(path.to_string_lossy().into_owned());
    format!("{key}={value}")
}

/// Whether the dotted `key` is set in `doc`.
fn has_key(doc: &toml::Table, key: &str) -> bool {
    let mut t = doc;
    let parts: Vec<&str> = key.split('.').collect();
    for (i, part) in parts.iter().enumerate() {
        match t.get(*part) {
            None => return false,
            Some(toml::Value::Table(inner)) if i + 1 < parts.len() => t = inner,
            Some(_) => return i + 1 == parts.len(),
        }
    }
    false
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
    put(&mut t, "editable", toml::Value::Boolean(c.modules_editable));
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
    put(
        &mut t,
        "trusted_proxies",
        list(c.server_trusted_proxies.iter().cloned()),
    );
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
