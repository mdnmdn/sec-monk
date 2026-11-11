//! Environments of child processes: the uv steps (everything inside `data_dir`, sentinel HOME) and the module
//! processes (the real user context, `SECMONK_*` inside `data_dir`, no secrets). Both start from
//! `env_clear()`; these maps are the complete environment.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;

use secmonk_config::Layout;

/// Which uv step an environment is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UvStep {
    /// `uv python install`: interpreter downloads allowed (unless offline).
    PythonInstall,
    /// Any other step (`uv sync`, `uv python find`): `UV_PYTHON_DOWNLOADS=never`.
    Other,
}

/// Inputs of [`uv_env`] that are not paths.
#[derive(Debug, Clone, Default)]
pub struct UvEnvOptions {
    /// `[python] version`.
    pub python_version: String,
    /// Offline mode.
    pub offline: bool,
    /// `[python] index_url`.
    pub index_url: Option<String>,
    /// `[python] find_links` (absolute).
    pub find_links: Option<std::path::PathBuf>,
}

/// Variables passed through to uv steps when set (corporate networks).
pub const UV_PASSTHROUGH: [&str; 12] = [
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
    "all_proxy",
    "SystemRoot",
    "SYSTEMROOT",
];

/// Every variable a module process may receive (the union of [`MODULE_BASE`], [`MODULE_TARGET_VARS`] and
/// [`MODULE_NETWORK_VARS`]; which ones a module gets depends on its capabilities, [`module_env_for`]).
pub const MODULE_PASSTHROUGH: [&str; 40] = [
    "HOME",
    "USERPROFILE",
    "USER",
    "LOGNAME",
    "USERNAME",
    "LANG",
    "PATH",
    "SSH_AUTH_SOCK",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
    "KUBECONFIG",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
    "all_proxy",
    "XDG_RUNTIME_DIR",
    "SystemRoot",
    "SYSTEMROOT",
    "windir",
    "COMSPEC",
    "PATHEXT",
    "APPDATA",
    "LOCALAPPDATA",
    "ProgramData",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "COMPUTERNAME",
    "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS",
];

/// The minimal system `PATH` of uv steps.
pub fn minimal_path(get: &dyn Fn(&str) -> Option<OsString>) -> OsString {
    if cfg!(windows) {
        let root = get("SystemRoot").unwrap_or_else(|| OsString::from(r"C:\Windows"));
        let r = root.to_string_lossy();
        OsString::from(format!(r"{r}\System32;{r};{r}\System32\Wbem"))
    } else {
        OsString::from("/usr/bin:/bin:/usr/sbin:/sbin")
    }
}

fn s(p: &Path) -> OsString {
    p.as_os_str().to_os_string()
}

/// The sentinel directories (`uv-home/...`) of uv steps; created before a step runs, must stay empty.
pub fn sentinel_dirs(layout: &Layout) -> Vec<(&'static str, std::path::PathBuf)> {
    let h = layout.uv_home();
    vec![
        ("HOME", h.join("home")),
        ("USERPROFILE", h.join("home")),
        ("XDG_CACHE_HOME", h.join("xdg-cache")),
        ("XDG_DATA_HOME", h.join("xdg-data")),
        ("XDG_CONFIG_HOME", h.join("xdg-config")),
        ("XDG_STATE_HOME", h.join("xdg-state")),
        ("XDG_BIN_HOME", h.join("xdg-bin")),
        ("APPDATA", h.join("appdata")),
        ("LOCALAPPDATA", h.join("localappdata")),
    ]
}

/// The complete environment of a uv step (configuration.md, "Every uv step runs with env_clear() and exactly
/// these variables"). `venv` sets `UV_PROJECT_ENVIRONMENT`. `get` reads the host environment (pass-through
/// variables only).
pub fn uv_env(
    layout: &Layout,
    opts: &UvEnvOptions,
    step: UvStep,
    venv: Option<&Path>,
    get: &dyn Fn(&str) -> Option<OsString>,
) -> BTreeMap<String, OsString> {
    let mut e: BTreeMap<String, OsString> = BTreeMap::new();
    let mut set = |k: &str, v: OsString| {
        e.insert(k.to_string(), v);
    };
    set("UV_CACHE_DIR", s(&layout.uv_cache()));
    set("UV_PYTHON_INSTALL_DIR", s(&layout.python()));
    set("UV_PYTHON_BIN_DIR", s(&layout.python_bin()));
    set("UV_PYTHON_INSTALL_BIN", "0".into());
    set("UV_PYTHON_INSTALL_REGISTRY", "0".into());
    set("UV_TOOL_DIR", s(&layout.uv_tools()));
    set("UV_TOOL_BIN_DIR", s(&layout.uv_tools_bin()));
    if let Some(v) = venv {
        set("UV_PROJECT_ENVIRONMENT", s(v));
    }
    set("UV_NO_CONFIG", "1".into());
    set("UV_NO_ENV_FILE", "1".into());
    set("UV_NO_PROGRESS", "1".into());
    set("UV_PYTHON_PREFERENCE", "only-managed".into());
    let downloads = if step == UvStep::PythonInstall && !opts.offline {
        "automatic"
    } else {
        "never"
    };
    set("UV_PYTHON_DOWNLOADS", downloads.into());
    set("UV_PYTHON", opts.python_version.clone().into());
    set("UV_LINK_MODE", "copy".into());
    if opts.offline {
        set("UV_OFFLINE", "1".into());
    }
    if let Some(u) = &opts.index_url {
        set("UV_INDEX_URL", u.into());
    }
    if let Some(f) = &opts.find_links {
        set("UV_FIND_LINKS", s(f));
    }
    set("PYTHONPYCACHEPREFIX", s(&layout.pycache()));
    set(
        "PIP_CONFIG_FILE",
        if cfg!(windows) {
            "NUL".into()
        } else {
            "/dev/null".into()
        },
    );
    for (k, dir) in sentinel_dirs(layout) {
        set(k, s(&dir));
    }
    for k in ["TMPDIR", "TEMP", "TMP"] {
        set(k, s(&layout.tmp()));
    }
    set("PATH", minimal_path(get));
    for k in UV_PASSTHROUGH {
        if let Some(v) = get(k) {
            set(k, v);
        }
    }
    e
}

/// Passed to every module: user context, locale, `PATH`, Windows system variables.
pub const MODULE_BASE: [&str; 22] = [
    "HOME",
    "USERPROFILE",
    "USER",
    "LOGNAME",
    "USERNAME",
    "LANG",
    "PATH",
    "XDG_RUNTIME_DIR",
    "SystemRoot",
    "SYSTEMROOT",
    "windir",
    "COMSPEC",
    "PATHEXT",
    "APPDATA",
    "LOCALAPPDATA",
    "ProgramData",
    "ProgramFiles",
    "ProgramFiles(x86)",
    "ProgramW6432",
    "COMPUTERNAME",
    "PROCESSOR_ARCHITECTURE",
    "NUMBER_OF_PROCESSORS",
];

/// Credentials and endpoints of remote targets (ssh agent, Docker engines, Kubernetes): only modules declaring
/// `read-target` (py-probe).
pub const MODULE_TARGET_VARS: [&str; 7] = [
    "SSH_AUTH_SOCK",
    "DOCKER_HOST",
    "DOCKER_CONTEXT",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
    "KUBECONFIG",
];

/// Proxy and CA variables: only modules declaring `network` (py-sources, py-probe for registries).
pub const MODULE_NETWORK_VARS: [&str; 11] = [
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "HTTPS_PROXY",
    "HTTP_PROXY",
    "NO_PROXY",
    "ALL_PROXY",
    "https_proxy",
    "http_proxy",
    "no_proxy",
    "all_proxy",
];

/// The capability (manifest wire string) that unlocks [`MODULE_TARGET_VARS`].
pub const CAP_TARGET_VARS: &str = "read-target";
/// The capability that unlocks [`MODULE_NETWORK_VARS`].
pub const CAP_NETWORK_VARS: &str = "network";

/// The complete environment of a module process with every pass-through group (a module declaring all
/// capabilities). Prefer [`module_env_for`] with the manifest's capabilities.
pub fn module_env(
    layout: &Layout,
    get: &dyn Fn(&str) -> Option<OsString>,
) -> BTreeMap<String, OsString> {
    module_env_for(layout, &[CAP_TARGET_VARS, CAP_NETWORK_VARS], get)
}

/// The complete environment of a module process (configuration.md, "Module process environment"), scoped by the
/// manifest `capabilities` (wire strings): [`MODULE_BASE`] always, [`MODULE_TARGET_VARS`] with `read-target`,
/// [`MODULE_NETWORK_VARS`] with `network`, then the `SECMONK_*` / temp / pycache variables inside `data_dir`.
pub fn module_env_for(
    layout: &Layout,
    capabilities: &[&str],
    get: &dyn Fn(&str) -> Option<OsString>,
) -> BTreeMap<String, OsString> {
    let mut e: BTreeMap<String, OsString> = BTreeMap::new();
    let mut groups: Vec<&[&str]> = vec![&MODULE_BASE];
    if capabilities.contains(&CAP_TARGET_VARS) {
        groups.push(&MODULE_TARGET_VARS);
    }
    if capabilities.contains(&CAP_NETWORK_VARS) {
        groups.push(&MODULE_NETWORK_VARS);
    }
    for k in groups.into_iter().flatten() {
        if let Some(v) = get(k) {
            e.insert(k.to_string(), v);
        }
    }
    for k in [
        "LC_ALL",
        "LC_CTYPE",
        "LC_MESSAGES",
        "LC_COLLATE",
        "LC_NUMERIC",
        "LC_TIME",
        "LC_MONETARY",
    ] {
        if let Some(v) = get(k) {
            e.insert(k.to_string(), v);
        }
    }
    e.insert("SECMONK_HOME".into(), s(&layout.python_home()));
    e.insert("SECMONK_CACHE".into(), s(&layout.secmonk_cache()));
    // A conformance test asserts this file never appears: modules must not open the Python version's DB.
    e.insert(
        "SECMONK_DB".into(),
        s(&layout.python_home().join("forbidden.db")),
    );
    for k in ["TMPDIR", "TEMP", "TMP"] {
        e.insert(k.into(), s(&layout.tmp()));
    }
    e.insert("PYTHONPYCACHEPREFIX".into(), s(&layout.pycache()));
    e.insert("PYTHONUTF8".into(), "1".into());
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_env(k: &str) -> Option<OsString> {
        match k {
            "HOME" => Some("/home/u".into()),
            "HTTPS_PROXY" => Some("http://proxy.invalid:3128".into()),
            "NVD_API_KEY" => Some("k1".into()),
            "UV_CACHE_DIR" => Some("/other".into()),
            "PYTHONPATH" => Some("/other".into()),
            "SSH_AUTH_SOCK" => Some("/run/a.sock".into()),
            "LC_ALL" => Some("C.UTF-8".into()),
            _ => None,
        }
    }

    #[test]
    fn uv_env_is_contained() {
        let layout = Layout::new(Path::new("/data/sec-monk"));
        let opts = UvEnvOptions {
            python_version: "3.13".into(),
            ..Default::default()
        };
        let venv = layout.venv("secmonk-modules");
        let e = uv_env(&layout, &opts, UvStep::Other, Some(&venv), &fake_env);
        // every path variable points inside data_dir
        for (k, v) in &e {
            let v = v.to_string_lossy();
            if v.starts_with('/') && !matches!(k.as_str(), "PIP_CONFIG_FILE" | "PATH") {
                assert!(v.starts_with("/data/sec-monk/"), "{k}={v}");
            }
        }
        assert_eq!(e["HOME"], "/data/sec-monk/uv-home/home");
        assert_eq!(e["TMPDIR"], "/data/sec-monk/tmp");
        assert_eq!(e["UV_PYTHON_DOWNLOADS"], "never");
        assert_eq!(e["UV_PYTHON_PREFERENCE"], "only-managed");
        assert_eq!(e["UV_NO_CONFIG"], "1");
        assert_eq!(
            e["UV_PROJECT_ENVIRONMENT"],
            "/data/sec-monk/venvs/secmonk-modules"
        );
        assert_eq!(e["HTTPS_PROXY"], "http://proxy.invalid:3128");
        assert!(
            !e.contains_key("UV_MANAGED_PYTHON"),
            "conflicts with UV_PYTHON_PREFERENCE"
        );
        assert!(
            !e.contains_key("NVD_API_KEY")
                && !e.contains_key("PYTHONPATH")
                && !e.contains_key("UV_OFFLINE")
        );
        let install = uv_env(&layout, &opts, UvStep::PythonInstall, None, &fake_env);
        assert_eq!(install["UV_PYTHON_DOWNLOADS"], "automatic");
        assert!(!install.contains_key("UV_PROJECT_ENVIRONMENT"));
        let off = UvEnvOptions {
            offline: true,
            ..opts
        };
        let e = uv_env(&layout, &off, UvStep::PythonInstall, None, &fake_env);
        assert_eq!(
            (
                e["UV_PYTHON_DOWNLOADS"].as_os_str(),
                e["UV_OFFLINE"].as_os_str()
            ),
            ("never".as_ref(), "1".as_ref())
        );
    }
}
