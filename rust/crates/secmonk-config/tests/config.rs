//! Lookup order, ownership check, path resolution, layout, the dev config of the repo.

use std::path::{Path, PathBuf};

use secmonk_config::*;

fn write(p: &Path, text: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn opts(root: &Path) -> LoadOptions {
    LoadOptions {
        cwd: root.join("cwd"),
        home: Some(root.join("home")),
        user_config_root: Some(root.join("cfgroot")),
        user_data_root: Some(root.join("dataroot")),
        ..Default::default()
    }
}

#[test]
fn lookup_order() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    std::fs::create_dir_all(r.join("cwd")).unwrap();
    let mut o = opts(r);
    assert_eq!(locate(&o).unwrap(), None);

    write(&r.join("cfgroot/sec-monk/sec-monk.toml"), "");
    assert_eq!(locate(&o).unwrap().unwrap().origin, ConfigOrigin::User);

    write(&r.join("cwd/sec-monk.toml"), "");
    assert_eq!(locate(&o).unwrap().unwrap().origin, ConfigOrigin::Cwd);

    write(&r.join("env.toml"), "");
    o.env_config = Some(r.join("env.toml").into_os_string());
    assert_eq!(locate(&o).unwrap().unwrap().origin, ConfigOrigin::Env);

    write(&r.join("flag.toml"), "");
    o.cli_config = Some(r.join("flag.toml"));
    let l = locate(&o).unwrap().unwrap();
    assert_eq!(
        (l.origin, l.path),
        (ConfigOrigin::Flag, r.join("flag.toml"))
    );

    o.cli_config = Some(r.join("missing.toml"));
    assert!(matches!(locate(&o), Err(ConfigError::NotFound(_))));
    o.cli_config = None;
    o.env_config = Some(r.join("missing.toml").into_os_string());
    assert!(matches!(locate(&o), Err(ConfigError::NotFound(_))));
}

#[cfg(unix)]
#[test]
fn ownership_check_refuses_writable_files() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("sec-monk.toml");
    write(&f, "");
    assert!(check_owner(&f).is_ok());
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o620)).unwrap();
    assert!(matches!(
        check_owner(&f),
        Err(ConfigError::Untrusted { .. })
    ));
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o602)).unwrap();
    assert!(matches!(
        check_owner(&f),
        Err(ConfigError::Untrusted { .. })
    ));
    assert!(matches!(
        check_owner(d.path()),
        Err(ConfigError::Untrusted { .. })
    ));
    // a group-writable ./sec-monk.toml is refused by the lookup itself
    let mut o = opts(d.path());
    o.cwd = d.path().to_path_buf();
    assert!(matches!(locate(&o), Err(ConfigError::Untrusted { .. })));
}

#[test]
fn paths_resolve_against_the_config_file() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    std::fs::create_dir_all(r.join("cwd")).unwrap();
    write(
        &r.join("conf/sec-monk.toml"),
        r#"
config_version = 1
data_dir = "_data"
[database]
state = "sqlite://{data_dir}/db/state.sqlite3"
[uv]
archive = "~/uv.tar.gz"
[modules]
python_project = "python"
enabled = ["py-probe"]
[modules.py-sources]
request_timeout_s = 21600
"#,
    );
    let mut o = opts(r);
    o.cli_config = Some(r.join("conf/sec-monk.toml"));
    let c = load(&o).unwrap();
    let dd = r.join("conf/_data").canonicalize().unwrap();
    assert_eq!(c.data_dir, dd);
    assert!(c.data_dir.is_absolute());
    assert_eq!(
        c.state_url,
        format!(
            "sqlite://{}/db/state.sqlite3",
            dd.to_string_lossy().replace('\\', "/")
        )
    );
    assert!(c.mirror_url.ends_with("/db/mirror.sqlite3"));
    assert_eq!(c.uv_archive, Some(r.join("home/uv.tar.gz")));
    assert_eq!(c.python_project, r.join("conf/python"));
    assert_eq!(
        c.module_overrides["py-sources"].request_timeout_s,
        Some(21600)
    );
    assert_eq!(c.ui_static_dir, r.join("conf/../src/secmonk/web/static"));
    c.layout().create().unwrap();
    assert!(c.layout().uv_home().is_dir());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(c.layout().tmp())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);
    }
}

#[test]
fn defaults_without_a_file() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("cwd")).unwrap();
    let c = load(&opts(d.path())).unwrap();
    assert_eq!(c.origin, ConfigOrigin::Defaults);
    assert_eq!(
        c.data_dir,
        d.path().join("dataroot/sec-monk").canonicalize().unwrap()
    );
    assert_eq!(c.python_version, "3.13");
    assert_eq!(c.min_confidence, 0.5);
    // no `[modules] enabled`: the four shipped modules (the shipped manifests are the source of truth)
    assert_eq!(
        c.modules_enabled,
        ["py-engine", "py-procmon", "py-probe", "py-sources"]
    );
    for n in &c.modules_enabled {
        assert!(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("../../python/modules/{n}.toml"))
                .exists()
        );
    }
}

#[test]
fn explicit_enabled_list_replaces_the_default() {
    let p = PathBuf::from("x.toml");
    let none = parse("config_version = 1\n[modules]\nenabled = []\n", &p).unwrap();
    assert_eq!(none.modules.enabled, Some(vec![]));
    let one = parse(
        "config_version = 1\n[modules]\nenabled = [\"py-probe\"]\n",
        &p,
    )
    .unwrap();
    assert_eq!(one.modules.enabled, Some(vec!["py-probe".to_string()]));
    let absent = parse("config_version = 1\n", &p).unwrap();
    assert_eq!(absent.modules.enabled, None); // None -> DEFAULT_MODULES in `load`
}

#[test]
fn bad_files_are_refused() {
    let p = PathBuf::from("x.toml");
    assert!(parse("config_version = 2", &p).is_err());
    assert!(parse("data-dir = \"x\"", &p).is_err());
    assert!(parse("[ui]\nunknown = 1", &p).is_err());
    assert!(parse("[modules]\nenable = [\"x\"]", &p).is_err());
    assert!(parse("[modules.py-probe]\ncapabilities = []", &p).is_err());
    let raw = parse("[uv.sha256]\nx = \"nothex\"", &p).unwrap();
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("cwd")).unwrap();
    assert!(resolve(raw, ConfigOrigin::Flag, None, &opts(d.path())).is_err());
}

#[cfg(unix)]
#[test]
fn symlinked_data_dir_is_refused() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir(d.path().join("real")).unwrap();
    std::os::unix::fs::symlink(d.path().join("real"), d.path().join("link")).unwrap();
    assert!(layout::ensure_private_dir(&d.path().join("link")).is_err());
}

#[test]
fn repo_dev_config_parses() {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../sec-monk.toml");
    let raw = parse(&std::fs::read_to_string(&p).unwrap(), &p).unwrap();
    assert_eq!(raw.data_dir.as_deref(), Some("_data"));
    assert_eq!(raw.uv.sha256.len(), 8);
    assert_eq!(raw.modules.enabled.unwrap().len(), 4);
}

#[test]
fn cwd_config_found_in_every_build() {
    // decision 2026-11-11: ./sec-monk.toml is looked up in release builds too (checks still apply)
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    write(&r.join("cwd/sec-monk.toml"), "");
    write(&r.join("cfgroot/sec-monk/sec-monk.toml"), "");
    let o = opts(r);
    // release-style: no SECMONK_DEV, nothing but the default options; cwd still wins over the user file
    assert_eq!(locate(&o).unwrap().unwrap().origin, ConfigOrigin::Cwd);
}

#[cfg(unix)]
#[test]
fn symlinked_or_special_config_is_refused() {
    // regression: the check followed symlinks and read the file again by path (TOCTOU)
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    write(&r.join("real.toml"), "data_dir = \"x\"");
    std::fs::create_dir_all(r.join("cfgroot/sec-monk")).unwrap();
    std::os::unix::fs::symlink(
        r.join("real.toml"),
        r.join("cfgroot/sec-monk/sec-monk.toml"),
    )
    .unwrap();
    let o = opts(r);
    let err = locate(&o).unwrap_err();
    assert!(
        matches!(&err, ConfigError::Untrusted { reason, .. } if reason.contains("symlink")),
        "{err}"
    );
    // the read itself refuses a symlink too (a swap after locate)
    let l = Located {
        path: r.join("cfgroot/sec-monk/sec-monk.toml"),
        origin: ConfigOrigin::User,
    };
    assert!(matches!(
        read_config(&l),
        Err(ConfigError::Untrusted { .. })
    ));
    // --config may name a symlink: the user chose it explicitly
    let l = Located {
        origin: ConfigOrigin::Flag,
        ..l
    };
    assert_eq!(read_config(&l).unwrap(), "data_dir = \"x\"");
    // a FIFO is refused without blocking
    let fifo = r.join("fifo.toml");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    assert!(matches!(
        check_owner(&fifo),
        Err(ConfigError::Untrusted { .. })
    ));
}

#[cfg(unix)]
#[test]
fn writable_config_directory_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("shared");
    let f = dir.join("sec-monk.toml");
    write(&f, "");
    assert!(check_owner(&f).is_ok());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o775)).unwrap();
    let err = check_owner(&f).unwrap_err();
    assert!(
        matches!(&err, ConfigError::Untrusted { reason, .. } if reason.contains("directory")),
        "{err}"
    );
    // sticky (like /tmp): others cannot replace a file they do not own
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o1777)).unwrap();
    assert!(check_owner(&f).is_ok());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn windows_verbatim_prefix_is_stripped() {
    // regression: canonicalize() on Windows yields \\?\C:\..., which broke the sqlite:// and file: URIs
    assert_eq!(
        strip_verbatim(r"\\?\C:\Users\u\AppData\Local\sec-monk"),
        r"C:\Users\u\AppData\Local\sec-monk"
    );
    assert_eq!(
        strip_verbatim(r"\\?\UNC\server\share\sec-monk"),
        r"\\server\share\sec-monk"
    );
    assert_eq!(strip_verbatim("/data/sec-monk"), "/data/sec-monk");
    // the resolved data_dir never carries the prefix (a no-op off Windows, dunce on Windows)
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("cwd")).unwrap();
    let c = load(&opts(d.path())).unwrap();
    assert!(!c.data_dir.to_string_lossy().starts_with(r"\\?\"));
    assert!(!c.state_url.contains('?') && !c.state_url.contains('\\'));
}

#[test]
fn source_implementations_default_and_override() {
    let d = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(d.path().join("cwd")).unwrap();
    let p = PathBuf::from("x.toml");
    let load = |text: &str| {
        let raw = parse(text, &p).unwrap();
        resolve(raw, ConfigOrigin::Flag, None, &opts(d.path()))
    };
    let c = load("config_version = 1\n").unwrap();
    // unset: the default the caller passes (the importer's `default_rust`, secmonk_sources::IMPORTERS)
    assert_eq!(c.source_impl("kev", SourceImpl::Rust), SourceImpl::Rust);
    assert_eq!(c.source_impl("osv", SourceImpl::Python), SourceImpl::Python);
    let c = load("[sources.implementation]\nkev = \"python\"\nosv = \"rust\"\n").unwrap();
    assert_eq!(c.source_impl("kev", SourceImpl::Rust), SourceImpl::Python);
    assert_eq!(c.source_impl("osv", SourceImpl::Python), SourceImpl::Rust); // the host refuses it: no Rust osv
    assert!(parse("[sources.implementation]\nkev = \"go\"\n", &p).is_err());
    assert!(parse("[sources]\nimplementations = {}\n", &p).is_err());
    assert!(load("[sources.implementation]\n\"Bad Name\" = \"rust\"\n").is_err());
}

fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect()
}

fn base(d: &Path) -> LoadOptions {
    std::fs::create_dir_all(d.join("cwd")).unwrap();
    opts(d)
}

#[test]
fn env_names_map_to_dotted_keys() {
    assert_eq!(env_key("SECMONK_DATA_DIR").as_deref(), Some("data_dir"));
    assert_eq!(
        env_key("SECMONK_SERVER__LISTEN").as_deref(),
        Some("server.listen")
    );
    assert_eq!(
        env_key("SECMONK_NODE__UPSTREAM__URL").as_deref(),
        Some("node.upstream.url")
    );
    for r in RESERVED_ENV {
        assert_eq!(env_key(r), None, "{r}");
    }
    assert_eq!(env_key("HOME"), None);
    // other tools' SECMONK_ variables (Python project, test hooks) are not overrides
    for other in [
        "SECMONK_HOME",
        "SECMONK_DB",
        "SECMONK_SSH_PASSWORD",
        "SECMONK_TEST_OSV_HOOK",
    ] {
        assert_eq!(env_key(other), None, "{other}");
    }
    assert_eq!(parse_set("a.b=c=d").unwrap(), ("a.b".into(), "c=d".into()));
    assert!(parse_set("novalue").is_err());
    assert!(parse_set("=x").is_err());
    assert!(parse_set("a b=1").is_err());
}

#[test]
fn override_values_are_typed_or_strings() {
    let d = tempfile::tempdir().unwrap();
    let mut o = base(d.path());
    o.cli_overrides = vec![
        "python.offline=true".into(),
        "engine.min_confidence=0.8".into(),
        "modules.enabled=[\"py-probe\"]".into(),
        // a number-looking value for a string key stays text
        "python.version=3.12".into(),
        "log.level=debug".into(),
        "log.keep_days=3".into(),
    ];
    let c = load(&o).unwrap();
    assert!(c.offline);
    assert_eq!(c.min_confidence, 0.8);
    assert_eq!(c.modules_enabled, ["py-probe"]);
    assert_eq!(c.python_version, "3.12");
    assert_eq!(c.log_level, "debug");
    assert_eq!(c.log_keep_days, 3);
}

#[test]
fn precedence_cli_over_env_over_file_over_defaults() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    write(
        &r.join("conf/sec-monk.toml"),
        "data_dir = \"_data\"\n[log]\nlevel = \"warn\"\nkeep_days = 9\n[engine]\nmin_confidence = 0.1\n",
    );
    let mut o = base(r);
    o.cli_config = Some(r.join("conf/sec-monk.toml"));
    let c = load(&o).unwrap();
    assert_eq!((c.log_level.as_str(), c.log_keep_days), ("warn", 9));
    o.env_overrides = env(&[
        ("SECMONK_LOG__LEVEL", "error"),
        ("SECMONK_LOG__KEEP_DAYS", "5"),
    ]);
    let c = load(&o).unwrap();
    assert_eq!((c.log_level.as_str(), c.log_keep_days), ("error", 5));
    assert_eq!(c.min_confidence, 0.1, "untouched file value stays");
    o.cli_overrides = vec!["log.level=trace".into()];
    let c = load(&o).unwrap();
    assert_eq!((c.log_level.as_str(), c.log_keep_days), ("trace", 5));
}

#[test]
fn overrides_apply_without_a_file_too() {
    let d = tempfile::tempdir().unwrap();
    let mut o = base(d.path());
    o.env_overrides = env(&[("SECMONK_SERVER__LISTEN", "127.0.0.1:9000")]);
    let c = load(&o).unwrap();
    assert_eq!(c.origin, ConfigOrigin::Defaults);
    assert_eq!(c.server_listen.as_deref(), Some("127.0.0.1:9000"));
}

#[test]
fn unknown_or_mistyped_overrides_are_refused_by_name() {
    let d = tempfile::tempdir().unwrap();
    let mut o = base(d.path());
    o.cli_overrides = vec!["server.lissten=1".into()];
    let e = load(&o).unwrap_err().to_string();
    assert!(e.contains("--set server.lissten"), "{e}");
    o.cli_overrides = vec!["nope=1".into()];
    assert!(load(&o).is_err());
    o.cli_overrides = vec!["engine.min_confidence=abc".into()];
    assert!(load(&o).unwrap_err().to_string().contains("--set"));
    o.cli_overrides.clear();
    o.env_overrides = env(&[("SECMONK_SERVER__LISTENN", "x")]);
    let e = load(&o).unwrap_err().to_string();
    assert!(e.contains("SECMONK_SERVER__LISTENN"), "{e}");
    // reserved variables are not overrides even if passed in
    o.env_overrides = env(&[("SECMONK_LOG", "debug"), ("SECMONK_API_KEY", "x")]);
    assert!(load(&o).is_ok());
}

#[test]
fn relative_override_paths_resolve_against_the_cwd() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    write(
        &r.join("conf/sec-monk.toml"),
        "data_dir = \"_data\"\n[paths]\ntools = \"filetools\"\n",
    );
    let mut o = base(r);
    o.cli_config = Some(r.join("conf/sec-monk.toml"));
    o.env_overrides = env(&[("SECMONK_PATHS__VENVS", "envvenvs")]);
    o.cli_overrides = vec!["paths.python=clipy".into(), "paths.logs=~/logs".into()];
    let c = load(&o).unwrap();
    // file value: file directory; overrides: cwd (or ~)
    assert_eq!(c.paths.tools, Some(r.join("conf/filetools")));
    assert_eq!(c.paths.venvs, Some(r.join("cwd/envvenvs")));
    assert_eq!(c.paths.python, Some(r.join("cwd/clipy")));
    assert_eq!(c.paths.logs, Some(r.join("home/logs")));
    // data_dir too
    o.cli_overrides = vec!["data_dir=elsewhere".into()];
    let c = load(&o).unwrap();
    assert_eq!(c.data_dir, r.join("cwd/elsewhere").canonicalize().unwrap());
    // `uv.path = auto` is not a path
    o.cli_overrides = vec!["uv.path=auto".into()];
    assert_eq!(load(&o).unwrap().uv_path, Some(UvPath::Auto));
}

#[test]
fn db_dir_placeholder() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    let mut o = base(r);
    let c = load(&o).unwrap();
    let dd = c.data_dir.to_string_lossy().replace('\\', "/");
    assert_eq!(c.state_url, format!("sqlite://{dd}/db/state.sqlite3"));
    assert_eq!(c.mirror_url, format!("sqlite://{dd}/db/mirror.sqlite3"));
    o.cli_overrides = vec![
        format!("paths.db={}", r.join("dbs").display()),
        "database.mirror=sqlite://{db_dir}/m.sqlite3".into(),
    ];
    let c = load(&o).unwrap();
    let db = r.join("dbs").to_string_lossy().replace('\\', "/");
    assert_eq!(c.state_url, format!("sqlite://{db}/state.sqlite3"));
    assert_eq!(c.mirror_url, format!("sqlite://{db}/m.sqlite3"));
    assert_eq!(c.layout().db(), r.join("dbs"));
}

#[test]
fn new_sections_have_defaults() {
    let d = tempfile::tempdir().unwrap();
    let c = load(&base(d.path())).unwrap();
    assert_eq!(c.paths, MovedDirs::default());
    assert_eq!(c.uv_path, None);
    assert!(!c.uv_any_version);
    assert_eq!(c.server_listen, None);
    assert_eq!(
        (c.server_tls_cert.clone(), c.server_tls_key.clone()),
        (None, None)
    );
    assert!(c.server_allow_hosts.is_empty());
    assert!(!c.server_insecure_http);
    assert!(c.server_allow_actions && c.server_serve_ui);
    assert_eq!(c.server_auth, AuthMode::Auto);
    assert_eq!(c.auth_keys_file, c.data_dir.join("auth/api_keys.toml"));
    assert_eq!(c.auth_jwt_secret_file, c.data_dir.join("auth/jwt.key"));
    assert_eq!((c.auth_jwt_ttl_s, c.auth_rate_per_minute), (3600, 600));
    assert!(c.node_mirror);
    assert!(c.node_serve.is_empty());
    assert_eq!(c.node_matcher, MatcherMode::Local);
    assert_eq!(c.node_upstream_url, None);
    assert_eq!(c.node_upstream_api_key_env, "SECMONK_UPSTREAM_API_KEY");
    assert!(c.node_upstream_sources.is_empty());
}

#[test]
fn new_sections_parse_and_resolve() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    write(
        &r.join("conf/sec-monk.toml"),
        r#"
data_dir = "_data"
[paths]
auth = "authdir"
[uv]
path = "bin/uv"
any_version = true
[server]
listen = "0.0.0.0:8765"
tls_cert = "tls/cert.pem"
tls_key = "tls/key.pem"
allow_hosts = ["scan.example"]
auth = "required"
[auth]
jwt_ttl_s = 60
[node]
serve = ["match", "feed", "match"]
matcher = "remote"
[node.upstream]
url = "https://mirror.example:8765"
ca_cert = "ca.pem"
sources = ["kev"]
"#,
    );
    let mut o = base(r);
    o.cli_config = Some(r.join("conf/sec-monk.toml"));
    let c = load(&o).unwrap();
    assert_eq!(c.uv_path, Some(UvPath::File(r.join("conf/bin/uv"))));
    assert!(c.uv_any_version);
    assert_eq!(c.server_tls_cert, Some(r.join("conf/tls/cert.pem")));
    assert_eq!(c.server_auth, AuthMode::Required);
    assert_eq!(c.server_allow_hosts, ["scan.example"]);
    assert_eq!(c.auth_keys_file, r.join("conf/authdir/api_keys.toml"));
    assert_eq!(c.auth_jwt_ttl_s, 60);
    assert_eq!(c.node_serve, [NodeService::Feed, NodeService::Match]);
    assert_eq!(c.node_matcher, MatcherMode::Remote);
    assert_eq!(c.node_upstream_ca_cert, Some(r.join("conf/ca.pem")));
    assert_eq!(c.node_upstream_sources, ["kev"]);
    assert_eq!(c.layout().auth(), r.join("conf/authdir"));
}

#[test]
fn new_sections_are_validated() {
    let d = tempfile::tempdir().unwrap();
    let mut o = base(d.path());
    let bad = |o: &mut LoadOptions, sets: &[&str]| {
        o.cli_overrides = sets.iter().map(|s| (*s).to_string()).collect();
        load(o).unwrap_err().to_string()
    };
    assert!(bad(&mut o, &["node.serve=[\"bogus\"]"]).contains("--set node.serve"));
    assert!(bad(&mut o, &["node.matcher=remote"]).contains("node.upstream.url"));
    assert!(bad(&mut o, &["node.upstream.sources=[\"kev\"]"]).contains("node.upstream.url"));
    assert!(bad(&mut o, &["server.tls_cert=/c.pem"]).contains("together"));
    assert!(bad(&mut o, &["server.tls_key=/k.pem"]).contains("together"));
    assert!(bad(&mut o, &["server.auth=maybe"]).contains("--set server.auth"));
    assert!(bad(&mut o, &["server.listen=0.0.0.0:1", "server.auth=off"]).contains("loopback"));
    assert!(bad(&mut o, &["auth.jwt_ttl_s=0"]).contains("jwt_ttl_s"));
    assert!(bad(&mut o, &["node.upstream.url=ftp://x"]).contains("http(s)"));
    assert!(bad(&mut o, &["uv.pathh=1"]).contains("uv.pathh"));
    assert!(bad(&mut o, &["server.trusted_proxies=[\"nope\"]"]).contains("trusted_proxies"));
    assert!(bad(&mut o, &["server.trusted_proxies=[\"10.0.0.0/33\"]"]).contains("trusted_proxies"));
    assert!(bad(&mut o, &["server.auth=off", "node.serve=[\"feed\"]"]).contains("node.serve"));
    // loopback with auth off is fine
    o.cli_overrides = vec!["server.listen=127.0.0.1:1".into(), "server.auth=off".into()];
    assert!(load(&o).is_ok());
}

#[test]
fn layout_honours_moved_directories() {
    let root = Path::new("/data/sec-monk");
    let l = Layout::new(root);
    assert_eq!(l.tools(), root.join("tools"));
    assert_eq!(l.downloads(), root.join("tools/downloads"));
    assert_eq!(l.python_bin(), root.join("python/bin"));
    assert_eq!(l.secmonk_cache(), root.join("cache/secmonk"));
    assert_eq!(l.module_logs(), root.join("logs/modules"));
    assert_eq!(l.auth(), root.join("auth"));
    assert!(l.dirs().contains(&root.join("auth")));
    let shared = Path::new("/shared");
    let l = Layout::with_moved(
        root,
        MovedDirs {
            tools: Some(shared.join("tools")),
            python: Some(shared.join("py")),
            venvs: Some(shared.join("venvs")),
            uv_cache: Some(shared.join("uvc")),
            cache: Some(shared.join("cache")),
            logs: Some(shared.join("logs")),
            db: Some(shared.join("db")),
            auth: Some(shared.join("auth")),
        },
    );
    assert_eq!(l.tools(), shared.join("tools"));
    assert_eq!(l.downloads(), shared.join("tools/downloads"));
    assert_eq!(l.uv_dir("1.0"), shared.join("tools/uv-1.0"));
    assert_eq!(l.python(), shared.join("py"));
    assert_eq!(l.python_bin(), shared.join("py/bin"));
    assert_eq!(l.venv("e"), shared.join("venvs/e"));
    assert_eq!(l.uv_cache(), shared.join("uvc"));
    assert_eq!(l.secmonk_cache(), shared.join("cache"));
    assert_eq!(l.logs(), shared.join("logs"));
    assert_eq!(l.module_logs(), shared.join("logs/modules"));
    assert_eq!(l.db(), shared.join("db"));
    assert_eq!(l.auth(), shared.join("auth"));
    assert_eq!(l.pycache(), root.join("pycache"));
}

#[test]
fn layout_create_makes_moved_directories() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    let mut o = base(r);
    o.cli_overrides = vec![
        format!("paths.tools={}", r.join("shared/tools").display()),
        format!("paths.auth={}", r.join("shared/auth").display()),
    ];
    let c = load(&o).unwrap();
    c.layout().create().unwrap();
    assert!(r.join("shared/tools/downloads").is_dir());
    assert!(r.join("shared/auth").is_dir());
    assert!(!c.data_dir.join("tools").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(r.join("shared/auth"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(m & 0o777, 0o700);
    }
}

#[test]
fn effective_toml_round_trips() {
    let d = tempfile::tempdir().unwrap();
    let mut o = base(d.path());
    o.cli_overrides = vec![
        "node.upstream.url=https://m.example".into(),
        "node.matcher=remote".into(),
    ];
    let c = load(&o).unwrap();
    let text = effective_toml(&c);
    assert!(text.contains("[node.upstream]"), "{text}");
    let raw = parse(&text, Path::new("effective.toml")).unwrap();
    assert_eq!(raw.node.matcher, Some(MatcherMode::Remote));
    assert_eq!(raw.python.version.as_deref(), Some("3.13"));
}

#[test]
fn trusted_proxies_and_loopback_helpers() {
    let d = tempfile::tempdir().unwrap();
    let mut o = base(d.path());
    o.cli_overrides =
        vec!["server.trusted_proxies=[\"10.0.0.1\", \"192.168.0.0/16\", \"fd00::/8\"]".into()];
    let c = load(&o).unwrap();
    assert_eq!(
        c.server_trusted_proxies,
        ["10.0.0.1", "192.168.0.0/16", "fd00::/8"]
    );
    assert!(effective_toml(&c).contains("trusted_proxies"));

    let a = |s: &str| is_loopback_addr(&s.parse().unwrap());
    assert!(a("127.0.0.1:1") && a("127.9.9.9:1") && a("[::1]:1") && a("[::ffff:127.0.0.1]:1"));
    assert!(!a("0.0.0.0:1") && !a("10.0.0.1:1") && !a("[::]:1") && !a("[::ffff:10.0.0.1]:1"));
    assert!(is_loopback_listen("localhost:1") && is_loopback_listen("[::ffff:127.0.0.1]:1"));
    assert!(!is_loopback_listen("0.0.0.0:1"));
}

#[test]
fn app_defaults_sit_below_the_file_and_the_overrides() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    let bundled = r.join("bundle/python-project/rust/python");
    let defaults = vec![
        path_setting("modules.python_project", &bundled),
        "modules.editable=false".to_string(),
    ];
    // no file: the app defaults apply
    let mut o = opts(r);
    o.app_defaults = defaults.clone();
    let c = load(&o).unwrap();
    assert_eq!(c.python_project, bundled);
    assert!(!c.modules_editable);
    // without app defaults the dev values stay
    let c = load(&opts(r)).unwrap();
    assert!(c.modules_editable);
    // a file that sets python_project wins over the app default; editable still comes from the default
    write(
        &r.join("cwd/sec-monk.toml"),
        "[modules]\npython_project = \"mine\"\n",
    );
    let mut o = opts(r);
    o.app_defaults = defaults.clone();
    let c = load(&o).unwrap();
    assert_eq!(c.python_project, r.join("cwd/mine"));
    assert!(!c.modules_editable);
    // --set wins over both
    o.cli_overrides = vec!["modules.editable=true".into()];
    assert!(load(&o).unwrap().modules_editable);
    // an app default naming an unknown key is refused like any override
    let mut o = opts(r);
    o.app_defaults = vec!["modules.nope=1".into()];
    assert!(load(&o).is_err());
}

#[test]
fn path_settings_survive_backslashes_and_non_ascii() {
    let d = tempfile::tempdir().unwrap();
    let r = d.path();
    for name in ["C:\\Program Files\\sec-monk\\python", "Jos\u{e9} \"q\" dir"] {
        let p = r.join(name);
        let mut o = opts(r);
        o.app_defaults = vec![path_setting("modules.python_project", &p)];
        assert_eq!(load(&o).unwrap().python_project, p, "{name}");
    }
}
