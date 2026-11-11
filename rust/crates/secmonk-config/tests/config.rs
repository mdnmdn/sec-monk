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
