//! The module environment is an allowlist plus the `SECMONK_*` / temp / pycache variables inside data_dir.
//! (Kept as an integration test: compiled into a unit-test object together with the allowlist, this code is
//! blocked by the endpoint security of the development Mac, see the crate docs.)

use std::ffi::OsString;
use std::path::Path;

use secmonk_config::Layout;
use secmonk_runtime::env::module_env;

#[test]
fn module_env_is_an_allowlist() {
    let layout = Layout::new(Path::new("/data/sec-monk"));
    let any = |k: &str| Some(OsString::from(format!("v-{}", k.len())));
    let e = module_env(&layout, &any);
    assert!(!e.contains_key("NOT_ALLOWED_VARIABLE"));
    assert!(!e.contains_key("PYTHONPATH"));
    assert_eq!(e["SECMONK_HOME"], layout.python_home().into_os_string());
    assert!(Path::new(&e["SECMONK_DB"]).starts_with(layout.python_home()));
    assert_eq!(e["TMPDIR"], layout.tmp().into_os_string());
    assert!(e.contains_key("PATH") && e.contains_key("HOME"));
}

#[test]
fn module_env_is_scoped_by_capabilities() {
    // regression: SSH_AUTH_SOCK, DOCKER_*, KUBECONFIG and the proxies went to every module
    use secmonk_runtime::env::{
        MODULE_BASE, MODULE_NETWORK_VARS, MODULE_PASSTHROUGH, MODULE_TARGET_VARS, module_env_for,
    };
    let layout = Layout::new(Path::new("/data/sec-monk"));
    let any = |k: &str| Some(OsString::from(format!("v-{}", k.len())));
    let has = |e: &std::collections::BTreeMap<String, OsString>, ks: &[&str]| {
        ks.iter().all(|k| e.contains_key(*k))
    };
    let none = |e: &std::collections::BTreeMap<String, OsString>, ks: &[&str]| {
        ks.iter().all(|k| !e.contains_key(*k))
    };
    // the groups partition the allowlist
    let mut union: Vec<&str> =
        [&MODULE_BASE[..], &MODULE_TARGET_VARS, &MODULE_NETWORK_VARS].concat();
    let mut all = MODULE_PASSTHROUGH.to_vec();
    union.sort();
    all.sort();
    assert_eq!(union, all);
    // py-engine
    let e = module_env_for(&layout, &["db-read"], &any);
    assert!(
        has(&e, &MODULE_BASE) && none(&e, &MODULE_TARGET_VARS) && none(&e, &MODULE_NETWORK_VARS)
    );
    // py-procmon
    let caps = ["local-system", "run-commands", "db-read", "stateful"];
    let e = module_env_for(&layout, &caps, &any);
    assert!(none(&e, &MODULE_TARGET_VARS) && none(&e, &MODULE_NETWORK_VARS));
    // py-sources: proxies and CAs only
    let e = module_env_for(&layout, &["network", "writes-staging"], &any);
    assert!(has(&e, &MODULE_NETWORK_VARS) && none(&e, &MODULE_TARGET_VARS));
    // py-probe: everything
    let e = module_env_for(&layout, &["read-target", "run-commands", "network"], &any);
    assert!(has(&e, &MODULE_PASSTHROUGH));
    assert_eq!(e["SECMONK_HOME"], layout.python_home().into_os_string());
}
