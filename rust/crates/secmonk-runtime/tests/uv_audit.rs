//! `uv_audit` (ignored: needs the network, ~20 s): a real install with the pinned uv into a temp data_dir
//! (uv download + sha256, `uv python install`, `uv lock` + `uv sync --frozen` of a fixture project, then the
//! module launch command), asserting that nothing is written outside data_dir:
//!
//! - the sentinel `uv-home/` (HOME, XDG_*, APPDATA of every uv step) is still empty;
//! - the project directory gained only `uv.lock` (no `.venv`, `__pycache__`, build output);
//! - the usual uv/Python user locations got no file newer than the start of the test;
//! - the real temp directory got no new uv entries.
//!
//! Run: `cargo test -p secmonk-runtime --test uv_audit -- --ignored --nocapture`.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use secmonk_config::{Layout, TrustMode};
use secmonk_runtime::env::UvStep;
use secmonk_runtime::{PythonRuntime, UvRuntime, UvSettings, pins, platform};

fn walk(root: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        out.push(p.clone());
        if depth > 0 && e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
            walk(&p, depth - 1, out);
        }
    }
}

fn newer_than(root: &Path, depth: usize, t: SystemTime) -> Vec<PathBuf> {
    let mut all = Vec::new();
    walk(root, depth, &mut all);
    all.into_iter()
        .filter(|p| {
            std::fs::symlink_metadata(p)
                .and_then(|m| m.modified())
                .map(|m| m > t)
                .unwrap_or(false)
        })
        .collect()
}

fn tree(root: &Path) -> BTreeSet<String> {
    let mut all = Vec::new();
    walk(root, 16, &mut all);
    all.iter()
        .map(|p| p.strip_prefix(root).unwrap().to_string_lossy().into_owned())
        .collect()
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        let t = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &t);
        } else {
            std::fs::copy(e.path(), t).unwrap();
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "network: downloads uv, a Python build and uv_build"]
async fn uv_audit() {
    let start = SystemTime::now() - Duration::from_secs(1);
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let data = root.join("data");
    let layout = Layout::new(&data);
    layout.create().unwrap();
    let project = root.join("project");
    copy_dir(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/audit-project"),
        &project,
    );

    let settings = UvSettings {
        layout: layout.clone(),
        uv_version: pins::UV_VERSION.into(),
        uv_url: pins::UV_URL.into(),
        uv_archive: None,
        uv_sha256: Default::default(),
        python_version: "3.13".into(),
        offline: false,
        index_url: None,
        find_links: None,
        trust: TrustMode::Dev,
        module_pins: Default::default(),
        asset: platform::host_asset(),
        uv_path: None,
        uv_any_version: false,
    };
    let rt = UvRuntime::new(settings);
    let t = std::time::Instant::now();
    let info = rt.ensure().await.unwrap();
    eprintln!(
        "ensure (uv download + verify + python install): {:?} -> {}",
        t.elapsed(),
        info.uv.display()
    );

    rt.run_uv(
        "uv lock",
        UvStep::Other,
        None,
        &["lock".into(), "--project".into(), project.clone().into()],
    )
    .await
    .unwrap();
    let before = tree(&project);
    assert!(before.contains("uv.lock"));

    let t = std::time::Instant::now();
    let env = rt.ensure_env(&project, "audit").await.unwrap();
    eprintln!(
        "ensure_env (uv sync --frozen): {:?} synced={}",
        t.elapsed(),
        env.synced
    );
    assert!(env.synced && env.python.exists());
    let again = rt.ensure_env(&project, "audit").await.unwrap();
    assert!(!again.synced, "install marker reused");

    let entry: Vec<String> = [
        "-I",
        "-c",
        "import secmonk_audit_fixture as m, sys; print(m.MARKER, sys.prefix)",
    ]
    .map(String::from)
    .into();
    let spec = rt.command("audit", &entry).unwrap();
    let out = spec.to_command().output().await.unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    eprintln!("launch: {} {}", out.status, stdout.trim());
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(stdout.contains("secmonk-audit-fixture-ok"));
    assert!(stdout.contains(&layout.venv("audit").to_string_lossy().into_owned()));

    // 1. sentinel HOME/XDG/APPDATA of uv steps: empty directories only
    let mut sentinel = Vec::new();
    walk(&layout.uv_home(), 8, &mut sentinel);
    let files: Vec<_> = sentinel.iter().filter(|p| !p.is_dir()).collect();
    assert!(
        files.is_empty(),
        "uv wrote into the sentinel home: {files:?}"
    );
    // 2. project: only uv.lock appeared (before == after the sync and the launch)
    assert_eq!(tree(&project), before, "the project directory changed");
    // 3. user-level uv / Python locations
    let home = dirs::home_dir().unwrap();
    let mut leaks = Vec::new();
    for rel in [
        ".cache/uv",
        ".local/share/uv",
        ".local/bin",
        ".config/uv",
        "Library/Caches/uv",
        "Library/Application Support/uv",
        ".python_history",
    ] {
        leaks.extend(newer_than(&home.join(rel), 3, start));
    }
    assert!(
        leaks.is_empty(),
        "files written in user locations: {leaks:?}"
    );
    // 4. the real temp directory: no new uv entries
    let real_tmp = std::env::temp_dir();
    let tmp_leaks: Vec<_> = newer_than(&real_tmp, 0, start)
        .into_iter()
        .filter(|p| !p.starts_with(&root))
        .filter(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().to_lowercase().contains("uv"))
                .unwrap_or(false)
        })
        .collect();
    assert!(
        tmp_leaks.is_empty(),
        "uv entries in the real temp dir: {tmp_leaks:?}"
    );

    let mut sizes = Vec::new();
    for d in ["tools", "python", "uv-cache", "venvs", "pycache", "tmp"] {
        let mut all = Vec::new();
        walk(&data.join(d), 32, &mut all);
        let bytes: u64 = all
            .iter()
            .filter_map(|p| std::fs::symlink_metadata(p).ok())
            .map(|m| m.len())
            .sum();
        sizes.push(format!("{d}={}MB", bytes / 1_000_000));
    }
    eprintln!("data_dir usage: {}", sizes.join(" "));
}
