//! The engine over the real Python modules (`py-sources`, `py-engine`) of `rust/python`, started from the dev venv
//! `rust/python/.venv` (no uv). Gated: skipped when the venv is missing. Offline: `kev` syncs from the repo fixture.
//!
//! Only this test names the module host: the engine itself receives trait objects (architecture.md §2);
//! `rust/deny.toml` lists `secmonk-engine` as a dev-only wrapper of `secmonk-modhost`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use secmonk_config::{Config, LoadOptions};
use secmonk_engine::{EngineConfig, EngineDeps, EngineService, FindingsQuery, SecmonkEngine};
use secmonk_model::{Asset, Category, Component, Inventory};
use secmonk_modhost::adapters::{PyEngine, PySource};
use secmonk_modhost::hello::HostSettings;
use secmonk_modhost::registry::Registry;
use secmonk_modhost::supervisor::ModuleHandle;
use secmonk_runtime::{
    EnvInfo, LaunchSpec, PythonRuntime, RuntimeError, RuntimeInfo, RuntimeResult,
};
use secmonk_store::{MirrorStore, SqliteStore, StateStore, StoreOptions};
use secmonk_traits::{
    CallCtx, CollectEnd, CollectItem, CollectParams, Collector, CollectorInfo, Probe, ResultStream,
    Source, StepResult, WireError,
};
use serde_json::{Value, json};

fn rust_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// Whether the dev venv and the fixtures exist. Missing: the test is skipped, or fails when `SECMONK_REQUIRE_VENV=1`
/// (CI and release checks must run these tests, not skip them).
fn available(paths: &[&Path], what: &str) -> bool {
    let missing: Vec<String> = paths
        .iter()
        .filter(|p| !p.exists())
        .map(|p| p.display().to_string())
        .collect();
    if missing.is_empty() {
        return true;
    }
    assert!(
        std::env::var("SECMONK_REQUIRE_VENV").as_deref() != Ok("1"),
        "SECMONK_REQUIRE_VENV=1 but missing: {missing:?} (cd rust/python && uv sync)"
    );
    eprintln!("missing {missing:?}: {what} skipped");
    false
}

/// The dev venv as a runtime: modules start with its interpreter and the module environment of `data_dir`.
struct DevVenv {
    python: PathBuf,
    config: Config,
}

#[async_trait]
impl PythonRuntime for DevVenv {
    async fn ensure(&self) -> RuntimeResult<RuntimeInfo> {
        Err(RuntimeError::Offline("dev venv: no uv".into()))
    }

    async fn ensure_env(&self, _: &Path, _: &str) -> RuntimeResult<EnvInfo> {
        Err(RuntimeError::Offline("dev venv: no uv".into()))
    }

    fn command(&self, _env: &str, entry: &[String]) -> RuntimeResult<LaunchSpec> {
        self.command_for(_env, entry, &["read-target", "network"])
    }

    fn command_for(
        &self,
        _env: &str,
        entry: &[String],
        caps: &[&str],
    ) -> RuntimeResult<LaunchSpec> {
        let layout = self.config.layout();
        let mut args: Vec<OsString> = vec!["-X".into()];
        let mut prefix = OsString::from("pycache_prefix=");
        prefix.push(layout.pycache());
        args.push(prefix);
        args.extend(entry.iter().map(OsString::from));
        let env: BTreeMap<String, OsString> =
            secmonk_runtime::env::module_env_for(&layout, caps, &|k| std::env::var_os(k));
        Ok(LaunchSpec {
            program: self.python.clone(),
            args,
            env,
            cwd: layout.tmp(),
        })
    }
}

/// No collectors: this test drives sources and engine steps only (the probe has its own tests).
struct NoProbe;

#[async_trait]
impl Collector for NoProbe {
    fn collectors(&self) -> Vec<CollectorInfo> {
        Vec::new()
    }
    async fn expand_targets(
        &self,
        _: CollectParams,
        _: CallCtx,
    ) -> StepResult<Vec<Option<String>>> {
        Ok(Vec::new())
    }
    async fn collect(
        &self,
        _: CollectParams,
        _: CallCtx,
    ) -> StepResult<ResultStream<CollectItem, CollectEnd>> {
        Err(WireError::new(
            secmonk_traits::ErrorCode::UnknownCollector,
            "no collectors",
        ))
    }
}

#[async_trait]
impl Probe for NoProbe {
    fn methods(&self) -> Vec<String> {
        Vec::new()
    }
    async fn call(&self, m: &str, _: Value, _: CallCtx) -> StepResult<Value> {
        Err(WireError::new(
            secmonk_traits::ErrorCode::UnknownMethod,
            format!("no {m}"),
        ))
    }
}

fn config(dir: &Path) -> Config {
    let file = dir.join("sec-monk.toml");
    let text = format!(
        "config_version = 1\ndata_dir = {:?}\n[modules]\npython_project = {:?}\nenabled = [\"py-engine\", \
         \"py-sources\"]\ntrust = \"dev\"\n",
        dir.join("data").display().to_string(),
        rust_root().join("python").display().to_string(),
    );
    std::fs::write(&file, text).unwrap();
    secmonk_config::load(&LoadOptions {
        cli_config: Some(file),
        cwd: dir.to_path_buf(),
        ..Default::default()
    })
    .unwrap()
}

async fn wait_job(engine: &SecmonkEngine, id: u64) -> Value {
    wait_job_secs(engine, id, 60).await
}

async fn wait_job_secs(engine: &SecmonkEngine, id: u64, secs: u64) -> Value {
    for _ in 0..secs * 20 {
        let j = engine.job_get(id).await.unwrap();
        if j["status"] != "running" {
            return j;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("job {id} did not finish in {secs} s");
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_and_match_over_the_real_modules() {
    let root = rust_root();
    let python = root.join("python/.venv/bin/python");
    let fixture = root.join("../tests/fixtures/sources/kev/known_exploited_vulnerabilities.json");
    if !available(&[&python, &fixture], "real-module test") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path());
    let layout = config.layout();
    layout.create().unwrap();
    let state_db = config.data_dir.join("db/state.sqlite3");
    let store = SqliteStore::open(
        &state_db,
        &config.data_dir.join("db/mirror.sqlite3"),
        &StoreOptions::default(),
    )
    .await
    .unwrap();
    let registry = Registry::load_dir(&root.join("python/modules"), &config).unwrap();
    let runtime: Arc<dyn PythonRuntime> = Arc::new(DevVenv {
        python,
        config: config.clone(),
    });
    let settings = HostSettings {
        min_confidence: 0.5,
        state_db: Some(store.state_path().to_path_buf()),
        mirror_db: Some(store.mirror_path().to_path_buf()),
        allow_db_read: true,
        process_target: None,
        process_options: Vec::new(),
        modules_root: Some(layout.modules()),
    };
    let handle = |name: &str| {
        ModuleHandle::python(
            registry.get(name).unwrap(),
            runtime.clone(),
            settings.clone(),
        )
    };
    let (engine_h, sources_h) = (handle("py-engine"), handle("py-sources"));
    let source: Arc<dyn Source> = Arc::new(PySource::new(sources_h.clone()));
    let steps = Arc::new(PyEngine::new(engine_h.clone()));
    let mut ec = EngineConfig::new("0.0.0-test", &state_db);
    ec.data_dir = config.data_dir.clone();
    ec.nvd_api_key_env = None;
    let engine = SecmonkEngine::new(EngineDeps {
        config: ec,
        state: Arc::new(store.clone()),
        mirror: Arc::new(store.clone()),
        steps,
        procmon: None,
        sources: vec![source],
        probe: Arc::new(NoProbe),
        modules: None,
    });

    // 1. sync kev from the fixture: py-sources runs the unchanged source on staging, the host applies and acks
    let body = json!({"kind": "sync", "sources": ["kev"], "path": fixture.display().to_string()});
    let started = engine
        .job_start(body.as_object().cloned().unwrap())
        .await
        .unwrap();
    let job = wait_job(&engine, started["id"].as_u64().unwrap()).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    let entry = &job["result"]["sources"][0];
    assert!(entry["records"].as_u64().unwrap() > 0, "{entry}");
    let first = store
        .applied_seq("kev")
        .await
        .unwrap()
        .expect("batches applied");
    // a second sync of the same file streams nothing new (the first run was acknowledged)
    let started = engine
        .job_start(body.as_object().cloned().unwrap())
        .await
        .unwrap();
    let again = wait_job(&engine, started["id"].as_u64().unwrap()).await;
    assert_eq!(again["status"], "ok", "{again:#}");
    let second = store.applied_seq("kev").await.unwrap().unwrap();
    assert!(second >= first, "seqs never go back ({first} -> {second})");

    // 2. py-engine reads the host's mirror: sources status lists kev
    let s = engine.sources().await.unwrap();
    assert_eq!(s["db"]["exists"], true, "{s:#}");
    assert!(s["status"].to_string().contains("kev"), "{s:#}");

    // 3. a stored inventory, matched by py-engine, its finding set written by the host
    let inv = Inventory {
        schema: Some("secmonk-inventory/2".into()),
        classified: Some(true),
        asset: Asset {
            id: "host:real-test".into(),
            kind: "host".into(),
            name: "real-test".into(),
            os_name: None,
            os_version: None,
            platform: None,
            meta: Default::default(),
        },
        collector: "fs".into(),
        components: vec![Component {
            name: "requests".into(),
            version: Some("2.0.0".into()),
            category: Category::Library,
            purl: Some("pkg:pypi/requests@2.0.0".into()),
            cpe: None,
            vendor: None,
            ecosystem: Some("PyPI".into()),
            source_path: None,
            meta: Default::default(),
        }],
        warnings: Vec::new(),
        partial: false,
        partial_reason: None,
    };
    store.save_inventory(&inv, None).await.unwrap();
    let r = engine.match_asset("host:real-test").await.unwrap();
    assert_eq!(r["asset"], "host:real-test");
    assert_eq!(r["stats"]["components"], 1, "{r}");
    let f = engine
        .findings(&FindingsQuery {
            priority: None,
            asset: Some("host:real-test".into()),
            include_closed: false,
            fixable: false,
            hide_minor: false,
            hide_deferred: false,
            limit: 200,
        })
        .await
        .unwrap();
    assert!(f["findings"].is_array(), "{f}");

    engine.shutdown().await;
    engine_h.shutdown().await;
    sources_h.shutdown().await;
    store.close().await;
}

/// Compare the host's mirror with the module's staging database, table by table and row by row (duplicates count,
/// JSON normalized), with the dev venv's Python: the W2.2 round-trip check, over the Rust store.
fn assert_mirror_equals_staging(python: &Path, mirror: &Path, staging: &Path, what: &str) {
    let script = "import json, sqlite3, sys\n\
                  J = {'data', 'cwes', 'extra', 'events', 'versions'}\n\
                  T = ['source_sync', 'raw_record', 'vulnerability', 'alias', 'affected', 'kev', 'epss', 'distro_triage']\n\
                  def rows(c, t):\n\
                  \x20   cols = [r[1] for r in c.execute(f'PRAGMA table_info({t})') if r[1] != 'rowid_']\n\
                  \x20   out = [tuple(json.dumps(json.loads(v), sort_keys=True) if k in J and isinstance(v, str) else v\n\
                  \x20                for k, v in zip(cols, r)) for r in c.execute(f\"SELECT {', '.join(cols)} FROM {t}\")]\n\
                  \x20   return sorted(out, key=lambda r: json.dumps(r, default=str))\n\
                  m, s = sqlite3.connect(sys.argv[1]), sqlite3.connect(sys.argv[2])\n\
                  bad = [f'{t}: mirror {len(rows(m, t))} rows, staging {len(rows(s, t))}' for t in T if rows(m, t) != rows(s, t)]\n\
                  print('\\n'.join(bad))\n\
                  sys.exit(1 if bad else 0)\n";
    let dir = tempfile::tempdir().unwrap();
    let out = std::process::Command::new(python)
        .arg("-I")
        .arg("-c")
        .arg(script)
        .arg(mirror)
        .arg(staging)
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{what}: the mirror differs from staging:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_repairs_and_never_loses_or_duplicates_rows() {
    // review M1/M5 end to end: real py-sources, real store; crash between apply and ack, a recreated staging file,
    // a reset mirror, a normal sync after a repair. After each step the mirror equals staging row by row.
    let root = rust_root();
    let python = root.join("python/.venv/bin/python");
    let fix = root.join("../tests/fixtures/sources");
    let osv = fix.join("osv/sample-all.zip");
    let msrc = fix.join("msrc/cvrf-2024-Aug.synthetic.json");
    if !available(&[&python, &osv, &msrc], "real-module test") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path());
    let layout = config.layout();
    layout.create().unwrap();
    let staging = layout.modules().join("py-sources").join("staging.sqlite3");
    let registry = Registry::load_dir(&root.join("python/modules"), &config).unwrap();
    let runtime: Arc<dyn PythonRuntime> = Arc::new(DevVenv {
        python: python.clone(),
        config: config.clone(),
    });
    let open = |n: &str| {
        let db = config.data_dir.join(format!("db{n}"));
        async move {
            SqliteStore::open(
                &db.join("state.sqlite3"),
                &db.join("mirror.sqlite3"),
                &StoreOptions::default(),
            )
            .await
            .unwrap()
        }
    };
    let store = open("1").await;
    let settings = HostSettings {
        min_confidence: 0.5,
        state_db: Some(store.state_path().to_path_buf()),
        mirror_db: Some(store.mirror_path().to_path_buf()),
        allow_db_read: true,
        process_target: None,
        process_options: Vec::new(),
        modules_root: Some(layout.modules()),
    };
    let sources_h = ModuleHandle::python(
        registry.get("py-sources").unwrap(),
        runtime.clone(),
        settings.clone(),
    );
    let engine_h = ModuleHandle::python(registry.get("py-engine").unwrap(), runtime, settings);
    let source = Arc::new(PySource::new(sources_h.clone()));
    let steps = Arc::new(PyEngine::new(engine_h.clone()));
    let engine_over = |store: &SqliteStore| {
        let mut ec = EngineConfig::new("0.0.0-test", store.state_path());
        ec.data_dir = config.data_dir.clone();
        ec.nvd_api_key_env = None;
        SecmonkEngine::new(EngineDeps {
            config: ec,
            state: Arc::new(store.clone()),
            mirror: Arc::new(store.clone()),
            steps: steps.clone(),
            procmon: None,
            sources: vec![source.clone() as Arc<dyn Source>],
            probe: Arc::new(NoProbe),
            modules: None,
        })
    };
    async fn sync(engine: &SecmonkEngine, name: &str, path: &Path, full: bool) -> Value {
        let body = json!({"kind": "sync", "sources": [name], "path": path.display().to_string(), "full": full});
        let started = engine
            .job_start(body.as_object().cloned().unwrap())
            .await
            .unwrap();
        let job = wait_job(engine, started["id"].as_u64().unwrap()).await;
        assert_eq!(job["status"], "ok", "{job:#}");
        job
    }
    let logs = |job: &Value| job["log"].to_string();

    // 1. first syncs
    let engine = engine_over(&store);
    sync(&engine, "osv", &osv, false).await;
    sync(&engine, "msrc", &msrc, false).await;
    assert_mirror_equals_staging(&python, store.mirror_path(), &staging, "first syncs");

    // 2. a crash between apply and ack: the host applied a full msrc re-import and stopped before `source.ack`
    let params: secmonk_model::SyncParams = serde_json::from_value(json!({
        "source": "msrc", "options": {"path": msrc.display().to_string(), "full": true}}))
    .unwrap();
    let mut stream = source.sync(params, CallCtx::default()).await.unwrap();
    let mut applied = 0;
    while let Some(m) = futures_util::StreamExt::next(&mut stream).await {
        if let secmonk_traits::StreamMsg::Item(b) = m.unwrap() {
            assert!(!store.apply_rows(&b).await.unwrap().needs_repair);
            applied += 1;
        }
    }
    assert!(applied > 0, "a full re-import changes rows");
    let job = sync(&engine, "msrc", &msrc, true).await;
    assert!(
        logs(&job).contains("replayed batch(es) were already applied"),
        "{job:#}"
    );
    assert_mirror_equals_staging(
        &python,
        store.mirror_path(),
        &staging,
        "replay after a crash",
    );

    // 3. the staging file is recreated: seqs restart at 1 under a new generation; both sources are repaired
    engine.shutdown().await;
    for ext in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{}{ext}", staging.display()));
    }
    let engine = engine_over(&store);
    let job = sync(&engine, "osv", &osv, false).await;
    assert!(
        logs(&job).contains("the staging database was recreated"),
        "{job:#}"
    );
    let job = sync(&engine, "msrc", &msrc, false).await;
    assert!(
        logs(&job).contains("mirror repaired from the staging export"),
        "{job:#}"
    );
    assert_mirror_equals_staging(&python, store.mirror_path(), &staging, "recreated staging");

    // 4. a normal sync after the repair (deletes and updates of `affected` travel as operations)
    let job = sync(&engine, "msrc", &msrc, true).await;
    assert!(!logs(&job).contains("repaired"), "{job:#}");
    assert_mirror_equals_staging(
        &python,
        store.mirror_path(),
        &staging,
        "sync after a repair",
    );

    // 5. the mirror is reset (a new file) while staging keeps everything it acknowledged
    engine.shutdown().await;
    let reset = open("2").await;
    let engine = engine_over(&reset);
    let job = sync(&engine, "osv", &osv, false).await; // no change in staging: the empty stream triggers the export
    assert!(
        logs(&job).contains("mirror repaired from the staging export"),
        "{job:#}"
    );
    let job = sync(&engine, "msrc", &msrc, true).await; // changes: the batches say what staging acknowledged
    assert!(
        logs(&job).contains("the mirror has no applied state"),
        "{job:#}"
    );
    assert_mirror_equals_staging(&python, reset.mirror_path(), &staging, "reset mirror");
    let st = reset.applied_state("msrc").await.unwrap().unwrap();
    assert!(st.generation.is_some());

    engine.shutdown().await;
    engine_h.shutdown().await;
    sources_h.shutdown().await;
    store.close().await;
    reset.close().await;
}

/// Compare two mirror databases table by table and row by row (duplicates count, JSON normalized), ignoring the
/// `table.column`s in `ignore` (run timestamps) and comparing only `tables` (all mirror tables when empty).
fn assert_mirrors_equal(
    python: &Path,
    a: &Path,
    b: &Path,
    what: &str,
    ignore: &[&str],
    tables: &[&str],
) {
    let script = "import json, sqlite3, sys\n\
                  J = {'data', 'cwes', 'extra', 'events', 'versions'}\n\
                  ALL = ['source_sync', 'raw_record', 'vulnerability', 'alias', 'affected', 'kev', 'epss', 'distro_triage']\n\
                  IGN = set(filter(None, sys.argv[3].split(',')))\n\
                  T = list(filter(None, sys.argv[4].split(','))) or ALL\n\
                  def rows(c, t):\n\
                  \x20   cols = [r[1] for r in c.execute(f'PRAGMA table_info({t})') if r[1] != 'rowid_' and f'{t}.{r[1]}' not in IGN]\n\
                  \x20   out = [tuple(json.dumps(json.loads(v), sort_keys=True) if k in J and isinstance(v, str) else v\n\
                  \x20                for k, v in zip(cols, r)) for r in c.execute(f\"SELECT {', '.join(cols)} FROM {t}\")]\n\
                  \x20   return sorted(out, key=lambda r: json.dumps(r, default=str))\n\
                  a, b = sqlite3.connect(sys.argv[1]), sqlite3.connect(sys.argv[2])\n\
                  bad = []\n\
                  for t in T:\n\
                  \x20   ra, rb = rows(a, t), rows(b, t)\n\
                  \x20   if ra != rb:\n\
                  \x20       bad.append(f'{t}: {len(ra)} rows vs {len(rb)}; only left: {[r for r in ra if r not in rb][:3]}; only right: {[r for r in rb if r not in ra][:3]}')\n\
                  print('\\n'.join(bad))\n\
                  sys.exit(1 if bad else 0)\n";
    let dir = tempfile::tempdir().unwrap();
    let out = std::process::Command::new(python)
        .arg("-I")
        .arg("-c")
        .arg(script)
        .arg(a)
        .arg(b)
        .arg(ignore.join(","))
        .arg(tables.join(","))
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{what}: the mirrors differ:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The setup of a differential test (stage 6, component-lifecycle.md): mirrors in one data directory, a `py-sources`
/// per Python-written mirror (its staging belongs to that mirror), one `py-engine` for the engine steps, and engines
/// over a mirror with the given sources (a name served by two sources is taken from the first, as in the host).
struct Diff {
    python: PathBuf,
    config: Config,
    registry: Registry,
    runtime: Arc<dyn PythonRuntime>,
    steps: Arc<PyEngine>,
    handles: Vec<ModuleHandle>,
    stores: Vec<SqliteStore>,
    engines: Vec<Arc<SecmonkEngine>>,
    _dir: tempfile::TempDir,
}

impl Diff {
    /// `None` when the dev venv or a fixture is missing (skipped; fails with `SECMONK_REQUIRE_VENV=1`).
    async fn new(fixtures: &[&Path]) -> Option<Diff> {
        let root = rust_root();
        let python = root.join("python/.venv/bin/python");
        let mut need: Vec<&Path> = vec![&python];
        need.extend_from_slice(fixtures);
        if !available(&need, "differential test") {
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        let config = config(dir.path());
        config.layout().create().unwrap();
        let registry = Registry::load_dir(&root.join("python/modules"), &config).unwrap();
        let runtime: Arc<dyn PythonRuntime> = Arc::new(DevVenv {
            python: python.clone(),
            config: config.clone(),
        });
        let db = config.data_dir.join("db-steps");
        let steps_store = SqliteStore::open(
            &db.join("state.sqlite3"),
            &db.join("mirror.sqlite3"),
            &StoreOptions::default(),
        )
        .await
        .unwrap();
        let engine_h = ModuleHandle::python(
            registry.get("py-engine").unwrap(),
            runtime.clone(),
            Diff::settings(&steps_store, config.layout().modules()),
        );
        Some(Diff {
            python,
            config,
            registry,
            runtime,
            steps: Arc::new(PyEngine::new(engine_h.clone())),
            handles: vec![engine_h],
            stores: vec![steps_store],
            engines: Vec::new(),
            _dir: dir,
        })
    }

    fn settings(store: &SqliteStore, modules_root: PathBuf) -> HostSettings {
        HostSettings {
            min_confidence: 0.5,
            state_db: Some(store.state_path().to_path_buf()),
            mirror_db: Some(store.mirror_path().to_path_buf()),
            allow_db_read: true,
            process_target: None,
            process_options: Vec::new(),
            modules_root: Some(modules_root),
        }
    }

    /// A new mirror (and state) database `db-<name>`.
    async fn store(&mut self, name: &str) -> SqliteStore {
        let db = self.config.data_dir.join(format!("db-{name}"));
        let s = SqliteStore::open(
            &db.join("state.sqlite3"),
            &db.join("mirror.sqlite3"),
            &StoreOptions::default(),
        )
        .await
        .unwrap();
        self.stores.push(s.clone());
        s
    }

    /// A `py-sources` over `store` with its own modules directory (its staging file is returned too).
    fn py_sources(&mut self, store: &SqliteStore, modules: &str) -> (Arc<dyn Source>, PathBuf) {
        let root = self.config.data_dir.join(modules);
        std::fs::create_dir_all(&root).unwrap();
        let h = ModuleHandle::python(
            self.registry.get("py-sources").unwrap(),
            self.runtime.clone(),
            Diff::settings(store, root.clone()),
        );
        self.handles.push(h.clone());
        (
            Arc::new(PySource::new(h)),
            root.join("py-sources/staging.sqlite3"),
        )
    }

    /// An engine over `store` with `sources` (in order of precedence).
    fn engine(&mut self, store: &SqliteStore, sources: Vec<Arc<dyn Source>>) -> Arc<SecmonkEngine> {
        let mut ec = EngineConfig::new("0.0.0-test", store.state_path());
        ec.data_dir = self.config.data_dir.clone();
        ec.nvd_api_key_env = None;
        let e = SecmonkEngine::new(EngineDeps {
            config: ec,
            state: Arc::new(store.clone()),
            mirror: Arc::new(store.clone()),
            steps: self.steps.clone(),
            procmon: None,
            sources,
            probe: Arc::new(NoProbe),
            modules: None,
        });
        self.engines.push(e.clone());
        e
    }

    fn view(store: &SqliteStore) -> Arc<dyn secmonk_traits::MirrorView> {
        Arc::new(secmonk_engine::StoreMirrorView::new(Arc::new(
            store.clone(),
        )))
    }

    async fn close(self) {
        for e in &self.engines {
            e.shutdown().await;
        }
        for h in &self.handles {
            h.shutdown().await;
        }
        for s in &self.stores {
            s.close().await;
        }
    }
}

/// One sync job of `sources` through `engine`, with `path` and the other plan keys in `extra`.
async fn sync_job(engine: &SecmonkEngine, sources: &[&str], path: &Path, extra: Value) -> Value {
    sync_job_secs(engine, sources, path, extra, 60).await
}

async fn sync_job_secs(
    engine: &SecmonkEngine,
    sources: &[&str],
    path: &Path,
    extra: Value,
    secs: u64,
) -> Value {
    let mut b = json!({"kind": "sync", "sources": sources, "path": path.display().to_string()});
    for (k, v) in extra.as_object().unwrap() {
        b[k] = v.clone();
    }
    let started = engine
        .job_start(b.as_object().cloned().unwrap())
        .await
        .unwrap();
    wait_job_secs(engine, started["id"].as_u64().unwrap(), secs).await
}

/// The first entry of a sync job's result.
fn entry_of(job: &Value) -> Value {
    job["result"]["sources"][0].clone()
}

/// Both versions' entries agree on status, records and message.
fn check_entries(a: &Value, b: &Value, what: &str) {
    for k in ["status", "records", "message"] {
        assert_eq!(
            entry_of(a)[k],
            entry_of(b)[k],
            "{what}: entry {k}\npy: {a:#}\nrs: {b:#}"
        );
    }
}

/// `(cve_id, extra)` of every `kev` row as stored (raw text), ordered by CVE.
fn kev_extra_text(python: &Path, mirror: &Path) -> Vec<(String, String)> {
    let dir = tempfile::tempdir().unwrap();
    let out = std::process::Command::new(python)
        .arg("-I")
        .arg("-c")
        .arg(
            "import json, sqlite3, sys\n\
             c = sqlite3.connect(sys.argv[1])\n\
             print(json.dumps(c.execute('SELECT cve_id, extra FROM kev ORDER BY cve_id').fetchall()))\n",
        )
        .arg(mirror)
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

/// The kev fixture changed: `drop` entries removed from the end, the first entry's product renamed, one new entry
/// with an unmapped field, another catalog version.
fn kev_update(fixture: &Path, dir: &Path) -> PathBuf {
    let mut doc: Value = serde_json::from_slice(&std::fs::read(fixture).unwrap()).unwrap();
    let v = doc["vulnerabilities"].as_array_mut().unwrap();
    v.truncate(v.len() - 2);
    v[0]["product"] = json!("Log4j2 (renamed)");
    v[1]["knownRansomwareCampaignUse"] = json!("Unknown");
    v.push(json!({
        "cveID": "CVE-2026-99999", "vendorProject": "Example", "product": "Widget",
        "vulnerabilityName": "Example Widget Synthetic Vulnerability", "dateAdded": "2026-11-10",
        "shortDescription": "Synthetic entry of the differential test (no real CVE).", "requiredAction": "None.",
        "dueDate": "2026-12-01", "knownRansomwareCampaignUse": "Known", "notes": "", "cwes": [],
        "newField": {"nested": [1, 2.5, "ü"]}
    }));
    doc["count"] = json!(v.len());
    doc["catalogVersion"] = json!("2026.11.10");
    let p = dir.join("kev-update.json");
    std::fs::write(&p, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
    p
}

#[tokio::test(flavor = "multi_thread")]
async fn native_kev_matches_py_sources() {
    // Stage 6 differential test (component-lifecycle.md): the native kev source and py-sources' kev, each through
    // the engine on its own mirror, leave identical mirrors (run timestamps aside) after every step; a mirror that
    // switches from py-sources to the native importer and back to py-sources ends where ADR-0010/0011 say.
    let fixture =
        rust_root().join("../tests/fixtures/sources/kev/known_exploited_vulnerabilities.json");
    let Some(mut d) = Diff::new(&[&fixture]).await else {
        return;
    };
    let python = d.python.clone();
    let dir = tempfile::tempdir().unwrap();
    let (py_store, rs_store, switch_store) = (
        d.store("py").await,
        d.store("rs").await,
        d.store("switch").await,
    );
    let (py_src, _) = d.py_sources(&py_store, "modules-py");
    let (switch_src, switch_staging) = d.py_sources(&switch_store, "modules-switch");
    let native = |store: &SqliteStore| -> Arc<dyn Source> {
        Arc::new(secmonk_sources::kev::KevSource::new(Diff::view(store)))
    };
    let py = d.engine(&py_store, vec![py_src]);
    let rs = d.engine(&rs_store, vec![native(&rs_store)]);
    let switch_py = d.engine(&switch_store, vec![switch_src]);
    let switch_rs = d.engine(&switch_store, vec![native(&switch_store)]);

    async fn sync(engine: &SecmonkEngine, path: &Path, extra: Value) -> Value {
        sync_job(engine, &["kev"], path, extra).await
    }
    let entry = entry_of;
    const TIMESTAMPS: &[&str] = &["raw_record.fetched_at", "source_sync.last_sync"];
    let same = |what: &str| {
        assert_mirrors_equal(
            &python,
            py_store.mirror_path(),
            rs_store.mirror_path(),
            what,
            TIMESTAMPS,
            &[],
        );
    };
    // both versions on the same input: same entry (status, records, message) and the same mirror
    async fn both(
        py: &SecmonkEngine,
        rs: &SecmonkEngine,
        path: &Path,
        extra: Value,
    ) -> (Value, Value) {
        let a = sync(py, path, extra.clone()).await;
        let b = sync(rs, path, extra).await;
        (a, b)
    }
    let updated = kev_update(&fixture, dir.path());
    let small = {
        let mut doc: Value = serde_json::from_slice(&std::fs::read(&fixture).unwrap()).unwrap();
        doc["vulnerabilities"].as_array_mut().unwrap().truncate(2);
        let p = dir.path().join("kev-small.json");
        std::fs::write(&p, serde_json::to_vec(&doc).unwrap()).unwrap();
        p
    };

    // 1. first sync; the switch mirror starts on py-sources
    let (a, b) = both(&py, &rs, &fixture, json!({})).await;
    check_entries(&a, &b, "first sync");
    assert_eq!(entry(&b)["status"], "ok");
    let kev_rows = rs_store
        .count_rows(secmonk_model::MirrorTable::Kev, "kev")
        .await
        .unwrap();
    assert_eq!(kev_rows, 9, "the comparison is not vacuous");
    same("first sync");
    // `same` compares JSON normalized; the stored text of `kev.extra` must be equal too (feed key order, compact)
    let (pa, pb) = (
        kev_extra_text(&python, py_store.mirror_path()),
        kev_extra_text(&python, rs_store.mirror_path()),
    );
    assert_eq!(pa, pb, "kev.extra as stored");
    let log4j = pb.iter().find(|(c, _)| c == "CVE-2021-44228").unwrap();
    assert!(
        log4j
            .1
            .starts_with("{\"shortDescription\":\"Apache Log4j2 contains")
            && log4j.1.contains("\"forensicTriage\":\"No\",\"notes\":")
            && log4j
                .1
                .ends_with("\"cwes\":[\"CWE-20\",\"CWE-400\",\"CWE-502\"]}"),
        "unmapped fields in feed order: {}",
        log4j.1
    );
    assert_eq!(sync(&switch_py, &fixture, json!({})).await["status"], "ok");

    // 2. the same feed again (no change)
    let (a, b) = both(&py, &rs, &fixture, json!({})).await;
    check_entries(&a, &b, "second sync");
    same("second sync");

    // 3. an update: removed, changed and added entries; the switch mirror uses the native importer for it
    let (a, b) = both(&py, &rs, &updated, json!({})).await;
    check_entries(&a, &b, "update");
    same("update");
    let job = sync(&switch_rs, &updated, json!({})).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    assert!(
        job["log"]
            .to_string()
            .contains("kev: native importer: applied state of generation "),
        "{job:#}"
    );
    assert_mirrors_equal(
        &python,
        py_store.mirror_path(),
        switch_store.mirror_path(),
        "switch from py-sources to the native importer",
        TIMESTAMPS,
        &[],
    );

    // 3a. a failed and a limited Python run after the native one: staging is stale, nothing is applied (review M1)
    let a_dir = dir.path().join("a-directory.json");
    std::fs::create_dir(&a_dir).unwrap();
    for (path, extra, status) in [
        (&a_dir, json!({}), "error"),
        (&fixture, json!({"limit": 3}), "partial"),
    ] {
        let job = sync(&switch_py, path, extra).await;
        let e = entry(&job);
        assert_eq!(e["status"], "error", "{status}: {job:#}");
        let msg = e["message"].as_str().unwrap();
        assert!(
            msg.starts_with(&format!("{status}: "))
                && msg.ends_with(
                    "; not applied: mirror keeps the native importer data until a successful py-sources sync"
                ),
            "{msg}"
        );
        assert_mirrors_equal(
            &python,
            py_store.mirror_path(),
            switch_store.mirror_path(),
            &format!("a {status} Python run after Rust"),
            TIMESTAMPS,
            &[],
        );
        let st = switch_store.applied_state("kev").await.unwrap().unwrap();
        assert_eq!(
            st.generation.as_deref(),
            Some(secmonk_traits::NATIVE_GENERATION)
        );
    }

    // 3b. switch back to py-sources: another generation, repair from the staging export
    let job = sync(&switch_py, &updated, json!({})).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    assert!(
        job["log"]
            .to_string()
            .contains("repaired from the staging export"),
        "{job:#}"
    );
    assert!(
        job["log"].to_string().contains(
            "kev: repair from py-sources export: the last applied batches came from the native importer"
        ),
        "{job:#}"
    );
    assert_mirror_equals_staging(
        &python,
        switch_store.mirror_path(),
        &switch_staging,
        "switch back to py-sources",
    );
    assert_mirrors_equal(
        &python,
        py_store.mirror_path(),
        switch_store.mirror_path(),
        "switch back to py-sources vs py-sources only",
        TIMESTAMPS,
        &[],
    );

    // 4. a limited run (partial, nothing deleted, the cursor kept)
    let (a, b) = both(&py, &rs, &fixture, json!({"limit": 3})).await;
    check_entries(&a, &b, "limit");
    assert_eq!(entry(&b)["status"], "partial");
    same("limit");

    // 5. a snapshot under half of the stored rows is refused; 6. unreadable or invalid input
    let (a, b) = both(&py, &rs, &small, json!({})).await;
    check_entries(&a, &b, "snapshot guard");
    assert_eq!(entry(&b)["status"], "error");
    same("snapshot guard");
    // (a missing path is refused by the engine before any source runs; a directory reaches the source)
    let (a, b) = both(&py, &rs, &a_dir, json!({})).await;
    assert_eq!(entry(&a)["status"], "error");
    check_entries(&a, &b, "unreadable file"); // "[Errno 21] Is a directory: '<path>'" in both
    same("unreadable file");
    let not_json = dir.path().join("not.json");
    std::fs::write(&not_json, "{").unwrap();
    let (a, b) = both(&py, &rs, &not_json, json!({})).await;
    assert_eq!(
        (entry(&a)["status"].clone(), entry(&b)["status"].clone()),
        (json!("error"), json!("error"))
    );
    // json.loads and serde_json word their errors differently: the status row compares without the message
    assert_mirrors_equal(
        &python,
        py_store.mirror_path(),
        rs_store.mirror_path(),
        "invalid JSON",
        &[
            "raw_record.fetched_at",
            "source_sync.last_sync",
            "source_sync.message",
        ],
        &[],
    );

    // 7. forced replacement
    let (a, b) = both(&py, &rs, &small, json!({"full": true})).await;
    check_entries(&a, &b, "full");
    same("full");

    // 8. repair: the Rust mirror is reset (a new file); the next native sync rebuilds kev and source_sync. Raw
    // records of CVEs that left the feed are not restored (py-sources would restore them from staging; ADR-0011).
    let reset = d.store("rs-reset").await;
    let rs2 = d.engine(&reset, vec![native(&reset)]);
    let (a, b) = both(&py, &rs2, &fixture, json!({})).await;
    check_entries(&a, &b, "after a mirror reset");
    assert_mirrors_equal(
        &python,
        py_store.mirror_path(),
        reset.mirror_path(),
        "after a mirror reset",
        TIMESTAMPS,
        &[
            "kev",
            "source_sync",
            "vulnerability",
            "alias",
            "affected",
            "epss",
            "distro_triage",
        ],
    );

    d.close().await;
}

/// gzip of `data` (test-time fixture variants).
fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// The EUVD fixture with EPSS scores for a CVE of the FIRST file (`CVE-2021-44228`, score `log4j`) and for a CVE
/// the FIRST file lacks (`CVE-2099-0001`, score `other`). Synthetic additions; written to `dir/name`.
fn euvd_variant(fixture: &Path, dir: &Path, name: &str, log4j: f64, other: f64) -> PathBuf {
    let mut doc: Value = serde_json::from_slice(&std::fs::read(fixture).unwrap()).unwrap();
    let items = doc["items"].as_array_mut().unwrap();
    items[0]["epss"] = json!(log4j);
    let mut extra = items[0].clone();
    extra["id"] = json!("EUVD-2099-00001");
    extra["aliases"] = json!("CVE-2099-0001");
    extra["description"] = json!("Synthetic record of the epss differential test (no real CVE).");
    extra["epss"] = json!(other);
    extra["dateUpdated"] = json!("2026-10-01T00:00:00.000Z");
    items.push(extra);
    doc["total"] = json!(items.len());
    let p = dir.join(name);
    std::fs::write(&p, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
    p
}

/// The EPSS fixture changed: two rows removed, two scores changed, two rows added, a later `score_date`; gzipped.
fn epss_update(fixture: &Path, dir: &Path) -> PathBuf {
    let text = std::fs::read_to_string(fixture).unwrap();
    let mut out = String::new();
    for line in text.lines() {
        let line = line.replace("score_date:2026-11-06", "score_date:2026-11-07");
        if line.starts_with("CVE-2019-0708") || line.starts_with("CVE-2020-1472") {
            continue; // removed: the stored rows stay (the Python source never deletes)
        }
        let line = match line.split(',').next() {
            Some("CVE-2021-44228") => "CVE-2021-44228,0.97500,0.99990".to_owned(),
            Some("CVE-2023-0001") => "CVE-2023-0001,0.00051,0.05000".to_owned(),
            _ => line,
        };
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str("CVE-2026-99998,0.00010,0.01000\nCVE-2026-99999,0.00020,0.02000\n");
    let p = dir.join("epss-update.csv.gz");
    std::fs::write(&p, gzip(out.as_bytes())).unwrap();
    p
}

/// Lines the parser must treat as the Python source does: comment and header variants, whitespace (also
/// non-breaking), CRLF, lower-case ids, extra columns, short and non-numeric lines, `_` in numbers, exponents, Unicode
/// decimal digits, a NaN
/// (NULL), an empty id, duplicates (the later one is stored), a `score_date` change in the middle. Synthetic.
const EPSS_ODD: &str = "CVE-1999-0001,0.1,0.2\n\
    \x20 #model_version:v1,score_date:2026-01-02T00:00:00+0000\n\
    CVE,EPSS,PERCENTILE\n\
    \n\
    \x20 cve-1999-0002 , 0.3 , 0.4 ,extra\r\n\
    CVE-1999-0003,not-a-number,0.5\n\
    CVE-1999-0004,0.5\n\
    CVE-1999-0005,1_0e-1,+.5\n\
    CVE-1999-0006,2.5E-05,1\n\
    CVE-1999-0007,nan,0.5\n\
    CVE-1999-0008,1__0,0.5\n\
    \u{a0}CVE-1999-0009\u{a0},0.25\u{a0},0.75\n\
    CVE-1999-0010,\u{ff10}.\u{ff15},\u{660}.\u{667}\u{665}\n\
    ,0.6,0.6\n\
    #no date here\n\
    #score_date:2026-01-03\n\
    CVE-1999-0002,0.6,0.7";

#[tokio::test(flavor = "multi_thread")]
async fn native_epss_matches_py_sources() {
    // Stage 6 differential test (component-lifecycle.md) for epss: py-sources' epss and the native one, each through
    // the engine on its own mirror, leave identical mirrors (run timestamps aside) after every step. EUVD-provided
    // scores (source 'euvd') are synced through py-sources on both mirrors, so the ownership rule of the sourceless
    // epss key is compared too. A third mirror switches py-sources -> native -> py-sources.
    let root = rust_root();
    let fixture = root.join("../tests/fixtures/sources/epss/epss_scores-sample.csv");
    let euvd_fixture = root.join("../tests/fixtures/sources/euvd/exploited-sample.json");
    let Some(mut d) = Diff::new(&[&fixture, &euvd_fixture]).await else {
        return;
    };
    let python = d.python.clone();
    let dir = tempfile::tempdir().unwrap();
    let (py_store, rs_store, switch_store) = (
        d.store("py").await,
        d.store("rs").await,
        d.store("switch").await,
    );
    let (py_src, _) = d.py_sources(&py_store, "modules-py");
    let (rs_py_src, _) = d.py_sources(&rs_store, "modules-rs"); // euvd on the Rust mirror
    let (switch_src, switch_staging) = d.py_sources(&switch_store, "modules-switch");
    let native = |store: &SqliteStore| -> Arc<dyn Source> {
        Arc::new(secmonk_sources::epss::EpssSource::new(Diff::view(store)))
    };
    let py = d.engine(&py_store, vec![py_src]);
    let rs = d.engine(&rs_store, vec![native(&rs_store), rs_py_src]);
    let switch_py = d.engine(&switch_store, vec![switch_src.clone()]);
    let switch_rs = d.engine(&switch_store, vec![native(&switch_store), switch_src]);

    const TIMESTAMPS: &[&str] = &["raw_record.fetched_at", "source_sync.last_sync"];
    let compare = |other: &SqliteStore, what: &str, ignore: &[&str]| {
        assert_mirrors_equal(
            &python,
            py_store.mirror_path(),
            other.mirror_path(),
            what,
            ignore,
            &[],
        );
    };
    let same = |what: &str| compare(&rs_store, what, TIMESTAMPS);
    // both versions on the same input: same entry and the same mirror; returns the Rust job
    let step = |path: PathBuf, extra: Value, what: &'static str| {
        let (py, rs) = (py.clone(), rs.clone());
        async move {
            let a = sync_job(&py, &["epss"], &path, extra.clone()).await;
            let b = sync_job(&rs, &["epss"], &path, extra).await;
            check_entries(&a, &b, what);
            b
        }
    };
    let euvd = |path: PathBuf| {
        let engines = [py.clone(), rs.clone(), switch_py.clone()];
        async move {
            for e in engines {
                let job = sync_job(&e, &["euvd"], &path, json!({})).await;
                assert_eq!(entry_of(&job)["status"], "ok", "{job:#}");
            }
        }
    };
    let epss_rows = |store: &SqliteStore, source: &'static str| {
        let store = store.clone();
        async move {
            store
                .count_rows(secmonk_model::MirrorTable::Epss, source)
                .await
                .unwrap()
        }
    };

    // 0. EUVD scores first: one for a CVE of the FIRST file, one for a CVE it lacks
    euvd(euvd_variant(
        &euvd_fixture,
        dir.path(),
        "euvd-1.json",
        0.5,
        0.25,
    ))
    .await;
    same("euvd before epss");
    assert_eq!(epss_rows(&rs_store, "euvd").await, 2);

    // 1. first sync: FIRST replaces the EUVD row of its CVE, the other EUVD row stays
    let b = step(fixture.clone(), json!({}), "first sync").await;
    assert_eq!(entry_of(&b)["status"], "ok", "{b:#}");
    assert_eq!(entry_of(&b)["records"], 10);
    same("first sync");
    assert_eq!(
        (
            epss_rows(&rs_store, "epss").await,
            epss_rows(&rs_store, "euvd").await
        ),
        (10, 1),
        "the comparison is not vacuous"
    );
    assert_eq!(
        sync_job(&switch_py, &["epss"], &fixture, json!({})).await["status"],
        "ok"
    );

    // 2. the same file again (no change)
    step(fixture.clone(), json!({}), "second sync").await;
    same("second sync");

    // 3. an update (gzip): removed rows stay, changed rows change, new rows are added
    let updated = epss_update(&fixture, dir.path());
    let b = step(updated.clone(), json!({}), "update").await;
    assert_eq!(entry_of(&b)["records"], 10);
    same("update");
    assert_eq!(epss_rows(&rs_store, "epss").await, 12);
    // the switch mirror: native importer for the same update
    let job = sync_job(&switch_rs, &["epss"], &updated, json!({})).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    assert!(
        job["log"]
            .to_string()
            .contains("epss: native importer: applied state of generation "),
        "{job:#}"
    );
    // (the switch mirror has no EUVD rows: compare the epss rows of source 'epss' and the epss sync state)
    let only_epss = |what: &str| {
        let out = std::process::Command::new(&python)
            .arg("-I")
            .arg("-c")
            .arg(
                "import sqlite3, sys\n\
                 q = \"SELECT cve_id, score, percentile, date, source FROM epss WHERE source='epss' ORDER BY cve_id\"\n\
                 s = \"SELECT source, cursor, records, status, message FROM source_sync WHERE source='epss'\"\n\
                 a, b = sqlite3.connect(sys.argv[1]), sqlite3.connect(sys.argv[2])\n\
                 sys.exit(0 if a.execute(q).fetchall() == b.execute(q).fetchall() and a.execute(s).fetchall() == b.execute(s).fetchall() else 1)\n",
            )
            .arg(py_store.mirror_path())
            .arg(switch_store.mirror_path())
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{what}: epss rows differ: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    only_epss("switch from py-sources to the native importer");

    // 3a. a failed and a limited Python run after the native one: nothing applied, native state kept
    let a_dir = dir.path().join("a-directory.csv");
    std::fs::create_dir(&a_dir).unwrap();
    for (path, extra, status) in [
        (&a_dir, json!({}), "error"),
        (&fixture, json!({"limit": 3}), "partial"),
    ] {
        let job = sync_job(&switch_py, &["epss"], path, extra).await;
        let e = entry_of(&job);
        assert_eq!(e["status"], "error", "{status}: {job:#}");
        assert!(
            e["message"].as_str().unwrap().ends_with(
                "; not applied: mirror keeps the native importer data until a successful py-sources sync"
            ),
            "{job:#}"
        );
        only_epss(&format!("a {status} Python run after Rust"));
        let st = switch_store.applied_state("epss").await.unwrap().unwrap();
        assert_eq!(
            st.generation.as_deref(),
            Some(secmonk_traits::NATIVE_GENERATION)
        );
    }

    // 3b. switch back to py-sources: repair from the staging export
    let job = sync_job(&switch_py, &["epss"], &updated, json!({})).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    assert!(
        job["log"].to_string().contains(
            "epss: repair from py-sources export: the last applied batches came from the native importer"
        ),
        "{job:#}"
    );
    assert_mirror_equals_staging(
        &python,
        switch_store.mirror_path(),
        &switch_staging,
        "switch back to py-sources",
    );
    only_epss("switch back to py-sources vs py-sources only");

    // 4. EUVD again with other scores: its own row changes, the FIRST row of the shared CVE does not
    euvd(euvd_variant(
        &euvd_fixture,
        dir.path(),
        "euvd-2.json",
        0.1,
        0.3,
    ))
    .await;
    same("euvd after epss");

    // 5. parser edge cases (forced: fewer rows than stored)
    let odd = dir.path().join("odd.csv");
    std::fs::write(&odd, EPSS_ODD).unwrap();
    let b = step(odd.clone(), json!({"full": true}), "odd lines").await;
    assert_eq!(entry_of(&b)["status"], "ok", "{b:#}");
    same("odd lines");

    // 6. a limited run (partial, cursor kept)
    let b = step(fixture.clone(), json!({"limit": 3}), "limit").await;
    assert_eq!(entry_of(&b)["status"], "partial");
    same("limit");

    // 7. guard: a file under half of the stored rows; an empty file (also with --full)
    let small = dir.path().join("small.csv");
    let head: String = std::fs::read_to_string(&fixture)
        .unwrap()
        .lines()
        .take(5)
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&small, head).unwrap();
    let b = step(small.clone(), json!({}), "snapshot guard").await;
    assert_eq!(entry_of(&b)["status"], "error");
    same("snapshot guard");
    let empty = dir.path().join("empty.csv");
    std::fs::write(&empty, "#score_date:2026-11-08\ncve,epss,percentile\n").unwrap();
    for full in [false, true] {
        let b = step(empty.clone(), json!({"full": full}), "empty file").await;
        assert_eq!(entry_of(&b)["status"], "error");
        same("empty file");
    }

    // 8. unreadable or broken input: same status and message
    let cut = gzip(std::fs::read(&fixture).unwrap().as_slice());
    let truncated = dir.path().join("truncated.csv.gz");
    std::fs::write(&truncated, &cut[..cut.len() / 2]).unwrap();
    let long = dir.path().join("long.csv");
    std::fs::write(&long, "x".repeat(70_000)).unwrap();
    for (path, what) in [
        (&a_dir, "a directory"),
        (&truncated, "truncated gzip"),
        (&long, "a line over 64 KiB"),
    ] {
        let b = step(path.clone(), json!({}), what).await;
        assert_eq!(entry_of(&b)["status"], "error", "{what}");
        same(what);
    }
    // invalid UTF-8: same status, Python's message names the reason (`invalid start byte`)
    let bad = dir.path().join("bad-utf8.csv");
    std::fs::write(&bad, b"CVE-1,0.1,0.2\nCVE-\xff,0.1,0.2\n").unwrap();
    let a = sync_job(&py, &["epss"], &bad, json!({})).await;
    let b = sync_job(&rs, &["epss"], &bad, json!({})).await;
    assert_eq!(
        (
            entry_of(&a)["status"].clone(),
            entry_of(&b)["status"].clone()
        ),
        (json!("error"), json!("error"))
    );
    let (ma, mb) = (
        entry_of(&a)["message"].as_str().unwrap().to_owned(),
        entry_of(&b)["message"].as_str().unwrap().to_owned(),
    );
    assert!(ma.starts_with(&mb), "py: {ma}\nrs: {mb}");
    compare(
        &rs_store,
        "invalid UTF-8",
        &[
            "raw_record.fetched_at",
            "source_sync.last_sync",
            "source_sync.message",
        ],
    );

    // 9. forced replacement with a small file
    step(small.clone(), json!({"full": true}), "full").await;
    same("full");

    d.close().await;
}

/// A synthetic EPSS file of `n` rows in the real file's layout (comment line, header, `cve,epss,percentile`), gzipped.
fn synthetic_epss(n: usize, date: &str, salt: u64) -> Vec<u8> {
    let mut text =
        format!("#model_version:v2025.03.14,score_date:{date}T12:55:00Z\ncve,epss,percentile\n");
    for i in 0..n {
        let year = 1999 + (i / 40_000);
        let h = (i as u64).wrapping_mul(2_654_435_761).wrapping_add(salt) % 100_000;
        text.push_str(&format!(
            "CVE-{year}-{:05},0.{h:05},0.{:05}\n",
            i % 100_000,
            99_999 - h
        ));
    }
    gzip(text.as_bytes())
}

// Volume measurements (source-epss.md "Volume"). Ignored: run by hand, each in its own process so that the peak
// resident set (`/usr/bin/time -l <test binary> --ignored --exact <name>`) belongs to one measurement:
// `epss_volume_baseline` (the file and a store, nothing else), `epss_volume_native_stream` (parse, guard and every
// batch built, nothing applied), `epss_volume_row_keys` (the read of all keys, which epss itself does not need),
// `epss_volume_sync` (native importer, then py-sources, through the engine: first sync and re-sync with a new
// score_date, so every row changes; py-sources runs in a child process). Rows: `SECMONK_EPSS_ROWS` (400 000);
// `SECMONK_EPSS_FILL_ONLY=1` stops `epss_volume_row_keys` before the read (the peak of the fill alone);
// `SECMONK_EPSS_NATIVE_ONLY=1` runs only the native half of `epss_volume_sync` (its peak without py-sources).

struct Volume {
    d: Diff,
    n: usize,
    day1: PathBuf,
    day2: PathBuf,
    _dir: tempfile::TempDir,
}

async fn volume() -> Option<Volume> {
    let n: usize = std::env::var("SECMONK_EPSS_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400_000);
    let d = Diff::new(&[]).await?;
    let dir = tempfile::tempdir().unwrap();
    let day1 = dir.path().join("day1.csv.gz");
    let day2 = dir.path().join("day2.csv.gz");
    std::fs::write(&day1, synthetic_epss(n, "2026-11-10", 1)).unwrap();
    std::fs::write(&day2, synthetic_epss(n, "2026-11-11", 7)).unwrap();
    eprintln!(
        "epss volume: {n} rows, gzip {} KiB",
        std::fs::metadata(&day1).unwrap().len() / 1024
    );
    Some(Volume {
        d,
        n,
        day1,
        day2,
        _dir: dir,
    })
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "volume measurement, run by hand (source-epss.md)"]
async fn epss_volume_baseline() {
    let Some(mut v) = volume().await else { return };
    let _store = v.d.store("baseline").await;
    v.d.close().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "volume measurement, run by hand (source-epss.md)"]
async fn epss_volume_native_stream() {
    let Some(mut v) = volume().await else { return };
    let store = v.d.store("scratch").await;
    let src = secmonk_sources::epss::EpssSource::new(Diff::view(&store));
    let t = std::time::Instant::now();
    let params: secmonk_traits::SyncParams = serde_json::from_value(
        json!({"source": "epss", "options": {"path": v.day1.display().to_string()}}),
    )
    .unwrap();
    let mut stream = src.sync(params, CallCtx::default()).await.unwrap();
    let (mut batches, mut first_at, mut ops) = (0u64, 0.0, 0usize);
    while let Some(m) = futures_util::StreamExt::next(&mut stream).await {
        if let secmonk_traits::StreamMsg::Item(b) = m.unwrap() {
            batches += 1;
            ops += b.ops.len();
            if batches == 1 {
                first_at = t.elapsed().as_secs_f64();
            }
        }
    }
    assert_eq!(ops, v.n + 1);
    eprintln!(
        "epss volume: native stream: first batch after {first_at:.2} s (download aside: parse + guard), all {batches} \
         batches built in {:.2} s",
        t.elapsed().as_secs_f64()
    );
    v.d.close().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "volume measurement, run by hand (source-epss.md)"]
async fn epss_volume_row_keys() {
    let Some(mut v) = volume().await else { return };
    let store = v.d.store("keys").await;
    // fill the mirror with n epss rows, one batch at a time (low memory)
    let mut seq = 0;
    for chunk in (0..v.n).collect::<Vec<_>>().chunks(5000) {
        seq += 1;
        let ops: Vec<Value> = chunk
            .iter()
            .map(|i| json!({"op": "upsert", "table": "epss", "row": {"cve_id": format!("CVE-{}-{:05}", 1999 + i / 40_000, i % 100_000),
                     "score": 0.5, "percentile": 0.5, "date": "2026-11-10", "source": "epss"}}))
            .collect();
        let batch: secmonk_model::RowsBatch = serde_json::from_value(
            json!({"kind": "rows", "seq": seq, "source": "epss", "ops": ops}),
        )
        .unwrap();
        store.apply_rows(&batch).await.unwrap();
    }
    if std::env::var("SECMONK_EPSS_FILL_ONLY").as_deref() == Ok("1") {
        // the peak of the fill alone, to subtract from the run with the read
        v.d.close().await;
        return;
    }
    let view = Diff::view(&store);
    let t = std::time::Instant::now();
    let c = view
        .count_rows(secmonk_model::MirrorTable::Epss, "epss")
        .await
        .unwrap();
    let count_s = t.elapsed().as_secs_f64();
    let t = std::time::Instant::now();
    let keys = view
        .row_keys(secmonk_model::MirrorTable::Epss, "epss")
        .await
        .unwrap();
    eprintln!(
        "epss volume: count_rows {c} in {count_s:.3} s; row_keys {} keys in {:.2} s",
        keys.len(),
        t.elapsed().as_secs_f64()
    );
    drop(keys);
    v.d.close().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "volume measurement, run by hand (source-epss.md)"]
async fn epss_volume_sync() {
    let Some(mut v) = volume().await else { return };
    let rs_store = v.d.store("rs").await;
    let rs = v.d.engine(
        &rs_store,
        vec![Arc::new(secmonk_sources::epss::EpssSource::new(Diff::view(
            &rs_store,
        ))) as Arc<dyn Source>],
    );
    let py_store = v.d.store("py").await;
    let (py_src, _) = v.d.py_sources(&py_store, "modules-py");
    let py = v.d.engine(&py_store, vec![py_src]);
    let mut report = Vec::new();
    let native_only = std::env::var("SECMONK_EPSS_NATIVE_ONLY").as_deref() == Ok("1");
    for (name, engine) in [("native", &rs), ("py-sources", &py)] {
        if native_only && name != "native" {
            continue;
        }
        for (what, path) in [("first sync", &v.day1), ("re-sync", &v.day2)] {
            let t = std::time::Instant::now();
            let job = sync_job_secs(engine, &["epss"], path, json!({}), 900).await;
            assert_eq!(entry_of(&job)["status"], "ok", "{job:#}");
            report.push(format!("{name} {what}: {:.1} s", t.elapsed().as_secs_f64()));
        }
    }
    if native_only {
        eprintln!("epss volume: {}", report.join("; "));
        v.d.close().await;
        return;
    }
    assert_mirrors_equal(
        &v.d.python,
        py_store.mirror_path(),
        rs_store.mirror_path(),
        "volume",
        &["source_sync.last_sync"],
        &["epss", "source_sync"],
    );
    eprintln!("epss volume: {}", report.join("; "));
    v.d.close().await;
}
