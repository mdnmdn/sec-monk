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
    for _ in 0..1200 {
        let j = engine.job_get(id).await.unwrap();
        if j["status"] != "running" {
            return j;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("job {id} did not finish in 60 s");
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
    let root = rust_root();
    let python = root.join("python/.venv/bin/python");
    let fixture = root.join("../tests/fixtures/sources/kev/known_exploited_vulnerabilities.json");
    if !available(&[&python, &fixture], "differential test") {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = config(dir.path());
    let layout = config.layout();
    layout.create().unwrap();
    let registry = Registry::load_dir(&root.join("python/modules"), &config).unwrap();
    let runtime: Arc<dyn PythonRuntime> = Arc::new(DevVenv {
        python: python.clone(),
        config: config.clone(),
    });
    let open = |n: &str| {
        let db = config.data_dir.join(format!("db-{n}"));
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
    let (py_store, rs_store, switch_store) =
        (open("py").await, open("rs").await, open("switch").await);
    // one py-sources per python-written mirror: its staging (module_dir) belongs to that mirror
    let py_sources = |store: &SqliteStore, modules: &str| {
        let settings = HostSettings {
            min_confidence: 0.5,
            state_db: Some(store.state_path().to_path_buf()),
            mirror_db: Some(store.mirror_path().to_path_buf()),
            allow_db_read: true,
            process_target: None,
            process_options: Vec::new(),
            modules_root: Some(config.data_dir.join(modules)),
        };
        std::fs::create_dir_all(config.data_dir.join(modules)).unwrap();
        ModuleHandle::python(
            registry.get("py-sources").unwrap(),
            runtime.clone(),
            settings,
        )
    };
    let (py_h, switch_h) = (
        py_sources(&py_store, "modules-py"),
        py_sources(&switch_store, "modules-switch"),
    );
    let switch_staging = config
        .data_dir
        .join("modules-switch/py-sources/staging.sqlite3");
    let engine_h = ModuleHandle::python(
        registry.get("py-engine").unwrap(),
        runtime.clone(),
        HostSettings {
            min_confidence: 0.5,
            state_db: Some(py_store.state_path().to_path_buf()),
            mirror_db: Some(py_store.mirror_path().to_path_buf()),
            allow_db_read: true,
            process_target: None,
            process_options: Vec::new(),
            modules_root: Some(layout.modules()),
        },
    );
    let steps = Arc::new(PyEngine::new(engine_h.clone()));
    let native = |store: &SqliteStore| -> Arc<dyn Source> {
        let view = secmonk_engine::StoreMirrorView::new(Arc::new(store.clone()));
        Arc::new(secmonk_sources::kev::KevSource::new(Arc::new(view)))
    };
    let engine_over = |store: &SqliteStore, source: Arc<dyn Source>| {
        let mut ec = EngineConfig::new("0.0.0-test", store.state_path());
        ec.data_dir = config.data_dir.clone();
        ec.nvd_api_key_env = None;
        SecmonkEngine::new(EngineDeps {
            config: ec,
            state: Arc::new(store.clone()),
            mirror: Arc::new(store.clone()),
            steps: steps.clone(),
            procmon: None,
            sources: vec![source],
            probe: Arc::new(NoProbe),
            modules: None,
        })
    };
    let py = engine_over(&py_store, Arc::new(PySource::new(py_h.clone())));
    let rs = engine_over(&rs_store, native(&rs_store));
    let switch_py = engine_over(&switch_store, Arc::new(PySource::new(switch_h.clone())));
    let switch_rs = engine_over(&switch_store, native(&switch_store));

    async fn sync(engine: &SecmonkEngine, path: &Path, extra: Value) -> Value {
        let mut b = json!({"kind": "sync", "sources": ["kev"], "path": path.display().to_string()});
        for (k, v) in extra.as_object().unwrap() {
            b[k] = v.clone();
        }
        let started = engine
            .job_start(b.as_object().cloned().unwrap())
            .await
            .unwrap();
        wait_job(engine, started["id"].as_u64().unwrap()).await
    }
    let entry = |job: &Value| job["result"]["sources"][0].clone();
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
    let check_entries = |a: &Value, b: &Value, what: &str| {
        for k in ["status", "records", "message"] {
            assert_eq!(
                entry(a)[k],
                entry(b)[k],
                "{what}: entry {k}\npy: {a:#}\nrs: {b:#}"
            );
        }
    };
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
    let reset = open("rs-reset").await;
    let rs2 = engine_over(&reset, native(&reset));
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

    for e in [&py, &rs, &rs2, &switch_py, &switch_rs] {
        e.shutdown().await;
    }
    for h in [&py_h, &switch_h, &engine_h] {
        h.shutdown().await;
    }
    for s in [&py_store, &rs_store, &switch_store, &reset] {
        s.close().await;
    }
}
