//! Shared by the tests over the real Python modules (`py-sources`, `py-engine`) of `rust/python`, started from the
//! dev venv `rust/python/.venv` (no uv): `real_modules.rs` and the per-source differential tests `native_<source>.rs`
//! (one file per native importer, so importers are ported in parallel without editing a shared test file; template:
//! rust/_docs/tech/component-lifecycle.md "Porting a source to a native importer"). Gated: a test is skipped when the
//! venv is missing, and fails instead with `SECMONK_REQUIRE_VENV=1`.
//!
//! Only these tests name the module host: the engine itself receives trait objects (architecture.md §2);
//! `rust/deny.toml` lists `secmonk-engine` as a dev-only wrapper of `secmonk-modhost`.

#![allow(dead_code, unreachable_pub, unused_imports)]

// re-exported: the test files `use common::*`
pub use std::collections::BTreeMap;
pub use std::ffi::OsString;
pub use std::path::{Path, PathBuf};
pub use std::sync::Arc;
pub use std::time::Duration;

pub use async_trait::async_trait;
pub use secmonk_config::{Config, LoadOptions};
pub use secmonk_engine::{EngineConfig, EngineDeps, EngineService, FindingsQuery, SecmonkEngine};
pub use secmonk_model::{Asset, Category, Component, Inventory};
pub use secmonk_modhost::adapters::{PyEngine, PySource};
pub use secmonk_modhost::hello::HostSettings;
pub use secmonk_modhost::registry::Registry;
pub use secmonk_modhost::supervisor::ModuleHandle;
pub use secmonk_runtime::{
    EnvInfo, LaunchSpec, PythonRuntime, RuntimeError, RuntimeInfo, RuntimeResult,
};
pub use secmonk_store::{MirrorStore, SqliteStore, StateStore, StoreOptions};
pub use secmonk_traits::{
    CallCtx, CollectEnd, CollectItem, CollectParams, Collector, CollectorInfo, Probe, ResultStream,
    Source, StepResult, WireError,
};
pub use serde_json::{Value, json};

pub fn rust_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// Whether the dev venv and the fixtures exist. Missing: the test is skipped, or fails when `SECMONK_REQUIRE_VENV=1`
/// (CI and release checks must run these tests, not skip them).
pub fn available(paths: &[&Path], what: &str) -> bool {
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
pub struct DevVenv {
    pub python: PathBuf,
    pub config: Config,
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

/// A runtime that adds `env` to every module it launches (test-only hooks such as `SECMONK_TEST_NVD_HOOK`, which the
/// host never passes to a module).
pub struct EnvRuntime {
    pub inner: Arc<dyn PythonRuntime>,
    pub env: Vec<(String, OsString)>,
}

#[async_trait]
impl PythonRuntime for EnvRuntime {
    async fn ensure(&self) -> RuntimeResult<RuntimeInfo> {
        self.inner.ensure().await
    }

    async fn ensure_env(&self, project: &Path, env: &str) -> RuntimeResult<EnvInfo> {
        self.inner.ensure_env(project, env).await
    }

    fn command(&self, env: &str, entry: &[String]) -> RuntimeResult<LaunchSpec> {
        self.command_for(env, entry, &["read-target", "network"])
    }

    fn command_for(&self, env: &str, entry: &[String], caps: &[&str]) -> RuntimeResult<LaunchSpec> {
        let mut spec = self.inner.command_for(env, entry, caps)?;
        for (k, v) in &self.env {
            spec.env.insert(k.clone(), v.clone());
        }
        Ok(spec)
    }
}

/// No collectors: this test drives sources and engine steps only (the probe has its own tests).
pub struct NoProbe;

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

/// The config of a test data directory. The modules get 120 s for their `hello` (the manifest default is 20 s): under
/// a full `cargo test --workspace` many Python modules start at once, and a slow start is not what these tests check.
pub fn config(dir: &Path) -> Config {
    let file = dir.join("sec-monk.toml");
    let text = format!(
        "config_version = 1\ndata_dir = {:?}\n[modules]\npython_project = {:?}\nenabled = [\"py-engine\", \
         \"py-sources\"]\ntrust = \"dev\"\n[modules.py-sources]\nhello_timeout_s = 120\n\
         [modules.py-engine]\nhello_timeout_s = 120\n",
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

pub async fn wait_job(engine: &SecmonkEngine, id: u64) -> Value {
    wait_job_secs(engine, id, 60).await
}

pub async fn wait_job_secs(engine: &SecmonkEngine, id: u64, secs: u64) -> Value {
    for _ in 0..secs * 20 {
        let j = engine.job_get(id).await.unwrap();
        if j["status"] != "running" {
            return j;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("job {id} did not finish in {secs} s");
}

/// Compare the host's mirror with the module's staging database, table by table and row by row (duplicates count,
/// JSON normalized), with the dev venv's Python: the W2.2 round-trip check, over the Rust store.
pub fn assert_mirror_equals_staging(python: &Path, mirror: &Path, staging: &Path, what: &str) {
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

/// Compare two mirror databases table by table and row by row (duplicates count, JSON normalized), ignoring the
/// `table.column`s in `ignore` (run timestamps) and comparing only `tables` (all mirror tables when empty).
pub fn assert_mirrors_equal(
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
pub struct Diff {
    pub python: PathBuf,
    pub config: Config,
    pub registry: Registry,
    pub runtime: Arc<dyn PythonRuntime>,
    pub steps: Arc<PyEngine>,
    pub handles: Vec<ModuleHandle>,
    pub stores: Vec<SqliteStore>,
    pub engines: Vec<Arc<SecmonkEngine>>,
    _dir: tempfile::TempDir,
}

impl Diff {
    /// `None` when the dev venv or a fixture is missing (skipped; fails with `SECMONK_REQUIRE_VENV=1`).
    pub async fn new(fixtures: &[&Path]) -> Option<Diff> {
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

    pub fn settings(store: &SqliteStore, modules_root: PathBuf) -> HostSettings {
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
    pub async fn store(&mut self, name: &str) -> SqliteStore {
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
    pub fn py_sources(&mut self, store: &SqliteStore, modules: &str) -> (Arc<dyn Source>, PathBuf) {
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

    /// [`Diff::py_sources`] whose module process also gets `env` ([`EnvRuntime`]).
    pub fn py_sources_env(
        &mut self,
        store: &SqliteStore,
        modules: &str,
        env: &[(&str, &Path)],
    ) -> (Arc<dyn Source>, PathBuf) {
        let root = self.config.data_dir.join(modules);
        std::fs::create_dir_all(&root).unwrap();
        let runtime: Arc<dyn PythonRuntime> = Arc::new(EnvRuntime {
            inner: self.runtime.clone(),
            env: env
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.as_os_str().to_os_string()))
                .collect(),
        });
        let h = ModuleHandle::python(
            self.registry.get("py-sources").unwrap(),
            runtime,
            Diff::settings(store, root.clone()),
        );
        self.handles.push(h.clone());
        (
            Arc::new(PySource::new(h)),
            root.join("py-sources/staging.sqlite3"),
        )
    }

    /// An engine over `store` with `sources` (in order of precedence).
    pub fn engine(
        &mut self,
        store: &SqliteStore,
        sources: Vec<Arc<dyn Source>>,
    ) -> Arc<SecmonkEngine> {
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
            node_store: None,
        });
        self.engines.push(e.clone());
        e
    }

    pub fn view(store: &SqliteStore) -> Arc<dyn secmonk_traits::MirrorView> {
        Arc::new(secmonk_engine::StoreMirrorView::new(Arc::new(
            store.clone(),
        )))
    }

    pub async fn close(self) {
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
pub async fn sync_job(
    engine: &SecmonkEngine,
    sources: &[&str],
    path: &Path,
    extra: Value,
) -> Value {
    sync_job_secs(engine, sources, path, extra, 60).await
}

pub async fn sync_job_secs(
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
pub fn entry_of(job: &Value) -> Value {
    job["result"]["sources"][0].clone()
}

/// Both versions' entries agree on status, records and message.
pub fn check_entries(a: &Value, b: &Value, what: &str) {
    for k in ["status", "records", "message"] {
        assert_eq!(
            entry_of(a)[k],
            entry_of(b)[k],
            "{what}: entry {k}\npy: {a:#}\nrs: {b:#}"
        );
    }
}

/// gzip of `data` (test-time fixture variants).
pub fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// The EUVD fixture with EPSS scores for a CVE of the FIRST file (`CVE-2021-44228`, score `log4j`) and for a CVE
/// the FIRST file lacks (`CVE-2099-0001`, score `other`). Synthetic additions; written to `dir/name`.
pub fn euvd_variant(fixture: &Path, dir: &Path, name: &str, log4j: f64, other: f64) -> PathBuf {
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

/// Compare the rows of `source` in two mirror databases: every table in `tables` (`WHERE source = ?`; for
/// `source_sync` the source's own row), duplicates counted, JSON normalized, `ignore`d `table.column`s left out. For a
/// mirror that went through another history of the other sources (a switch mirror without the FIRST epss rows).
pub fn assert_source_rows_equal(
    python: &Path,
    a: &Path,
    b: &Path,
    source: &str,
    what: &str,
    ignore: &[&str],
    tables: &[&str],
) {
    let script = "import json, sqlite3, sys\n\
                  J = {'data', 'cwes', 'extra', 'events', 'versions'}\n\
                  SRC = sys.argv[3]\n\
                  IGN = set(filter(None, sys.argv[4].split(',')))\n\
                  T = list(filter(None, sys.argv[5].split(',')))\n\
                  def rows(c, t):\n\
                  \x20   cols = [r[1] for r in c.execute(f'PRAGMA table_info({t})') if r[1] != 'rowid_' and f'{t}.{r[1]}' not in IGN]\n\
                  \x20   out = [tuple(json.dumps(json.loads(v), sort_keys=True) if k in J and isinstance(v, str) else v\n\
                  \x20                for k, v in zip(cols, r)) for r in c.execute(f\"SELECT {', '.join(cols)} FROM {t} WHERE source = ?\", (SRC,))]\n\
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
        .arg(source)
        .arg(ignore.join(","))
        .arg(tables.join(","))
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{what}: the {source} rows differ:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Validate `{schema ref: [values]}` with `rust/python/tests/contracts.py` in the dev venv. `None` = no venv (skipped;
/// fails with `SECMONK_REQUIRE_VENV=1`).
pub fn check_contracts(cases: &[(&str, Value)]) -> Option<()> {
    let root = rust_root();
    let py = root.join("python/.venv/bin/python");
    if !available(&[&py], "contract check") {
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("cases.json");
    let cases: Vec<Value> = cases.iter().map(|(r, v)| json!([r, v])).collect();
    std::fs::write(&data, serde_json::to_vec(&cases).unwrap()).unwrap();
    let script = "import json, sys\n\
                  sys.path.insert(0, sys.argv[1])\n\
                  from tests.contracts import errors\n\
                  bad = []\n\
                  for ref, value in json.load(open(sys.argv[2])):\n\
                  \x20   bad += [f'{ref}: {e}' for e in errors(ref, value)]\n\
                  print('\\n'.join(bad))\n\
                  sys.exit(1 if bad else 0)\n";
    let out = std::process::Command::new(&py)
        .arg("-I")
        .arg("-c")
        .arg(script)
        .arg(root.join("python"))
        .arg(&data)
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "payloads do not satisfy the contracts:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Some(())
}

/// The row-contract check of a native importer: run `src` directly (no engine) once per `options`, apply every
/// batch to `store` (none may be skipped), and validate every batch and end against `source/rows.schema.json` and
/// `source/sync-end.schema.json`. Returns the number of `delete` operations seen (a test asserts the deletes it
/// expects are among the cases).
pub async fn check_row_contract(
    src: &dyn Source,
    store: &SqliteStore,
    source: &str,
    runs: &[Value],
) -> usize {
    use futures_util::StreamExt;
    let mut cases: Vec<(&str, Value)> = Vec::new();
    for options in runs {
        let params: secmonk_traits::SyncParams =
            serde_json::from_value(json!({"source": source, "options": options})).unwrap();
        let mut stream = src.sync(params, CallCtx::default()).await.unwrap();
        while let Some(m) = stream.next().await {
            match m.unwrap() {
                secmonk_traits::StreamMsg::Item(b) => {
                    assert!(!store.apply_rows(&b).await.unwrap().skipped);
                    cases.push(("source/rows.schema.json", serde_json::to_value(&b).unwrap()));
                }
                secmonk_traits::StreamMsg::End(e) => cases.push((
                    "source/sync-end.schema.json",
                    serde_json::to_value(&e).unwrap(),
                )),
            }
        }
    }
    let deletes = cases
        .iter()
        .map(|(_, v)| v.to_string().matches(r#""op":"delete""#).count())
        .sum();
    check_contracts(&cases);
    deletes
}
