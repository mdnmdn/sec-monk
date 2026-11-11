//! [`Host`]: the started application core (runtime, stores, module host, probe, engine) and its shutdown.

use std::path::PathBuf;
use std::sync::Arc;

use secmonk_config::{Config, ConfigError};
use secmonk_modhost::adapters::{PyCollector, PyEngine, PySource};
use secmonk_modhost::hello::HostSettings;
use secmonk_modhost::registry::{Registry, RegistryError};
use secmonk_modhost::supervisor::ModuleHandle;
use secmonk_probe::ProbeService;
use secmonk_proto::manifest::{ModuleKind, ModuleRuntime};
use secmonk_runtime::{PythonRuntime, RuntimeError, UvRuntime, UvSettings};
use secmonk_traits::Source;

use crate::startup::{Phase, Progress};

/// Why [`Host::start`] failed. The messages are already free of secrets (the runtime scrubs uv's stderr).
#[derive(Debug, thiserror::Error)]
pub enum HostError {
    /// uv, Python or the module venv.
    #[error("{0}")]
    Runtime(#[from] RuntimeError),
    /// A manifest or a pin.
    #[error("module registry: {0}")]
    Registry(#[from] RegistryError),
    /// The data directory.
    #[error("{0}")]
    Config(#[from] ConfigError),
    /// The stores.
    #[cfg(feature = "engine")]
    #[error("{0}")]
    Store(#[from] secmonk_store::StoreError),
    /// A module that must run at start cannot start.
    #[error("{module}: {message}")]
    Module {
        /// Module name.
        module: String,
        /// Why.
        message: String,
    },
    /// A setting this build cannot honour.
    #[error("{0}")]
    Unsupported(String),
    /// Another instance already runs on this `data_dir`.
    #[error("{0}")]
    InstanceRunning(String),
}

/// Take the exclusive, non-blocking `run/instance.lock` of `layout` (advisory file lock, released when the file
/// closes, also when the process dies). Err = another instance owns the data directory.
fn take_instance_lock(layout: &secmonk_config::layout::Layout) -> Result<std::fs::File, HostError> {
    let path = layout.instance_lock();
    let mut open = std::fs::OpenOptions::new();
    open.create(true).truncate(false).write(true).read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        open.mode(0o600);
    }
    let file = open
        .open(&path)
        .map_err(|e| secmonk_config::ConfigError::io(&path, e))?;
    match file.try_lock() {
        Ok(()) => {
            use std::io::Write as _;
            let _ = file.set_len(0);
            let _ = (&file).write_all(format!("{}\n", std::process::id()).as_bytes());
            Ok(file)
        }
        Err(std::fs::TryLockError::WouldBlock) => Err(HostError::InstanceRunning(format!(
            "another sec-monk instance is already running on {} (lock {}); quit it first",
            layout.root.display(),
            path.display()
        ))),
        Err(std::fs::TryLockError::Error(e)) => {
            Err(secmonk_config::ConfigError::io(&path, e).into())
        }
    }
}

/// The started core. Cheap parts are shared as `Arc`s; keep the `Host` alive until [`Host::shutdown`].
pub struct Host {
    /// The resolved configuration.
    pub config: Arc<Config>,
    /// The module registry (enabled modules, manifests, effective limits).
    pub registry: Registry,
    /// One supervised handle per registered module.
    pub modules: Vec<ModuleHandle>,
    /// The probe service: collector allowlist and fixed probe methods over `py-probe`.
    pub probe: Arc<ProbeService>,
    /// Vulnerability sources: the native ones selected by `[sources.implementation]`, then `py-sources`.
    pub sources: Vec<Arc<dyn Source>>,
    /// Engine steps (`py-engine`): classify, match, versions, scoring, reports.
    pub steps: Option<Arc<PyEngine>>,
    /// Process monitor reports (`py-procmon`).
    pub procmon: Option<Arc<PyEngine>>,
    /// The stores (state and mirror).
    #[cfg(feature = "engine")]
    pub store: secmonk_store::SqliteStore,
    /// The engine behind the API (coerces to `Arc<dyn EngineService>`).
    #[cfg(feature = "engine")]
    pub engine: Arc<secmonk_engine::SecmonkEngine>,
    /// `run/instance.lock`, held until the host is dropped.
    _instance_lock: std::fs::File,
}

impl std::fmt::Debug for Host {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Host")
            .field("data_dir", &self.config.data_dir)
            .field(
                "modules",
                &self
                    .modules
                    .iter()
                    .map(ModuleHandle::name)
                    .collect::<Vec<_>>(),
            )
            .finish_non_exhaustive()
    }
}

/// `file` of a `sqlite://` URL as a path (the stores are SQLite only in the prototype).
#[cfg(feature = "engine")]
fn sqlite_file(url: &str) -> Result<PathBuf, HostError> {
    Config::sqlite_path(url).ok_or_else(|| {
        HostError::Unsupported(format!(
            "database {url:?}: only sqlite:// is supported in this build"
        ))
    })
}

impl Host {
    /// Start everything, first run included: download and verify the pinned uv, install Python and the module
    /// venv inside `data_dir`, open the stores, start the modules, build the engine.
    ///
    /// `progress` is told when each [`Phase`] begins. Dropping the future (cancellation) kills any uv child.
    pub async fn start(
        config: Arc<Config>,
        progress: Progress,
        allow_actions: bool,
    ) -> Result<Host, HostError> {
        config.layout().create()?;
        let lock = take_instance_lock(&config.layout())?;
        progress(Phase::Uv);
        let runtime = Arc::new(UvRuntime::new(UvSettings::from_config(&config)));
        runtime.ensure_uv().await?;
        Self::start_locked(config, runtime, progress, lock, allow_actions).await
    }

    /// [`Host::start`] from the Python phase on, over any [`PythonRuntime`] (tests, offline images). The runtime
    /// must already have uv; `ensure` is still called and is cheap when everything is installed.
    pub async fn start_with(
        config: Arc<Config>,
        runtime: Arc<dyn PythonRuntime>,
        progress: Progress,
    ) -> Result<Host, HostError> {
        config.layout().create()?;
        let lock = take_instance_lock(&config.layout())?;
        Self::start_locked(config, runtime, progress, lock, true).await
    }

    async fn start_locked(
        config: Arc<Config>,
        runtime: Arc<dyn PythonRuntime>,
        progress: Progress,
        instance_lock: std::fs::File,
        allow_actions: bool,
    ) -> Result<Host, HostError> {
        let layout = config.layout();
        // 1. interpreter and module venv
        progress(Phase::Python);
        runtime.ensure().await?;
        let registry = Registry::load_dir(&config.python_project.join("modules"), &config)?;
        progress(Phase::ModuleEnv);
        let mut envs: Vec<String> = Vec::new();
        for e in registry.iter().filter(|e| e.available) {
            if let Some(py) = e
                .manifest
                .python
                .as_ref()
                .filter(|_| e.manifest.runtime == ModuleRuntime::Python)
                && !envs.contains(&py.env)
            {
                envs.push(py.env.clone());
            }
        }
        for env in &envs {
            runtime.ensure_env(&config.python_project, env).await?;
        }

        // 2. stores
        progress(Phase::Databases);
        #[cfg(feature = "engine")]
        let store = {
            if config.database_backend != "sqlite" {
                return Err(HostError::Unsupported(format!(
                    "database backend {:?}: only sqlite is supported in this build",
                    config.database_backend
                )));
            }
            let opts = secmonk_store::StoreOptions::default();
            secmonk_store::SqliteStore::open(
                &sqlite_file(&config.state_url)?,
                &sqlite_file(&config.mirror_url)?,
                &opts,
            )
            .await?
        };

        // 3. modules: one supervised handle each, with the hello settings
        progress(Phase::Modules);
        #[cfg(feature = "engine")]
        let (state_db, mirror_db) = (
            Some(store.state_path().to_path_buf()),
            Some(store.mirror_path().to_path_buf()),
        );
        #[cfg(not(feature = "engine"))]
        let (state_db, mirror_db): (Option<PathBuf>, Option<PathBuf>) = (None, None);
        let settings = HostSettings {
            min_confidence: config.min_confidence,
            state_db,
            mirror_db,
            allow_db_read: true,
            process_target: config
                .ui_snapshot
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            process_options: Vec::new(),
            modules_root: Some(layout.modules()),
        };
        let mut modules = Vec::new();
        for e in registry.iter() {
            if e.manifest.runtime != ModuleRuntime::Python {
                tracing::warn!(module = %e.manifest.name, "not a python module: skipped (no in-process modules yet)");
                continue;
            }
            modules.push(ModuleHandle::python(e, runtime.clone(), settings.clone()));
        }
        let handle = |name: &str| modules.iter().find(|h| h.name() == name).cloned();

        // 4. probe: the collector allowlist over py-probe (feature `probe`)
        let mut probe = ProbeService::new();
        #[cfg(feature = "probe")]
        {
            let mut provider: Option<Arc<PyCollector>> = None;
            for e in registry
                .iter()
                .filter(|e| e.manifest.kind == ModuleKind::Probe)
            {
                let Some(h) = handle(&e.manifest.name) else {
                    continue;
                };
                let c = Arc::new(PyCollector::new(h));
                probe.register(c.clone()).map_err(|d| HostError::Module {
                    module: e.manifest.name.clone(),
                    message: d.to_string(),
                })?;
                provider.get_or_insert(c);
            }
            if let Some(p) = provider {
                probe = probe.with_methods(p);
            }
        }
        let probe = Arc::new(probe);

        // 5. sources and engine steps: native sources first (a name served twice is taken from the first, so
        // `[sources.implementation] <name> = "rust"` wins over py-sources), then the Python source modules
        #[cfg(feature = "engine")]
        let mut sources: Vec<Arc<dyn Source>> = {
            let served: Vec<String> = registry
                .iter()
                .filter(|e| e.manifest.kind == ModuleKind::Source)
                .flat_map(|e| e.manifest.provides.sources.iter().flatten())
                .map(|i| i.name.clone())
                .collect();
            crate::engine::native_sources(&config, &store, &served)?
        };
        #[cfg(not(feature = "engine"))]
        let mut sources: Vec<Arc<dyn Source>> = Vec::new();
        sources.extend(
            registry
                .iter()
                .filter(|e| e.manifest.kind == ModuleKind::Source)
                .filter_map(|e| handle(&e.manifest.name))
                .map(|h| Arc::new(PySource::new(h)) as Arc<dyn Source>),
        );
        let steps = handle("py-engine").map(|h| Arc::new(PyEngine::new(h)));
        let procmon = handle("py-procmon").map(|h| Arc::new(PyEngine::new(h)));

        // eager modules start now, so a broken install fails the start instead of the first request
        for e in registry.eager() {
            if let Some(h) = handle(&e.manifest.name) {
                h.session().await.map_err(|err| HostError::Module {
                    module: e.manifest.name.clone(),
                    message: err.error,
                })?;
            }
        }

        // 6. engine
        #[cfg(feature = "engine")]
        let engine = crate::engine::build(crate::engine::Parts {
            config: &config,
            store: &store,
            probe: &probe,
            sources: &sources,
            steps: steps.as_ref(),
            allow_actions,
            procmon: procmon.as_ref(),
            modules: registry
                .iter()
                .filter_map(|e| handle(&e.manifest.name).map(|h| (h, e.available)))
                .collect(),
        })?;

        Ok(Host {
            config,
            registry,
            modules,
            probe,
            sources,
            steps,
            procmon,
            #[cfg(feature = "engine")]
            store,
            #[cfg(feature = "engine")]
            engine,
            _instance_lock: instance_lock,
        })
    }

    /// Stop the modules (close their input, wait `cancel_grace_s`, kill) and close the stores.
    pub async fn shutdown(&self) {
        // the running job is stored as interrupted while the store and the modules are still up
        #[cfg(feature = "engine")]
        self.engine.shutdown().await;
        // all modules at once: each waits its own cancel grace, so the total is one grace, not one per module
        futures_util::future::join_all(self.modules.iter().map(ModuleHandle::shutdown)).await;
        #[cfg(feature = "engine")]
        self.store.close().await;
        tracing::info!("host stopped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_instance_on_the_same_data_dir_is_refused() {
        let d = tempfile::tempdir().unwrap();
        let layout = secmonk_config::layout::Layout::new(d.path());
        layout.create().unwrap();
        let first = take_instance_lock(&layout).unwrap();
        let err = take_instance_lock(&layout).unwrap_err();
        assert!(matches!(err, HostError::InstanceRunning(_)));
        let msg = err.to_string();
        assert!(
            msg.contains("already running") && msg.contains("instance.lock"),
            "{msg}"
        );
        // another data_dir is independent; dropping the holder frees the lock
        let other = tempfile::tempdir().unwrap();
        let l2 = secmonk_config::layout::Layout::new(other.path());
        l2.create().unwrap();
        assert!(take_instance_lock(&l2).is_ok());
        drop(first);
        assert!(take_instance_lock(&layout).is_ok());
    }
}
