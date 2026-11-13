//! What the engine is built from ([`EngineDeps`]): the stores, the engine steps, the sources, the probe and a few
//! settings. Trait objects only: the composition root (`secmonk-host` / the desktop crate) injects the module host's
//! adapters (`PyEngine`, `PySource`, `PyCollector` behind the probe service) or Rust implementations, and the engine
//! cannot tell them apart (architecture.md §2, "Engine construction (W3.1)").

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use secmonk_store::{MirrorNodeStore, MirrorStore, StateStore};
use secmonk_traits::{EngineSteps, Probe, Reporter, Source};
use serde::Serialize;

/// Settings of the engine (filled from `secmonk-config` `Config` by the composition root).
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// App version (`/api/meta` `version`).
    pub version: String,
    /// `<data_dir>` (absolute).
    pub data_dir: PathBuf,
    /// The state database file: `db.path` of `/api/meta` and `/api/sources`, the path of `no-db` messages.
    pub state_db: PathBuf,
    /// `[engine] min_confidence` (default of scans and re-matches; `0.0..=1.0`).
    pub min_confidence: f64,
    /// The process monitor reads a snapshot file (`[ui] snapshot`): `/api/meta` `mode = snapshot`.
    pub snapshot_mode: bool,
    /// Name of the environment variable holding the NVD API key (`[sources] nvd_api_key_env`, default
    /// `NVD_API_KEY`); read when a sync starts and passed as a call secret, never stored or logged.
    pub nvd_api_key_env: Option<String>,
    /// Whether actions (scan/sync jobs, discovery, docker and kubeconfig listings) are allowed. The API's
    /// `actions` gate answers 403 first; the engine refuses them too when false (defense in depth).
    pub allow_actions: bool,
}

impl EngineConfig {
    /// Defaults for `version` and `state_db`: `min_confidence` 0.5, live mode, `NVD_API_KEY`, actions allowed,
    /// `data_dir` = the state database's grandparent (`<data_dir>/db/state.sqlite3`).
    pub fn new(version: impl Into<String>, state_db: impl Into<PathBuf>) -> EngineConfig {
        let state_db: PathBuf = state_db.into();
        let data_dir = state_db
            .parent()
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .unwrap_or_default();
        EngineConfig {
            version: version.into(),
            data_dir,
            state_db,
            min_confidence: 0.5,
            snapshot_mode: false,
            nvd_api_key_env: Some("NVD_API_KEY".into()),
            allow_actions: true,
        }
    }
}

/// One module (or in-process component) behind the engine, for `/api/meta` `engine.modules`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModuleInfo {
    /// Module name (`py-engine`).
    pub name: String,
    /// `python` or `rust`.
    pub runtime: String,
    /// `ready`, `starting`, `stopped`, `failed`, `unavailable`, ... (free text from the module host).
    pub state: String,
}

/// Live module states for `/api/meta` (implemented by the composition root over `ModuleHandle::state`).
#[async_trait]
pub trait ModuleStatus: Send + Sync {
    /// Every module, in a stable order.
    async fn modules(&self) -> Vec<ModuleInfo>;
}

/// Everything [`crate::SecmonkEngine::new`] needs.
#[derive(Clone)]
pub struct EngineDeps {
    /// Settings.
    pub config: EngineConfig,
    /// Inventory, findings, run history (the host is the only writer, rust ADR-0006).
    pub state: Arc<dyn StateStore>,
    /// The vulnerability mirror (row batches of the sources, rust ADR-0010).
    pub mirror: Arc<dyn MirrorStore>,
    /// classify, match, versions, scoring and the `reports.*` payloads (`py-engine`).
    pub steps: Arc<dyn EngineSteps>,
    /// The process monitor (`procmon.*`, `py-procmon`); `None` where it does not run (Windows): the process routes
    /// answer `unsupported-platform`.
    pub procmon: Option<Arc<dyn Reporter>>,
    /// The vulnerability sources (`py-sources`); a source name served twice is taken from the first.
    pub sources: Vec<Arc<dyn Source>>,
    /// Collectors and the probe methods (`discover.host`, `docker.*`, `k8s.kubeconfigs`): the probe service with its
    /// allowlist (`secmonk_probe::ProbeService`).
    pub probe: Arc<dyn Probe>,
    /// Module states for `/api/meta` (optional: `engine.modules` is `[]` without it).
    pub modules: Option<Arc<dyn ModuleStatus>>,
    /// The mirror's node reads and version records (`SqliteStore::mirror_node_store`). With it, a sync job records
    /// each source's served version after a complete run and re-matches the stored assets the sync affected
    /// (`crate::node`); `None`: neither.
    pub node_store: Option<Arc<dyn MirrorNodeStore>>,
}

impl std::fmt::Debug for EngineDeps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineDeps")
            .field("config", &self.config)
            .field("procmon", &self.procmon.is_some())
            .field("sources", &self.sources.len())
            .field("node_store", &self.node_store.is_some())
            .finish_non_exhaustive()
    }
}
