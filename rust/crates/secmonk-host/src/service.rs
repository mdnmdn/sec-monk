//! [`Service`]: the host starting in the background behind a [`Gate`], for the desktop window and the headless
//! server alike. Build it, hand [`Service::engine`] to the API router, spawn [`Service::run`] on the runtime, and
//! call [`Service::shutdown`] on exit.

use std::sync::{Arc, Mutex};

use secmonk_api::Mount;
use secmonk_config::{Config, ConfigError, NodeService};
use secmonk_engine::EngineService;
use secmonk_node::NodeApi;
use secmonk_traits::node::{Feed, MatchService, VulnInfo};
use tokio_util::sync::CancellationToken;

use crate::gate::Gate;
use crate::host::Host;
use crate::node::{LazyNode, NodePlan};
use crate::startup::{StartupCell, StartupState};

/// A host that starts in the background.
pub struct Service {
    config: Arc<Config>,
    gate: Arc<Gate>,
    startup: StartupCell,
    host: Mutex<Option<Arc<Host>>>,
    cancel: CancellationToken,
    /// The node services behind the `/node/v1` mount, filled when the host is ready.
    node: Arc<LazyNode>,
    /// The binding's actions setting, also given to the engine (`EngineConfig::allow_actions`).
    allow_actions: bool,
    /// Held by [`Service::run`] for its whole duration: the shutdown waits on it, so it never misses a host that
    /// was still being built.
    running: tokio::sync::Mutex<()>,
    /// The node roles, decided once from `[node]` when the service is built.
    plan: Result<NodePlan, ConfigError>,
}

impl std::fmt::Debug for Service {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Service")
            .field("startup", &self.startup.get())
            .finish_non_exhaustive()
    }
}

impl Service {
    /// Nothing runs yet; the gate answers "preparing" until [`Service::run`] has built the engine.
    pub fn new(config: Arc<Config>) -> Arc<Service> {
        Service::with_actions(config, true)
    }

    /// [`Service::new`] for a binding with `allow_actions` (false: the engine refuses scans and syncs, like the
    /// router's 403 on a non-loopback listener).
    pub fn with_actions(config: Arc<Config>, allow_actions: bool) -> Arc<Service> {
        let plan = NodePlan::from_config(&config);
        let startup = StartupCell::new();
        let state_db = Config::sqlite_path(&config.state_url)
            .unwrap_or_else(|| config.data_dir.join("db/state.sqlite3"));
        let gate = Arc::new(Gate::new(
            env!("CARGO_PKG_VERSION"),
            config.data_dir.clone(),
            state_db,
            startup.clone(),
        ));
        Arc::new(Service {
            config,
            gate,
            startup,
            host: Mutex::new(None),
            cancel: CancellationToken::new(),
            node: Arc::new(LazyNode::new()),
            allow_actions,
            running: tokio::sync::Mutex::new(()),
            plan,
        })
    }

    /// The engine service for the API router (the gate: preparing, then the real engine).
    pub fn engine(&self) -> Arc<dyn EngineService> {
        self.gate.clone()
    }

    /// The node roles decided from `[node]` (computed once; the error is the refused combination).
    pub fn node_plan(&self) -> Result<&NodePlan, &ConfigError> {
        self.plan.as_ref()
    }

    /// The `/node/v1` mount for the services `[node] serve` lists: `Ok(None)` when nothing is served, `Err` when the
    /// roles are refused or the node id file cannot be used (never swallowed: the server must not start without
    /// the node API it was configured to offer). The mount can be added to the server before the host is ready:
    /// its services answer 503 "node services are starting" until then. The desktop window does not mount it.
    pub fn node_mount(&self) -> Result<Option<Arc<dyn Mount>>, String> {
        let plan = self.plan.as_ref().map_err(|e| e.to_string())?;
        if plan.serve.is_empty() {
            return Ok(None);
        }
        let id = crate::node::node_id(&self.config).map_err(|e| format!("node id: {e}"))?;
        let lazy = &self.node;
        let matcher = plan
            .serves(NodeService::Match)
            .then(|| lazy.clone() as Arc<dyn MatchService>);
        let vulninfo = plan
            .serves(NodeService::Vulninfo)
            .then(|| lazy.clone() as Arc<dyn VulnInfo>);
        let feed = plan
            .serves(NodeService::Feed)
            .then(|| lazy.clone() as Arc<dyn Feed>);
        Ok(Some(Arc::new(NodeApi::derived(
            matcher,
            vulninfo,
            feed,
            id,
            plan.mirror,
        ))))
    }

    /// Where startup stands.
    pub fn state(&self) -> StartupState {
        self.startup.get()
    }

    /// The configuration.
    pub fn config(&self) -> &Arc<Config> {
        &self.config
    }

    /// Start the host and put its engine behind the gate. Returns when startup ends (success or failure) or
    /// [`Service::shutdown`] cancels it.
    pub async fn run(self: Arc<Self>) {
        let _running = self.running.lock().await;
        let plan = match &self.plan {
            Ok(p) => p.clone(),
            Err(e) => {
                let why = e.to_string();
                tracing::error!("startup failed: {why}");
                self.startup.set(StartupState::Failed(why));
                return;
            }
        };
        let started = tokio::select! {
            () = self.cancel.cancelled() => {
                tracing::info!("startup cancelled");
                return;
            }
            r = Host::start_with_plan(self.config.clone(), plan, self.startup.progress(), self.allow_actions) => r,
        };
        match started {
            Ok(host) => {
                let host = Arc::new(host);
                if self.cancel.is_cancelled() {
                    // the shutdown began while the host was being built: stop it here, it is never served
                    host.shutdown().await;
                } else {
                    if let Some(n) = &host.node {
                        self.node.set(n.clone());
                    }
                    self.gate
                        .set_engine(host.engine.clone() as Arc<dyn EngineService>);
                    *self.host.lock().unwrap_or_else(|p| p.into_inner()) = Some(host);
                    self.startup.set(StartupState::Ready);
                    tracing::info!("ready");
                }
            }
            Err(e) => {
                let why = secmonk_safeio::scrub_text(&e.to_string());
                tracing::error!("startup failed: {why}");
                self.startup.set(StartupState::Failed(why));
            }
        }
    }

    /// Cancel a startup in progress (and wait until [`Service::run`] has ended), stop the modules and close the
    /// stores. The gate refuses requests (503) from the first line on. Safe to call twice.
    pub async fn shutdown(&self) {
        self.startup.set(StartupState::Stopping);
        self.cancel.cancel();
        let _running = self.running.lock().await;
        let host = self.host.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(h) = host {
            h.shutdown().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_node_mount_exists_only_for_a_serving_node_and_answers_starting_first() {
        let off = Service::new(Arc::new(crate::testutil::config_from_toml("")));
        assert!(off.node_mount().unwrap().is_none());
        let on = Service::new(Arc::new(crate::testutil::config_from_toml(
            "[node]\nserve = [\"match\"]\n",
        )));
        let mount = on.node_mount().unwrap().expect("mounted");
        assert_eq!(mount.prefix(), "/node/v1/");
        // the host is not ready: the service answers 503, not 404 (it is enabled)
        let req = http::Request::builder()
            .method("POST")
            .uri("/node/v1/match/changes")
            .body(br#"{"since":{}}"#.to_vec())
            .unwrap();
        let resp = mount.handle(req, None).await;
        assert_eq!(
            resp.status(),
            503,
            "{}",
            String::from_utf8_lossy(resp.body())
        );
        // a service that is not listed is not there
        let req = http::Request::builder()
            .uri("/node/v1/feed/status")
            .body(Vec::new())
            .unwrap();
        assert_eq!(mount.handle(req, None).await.status(), 404);
    }

    #[tokio::test]
    async fn shutdown_refuses_requests_first_and_a_late_start_never_serves() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir_all(r.join("cwd")).unwrap();
        let config = Arc::new(
            secmonk_config::load(&secmonk_config::LoadOptions {
                cwd: r.join("cwd"),
                home: Some(r.join("home")),
                user_config_root: Some(r.join("cfgroot")),
                user_data_root: Some(r.join("dataroot")),
                ..Default::default()
            })
            .unwrap(),
        );
        let s = Service::new(config);
        s.shutdown().await;
        assert_eq!(s.state(), StartupState::Stopping);
        let e = s.engine().assets().await.unwrap_err();
        assert_eq!(e.message, "sec-monk is shutting down");
        // a start that begins after the shutdown ends at once, and never reports Ready
        tokio::time::timeout(std::time::Duration::from_secs(5), s.clone().run())
            .await
            .unwrap();
        assert_eq!(s.state(), StartupState::Stopping);
        s.shutdown().await; // twice is fine
    }
}
