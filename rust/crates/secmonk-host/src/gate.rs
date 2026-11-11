//! [`Gate`]: the [`EngineService`] the API router is built on while the host is still starting.
//!
//! Until the real engine is set, `meta` answers (so the UI knows the app is there) and every other route fails
//! with 503 and a hint: the UI's own error state shows "sec-monk is preparing its Python runtime (step 2 of 5:
//! installing Python)" instead of an empty window. When startup ends the gate forwards to the engine, or keeps
//! answering with the failure (so the message reaches the user instead of a blank page).

use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use secmonk_engine::skeleton::{FEATURES, current_platform};
use secmonk_engine::{
    DiscoverQuery, DockerListQuery, EngineError, EngineResult, EngineService, ErrorKind,
    FindingsQuery, JobsQuery, JsonObject, VulnSearchQuery,
};
use serde_json::{Value, json};

use crate::startup::{StartupCell, StartupState};

/// Forwards to the engine once there is one.
pub struct Gate {
    version: String,
    data_dir: PathBuf,
    state_db: PathBuf,
    startup: StartupCell,
    inner: RwLock<Option<Arc<dyn EngineService>>>,
}

impl std::fmt::Debug for Gate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gate")
            .field("startup", &self.startup.get())
            .finish_non_exhaustive()
    }
}

impl Gate {
    /// A gate over `startup`; `state_db` is shown in `meta` until the engine reports it.
    pub fn new(
        version: impl Into<String>,
        data_dir: PathBuf,
        state_db: PathBuf,
        startup: StartupCell,
    ) -> Gate {
        Gate {
            version: version.into(),
            data_dir,
            state_db,
            startup,
            inner: RwLock::new(None),
        }
    }

    /// Start forwarding to `engine`.
    pub fn set_engine(&self, engine: Arc<dyn EngineService>) {
        *self.inner.write().unwrap_or_else(|p| p.into_inner()) = Some(engine);
    }

    /// The engine to forward to: none until it is set, and none once the shutdown began (every route, `meta`
    /// included, then answers 503 "shutting down" while the engine closes its job and the modules stop).
    fn engine(&self) -> Option<Arc<dyn EngineService>> {
        if self.startup.get() == StartupState::Stopping {
            return None;
        }
        self.inner.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// The error every route answers while there is no engine (503 + hint).
    pub fn not_ready(&self) -> EngineError {
        let dir = self.data_dir.display();
        match self.startup.get() {
            StartupState::Preparing(p) => {
                let (n, total) = p.step();
                EngineError::new(
                    ErrorKind::ModuleUnavailable,
                    format!("sec-monk is preparing its Python runtime (step {n} of {total}: {p})"),
                )
                .with_hint(format!(
                    "The first start downloads uv and Python into {dir}; this takes about a minute. \
                     Reload this page when it is done."
                ))
            }
            StartupState::Failed(why) => {
                let hint = if why.contains("already running") {
                    "Quit the other sec-monk instance that uses this data directory, then start the app again."
                        .to_owned()
                } else {
                    format!(
                        "Check the network (the first start downloads uv and Python) and the log files in {dir}/logs, \
                         then restart the app."
                    )
                };
                EngineError::new(
                    ErrorKind::ModuleUnavailable,
                    format!("sec-monk could not start: {why}"),
                )
                .with_hint(hint)
            }
            StartupState::Stopping => {
                EngineError::new(ErrorKind::ModuleUnavailable, "sec-monk is shutting down")
            }
            StartupState::Ready => {
                EngineError::new(ErrorKind::ModuleUnavailable, "sec-monk is starting")
            }
        }
    }

    fn preparing_meta(&self) -> Value {
        let (state, step) = match self.startup.get() {
            StartupState::Preparing(p) => ("preparing", Some(p.to_string())),
            StartupState::Failed(_) => ("failed", None),
            StartupState::Stopping => ("stopping", None),
            StartupState::Ready => ("starting", None),
        };
        json!({
            "version": self.version,
            "mode": "live",
            "platform": current_platform(),
            "db": {"path": self.state_db.display().to_string(), "exists": false},
            "features": FEATURES,
            "engine": {"runtime": "rust", "schema": state, "step": step, "modules": []},
        })
    }
}

macro_rules! forward {
    ($self:ident, $method:ident($($arg:expr),*)) => {
        match $self.engine() {
            Some(e) => e.$method($($arg),*).await,
            None => Err($self.not_ready()),
        }
    };
}

#[async_trait]
impl EngineService for Gate {
    async fn meta(&self) -> EngineResult<Value> {
        match self.engine() {
            Some(e) => e.meta().await,
            None => Ok(self.preparing_meta()),
        }
    }
    async fn processes(&self, refresh: bool) -> EngineResult<Value> {
        forward!(self, processes(refresh))
    }
    async fn processes_watch(&self) -> EngineResult<Value> {
        forward!(self, processes_watch())
    }
    async fn processes_save(&self) -> EngineResult<Value> {
        forward!(self, processes_save())
    }
    async fn overview(&self) -> EngineResult<Value> {
        forward!(self, overview())
    }
    async fn assets(&self) -> EngineResult<Value> {
        forward!(self, assets())
    }
    async fn asset_detail(&self, id: &str, limit: u32) -> EngineResult<Value> {
        forward!(self, asset_detail(id, limit))
    }
    async fn sbom(&self, id: &str, with_vulns: bool) -> EngineResult<Value> {
        forward!(self, sbom(id, with_vulns))
    }
    async fn match_asset(&self, id: &str) -> EngineResult<Value> {
        forward!(self, match_asset(id))
    }
    async fn unmatched(&self) -> EngineResult<Value> {
        forward!(self, unmatched())
    }
    async fn findings(&self, query: &FindingsQuery) -> EngineResult<Value> {
        forward!(self, findings(query))
    }
    async fn vuln_show(&self, id: &str, raw: bool) -> EngineResult<Value> {
        forward!(self, vuln_show(id, raw))
    }
    async fn vuln_search(&self, query: &VulnSearchQuery) -> EngineResult<Value> {
        forward!(self, vuln_search(query))
    }
    async fn sources(&self) -> EngineResult<Value> {
        forward!(self, sources())
    }
    async fn collectors(&self) -> EngineResult<Value> {
        forward!(self, collectors())
    }
    async fn jobs_list(&self, query: &JobsQuery) -> EngineResult<Value> {
        forward!(self, jobs_list(query))
    }
    async fn job_get(&self, id: u64) -> EngineResult<Value> {
        forward!(self, job_get(id))
    }
    async fn job_start(&self, body: JsonObject) -> EngineResult<Value> {
        forward!(self, job_start(body))
    }
    async fn discover(&self, query: &DiscoverQuery) -> EngineResult<Value> {
        forward!(self, discover(query))
    }
    async fn k8s_kubeconfigs(&self) -> EngineResult<Value> {
        forward!(self, k8s_kubeconfigs())
    }
    async fn docker_contexts(&self) -> EngineResult<Value> {
        forward!(self, docker_contexts())
    }
    async fn docker_containers(&self, query: &DockerListQuery) -> EngineResult<Value> {
        forward!(self, docker_containers(query))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::startup::Phase;

    fn gate() -> (Gate, StartupCell) {
        let cell = StartupCell::new();
        (
            Gate::new(
                "0.1.0",
                "/d".into(),
                "/d/db/state.sqlite3".into(),
                cell.clone(),
            ),
            cell,
        )
    }

    #[tokio::test]
    async fn meta_answers_while_everything_else_says_preparing() {
        let (g, cell) = gate();
        cell.progress()(Phase::Python);
        let m = g.meta().await.unwrap();
        assert_eq!(m["engine"]["schema"], "preparing");
        assert_eq!(m["engine"]["step"], "installing Python");
        assert_eq!(m["db"]["exists"], false);
        let e = g.overview().await.unwrap_err();
        assert_eq!(e.kind, ErrorKind::ModuleUnavailable);
        assert!(
            e.message.contains("step 2 of 5: installing Python"),
            "{}",
            e.message
        );
        assert!(e.hint.unwrap().contains("downloads uv and Python into /d"));
        assert!(
            g.jobs_list(&JobsQuery {
                kind: None,
                limit: 5
            })
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn failure_is_shown_and_the_engine_takes_over() {
        let (g, cell) = gate();
        cell.set(StartupState::Failed("download of x failed".into()));
        let e = g.assets().await.unwrap_err();
        assert_eq!(e.message, "sec-monk could not start: download of x failed");
        assert_eq!(g.meta().await.unwrap()["engine"]["schema"], "failed");
        assert!(!e.hint.as_deref().unwrap_or("").contains("data directory"));

        // a second instance on the data directory gets its own hint, not the network one
        let (g2, cell2) = gate();
        cell2.set(StartupState::Failed(
            "another sec-monk instance is already running on /d".into(),
        ));
        let e2 = g2.assets().await.unwrap_err();
        assert!(
            e2.hint.as_deref().unwrap().contains("Quit the other"),
            "{:?}",
            e2.hint
        );

        let engine = Arc::new(secmonk_engine::SkeletonEngine::new(
            secmonk_engine::EngineInfo::new("9.9.9", "/e/state.sqlite3"),
        ));
        g.set_engine(engine);
        assert_eq!(g.meta().await.unwrap()["version"], "9.9.9");
        assert_eq!(g.assets().await.unwrap_err().kind, ErrorKind::NoDb);
    }

    #[tokio::test]
    async fn nothing_is_forwarded_once_stopping() {
        let (g, cell) = gate();
        let engine = Arc::new(secmonk_engine::SkeletonEngine::new(
            secmonk_engine::EngineInfo::new("9.9.9", "/e/state.sqlite3"),
        ));
        g.set_engine(engine);
        cell.set(StartupState::Ready);
        assert_eq!(g.meta().await.unwrap()["version"], "9.9.9");
        cell.set(StartupState::Stopping);
        let e = g.assets().await.unwrap_err();
        assert_eq!(e.kind, ErrorKind::ModuleUnavailable);
        assert_eq!(e.message, "sec-monk is shutting down");
        assert_eq!(g.meta().await.unwrap()["engine"]["schema"], "stopping");
    }
}
