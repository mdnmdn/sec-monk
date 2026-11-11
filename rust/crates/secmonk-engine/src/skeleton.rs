//! The skeleton engine: answers what is honestly known without a store or modules (meta, an empty job history,
//! `no-db` for every database read) and `not-implemented` for the rest. Wave W3 replaces it.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use secmonk_traits::Collector;
use serde_json::{Value, json};

use crate::error::{EngineError, EngineResult};
use crate::params::{DiscoverQuery, DockerListQuery, FindingsQuery, JobsQuery, VulnSearchQuery};
use crate::service::{EngineService, JsonObject};

/// `FEATURES` of `web/server.py`.
pub const FEATURES: [&str; 8] = [
    "processes",
    "overview",
    "assets",
    "findings",
    "vulns",
    "sources",
    "scan",
    "jobs",
];

/// Facts the engine reports about itself.
#[derive(Debug, Clone)]
pub struct EngineInfo {
    pub version: String,
    /// `live`, or `snapshot` when the process monitor reads a snapshot file (`[ui] snapshot`).
    pub snapshot_mode: bool,
    /// The state database file (`db.path` in `/api/meta`, the path in `no-db` messages).
    pub state_db: PathBuf,
}

impl EngineInfo {
    pub fn new(version: impl Into<String>, state_db: impl Into<PathBuf>) -> Self {
        Self {
            version: version.into(),
            snapshot_mode: false,
            state_db: state_db.into(),
        }
    }
}

/// `backend.current_platform`: `darwin`, `linux` or `windows`.
pub fn current_platform() -> &'static str {
    match std::env::consts::OS {
        "macos" => "darwin",
        other => other,
    }
}

#[derive(Clone)]
pub struct SkeletonEngine {
    info: EngineInfo,
    collectors: Option<Arc<dyn Collector>>,
}

impl std::fmt::Debug for SkeletonEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SkeletonEngine")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl SkeletonEngine {
    pub fn new(info: EngineInfo) -> Self {
        Self {
            info,
            collectors: None,
        }
    }

    /// The probe's collectors (the engine sees a trait object, never which probe is behind it).
    pub fn with_collectors(mut self, collectors: Arc<dyn Collector>) -> Self {
        self.collectors = Some(collectors);
        self
    }

    fn no_db<T>(&self) -> EngineResult<T> {
        Err(EngineError::no_db(self.info.state_db.display()))
    }
}

#[async_trait]
impl EngineService for SkeletonEngine {
    async fn meta(&self) -> EngineResult<Value> {
        Ok(json!({
            "version": self.info.version,
            "mode": if self.info.snapshot_mode { "snapshot" } else { "live" },
            "platform": current_platform(),
            "db": {"path": self.info.state_db.display().to_string(), "exists": self.info.state_db.exists()},
            "features": FEATURES,
            "engine": {"runtime": "rust", "schema": "skeleton", "modules": []},
        }))
    }

    async fn processes(&self, _refresh: bool) -> EngineResult<Value> {
        Err(EngineError::not_implemented("GET /api/processes"))
    }

    async fn processes_watch(&self) -> EngineResult<Value> {
        Err(EngineError::not_implemented("GET /api/processes/watch"))
    }

    async fn processes_save(&self) -> EngineResult<Value> {
        Err(EngineError::not_implemented("POST /api/processes/save"))
    }

    async fn overview(&self) -> EngineResult<Value> {
        self.no_db()
    }

    async fn assets(&self) -> EngineResult<Value> {
        self.no_db()
    }

    async fn asset_detail(&self, _id: &str, _limit: u32) -> EngineResult<Value> {
        self.no_db()
    }

    async fn sbom(&self, _id: &str, _with_vulns: bool) -> EngineResult<Value> {
        self.no_db()
    }

    async fn match_asset(&self, _id: &str) -> EngineResult<Value> {
        self.no_db()
    }

    async fn unmatched(&self) -> EngineResult<Value> {
        self.no_db()
    }

    async fn findings(&self, _query: &FindingsQuery) -> EngineResult<Value> {
        self.no_db()
    }

    async fn vuln_show(&self, _id: &str, _raw: bool) -> EngineResult<Value> {
        self.no_db()
    }

    async fn vuln_search(&self, _query: &VulnSearchQuery) -> EngineResult<Value> {
        self.no_db()
    }

    async fn sources(&self) -> EngineResult<Value> {
        Err(EngineError::not_implemented("GET /api/sources"))
    }

    async fn collectors(&self) -> EngineResult<Value> {
        let Some(c) = &self.collectors else {
            return Err(EngineError::not_implemented("GET /api/collectors"));
        };
        let mut rows = c.collectors();
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(Value::Array(
            rows.into_iter()
                .map(|i| json!({"name": i.name, "description": i.description, "in_all": true}))
                .collect(),
        ))
    }

    async fn jobs_list(&self, _query: &JobsQuery) -> EngineResult<Value> {
        // Honest: this process has run no job and there is no history store yet.
        Ok(json!([]))
    }

    async fn job_get(&self, id: u64) -> EngineResult<Value> {
        Err(EngineError::unknown_job(id))
    }

    async fn job_start(&self, _body: JsonObject) -> EngineResult<Value> {
        Err(EngineError::not_implemented("POST /api/jobs"))
    }

    async fn discover(&self, _query: &DiscoverQuery) -> EngineResult<Value> {
        Err(EngineError::not_implemented("GET /api/discover"))
    }

    async fn k8s_kubeconfigs(&self) -> EngineResult<Value> {
        Err(EngineError::not_implemented("GET /api/k8s/kubeconfigs"))
    }

    async fn docker_contexts(&self) -> EngineResult<Value> {
        Err(EngineError::not_implemented("GET /api/docker/contexts"))
    }

    async fn docker_containers(&self, _query: &DockerListQuery) -> EngineResult<Value> {
        Err(EngineError::not_implemented("GET /api/docker/containers"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorKind;

    fn engine() -> SkeletonEngine {
        SkeletonEngine::new(EngineInfo::new("0.1.0", "/nonexistent/state.sqlite3"))
    }

    #[tokio::test]
    async fn meta_reports_the_state_path_and_features() {
        let m = engine().meta().await.unwrap();
        assert_eq!(m["db"]["exists"], false);
        assert_eq!(m["db"]["path"], "/nonexistent/state.sqlite3");
        assert_eq!(m["features"].as_array().unwrap().len(), 8);
        assert_eq!(m["mode"], "live");
    }

    #[tokio::test]
    async fn database_reads_answer_no_db() {
        let e = engine().overview().await.unwrap_err();
        assert_eq!(e.kind, ErrorKind::NoDb);
        assert_eq!(e.message, "no database at /nonexistent/state.sqlite3");
    }

    #[tokio::test]
    async fn unbuilt_parts_say_so() {
        let e = engine()
            .discover(&DiscoverQuery {
                target: None,
                options: vec![],
            })
            .await
            .unwrap_err();
        assert_eq!(e.kind, ErrorKind::NotImplemented);
    }
}
