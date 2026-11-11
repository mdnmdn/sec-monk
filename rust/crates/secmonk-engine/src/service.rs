//! `EngineService`: what the API router calls, one async method per `/api` route. Payloads are the final JSON
//! values the UI gets (equal to the Python server's); validation of query strings and bodies happens in
//! `secmonk-api`, business rules (busy, unknown asset, no database) here.

use async_trait::async_trait;
use serde_json::{Map, Value};

use crate::error::EngineResult;
use crate::params::{DiscoverQuery, DockerListQuery, FindingsQuery, JobsQuery, VulnSearchQuery};

/// A JSON object (the validated body of `POST /api/jobs`).
pub type JsonObject = Map<String, Value>;

#[async_trait]
pub trait EngineService: Send + Sync {
    /// 1 `GET /api/meta`, without the transport facts (`bind`, `actions`) which the router sets.
    async fn meta(&self) -> EngineResult<Value>;
    /// 2 `GET /api/processes[?refresh=1]`
    async fn processes(&self, refresh: bool) -> EngineResult<Value>;
    /// 3 `GET /api/processes/watch`
    async fn processes_watch(&self) -> EngineResult<Value>;
    /// 4 `POST /api/processes/save`
    async fn processes_save(&self) -> EngineResult<Value>;
    /// 5 `GET /api/overview`
    async fn overview(&self) -> EngineResult<Value>;
    /// 6 `GET /api/assets`
    async fn assets(&self) -> EngineResult<Value>;
    /// 7 `GET /api/assets/detail?id=&limit=`
    async fn asset_detail(&self, id: &str, limit: u32) -> EngineResult<Value>;
    /// 8 `GET /api/assets/<id>/sbom[?vulns=1]`: the CycloneDX document (the router adds the download headers).
    async fn sbom(&self, id: &str, with_vulns: bool) -> EngineResult<Value>;
    /// 9 `POST /api/assets/match?id=`
    async fn match_asset(&self, id: &str) -> EngineResult<Value>;
    /// 10 `GET /api/unmatched`
    async fn unmatched(&self) -> EngineResult<Value>;
    /// 11 `GET /api/findings`
    async fn findings(&self, query: &FindingsQuery) -> EngineResult<Value>;
    /// 12 `GET /api/vulns/show?id=&raw=`
    async fn vuln_show(&self, id: &str, raw: bool) -> EngineResult<Value>;
    /// 13 `GET /api/vulns/search`
    async fn vuln_search(&self, query: &VulnSearchQuery) -> EngineResult<Value>;
    /// 14 `GET /api/sources`
    async fn sources(&self) -> EngineResult<Value>;
    /// 15 `GET /api/collectors`
    async fn collectors(&self) -> EngineResult<Value>;
    /// 16 `GET /api/jobs`
    async fn jobs_list(&self, query: &JobsQuery) -> EngineResult<Value>;
    /// 17 `GET /api/jobs/<id>`
    async fn job_get(&self, id: u64) -> EngineResult<Value>;
    /// 18 `POST /api/jobs`: the body is a JSON object (size and content type already checked); the engine
    /// validates it (`_prepare_sync`, `_prepare_scan`, `_prepare_batch`) and answers the new job (HTTP 202).
    async fn job_start(&self, body: JsonObject) -> EngineResult<Value>;
    /// 19 `GET /api/discover`
    async fn discover(&self, query: &DiscoverQuery) -> EngineResult<Value>;
    /// 20 `GET /api/k8s/kubeconfigs`
    async fn k8s_kubeconfigs(&self) -> EngineResult<Value>;
    /// 21 `GET /api/docker/contexts`
    async fn docker_contexts(&self) -> EngineResult<Value>;
    /// 22 `GET /api/docker/containers`
    async fn docker_containers(&self, query: &DockerListQuery) -> EngineResult<Value>;
}
