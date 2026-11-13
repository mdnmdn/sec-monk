//! [`CachedVulnInfo`]: the [`VulnInfo`] of a state-only node: summaries from the state's node cache
//! (`vuln_summary`), the misses asked of the (remote) service and cached; `detail` and `search` go to the service
//! uncached (proposal §3.5: they are rare, big and must be current).

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use secmonk_model::node::{MAX_IDS, SummariesResponse, VulnSummary};
use secmonk_store::NodeCacheStore;
use secmonk_traits::StepResult;
use secmonk_traits::node::VulnInfo;
use serde_json::Value;

use super::local::store_wire;

/// `VulnInfo` over the node cache with the service as fallback.
pub struct CachedVulnInfo {
    cache: Arc<dyn NodeCacheStore>,
    service: Arc<dyn VulnInfo>,
}

impl std::fmt::Debug for CachedVulnInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedVulnInfo").finish_non_exhaustive()
    }
}

impl CachedVulnInfo {
    /// Summaries from `cache`, misses from `service`.
    pub fn new(cache: Arc<dyn NodeCacheStore>, service: Arc<dyn VulnInfo>) -> CachedVulnInfo {
        CachedVulnInfo { cache, service }
    }
}

#[async_trait]
impl VulnInfo for CachedVulnInfo {
    /// The cached summaries of `ids`, the others asked of the service (chunks of `MAX_IDS`) and cached; in input
    /// order, one per distinct id; `missing` = the ids neither knows. Any number of ids (the cache is local).
    async fn summaries(&self, ids: &[String]) -> StepResult<SummariesResponse> {
        let mut seen = BTreeSet::new();
        let distinct: Vec<String> = ids
            .iter()
            .filter(|i| seen.insert(i.as_str()))
            .cloned()
            .collect();
        let mut found: HashMap<String, VulnSummary> = self
            .cache
            .cached_summaries(&distinct)
            .await
            .map_err(store_wire)?
            .into_iter()
            .map(|s| (s.id.clone(), s))
            .collect();
        let misses: Vec<String> = distinct
            .iter()
            .filter(|i| !found.contains_key(*i))
            .cloned()
            .collect();
        for chunk in misses.chunks(MAX_IDS) {
            let r = self.service.summaries(chunk).await?;
            // only what was asked (a service answering other ids does not fill the cache with them)
            let asked: BTreeSet<&str> = chunk.iter().map(String::as_str).collect();
            let got: Vec<VulnSummary> = r
                .summaries
                .into_iter()
                .filter(|s| asked.contains(s.id.as_str()))
                .collect();
            self.cache.put_summaries(&got).await.map_err(store_wire)?;
            found.extend(got.into_iter().map(|s| (s.id.clone(), s)));
        }
        let mut summaries = Vec::new();
        let mut missing = Vec::new();
        for id in distinct {
            match found.remove(&id) {
                Some(s) => summaries.push(s),
                None => missing.push(id),
            }
        }
        Ok(SummariesResponse { summaries, missing })
    }

    async fn detail(&self, id: &str, raw: bool) -> StepResult<Value> {
        self.service.detail(id, raw).await
    }

    async fn search(&self, params: Value) -> StepResult<Value> {
        self.service.search(params).await
    }
}
