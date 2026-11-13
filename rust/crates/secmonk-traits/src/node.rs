//! Mirror-node traits: the three interfaces a node offers (`MatchService`, `VulnInfo`, `Feed`). Each has an
//! in-process implementation over the stores and a remote one over the node binding; one conformance suite runs
//! against both (proposal §3.6). Types: `secmonk_model::node`.

use async_trait::async_trait;
use secmonk_model::node::{
    ChangesRequest, ChangesResponse, FeedPage, FeedSinceRequest, FeedStatus,
    MatchComponentsRequest, MatchComponentsResponse, SummariesResponse, Versions,
};
use serde_json::Value;

use crate::StepResult;

/// Matching per component on a mirror (proposal §3.3).
#[async_trait]
pub trait MatchService: Send + Sync {
    /// The complete match sets, lookup keys and versions of up to `MAX_COMPONENTS` components. Too many components
    /// is `invalid-params`.
    async fn match_components(
        &self,
        req: MatchComponentsRequest,
    ) -> StepResult<MatchComponentsResponse>;

    /// What changed in each source since the client's versions: lookup keys and vulnerability ids, or `resync`.
    /// Carries no inventory.
    async fn changes(&self, req: ChangesRequest) -> StepResult<ChangesResponse>;

    /// The node's matcher and source versions.
    async fn versions(&self) -> StepResult<Versions>;
}

/// Vulnerability information by id (proposal §3.5): a call to the mirror part, or a state-side cache filled from a
/// remote mirror.
#[async_trait]
pub trait VulnInfo: Send + Sync {
    /// Summaries of `ids` (at most `MAX_IDS`); ids the node has nothing for are in `missing`.
    async fn summaries(&self, ids: &[String]) -> StepResult<SummariesResponse>;

    /// The `vulns/show` payload for `id` (`raw`: with the records as published).
    async fn detail(&self, id: &str, raw: bool) -> StepResult<Value>;

    /// The `vulns/search` payload for the query parameters `params` (as the API's query string, as an object).
    async fn search(&self, params: Value) -> StepResult<Value>;
}

/// The feed a mirror publishes to other mirrors (proposal §4, P4).
#[async_trait]
pub trait Feed: Send + Sync {
    /// Versions of every source this node serves.
    async fn status(&self) -> StepResult<FeedStatus>;

    /// A page of `secmonk-mirror-rows/1` batches since a version, or of the whole snapshot.
    async fn since(&self, req: FeedSinceRequest) -> StepResult<FeedPage>;
}
