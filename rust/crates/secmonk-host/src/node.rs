//! Mirror-node composition (rust ADR-0013, `rust/_docs/tech/node-api.md`, `engine-service.md` "Node services").
//!
//! The host decides which roles this node plays from `[node]` ([`NodePlan`], a pure function of the configuration)
//! and wires them:
//!
//! - **mirror**: the engine gets the mirror's node store (versions after syncs, re-match after a sync);
//! - **serve**: a [`LocalNode`] (match / vulninfo / feed over the mirror and `py-engine`) behind the `/node/v1`
//!   mount. The mount exists before the host is ready, so it holds a [`LazyNode`] that answers "starting" until
//!   the service fills it;
//! - **follow**: a [`FollowedSource`] (the upstream's feed as a native source) ahead of the other sources;
//! - **state-only matching** (`matcher = "remote"`): [`StateOnlySteps`], the engine steps with the `NodeMatcher`
//!   in place of the local matcher, and the vulnerability reports answered by the upstream.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use secmonk_config::{Config, ConfigError, MatcherMode, NodeService};
use secmonk_engine::StoreMirrorView;
use secmonk_engine::node::{LocalNode, LocalNodeSettings, NodeMatcher};
use secmonk_model::node::{
    ChangesRequest, ChangesResponse, FeedPage, FeedSinceRequest, FeedStatus,
    MatchComponentsRequest, MatchComponentsResponse, SummariesResponse, Versions,
};
use secmonk_model::{Component, RowOp};
use secmonk_modhost::adapters::PyEngine;
use secmonk_node::{BatchLocalizer, FeedSource, LocalVersionFn, RemoteConfig, RemoteNode};
use secmonk_store::{MirrorNodeStore, SqliteStore};
use secmonk_traits::node::{Feed, MatchService, VulnInfo};
use secmonk_traits::{
    CallCtx, Classifier, EngineSteps, ErrorCode, MatchParams, MatchResult, Matcher, Reporter,
    ResultStream, RowsBatch, Source, SourceInfo, StepResult, SyncEnd, SyncParams, VersionOracle,
    WireError,
};
use serde_json::Value;

use crate::host::HostError;

/// Seconds a call to the upstream may take (connect and total).
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(60);

/// File in `<paths.auth>` that holds the node's stable identity (16 hex digits).
pub const NODE_ID_FILE: &str = "node_id";

// ---------------------------------------------------------------------------------------------------------------
// The role plan

/// The roles of this node, decided from `[node]` and `[sources.implementation]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodePlan {
    /// The node has a mirror part (`[node] mirror`): versions are recorded, a sync re-matches.
    pub mirror: bool,
    /// The Node API services offered (`[node] serve`), sorted.
    pub serve: Vec<NodeService>,
    /// Sources followed from the upstream feed (`[node.upstream] sources`).
    pub follow: Vec<String>,
    /// Match through the upstream (`[node] matcher = "remote"`).
    pub remote_matcher: bool,
}

impl NodePlan {
    /// Decide the roles and refuse the combinations that cannot work:
    ///
    /// - `serve` without a mirror (every service reads the mirror);
    /// - `follow` without a mirror (a followed feed is written into the mirror);
    /// - a followed source that `[sources.implementation]` also forces to `rust` or `python`.
    ///
    /// (`matcher = "remote"` and `follow` without `node.upstream.url` are refused by the configuration itself.)
    pub fn from_config(config: &Config) -> Result<NodePlan, ConfigError> {
        let plan = NodePlan {
            mirror: config.node_mirror,
            serve: config.node_serve.clone(),
            follow: config.node_upstream_sources.clone(),
            remote_matcher: config.node_matcher == MatcherMode::Remote,
        };
        if !plan.serve.is_empty() && !plan.mirror {
            return Err(ConfigError::Invalid(format!(
                "node.serve = [{}] needs a mirror part to serve from: set node.mirror = true (or empty node.serve)",
                plan.serve
                    .iter()
                    .map(|s| format!("{:?}", s.as_str()))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        if !plan.follow.is_empty() && !plan.mirror {
            return Err(ConfigError::Invalid(
                "node.upstream.sources writes the followed feed into the mirror: set node.mirror = true \
                 (or empty node.upstream.sources)"
                    .into(),
            ));
        }
        if let Some(name) = plan
            .follow
            .iter()
            .find(|n| config.source_impls.contains_key(*n))
        {
            return Err(ConfigError::Invalid(format!(
                "source {name:?} is followed from the upstream (node.upstream.sources) and also set in \
                 [sources.implementation]: remove one of them"
            )));
        }
        if plan.remote_matcher && plan.mirror {
            tracing::warn!(
                "node.matcher = \"remote\" with node.mirror = true: the local mirror is not used for matching"
            );
        }
        Ok(plan)
    }

    /// Whether a connection to the upstream is needed.
    pub fn needs_upstream(&self) -> bool {
        self.remote_matcher || !self.follow.is_empty()
    }

    /// Whether `s` is offered.
    pub fn serves(&self, s: NodeService) -> bool {
        self.serve.contains(&s)
    }

    /// One line for the log: `mirror, serve=[match], follow=[kev, osv], matcher=local`.
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if self.mirror {
            parts.push("mirror".into());
        }
        if !self.serve.is_empty() {
            let s: Vec<&str> = self.serve.iter().map(|s| s.as_str()).collect();
            parts.push(format!("serve=[{}]", s.join(", ")));
        }
        if !self.follow.is_empty() {
            parts.push(format!("follow=[{}]", self.follow.join(", ")));
        }
        parts.push(format!(
            "matcher={}",
            if self.remote_matcher {
                "remote"
            } else {
                "local"
            }
        ));
        parts.join(", ")
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The node id

/// The node's stable identity, `node:<16 hex>`: generated once and kept in `<paths.auth>/node_id` (0600).
pub fn node_id(config: &Config) -> Result<String, String> {
    crate::apikeys::ensure_auth_dirs(config)?;
    let path = config.layout().auth().join(NODE_ID_FILE);
    read_or_create_node_id(&path)
        .map(|h| format!("node:{h}"))
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn valid_id(s: &str) -> bool {
    s.len() == 16 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The 16 hex digits in `path`. A missing file is created atomically (temp file with mode 0600, hard-linked into
/// place, so a reader never sees a partial file and a concurrent creator wins cleanly). An existing but empty or
/// invalid file is never deleted: it may be a concurrent creator's, so it is re-read a few times, then an error.
fn read_or_create_node_id(path: &Path) -> std::io::Result<String> {
    use std::io::Write as _;
    match std::fs::read_to_string(path) {
        Ok(text) => {
            if let Some(id) = valid_content(&text) {
                return Ok(id);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut bytes = [0u8; 8];
            getrandom::fill(&mut bytes).map_err(|e| std::io::Error::other(e.to_string()))?;
            let id: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            let tmp = path.with_extension(format!("tmp-{}-{id}", std::process::id()));
            let mut open = std::fs::OpenOptions::new();
            open.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                open.mode(0o600);
            }
            let mut f = open.open(&tmp)?;
            let written = f
                .write_all(format!("{id}\n").as_bytes())
                .and_then(|()| f.sync_all());
            drop(f);
            let linked = written.and_then(|()| std::fs::hard_link(&tmp, path));
            let _ = std::fs::remove_file(&tmp);
            match linked {
                Ok(()) => return Ok(id),
                // another process linked its file first: read theirs below
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        Err(e) => return Err(e),
    }
    for attempt in 0..5 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if let Some(id) = std::fs::read_to_string(path)
            .ok()
            .and_then(|t| valid_content(&t))
        {
            return Ok(id);
        }
    }
    Err(std::io::Error::other(
        "the node id file is empty or invalid (not replaced automatically: remove it to generate a new identity)",
    ))
}

fn valid_content(text: &str) -> Option<String> {
    let id = text.trim();
    valid_id(id).then(|| id.to_owned())
}

// ---------------------------------------------------------------------------------------------------------------
// The services, resolved lazily

/// The three services of a node with a mirror, once the host is ready.
#[derive(Clone)]
pub struct NodeServices {
    /// `match.*`.
    pub matcher: Arc<dyn MatchService>,
    /// `vulninfo.*`.
    pub vulninfo: Arc<dyn VulnInfo>,
    /// `feed.*`.
    pub feed: Arc<dyn Feed>,
}

impl NodeServices {
    /// All three over one [`LocalNode`].
    pub fn from_local(node: Arc<LocalNode>) -> NodeServices {
        NodeServices {
            matcher: node.clone(),
            vulninfo: node.clone(),
            feed: node,
        }
    }
}

impl std::fmt::Debug for NodeServices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeServices").finish_non_exhaustive()
    }
}

/// The services behind the `/node/v1` mount, which is built before the host is ready: every call answers
/// `module-unavailable` ("node services are starting", HTTP 503) until [`LazyNode::set`], then delegates.
#[derive(Default)]
pub struct LazyNode {
    inner: OnceLock<NodeServices>,
}

impl std::fmt::Debug for LazyNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyNode")
            .field("ready", &self.is_ready())
            .finish()
    }
}

impl LazyNode {
    /// Not ready.
    pub fn new() -> LazyNode {
        LazyNode::default()
    }

    /// The services are ready (the first call wins).
    pub fn set(&self, services: NodeServices) {
        let _ = self.inner.set(services);
    }

    /// Whether [`LazyNode::set`] has been called.
    pub fn is_ready(&self) -> bool {
        self.inner.get().is_some()
    }

    fn ready(&self) -> StepResult<&NodeServices> {
        self.inner.get().ok_or_else(|| {
            WireError::new(ErrorCode::ModuleUnavailable, "node services are starting")
                .with_hint("the node is still starting; retry shortly")
        })
    }
}

#[async_trait]
impl MatchService for LazyNode {
    async fn match_components(
        &self,
        req: MatchComponentsRequest,
    ) -> StepResult<MatchComponentsResponse> {
        self.ready()?.matcher.match_components(req).await
    }

    async fn changes(&self, req: ChangesRequest) -> StepResult<ChangesResponse> {
        self.ready()?.matcher.changes(req).await
    }

    async fn versions(&self) -> StepResult<Versions> {
        self.ready()?.matcher.versions().await
    }
}

#[async_trait]
impl VulnInfo for LazyNode {
    async fn summaries(&self, ids: &[String]) -> StepResult<SummariesResponse> {
        self.ready()?.vulninfo.summaries(ids).await
    }

    async fn detail(&self, id: &str, raw: bool) -> StepResult<Value> {
        self.ready()?.vulninfo.detail(id, raw).await
    }

    async fn search(&self, params: Value) -> StepResult<Value> {
        self.ready()?.vulninfo.search(params).await
    }
}

#[async_trait]
impl Feed for LazyNode {
    async fn status(&self) -> StepResult<FeedStatus> {
        self.ready()?.feed.status().await
    }

    async fn since(&self, req: FeedSinceRequest) -> StepResult<FeedPage> {
        self.ready()?.feed.since(req).await
    }
}

// ---------------------------------------------------------------------------------------------------------------
// State-only matching: the composite engine steps

/// The engine steps of a state-only node: classify and the version oracle stay `py-engine`, matching goes to
/// `matcher` (the `NodeMatcher` over the upstream), and the vulnerability reports (`vulns/show`, `vulns/search`)
/// are answered by the upstream's `VulnInfo`, since the local mirror has nothing to show. Every other report is
/// `py-engine`'s.
pub struct StateOnlySteps {
    base: Arc<dyn EngineSteps>,
    matcher: Arc<dyn Matcher>,
    info: Arc<dyn VulnInfo>,
}

impl std::fmt::Debug for StateOnlySteps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateOnlySteps").finish_non_exhaustive()
    }
}

impl StateOnlySteps {
    /// `base`: the local steps; `matcher`: the matcher in its place; `info`: the upstream's vulnerability reads.
    pub fn new(
        base: Arc<dyn EngineSteps>,
        matcher: Arc<dyn Matcher>,
        info: Arc<dyn VulnInfo>,
    ) -> StateOnlySteps {
        StateOnlySteps {
            base,
            matcher,
            info,
        }
    }
}

#[async_trait]
impl Classifier for StateOnlySteps {
    async fn classify(
        &self,
        components: Vec<Component>,
        ctx: CallCtx,
    ) -> StepResult<Vec<Component>> {
        self.base.classify(components, ctx).await
    }
}

#[async_trait]
impl Matcher for StateOnlySteps {
    async fn match_asset(&self, params: MatchParams, ctx: CallCtx) -> StepResult<MatchResult> {
        self.matcher.match_asset(params, ctx).await
    }
}

#[async_trait]
impl Reporter for StateOnlySteps {
    fn methods(&self) -> Vec<String> {
        self.base.methods()
    }

    async fn report(&self, method: &str, params: Value, ctx: CallCtx) -> StepResult<Value> {
        match method {
            "reports.vuln_detail" => {
                let id = params.get("id").and_then(Value::as_str).ok_or_else(|| {
                    WireError::invalid_params("reports.vuln_detail: id is required")
                })?;
                let raw = params.get("raw").and_then(Value::as_bool).unwrap_or(false);
                self.info.detail(id, raw).await
            }
            // the engine wraps the rows (`{results, limit, limit_reached}`), the upstream's payload already is
            // that wrapper: hand back the rows
            "reports.vuln_search" => {
                let mut payload = self.info.search(params).await?;
                Ok(payload
                    .get_mut("results")
                    .map(Value::take)
                    .unwrap_or(payload))
            }
            other => self.base.report(other, params, ctx).await,
        }
    }
}

#[async_trait]
impl VersionOracle for StateOnlySteps {
    async fn compare(
        &self,
        a: &str,
        b: &str,
        scheme: &str,
        ctx: CallCtx,
    ) -> StepResult<std::cmp::Ordering> {
        self.base.compare(a, b, scheme, ctx).await
    }

    async fn in_range(
        &self,
        version: &str,
        events: &[Value],
        scheme: &str,
        ctx: CallCtx,
    ) -> StepResult<bool> {
        self.base.in_range(version, events, scheme, ctx).await
    }

    async fn first_fixed(
        &self,
        version: &str,
        events: &[Value],
        scheme: &str,
        ctx: CallCtx,
    ) -> StepResult<Option<String>> {
        self.base.first_fixed(version, events, scheme, ctx).await
    }

    async fn scheme(&self, ecosystem: Option<&str>, ctx: CallCtx) -> StepResult<String> {
        self.base.scheme(ecosystem, ctx).await
    }

    async fn priority(&self, params: Value, ctx: CallCtx) -> StepResult<String> {
        self.base.priority(params, ctx).await
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Following

/// `BatchLocalizer` over the mirror's `localize_feed_batch`.
struct StoreLocalizer(Arc<dyn MirrorNodeStore>);

#[async_trait]
impl BatchLocalizer for StoreLocalizer {
    async fn localize(&self, batch: &RowsBatch) -> StepResult<Vec<RowOp>> {
        self.0
            .localize_feed_batch(batch)
            .await
            .map_err(|e| WireError::new(ErrorCode::Internal, format!("StoreError: {e}")))
    }
}

/// A [`FeedSource`] that refreshes the local versions it passes to the feed before each sync (`FeedSource` takes a
/// synchronous `LocalVersionFn`; the versions live in the mirror, behind an async store).
///
/// A source whose local rows were written by another importer than the upstream's (proposal §3.2 rule 2) gets no
/// local version, so the whole source is requested: a delta over rows of another importer could mix them.
pub struct FollowedSource {
    inner: FeedSource,
    store: Arc<dyn MirrorNodeStore>,
    upstream: Arc<dyn Feed>,
    versions: Arc<RwLock<BTreeMap<String, String>>>,
}

impl FollowedSource {
    /// Follow `sources` of `upstream`, writing into the mirror behind `store` / `view`.
    pub fn new(
        sources: Vec<String>,
        upstream: Arc<dyn Feed>,
        store: Arc<dyn MirrorNodeStore>,
        view: Arc<dyn secmonk_traits::MirrorView>,
    ) -> FollowedSource {
        let versions: Arc<RwLock<BTreeMap<String, String>>> = Arc::default();
        let cache = versions.clone();
        let local: LocalVersionFn =
            Arc::new(move |source: &str| cache.read().ok().and_then(|m| m.get(source).cloned()));
        let inner = FeedSource::new(
            sources,
            upstream.clone(),
            view,
            Arc::new(StoreLocalizer(store.clone())),
            local,
        );
        FollowedSource {
            inner,
            store,
            upstream,
            versions,
        }
    }

    /// Reload the local versions from the mirror (`source_versions()`).
    async fn refresh(&self) -> StepResult<()> {
        let local = self
            .store
            .source_versions()
            .await
            .map_err(|e| WireError::new(ErrorCode::Internal, format!("StoreError: {e}")))?;
        // the upstream's importers: without them the importer guard (proposal §3.2 rule 2) cannot run, so an
        // upstream that cannot be asked fails the sync here instead of sending a local version blindly
        let upstream: BTreeMap<String, String> = self
            .upstream
            .status()
            .await
            .map_err(|e| {
                let mut w = WireError::new(e.code, format!("upstream feed status: {}", e.error));
                w.hint = e.hint;
                w
            })?
            .sources
            .into_iter()
            .map(|v| (v.source, v.importer))
            .collect();
        let mut map = BTreeMap::new();
        for v in local {
            let Some(version) = v.version else { continue };
            if upstream
                .get(&v.source)
                .is_some_and(|importer| *importer != v.importer)
            {
                continue;
            }
            map.insert(v.source, version);
        }
        *self.versions.write().unwrap_or_else(|p| p.into_inner()) = map;
        Ok(())
    }
}

impl std::fmt::Debug for FollowedSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.inner.fmt(f)
    }
}

#[async_trait]
impl Source for FollowedSource {
    fn sources(&self) -> Vec<SourceInfo> {
        self.inner.sources()
    }

    fn sync_all_order(&self) -> Vec<String> {
        self.inner.sync_all_order()
    }

    async fn sync(
        &self,
        params: SyncParams,
        ctx: CallCtx,
    ) -> StepResult<ResultStream<RowsBatch, SyncEnd>> {
        self.refresh().await?;
        self.inner.sync(params, ctx).await
    }

    async fn ack(&self, source: &str, through_seq: u64, ctx: CallCtx) -> StepResult<()> {
        self.inner.ack(source, through_seq, ctx).await
    }

    async fn export(
        &self,
        source: &str,
        ctx: CallCtx,
    ) -> StepResult<ResultStream<RowsBatch, Value>> {
        self.inner.export(source, ctx).await
    }

    fn native(&self) -> bool {
        self.inner.native()
    }

    fn importer_version(&self, source: &str) -> Option<String> {
        self.inner.importer_version(source)
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Composition

/// The `RemoteNode` for `[node.upstream]`: the API key comes from the variable `node.upstream.api_key_env` names,
/// read through `env` (the host passes the process environment; this is the only place it is read).
pub(crate) fn upstream_remote(
    config: &Config,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Arc<RemoteNode>, HostError> {
    let invalid = |m: String| HostError::Config(ConfigError::Invalid(m));
    let url = config
        .node_upstream_url
        .clone()
        .ok_or_else(|| invalid("node.upstream.url is required by the node roles".into()))?;
    let var = &config.node_upstream_api_key_env;
    let key = env(var)
        .map(|k| k.trim().to_owned())
        .filter(|k| !k.is_empty());
    let api_key = key.ok_or_else(|| {
        invalid(format!(
            "node.upstream: the environment variable {var} is not set or empty; it must hold the API key of \
             the upstream node (node.upstream.api_key_env names the variable)"
        ))
    })?;
    RemoteNode::new(RemoteConfig {
        base_url: url,
        api_key,
        ca_cert: config.node_upstream_ca_cert.clone(),
        timeout: UPSTREAM_TIMEOUT,
    })
    .map(Arc::new)
    .map_err(|e| invalid(format!("node.upstream: {}", e.error)))
}

/// What the composition decided, for the host to hand to the sources list and the engine.
pub(crate) struct Composed {
    /// Sources that go ahead of every other source (the followed feed).
    pub(crate) front_sources: Vec<Arc<dyn Source>>,
    /// The steps the engine gets (`py-engine`, or [`StateOnlySteps`] over it).
    pub(crate) steps: Arc<dyn EngineSteps>,
    /// `EngineDeps::node_store`.
    pub(crate) node_store: Option<Arc<dyn MirrorNodeStore>>,
    /// The services to serve, when `serve` is not empty.
    pub(crate) services: Option<NodeServices>,
}

/// Wire the roles of `plan` over the store and `py-engine`.
pub(crate) fn compose(
    config: &Config,
    plan: &NodePlan,
    store: &SqliteStore,
    py: &Arc<PyEngine>,
    env: &dyn Fn(&str) -> Option<String>,
) -> Result<Composed, HostError> {
    let remote = if plan.needs_upstream() {
        Some(upstream_remote(config, env)?)
    } else {
        None
    };
    let node_store = plan.mirror.then(|| store.mirror_node_store());

    let mut front_sources: Vec<Arc<dyn Source>> = Vec::new();
    if !plan.follow.is_empty()
        && let Some(remote) = &remote
    {
        let view: Arc<dyn secmonk_traits::MirrorView> =
            Arc::new(StoreMirrorView::new(Arc::new(store.clone())));
        front_sources.push(Arc::new(FollowedSource::new(
            plan.follow.clone(),
            remote.clone(),
            store.mirror_node_store(),
            view,
        )));
    }

    let steps: Arc<dyn EngineSteps> = match (&remote, plan.remote_matcher) {
        (Some(remote), true) => {
            let matcher = Arc::new(NodeMatcher::new(
                remote.clone(),
                remote.clone(),
                store.node_cache_store(),
                py.clone(),
                Arc::new(store.clone()),
            ));
            Arc::new(StateOnlySteps::new(py.clone(), matcher, remote.clone()))
        }
        _ => py.clone(),
    };

    let services = if plan.serve.is_empty() {
        None
    } else {
        let id = node_id(config).map_err(|e| HostError::Config(ConfigError::Invalid(e)))?;
        let local = Arc::new(LocalNode::new(
            store.mirror_node_store(),
            py.clone(),
            py.clone(),
            LocalNodeSettings {
                node_id: Some(id),
                ..LocalNodeSettings::default()
            },
        ));
        Some(NodeServices::from_local(local))
    };

    tracing::info!("node roles: {}", plan.describe());
    Ok(Composed {
        front_sources,
        steps,
        node_store,
        services,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn config(toml: &str) -> Config {
        crate::testutil::config_from_toml(toml)
    }

    #[test]
    fn the_default_is_a_mirror_matching_locally() {
        let p = NodePlan::from_config(&config("")).unwrap();
        assert_eq!(
            p,
            NodePlan {
                mirror: true,
                serve: vec![],
                follow: vec![],
                remote_matcher: false
            }
        );
        assert!(!p.needs_upstream());
        assert_eq!(p.describe(), "mirror, matcher=local");
    }

    #[test]
    fn roles_are_read_from_the_configuration() {
        let p = NodePlan::from_config(&config(
            "[node]\nserve = [\"vulninfo\", \"match\", \"match\"]\nmatcher = \"remote\"\n\
             [node.upstream]\nurl = \"https://up.example:8765\"\nsources = [\"kev\", \"osv\"]\n",
        ))
        .unwrap();
        assert_eq!(p.serve, vec![NodeService::Match, NodeService::Vulninfo]);
        assert_eq!(p.follow, vec!["kev", "osv"]);
        assert!(p.remote_matcher && p.needs_upstream());
        assert!(p.serves(NodeService::Match) && !p.serves(NodeService::Feed));
        assert_eq!(
            p.describe(),
            "mirror, serve=[match, vulninfo], follow=[kev, osv], matcher=remote"
        );
    }

    #[test]
    fn serving_or_following_needs_a_mirror() {
        for svc in ["feed", "match", "vulninfo"] {
            let e = NodePlan::from_config(&config(&format!(
                "[node]\nmirror = false\nserve = [\"{svc}\"]\n"
            )))
            .unwrap_err()
            .to_string();
            assert!(
                e.contains("node.serve") && e.contains("node.mirror = true"),
                "{e}"
            );
            assert!(e.contains(svc), "{e}");
        }
        let e = NodePlan::from_config(&config(
            "[node]\nmirror = false\n[node.upstream]\nurl = \"https://up.example\"\nsources = [\"kev\"]\n",
        ))
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("node.upstream.sources") && e.contains("node.mirror"),
            "{e}"
        );
        // a state-only node (no mirror, remote matcher, nothing served) is fine
        let p = NodePlan::from_config(&config(
            "[node]\nmirror = false\nmatcher = \"remote\"\n[node.upstream]\nurl = \"https://up.example\"\n",
        ))
        .unwrap();
        assert_eq!(p.describe(), "matcher=remote");
    }

    #[test]
    fn a_followed_source_cannot_also_be_forced_to_an_implementation() {
        for imp in ["rust", "python"] {
            let e = NodePlan::from_config(&config(&format!(
                "[node.upstream]\nurl = \"https://up.example\"\nsources = [\"kev\"]\n\
                 [sources.implementation]\nkev = \"{imp}\"\n"
            )))
            .unwrap_err()
            .to_string();
            assert!(
                e.contains("\"kev\"") && e.contains("sources.implementation"),
                "{e}"
            );
        }
        // another source's implementation does not conflict
        assert!(
            NodePlan::from_config(&config(
                "[node.upstream]\nurl = \"https://up.example\"\nsources = [\"kev\"]\n\
                 [sources.implementation]\nepss = \"python\"\n"
            ))
            .is_ok()
        );
    }

    #[test]
    fn the_upstream_key_comes_from_the_named_variable() {
        let c = config(
            "[node.upstream]\nurl = \"https://up.example:8765\"\napi_key_env = \"MY_UP_KEY\"\n",
        );
        let none = |_: &str| None;
        let e = upstream_remote(&c, &none).err().unwrap().to_string();
        assert!(e.contains("MY_UP_KEY") && e.contains("not set"), "{e}");
        let blank = |_: &str| Some("  ".to_owned());
        assert!(upstream_remote(&c, &blank).is_err());
        let asked = Mutex::new(Vec::new());
        let set = |n: &str| {
            asked.lock().unwrap().push(n.to_owned());
            Some("smk_aaaa_bbbb".to_owned())
        };
        assert!(upstream_remote(&c, &set).is_ok());
        assert_eq!(*asked.lock().unwrap(), vec!["MY_UP_KEY"]);
    }

    #[test]
    fn the_node_id_is_stable_and_private() {
        let d = tempfile::tempdir().unwrap();
        let c = crate::testutil::temp_config(d.path(), &[]);
        let a = node_id(&c).unwrap();
        let b = node_id(&c).unwrap();
        assert_eq!(a, b);
        let hex = a.strip_prefix("node:").unwrap();
        assert!(valid_id(hex), "{a}");
        let path = c.layout().auth().join(NODE_ID_FILE);
        assert_eq!(std::fs::read_to_string(&path).unwrap().trim(), hex);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        // another data directory gets another id; a damaged file is an error, never deleted
        let d2 = tempfile::tempdir().unwrap();
        let c2 = crate::testutil::temp_config(d2.path(), &[]);
        assert_ne!(node_id(&c2).unwrap(), a);
        std::fs::write(&path, "not an id").unwrap();
        assert!(node_id(&c).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "not an id");
        std::fs::write(&path, "").unwrap();
        assert!(node_id(&c).is_err());
        std::fs::remove_file(&path).unwrap();
        let fresh = node_id(&c).unwrap();
        assert!(valid_id(fresh.strip_prefix("node:").unwrap()));
        assert_eq!(node_id(&c).unwrap(), fresh);
    }

    #[test]
    fn concurrent_node_id_creation_agrees() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("node_id");
        let ids: Vec<String> = (0..8)
            .map(|_| {
                let p = path.clone();
                std::thread::spawn(move || read_or_create_node_id(&p).unwrap())
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect();
        assert!(ids.iter().all(|i| *i == ids[0]), "{ids:?}");
        assert_eq!(
            std::fs::read_dir(d.path()).unwrap().count(),
            1,
            "no temp files left"
        );
    }

    // --- fakes -------------------------------------------------------------------------------------------------

    #[derive(Default)]
    struct Fake {
        calls: AtomicUsize,
    }

    #[async_trait]
    impl MatchService for Fake {
        async fn match_components(
            &self,
            _req: MatchComponentsRequest,
        ) -> StepResult<MatchComponentsResponse> {
            Err(WireError::new(ErrorCode::Internal, "fake match"))
        }
        async fn changes(&self, _req: ChangesRequest) -> StepResult<ChangesResponse> {
            Err(WireError::new(ErrorCode::Internal, "fake changes"))
        }
        async fn versions(&self) -> StepResult<Versions> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::from_value(serde_json::json!({
                "matcher": "m1", "sources": {}
            }))
            .unwrap())
        }
    }

    #[async_trait]
    impl VulnInfo for Fake {
        async fn summaries(&self, ids: &[String]) -> StepResult<SummariesResponse> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::from_value(serde_json::json!({
                "summaries": [], "missing": ids
            }))
            .unwrap())
        }
        async fn detail(&self, id: &str, raw: bool) -> StepResult<Value> {
            Ok(serde_json::json!({"from": "upstream", "id": id, "raw": raw}))
        }
        async fn search(&self, params: Value) -> StepResult<Value> {
            Ok(serde_json::json!({
                "results": [{"saw": params}], "limit": 5, "limit_reached": false
            }))
        }
    }

    #[async_trait]
    impl Feed for Fake {
        async fn status(&self) -> StepResult<FeedStatus> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(serde_json::from_value(serde_json::json!({
                "node_id": "node:fake", "matcher": "m1", "sources": []
            }))
            .unwrap())
        }
        async fn since(&self, _req: FeedSinceRequest) -> StepResult<FeedPage> {
            Err(WireError::new(ErrorCode::Internal, "fake since"))
        }
    }

    /// A feed that only answers `status`, with the given `(source, importer)` pairs.
    struct StatusFeed(Vec<(&'static str, &'static str)>);

    #[async_trait]
    impl Feed for StatusFeed {
        async fn status(&self) -> StepResult<FeedStatus> {
            let sources: Vec<Value> = self
                .0
                .iter()
                .map(|(s, i)| {
                    serde_json::json!({
                        "source": s, "version": "9", "importer": i, "kind": "snapshot", "records": 1
                    })
                })
                .collect();
            Ok(serde_json::from_value(serde_json::json!({
                "matcher": "m1", "sources": sources
            }))
            .unwrap())
        }
        async fn since(&self, _req: FeedSinceRequest) -> StepResult<FeedPage> {
            Err(WireError::new(ErrorCode::Internal, "no pages"))
        }
    }

    #[tokio::test]
    async fn a_followed_source_passes_local_versions_of_the_upstreams_importer_only() {
        use secmonk_model::node::VersionKind;
        let d = tempfile::tempdir().unwrap();
        let store = SqliteStore::open(
            &d.path().join("state.sqlite3"),
            &d.path().join("mirror.sqlite3"),
            &secmonk_store::StoreOptions::default(),
        )
        .await
        .unwrap();
        let nodes = store.mirror_node_store();
        nodes
            .record_complete_version("kev", "v-kev", "rust/1", VersionKind::Snapshot)
            .await
            .unwrap();
        nodes
            .record_complete_version("epss", "v-epss", "python/1", VersionKind::Snapshot)
            .await
            .unwrap();
        let view: Arc<dyn secmonk_traits::MirrorView> =
            Arc::new(StoreMirrorView::new(Arc::new(store.clone())));
        // the upstream's kev is rust/1 (same: delta), its epss rust/1 (local python/1: everything)
        let upstream = Arc::new(StatusFeed(vec![("kev", "rust/1"), ("epss", "rust/1")]));
        let f = FollowedSource::new(
            vec!["kev".into(), "epss".into()],
            upstream,
            nodes.clone(),
            view.clone(),
        );
        assert!(
            f.versions.read().unwrap().is_empty(),
            "nothing before a sync"
        );
        f.refresh().await.unwrap();
        {
            let v = f.versions.read().unwrap();
            assert_eq!(v.get("kev").map(String::as_str), Some("v-kev"));
            assert!(!v.contains_key("epss"), "{v:?}");
        }
        // a new version recorded by a sync is seen by the next refresh (an upstream that lists no importer filters nothing)
        nodes
            .record_complete_version("kev", "v-kev2", "rust/1", VersionKind::Snapshot)
            .await
            .unwrap();
        let down = FollowedSource::new(
            vec!["kev".into()],
            Arc::new(Fake::default()),
            nodes,
            view.clone(),
        );
        down.refresh().await.unwrap();
        assert_eq!(
            down.versions.read().unwrap().get("kev").map(String::as_str),
            Some("v-kev2")
        );
        assert!(f.native() && f.sources().len() == 2);
        // an upstream whose status cannot be read fails the sync (no local version is sent unguarded)
        let blind = FollowedSource::new(
            vec!["kev".into()],
            Arc::new(DownFeed),
            store.mirror_node_store(),
            view,
        );
        let e = blind.refresh().await.unwrap_err();
        assert_eq!(e.code, ErrorCode::HostUnreachable);
        assert!(e.error.contains("upstream feed status"), "{}", e.error);
        let e = blind
            .sync(
                SyncParams {
                    source: "kev".into(),
                    options: Default::default(),
                    secrets: None,
                },
                CallCtx::default(),
            )
            .await
            .err()
            .unwrap();
        assert_eq!(e.code, ErrorCode::HostUnreachable);
        store.close().await;
    }

    /// A feed whose node cannot be reached.
    struct DownFeed;

    #[async_trait]
    impl Feed for DownFeed {
        async fn status(&self) -> StepResult<FeedStatus> {
            Err(WireError::new(
                ErrorCode::HostUnreachable,
                "connection refused",
            ))
        }
        async fn since(&self, _req: FeedSinceRequest) -> StepResult<FeedPage> {
            Err(WireError::new(
                ErrorCode::HostUnreachable,
                "connection refused",
            ))
        }
    }

    #[tokio::test]
    async fn the_lazy_node_says_starting_and_then_delegates() {
        let lazy = LazyNode::new();
        let starting = |e: WireError| {
            assert_eq!(e.code, ErrorCode::ModuleUnavailable);
            assert!(e.error.contains("starting"), "{}", e.error);
        };
        starting(lazy.versions().await.unwrap_err());
        starting(lazy.summaries(&[]).await.unwrap_err());
        starting(lazy.detail("X", false).await.unwrap_err());
        starting(lazy.search(Value::Null).await.unwrap_err());
        starting(lazy.status().await.unwrap_err());
        starting(lazy.changes(ChangesRequest::default()).await.unwrap_err());
        assert!(!lazy.is_ready());

        let fake = Arc::new(Fake::default());
        lazy.set(NodeServices {
            matcher: fake.clone(),
            vulninfo: fake.clone(),
            feed: fake.clone(),
        });
        assert!(lazy.is_ready());
        assert_eq!(lazy.versions().await.unwrap().matcher, "m1");
        assert_eq!(
            lazy.summaries(&["A".into()]).await.unwrap().missing,
            vec!["A"]
        );
        assert_eq!(
            lazy.status().await.unwrap().node_id.as_deref(),
            Some("node:fake")
        );
        assert_eq!(
            lazy.changes(ChangesRequest::default())
                .await
                .unwrap_err()
                .error,
            "fake changes"
        );
        assert_eq!(fake.calls.load(Ordering::SeqCst), 3);
        // the services are set once
        lazy.set(NodeServices {
            matcher: Arc::new(Fake::default()),
            vulninfo: Arc::new(Fake::default()),
            feed: Arc::new(Fake::default()),
        });
        assert_eq!(lazy.versions().await.unwrap().matcher, "m1");
        assert_eq!(fake.calls.load(Ordering::SeqCst), 4);
    }

    /// `py-engine` stand-in: every method names itself.
    struct Base;

    #[async_trait]
    impl Classifier for Base {
        async fn classify(
            &self,
            mut components: Vec<Component>,
            _ctx: CallCtx,
        ) -> StepResult<Vec<Component>> {
            components.truncate(1);
            Ok(components)
        }
    }
    #[async_trait]
    impl Matcher for Base {
        async fn match_asset(&self, _p: MatchParams, _c: CallCtx) -> StepResult<MatchResult> {
            Err(WireError::new(ErrorCode::Internal, "base matcher"))
        }
    }
    #[async_trait]
    impl Reporter for Base {
        fn methods(&self) -> Vec<String> {
            vec!["reports.status".into(), "reports.vuln_detail".into()]
        }
        async fn report(&self, method: &str, _p: Value, _c: CallCtx) -> StepResult<Value> {
            Ok(serde_json::json!({"from": "base", "method": method}))
        }
    }
    #[async_trait]
    impl VersionOracle for Base {
        async fn compare(
            &self,
            _a: &str,
            _b: &str,
            _s: &str,
            _c: CallCtx,
        ) -> StepResult<std::cmp::Ordering> {
            Ok(std::cmp::Ordering::Less)
        }
        async fn in_range(
            &self,
            _v: &str,
            _e: &[Value],
            _s: &str,
            _c: CallCtx,
        ) -> StepResult<bool> {
            Ok(true)
        }
        async fn first_fixed(
            &self,
            _v: &str,
            _e: &[Value],
            _s: &str,
            _c: CallCtx,
        ) -> StepResult<Option<String>> {
            Ok(Some("9".into()))
        }
        async fn scheme(&self, _e: Option<&str>, _c: CallCtx) -> StepResult<String> {
            Ok("semver".into())
        }
        async fn priority(&self, _p: Value, _c: CallCtx) -> StepResult<String> {
            Ok("P2".into())
        }
    }

    struct Remote;
    #[async_trait]
    impl Matcher for Remote {
        async fn match_asset(&self, _p: MatchParams, _c: CallCtx) -> StepResult<MatchResult> {
            Err(WireError::new(ErrorCode::Internal, "node matcher"))
        }
    }

    #[tokio::test]
    async fn the_state_only_steps_delegate_each_role() {
        let steps =
            StateOnlySteps::new(Arc::new(Base), Arc::new(Remote), Arc::new(Fake::default()));
        let ctx = CallCtx::default;
        // matching: the node matcher, not the base's
        let e = steps
            .match_asset(
                MatchParams::Persisted {
                    asset_id: "a".into(),
                    min_confidence: 0.0,
                    view_limit: None,
                },
                ctx(),
            )
            .await
            .unwrap_err();
        assert_eq!(e.error, "node matcher");
        // classify and the oracle: the base
        let c: Component = serde_json::from_value(
            serde_json::json!({"name": "a", "version": "1", "category": "library"}),
        )
        .unwrap();
        assert_eq!(
            steps
                .classify(vec![c.clone(), c], ctx())
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            steps.compare("1", "2", "semver", ctx()).await.unwrap(),
            std::cmp::Ordering::Less
        );
        assert!(steps.in_range("1", &[], "semver", ctx()).await.unwrap());
        assert_eq!(
            steps
                .first_fixed("1", &[], "semver", ctx())
                .await
                .unwrap()
                .as_deref(),
            Some("9")
        );
        assert_eq!(steps.scheme(None, ctx()).await.unwrap(), "semver");
        assert_eq!(steps.priority(Value::Null, ctx()).await.unwrap(), "P2");
        // reports: the base's, except the vulnerability reads, which go upstream
        assert_eq!(steps.methods(), Reporter::methods(&Base));
        let r = steps
            .report("reports.status", Value::Null, ctx())
            .await
            .unwrap();
        assert_eq!(r["from"], "base");
        let r = steps
            .report(
                "reports.vuln_detail",
                serde_json::json!({"id": "CVE-1", "raw": true}),
                ctx(),
            )
            .await
            .unwrap();
        assert_eq!(
            (r["from"].as_str(), r["id"].as_str(), r["raw"].as_bool()),
            (Some("upstream"), Some("CVE-1"), Some(true))
        );
        let rows = steps
            .report(
                "reports.vuln_search",
                serde_json::json!({"package": "x", "limit": 5}),
                ctx(),
            )
            .await
            .unwrap();
        assert_eq!(
            rows[0]["saw"]["package"], "x",
            "rows, not the wrapper: {rows}"
        );
        let e = steps
            .report("reports.vuln_detail", serde_json::json!({}), ctx())
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::InvalidParams);
    }
}
