//! [`LocalNode`]: the in-process `MatchService`, `VulnInfo` and `Feed` of a node with a mirror (proposal §3.3-3.6,
//! brief §6), over the mirror's [`MirrorNodeStore`], the engine's [`Matcher`] (py-engine, ephemeral mode) and its
//! [`Reporter`] (`reports.vuln_detail` / `reports.vuln_search`, the payloads of `/api/vulns/show` and
//! `/api/vulns/search`).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use secmonk_model::node::{
    ChangesRequest, ChangesResponse, ComponentIdentity, ComponentMatch, ComponentResult, Coverage,
    DEFAULT_OVERLAP_S, FeedMode, FeedPage, FeedSinceRequest, FeedStatus, MATCHER_VERSION,
    MAX_COMPONENTS, MAX_IDS, MatchComponentsRequest, MatchComponentsResponse, SourceChanges,
    SourceVersion, SummariesResponse, VersionKind, Versions, apply_overlap, parse_since_token,
};
use secmonk_model::{
    Asset, Component, INVENTORY_SCHEMA, Inventory, JsonMap, MatchParams, MatchResult,
};
use secmonk_store::{MirrorNodeStore, StoreError};
use secmonk_traits::node::{Feed, MatchService, VulnInfo};
use secmonk_traits::{CallCtx, ErrorCode, Matcher, Reporter, StepError, StepResult, WireError};
use serde_json::{Value, json};

use super::keys::component_lookup_keys;

/// Most changed records one source may answer in `match.changes` before it answers `resync("too many changes")`.
pub const CHANGES_LIMIT: usize = 20_000;
/// Records (record sources) or rows (snapshot sources) of a feed page when the request names no limit.
pub const FEED_DEFAULT_LIMIT: u32 = 2_000;
/// Most records or rows a feed request may ask for (the store clamps further: `MAX_FEED_RECORDS` records,
/// `MAX_ROWS_PAGE` rows per page).
pub const FEED_MAX_LIMIT: u32 = 10_000;
/// Most finding rows one ephemeral match returns (py-engine's `view_limit` bound): a chunk with more findings is
/// split and matched again.
const VIEW_LIMIT: u32 = 5_000;
/// The synthetic asset of a `match.components` request.
pub const MATCH_ASSET_ID: &str = "node:match-components";
/// Keys of a `SnapshotDiff` that mean "this diff is not known: answer `resync`" (an importer whose diff would cost
/// too much, see `secmonk-engine` `sync` and `rust/_docs/tech/engine-service.md`).
pub const DIFF_UNKNOWN_KEY: &str = "*";

/// A store failure as a wire error.
pub(crate) fn store_wire(e: StoreError) -> StepError {
    match e {
        StoreError::Invalid(m) => WireError::invalid_params(m),
        StoreError::Stale(m) => WireError::new(ErrorCode::Stale, m),
        StoreError::NotFound(m) => WireError::new(ErrorCode::UnknownSource, m),
        other => WireError::internal("StoreError", other),
    }
}

/// Settings of a [`LocalNode`].
#[derive(Debug, Clone, PartialEq)]
pub struct LocalNodeSettings {
    /// The node's identity (`feed.status`, `/node/v1/info`).
    pub node_id: Option<String>,
    /// Seconds deltas read below the client's version (proposal §3.2 rule 3).
    pub overlap_s: u64,
    /// The matcher version served ([`MATCHER_VERSION`]).
    pub matcher_version: String,
}

impl Default for LocalNodeSettings {
    fn default() -> Self {
        LocalNodeSettings {
            node_id: None,
            overlap_s: DEFAULT_OVERLAP_S,
            matcher_version: MATCHER_VERSION.to_owned(),
        }
    }
}

/// The node services of a node with a mirror, in process.
pub struct LocalNode {
    store: Arc<dyn MirrorNodeStore>,
    matcher: Arc<dyn Matcher>,
    reporter: Arc<dyn Reporter>,
    settings: LocalNodeSettings,
}

impl std::fmt::Debug for LocalNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalNode")
            .field("settings", &self.settings)
            .finish_non_exhaustive()
    }
}

/// What identifies a component in a view row (`reports.finding_dict`): name, version, category and purl (the
/// matcher's classify may fill `ecosystem` and `vendor`, so they are not part of it).
type Signature = (String, Option<String>, String, Option<String>);

fn signature(c: &ComponentIdentity) -> Signature {
    (
        c.name.clone(),
        c.version.clone(),
        c.category.as_str().to_owned(),
        c.purl.clone(),
    )
}

fn row_signature(row: &JsonMap) -> Option<Signature> {
    let s = |k: &str| row.get(k).and_then(Value::as_str).map(str::to_owned);
    Some((s("component")?, s("version"), s("category")?, s("purl")))
}

fn row_match(row: &JsonMap) -> Option<ComponentMatch> {
    let s = |k: &str| row.get(k).and_then(Value::as_str).map(str::to_owned);
    Some(ComponentMatch {
        vuln_id: s("vuln_id")?,
        advisory_ids: row
            .get("advisory_ids")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        matched_by: s("matched_by"),
        confidence: row.get("confidence").and_then(Value::as_f64),
        fixed_version: s("fixed_version"),
        triage: s("triage"),
        triage_source: s("triage_source"),
    })
}

/// The component a [`ComponentIdentity`] describes (no path; the identity meta only).
pub(crate) fn component_of(c: &ComponentIdentity) -> Component {
    Component {
        name: c.name.clone(),
        version: c.version.clone(),
        category: c.category,
        purl: c.purl.clone(),
        cpe: c.cpe.clone(),
        vendor: c.vendor.clone(),
        ecosystem: c.ecosystem.clone(),
        source_path: None,
        meta: c.meta.clone(),
    }
}

/// The synthetic inventory of a `match.components` chunk: one asset without facts.
fn synthetic_inventory(components: &[&ComponentIdentity]) -> Inventory {
    Inventory {
        schema: Some(INVENTORY_SCHEMA.to_owned()),
        classified: Some(true),
        asset: Asset {
            id: MATCH_ASSET_ID.to_owned(),
            kind: "directory".into(),
            name: MATCH_ASSET_ID.to_owned(),
            os_name: None,
            os_version: None,
            platform: None,
            meta: JsonMap::new(),
        },
        collector: "node".into(),
        components: components.iter().map(|c| component_of(c)).collect(),
        warnings: Vec::new(),
        partial: false,
        partial_reason: None,
    }
}

/// The base source of a qualified `source_sync` name (`osv:PyPI` -> `osv`).
pub(crate) fn base_source(name: &str) -> &str {
    name.split_once(':').map_or(name, |(b, _)| b)
}

/// The `vulns/search` query of `params` (as the API's query string): package, ecosystem, product, version, limit
/// (1..=1000, default 50).
fn search_params(params: &Value) -> StepResult<(Value, u32)> {
    let obj = params
        .as_object()
        .ok_or_else(|| WireError::invalid_params("search: expected an object"))?;
    let s = |k: &str| -> StepResult<Value> {
        match obj.get(k) {
            None | Some(Value::Null) => Ok(Value::Null),
            Some(Value::String(v)) if v.is_empty() => Ok(Value::Null),
            Some(Value::String(v)) => Ok(Value::String(v.clone())),
            Some(_) => Err(WireError::invalid_params(format!("{k}: expected a string"))),
        }
    };
    let limit = match obj.get("limit") {
        None | Some(Value::Null) => 50,
        Some(v) => {
            let n = v
                .as_u64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
                .ok_or_else(|| WireError::invalid_params("limit: expected an integer"))?;
            u32::try_from(n.clamp(1, 1000)).unwrap_or(1000)
        }
    };
    Ok((
        json!({"package": s("package")?, "ecosystem": s("ecosystem")?, "product": s("product")?,
               "version": s("version")?, "limit": limit}),
        limit,
    ))
}

impl LocalNode {
    /// The node services over a mirror, the engine's matcher and its report builder.
    pub fn new(
        store: Arc<dyn MirrorNodeStore>,
        matcher: Arc<dyn Matcher>,
        reporter: Arc<dyn Reporter>,
        settings: LocalNodeSettings,
    ) -> LocalNode {
        LocalNode {
            store,
            matcher,
            reporter,
            settings,
        }
    }

    /// The node's settings.
    pub fn settings(&self) -> &LocalNodeSettings {
        &self.settings
    }

    async fn current_versions(&self) -> StepResult<Versions> {
        let sources = self.store.source_versions().await.map_err(store_wire)?;
        Ok(Versions::new(&self.settings.matcher_version, sources))
    }

    /// One ephemeral match of `chunk` (distinct signatures): its findings per signature. A chunk with more findings
    /// than one view holds is split in two and matched again.
    async fn match_chunk(
        &self,
        chunk: &[&ComponentIdentity],
        min_confidence: f64,
    ) -> StepResult<HashMap<Signature, Vec<ComponentMatch>>> {
        let mut out: HashMap<Signature, Vec<ComponentMatch>> = HashMap::new();
        let mut todo: Vec<Vec<&ComponentIdentity>> = vec![chunk.to_vec()];
        while let Some(part) = todo.pop() {
            if part.is_empty() {
                continue;
            }
            let r: MatchResult = self
                .matcher
                .match_asset(
                    MatchParams::Ephemeral {
                        inventory: Box::new(synthetic_inventory(&part)),
                        min_confidence,
                        view_limit: Some(VIEW_LIMIT),
                    },
                    CallCtx::default(),
                )
                .await?;
            if r.stats.findings > r.view.len() as u64 || r.view.len() >= VIEW_LIMIT as usize {
                if part.len() == 1 {
                    return Err(WireError::internal(
                        "MatchError",
                        format!(
                            "component {} has more than {VIEW_LIMIT} findings",
                            part[0].key()
                        ),
                    ));
                }
                let (a, b) = part.split_at(part.len() / 2);
                todo.push(a.to_vec());
                todo.push(b.to_vec());
                continue;
            }
            let sigs: BTreeSet<Signature> = part.iter().map(|c| signature(c)).collect();
            for row in &r.view {
                let (Some(sig), Some(m)) = (row_signature(row), row_match(row)) else {
                    return Err(WireError::protocol(
                        "engine.match: a view row without component, category or vuln_id",
                    ));
                };
                if !sigs.contains(&sig) {
                    return Err(WireError::protocol(format!(
                        "engine.match: a finding of a component that was not sent ({})",
                        sig.0
                    )));
                }
                out.entry(sig).or_default().push(m);
            }
        }
        Ok(out)
    }
}

#[async_trait]
impl MatchService for LocalNode {
    async fn match_components(
        &self,
        req: MatchComponentsRequest,
    ) -> StepResult<MatchComponentsResponse> {
        if req.components.len() > MAX_COMPONENTS {
            return Err(WireError::invalid_params(format!(
                "components: at most {MAX_COMPONENTS} per request ({} given)",
                req.components.len()
            )));
        }
        let min_confidence = req.min_confidence.unwrap_or(0.0);
        if !(0.0..=1.0).contains(&min_confidence) {
            return Err(WireError::invalid_params("min_confidence: expected 0..1"));
        }
        let as_of = self.current_versions().await?;
        // distinct keys, first occurrence wins; components that the view cannot tell apart (same name, version,
        // category and purl: keys that differ only by vendor) go to separate rounds
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut rounds: Vec<(BTreeSet<Signature>, Vec<&ComponentIdentity>)> = Vec::new();
        for c in &req.components {
            if !seen.insert(c.key()) {
                continue;
            }
            let sig = signature(c);
            match rounds.iter_mut().find(|(s, _)| !s.contains(&sig)) {
                Some((s, v)) => {
                    s.insert(sig);
                    v.push(c);
                }
                None => rounds.push((BTreeSet::from([sig]), vec![c])),
            }
        }
        let mut by_key: HashMap<String, Vec<ComponentMatch>> = HashMap::new();
        for (_, comps) in &rounds {
            let found = self.match_chunk(comps, min_confidence).await?;
            for c in comps {
                let mut m = found.get(&signature(c)).cloned().unwrap_or_default();
                m.sort_by(|a, b| a.vuln_id.cmp(&b.vuln_id));
                by_key.insert(c.key(), m);
            }
        }
        let results = req
            .components
            .iter()
            .map(|c| {
                let key = c.key();
                ComponentResult {
                    matches: by_key.get(&key).cloned().unwrap_or_default(),
                    lookup_keys: component_lookup_keys(c),
                    key,
                }
            })
            .collect();
        let coverage = Coverage {
            sources: as_of
                .sources
                .values()
                .filter(|s| s.version.is_some())
                .map(|s| s.source.clone())
                .collect(),
            ecosystems: self.store.covered_ecosystems().await.map_err(store_wire)?,
        };
        Ok(MatchComponentsResponse {
            results,
            as_of,
            coverage,
        })
    }

    async fn changes(&self, req: ChangesRequest) -> StepResult<ChangesResponse> {
        let as_of = self.current_versions().await?;
        let matcher_changed = req.matcher.as_deref().is_some_and(|m| m != as_of.matcher);
        let mut out: BTreeMap<String, SourceChanges> = BTreeMap::new();
        for (name, sv) in &as_of.sources {
            let answer = if matcher_changed {
                SourceChanges::Resync("matcher".into())
            } else {
                self.source_changes(name, sv, req.since.get(name)).await?
            };
            out.insert(name.clone(), answer);
        }
        for name in req.since.keys() {
            if !as_of.sources.contains_key(name) {
                out.insert(name.clone(), SourceChanges::Resync("source removed".into()));
            }
        }
        Ok(ChangesResponse {
            sources: out,
            as_of,
        })
    }

    async fn versions(&self) -> StepResult<Versions> {
        self.current_versions().await
    }
}

impl LocalNode {
    /// The changes of one source since the client's token.
    async fn source_changes(
        &self,
        name: &str,
        sv: &SourceVersion,
        client: Option<&String>,
    ) -> StepResult<SourceChanges> {
        let (token, server) = match (client, sv.version.as_deref()) {
            // the source never completed an import here: nothing is served, nothing changed
            (None, None) => return Ok(SourceChanges::Unchanged),
            (None, Some(_)) => return Ok(SourceChanges::Resync("new source".into())),
            // the client holds a version this node does not serve (no complete import here)
            (Some(_), None) => return Ok(SourceChanges::Resync("no version".into())),
            (Some(t), Some(v)) => (t, v),
        };
        let Some((importer, version)) = parse_since_token(token) else {
            return Ok(SourceChanges::Resync("bad version".into()));
        };
        if importer != sv.importer {
            return Ok(SourceChanges::Resync("importer".into()));
        }
        if version == server {
            return Ok(SourceChanges::Unchanged);
        }
        match sv.kind {
            VersionKind::Record => {
                let changed = self
                    .store
                    .changed_vulns(
                        base_source(name),
                        version,
                        self.settings.overlap_s,
                        CHANGES_LIMIT + 1,
                    )
                    .await
                    .map_err(store_wire)?;
                if changed.len() > CHANGES_LIMIT {
                    return Ok(SourceChanges::Resync("too many changes".into()));
                }
                let ids: BTreeSet<String> = changed.into_iter().map(|(id, _)| id).collect();
                let ids: Vec<String> = ids.into_iter().collect();
                let keys = self
                    .store
                    .lookup_keys_for_vulns(&ids)
                    .await
                    .map_err(store_wire)?;
                Ok(SourceChanges::Changed {
                    changed_keys: keys,
                    changed_ids: ids,
                })
            }
            VersionKind::Snapshot => {
                let Some(diffs) = self
                    .store
                    .snapshot_diffs_since(name, version)
                    .await
                    .map_err(store_wire)?
                else {
                    return Ok(SourceChanges::Resync("no diff log".into()));
                };
                if diffs
                    .iter()
                    .any(|d| d.keys.iter().any(|k| k == DIFF_UNKNOWN_KEY))
                {
                    return Ok(SourceChanges::Resync("no diff for this version".into()));
                }
                let mut ids = BTreeSet::new();
                let mut keys = BTreeSet::new();
                for d in diffs {
                    ids.extend(d.ids);
                    keys.extend(d.keys);
                }
                Ok(SourceChanges::Changed {
                    changed_keys: keys.into_iter().collect(),
                    changed_ids: ids.into_iter().collect(),
                })
            }
        }
    }

    /// The served version of a feed source: its own entry, else (a base source such as `osv` whose versions are per
    /// ecosystem) one synthesized from its qualified entries with the OLDEST version (a follower that applies from
    /// it re-reads more, never less).
    async fn feed_version(&self, source: &str) -> StepResult<SourceVersion> {
        let all = self.store.source_versions().await.map_err(store_wire)?;
        if let Some(v) = all.iter().find(|v| v.source == source) {
            return Ok(v.clone());
        }
        let parts: Vec<&SourceVersion> = all
            .iter()
            .filter(|v| base_source(&v.source) == source)
            .collect();
        let Some(first) = parts.first() else {
            return Err(WireError::new(
                ErrorCode::UnknownSource,
                format!("unknown source {source:?}"),
            ));
        };
        let version = if parts.iter().all(|p| p.version.is_some()) {
            parts.iter().filter_map(|p| p.version.clone()).min()
        } else {
            None
        };
        Ok(SourceVersion {
            source: source.to_owned(),
            version,
            importer: first.importer.clone(),
            kind: VersionKind::default_for(source),
            records: parts.iter().map(|p| p.records).sum(),
            last_sync: parts.iter().filter_map(|p| p.last_sync.clone()).max(),
            status: None,
        })
    }
}

#[async_trait]
impl VulnInfo for LocalNode {
    async fn summaries(&self, ids: &[String]) -> StepResult<SummariesResponse> {
        if ids.len() > MAX_IDS {
            return Err(WireError::invalid_params(format!(
                "ids: at most {MAX_IDS} per request ({} given)",
                ids.len()
            )));
        }
        let summaries = self.store.summaries(ids).await.map_err(store_wire)?;
        let found: BTreeSet<&str> = summaries.iter().map(|s| s.id.as_str()).collect();
        let mut missing: Vec<String> = Vec::new();
        for i in ids {
            if !found.contains(i.as_str()) && !missing.contains(i) {
                missing.push(i.clone());
            }
        }
        Ok(SummariesResponse { summaries, missing })
    }

    async fn detail(&self, id: &str, raw: bool) -> StepResult<Value> {
        let v = self
            .reporter
            .report(
                "reports.vuln_detail",
                json!({"id": id, "raw": raw}),
                CallCtx::default(),
            )
            .await?;
        if v.is_null() {
            return Err(WireError::new(
                ErrorCode::UnknownVuln,
                format!("unknown vulnerability id {id:?}"),
            ));
        }
        Ok(v)
    }

    async fn search(&self, params: Value) -> StepResult<Value> {
        let (params, limit) = search_params(&params)?;
        let rows = self
            .reporter
            .report("reports.vuln_search", params, CallCtx::default())
            .await?;
        let n = rows.as_array().map_or(0, Vec::len);
        Ok(json!({"results": rows, "limit": limit, "limit_reached": n >= limit as usize}))
    }
}

#[async_trait]
impl Feed for LocalNode {
    async fn status(&self) -> StepResult<FeedStatus> {
        let v = self.current_versions().await?;
        Ok(FeedStatus {
            node_id: self.settings.node_id.clone(),
            matcher: v.matcher,
            sources: v.sources.into_values().collect(),
        })
    }

    /// `since` is the follower's version of the source, either the plain upstream version or the token
    /// `"<importer>@<version>"`; with a token whose importer differs from this node's, the answer is the whole
    /// source (snapshot mode).
    async fn since(&self, req: FeedSinceRequest) -> StepResult<FeedPage> {
        let version = self.feed_version(&req.source).await?;
        let limit = req
            .limit
            .unwrap_or(FEED_DEFAULT_LIMIT)
            .clamp(1, FEED_MAX_LIMIT) as usize;
        let page = req.page.as_deref();
        let (mode, (batches, next_page)) = match version.kind {
            VersionKind::Snapshot => (
                FeedMode::Snapshot,
                self.store
                    .rows_snapshot(&req.source, page, limit)
                    .await
                    .map_err(store_wire)?,
            ),
            VersionKind::Record => {
                let since = req
                    .since
                    .as_deref()
                    .filter(|s| !s.is_empty())
                    .and_then(|s| match parse_since_token(s) {
                        Some((importer, v)) => (importer == version.importer).then_some(v),
                        None => Some(s),
                    });
                match since {
                    Some(v) => {
                        let lower = apply_overlap(v, self.settings.overlap_s);
                        (
                            FeedMode::Delta,
                            self.store
                                .rows_since(&req.source, Some(&lower), page, limit)
                                .await
                                .map_err(store_wire)?,
                        )
                    }
                    None => (
                        FeedMode::Snapshot,
                        self.store
                            .rows_since(&req.source, None, page, limit)
                            .await
                            .map_err(store_wire)?,
                    ),
                }
            }
        };
        Ok(FeedPage {
            source: req.source,
            version,
            mode,
            batches,
            next_page,
        })
    }
}
