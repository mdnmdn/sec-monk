//! [`NodeMatcher`]: the [`Matcher`] of a state-only node (proposal §3.3-3.5). It never reads a mirror: match sets
//! come per component key from a [`MatchService`] and are kept in the state's node cache ([`NodeCacheStore`]),
//! vulnerability facts come from [`VulnInfo::summaries`] (cached too), and the node scores per asset itself
//! (`scoring.priority` through [`VersionOracle::priority`] with the asset's `meta`) and keeps the finding lifecycle.
//!
//! **Freshness of a cached answer.** Every answer is stamped `"<matcher>#<epoch>"` in its `as_of.matcher`. The cache
//! is kept current by [`NodeMatcher::poll_changes`] (`match.changes` since the versions it last saw): components hit by
//! changed lookup keys or vulnerability ids are asked again, and a `resync` of a source raises the epoch and records
//! it for that source. An answer is current when its matcher is the service's and no source whose **family** covers
//! the component (proposal §3.3 table: `osv:<Eco>` -> `pkg:<eco>/…` keys, `debian-tracker` -> `pkg:debian…` keys,
//! `kev` / `epss` -> none, any other source -> every component) was resynced after the answer's epoch. Components
//! of the stored inventory are re-asked during the poll; others are re-asked when a scan next needs them.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use async_trait::async_trait;
use secmonk_model::node::{
    AsOf, ComponentIdentity, ComponentMatch, ComponentResult, MAX_COMPONENTS, MAX_IDS,
    MatchComponentsRequest, Versions, VulnSummary,
};
use secmonk_model::time::now_iso;
use secmonk_model::{
    BasedOn, Component, Finding, FindingStatus, JsonMap, MatchMode, MatchParams, MatchResult,
    MatchStats,
};
use secmonk_store::{NodeCacheStore, StateStore};
use secmonk_traits::node::{MatchService, VulnInfo};
use secmonk_traits::{CallCtx, ErrorCode, Matcher, StepResult, VersionOracle, WireError};
use serde_json::json;
use tokio::sync::Mutex;

use super::MAX_VIEW_LIMIT;
use super::changes::{ChangeSummary, affected_components, in_family};
use super::keys::component_lookup_keys;
use super::local::store_wire;
use super::versions::matcher_version;

/// `node_sync` name of the versions the cache is current at (JSON [`AsOf`]).
pub const SYNC_AS_OF: &str = "match.as_of";
/// `node_sync` name of the cache epoch (an integer).
pub const SYNC_EPOCH: &str = "match.epoch";
/// `node_sync` name of the epoch of the last `resync` per source (JSON object source -> epoch).
pub const SYNC_RESYNC: &str = "match.resync";
/// `node_sync` name of this node's own matcher version when the cache was last made current (its lookup keys and
/// matching code; a change starts a new epoch like a change of the service's matcher).
pub const SYNC_LOCAL: &str = "match.local";
/// The stamp of an answer invalidated because its component was hit while not in the stored inventory.
const INVALID_STAMP: &str = "invalidated#0";
/// Rows in `view` when the params name no limit (py-engine's default).
const DEFAULT_VIEW: u32 = 500;

/// What [`NodeMatcher::poll_changes`] did.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PollStats {
    /// Component keys of the stored inventory that were asked again (their match sets may have changed).
    pub hit_keys: Vec<String>,
    /// Vulnerability ids that changed (their summaries were refreshed; findings on them may score differently).
    pub changed_ids: Vec<String>,
    /// Sources that answered `resync`.
    pub resynced: Vec<String>,
    /// Cached answers of components not in the stored inventory that were invalidated.
    pub invalidated: u64,
    /// Summaries fetched again.
    pub summaries: u64,
    /// The versions the cache is current at now.
    pub as_of: AsOf,
}

fn stamp(matcher: &str, epoch: u64) -> String {
    format!("{matcher}#{epoch}")
}

/// `(matcher, epoch)` of a stamp.
fn parse_stamp(s: &str) -> Option<(&str, u64)> {
    let (m, e) = s.rsplit_once('#')?;
    Some((m, e.parse().ok()?))
}

/// The node-cache state the freshness rule needs.
struct CacheState {
    /// The service's matcher at the last poll.
    matcher: String,
    epoch: u64,
    /// Source -> epoch of its last resync.
    resync: BTreeMap<String, u64>,
}

impl CacheState {
    /// Whether an answer stamped `as_of` is current for a component whose lookup keys are `keys` (the stored ones
    /// when there are, else `component_lookup_keys(ident)`).
    fn fresh(
        &self,
        as_of: Option<&AsOf>,
        ident: &ComponentIdentity,
        stored: Option<&Vec<String>>,
    ) -> bool {
        let Some((m, e)) = as_of.and_then(|a| parse_stamp(&a.matcher)) else {
            return false;
        };
        if m != self.matcher {
            return false;
        }
        let stale_sources: Vec<&String> = self
            .resync
            .iter()
            .filter(|(_, r)| **r > e)
            .map(|(s, _)| s)
            .collect();
        if stale_sources.is_empty() {
            return true;
        }
        let computed;
        let keys: &[String] = match stored {
            Some(k) => k,
            None => {
                computed = component_lookup_keys(ident);
                &computed
            }
        };
        !stale_sources.iter().any(|s| in_family(s, keys))
    }
}

/// The matcher of a state-only node.
pub struct NodeMatcher {
    service: Arc<dyn MatchService>,
    info: Arc<dyn VulnInfo>,
    cache: Arc<dyn NodeCacheStore>,
    oracle: Arc<dyn VersionOracle>,
    state: Arc<dyn StateStore>,
    /// This node's own matcher version (lookup keys, scoring code): saved as [`SYNC_LOCAL`].
    local_version: String,
    /// One poll at a time: two concurrent polls would read the same saved state and race on the epoch.
    poll_lock: Mutex<()>,
}

impl std::fmt::Debug for NodeMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeMatcher").finish_non_exhaustive()
    }
}

/// One component to score: its state id (or a synthetic one), the component and its key.
struct Item {
    id: i64,
    component: Component,
    ident: ComponentIdentity,
    key: String,
}

impl NodeMatcher {
    /// A matcher over a match service, a summary service, the state's node cache, the version oracle (for
    /// `scoring.priority`) and the state store (inventory and findings of persisted matches).
    pub fn new(
        service: Arc<dyn MatchService>,
        info: Arc<dyn VulnInfo>,
        cache: Arc<dyn NodeCacheStore>,
        oracle: Arc<dyn VersionOracle>,
        state: Arc<dyn StateStore>,
    ) -> NodeMatcher {
        NodeMatcher {
            service,
            info,
            cache,
            oracle,
            state,
            local_version: matcher_version().to_owned(),
            poll_lock: Mutex::new(()),
        }
    }

    /// This node's own matcher version (default: [`matcher_version`](super::matcher_version) of this build). When
    /// it differs from the one saved with the cache, the next poll starts a new epoch: every cached answer is
    /// asked again (the lookup keys and the code that reads them may have changed).
    #[must_use]
    pub fn with_local_version(mut self, version: impl Into<String>) -> NodeMatcher {
        self.local_version = version.into();
        self
    }

    /// The lookup keys of `idents` (component key -> keys): the stored ones (as the service returned them) when
    /// there are, else [`component_lookup_keys`].
    async fn lookup_keys(
        &self,
        idents: &BTreeMap<String, ComponentIdentity>,
    ) -> StepResult<BTreeMap<String, Vec<String>>> {
        let keys: Vec<String> = idents.keys().cloned().collect();
        let mut stored = self
            .cache
            .stored_lookup_keys(&keys)
            .await
            .map_err(store_wire)?;
        Ok(idents
            .iter()
            .map(|(k, ident)| {
                let lk = stored
                    .remove(k)
                    .unwrap_or_else(|| component_lookup_keys(ident));
                (k.clone(), lk)
            })
            .collect())
    }

    async fn sync_get(&self, name: &str) -> StepResult<Option<String>> {
        self.cache.node_sync_get(name).await.map_err(store_wire)
    }

    /// Save the cache state in one transaction (all or nothing).
    async fn save_state(
        &self,
        epoch: u64,
        resync: &BTreeMap<String, u64>,
        as_of: &str,
    ) -> StepResult<()> {
        let epoch = epoch.to_string();
        let resync =
            serde_json::to_string(resync).map_err(|e| WireError::internal("SerializeError", e))?;
        self.cache
            .node_sync_set_many(&[
                (SYNC_EPOCH, &epoch),
                (SYNC_RESYNC, &resync),
                (SYNC_AS_OF, as_of),
                (SYNC_LOCAL, &self.local_version),
            ])
            .await
            .map_err(store_wire)
    }

    async fn cache_state(&self) -> StepResult<(Option<AsOf>, CacheState)> {
        let as_of: Option<AsOf> = self
            .sync_get(SYNC_AS_OF)
            .await?
            .and_then(|s| serde_json::from_str(&s).ok());
        let epoch = self
            .sync_get(SYNC_EPOCH)
            .await?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let resync = self
            .sync_get(SYNC_RESYNC)
            .await?
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        let matcher = as_of
            .as_ref()
            .map(|a| a.matcher.clone())
            .unwrap_or_default();
        Ok((
            as_of,
            CacheState {
                matcher,
                epoch,
                resync,
            },
        ))
    }

    /// Every current component of the stored inventory, by key.
    async fn inventory(&self) -> StepResult<BTreeMap<String, ComponentIdentity>> {
        let mut out = BTreeMap::new();
        for asset in self.state.asset_ids().await.map_err(store_wire)? {
            for c in self
                .state
                .current_components(&asset)
                .await
                .map_err(store_wire)?
            {
                let ident = ComponentIdentity::from_component(&c.component);
                out.entry(ident.key()).or_insert(ident);
            }
        }
        Ok(out)
    }

    /// Ask the service for `idents` (distinct keys), store the answers stamped with `epoch`.
    async fn ask(&self, idents: &[ComponentIdentity], epoch: u64) -> StepResult<()> {
        for chunk in idents.chunks(MAX_COMPONENTS) {
            let resp = self
                .service
                .match_components(MatchComponentsRequest {
                    components: chunk.to_vec(),
                    min_confidence: None,
                })
                .await?;
            let stamped = Versions {
                matcher: stamp(&resp.as_of.matcher, epoch),
                sources: resp.as_of.sources,
            };
            self.cache
                .put_component_results(&resp.results, &stamped)
                .await
                .map_err(store_wire)?;
        }
        Ok(())
    }

    /// Fetch and cache the summaries of `ids` (chunks of `MAX_IDS`); returns how many came back.
    async fn fetch_summaries(&self, ids: &[String]) -> StepResult<u64> {
        let mut n = 0;
        for chunk in ids.chunks(MAX_IDS) {
            let r = self.info.summaries(chunk).await?;
            n += r.summaries.len() as u64;
            self.cache
                .put_summaries(&r.summaries)
                .await
                .map_err(store_wire)?;
        }
        Ok(n)
    }

    /// `match.changes` since the versions the cache saw last; the hit components of the stored inventory asked
    /// again, the summaries of changed ids fetched again, a `resync` recorded per source (see the module doc), the
    /// new versions saved. The first poll (nothing saved) only saves the versions and starts a new epoch: nothing
    /// cached before can be trusted.
    ///
    /// Polls run one at a time (a mutex), and the epoch, the resync map, the versions and this node's own matcher
    /// version are saved together in one transaction **after** every call to the service succeeded: a poll that
    /// fails half-way leaves the saved state as it was (the next poll asks the same changes again; answers stored
    /// before the failure are current anyway, they were computed after the changes).
    pub async fn poll_changes(&self) -> StepResult<PollStats> {
        let _one = self.poll_lock.lock().await;
        let (stored, mut st) = self.cache_state().await?;
        let saved_local = self.sync_get(SYNC_LOCAL).await?;
        let resp = self
            .service
            .changes(secmonk_model::node::ChangesRequest {
                since: stored.as_ref().map(|a| a.since.clone()).unwrap_or_default(),
                matcher: stored.as_ref().map(|a| a.matcher.clone()),
            })
            .await?;
        let new_as_of = resp.as_of.as_of();
        let mut stats = PollStats {
            as_of: new_as_of.clone(),
            ..PollStats::default()
        };
        let save_as_of = serde_json::to_string(&new_as_of)
            .map_err(|e| WireError::internal("SerializeError", e))?;
        let matcher_changed = stored
            .as_ref()
            .is_none_or(|a| a.matcher != new_as_of.matcher);
        let local_changed =
            stored.is_some() && saved_local.as_deref() != Some(self.local_version.as_str());
        if matcher_changed || local_changed {
            // nothing answered under another matcher is current: a new epoch, every source counts as resynced
            st.epoch += 1;
            stats.resynced = resp.sources.keys().cloned().collect();
            if stored.is_some() {
                // the stored inventory is asked again under the new matcher (before anything is saved)
                let inv = self.inventory().await?;
                let idents: Vec<ComponentIdentity> = inv.values().cloned().collect();
                self.ask(&idents, st.epoch).await?;
                stats.hit_keys = inv.into_keys().collect();
            }
            self.save_state(st.epoch, &BTreeMap::new(), &save_as_of)
                .await?;
            return Ok(stats);
        }
        let changes = ChangeSummary::of(&resp.sources);
        // cached answers hit by a changed key or id (components of the inventory or not)
        let by_keys: Vec<String> = changes.keys.iter().cloned().collect();
        let by_ids: Vec<String> = changes.ids.iter().cloned().collect();
        let mut cached_hit: BTreeSet<String> = self
            .cache
            .components_by_lookup_keys(&by_keys)
            .await
            .map_err(store_wire)?
            .into_iter()
            .collect();
        let with_changed_ids: BTreeSet<String> = self
            .cache
            .components_by_vuln_ids(&by_ids)
            .await
            .map_err(store_wire)?
            .into_iter()
            .collect();
        cached_hit.extend(with_changed_ids.iter().cloned());
        let resynced: Vec<String> = changes.resynced.iter().map(|(s, _)| s.clone()).collect();
        let needs_inventory = !cached_hit.is_empty() || !resynced.is_empty();
        let inv = if needs_inventory {
            self.inventory().await?
        } else {
            BTreeMap::new()
        };
        if !resynced.is_empty() {
            st.epoch += 1;
            for s in changes.match_resyncs() {
                st.resync.insert(s.to_owned(), st.epoch);
            }
        }
        let lookup = self.lookup_keys(&inv).await?;
        let asked: BTreeSet<String> = affected_components(&changes, &lookup, &with_changed_ids);
        // hit components not in the stored inventory: invalidated (re-asked when a scan needs them)
        let gone: Vec<String> = cached_hit
            .into_iter()
            .filter(|k| !inv.contains_key(k))
            .collect();
        if !gone.is_empty() {
            let invalid: Vec<ComponentResult> = gone
                .iter()
                .map(|k| ComponentResult {
                    key: k.clone(),
                    matches: Vec::new(),
                    lookup_keys: Vec::new(),
                })
                .collect();
            self.cache
                .put_component_results(
                    &invalid,
                    &Versions {
                        matcher: INVALID_STAMP.into(),
                        sources: BTreeMap::new(),
                    },
                )
                .await
                .map_err(store_wire)?;
        }
        let idents: Vec<ComponentIdentity> =
            asked.iter().filter_map(|k| inv.get(k).cloned()).collect();
        self.ask(&idents, st.epoch).await?;
        // summaries: the changed ids this node holds, or every matched id after an enrichment resync
        let refresh: Vec<String> = if changes.enrichment_resync() {
            let keys: Vec<String> = inv.keys().cloned().collect();
            let mut ids = BTreeSet::new();
            for ms in self
                .cache
                .component_matches(&keys)
                .await
                .map_err(store_wire)?
                .into_values()
            {
                ids.extend(ms.into_iter().map(|m| m.vuln_id));
            }
            ids.extend(changes.ids.iter().cloned());
            ids.into_iter().collect()
        } else {
            self.cache
                .cached_summaries(&by_ids)
                .await
                .map_err(store_wire)?
                .into_iter()
                .map(|s| s.id)
                .collect()
        };
        stats.summaries = self.fetch_summaries(&refresh).await?;
        self.save_state(st.epoch, &st.resync, &save_as_of).await?;
        stats.invalidated = gone.len() as u64;
        stats.hit_keys = asked.into_iter().collect();
        stats.changed_ids = by_ids;
        stats.resynced = resynced;
        Ok(stats)
    }

    /// The match sets of `items` (asked for the keys without a current answer).
    async fn match_sets(
        &self,
        items: &[Item],
    ) -> StepResult<BTreeMap<String, Vec<ComponentMatch>>> {
        self.poll_changes().await?;
        let (_, st) = self.cache_state().await?;
        let keys: Vec<String> = items
            .iter()
            .map(|i| i.key.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let as_of = self
            .cache
            .component_as_of(&keys)
            .await
            .map_err(store_wire)?;
        let stored = if st.resync.is_empty() {
            BTreeMap::new()
        } else {
            self.cache
                .stored_lookup_keys(&keys)
                .await
                .map_err(store_wire)?
        };
        let mut seen = BTreeSet::new();
        let stale: Vec<ComponentIdentity> = items
            .iter()
            .filter(|i| seen.insert(i.key.clone()))
            .filter(|i| !st.fresh(as_of.get(&i.key), &i.ident, stored.get(&i.key)))
            .map(|i| i.ident.clone())
            .collect();
        self.ask(&stale, st.epoch).await?;
        self.cache
            .component_matches(&keys)
            .await
            .map_err(store_wire)
    }

    /// Summaries of `ids` from the cache, the misses fetched and cached.
    async fn summaries(&self, ids: &[String]) -> StepResult<HashMap<String, VulnSummary>> {
        let mut out: HashMap<String, VulnSummary> = self
            .cache
            .cached_summaries(ids)
            .await
            .map_err(store_wire)?
            .into_iter()
            .map(|s| (s.id.clone(), s))
            .collect();
        let missing: Vec<String> = ids
            .iter()
            .filter(|i| !out.contains_key(*i))
            .cloned()
            .collect();
        for chunk in missing.chunks(MAX_IDS) {
            let r = self.info.summaries(chunk).await?;
            self.cache
                .put_summaries(&r.summaries)
                .await
                .map_err(store_wire)?;
            out.extend(r.summaries.into_iter().map(|s| (s.id.clone(), s)));
        }
        Ok(out)
    }

    /// The findings of `items` (status open, timestamps now), before the lifecycle; and the raw match count.
    async fn score(
        &self,
        items: &[Item],
        asset_meta: &JsonMap,
        min_confidence: f64,
    ) -> StepResult<(Vec<Finding>, u64)> {
        let sets = self.match_sets(items).await?;
        let ids: Vec<String> = sets
            .values()
            .flatten()
            .map(|m| m.vuln_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let summaries = self.summaries(&ids).await?;
        let now = now_iso();
        let mut prio_cache: HashMap<String, Option<String>> = HashMap::new();
        let mut out = Vec::new();
        let mut raw = 0u64;
        let mut done = BTreeSet::new();
        for item in items {
            let Some(ms) = sets.get(&item.key) else {
                continue;
            };
            for m in ms {
                raw += 1;
                if m.confidence.is_some_and(|c| c < min_confidence)
                    || !done.insert((item.id, m.vuln_id.clone()))
                {
                    continue;
                }
                let s = summaries.get(&m.vuln_id);
                let severity = s.and_then(|s| s.severity.clone());
                let cvss = s.and_then(|s| s.cvss_score);
                let epss = s.and_then(|s| s.epss);
                let kev = s.is_some_and(|s| s.kev);
                let params = json!({"cvss": cvss, "epss": epss, "kev": kev, "asset_meta": asset_meta,
                                    "triage": m.triage, "severity": severity});
                let pk = json!([cvss, epss, kev, m.triage, severity]).to_string();
                let priority = match prio_cache.get(&pk) {
                    Some(p) => p.clone(),
                    None => {
                        let p = Some(self.oracle.priority(params, CallCtx::default()).await?);
                        prio_cache.insert(pk, p.clone());
                        p
                    }
                };
                out.push(Finding {
                    component_id: item.id,
                    vuln_id: m.vuln_id.clone(),
                    advisory_ids: m.advisory_ids.clone(),
                    matched_by: m.matched_by.clone(),
                    confidence: m.confidence,
                    fixed_version: m.fixed_version.clone(),
                    severity,
                    cvss_score: cvss,
                    epss,
                    kev,
                    priority,
                    status: FindingStatus::Open,
                    first_seen: Some(now.clone()),
                    last_seen: Some(now.clone()),
                    fixed_at: None,
                    triage: m.triage.clone(),
                    triage_source: m.triage_source.clone(),
                });
            }
        }
        out.sort_by(|a, b| (a.component_id, &a.vuln_id).cmp(&(b.component_id, &b.vuln_id)));
        Ok((out, raw))
    }
}

/// The lifecycle of `match_asset`: a re-detected finding keeps `first_seen` and a `suppressed` status; an open
/// finding not re-detected becomes `fixed` (`fixed_at` now); fixed and suppressed ones not re-detected stay.
fn lifecycle(new: Vec<Finding>, old: Vec<Finding>) -> Vec<Finding> {
    let now = now_iso();
    let mut old_by: HashMap<(i64, String), Finding> = old
        .into_iter()
        .map(|f| ((f.component_id, f.vuln_id.clone()), f))
        .collect();
    let mut out: Vec<Finding> = Vec::new();
    for mut f in new {
        if let Some(o) = old_by.remove(&(f.component_id, f.vuln_id.clone())) {
            f.first_seen = o.first_seen.or(f.first_seen);
            if o.status == FindingStatus::Suppressed {
                f.status = FindingStatus::Suppressed;
            }
        }
        out.push(f);
    }
    for (_, mut o) in old_by {
        if o.status == FindingStatus::Open {
            o.status = FindingStatus::Fixed;
            o.fixed_at = Some(now.clone());
        }
        out.push(o);
    }
    out.sort_by(|a, b| (a.component_id, &a.vuln_id).cmp(&(b.component_id, &b.vuln_id)));
    out
}

/// A finding as an API finding row (`reports.finding_dict`, `api/finding-row.schema.json`).
fn view_row(asset_id: &str, f: &Finding, c: &Component) -> JsonMap {
    let v = json!({
        "asset_id": asset_id, "priority": f.priority, "vuln_id": f.vuln_id, "component": c.name,
        "version": c.version, "category": c.category.as_str(), "fixed_version": f.fixed_version,
        "severity": f.severity, "cvss_score": f.cvss_score, "epss": f.epss, "kev": f.kev, "triage": f.triage,
        "matched_by": f.matched_by, "confidence": f.confidence, "status": f.status.as_str(),
        "component_id": f.component_id, "advisory_ids": f.advisory_ids, "triage_source": f.triage_source,
        "first_seen": f.first_seen, "last_seen": f.last_seen, "fixed_at": f.fixed_at, "ecosystem": c.ecosystem,
        "purl": c.purl,
    });
    v.as_object().cloned().unwrap_or_default()
}

/// The open findings as view rows in `queries.findings` order (priority, KEV first, EPSS and CVSS descending,
/// vuln id, component name; NULL priority first and NULL scores last, as SQLite sorts), at most `limit`.
fn view(asset_id: &str, set: &[Finding], items: &[Item], limit: u32) -> Vec<JsonMap> {
    let by_id: HashMap<i64, &Component> = items.iter().map(|i| (i.id, &i.component)).collect();
    let mut open: Vec<(&Finding, &Component)> = set
        .iter()
        .filter(|f| f.status == FindingStatus::Open)
        .filter_map(|f| by_id.get(&f.component_id).map(|c| (f, *c)))
        .collect();
    let desc = |a: Option<f64>, b: Option<f64>| {
        b.unwrap_or(f64::NEG_INFINITY)
            .partial_cmp(&a.unwrap_or(f64::NEG_INFINITY))
            .unwrap_or(std::cmp::Ordering::Equal)
    };
    open.sort_by(|(a, ca), (b, cb)| {
        a.priority
            .cmp(&b.priority)
            .then(b.kev.cmp(&a.kev))
            .then(desc(a.epss, b.epss))
            .then(desc(a.cvss_score, b.cvss_score))
            .then(a.vuln_id.cmp(&b.vuln_id))
            .then(ca.name.cmp(&cb.name))
    });
    open.into_iter()
        .take(limit as usize)
        .map(|(f, c)| view_row(asset_id, f, c))
        .collect()
}

#[async_trait]
impl Matcher for NodeMatcher {
    async fn match_asset(&self, params: MatchParams, _ctx: CallCtx) -> StepResult<MatchResult> {
        match params {
            MatchParams::Persisted {
                asset_id,
                min_confidence,
                view_limit,
            } => {
                check_params(min_confidence, view_limit)?;
                let Some(facts) = self
                    .state
                    .asset_reuse_facts(&asset_id)
                    .await
                    .map_err(store_wire)?
                else {
                    return Err(WireError::new(
                        ErrorCode::UnknownAsset,
                        format!("unknown asset {asset_id:?}"),
                    ));
                };
                let latest = facts.latest_scan_id;
                let items: Vec<Item> = self
                    .state
                    .current_components(&asset_id)
                    .await
                    .map_err(store_wire)?
                    .into_iter()
                    .map(|s| {
                        let ident = ComponentIdentity::from_component(&s.component);
                        Item {
                            id: s.id,
                            key: ident.key(),
                            ident,
                            component: s.component,
                        }
                    })
                    .collect();
                let (found, raw) = self.score(&items, &facts.meta, min_confidence).await?;
                let n = found.len() as u64;
                let old = self
                    .state
                    .asset_findings(&asset_id)
                    .await
                    .map_err(store_wire)?;
                let set = lifecycle(found, old);
                let view = view(&asset_id, &set, &items, view_limit.unwrap_or(DEFAULT_VIEW));
                Ok(MatchResult {
                    asset_id,
                    mode: MatchMode::Persisted,
                    stats: MatchStats {
                        components: items.len() as u64,
                        matches: raw,
                        findings: n,
                        ..MatchStats::default()
                    },
                    based_on: Some(BasedOn {
                        latest_scan_id: latest,
                        mirror_synced_at: None,
                    }),
                    finding_set: Some(set),
                    view,
                })
            }
            MatchParams::Ephemeral {
                inventory,
                min_confidence,
                view_limit,
            } => {
                check_params(min_confidence, view_limit)?;
                let mut items: Vec<Item> = Vec::new();
                let mut seen = BTreeSet::new();
                for c in inventory.components {
                    let ident = ComponentIdentity::from_component(&c);
                    let key = ident.key();
                    if !seen.insert(key.clone()) {
                        continue;
                    }
                    items.push(Item {
                        id: items.len() as i64 + 1,
                        component: c,
                        ident,
                        key,
                    });
                }
                let (set, raw) = self
                    .score(&items, &inventory.asset.meta, min_confidence)
                    .await?;
                let asset_id = inventory.asset.id;
                let view = view(&asset_id, &set, &items, view_limit.unwrap_or(DEFAULT_VIEW));
                Ok(MatchResult {
                    asset_id,
                    mode: MatchMode::Ephemeral,
                    stats: MatchStats {
                        components: items.len() as u64,
                        matches: raw,
                        findings: set.len() as u64,
                        ..MatchStats::default()
                    },
                    based_on: None,
                    finding_set: None,
                    view,
                })
            }
        }
    }
}

fn check_params(min_confidence: f64, view_limit: Option<u32>) -> StepResult<()> {
    if !(0.0..=1.0).contains(&min_confidence) {
        return Err(WireError::invalid_params("min_confidence: expected 0..1"));
    }
    if view_limit.is_some_and(|l| l > MAX_VIEW_LIMIT) {
        return Err(WireError::invalid_params(format!(
            "view_limit: expected 0..{MAX_VIEW_LIMIT}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_parse() {
        assert_eq!(parse_stamp("py-engine/1#3"), Some(("py-engine/1", 3)));
        assert_eq!(parse_stamp("x"), None);
    }

    #[test]
    fn lifecycle_keeps_first_seen_and_suppressed() {
        let f = |c: i64, v: &str, s: FindingStatus, first: &str| Finding {
            component_id: c,
            vuln_id: v.into(),
            advisory_ids: vec![],
            matched_by: None,
            confidence: Some(1.0),
            fixed_version: None,
            severity: None,
            cvss_score: None,
            epss: None,
            kev: false,
            priority: Some("P4".into()),
            status: s,
            first_seen: Some(first.into()),
            last_seen: Some(first.into()),
            fixed_at: None,
            triage: None,
            triage_source: None,
        };
        let old = vec![
            f(1, "CVE-1", FindingStatus::Suppressed, "old"),
            f(1, "CVE-2", FindingStatus::Open, "old"),
            f(2, "CVE-3", FindingStatus::Fixed, "old"),
        ];
        let new = vec![
            f(1, "CVE-1", FindingStatus::Open, "now"),
            f(2, "CVE-4", FindingStatus::Open, "now"),
        ];
        let set = lifecycle(new, old);
        let get = |c: i64, v: &str| {
            set.iter()
                .find(|x| x.component_id == c && x.vuln_id == v)
                .unwrap()
        };
        assert_eq!(get(1, "CVE-1").status, FindingStatus::Suppressed);
        assert_eq!(get(1, "CVE-1").first_seen.as_deref(), Some("old"));
        assert_eq!(get(1, "CVE-2").status, FindingStatus::Fixed);
        assert!(get(1, "CVE-2").fixed_at.is_some());
        assert_eq!(get(2, "CVE-3").status, FindingStatus::Fixed);
        assert_eq!(get(2, "CVE-4").first_seen.as_deref(), Some("now"));
        assert_eq!(set.len(), 4);
    }
}
