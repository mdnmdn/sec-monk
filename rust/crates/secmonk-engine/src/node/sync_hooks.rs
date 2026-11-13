//! What the sync job does for the node services (proposal §3.2 rule 1, P0 "a sync updates existing findings"):
//!
//! - **versions after a complete run**: when a source's run is `ok`, its `source_sync` cursors (the source and its
//!   qualified rows, `osv:PyPI`) are recorded as the served version with the importer version
//!   (`MirrorNodeStore::record_complete_version`); a snapshot source also records what changed between the previous
//!   and the new version (`SnapshotDiff`);
//! - **re-match after the sync**: `LocalNode::changes` since the versions before the job; the stored assets with a
//!   current component whose lookup keys meet a changed key, or with a finding on a changed id, are matched again
//!   (persisted, as `assets/match`); a `resync` of any source re-matches every asset. A failure is a warning in the
//!   job log, never a failed sync.
//!
//! **Snapshot diffs.** `kev` and `debian-tracker` compare a hash of every row before and after the run (rows read
//! with `MirrorStore::rows_page`; only the hashes of the previous rows are kept in memory) and record the changed
//! CVE ids (and, for `debian-tracker`, the `pkg:<ecosystem>/<package>` keys of the changed rows). `epss` changes
//! nearly every row every day, and a source above [`SNAPSHOT_DIFF_MAX_ROWS`] rows costs too much to compare: their
//! diff is recorded with the single key [`DIFF_UNKNOWN_KEY`], and `match.changes` answers `resync` for them.

use std::collections::{BTreeSet, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use secmonk_model::node::{
    ChangesRequest, SnapshotDiff, SourceChanges, VersionKind, Versions, pkg_key,
};
use secmonk_model::time::now_iso;
use secmonk_model::{JsonMap, MirrorTable};
use secmonk_traits::node::MatchService;
use secmonk_traits::{Matcher, Reporter, Source};
use serde_json::Value;

use super::keys::component_lookup_keys;
use super::local::{DIFF_UNKNOWN_KEY, LocalNode, LocalNodeSettings, base_source};
use crate::engine::Inner;
use crate::jobs::Job;

/// Importer version recorded for a module source (`py-sources`) that declares none.
pub const DEFAULT_IMPORTER_MODULE: &str = "python/1";
/// Importer version recorded for a native source (`Source::native`) that declares none.
pub const DEFAULT_IMPORTER_NATIVE: &str = "rust/1";
/// Above this many rows a snapshot source records an unknown diff instead of comparing its rows.
pub const SNAPSHOT_DIFF_MAX_ROWS: u64 = 300_000;
/// Rows per page when hashing a snapshot table.
const PAGE: usize = 5_000;

/// The rows of a snapshot source before its run: hash -> (CVE id, lookup key).
pub(crate) struct SnapshotBefore {
    rows: Option<HashMap<u64, (String, Option<String>)>>,
}

/// The table a snapshot source replaces and whether its rows give lookup keys.
fn snapshot_table(source: &str) -> Option<(MirrorTable, bool)> {
    match source {
        "kev" => Some((MirrorTable::Kev, false)),
        "debian-tracker" => Some((MirrorTable::DistroTriage, true)),
        _ => None,
    }
}

fn row_hash(row: &JsonMap) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    serde_json::to_string(row).unwrap_or_default().hash(&mut h);
    h.finish()
}

fn row_facts(row: &JsonMap, keys: bool) -> (String, Option<String>) {
    let s = |k: &str| row.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
    let key = keys.then(|| pkg_key(&s("ecosystem"), &s("package")));
    (s("cve_id"), key)
}

impl Inner {
    /// The in-process node services, when the engine has the mirror's node store.
    pub(crate) fn local_node(&self) -> Option<LocalNode> {
        let store = self.deps.node_store.clone()?;
        let matcher: Arc<dyn Matcher> = self.deps.steps.clone();
        let reporter: Arc<dyn Reporter> = self.deps.steps.clone();
        Some(LocalNode::new(
            store,
            matcher,
            reporter,
            LocalNodeSettings::default(),
        ))
    }

    /// The node's versions before a sync job (`None` without a node store or when they cannot be read).
    pub(crate) async fn versions_before_sync(&self, job: &Arc<Job>) -> Option<Versions> {
        let node = self.local_node()?;
        match node.versions().await {
            Ok(v) => Some(v),
            Err(e) => {
                job.say(format!(
                    "warning: source versions not read before the sync: {}",
                    e.error
                ));
                None
            }
        }
    }

    /// Hash the rows of a snapshot source before its run (`None` for other sources and without a node store).
    pub(crate) async fn snapshot_before(&self, source: &str) -> Option<SnapshotBefore> {
        self.deps.node_store.as_ref()?;
        if VersionKind::default_for(source) != VersionKind::Snapshot {
            return None;
        }
        let Some((table, keys)) = snapshot_table(source) else {
            return Some(SnapshotBefore { rows: None });
        };
        Some(SnapshotBefore {
            rows: self.hash_rows(table, source, keys).await,
        })
    }

    /// Every row of `table` of `source` as hash -> facts; `None` above [`SNAPSHOT_DIFF_MAX_ROWS`] or on a read error.
    async fn hash_rows(
        &self,
        table: MirrorTable,
        source: &str,
        keys: bool,
    ) -> Option<HashMap<u64, (String, Option<String>)>> {
        let n = self.deps.mirror.count_rows(table, source).await.ok()?;
        if n > SNAPSHOT_DIFF_MAX_ROWS {
            return None;
        }
        let mut out = HashMap::new();
        let mut after = None;
        loop {
            let (rows, next) = self
                .deps
                .mirror
                .rows_page(table, source, after, PAGE)
                .await
                .ok()?;
            for r in &rows {
                out.insert(row_hash(r), row_facts(r, keys));
            }
            match next {
                Some(n) => after = Some(n),
                None => return Some(out),
            }
        }
    }

    /// After an `ok` run of `name`: record the served version of the source and of its qualified rows, and for a
    /// snapshot source the diff from the previous version. Failures are job-log warnings.
    pub(crate) async fn record_versions(
        &self,
        job: &Arc<Job>,
        name: &str,
        src: &Arc<dyn Source>,
        prev: Option<&Versions>,
        before: Option<SnapshotBefore>,
    ) {
        let Some(store) = self.deps.node_store.clone() else {
            return;
        };
        let importer = src.importer_version(name).unwrap_or_else(|| {
            if src.native() {
                DEFAULT_IMPORTER_NATIVE.into()
            } else {
                DEFAULT_IMPORTER_MODULE.into()
            }
        });
        let names: Vec<String> = match store.source_versions().await {
            Ok(v) => v
                .into_iter()
                .map(|v| v.source)
                .filter(|s| base_source(s) == name)
                .collect(),
            Err(e) => {
                job.say(format!("warning: {name}: version not recorded: {e}"));
                return;
            }
        };
        for n in names {
            let state = match self.deps.mirror.sync_state(&n).await {
                Ok(Some(s)) => s,
                Ok(None) => continue,
                Err(e) => {
                    job.say(format!("warning: {n}: version not recorded: {e}"));
                    continue;
                }
            };
            let Some(cursor) = state
                .cursor
                .filter(|c| !c.is_empty() && state.status.as_deref() == Some("ok"))
            else {
                continue;
            };
            let kind = VersionKind::default_for(&n);
            if let Err(e) = store
                .record_complete_version(&n, &cursor, &importer, kind)
                .await
            {
                job.say(format!("warning: {n}: version not recorded: {e}"));
                continue;
            }
            if kind != VersionKind::Snapshot || n != name {
                continue;
            }
            let prev_version = prev
                .and_then(|p| p.sources.get(&n))
                .and_then(|v| v.version.clone());
            if prev_version.as_deref() == Some(cursor.as_str()) {
                continue;
            }
            let (ids, keys) = match (
                before.as_ref().and_then(|b| b.rows.as_ref()),
                snapshot_table(&n),
            ) {
                (Some(old), Some((table, with_keys))) => {
                    match self.hash_rows(table, &n, with_keys).await {
                        Some(new) => {
                            let mut ids = BTreeSet::new();
                            let mut keys = BTreeSet::new();
                            for (h, (id, key)) in old.iter().chain(new.iter()) {
                                if old.contains_key(h) && new.contains_key(h) {
                                    continue;
                                }
                                if !id.is_empty() {
                                    ids.insert(id.clone());
                                }
                                keys.extend(key.clone());
                            }
                            (ids.into_iter().collect(), keys.into_iter().collect())
                        }
                        None => (Vec::new(), vec![DIFF_UNKNOWN_KEY.to_owned()]),
                    }
                }
                _ => (Vec::new(), vec![DIFF_UNKNOWN_KEY.to_owned()]),
            };
            let diff = SnapshotDiff {
                source: n.clone(),
                version: cursor.clone(),
                prev_version,
                created_at: now_iso(),
                ids,
                keys,
            };
            if let Err(e) = store.snapshot_diff_put(&diff).await {
                job.say(format!("warning: {n}: snapshot diff not recorded: {e}"));
            }
        }
    }

    /// Re-match the stored assets the sync affected (see the module doc). Never fails the job.
    pub(crate) async fn rematch_after_sync(&self, job: &Arc<Job>, before: Versions) {
        let Some(node) = self.local_node() else {
            return;
        };
        if let Err(e) = self.rematch_inner(job, &node, before).await {
            job.say(format!("warning: re-match after the sync failed: {e}"));
        }
    }

    async fn rematch_inner(
        &self,
        job: &Arc<Job>,
        node: &LocalNode,
        before: Versions,
    ) -> Result<(), String> {
        let resp = node
            .changes(ChangesRequest {
                since: before.since(),
                matcher: Some(before.matcher.clone()),
            })
            .await
            .map_err(|e| e.error)?;
        let mut keys: BTreeSet<String> = BTreeSet::new();
        let mut ids: BTreeSet<String> = BTreeSet::new();
        let mut resync: Vec<String> = Vec::new();
        let mut changed = 0usize;
        for (s, c) in &resp.sources {
            match c {
                SourceChanges::Unchanged => {}
                SourceChanges::Changed {
                    changed_keys,
                    changed_ids,
                } => {
                    changed += 1;
                    keys.extend(changed_keys.iter().cloned());
                    ids.extend(changed_ids.iter().cloned());
                }
                SourceChanges::Resync(r) => {
                    changed += 1;
                    resync.push(format!("{s} ({r})"));
                }
            }
        }
        if changed == 0 || (resync.is_empty() && keys.is_empty() && ids.is_empty()) {
            return Ok(());
        }
        let state = &self.deps.state;
        let assets = state.asset_ids().await.map_err(|e| e.to_string())?;
        if assets.is_empty() {
            return Ok(());
        }
        let selected: Vec<String> = if resync.is_empty() {
            let ids: Vec<String> = ids.iter().cloned().collect();
            let mut hit: BTreeSet<String> = state
                .assets_with_findings_on(&ids)
                .await
                .map_err(|e| e.to_string())?
                .into_iter()
                .collect();
            for a in &assets {
                if hit.contains(a) {
                    continue;
                }
                let comps = state
                    .current_components(a)
                    .await
                    .map_err(|e| e.to_string())?;
                let touched = comps.iter().any(|c| {
                    let ident =
                        secmonk_model::node::ComponentIdentity::from_component(&c.component);
                    component_lookup_keys(&ident)
                        .iter()
                        .any(|k| keys.contains(k))
                });
                if touched {
                    hit.insert(a.clone());
                }
            }
            hit.into_iter().collect()
        } else {
            job.say(format!(
                "re-match after the sync: resync of {}: every asset",
                resync.join(", ")
            ));
            assets.clone()
        };
        let mut failed = 0usize;
        for a in &selected {
            if let Err(e) = self
                .match_persisted(a, self.deps.config.min_confidence, 0)
                .await
            {
                failed += 1;
                job.say(format!("warning: re-match of {a} failed: {}", e.message));
            }
        }
        job.say(format!(
            "re-match after the sync: {changed} source(s) changed ({} key(s), {} id(s)); {} of {} asset(s) \
             re-matched{}",
            keys.len(),
            ids.len(),
            selected.len() - failed,
            assets.len(),
            if failed > 0 {
                format!(", {failed} failed")
            } else {
                String::new()
            }
        ));
        Ok(())
    }
}
