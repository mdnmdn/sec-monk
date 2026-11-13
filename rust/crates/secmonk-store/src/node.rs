//! Storage behind the mirror-node interfaces (`secmonk_model::node`, `secmonk_traits::node`): two traits next to
//! [`crate::MirrorStore`] / [`crate::StateStore`] (not methods of them, so existing implementors are untouched).
//!
//! - [`MirrorNodeStore`]: what a node with a mirror reads to serve versions, changes, summaries and the feed;
//! - [`NodeCacheStore`]: what a state node keeps of a match service's answers and of remote summaries.
//!
//! The SQLite store implements both (`sqlite::node`); [`crate::SqliteStore::mirror_node_store`] and
//! [`crate::SqliteStore::node_cache_store`] hand out `Arc<dyn ...>`. Tables: `rust/_docs/tech/data-model.md`.

use std::collections::BTreeMap;

use async_trait::async_trait;
use secmonk_model::RowOp;
use secmonk_model::RowsBatch;
use secmonk_model::node::{
    AsOf, ComponentMatch, ComponentResult, SnapshotDiff, SourceVersion, VersionKind, Versions,
    VulnSummary,
};

use crate::StoreResult;

/// Snapshot diffs kept per source ([`MirrorNodeStore::snapshot_diff_put`] prunes older ones).
pub const SNAPSHOT_DIFF_KEEP: usize = 10;

/// Most records per [`MirrorNodeStore::rows_since`] page.
pub const MAX_FEED_RECORDS: usize = crate::MAX_ROWS_IDS;

/// Mirror-side reads and writes for a node that serves versions, changes, summaries and a feed.
#[async_trait]
pub trait MirrorNodeStore: Send + Sync {
    /// The served version of every source known to `source_sync` (plus any `source_version` row without one),
    /// sorted by source name, qualified names (`osv:PyPI`) as their own entries.
    ///
    /// **Rule for `version`**: the `source_version.version` recorded by [`record_complete_version`] when there is one
    /// (the last version a complete import reached; a later `partial` or `error` run does not move it), else
    /// `source_sync.cursor` when `source_sync.status` is `ok` (importers write `ok` | `partial` | `error`; a
    /// `partial` or `error` run's cursor is never served), else `None`. `importer` is the recorded one, else
    /// `"unknown"`; `kind` the recorded one, else [`VersionKind::default_for`]. `records`, `last_sync` and
    /// `status` come from `source_sync`.
    ///
    /// [`record_complete_version`]: MirrorNodeStore::record_complete_version
    async fn source_versions(&self) -> StoreResult<Vec<SourceVersion>>;

    /// Record that a COMPLETE import of `source` reached `version` with `importer` (the engine calls it after an
    /// `ok` run, never after `partial` or `error`). Replaces the previous record; sets `completed_at` to now.
    async fn record_complete_version(
        &self,
        source: &str,
        version: &str,
        importer: &str,
        kind: VersionKind,
    ) -> StoreResult<()>;

    /// `(vuln_id, modified)` of the records of `source` with `modified > since_modified - overlap_s`, ordered by
    /// `modified` then id, at most `limit` (ask for one more than you can serve to know it overflowed). The
    /// subtraction is done on the timestamp text ([`secmonk_model::node::apply_overlap`]; an unparsable `since`
    /// is used as it is). Records without `modified` never match.
    async fn changed_vulns(
        &self,
        source: &str,
        since_modified: &str,
        overlap_s: u64,
        limit: usize,
    ) -> StoreResult<Vec<(String, String)>>;

    /// The lookup keys of the `affected` rows of `ids` (every source): `pkg:<ecosystem>/<package>` for a row with
    /// a package, `prod:<lower(product)>` for a row with a product (both when it has both). Sorted, distinct.
    /// `ids` are read in chunks of 500.
    async fn lookup_keys_for_vulns(&self, ids: &[String]) -> StoreResult<Vec<String>>;

    /// The summaries of the ids the mirror knows (one per distinct id, in input order; the others are the caller's
    /// `missing`). Merge rule per id: the rows of every source for the id and for its aliases (the `alias` table,
    /// both directions, one hop) are ordered `nvd`, `cvelist`, other sources by name, rows of the id itself before
    /// rows of an alias; CVSS score, vector and severity come from the first row with a score (severity of the
    /// first row with one when none has a score); `summary` and `withdrawn` from the first row that has one among
    /// the rows of the id itself (all rows when there is none); `published` is the earliest and `modified` the
    /// latest over all rows; KEV and EPSS are read for the id, else for an alias.
    async fn summaries(&self, ids: &[String]) -> StoreResult<Vec<VulnSummary>>;

    /// Ecosystems that have `affected` rows (sorted, distinct): the `coverage` of an answer.
    async fn covered_ecosystems(&self) -> StoreResult<Vec<String>>;

    /// Record a snapshot source's difference between two versions; keeps the newest [`SNAPSHOT_DIFF_KEEP`] per
    /// source. Replaces a diff with the same `(source, version)`.
    async fn snapshot_diff_put(&self, diff: &SnapshotDiff) -> StoreResult<()>;

    /// The diffs that lead from `since_version` to the newest recorded version, oldest first: `Some(vec![])` when
    /// `since_version` is the newest, `None` when the chain from `since_version` is not recorded (too old, never
    /// seen): the follower gets the whole snapshot.
    async fn snapshot_diffs_since(
        &self,
        source: &str,
        since_version: &str,
    ) -> StoreResult<Option<Vec<SnapshotDiff>>>;

    /// A page of the records of `source` modified after `since_modified` (exact: `modified > since_modified`, the
    /// caller applies any overlap with [`secmonk_model::node::apply_overlap`]; `None`: every record, by id),
    /// as `secmonk-mirror-rows/1` batches of replace units, and the cursor of the next page. `limit` is records
    /// (clamped to `1..=`[`MAX_FEED_RECORDS`]). A unit is `delete affected {source, vuln_id}` (marker), `upsert
    /// vulnerability`, `upsert raw_record` (the row with `record_id` = the id, when there is one), `upsert alias`
    /// per alias, `upsert affected` per row. Batches have page-local `seq` from 1, no generation, at most 5000 ops
    /// and about 2 MiB. Applied to an empty mirror with `apply_rows` they reproduce the records; applied to a mirror
    /// that has older versions of them, pass them through [`localize_feed_batch`](MirrorNodeStore::localize_feed_batch) first.
    async fn rows_since(
        &self,
        source: &str,
        since_modified: Option<&str>,
        page: Option<&str>,
        limit: usize,
    ) -> StoreResult<(Vec<RowsBatch>, Option<String>)>;

    /// A page of a snapshot source's table (`kev`, `epss`, `debian-tracker`: `kev`, `epss`, `distro_triage` rows)
    /// as upsert-only batches (the follower deletes what is absent, rust ADR-0011), via
    /// [`crate::MirrorStore::rows_page`]; `limit` rows, `1..=MAX_ROWS_PAGE`. Another source is `Invalid`.
    async fn rows_snapshot(
        &self,
        source: &str,
        page: Option<&str>,
        limit: usize,
    ) -> StoreResult<(Vec<RowsBatch>, Option<String>)>;

    /// The operations to apply for a feed batch on THIS mirror: every `delete affected {source, vuln_id}` marker of
    /// a replace unit becomes one delete per `affected` row this mirror has for the record (the store deletes one
    /// row per delete op), preceded by a delete of every stored `alias` of the record that the unit does not
    /// upsert; everything else is copied. The result can exceed one batch (5000 ops): the caller cuts it.
    async fn localize_feed_batch(&self, batch: &RowsBatch) -> StoreResult<Vec<RowOp>>;
}

/// Match answers and remote summaries kept by a state node (`component_match`, `component_lookup`,
/// `vuln_summary`, `node_sync` of the state database).
#[async_trait]
pub trait NodeCacheStore: Send + Sync {
    /// Replace, in one transaction, everything stored for each result's component key by the result (matches and
    /// lookup keys), stamped with `as_of`. A component with no match is stored as a marker so that "answered,
    /// nothing" differs from "never asked".
    async fn put_component_results(
        &self,
        results: &[ComponentResult],
        as_of: &Versions,
    ) -> StoreResult<()>;

    /// The stored match sets of `keys`; a key with a stored answer is present (empty when it matched nothing), a
    /// key never answered is absent.
    async fn component_matches(
        &self,
        keys: &[String],
    ) -> StoreResult<BTreeMap<String, Vec<ComponentMatch>>>;

    /// The versions each of `keys` was last answered at (absent: never answered).
    async fn component_as_of(&self, keys: &[String]) -> StoreResult<BTreeMap<String, AsOf>>;

    /// Component keys that used any of the lookup keys (sorted, distinct).
    async fn components_by_lookup_keys(&self, keys: &[String]) -> StoreResult<Vec<String>>;

    /// Component keys that have a match whose `vuln_id` or one of whose `advisory_ids` is in `ids` (sorted,
    /// distinct).
    async fn components_by_vuln_ids(&self, ids: &[String]) -> StoreResult<Vec<String>>;

    /// Store summaries (replacing the stored ones), `fetched_at` = now.
    async fn put_summaries(&self, summaries: &[VulnSummary]) -> StoreResult<()>;

    /// The stored summaries of the ids that have one, in input order.
    async fn cached_summaries(&self, ids: &[String]) -> StoreResult<Vec<VulnSummary>>;

    /// A named value of the sync with an upstream (the last `since` map as JSON, ...).
    async fn node_sync_get(&self, name: &str) -> StoreResult<Option<String>>;

    /// Set a named value.
    async fn node_sync_set(&self, name: &str, value: &str) -> StoreResult<()>;
}
