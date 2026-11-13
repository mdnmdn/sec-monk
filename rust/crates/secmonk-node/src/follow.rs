//! [`FeedSource`]: following an upstream node's feed as a native [`Source`] (rust ADR-0011, proposal §4 P4).
//!
//! `sync(source)` pages through `Feed::since(source, since = <local version>)` and streams `secmonk-mirror-rows/1`
//! batches of the `native-rust` generation, numbered from the applied seq like every native importer:
//!
//! - **delta pages** (record sources): each upstream batch goes through the [`BatchLocalizer`] (the host adapts
//!   `MirrorNodeStore::localize_feed_batch`: the per-record `delete affected {source, vuln_id}` marker becomes one
//!   delete per local `affected` row, plus deletes of local aliases the record no longer has); the localized
//!   operations are re-cut into batches of at most [`MAX_OPS`] operations / about [`MAX_BYTES`] bytes.
//! - **snapshot pages** (kev, epss, debian-tracker): upserts only. The full replace is the native importers' own
//!   mechanism (kev.rs): upserts for every upstream row, and a `delete` for every locally stored row whose key
//!   the upstream snapshot did not have, computed through [`MirrorView::row_keys`] once the last page is read (a
//!   set of the keys seen, one text per row, is the memory cost). The deletes follow the upserts, so a stream cut
//!   short leaves old rows that the next sync removes (it converges, rust ADR-0011 §4). The snapshot guard of
//!   the Python sources applies unless `options.full`: an empty snapshot, or one under half of the stored rows,
//!   is refused (nothing is deleted, the run ends `error`). `raw_record` rows are upserted, never deleted (as
//!   kev.rs does); `affected` rows in a snapshot page are refused (they have no natural key to diff).
//!
//! The run ends with the `source_sync` row of the upstream's version **as of the first page** (records modified
//! while the run pages are re-sent next time by the overlap), so `source_versions()` serves the same version
//! further down. A failure of the upstream (unreachable, refused, a bad page) ends the run with an `error` entry
//! and its `source_sync` row, as the native importers do for feed problems; failures of the local side (the
//! mirror view, the localizer) are errors of the call.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use futures_util::StreamExt;
use secmonk_model::node::{FeedMode, FeedPage, FeedSinceRequest, SourceVersion};
use secmonk_model::{JsonMap, MirrorTable, RowOp, SyncEntry};
use secmonk_traits::node::Feed;
use secmonk_traits::{
    CallCtx, ErrorCode, MirrorView, NATIVE_GENERATION, ProgressUpdate, ResultStream, RowsBatch,
    Source, SourceInfo, StepResult, StreamMsg, SyncEnd, SyncParams, WireError,
};
use serde_json::{Value, json};

/// Operations per batch.
pub const MAX_OPS: usize = 5_000;
/// Approximate JSON bytes per batch (one larger operation goes in a batch of its own).
pub const MAX_BYTES: usize = 2 * 1024 * 1024;
/// Most pages of one run (a loop guard: a node that never ends its pages).
pub const MAX_PAGES: u64 = 1_000_000;
/// Longest error / progress text kept.
const MAX_MESSAGE: usize = 500;
/// Restarts of a snapshot run whose upstream moved to a new version between pages (`stale` answer).
pub const MAX_RESTARTS: u32 = 3;

/// Turns an upstream batch into the operations to apply on this mirror (the host adapts
/// `MirrorNodeStore::localize_feed_batch`). The result may exceed one batch.
#[async_trait]
pub trait BatchLocalizer: Send + Sync {
    /// The operations of `batch` for this mirror.
    async fn localize(&self, batch: &RowsBatch) -> StepResult<Vec<RowOp>>;
}

/// The version this mirror holds of a source (what `source_versions()` serves): the plain upstream version, `None`
/// for none (everything is then requested).
pub type LocalVersionFn = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// The sources followed from an upstream node.
pub struct FeedSource {
    names: Vec<String>,
    feed: Arc<dyn Feed>,
    view: Arc<dyn MirrorView>,
    localizer: Arc<dyn BatchLocalizer>,
    local_version: LocalVersionFn,
    page_limit: Option<u32>,
    limits: (usize, usize),
    importers: Arc<Mutex<HashMap<String, String>>>,
}

impl std::fmt::Debug for FeedSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeedSource")
            .field("sources", &self.names)
            .finish_non_exhaustive()
    }
}

impl FeedSource {
    /// Follow `sources` (`[node.upstream] sources`) over `feed` (a `RemoteNode`).
    pub fn new(
        sources: Vec<String>,
        feed: Arc<dyn Feed>,
        view: Arc<dyn MirrorView>,
        localizer: Arc<dyn BatchLocalizer>,
        local_version: LocalVersionFn,
    ) -> FeedSource {
        FeedSource {
            names: sources,
            feed,
            view,
            localizer,
            local_version,
            page_limit: None,
            limits: (MAX_OPS, MAX_BYTES),
            importers: Arc::default(),
        }
    }

    /// Ask for pages of this many records / rows (the upstream clamps it).
    #[must_use]
    pub fn with_page_limit(mut self, limit: u32) -> FeedSource {
        self.page_limit = Some(limit);
        self
    }

    /// Smaller batches (tests).
    #[must_use]
    pub fn with_limits(mut self, ops: usize, bytes: usize) -> FeedSource {
        self.limits = (ops.clamp(1, MAX_OPS), bytes);
        self
    }

    /// The importer version the upstream reported on the last page of `source`, so this node serves the same
    /// version further down (chaining). `None` before the first page. (The engine's defaulted
    /// `Source::importer_version` is not in the trait yet: the host adapts this method.)
    pub fn upstream_importer(&self, source: &str) -> Option<String> {
        self.importers
            .lock()
            .ok()
            .and_then(|m| m.get(source).cloned())
    }

    fn follows(&self, source: &str) -> bool {
        self.names.iter().any(|n| n == source)
    }
}

/// The natural key columns of a table a snapshot page can carry (`mirror_schema`); empty: not diffed.
fn key_columns(t: MirrorTable) -> &'static [&'static str] {
    match t {
        MirrorTable::Kev | MirrorTable::Epss => &["cve_id"],
        MirrorTable::DistroTriage => &["ecosystem", "package", "cve_id", "source"],
        MirrorTable::Vulnerability => &["source", "id"],
        MirrorTable::Alias => &["vuln_id", "alias", "source"],
        _ => &[],
    }
}

/// The tables a snapshot source is made of (checked even when the snapshot has no row of one).
fn snapshot_tables(source: &str) -> &'static [MirrorTable] {
    match source {
        "kev" => &[MirrorTable::Kev],
        "epss" => &[MirrorTable::Epss],
        "debian-tracker" => &[MirrorTable::DistroTriage],
        _ => &[],
    }
}

/// Whether a row (or a key) belongs to `source`: its `source` column is exactly the followed source.
fn of_source(m: &JsonMap, source: &str) -> bool {
    m.get("source").and_then(Value::as_str) == Some(source)
}

/// What an upstream page may carry for the followed `source` (upstream rows are untrusted, BP 11): a page of the
/// wrong mode for the source is refused, and so is any operation outside
///
/// - **delta** (record sources): `upsert` of `vulnerability`, `alias`, `affected`, `raw_record` and the replace-unit
///   marker `delete affected {source, vuln_id}`;
/// - **snapshot** (kev, epss, debian-tracker): `upsert` of the source's own snapshot tables and `raw_record`;
///
/// with `source` = the followed source on every row, key and batch. Never `source_sync`, `source_applied`, another
/// table, another source's rows or a delete in a snapshot. The whole page is refused before any of it is queued.
fn check_page(source: &str, page: &FeedPage) -> Result<(), String> {
    let own = snapshot_tables(source);
    let snapshot = page.mode == FeedMode::Snapshot;
    if snapshot && own.is_empty() {
        return Err(format!(
            "upstream answered a snapshot page for the record source {source:?}; refused"
        ));
    }
    if !snapshot && !own.is_empty() {
        return Err(format!(
            "upstream answered a delta page for the snapshot source {source:?}; refused"
        ));
    }
    for b in &page.batches {
        if b.source != source {
            return Err(format!(
                "upstream page of {source:?} carries a batch of source {:?}; refused",
                short(&b.source)
            ));
        }
        for op in &b.ops {
            let ok = match op {
                RowOp::Upsert { table, row } => {
                    let allowed = if snapshot {
                        own.contains(table) || *table == MirrorTable::RawRecord
                    } else {
                        matches!(
                            table,
                            MirrorTable::Vulnerability
                                | MirrorTable::Alias
                                | MirrorTable::Affected
                                | MirrorTable::RawRecord
                        )
                    };
                    allowed && of_source(row, source)
                }
                RowOp::Delete {
                    table: MirrorTable::Affected,
                    key,
                } if !snapshot => {
                    key.len() == 2
                        && of_source(key, source)
                        && key.get("vuln_id").and_then(Value::as_str).is_some()
                }
                RowOp::Delete { .. } => false,
            };
            if !ok {
                let (kind, table) = match op {
                    RowOp::Upsert { table, .. } => ("upsert", table),
                    RowOp::Delete { table, .. } => ("delete", table),
                };
                return Err(format!(
                    "upstream {} page of {source:?} carries a {kind} of {} that a follower does not accept \
                     (wrong table, operation or source); refused",
                    if snapshot { "snapshot" } else { "delta" },
                    table.as_str()
                ));
            }
        }
    }
    Ok(())
}

/// One text per row key, from the row (or the key map) and the table's key columns.
fn key_text(cols: &[&str], m: &JsonMap) -> String {
    let mut s = String::new();
    for c in cols {
        match m.get(*c) {
            Some(Value::String(v)) => s.push_str(v),
            Some(Value::Null) | None => {}
            Some(v) => s.push_str(&v.to_string()),
        }
        s.push('\u{1f}');
    }
    s
}

/// Cuts operations into native batches as they come.
struct Cutter {
    source: String,
    next_seq: u64,
    ops_cap: usize,
    bytes_cap: usize,
    cur: Vec<RowOp>,
    bytes: usize,
    emitted: u64,
}

impl Cutter {
    fn push(&mut self, op: RowOp, out: &mut VecDeque<RowsBatch>) {
        let size = serde_json::to_string(&op).map_or(0, |s| s.len());
        if !self.cur.is_empty()
            && (self.cur.len() >= self.ops_cap || self.bytes + size > self.bytes_cap)
        {
            self.flush(out);
        }
        self.bytes += size;
        self.cur.push(op);
    }

    fn flush(&mut self, out: &mut VecDeque<RowsBatch>) {
        if self.cur.is_empty() {
            return;
        }
        out.push_back(RowsBatch {
            kind: "rows".into(),
            seq: self.next_seq,
            source: self.source.clone(),
            ops: std::mem::take(&mut self.cur),
            generation: Some(NATIVE_GENERATION.to_owned()),
            acked_through: None,
        });
        self.next_seq += 1;
        self.emitted += 1;
        self.bytes = 0;
    }

    fn last_seq(&self) -> u64 {
        if self.emitted == 0 {
            0
        } else {
            self.next_seq - 1
        }
    }
}

enum Phase {
    Pages,
    Stale,
    Finish,
    End,
    Done,
}

struct Run {
    feed: Arc<dyn Feed>,
    view: Arc<dyn MirrorView>,
    localizer: Arc<dyn BatchLocalizer>,
    importers: Arc<Mutex<HashMap<String, String>>>,
    source: String,
    since: Option<String>,
    full: bool,
    page_limit: Option<u32>,
    page: Option<String>,
    pages: u64,
    restarts: u32,
    phase: Phase,
    cutter: Cutter,
    out: VecDeque<RowsBatch>,
    first_version: Option<SourceVersion>,
    snapshot: bool,
    seen: HashMap<MirrorTable, HashSet<String>>,
    failure: Option<String>,
    records: u64,
    n_ops: u64,
    t0: Instant,
    ctx: CallCtx,
}

fn short(s: &str) -> String {
    s.chars().take(MAX_MESSAGE).collect()
}

impl Run {
    fn fail(&mut self, message: String) {
        self.failure = Some(short(&message));
        self.phase = Phase::Finish;
    }

    fn progress(&self, message: String) {
        self.ctx.report(ProgressUpdate {
            message: Some(message),
            ..ProgressUpdate::default()
        });
    }

    fn push_op(&mut self, op: RowOp) {
        self.n_ops += 1;
        if let RowOp::Upsert { table, .. } = &op
            && !matches!(
                table,
                MirrorTable::SourceSync
                    | MirrorTable::RawRecord
                    | MirrorTable::Alias
                    | MirrorTable::Affected
            )
        {
            self.records += 1;
        }
        self.cutter.push(op, &mut self.out);
    }

    /// One page: request, check, localize / track, queue the operations.
    async fn fetch_page(&mut self) -> StepResult<()> {
        self.pages += 1;
        if self.pages > MAX_PAGES {
            self.fail(format!(
                "upstream paged more than {MAX_PAGES} pages; stopping"
            ));
            return Ok(());
        }
        let req = FeedSinceRequest {
            source: self.source.clone(),
            since: self.since.clone(),
            page: self.page.clone(),
            limit: self.page_limit,
        };
        let page: FeedPage = match self.feed.since(req).await {
            Ok(p) => p,
            // the upstream's snapshot moved to a new version between two pages: start again from the first page
            // (what was queued are upserts; the deletes are computed from the new pass alone)
            Err(e)
                if e.code == ErrorCode::Stale
                    && self.page.is_some()
                    && self.restarts < MAX_RESTARTS =>
            {
                self.restarts += 1;
                self.page = None;
                self.seen.clear();
                self.first_version = None;
                self.progress(format!(
                    "{}: the upstream changed version while paging; restarting ({}/{MAX_RESTARTS})",
                    self.source, self.restarts
                ));
                return Ok(());
            }
            Err(e) => {
                self.fail(format!("upstream feed: {}", e.error));
                return Ok(());
            }
        };
        if page.source != self.source {
            self.fail(format!(
                "upstream answered for source {:?}, asked {:?}",
                short(&page.source),
                self.source
            ));
            return Ok(());
        }
        if page.next_page.is_some() && page.next_page == self.page {
            self.fail("upstream repeated its page cursor; stopping".into());
            return Ok(());
        }
        if let Err(m) = check_page(&self.source, &page) {
            self.fail(m);
            return Ok(());
        }
        if let Ok(mut m) = self.importers.lock() {
            m.insert(self.source.clone(), page.version.importer.clone());
        }
        let FeedPage {
            version,
            mode,
            batches,
            next_page,
            ..
        } = page;
        if self.first_version.is_none() {
            self.first_version = Some(version);
        }
        let snapshot = mode == FeedMode::Snapshot;
        self.snapshot |= snapshot;
        let n_batches = batches.len();
        // batches and their operations are consumed, not copied
        for batch in batches {
            let ops = if snapshot {
                batch.ops
            } else {
                self.localizer.localize(&batch).await?
            };
            for op in ops {
                if snapshot {
                    self.track(&op);
                }
                self.push_op(op);
            }
        }
        self.progress(format!(
            "{}: page {} ({n_batches} batches, {})",
            self.source,
            self.pages,
            if snapshot { "snapshot" } else { "delta" }
        ));
        match next_page {
            Some(next) => self.page = Some(next),
            None => {
                self.phase = if self.snapshot {
                    Phase::Stale
                } else {
                    Phase::Finish
                };
            }
        }
        Ok(())
    }

    /// Remember the key of a snapshot upsert (the page was checked: only keyed snapshot tables and `raw_record`).
    fn track(&mut self, op: &RowOp) {
        if let RowOp::Upsert { table, row } = op {
            let cols = key_columns(*table);
            if !cols.is_empty() {
                self.seen
                    .entry(*table)
                    .or_default()
                    .insert(key_text(cols, row));
            }
        }
    }

    /// The deletes of a snapshot: stored keys the snapshot did not have (after the guard).
    async fn stale(&mut self) -> StepResult<()> {
        let mut tables: Vec<MirrorTable> = snapshot_tables(&self.source).to_vec();
        for t in self.seen.keys() {
            if !tables.contains(t) {
                tables.push(*t);
            }
        }
        for table in tables {
            let cols = key_columns(table);
            if cols.is_empty() {
                continue;
            }
            let empty = HashSet::new();
            let seen = self.seen.get(&table).unwrap_or(&empty);
            let stored = self.view.row_keys(table, &self.source).await?;
            let (old, new) = (stored.len() as u64, seen.len() as u64);
            if !self.full {
                if new == 0 && old > 0 {
                    self.fail(format!(
                        "refusing to replace {old} {} rows with an empty snapshot (use full to force)",
                        table.as_str()
                    ));
                    return Ok(());
                }
                if old > 0 && new * 2 < old {
                    self.fail(format!(
                        "refusing to replace {old} {} rows with a snapshot of only {new} (< 50%; use full to force)",
                        table.as_str()
                    ));
                    return Ok(());
                }
            }
            let gone: Vec<JsonMap> = stored
                .into_iter()
                .filter(|k| !seen.contains(&key_text(cols, k)))
                .collect();
            for key in gone {
                self.push_op(RowOp::Delete { table, key });
            }
        }
        self.phase = Phase::Finish;
        Ok(())
    }

    /// The `source_sync` row and the last batch.
    fn finish(&mut self) {
        let now = secmonk_model::time::now_iso();
        let mut row = JsonMap::new();
        row.insert("source".into(), json!(self.source));
        let (status, message) = match (&self.failure, &self.first_version) {
            (Some(m), _) => ("error", Some(m.clone())),
            (None, v) => {
                row.insert("last_sync".into(), json!(now));
                if let Some(v) = v {
                    if let Some(cursor) = &v.version {
                        row.insert("cursor".into(), json!(cursor));
                    }
                    row.insert("records".into(), json!(v.records));
                    (
                        "ok",
                        Some(format!(
                            "followed upstream {}@{}: {} records, {} operations",
                            v.importer,
                            v.version.as_deref().unwrap_or("-"),
                            self.records,
                            self.n_ops
                        )),
                    )
                } else {
                    row.insert("records".into(), json!(self.records));
                    ("ok", Some("upstream answered no page".to_owned()))
                }
            }
        };
        row.insert("status".into(), json!(status));
        row.insert("message".into(), json!(message));
        self.push_op(RowOp::Upsert {
            table: MirrorTable::SourceSync,
            row,
        });
        self.cutter.flush(&mut self.out);
        self.failure = if status == "error" {
            message
        } else {
            self.failure.take()
        };
        self.phase = Phase::End;
    }

    async fn next(&mut self) -> Option<StepResult<StreamMsg<RowsBatch, SyncEnd>>> {
        loop {
            if let Some(b) = self.out.pop_front() {
                return Some(Ok(StreamMsg::Item(b)));
            }
            let step = match self.phase {
                Phase::Pages => self.fetch_page().await,
                Phase::Stale => self.stale().await,
                Phase::Finish => {
                    self.finish();
                    Ok(())
                }
                Phase::End => {
                    self.phase = Phase::Done;
                    let (status, message) = match &self.failure {
                        Some(m) => ("error", Some(m.clone())),
                        None => ("ok", None),
                    };
                    let message = message.or_else(|| {
                        self.first_version.as_ref().map(|v| {
                            format!(
                                "followed upstream {}@{}",
                                v.importer,
                                v.version.as_deref().unwrap_or("-")
                            )
                        })
                    });
                    return Some(Ok(StreamMsg::End(SyncEnd {
                        entry: SyncEntry {
                            source: self.source.clone(),
                            status: status.into(),
                            records: self.records,
                            seconds: (self.t0.elapsed().as_secs_f64() * 10.0).round() / 10.0,
                            message,
                        },
                        batches: self.cutter.emitted,
                        last_seq: self.cutter.last_seq(),
                        ops: self.n_ops,
                    })));
                }
                Phase::Done => return None,
            };
            if let Err(e) = step {
                self.phase = Phase::Done;
                return Some(Err(e));
            }
        }
    }
}

#[async_trait]
impl Source for FeedSource {
    fn sources(&self) -> Vec<SourceInfo> {
        self.names
            .iter()
            .map(|n| SourceInfo {
                name: n.clone(),
                description: "followed from the upstream mirror node's feed".into(),
                in_all: true,
            })
            .collect()
    }

    fn sync_all_order(&self) -> Vec<String> {
        Vec::new()
    }

    async fn sync(
        &self,
        params: SyncParams,
        ctx: CallCtx,
    ) -> StepResult<ResultStream<RowsBatch, SyncEnd>> {
        if !self.follows(&params.source) {
            return Err(WireError::new(
                ErrorCode::UnknownSource,
                format!(
                    "unknown source {:?} (followed: {})",
                    params.source,
                    self.names.join(", ")
                ),
            ));
        }
        let t0 = Instant::now();
        let full = params.options.full.unwrap_or(false);
        let since = match params.options.since.clone().flatten() {
            Some(s) if !s.is_empty() => Some(s),
            _ if full => None,
            _ => (self.local_version)(&params.source),
        };
        let first_seq = self
            .view
            .applied(&params.source)
            .await?
            .filter(|a| a.generation.as_deref() == Some(NATIVE_GENERATION))
            .map_or(0, |a| a.seq)
            + 1;
        let run = Run {
            feed: self.feed.clone(),
            view: self.view.clone(),
            localizer: self.localizer.clone(),
            importers: self.importers.clone(),
            cutter: Cutter {
                source: params.source.clone(),
                next_seq: first_seq,
                ops_cap: self.limits.0,
                bytes_cap: self.limits.1,
                cur: Vec::new(),
                bytes: 0,
                emitted: 0,
            },
            source: params.source,
            since,
            full,
            page_limit: self.page_limit,
            page: None,
            pages: 0,
            restarts: 0,
            phase: Phase::Pages,
            out: VecDeque::new(),
            first_version: None,
            snapshot: false,
            seen: HashMap::new(),
            failure: None,
            records: 0,
            n_ops: 0,
            t0,
            ctx,
        };
        Ok(futures_util::stream::unfold(run, |mut r| async move {
            let m = r.next().await?;
            Some((m, r))
        })
        .boxed())
    }

    async fn ack(&self, _source: &str, _through_seq: u64, _ctx: CallCtx) -> StepResult<()> {
        Ok(()) // no change log: nothing to drop
    }

    async fn export(
        &self,
        source: &str,
        _ctx: CallCtx,
    ) -> StepResult<ResultStream<RowsBatch, Value>> {
        Err(WireError::new(
            ErrorCode::UnknownMethod,
            format!(
                "{source}: native importer: no staging database, source.export is not supported; run a sync to rewrite the rows"
            ),
        ))
    }

    fn native(&self) -> bool {
        true
    }

    /// The upstream's importer from the last page of `source` ([`FeedSource::upstream_importer`]): the follower
    /// serves the same version further down. `None` before the first page (the engine's default then applies).
    fn importer_version(&self, source: &str) -> Option<String> {
        self.upstream_importer(source)
    }
}
