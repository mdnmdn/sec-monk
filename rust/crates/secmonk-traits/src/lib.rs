//! Domain traits of sec-monk (`secmonk-traits`).
//!
//! The engine sees only these traits (`Arc<dyn Collector>`, `Arc<dyn Source>`, `Arc<dyn Matcher>`, ...); the
//! desktop crate injects either Rust implementations (in-process) or the module host's adapters
//! (`secmonk_modhost::adapters::Py*`, a Python module over `secmonk-wire/1`). The engine cannot tell them apart.
//!
//! **Async style**: `async-trait` (boxed futures), because the traits are used as trait objects and native
//! `async fn` in traits is not dyn-compatible. Every future and stream is `Send`.
//!
//! **Cancellation**: dropping a returned future or stream cancels the call (the module adapter sends `cancel`
//! for the request in flight). Deadlines and progress travel in [`CallCtx`].
//!
//! **Errors**: every method fails with [`StepError`] = [`secmonk_proto::WireError`] (`{code, error, hint}`),
//! the same shape on the wire, in the engine and at the API.

use std::fmt;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures_core::Stream;
use serde_json::Value;

pub use secmonk_model::{
    CollectEnd, CollectItem, CollectParams, Component, Inventory, JsonMap, MatchParams,
    MatchResult, MirrorTable, RowsBatch, SyncEnd, SyncParams,
};
pub use secmonk_proto::{CollectorInfo, ErrorCode, SourceInfo, WireError};

pub mod collect;

/// Error of every trait method.
pub type StepError = WireError;
/// Result of every trait method.
pub type StepResult<T> = Result<T, StepError>;

/// One message of a streaming call: items, then exactly one `End` with the summary.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamMsg<T, E> {
    /// A stream item.
    Item(T),
    /// The stream finished; summary result.
    End(E),
}

/// A streaming call's result: `Item`* then `End`, or an error. Dropping it cancels the call.
pub type ResultStream<T, E> = Pin<Box<dyn Stream<Item = StepResult<StreamMsg<T, E>>> + Send>>;

/// Progress report of a running call (`progress` frames).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProgressUpdate {
    /// Line for the job log.
    pub message: Option<String>,
    /// Units done.
    pub done: Option<u64>,
    /// Units in total.
    pub total: Option<u64>,
    /// Unit name.
    pub unit: Option<String>,
}

/// Progress callback.
pub type ProgressFn = Arc<dyn Fn(ProgressUpdate) + Send + Sync>;

/// Per-call context.
#[derive(Clone, Default)]
pub struct CallCtx {
    /// Deadline of the call; `None` = the implementation's default (manifest `request_timeout_s`).
    pub deadline: Option<Duration>,
    /// Receives progress updates.
    pub progress: Option<ProgressFn>,
}

impl fmt::Debug for CallCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CallCtx")
            .field("deadline", &self.deadline)
            .field("progress", &self.progress.is_some())
            .finish()
    }
}

impl CallCtx {
    /// A context with a deadline.
    pub fn with_deadline(deadline: Duration) -> CallCtx {
        CallCtx {
            deadline: Some(deadline),
            progress: None,
        }
    }

    /// Report progress (no-op without a callback).
    pub fn report(&self, update: ProgressUpdate) {
        if let Some(p) = &self.progress {
            p(update);
        }
    }
}

/// Reads targets into inventories (`collector.*`).
#[async_trait]
pub trait Collector: Send + Sync {
    /// The collectors served (name, description, platforms).
    fn collectors(&self) -> Vec<CollectorInfo>;

    /// One target spec -> the targets to collect (`collector.expand_targets`).
    async fn expand_targets(
        &self,
        params: CollectParams,
        ctx: CallCtx,
    ) -> StepResult<Vec<Option<String>>>;

    /// Collect one target (`collector.collect`): `Asset`, `Components`* and `Warning`* items, then the end
    /// summary. Components are **unclassified**; use [`collect::assemble`] to build a capped [`Inventory`].
    async fn collect(
        &self,
        params: CollectParams,
        ctx: CallCtx,
    ) -> StepResult<ResultStream<CollectItem, CollectEnd>>;
}

/// A probe: collectors plus the other target-side methods (`discover.host`, `docker.*`, `k8s.kubeconfigs`,
/// `process.snapshot`). Their payloads are passed through as JSON (schemas in `rust/contracts/schemas/`).
#[async_trait]
pub trait Probe: Collector {
    /// Methods served besides `collector.*`.
    fn methods(&self) -> Vec<String>;

    /// Call one of [`Probe::methods`].
    async fn call(&self, method: &str, params: Value, ctx: CallCtx) -> StepResult<Value>;
}

/// A vulnerability source (`source.*`). Never gets a database handle: it streams mirror row batches that
/// the host applies, one transaction per batch, then acknowledges.
#[async_trait]
pub trait Source: Send + Sync {
    /// The sources served.
    fn sources(&self) -> Vec<SourceInfo>;

    /// Order of `sync all`.
    fn sync_all_order(&self) -> Vec<String>;

    /// Sync one source: row batches, then the run's [`SyncEnd`].
    async fn sync(
        &self,
        params: SyncParams,
        ctx: CallCtx,
    ) -> StepResult<ResultStream<RowsBatch, SyncEnd>>;

    /// Acknowledge batches through `through_seq` (applied by the host).
    async fn ack(&self, source: &str, through_seq: u64, ctx: CallCtx) -> StepResult<()>;

    /// Every staged row of a source (rebuild the mirror). The end value is the last sequence number.
    async fn export(
        &self,
        source: &str,
        ctx: CallCtx,
    ) -> StepResult<ResultStream<RowsBatch, Value>>;

    /// Whether this implementation is a **native importer** (rust ADR-0011): it computes its batches against the
    /// mirror itself (through a [`MirrorView`]) instead of replaying a change log, so it has nothing to acknowledge or
    /// export. Its batches carry [`NATIVE_GENERATION`] and no `acked_through`; before the stream the host resets an
    /// applied state of another generation, and it never repairs the source from [`Source::export`]: the next sync
    /// is the repair.
    fn native(&self) -> bool {
        false
    }
}

/// The `generation` of every batch of a native importer (rust ADR-0011). The applied state of a source synced by
/// the native importer carries it, so a later batch of a staging module (`py-sources`) has another generation and
/// the host repairs the source from that module's export (rust ADR-0010).
pub const NATIVE_GENERATION: &str = "native-rust";

/// The applied state of a source, as a native source reads it (`source_applied`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedMark {
    /// Last applied batch seq.
    pub seq: u64,
    /// Generation of that seq.
    pub generation: Option<String>,
}

/// Read-only view of the mirror for native sources (rust ADR-0011): the previous state a source needs to compute
/// its row operations (the snapshot guard's row count, the keys to delete, the seq to continue from). Implemented by
/// the engine over its `MirrorStore`; a source never gets a database handle and never writes through this.
#[async_trait]
pub trait MirrorView: Send + Sync {
    /// The source's applied state, if any.
    async fn applied(&self, source: &str) -> StepResult<Option<AppliedMark>>;

    /// Rows of `table` whose `source` column is `source`.
    async fn count_rows(&self, table: MirrorTable, source: &str) -> StepResult<u64>;

    /// Primary keys (column -> value) of the rows of `table` whose `source` column is `source`. Tables with a natural
    /// key only (not `affected`).
    async fn row_keys(&self, table: MirrorTable, source: &str) -> StepResult<Vec<JsonMap>>;

    /// The rows of `table` whose `source` column is `source` and whose id column ([`MirrorTable::id_column`]) is one
    /// of `ids` (at most [`MAX_VIEW_IDS`]; more is `invalid-params`), in storage order (rust ADR-0012). Each row has
    /// every column of the table's upsert row (not `affected.rowid_`): text as strings, numbers as numbers, JSON
    /// columns parsed. Given back unchanged as an `affected` delete key, a row deletes one row equal to it.
    /// `source_sync` has no id column: `invalid-params`.
    async fn rows_by_id(
        &self,
        table: MirrorTable,
        source: &str,
        ids: &[String],
    ) -> StepResult<Vec<JsonMap>>;

    /// One page of the rows of `table` whose `source` column is `source`, in storage order, after the cursor
    /// `after` (`None`: from the start), at most `limit` rows (1..=[`MAX_VIEW_PAGE`]); rows as in
    /// [`MirrorView::rows_by_id`]. [`RowPage::next`] is the cursor of the following page, `None` after the last one.
    /// A cursor is valid within one sync only (jobs are serialized; the rows do not change between pages unless the
    /// source's own batches change them). Pages follow storage order, not a snapshot: a row inserted while paging
    /// (by the source's own batches applied in between) gets a higher position and can appear in a later page, also an
    /// `affected` row that was deleted and inserted again (it gets a new position); a deleted row not yet reached does
    /// not appear. An importer that pages while its batches are applied must skip the rows it wrote itself.
    async fn rows_page(
        &self,
        table: MirrorTable,
        source: &str,
        after: Option<u64>,
        limit: usize,
    ) -> StepResult<RowPage>;
}

/// Most ids per [`MirrorView::rows_by_id`] call.
pub const MAX_VIEW_IDS: usize = 500;

/// Most rows per [`MirrorView::rows_page`] call.
pub const MAX_VIEW_PAGE: usize = 5_000;

/// One page of [`MirrorView::rows_page`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RowPage {
    /// The rows of this page.
    pub rows: Vec<JsonMap>,
    /// The cursor of the next page; `None` when this page is the last.
    pub next: Option<u64>,
}

/// `engine.classify`: identity (CPE, vendor, product, ecosystem) for unclassified components.
#[async_trait]
pub trait Classifier: Send + Sync {
    /// Classify; same length and order as the input. At most 5000 components per call (chunk above).
    async fn classify(
        &self,
        components: Vec<Component>,
        ctx: CallCtx,
    ) -> StepResult<Vec<Component>>;
}

/// `engine.match`: persisted (returns the asset's finding set for `StateStore::replace_findings`) or
/// ephemeral (nothing stored).
#[async_trait]
pub trait Matcher: Send + Sync {
    /// Match.
    async fn match_asset(&self, params: MatchParams, ctx: CallCtx) -> StepResult<MatchResult>;
}

/// Report payloads (`reports.*`, `procmon.*`): JSON in, JSON out, schemas per route in
/// `rust/contracts/catalog/module-methods.json`.
#[async_trait]
pub trait Reporter: Send + Sync {
    /// The report methods served.
    fn methods(&self) -> Vec<String>;

    /// Build one payload.
    async fn report(&self, method: &str, params: Value, ctx: CallCtx) -> StepResult<Value>;
}

/// Version semantics (`versions.*`, `scoring.priority`).
#[async_trait]
pub trait VersionOracle: Send + Sync {
    /// Compare `a` and `b` under `scheme`.
    async fn compare(
        &self,
        a: &str,
        b: &str,
        scheme: &str,
        ctx: CallCtx,
    ) -> StepResult<std::cmp::Ordering>;

    /// Whether `version` is affected by the OSV-style `events` under `scheme`.
    async fn in_range(
        &self,
        version: &str,
        events: &[Value],
        scheme: &str,
        ctx: CallCtx,
    ) -> StepResult<bool>;

    /// The first fixed version of `events` above `version`, if any.
    async fn first_fixed(
        &self,
        version: &str,
        events: &[Value],
        scheme: &str,
        ctx: CallCtx,
    ) -> StepResult<Option<String>>;

    /// The version scheme of an ecosystem.
    async fn scheme(&self, ecosystem: Option<&str>, ctx: CallCtx) -> StepResult<String>;

    /// `scoring.priority` (`P1`..`P4`); `params` as in `engine/versions.schema.json#/$defs/priority_params`.
    async fn priority(&self, params: Value, ctx: CallCtx) -> StepResult<String>;
}

/// Every engine step in one object (what `py-engine` serves).
pub trait EngineSteps: Classifier + Matcher + Reporter + VersionOracle {}

impl<T: Classifier + Matcher + Reporter + VersionOracle> EngineSteps for T {}
