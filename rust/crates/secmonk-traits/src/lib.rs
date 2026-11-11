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
    CollectEnd, CollectItem, CollectParams, Component, Inventory, MatchParams, MatchResult,
    RowsBatch, SyncEnd, SyncParams,
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
