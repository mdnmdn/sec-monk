//! What the native importers share: the outcome of one run, the `source_sync` row (`db.set_sync_state`), the first
//! seq (continuing the native generation), and the lazy stream of batches and end (one batch in memory at a time).
//! The operations of a run are an async stream ([`Ops`]), so an importer may read the mirror view while the engine
//! applies the batches already cut (rust ADR-0012).

use std::sync::{Arc, Mutex};
use std::time::Instant;

use futures_util::StreamExt;
use futures_util::stream::BoxStream;
use secmonk_model::{JsonMap, MirrorTable, RowOp, SyncEntry, SyncOptions};
use secmonk_traits::{
    CallCtx, ErrorCode, MirrorView, NATIVE_GENERATION, ProgressFn, ProgressUpdate, ResultStream,
    RowsBatch, StepResult, StreamMsg, SyncEnd, WireError,
};
use serde_json::json;

use crate::batch::{Cutter, Limits};
use crate::feed;

/// Row operations of one run, produced as the stream is read. An `Err` ends the stream with that error: the engine
/// reports the source as failed, the batches applied before it stay, and the next sync converges (rust ADR-0011).
pub(crate) type Ops = BoxStream<'static, StepResult<RowOp>>;

/// [`Ops`] from operations computed up front (kev, epss).
pub(crate) fn iter_ops<I>(ops: I) -> Ops
where
    I: IntoIterator<Item = RowOp>,
    I::IntoIter: Send + 'static,
{
    futures_util::stream::iter(ops.into_iter().map(Ok)).boxed()
}

/// What one run produced before batching (the `SyncResult` of the Python source).
pub(crate) struct Outcome {
    pub(crate) status: String,
    /// `SyncResult.records`: the records this run imported (the end entry's `records`).
    pub(crate) records: u64,
    /// `SyncResult.total`: the `source_sync.records` of the run when it differs from `records` (msrc: the source's
    /// rows after the run); `None`: `records`.
    pub(crate) total: Option<u64>,
    pub(crate) cursor: Option<String>,
    pub(crate) message: Option<String>,
    pub(crate) ops: Ops,
}

impl Outcome {
    /// A failed run: no rows, only the `source_sync` status (`set_sync_state` keeps the last good totals).
    pub(crate) fn error(message: String) -> Outcome {
        Outcome {
            status: "error".into(),
            records: 0,
            total: None,
            cursor: None,
            message: Some(message),
            ops: iter_ops(std::iter::empty()),
        }
    }
}

/// The end of a run whose status is known only once its operations were produced (nvd: pages written one by one,
/// a failure on a later page decides the status): the fields of [`Outcome`] without the operations.
#[derive(Debug, Clone, Default)]
pub(crate) struct Tail {
    pub(crate) status: String,
    /// `SyncResult.records`.
    pub(crate) records: u64,
    /// `SyncResult.total` when it differs from `records`.
    pub(crate) total: Option<u64>,
    pub(crate) cursor: Option<String>,
    pub(crate) message: Option<String>,
}

/// Where an importer leaves its [`Tail`] before its operation stream ends ([`stream_deferred`] reads it then).
pub(crate) type TailCell = Arc<Mutex<Option<Tail>>>;

/// `options.limit`: `None`, or >= 1 (`py-sources` answers `invalid-params` for 0 too).
pub(crate) fn limit(opts: &SyncOptions) -> StepResult<Option<u64>> {
    match opts.limit.flatten() {
        Some(0) => Err(WireError::new(
            ErrorCode::InvalidParams,
            "options.limit: expected >= 1",
        )),
        l => Ok(l),
    }
}

/// `base.snapshot_guard`: the refusal of a snapshot of `new` rows that would replace `old` stored rows, unless
/// `full`: none at all, or fewer than half. The text has no source prefix (each importer adds its own, as its
/// Python source does).
pub(crate) fn snapshot_guard(old: u64, new: u64, full: bool) -> Option<String> {
    if full {
        return None;
    }
    if new == 0 {
        return Some(
            "refusing to replace the data with an empty snapshot (use --full to force)".into(),
        );
    }
    if old > 0 && new * 2 < old {
        return Some(format!(
            "refusing to replace {old} rows with a snapshot of only {new} (< 50%; use --full to force)"
        ));
    }
    None
}

/// An internal error of an importer (an invariant broken, a task that failed): `<source>: native importer: <msg>`;
/// a message that already starts with `<source>: ` is kept as it is.
pub(crate) fn internal(source: &str, msg: String) -> WireError {
    let text = if msg
        .strip_prefix(source)
        .is_some_and(|r| r.starts_with(": "))
    {
        msg
    } else {
        format!("{source}: native importer: {msg}")
    };
    WireError::new(ErrorCode::Internal, text)
}

/// Progress lines for the job log (`ctx.progress`), scrubbed of URL credentials.
pub(crate) struct Progress(Option<ProgressFn>);

impl Progress {
    pub(crate) fn new(ctx: &CallCtx) -> Progress {
        Progress(ctx.progress.clone())
    }

    /// One log line.
    pub(crate) fn line(&self, m: String) {
        if let Some(p) = &self.0 {
            p(ProgressUpdate {
                message: Some(feed::scrub(&m)),
                ..ProgressUpdate::default()
            });
        }
    }
}

/// `unknown-source` unless `requested` is `name`.
pub(crate) fn check_name(name: &str, requested: &str) -> StepResult<()> {
    if requested == name {
        return Ok(());
    }
    Err(WireError::new(
        ErrorCode::UnknownSource,
        format!("unknown source {requested:?} (known: {name})"),
    ))
}

/// `source.export` of a native importer: refused (no staging database).
pub(crate) fn export_refused(source: &str) -> WireError {
    WireError::new(
        ErrorCode::UnknownMethod,
        format!(
            "{source}: native importer: no staging database, source.export is not supported; run a sync to rewrite the rows"
        ),
    )
}

/// The first seq of this run: after the applied seq when it belongs to the native generation, else 1.
pub(crate) async fn first_seq(view: &dyn MirrorView, name: &str) -> StepResult<u64> {
    let base = view
        .applied(name)
        .await?
        .filter(|a| a.generation.as_deref() == Some(NATIVE_GENERATION))
        .map_or(0, |a| a.seq);
    Ok(base + 1)
}

/// `db.set_sync_state` as a row operation. ok/partial: `last_sync` = now, the cursor only when there is one (the
/// SQL's `COALESCE(excluded.cursor, cursor)`), records (`SyncResult.total`, else `.records`), status, message. error: status and message only (an upsert
/// updates only the given columns; a new row gets `last_sync`/`cursor` NULL and `records` 0, as there).
pub(crate) fn sync_row(
    source: &str,
    status: &str,
    records: u64,
    cursor: Option<String>,
    message: Option<String>,
    now: &str,
) -> RowOp {
    let mut row = JsonMap::new();
    row.insert("source".into(), json!(source));
    if status != "error" {
        row.insert("last_sync".into(), json!(now));
        if let Some(c) = cursor {
            row.insert("cursor".into(), json!(c));
        }
        row.insert("records".into(), json!(records));
    }
    row.insert("status".into(), json!(status));
    row.insert("message".into(), json!(message));
    RowOp::Upsert {
        table: MirrorTable::SourceSync,
        row,
    }
}

/// The run's batches (its operations, then the `source_sync` row), cut as the stream is read, then the end.
/// Messages pass `scrub_text`. `source_sync.records` is `outcome.total` (else `records`), the end entry's `records`
/// is `outcome.records`. The stream is lazy, so `SyncEnd.entry.seconds` (measured when the end is produced)
/// includes the time the consumer spent between batches, the engine's applies included; the engine does not use it
/// and reports its own seconds per source. An error of the operations ends the stream with that error (no end).
pub(crate) fn stream(
    name: &str,
    outcome: Outcome,
    first_seq: u64,
    limits: Limits,
    t0: Instant,
) -> ResultStream<RowsBatch, SyncEnd> {
    let message = outcome.message.as_deref().map(feed::scrub);
    let now = secmonk_model::time::now_iso();
    let last = sync_row(
        name,
        &outcome.status,
        outcome.total.unwrap_or(outcome.records),
        outcome.cursor,
        message.clone(),
        &now,
    );
    let batches = Batches {
        ops: outcome
            .ops
            .chain(futures_util::stream::iter([Ok(last)]))
            .boxed(),
        cutter: Cutter::new(name, first_seq, limits),
        n_ops: 0,
        entry: Some(SyncEntry {
            source: name.to_owned(),
            status: outcome.status,
            records: outcome.records,
            seconds: 0.0,
            message,
        }),
        t0,
        tail: None,
    };
    futures_util::stream::unfold(batches, |mut b| async move {
        let msg = b.next().await?;
        Some((msg, b))
    })
    .boxed()
}

/// [`stream`] for a run whose end is decided by its operations: `ops` is read to its end, then the [`Tail`] the
/// importer left in `tail` gives the `source_sync` row (the last operation) and the end entry. A stream that ends
/// without a tail is an internal error of the importer.
pub(crate) fn stream_deferred(
    name: &str,
    ops: Ops,
    tail: TailCell,
    first_seq: u64,
    limits: Limits,
    t0: Instant,
) -> ResultStream<RowsBatch, SyncEnd> {
    let (source, cell) = (name.to_owned(), tail.clone());
    let last = futures_util::stream::once(async move {
        let t = read_tail(&cell, &source)?;
        let message = t.message.as_deref().map(feed::scrub);
        Ok(sync_row(
            &source,
            &t.status,
            t.total.unwrap_or(t.records),
            t.cursor,
            message,
            &secmonk_model::time::now_iso(),
        ))
    });
    let batches = Batches {
        ops: ops.chain(last).boxed(),
        cutter: Cutter::new(name, first_seq, limits),
        n_ops: 0,
        entry: Some(SyncEntry {
            source: name.to_owned(),
            status: String::new(),
            records: 0,
            seconds: 0.0,
            message: None,
        }),
        t0,
        tail: Some(tail),
    };
    futures_util::stream::unfold(batches, |mut b| async move {
        let msg = b.next().await?;
        Some((msg, b))
    })
    .boxed()
}

/// The tail an importer left (an internal error when there is none).
fn read_tail(cell: &TailCell, source: &str) -> StepResult<Tail> {
    cell.lock()
        .map_err(|_| internal(source, "result lock poisoned".into()))?
        .clone()
        .ok_or_else(|| internal(source, "the operations ended without a result".into()))
}

/// The state of the lazy batch stream behind [`stream`] and [`stream_deferred`].
struct Batches {
    ops: Ops,
    cutter: Cutter,
    n_ops: u64,
    entry: Option<SyncEntry>,
    t0: Instant,
    /// [`stream_deferred`]: the entry's status, records and message come from here at the end.
    tail: Option<TailCell>,
}

impl Batches {
    /// The next batch, or the end; `None` after the end or an error.
    async fn next(&mut self) -> Option<StepResult<StreamMsg<RowsBatch, SyncEnd>>> {
        let mut entry = self.entry.take()?;
        while let Some(op) = self.ops.next().await {
            let op = match op {
                Ok(op) => op,
                Err(e) => return Some(Err(e)), // `entry` stays taken: the stream ends here
            };
            self.n_ops += 1;
            if let Some(b) = self.cutter.push(op) {
                self.entry = Some(entry);
                return Some(Ok(StreamMsg::Item(b)));
            }
        }
        if let Some(b) = self.cutter.finish() {
            self.entry = Some(entry);
            return Some(Ok(StreamMsg::Item(b)));
        }
        if let Some(cell) = &self.tail {
            let t = match read_tail(cell, &entry.source) {
                Ok(t) => t,
                Err(e) => return Some(Err(e)),
            };
            entry.status = t.status;
            entry.records = t.records;
            entry.message = t.message.as_deref().map(feed::scrub);
        }
        entry.seconds = (self.t0.elapsed().as_secs_f64() * 10.0).round() / 10.0;
        Some(Ok(StreamMsg::End(SyncEnd {
            entry,
            batches: self.cutter.emitted(),
            last_seq: self.cutter.last_seq(),
            ops: self.n_ops,
        })))
    }
}
