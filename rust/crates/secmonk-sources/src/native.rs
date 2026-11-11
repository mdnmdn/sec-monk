//! What the native importers share: the outcome of one run, the `source_sync` row (`db.set_sync_state`), the first
//! seq (continuing the native generation), and the lazy stream of batches and end (one batch in memory at a time).

use std::time::Instant;

use futures_util::StreamExt;
use secmonk_model::{JsonMap, MirrorTable, RowOp, SyncEntry, SyncOptions};
use secmonk_traits::{
    ErrorCode, MirrorView, NATIVE_GENERATION, ResultStream, RowsBatch, StepResult, StreamMsg,
    SyncEnd, WireError,
};
use serde_json::json;

use crate::batch::{Cutter, Limits};
use crate::feed;

/// Row operations of one run, produced as the stream is read.
pub(crate) type Ops = Box<dyn Iterator<Item = RowOp> + Send>;

/// What one run produced before batching (the `SyncResult` of the Python source).
pub(crate) struct Outcome {
    pub(crate) status: String,
    pub(crate) records: u64,
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
            cursor: None,
            message: Some(message),
            ops: Box::new(std::iter::empty()),
        }
    }
}

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
/// SQL's `COALESCE(excluded.cursor, cursor)`), records, status, message. error: status and message only (an upsert
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
/// Messages pass `scrub_text`. The stream is lazy, so `SyncEnd.entry.seconds` (measured when the end is produced)
/// includes the time the consumer spent between batches, the engine's applies included; the engine does not use it
/// and reports its own seconds per source.
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
        outcome.records,
        outcome.cursor,
        message.clone(),
        &now,
    );
    let batches = Batches {
        ops: Box::new(outcome.ops.chain(std::iter::once(last))),
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
    };
    futures_util::stream::iter(batches).boxed()
}

/// The lazy batch iterator behind [`stream`].
struct Batches {
    ops: Ops,
    cutter: Cutter,
    n_ops: u64,
    entry: Option<SyncEntry>,
    t0: Instant,
}

impl Iterator for Batches {
    type Item = StepResult<StreamMsg<RowsBatch, SyncEnd>>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut entry = self.entry.take()?;
        for op in self.ops.by_ref() {
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
        entry.seconds = (self.t0.elapsed().as_secs_f64() * 10.0).round() / 10.0;
        Some(Ok(StreamMsg::End(SyncEnd {
            entry,
            batches: self.cutter.emitted(),
            last_seq: self.cutter.last_seq(),
            ops: self.n_ops,
        })))
    }
}
