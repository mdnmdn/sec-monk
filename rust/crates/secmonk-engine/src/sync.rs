//! Sync jobs: port of `web/jobs.py` `_sync` and `ops.sync_source` over the source row stream (rust ADR-0010). Per
//! source: `Source.sync` streams `secmonk-mirror-rows/1` batches; each is applied in one transaction by
//! `MirrorStore.apply_rows` (allowlists, source binding, idempotent by `seq` within the staging `generation`); after
//! the stream's `end` the host acknowledges through the last applied seq with `source.ack`. The ack comes after the
//! stream because `py-sources` serves one request at a time; a replay of un-acknowledged batches is skipped by the
//! store.
//!
//! **Repair** (review M1/M5): when a batch cannot be compared with the mirror (another staging generation, or the
//! module acknowledged more than the mirror applied) or a stream brings no batch to a mirror with no applied state for
//! the source, the rest of the stream is drained unapplied and the source is rebuilt from `source.export` in one
//! store transaction (delete the source's rows, apply the export, record the export's high-water mark and
//! generation), then acknowledged through that mark.
//!
//! **Native importers** (rust ADR-0011, `Source::native`): batches computed against the mirror through a read-only
//! `MirrorView`, under `NATIVE_GENERATION`; no ack, no export repair (see `sync_native`).
//!
//! One failing source never stops the others: its entry gets status `error` (as `ops.sync_source` does).

use std::sync::Arc;
use std::time::Instant;

use futures_util::StreamExt;
use secmonk_model::{JobStatus, RowsBatch, SyncOptions, SyncParams, SyncSecrets};
use secmonk_store::AppliedState;
use secmonk_traits::{CallCtx, NATIVE_GENERATION, ProgressUpdate, Source, StreamMsg};
use serde_json::{Value, json};

use crate::engine::{Inner, store_err};
use crate::error::{EngineError, EngineResult, ErrorKind};
use crate::jobs::Job;
use crate::opts::{expand_user, thousands};
use crate::payload::sync_status;
use crate::prepare::SyncPlan;

/// What one source's run produced (before it becomes the entry).
#[derive(Debug, Default)]
struct Outcome {
    status: String,
    records: u64,
    message: Option<String>,
    /// Batches received (applied, skipped or drained).
    received: u64,
    /// Batches skipped as already applied.
    skipped: u64,
    /// Highest seq applied or skipped: what `source.ack` acknowledges (when no repair is needed).
    through: Option<u64>,
    /// Why the source must be rebuilt from `source.export` (the stream is then drained unapplied).
    repair: Option<String>,
    /// Batches received after the repair was decided (not applied).
    drained: u64,
    /// The source was rebuilt from `source.export`.
    repaired: bool,
}

impl Outcome {
    fn error(mut self, text: impl Into<String>) -> Outcome {
        self.status = "error".into();
        self.message = Some(text.into());
        self
    }
}

/// `round(secs, 1)`.
fn round1(secs: f64) -> f64 {
    (secs * 10.0).round() / 10.0
}

/// The options of `source.sync` from the plan (`SyncOptions(...)` of `_sync`).
fn sync_options(plan: &SyncPlan) -> SyncOptions {
    SyncOptions {
        path: plan
            .path
            .as_deref()
            .map(|p| Some(expand_user(p).display().to_string())),
        ecosystems: Some(plan.ecosystems.clone()),
        ids: None,
        since: plan.since.clone().map(Some),
        full: Some(plan.full),
        limit: plan.limit.map(Some),
    }
}

impl Inner {
    /// `JobRunner._sync`: every source in order, then `ops.sync_status`; result `{"sources": [entry...]}`.
    pub(crate) async fn run_sync(
        self: &Arc<Self>,
        job: &Arc<Job>,
        plan: SyncPlan,
    ) -> EngineResult<(JobStatus, Option<Value>, Option<String>)> {
        let api_key = self
            .deps
            .config
            .nvd_api_key_env
            .as_deref()
            .and_then(|var| std::env::var(var).ok())
            .filter(|k| !k.is_empty());
        let options = sync_options(&plan);
        let registry = self.sources();
        let mut entries: Vec<Value> = Vec::new();
        let (mut skipped, mut repaired) = (0u64, 0u64);
        // node services: the versions before the job (the re-match after it asks what changed since them)
        let versions_before = self.versions_before_sync(job).await;
        for name in &plan.sources {
            job.say(format!("syncing {name}…"));
            let t0 = Instant::now();
            let outcome = match registry.iter().find(|(i, _)| &i.name == name) {
                Some((_, src)) => {
                    let params = SyncParams {
                        source: name.clone(),
                        options: options.clone(),
                        secrets: api_key.clone().map(|k| SyncSecrets { api_key: Some(k) }),
                    };
                    let snapshot = self.snapshot_before(name).await;
                    let out = self.sync_one(job, src, params).await;
                    if out.status == "ok" {
                        self.record_versions(job, name, src, versions_before.as_ref(), snapshot)
                            .await;
                    }
                    out
                }
                None => Outcome::default().error(format!("KeyError: unknown source {name:?}")),
            };
            let secs = t0.elapsed().as_secs_f64();
            let message = outcome.message.as_deref().map(secmonk_safeio::scrub_text);
            job.say(
                format!(
                    "{name}: {} — {} records in {secs:.1}s {}",
                    outcome.status,
                    thousands(outcome.records),
                    message.as_deref().unwrap_or("")
                )
                .trim_end(),
            );
            if outcome.skipped > 0 {
                job.say(format!(
                    "{name}: {} replayed batch(es) were already applied",
                    outcome.skipped
                ));
            }
            skipped += outcome.skipped;
            repaired += u64::from(outcome.repaired);
            entries.push(json!({
                "source": name, "status": outcome.status, "records": outcome.records, "seconds": round1(secs),
                "message": message,
            }));
        }
        if skipped > 0 || repaired > 0 {
            job.say(format!(
                "mirror: {skipped} replayed batch(es) skipped, {repaired} source(s) repaired from the staging export"
            ));
        }
        if let Some(before) = versions_before {
            self.rematch_after_sync(job, before).await;
        }
        if let Err(e) = self.deps.mirror.checkpoint().await {
            tracing::warn!(error = %e, "mirror checkpoint after the sync failed");
        }
        Ok((
            sync_status(&entries),
            Some(json!({"sources": entries})),
            None,
        ))
    }

    /// `ops.sync_source` for one source: stream, apply each batch, then ack (or repair, then ack the repair). Never
    /// fails: a failure is the outcome's `error` status.
    async fn sync_one(&self, job: &Arc<Job>, src: &Arc<dyn Source>, params: SyncParams) -> Outcome {
        let name = params.source.clone();
        let progress_job = job.clone();
        let ctx = CallCtx {
            deadline: None,
            progress: Some(Arc::new(move |u: ProgressUpdate| {
                if let Some(m) = u.message {
                    progress_job.say(m);
                }
            })),
        };
        let mut out = Outcome::default();
        let before = match self.deps.mirror.applied_state(&name).await {
            Ok(a) => a,
            Err(e) => return out.error(store_err(e).message),
        };
        if src.native() {
            return self.sync_native(job, src, params, ctx, before).await;
        }
        let streamed = self
            .stream_into_mirror(src, params, ctx, before.as_ref(), &mut out)
            .await;
        if streamed.is_ok() && out.repair.is_none() && out.received == 0 && before.is_none() {
            // Nothing streamed and nothing recorded: either a first sync with no change (the export is empty) or a
            // mirror that lost the source while staging kept it (the export restores it).
            out.repair = Some("the mirror has no applied state for this source".into());
        }
        if let Some(reason) = out.repair.clone() {
            if let Err(e) = streamed {
                // no repair on a broken stream: nothing was acknowledged, the next sync decides again
                return out.error(e.message);
            }
            if out.status != "ok" && is_native(before.as_ref()) {
                // The mirror holds rows of the native importer that are newer than the module's staging database.
                // Staging is complete only after an ok sync: a failed run left it at its state before the switch to
                // the native importer, a limited run upserted a subset. The mirror and the native applied state stay;
                // nothing is acknowledged; the next ok sync repairs from the staging export.
                let status = out.status.clone();
                let message = match out.message.as_deref() {
                    Some(m) if !m.is_empty() => format!("{status}: {m}"),
                    _ => status.clone(),
                };
                let message = format!(
                    "{message}; not applied: mirror keeps the native importer data until a successful py-sources sync"
                );
                job.say(format!(
                    "{name}: {message} ({} batch(es) drained)",
                    out.drained
                ));
                out.records = 0;
                return out.error(message);
            }
            if is_native(before.as_ref()) {
                job.say(format!(
                    "{name}: repair from py-sources export: the last applied batches came from the native importer"
                ));
            }
            if out.drained > 0 {
                job.say(format!(
                    "{name}: {} batch(es) not applied ({reason})",
                    out.drained
                ));
            }
            return match self.repair(src, &name).await {
                Ok((stats, high_water)) => {
                    out.repaired = true;
                    if stats.upserts > 0 || stats.deleted > 0 || out.drained > 0 {
                        job.say(format!(
                            "{name}: mirror repaired from the staging export ({reason}): {} row(s) removed, {} \
                             written, applied through seq {high_water}",
                            thousands(stats.deleted),
                            thousands(stats.upserts)
                        ));
                    }
                    if high_water > 0
                        && let Err(e) = src.ack(&name, high_water, CallCtx::default()).await
                    {
                        job.say(format!(
                            "{name}: could not acknowledge the repair (its batches will be replayed and skipped): {}",
                            e.error
                        ));
                    }
                    out
                }
                Err(e) => out.error(format!("repair failed ({reason}): {}", e.message)),
            };
        }
        // Acknowledge what was applied, also after a failure (the module drops those batches from its log).
        if let Some(through) = out.through
            && let Err(e) = src.ack(&name, through, CallCtx::default()).await
        {
            job.say(format!(
                "{name}: could not acknowledge the applied batches (they will be replayed and skipped): {}",
                e.error
            ));
        }
        match streamed {
            Ok(()) => out,
            Err(e) => out.error(e.message),
        }
    }

    /// A native importer (rust ADR-0011) computed its batches against the mirror itself: there is no change log, so
    /// no replay, no ack and no export repair (the next sync is the repair). When the source's applied state has
    /// another generation (written by `py-sources`), it is reset first, so the native seqs start at 1 under
    /// [`NATIVE_GENERATION`]; a later `py-sources` batch has another generation again and is repaired from the staging
    /// export. A batch the store skips or refuses is an error: no batch of a native stream may be dropped.
    async fn sync_native(
        &self,
        job: &Arc<Job>,
        src: &Arc<dyn Source>,
        params: SyncParams,
        ctx: CallCtx,
        mut before: Option<AppliedState>,
    ) -> Outcome {
        let name = params.source.clone();
        let mut out = Outcome::default();
        if let Some(a) = before
            .as_ref()
            .filter(|a| a.generation.as_deref() != Some(NATIVE_GENERATION))
        {
            if let Err(e) = self.deps.mirror.reset_applied_seq(&name).await {
                return out.error(store_err(e).message);
            }
            job.say(format!(
                "{name}: native importer: applied state of generation {} (seq {}) reset; full sync against the mirror",
                a.generation.as_deref().unwrap_or("none"),
                a.seq
            ));
            before = None;
        }
        let streamed = self
            .stream_into_mirror(src, params, ctx, before.as_ref(), &mut out)
            .await;
        if let Some(reason) = out.repair.take() {
            return out.error(format!(
                "native importer: batch refused by the mirror store ({reason}); run the sync again"
            ));
        }
        if out.skipped > 0 {
            let skipped = out.skipped;
            return out.error(format!(
                "native importer: {skipped} batch(es) skipped by the mirror store (seq at or below the applied seq: \
                 another writer changed the applied state during the sync); run the sync again"
            ));
        }
        match streamed {
            Ok(()) => out,
            Err(e) => out.error(e.message),
        }
    }

    /// The stream of one `source.sync`: batches applied in order until one needs a repair (the rest is drained);
    /// `end` fills status, records and message.
    async fn stream_into_mirror(
        &self,
        src: &Arc<dyn Source>,
        params: SyncParams,
        ctx: CallCtx,
        before: Option<&AppliedState>,
        out: &mut Outcome,
    ) -> EngineResult<()> {
        let name = params.source.clone();
        let mut stream = src.sync(params, ctx).await?;
        let mut last_seq: Option<u64> = None;
        while let Some(msg) = stream.next().await {
            match msg? {
                StreamMsg::Item(batch) => {
                    check_batch(&name, &batch, last_seq)?;
                    last_seq = Some(batch.seq);
                    out.received += 1;
                    if out.repair.is_some() {
                        out.drained += 1;
                        continue;
                    }
                    let stats = self
                        .deps
                        .mirror
                        .apply_rows(&batch)
                        .await
                        .map_err(store_err)?;
                    if stats.needs_repair {
                        out.repair = Some(repair_reason(before, &batch));
                        out.drained += 1;
                        continue;
                    }
                    if stats.skipped {
                        out.skipped += 1;
                    }
                    out.through = Some(batch.seq);
                }
                StreamMsg::End(end) => {
                    out.status = end.entry.status;
                    out.records = end.entry.records;
                    out.message = end.entry.message;
                    if end.batches != out.received
                        || (end.batches > 0 && Some(end.last_seq) != last_seq)
                    {
                        return Err(EngineError::new(
                            ErrorKind::Internal,
                            format!(
                                "ProtocolError: the {name} sync announced {} batch(es) through seq {}, {} received",
                                end.batches, end.last_seq, out.received
                            ),
                        ));
                    }
                    return Ok(());
                }
            }
        }
        Err(EngineError::new(
            ErrorKind::Internal,
            format!("ProtocolError: the {name} sync stream ended without its result"),
        ))
    }

    /// The export repair: `source.export` applied in one store transaction that first deletes the source's rows,
    /// committed with the export's high-water mark and generation. Returns the stats and the mark (to acknowledge).
    async fn repair(
        &self,
        src: &Arc<dyn Source>,
        name: &str,
    ) -> EngineResult<(secmonk_store::RepairStats, u64)> {
        let mut stream = src.export(name, CallCtx::default()).await?;
        let mut tx = self
            .deps
            .mirror
            .begin_repair(name)
            .await
            .map_err(store_err)?;
        let mut generation: Option<String> = None;
        let mut received = 0u64;
        while let Some(msg) = stream.next().await {
            match msg? {
                StreamMsg::Item(batch) => {
                    check_batch(name, &batch, None)?;
                    if batch.generation.is_some() {
                        if generation.is_some() && generation != batch.generation {
                            return Err(protocol(format!(
                                "the {name} export changed generation mid-stream"
                            )));
                        }
                        generation.clone_from(&batch.generation);
                    }
                    received += 1;
                    tx.apply(&batch).await.map_err(store_err)?;
                }
                StreamMsg::End(end) => {
                    let high_water =
                        end.get("high_water")
                            .and_then(Value::as_u64)
                            .ok_or_else(|| {
                                protocol(format!("the {name} export ended without its high_water"))
                            })?;
                    let end_gen = end
                        .get("generation")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    if generation.is_some() && end_gen != generation {
                        return Err(protocol(format!(
                            "the {name} export ended with another generation"
                        )));
                    }
                    if end.get("batches").and_then(Value::as_u64) != Some(received) {
                        return Err(protocol(format!(
                            "the {name} export announced another batch count than the {received} received"
                        )));
                    }
                    let stats = tx
                        .commit(high_water, end_gen.as_deref())
                        .await
                        .map_err(store_err)?;
                    return Ok((stats, high_water));
                }
            }
        }
        Err(protocol(format!(
            "the {name} export stream ended without its result"
        )))
    }
}

fn protocol(msg: String) -> EngineError {
    EngineError::new(ErrorKind::Internal, format!("ProtocolError: {msg}"))
}

/// Every streamed batch names the requested source; within a stream, seqs increase.
fn check_batch(name: &str, batch: &RowsBatch, last_seq: Option<u64>) -> EngineResult<()> {
    if batch.source != name {
        return Err(protocol(format!(
            "a {name} stream carried a batch of source {:?}",
            batch.source
        )));
    }
    if let Some(last) = last_seq
        && batch.seq <= last
    {
        return Err(protocol(format!(
            "batch seq {} after {last} (not increasing)",
            batch.seq
        )));
    }
    Ok(())
}

/// The applied state was written by a native source (rust ADR-0011).
fn is_native(before: Option<&AppliedState>) -> bool {
    before.is_some_and(|a| a.generation.as_deref() == Some(NATIVE_GENERATION))
}

/// Why the store refused to compare a batch with the mirror (for the job log).
fn repair_reason(before: Option<&AppliedState>, batch: &RowsBatch) -> String {
    let acked = batch.acked_through.unwrap_or(0);
    match before {
        Some(a) if is_native(Some(a)) => {
            "the last applied batches came from the native importer (generation native-rust)".into()
        }
        Some(a) if a.generation.is_some() && a.generation != batch.generation => {
            "the staging database was recreated (another generation)".into()
        }
        Some(a) if a.generation.is_none() => "the applied seq has no staging generation yet".into(),
        Some(a) => format!(
            "staging acknowledged through seq {acked}, the mirror applied only through {}",
            a.seq
        ),
        None => {
            format!("the mirror has no applied state but staging acknowledged through seq {acked}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_follow_the_plan() {
        let plan = SyncPlan {
            sources: vec!["osv".into()],
            ecosystems: vec!["PyPI".into()],
            since: Some("2026-01-01".into()),
            full: true,
            limit: Some(10),
            path: Some("/tmp/x".into()),
        };
        let o = sync_options(&plan);
        assert_eq!(o.path, Some(Some("/tmp/x".into())));
        assert_eq!(o.ecosystems, Some(vec!["PyPI".to_owned()]));
        assert_eq!(o.since, Some(Some("2026-01-01".into())));
        assert_eq!(o.full, Some(true));
        assert_eq!(o.limit, Some(Some(10)));
        let empty = sync_options(&SyncPlan {
            sources: vec![],
            ecosystems: vec![],
            since: None,
            full: false,
            limit: None,
            path: None,
        });
        let v = serde_json::to_value(&empty).unwrap();
        assert_eq!(v, json!({"ecosystems": [], "full": false}));
    }

    #[test]
    fn seconds_are_rounded_like_python() {
        assert_eq!(round1(1.26), 1.3);
        assert_eq!(round1(0.04), 0.0);
    }
}
