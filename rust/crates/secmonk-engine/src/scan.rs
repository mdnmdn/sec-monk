//! Scan jobs: ports of `ops.scan_items`, `ops.scan_target` and the image reuse rule `ops._reuse_image`. Per target:
//! reuse check (store reads + probe `docker.image_check`) or `Probe.collect` -> assemble (caps) -> `engine.classify`
//! -> sanitize -> `StateStore.save_inventory` -> persisted `engine.match` -> `replace_findings` (stale check); with
//! `save: false` an ephemeral match instead (nothing written).

use std::sync::Arc;

use secmonk_model::{CollectParams, Inventory, JobStatus, MatchParams};
use secmonk_safeio::{redact_labels, scrub_text};
use secmonk_traits::{CallCtx, collect};
use serde_json::{Map, Value, json};

use crate::engine::{Inner, store_err};
use crate::error::{EngineError, EngineResult, ErrorKind};
use crate::jobs::Job;
use crate::opts::{option_key, truthy};
use crate::payload::{
    STORED_FINDINGS, blank_entry, image_facts, priority_counts, redact_target, scan_result,
    stats_line,
};
use crate::prepare::{ScanItem, ScanPlan, repr_target};

/// Untrusted strings of an inventory, before storage: warnings and the partial reason scrubbed of URL secrets,
/// secret-looking labels redacted (collectors redact already; this is the host's backstop).
pub(crate) fn sanitize(inv: &mut Inventory) {
    for w in &mut inv.warnings {
        *w = scrub_text(w);
    }
    if let Some(r) = &inv.partial_reason {
        inv.partial_reason = Some(scrub_text(r));
    }
    if let Some(Value::Object(labels)) = inv.asset.meta.get("labels") {
        let red = redact_labels(labels);
        inv.asset.meta.insert("labels".into(), Value::Object(red));
    }
}

/// A target failure as shown in its entry (`scrub_text(f"{type(e).__name__}: {e}")`; module texts carry the type).
fn failure_text(e: &EngineError) -> String {
    scrub_text(&e.message)
}

/// What the reuse rule found.
struct Reused {
    asset: String,
    scan_id: i64,
    meta: Map<String, Value>,
}

impl Inner {
    /// `ops.scan_items` + `ops.scan_result`.
    pub(crate) async fn run_scan(
        self: &Arc<Self>,
        job: &Arc<Job>,
        plan: ScanPlan,
    ) -> EngineResult<(JobStatus, Option<Value>, Option<String>)> {
        let mut entries: Vec<Map<String, Value>> = Vec::new();
        let n_items = plan.items.len();
        for item in &plan.items {
            let targets = match self.expand(item).await {
                Ok(t) => t,
                Err(e) if plan.strict_expand => return Err(e),
                Err(e) => {
                    let mut entry = blank_entry(
                        &item.collector,
                        redact_target(item.target.as_deref()).as_deref(),
                    );
                    let text = failure_text(&e);
                    job.say(format!("{}: error: {text}", item.collector));
                    entry.insert("error".into(), json!(text));
                    entries.push(entry);
                    continue;
                }
            };
            if n_items > 1 || targets.len() > 1 || targets[0] != item.target {
                let shown: Vec<String> = targets
                    .iter()
                    .map(|t| redact_target(t.as_deref()).unwrap_or_else(|| "None".into()))
                    .collect();
                job.say(format!(
                    "{}: {} target(s): {}",
                    item.collector,
                    targets.len(),
                    shown.join(", ")
                ));
            }
            for t in targets {
                entries.push(self.scan_target(job, item, t, &plan).await);
            }
        }
        let (status, result, error) = scan_result(entries, plan.save);
        Ok((status, Some(result), error))
    }

    /// `ops.expand_targets` through the probe.
    async fn expand(&self, item: &ScanItem) -> EngineResult<Vec<Option<String>>> {
        let targets = self
            .deps
            .probe
            .expand_targets(
                CollectParams {
                    collector: item.collector.clone(),
                    target: item.target.clone(),
                    options: item.options.clone(),
                },
                CallCtx::default(),
            )
            .await?;
        if targets.is_empty() {
            return Err(EngineError::new(
                ErrorKind::CollectError,
                format!(
                    "ValueError: no {} target matches {}",
                    item.collector,
                    repr_target(item.target.as_deref())
                ),
            ));
        }
        Ok(targets)
    }

    /// `ops.scan_target`: never fails; a failure is the entry's `error`.
    async fn scan_target(
        &self,
        job: &Arc<Job>,
        item: &ScanItem,
        target: Option<String>,
        plan: &ScanPlan,
    ) -> Map<String, Value> {
        let shown = redact_target(target.as_deref());
        let mut entry = blank_entry(&item.collector, shown.as_deref());
        if let Err(e) = self
            .scan_target_inner(job, item, target, shown.as_deref(), plan, &mut entry)
            .await
        {
            let text = failure_text(&e);
            job.say(format!("error: {text}"));
            entry.insert("error".into(), json!(text));
        }
        entry
    }

    async fn scan_target_inner(
        &self,
        job: &Arc<Job>,
        item: &ScanItem,
        target: Option<String>,
        shown: Option<&str>,
        plan: &ScanPlan,
        entry: &mut Map<String, Value>,
    ) -> EngineResult<()> {
        let mc = plan.min_confidence;
        if let Some(r) = self
            .reuse_image(job, item, target.as_deref(), plan.save)
            .await?
        {
            let (stats, rows) = self
                .match_persisted(&r.asset, mc, STORED_FINDINGS as u32)
                .await?;
            entry.insert("asset".into(), json!(r.asset));
            entry.insert("scan_id".into(), json!(r.scan_id));
            entry.insert("counts".into(), Value::Object(priority_counts(&rows)));
            entry.insert("stats".into(), stats.clone());
            entry.insert("findings".into(), Value::Array(rows));
            entry.insert("reused".into(), json!(true));
            entry.insert("reused_scan_id".into(), json!(r.scan_id));
            image_facts(entry, &r.meta);
            job.say(stats_line(&stats));
            return Ok(());
        }
        // `rescan` is the engine's option, not the collector's
        let options: Vec<String> = item
            .options
            .iter()
            .filter(|o| option_key(o) != Some("rescan"))
            .cloned()
            .collect();
        job.say(match shown.filter(|s| !s.is_empty()) {
            Some(s) => format!("collecting with {} on {s}…", item.collector),
            None => format!("collecting with {}…", item.collector),
        });
        let stream = self
            .deps
            .probe
            .collect(
                CollectParams {
                    collector: item.collector.clone(),
                    target: target.clone(),
                    options,
                },
                CallCtx::default(),
            )
            .await?;
        let mut inv = collect::assemble(stream, collect::Caps::default()).await?;
        self.classify(&mut inv).await?;
        sanitize(&mut inv);
        let partial = inv.partial;
        entry.insert("asset".into(), json!(inv.asset.id));
        entry.insert("warnings".into(), json!(inv.warnings));
        entry.insert("partial".into(), json!(partial));
        if inv.asset.id.starts_with("image:") {
            image_facts(entry, &inv.asset.meta);
        }
        job.say(format!(
            "{}: {} components",
            inv.asset.id,
            inv.components.len()
        ));
        for w in &inv.warnings {
            job.say(format!("warning: {w}"));
        }
        if partial {
            job.say("partial inventory — previous components kept");
        }
        job.say("matching against the local mirror…");
        let (scan_id, stats, rows) = if plan.save {
            let scan_id = self
                .deps
                .state
                .save_inventory(&inv, Some(job.id))
                .await
                .map_err(store_err)?;
            let (stats, rows) = self
                .match_persisted(&inv.asset.id, mc, STORED_FINDINGS as u32)
                .await?;
            (Some(scan_id), stats, rows)
        } else {
            let r = self
                .deps
                .steps
                .match_asset(
                    MatchParams::Ephemeral {
                        inventory: Box::new(inv),
                        min_confidence: mc,
                        view_limit: Some(STORED_FINDINGS as u32),
                    },
                    CallCtx::default(),
                )
                .await?;
            let stats = serde_json::to_value(&r.stats).unwrap_or_else(|_| json!({}));
            (None, stats, r.view.into_iter().map(Value::Object).collect())
        };
        entry.insert("scan_id".into(), json!(scan_id));
        entry.insert("counts".into(), Value::Object(priority_counts(&rows)));
        entry.insert("stats".into(), stats.clone());
        entry.insert("findings".into(), Value::Array(rows));
        job.say(stats_line(&stats));
        Ok(())
    }

    /// `ops._reuse_image`: an engine image already inventoried (asset `image:@<Id>`) is not collected again when
    /// every trust condition holds (saving, no `rescan=true`, latest scan complete, current inventory format,
    /// `id_verified`, the engine answers for this Id now, same engine and platform). The probe half is
    /// `docker.image_check`; the rule and the write are here. `Ok(None)` = collect.
    async fn reuse_image(
        &self,
        job: &Arc<Job>,
        item: &ScanItem,
        target: Option<&str>,
        save: bool,
    ) -> EngineResult<Option<Reused>> {
        let Some(target) = target.filter(|t| !t.is_empty()) else {
            return Ok(None);
        };
        if item.collector != "docker-engine"
            || !save
            || item.opts.get("rescan") == Some(&Value::Bool(true))
        {
            return Ok(None);
        }
        let check = match self
            .deps
            .probe
            .call(
                "docker.image_check",
                json!({"target": target, "options": item.options}),
                CallCtx::default(),
            )
            .await
        {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e.error, "docker.image_check failed: collecting");
                return Ok(None);
            }
        };
        let (Some(asset_id), Some(version)) = (
            check.get("asset_id").and_then(Value::as_str),
            check.get("inventory_version").and_then(Value::as_str),
        ) else {
            return Ok(None);
        };
        let Some(facts) = self
            .deps
            .state
            .asset_reuse_facts(asset_id)
            .await
            .map_err(store_err)?
        else {
            return Ok(None);
        };
        let Some(last) = facts.latest_scan_id else {
            return Ok(None);
        };
        let meta = facts.meta.clone();
        let stored_version = meta.get("inventory_version").map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        });
        if facts.latest_scan_partial
            || stored_version.as_deref() != Some(version)
            || meta.get("id_verified") != Some(&Value::Bool(true))
        {
            job.say(format!(
                "{asset_id}: stored inventory is partial, unverified or from another format — collecting again"
            ));
            return Ok(None);
        }
        let fresh = match (
            check.get("meta"),
            check.get("error").and_then(Value::as_str),
        ) {
            (Some(Value::Object(m)), None) => m.clone(),
            (_, err) => {
                job.say(format!(
                    "{asset_id}: cannot confirm the image on the engine ({}) — collecting again",
                    err.unwrap_or("Error")
                ));
                return Ok(None);
            }
        };
        let iid = target.strip_prefix("image:").unwrap_or(target);
        if fresh.get("image_id").and_then(Value::as_str) != Some(iid) {
            job.say(format!(
                "{asset_id}: the engine reports another image for this Id — collecting again"
            ));
            return Ok(None);
        }
        let engine = check.get("engine").cloned().unwrap_or(Value::Null);
        let platform = fresh.get("platform").filter(|v| truthy(v));
        let stored_platform = meta
            .get("platform")
            .filter(|v| truthy(v))
            .cloned()
            .or_else(|| {
                facts
                    .platform
                    .clone()
                    .filter(|p| !p.is_empty())
                    .map(Value::String)
            });
        let platform_differs = matches!((platform, &stored_platform), (Some(p), Some(s)) if p != s);
        if meta.get("engine").unwrap_or(&Value::Null) != &engine || platform_differs {
            job.say(format!(
                "{asset_id}: inventoried through another engine or platform — collecting again"
            ));
            return Ok(None);
        }
        let refs: Vec<Value> = fresh
            .get("requested_refs")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut new = meta.clone();
        for (k, v) in &fresh {
            if k != "requested_ref" && k != "requested_refs" {
                new.insert(k.clone(), v.clone());
            }
        }
        new.insert("engine".into(), engine);
        let requested = match refs.first() {
            Some(r) => r.clone(),
            None => meta
                .get("requested_ref")
                .filter(|v| truthy(v))
                .or_else(|| fresh.get("requested_ref"))
                .cloned()
                .unwrap_or(Value::Null),
        };
        new.insert("requested_ref".into(), requested.clone());
        new.shift_remove("requested_refs");
        if !refs.is_empty() {
            new.insert("requested_refs".into(), Value::Array(refs));
        }
        let tags: Vec<&str> = fresh
            .get("tags")
            .and_then(Value::as_array)
            .map(|t| t.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let mut name = facts.name.clone();
        if !tags.is_empty() && !name.as_deref().is_some_and(|n| tags.contains(&n)) {
            name = match requested.as_str() {
                Some(r) if tags.contains(&r) => Some(r.to_owned()),
                _ => tags.iter().min().map(|t| (*t).to_owned()),
            };
        }
        self.deps
            .state
            .update_asset_reused(asset_id, name.as_deref(), &new)
            .await
            .map_err(store_err)?;
        job.say(format!(
            "{asset_id}: already inventoried (scan {last}): reusing it, matching against the current mirror"
        ));
        Ok(Some(Reused {
            asset: asset_id.to_owned(),
            scan_id: last,
            meta: new,
        }))
    }
}
