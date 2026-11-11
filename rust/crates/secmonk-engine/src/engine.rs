//! [`SecmonkEngine`]: the engine service over the stores, the engine steps, the sources and the probe.
//!
//! Reads come from `Reporter` (`reports.*`, `procmon.*`: the py-engine payload builders on a read-only snapshot) or
//! from the state store (run history); every write goes through the store (the host is the only writer, rust
//! ADR-0006). Jobs (scan, sync) run one at a time as tokio tasks (`scan.rs`, `sync.rs`).

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use secmonk_model::{
    Inventory, JobFinish, JobKind as ModelJobKind, JobOrigin, JobStatus, MatchParams, NewJob,
};
use secmonk_store::StoreError;
use secmonk_traits::{CallCtx, Source};
use serde_json::{Value, json};

use crate::deps::EngineDeps;
use crate::error::{EngineError, EngineResult, ErrorKind};
use crate::jobs::{Job, Live, Running};
use crate::params::{
    DiscoverQuery, DockerListQuery, FindingsQuery, JobKind, JobsQuery, VulnSearchQuery,
};
use crate::payload::{job_dict, job_summary, stored_result};
use crate::prepare::{Plan, Registry, SYNC_ALL_ORDER, Work, prepare};
use crate::service::{EngineService, JsonObject};
use crate::skeleton::{FEATURES, current_platform};

/// `/api/meta` `engine.schema`.
pub const SCHEMA_LABEL: &str = "state/3+mirror/3";
/// How long `shutdown` waits for the interrupted job's row to be stored.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// A store failure as an engine error (`<Type>: <message>` for the 500 body).
pub(crate) fn store_err(e: StoreError) -> EngineError {
    match e {
        StoreError::Invalid(m) => EngineError::invalid(m),
        StoreError::Stale(m) => EngineError::new(ErrorKind::Busy, format!("stale: {m}")),
        other => EngineError::new(ErrorKind::Internal, format!("StoreError: {other}")),
    }
}

/// What a job start, a write route or a `POST` answers once the shutdown began: the shape of the host gate's
/// "stopping" state (`ModuleUnavailable` = 503, no code), so the UI sees one message whichever layer refused.
fn closing_error() -> EngineError {
    EngineError::new(ErrorKind::ModuleUnavailable, "sec-monk is shutting down")
}

/// `Live::starting` while a job start is between its busy check and its job being listed. Dropping the guard
/// clears the flag, also when the start fails or its future is dropped mid-`await` (else the engine would stay
/// busy forever).
struct StartingGuard<'a> {
    inner: &'a Inner,
}

impl<'a> StartingGuard<'a> {
    fn arm(inner: &'a Inner, live: &mut Live) -> StartingGuard<'a> {
        live.starting = true;
        StartingGuard { inner }
    }
}

impl Drop for StartingGuard<'_> {
    fn drop(&mut self) {
        self.inner.live().starting = false;
    }
}

/// Shared state of the engine (the jobs' tasks hold an `Arc` of it).
pub(crate) struct Inner {
    pub(crate) deps: EngineDeps,
    pub(crate) live: Mutex<Live>,
    /// Set (once, under the `live` lock) when [`SecmonkEngine::shutdown`] begins: no job starts and no write
    /// route runs after it.
    closing: AtomicBool,
    startup: tokio::sync::OnceCell<()>,
    discovering: tokio::sync::Mutex<()>,
}

/// The engine service. Build it with [`SecmonkEngine::new`].
pub struct SecmonkEngine {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for SecmonkEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecmonkEngine")
            .field("deps", &self.inner.deps)
            .finish_non_exhaustive()
    }
}

impl SecmonkEngine {
    /// Build the engine from its dependencies. No I/O and no task here: the first history read or job start marks
    /// runs of dead processes `interrupted`. `Arc<SecmonkEngine>` coerces to `Arc<dyn EngineService>`.
    pub fn new(deps: EngineDeps) -> Arc<SecmonkEngine> {
        Arc::new(SecmonkEngine {
            inner: Arc::new(Inner {
                deps,
                live: Mutex::new(Live::default()),
                closing: AtomicBool::new(false),
                startup: tokio::sync::OnceCell::new(),
                discovering: tokio::sync::Mutex::new(()),
            }),
        })
    }

    /// App exit: refuse new jobs and writes from now on (503 "sec-monk is shutting down", as the host's gate), abort
    /// the running job (dropping its module calls sends `cancel`) and store it as `error` / `interrupted`. Waits at
    /// most 5 s for the row.
    pub async fn shutdown(&self) {
        let running = {
            let mut live = self.inner.live();
            self.inner.closing.store(true, Ordering::SeqCst);
            live.running.take()
        };
        if let Some(r) = running {
            r.work.abort();
            let _ = tokio::time::timeout(SHUTDOWN_GRACE, r.done).await;
        }
    }

    /// Whether a job is running or starting (`JobRunner.busy`).
    pub fn busy(&self) -> bool {
        self.inner.live().busy()
    }
}

impl Inner {
    pub(crate) fn live(&self) -> std::sync::MutexGuard<'_, Live> {
        self.live.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn state_path(&self) -> String {
        self.deps.config.state_db.display().to_string()
    }

    /// Runs left `running` by a dead process -> `error` / `interrupted` (once; never fails the request).
    async fn startup(&self) {
        self.startup
            .get_or_init(|| async {
                if let Err(e) = self.deps.state.job_mark_interrupted().await {
                    tracing::warn!(error = %e, "could not mark interrupted runs");
                }
            })
            .await;
    }

    /// The store is initialized: something was synced, scanned or run.
    pub(crate) async fn initialized(&self) -> EngineResult<bool> {
        if self.deps.state.is_initialized().await.map_err(store_err)? {
            return Ok(true);
        }
        self.deps.mirror.is_initialized().await.map_err(store_err)
    }

    async fn require_db(&self) -> EngineResult<()> {
        if self.initialized().await? {
            Ok(())
        } else {
            Err(EngineError::no_db(self.state_path()))
        }
    }

    fn require_actions(&self) -> EngineResult<()> {
        if self.deps.config.allow_actions {
            return Ok(());
        }
        Err(EngineError::invalid("actions are disabled on this server").with_hint(
            "The UI listens on a non-loopback address: start it with --allow-actions to run scans, syncs and \
             docker queries from the browser.",
        ))
    }

    /// After the shutdown began: the error every job start and write answers (the gate's "stopping" shape).
    fn refuse_when_closing(&self) -> EngineResult<()> {
        if self.closing.load(Ordering::SeqCst) {
            return Err(closing_error());
        }
        Ok(())
    }

    /// `refuse_writes_while_busy`: re-match and process save wait for the job (and nothing writes once closing).
    fn refuse_writes_while_busy(&self) -> EngineResult<()> {
        self.refuse_when_closing()?;
        if self.live().busy() {
            return Err(
                EngineError::new(ErrorKind::Busy, "a job is writing to the database")
                    .with_hint("Try again when it has finished (Jobs)."),
            );
        }
        Ok(())
    }

    async fn report(&self, method: &str, params: Value) -> EngineResult<Value> {
        Ok(self
            .deps
            .steps
            .report(method, params, CallCtx::default())
            .await?)
    }

    /// The sources by name (first module wins), sorted by name.
    pub(crate) fn sources(&self) -> Vec<(secmonk_proto::SourceInfo, Arc<dyn Source>)> {
        let mut out: Vec<(secmonk_proto::SourceInfo, Arc<dyn Source>)> = Vec::new();
        for s in &self.deps.sources {
            for info in s.sources() {
                if !out.iter().any(|(i, _)| i.name == info.name) {
                    out.push((info, s.clone()));
                }
            }
        }
        out.sort_by(|a, b| a.0.name.cmp(&b.0.name));
        out
    }

    fn sync_all_order(&self) -> Vec<String> {
        self.deps
            .sources
            .iter()
            .map(|s| s.sync_all_order())
            .find(|o| !o.is_empty())
            .unwrap_or_else(|| SYNC_ALL_ORDER.iter().map(|s| (*s).to_owned()).collect())
    }

    pub(crate) fn collector_names(&self) -> BTreeSet<String> {
        self.deps
            .probe
            .collectors()
            .into_iter()
            .map(|c| c.name)
            .collect()
    }

    /// Persisted `engine.match` of a stored asset, then the finding set replaced in the store. A scan that landed
    /// between the module's read and the write (`stale`) re-runs the match once.
    pub(crate) async fn match_persisted(
        &self,
        asset_id: &str,
        min_confidence: f64,
        view_limit: u32,
    ) -> EngineResult<(Value, Vec<Value>)> {
        let mut attempt = 0;
        loop {
            attempt += 1;
            let r = self
                .deps
                .steps
                .match_asset(
                    MatchParams::Persisted {
                        asset_id: asset_id.to_owned(),
                        min_confidence,
                        view_limit: Some(view_limit),
                    },
                    CallCtx::default(),
                )
                .await?;
            let (Some(set), Some(based_on)) = (r.finding_set.as_ref(), r.based_on.as_ref()) else {
                return Err(EngineError::new(
                    ErrorKind::Internal,
                    "ProtocolError: persisted match without finding_set / based_on",
                ));
            };
            if r.asset_id != asset_id {
                return Err(EngineError::new(
                    ErrorKind::Internal,
                    "ProtocolError: match answered for another asset",
                ));
            }
            match self
                .deps
                .state
                .replace_findings(asset_id, set, based_on)
                .await
            {
                Ok(_) => {
                    let stats = serde_json::to_value(&r.stats).unwrap_or_else(|_| json!({}));
                    return Ok((stats, r.view.into_iter().map(Value::Object).collect()));
                }
                Err(StoreError::Stale(_)) if attempt < 2 => continue,
                Err(e) => return Err(store_err(e)),
            }
        }
    }

    // ------------------------------------------------------------------------------------------- jobs

    async fn job_start(self: &Arc<Self>, body: JsonObject) -> EngineResult<Value> {
        self.require_actions()?;
        self.refuse_when_closing()?;
        self.startup().await;
        let collectors = self.collector_names();
        let sources: Vec<(String, bool)> = self
            .sources()
            .into_iter()
            .map(|(i, _)| (i.name, i.in_all))
            .collect();
        let order = self.sync_all_order();
        let state_db = self.state_path();
        let reg = Registry {
            collectors: &collectors,
            sources: &sources,
            sync_all_order: &order,
            min_confidence: self.deps.config.min_confidence,
            db_exists: self.initialized().await?,
            state_db: &state_db,
        };
        let plan = prepare(&body, &reg)?;
        // `starting` is reset by the guard however this function ends (an error, or the request future dropped
        // while the job row is being inserted: review L7).
        let _starting = {
            let mut live = self.live();
            if self.closing.load(Ordering::SeqCst) {
                return Err(closing_error());
            }
            if live.busy() {
                return Err(EngineError::new(ErrorKind::Busy, "another job is running")
                    .with_hint("Wait for it to finish (Jobs in the sidebar)."));
            }
            StartingGuard::arm(self, &mut live)
        };
        let Plan {
            kind,
            title,
            params,
            work,
        } = plan;
        let started = secmonk_model::time::now_iso();
        let new = NewJob {
            kind,
            origin: JobOrigin::Ui,
            title: Some(title.clone()),
            params: Some(params.clone()),
            started_at: Some(started.clone()),
            owner: secmonk_store::jobs::this_owner(),
        };
        let id = match self.deps.state.job_insert(&new).await {
            Ok(id) => id,
            Err(e) => {
                return Err(EngineError::new(
                    ErrorKind::Internal,
                    format!("cannot record the job: StoreError: {e}"),
                )
                .with_hint("Try again in a moment."));
            }
        };
        let job = Arc::new(Job::new(id, kind, title, params, started));
        let payload = job.to_dict(true);
        let mut live = self.live();
        if self.closing.load(Ordering::SeqCst) {
            // the shutdown began while the row was inserted: it never runs, its row is closed as interrupted
            drop(live);
            self.finish_job(
                &job,
                Err(EngineError::new(ErrorKind::Internal, "interrupted")),
            )
            .await;
            return Err(closing_error());
        }
        let work_task = {
            let inner = self.clone();
            let job = job.clone();
            tokio::spawn(async move { inner.run_work(&job, work).await })
        };
        let abort = work_task.abort_handle();
        let done = {
            let inner = self.clone();
            let job = job.clone();
            tokio::spawn(async move {
                let out = match work_task.await {
                    Ok(r) => r,
                    Err(e) if e.is_cancelled() => {
                        Err(EngineError::new(ErrorKind::Internal, "interrupted"))
                    }
                    Err(_) => Err(EngineError::new(
                        ErrorKind::Internal,
                        "internal error: the job task panicked",
                    )),
                };
                inner.finish_job(&job, out).await;
            })
        };
        live.push(job.clone());
        live.running = Some(Running {
            job,
            work: abort,
            done,
        });
        Ok(payload)
    }

    async fn run_work(
        self: &Arc<Self>,
        job: &Arc<Job>,
        work: Work,
    ) -> EngineResult<(JobStatus, Option<Value>, Option<String>)> {
        match work {
            Work::Sync(p) => self.run_sync(job, p).await,
            Work::Scan(p) => self.run_scan(job, p).await,
        }
    }

    /// `JobRunner._run` after the work: store the outcome (capped, scrubbed), then show it as finished.
    async fn finish_job(
        &self,
        job: &Arc<Job>,
        out: EngineResult<(JobStatus, Option<Value>, Option<String>)>,
    ) {
        let (status, result, error) = match out {
            Ok(t) => t,
            Err(e) => (JobStatus::Error, None, Some(e.message)),
        };
        let error = error.map(|e| secmonk_safeio::scrub_text(&e));
        if let Some(e) = &error {
            job.say(format!("error: {e}"));
        }
        let stored = stored_result(job.kind, result.as_ref());
        let fin = JobFinish {
            status,
            summary: Some(job_summary(job.kind, stored.as_ref())),
            result: stored,
            error: error.clone(),
            log: job.log(),
        };
        if let Err(e) = self.deps.state.job_finish(job.id, &fin).await {
            job.say(format!(
                "could not record the run in the history: StoreError: {e}"
            ));
        }
        job.finish(status, result, error);
        let mut live = self.live();
        if live.running.as_ref().is_some_and(|r| r.job.id == job.id) {
            live.running = None;
        }
    }

    async fn jobs_list(&self, q: &JobsQuery) -> EngineResult<Value> {
        self.startup().await;
        let kind = q.kind.map(|k| match k {
            JobKind::Scan => ModelJobKind::Scan,
            JobKind::Sync => ModelJobKind::Sync,
        });
        let limit = q.limit.clamp(1, 200) as usize;
        let mut out: std::collections::BTreeMap<i64, Value> = Default::default();
        for r in self
            .deps
            .state
            .job_rows(kind, limit as i64)
            .await
            .map_err(store_err)?
        {
            out.insert(r.id, job_dict(&r, false));
        }
        let live: Vec<Arc<Job>> = self
            .live()
            .jobs
            .iter()
            .filter(|j| kind.is_none_or(|k| j.kind == k))
            .cloned()
            .collect();
        for j in live {
            out.insert(j.id, j.to_dict(false)); // live state wins over the stored row
        }
        Ok(Value::Array(out.into_values().rev().take(limit).collect()))
    }

    async fn job_get(&self, id: u64) -> EngineResult<Value> {
        self.startup().await;
        let Ok(id) = i64::try_from(id) else {
            return Err(EngineError::unknown_job(id));
        };
        let live = self.live().jobs.iter().find(|j| j.id == id).cloned();
        if let Some(j) = live {
            return Ok(j.to_dict(true));
        }
        match self.deps.state.job_row(id).await.map_err(store_err)? {
            Some(r) => Ok(job_dict(&r, true)),
            None => Err(EngineError::unknown_job(id as u64)),
        }
    }

    // ------------------------------------------------------------------------------------------- writes

    async fn match_asset(&self, id: &str) -> EngineResult<Value> {
        self.refuse_writes_while_busy()?;
        self.require_db().await?;
        if !self.deps.state.asset_exists(id).await.map_err(store_err)? {
            return Err(EngineError::unknown_asset(id));
        }
        let (stats, _) = self
            .match_persisted(id, self.deps.config.min_confidence, 0)
            .await?;
        Ok(json!({"asset": id, "stats": stats}))
    }

    async fn processes_save(&self) -> EngineResult<Value> {
        self.refuse_writes_while_busy()?;
        let pm = self.procmon()?;
        let r = pm
            .report("procmon.inventory", json!({}), CallCtx::default())
            .await?;
        let mut inv: Inventory = serde_json::from_value(
            r.get("inventory").cloned().unwrap_or(Value::Null),
        )
        .map_err(|e| {
            EngineError::new(
                ErrorKind::Internal,
                format!("ProtocolError: procmon.inventory: {e}"),
            )
        })?;
        self.classify(&mut inv).await?;
        crate::scan::sanitize(&mut inv);
        let scan_id = self
            .deps
            .state
            .save_inventory(&inv, None)
            .await
            .map_err(store_err)?;
        let (stats, _) = self
            .match_persisted(&inv.asset.id, self.deps.config.min_confidence, 0)
            .await?;
        Ok(json!({"asset": inv.asset.id, "scan_id": scan_id, "stats": stats}))
    }

    /// `engine.classify` on ingest (components a collector streamed unclassified).
    pub(crate) async fn classify(&self, inv: &mut Inventory) -> EngineResult<()> {
        if inv.is_classified() {
            return Ok(());
        }
        if !inv.components.is_empty() {
            let comps = std::mem::take(&mut inv.components);
            inv.components = self.deps.steps.classify(comps, CallCtx::default()).await?;
        }
        inv.classified = Some(true);
        Ok(())
    }

    fn procmon(&self) -> EngineResult<&Arc<dyn secmonk_traits::Reporter>> {
        self.deps.procmon.as_ref().ok_or_else(|| {
            EngineError::new(
                ErrorKind::UnsupportedPlatform,
                "UnsupportedPlatformError: no process monitor on this platform",
            )
            .with_hint(
                "Live process snapshots exist only on macOS and Linux so far. Start the app with a snapshot file \
                 (`[ui] snapshot` in sec-monk.toml).",
            )
        })
    }
}

#[async_trait]
impl EngineService for SecmonkEngine {
    async fn meta(&self) -> EngineResult<Value> {
        let i = &self.inner;
        let exists = i.initialized().await.unwrap_or(false);
        let modules = match &i.deps.modules {
            Some(m) => serde_json::to_value(m.modules().await).unwrap_or_else(|_| json!([])),
            None => json!([]),
        };
        Ok(json!({
            "version": i.deps.config.version,
            "mode": if i.deps.config.snapshot_mode { "snapshot" } else { "live" },
            "platform": current_platform(),
            "db": {"path": i.state_path(), "exists": exists},
            "features": FEATURES,
            "engine": {"runtime": "rust", "schema": SCHEMA_LABEL, "modules": modules},
        }))
    }

    async fn processes(&self, refresh: bool) -> EngineResult<Value> {
        let pm = self.inner.procmon()?;
        Ok(pm
            .report(
                "procmon.payload",
                json!({"refresh": refresh}),
                CallCtx::default(),
            )
            .await?)
    }

    async fn processes_watch(&self) -> EngineResult<Value> {
        let pm = self.inner.procmon()?;
        Ok(pm
            .report("procmon.watch", json!({}), CallCtx::default())
            .await?)
    }

    async fn processes_save(&self) -> EngineResult<Value> {
        self.inner.processes_save().await
    }

    async fn overview(&self) -> EngineResult<Value> {
        self.inner.require_db().await?;
        self.inner.report("reports.overview", json!({})).await
    }

    async fn assets(&self) -> EngineResult<Value> {
        self.inner.require_db().await?;
        self.inner.report("reports.assets", json!({})).await
    }

    async fn asset_detail(&self, id: &str, limit: u32) -> EngineResult<Value> {
        self.inner.require_db().await?;
        self.inner
            .report("reports.asset_detail", json!({"id": id, "limit": limit}))
            .await
    }

    async fn sbom(&self, id: &str, with_vulns: bool) -> EngineResult<Value> {
        self.inner.require_db().await?;
        self.inner
            .report(
                "reports.sbom",
                json!({"asset_id": id, "with_vulns": with_vulns}),
            )
            .await
    }

    async fn match_asset(&self, id: &str) -> EngineResult<Value> {
        self.inner.match_asset(id).await
    }

    async fn unmatched(&self) -> EngineResult<Value> {
        self.inner.require_db().await?;
        self.inner.report("reports.unmatched", json!({})).await
    }

    async fn findings(&self, q: &FindingsQuery) -> EngineResult<Value> {
        self.inner.require_db().await?;
        let rows = self
            .inner
            .report(
                "reports.findings",
                json!({
                    "asset": q.asset, "priority": q.priority, "include_closed": q.include_closed,
                    "fixable": q.fixable, "hide_minor": q.hide_minor, "hide_deferred": q.hide_deferred,
                    "limit": q.limit,
                }),
            )
            .await?;
        let n = rows.as_array().map_or(0, Vec::len);
        Ok(json!({"findings": rows, "limit": q.limit, "limit_reached": n >= q.limit as usize}))
    }

    async fn vuln_show(&self, id: &str, raw: bool) -> EngineResult<Value> {
        self.inner.require_db().await?;
        self.inner
            .report("reports.vuln_detail", json!({"id": id, "raw": raw}))
            .await
    }

    async fn vuln_search(&self, q: &VulnSearchQuery) -> EngineResult<Value> {
        self.inner.require_db().await?;
        let rows = self
            .inner
            .report(
                "reports.vuln_search",
                json!({
                    "package": q.package, "ecosystem": q.ecosystem, "product": q.product, "version": q.version,
                    "limit": q.limit,
                }),
            )
            .await?;
        let n = rows.as_array().map_or(0, Vec::len);
        Ok(json!({"results": rows, "limit": q.limit, "limit_reached": n >= q.limit as usize}))
    }

    async fn sources(&self) -> EngineResult<Value> {
        let i = &self.inner;
        let status = if i.initialized().await? {
            i.report("reports.status", json!({})).await?
        } else {
            Value::Null
        };
        let registry: Vec<Value> = i
            .sources()
            .into_iter()
            .map(|(s, _)| json!({"name": s.name, "description": s.description, "in_all": s.in_all}))
            .collect();
        Ok(json!({
            "db": {"path": i.state_path(), "exists": !status.is_null()},
            "registry": registry,
            "sync_all_order": i.sync_all_order(),
            "status": status,
        }))
    }

    async fn collectors(&self) -> EngineResult<Value> {
        let mut rows = self.inner.deps.probe.collectors();
        rows.sort_by(|a, b| a.name.cmp(&b.name));
        rows.dedup_by(|a, b| a.name == b.name);
        Ok(Value::Array(
            rows.into_iter()
                .map(|i| json!({"name": i.name, "description": i.description, "in_all": true}))
                .collect(),
        ))
    }

    async fn jobs_list(&self, query: &JobsQuery) -> EngineResult<Value> {
        self.inner.jobs_list(query).await
    }

    async fn job_get(&self, id: u64) -> EngineResult<Value> {
        self.inner.job_get(id).await
    }

    async fn job_start(&self, body: JsonObject) -> EngineResult<Value> {
        self.inner.job_start(body).await
    }

    async fn discover(&self, q: &DiscoverQuery) -> EngineResult<Value> {
        let i = &self.inner;
        i.require_actions()?;
        crate::opts::parse_opts(&q.options)
            .map_err(|e| EngineError::invalid(format!("opt: {e}")))?;
        let Ok(_guard) = i.discovering.try_lock() else {
            return Err(
                EngineError::new(ErrorKind::Busy, "a discovery is already running")
                    .with_hint("Wait for it to finish, then try again."),
            );
        };
        Ok(i.deps
            .probe
            .call(
                "discover.host",
                json!({"target": q.target, "options": q.options}),
                CallCtx::default(),
            )
            .await?)
    }

    async fn k8s_kubeconfigs(&self) -> EngineResult<Value> {
        let i = &self.inner;
        i.require_actions()?;
        Ok(i.deps
            .probe
            .call("k8s.kubeconfigs", json!({}), CallCtx::default())
            .await?)
    }

    async fn docker_contexts(&self) -> EngineResult<Value> {
        let i = &self.inner;
        i.require_actions()?;
        Ok(i.deps
            .probe
            .call("docker.contexts", json!({}), CallCtx::default())
            .await?)
    }

    async fn docker_containers(&self, q: &DockerListQuery) -> EngineResult<Value> {
        let i = &self.inner;
        i.require_actions()?;
        crate::opts::parse_opts(&q.options)
            .map_err(|e| EngineError::invalid(format!("opt: {e}")))?;
        Ok(i.deps
            .probe
            .call(
                "docker.containers",
                json!({"host": q.host, "context": q.context, "all": q.all, "match": q.selector,
                       "options": q.options}),
                CallCtx::default(),
            )
            .await?)
    }
}
