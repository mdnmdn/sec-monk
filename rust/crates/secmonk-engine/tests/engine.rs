//! Engine tests over fakes: a real SQLite store in a temporary directory, fake `EngineSteps`, `Source` and `Probe`.
//! The payloads the engine builds itself (meta, sources, collectors, jobs, match results) are checked against the
//! `rust/contracts` schemas with the dev venv's `jsonschema` when `rust/python/.venv` exists.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use secmonk_engine::{
    EngineConfig, EngineDeps, EngineService, ErrorKind, JobsQuery, SecmonkEngine,
};
use secmonk_model::{Asset, Category, Component, MatchParams, MatchResult, RowsBatch, SyncEnd};
use secmonk_store::{MirrorStore, SqliteStore, StateStore, StoreOptions};
use secmonk_traits::ErrorCode;
use secmonk_traits::{
    CallCtx, Classifier, CollectEnd, CollectItem, CollectParams, Collector, CollectorInfo, Matcher,
    Probe, ProgressUpdate, Reporter, ResultStream, Source, SourceInfo, StepResult, StreamMsg,
    SyncParams, VersionOracle, WireError,
};
use serde_json::{Map, Value, json};

// ------------------------------------------------------------------------------------------------ fakes

/// classify = identity, persisted match = an empty finding set on the asset's latest scan, reports = canned.
struct FakeSteps {
    store: Arc<SqliteStore>,
    /// The next persisted match answers a stale `based_on` (a scan landed meanwhile).
    stale_once: AtomicBool,
    persisted_calls: AtomicU64,
}

#[async_trait]
impl Classifier for FakeSteps {
    async fn classify(&self, components: Vec<Component>, _: CallCtx) -> StepResult<Vec<Component>> {
        Ok(components
            .into_iter()
            .map(|mut c| {
                c.ecosystem.get_or_insert_with(|| "PyPI".into());
                c
            })
            .collect())
    }
}

fn view_row(asset: &str) -> Map<String, Value> {
    json!({"asset_id": asset, "vuln_id": "CVE-2026-0001", "priority": "P2", "kev": false, "status": "open"})
        .as_object()
        .cloned()
        .unwrap()
}

#[async_trait]
impl Matcher for FakeSteps {
    async fn match_asset(&self, params: MatchParams, _: CallCtx) -> StepResult<MatchResult> {
        let (asset, persisted, n) = match &params {
            MatchParams::Persisted { asset_id, .. } => (asset_id.clone(), true, 0),
            MatchParams::Ephemeral { inventory, .. } => (
                inventory.asset.id.clone(),
                false,
                inventory.components.len(),
            ),
        };
        let mut r = json!({
            "asset_id": asset, "mode": if persisted { "persisted" } else { "ephemeral" },
            "stats": {"components": n, "matches": 1, "findings": 1}, "view": [view_row(&asset)],
        });
        if persisted {
            self.persisted_calls.fetch_add(1, Ordering::SeqCst);
            let mut latest = self.store.latest_scan_id(&asset).await.unwrap();
            if self.stale_once.swap(false, Ordering::SeqCst) {
                latest = latest.map(|l| l - 1);
            }
            r["based_on"] = json!({"latest_scan_id": latest});
            r["finding_set"] = json!([]);
        }
        Ok(serde_json::from_value(r).unwrap())
    }
}

#[async_trait]
impl Reporter for FakeSteps {
    fn methods(&self) -> Vec<String> {
        vec!["reports.status".into()]
    }

    async fn report(&self, method: &str, _: Value, _: CallCtx) -> StepResult<Value> {
        match method {
            "reports.status" => Ok(json!({"sources": [], "counts": {}})),
            m => Err(WireError::new(ErrorCode::UnknownMethod, format!("no {m}"))),
        }
    }
}

#[async_trait]
impl VersionOracle for FakeSteps {
    async fn compare(
        &self,
        _: &str,
        _: &str,
        _: &str,
        _: CallCtx,
    ) -> StepResult<std::cmp::Ordering> {
        Ok(std::cmp::Ordering::Equal)
    }
    async fn in_range(&self, _: &str, _: &[Value], _: &str, _: CallCtx) -> StepResult<bool> {
        Ok(false)
    }
    async fn first_fixed(
        &self,
        _: &str,
        _: &[Value],
        _: &str,
        _: CallCtx,
    ) -> StepResult<Option<String>> {
        Ok(None)
    }
    async fn scheme(&self, _: Option<&str>, _: CallCtx) -> StepResult<String> {
        Ok("semver".into())
    }
    async fn priority(&self, _: Value, _: CallCtx) -> StepResult<String> {
        Ok("P4".into())
    }
}

/// What one fake `source.sync` does.
#[derive(Clone)]
enum Script {
    /// Stream these batches, then `end` with this entry status.
    Batches(Vec<RowsBatch>, &'static str),
    /// Never answer (until dropped).
    Hang,
    /// Fail the call.
    Fail(&'static str),
}

/// What one fake `source.export` does (default: an empty export, high-water 0).
#[derive(Clone)]
enum Export {
    /// Stream these batches, then `end` with this high-water mark and generation.
    Batches(Vec<RowsBatch>, u64, &'static str),
    /// Stream these batches, then fail (the repair must roll back).
    FailAfter(Vec<RowsBatch>),
}

struct FakeSource {
    scripts: Mutex<std::collections::HashMap<String, Script>>,
    exports: Mutex<std::collections::HashMap<String, Export>>,
    acks: Mutex<Vec<(String, u64)>>,
    secrets_seen: Mutex<Vec<Option<String>>>,
}

impl FakeSource {
    fn new(scripts: &[(&str, Script)]) -> Arc<FakeSource> {
        Arc::new(FakeSource {
            scripts: Mutex::new(
                scripts
                    .iter()
                    .map(|(n, s)| ((*n).to_owned(), s.clone()))
                    .collect(),
            ),
            exports: Mutex::new(Default::default()),
            acks: Mutex::new(Vec::new()),
            secrets_seen: Mutex::new(Vec::new()),
        })
    }

    fn script(&self, source: &str, s: Script) {
        self.scripts.lock().unwrap().insert(source.into(), s);
    }

    fn export(&self, source: &str, e: Export) {
        self.exports.lock().unwrap().insert(source.into(), e);
    }
}

#[async_trait]
impl Source for FakeSource {
    fn sources(&self) -> Vec<SourceInfo> {
        ["kev", "epss", "osv"]
            .iter()
            .map(|n| SourceInfo {
                name: (*n).into(),
                description: format!("{n} feed"),
                in_all: *n != "osv",
            })
            .collect()
    }

    fn sync_all_order(&self) -> Vec<String> {
        vec!["kev".into(), "epss".into(), "osv".into()]
    }

    async fn sync(
        &self,
        params: SyncParams,
        ctx: CallCtx,
    ) -> StepResult<ResultStream<RowsBatch, SyncEnd>> {
        self.secrets_seen
            .lock()
            .unwrap()
            .push(params.secrets.as_ref().and_then(|s| s.api_key.clone()));
        let script = self.scripts.lock().unwrap().get(&params.source).cloned();
        ctx.report(ProgressUpdate {
            message: Some(format!("{}: downloading", params.source)),
            ..Default::default()
        });
        match script {
            None => Err(WireError::new(ErrorCode::UnknownSource, "unknown source")),
            Some(Script::Fail(m)) => Err(WireError::new(ErrorCode::Internal, m)),
            Some(Script::Hang) => Ok(futures_util::stream::pending().boxed()),
            Some(Script::Batches(batches, status)) => {
                let n = batches.len() as u64;
                let last = batches.last().map_or(0, |b| b.seq);
                let ops: u64 = batches.iter().map(|b| b.ops.len() as u64).sum();
                let end: SyncEnd = serde_json::from_value(json!({
                    "entry": {"source": params.source, "status": status, "records": 1234, "seconds": 0.1,
                              "message": if status == "ok" { Value::Null } else { json!("half of it") }},
                    "batches": n, "last_seq": last, "ops": ops,
                }))
                .unwrap();
                let mut msgs: Vec<StepResult<StreamMsg<RowsBatch, SyncEnd>>> = batches
                    .into_iter()
                    .map(|b| Ok(StreamMsg::Item(b)))
                    .collect();
                msgs.push(Ok(StreamMsg::End(end)));
                Ok(futures_util::stream::iter(msgs).boxed())
            }
        }
    }

    async fn ack(&self, source: &str, through_seq: u64, _: CallCtx) -> StepResult<()> {
        self.acks
            .lock()
            .unwrap()
            .push((source.to_owned(), through_seq));
        Ok(())
    }

    async fn export(&self, source: &str, _: CallCtx) -> StepResult<ResultStream<RowsBatch, Value>> {
        let script = self.exports.lock().unwrap().get(source).cloned();
        let script = script.unwrap_or(Export::Batches(vec![], 0, GEN_A));
        let (batches, end) = match script {
            Export::Batches(b, hw, generation) => {
                let end = json!({"entry": {"source": source, "status": "ok", "records": 0, "seconds": 0.0,
                                           "message": null},
                                 "batches": b.len(), "last_seq": b.len(), "ops": 0, "high_water": hw,
                                 "generation": generation});
                (b, Ok(StreamMsg::End(end)))
            }
            Export::FailAfter(b) => (b, Err(WireError::new(ErrorCode::Internal, "OSError: disk"))),
        };
        let mut msgs: Vec<StepResult<StreamMsg<RowsBatch, Value>>> = batches
            .into_iter()
            .map(|b| Ok(StreamMsg::Item(b)))
            .collect();
        msgs.push(end);
        Ok(futures_util::stream::iter(msgs).boxed())
    }
}

/// One collector `fs`: an asset `host:<target>` with two components.
struct FakeProbe {
    calls: Mutex<Vec<String>>,
}

#[async_trait]
impl Collector for FakeProbe {
    fn collectors(&self) -> Vec<CollectorInfo> {
        vec![CollectorInfo {
            name: "fs".into(),
            description: "a directory tree".into(),
            platforms: None,
        }]
    }

    async fn expand_targets(
        &self,
        p: CollectParams,
        _: CallCtx,
    ) -> StepResult<Vec<Option<String>>> {
        match p.target.as_deref() {
            Some("none") => Ok(vec![]),
            Some(t) if t.contains(',') => Ok(t.split(',').map(|s| Some(s.to_owned())).collect()),
            t => Ok(vec![t.map(str::to_owned)]),
        }
    }

    async fn collect(
        &self,
        p: CollectParams,
        _: CallCtx,
    ) -> StepResult<ResultStream<CollectItem, CollectEnd>> {
        let t = p.target.clone().unwrap_or_default();
        if t == "broken" {
            return Err(WireError::new(
                ErrorCode::CollectError,
                "OSError: cannot read https://u:pw@h/x",
            ));
        }
        let asset = Asset {
            id: format!("host:{t}"),
            kind: "host".into(),
            name: t.clone(),
            os_name: None,
            os_version: None,
            platform: None,
            meta: Default::default(),
        };
        let comp = |n: &str| Component {
            name: n.into(),
            version: Some("1.0".into()),
            category: Category::Library,
            purl: Some(format!("pkg:pypi/{n}@1.0")),
            cpe: None,
            vendor: None,
            ecosystem: None,
            source_path: None,
            meta: Default::default(),
        };
        let items = vec![
            Ok(StreamMsg::Item(CollectItem::Asset {
                schema: "secmonk-inventory/2".into(),
                collector: "fs".into(),
                classified: false,
                asset,
            })),
            Ok(StreamMsg::Item(CollectItem::Components {
                components: vec![comp("a"), comp("b")],
            })),
            Ok(StreamMsg::Item(CollectItem::Warning {
                message: "skipped https://u:secret@x/y".into(),
            })),
            Ok(StreamMsg::End(CollectEnd {
                partial: false,
                partial_reason: None,
                components: 2,
                warnings: 1,
            })),
        ];
        Ok(futures_util::stream::iter(items).boxed())
    }
}

#[async_trait]
impl Probe for FakeProbe {
    fn methods(&self) -> Vec<String> {
        vec!["docker.contexts".into()]
    }

    async fn call(&self, method: &str, _: Value, _: CallCtx) -> StepResult<Value> {
        self.calls.lock().unwrap().push(method.to_owned());
        match method {
            "docker.contexts" => Ok(json!({"contexts": [], "current": null})),
            "docker.image_check" => Err(WireError::new(ErrorCode::CollectError, "no engine")),
            m => Err(WireError::new(ErrorCode::UnknownMethod, format!("no {m}"))),
        }
    }
}

// ------------------------------------------------------------------------------------------------ harness

struct Harness {
    _dir: tempfile::TempDir,
    store: Arc<SqliteStore>,
    steps: Arc<FakeSteps>,
    source: Arc<FakeSource>,
    engine: Arc<SecmonkEngine>,
}

async fn harness_with(
    scripts: &[(&str, Script)],
    tweak: impl FnOnce(&mut EngineConfig),
) -> Harness {
    harness_full(scripts, tweak, |_| Vec::new()).await
}

/// The harness with `extra(store)` sources ahead of the fake one (native sources over the harness's mirror).
async fn harness_full(
    scripts: &[(&str, Script)],
    tweak: impl FnOnce(&mut EngineConfig),
    extra: impl FnOnce(Arc<SqliteStore>) -> Vec<Arc<dyn Source>>,
) -> Harness {
    let dir = tempfile::tempdir().unwrap();
    let state_db = dir.path().join("db/state.sqlite3");
    let store = Arc::new(
        SqliteStore::open(
            &state_db,
            &dir.path().join("db/mirror.sqlite3"),
            &StoreOptions::default(),
        )
        .await
        .unwrap(),
    );
    let steps = Arc::new(FakeSteps {
        store: store.clone(),
        stale_once: AtomicBool::new(false),
        persisted_calls: AtomicU64::new(0),
    });
    let source = FakeSource::new(scripts);
    let mut config = EngineConfig::new("0.0.0-test", &state_db);
    config.nvd_api_key_env = Some("SECMONK_TEST_NVD_KEY_UNSET".into());
    tweak(&mut config);
    let engine = SecmonkEngine::new(EngineDeps {
        config,
        state: store.clone(),
        mirror: store.clone(),
        steps: steps.clone(),
        procmon: None,
        sources: {
            let mut v = extra(store.clone());
            v.push(source.clone());
            v
        },
        probe: Arc::new(FakeProbe {
            calls: Mutex::new(Vec::new()),
        }),
        modules: None,
    });
    Harness {
        _dir: dir,
        store,
        steps,
        source,
        engine,
    }
}

async fn harness(scripts: &[(&str, Script)]) -> Harness {
    harness_with(scripts, |_| {}).await
}

fn batch(source: &str, seq: u64, ops: Value) -> RowsBatch {
    serde_json::from_value(json!({"kind": "rows", "seq": seq, "source": source, "ops": ops}))
        .unwrap()
}

const GEN_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GEN_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

/// A batch bound to a staging generation (what py-sources streams since W4.4).
fn gbatch(source: &str, seq: u64, generation: &str, acked: u64, ops: Value) -> RowsBatch {
    serde_json::from_value(
        json!({"kind": "rows", "seq": seq, "source": source, "ops": ops,
                                  "generation": generation, "acked_through": acked}),
    )
    .unwrap()
}

/// A `source_sync` upsert: the observable row of these tests (`MirrorStore::sync_state`).
fn sync_row(source: &str, status: &str) -> Value {
    json!({"op": "upsert", "table": "source_sync", "row": {"source": source, "status": status}})
}

async fn status_of(store: &SqliteStore, source: &str) -> Option<String> {
    store
        .sync_state(source)
        .await
        .unwrap()
        .and_then(|s| s.status)
}

fn kev_row(cve: &str) -> Value {
    json!({"op": "upsert", "table": "kev", "row": {"cve_id": cve, "source": "kev"}})
}

fn body(v: Value) -> Map<String, Value> {
    v.as_object().cloned().unwrap()
}

/// Wait for a job to leave `running`; returns its full payload.
async fn wait_job(engine: &SecmonkEngine, id: u64) -> Value {
    for _ in 0..500 {
        let j = engine.job_get(id).await.unwrap();
        if j["status"] != "running" {
            return j;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("job {id} did not finish");
}

async fn run_job(engine: &SecmonkEngine, b: Value) -> Value {
    let started = engine.job_start(body(b)).await.unwrap();
    assert_eq!(started["status"], "running");
    wait_job(engine, started["id"].as_u64().unwrap()).await
}

fn log_of(job: &Value) -> Vec<String> {
    job["log"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_owned())
        .collect()
}

// ------------------------------------------------------------------------------------------------ sync

#[tokio::test]
async fn sync_applies_batches_then_acks() {
    let h = harness(&[
        (
            "kev",
            Script::Batches(
                vec![
                    batch("kev", 5, json!([kev_row("CVE-1")])),
                    batch("kev", 6, json!([kev_row("CVE-2")])),
                ],
                "ok",
            ),
        ),
        ("epss", Script::Batches(vec![], "partial")),
    ])
    .await;
    let job = run_job(&h.engine, json!({"kind": "sync", "sources": "all"})).await;
    assert_eq!(job["status"], "partial", "{job}");
    assert_eq!(job["title"], "sync kev, epss");
    let entries = job["result"]["sources"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["source"], "kev");
    assert_eq!(entries[0]["status"], "ok");
    assert_eq!(entries[0]["records"], 1234);
    assert!(entries[0]["seconds"].is_f64());
    assert_eq!(entries[1]["status"], "partial");
    assert_eq!(entries[1]["message"], "half of it");
    assert_eq!(h.store.applied_seq("kev").await.unwrap(), Some(6));
    assert_eq!(
        *h.source.acks.lock().unwrap(),
        vec![("kev".to_owned(), 6)],
        "acked once, after the stream"
    );
    assert!(MirrorStore::is_initialized(&*h.store).await.unwrap());
    let log = log_of(&job);
    assert!(log.iter().any(|l| l.ends_with("syncing kev…")), "{log:?}");
    assert!(
        log.iter().any(|l| l.ends_with("kev: downloading")),
        "progress reaches the log: {log:?}"
    );
    assert!(
        log.iter()
            .any(|l| l.contains("kev: ok — 1,234 records in ")),
        "{log:?}"
    );
    assert!(
        log.iter()
            .any(|l| l.contains("epss: partial — 1,234 records in ") && l.ends_with("half of it"))
    );
    // no key in the environment: no secret sent
    assert_eq!(*h.source.secrets_seen.lock().unwrap(), vec![None, None]);
    // the stored run equals what the live job showed
    let stored = h
        .store
        .job_row(job["id"].as_i64().unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        stored.result.as_ref().unwrap()["sources"],
        job["result"]["sources"]
    );
    assert_eq!(
        stored.summary.as_ref().unwrap()["sources"],
        2,
        "{:?}",
        stored.summary
    );
}

#[tokio::test]
async fn a_replayed_sync_is_skipped_and_acked_again() {
    let b = batch("kev", 3, json!([kev_row("CVE-1")]));
    let h = harness(&[("kev", Script::Batches(vec![b.clone()], "ok"))]).await;
    h.store.apply_rows(&b).await.unwrap(); // applied before a crash, never acknowledged
    let job = run_job(&h.engine, json!({"kind": "sync", "sources": ["kev"]})).await;
    assert_eq!(job["status"], "ok");
    assert!(
        log_of(&job)
            .iter()
            .any(|l| l.contains("1 replayed batch(es) were already applied"))
    );
    assert_eq!(*h.source.acks.lock().unwrap(), vec![("kev".to_owned(), 3)]);
}

#[tokio::test]
async fn one_failing_source_does_not_stop_the_others() {
    let h = harness(&[
        // a batch of another source's table: refused by the store; the batch before it is applied and acked
        (
            "kev",
            Script::Batches(
                vec![
                    batch("kev", 1, json!([kev_row("CVE-1")])),
                    batch("kev", 2, json!([{"op": "upsert", "table": "affected", "row":
                        {"source": "osv", "vuln_id": "X", "ecosystem": "npm", "package": "p", "events": []}}])),
                ],
                "ok",
            ),
        ),
        ("epss", Script::Fail("ConnectionError: https://user:pw@example.invalid/feed refused")),
        ("osv", Script::Batches(vec![batch("osv", 1, json!([]))], "ok")),
    ])
    .await;
    let job = run_job(
        &h.engine,
        json!({"kind": "sync", "sources": ["kev", "epss", "osv"]}),
    )
    .await;
    assert_eq!(job["status"], "error");
    assert_eq!(job["error"], Value::Null, "a sync's error is per source");
    let e = job["result"]["sources"].as_array().unwrap();
    assert_eq!(e[0]["status"], "error");
    assert_eq!(e[0]["records"], 0);
    assert_eq!(e[1]["status"], "error");
    let m = e[1]["message"].as_str().unwrap();
    assert!(
        m.starts_with("ConnectionError: ") && !m.contains("pw"),
        "scrubbed: {m}"
    );
    assert_eq!(e[2]["status"], "ok");
    assert_eq!(h.store.applied_seq("kev").await.unwrap(), Some(1));
    let acks = h.source.acks.lock().unwrap().clone();
    assert_eq!(acks, vec![("kev".to_owned(), 1), ("osv".to_owned(), 1)]);
}

#[tokio::test]
async fn a_short_stream_is_a_protocol_error() {
    let mut b = vec![batch("kev", 1, json!([kev_row("CVE-1")]))];
    b.push(batch("kev", 1, json!([kev_row("CVE-2")]))); // seq not increasing
    let h = harness(&[("kev", Script::Batches(b, "ok"))]).await;
    let job = run_job(&h.engine, json!({"kind": "sync", "sources": ["kev"]})).await;
    let e = &job["result"]["sources"][0];
    assert_eq!(e["status"], "error");
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .starts_with("ProtocolError: batch seq 1 after 1"),
        "{e}"
    );
}

#[tokio::test]
async fn the_api_key_is_a_call_secret() {
    let h = harness_with(&[("kev", Script::Batches(vec![], "ok"))], |c| {
        c.nvd_api_key_env = Some("HOME".into());
    })
    .await;
    let job = run_job(&h.engine, json!({"kind": "sync", "sources": ["kev"]})).await;
    assert_eq!(job["status"], "ok");
    assert_eq!(
        *h.source.secrets_seen.lock().unwrap(),
        vec![std::env::var("HOME").ok()]
    );
}

#[tokio::test]
async fn a_recreated_staging_is_repaired_not_skipped() {
    // review M1 (a): the staging file was recreated, its seqs restart at 1 under a new generation
    let h = harness(&[]).await;
    h.store
        .apply_rows(&gbatch(
            "kev",
            10,
            GEN_A,
            0,
            json!([
                sync_row("kev", "old"),
                sync_row("kev:qual", "old"),
                kev_row("CVE-1")
            ]),
        ))
        .await
        .unwrap();
    h.source.script(
        "kev",
        Script::Batches(
            vec![
                gbatch("kev", 1, GEN_B, 0, json!([kev_row("CVE-2")])),
                gbatch("kev", 2, GEN_B, 0, json!([sync_row("kev", "new")])),
            ],
            "ok",
        ),
    );
    h.source.export(
        "kev",
        Export::Batches(
            vec![gbatch(
                "kev",
                1,
                GEN_B,
                0,
                json!([sync_row("kev", "new"), kev_row("CVE-2")]),
            )],
            2,
            GEN_B,
        ),
    );
    let job = run_job(&h.engine, json!({"kind": "sync", "sources": ["kev"]})).await;
    assert_eq!(job["status"], "ok", "{job}");
    let log = log_of(&job);
    assert!(
        log.iter().any(|l| l.contains("2 batch(es) not applied")
            && l.contains("the staging database was recreated")),
        "{log:?}"
    );
    assert!(
        log.iter()
            .any(|l| l.contains("kev: mirror repaired from the staging export")),
        "{log:?}"
    );
    assert!(
        log.iter().any(|l| l.contains(
            "mirror: 0 replayed batch(es) skipped, 1 source(s) repaired from the staging export"
        )),
        "{log:?}"
    );
    let state = h.store.applied_state("kev").await.unwrap().unwrap();
    assert_eq!((state.seq, state.generation.as_deref()), (2, Some(GEN_B)));
    assert_eq!(status_of(&h.store, "kev").await.as_deref(), Some("new"));
    assert_eq!(
        status_of(&h.store, "kev:qual").await,
        None,
        "rows the export does not have are gone"
    );
    assert_eq!(
        *h.source.acks.lock().unwrap(),
        vec![("kev".to_owned(), 2)],
        "acknowledged through the high-water mark only"
    );

    // the next sync of the same generation applies normally
    h.source.script(
        "kev",
        Script::Batches(
            vec![gbatch(
                "kev",
                3,
                GEN_B,
                2,
                json!([sync_row("kev", "third")]),
            )],
            "ok",
        ),
    );
    let job = run_job(&h.engine, json!({"kind": "sync", "sources": ["kev"]})).await;
    assert_eq!(job["status"], "ok", "{job}");
    assert!(!log_of(&job).iter().any(|l| l.contains("repaired")));
    assert_eq!(status_of(&h.store, "kev").await.as_deref(), Some("third"));
    assert_eq!(h.store.applied_seq("kev").await.unwrap(), Some(3));
    assert_eq!(h.source.acks.lock().unwrap().last().unwrap().1, 3);
}

#[tokio::test]
async fn a_reset_mirror_is_rebuilt_from_the_export() {
    // review M1 (b): the mirror lost its rows; staging kept them and acknowledged them long ago
    let h = harness(&[]).await;
    // (1) a sync with changes: the batch says staging acknowledged through 5, the mirror has nothing
    h.source.script(
        "kev",
        Script::Batches(
            vec![gbatch("kev", 6, GEN_A, 5, json!([kev_row("CVE-6")]))],
            "ok",
        ),
    );
    h.source.export(
        "kev",
        Export::Batches(
            vec![gbatch(
                "kev",
                1,
                GEN_A,
                5,
                json!([sync_row("kev", "ok"), kev_row("CVE-6")]),
            )],
            6,
            GEN_A,
        ),
    );
    let job = run_job(&h.engine, json!({"kind": "sync", "sources": ["kev"]})).await;
    assert_eq!(job["status"], "ok", "{job}");
    assert!(
        log_of(&job).iter().any(|l| l
            .contains("the mirror has no applied state but staging acknowledged through seq 5")),
        "{job}"
    );
    assert_eq!(status_of(&h.store, "kev").await.as_deref(), Some("ok"));
    assert_eq!(h.store.applied_seq("kev").await.unwrap(), Some(6));
    // (2) a sync without any change on a mirror without state: the export decides
    h.source.script("epss", Script::Batches(vec![], "ok"));
    h.source.export(
        "epss",
        Export::Batches(
            vec![gbatch(
                "epss",
                1,
                GEN_A,
                4,
                json!([sync_row("epss", "kept")]),
            )],
            9,
            GEN_A,
        ),
    );
    let job = run_job(&h.engine, json!({"kind": "sync", "sources": ["epss"]})).await;
    assert_eq!(job["status"], "ok", "{job}");
    assert_eq!(status_of(&h.store, "epss").await.as_deref(), Some("kept"));
    let state = h.store.applied_state("epss").await.unwrap().unwrap();
    assert_eq!((state.seq, state.generation.as_deref()), (9, Some(GEN_A)));
    assert_eq!(
        *h.source.acks.lock().unwrap(),
        vec![("kev".to_owned(), 6), ("epss".to_owned(), 9)]
    );
}

#[tokio::test]
async fn a_failed_repair_changes_nothing_and_acknowledges_nothing() {
    let h = harness(&[]).await;
    h.store
        .apply_rows(&gbatch(
            "kev",
            10,
            GEN_A,
            0,
            json!([sync_row("kev", "before")]),
        ))
        .await
        .unwrap();
    h.source.script(
        "kev",
        Script::Batches(
            vec![gbatch("kev", 1, GEN_B, 0, json!([sync_row("kev", "x")]))],
            "ok",
        ),
    );
    h.source.export(
        "kev",
        Export::FailAfter(vec![gbatch(
            "kev",
            1,
            GEN_B,
            0,
            json!([sync_row("kev", "half")]),
        )]),
    );
    let job = run_job(&h.engine, json!({"kind": "sync", "sources": ["kev"]})).await;
    let e = &job["result"]["sources"][0];
    assert_eq!(e["status"], "error", "{job}");
    assert!(
        e["message"]
            .as_str()
            .unwrap()
            .starts_with("repair failed (the staging database"),
        "{e}"
    );
    assert_eq!(
        status_of(&h.store, "kev").await.as_deref(),
        Some("before"),
        "the delete and the half export were rolled back"
    );
    let state = h.store.applied_state("kev").await.unwrap().unwrap();
    assert_eq!((state.seq, state.generation.as_deref()), (10, Some(GEN_A)));
    assert!(h.source.acks.lock().unwrap().is_empty());
}

// ------------------------------------------------------------------------------------------------ jobs

#[tokio::test]
async fn one_job_at_a_time_and_shutdown_interrupts() {
    let h = harness(&[("kev", Script::Hang)]).await;
    let started = h
        .engine
        .job_start(body(json!({"kind": "sync", "sources": ["kev"]})))
        .await
        .unwrap();
    assert!(h.engine.busy());
    let e = h
        .engine
        .job_start(body(json!({"kind": "sync", "sources": ["kev"]})))
        .await
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Busy);
    assert_eq!(e.message, "another job is running");
    // writes wait for the job
    let e = h.engine.match_asset("host:x").await.unwrap_err();
    assert_eq!(
        (e.kind, e.message.as_str()),
        (ErrorKind::Busy, "a job is writing to the database")
    );
    // the list shows the live job
    let list = h
        .engine
        .jobs_list(&JobsQuery {
            kind: None,
            limit: 20,
        })
        .await
        .unwrap();
    assert_eq!(list[0]["id"], started["id"]);
    assert_eq!(list[0]["status"], "running");
    assert!(list[0].get("log").is_none(), "no log in the list");

    h.engine.shutdown().await;
    assert!(!h.engine.busy());
    let id = started["id"].as_u64().unwrap();
    let job = h.engine.job_get(id).await.unwrap();
    assert_eq!(job["status"], "error");
    assert_eq!(job["error"], "interrupted");
    let row = h.store.job_row(id as i64).await.unwrap().unwrap();
    assert_eq!(row.error.as_deref(), Some("interrupted"));
    assert!(h.engine.job_get(9999).await.is_err());
}

#[tokio::test]
async fn after_shutdown_jobs_and_writes_are_refused() {
    // review M3 (engine side): the host's gate answers "shutting down" once it stops, the engine too
    let h = harness(&[("kev", Script::Batches(vec![], "ok"))]).await;
    run_job(
        &h.engine,
        json!({"kind": "scan", "collector": "fs", "target": "box1"}),
    )
    .await;
    h.engine.shutdown().await;
    let stopping = |e: secmonk_engine::EngineError| {
        assert_eq!(
            (e.kind, e.message.as_str()),
            (ErrorKind::ModuleUnavailable, "sec-monk is shutting down")
        );
    };
    stopping(
        h.engine
            .job_start(body(json!({"kind": "sync", "sources": ["kev"]})))
            .await
            .unwrap_err(),
    );
    stopping(h.engine.match_asset("host:box1").await.unwrap_err());
    stopping(h.engine.processes_save().await.unwrap_err());
    assert!(!h.engine.busy());
    assert_eq!(
        h.store.job_rows(None, 10).await.unwrap().len(),
        1,
        "no new run"
    );
    // reads still answer while the app closes
    assert!(h.engine.collectors().await.is_ok());
}

/// The state store with a gate in `job_insert`: the test sees the insert begin and decides when it ends.
struct GatedState {
    store: Arc<SqliteStore>,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait]
impl StateStore for GatedState {
    async fn save_inventory(
        &self,
        inv: &secmonk_model::Inventory,
        job_id: Option<i64>,
    ) -> secmonk_store::StoreResult<i64> {
        self.store.save_inventory(inv, job_id).await
    }
    async fn asset_exists(&self, a: &str) -> secmonk_store::StoreResult<bool> {
        self.store.asset_exists(a).await
    }
    async fn asset_reuse_facts(
        &self,
        a: &str,
    ) -> secmonk_store::StoreResult<Option<secmonk_store::AssetReuseFacts>> {
        self.store.asset_reuse_facts(a).await
    }
    async fn update_asset_meta(
        &self,
        a: &str,
        meta: &Map<String, Value>,
    ) -> secmonk_store::StoreResult<()> {
        self.store.update_asset_meta(a, meta).await
    }
    async fn update_asset_reused(
        &self,
        a: &str,
        name: Option<&str>,
        meta: &Map<String, Value>,
    ) -> secmonk_store::StoreResult<()> {
        self.store.update_asset_reused(a, name, meta).await
    }
    async fn latest_scan_id(&self, a: &str) -> secmonk_store::StoreResult<Option<i64>> {
        self.store.latest_scan_id(a).await
    }
    async fn replace_findings(
        &self,
        a: &str,
        set: &[secmonk_model::Finding],
        based_on: &secmonk_model::BasedOn,
    ) -> secmonk_store::StoreResult<u64> {
        self.store.replace_findings(a, set, based_on).await
    }
    async fn job_insert(&self, job: &secmonk_model::NewJob) -> secmonk_store::StoreResult<i64> {
        self.entered.notify_one();
        self.release.notified().await;
        self.store.job_insert(job).await
    }
    async fn job_finish(
        &self,
        id: i64,
        fin: &secmonk_model::JobFinish,
    ) -> secmonk_store::StoreResult<()> {
        self.store.job_finish(id, fin).await
    }
    async fn job_rows(
        &self,
        kind: Option<secmonk_model::JobKind>,
        limit: i64,
    ) -> secmonk_store::StoreResult<Vec<secmonk_model::JobRow>> {
        self.store.job_rows(kind, limit).await
    }
    async fn job_row(&self, id: i64) -> secmonk_store::StoreResult<Option<secmonk_model::JobRow>> {
        self.store.job_row(id).await
    }
    async fn job_mark_interrupted(&self) -> secmonk_store::StoreResult<u64> {
        self.store.job_mark_interrupted().await
    }
    async fn is_initialized(&self) -> secmonk_store::StoreResult<bool> {
        StateStore::is_initialized(&*self.store).await
    }
}

async fn gated_engine() -> (Harness, Arc<GatedState>) {
    let h = harness(&[("kev", Script::Hang)]).await;
    let gated = Arc::new(GatedState {
        store: h.store.clone(),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    let mut config = EngineConfig::new("0.0.0-test", h.store.state_path());
    config.nvd_api_key_env = None;
    let engine = SecmonkEngine::new(EngineDeps {
        config,
        state: gated.clone(),
        mirror: h.store.clone(),
        steps: h.steps.clone(),
        procmon: None,
        sources: vec![h.source.clone()],
        probe: Arc::new(FakeProbe {
            calls: Mutex::new(Vec::new()),
        }),
        modules: None,
    });
    (Harness { engine, ..h }, gated)
}

#[tokio::test]
async fn a_dropped_job_start_does_not_leave_the_engine_busy() {
    // review L7: the request future is dropped while the job row is being inserted
    let (h, gated) = gated_engine().await;
    let engine = h.engine.clone();
    let start = tokio::spawn(async move {
        engine
            .job_start(body(json!({"kind": "sync", "sources": ["kev"]})))
            .await
    });
    gated.entered.notified().await;
    assert!(h.engine.busy(), "starting");
    start.abort();
    assert!(start.await.unwrap_err().is_cancelled());
    assert!(!h.engine.busy(), "the guard reset `starting`");
    // the engine accepts the next job
    gated.release.notify_one();
    let started = h
        .engine
        .job_start(body(json!({"kind": "sync", "sources": ["kev"]})))
        .await
        .unwrap();
    assert_eq!(started["status"], "running");
    h.engine.shutdown().await;
}

#[tokio::test]
async fn a_shutdown_during_a_job_start_closes_the_new_run() {
    let (h, gated) = gated_engine().await;
    let engine = h.engine.clone();
    let start = tokio::spawn(async move {
        engine
            .job_start(body(json!({"kind": "sync", "sources": ["kev"]})))
            .await
    });
    gated.entered.notified().await;
    h.engine.shutdown().await;
    gated.release.notify_one();
    let e = start.await.unwrap().unwrap_err();
    assert_eq!(
        (e.kind, e.message.as_str()),
        (ErrorKind::ModuleUnavailable, "sec-monk is shutting down")
    );
    assert!(!h.engine.busy());
    let rows = h.store.job_rows(None, 10).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status, Some(secmonk_model::JobStatus::Error));
    assert_eq!(rows[0].error.as_deref(), Some("interrupted"));
}

#[tokio::test]
async fn actions_can_be_disabled() {
    let h = harness_with(&[], |c| c.allow_actions = false).await;
    let e = h
        .engine
        .job_start(body(json!({"kind": "sync", "sources": ["kev"]})))
        .await
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::InvalidParams);
    assert_eq!(e.message, "actions are disabled on this server");
    assert!(h.engine.docker_contexts().await.is_err());
    // reads still answer
    assert!(h.engine.collectors().await.is_ok());
}

#[tokio::test]
async fn invalid_bodies_are_refused_before_any_row() {
    let h = harness(&[]).await;
    let e = h
        .engine
        .job_start(body(json!({"kind": "sync", "sources": ["bogus"]})))
        .await
        .unwrap_err();
    assert_eq!(e.message, "unknown source bogus (known: epss, kev, osv)");
    let e = h
        .engine
        .job_start(body(
            json!({"kind": "scan", "collector": "fs", "target": "/x", "save": false}),
        ))
        .await
        .unwrap_err();
    assert_eq!(e.kind, ErrorKind::Busy);
    assert!(e.message.starts_with("no database at "), "{}", e.message);
    assert!(h.store.job_rows(None, 10).await.unwrap().is_empty());
}

// ------------------------------------------------------------------------------------------------ scans

#[tokio::test]
async fn a_saved_scan_stores_the_inventory_and_its_findings() {
    let h = harness(&[]).await;
    let job = run_job(
        &h.engine,
        json!({"kind": "scan", "collector": "fs", "target": "box1", "options": "token=s3cret"}),
    )
    .await;
    assert_eq!(job["status"], "ok", "{job}");
    assert_eq!(
        job["params"]["options"],
        json!(["token=***"]),
        "redacted params"
    );
    let t = &job["result"]["targets"][0];
    assert_eq!(t["asset"], "host:box1");
    assert!(t["scan_id"].is_i64());
    assert_eq!(t["counts"]["P2"], 1);
    assert_eq!(t["findings"].as_array().unwrap().len(), 1);
    assert_eq!(
        t["warnings"],
        json!(["skipped https://u@x/y"]),
        "warnings scrubbed: {t}"
    );
    assert_eq!(job["result"]["saved"], true);
    assert!(h.store.asset_exists("host:box1").await.unwrap());
    assert_eq!(
        h.store.latest_scan_id("host:box1").await.unwrap(),
        t["scan_id"].as_i64()
    );
    let log = log_of(&job);
    assert!(
        log.iter().any(|l| l.ends_with("host:box1: 2 components")),
        "{log:?}"
    );

    // re-match: a stale based_on is retried once
    h.steps.stale_once.store(true, Ordering::SeqCst);
    let before = h.steps.persisted_calls.load(Ordering::SeqCst);
    let r = h.engine.match_asset("host:box1").await.unwrap();
    assert_eq!(r["asset"], "host:box1");
    assert_eq!(r["stats"]["findings"], 1);
    assert_eq!(h.steps.persisted_calls.load(Ordering::SeqCst) - before, 2);
    let e = h.engine.match_asset("host:nope").await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::UnknownAsset);
}

#[tokio::test]
async fn scan_without_saving_and_failing_targets() {
    let h = harness(&[]).await;
    run_job(
        &h.engine,
        json!({"kind": "scan", "collector": "fs", "target": "seed"}),
    )
    .await;
    let job = run_job(
        &h.engine,
        json!({"kind": "scan", "collector": "fs", "target": "a,broken", "save": false}),
    )
    .await;
    assert_eq!(job["status"], "partial", "{job}");
    let ts = job["result"]["targets"].as_array().unwrap();
    assert_eq!(ts[0]["scan_id"], Value::Null);
    assert_eq!(
        ts[0]["stats"]["components"], 2,
        "ephemeral match on the classified inventory"
    );
    let err = ts[1]["error"].as_str().unwrap();
    assert!(
        err.starts_with("OSError: cannot read") && !err.contains("pw"),
        "{err}"
    );
    assert!(
        !h.store.asset_exists("host:a").await.unwrap(),
        "nothing saved"
    );
    // a single collector whose target matches nothing fails as a whole
    let job = run_job(
        &h.engine,
        json!({"kind": "scan", "collector": "fs", "target": "none"}),
    )
    .await;
    assert_eq!(job["status"], "error");
    assert_eq!(job["error"], "ValueError: no fs target matches 'none'");
}

#[tokio::test]
async fn reads_need_a_database_and_procs_need_a_monitor() {
    let h = harness(&[]).await;
    let e = h.engine.overview().await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::NoDb);
    let e = h.engine.processes(false).await.unwrap_err();
    assert_eq!(e.kind, ErrorKind::UnsupportedPlatform);
    let s = h.engine.sources().await.unwrap();
    assert_eq!(s["status"], Value::Null);
    assert_eq!(s["db"]["exists"], false);
    assert_eq!(s["sync_all_order"], json!(["kev", "epss", "osv"]));
    let m = h.engine.meta().await.unwrap();
    assert_eq!(m["engine"]["runtime"], "rust");
    assert_eq!(m["db"]["exists"], false);
}

// ------------------------------------------------------------------------------------------------ contracts

fn rust_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

/// Validate `{schema ref: [values]}` with `rust/python/tests/contracts.py` in the dev venv. `None` = no venv.
fn check_contracts(cases: &[(&str, Value)]) -> Option<()> {
    let root = rust_root();
    let py = root.join("python/.venv/bin/python");
    if !py.exists() {
        eprintln!("rust/python/.venv missing: contract checks skipped");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("cases.json");
    let cases: Vec<Value> = cases.iter().map(|(r, v)| json!([r, v])).collect();
    std::fs::write(&data, serde_json::to_vec(&cases).unwrap()).unwrap();
    let script = "import json, sys\n\
                  sys.path.insert(0, sys.argv[1])\n\
                  from tests.contracts import errors\n\
                  bad = []\n\
                  for ref, value in json.load(open(sys.argv[2])):\n\
                  \x20   bad += [f'{ref}: {e}' for e in errors(ref, value)]\n\
                  print('\\n'.join(bad))\n\
                  sys.exit(1 if bad else 0)\n";
    let out = std::process::Command::new(&py)
        .arg("-I")
        .arg("-c")
        .arg(script)
        .arg(root.join("python"))
        .arg(&data)
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "payloads do not satisfy the contracts:\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Some(())
}

#[tokio::test]
async fn payloads_follow_the_contracts() {
    let h = harness(&[(
        "kev",
        Script::Batches(vec![batch("kev", 1, json!([kev_row("CVE-1")]))], "ok"),
    )])
    .await;
    let mut cases: Vec<(&str, Value)> = vec![
        ("api/sources.schema.json", h.engine.sources().await.unwrap()),
        (
            "api/collectors.schema.json",
            h.engine.collectors().await.unwrap(),
        ),
    ];
    let started = h
        .engine
        .job_start(body(json!({"kind": "sync", "sources": ["kev"]})))
        .await
        .unwrap();
    cases.push(("api/job.schema.json", started.clone()));
    cases.push((
        "api/job.schema.json",
        wait_job(&h.engine, started["id"].as_u64().unwrap()).await,
    ));
    let scan = run_job(
        &h.engine,
        json!({"kind": "scan", "collector": "fs", "target": "b,broken"}),
    )
    .await;
    cases.push(("api/job.schema.json", scan));
    cases.push((
        "api/job-list.schema.json",
        h.engine
            .jobs_list(&JobsQuery {
                kind: None,
                limit: 20,
            })
            .await
            .unwrap(),
    ));
    cases.push((
        "api/match-result.schema.json",
        h.engine.match_asset("host:b").await.unwrap(),
    ));
    // the meta the router completes with the transport facts
    let mut meta = h.engine.meta().await.unwrap();
    meta["bind"] = json!("127.0.0.1:0");
    meta["actions"] = json!(true);
    cases.push(("api/meta.schema.json", meta));
    check_contracts(&cases);
}

// ------------------------------------------------------------------------------------------------ native kev (ADR-0011)

fn kev_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/fixtures/sources/kev/known_exploited_vulnerabilities.json")
}

/// The fixture with `keep` of its entries (in order) and another catalog version, written to `dir`.
fn kev_variant(dir: &Path, name: &str, keep: usize, version: &str) -> PathBuf {
    let mut doc: Value = serde_json::from_slice(&std::fs::read(kev_fixture()).unwrap()).unwrap();
    let v = doc["vulnerabilities"].as_array_mut().unwrap();
    v.truncate(keep);
    doc["count"] = json!(keep);
    doc["catalogVersion"] = json!(version);
    let p = dir.join(name);
    std::fs::write(&p, serde_json::to_vec(&doc).unwrap()).unwrap();
    p
}

fn native_kev(
    limits: Option<secmonk_sources::batch::Limits>,
) -> impl FnOnce(Arc<SqliteStore>) -> Vec<Arc<dyn Source>> {
    move |store| {
        let view = Arc::new(secmonk_engine::StoreMirrorView::new(store));
        let mut kev = secmonk_sources::kev::KevSource::new(view);
        if let Some(l) = limits {
            kev = kev.with_limits(l);
        }
        vec![Arc::new(kev) as Arc<dyn Source>]
    }
}

async fn kev_keys(store: &SqliteStore) -> Vec<String> {
    store
        .row_keys(secmonk_model::MirrorTable::Kev, "kev")
        .await
        .unwrap()
        .into_iter()
        .map(|k| k["cve_id"].as_str().unwrap().to_owned())
        .collect()
}

async fn sync_kev(h: &Harness, path: &Path, extra: Value) -> Value {
    let mut b = json!({"kind": "sync", "sources": ["kev"], "path": path.display().to_string()});
    for (k, v) in extra.as_object().unwrap() {
        b[k] = v.clone();
    }
    run_job(&h.engine, b).await
}

#[tokio::test]
async fn native_kev_syncs_through_the_engine_without_ack_or_export() {
    let h = harness_full(&[], |_| {}, native_kev(None)).await;
    let fixture = kev_fixture();
    let job = sync_kev(&h, &fixture, json!({})).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    let entry = &job["result"]["sources"][0];
    assert_eq!(entry["records"], 9, "{entry}");
    assert_eq!(kev_keys(&h.store).await.len(), 9);
    let mirror: &dyn MirrorStore = &*h.store;
    assert_eq!(
        mirror
            .count_rows(secmonk_model::MirrorTable::RawRecord, "kev")
            .await
            .unwrap(),
        9
    );
    let st = h.store.applied_state("kev").await.unwrap().unwrap();
    assert_eq!(
        (st.seq, st.generation.as_deref()),
        (1, Some(secmonk_traits::NATIVE_GENERATION))
    );
    let sync = h.store.sync_state("kev").await.unwrap().unwrap();
    assert_eq!(sync.cursor.as_deref(), Some("2026.11.06"));
    assert_eq!(sync.records, Some(9));
    assert!(
        h.source.acks.lock().unwrap().is_empty(),
        "the fake py-sources is never asked"
    );

    // the same feed again: the seqs continue, nothing changes
    let job = sync_kev(&h, &fixture, json!({})).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    assert_eq!(h.store.applied_seq("kev").await.unwrap(), Some(2));
    assert_eq!(kev_keys(&h.store).await.len(), 9);

    // an update: 6 of 9 entries remain; the 3 others are deleted (their raw records stay, as in Python)
    let d = tempfile::tempdir().unwrap();
    let six = kev_variant(d.path(), "six.json", 6, "2026.11.10");
    let job = sync_kev(&h, &six, json!({})).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    assert_eq!(kev_keys(&h.store).await.len(), 6);
    assert_eq!(
        mirror
            .count_rows(secmonk_model::MirrorTable::RawRecord, "kev")
            .await
            .unwrap(),
        9
    );
    let sync = h.store.sync_state("kev").await.unwrap().unwrap();
    assert_eq!(sync.cursor.as_deref(), Some("2026.11.10"));

    // under half of the stored rows: refused, the rows and the last good totals stay
    let two = kev_variant(d.path(), "two.json", 2, "2026.11.11");
    let job = sync_kev(&h, &two, json!({})).await;
    assert_eq!(job["status"], "error", "{job:#}");
    assert_eq!(kev_keys(&h.store).await.len(), 6);
    let sync = h.store.sync_state("kev").await.unwrap().unwrap();
    assert_eq!(sync.status.as_deref(), Some("error"));
    assert_eq!(
        (sync.records, sync.cursor.as_deref()),
        (Some(6), Some("2026.11.10"))
    );
    // forced
    let job = sync_kev(&h, &two, json!({"full": true})).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    assert_eq!(kev_keys(&h.store).await.len(), 2);
}

#[tokio::test]
async fn native_kev_resets_a_staging_applied_state_and_converges_after_a_partial_stream() {
    // the mirror holds what py-sources applied: a staging generation, a row that is not in the feed
    let h = harness_full(
        &[],
        |_| {},
        native_kev(Some(secmonk_sources::batch::Limits {
            ops: 4,
            bytes: 1 << 20,
        })),
    )
    .await;
    let stale = gbatch(
        "kev",
        5,
        GEN_A,
        0,
        json!([kev_row("CVE-2000-0001"), sync_row("kev", "ok")]),
    );
    assert!(!h.store.apply_rows(&stale).await.unwrap().needs_repair);
    let job = sync_kev(&h, &kev_fixture(), json!({})).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    assert!(
        log_of(&job)
            .iter()
            .any(|l| l.ends_with(&format!(
                "kev: native importer: applied state of generation {GEN_A} (seq 5) reset; full sync against the mirror"
            ))),
        "{job:#}"
    );
    let keys = kev_keys(&h.store).await;
    assert_eq!(keys.len(), 9);
    assert!(!keys.contains(&"CVE-2000-0001".to_owned()));
    let st = h.store.applied_state("kev").await.unwrap().unwrap();
    assert_eq!(
        st.generation.as_deref(),
        Some(secmonk_traits::NATIVE_GENERATION)
    );
    assert_eq!(st.seq, 5, "19 ops in batches of 4");

    // a host that stopped mid-stream: two batches of an update applied, the rest lost (no ack, no log to replay)
    let d = tempfile::tempdir().unwrap();
    let six = kev_variant(d.path(), "six.json", 6, "2026.11.10");
    let src = native_kev(Some(secmonk_sources::batch::Limits {
        ops: 4,
        bytes: 1 << 20,
    }))(h.store.clone())
    .remove(0);
    let params: SyncParams = serde_json::from_value(
        json!({"source": "kev", "options": {"path": six.display().to_string()}}),
    )
    .unwrap();
    let mut stream = src.sync(params, CallCtx::default()).await.unwrap();
    for _ in 0..2 {
        let StreamMsg::Item(b) = stream.next().await.unwrap().unwrap() else {
            panic!("a batch expected");
        };
        assert!(!h.store.apply_rows(&b).await.unwrap().skipped);
    }
    drop(stream);
    assert_eq!(kev_keys(&h.store).await.len(), 6, "the deletes came first");
    assert_ne!(
        h.store
            .sync_state("kev")
            .await
            .unwrap()
            .unwrap()
            .cursor
            .as_deref(),
        Some("2026.11.10"),
        "the status row comes last"
    );
    // the next sync is the repair: computed against the mirror as it is
    let job = sync_kev(&h, &six, json!({})).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    assert_eq!(kev_keys(&h.store).await.len(), 6);
    let sync = h.store.sync_state("kev").await.unwrap().unwrap();
    assert_eq!(
        (sync.records, sync.cursor.as_deref()),
        (Some(6), Some("2026.11.10"))
    );
    assert!(h.source.acks.lock().unwrap().is_empty());
}

/// A view that forgets the applied state: the source numbers from 1 again, as if another writer had advanced the
/// applied state between its read and the apply.
struct ForgetfulView(secmonk_engine::StoreMirrorView);

#[async_trait]
impl secmonk_traits::MirrorView for ForgetfulView {
    async fn applied(&self, _: &str) -> StepResult<Option<secmonk_traits::AppliedMark>> {
        Ok(None)
    }
    async fn count_rows(&self, t: secmonk_model::MirrorTable, s: &str) -> StepResult<u64> {
        self.0.count_rows(t, s).await
    }
    async fn row_keys(
        &self,
        t: secmonk_model::MirrorTable,
        s: &str,
    ) -> StepResult<Vec<Map<String, Value>>> {
        self.0.row_keys(t, s).await
    }
    async fn rows_by_id(
        &self,
        t: secmonk_model::MirrorTable,
        s: &str,
        ids: &[String],
    ) -> StepResult<Vec<Map<String, Value>>> {
        self.0.rows_by_id(t, s, ids).await
    }
    async fn rows_page(
        &self,
        t: secmonk_model::MirrorTable,
        s: &str,
        after: Option<u64>,
        limit: usize,
    ) -> StepResult<secmonk_traits::RowPage> {
        self.0.rows_page(t, s, after, limit).await
    }
}

#[tokio::test]
async fn a_native_batch_the_store_skips_is_an_error() {
    let h = harness_full(
        &[],
        |_| {},
        |store| {
            let view = ForgetfulView(secmonk_engine::StoreMirrorView::new(store));
            vec![Arc::new(secmonk_sources::kev::KevSource::new(Arc::new(view))) as Arc<dyn Source>]
        },
    )
    .await;
    let job = sync_kev(&h, &kev_fixture(), json!({})).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    // the second run streams seq 1 again: the store skips it, the engine must not report success
    let job = sync_kev(&h, &kev_fixture(), json!({})).await;
    let entry = &job["result"]["sources"][0];
    assert_eq!(entry["status"], "error", "{job:#}");
    assert!(
        entry["message"]
            .as_str()
            .unwrap()
            .contains("batch(es) skipped by the mirror store"),
        "{entry}"
    );
}

/// Another engine over the harness's store and steps with only the fake (staging-style) source: the same mirror
/// switched back to `py-sources`.
fn python_engine(h: &Harness) -> Arc<SecmonkEngine> {
    let mut config = EngineConfig::new("0.0.0-test", h.store.state_path());
    config.nvd_api_key_env = Some("SECMONK_TEST_NVD_KEY_UNSET".into());
    SecmonkEngine::new(EngineDeps {
        config,
        state: h.store.clone(),
        mirror: h.store.clone(),
        steps: h.steps.clone(),
        procmon: None,
        sources: vec![h.source.clone()],
        probe: Arc::new(FakeProbe {
            calls: Mutex::new(Vec::new()),
        }),
        modules: None,
    })
}

#[tokio::test]
async fn a_failed_or_limited_python_run_after_native_syncs_never_rolls_the_mirror_back() {
    // review W6.5 M1: staging is stale after a native era; only an ok run may repair from its export
    let h = harness_full(&[], |_| {}, native_kev(None)).await;
    let job = sync_kev(&h, &kev_fixture(), json!({})).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    let py = python_engine(&h);
    // the stale staging export: one old row
    h.source.export(
        "kev",
        Export::Batches(
            vec![gbatch(
                "kev",
                1,
                GEN_A,
                3,
                json!([kev_row("CVE-2000-0001"), sync_row("kev", "ok")]),
            )],
            7,
            GEN_A,
        ),
    );
    for status in ["error", "partial"] {
        // what py-sources streams after a failed / limited run: its staging generation, at least the status row
        h.source.script(
            "kev",
            Script::Batches(
                vec![gbatch("kev", 7, GEN_A, 3, json!([sync_row("kev", status)]))],
                status,
            ),
        );
        let job = run_job(&py, json!({"kind": "sync", "sources": ["kev"]})).await;
        let entry = &job["result"]["sources"][0];
        assert_eq!(entry["status"], "error", "{status}: {job:#}");
        assert_eq!(entry["records"], 0, "{status}");
        let msg = entry["message"].as_str().unwrap();
        assert!(
            msg == format!(
                "{status}: half of it; not applied: mirror keeps the native importer data until a successful \
                 py-sources sync"
            ),
            "{msg}"
        );
        assert!(
            !log_of(&job).iter().any(|l| l.contains("repaired")),
            "{job:#}"
        );
        assert_eq!(
            kev_keys(&h.store).await.len(),
            9,
            "{status}: the mirror is unchanged"
        );
        assert_eq!(status_of(&h.store, "kev").await.as_deref(), Some("ok"));
        let st = h.store.applied_state("kev").await.unwrap().unwrap();
        assert_eq!(
            (st.seq, st.generation.as_deref()),
            (1, Some(secmonk_traits::NATIVE_GENERATION)),
            "{status}: the native applied state stays"
        );
        assert!(
            h.source.acks.lock().unwrap().is_empty(),
            "nothing acknowledged"
        );
    }
    // an ok run repairs the source from the staging export
    h.source.script(
        "kev",
        Script::Batches(
            vec![gbatch("kev", 7, GEN_A, 3, json!([sync_row("kev", "ok")]))],
            "ok",
        ),
    );
    let job = run_job(&py, json!({"kind": "sync", "sources": ["kev"]})).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    assert!(
        log_of(&job)
            .iter()
            .any(|l| l.ends_with(
                "kev: repair from py-sources export: the last applied batches came from the native importer"
            )),
        "{job:#}"
    );
    assert_eq!(kev_keys(&h.store).await, vec!["CVE-2000-0001".to_owned()]);
    let st = h.store.applied_state("kev").await.unwrap().unwrap();
    assert_eq!((st.seq, st.generation.as_deref()), (7, Some(GEN_A)));
    py.shutdown().await;
}

#[tokio::test]
async fn native_kev_batches_follow_the_row_contract() {
    // review W6.5 L2: every native batch and end validates against rust/contracts (source/rows, source/sync-end)
    let h = harness(&[]).await;
    let src = native_kev(Some(secmonk_sources::batch::Limits {
        ops: 7,
        bytes: 1 << 20,
    }))(h.store.clone())
    .remove(0);
    let d = tempfile::tempdir().unwrap();
    let six = kev_variant(d.path(), "six.json", 6, "2026.11.10");
    let bad = d.path().join("bad.json");
    std::fs::write(&bad, r#"{"vulnerabilities": [{"product": "x"}]}"#).unwrap();
    let mut cases: Vec<(&str, Value)> = Vec::new();
    for (path, options) in [
        (kev_fixture(), json!({})),
        (six.clone(), json!({})),             // deletes
        (kev_fixture(), json!({"limit": 3})), // partial
        (bad.clone(), json!({})),             // error: only the status row
    ] {
        let mut o = options;
        o["path"] = json!(path.display().to_string());
        let params: SyncParams =
            serde_json::from_value(json!({"source": "kev", "options": o})).unwrap();
        let mut stream = src.sync(params, CallCtx::default()).await.unwrap();
        while let Some(m) = stream.next().await {
            match m.unwrap() {
                StreamMsg::Item(b) => {
                    assert!(!h.store.apply_rows(&b).await.unwrap().skipped);
                    cases.push(("source/rows.schema.json", serde_json::to_value(&b).unwrap()));
                }
                StreamMsg::End(e) => cases.push((
                    "source/sync-end.schema.json",
                    serde_json::to_value(&e).unwrap(),
                )),
            }
        }
    }
    let deletes = cases
        .iter()
        .filter(|(_, v)| v.to_string().contains(r#""op":"delete""#))
        .count();
    assert!(deletes > 0, "a delete batch is among the cases");
    assert!(cases.len() >= 8);
    check_contracts(&cases);
}

fn epss_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/fixtures/sources/epss/epss_scores-sample.csv")
}

fn native_epss(
    limits: Option<secmonk_sources::batch::Limits>,
) -> impl FnOnce(Arc<SqliteStore>) -> Vec<Arc<dyn Source>> {
    move |store| {
        let view = Arc::new(secmonk_engine::StoreMirrorView::new(store));
        let mut epss = secmonk_sources::epss::EpssSource::new(view);
        if let Some(l) = limits {
            epss = epss.with_limits(l);
        }
        vec![Arc::new(epss) as Arc<dyn Source>]
    }
}

async fn epss_keys(store: &SqliteStore, source: &str) -> Vec<String> {
    store
        .row_keys(secmonk_model::MirrorTable::Epss, source)
        .await
        .unwrap()
        .into_iter()
        .map(|k| k["cve_id"].as_str().unwrap().to_owned())
        .collect()
}

/// `epss` upserts of the EUVD source (`source = 'euvd'`, no percentile), as `py-sources` streams them.
fn euvd_epss(seq: u64, cves: &[(&str, f64)]) -> RowsBatch {
    let ops: Vec<Value> = cves
        .iter()
        .map(|(c, s)| {
            json!({"op": "upsert", "table": "epss",
                   "row": {"cve_id": c, "score": s, "percentile": null, "date": "2026-10-01", "source": "euvd"}})
        })
        .collect();
    batch("euvd", seq, Value::Array(ops))
}

#[tokio::test]
async fn native_epss_replaces_euvd_rows_of_its_cves_and_keeps_the_others() {
    // ownership of the sourceless epss key: a FIRST row replaces a EUVD row of the same CVE, EUVD never replaces a
    // FIRST row, and a CVE the FIRST file lacks keeps its EUVD row (src/secmonk/sources/{epss,euvd}.py)
    let h = harness_full(&[], |_| {}, native_epss(None)).await;
    h.store
        .apply_rows(&euvd_epss(
            1,
            &[("CVE-2021-44228", 0.5), ("CVE-2099-0001", 0.25)],
        ))
        .await
        .unwrap();
    let path = epss_fixture();
    let job = run_job(
        &h.engine,
        json!({"kind": "sync", "sources": ["epss"], "path": path.display().to_string()}),
    )
    .await;
    assert_eq!(job["status"], "ok", "{job:#}");
    assert_eq!(job["result"]["sources"][0]["records"], 10);
    let first = epss_keys(&h.store, "epss").await;
    assert_eq!(first.len(), 10);
    assert!(first.contains(&"CVE-2021-44228".to_owned()));
    assert_eq!(epss_keys(&h.store, "euvd").await, vec!["CVE-2099-0001"]);
    // a later EUVD score of a FIRST CVE changes nothing; of its own CVE it is applied
    h.store
        .apply_rows(&euvd_epss(
            2,
            &[("CVE-2021-44228", 0.1), ("CVE-2099-0001", 0.3)],
        ))
        .await
        .unwrap();
    assert_eq!(epss_keys(&h.store, "epss").await.len(), 10);
    assert_eq!(epss_keys(&h.store, "euvd").await, vec!["CVE-2099-0001"]);
    // a smaller FIRST file deletes nothing (the Python source only upserts)
    let d = tempfile::tempdir().unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    let six: String = text.lines().take(9).map(|l| format!("{l}\n")).collect();
    let p = d.path().join("six.csv");
    std::fs::write(&p, six).unwrap();
    let job = run_job(
        &h.engine,
        json!({"kind": "sync", "sources": ["epss"], "path": p.display().to_string()}),
    )
    .await;
    assert_eq!(job["result"]["sources"][0]["records"], 6, "{job:#}");
    assert_eq!(epss_keys(&h.store, "epss").await.len(), 10);
    assert_eq!(epss_keys(&h.store, "euvd").await, vec!["CVE-2099-0001"]);
    let st = h.store.applied_state("epss").await.unwrap().unwrap();
    assert_eq!(
        st.generation.as_deref(),
        Some(secmonk_traits::NATIVE_GENERATION)
    );
}

#[tokio::test]
async fn native_epss_batches_follow_the_row_contract() {
    // every native epss batch and end validates against rust/contracts (source/rows, source/sync-end)
    let h = harness(&[]).await;
    let src = native_epss(Some(secmonk_sources::batch::Limits {
        ops: 4,
        bytes: 1 << 20,
    }))(h.store.clone())
    .remove(0);
    let d = tempfile::tempdir().unwrap();
    let missing = d.path().join("missing.csv");
    let odd = d.path().join("odd.csv");
    std::fs::write(
        &odd,
        "CVE-0000-0001,0.1,0.2\n#score_date:2026-01-03\n,0.5,0.5\nCVE-0000-0002,1e-5,1\n",
    )
    .unwrap();
    let mut cases: Vec<(&str, Value)> = Vec::new();
    for (path, options) in [
        (epss_fixture(), json!({})),
        (epss_fixture(), json!({"limit": 3})), // partial
        (odd, json!({"full": true})),          // null date, empty cve_id, exponent
        (missing, json!({})),                  // error: only the status row
    ] {
        let mut o = options;
        o["path"] = json!(path.display().to_string());
        let params: SyncParams =
            serde_json::from_value(json!({"source": "epss", "options": o})).unwrap();
        let mut stream = src.sync(params, CallCtx::default()).await.unwrap();
        while let Some(m) = stream.next().await {
            match m.unwrap() {
                StreamMsg::Item(b) => {
                    assert!(!h.store.apply_rows(&b).await.unwrap().skipped);
                    cases.push(("source/rows.schema.json", serde_json::to_value(&b).unwrap()));
                }
                StreamMsg::End(e) => cases.push((
                    "source/sync-end.schema.json",
                    serde_json::to_value(&e).unwrap(),
                )),
            }
        }
    }
    assert!(cases.len() >= 10);
    check_contracts(&cases);
}
