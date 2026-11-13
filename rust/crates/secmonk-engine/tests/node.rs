//! Node services in process (`secmonk_engine::node`): `LocalNode` over a real SQLite mirror filled through
//! `apply_rows` and a fake matcher; the versions a sync job records and the re-match after it; `NodeMatcher` over
//! fake services and a real state store.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use secmonk_engine::node::{
    DIFF_UNKNOWN_KEY, LocalNode, LocalNodeSettings, NodeMatcher, component_lookup_keys,
    default_importer_module, matcher_version,
};
use secmonk_engine::{EngineConfig, EngineDeps, EngineService, SecmonkEngine};
use secmonk_model::node::*;
use secmonk_model::*;
use secmonk_store::{MirrorStore, NodeCacheStore, SqliteStore, StateStore, StoreOptions};
use secmonk_traits::node::{Feed, MatchService, VulnInfo};
use secmonk_traits::{
    CallCtx, Classifier, CollectEnd, CollectItem, CollectParams, Collector, CollectorInfo,
    ErrorCode, Matcher, Probe, Reporter, ResultStream, Source, SourceInfo, StepResult, StreamMsg,
    VersionOracle, WireError,
};
use serde_json::{Map, Value, json};

// ------------------------------------------------------------------------------------------------ mirror rows

async fn open(dir: &std::path::Path) -> Arc<SqliteStore> {
    Arc::new(
        SqliteStore::open(
            &dir.join("db/state.sqlite3"),
            &dir.join("db/mirror.sqlite3"),
            &StoreOptions::default(),
        )
        .await
        .unwrap(),
    )
}

fn batch(source: &str, seq: u64, ops: Value) -> RowsBatch {
    serde_json::from_value(json!({"kind": "rows", "seq": seq, "source": source, "ops": ops}))
        .unwrap()
}

fn up(table: &str, row: Value) -> Value {
    json!({"op": "upsert", "table": table, "row": row})
}

fn vuln(source: &str, id: &str, modified: &str) -> Value {
    up(
        "vulnerability",
        json!({"source": source, "id": id, "summary": format!("{id} summary"),
               "published": "2024-01-01T00:00:00Z", "modified": modified, "severity": "HIGH", "cvss_score": 7.5}),
    )
}

fn aff(
    source: &str,
    id: &str,
    eco: Option<&str>,
    pkg: Option<&str>,
    product: Option<&str>,
) -> Value {
    up(
        "affected",
        json!({"source": source, "vuln_id": id, "ecosystem": eco, "package": pkg, "product": product,
               "events": [{"introduced": "0"}, {"fixed": "2.0"}], "status": "affected"}),
    )
}

fn sync_row(source: &str, status: &str, cursor: &str) -> Value {
    up(
        "source_sync",
        json!({"source": source, "status": status, "cursor": cursor, "records": 1,
               "last_sync": "2026-11-01T00:00:00Z"}),
    )
}

fn kev_row(cve: &str) -> Value {
    up(
        "kev",
        json!({"cve_id": cve, "source": "kev", "date_added": "2026-01-01"}),
    )
}

/// osv (PyPI requests, npm left-pad) and nvd (product openssl), both with an ok cursor; KEV.
async fn fill(store: &SqliteStore) {
    store
        .apply_rows(&batch(
            "osv",
            1,
            json!([
                vuln("osv", "GHSA-1", "2024-02-01T10:00:00Z"),
                aff("osv", "GHSA-1", Some("PyPI"), Some("requests"), None),
                vuln("osv", "GHSA-2", "2024-03-01T10:00:00Z"),
                aff("osv", "GHSA-2", Some("npm"), Some("left-pad"), None),
                sync_row("osv", "ok", "2024-03-01T10:00:00Z"),
            ]),
        ))
        .await
        .unwrap();
    store
        .apply_rows(&batch(
            "nvd",
            1,
            json!([
                vuln("nvd", "CVE-1", "2024-02-02T00:00:00Z"),
                aff("nvd", "CVE-1", None, None, Some("OpenSSL")),
                sync_row("nvd", "ok", "2024-02-02T00:00:00Z"),
            ]),
        ))
        .await
        .unwrap();
    store
        .apply_rows(&batch(
            "kev",
            1,
            json!([kev_row("CVE-1"), sync_row("kev", "ok", "2026.01.01")]),
        ))
        .await
        .unwrap();
}

// ------------------------------------------------------------------------------------------------ fakes

fn row(asset: &str, c: &Component, vuln: &str, i: usize) -> Map<String, Value> {
    json!({"asset_id": asset, "priority": "P3", "vuln_id": vuln, "component": c.name, "version": c.version,
           "category": c.category.as_str(), "fixed_version": "2.0", "severity": "HIGH", "cvss_score": 7.5,
           "epss": null, "kev": false, "triage": null, "matched_by": "osv-package", "confidence": 1.0,
           "status": "open", "component_id": i as i64 + 1, "advisory_ids": [vuln], "triage_source": null,
           "first_seen": "x", "last_seen": "x", "fixed_at": null, "ecosystem": c.ecosystem, "purl": c.purl})
    .as_object()
    .cloned()
    .unwrap()
}

/// Engine steps: an ephemeral match gives each component named in `vulns` its findings (the view capped at `cap`
/// rows while `stats.findings` counts them all); a persisted match records the asset and answers an empty set.
struct Steps {
    store: Arc<SqliteStore>,
    vulns: BTreeMap<String, Vec<String>>,
    cap: usize,
    ephemeral_calls: Mutex<Vec<(usize, Option<u32>)>>,
    persisted: Mutex<Vec<String>>,
}

impl Steps {
    fn new(store: Arc<SqliteStore>, vulns: &[(&str, &[&str])], cap: usize) -> Arc<Steps> {
        Arc::new(Steps {
            store,
            vulns: vulns
                .iter()
                .map(|(n, v)| ((*n).to_owned(), v.iter().map(|s| (*s).to_owned()).collect()))
                .collect(),
            cap,
            ephemeral_calls: Mutex::new(Vec::new()),
            persisted: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait]
impl Classifier for Steps {
    async fn classify(&self, c: Vec<Component>, _: CallCtx) -> StepResult<Vec<Component>> {
        Ok(c)
    }
}

#[async_trait]
impl Matcher for Steps {
    async fn match_asset(&self, params: MatchParams, _: CallCtx) -> StepResult<MatchResult> {
        match params {
            MatchParams::Ephemeral {
                inventory,
                view_limit,
                ..
            } => {
                self.ephemeral_calls
                    .lock()
                    .unwrap()
                    .push((inventory.components.len(), view_limit));
                let mut view = Vec::new();
                for (i, c) in inventory.components.iter().enumerate() {
                    for v in self.vulns.get(&c.name).into_iter().flatten() {
                        view.push(row(&inventory.asset.id, c, v, i));
                    }
                }
                let findings = view.len() as u64;
                if inventory.components.len() > 1 {
                    view.truncate(self.cap);
                }
                Ok(MatchResult {
                    asset_id: inventory.asset.id.clone(),
                    mode: MatchMode::Ephemeral,
                    stats: MatchStats {
                        components: inventory.components.len() as u64,
                        matches: findings,
                        findings,
                        ..Default::default()
                    },
                    based_on: None,
                    finding_set: None,
                    view,
                })
            }
            MatchParams::Persisted { asset_id, .. } => {
                self.persisted.lock().unwrap().push(asset_id.clone());
                let latest = self.store.latest_scan_id(&asset_id).await.unwrap();
                Ok(serde_json::from_value(json!({
                    "asset_id": asset_id, "mode": "persisted",
                    "stats": {"components": 0, "matches": 0, "findings": 0}, "view": [],
                    "based_on": {"latest_scan_id": latest}, "finding_set": [],
                }))
                .unwrap())
            }
        }
    }
}

#[async_trait]
impl Reporter for Steps {
    fn methods(&self) -> Vec<String> {
        vec![]
    }

    async fn report(&self, method: &str, params: Value, _: CallCtx) -> StepResult<Value> {
        match method {
            "reports.vuln_detail" if params["id"] == "CVE-1" => {
                Ok(json!({"id": "CVE-1", "raw": params["raw"]}))
            }
            "reports.vuln_detail" => Ok(Value::Null),
            "reports.vuln_search" => Ok(json!([{"vuln_id": "CVE-1", "q": params}])),
            "reports.status" => Ok(json!({"sources": []})),
            m => Err(WireError::new(ErrorCode::UnknownMethod, m.to_owned())),
        }
    }
}

#[async_trait]
impl VersionOracle for Steps {
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
    async fn priority(&self, p: Value, _: CallCtx) -> StepResult<String> {
        Ok(if p["kev"] == true {
            "P1".into()
        } else {
            "P3".into()
        })
    }
}

fn ident(name: &str, purl: Option<&str>, vendor: Option<&str>) -> ComponentIdentity {
    let mut v = json!({"name": name, "version": "1.0", "category": "library"});
    if let Some(p) = purl {
        v["purl"] = json!(p);
        v["ecosystem"] = json!("PyPI");
    }
    if let Some(x) = vendor {
        v["vendor"] = json!(x);
        v["category"] = json!("application");
    }
    serde_json::from_value(v).unwrap()
}

fn local(store: &Arc<SqliteStore>, steps: &Arc<Steps>) -> LocalNode {
    LocalNode::new(
        store.mirror_node_store(),
        steps.clone(),
        steps.clone(),
        LocalNodeSettings {
            node_id: Some("node-a".into()),
            ..Default::default()
        },
    )
}

// ------------------------------------------------------------------------------------------------ LocalNode

#[tokio::test]
async fn match_components_regroups_the_ephemeral_findings_per_component() {
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    fill(&store).await;
    let steps = Steps::new(
        store.clone(),
        &[("requests", &["CVE-1", "CVE-2"]), ("tool", &["CVE-9"])],
        5_000,
    );
    let node = local(&store, &steps);
    let comps = vec![
        ident("requests", Some("pkg:pypi/requests@1.0"), None),
        ident("clean", Some("pkg:pypi/clean@1.0"), None),
        // two components the view cannot tell apart (same name, version, category; vendor differs)
        ident("tool", None, Some("acme")),
        ident("tool", None, Some("other")),
        // a duplicate key
        ident("requests", Some("pkg:pypi/requests@1.0"), None),
    ];
    let r = node
        .match_components(MatchComponentsRequest {
            components: comps.clone(),
            min_confidence: None,
        })
        .await
        .unwrap();
    assert_eq!(r.results.len(), 5, "one result per requested component");
    for (res, c) in r.results.iter().zip(&comps) {
        assert_eq!(res.key, c.key());
        assert_eq!(res.lookup_keys, component_lookup_keys(c));
    }
    let ids = |i: usize| -> Vec<&str> {
        r.results[i]
            .matches
            .iter()
            .map(|m| m.vuln_id.as_str())
            .collect()
    };
    assert_eq!(ids(0), ["CVE-1", "CVE-2"]);
    assert!(ids(1).is_empty());
    assert_eq!(ids(2), ["CVE-9"]);
    assert_eq!(ids(3), ["CVE-9"]);
    assert_eq!(r.results[0].lookup_keys, ["pkg:pypi/requests"]);
    let m = &r.results[0].matches[0];
    assert_eq!(m.matched_by.as_deref(), Some("osv-package"));
    assert_eq!(m.fixed_version.as_deref(), Some("2.0"));
    assert_eq!(m.confidence, Some(1.0));
    // two rounds (the colliding "tool"), each an ephemeral match with the full view
    let calls = steps.ephemeral_calls.lock().unwrap().clone();
    assert_eq!(calls, [(3, Some(5_000)), (1, Some(5_000))]);
    assert_eq!(r.coverage.sources, ["kev", "nvd", "osv"]);
    assert_eq!(r.coverage.ecosystems, ["PyPI", "npm"]);
    assert_eq!(r.as_of.matcher, matcher_version());
    // too many components
    let many = vec![ident("x", None, None); MAX_COMPONENTS + 1];
    let e = node
        .match_components(MatchComponentsRequest {
            components: many,
            min_confidence: None,
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::InvalidParams);
}

#[tokio::test]
async fn a_capped_view_splits_the_request() {
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    let steps = Steps::new(
        store.clone(),
        &[("a", &["CVE-1"]), ("b", &["CVE-2"]), ("c", &["CVE-3"])],
        1,
    );
    let node = local(&store, &steps);
    let r = node
        .match_components(MatchComponentsRequest {
            components: vec![
                ident("a", None, None),
                ident("b", None, None),
                ident("c", None, None),
            ],
            min_confidence: None,
        })
        .await
        .unwrap();
    let got: Vec<Vec<String>> = r
        .results
        .iter()
        .map(|x| x.matches.iter().map(|m| m.vuln_id.clone()).collect())
        .collect();
    assert_eq!(got, [vec!["CVE-1"], vec!["CVE-2"], vec!["CVE-3"]]);
    assert!(steps.ephemeral_calls.lock().unwrap().len() > 1);
}

fn since(store_versions: &Versions) -> BTreeMap<String, String> {
    store_versions.since()
}

#[tokio::test]
async fn changes_answer_every_branch() {
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    fill(&store).await;
    let ns = store.mirror_node_store();
    ns.record_complete_version(
        "osv",
        "2024-03-01T10:00:00Z",
        "python/1",
        VersionKind::Record,
    )
    .await
    .unwrap();
    ns.record_complete_version(
        "nvd",
        "2024-02-02T00:00:00Z",
        "python/1",
        VersionKind::Record,
    )
    .await
    .unwrap();
    ns.record_complete_version("kev", "2026.01.01", "rust/1", VersionKind::Snapshot)
        .await
        .unwrap();
    let steps = Steps::new(store.clone(), &[], 5_000);
    let node = local(&store, &steps);
    let v0 = node.versions().await.unwrap();
    assert_eq!(v0.matcher, matcher_version());

    // same versions: unchanged
    let r = node
        .changes(ChangesRequest {
            since: since(&v0),
            matcher: Some(matcher_version().into()),
        })
        .await
        .unwrap();
    assert!(
        r.sources.values().all(|c| *c == SourceChanges::Unchanged),
        "{r:?}"
    );

    // another matcher: every source resyncs
    let r = node
        .changes(ChangesRequest {
            since: since(&v0),
            matcher: Some("py-engine/0".into()),
        })
        .await
        .unwrap();
    assert!(
        r.sources
            .values()
            .all(|c| *c == SourceChanges::Resync("matcher".into()))
    );

    // a record source moved on: changed ids and their keys (the overlap reads one hour below the client's version)
    store
        .apply_rows(&batch(
            "osv",
            2,
            json!([
                vuln("osv", "GHSA-3", "2024-04-01T10:00:00Z"),
                aff("osv", "GHSA-3", Some("PyPI"), Some("Flask"), None),
                sync_row("osv", "ok", "2024-04-01T10:00:00Z"),
            ]),
        ))
        .await
        .unwrap();
    ns.record_complete_version(
        "osv",
        "2024-04-01T10:00:00Z",
        "python/1",
        VersionKind::Record,
    )
    .await
    .unwrap();
    // a snapshot source with a recorded diff, and one diff marked unknown
    ns.record_complete_version("kev", "2026.02.01", "rust/1", VersionKind::Snapshot)
        .await
        .unwrap();
    ns.snapshot_diff_put(&SnapshotDiff {
        source: "kev".into(),
        version: "2026.02.01".into(),
        prev_version: Some("2026.01.01".into()),
        created_at: "2026-02-01T00:00:00Z".into(),
        ids: vec!["CVE-7".into()],
        keys: vec![],
    })
    .await
    .unwrap();
    let mut client = since(&v0);
    client.insert("gone".into(), "python/1@x".into());
    client.insert("nvd".into(), "rust/1@2024-02-02T00:00:00Z".into());
    let r = node
        .changes(ChangesRequest {
            since: client.clone(),
            matcher: None,
        })
        .await
        .unwrap();
    // GHSA-2 sits at the client's version: the overlap hour re-reads it (records are replaced whole)
    assert_eq!(
        r.sources["osv"],
        SourceChanges::Changed {
            changed_keys: vec!["pkg:npm/left-pad".into(), "pkg:pypi/flask".into()],
            changed_ids: vec!["GHSA-2".into(), "GHSA-3".into()],
        }
    );
    assert_eq!(
        r.sources["kev"],
        SourceChanges::Changed {
            changed_keys: vec![],
            changed_ids: vec!["CVE-7".into()]
        }
    );
    assert_eq!(r.sources["nvd"], SourceChanges::Resync("importer".into()));
    assert_eq!(
        r.sources["gone"],
        SourceChanges::Resync("source removed".into())
    );
    assert_eq!(r.as_of.since()["osv"], "python/1@2024-04-01T10:00:00Z");

    // a client that never saw a source, and a snapshot version without a diff chain
    client.remove("osv");
    client.insert("kev".into(), "rust/1@2025.12.01".into());
    let r = node
        .changes(ChangesRequest {
            since: client.clone(),
            matcher: None,
        })
        .await
        .unwrap();
    assert_eq!(r.sources["osv"], SourceChanges::Resync("new source".into()));
    assert_eq!(
        r.sources["kev"],
        SourceChanges::Resync("no diff log".into())
    );

    // a diff recorded as unknown (epss, a too large table): resync
    ns.record_complete_version("kev", "2026.03.01", "rust/1", VersionKind::Snapshot)
        .await
        .unwrap();
    ns.snapshot_diff_put(&SnapshotDiff {
        source: "kev".into(),
        version: "2026.03.01".into(),
        prev_version: Some("2026.02.01".into()),
        created_at: "2026-03-01T00:00:00Z".into(),
        ids: vec![],
        keys: vec![DIFF_UNKNOWN_KEY.into()],
    })
    .await
    .unwrap();
    client.insert("kev".into(), "rust/1@2026.02.01".into());
    let r = node
        .changes(ChangesRequest {
            since: client,
            matcher: None,
        })
        .await
        .unwrap();
    assert_eq!(
        r.sources["kev"],
        SourceChanges::Resync("no diff for this version".into())
    );
}

#[tokio::test]
async fn summaries_detail_and_search() {
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    fill(&store).await;
    let steps = Steps::new(store.clone(), &[], 5_000);
    let node = local(&store, &steps);
    let r = node
        .summaries(&["CVE-1".into(), "NOPE".into(), "GHSA-1".into()])
        .await
        .unwrap();
    assert_eq!(r.summaries.len(), 2);
    assert!(r.summaries[0].kev);
    assert_eq!(r.missing, ["NOPE"]);
    let too_many: Vec<String> = (0..=MAX_IDS).map(|i| format!("X-{i}")).collect();
    assert_eq!(
        node.summaries(&too_many).await.unwrap_err().code,
        ErrorCode::InvalidParams
    );
    assert_eq!(node.detail("CVE-1", true).await.unwrap()["raw"], true);
    assert_eq!(
        node.detail("CVE-404", false).await.unwrap_err().code,
        ErrorCode::UnknownVuln
    );
    let s = node
        .search(json!({"package": "requests", "limit": "5"}))
        .await
        .unwrap();
    assert_eq!(s["limit"], 5);
    assert_eq!(s["results"][0]["q"]["package"], "requests");
    assert_eq!(s["results"][0]["q"]["product"], Value::Null);
}

#[tokio::test]
async fn feed_serves_deltas_and_snapshots() {
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    fill(&store).await;
    let ns = store.mirror_node_store();
    ns.record_complete_version(
        "osv",
        "2024-03-01T10:00:00Z",
        "python/1",
        VersionKind::Record,
    )
    .await
    .unwrap();
    let steps = Steps::new(store.clone(), &[], 5_000);
    let node = local(&store, &steps);
    let st = node.status().await.unwrap();
    assert_eq!(st.node_id.as_deref(), Some("node-a"));
    assert_eq!(st.sources.len(), 3);

    let vulns_of = |p: &FeedPage| -> Vec<String> {
        p.batches
            .iter()
            .flat_map(|b| b.ops.iter())
            .filter_map(|o| match o {
                RowOp::Upsert {
                    table: MirrorTable::Vulnerability,
                    row,
                } => row.get("id").and_then(Value::as_str).map(str::to_owned),
                _ => None,
            })
            .collect()
    };
    // delta since the follower's version (GHSA-2 is within the overlap hour of 10:30)
    let p = node
        .since(FeedSinceRequest {
            source: "osv".into(),
            since: Some("python/1@2024-03-01T10:30:00Z".into()),
            page: None,
            limit: None,
        })
        .await
        .unwrap();
    assert_eq!(p.mode, FeedMode::Delta);
    assert_eq!(vulns_of(&p), ["GHSA-2"]);
    assert_eq!(p.version.version.as_deref(), Some("2024-03-01T10:00:00Z"));
    // a plain version (no importer): delta too
    let p = node
        .since(FeedSinceRequest {
            source: "osv".into(),
            since: Some("2024-01-01T00:00:00Z".into()),
            page: None,
            limit: Some(1),
        })
        .await
        .unwrap();
    assert_eq!(p.mode, FeedMode::Delta);
    assert_eq!(vulns_of(&p), ["GHSA-1"]);
    assert!(p.next_page.is_some());
    // another importer, or no version: every record, still as replace units (a record source is never a snapshot)
    for since in [Some("rust/1@2024-03-01T10:30:00Z".to_owned()), None] {
        let p = node
            .since(FeedSinceRequest {
                source: "osv".into(),
                since,
                page: None,
                limit: None,
            })
            .await
            .unwrap();
        assert_eq!(p.mode, FeedMode::Delta);
        assert_eq!(vulns_of(&p), ["GHSA-1", "GHSA-2"]);
    }
    // a snapshot source: always the whole table
    let p = node
        .since(FeedSinceRequest {
            source: "kev".into(),
            since: Some("rust/1@2026.01.01".into()),
            page: None,
            limit: None,
        })
        .await
        .unwrap();
    assert_eq!(p.mode, FeedMode::Snapshot);
    assert_eq!(p.batches[0].ops.len(), 1);
    let e = node
        .since(FeedSinceRequest {
            source: "nope".into(),
            since: None,
            page: None,
            limit: None,
        })
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::UnknownSource);
}

// ------------------------------------------------------------------------------------------------ sync job

struct ScriptSource {
    native: bool,
    importer: Option<&'static str>,
    scripts: Mutex<BTreeMap<String, (Vec<RowsBatch>, &'static str)>>,
}

#[async_trait]
impl Source for ScriptSource {
    fn sources(&self) -> Vec<SourceInfo> {
        ["kev", "osv"]
            .iter()
            .map(|n| SourceInfo {
                name: (*n).into(),
                description: String::new(),
                in_all: true,
            })
            .collect()
    }

    fn sync_all_order(&self) -> Vec<String> {
        vec!["kev".into(), "osv".into()]
    }

    async fn sync(
        &self,
        p: SyncParams,
        _: CallCtx,
    ) -> StepResult<ResultStream<RowsBatch, SyncEnd>> {
        let (batches, status) = self
            .scripts
            .lock()
            .unwrap()
            .get(&p.source)
            .cloned()
            .ok_or_else(|| WireError::new(ErrorCode::UnknownSource, "no"))?;
        let end: SyncEnd = serde_json::from_value(json!({
            "entry": {"source": p.source, "status": status, "records": 1, "seconds": 0.0, "message": null},
            "batches": batches.len(), "last_seq": batches.last().map_or(0, |b| b.seq), "ops": 0,
        }))
        .unwrap();
        let mut msgs: Vec<StepResult<StreamMsg<RowsBatch, SyncEnd>>> = batches
            .into_iter()
            .map(|b| Ok(StreamMsg::Item(b)))
            .collect();
        msgs.push(Ok(StreamMsg::End(end)));
        Ok(futures_util::stream::iter(msgs).boxed())
    }

    async fn ack(&self, _: &str, _: u64, _: CallCtx) -> StepResult<()> {
        Ok(())
    }

    async fn export(&self, s: &str, _: CallCtx) -> StepResult<ResultStream<RowsBatch, Value>> {
        let end = json!({"batches": 0, "high_water": 0, "entry": {"source": s}});
        Ok(futures_util::stream::iter(vec![Ok(StreamMsg::End(end))]).boxed())
    }

    fn native(&self) -> bool {
        self.native
    }

    fn importer_version(&self, _: &str) -> Option<String> {
        self.importer.map(str::to_owned)
    }
}

struct NoProbe;

#[async_trait]
impl Collector for NoProbe {
    fn collectors(&self) -> Vec<CollectorInfo> {
        vec![]
    }
    async fn expand_targets(
        &self,
        _: CollectParams,
        _: CallCtx,
    ) -> StepResult<Vec<Option<String>>> {
        Ok(vec![])
    }
    async fn collect(
        &self,
        _: CollectParams,
        _: CallCtx,
    ) -> StepResult<ResultStream<CollectItem, CollectEnd>> {
        Err(WireError::new(ErrorCode::CollectError, "no"))
    }
}

#[async_trait]
impl Probe for NoProbe {
    fn methods(&self) -> Vec<String> {
        vec![]
    }
    async fn call(&self, _: &str, _: Value, _: CallCtx) -> StepResult<Value> {
        Err(WireError::new(ErrorCode::UnknownMethod, "no"))
    }
}

fn engine(
    store: &Arc<SqliteStore>,
    steps: &Arc<Steps>,
    src: Arc<ScriptSource>,
) -> Arc<SecmonkEngine> {
    let mut config = EngineConfig::new("0.0.0-test", store.state_path());
    config.nvd_api_key_env = None;
    SecmonkEngine::new(EngineDeps {
        config,
        state: store.clone(),
        mirror: store.clone(),
        steps: steps.clone(),
        procmon: None,
        sources: vec![src],
        probe: Arc::new(NoProbe),
        modules: None,
        node_store: Some(store.mirror_node_store()),
    })
}

async fn run_sync(engine: &SecmonkEngine, sources: &[&str]) -> Value {
    let b = json!({"kind": "sync", "sources": sources});
    let started = engine
        .job_start(b.as_object().cloned().unwrap())
        .await
        .unwrap();
    let id = started["id"].as_u64().unwrap();
    for _ in 0..500 {
        let j = engine.job_get(id).await.unwrap();
        if j["status"] != "running" {
            return j;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("job {id} did not finish");
}

fn log_text(job: &Value) -> String {
    job["log"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n")
}

fn script(src: &ScriptSource, source: &str, batches: Vec<RowsBatch>, status: &'static str) {
    src.scripts
        .lock()
        .unwrap()
        .insert(source.into(), (batches, status));
}

async fn version_of(store: &SqliteStore, source: &str) -> SourceVersion {
    store
        .mirror_node_store()
        .source_versions()
        .await
        .unwrap()
        .into_iter()
        .find(|v| v.source == source)
        .unwrap()
}

#[tokio::test]
async fn a_complete_sync_records_versions_and_snapshot_diffs() {
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    let steps = Steps::new(store.clone(), &[], 5_000);
    let src = Arc::new(ScriptSource {
        native: false,
        importer: None,
        scripts: Mutex::new(BTreeMap::new()),
    });
    let e = engine(&store, &steps, src.clone());
    script(
        &src,
        "osv",
        vec![batch(
            "osv",
            1,
            json!([
                vuln("osv", "GHSA-1", "2024-02-01T10:00:00Z"),
                aff("osv", "GHSA-1", Some("PyPI"), Some("requests"), None),
                sync_row("osv", "ok", "2024-02-01T10:00:00Z"),
                sync_row("osv:PyPI", "ok", "2024-02-01T09:00:00Z")
            ]),
        )],
        "ok",
    );
    script(
        &src,
        "kev",
        vec![batch(
            "kev",
            1,
            json!([
                kev_row("CVE-1"),
                kev_row("CVE-2"),
                sync_row("kev", "ok", "v1")
            ]),
        )],
        "ok",
    );
    let job = run_sync(&e, &["kev", "osv"]).await;
    assert_eq!(job["status"], "ok", "{}", log_text(&job));
    let osv = version_of(&store, "osv").await;
    assert_eq!(osv.version.as_deref(), Some("2024-02-01T10:00:00Z"));
    assert_eq!(osv.importer, default_importer_module());
    assert!(osv.importer.starts_with("python/"));
    assert_eq!(
        version_of(&store, "osv:PyPI").await.importer,
        default_importer_module()
    );
    let kev = version_of(&store, "kev").await;
    assert_eq!(
        (kev.version.as_deref(), kev.kind),
        (Some("v1"), VersionKind::Snapshot)
    );

    // the next kev catalog drops CVE-1 and adds CVE-3: the diff names both
    script(
        &src,
        "kev",
        vec![batch(
            "kev",
            2,
            json!([{"op": "delete", "table": "kev", "key": {"cve_id": "CVE-1"}}, kev_row("CVE-3"),
                   sync_row("kev", "ok", "v2")]),
        )],
        "ok",
    );
    let job = run_sync(&e, &["kev"]).await;
    assert_eq!(job["status"], "ok", "{}", log_text(&job));
    let diffs = store
        .mirror_node_store()
        .snapshot_diffs_since("kev", "v1")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(diffs.len(), 1);
    assert_eq!(diffs[0].ids, ["CVE-1", "CVE-3"]);
    assert_eq!(diffs[0].prev_version.as_deref(), Some("v1"));

    // a partial run moves nothing
    script(
        &src,
        "osv",
        vec![batch(
            "osv",
            2,
            json!([sync_row("osv", "partial", "2025-01-01T00:00:00Z")]),
        )],
        "partial",
    );
    run_sync(&e, &["osv"]).await;
    assert_eq!(
        version_of(&store, "osv").await.version.as_deref(),
        Some("2024-02-01T10:00:00Z")
    );

    // the importer version a source declares, and the native default
    let src2 = Arc::new(ScriptSource {
        native: true,
        importer: None,
        scripts: Mutex::new(BTreeMap::new()),
    });
    let e2 = engine(&store, &steps, src2.clone());
    script(
        &src2,
        "osv",
        vec![batch(
            "osv",
            1,
            json!([sync_row("osv", "ok", "2025-02-01T00:00:00Z")]),
        )],
        "ok",
    );
    let job = run_sync(&e2, &["osv"]).await;
    assert_eq!(job["status"], "ok", "{}", log_text(&job));
    assert_eq!(version_of(&store, "osv").await.importer, "rust/1");
    let src3 = Arc::new(ScriptSource {
        native: false,
        importer: Some("py-sources/2"),
        scripts: Mutex::new(BTreeMap::new()),
    });
    let e3 = engine(&store, &steps, src3.clone());
    script(
        &src3,
        "osv",
        vec![batch(
            "osv",
            3,
            json!([sync_row("osv", "ok", "2025-03-01T00:00:00Z")]),
        )],
        "ok",
    );
    run_sync(&e3, &["osv"]).await;
    assert_eq!(version_of(&store, "osv").await.importer, "py-sources/2");
}

fn component(name: &str) -> Component {
    Component {
        name: name.into(),
        version: Some("1.0".into()),
        category: Category::Library,
        purl: Some(format!("pkg:pypi/{name}@1.0")),
        cpe: None,
        vendor: None,
        ecosystem: Some("PyPI".into()),
        source_path: None,
        meta: Default::default(),
    }
}

fn inventory(asset: &str, comps: &[&str]) -> Inventory {
    serde_json::from_value(json!({
        "schema": "secmonk-inventory/1", "classified": true,
        "asset": {"id": asset, "type": "directory", "name": asset},
        "collector": "fs", "components": comps.iter().map(|c| component(c)).collect::<Vec<_>>(),
        "warnings": [],
    }))
    .unwrap()
}

#[tokio::test]
async fn a_sync_rematches_the_assets_it_affects() {
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    let steps = Steps::new(store.clone(), &[], 5_000);
    let src = Arc::new(ScriptSource {
        native: false,
        importer: None,
        scripts: Mutex::new(BTreeMap::new()),
    });
    let e = engine(&store, &steps, src.clone());
    store
        .save_inventory(&inventory("dir:/a", &["requests"]), None)
        .await
        .unwrap();
    store
        .save_inventory(&inventory("dir:/b", &["flask"]), None)
        .await
        .unwrap();
    store
        .save_inventory(&inventory("dir:/c", &["left-pad"]), None)
        .await
        .unwrap();

    // first sync of osv: a source new to the node -> every asset
    script(
        &src,
        "osv",
        vec![batch(
            "osv",
            1,
            json!([
                vuln("osv", "GHSA-1", "2024-02-01T10:00:00Z"),
                aff("osv", "GHSA-1", Some("PyPI"), Some("requests"), None),
                // the high-water is two hours past GHSA-1: the next delta (one hour of overlap) skips it
                sync_row("osv", "ok", "2024-02-01T12:00:00Z")
            ]),
        )],
        "ok",
    );
    let job = run_sync(&e, &["osv"]).await;
    let mut got = std::mem::take(&mut *steps.persisted.lock().unwrap());
    got.sort();
    assert_eq!(got, ["dir:/a", "dir:/b", "dir:/c"], "{}", log_text(&job));
    assert!(log_text(&job).contains("resync of osv (new source)"));

    // a later delta touching flask (a new record) -> only that asset
    script(
        &src,
        "osv",
        vec![batch(
            "osv",
            2,
            json!([
                vuln("osv", "GHSA-2", "2024-05-01T10:00:00Z"),
                aff("osv", "GHSA-2", Some("PyPI"), Some("Flask"), None),
                sync_row("osv", "ok", "2024-05-01T10:00:00Z")
            ]),
        )],
        "ok",
    );
    let job = run_sync(&e, &["osv"]).await;
    assert_eq!(
        *steps.persisted.lock().unwrap(),
        ["dir:/b"],
        "{}",
        log_text(&job)
    );
    assert!(
        log_text(&job).contains("1 of 3 asset(s) re-matched"),
        "{}",
        log_text(&job)
    );
    steps.persisted.lock().unwrap().clear();

    // a sync that changes nothing re-matches nothing
    script(&src, "osv", vec![], "ok");
    run_sync(&e, &["osv"]).await;
    assert!(steps.persisted.lock().unwrap().is_empty());
}

// ------------------------------------------------------------------------------------------------ NodeMatcher

/// A match service: `requests` matches CVE-1 (confidence 1.0) and GHSA-L (0.3); counts the components asked.
struct FakeService {
    asked: Mutex<Vec<String>>,
    changes: Mutex<Option<ChangesResponse>>,
    versions: Versions,
}

#[async_trait]
impl MatchService for FakeService {
    async fn match_components(
        &self,
        req: MatchComponentsRequest,
    ) -> StepResult<MatchComponentsResponse> {
        let mut results = Vec::new();
        for c in &req.components {
            self.asked.lock().unwrap().push(c.name.clone());
            let m = |id: &str, conf: f64| ComponentMatch {
                vuln_id: id.into(),
                advisory_ids: vec![id.into()],
                matched_by: Some("osv-package".into()),
                confidence: Some(conf),
                fixed_version: Some("2.0".into()),
                triage: None,
                triage_source: None,
            };
            let matches = if c.name == "requests" {
                vec![m("CVE-1", 1.0), m("GHSA-L", 0.3)]
            } else {
                vec![]
            };
            results.push(ComponentResult {
                key: c.key(),
                matches,
                lookup_keys: component_lookup_keys(c),
            });
        }
        Ok(MatchComponentsResponse {
            results,
            as_of: self.versions.clone(),
            coverage: Coverage::default(),
        })
    }

    async fn changes(&self, _: ChangesRequest) -> StepResult<ChangesResponse> {
        Ok(self
            .changes
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| ChangesResponse {
                sources: BTreeMap::new(),
                as_of: self.versions.clone(),
            }))
    }

    async fn versions(&self) -> StepResult<Versions> {
        Ok(self.versions.clone())
    }
}

struct FakeInfo {
    calls: AtomicU64,
}

#[async_trait]
impl VulnInfo for FakeInfo {
    async fn summaries(&self, ids: &[String]) -> StepResult<SummariesResponse> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let summaries = ids
            .iter()
            .map(|id| VulnSummary {
                id: id.clone(),
                aliases: vec![],
                summary: None,
                severity: Some("CRITICAL".into()),
                cvss_score: Some(9.8),
                cvss_vector: None,
                published: None,
                modified: None,
                withdrawn: None,
                kev: id == "CVE-1",
                kev_date_added: None,
                epss: Some(0.5),
                epss_percentile: None,
                sources: vec!["nvd".into()],
            })
            .collect();
        Ok(SummariesResponse {
            summaries,
            missing: vec![],
        })
    }
    async fn detail(&self, _: &str, _: bool) -> StepResult<Value> {
        Ok(Value::Null)
    }
    async fn search(&self, _: Value) -> StepResult<Value> {
        Ok(Value::Null)
    }
}

fn versions(osv: &str) -> Versions {
    Versions::new(
        matcher_version(),
        [SourceVersion {
            source: "osv:PyPI".into(),
            version: Some(osv.into()),
            importer: "python/1".into(),
            kind: VersionKind::Record,
            records: 1,
            last_sync: None,
            status: Some("ok".into()),
        }],
    )
}

#[tokio::test]
async fn node_matcher_matches_from_the_cache_and_follows_changes() {
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    let steps = Steps::new(store.clone(), &[], 5_000);
    let service = Arc::new(FakeService {
        asked: Mutex::new(Vec::new()),
        changes: Mutex::new(None),
        versions: versions("v1"),
    });
    let info = Arc::new(FakeInfo {
        calls: AtomicU64::new(0),
    });
    let cache: Arc<dyn NodeCacheStore> = store.node_cache_store();
    let m = NodeMatcher::new(
        service.clone(),
        info.clone(),
        cache.clone(),
        steps.clone(),
        store.clone(),
    );
    store
        .save_inventory(&inventory("dir:/a", &["requests", "clean"]), None)
        .await
        .unwrap();

    // persisted: the complete set, accepted by replace_findings
    let r = m
        .match_asset(
            MatchParams::Persisted {
                asset_id: "dir:/a".into(),
                min_confidence: 0.5,
                view_limit: None,
            },
            CallCtx::default(),
        )
        .await
        .unwrap();
    let set = r.finding_set.clone().unwrap();
    assert_eq!(set.len(), 1, "GHSA-L is below min_confidence");
    let f = &set[0];
    assert_eq!(
        (f.vuln_id.as_str(), f.kev, f.priority.as_deref()),
        ("CVE-1", true, Some("P1"))
    );
    assert_eq!(
        (f.severity.as_deref(), f.cvss_score, f.epss),
        (Some("CRITICAL"), Some(9.8), Some(0.5))
    );
    assert_eq!(r.stats.matches, 2);
    assert_eq!(r.view.len(), 1);
    assert_eq!(r.view[0]["component"], "requests");
    store
        .replace_findings("dir:/a", &set, r.based_on.as_ref().unwrap())
        .await
        .unwrap();
    let mut asked = std::mem::take(&mut *service.asked.lock().unwrap());
    asked.sort();
    assert_eq!(asked, ["clean", "requests"]);
    assert_eq!(info.calls.load(Ordering::SeqCst), 1);

    // again: everything from the cache
    let r2 = m
        .match_asset(
            MatchParams::Persisted {
                asset_id: "dir:/a".into(),
                min_confidence: 0.0,
                view_limit: None,
            },
            CallCtx::default(),
        )
        .await
        .unwrap();
    assert!(service.asked.lock().unwrap().is_empty());
    assert_eq!(
        info.calls.load(Ordering::SeqCst),
        1,
        "every matched id was cached by the first match"
    );
    let set2 = r2.finding_set.unwrap();
    assert_eq!(set2.len(), 2);
    assert_eq!(
        set2.iter()
            .find(|f| f.vuln_id == "CVE-1")
            .unwrap()
            .first_seen,
        f.first_seen,
        "first_seen kept"
    );

    // a change under requests' key: the poll asks requests again, not clean
    *service.changes.lock().unwrap() = Some(ChangesResponse {
        sources: BTreeMap::from([(
            "osv:PyPI".into(),
            SourceChanges::Changed {
                changed_keys: vec!["pkg:pypi/requests".into()],
                changed_ids: vec![],
            },
        )]),
        as_of: versions("v2"),
    });
    let p = m.poll_changes().await.unwrap();
    assert_eq!(p.hit_keys, ["pkg:pypi/requests@1.0"]);
    assert_eq!(*service.asked.lock().unwrap(), ["requests"]);
    service.asked.lock().unwrap().clear();

    // a resync of osv:PyPI: both PyPI components asked again
    *service.changes.lock().unwrap() = Some(ChangesResponse {
        sources: BTreeMap::from([("osv:PyPI".into(), SourceChanges::Resync("importer".into()))]),
        as_of: versions("v3"),
    });
    let p = m.poll_changes().await.unwrap();
    assert_eq!(p.resynced, ["osv:PyPI"]);
    assert_eq!(p.hit_keys.len(), 2);
    service.asked.lock().unwrap().clear();
    *service.changes.lock().unwrap() = None;

    // ephemeral: an inventory never stored; a component already cached is not asked again
    let r = m
        .match_asset(
            MatchParams::Ephemeral {
                inventory: Box::new(inventory("tmp:x", &["requests", "other"])),
                min_confidence: 0.0,
                view_limit: Some(10),
            },
            CallCtx::default(),
        )
        .await
        .unwrap();
    assert_eq!(*service.asked.lock().unwrap(), ["other"]);
    assert!(r.finding_set.is_none() && r.based_on.is_none());
    assert_eq!(r.view.len(), 2);
    assert_eq!(r.view[0]["vuln_id"], "CVE-1", "P1 first");
    assert_eq!(r.view[0]["asset_id"], "tmp:x");

    // an unknown asset
    let e = m
        .match_asset(
            MatchParams::Persisted {
                asset_id: "nope".into(),
                min_confidence: 0.0,
                view_limit: None,
            },
            CallCtx::default(),
        )
        .await
        .unwrap_err();
    assert_eq!(e.code, ErrorCode::UnknownAsset);
}

#[tokio::test]
async fn engine_service_still_answers_reads() {
    // the node store changes nothing for the API (smoke)
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    let steps = Steps::new(store.clone(), &[], 5_000);
    let src = Arc::new(ScriptSource {
        native: false,
        importer: None,
        scripts: Mutex::new(BTreeMap::new()),
    });
    let e = engine(&store, &steps, src);
    assert_eq!(e.meta().await.unwrap()["engine"]["runtime"], "rust");
}

#[tokio::test]
async fn state_reads_for_the_node_services() {
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    store
        .save_inventory(&inventory("dir:/a", &["requests", "flask"]), None)
        .await
        .unwrap();
    store
        .save_inventory(&inventory("dir:/b", &["flask"]), None)
        .await
        .unwrap();
    // a partial re-scan keeps what the complete scan saw; a complete one drops what it lacks
    let mut partial = inventory("dir:/a", &["click"]);
    partial.partial = true;
    store.save_inventory(&partial, None).await.unwrap();
    let names = |v: Vec<secmonk_store::StoredComponent>| -> Vec<String> {
        v.into_iter().map(|c| c.component.name).collect()
    };
    assert_eq!(
        names(store.current_components("dir:/a").await.unwrap()),
        ["click", "flask", "requests"]
    );
    store
        .save_inventory(&inventory("dir:/a", &["flask"]), None)
        .await
        .unwrap();
    let comps = store.current_components("dir:/a").await.unwrap();
    assert_eq!(names(comps.clone()), ["flask"]);
    assert_eq!(
        comps[0].component.purl.as_deref(),
        Some("pkg:pypi/flask@1.0")
    );
    assert_eq!(store.asset_ids().await.unwrap(), ["dir:/a", "dir:/b"]);

    let latest = store.latest_scan_id("dir:/b").await.unwrap();
    let f: Finding = serde_json::from_value(json!({
        "component_id": store.current_components("dir:/b").await.unwrap()[0].id, "vuln_id": "CVE-5",
        "advisory_ids": ["GHSA-X", "CVE-5"], "matched_by": "osv-package", "confidence": 1.0, "kev": true,
        "priority": "P1", "status": "suppressed", "first_seen": "t0", "last_seen": "t1",
    }))
    .unwrap();
    store
        .replace_findings(
            "dir:/b",
            std::slice::from_ref(&f),
            &BasedOn {
                latest_scan_id: latest,
                mirror_synced_at: None,
            },
        )
        .await
        .unwrap();
    assert_eq!(store.asset_findings("dir:/b").await.unwrap(), [f]);
    assert!(store.asset_findings("dir:/a").await.unwrap().is_empty());
    for id in ["GHSA-X", "CVE-5"] {
        assert_eq!(
            store.assets_with_findings_on(&[id.into()]).await.unwrap(),
            ["dir:/b"]
        );
    }
    assert!(
        store
            .assets_with_findings_on(&["CVE-6".into()])
            .await
            .unwrap()
            .is_empty()
    );
}
