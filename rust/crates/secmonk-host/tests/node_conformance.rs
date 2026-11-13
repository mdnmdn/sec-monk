//! Mirror-node acceptance tests that span crates (proposal `2026-11-12-mirror-nodes-feed-match-service` §3.6 and §8):
//!
//! 1. **Conformance**: one suite over `MatchService` + `VulnInfo` + `Feed`, run against `LocalNode` in process and
//!    against `RemoteNode` over a real HTTP server (`secmonk_api::Server`, auth on, `NodeApi` over the same
//!    `LocalNode`); the answers must be identical as JSON.
//! 2. **Follow end to end**: a node B with an empty mirror follows node A through `FollowedSource` (the host's
//!    adapters over `RemoteNode`) applied by the engine's own sync job; rows and versions are equal, also after A
//!    changes (a delta from B's version).
//! 3. **Incremental against full**: after each change batch, the findings the sync job's re-match left in state equal
//!    a fresh full match of every asset on the same mirror state.
//!
//! The fixtures are synthetic: ids, package names and timestamps are made up (`tests/fixtures` rules of AGENTS.md).
#![cfg(feature = "engine")]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use futures_util::StreamExt;
use secmonk_api::{HostPolicy, Mount, Router, RouterOptions, Server, StaticDir, accept_loop};
use secmonk_auth::{Authenticator, JwtSigner, KeyStore, Scopes};
use secmonk_engine::node::{LocalNode, LocalNodeSettings, matcher_version};
use secmonk_engine::{
    EngineConfig, EngineDeps, EngineInfo, EngineService, SecmonkEngine, SkeletonEngine,
    StoreMirrorView,
};
use secmonk_host::node::FollowedSource;
use secmonk_model::node::*;
use secmonk_model::*;
use secmonk_node::{NodeApi, RemoteConfig, RemoteNode};
use secmonk_store::{MirrorStore, SqliteStore, StateStore, StoreOptions};
use secmonk_traits::node::{Feed, MatchService, VulnInfo};
use secmonk_traits::{
    CallCtx, Classifier, CollectEnd, CollectItem, CollectParams, Collector, CollectorInfo,
    EngineSteps, ErrorCode, MatchParams, MatchResult, Matcher, Probe, Reporter, ResultStream,
    Source, SourceInfo, StepResult, StreamMsg, VersionOracle, WireError,
};
use serde::Serialize;
use serde_json::{Map, Value, json};
use tokio::net::TcpListener;

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

fn vuln(source: &str, id: &str, modified: &str, extra: Value) -> Value {
    let mut row = json!({"source": source, "id": id, "summary": format!("{id} summary"),
        "published": "2024-01-01T00:00:00Z", "modified": modified, "severity": "HIGH", "cvss_score": 7.5});
    for (k, v) in extra.as_object().unwrap() {
        row[k] = v.clone();
    }
    up("vulnerability", row)
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

fn alias(source: &str, id: &str, alias: &str) -> Value {
    up(
        "alias",
        json!({"vuln_id": id, "alias": alias, "source": source, "kind": "alias"}),
    )
}

fn raw(source: &str, id: &str, modified: &str) -> Value {
    up(
        "raw_record",
        json!({"source": source, "record_id": id, "modified": modified,
               "fetched_at": "2026-11-01T00:00:00+00:00", "data": {"id": id}}),
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

/// The matcher version and importers the fixtures record.
const PY: &str = "python/1";
const RS: &str = "rust/1";

/// Record `cursor` as the complete version of `source` (what a sync job does after an `ok` run).
async fn publish(
    store: &SqliteStore,
    source: &str,
    cursor: &str,
    importer: &str,
    kind: VersionKind,
) {
    store
        .mirror_node_store()
        .record_complete_version(source, cursor, importer, kind)
        .await
        .unwrap();
}

/// Mirror of node A: osv (3 records, aliases, raw, a duplicate affected row), nvd (1 record), kev (3 entries),
/// each with an ok cursor and a recorded version; a kev diff for the second catalog version.
async fn fill_a(store: &SqliteStore) {
    store
        .apply_rows(&batch(
            "osv",
            1,
            json!([
                vuln("osv", "GHSA-1", "2024-02-01T10:00:00Z", json!({})),
                raw("osv", "GHSA-1", "2024-02-01T10:00:00Z"),
                alias("osv", "GHSA-1", "CVE-1"),
                alias("osv", "GHSA-1", "PYSEC-1"),
                aff("osv", "GHSA-1", Some("PyPI"), Some("requests"), None),
                aff("osv", "GHSA-1", Some("PyPI"), Some("requests"), None),
                vuln(
                    "osv",
                    "GHSA-2",
                    "2024-03-01T10:00:00Z",
                    json!({"cvss_score": 5.5, "severity": "MEDIUM"})
                ),
                raw("osv", "GHSA-2", "2024-03-01T10:00:00Z"),
                aff("osv", "GHSA-2", Some("npm"), Some("left-pad"), None),
                vuln("osv", "GHSA-3", "2024-04-01T10:00:00Z", json!({})),
                aff("osv", "GHSA-3", Some("PyPI"), Some("flask"), None),
                sync_row("osv", "ok", "2024-04-01T10:00:00Z"),
            ]),
        ))
        .await
        .unwrap();
    store
        .apply_rows(&batch(
            "nvd",
            1,
            json!([
                vuln(
                    "nvd",
                    "CVE-1",
                    "2024-02-02T00:00:00Z",
                    json!({"severity": "CRITICAL", "cvss_score": 9.8})
                ),
                raw("nvd", "CVE-1", "2024-02-02T00:00:00Z"),
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
            json!([
                kev_row("CVE-1"),
                kev_row("CVE-5"),
                kev_row("CVE-9"),
                sync_row("kev", "ok", "2026.02.01"),
            ]),
        ))
        .await
        .unwrap();
    publish(
        store,
        "osv",
        "2024-04-01T10:00:00Z",
        PY,
        VersionKind::Record,
    )
    .await;
    publish(
        store,
        "nvd",
        "2024-02-02T00:00:00Z",
        PY,
        VersionKind::Record,
    )
    .await;
    publish(store, "kev", "2026.01.01", RS, VersionKind::Snapshot).await;
    publish(store, "kev", "2026.02.01", RS, VersionKind::Snapshot).await;
    store
        .mirror_node_store()
        .snapshot_diff_put(&SnapshotDiff {
            source: "kev".into(),
            version: "2026.02.01".into(),
            prev_version: Some("2026.01.01".into()),
            created_at: "2026-02-01T00:00:00Z".into(),
            ids: vec!["CVE-7".into()],
            keys: vec![],
        })
        .await
        .unwrap();
}

// ------------------------------------------------------------------------------------------------ engine steps

fn finding_row(asset: &str, c: &Component, vuln: &str, i: usize) -> Map<String, Value> {
    json!({"asset_id": asset, "priority": "P3", "vuln_id": vuln, "component": c.name, "version": c.version,
           "category": c.category.as_str(), "fixed_version": "2.0", "severity": "HIGH", "cvss_score": 7.5,
           "epss": null, "kev": false, "triage": null, "matched_by": "osv-package", "confidence": 1.0,
           "status": "open", "component_id": i as i64 + 1, "advisory_ids": [vuln], "triage_source": null,
           "first_seen": "x", "last_seen": "x", "fixed_at": null, "ecosystem": c.ecosystem, "purl": c.purl})
    .as_object()
    .cloned()
    .unwrap()
}

/// The stub matcher of the engine's node tests: an ephemeral match gives each component named in `vulns` its
/// findings; the details reports answer a few fixed ids. Persisted matches are not used by the node services.
struct Steps {
    vulns: BTreeMap<String, Vec<String>>,
}

impl Steps {
    fn new(vulns: &[(&str, &[&str])]) -> Arc<Steps> {
        Arc::new(Steps {
            vulns: vulns
                .iter()
                .map(|(n, v)| ((*n).to_owned(), v.iter().map(|s| (*s).to_owned()).collect()))
                .collect(),
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
        let MatchParams::Ephemeral { inventory, .. } = params else {
            return Err(WireError::new(
                ErrorCode::InvalidParams,
                "the stub only matches ephemeral inventories",
            ));
        };
        let mut view = Vec::new();
        for (i, c) in inventory.components.iter().enumerate() {
            for v in self.vulns.get(&c.name).into_iter().flatten() {
                view.push(finding_row(&inventory.asset.id, c, v, i));
            }
        }
        let findings = view.len() as u64;
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

fn local_node(store: &Arc<SqliteStore>, steps: &Arc<Steps>) -> Arc<LocalNode> {
    Arc::new(LocalNode::new(
        store.mirror_node_store(),
        steps.clone(),
        steps.clone(),
        LocalNodeSettings {
            node_id: Some("node-a".into()),
            ..Default::default()
        },
    ))
}

// ------------------------------------------------------------------------------------------------ HTTP node

/// `NodeApi` over `local` behind `secmonk_api::Server` (auth on) and a `RemoteNode` with a key that has the scopes
/// `match`, `vulninfo:read` and `feed:read` (the same server serves a second node's follower).
async fn serve(local: Arc<LocalNode>) -> Arc<RemoteNode> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let engine = Arc::new(SkeletonEngine::new(EngineInfo::new(
        "0.1.0",
        "/x/state.sqlite3",
    )));
    let router = Arc::new(Router::new(
        engine,
        RouterOptions {
            static_dir: StaticDir::new(std::env::temp_dir().join("secmonk-host-node-none")),
            host_policy: HostPolicy::http_server("127.0.0.1", addr.port(), &[]),
            actions: true,
        },
    ));
    let mut keys = KeyStore::in_memory();
    let key = keys
        .create(
            "peer",
            Scopes::parse(["match", "vulninfo:read", "feed:read"]).unwrap(),
            None,
        )
        .unwrap();
    let m: Arc<dyn MatchService> = local.clone();
    let v: Arc<dyn VulnInfo> = local.clone();
    let f: Arc<dyn Feed> = local;
    let api: Arc<dyn Mount> = Arc::new(NodeApi::derived(Some(m), Some(v), Some(f), "node-a", true));
    let server = Server::new(router)
        .with_auth(Arc::new(Authenticator::new(
            keys,
            JwtSigner::new(vec![7; 32], 3600),
            10_000,
        )))
        .with_mount(api);
    tokio::spawn(accept_loop(
        Arc::new(server),
        listener,
        None,
        Duration::from_secs(5),
        16,
    ));
    Arc::new(
        RemoteNode::new(RemoteConfig {
            base_url: format!("http://127.0.0.1:{}", addr.port()),
            api_key: key,
            ca_cert: None,
            timeout: Duration::from_secs(10),
        })
        .unwrap(),
    )
}

// ------------------------------------------------------------------------------------------------ 1. conformance

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

/// An answer as JSON; an error as its wire code (the text and hint are the transport's business).
fn js<T: Serialize>(r: StepResult<T>) -> Value {
    match r {
        Ok(v) => serde_json::to_value(v).unwrap(),
        Err(e) => json!({"error": format!("{:?}", e.code)}),
    }
}

/// Every page of a feed read until the end (at most 50 pages), as JSON.
async fn drain(
    svc: &(impl Feed + ?Sized),
    source: &str,
    since: Option<&str>,
    limit: usize,
) -> Vec<Value> {
    let mut pages = Vec::new();
    let mut page = None;
    loop {
        let p = svc
            .since(FeedSinceRequest {
                source: source.into(),
                since: since.map(str::to_owned),
                page: page.clone(),
                limit: Some(limit as u32),
            })
            .await
            .unwrap();
        let next = p.next_page.clone();
        pages.push(serde_json::to_value(p).unwrap());
        match next {
            Some(n) => page = Some(n),
            None => return pages,
        }
        assert!(pages.len() < 50, "the feed does not end");
    }
}

/// The conformance suite: what one implementation of the three services answers, as named JSON documents. Run it
/// against every implementation and compare; the documents are also checked against what the fixture implies.
async fn conformance(svc: &(impl MatchService + VulnInfo + Feed)) -> Vec<(String, Value)> {
    let mut out: Vec<(String, Value)> = Vec::new();
    let mut put = |name: &str, v: Value| out.push((name.to_owned(), v));

    // versions
    let versions = svc.versions().await.unwrap();
    put("versions", serde_json::to_value(&versions).unwrap());
    let own = versions.since();

    // changes: unchanged, changed (record + snapshot), resync (importer, source removed, new source, matcher)
    let req = |since: BTreeMap<String, String>, matcher: Option<&str>| ChangesRequest {
        since,
        matcher: matcher.map(str::to_owned),
    };
    put(
        "changes/unchanged",
        js(svc.changes(req(own.clone(), Some(&versions.matcher))).await),
    );
    put(
        "changes/unchanged-no-matcher",
        js(svc.changes(req(own.clone(), None)).await),
    );
    let moved: BTreeMap<String, String> = BTreeMap::from([
        ("osv".into(), format!("{PY}@2024-02-15T00:00:00Z")),
        ("nvd".into(), own["nvd"].clone()),
        ("kev".into(), format!("{RS}@2026.01.01")),
    ]);
    put("changes/changed", js(svc.changes(req(moved, None)).await));
    let mut other_importer = own.clone();
    other_importer.insert("nvd".into(), format!("{RS}@2024-02-02T00:00:00Z"));
    other_importer.insert("gone".into(), format!("{PY}@x"));
    put(
        "changes/resync-importer",
        js(svc.changes(req(other_importer, None)).await),
    );
    let mut new_source = own.clone();
    new_source.remove("osv");
    put(
        "changes/resync-new-source",
        js(svc.changes(req(new_source, None)).await),
    );
    put(
        "changes/resync-matcher",
        js(svc.changes(req(own.clone(), Some("py-engine/0"))).await),
    );

    // match.components: empty matches, collisions, a duplicate key, a confidence floor, an empty request
    let comps = vec![
        ident("requests", Some("pkg:pypi/requests@1.0"), None),
        ident("clean", Some("pkg:pypi/clean@1.0"), None),
        ident("tool", None, Some("acme")),
        ident("tool", None, Some("other")),
        ident("requests", Some("pkg:pypi/requests@1.0"), None),
    ];
    for (name, c, min) in [
        ("match/all", comps.clone(), None),
        ("match/min-confidence", comps.clone(), Some(0.5)),
        ("match/empty", vec![], None),
        ("match/one-clean", vec![comps[1].clone()], None),
    ] {
        put(
            name,
            js(svc
                .match_components(MatchComponentsRequest {
                    components: c,
                    min_confidence: min,
                })
                .await),
        );
    }

    // summaries with a missing id, an empty list, a repeated id
    for (name, ids) in [
        ("summaries/missing", vec!["CVE-1", "NOPE", "GHSA-1"]),
        ("summaries/empty", vec![]),
        ("summaries/repeated", vec!["GHSA-2", "GHSA-2"]),
        ("summaries/none-known", vec!["NOPE"]),
    ] {
        let ids: Vec<String> = ids.into_iter().map(str::to_owned).collect();
        put(name, js(svc.summaries(&ids).await));
    }
    put("detail/known", js(svc.detail("CVE-1", true).await));
    put("detail/unknown", js(svc.detail("CVE-404", false).await));

    // feed.status; feed.since: deltas to the end in pages of one, from a version, from nothing; kev snapshot
    put("feed/status", js(svc.status().await));
    put(
        "feed/osv-full",
        Value::Array(drain(svc, "osv", None, 1).await),
    );
    put(
        "feed/osv-since",
        Value::Array(drain(svc, "osv", Some(&format!("{PY}@2024-02-15T00:00:00Z")), 1).await),
    );
    put(
        "feed/osv-other-importer",
        Value::Array(drain(svc, "osv", Some(&format!("{RS}@2024-02-15T00:00:00Z")), 2).await),
    );
    put("feed/nvd", Value::Array(drain(svc, "nvd", None, 500).await));
    put(
        "feed/kev-snapshot",
        Value::Array(drain(svc, "kev", Some(&format!("{RS}@2026.01.01")), 1).await),
    );
    put(
        "feed/unknown-source",
        js(svc
            .since(FeedSinceRequest {
                source: "nope".into(),
                since: None,
                page: None,
                limit: None,
            })
            .await),
    );
    out
}

/// The facts of the fixture the suite must show (so equal answers are not equally empty ones).
fn check_fixture_facts(doc: &BTreeMap<&str, &Value>) {
    let ids = |v: &Value, k: &str| -> Vec<String> {
        v[k].as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        doc["changes/unchanged"]["sources"]["osv"],
        json!({"unchanged": true})
    );
    assert_eq!(
        doc["changes/unchanged"]["sources"]["kev"],
        json!({"unchanged": true})
    );
    let c = &doc["changes/changed"]["sources"];
    assert_eq!(ids(&c["osv"], "changed_ids"), ["GHSA-2", "GHSA-3"]);
    assert_eq!(ids(&c["kev"], "changed_ids"), ["CVE-7"]);
    assert_eq!(c["nvd"], json!({"unchanged": true}));
    let r = &doc["changes/resync-importer"]["sources"];
    assert_eq!(r["nvd"], json!({"resync": "importer"}));
    assert_eq!(r["gone"], json!({"resync": "source removed"}));
    assert_eq!(
        doc["changes/resync-new-source"]["sources"]["osv"],
        json!({"resync": "new source"})
    );
    assert_eq!(
        doc["changes/resync-matcher"]["sources"]["osv"],
        json!({"resync": "matcher"})
    );
    // 5 requested components, 5 results in order; the duplicate repeats the first; `clean` has no match
    let m = doc["match/all"]["results"].as_array().unwrap();
    assert_eq!(m.len(), 5);
    assert_eq!(m[0], m[4]);
    assert!(m[1]["matches"].as_array().unwrap().is_empty());
    assert_eq!(m[0]["matches"].as_array().unwrap().len(), 2);
    assert!(doc["match/empty"]["results"].as_array().unwrap().is_empty());
    let s = &doc["summaries/missing"];
    assert_eq!(s["missing"], json!(["NOPE"]));
    assert_eq!(s["summaries"].as_array().unwrap().len(), 2);
    assert_eq!(doc["summaries/none-known"]["missing"], json!(["NOPE"]));
    assert_eq!(*doc["detail/unknown"], json!({"error": "UnknownVuln"}));
    assert_eq!(
        *doc["feed/unknown-source"],
        json!({"error": "UnknownSource"})
    );
    assert_eq!(doc["feed/status"]["sources"].as_array().unwrap().len(), 3);
    for name in ["feed/osv-full", "feed/kev-snapshot"] {
        let pages = doc[name].as_array().unwrap();
        assert!(
            pages.len() >= 2,
            "{name}: paging to the end takes several pages"
        );
        assert!(pages.last().unwrap()["next_page"].is_null());
    }
    assert_eq!(doc["feed/kev-snapshot"][0]["mode"], "snapshot");
    assert_eq!(doc["feed/osv-full"][0]["mode"], "delta");
}

#[tokio::test]
async fn local_and_remote_nodes_conform() {
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    fill_a(&store).await;
    let steps = Steps::new(&[("requests", &["CVE-1", "CVE-2"]), ("tool", &["CVE-9"])]);
    let local = local_node(&store, &steps);
    let remote = serve(local.clone()).await;

    let a = conformance(&*local).await;
    let b = conformance(&*remote).await;
    assert_eq!(
        a.iter().map(|(n, _)| n).collect::<Vec<_>>(),
        b.iter().map(|(n, _)| n).collect::<Vec<_>>()
    );
    let mut diffs = Vec::new();
    for ((name, x), (_, y)) in a.iter().zip(&b) {
        if x != y {
            diffs.push(format!("{name}:\n  local:  {x}\n  remote: {y}"));
        }
    }
    assert!(
        diffs.is_empty(),
        "remote differs from local:\n{}",
        diffs.join("\n")
    );
    let doc: BTreeMap<&str, &Value> = a.iter().map(|(n, v)| (n.as_str(), v)).collect();
    check_fixture_facts(&doc);
    assert_eq!(doc["versions"]["matcher"], matcher_version());
}

// ------------------------------------------------------------------------------------------------ engine helpers

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
    steps: Arc<dyn EngineSteps>,
    src: Arc<dyn Source>,
) -> Arc<SecmonkEngine> {
    let mut config = EngineConfig::new("0.0.0-test", store.state_path());
    config.nvd_api_key_env = None;
    SecmonkEngine::new(EngineDeps {
        config,
        state: store.clone(),
        mirror: store.clone(),
        steps,
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
    for _ in 0..1000 {
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

async fn version_of(store: &SqliteStore, source: &str) -> SourceVersion {
    store
        .mirror_node_store()
        .source_versions()
        .await
        .unwrap()
        .into_iter()
        .find(|v| v.source == source)
        .unwrap_or_else(|| panic!("no version of {source}"))
}

/// Every row of `table` of `source`, as canonical JSON text, sorted.
async fn dump(store: &SqliteStore, table: MirrorTable, source: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut after = None;
    loop {
        let (rows, next) = store.rows_page(table, source, after, 100).await.unwrap();
        out.extend(rows.into_iter().map(|r| serde_json::to_string(&r).unwrap()));
        match next {
            Some(n) => after = Some(n),
            None => break,
        }
    }
    out.sort();
    out
}

async fn assert_same(a: &SqliteStore, b: &SqliteStore, source: &str, tables: &[MirrorTable]) {
    for t in tables {
        assert_eq!(
            dump(a, *t, source).await,
            dump(b, *t, source).await,
            "{} of {source}",
            t.as_str()
        );
    }
}

const RECORD_TABLES: [MirrorTable; 4] = [
    MirrorTable::Vulnerability,
    MirrorTable::Alias,
    MirrorTable::Affected,
    MirrorTable::RawRecord,
];

// ------------------------------------------------------------------------------------------------ 2. follow

#[tokio::test]
async fn a_follower_converges_on_its_upstream_and_follows_its_changes() {
    let d = tempfile::tempdir().unwrap();
    let (da, db) = (d.path().join("a"), d.path().join("b"));
    let a = open(&da).await;
    fill_a(&a).await;
    let steps_a = Steps::new(&[]);
    let remote = serve(local_node(&a, &steps_a)).await;

    // node B: an empty mirror that follows osv, nvd and kev of A through the host's adapters
    let b = open(&db).await;
    let view: Arc<dyn secmonk_traits::MirrorView> = Arc::new(StoreMirrorView::new(b.clone()));
    let followed = Arc::new(FollowedSource::new(
        vec!["osv".into(), "nvd".into(), "kev".into()],
        remote.clone(),
        b.mirror_node_store(),
        view,
    ));
    let eb = engine(&b, Steps::new(&[]), followed);

    let job = run_sync(&eb, &["osv", "nvd", "kev"]).await;
    assert_eq!(job["status"], "ok", "{}", log_text(&job));
    for s in ["osv", "nvd"] {
        assert_same(&a, &b, s, &RECORD_TABLES).await;
    }
    assert_same(&a, &b, "kev", &[MirrorTable::Kev]).await;
    assert_eq!(dump(&b, MirrorTable::Affected, "osv").await.len(), 4);
    assert_eq!(dump(&b, MirrorTable::Kev, "kev").await.len(), 3);
    let versions_equal = |name: &'static str| {
        let (a, b) = (a.clone(), b.clone());
        async move {
            let (va, vb) = (version_of(&a, name).await, version_of(&b, name).await);
            assert_eq!(vb.version, va.version, "version of {name}");
            assert_eq!(vb.importer, va.importer, "importer of {name}");
            assert_eq!(vb.kind, va.kind, "kind of {name}");
            assert_eq!(vb.status.as_deref(), Some("ok"));
        }
    };
    for s in ["osv", "nvd", "kev"] {
        versions_equal(s).await;
    }
    assert_eq!(version_of(&b, "osv").await.importer, PY);
    assert_eq!(version_of(&b, "kev").await.importer, RS);

    // A changes: GHSA-1 is rewritten (a field, one alias removed, one of its affected rows removed), GHSA-3 is
    // new, GHSA-2 untouched; the KEV catalog loses CVE-9 and gains CVE-6
    a.apply_rows(&batch(
        "osv",
        2,
        json!([
            {"op": "delete", "table": "affected", "key": {"source": "osv", "vuln_id": "GHSA-1"}},
            {"op": "delete", "table": "alias", "key": {"vuln_id": "GHSA-1", "alias": "PYSEC-1", "source": "osv"}},
            vuln("osv", "GHSA-1", "2024-06-01T00:00:00Z", json!({"severity": "LOW", "summary": "rewritten"})),
            raw("osv", "GHSA-1", "2024-06-01T00:00:00Z"),
            vuln("osv", "GHSA-4", "2024-06-02T00:00:00Z", json!({})),
            raw("osv", "GHSA-4", "2024-06-02T00:00:00Z"),
            alias("osv", "GHSA-4", "CVE-4"),
            aff("osv", "GHSA-4", Some("npm"), Some("right-pad"), None),
            sync_row("osv", "ok", "2024-06-02T00:00:00Z"),
        ]),
    ))
    .await
    .unwrap();
    a.apply_rows(&batch(
        "kev",
        2,
        json!([
            {"op": "delete", "table": "kev", "key": {"cve_id": "CVE-9"}},
            kev_row("CVE-6"),
            sync_row("kev", "ok", "2026.03.01"),
        ]),
    ))
    .await
    .unwrap();
    publish(&a, "osv", "2024-06-02T00:00:00Z", PY, VersionKind::Record).await;
    publish(&a, "kev", "2026.03.01", RS, VersionKind::Snapshot).await;
    assert_ne!(
        dump(&a, MirrorTable::Vulnerability, "osv").await,
        dump(&b, MirrorTable::Vulnerability, "osv").await,
        "the change is visible on A only"
    );

    let job = run_sync(&eb, &["osv", "nvd", "kev"]).await;
    assert_eq!(job["status"], "ok", "{}", log_text(&job));
    for s in ["osv", "nvd"] {
        assert_same(&a, &b, s, &RECORD_TABLES).await;
    }
    assert_same(&a, &b, "kev", &[MirrorTable::Kev]).await;
    // the shape of the change, not only the equality
    assert_eq!(
        dump(&b, MirrorTable::Affected, "osv").await.len(),
        4,
        "GHSA-1 lost one of its two identical rows on A; B has the record as A has it"
    );
    assert_eq!(
        dump(&b, MirrorTable::Alias, "osv").await.len(),
        2,
        "CVE-1 and CVE-4; PYSEC-1 removed"
    );
    let kev_ids: BTreeSet<String> = dump(&b, MirrorTable::Kev, "kev")
        .await
        .iter()
        .map(|r| {
            serde_json::from_str::<Value>(r).unwrap()["cve_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(
        kev_ids,
        BTreeSet::from(["CVE-1".to_owned(), "CVE-5".into(), "CVE-6".into()])
    );
    for s in ["osv", "nvd", "kev"] {
        versions_equal(s).await;
    }
    assert_eq!(
        version_of(&b, "osv").await.version.as_deref(),
        Some("2024-06-02T00:00:00Z")
    );
    assert_eq!(
        version_of(&b, "kev").await.version.as_deref(),
        Some("2026.03.01")
    );

    // a third run with nothing new changes nothing
    let before = dump(&b, MirrorTable::Vulnerability, "osv").await;
    let job = run_sync(&eb, &["osv", "nvd", "kev"]).await;
    assert_eq!(job["status"], "ok", "{}", log_text(&job));
    assert_eq!(dump(&b, MirrorTable::Vulnerability, "osv").await, before);
    assert_same(&a, &b, "osv", &RECORD_TABLES).await;
}

// ------------------------------------------------------------------------------------------------ 3. incremental

/// An engine step set whose matches depend on the mirror: a persisted match of an asset reads its current
/// components from state and matches each by exact (ecosystem, package) against the osv `affected` rows; the KEV
/// catalog and the vulnerability's severity come from the mirror at match time.
struct MirrorSteps {
    store: Arc<SqliteStore>,
}

fn wire<E: std::fmt::Display>(e: E) -> WireError {
    WireError::new(ErrorCode::Internal, format!("StoreError: {e}"))
}

impl MirrorSteps {
    async fn rows(&self, table: MirrorTable, source: &str) -> StepResult<Vec<Map<String, Value>>> {
        let mut out = Vec::new();
        let mut after = None;
        loop {
            let (rows, next) = self
                .store
                .rows_page(table, source, after, 500)
                .await
                .map_err(wire)?;
            out.extend(rows);
            match next {
                Some(n) => after = Some(n),
                None => return Ok(out),
            }
        }
    }

    /// The complete finding set of an asset on the mirror as it is now.
    async fn full(&self, asset: &str) -> StepResult<(Vec<Finding>, Option<i64>)> {
        let latest = self.store.latest_scan_id(asset).await.map_err(wire)?;
        let comps = self.store.current_components(asset).await.map_err(wire)?;
        let affected = self.rows(MirrorTable::Affected, "osv").await?;
        let sev: BTreeMap<String, Option<String>> = self
            .rows(MirrorTable::Vulnerability, "osv")
            .await?
            .into_iter()
            .map(|r| {
                (
                    r["id"].as_str().unwrap().to_owned(),
                    r.get("severity").and_then(Value::as_str).map(str::to_owned),
                )
            })
            .collect();
        let kev: BTreeSet<String> = self
            .rows(MirrorTable::Kev, "kev")
            .await?
            .into_iter()
            .filter_map(|r| r["cve_id"].as_str().map(str::to_owned))
            .collect();
        let text = |r: &Map<String, Value>, k: &str| {
            r.get(k).and_then(Value::as_str).map(str::to_lowercase)
        };
        let mut found: BTreeMap<(i64, String), Finding> = BTreeMap::new();
        for c in &comps {
            let (Some(eco), name) = (&c.component.ecosystem, &c.component.name) else {
                continue;
            };
            for r in &affected {
                if text(r, "ecosystem") != Some(eco.to_lowercase())
                    || text(r, "package") != Some(name.to_lowercase())
                {
                    continue;
                }
                let id = r["vuln_id"].as_str().unwrap().to_owned();
                if !sev.contains_key(&id) {
                    continue; // an affected row without its record: nothing to report
                }
                let is_kev = kev.contains(&id);
                found.insert(
                    (c.id, id.clone()),
                    serde_json::from_value(json!({
                        "component_id": c.id, "vuln_id": id, "advisory_ids": [id],
                        "matched_by": "osv-package", "confidence": 1.0, "severity": sev[&id],
                        "kev": is_kev, "priority": if is_kev { "P1" } else { "P3" }, "status": "open",
                        "first_seen": "t0", "last_seen": "t1",
                    }))
                    .unwrap(),
                );
            }
        }
        Ok((found.into_values().collect(), latest))
    }
}

#[async_trait]
impl Classifier for MirrorSteps {
    async fn classify(&self, c: Vec<Component>, _: CallCtx) -> StepResult<Vec<Component>> {
        Ok(c)
    }
}

#[async_trait]
impl Matcher for MirrorSteps {
    async fn match_asset(&self, params: MatchParams, _: CallCtx) -> StepResult<MatchResult> {
        let MatchParams::Persisted { asset_id, .. } = params else {
            return Err(WireError::new(
                ErrorCode::InvalidParams,
                "persisted matches only",
            ));
        };
        let (set, latest) = self.full(&asset_id).await?;
        Ok(MatchResult {
            asset_id,
            mode: MatchMode::Persisted,
            stats: MatchStats {
                findings: set.len() as u64,
                matches: set.len() as u64,
                ..Default::default()
            },
            based_on: Some(BasedOn {
                latest_scan_id: latest,
                mirror_synced_at: None,
            }),
            finding_set: Some(set),
            view: vec![],
        })
    }
}

#[async_trait]
impl Reporter for MirrorSteps {
    fn methods(&self) -> Vec<String> {
        vec![]
    }
    async fn report(&self, method: &str, _: Value, _: CallCtx) -> StepResult<Value> {
        Err(WireError::new(ErrorCode::UnknownMethod, method.to_owned()))
    }
}

#[async_trait]
impl VersionOracle for MirrorSteps {
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
        Ok("P3".into())
    }
}

/// A source whose next run is whatever `scripts` holds (a batch list per source name).
struct ScriptSource {
    scripts: Mutex<BTreeMap<String, Vec<RowsBatch>>>,
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
        p: secmonk_traits::SyncParams,
        _: CallCtx,
    ) -> StepResult<ResultStream<RowsBatch, secmonk_traits::SyncEnd>> {
        let batches = self
            .scripts
            .lock()
            .unwrap()
            .remove(&p.source)
            .ok_or_else(|| WireError::new(ErrorCode::UnknownSource, "nothing scripted"))?;
        let end: secmonk_traits::SyncEnd = serde_json::from_value(json!({
            "entry": {"source": p.source, "status": "ok", "records": 1, "seconds": 0.0, "message": null},
            "batches": batches.len(), "last_seq": batches.last().map_or(0, |b| b.seq), "ops": 0,
        }))
        .unwrap();
        let mut msgs: Vec<StepResult<StreamMsg<RowsBatch, secmonk_traits::SyncEnd>>> = batches
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
}

fn component(name: &str, eco: &str) -> Component {
    Component {
        name: name.into(),
        version: Some("1.0".into()),
        category: Category::Library,
        purl: Some(format!("pkg:{}/{name}@1.0", eco.to_lowercase())),
        cpe: None,
        vendor: None,
        ecosystem: Some(eco.into()),
        source_path: None,
        meta: Default::default(),
    }
}

fn inventory(asset: &str, comps: &[(&str, &str)]) -> Inventory {
    serde_json::from_value(json!({
        "schema": "secmonk-inventory/1", "classified": true,
        "asset": {"id": asset, "type": "directory", "name": asset},
        "collector": "fs", "components": comps.iter().map(|(n, e)| component(n, e)).collect::<Vec<_>>(),
        "warnings": [],
    }))
    .unwrap()
}

/// What a finding is, without the timestamps: (component id, vuln, severity, kev, priority, status).
fn essence(set: &[Finding]) -> BTreeSet<String> {
    set.iter()
        .map(|f| {
            format!(
                "{}|{}|{:?}|{}|{:?}|{}",
                f.component_id,
                f.vuln_id,
                f.severity,
                f.kev,
                f.priority,
                f.status.as_str()
            )
        })
        .collect()
}

/// Stored findings of every asset against a fresh full match of every asset on the mirror as it is now.
async fn assert_incremental_equals_full(
    store: &Arc<SqliteStore>,
    steps: &MirrorSteps,
    step: &str,
) -> usize {
    let mut total = 0;
    for asset in store.asset_ids().await.unwrap() {
        let (fresh, _) = steps.full(&asset).await.unwrap();
        let stored = store.asset_findings(&asset).await.unwrap();
        assert_eq!(
            essence(&stored),
            essence(&fresh),
            "{step}: findings of {asset}"
        );
        total += stored.len();
    }
    total
}

#[tokio::test]
async fn the_incremental_rematch_equals_a_full_match_after_every_change() {
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    let steps = Arc::new(MirrorSteps {
        store: store.clone(),
    });
    let src = Arc::new(ScriptSource {
        scripts: Mutex::new(BTreeMap::new()),
    });
    let e = engine(&store, steps.clone(), src.clone());
    // three assets over two ecosystems; `dir:/c` holds nothing any batch touches
    for (id, comps) in [
        ("dir:/a", vec![("requests", "PyPI"), ("flask", "PyPI")]),
        ("dir:/b", vec![("flask", "PyPI"), ("left-pad", "npm")]),
        ("dir:/c", vec![("left-pad", "npm"), ("click", "PyPI")]),
    ] {
        store
            .save_inventory(&inventory(id, &comps), None)
            .await
            .unwrap();
    }
    let script = |source: &str, seq: u64, ops: Value| {
        src.scripts
            .lock()
            .unwrap()
            .insert(source.into(), vec![batch(source, seq, ops)]);
    };
    let sync = |names: &'static [&'static str]| {
        let e = e.clone();
        async move {
            let job = run_sync(&e, names).await;
            assert_eq!(job["status"], "ok", "{}", log_text(&job));
            log_text(&job)
        }
    };

    // initial import: every asset is matched (a source new to the node)
    script(
        "osv",
        1,
        json!([
            vuln(
                "osv",
                "CVE-2024-0001",
                "2024-02-01T10:00:00Z",
                json!({"severity": "HIGH"})
            ),
            aff("osv", "CVE-2024-0001", Some("PyPI"), Some("requests"), None),
            vuln(
                "osv",
                "GHSA-L",
                "2024-02-02T10:00:00Z",
                json!({"severity": "LOW"})
            ),
            aff("osv", "GHSA-L", Some("npm"), Some("left-pad"), None),
            // the high-water mark is two hours past the last record: the overlap hour of the next delta skips it
            sync_row("osv", "ok", "2024-02-02T12:00:00Z"),
        ]),
    );
    script(
        "kev",
        1,
        json!([
            kev_row("CVE-2024-0001"),
            kev_row("CVE-9"),
            sync_row("kev", "ok", "k1")
        ]),
    );
    let log = sync(&["kev", "osv"]).await;
    let n = assert_incremental_equals_full(&store, &steps, "initial").await;
    assert_eq!(n, 3, "requests (a) + left-pad (b, c): {log}");
    let kev_of = |set: &[Finding], id: &str| set.iter().find(|f| f.vuln_id == id).map(|f| f.kev);
    let fa = store.asset_findings("dir:/a").await.unwrap();
    assert_eq!(kev_of(&fa, "CVE-2024-0001"), Some(true));

    // batch 1: a new vulnerability affecting flask (assets a and b, not c)
    script(
        "osv",
        2,
        json!([
            vuln(
                "osv",
                "CVE-2024-0002",
                "2024-05-01T10:00:00Z",
                json!({"severity": "MEDIUM"})
            ),
            aff("osv", "CVE-2024-0002", Some("PyPI"), Some("flask"), None),
            sync_row("osv", "ok", "2024-05-01T12:00:00Z"),
        ]),
    );
    let log = sync(&["osv"]).await;
    let n = assert_incremental_equals_full(&store, &steps, "batch 1: a vulnerability added").await;
    assert_eq!(n, 5, "two new findings: {log}");
    assert!(
        log.contains("2 of 3 asset(s) re-matched"),
        "only the flask assets: {log}"
    );
    let fb = store.asset_findings("dir:/b").await.unwrap();
    assert!(kev_of(&fb, "CVE-2024-0002") == Some(false));

    // batch 2: the record of CVE-2024-0001 loses its affected row (the record is rewritten, so it is a change)
    script(
        "osv",
        3,
        json!([
            {"op": "delete", "table": "affected", "key": {"source": "osv", "vuln_id": "CVE-2024-0001"}},
            vuln("osv", "CVE-2024-0001", "2024-06-01T10:00:00Z", json!({"severity": "HIGH"})),
            sync_row("osv", "ok", "2024-06-01T12:00:00Z"),
        ]),
    );
    let log = sync(&["osv"]).await;
    let n =
        assert_incremental_equals_full(&store, &steps, "batch 2: an affected row removed").await;
    assert_eq!(n, 4, "requests lost its finding: {log}");
    assert_eq!(
        kev_of(
            &store.asset_findings("dir:/a").await.unwrap(),
            "CVE-2024-0001"
        ),
        None
    );

    // batch 3: the KEV catalog changes: CVE-2024-0002 (flask) is added, CVE-2024-0001 and CVE-9 are dropped
    script(
        "kev",
        2,
        json!([
            {"op": "delete", "table": "kev", "key": {"cve_id": "CVE-2024-0001"}},
            {"op": "delete", "table": "kev", "key": {"cve_id": "CVE-9"}},
            kev_row("CVE-2024-0002"),
            sync_row("kev", "ok", "k2"),
        ]),
    );
    let log = sync(&["kev"]).await;
    let n = assert_incremental_equals_full(&store, &steps, "batch 3: a KEV entry changed").await;
    assert_eq!(n, 4, "{log}");
    for asset in ["dir:/a", "dir:/b"] {
        let set = store.asset_findings(asset).await.unwrap();
        assert_eq!(
            kev_of(&set, "CVE-2024-0002"),
            Some(true),
            "{asset} flask finding is KEV now"
        );
        let f = set.iter().find(|f| f.vuln_id == "CVE-2024-0002").unwrap();
        assert_eq!(f.priority.as_deref(), Some("P1"));
    }

    // and a batch that changes a record nobody has installed re-matches nothing
    script(
        "osv",
        4,
        json!([
            vuln("osv", "GHSA-X", "2024-07-01T10:00:00Z", json!({})),
            aff("osv", "GHSA-X", Some("PyPI"), Some("unused"), None),
            sync_row("osv", "ok", "2024-07-01T12:00:00Z"),
        ]),
    );
    let log = sync(&["osv"]).await;
    assert_incremental_equals_full(&store, &steps, "batch 4: an unrelated record").await;
    assert!(
        !log.contains("re-matched") || log.contains("0 of 3 asset(s) re-matched"),
        "{log}"
    );
}
