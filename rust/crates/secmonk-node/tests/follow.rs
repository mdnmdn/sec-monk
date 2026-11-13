//! `FeedSource` over a scripted feed, a fake mirror view and a fake localizer.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures_util::StreamExt;
use secmonk_model::node::{
    FeedMode, FeedPage, FeedSinceRequest, FeedStatus, MATCHER_VERSION, SourceVersion, VersionKind,
};
use secmonk_model::{JsonMap, MirrorTable, RowOp, RowsBatch, SyncOptions, SyncParams};
use secmonk_node::{BatchLocalizer, FeedSource};
use secmonk_traits::node::Feed;
use secmonk_traits::{
    AppliedMark, CallCtx, ErrorCode, MirrorView, NATIVE_GENERATION, RowPage, Source, StepResult,
    StreamMsg, SyncEnd, WireError,
};
use serde_json::{Value, json};

fn obj(v: Value) -> JsonMap {
    v.as_object().cloned().unwrap()
}

fn up(table: MirrorTable, row: Value) -> RowOp {
    RowOp::Upsert {
        table,
        row: obj(row),
    }
}

fn del(table: MirrorTable, key: Value) -> RowOp {
    RowOp::Delete {
        table,
        key: obj(key),
    }
}

fn batch(seq: u64, source: &str, ops: Vec<RowOp>) -> RowsBatch {
    RowsBatch {
        kind: "rows".into(),
        seq,
        source: source.into(),
        ops,
        generation: None,
        acked_through: None,
    }
}

fn sv(source: &str, version: &str, kind: VersionKind, importer: &str) -> SourceVersion {
    SourceVersion {
        source: source.into(),
        version: Some(version.into()),
        importer: importer.into(),
        kind,
        records: 42,
        last_sync: None,
        status: Some("ok".into()),
    }
}

fn page(
    source: &str,
    version: &str,
    mode: FeedMode,
    batches: Vec<RowsBatch>,
    next: Option<&str>,
) -> FeedPage {
    let kind = if mode == FeedMode::Delta {
        VersionKind::Record
    } else {
        VersionKind::Snapshot
    };
    FeedPage {
        source: source.into(),
        version: sv(source, version, kind, "py-sources/1"),
        mode,
        batches,
        next_page: next.map(Into::into),
    }
}

struct ScriptedFeed {
    pages: Mutex<VecDeque<StepResult<FeedPage>>>,
    requests: Mutex<Vec<FeedSinceRequest>>,
}

impl ScriptedFeed {
    fn new(pages: Vec<StepResult<FeedPage>>) -> Arc<ScriptedFeed> {
        Arc::new(ScriptedFeed {
            pages: Mutex::new(pages.into()),
            requests: Mutex::new(vec![]),
        })
    }
}

#[async_trait]
impl Feed for ScriptedFeed {
    async fn status(&self) -> StepResult<FeedStatus> {
        Ok(FeedStatus {
            node_id: None,
            matcher: MATCHER_VERSION.into(),
            sources: vec![],
        })
    }
    async fn since(&self, req: FeedSinceRequest) -> StepResult<FeedPage> {
        self.requests.lock().unwrap().push(req);
        self.pages
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or_else(|| Err(WireError::internal("Test", "no more pages")))
    }
}

#[derive(Default)]
struct FakeView {
    applied: Option<AppliedMark>,
    keys: Vec<(MirrorTable, JsonMap)>,
}

#[async_trait]
impl MirrorView for FakeView {
    async fn applied(&self, _source: &str) -> StepResult<Option<AppliedMark>> {
        Ok(self.applied.clone())
    }
    async fn count_rows(&self, table: MirrorTable, _source: &str) -> StepResult<u64> {
        Ok(self.keys.iter().filter(|(t, _)| *t == table).count() as u64)
    }
    async fn row_keys(&self, table: MirrorTable, _source: &str) -> StepResult<Vec<JsonMap>> {
        Ok(self
            .keys
            .iter()
            .filter(|(t, _)| *t == table)
            .map(|(_, k)| k.clone())
            .collect())
    }
    async fn rows_by_id(&self, _: MirrorTable, _: &str, _: &[String]) -> StepResult<Vec<JsonMap>> {
        Err(WireError::internal("Test", "unused"))
    }
    async fn rows_page(
        &self,
        _: MirrorTable,
        _: &str,
        _: Option<u64>,
        _: usize,
    ) -> StepResult<RowPage> {
        Err(WireError::internal("Test", "unused"))
    }
}

/// Expands the `delete affected {source, vuln_id}` marker into `fan` deletes of fake rows; copies the rest.
struct FakeLocalizer {
    fan: usize,
}

#[async_trait]
impl BatchLocalizer for FakeLocalizer {
    async fn localize(&self, b: &RowsBatch) -> StepResult<Vec<RowOp>> {
        let mut out = Vec::new();
        for op in &b.ops {
            match op {
                RowOp::Delete {
                    table: MirrorTable::Affected,
                    key,
                } => {
                    for i in 0..self.fan {
                        let mut k = key.clone();
                        k.insert("package".into(), json!(format!("p{i}")));
                        out.push(RowOp::Delete {
                            table: MirrorTable::Affected,
                            key: k,
                        });
                    }
                }
                other => out.push(other.clone()),
            }
        }
        Ok(out)
    }
}

fn source(feed: Arc<ScriptedFeed>, view: FakeView, fan: usize, local: Option<&str>) -> FeedSource {
    let local = local.map(str::to_owned);
    FeedSource::new(
        vec!["nvd".into(), "kev".into()],
        feed,
        Arc::new(view),
        Arc::new(FakeLocalizer { fan }),
        Arc::new(move |_| local.clone()),
    )
}

fn params(source: &str, full: bool) -> SyncParams {
    SyncParams {
        source: source.into(),
        options: SyncOptions {
            full: full.then_some(true),
            ..SyncOptions::default()
        },
        secrets: None,
    }
}

async fn run(s: &FeedSource, p: SyncParams) -> StepResult<(Vec<RowsBatch>, SyncEnd)> {
    let mut st = s.sync(p, CallCtx::default()).await?;
    let (mut items, mut end) = (vec![], None);
    while let Some(m) = st.next().await {
        match m? {
            StreamMsg::Item(b) => items.push(b),
            StreamMsg::End(e) => end = Some(e),
        }
    }
    assert!(end.is_some(), "a stream ends with its End");
    Ok((items, end.unwrap()))
}

fn replace_unit(id: &str) -> Vec<RowOp> {
    vec![
        del(
            MirrorTable::Affected,
            json!({"source": "nvd", "vuln_id": id}),
        ),
        up(
            MirrorTable::Vulnerability,
            json!({"source": "nvd", "id": id, "modified": "2026-11-02T00:00:00Z"}),
        ),
        up(
            MirrorTable::RawRecord,
            json!({"source": "nvd", "record_id": id, "data": {}}),
        ),
        up(
            MirrorTable::Affected,
            json!({"source": "nvd", "vuln_id": id, "ecosystem": "x", "package": "p"}),
        ),
    ]
}

fn sync_row(b: &RowsBatch) -> &JsonMap {
    match b.ops.last().unwrap() {
        RowOp::Upsert {
            table: MirrorTable::SourceSync,
            row,
        } => row,
        other => panic!("not the source_sync row: {other:?}"),
    }
}

#[tokio::test]
async fn delta_pages_are_localized_renumbered_and_recut() {
    let feed = ScriptedFeed::new(vec![
        Ok(page(
            "nvd",
            "2026-11-02T00:00:00Z",
            FeedMode::Delta,
            vec![batch(1, "nvd", replace_unit("CVE-1"))],
            Some("c1"),
        )),
        Ok(page(
            "nvd",
            "2026-11-03T00:00:00Z",
            FeedMode::Delta,
            vec![batch(1, "nvd", replace_unit("CVE-2"))],
            None,
        )),
    ]);
    let view = FakeView {
        applied: Some(AppliedMark {
            seq: 40,
            generation: Some(NATIVE_GENERATION.into()),
        }),
        ..FakeView::default()
    };
    // each marker fans out to 4000 deletes: 2 x (4000 + 3) + the source_sync row = 8007 ops in batches of <= 5000
    let s = source(feed.clone(), view, 4000, Some("2026-11-01T00:00:00Z"));
    let (batches, end) = run(&s, params("nvd", false)).await.unwrap();

    assert_eq!(
        batches.iter().map(|b| b.ops.len()).collect::<Vec<_>>(),
        vec![5000, 3007]
    );
    assert_eq!(
        batches.iter().map(|b| b.seq).collect::<Vec<_>>(),
        vec![41, 42],
        "continues the applied native seq"
    );
    assert!(batches.iter().all(|b| b.source == "nvd"
        && b.generation.as_deref() == Some(NATIVE_GENERATION)
        && b.acked_through.is_none()
        && b.kind == "rows"));
    let deletes = batches
        .iter()
        .flat_map(|b| &b.ops)
        .filter(|o| matches!(o, RowOp::Delete { .. }))
        .count();
    assert_eq!(
        deletes, 8000,
        "markers were replaced by the localized deletes"
    );

    // the run's source_sync row carries the version of the FIRST page and the upstream's record count
    let row = sync_row(&batches[1]);
    assert_eq!(row["cursor"], "2026-11-02T00:00:00Z");
    assert_eq!(row["status"], "ok");
    assert_eq!(row["records"], 42);
    assert_eq!(row["source"], "nvd");
    assert_eq!(
        (
            end.entry.status.as_str(),
            end.entry.records,
            end.batches,
            end.last_seq,
            end.ops
        ),
        ("ok", 2, 2, 42, 8007)
    );
    assert!(
        end.entry
            .message
            .unwrap()
            .contains("py-sources/1@2026-11-02T00:00:00Z")
    );

    // requests: the local version and the cursor of the previous page
    let reqs = feed.requests.lock().unwrap().clone();
    assert_eq!(reqs.len(), 2);
    assert_eq!(
        (
            reqs[0].source.as_str(),
            reqs[0].since.as_deref(),
            reqs[0].page.as_deref()
        ),
        ("nvd", Some("2026-11-01T00:00:00Z"), None)
    );
    assert_eq!(
        (reqs[1].since.as_deref(), reqs[1].page.as_deref()),
        (Some("2026-11-01T00:00:00Z"), Some("c1"))
    );
    assert_eq!(s.upstream_importer("nvd").as_deref(), Some("py-sources/1"));
    assert_eq!(s.importer_version("nvd").as_deref(), Some("py-sources/1"));
    assert_eq!(s.upstream_importer("kev"), None);
}

#[tokio::test]
async fn seq_starts_at_one_after_another_generation_and_full_ignores_the_local_version() {
    let feed = ScriptedFeed::new(vec![Ok(page(
        "nvd",
        "v",
        FeedMode::Delta,
        vec![batch(1, "nvd", replace_unit("CVE-1"))],
        None,
    ))]);
    let view = FakeView {
        applied: Some(AppliedMark {
            seq: 99,
            generation: Some("py-gen".into()),
        }),
        ..FakeView::default()
    };
    let s = source(feed.clone(), view, 1, Some("old"));
    let (batches, _) = run(&s, params("nvd", true)).await.unwrap();
    assert_eq!(batches[0].seq, 1);
    assert_eq!(feed.requests.lock().unwrap()[0].since, None);
}

#[tokio::test]
async fn small_limits_cut_more_batches() {
    let feed = ScriptedFeed::new(vec![Ok(page(
        "nvd",
        "v",
        FeedMode::Delta,
        vec![batch(1, "nvd", replace_unit("CVE-1"))],
        None,
    ))]);
    let s = source(feed, FakeView::default(), 1, None).with_limits(2, usize::MAX);
    let (batches, end) = run(&s, params("nvd", false)).await.unwrap();
    assert_eq!(
        batches.iter().map(|b| b.ops.len()).collect::<Vec<_>>(),
        vec![2, 2, 1]
    );
    assert_eq!((end.batches, end.last_seq), (3, 3));
}

fn kev_row(id: &str) -> RowOp {
    up(
        MirrorTable::Kev,
        json!({"cve_id": id, "source": "kev", "name": "n"}),
    )
}

fn stored_kev(ids: &[&str]) -> FakeView {
    FakeView {
        keys: ids
            .iter()
            .map(|i| (MirrorTable::Kev, obj(json!({"cve_id": i}))))
            .collect(),
        ..FakeView::default()
    }
}

#[tokio::test]
async fn snapshot_pages_replace_everything_of_the_source() {
    let raw = up(
        MirrorTable::RawRecord,
        json!({"source": "kev", "record_id": "CVE-1", "data": {}}),
    );
    let feed = ScriptedFeed::new(vec![
        Ok(page(
            "kev",
            "2026.11.01",
            FeedMode::Snapshot,
            vec![batch(1, "kev", vec![raw, kev_row("CVE-1")])],
            Some("c"),
        )),
        Ok(page(
            "kev",
            "2026.11.01",
            FeedMode::Snapshot,
            vec![batch(1, "kev", vec![kev_row("CVE-2")])],
            None,
        )),
    ]);
    // stored: CVE-1, CVE-2 and CVE-OLD, which left the snapshot
    let s = source(
        feed.clone(),
        stored_kev(&["CVE-1", "CVE-2", "CVE-OLD"]),
        1,
        Some("2026.10.01"),
    );
    let (batches, end) = run(&s, params("kev", false)).await.unwrap();
    let ops: Vec<&RowOp> = batches.iter().flat_map(|b| &b.ops).collect();
    // upserts first, then the delete of the stale key, then the source_sync row; the delta localizer was not used
    assert_eq!(ops.len(), 5);
    assert!(
        matches!(ops[3], RowOp::Delete { table: MirrorTable::Kev, key } if key["cve_id"] == "CVE-OLD")
    );
    assert_eq!(
        ops.iter()
            .filter(|o| matches!(o, RowOp::Delete { .. }))
            .count(),
        1
    );
    let row = sync_row(batches.last().unwrap());
    assert_eq!(
        (row["cursor"].as_str(), row["status"].as_str()),
        (Some("2026.11.01"), Some("ok"))
    );
    assert_eq!(end.entry.status, "ok");
    assert_eq!(end.entry.records, 2, "kev rows, not raw_record");
    assert_eq!(feed.requests.lock().unwrap()[1].page.as_deref(), Some("c"));
}

#[tokio::test]
async fn the_snapshot_guard_refuses_a_shrunk_snapshot_unless_full() {
    let mk = || {
        ScriptedFeed::new(vec![Ok(page(
            "kev",
            "v2",
            FeedMode::Snapshot,
            vec![batch(1, "kev", vec![kev_row("CVE-1")])],
            None,
        ))])
    };
    let many = ["CVE-1", "CVE-2", "CVE-3", "CVE-4"];
    let s = source(mk(), stored_kev(&many), 1, None);
    let (batches, end) = run(&s, params("kev", false)).await.unwrap();
    assert_eq!(end.entry.status, "error");
    assert!(
        end.entry
            .message
            .unwrap()
            .contains("refusing to replace 4 kev rows")
    );
    assert!(
        batches
            .iter()
            .flat_map(|b| &b.ops)
            .all(|o| !matches!(o, RowOp::Delete { .. })),
        "nothing deleted"
    );
    let row = sync_row(batches.last().unwrap());
    assert_eq!(row["status"], "error");
    assert!(
        !row.contains_key("cursor"),
        "the version does not move on an error"
    );

    let s = source(mk(), stored_kev(&many), 1, None);
    let (batches, end) = run(&s, params("kev", true)).await.unwrap();
    assert_eq!(end.entry.status, "ok");
    assert_eq!(
        batches
            .iter()
            .flat_map(|b| &b.ops)
            .filter(|o| matches!(o, RowOp::Delete { .. }))
            .count(),
        3
    );

    // an empty snapshot over stored rows
    let empty = ScriptedFeed::new(vec![Ok(page(
        "kev",
        "v2",
        FeedMode::Snapshot,
        vec![],
        None,
    ))]);
    let (_, end) = run(
        &source(empty, stored_kev(&["CVE-1"]), 1, None),
        params("kev", false),
    )
    .await
    .unwrap();
    assert_eq!(end.entry.status, "error");
    assert!(end.entry.message.unwrap().contains("empty snapshot"));
}

#[tokio::test]
async fn upstream_failures_end_the_run_with_an_error_entry() {
    // unreachable before any page
    let feed = ScriptedFeed::new(vec![Err(WireError::new(
        ErrorCode::HostUnreachable,
        "connection refused",
    ))]);
    let s = source(feed, FakeView::default(), 1, None);
    let (batches, end) = run(&s, params("nvd", false)).await.unwrap();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].ops.len(), 1);
    let row = sync_row(&batches[0]);
    assert_eq!(row["status"], "error");
    assert!(
        row["message"]
            .as_str()
            .unwrap()
            .contains("connection refused")
    );
    assert_eq!((end.entry.status.as_str(), end.batches), ("error", 1));

    // fails on the second page: the first page's batches were streamed, the version does not move
    let feed = ScriptedFeed::new(vec![
        Ok(page(
            "nvd",
            "v",
            FeedMode::Delta,
            vec![batch(1, "nvd", replace_unit("CVE-1"))],
            Some("c"),
        )),
        Err(WireError::new(ErrorCode::Timeout, "slow")),
    ]);
    let (batches, end) = run(
        &source(feed, FakeView::default(), 1, None),
        params("nvd", false),
    )
    .await
    .unwrap();
    assert_eq!(end.entry.status, "error");
    assert!(!sync_row(batches.last().unwrap()).contains_key("cursor"));

    // a page for another source, and a repeated cursor
    let feed = ScriptedFeed::new(vec![Ok(page("osv", "v", FeedMode::Delta, vec![], None))]);
    let (_, end) = run(
        &source(feed, FakeView::default(), 1, None),
        params("nvd", false),
    )
    .await
    .unwrap();
    assert!(end.entry.message.unwrap().contains("answered for source"));
    let feed = ScriptedFeed::new(vec![
        Ok(page("nvd", "v", FeedMode::Delta, vec![], Some("c"))),
        Ok(page("nvd", "v", FeedMode::Delta, vec![], Some("c"))),
    ]);
    let (_, end) = run(
        &source(feed, FakeView::default(), 1, None),
        params("nvd", false),
    )
    .await
    .unwrap();
    assert!(
        end.entry
            .message
            .unwrap()
            .contains("repeated its page cursor")
    );

    // affected rows cannot be diffed in a snapshot
    let aff = up(
        MirrorTable::Affected,
        json!({"source": "kev", "vuln_id": "x"}),
    );
    let feed = ScriptedFeed::new(vec![Ok(page(
        "kev",
        "v",
        FeedMode::Snapshot,
        vec![batch(1, "kev", vec![aff])],
        None,
    ))]);
    let (_, end) = run(
        &source(feed, FakeView::default(), 1, None),
        params("kev", false),
    )
    .await
    .unwrap();
    assert_eq!(end.entry.status, "error");
}

#[tokio::test]
async fn source_trait_surface() {
    let s = source(ScriptedFeed::new(vec![]), FakeView::default(), 1, None);
    assert!(s.native());
    assert_eq!(
        s.sources()
            .iter()
            .map(|i| i.name.as_str())
            .collect::<Vec<_>>(),
        vec!["nvd", "kev"]
    );
    assert!(s.ack("nvd", 1, CallCtx::default()).await.is_ok());
    assert_eq!(
        s.export("nvd", CallCtx::default())
            .await
            .err()
            .unwrap()
            .code,
        ErrorCode::UnknownMethod
    );
    let e = s
        .sync(params("osv", false), CallCtx::default())
        .await
        .err()
        .unwrap();
    assert_eq!(e.code, ErrorCode::UnknownSource);
}
