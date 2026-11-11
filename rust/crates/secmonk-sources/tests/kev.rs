//! The native KEV source over a fake mirror view: rows, deletes, snapshot guard, limit, seqs, errors, downloads
//! (a local HTTP server, never the network). Fixture: `tests/fixtures/sources/kev` of the repository (read only).
//! The comparison with the Python source is `secmonk-engine/tests/real_modules.rs` (differential test).

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use common::{of, ops, serve, serve_raw};
use secmonk_model::{JsonMap, MirrorTable, RowOp};
use secmonk_sources::batch::Limits;
use secmonk_sources::kev::KevSource;
use secmonk_traits::{
    AppliedMark, CallCtx, ErrorCode, MirrorView, NATIVE_GENERATION, RowsBatch, Source, StepResult,
    SyncEnd, SyncParams,
};
use serde_json::{Value, json};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/fixtures/sources/kev/known_exploited_vulnerabilities.json")
}

#[derive(Default)]
struct FakeView {
    applied: Option<AppliedMark>,
    keys: Vec<String>,
}

#[async_trait]
impl MirrorView for FakeView {
    async fn applied(&self, _: &str) -> StepResult<Option<AppliedMark>> {
        Ok(self.applied.clone())
    }
    async fn count_rows(&self, t: MirrorTable, s: &str) -> StepResult<u64> {
        assert_eq!((t, s), (MirrorTable::Kev, "kev"));
        Ok(self.keys.len() as u64)
    }
    async fn row_keys(&self, t: MirrorTable, s: &str) -> StepResult<Vec<JsonMap>> {
        assert_eq!((t, s), (MirrorTable::Kev, "kev"));
        Ok(self
            .keys
            .iter()
            .map(|k| json!({"cve_id": k}).as_object().cloned().unwrap())
            .collect())
    }
    async fn rows_by_id(&self, _: MirrorTable, _: &str, _: &[String]) -> StepResult<Vec<JsonMap>> {
        panic!("kev reads keys only")
    }
    async fn rows_page(
        &self,
        _: MirrorTable,
        _: &str,
        _: Option<u64>,
        _: usize,
    ) -> StepResult<secmonk_traits::RowPage> {
        panic!("kev reads keys only")
    }
}

fn params(options: Value) -> SyncParams {
    common::params("kev", options)
}

async fn run(src: &KevSource, options: Value) -> (Vec<RowsBatch>, SyncEnd, Vec<String>) {
    common::run(src, "kev", options).await
}

fn view(v: FakeView) -> Arc<dyn MirrorView> {
    Arc::new(v)
}

#[tokio::test]
async fn a_snapshot_becomes_raw_kev_and_sync_rows() {
    let src = KevSource::new(view(FakeView::default()));
    let path = fixture().display().to_string();
    let (b, end, _) = run(&src, json!({"path": path})).await;
    assert_eq!(b.len(), 1);
    assert_eq!(b[0].seq, 1);
    assert_eq!(b[0].generation.as_deref(), Some(NATIVE_GENERATION));
    assert_eq!(b[0].acked_through, None);
    let all = ops(&b);
    assert_eq!(all.len(), 9 * 2 + 1);
    assert!(
        of(&all, MirrorTable::Kev, false).is_empty(),
        "nothing to delete"
    );
    let kev = of(&all, MirrorTable::Kev, true);
    let log4j = kev
        .iter()
        .find(|r| r["cve_id"] == "CVE-2021-44228")
        .unwrap();
    assert_eq!(log4j["vendor"], "Apache");
    assert_eq!(log4j["ransomware"], "1");
    assert_eq!(log4j["source"], "kev");
    assert_eq!(
        log4j["extra"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        vec![
            "shortDescription",
            "requiredAction",
            "forensicTriage",
            "notes",
            "cwes"
        ],
        "unmapped fields in feed order"
    );
    let raw = of(&all, MirrorTable::RawRecord, true);
    assert_eq!(raw.len(), 9);
    assert_eq!(raw[0]["modified"], raw[0]["data"]["dateAdded"]);
    let sync = &of(&all, MirrorTable::SourceSync, true)[0];
    assert_eq!(sync["cursor"], "2026.11.06");
    assert_eq!(sync["records"], 9);
    assert_eq!(sync["status"], "ok");
    assert!(matches!(
        all.last(),
        Some(RowOp::Upsert {
            table: MirrorTable::SourceSync,
            ..
        })
    ));
    assert_eq!(end.entry.status, "ok");
    assert_eq!(end.entry.records, 9);
    assert_eq!(
        end.entry.message.as_deref(),
        Some(format!("9 entries from file {path}").as_str())
    );
    assert_eq!((end.batches, end.last_seq, end.ops), (1, 1, 19));
}

#[tokio::test]
async fn cves_that_left_the_feed_are_deleted_and_seqs_continue_in_the_native_generation() {
    let v = FakeView {
        applied: Some(AppliedMark {
            seq: 7,
            generation: Some(NATIVE_GENERATION.into()),
        }),
        keys: vec!["CVE-2000-0001".into(), "CVE-2021-44228".into()],
    };
    let src = KevSource::new(view(v)).with_limits(Limits {
        ops: 4,
        bytes: 1 << 20,
    });
    let (b, end, _) = run(&src, json!({"path": fixture().display().to_string()})).await;
    assert_eq!(
        b.iter().map(|b| b.seq).collect::<Vec<_>>(),
        vec![8, 9, 10, 11, 12]
    );
    assert_eq!(end.last_seq, 12);
    let all = ops(&b);
    assert_eq!(
        of(&all, MirrorTable::Kev, false),
        vec![
            json!({"cve_id": "CVE-2000-0001"})
                .as_object()
                .cloned()
                .unwrap()
        ]
    );
    assert!(matches!(all[0], RowOp::Delete { .. }), "deletes come first");

    // an applied state of another generation (py-sources staging): the engine resets it before the sync, seqs restart at 1
    let v = FakeView {
        applied: Some(AppliedMark {
            seq: 7,
            generation: Some("0123456789abcdef".into()),
        }),
        keys: vec![],
    };
    let (b, ..) = run(
        &KevSource::new(view(v)),
        json!({"path": fixture().display().to_string()}),
    )
    .await;
    assert_eq!(b[0].seq, 1);
}

#[tokio::test]
async fn the_snapshot_guard_limit_and_full_behave_like_python() {
    let many: Vec<String> = (0..30).map(|i| format!("CVE-1999-{i:04}")).collect();
    let path = fixture().display().to_string();
    let src = KevSource::new(view(FakeView {
        applied: None,
        keys: many.clone(),
    }));
    let (b, end, _) = run(&src, json!({"path": path})).await;
    assert_eq!(end.entry.status, "error");
    assert_eq!(
        end.entry.message.as_deref(),
        Some(
            "kev: refusing to replace 30 rows with a snapshot of only 9 (< 50%; use --full to force)"
        )
    );
    let all = ops(&b);
    assert_eq!(all.len(), 1, "only the status row");
    let row = &of(&all, MirrorTable::SourceSync, true)[0];
    assert_eq!(
        row.keys().collect::<Vec<_>>(),
        vec!["source", "status", "message"],
        "an error keeps the last good totals"
    );

    let (b, end, _) = run(&src, json!({"path": path, "full": true})).await;
    assert_eq!(end.entry.status, "ok");
    assert_eq!(of(&ops(&b), MirrorTable::Kev, false).len(), 30);

    let (b, end, _) = run(&src, json!({"path": path, "limit": 3})).await;
    assert_eq!(end.entry.status, "partial");
    assert_eq!(end.entry.records, 3);
    let all = ops(&b);
    assert!(
        of(&all, MirrorTable::Kev, false).is_empty(),
        "a limited run never deletes"
    );
    assert_eq!(of(&all, MirrorTable::Kev, true).len(), 3);
    assert!(!of(&all, MirrorTable::SourceSync, true)[0].contains_key("cursor"));

    let d = tempfile::tempdir().unwrap();
    let empty = d.path().join("empty.json");
    std::fs::write(&empty, r#"{"count": 3, "vulnerabilities": []}"#).unwrap();
    let (_, end, lines) = run(
        &KevSource::new(view(FakeView::default())),
        json!({"path": empty}),
    )
    .await;
    assert_eq!(
        end.entry.message.as_deref(),
        Some("kev: refusing to replace the data with an empty snapshot (use --full to force)")
    );
    assert_eq!(lines, vec!["kev: feed count 3 != 0 entries; using entries"]);

    let err = KevSource::new(view(FakeView::default()))
        .sync(params(json!({"limit": 0})), CallCtx::default())
        .await
        .err()
        .unwrap();
    assert_eq!(err.code, ErrorCode::InvalidParams);
}

#[tokio::test]
async fn bad_input_is_an_error_entry_never_rows() {
    let d = tempfile::tempdir().unwrap();
    let src = KevSource::new(view(FakeView::default()));
    let missing = d.path().join("missing.json");
    let (b, end, _) = run(&src, json!({"path": missing})).await;
    assert_eq!(end.entry.status, "error");
    assert_eq!(
        end.entry.message,
        Some(format!(
            "[Errno 2] No such file or directory: '{}'",
            missing.display()
        ))
    );
    assert_eq!(ops(&b).len(), 1);
    for (doc, msg) in [
        (r#"{"title": "x"}"#, "'vulnerabilities'"),
        (r#"{"vulnerabilities": [{"product": "x"}]}"#, "'cveID'"),
        (
            r#"{"vulnerabilities": [{"cveID": "CVE-1", "product": ["x"]}]}"#,
            "kev: CVE-1: product is not a string",
        ),
        (
            r#"{"vulnerabilities": {"a": 1}}"#,
            "kev: 'vulnerabilities' is not a list",
        ),
        (
            r#"{"vulnerabilities": [1]}"#,
            "kev: an entry is not an object",
        ),
    ] {
        let f = d.path().join("doc.json");
        std::fs::write(&f, doc).unwrap();
        let (b, end, _) = run(&src, json!({"path": f})).await;
        assert_eq!(end.entry.status, "error", "{doc}");
        assert_eq!(end.entry.message.as_deref(), Some(msg), "{doc}");
        assert_eq!(ops(&b).len(), 1, "{doc}");
    }
    let err = src
        .sync(
            serde_json::from_value(json!({"source": "epss", "options": {}})).unwrap(),
            CallCtx::default(),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(err.code, ErrorCode::UnknownSource);
    assert!(src.export("kev", CallCtx::default()).await.is_err());
    src.ack("kev", 3, CallCtx::default()).await.unwrap();
    assert!(src.native());
    assert_eq!(src.sources()[0].name, "kev");
}

#[tokio::test]
async fn the_mirror_is_tried_when_the_official_feed_fails_and_downloads_are_capped() {
    let body = std::fs::read(fixture()).unwrap();
    let base = serve(vec![(500, b"oops".to_vec()), (200, body.clone())]).await;
    let (official, mirror) = (
        format!("{base}/official.json"),
        format!("{base}/mirror.json"),
    );
    let src = KevSource::new(view(FakeView::default())).with_urls(&official, &mirror);
    let (b, end, lines) = run(&src, json!({})).await;
    assert_eq!(end.entry.status, "ok", "{end:?}");
    assert_eq!(ops(&b).len(), 19);
    let msg = end.entry.message.unwrap();
    assert!(
        msg.starts_with(&format!(
            "9 entries from mirror {mirror} (official failed: HTTP 500"
        )),
        "{msg}"
    );
    assert!(
        lines.iter().any(|l| l.contains("official feed failed")),
        "{lines:?}"
    );

    let base = serve(vec![(200, body.clone()), (200, body)]).await;
    let src = KevSource::new(view(FakeView::default()))
        .with_urls(&format!("{base}/a"), &format!("{base}/b"))
        .with_max_bytes(100);
    let (b, end, _) = run(&src, json!({})).await;
    assert_eq!(end.entry.status, "error");
    assert!(end.entry.message.unwrap().contains("larger than 100 bytes"));
    assert_eq!(ops(&b).len(), 1);
}

#[tokio::test]
async fn the_size_cap_holds_without_a_trustworthy_content_length() {
    // review W6.5 L1: the cap is enforced while the body streams, not only against Content-Length
    use secmonk_sources::feed::download_json;
    let body = format!("\"{}\"", "x".repeat(200));
    // no Content-Length: the body ends when the connection closes
    let url = serve_raw(
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{body}"
        )
        .into_bytes(),
    )
    .await;
    let e = download_json(&url, 100, true).await.unwrap_err();
    assert!(e.contains("larger than 100 bytes"), "{e}");
    assert_eq!(
        download_json(
            &serve_raw(format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{body}").into_bytes())
                .await,
            1000,
            true
        )
        .await
        .unwrap()
        .as_str()
        .unwrap()
        .len(),
        200,
        "under the cap: read to the end"
    );
    // chunked: two chunks of 101 bytes
    let chunk = "y".repeat(101);
    let url = serve_raw(
        format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n65\r\n{chunk}\r\n65\r\n{chunk}\r\n0\r\n\r\n"
        )
        .into_bytes(),
    )
    .await;
    let e = download_json(&url, 150, true).await.unwrap_err();
    assert!(e.contains("larger than 150 bytes"), "{e}");
    // understated Content-Length: the client reads only the declared bytes, never past the cap; the truncated
    // document is refused
    let url = serve_raw(
        format!("HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\n{body}")
            .into_bytes(),
    )
    .await;
    let e = download_json(&url, 100, true).await.unwrap_err();
    assert!(e.starts_with("invalid JSON"), "{e}");
    // overstated Content-Length above the cap: refused before the body is read
    let url = serve_raw(
        format!("HTTP/1.1 200 OK\r\nContent-Length: 5000\r\nConnection: close\r\n\r\n{body}")
            .into_bytes(),
    )
    .await;
    let e = download_json(&url, 100, true).await.unwrap_err();
    assert!(e.contains("larger than 100 bytes"), "{e}");
}
