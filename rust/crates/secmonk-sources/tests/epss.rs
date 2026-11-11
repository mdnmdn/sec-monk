//! The native EPSS source over a fake mirror view: rows, no deletes, snapshot guard, limit, full, seqs, gzip and
//! plain files, errors, the bulk download and the API mode (a local HTTP server, never the network). Fixtures:
//! `tests/fixtures/sources/epss` of the repository (read only, synthetic); gzip, larger and broken variants are
//! written at test time. The comparison with the Python source is `secmonk-engine/tests/real_modules.rs`.

mod common;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use common::{of, ops, serve, serve_logged};
use secmonk_model::{JsonMap, MirrorTable, RowOp};
use secmonk_sources::batch::Limits;
use secmonk_sources::epss::{Caps, EpssSource};
use secmonk_traits::{
    AppliedMark, CallCtx, ErrorCode, MirrorView, NATIVE_GENERATION, RowsBatch, Source, StepResult,
    SyncEnd,
};
use serde_json::{Value, json};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/fixtures/sources/epss")
        .join(name)
}

fn csv() -> PathBuf {
    fixture("epss_scores-sample.csv")
}

#[derive(Default)]
struct FakeView {
    applied: Option<AppliedMark>,
    stored: u64,
}

#[async_trait]
impl MirrorView for FakeView {
    async fn applied(&self, s: &str) -> StepResult<Option<AppliedMark>> {
        assert_eq!(s, "epss");
        Ok(self.applied.clone())
    }
    async fn count_rows(&self, t: MirrorTable, s: &str) -> StepResult<u64> {
        assert_eq!((t, s), (MirrorTable::Epss, "epss"));
        Ok(self.stored)
    }
    async fn row_keys(&self, _: MirrorTable, _: &str) -> StepResult<Vec<JsonMap>> {
        panic!("epss never deletes, so it never reads the stored keys")
    }
}

fn src(v: FakeView) -> EpssSource {
    EpssSource::new(Arc::new(v))
}

async fn run(src: &EpssSource, options: Value) -> (Vec<RowsBatch>, SyncEnd, Vec<String>) {
    common::run(src, "epss", options).await
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn write(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, data).unwrap();
    p
}

fn path_of(p: &Path) -> String {
    p.display().to_string()
}

#[tokio::test]
async fn a_csv_becomes_epss_upserts_and_the_sync_row() {
    let s = src(FakeView::default());
    let path = path_of(&csv());
    let (b, end, lines) = run(&s, json!({"path": path})).await;
    assert!(lines.is_empty());
    assert_eq!(b.len(), 1);
    assert_eq!(
        (b[0].seq, b[0].generation.as_deref(), b[0].acked_through),
        (1, Some(NATIVE_GENERATION), None)
    );
    let all = ops(&b);
    assert_eq!(all.len(), 11);
    assert!(
        all.iter().all(|o| matches!(o, RowOp::Upsert { .. })),
        "never a delete"
    );
    let rows = of(&all, MirrorTable::Epss, true);
    assert_eq!(rows.len(), 10);
    assert_eq!(
        Value::Object(rows[0].clone()),
        json!({"cve_id": "CVE-2021-44228", "score": 0.97431, "percentile": 0.99986, "date": "2026-11-06", "source": "epss"})
    );
    assert_eq!(
        rows[0].keys().collect::<Vec<_>>(),
        vec!["cve_id", "score", "percentile", "date", "source"]
    );
    let sync = &of(&all, MirrorTable::SourceSync, true)[0];
    assert_eq!(
        (&sync["cursor"], &sync["records"], &sync["status"]),
        (&json!("2026-11-06"), &json!(10), &json!("ok"))
    );
    assert!(matches!(
        all.last(),
        Some(RowOp::Upsert {
            table: MirrorTable::SourceSync,
            ..
        })
    ));
    assert_eq!(end.entry.status, "ok");
    assert_eq!(end.entry.records, 10);
    assert_eq!(
        end.entry.message.as_deref(),
        Some(format!("10 scores from file {path}").as_str())
    );
    assert_eq!((end.batches, end.last_seq, end.ops), (1, 1, 11));
}

#[tokio::test]
async fn gzip_and_plain_files_give_the_same_rows() {
    let d = tempfile::tempdir().unwrap();
    let text = std::fs::read(csv()).unwrap();
    let gz = write(d.path(), "scores.csv.gz", &gzip(&text));
    let s = src(FakeView::default());
    let (plain, ..) = run(&s, json!({"path": path_of(&csv())})).await;
    let (zipped, end, _) = run(&s, json!({"path": path_of(&gz)})).await;
    assert_eq!(
        of(&ops(&plain), MirrorTable::Epss, true),
        of(&ops(&zipped), MirrorTable::Epss, true)
    );
    assert_eq!(
        end.entry.message,
        Some(format!("10 scores from file {}", gz.display()))
    );
    // a broken gzip file is an error entry, never rows
    let cut = gzip(&text);
    let broken = write(d.path(), "broken.csv.gz", &cut[..cut.len() / 2]);
    let (b, end, _) = run(&s, json!({"path": path_of(&broken)})).await;
    assert_eq!(end.entry.status, "error");
    assert_eq!(
        end.entry.message.as_deref(),
        Some("DecompressError: truncated gz data (no end-of-stream marker)")
    );
    assert_eq!(ops(&b).len(), 1);
    // the decompression cap holds on the output
    let bomb = write(d.path(), "bomb.csv.gz", &gzip(&b"#\n".repeat(1 << 20)));
    let capped = src(FakeView::default()).with_caps(Caps {
        decompressed: 1000,
        ..Caps::default()
    });
    let (_, end, _) = run(&capped, json!({"path": path_of(&bomb)})).await;
    assert_eq!(
        end.entry.message.as_deref(),
        Some("DecompressError: decompressed data exceeds the 1000 byte limit")
    );
}

#[tokio::test]
async fn score_dates_duplicates_and_malformed_lines_follow_python() {
    let d = tempfile::tempdir().unwrap();
    let p = write(
        d.path(),
        "odd.csv",
        b"CVE-0000-0001,0.1,0.2\n\
          #model_version:v1,score_date:2026-01-02T00:00:00+0000\n\
          cve,epss,percentile\n\
          \n\
          cve-0000-0002 , 0.3 , 0.4 ,extra\r\n\
          CVE-0000-0003,not-a-number,0.5\n\
          CVE-0000-0004,0.5\n\
          #score_date:2026-01-03\n\
          CVE-0000-0002,0.6,0.7",
    );
    let (b, end, _) = run(&src(FakeView::default()), json!({"path": path_of(&p)})).await;
    let rows: Vec<Value> = of(&ops(&b), MirrorTable::Epss, true)
        .into_iter()
        .map(|r| json!([r["cve_id"], r["score"], r["date"]]))
        .collect();
    assert_eq!(
        rows,
        vec![
            json!(["CVE-0000-0001", 0.1, null]),
            json!(["CVE-0000-0002", 0.3, "2026-01-02"]),
            json!(["CVE-0000-0002", 0.6, "2026-01-03"]),
        ],
        "the later duplicate is applied last, as INSERT OR REPLACE"
    );
    assert_eq!(end.entry.records, 3);
    let sync = &of(&ops(&b), MirrorTable::SourceSync, true)[0];
    assert_eq!(sync["cursor"], "2026-01-03", "the last row's date");
}

#[tokio::test]
async fn seqs_continue_in_the_native_generation_and_restart_after_another() {
    let v = FakeView {
        applied: Some(AppliedMark {
            seq: 7,
            generation: Some(NATIVE_GENERATION.into()),
        }),
        stored: 10,
    };
    let s = src(v).with_limits(Limits {
        ops: 4,
        bytes: 1 << 20,
    });
    let (b, end, _) = run(&s, json!({"path": path_of(&csv())})).await;
    assert_eq!(
        b.iter().map(|b| (b.seq, b.ops.len())).collect::<Vec<_>>(),
        vec![(8, 4), (9, 4), (10, 3)]
    );
    assert_eq!((end.batches, end.last_seq, end.ops), (3, 10, 11));
    let v = FakeView {
        applied: Some(AppliedMark {
            seq: 7,
            generation: Some("0123456789abcdef".into()),
        }),
        stored: 0,
    };
    let (b, ..) = run(&src(v), json!({"path": path_of(&csv())})).await;
    assert_eq!(b[0].seq, 1);
}

#[tokio::test]
async fn a_large_file_streams_in_batches_of_5000() {
    let d = tempfile::tempdir().unwrap();
    let mut text = String::from(
        "#model_version:v2025.03.14,score_date:2026-11-06T12:55:00Z\ncve,epss,percentile\n",
    );
    for i in 0..12_000 {
        text.push_str(&format!("CVE-2026-{i:05},0.{i:05},0.{:05}\n", 99_999 - i));
    }
    let p = write(d.path(), "big.csv.gz", &gzip(text.as_bytes()));
    let (b, end, _) = run(&src(FakeView::default()), json!({"path": path_of(&p)})).await;
    assert_eq!(
        b.iter().map(|b| b.ops.len()).collect::<Vec<_>>(),
        vec![5000, 5000, 2001]
    );
    assert_eq!((end.batches, end.last_seq, end.ops), (3, 3, 12_001));
    assert_eq!(end.entry.records, 12_000);
}

#[tokio::test]
async fn the_snapshot_guard_limit_and_full_behave_like_python() {
    let path = path_of(&csv());
    let s = src(FakeView {
        applied: None,
        stored: 30,
    });
    let (b, end, _) = run(&s, json!({"path": path})).await;
    assert_eq!(end.entry.status, "error");
    assert_eq!(
        end.entry.message.as_deref(),
        Some(
            "ValueError: EPSS file has only 10 rows (stored: 30, < 50%); refusing (use --full to force)"
        )
    );
    let all = ops(&b);
    assert_eq!(all.len(), 1, "only the status row");
    assert_eq!(
        of(&all, MirrorTable::SourceSync, true)[0]
            .keys()
            .collect::<Vec<_>>(),
        vec!["source", "status", "message"],
        "an error keeps the last good totals"
    );
    let (b, end, _) = run(&s, json!({"path": path, "full": true})).await;
    assert_eq!(end.entry.status, "ok");
    assert_eq!(of(&ops(&b), MirrorTable::Epss, true).len(), 10);
    // 20 stored, 10 new: exactly half is accepted (`count * 2 < existing` refuses)
    let (_, end, _) = run(
        &src(FakeView {
            applied: None,
            stored: 20,
        }),
        json!({"path": path}),
    )
    .await;
    assert_eq!(end.entry.status, "ok");

    let (b, end, _) = run(&s, json!({"path": path, "limit": 3})).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("partial", 3)
    );
    let all = ops(&b);
    assert_eq!(of(&all, MirrorTable::Epss, true).len(), 3);
    assert!(!of(&all, MirrorTable::SourceSync, true)[0].contains_key("cursor"));

    let d = tempfile::tempdir().unwrap();
    let empty = write(
        d.path(),
        "empty.csv",
        b"#score_date:2026-11-06\ncve,epss,percentile\n",
    );
    for full in [false, true] {
        let (_, end, _) = run(
            &src(FakeView::default()),
            json!({"path": path_of(&empty), "full": full}),
        )
        .await;
        assert_eq!(
            end.entry.message.as_deref(),
            Some("ValueError: EPSS file has no rows; refusing"),
            "full={full}: an empty file is refused even with --full"
        );
    }
    let (_, end, _) = run(
        &src(FakeView::default()),
        json!({"path": path_of(&empty), "limit": 5}),
    )
    .await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("partial", 0),
        "no guard with --limit"
    );

    let err = src(FakeView::default())
        .sync(
            common::params("epss", json!({"limit": 0})),
            CallCtx::default(),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(err.code, ErrorCode::InvalidParams);
}

#[tokio::test]
async fn unreadable_files_are_error_entries_worded_like_python() {
    let d = tempfile::tempdir().unwrap();
    let s = src(FakeView::default());
    let missing = d.path().join("missing.csv");
    let (b, end, _) = run(&s, json!({"path": path_of(&missing)})).await;
    assert_eq!(
        end.entry.message,
        Some(format!(
            "FileNotFoundError: [Errno 2] No such file or directory: '{}'",
            missing.display()
        ))
    );
    assert_eq!(ops(&b).len(), 1);
    let (_, end, _) = run(&s, json!({"path": path_of(d.path())})).await;
    assert_eq!(
        end.entry.message,
        Some(format!(
            "IsADirectoryError: [Errno 21] Is a directory: '{}'",
            d.path().display()
        ))
    );
    let long = write(d.path(), "long.csv", &vec![b'x'; 70_000]);
    let (_, end, _) = run(&s, json!({"path": path_of(&long)})).await;
    assert_eq!(
        end.entry.message.as_deref(),
        Some("ValueError: EPSS line longer than 65536 bytes")
    );

    let err = s
        .sync(common::params("kev", json!({})), CallCtx::default())
        .await
        .err()
        .unwrap();
    assert_eq!(err.code, ErrorCode::UnknownSource);
    assert!(s.export("epss", CallCtx::default()).await.is_err());
    s.ack("epss", 3, CallCtx::default()).await.unwrap();
    assert!(s.native());
    assert_eq!(s.sources()[0].name, "epss");
}

#[tokio::test]
async fn the_bulk_file_is_downloaded_gzipped_and_capped() {
    let body = gzip(&std::fs::read(csv()).unwrap());
    let base = serve(vec![
        (200, body.clone()),
        (404, b"no".to_vec()),
        (200, body),
    ])
    .await;
    let bulk = format!("{base}/epss_scores-current.csv.gz");
    let s = src(FakeView::default()).with_urls(&bulk, &format!("{base}/api"));
    let (b, end, _) = run(&s, json!({})).await;
    assert_eq!(end.entry.status, "ok", "{end:?}");
    assert_eq!(of(&ops(&b), MirrorTable::Epss, true).len(), 10);
    assert_eq!(end.entry.message, Some(format!("10 scores from {bulk}")));
    let (b, end, _) = run(&s, json!({})).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.message),
        ("error", Some(format!("HTTP 404 for {bulk}")))
    );
    assert_eq!(ops(&b).len(), 1);
    let s = s.with_caps(Caps {
        download: 100,
        ..Caps::default()
    });
    let (_, end, _) = run(&s, json!({})).await;
    assert!(
        end.entry
            .message
            .unwrap()
            .ends_with("larger than 100 bytes")
    );
}

#[tokio::test]
async fn ids_query_the_api_in_batches_of_100() {
    let answer = std::fs::read(fixture("api-sample.json")).unwrap();
    let (base, log) = serve_logged(vec![(200, answer.clone())]).await;
    let api = format!("{base}/data/v1/epss");
    let s = src(FakeView {
        applied: None,
        stored: 1000, // no guard in API mode
    })
    .with_urls(&format!("{base}/bulk.csv.gz"), &api);
    let (b, end, lines) = run(
        &s,
        json!({"ids": ["cve-2021-44228", " CVE-2023-0001 ", "  "], "path": path_of(&csv())}),
    )
    .await;
    assert_eq!(
        log.lock().unwrap().clone(),
        vec!["GET /data/v1/epss?cve=CVE-2021-44228%2CCVE-2023-0001 HTTP/1.1".to_owned()],
        "ids are used instead of path; stripped, upper-cased, empty ones dropped"
    );
    assert_eq!(lines, vec!["epss: 2 scores from API"]);
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 2));
    assert_eq!(
        end.entry.message.as_deref(),
        Some("2 scores from FIRST API (2 ids)")
    );
    let all = ops(&b);
    let rows = of(&all, MirrorTable::Epss, true);
    assert_eq!(
        Value::Object(rows[1].clone()),
        json!({"cve_id": "CVE-2023-0001", "score": 0.00043, "percentile": 0.04819, "date": "2026-11-06", "source": "epss"})
    );
    assert_eq!(
        of(&all, MirrorTable::SourceSync, true)[0]["cursor"],
        "2026-11-06"
    );

    // 150 ids: two requests; --limit 120 keeps the first 120 ids (partial, no cursor)
    let ids: Vec<String> = (0..150).map(|i| format!("CVE-2026-{i:04}")).collect();
    let (base, log) = serve_logged(vec![(200, answer.clone()), (200, answer.clone())]).await;
    let s = src(FakeView::default()).with_urls("https://unused.invalid/x", &format!("{base}/api"));
    let (_, end, lines) = run(&s, json!({"ids": ids, "limit": 120})).await;
    let reqs = log.lock().unwrap().clone();
    assert_eq!(reqs.len(), 2);
    assert_eq!(reqs[0].matches("%2C").count(), 99);
    assert_eq!(reqs[1].matches("%2C").count(), 19);
    assert_eq!(lines.len(), 2);
    assert_eq!(
        (end.entry.status.as_str(), end.entry.message.as_deref()),
        ("partial", Some("4 scores from FIRST API (120 ids)"))
    );

    // blank ids only: API mode with nothing to ask (no request)
    let s = src(FakeView::default())
        .with_urls("https://unused.invalid/x", "https://unused.invalid/api");
    let (b, end, _) = run(&s, json!({"ids": ["  "], "path": path_of(&csv())})).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.message.as_deref()),
        ("ok", Some("0 scores from FIRST API (0 ids)"))
    );
    assert_eq!(ops(&b).len(), 1);

    // a bad answer fails the whole run (Python rolls back)
    let (base, _) = serve_logged(vec![(
        200,
        br#"{"data": [{"cve": "CVE-1", "epss": "abc", "percentile": "0.1"}]}"#.to_vec(),
    )])
    .await;
    let s = src(FakeView::default()).with_urls("https://unused.invalid/x", &format!("{base}/api"));
    let (b, end, _) = run(&s, json!({"ids": ["CVE-1"]})).await;
    assert_eq!(
        end.entry.message.as_deref(),
        Some("ValueError: could not convert string to float: 'abc'")
    );
    assert_eq!(ops(&b).len(), 1);
}
