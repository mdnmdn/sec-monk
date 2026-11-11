//! The native Debian tracker source over an in-memory mirror (`common::MemView`): rows of the JSON fixture and of the
//! repository checkout, a second run (nothing but the status row), an update (deletes, changed and new rows), the
//! guard, `--full`, limit, errors, caps, and the download (a local HTTP server, never the network). Fixtures:
//! `tests/fixtures/sources/debian-tracker` of the repository (read only, synthetic); the variants are written at test
//! time. Expected counts and cursors were taken from the Python source on the same files. The comparison with the
//! Python source is `secmonk-engine/tests/native_debian_tracker.rs` (differential test, also paging on the real store).
//! `MemView` pages by rowid as the store does (tested here too), so a snapshot over two full pages runs here as well.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::{MemView, of, ops, serve_logged};
use secmonk_model::{JsonMap, MirrorTable, RowOp};
use secmonk_sources::batch::Limits;
use secmonk_sources::debian_tracker::{Caps, DebianTrackerSource};
use secmonk_traits::{
    ErrorCode, MAX_VIEW_PAGE, MirrorView, NATIVE_GENERATION, RowsBatch, Source, SyncEnd,
};
use serde_json::{Value, json};

const T: MirrorTable = MirrorTable::DistroTriage;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/fixtures/sources/debian-tracker")
}

fn sample() -> PathBuf {
    fixtures().join("tracker-sample.json")
}

fn src(view: &Arc<MemView>) -> DebianTrackerSource {
    DebianTrackerSource::new(view.clone())
}

async fn run(src: &DebianTrackerSource, options: Value) -> (Vec<RowsBatch>, SyncEnd) {
    let (b, end, _) = common::run(src, "debian-tracker", options).await;
    (b, end)
}

async fn sync(
    view: &Arc<MemView>,
    src: &DebianTrackerSource,
    options: Value,
) -> (Vec<RowOp>, SyncEnd) {
    let (b, end) = run(src, options).await;
    view.apply(&b);
    (ops(&b), end)
}

fn path_opts(p: &Path) -> Value {
    json!({"path": p.display().to_string()})
}

fn triage(view: &MemView) -> Vec<JsonMap> {
    view.rows(T)
}

fn find<'a>(rows: &'a [JsonMap], eco: &str, pkg: &str, cve: &str) -> Option<&'a JsonMap> {
    rows.iter()
        .find(|r| r["ecosystem"] == eco && r["package"] == pkg && r["cve_id"] == cve)
}

fn status_row(view: &MemView) -> JsonMap {
    view.rows(MirrorTable::SourceSync)
        .into_iter()
        .find(|r| r["source"] == "debian-tracker")
        .unwrap()
}

/// The sample with: `tor` removed, the curl bookworm status changed, a new package; written to `dir`.
fn update(dir: &Path) -> PathBuf {
    let mut doc: Value = serde_json::from_slice(&std::fs::read(sample()).unwrap()).unwrap();
    let m = doc.as_object_mut().unwrap();
    m.remove("tor");
    m["curl"]["CVE-2023-38545"]["releases"]["bookworm"]["status"] = json!("open");
    m["curl"]["CVE-2023-38545"]["releases"]["bookworm"]
        .as_object_mut()
        .unwrap()
        .remove("fixed_version");
    m.insert(
        "zzz-new".into(),
        json!({"CVE-2026-0001": {"releases": {"trixie": {"status": "open", "urgency": "low"}}}}),
    );
    let p = dir.join("update.json");
    std::fs::write(&p, serde_json::to_vec(&doc).unwrap()).unwrap();
    p
}

#[tokio::test]
async fn the_json_fixture_becomes_triage_rows() {
    let view = MemView::new();
    let s = src(&view);
    let (all, end) = sync(&view, &s, path_opts(&sample())).await;
    assert_eq!(end.entry.status, "ok");
    assert_eq!(end.entry.records, 33);
    assert_eq!(
        end.entry.message.as_deref().unwrap(),
        format!(
            "33 triage rows from file {}; skipped 1 TEMP ids, 12 sid entries, 0 unknown-release entries",
            sample().display()
        )
    );
    assert_eq!(of(&all, T, false).len(), 0);
    let rows = triage(&view);
    assert_eq!(rows.len(), 33);
    let r = find(&rows, "Debian:12", "389-ds-base", "CVE-2024-2199").unwrap();
    assert_eq!(r["status"], "resolved");
    assert_eq!(r["fixed_version"], "2.3.1+dfsg1-1+deb12u1");
    assert_eq!(r["source"], "debian-tracker");
    assert_eq!(r.len(), 10, "every column: {r:?}");
    let st = status_row(&view);
    // the SHA-256 of the file, as the Python source computes it
    assert_eq!(
        st["cursor"],
        "642a9d32e5bdbe3704712004b45a6df4bd63f15567e4aa50b77205e3b8323051"
    );
    assert!(
        all.iter()
            .all(|o| o.table() == T || o.table() == MirrorTable::SourceSync)
    );

    // the same file again: only the status row
    let (again, end) = sync(&view, &s, path_opts(&sample())).await;
    assert_eq!(end.entry.records, 33);
    assert_eq!(again.len(), 1, "{again:?}");
    assert_eq!(again[0].table(), MirrorTable::SourceSync);
}

#[tokio::test]
async fn an_update_deletes_changes_and_adds_rows() {
    let view = MemView::new();
    let s = src(&view).with_limits(Limits {
        ops: 3,
        bytes: 1 << 20,
    });
    sync(&view, &s, path_opts(&sample())).await;
    let dir = tempfile::tempdir().unwrap();
    let (b, end) = run(&s, path_opts(&update(dir.path()))).await;
    assert!(b.len() > 1);
    assert!(
        b.iter()
            .all(|b| b.generation.as_deref() == Some(NATIVE_GENERATION))
    );
    view.apply(&b);
    let all = ops(&b);
    assert_eq!(end.entry.status, "ok");
    let deletes = of(&all, T, false);
    assert!(!deletes.is_empty());
    assert!(
        deletes
            .iter()
            .all(|k| k["package"] == "tor" && k.len() == 4),
        "{deletes:?}"
    );
    let upserts = of(&all, T, true);
    let mut names: Vec<String> = upserts
        .iter()
        .map(|r| {
            format!(
                "{} {}",
                r["package"].as_str().unwrap(),
                r["ecosystem"].as_str().unwrap()
            )
        })
        .collect();
    names.sort();
    assert_eq!(names, vec!["curl Debian:12", "zzz-new Debian:13"]);
    let rows = triage(&view);
    assert!(rows.iter().all(|r| r["package"] != "tor"));
    let curl = find(&rows, "Debian:12", "curl", "CVE-2023-38545").unwrap();
    assert_eq!(
        (&curl["status"], &curl["fixed_version"]),
        (&json!("open"), &Value::Null)
    );
    assert_eq!(rows.len() as u64, end.entry.records);
}

#[tokio::test]
async fn the_repository_checkout_with_advisories() {
    let view = MemView::new();
    let s = src(&view);
    let repo = fixtures().join("repo");
    let (_, end) = sync(&view, &s, path_opts(&repo)).await;
    assert_eq!(end.entry.status, "ok", "{:?}", end.entry.message);
    assert_eq!(end.entry.records, 31);
    assert_eq!(
        end.entry.message.as_deref().unwrap(),
        format!(
            "31 triage rows from repo checkout {}; skipped 1 TEMP ids, 14 sid entries, 0 unknown-release entries",
            repo.display()
        )
    );
    // sha256(repr(sorted(rows))) of the Python source
    assert_eq!(
        status_row(&view)["cursor"],
        "d9a7a13b163471401b8b67da13c3816e231831ccd3b45d1a869025b67e089f5a"
    );
    let rows = triage(&view);
    let ssh = find(&rows, "Debian:12", "openssh", "CVE-2024-6387").unwrap();
    assert_eq!(ssh["advisory"], "DSA-5724-1");
    let ssh11 = find(&rows, "Debian:11", "openssh", "CVE-2024-6387").unwrap();
    assert_eq!(ssh11["advisory"], "DLA-3901-1");
    // from the JSON rows to the checkout rows: the JSON-only rows are deleted
    let view2 = MemView::new();
    let s2 = src(&view2);
    sync(&view2, &s2, path_opts(&sample())).await;
    let (all, end) = sync(&view2, &s2, path_opts(&repo)).await;
    assert_eq!(end.entry.status, "ok");
    assert!(!of(&all, T, false).is_empty());
    let mut a = triage(&view2);
    let mut b = triage(&view);
    let key = |r: &JsonMap| serde_json::to_string(r).unwrap();
    a.sort_by_key(key);
    b.sort_by_key(key);
    assert_eq!(a, b);
}

#[tokio::test]
async fn limit_guard_and_full() {
    let view = MemView::new();
    let s = src(&view);
    let mut opts = path_opts(&sample());
    opts["limit"] = json!(2);
    let (all, end) = sync(&view, &s, opts).await;
    assert_eq!(end.entry.status, "partial");
    assert_eq!(end.entry.records, 6);
    assert!(status_row(&view).get("cursor").is_none());
    assert_eq!(of(&all, T, true).len(), 6);

    sync(&view, &s, path_opts(&sample())).await;
    let dir = tempfile::tempdir().unwrap();
    let tiny = dir.path().join("tiny.json");
    std::fs::write(
        &tiny,
        r#"{"p": {"CVE-2026-0001": {"releases": {"trixie": {"status": "open"}}}}}"#,
    )
    .unwrap();
    let (all, end) = sync(&view, &s, path_opts(&tiny)).await;
    assert_eq!(end.entry.status, "error");
    assert_eq!(
        end.entry.message.as_deref().unwrap(),
        "debian-tracker: refusing to replace 33 rows with a snapshot of only 1 (< 50%; use --full to force)"
    );
    assert_eq!(all.len(), 1);
    let empty = dir.path().join("empty.json");
    std::fs::write(&empty, "{}").unwrap();
    let (_, end) = sync(&view, &s, path_opts(&empty)).await;
    assert_eq!(
        end.entry.message.as_deref().unwrap(),
        "debian-tracker: refusing to replace the data with an empty snapshot (use --full to force)"
    );
    let mut full = path_opts(&empty);
    full["full"] = json!(true);
    let (all, end) = sync(&view, &s, full).await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 0));
    assert_eq!(of(&all, T, false).len(), 33);
    assert!(triage(&view).is_empty());
}

#[tokio::test]
async fn errors_and_caps() {
    let view = MemView::new();
    let s = src(&view);
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.json");
    let (all, end) = sync(&view, &s, path_opts(&missing)).await;
    assert_eq!(end.entry.status, "error");
    assert_eq!(
        end.entry.message.as_deref().unwrap(),
        format!(
            "FileNotFoundError: [Errno 2] No such file or directory: '{}'",
            missing.display()
        )
    );
    assert_eq!(all.len(), 1, "only the status row");
    for (doc, msg) in [
        ("[]", "TypeError: tracker JSON: top level is not an object"),
        (
            r#"{"p": {"CVE-2026-0001": {"releases": {"bookworm": {"status": 7}}}}}"#,
            "AttributeError: 'int' object has no attribute 'lower'",
        ),
    ] {
        let p = dir.path().join("bad.json");
        std::fs::write(&p, doc).unwrap();
        let (_, end) = sync(&view, &s, path_opts(&p)).await;
        assert_eq!(end.entry.message.as_deref(), Some(msg));
    }
    let p = dir.path().join("x.json");
    std::fs::write(&p, "{").unwrap();
    let (_, end) = sync(&view, &s, path_opts(&p)).await;
    assert!(end.entry.message.unwrap().starts_with("invalid JSON"));
    let small = src(&view).with_caps(Caps {
        rows: 5,
        ..Caps::default()
    });
    let (_, end) = sync(&view, &small, path_opts(&sample())).await;
    assert_eq!(
        end.entry.message.as_deref().unwrap(),
        "debian-tracker: native importer: more than 5 rows; refusing"
    );
    assert!(triage(&view).is_empty());
    // limit 0 is invalid, a wrong source name unknown
    let e = s
        .sync(
            common::params("debian-tracker", json!({"limit": 0})),
            Default::default(),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(e.code, ErrorCode::InvalidParams);
    let e = s
        .sync(common::params("kev", json!({})), Default::default())
        .await
        .err()
        .unwrap();
    assert_eq!(e.code, ErrorCode::UnknownSource);
    assert!(s.native());
    assert!(s.sources()[0].in_all);
}

#[cfg(unix)]
#[tokio::test]
async fn a_fifo_is_refused() {
    let view = MemView::new();
    let d = tempfile::tempdir().unwrap();
    let fifo = d.path().join("tracker.json");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let (_, end) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        sync(&view, &src(&view), path_opts(&fifo)),
    )
    .await
    .expect("no hang");
    assert_eq!(
        end.entry.message.as_deref().unwrap(),
        format!("OSError: not a regular file: '{}'", fifo.display())
    );
}

#[tokio::test]
async fn the_download_is_parsed_as_it_arrives() {
    let body = std::fs::read(sample()).unwrap();
    let gz = {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(&body).unwrap();
        e.finish().unwrap()
    };
    let (url, log) = serve_logged(vec![(200, gz.clone()), (404, b"no".to_vec()), (200, gz)]).await;
    let view = MemView::new();
    let s = src(&view).with_url(&format!("{url}/tracker/data/json"));
    let (_, end) = sync(&view, &s, json!({})).await;
    assert_eq!(end.entry.status, "ok", "{:?}", end.entry.message);
    assert_eq!(end.entry.records, 33);
    assert!(
        end.entry
            .message
            .unwrap()
            .contains(&format!("from {url}/tracker/data/json;"))
    );
    // no validator header: the digest of the decompressed content
    assert_eq!(
        status_row(&view)["cursor"],
        "642a9d32e5bdbe3704712004b45a6df4bd63f15567e4aa50b77205e3b8323051"
    );
    let (_, end) = sync(&view, &s, json!({})).await;
    assert_eq!(
        end.entry.message.as_deref().unwrap(),
        format!("HTTP 404 for {url}/tracker/data/json")
    );
    let capped = src(&view)
        .with_url(&format!("{url}/tracker/data/json"))
        .with_caps(Caps {
            download: 100,
            ..Caps::default()
        });
    let (_, end) = sync(&view, &capped, json!({})).await;
    assert_eq!(
        end.entry.message.as_deref().unwrap(),
        "ValueError: tracker download exceeds 100 bytes"
    );
    assert_eq!(log.lock().unwrap()[0], "GET /tracker/data/json HTTP/1.1");
    assert_eq!(triage(&view).len(), 33);
}

/// A stored `distro_triage` row of package `pkg` as the importer writes it (status `open`, the rest NULL).
fn stored(pkg: &str, source: &str) -> RowOp {
    let mut row = JsonMap::new();
    for (k, v) in [
        ("ecosystem", json!("Debian:12")),
        ("package", json!(pkg)),
        ("cve_id", json!("CVE-2024-1")),
        ("status", json!("open")),
        ("urgency", Value::Null),
        ("fixed_version", Value::Null),
        ("nodsa", Value::Null),
        ("note", Value::Null),
        ("advisory", Value::Null),
        ("source", json!(source)),
    ] {
        row.insert(k.into(), v);
    }
    RowOp::Upsert { table: T, row }
}

fn batch(ops: Vec<RowOp>) -> RowsBatch {
    RowsBatch {
        kind: "rows".into(),
        seq: 1,
        source: "debian-tracker".into(),
        ops,
        generation: None,
        acked_through: None,
    }
}

#[tokio::test]
async fn the_test_view_pages_by_rowid_like_the_store() {
    // review W9.6 L4: deletes between pages skip nothing; an exactly full page is followed by an empty one
    let view = MemView::new();
    let mut ops: Vec<RowOp> = (0..4)
        .map(|i| stored(&format!("p{i}"), "debian-tracker"))
        .collect();
    ops.insert(2, stored("other", "x"));
    view.apply(&[batch(ops)]);
    let page = |after| {
        let v = view.clone();
        async move { v.rows_page(T, "debian-tracker", after, 2).await.unwrap() }
    };
    let names = |rows: &[JsonMap]| -> Vec<String> {
        rows.iter()
            .map(|r| r["package"].as_str().unwrap().to_owned())
            .collect()
    };
    let p1 = page(None).await;
    assert_eq!(names(&p1.rows), vec!["p0", "p1"]);
    assert_eq!(p1.next, Some(2));
    // p2 (the next page's first row) deleted between the pages: p3 still comes
    let key = json!({"ecosystem": "Debian:12", "package": "p2", "cve_id": "CVE-2024-1", "source": "debian-tracker"})
        .as_object()
        .cloned()
        .unwrap();
    view.apply(&[batch(vec![RowOp::Delete { table: T, key }])]);
    let p2 = page(p1.next).await;
    assert_eq!(names(&p2.rows), vec!["p3"]);
    assert_eq!(p2.next, None);
    // an upsert of an existing key keeps its rowid (place); a new key goes last
    view.apply(&[batch(vec![
        stored("p0", "debian-tracker"),
        stored("p9", "debian-tracker"),
    ])]);
    let p1 = page(None).await;
    assert_eq!(names(&p1.rows), vec!["p0", "p1"]);
    let p2 = page(p1.next).await;
    assert_eq!(names(&p2.rows), vec!["p3", "p9"]);
    assert!(p2.next.is_some(), "an exactly full page");
    let p3 = page(p2.next).await;
    assert!(p3.rows.is_empty());
    assert_eq!(p3.next, None);
}

#[tokio::test]
async fn a_snapshot_is_compared_over_two_full_pages() {
    // 10 000 stored rows (exactly two pages); the new file keeps the second half and adds 1 000
    let view = MemView::new();
    let n = 2 * MAX_VIEW_PAGE;
    view.apply(&[batch(
        (0..n)
            .map(|i| stored(&format!("p{i:05}"), "debian-tracker"))
            .collect(),
    )]);
    let doc: serde_json::Map<String, Value> = (n / 2..n + 1000)
        .map(|i| {
            (
                format!("p{i:05}"),
                json!({"CVE-2024-1": {"releases": {"bookworm": {"status": "open"}}}}),
            )
        })
        .collect();
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("tracker.json");
    std::fs::write(&f, serde_json::to_vec(&doc).unwrap()).unwrap();
    let (ops, end) = sync(&view, &src(&view), path_opts(&f)).await;
    assert_eq!(end.entry.status, "ok", "{end:?}");
    let deletes = of(&ops, T, false);
    assert_eq!(deletes.len(), n / 2);
    assert!(
        deletes
            .iter()
            .all(|k| k["package"].as_str().unwrap() < "p05000")
    );
    let upserts = of(&ops, T, true);
    assert_eq!(upserts.len(), 1000, "unchanged rows are not rewritten");
    assert_eq!(triage(&view).len(), n / 2 + 1000);
}
