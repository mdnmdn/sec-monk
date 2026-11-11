//! The native MSRC source over an in-memory mirror (`common::MemView`): the fixture's rows, documents that keep their
//! own `affected` rows, an older document after a newer one, a document twice in one run, per-document errors and the
//! errors that stop a run, chunks of `rows_by_id`, caps, and the API (a local HTTP server, never the network).
//! Fixture: `tests/fixtures/sources/msrc` of the repository (read only, synthetic); the other documents are written
//! at test time (synthetic). The comparison with the Python source is `secmonk-engine/tests/native_msrc.rs`.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::{MemView, of, ops, serve_headers, serve_logged};
use secmonk_model::{JsonMap, MirrorTable, RowOp};
use secmonk_sources::batch::Limits;
use secmonk_sources::msrc::{Caps, MsrcSource};
use secmonk_traits::{ErrorCode, NATIVE_GENERATION, RowsBatch, Source, SyncEnd};
use serde_json::{Value, json};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/fixtures/sources/msrc/cvrf-2024-Aug.synthetic.json")
}

fn src(view: &Arc<MemView>) -> MsrcSource {
    MsrcSource::new(view.clone())
}

async fn run(src: &MsrcSource, options: Value) -> (Vec<RowsBatch>, SyncEnd, Vec<String>) {
    common::run(src, "msrc", options).await
}

/// Run and apply to the in-memory mirror.
async fn sync(view: &Arc<MemView>, src: &MsrcSource, options: Value) -> (Vec<RowOp>, SyncEnd) {
    let (b, end, _) = run(src, options).await;
    view.apply(&b);
    (ops(&b), end)
}

fn path_opts(p: &Path) -> Value {
    json!({"path": p.display().to_string()})
}

fn write(dir: &Path, name: &str, doc: &Value) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, serde_json::to_vec_pretty(doc).unwrap()).unwrap();
    p
}

/// A synthetic CVRF document: `vulns` as given, products 1 (Windows 10 22H2) and 2 (Windows 11 23H2).
fn doc(id: &str, released: &str, vulns: Value) -> Value {
    json!({
        "DocumentTracking": {"Identification": {"ID": {"Value": id}}, "CurrentReleaseDate": released,
                             "InitialReleaseDate": released},
        "ProductTree": {"FullProductName": [
            {"ProductID": "1", "Value": "Windows 10 Version 22H2 for x64-based Systems"},
            {"ProductID": "2", "Value": "Windows 11 Version 23H2 for x64-based Systems"}]},
        "Vulnerability": vulns
    })
}

/// A vulnerability fixed by KB `kb` in build `fixed` for the products `pids`.
fn vuln(cve: &str, kb: &str, fixed: &str, pids: &[&str]) -> Value {
    json!({"CVE": cve, "Title": {"Value": format!("{cve} title")},
           "CVSSScoreSets": [{"BaseScore": 7.8, "Vector": "CVSS:3.1/AV:L"}],
           "Remediations": [{"Type": 2, "Description": {"Value": kb}, "FixedBuild": fixed, "ProductID": pids}]})
}

fn affected_of(view: &MemView, cve: &str) -> Vec<(String, String, String)> {
    let mut out: Vec<(String, String, String)> = view
        .rows(MirrorTable::Affected)
        .into_iter()
        .filter(|r| r["vuln_id"] == cve)
        .map(|r| {
            (
                r["product"].as_str().unwrap().to_owned(),
                r["events"][1]["fixed"].as_str().unwrap().to_owned(),
                r["extra"]["document"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    out.sort();
    out
}

fn vuln_row(view: &MemView, cve: &str) -> JsonMap {
    view.rows(MirrorTable::Vulnerability)
        .into_iter()
        .find(|r| r["id"] == cve)
        .unwrap()
}

#[tokio::test]
async fn the_fixture_becomes_vulnerability_raw_and_affected_rows() {
    let view = MemView::new();
    let s = src(&view);
    let (all, end) = sync(&view, &s, path_opts(&fixture())).await;
    assert_eq!(end.entry.status, "ok", "{end:?}");
    assert_eq!(end.entry.records, 2);
    assert_eq!(end.entry.message.as_deref(), Some("2 vulnerabilities"));
    let v = vuln_row(&view, "CVE-2024-38063");
    assert_eq!(v["cvss_score"], json!(9.8));
    assert_eq!(v["severity"], "CRITICAL");
    assert_eq!(v["cvss_version"], "3.1");
    assert_eq!(v["modified"], "2024-08-14T07:00:00Z");
    assert_eq!(v["published"], "2024-08-13T07:00:00Z");
    assert_eq!(
        v["extra"],
        json!({"document": "2024-Aug", "kbs": ["KB5041160", "KB5041573", "KB5041580", "KB5041585"]})
    );
    assert_eq!(view.rows(MirrorTable::RawRecord).len(), 2);
    assert_eq!(
        affected_of(&view, "CVE-2024-38063")
            .into_iter()
            .map(|r| r.0)
            .collect::<Vec<_>>(),
        vec![
            "windows 10 version 22h2",
            "windows 11 version 23h2",
            "windows server 2022",
            "windows server 2022, 23h2 edition (server core installation)"
        ]
    );
    let w11 = view
        .rows(MirrorTable::Affected)
        .into_iter()
        .find(|r| r["product"] == "windows 11 version 23h2")
        .unwrap();
    assert_eq!(w11["extra"]["product_ids"], json!(["12086", "12087"]));
    assert_eq!(w11["extra"]["kb"], json!(["KB5041585"]));
    assert_eq!(w11["extra"]["supersedes"], json!(["5040442"]));
    assert!(
        affected_of(&view, "CVE-2024-38172").is_empty(),
        "no FixedBuild"
    );
    let sync_row = &view.rows(MirrorTable::SourceSync)[0];
    assert_eq!(sync_row["records"], 2);
    assert_eq!(sync_row["cursor"], "2024-08-14T07:00:00Z");
    assert!(of(&all, MirrorTable::Affected, false).is_empty());

    // the same file again: equal rows are not rewritten; the vulnerability rows are (same release date)
    let (all, end) = sync(&view, &s, path_opts(&fixture())).await;
    assert_eq!(end.entry.status, "ok");
    assert!(of(&all, MirrorTable::Affected, true).is_empty());
    assert!(of(&all, MirrorTable::Affected, false).is_empty());
    assert_eq!(of(&all, MirrorTable::Vulnerability, true).len(), 2);
    assert_eq!(view.rows(MirrorTable::Affected).len(), 4);
    let (b, _, _) = run(&s, path_opts(&fixture())).await;
    assert_eq!(b[0].seq, 3, "seqs continue the native generation");
    assert_eq!(b[0].generation.as_deref(), Some(NATIVE_GENERATION));
}

#[tokio::test]
async fn documents_keep_their_own_rows_and_the_newest_writes_the_vulnerability() {
    let view = MemView::new();
    let s = src(&view).with_limits(Limits {
        ops: 3,
        bytes: 1 << 20,
    });
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("cvrf");
    std::fs::create_dir(&dir).unwrap();
    let jan = doc(
        "2024-Jan",
        "2024-01-09T08:00:00Z",
        json!([vuln("CVE-1", "5034122", "10.0.19045.3930", &["1"])]),
    );
    let feb = doc(
        "2024-Feb",
        "2024-02-13T08:00:00Z",
        json!([vuln("CVE-1", "5034765", "10.0.22631.3155", &["2"])]),
    );
    // file names do not sort by date: the release date orders them
    write(&dir, "a-newer.json", &feb);
    write(&dir, "b-older.json", &jan);
    let (_, end) = sync(&view, &s, path_opts(&dir)).await;
    assert_eq!(end.entry.status, "ok", "{end:?}");
    assert_eq!(end.entry.records, 2, "vulnerabilities imported");
    assert_eq!(
        view.rows(MirrorTable::SourceSync)[0]["records"],
        1,
        "msrc vulnerabilities stored"
    );
    assert_eq!(
        view.rows(MirrorTable::SourceSync)[0]["cursor"],
        "2024-02-13T08:00:00Z"
    );
    assert_eq!(
        affected_of(&view, "CVE-1"),
        vec![
            (
                "windows 10 version 22h2".into(),
                "10.0.19045.3930".into(),
                "2024-Jan".into()
            ),
            (
                "windows 11 version 23h2".into(),
                "10.0.22631.3155".into(),
                "2024-Feb".into()
            ),
        ]
    );
    let v = vuln_row(&view, "CVE-1");
    assert_eq!(v["modified"], "2024-02-13T08:00:00Z");
    assert_eq!(
        v["extra"],
        json!({"document": "2024-Feb", "kbs": ["KB5034122", "KB5034765"]})
    );

    // the older month again with one KB more: only `extra.kbs` changes, its own affected row is replaced
    let jan2 = doc(
        "2024-Jan",
        "2024-01-09T08:00:00Z",
        json!([{"CVE": "CVE-1", "Remediations": [
            {"Type": 2, "Description": {"Value": "5034122"}, "FixedBuild": "10.0.19045.3931", "ProductID": ["1"]},
            {"Type": 3, "Description": {"Value": "5099999"}}]}]),
    );
    let p = write(d.path(), "jan2.json", &jan2);
    let (all, end) = sync(&view, &s, path_opts(&p)).await;
    assert_eq!(end.entry.status, "ok");
    let ups = of(&all, MirrorTable::Vulnerability, true);
    assert_eq!(ups.len(), 1);
    assert_eq!(
        ups[0],
        json!({"source": "msrc", "id": "CVE-1",
               "extra": {"document": "2024-Feb", "kbs": ["KB5034122", "KB5034765", "KB5099999"]}})
        .as_object()
        .cloned()
        .unwrap()
    );
    assert!(of(&all, MirrorTable::RawRecord, true).is_empty());
    assert_eq!(
        of(&all, MirrorTable::Affected, false).len(),
        1,
        "the January row only"
    );
    assert_eq!(
        affected_of(&view, "CVE-1"),
        vec![
            (
                "windows 10 version 22h2".into(),
                "10.0.19045.3931".into(),
                "2024-Jan".into()
            ),
            (
                "windows 11 version 23h2".into(),
                "10.0.22631.3155".into(),
                "2024-Feb".into()
            ),
        ]
    );
    assert_eq!(vuln_row(&view, "CVE-1")["modified"], "2024-02-13T08:00:00Z");
    // once more: nothing new
    let (all, _) = sync(&view, &s, path_opts(&p)).await;
    assert!(of(&all, MirrorTable::Vulnerability, true).is_empty());
    assert!(of(&all, MirrorTable::Affected, true).is_empty());

    // February revised: a product removed; its rows of February replaced, January's kept
    let feb2 = doc(
        "2024-Feb",
        "2024-02-20T08:00:00Z",
        json!([vuln("CVE-1", "5034765", "10.0.22631.3156", &[])]),
    );
    let p = write(d.path(), "feb2.json", &feb2);
    let (all, _) = sync(&view, &s, path_opts(&p)).await;
    assert_eq!(of(&all, MirrorTable::Affected, false).len(), 1);
    assert_eq!(
        affected_of(&view, "CVE-1"),
        vec![(
            "windows 10 version 22h2".into(),
            "10.0.19045.3931".into(),
            "2024-Jan".into()
        )]
    );
    assert_eq!(vuln_row(&view, "CVE-1")["modified"], "2024-02-20T08:00:00Z");
}

#[tokio::test]
async fn a_document_twice_in_one_run_replaces_what_the_run_wrote() {
    let view = MemView::new();
    let s = src(&view);
    let d = tempfile::tempdir().unwrap();
    let a = doc(
        "2024-Mar",
        "2024-03-12T07:00:00Z",
        json!([
            vuln("CVE-3", "5000001", "1.0", &["1", "2"]),
            vuln("CVE-3", "5000002", "2.0", &["1"])
        ]),
    );
    let b = doc(
        "2024-Mar",
        "2024-03-19T07:00:00Z",
        json!([vuln("CVE-3", "5000003", "3.0", &["2"])]),
    );
    write(d.path(), "a.json", &a);
    write(d.path(), "b.json", &b);
    let (_, end) = sync(&view, &s, path_opts(d.path())).await;
    assert_eq!(end.entry.records, 3);
    // in Python each occurrence deletes the rows the previous one of the same document wrote
    assert_eq!(
        affected_of(&view, "CVE-3"),
        vec![(
            "windows 11 version 23h2".into(),
            "3.0".into(),
            "2024-Mar".into()
        )]
    );
    assert_eq!(
        vuln_row(&view, "CVE-3")["extra"]["kbs"],
        json!(["KB5000001", "KB5000002", "KB5000003"])
    );
    assert_eq!(view.rows(MirrorTable::Vulnerability).len(), 1);
}

#[tokio::test]
async fn per_document_errors_and_errors_that_stop_the_run() {
    let view = MemView::new();
    let s = src(&view);
    let d = tempfile::tempdir().unwrap();
    let dir = d.path().join("docs");
    std::fs::create_dir(&dir).unwrap();
    // a document failing at its second vulnerability keeps the first (one transaction per vulnerability)
    write(
        &dir,
        "1.json",
        &doc(
            "2024-Apr",
            "2024-04-09T07:00:00Z",
            json!([
                vuln("CVE-4", "5000004", "4.0", &["1"]),
                "not a vulnerability",
                vuln("CVE-5", "5", "5", &["1"])
            ]),
        ),
    );
    write(
        &dir,
        "2.json",
        &doc(
            "2024-May",
            "2024-05-14T07:00:00Z",
            json!([vuln("CVE-6", "5000006", "6.0", &["2"])]),
        ),
    );
    write(&dir, "3.json", &json!(["a list"]));
    let (_, end, lines) = run(&s, path_opts(&dir)).await;
    assert_eq!(end.entry.status, "partial", "{end:?}");
    assert_eq!(end.entry.records, 1, "only the May document counts");
    assert_eq!(end.entry.message.as_deref(), Some("1 vulnerabilities"));
    assert!(
        lines
            .iter()
            .any(|l| l == "msrc: 1.json: 'str' object has no attribute 'get'"),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l == "msrc: 3.json: 'list' object has no attribute 'get'")
    );
    let (b, _, _) = run(&s, path_opts(&dir)).await;
    view.apply(&b);
    let ids: Vec<String> = view
        .rows(MirrorTable::Vulnerability)
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(&"CVE-4".to_owned()) && ids.contains(&"CVE-6".to_owned()));
    let st = &view.rows(MirrorTable::SourceSync)[0];
    assert_eq!(st["status"], "partial");
    assert_eq!(st["records"], 2);
    assert!(
        st.get("cursor").is_none(),
        "the first document failed: no cursor"
    );

    // a document that cannot be read sorts first (no date) and stops the run: error, nothing imported
    std::fs::create_dir(dir.join("4.json")).unwrap();
    let (b, end, _) = run(&s, path_opts(&dir)).await;
    assert_eq!(end.entry.status, "error");
    assert_eq!(
        end.entry.message.unwrap(),
        format!(
            "[Errno 21] Is a directory: '{}'",
            dir.join("4.json").display()
        )
    );
    assert_eq!(ops(&b).len(), 1, "the status row only");
    std::fs::remove_dir(dir.join("4.json")).unwrap();

    // a document without a date sorts before it by path: imported, then the run stops (partial)
    write(
        &dir,
        "0.json",
        &json!({"Vulnerability": [vuln("CVE-7", "5000007", "7.0", &["1"])]}),
    );
    std::fs::write(dir.join("00.json"), b"{\"Vulnerability\": [\"caf\xe9\"]}").unwrap();
    let (b, end, _) = run(&s, path_opts(&dir)).await;
    assert_eq!(end.entry.status, "partial", "{end:?}");
    assert_eq!(end.entry.records, 1);
    assert_eq!(
        end.entry.message.as_deref(),
        Some("'utf-8' codec can't decode byte 0xe9 in position 23: invalid continuation byte")
    );
    assert_eq!(of(&ops(&b), MirrorTable::Vulnerability, true).len(), 1);
    let sync_row = of(&ops(&b), MirrorTable::SourceSync, true);
    assert_eq!(sync_row[0]["records"], 1, "the run's count when it stops");

    // invalid JSON stops the run too
    std::fs::write(dir.join("00.json"), "{").unwrap();
    let (_, end, _) = run(&s, path_opts(&dir)).await;
    assert!(end.entry.message.unwrap().starts_with("invalid JSON"));

    // the path itself
    let missing = d.path().join("nope");
    let (_, end, _) = run(&s, path_opts(&missing)).await;
    assert_eq!(end.entry.status, "error");
    assert_eq!(
        end.entry.message.unwrap(),
        format!("path not found: {}", missing.display())
    );
    let empty = d.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let (_, end, _) = run(&s, path_opts(&empty)).await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 0));
    #[cfg(unix)]
    {
        let fifo = d.path().join("fifo");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let (_, end, _) = run(&s, path_opts(&fifo)).await;
        assert_eq!(
            end.entry.message.unwrap(),
            format!("not a regular file: '{}'", fifo.display())
        );
    }

    // limit is ignored with a path (as in Python); 0 is refused
    let (_, end, _) = run(
        &s,
        json!({"path": fixture().display().to_string(), "limit": 1}),
    )
    .await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 2));
    let e = match s
        .sync(
            common::params("msrc", json!({"path": "x", "limit": 0})),
            Default::default(),
        )
        .await
    {
        Err(e) => e,
        Ok(_) => panic!("limit 0 accepted"),
    };
    assert_eq!(e.code, ErrorCode::InvalidParams);
}

#[tokio::test]
async fn the_branch_that_writes_the_row_raises_the_vector_error() {
    let view = MemView::new();
    let s = src(&view);
    let d = tempfile::tempdir().unwrap();
    let bad = |released: &str| {
        doc(
            "2024-Jun",
            released,
            json!([{"CVE": "CVE-8", "CVSSScoreSets": [{"BaseScore": 5, "Vector": 31}]}]),
        )
    };
    // stored newer row: the older document does not compute the vector, no error
    let newer = doc(
        "2024-Jul",
        "2024-07-09T07:00:00Z",
        json!([vuln("CVE-8", "5000008", "8.0", &["1"])]),
    );
    sync(&view, &s, path_opts(&write(d.path(), "jul.json", &newer))).await;
    let (_, end) = sync(
        &view,
        &s,
        path_opts(&write(d.path(), "jun.json", &bad("2024-06-11T07:00:00Z"))),
    )
    .await;
    assert_eq!(end.entry.status, "ok", "{end:?}");
    // a newer document with the same vector fails
    let (_, end) = sync(
        &view,
        &s,
        path_opts(&write(d.path(), "aug.json", &bad("2024-08-13T07:00:00Z"))),
    )
    .await;
    assert_eq!(end.entry.status, "partial", "{end:?}");
    assert_eq!(end.entry.records, 0);
}

#[tokio::test]
async fn many_vulnerabilities_are_read_in_chunks_and_caps_refuse_large_input() {
    let view = MemView::new();
    let s = src(&view);
    let d = tempfile::tempdir().unwrap();
    let many: Vec<Value> = (0..600)
        .map(|i| vuln(&format!("CVE-{i}"), "5000000", &format!("1.{i}"), &["1"]))
        .collect();
    let p = write(
        d.path(),
        "many.json",
        &doc("2024-Sep", "2024-09-10T07:00:00Z", Value::Array(many)),
    );
    // MemView::rows_by_id asserts at most MAX_VIEW_IDS ids per call
    let (_, end) = sync(&view, &s, path_opts(&p)).await;
    assert_eq!(end.entry.records, 600);
    assert_eq!(view.rows(MirrorTable::Affected).len(), 600);
    let (all, _) = sync(&view, &s, path_opts(&p)).await;
    assert!(
        of(&all, MirrorTable::Affected, true).is_empty(),
        "unchanged"
    );

    let capped = |caps: Caps| src(&view).with_caps(caps);
    let (b, end, _) = run(
        &capped(Caps {
            vulnerabilities: 550,
            ..Caps::default()
        }),
        path_opts(&p),
    )
    .await;
    assert_eq!(
        end.entry.message.as_deref(),
        Some("msrc: more than 550 vulnerabilities in total; refusing")
    );
    assert_eq!(ops(&b).len(), 1);
    let (_, end, _) = run(
        &capped(Caps {
            total_bytes: 1000,
            ..Caps::default()
        }),
        path_opts(&p),
    )
    .await;
    assert_eq!(
        end.entry.message.as_deref(),
        Some("msrc: documents larger than 1000 bytes in total; refusing")
    );
    let (_, end, _) = run(
        &capped(Caps {
            document_bytes: 1000,
            ..Caps::default()
        }),
        path_opts(&p),
    )
    .await;
    assert_eq!(
        end.entry.message.unwrap(),
        format!("{}: larger than 1000 bytes", p.display())
    );
    let (_, end, _) = run(
        &capped(Caps {
            documents: 0,
            ..Caps::default()
        }),
        path_opts(d.path()),
    )
    .await;
    assert!(
        end.entry
            .message
            .unwrap()
            .starts_with("msrc: more than 0 documents under ")
    );
}

#[tokio::test]
async fn the_api_months_are_filtered_and_read_in_order() {
    let view = MemView::new();
    let jan = doc(
        "2024-Jan",
        "2024-01-09T08:00:00Z",
        json!([vuln("CVE-1", "5034122", "1.0", &["1"])]),
    );
    let feb = doc(
        "2024-Feb",
        "2024-02-13T08:00:00Z",
        json!([vuln("CVE-2", "5034765", "2.0", &["2"])]),
    );
    let body = |v: &Value| serde_json::to_vec(v).unwrap();
    let updates = |other: &str| {
        json!({"value": [
            {"ID": "2024-Feb", "CurrentReleaseDate": "2024-02-13T08:00:00Z"},
            {"ID": "2024-Jan", "CurrentReleaseDate": "2024-01-09T08:00:00Z",
             "CvrfUrl": format!("{other}/cvrf/2024-Jan")}]})
    };
    // without CvrfUrl the documents are `<base>/cvrf/<ID or Alias>`
    let no_url = json!({"value": [
        {"ID": "2024-Feb", "CurrentReleaseDate": "2024-02-13T08:00:00Z"},
        {"Alias": "2024-Jan", "CurrentReleaseDate": "2024-01-09T08:00:00Z"}]});
    let (base, log) = serve_logged(vec![
        (200, body(&no_url)),
        (200, body(&jan)),
        (200, body(&feb)),
    ])
    .await;
    let s = src(&view).with_base_url(&format!("{base}/cvrf/v3.0"));
    let (_, end) = sync(&view, &s, json!({})).await;
    assert_eq!(end.entry.status, "ok", "{end:?}");
    assert_eq!(end.entry.records, 2);
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            "GET /cvrf/v3.0/updates HTTP/1.1",
            "GET /cvrf/v3.0/cvrf/2024-Jan HTTP/1.1",
            "GET /cvrf/v3.0/cvrf/2024-Feb HTTP/1.1",
        ]
    );
    assert_eq!(
        view.rows(MirrorTable::SourceSync)[0]["cursor"],
        "2024-02-13T08:00:00Z"
    );

    // the stored cursor skips both months; `full` reads them again, `limit` keeps the newest, `since` filters
    let (base, log) = serve_logged(vec![(200, body(&no_url))]).await;
    let s = src(&view).with_base_url(&base);
    let (_, end) = sync(&view, &s, json!({})).await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 0));
    assert_eq!(log.lock().unwrap().len(), 1);
    let (base, log) = serve_logged(vec![(200, body(&no_url)), (200, body(&feb))]).await;
    let s = src(&view).with_base_url(&base);
    let (_, end) = sync(&view, &s, json!({"full": true, "limit": 1})).await;
    assert_eq!(end.entry.records, 1);
    assert_eq!(log.lock().unwrap()[1], "GET /cvrf/2024-Feb HTTP/1.1");
    let (base, log) = serve_logged(vec![(200, body(&no_url)), (200, body(&feb))]).await;
    let s = src(&view).with_base_url(&base);
    let (_, end) = sync(&view, &s, json!({"full": true, "since": "2024-02-01"})).await;
    assert_eq!(end.entry.records, 1);
    assert_eq!(log.lock().unwrap().len(), 2);

    // a CvrfUrl on another origin is refused before it is requested (the run stops there)
    let other = "http://127.0.0.1:9";
    let (base, log) = serve_logged(vec![(200, body(&updates(other)))]).await;
    let s = src(&view).with_base_url(&base);
    let (b, end, _) = run(&s, json!({"full": true})).await;
    assert_eq!(end.entry.status, "error", "{end:?}");
    assert_eq!(
        end.entry.message.unwrap(),
        format!("msrc: document URL {other}/cvrf/2024-Jan is not on {base}; refusing")
    );
    assert_eq!(ops(&b).len(), 1);
    assert_eq!(log.lock().unwrap().len(), 1);

    // an HTTP error after a good month: partial, the good month imported
    let (base, _) = serve_logged(vec![
        (200, body(&no_url)),
        (200, body(&jan)),
        (404, b"no".to_vec()),
    ])
    .await;
    let s = src(&view).with_base_url(&base);
    let (b, end, lines) = run(&s, json!({"full": true})).await;
    assert_eq!(end.entry.status, "partial", "{end:?}");
    assert_eq!(end.entry.records, 1);
    assert_eq!(
        end.entry.message.unwrap(),
        format!("HTTP 404 for {base}/cvrf/2024-Feb")
    );
    assert_eq!(lines, vec!["msrc: 2024-Jan", "msrc: 2024-Feb"]);
    assert_eq!(of(&ops(&b), MirrorTable::Vulnerability, true).len(), 1);

    // a document URL may redirect within the origin of the base, not elsewhere: the run stops at that month
    let other = "http://127.0.0.1:9";
    let (base, log) = serve_headers(vec![
        (200, vec![], body(&no_url)),
        (
            302,
            vec![("Location", "/moved/2024-Jan".into())],
            Vec::new(),
        ),
        (200, vec![], body(&jan)),
        (
            302,
            vec![("Location", format!("{other}/cvrf/2024-Feb"))],
            Vec::new(),
        ),
    ])
    .await;
    let s = src(&view).with_base_url(&base);
    let (b, end, _) = run(&s, json!({"full": true})).await;
    assert_eq!(end.entry.status, "partial", "{end:?}");
    assert_eq!(end.entry.records, 1);
    assert_eq!(
        end.entry.message.unwrap(),
        format!(
            "{base}/cvrf/2024-Feb: redirect to {other}/cvrf/2024-Feb is not on {base}; refusing"
        )
    );
    assert_eq!(of(&ops(&b), MirrorTable::Vulnerability, true).len(), 1);
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            "GET /updates HTTP/1.1",
            "GET /cvrf/2024-Jan HTTP/1.1",
            "GET /moved/2024-Jan HTTP/1.1",
            "GET /cvrf/2024-Feb HTTP/1.1",
        ]
    );

    // an updates answer that is not an object
    let (base, _) = serve_logged(vec![(200, b"[]".to_vec())]).await;
    let (_, end, _) = run(&src(&view).with_base_url(&base), json!({})).await;
    assert_eq!(
        end.entry.message.as_deref(),
        Some("AttributeError: 'list' object has no attribute 'get'")
    );
}
