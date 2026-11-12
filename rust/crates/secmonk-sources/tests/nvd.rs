//! The native NVD source over an in-memory mirror (`common::MemView`): the fixture's rows, a second run, changed and
//! rejected CVEs, pages of a directory, an id seen twice, chunks of `rows_by_id`, limit, the errors that stop a run at
//! a page (caught and uncaught, as Python's sync and `ops.sync_source`), caps, and the API against a local HTTP server
//! (never the network): paging, delta windows and `nvd:progress`, `--since`, ids, the `apiKey` header, pacing, retries
//! with `Retry-After`, no redirects, the key absent from every message. Fixture: `tests/fixtures/sources/nvd` of the
//! repository (read only, synthetic); the other pages are written at test time (synthetic). The comparison with the
//! Python source is `secmonk-engine/tests/native_nvd.rs`.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use common::{Answer, MemView, of, ops, serve_heads};
use secmonk_model::{JsonMap, MirrorTable, RowOp};
use secmonk_sources::batch::Limits;
use secmonk_sources::nvd::{Caps, NvdSource, Timing};
use secmonk_traits::{RowsBatch, Source, SyncEnd, SyncParams};
use serde_json::{Value, json};

const KEY: &str = "0f1e2d3c-SECRET-API-KEY-4b5a6978";

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/fixtures/sources/nvd/cve-2021-44228.json")
}

fn fast() -> Timing {
    Timing {
        pause_with_key: Duration::ZERO,
        pause_without_key: Duration::ZERO,
        backoff_base: Duration::from_millis(1),
        backoff_max: Duration::from_millis(20),
        retries: 2,
        request_total: Duration::from_secs(30),
    }
}

fn src(view: &Arc<MemView>) -> NvdSource {
    NvdSource::new(view.clone()).with_timing(fast())
}

async fn run(src: &NvdSource, options: Value) -> (Vec<RowsBatch>, SyncEnd, Vec<String>) {
    common::run(src, "nvd", options).await
}

/// A run with the API key as a call secret.
async fn run_key(src: &NvdSource, options: Value) -> (Vec<RowsBatch>, SyncEnd, Vec<String>) {
    let params: SyncParams = serde_json::from_value(
        json!({"source": "nvd", "options": options, "secrets": {"api_key": KEY}}),
    )
    .unwrap();
    let lines = Arc::new(std::sync::Mutex::new(Vec::new()));
    let l = lines.clone();
    let ctx = secmonk_traits::CallCtx {
        deadline: None,
        progress: Some(Arc::new(move |u: secmonk_traits::ProgressUpdate| {
            l.lock().unwrap().extend(u.message);
        })),
    };
    let mut s = src.sync(params, ctx).await.unwrap();
    let (mut batches, mut end) = (Vec::new(), None);
    while let Some(m) = futures_util::StreamExt::next(&mut s).await {
        match m.unwrap() {
            secmonk_traits::StreamMsg::Item(b) => batches.push(b),
            secmonk_traits::StreamMsg::End(e) => end = Some(e),
        }
    }
    let lines = lines.lock().unwrap().clone();
    (batches, end.unwrap(), lines)
}

/// Run and apply to the in-memory mirror.
async fn sync(view: &Arc<MemView>, src: &NvdSource, options: Value) -> (Vec<RowOp>, SyncEnd) {
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

/// An API page of `cves` (`totalResults` = `total`).
fn page(cves: &[Value], total: usize) -> Value {
    json!({"resultsPerPage": cves.len(), "startIndex": 0, "totalResults": total, "format": "NVD_CVE",
           "version": "2.0", "vulnerabilities": cves.iter().map(|c| json!({"cve": c})).collect::<Vec<_>>()})
}

/// A synthetic CVE with one vulnerable cpeMatch per product (`<vendor>:<product>` up to `<fixed>`).
fn cve(id: &str, modified: &str, products: &[(&str, &str)]) -> Value {
    let matches: Vec<Value> = products
        .iter()
        .enumerate()
        .map(|(i, (p, fixed))| {
            json!({"vulnerable": true, "criteria": format!("cpe:2.3:a:{p}:*:*:*:*:*:*:*:*"),
                   "versionEndExcluding": fixed, "matchCriteriaId": format!("{id}-{i}")})
        })
        .collect();
    json!({"id": id, "sourceIdentifier": "cna@example.org", "published": "2026-01-01T00:00:00.000",
           "lastModified": modified, "vulnStatus": "Analyzed", "cveTags": [],
           "descriptions": [{"lang": "en", "value": format!("{id} synthetic")}],
           "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
               "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N", "baseScore": 7.5, "baseSeverity": "HIGH"}}]},
           "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-79"}]}],
           "configurations": [{"nodes": [{"operator": "OR", "negate": false, "cpeMatch": matches}]}]})
}

fn rows_of(view: &MemView, t: MirrorTable) -> Vec<JsonMap> {
    view.rows(t)
        .into_iter()
        .filter(|r| r["source"] == "nvd")
        .collect()
}

fn products_of(view: &MemView, id: &str) -> Vec<String> {
    let mut out: Vec<String> = rows_of(view, MirrorTable::Affected)
        .into_iter()
        .filter(|r| r["vuln_id"] == id)
        .map(|r| r["product"].as_str().unwrap().to_owned())
        .collect();
    out.sort();
    out
}

fn sync_row(ops: &[RowOp], source: &str) -> JsonMap {
    of(ops, MirrorTable::SourceSync, true)
        .into_iter()
        .rfind(|r| r["source"] == source)
        .unwrap_or_else(|| panic!("no {source} row in {ops:#?}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn the_fixture_gives_python_rows_and_a_second_run_rewrites_no_affected_row() {
    let view = MemView::new();
    let s = src(&view);
    let (o, end) = sync(&view, &s, path_opts(&fixture())).await;
    assert_eq!(end.entry.status, "ok");
    assert_eq!(end.entry.records, 1);
    let shown = fixture().display().to_string();
    let shown = secmonk_sources::feed::py_path(Path::new(&shown));
    assert_eq!(
        end.entry.message.as_deref(),
        Some(format!("from file {shown}").as_str())
    );
    let v = &rows_of(&view, MirrorTable::Vulnerability)[0];
    assert_eq!(v["id"], "CVE-2021-44228");
    assert_eq!(
        (v["cvss_score"].clone(), v["severity"].clone()),
        (json!(10.0), json!("CRITICAL"))
    );
    assert_eq!(
        v["cvss_vector"],
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
    );
    assert_eq!(v["cvss_version"], "3.1");
    assert_eq!(v["cwes"], json!(["CWE-917"]));
    assert_eq!(v["state"], "Analyzed");
    assert_eq!(v["modified"], "2026-11-06T00:00:00.000");
    assert_eq!(
        v["extra"],
        json!({"sourceIdentifier": "psirt@apache.org", "cveTags": []})
    );
    let a = rows_of(&view, MirrorTable::Affected);
    assert_eq!(a.len(), 1);
    assert_eq!(
        a[0]["events"],
        json!([{"introduced": "2.0"}, {"fixed": "2.15.0"}])
    );
    assert_eq!(
        (a[0]["vendor"].as_str(), a[0]["product"].as_str()),
        (Some("apache"), Some("log4j"))
    );
    assert_eq!(a[0]["range_type"], "CPE");
    let raw = &rows_of(&view, MirrorTable::RawRecord)[0];
    assert_eq!(raw["record_id"], "CVE-2021-44228");
    assert_eq!(raw["data"]["id"], "CVE-2021-44228");
    let st = sync_row(&o, "nvd");
    assert_eq!(
        (st["status"].as_str(), st["records"].as_u64()),
        (Some("ok"), Some(1))
    );
    assert!(!st.contains_key("cursor"), "no cursor from a file");

    let (o, end) = sync(&view, &s, path_opts(&fixture())).await;
    assert_eq!(end.entry.records, 1);
    assert!(
        of(&o, MirrorTable::Affected, true).is_empty()
            && of(&o, MirrorTable::Affected, false).is_empty()
    );
    assert_eq!(rows_of(&view, MirrorTable::Affected).len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn changed_rejected_and_repeated_cves_across_pages() {
    let view = MemView::new();
    let s = src(&view);
    let d = tempfile::tempdir().unwrap();
    let a = cve(
        "CVE-2099-0001",
        "2026-01-01T00:00:00.000",
        &[("acme:alpha", "1.0"), ("acme:beta", "2.0")],
    );
    let b = cve(
        "CVE-2099-0002",
        "2026-01-01T00:00:00.000",
        &[("acme:gamma", "3.0")],
    );
    write(d.path(), "p1.json", &page(&[a.clone(), b.clone()], 2));
    let (_, end) = sync(&view, &s, path_opts(d.path())).await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 2));
    assert_eq!(products_of(&view, "CVE-2099-0001"), vec!["alpha", "beta"]);

    // a changed configuration, a rejected CVE, the same CVE on two pages (sorted by name: p1 then p2)
    let mut a2 = cve(
        "CVE-2099-0001",
        "2026-02-01T00:00:00.000",
        &[("acme:alpha", "1.1"), ("acme:delta", "4.0")],
    );
    let mut b2 = b.clone();
    b2["vulnStatus"] = json!("Rejected");
    b2["lastModified"] = json!("2026-02-02T00:00:00.000");
    std::fs::remove_file(d.path().join("p1.json")).unwrap();
    write(
        d.path(),
        "p2.json",
        &page(
            &[cve(
                "CVE-2099-0001",
                "2026-03-01T00:00:00.000",
                &[("acme:omega", "9")],
            )],
            1,
        ),
    );
    write(d.path(), "p1.json", &page(&[a2.clone(), b2], 2));
    write(d.path(), "notes.txt", &json!("ignored"));
    let (o, end) = sync(&view, &s, path_opts(d.path())).await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 3));
    assert_eq!(
        products_of(&view, "CVE-2099-0001"),
        vec!["omega"],
        "the later page counts"
    );
    assert!(
        products_of(&view, "CVE-2099-0002").is_empty(),
        "a rejected CVE drops its rows"
    );
    let vb = rows_of(&view, MirrorTable::Vulnerability)
        .into_iter()
        .find(|r| r["id"] == "CVE-2099-0002")
        .unwrap();
    assert_eq!(
        (vb["state"].as_str(), vb["withdrawn"].as_str()),
        (Some("REJECTED"), Some("2026-02-02T00:00:00.000"))
    );
    // first emission: 2 stored deleted, 2 new; second: those 2 deleted by record key, 1 new
    assert_eq!(of(&o, MirrorTable::Affected, false).len(), 2 + 1 + 2);

    // the same CVE twice in one page (one chunk)
    a2["lastModified"] = json!("2026-04-01T00:00:00.000");
    let twice = page(&[cve("CVE-2099-0001", "x", &[("acme:one", "1")]), a2], 2);
    std::fs::remove_file(d.path().join("p2.json")).unwrap();
    write(d.path(), "p1.json", &twice);
    let (_, end) = sync(&view, &s, path_opts(d.path())).await;
    assert_eq!(end.entry.records, 2);
    assert_eq!(products_of(&view, "CVE-2099-0001"), vec!["alpha", "delta"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn many_records_are_read_in_chunks_and_limit_stops_exactly() {
    let view = MemView::new();
    let s = src(&view).with_limits(Limits {
        ops: 50,
        bytes: 1 << 20,
    });
    let d = tempfile::tempdir().unwrap();
    let cves: Vec<Value> = (0..1300)
        .map(|i| {
            cve(
                &format!("CVE-2098-{i:05}"),
                "2026-01-01T00:00:00.000",
                &[("v:p", "1")],
            )
        })
        .collect();
    write(d.path(), "a.json", &page(&cves[..1200], 1300));
    write(d.path(), "b.json", &page(&cves[1200..], 1300));
    let (b, end, lines) = run(&s, path_opts(d.path())).await;
    view.apply(&b);
    assert_eq!(end.entry.records, 1300);
    assert_eq!(rows_of(&view, MirrorTable::Affected).len(), 1300);
    assert_eq!(lines, vec!["nvd: 1200 records", "nvd: 1300 records"]);
    let (o, end) = sync(&view, &s, path_opts(d.path())).await;
    assert_eq!(end.entry.records, 1300);
    assert!(
        of(&o, MirrorTable::Affected, false).is_empty(),
        "unchanged: nothing replaced"
    );

    // limit: the first N records, status ok (the file branch of Python's sync), later files not read
    std::fs::write(d.path().join("c.json"), "not json").unwrap();
    let view = MemView::new();
    let (_, end) = sync(
        &view,
        &src(&view),
        json!({"path": d.path().display().to_string(), "limit": 1201}),
    )
    .await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 1201));
    assert_eq!(rows_of(&view, MirrorTable::Vulnerability).len(), 1201);
    let view = MemView::new();
    let (_, end) = sync(
        &view,
        &src(&view),
        json!({"path": d.path().display().to_string(), "limit": 1200}),
    )
    .await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 1200));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failing_page_keeps_the_pages_before_it() {
    let d = tempfile::tempdir().unwrap();
    let a = cve("CVE-2099-0001", "m", &[("v:a", "1")]);
    let b = cve("CVE-2099-0002", "m", &[("v:b", "1")]);
    write(d.path(), "1.json", &page(std::slice::from_ref(&a), 1));
    let cases: Vec<(&str, Value, &str, u64, &str)> = vec![
        // caught (KeyError): partial, the records before the failing one counted, the page not written
        (
            "2.json",
            json!({"vulnerabilities": [{"cve": b}, {"nocve": 1}]}),
            "partial",
            2,
            "KeyError: 'cve'",
        ),
        // uncaught (AttributeError from `doc.get`): error, no records
        (
            "2.json",
            json!([1]),
            "error",
            0,
            "AttributeError: 'list' object has no attribute 'get'",
        ),
        (
            "2.json",
            json!({"vulnerabilities": [{"cve": {"id": "C", "metrics": []}}]}),
            "error",
            0,
            "AttributeError: 'list' object has no attribute 'get'",
        ),
    ];
    for (name, doc, status, records, message) in cases {
        let view = MemView::new();
        write(d.path(), name, &doc);
        let (o, end) = sync(&view, &src(&view), path_opts(d.path())).await;
        assert_eq!(end.entry.status, status, "{doc}");
        assert_eq!(end.entry.records, records);
        assert_eq!(end.entry.message.as_deref(), Some(message));
        let ids: Vec<Value> = rows_of(&view, MirrorTable::Vulnerability)
            .into_iter()
            .map(|r| r["id"].clone())
            .collect();
        assert_eq!(ids, vec![json!("CVE-2099-0001")], "only the first page");
        let st = sync_row(&o, "nvd");
        assert_eq!(st["status"], status);
        if status == "error" {
            assert!(
                !st.contains_key("records"),
                "an error keeps the stored totals"
            );
        }
    }
    // a directory named *.json, invalid UTF-8, a missing file, an empty directory, a FIFO
    let view = MemView::new();
    std::fs::remove_file(d.path().join("2.json")).unwrap();
    std::fs::create_dir(d.path().join("2.json")).unwrap();
    let (_, end) = sync(&view, &src(&view), path_opts(d.path())).await;
    assert_eq!(end.entry.status, "partial");
    let dir_json = secmonk_sources::feed::py_path(&d.path().join("2.json"));
    assert_eq!(
        end.entry.message,
        Some(format!(
            "IsADirectoryError: [Errno 21] Is a directory: '{dir_json}'"
        ))
    );
    let e = tempfile::tempdir().unwrap();
    std::fs::write(e.path().join("x.json"), b"{\"a\": \"caf\xe9\"}").unwrap();
    let (_, end) = sync(&view, &src(&view), path_opts(&e.path().join("x.json"))).await;
    assert_eq!(
        end.entry.message.as_deref(),
        Some(
            "UnicodeDecodeError: 'utf-8' codec can't decode byte 0xe9 in position 10: invalid continuation byte"
        )
    );
    assert_eq!(end.entry.status, "error");
    let missing = e.path().join("missing.json");
    let (_, end) = sync(&view, &src(&view), path_opts(&missing)).await;
    assert_eq!(
        end.entry.message,
        Some(format!(
            "FileNotFoundError: [Errno 2] No such file or directory: '{}'",
            missing.display()
        ))
    );
    let empty = tempfile::tempdir().unwrap();
    let (_, end) = sync(&view, &src(&view), path_opts(empty.path())).await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 0));
}

#[tokio::test]
async fn limit_zero_is_invalid_params() {
    let view = MemView::new();
    let e = src(&view)
        .sync(
            common::params("nvd", json!({"limit": 0})),
            secmonk_traits::CallCtx::default(),
        )
        .await
        .err()
        .unwrap();
    assert_eq!(e.code, secmonk_traits::ErrorCode::InvalidParams);
}

#[tokio::test(flavor = "multi_thread")]
async fn caps_refuse_large_input() {
    let d = tempfile::tempdir().unwrap();
    let cves: Vec<Value> = (0..3)
        .map(|i| cve(&format!("CVE-2097-{i}"), "m", &[("v:p", "1")]))
        .collect();
    let p = write(d.path(), "p.json", &page(&cves, 3));
    let view = MemView::new();
    let caps = Caps {
        records: 2,
        ..Caps::default()
    };
    let (_, end) = sync(&view, &src(&view).with_caps(caps), path_opts(&p)).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.message.as_deref()),
        (
            "error",
            Some("nvd: more than 2 records in one page; refusing")
        )
    );
    // two pages of two: the second passes the page cap and not the run cap (its records are not written)
    let two = tempfile::tempdir().unwrap();
    write(two.path(), "a.json", &page(&cves[..2], 4));
    write(two.path(), "b.json", &page(&cves[1..], 4));
    let caps = Caps {
        records: 3,
        ..Caps::default()
    };
    let v2 = MemView::new();
    let (_, end) = sync(&v2, &src(&v2).with_caps(caps), path_opts(two.path())).await;
    assert_eq!(
        (
            end.entry.status.as_str(),
            end.entry.records,
            end.entry.message.as_deref()
        ),
        (
            "partial",
            2,
            Some("nvd: more than 3 records in one run; refusing")
        )
    );
    assert_eq!(rows_of(&v2, MirrorTable::Vulnerability).len(), 2);
    let caps = Caps {
        file_bytes: 100,
        ..Caps::default()
    };
    let (_, end) = sync(&view, &src(&view).with_caps(caps), path_opts(&p)).await;
    let shown = secmonk_sources::feed::py_path(&p);
    assert_eq!(
        end.entry.message,
        Some(format!("nvd: {shown}: larger than 100 bytes; refusing"))
    );
    let caps = Caps {
        record_bytes: 100,
        ..Caps::default()
    };
    let (_, end) = sync(&view, &src(&view).with_caps(caps), path_opts(&p)).await;
    assert_eq!(
        end.entry.message.as_deref(),
        Some("nvd: a record is larger than 100 bytes; refusing")
    );
    assert!(rows_of(&view, MirrorTable::Vulnerability).is_empty());
}

/// A batch that stores the `nvd` cursor (as a previous run left it).
fn cursor_batch(cursor: &str) -> RowsBatch {
    RowsBatch {
        kind: "rows".into(),
        seq: 1,
        source: "nvd".into(),
        ops: vec![RowOp::Upsert {
            table: MirrorTable::SourceSync,
            row: json!({"source": "nvd", "cursor": cursor, "status": "ok"})
                .as_object()
                .unwrap()
                .clone(),
        }],
        generation: Some(secmonk_traits::NATIVE_GENERATION.into()),
        acked_through: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn stored_rows_beyond_the_cap_refuse_the_page_before_its_first_operation() {
    // review W10.3 L1: the stored rows are counted in the page's check, so no operation of the page is emitted
    let view = MemView::new();
    let row = |i: usize| RowOp::Upsert {
        table: MirrorTable::Affected,
        row: json!({"source": "nvd", "vuln_id": "CVE-2091-0002", "product": format!("p{i}")})
            .as_object()
            .unwrap()
            .clone(),
    };
    let mut seed = cursor_batch("2026-01-01T00:00:00.000Z");
    seed.ops = (0..3).map(row).collect();
    view.apply(&[seed]);
    let d = tempfile::tempdir().unwrap();
    write(
        d.path(),
        "a.json",
        &page(&[cve("CVE-2091-0001", "m", &[("v:p", "1")])], 1),
    );
    write(
        d.path(),
        "b.json",
        &page(
            &[
                cve("CVE-2091-0003", "m", &[]),
                cve("CVE-2091-0002", "m", &[("v:p", "1")]),
            ],
            2,
        ),
    );
    let caps = Caps {
        matches: 2,
        ..Caps::default()
    };
    let (o, end) = sync(&view, &src(&view).with_caps(caps), path_opts(d.path())).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("partial", 1)
    );
    assert_eq!(
        end.entry.message.as_deref(),
        Some(
            "nvd: native importer: CVE-2091-0002: 3 stored affected rows (more than 2); refusing, sync nvd with the python implementation"
        )
    );
    let ids: Vec<Value> = of(&o, MirrorTable::Vulnerability, true)
        .into_iter()
        .map(|r| r["id"].clone())
        .collect();
    assert_eq!(
        ids,
        vec![json!("CVE-2091-0001")],
        "nothing of the refused page"
    );
}

fn body(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap()
}

fn request_line(head: &str) -> String {
    head.lines().next().unwrap_or("").to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_full_pull_pages_with_the_key_header_and_sets_the_cursor() {
    let cves: Vec<Value> = (0..3)
        .map(|i| cve(&format!("CVE-2096-{i}"), "m", &[("v:p", "1")]))
        .collect();
    let (url, log) = serve_heads(vec![
        (200, vec![], body(&page(&cves[..2], 3))),
        (200, vec![], body(&page(&cves[2..], 3))),
    ])
    .await;
    let view = MemView::new();
    let s = src(&view)
        .with_api_url(&format!("{url}/rest/json/cves/2.0"))
        .with_now("2026-11-11T08:00:00.123456Z");
    let (b, end, lines) = run_key(&s, json!({})).await;
    view.apply(&b);
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 3));
    assert_eq!(end.entry.message.as_deref(), Some("full, NVD API with key"));
    let heads = log.lock().unwrap().clone();
    assert_eq!(
        heads.iter().map(|h| request_line(h)).collect::<Vec<_>>(),
        vec![
            "GET /rest/json/cves/2.0?resultsPerPage=2000&startIndex=0 HTTP/1.1",
            "GET /rest/json/cves/2.0?resultsPerPage=2000&startIndex=2 HTTP/1.1"
        ]
    );
    assert!(heads.iter().all(|h| {
        h.to_ascii_lowercase()
            .contains(&format!("apikey: {}", KEY.to_ascii_lowercase()))
    }));
    let st = sync_row(&ops(&b), "nvd");
    assert_eq!(st["cursor"], "2026-11-11T08:00:00.123Z");
    assert!(
        of(&ops(&b), MirrorTable::SourceSync, true)
            .iter()
            .all(|r| r["source"] == "nvd"),
        "no window: no progress row"
    );
    let text = format!(
        "{lines:?} {end:?} {:?}",
        ops(&b)
            .iter()
            .filter(|o| matches!(
                o,
                RowOp::Upsert {
                    table: MirrorTable::SourceSync,
                    ..
                }
            ))
            .collect::<Vec<_>>()
    );
    assert!(!text.contains(KEY));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_delta_runs_windows_from_the_stored_cursor_and_records_progress() {
    let view = MemView::new();
    // a stored cursor (as the previous run left it) and an older progress row
    view.apply(&[RowsBatch {
        kind: "rows".into(),
        seq: 1,
        source: "nvd".into(),
        ops: vec![
            RowOp::Upsert { table: MirrorTable::SourceSync, row: json!({"source": "nvd", "cursor": "2026-01-01T00:00:00.000Z", "status": "ok"}).as_object().unwrap().clone() },
            RowOp::Upsert { table: MirrorTable::SourceSync, row: json!({"source": "nvd:progress", "cursor": "2025-06-01T00:00:00.000Z", "status": "ok"}).as_object().unwrap().clone() },
        ],
        generation: Some(secmonk_traits::NATIVE_GENERATION.into()),
        acked_through: None,
    }]);
    let c = |i: usize| cve(&format!("CVE-2095-{i}"), "m", &[("v:p", "1")]);
    let (url, log) = serve_heads(vec![
        (200, vec![], body(&page(&[c(0)], 1))),
        (200, vec![], body(&page(&[], 0))),
    ])
    .await;
    let s = src(&view)
        .with_api_url(&url)
        .with_now("2026-06-15T00:00:00Z");
    let (b, end, _) = run(&s, json!({})).await;
    view.apply(&b);
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 1));
    assert_eq!(
        end.entry.message.as_deref(),
        Some("delta since 2026-01-01T00:00:00.000Z, NVD API without key")
    );
    let lines: Vec<String> = log
        .lock()
        .unwrap()
        .iter()
        .map(|h| request_line(h))
        .collect();
    assert_eq!(
        lines,
        vec![
            "GET /?lastModStartDate=2026-01-01T00%3A00%3A00.000Z&lastModEndDate=2026-04-30T00%3A00%3A00.000Z&resultsPerPage=2000&startIndex=0 HTTP/1.1",
            "GET /?lastModStartDate=2026-04-30T00%3A00%3A00.000Z&lastModEndDate=2026-06-15T00%3A00%3A00.000Z&resultsPerPage=2000&startIndex=0 HTTP/1.1",
        ]
    );
    let o = ops(&b);
    let progress: Vec<String> = of(&o, MirrorTable::SourceSync, true)
        .into_iter()
        .filter(|r| r["source"] == "nvd:progress")
        .map(|r| r["cursor"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        progress,
        vec!["2026-04-30T00:00:00.000Z", "2026-06-15T00:00:00.000Z"]
    );
    assert_eq!(sync_row(&o, "nvd")["cursor"], "2026-06-15T00:00:00.000Z");
    assert_eq!(
        sync_row(&o, "nvd:progress")["message"],
        "last completed window end"
    );

    // a failure in the second window of an untrusted --since run (no stored cursor): partial, no cursor, no progress
    let (url, _) = serve_heads(vec![
        (200, vec![], body(&page(&[c(1)], 1))),
        (404, vec![], b"{}".to_vec()),
    ])
    .await;
    let view2 = MemView::new();
    let s = src(&view2)
        .with_api_url(&url)
        .with_now("2026-06-15T00:00:00Z");
    let (b, end, _) = run(&s, json!({"since": "2026-01"})).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("partial", 1)
    );
    assert_eq!(
        end.entry.message,
        Some(format!("HTTPStatusError: HTTP 404 for {url}"))
    );
    let o = ops(&b);
    // no stored cursor: a --since run does not move it (and writes no progress row)
    assert!(
        of(&o, MirrorTable::SourceSync, true)
            .iter()
            .all(|r| r["source"] == "nvd")
    );
    assert!(!sync_row(&o, "nvd").contains_key("cursor"));

    // trusted --since (before the stored cursor), failing in window 2: the cursor of window 1, and its `nvd:progress`
    // row written when window 1 completed and kept (Python's `set_sync_state` commits it at once; review W10.3 H1;
    // Python: tests/sources/test_review_fixes.py::test_nvd_partial_failure_keeps_completed_windows asserts
    // `progress == res.cursor`). Caught (404: partial) and uncaught (a non-number totalResults: error) alike.
    let mut window2_failures: Vec<(Answer, &str)> =
        vec![((404, vec![], b"{}".to_vec()), "partial")];
    let mut bad_total = page(&[c(2)], 1);
    bad_total["totalResults"] = json!("many");
    window2_failures.push(((200, vec![], body(&bad_total)), "error"));
    for (fail, status) in window2_failures {
        let resumed = MemView::new();
        resumed.apply(&[cursor_batch("2026-06-15T00:00:00.000Z")]);
        let (url, _) = serve_heads(vec![(200, vec![], body(&page(&[c(1)], 1))), fail]).await;
        let s = src(&resumed)
            .with_api_url(&url)
            .with_now("2026-07-01T00:00:00Z");
        let (b, end, _) = run(&s, json!({"since": "2026-03-01"})).await;
        resumed.apply(&b);
        assert_eq!(end.entry.status, status);
        let o = ops(&b);
        assert_eq!(
            sync_row(&o, "nvd:progress")["cursor"],
            "2026-06-28T00:00:00.000Z",
            "{o:#?}"
        );
        if status == "partial" {
            assert_eq!(sync_row(&o, "nvd")["cursor"], "2026-06-28T00:00:00.000Z");
        } else {
            assert!(
                !sync_row(&o, "nvd").contains_key("cursor"),
                "an error keeps the stored cursor"
            );
        }
        // the next run resumes after the completed window instead of downloading it again
        let (url, log) = serve_heads(vec![(200, vec![], body(&page(&[], 0)))]).await;
        let s = src(&resumed)
            .with_api_url(&url)
            .with_now("2026-07-01T00:00:00Z");
        let (_, end, _) = run(&s, json!({})).await;
        assert_eq!(end.entry.status, "ok");
        let first = request_line(&log.lock().unwrap()[0]);
        assert!(
            first.contains("lastModStartDate=2026-06-28T00%3A00%3A00.000Z"),
            "{first}"
        );
    }

    // a bad --since: error before any request
    let (b, end, _) = run(
        &src(&view).with_api_url("http://127.0.0.1:9"),
        json!({"since": "yesterday"}),
    )
    .await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.message.as_deref()),
        (
            "error",
            Some("ValueError: Invalid isoformat string: 'yesterday'")
        )
    );
    assert_eq!(ops(&b).len(), 1);
    // a cursor in the future: no window, nothing requested, the cursor kept
    let (b, end, _) = run(
        &src(&view)
            .with_api_url("http://127.0.0.1:9")
            .with_now("2025-01-01T00:00:00Z"),
        json!({}),
    )
    .await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 0));
    assert!(!sync_row(&ops(&b), "nvd").contains_key("cursor"));
}

#[tokio::test(flavor = "multi_thread")]
async fn retries_follow_retry_after_and_give_up_after_the_last_one() {
    let c = cve("CVE-2094-0001", "m", &[("v:p", "1")]);
    let (url, log) = serve_heads(vec![
        (503, vec![("Retry-After", "0".into())], b"busy".to_vec()),
        (0, vec![], Vec::new()), // connection closed without an answer: a transport error
        (200, vec![], body(&page(std::slice::from_ref(&c), 1))),
    ])
    .await;
    let view = MemView::new();
    let s = src(&view)
        .with_api_url(&url)
        .with_now("2026-01-01T00:00:00Z");
    let (_, end, lines) = run_key(&s, json!({"full": true})).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("ok", 1),
        "{lines:?}"
    );
    assert_eq!(log.lock().unwrap().len(), 3);
    assert!(
        lines[0].starts_with("nvd: native importer: HTTP 503 for ")
            && lines[0].ends_with("; retry 1 of 2 in 0.0 s"),
        "{lines:?}"
    );
    assert!(lines[1].contains("retry 2 of 2"), "{lines:?}");
    assert!(!format!("{lines:?}{end:?}").contains(KEY));

    // a status that is not retried, then retries used up
    let (url, log) = serve_heads(vec![(400, vec![], Vec::new())]).await;
    let (_, end, _) = run(&src(&view).with_api_url(&url), json!({"full": true})).await;
    assert_eq!(end.entry.status, "error");
    assert_eq!(log.lock().unwrap().len(), 1);
    let (url, log) = serve_heads(vec![
        (429, vec![], Vec::new()),
        (429, vec![], Vec::new()),
        (429, vec![], Vec::new()),
    ])
    .await;
    let (_, end, _) = run(&src(&view).with_api_url(&url), json!({"full": true})).await;
    assert_eq!(
        end.entry.message,
        Some(format!("HTTPStatusError: HTTP 429 for {url}"))
    );
    assert_eq!(log.lock().unwrap().len(), 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn redirects_are_not_followed_and_ids_are_requested_one_by_one() {
    let (elsewhere, other_log) = serve_heads(vec![(200, vec![], b"{}".to_vec())]).await;
    let (url, _) = serve_heads(vec![(
        302,
        vec![("Location", format!("{elsewhere}/steal"))],
        Vec::new(),
    )])
    .await;
    let view = MemView::new();
    let (_, end, _) = run_key(&src(&view).with_api_url(&url), json!({"full": true})).await;
    assert_eq!(end.entry.status, "error");
    assert!(
        end.entry
            .message
            .as_deref()
            .unwrap()
            .starts_with("HTTPStatusError: HTTP 302 for ")
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        other_log.lock().unwrap().is_empty(),
        "the key never left the API origin"
    );

    let c = |id: &str| cve(id, "m", &[("v:p", "1")]);
    let (url, log) = serve_heads(vec![
        (200, vec![], body(&page(&[c("CVE-2093-0001")], 1))),
        (200, vec![], body(&page(&[], 0))),
    ])
    .await;
    let (b, end, _) = run(
        &src(&view).with_api_url(&url),
        json!({"ids": [" cve-2093-0001 ", "CVE-2093-9999"]}),
    )
    .await;
    assert_eq!(
        (
            end.entry.status.as_str(),
            end.entry.records,
            end.entry.message.as_deref()
        ),
        ("ok", 1, Some("2 ids"))
    );
    let lines: Vec<String> = log
        .lock()
        .unwrap()
        .iter()
        .map(|h| request_line(h))
        .collect();
    assert_eq!(
        lines,
        vec![
            "GET /?cveId=CVE-2093-0001 HTTP/1.1",
            "GET /?cveId=CVE-2093-9999 HTTP/1.1"
        ]
    );
    assert!(!sync_row(&ops(&b), "nvd").contains_key("cursor"));
}

#[tokio::test(flavor = "multi_thread")]
async fn requests_are_paced_and_capped() {
    let (url, log) = serve_heads(vec![
        (200, vec![], body(&page(&[], 0))),
        (200, vec![], body(&page(&[], 0))),
    ])
    .await;
    let view = MemView::new();
    let pace = Timing {
        pause_without_key: Duration::from_millis(300),
        ..fast()
    };
    let s = src(&view).with_api_url(&url).with_timing(pace);
    let t = std::time::Instant::now();
    let (_, end, _) = run(&s, json!({"ids": ["A", "B"]})).await;
    assert_eq!(end.entry.status, "ok");
    assert!(
        t.elapsed() >= Duration::from_millis(300),
        "{:?}",
        t.elapsed()
    );
    assert_eq!(log.lock().unwrap().len(), 2);

    let (url, _) = serve_heads(vec![(
        200,
        vec![],
        body(&page(&[cve("CVE-2092-1", "m", &[])], 5)),
    )])
    .await;
    let caps = Caps {
        requests: 1,
        ..Caps::default()
    };
    let (_, end, _) = run(
        &src(&view).with_api_url(&url).with_caps(caps),
        json!({"full": true}),
    )
    .await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("partial", 1)
    );
    assert_eq!(
        end.entry.message.as_deref(),
        Some("nvd: more than 1 API requests in one run; refusing")
    );
    // a page claiming more results with a non-number total: Python's comparison fails after the page
    let mut p = page(&[cve("CVE-2092-2", "m", &[])], 1);
    p["totalResults"] = json!("many");
    let (url, _) = serve_heads(vec![(200, vec![], body(&p))]).await;
    let (b, end, _) = run(&src(&view).with_api_url(&url), json!({"full": true})).await;
    assert_eq!(end.entry.status, "error");
    assert_eq!(
        end.entry.message.as_deref(),
        Some("TypeError: '>=' not supported between instances of 'int' and 'str'")
    );
    assert_eq!(
        of(&ops(&b), MirrorTable::Vulnerability, true).len(),
        1,
        "the page was written"
    );
}
