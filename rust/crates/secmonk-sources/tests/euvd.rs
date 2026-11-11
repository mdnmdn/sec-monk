//! The native EUVD source over an in-memory mirror (`common::MemView`): rows of a record, children replaced only when
//! they change, duplicate ids, limit, chunks of `rows_by_id`, errors, caps, and the API (a local HTTP server, never
//! the network). Fixture: `tests/fixtures/sources/euvd` of the repository (read only, synthetic). The comparison with
//! the Python source is `secmonk-engine/tests/native_euvd.rs` (differential test).

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use common::{MemView, of, ops, serve, serve_logged};
use secmonk_model::{JsonMap, MirrorTable, RowOp};
use secmonk_sources::batch::Limits;
use secmonk_sources::euvd::{Caps, EuvdSource};
use secmonk_traits::{ErrorCode, NATIVE_GENERATION, RowsBatch, Source, SyncEnd};
use serde_json::{Value, json};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../tests/fixtures/sources/euvd/exploited-sample.json")
}

fn src(view: &Arc<MemView>) -> EuvdSource {
    EuvdSource::new(view.clone())
}

async fn run(src: &EuvdSource, options: Value) -> (Vec<RowsBatch>, SyncEnd) {
    let (b, end, _) = common::run(src, "euvd", options).await;
    (b, end)
}

/// Run and apply to the in-memory mirror.
async fn sync(view: &Arc<MemView>, src: &EuvdSource, options: Value) -> (Vec<RowOp>, SyncEnd) {
    let (b, end) = run(src, options).await;
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

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

fn col(rows: &[JsonMap], c: &str) -> Vec<String> {
    sorted(
        rows.iter()
            .map(|r| match &r[c] {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect(),
    )
}

#[tokio::test]
async fn the_fixture_becomes_raw_vulnerability_alias_and_epss_rows() {
    let view = MemView::new();
    let s = src(&view);
    let (all, end) = sync(&view, &s, path_opts(&fixture())).await;
    assert_eq!(end.entry.status, "ok");
    assert_eq!(end.entry.records, 2);
    assert_eq!(
        end.entry.message.as_deref().unwrap(),
        format!("2 records from file {}", fixture().display())
    );
    assert_eq!(view.rows(MirrorTable::RawRecord).len(), 2);
    let vulns = view.rows(MirrorTable::Vulnerability);
    let log4j = vulns.iter().find(|r| r["id"] == "EUVD-2021-30001").unwrap();
    assert_eq!(log4j["severity"], "CRITICAL");
    assert_eq!(log4j["cvss_score"], json!(10.0));
    assert_eq!(
        log4j["extra"],
        json!({"exploited": true, "epss": 0.97431, "assigner": "psirt@apache.org", "vendors": [],
               "products": []})
    );
    assert_eq!(
        view.rows(MirrorTable::Alias),
        vec![
            json!({"vuln_id": "EUVD-2021-30001", "alias": "CVE-2021-44228", "source": "euvd", "kind": "alias"})
                .as_object()
                .cloned()
                .unwrap()
        ]
    );
    assert_eq!(
        view.rows(MirrorTable::Epss),
        vec![
            json!({"cve_id": "CVE-2021-44228", "score": 0.97431, "percentile": null, "date": "2026-11-06",
                   "source": "euvd"})
            .as_object()
            .cloned()
            .unwrap()
        ]
    );
    assert!(of(&all, MirrorTable::Affected, true).is_empty());
    let sync_row = view.rows(MirrorTable::SourceSync);
    assert_eq!(sync_row[0]["records"], 2);
    assert!(
        sync_row[0].get("cursor").is_none(),
        "no cursor: the stored one is kept"
    );

    // the same file again: raw, vulnerability and epss rows refreshed, the unchanged aliases left alone
    let (all, end) = sync(&view, &s, path_opts(&fixture())).await;
    assert_eq!(end.entry.status, "ok");
    assert!(of(&all, MirrorTable::Alias, true).is_empty());
    assert!(of(&all, MirrorTable::Alias, false).is_empty());
    assert_eq!(of(&all, MirrorTable::Vulnerability, true).len(), 2);
    let b = run(&s, path_opts(&fixture())).await.0;
    assert_eq!(b[0].seq, 3, "seqs continue the native generation");
    assert_eq!(b[0].generation.as_deref(), Some(NATIVE_GENERATION));
}

#[tokio::test]
async fn children_follow_the_record_and_only_the_last_record_of_an_id_counts() {
    let view = MemView::new();
    let s = src(&view).with_limits(Limits {
        ops: 3,
        bytes: 1 << 20,
    });
    let d = tempfile::tempdir().unwrap();
    let rec = |id: &str, aliases: &str, products: Value, epss: Value| {
        json!({"id": id, "aliases": aliases, "products": products, "epss": epss,
               "dateUpdated": "2026-11-01T00:00:00Z", "baseScore": 5.0})
    };
    let first = write(
        d.path(),
        "first.json",
        &json!([
            rec(
                "EUVD-1",
                "CVE-1\nCVE-2",
                json!([{"vendor": "Acme", "product": "One", "version": "1"},
                                                 {"vendor": "Acme", "product": "Two"}]),
                json!(0.1)
            ),
            rec("EUVD-2", "CVE-3", json!([]), json!(null)),
        ]),
    );
    let (_, end) = sync(&view, &s, path_opts(&first)).await;
    assert_eq!(end.entry.status, "ok", "{end:?}");
    assert_eq!(
        col(&view.rows(MirrorTable::Affected), "product"),
        vec!["one", "two"]
    );
    assert_eq!(
        col(&view.rows(MirrorTable::Alias), "alias"),
        vec!["CVE-1", "CVE-2", "CVE-3"]
    );

    // EUVD-1 changes: one product and one alias less, another alias; EUVD-1 appears twice (the later one counts,
    // the earlier one's epss rows stay, as in Python); EUVD-2 unchanged
    let second = write(
        d.path(),
        "second.json",
        &json!({"items": [
            rec("EUVD-1", "CVE-9", json!([]), json!(0.9)),
            rec("EUVD-2", "CVE-3", json!([]), json!(null)),
            rec("EUVD-1", "CVE-1, cve-4", json!([{"vendor": "Acme", "product": "One", "version": "1"}]),
                json!(0.2)),
        ]}),
    );
    let (all, end) = sync(&view, &s, path_opts(&second)).await;
    assert_eq!(end.entry.records, 2, "distinct ids");
    assert_eq!(
        col(&view.rows(MirrorTable::Affected), "product"),
        vec!["one"]
    );
    assert_eq!(
        col(&view.rows(MirrorTable::Alias), "alias"),
        vec!["CVE-1", "CVE-3", "CVE-4"]
    );
    assert_eq!(
        of(&all, MirrorTable::Alias, false),
        vec![
            json!({"vuln_id": "EUVD-1", "alias": "CVE-2", "source": "euvd"})
                .as_object()
                .cloned()
                .unwrap()
        ]
    );
    // the earlier EUVD-1 record wrote CVE-9's score; the later one CVE-1 and CVE-4
    let epss = view.rows(MirrorTable::Epss);
    let score = |c: &str| {
        epss.iter()
            .find(|r| r["cve_id"] == c)
            .map(|r| r["score"].clone())
    };
    assert_eq!(score("CVE-9"), Some(json!(0.9)));
    assert_eq!(score("CVE-1"), Some(json!(0.2)));
    assert_eq!(score("CVE-2"), Some(json!(0.1)), "never deleted");
    assert_eq!(
        of(&all, MirrorTable::RawRecord, true).len(),
        2,
        "one raw row per id"
    );
    // affected of EUVD-1 replaced (2 deletes keyed by the record, 1 insert); EUVD-2 untouched
    let deletes = of(&all, MirrorTable::Affected, false);
    assert_eq!(deletes.len(), 2);
    assert!(
        deletes
            .iter()
            .all(|k| k.len() == 2 && k["vuln_id"] == "EUVD-1")
    );
}

#[tokio::test]
async fn limit_errors_and_a_bad_record_store_nothing() {
    let view = MemView::new();
    let s = src(&view);
    let d = tempfile::tempdir().unwrap();
    let (all, end) = sync(
        &view,
        &s,
        json!({"path": fixture().display().to_string(), "limit": 1}),
    )
    .await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 1));
    assert_eq!(of(&all, MirrorTable::Vulnerability, true).len(), 1);

    let bad = write(
        d.path(),
        "bad.json",
        &json!([{"id": "EUVD-1", "aliases": "CVE-1"}, {"id": "EUVD-2", "aliases": "CVE-2", "epss": "x"}]),
    );
    let not_json = d.path().join("not.json");
    std::fs::write(&not_json, "{").unwrap();
    let shape = write(d.path(), "shape.json", &json!({"total": 0}));
    let latin1 = d.path().join("latin1.json");
    std::fs::write(&latin1, b"[{\"id\": \"caf\xe9\"}]").unwrap();
    let missing = d.path().join("missing.json");
    for (p, msg) in [
        (
            bad.clone(),
            "could not convert string to float: 'x'".to_owned(),
        ),
        (
            shape,
            "unexpected EUVD response shape (no list of records)".to_owned(),
        ),
        (
            latin1,
            "'utf-8' codec can't decode byte 0xe9 in position 12: invalid continuation byte"
                .to_owned(),
        ),
        (
            missing.clone(),
            format!(
                "[Errno 2] No such file or directory: '{}'",
                missing.display()
            ),
        ),
        (
            d.path().to_path_buf(),
            format!("[Errno 21] Is a directory: '{}'", d.path().display()),
        ),
    ] {
        let (all, end) = run(&s, path_opts(&p)).await;
        let all = ops(&all);
        assert_eq!(end.entry.status, "error", "{p:?}");
        assert_eq!(end.entry.message.as_deref(), Some(msg.as_str()), "{p:?}");
        assert_eq!(all.len(), 1, "only the source_sync row: {all:?}");
    }
    let (_, end) = run(&s, path_opts(&not_json)).await;
    assert!(end.entry.message.unwrap().starts_with("invalid JSON"));
    // limit 0 is refused as py-sources refuses it
    let e = match s
        .sync(
            common::params("euvd", json!({"limit": 0})),
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
async fn many_records_are_read_in_chunks_and_caps_refuse_large_input() {
    let view = MemView::new();
    let s = src(&view);
    let d = tempfile::tempdir().unwrap();
    let many: Vec<Value> = (0..700)
        .map(|i| {
            json!({"id": format!("EUVD-{i}"), "aliases": format!("CVE-{i}"),
                        "products": [{"product": "p"}]})
        })
        .collect();
    let p = write(d.path(), "many.json", &Value::Array(many));
    // MemView::rows_by_id asserts at most MAX_VIEW_IDS ids per call
    let (_, end) = sync(&view, &s, path_opts(&p)).await;
    assert_eq!(end.entry.records, 700);
    assert_eq!(view.rows(MirrorTable::Affected).len(), 700);
    let (all, _) = sync(&view, &s, path_opts(&p)).await;
    assert!(
        of(&all, MirrorTable::Affected, true).is_empty(),
        "unchanged"
    );

    let capped = src(&view).with_caps(Caps {
        records: 600,
        ..Caps::default()
    });
    let (_, end) = run(&capped, path_opts(&p)).await;
    assert_eq!(
        end.entry.message.as_deref(),
        Some("euvd: more than 600 records; refusing")
    );
    let capped = src(&view).with_caps(Caps {
        total_bytes: 1_000,
        ..Caps::default()
    });
    let (_, end) = run(&capped, path_opts(&p)).await;
    assert!(
        end.entry
            .message
            .unwrap()
            .ends_with("larger than 1000 bytes")
    );
}

#[tokio::test]
async fn the_api_views_and_pages_are_read_in_order() {
    let view = MemView::new();
    let exploited = json!({"items": [{"id": "EUVD-E", "exploited": false}]});
    let last = json!([{"id": "EUVD-L"}, {"id": "EUVD-E", "exploited": false}]);
    let page =
        |ids: &[&str]| json!({"content": ids.iter().map(|i| json!({"id": i})).collect::<Vec<_>>()});
    let body = |v: &Value| serde_json::to_vec(v).unwrap();
    let (base, log) = serve_logged(vec![
        (200, body(&exploited)),
        (200, body(&last)),
        (200, body(&page(&["EUVD-P1", "EUVD-P2"]))),
        (200, body(&page(&["EUVD-P3", "EUVD-P4"]))),
    ])
    .await;
    let s = src(&view).with_base_url(&format!("{base}/api"));
    let (_, end) = sync(&view, &s, json!({"limit": 3})).await;
    assert_eq!(end.entry.status, "ok", "{end:?}");
    assert_eq!(end.entry.records, 5);
    assert_eq!(
        end.entry.message.as_deref().unwrap(),
        format!("5 records from {base}/api")
    );
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            "GET /api/exploitedvulnerabilities?size=100 HTTP/1.1",
            "GET /api/lastvulnerabilities HTTP/1.1",
            "GET /api/vulnerabilities?page=0&size=100 HTTP/1.1",
            "GET /api/vulnerabilities?page=1&size=100 HTTP/1.1",
        ]
    );
    let ids = col(&view.rows(MirrorTable::Vulnerability), "id");
    assert_eq!(
        ids,
        vec!["EUVD-E", "EUVD-L", "EUVD-P1", "EUVD-P2", "EUVD-P3"]
    );
    // EUVD-E came last from the recent view, which is not the exploited one: Python stores exploited = false
    let e = view
        .rows(MirrorTable::Vulnerability)
        .into_iter()
        .find(|r| r["id"] == "EUVD-E")
        .unwrap();
    assert_eq!(e["extra"]["exploited"], false);

    // without limit: two requests; an HTTP error is the run's error
    let base = serve(vec![(200, body(&exploited)), (404, b"no".to_vec())]).await;
    let s = src(&view).with_base_url(&base);
    let (b, end) = run(&s, json!({})).await;
    assert_eq!(end.entry.status, "error");
    assert_eq!(
        end.entry.message.as_deref(),
        Some(format!("HTTP 404 for {base}/lastvulnerabilities").as_str())
    );
    assert_eq!(ops(&b).len(), 1);
}

#[tokio::test]
async fn a_repeated_id_across_chunks_and_identical_products() {
    // review W9.1 L6: the two records of an id in different chunks (at most 500 records each); two identical
    // products are two rows, kept when unchanged and both removed when one goes
    let view = MemView::new();
    let s = src(&view);
    let d = tempfile::tempdir().unwrap();
    let p = json!({"vendor": "Acme", "product": "Same", "version": "1"});
    let mut items: Vec<Value> = vec![
        json!({"id": "EUVD-X", "aliases": "CVE-9", "epss": 0.9, "products": [{"product": "Old"}]}),
    ];
    items.extend((0..600).map(|i| json!({"id": format!("EUVD-{i}")})));
    items.push(json!({"id": "EUVD-X", "aliases": "CVE-1", "epss": 0.1, "products": [p, p]}));
    let path = write(d.path(), "cross.json", &Value::Array(items.clone()));
    let (_, end) = sync(&view, &s, path_opts(&path)).await;
    assert_eq!(end.entry.records, 601);
    let x = |t: MirrorTable| -> Vec<JsonMap> {
        view.rows(t)
            .into_iter()
            .filter(|r| r.get("vuln_id").or(r.get("id")) == Some(&json!("EUVD-X")))
            .collect()
    };
    assert_eq!(
        col(&x(MirrorTable::Affected), "product"),
        vec!["same", "same"]
    );
    assert_eq!(col(&x(MirrorTable::Alias), "alias"), vec!["CVE-1"]);
    let epss = view.rows(MirrorTable::Epss);
    assert_eq!(
        epss.len(),
        2,
        "the earlier record's CVE-9 score stays: {epss:?}"
    );
    // the same file: the two identical rows are not rewritten
    let (all, _) = sync(&view, &s, path_opts(&path)).await;
    assert!(of(&all, MirrorTable::Affected, true).is_empty());
    assert!(of(&all, MirrorTable::Affected, false).is_empty());
    // one of the two goes: both stored rows deleted, one inserted
    *items.last_mut().unwrap() =
        json!({"id": "EUVD-X", "aliases": "CVE-1", "epss": 0.1, "products": [p]});
    let path = write(d.path(), "one.json", &Value::Array(items));
    let (all, _) = sync(&view, &s, path_opts(&path)).await;
    assert_eq!(of(&all, MirrorTable::Affected, false).len(), 2);
    assert_eq!(of(&all, MirrorTable::Affected, true).len(), 1);
    assert_eq!(x(MirrorTable::Affected).len(), 1);
}

#[tokio::test]
async fn stored_rows_beyond_the_caps_refuse_the_run() {
    // rows py-sources wrote from a record above the children cap (before a switch): refused, not read in chunks
    let view = MemView::new();
    let rows: Vec<Value> = (0..30)
        .map(|i| {
            json!({"op": "upsert", "table": "affected",
                   "row": {"source": "euvd", "vuln_id": "EUVD-1", "product": format!("p{i}")}})
        })
        .collect();
    let b: RowsBatch =
        serde_json::from_value(json!({"kind": "rows", "seq": 1, "source": "euvd", "ops": rows}))
            .unwrap();
    view.apply(&[b]);
    let s = src(&view).with_caps(Caps {
        children: 20,
        ..Caps::default()
    });
    let d = tempfile::tempdir().unwrap();
    let path = write(d.path(), "one.json", &json!([{"id": "EUVD-1"}]));
    let mut stream = s
        .sync(common::params("euvd", path_opts(&path)), Default::default())
        .await
        .unwrap();
    let mut err = None;
    while let Some(m) = futures_util::StreamExt::next(&mut stream).await {
        if let Err(e) = m {
            err = Some(e);
        }
    }
    let e = err.expect("the stream ends with an error");
    assert_eq!(
        e.error,
        "euvd: native importer: EUVD-1: 30 stored affected rows (more than 20); refusing, sync euvd with the \
         python implementation"
    );
}
