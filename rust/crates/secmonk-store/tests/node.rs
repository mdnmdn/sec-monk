//! Mirror-node storage: versions, changed ids, lookup keys, summaries, feed rows (round trip between two mirrors),
//! snapshot diffs and the state-side match cache.

use std::collections::BTreeMap;

use secmonk_model::node::*;
use secmonk_model::*;
use secmonk_store::*;
use serde_json::{Value, json};

async fn open(dir: &std::path::Path) -> SqliteStore {
    SqliteStore::open(
        &dir.join("state.sqlite3"),
        &dir.join("mirror.sqlite3"),
        &StoreOptions::default(),
    )
    .await
    .unwrap()
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
        "published": "2024-01-01T00:00:00Z", "modified": modified});
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

/// A mirror with two record sources, KEV, EPSS and debian-tracker rows.
async fn fill(store: &SqliteStore) {
    store
        .apply_rows(&batch(
            "osv",
            1,
            json!([
                vuln(
                    "osv",
                    "GHSA-1",
                    "2024-02-01T10:00:00Z",
                    json!({"severity": "HIGH"})
                ),
                raw("osv", "GHSA-1", "2024-02-01T10:00:00Z"),
                alias("osv", "GHSA-1", "CVE-1"),
                alias("osv", "GHSA-1", "PYSEC-1"),
                aff("osv", "GHSA-1", Some("PyPI"), Some("requests"), None),
                aff("osv", "GHSA-1", Some("PyPI"), Some("requests"), None),
                vuln(
                    "osv",
                    "GHSA-2",
                    "2024-03-01T10:00:00Z",
                    json!({"cvss_score": 5.5})
                ),
                raw("osv", "GHSA-2", "2024-03-01T10:00:00Z"),
                aff("osv", "GHSA-2", Some("npm"), Some("left-pad"), None),
                vuln("osv", "GHSA-3", "2024-04-01T10:00:00Z", json!({})),
                aff("osv", "GHSA-3", Some("PyPI"), Some("flask"), None),
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
                    "2024-02-02T00:00:00.000",
                    json!({"severity": "CRITICAL", "cvss_score": 9.8,
                           "cvss_vector": "CVSS:3.1/AV:N", "published": "2023-12-31T00:00:00.000"})
                ),
                raw("nvd", "CVE-1", "2024-02-02T00:00:00.000"),
                aff("nvd", "CVE-1", None, None, Some("Requests")),
            ]),
        ))
        .await
        .unwrap();
    store
        .apply_rows(&batch(
            "kev",
            1,
            json!([
                up(
                    "kev",
                    json!({"cve_id": "CVE-1", "vendor": "v", "product": "p", "name": "n",
                                 "date_added": "2024-05-05", "source": "kev", "extra": {"a": 1}})
                ),
                up(
                    "kev",
                    json!({"cve_id": "CVE-9", "date_added": "2024-05-06", "source": "kev"})
                ),
            ]),
        ))
        .await
        .unwrap();
    store
        .apply_rows(&batch(
            "epss",
            1,
            json!([up(
                "epss",
                json!({"cve_id": "CVE-1", "score": 0.25, "percentile": 0.9, "date": "2024-05-05", "source": "epss"})
            )]),
        ))
        .await
        .unwrap();
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

async fn assert_same(a: &SqliteStore, b: &SqliteStore, source: &str) {
    for t in [
        MirrorTable::Vulnerability,
        MirrorTable::Alias,
        MirrorTable::Affected,
        MirrorTable::RawRecord,
    ] {
        assert_eq!(
            dump(a, t, source).await,
            dump(b, t, source).await,
            "{} of {source}",
            t.as_str()
        );
    }
}

/// Apply every page of a feed to `b` the way a follower does: localize, cut, apply with fresh seqs.
async fn follow(
    a: &SqliteStore,
    b: &SqliteStore,
    source: &str,
    since: Option<&str>,
    limit: usize,
) -> usize {
    let mut page = None;
    let mut pages = 0;
    let mut seq = b.applied_seq(source).await.unwrap().unwrap_or(0);
    loop {
        let (batches, next) = a
            .rows_since(source, since, page.as_deref(), limit)
            .await
            .unwrap();
        pages += 1;
        for mut bt in batches {
            let ops = b.localize_feed_batch(&bt).await.unwrap();
            for chunk in ops.chunks(5000) {
                seq += 1;
                bt.seq = seq;
                bt.ops = chunk.to_vec();
                b.apply_rows(&bt).await.unwrap();
            }
        }
        match next {
            Some(n) => page = Some(n),
            None => return pages,
        }
    }
}

#[tokio::test]
async fn versions_follow_complete_imports_only() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path()).await;
    let sync = |source: &str, cursor: Option<&str>, status: &str, records: u64| {
        batch(
            source,
            1,
            json!([up(
                "source_sync",
                json!({"source": source, "last_sync": "2026-11-01T00:00:00+00:00",
                       "cursor": cursor, "records": records, "status": status})
            )]),
        )
    };
    s.apply_rows(&sync("nvd", Some("2026-10-31T00:00:00.000"), "ok", 10))
        .await
        .unwrap();
    s.apply_rows(&sync("cvelist", Some("2026-10-30T00:00:00Z"), "partial", 5))
        .await
        .unwrap();
    s.apply_rows(&sync("kev", None, "error", 0)).await.unwrap();
    s.apply_rows(&sync("euvd", Some("2026-01-01T00:00:00Z"), "ok", 2))
        .await
        .unwrap();
    let v = |vs: &[SourceVersion], n: &str| vs.iter().find(|x| x.source == n).cloned().unwrap();

    let vs = s.source_versions().await.unwrap();
    assert_eq!(
        vs.iter().map(|x| x.source.as_str()).collect::<Vec<_>>(),
        ["cvelist", "euvd", "kev", "nvd"]
    );
    // ok: the cursor, importer unknown; partial / error: no version
    assert_eq!(
        v(&vs, "nvd").version.as_deref(),
        Some("2026-10-31T00:00:00.000")
    );
    assert_eq!(v(&vs, "nvd").importer, "unknown");
    assert_eq!(v(&vs, "nvd").records, 10);
    assert_eq!(v(&vs, "cvelist").version, None);
    assert_eq!(v(&vs, "kev").version, None);
    assert_eq!(v(&vs, "kev").kind, VersionKind::Snapshot);
    assert_eq!(v(&vs, "nvd").kind, VersionKind::Record);

    // a recorded complete version wins, and a later partial run does not move it
    s.record_complete_version(
        "cvelist",
        "2026-10-01T00:00:00Z",
        "rust/1",
        VersionKind::Record,
    )
    .await
    .unwrap();
    s.record_complete_version(
        "nvd",
        "2026-10-20T00:00:00.000",
        "rust/1",
        VersionKind::Record,
    )
    .await
    .unwrap();
    let vs = s.source_versions().await.unwrap();
    assert_eq!(
        v(&vs, "cvelist").version.as_deref(),
        Some("2026-10-01T00:00:00Z")
    );
    assert_eq!(v(&vs, "cvelist").status.as_deref(), Some("partial"));
    assert_eq!(
        v(&vs, "nvd").version.as_deref(),
        Some("2026-10-20T00:00:00.000")
    );
    assert_eq!(v(&vs, "nvd").importer, "rust/1");
    let versions = Versions::new(MATCHER_VERSION, vs);
    assert_eq!(versions.since()["nvd"], "rust/1@2026-10-20T00:00:00.000");
    assert!(!versions.since().contains_key("kev"));

    // replaced, not duplicated; bad input refused
    s.record_complete_version(
        "nvd",
        "2026-10-25T00:00:00.000",
        "rust/2",
        VersionKind::Record,
    )
    .await
    .unwrap();
    let vs = s.source_versions().await.unwrap();
    assert_eq!(v(&vs, "nvd").importer, "rust/2");
    assert!(
        s.record_complete_version("nvd", "v", "a@b", VersionKind::Record)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn changed_vulns_read_from_the_overlap() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path()).await;
    fill(&s).await;
    let ids = |v: Vec<(String, String)>| v.into_iter().map(|x| x.0).collect::<Vec<_>>();
    assert_eq!(
        ids(s
            .changed_vulns("osv", "2024-02-15T00:00:00Z", 0, 10)
            .await
            .unwrap()),
        ["GHSA-2", "GHSA-3"]
    );
    // 30 days of overlap reaches back to GHSA-1 (2024-02-01)
    assert_eq!(
        ids(s
            .changed_vulns("osv", "2024-02-15T00:00:00Z", 30 * 86_400, 10)
            .await
            .unwrap()),
        ["GHSA-1", "GHSA-2", "GHSA-3"]
    );
    // strictly after: the stored value itself is not newer than itself
    assert_eq!(
        ids(s
            .changed_vulns("osv", "2024-03-01T10:00:00Z", 0, 10)
            .await
            .unwrap()),
        ["GHSA-3"]
    );
    // one hour of overlap includes a record 10 minutes below the version
    assert_eq!(
        ids(s
            .changed_vulns("osv", "2024-03-01T10:10:00Z", 3600, 10)
            .await
            .unwrap()),
        ["GHSA-2", "GHSA-3"]
    );
    assert_eq!(
        s.changed_vulns("osv", "2024-02-15T00:00:00Z", 0, 1)
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        s.changed_vulns("nvd", "2030-01-01T00:00:00Z", 0, 10)
            .await
            .unwrap()
            .is_empty()
    );
    // the nvd's own timestamp shape compares with itself
    assert_eq!(
        ids(s
            .changed_vulns("nvd", "2024-02-01T23:00:00.000", 3600, 10)
            .await
            .unwrap()),
        ["CVE-1"]
    );
}

#[tokio::test]
async fn lookup_keys_come_from_affected_rows() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path()).await;
    fill(&s).await;
    let ids = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    assert_eq!(
        s.lookup_keys_for_vulns(&ids(&["GHSA-1", "GHSA-2", "CVE-1", "nope"]))
            .await
            .unwrap(),
        ["pkg:npm/left-pad", "pkg:pypi/requests", "prod:requests"]
    );
    assert!(s.lookup_keys_for_vulns(&[]).await.unwrap().is_empty());
    // more ids than one IN list holds
    let many: Vec<String> = (0..1200)
        .map(|i| format!("X-{i}"))
        .chain(["GHSA-3".to_string()])
        .collect();
    assert_eq!(
        s.lookup_keys_for_vulns(&many).await.unwrap(),
        ["pkg:pypi/flask"]
    );
    assert_eq!(s.covered_ecosystems().await.unwrap(), ["PyPI", "npm"]);
}

#[tokio::test]
async fn summaries_merge_rows_aliases_kev_and_epss() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path()).await;
    fill(&s).await;
    let got = s
        .summaries(&[
            "CVE-1".into(),
            "GHSA-1".into(),
            "CVE-9".into(),
            "NOPE".into(),
            "CVE-1".into(),
        ])
        .await
        .unwrap();
    assert_eq!(
        got.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(),
        ["CVE-1", "GHSA-1", "CVE-9"]
    );
    let cve = &got[0];
    assert_eq!(cve.aliases, ["GHSA-1"]);
    assert_eq!(cve.summary.as_deref(), Some("CVE-1 summary"));
    assert_eq!(cve.severity.as_deref(), Some("CRITICAL"));
    assert_eq!(cve.cvss_score, Some(9.8));
    assert_eq!(cve.cvss_vector.as_deref(), Some("CVSS:3.1/AV:N"));
    assert_eq!(cve.published.as_deref(), Some("2023-12-31T00:00:00.000"));
    assert_eq!(cve.modified.as_deref(), Some("2024-02-02T00:00:00.000"));
    assert!(cve.kev);
    assert_eq!(cve.kev_date_added.as_deref(), Some("2024-05-05"));
    assert_eq!(cve.epss, Some(0.25));
    assert_eq!(cve.epss_percentile, Some(0.9));
    assert_eq!(cve.sources, ["epss", "kev", "nvd", "osv"]);
    // an advisory id: its own text, the nvd's cvss through the alias, kev and epss through the alias
    let ghsa = &got[1];
    assert_eq!(ghsa.aliases, ["CVE-1", "PYSEC-1"]);
    assert_eq!(ghsa.summary.as_deref(), Some("GHSA-1 summary"));
    assert_eq!(ghsa.cvss_score, Some(9.8));
    assert_eq!(ghsa.severity.as_deref(), Some("CRITICAL"));
    assert!(ghsa.kev);
    // kev only
    let k = &got[2];
    assert!(k.kev && k.summary.is_none() && k.sources == ["kev"]);
    // no nvd/cvelist row: another source's score is used
    let g2 = s.summaries(&["GHSA-2".into()]).await.unwrap();
    assert_eq!(g2[0].cvss_score, Some(5.5));
    assert!(!g2[0].kev);
}

#[tokio::test]
async fn feed_rows_round_trip_between_mirrors() {
    let d = tempfile::tempdir().unwrap();
    let (da, db) = (d.path().join("a"), d.path().join("b"));
    let a = open(&da).await;
    let b = open(&db).await;
    fill(&a).await;

    // everything, in pages of two records
    let pages = follow(&a, &b, "osv", None, 2).await;
    assert_eq!(pages, 2);
    follow(&a, &b, "nvd", None, 500).await;
    assert_same(&a, &b, "osv").await;
    assert_same(&a, &b, "nvd").await;
    assert_eq!(dump(&b, MirrorTable::Affected, "osv").await.len(), 4);

    // a delta page is a replace unit per record, children included
    let (batches, next) = a
        .rows_since("osv", Some("2024-02-15T00:00:00Z"), None, 10)
        .await
        .unwrap();
    assert!(next.is_none());
    let ops: Vec<(&str, MirrorTable)> = batches
        .iter()
        .flat_map(|b| &b.ops)
        .map(|o| {
            (
                if matches!(o, RowOp::Delete { .. }) {
                    "delete"
                } else {
                    "upsert"
                },
                o.table(),
            )
        })
        .collect();
    assert_eq!(
        ops[..4],
        [
            ("delete", MirrorTable::Affected),
            ("upsert", MirrorTable::Vulnerability),
            ("upsert", MirrorTable::RawRecord),
            ("upsert", MirrorTable::Affected),
        ]
    );
    assert!(
        batches
            .iter()
            .all(|b| b.kind == "rows" && b.generation.is_none() && b.seq >= 1)
    );

    // A changes: GHSA-1 loses an affected row and an alias, GHSA-2 is rewritten; GHSA-3 is untouched
    let mut seq = a.applied_seq("osv").await.unwrap().unwrap();
    seq += 1;
    a.apply_rows(&batch(
        "osv",
        seq,
        json!([
            {"op": "delete", "table": "affected", "key": {"source": "osv", "vuln_id": "GHSA-1"}},
            {"op": "delete", "table": "alias", "key": {"vuln_id": "GHSA-1", "alias": "PYSEC-1", "source": "osv"}},
            vuln("osv", "GHSA-1", "2024-06-01T00:00:00Z", json!({"severity": "LOW"})),
            vuln("osv", "GHSA-2", "2024-06-02T00:00:00Z", json!({"summary": "rewritten"})),
            aff("osv", "GHSA-2", Some("npm"), Some("right-pad"), None),
            aff("osv", "GHSA-2", Some("npm"), Some("left-pad"), None),
        ]),
    ))
    .await
    .unwrap();
    let before = dump(&b, MirrorTable::Vulnerability, "osv").await;
    assert_ne!(before, dump(&a, MirrorTable::Vulnerability, "osv").await);
    follow(&a, &b, "osv", Some("2024-05-01T00:00:00Z"), 10).await;
    assert_same(&a, &b, "osv").await;
    assert_eq!(dump(&b, MirrorTable::Affected, "osv").await.len(), 5);
    assert_eq!(dump(&b, MirrorTable::Alias, "osv").await.len(), 1);

    // an empty mirror has nothing to delete: the markers expand to nothing, the rest is copied
    let c = open(&d.path().join("c")).await;
    let (bt, _) = a.rows_since("osv", None, None, 10).await.unwrap();
    let expect: Vec<RowOp> = bt[0]
        .ops
        .iter()
        .filter(|o| !matches!(o, RowOp::Delete { .. }))
        .cloned()
        .collect();
    assert_eq!(c.localize_feed_batch(&bt[0]).await.unwrap(), expect);
    // a cursor that is not ours is refused
    assert!(a.rows_since("osv", None, Some("d1|x|y"), 1).await.is_err());
    assert!(
        a.rows_since("osv", Some("2024"), Some("i1|x"), 1)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn delta_pages_continue_after_equal_timestamps() {
    let d = tempfile::tempdir().unwrap();
    let a = open(&d.path().join("a")).await;
    let ops: Vec<Value> = (0..7)
        .map(|i| {
            vuln(
                "osv",
                &format!("OSV-{i}"),
                "2024-01-01T00:00:00Z",
                json!({}),
            )
        })
        .collect();
    a.apply_rows(&batch("osv", 1, Value::Array(ops)))
        .await
        .unwrap();
    let mut seen = Vec::new();
    let mut page = None;
    loop {
        let (b, next) = a
            .rows_since("osv", Some("2023-01-01T00:00:00Z"), page.as_deref(), 3)
            .await
            .unwrap();
        for bt in b {
            for op in bt.ops {
                if let RowOp::Upsert {
                    table: MirrorTable::Vulnerability,
                    row,
                } = op
                {
                    seen.push(row["id"].as_str().unwrap().to_owned());
                }
            }
        }
        match next {
            Some(n) => page = Some(n),
            None => break,
        }
    }
    assert_eq!(seen, (0..7).map(|i| format!("OSV-{i}")).collect::<Vec<_>>());
}

#[tokio::test]
async fn snapshot_pages_round_trip_and_diffs_chain() {
    let d = tempfile::tempdir().unwrap();
    let a = open(&d.path().join("a")).await;
    let b = open(&d.path().join("b")).await;
    fill(&a).await;
    a.apply_rows(&batch(
        "debian-tracker",
        1,
        json!([up(
            "distro_triage",
            json!({"ecosystem": "Debian:12", "package": "openssl", "cve_id": "CVE-1", "status": "resolved",
                   "fixed_version": "3.0.1", "source": "debian-tracker"})
        )]),
    ))
    .await
    .unwrap();
    for (source, table) in [
        ("kev", MirrorTable::Kev),
        ("epss", MirrorTable::Epss),
        ("debian-tracker", MirrorTable::DistroTriage),
    ] {
        let mut page = None;
        let mut seq = 0;
        loop {
            let (batches, next) = a.rows_snapshot(source, page.as_deref(), 1).await.unwrap();
            for mut bt in batches {
                seq += 1;
                bt.seq = seq;
                b.apply_rows(&bt).await.unwrap();
            }
            match next {
                Some(n) => page = Some(n),
                None => break,
            }
        }
        assert_eq!(
            dump(&a, table, source).await,
            dump(&b, table, source).await,
            "{source}"
        );
    }
    assert!(a.rows_snapshot("osv", None, 10).await.is_err());

    let diff = |v: &str, prev: Option<&str>| SnapshotDiff {
        source: "kev".into(),
        version: v.into(),
        prev_version: prev.map(Into::into),
        created_at: "2026-11-01T00:00:00+00:00".into(),
        ids: vec![format!("CVE-{v}")],
        keys: vec![format!("prod:{v}")],
    };
    assert_eq!(a.snapshot_diffs_since("kev", "1").await.unwrap(), None);
    for (v, p) in [("2", None), ("3", Some("2")), ("4", Some("3"))] {
        a.snapshot_diff_put(&diff(v, p)).await.unwrap();
    }
    let versions = |r: Option<Vec<SnapshotDiff>>| {
        r.map(|v| v.into_iter().map(|d| d.version).collect::<Vec<_>>())
    };
    assert_eq!(
        versions(a.snapshot_diffs_since("kev", "4").await.unwrap()),
        Some(vec![])
    );
    assert_eq!(
        versions(a.snapshot_diffs_since("kev", "3").await.unwrap()),
        Some(vec!["4".into()])
    );
    assert_eq!(
        versions(a.snapshot_diffs_since("kev", "2").await.unwrap()),
        Some(vec!["3".into(), "4".into()])
    );
    // before the first recorded diff: its prev is unknown, so no chain
    assert_eq!(a.snapshot_diffs_since("kev", "1").await.unwrap(), None);
    let d3 = a.snapshot_diffs_since("kev", "2").await.unwrap().unwrap();
    assert_eq!(d3[0].ids, ["CVE-3"]);
    assert_eq!(d3[0].keys, ["prod:3"]);
    // only the newest SNAPSHOT_DIFF_KEEP are kept
    let mut prev = "4".to_string();
    for i in 5..20 {
        a.snapshot_diff_put(&diff(&i.to_string(), Some(&prev)))
            .await
            .unwrap();
        prev = i.to_string();
    }
    assert_eq!(a.snapshot_diffs_since("kev", "4").await.unwrap(), None);
    assert_eq!(
        a.snapshot_diffs_since("kev", "10")
            .await
            .unwrap()
            .unwrap()
            .len(),
        9
    );
}

fn matched(id: &str, adv: &[&str]) -> ComponentMatch {
    ComponentMatch {
        vuln_id: id.into(),
        advisory_ids: adv.iter().map(|s| s.to_string()).collect(),
        matched_by: Some("osv-package".into()),
        confidence: Some(1.0),
        fixed_version: Some("2.0".into()),
        triage: None,
        triage_source: None,
    }
}

#[tokio::test]
async fn node_cache_keeps_answers_lookups_and_summaries() {
    let d = tempfile::tempdir().unwrap();
    let s = open(d.path()).await;
    let cache = s.node_cache_store();
    let versions = Versions::new(
        MATCHER_VERSION,
        [SourceVersion {
            source: "nvd".into(),
            version: Some("v1".into()),
            importer: "rust/1".into(),
            kind: VersionKind::Record,
            records: 1,
            last_sync: None,
            status: None,
        }],
    );
    let res = |key: &str, m: Vec<ComponentMatch>, lk: &[&str]| ComponentResult {
        key: key.into(),
        matches: m,
        lookup_keys: lk.iter().map(|s| s.to_string()).collect(),
    };
    cache
        .put_component_results(
            &[
                res(
                    "pkg:pypi/requests@2.0",
                    vec![
                        matched("CVE-1", &["GHSA-1", "CVE-1"]),
                        matched("CVE-2", &[]),
                    ],
                    &["pkg:PyPI/requests"],
                ),
                res("pkg:npm/clean@1", vec![], &["pkg:npm/clean"]),
            ],
            &versions,
        )
        .await
        .unwrap();
    let keys: Vec<String> = ["pkg:pypi/requests@2.0", "pkg:npm/clean@1", "never"]
        .map(String::from)
        .to_vec();
    let got = cache.component_matches(&keys).await.unwrap();
    assert_eq!(got.len(), 2, "answered keys only: {got:?}");
    assert_eq!(got["pkg:pypi/requests@2.0"].len(), 2);
    assert_eq!(
        got["pkg:pypi/requests@2.0"][0],
        matched("CVE-1", &["GHSA-1", "CVE-1"])
    );
    assert!(got["pkg:npm/clean@1"].is_empty());
    let as_of = cache.component_as_of(&keys).await.unwrap();
    assert_eq!(as_of.len(), 2);
    assert_eq!(as_of["pkg:npm/clean@1"], versions.as_of());

    assert_eq!(
        cache
            .components_by_lookup_keys(&["pkg:PyPI/requests".into(), "x".into()])
            .await
            .unwrap(),
        ["pkg:pypi/requests@2.0"]
    );
    // by canonical id and by advisory id
    assert_eq!(
        cache
            .components_by_vuln_ids(&["CVE-2".into()])
            .await
            .unwrap(),
        ["pkg:pypi/requests@2.0"]
    );
    assert_eq!(
        cache
            .components_by_vuln_ids(&["GHSA-1".into()])
            .await
            .unwrap(),
        ["pkg:pypi/requests@2.0"]
    );
    assert!(
        cache
            .components_by_vuln_ids(&["GHSA-9".into()])
            .await
            .unwrap()
            .is_empty()
    );

    // replaced whole per key, in one transaction
    cache
        .put_component_results(
            &[res(
                "pkg:pypi/requests@2.0",
                vec![matched("CVE-3", &[])],
                &["prod:requests"],
            )],
            &versions,
        )
        .await
        .unwrap();
    let got = cache.component_matches(&keys[..1]).await.unwrap();
    assert_eq!(got["pkg:pypi/requests@2.0"], [matched("CVE-3", &[])]);
    assert!(
        cache
            .components_by_lookup_keys(&["pkg:PyPI/requests".into()])
            .await
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        cache
            .components_by_lookup_keys(&["prod:requests".into()])
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(
        cache
            .components_by_vuln_ids(&["CVE-2".into()])
            .await
            .unwrap()
            .is_empty()
    );

    // summaries and sync values
    let mirror = tempfile::tempdir().unwrap();
    let m = open(mirror.path()).await;
    fill(&m).await;
    let sums = m
        .summaries(&["CVE-1".into(), "GHSA-2".into()])
        .await
        .unwrap();
    cache.put_summaries(&sums).await.unwrap();
    let back = cache
        .cached_summaries(&["GHSA-2".into(), "x".into(), "CVE-1".into()])
        .await
        .unwrap();
    assert_eq!(back, [sums[1].clone(), sums[0].clone()]);
    assert_eq!(cache.node_sync_get("upstream").await.unwrap(), None);
    cache
        .node_sync_set("upstream", "{\"nvd\":\"rust/1@v1\"}")
        .await
        .unwrap();
    cache
        .node_sync_set("upstream", "{\"nvd\":\"rust/1@v2\"}")
        .await
        .unwrap();
    assert_eq!(
        cache.node_sync_get("upstream").await.unwrap().as_deref(),
        Some("{\"nvd\":\"rust/1@v2\"}")
    );

    let _: BTreeMap<String, String> = versions.since();
    s.close().await;
}
