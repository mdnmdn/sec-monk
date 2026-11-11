//! Store tests: migrations, the save_inventory golden comparison with Python, mirror row batches, findings,
//! run history.

use secmonk_model::*;
use secmonk_store::*;
use serde_json::{Map, Value, json};
use sqlx::{Row, SqlitePool};

async fn open(dir: &std::path::Path) -> SqliteStore {
    SqliteStore::open(
        &dir.join("db/state.sqlite3"),
        &dir.join("db/mirror.sqlite3"),
        &StoreOptions::default(),
    )
    .await
    .unwrap()
}

/// Read `cols` of every row as JSON values (INTEGER, REAL, TEXT, NULL), timestamps normalized.
async fn rows(
    pool: &SqlitePool,
    table: &str,
    cols: &[String],
    order: &str,
) -> Vec<Map<String, Value>> {
    let sql = format!("SELECT {} FROM {table} ORDER BY {order}", cols.join(", "));
    let mut out = Vec::new();
    for r in sqlx::query(sqlx::AssertSqlSafe(sql))
        .fetch_all(pool)
        .await
        .unwrap()
    {
        let mut m = Map::new();
        for c in cols {
            let v = if let Ok(v) = r.try_get::<Option<i64>, _>(c.as_str()) {
                v.map(Value::from).unwrap_or(Value::Null)
            } else if let Ok(v) = r.try_get::<Option<f64>, _>(c.as_str()) {
                v.map(Value::from).unwrap_or(Value::Null)
            } else {
                r.try_get::<Option<String>, _>(c.as_str())
                    .unwrap()
                    .map(Value::from)
                    .unwrap_or(Value::Null)
            };
            let v = match (c.as_str(), v) {
                ("first_seen" | "last_seen" | "started_at" | "finished_at", Value::String(_)) => {
                    json!("TS")
                }
                (_, v) => v,
            };
            m.insert(c.clone(), v);
        }
        out.push(m);
    }
    out
}

#[tokio::test]
async fn save_inventory_matches_python() {
    let golden: Value = serde_json::from_str(include_str!("golden/save_inventory.json")).unwrap();
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    let invs: Vec<Inventory> = serde_json::from_value(golden["inventories"].clone()).unwrap();
    let mut ids = Vec::new();
    for inv in &invs {
        ids.push(store.save_inventory(inv, Some(7)).await.unwrap());
    }
    assert_eq!(json!(ids), golden["scan_ids"]);
    let pool = SqlitePool::connect(&format!("sqlite://{}", store.state_path().display()))
        .await
        .unwrap();
    for (table, order) in [
        ("asset", "id"),
        ("scan", "id"),
        ("component", "id"),
        ("asset_component", "asset_id, component_id"),
    ] {
        let want = golden[table].as_array().unwrap();
        let cols: Vec<String> = want[0].as_object().unwrap().keys().cloned().collect();
        let got = rows(&pool, table, &cols, order).await;
        let want: Vec<Map<String, Value>> = want
            .iter()
            .map(|v| v.as_object().unwrap().clone())
            .collect();
        assert_eq!(got.len(), want.len(), "{table}");
        for (g, w) in got.iter().zip(&want) {
            assert_eq!(g, w, "{table}");
        }
    }
    // promoted columns (R4) and the v3 scan columns
    let r = sqlx::query("SELECT partial, partial_reason, job_id FROM scan ORDER BY id")
        .fetch_all(&pool)
        .await
        .unwrap();
    assert_eq!((r[0].get::<i64, _>(0), r[1].get::<i64, _>(0)), (0, 1));
    assert_eq!(
        r[1].get::<Option<String>, _>(1).as_deref(),
        Some("layer skipped")
    );
    assert_eq!(r[1].get::<Option<i64>, _>(2), Some(7));
    let r = sqlx::query(
        "SELECT product, product_source, bundle_id FROM component WHERE name='Google Chrome'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(r.get::<Option<String>, _>(0).as_deref(), Some("chrome"));
    assert_eq!(
        r.get::<Option<String>, _>(1).as_deref(),
        Some("alias-table")
    );
    assert_eq!(
        r.get::<Option<String>, _>(2).as_deref(),
        Some("com.google.Chrome")
    );
    assert!(StateStore::is_initialized(&store).await.unwrap());
    let facts = store
        .asset_reuse_facts("dir:/work/npm-v3")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (facts.latest_scan_id, facts.latest_scan_partial),
        (Some(2), true)
    );
    let mut meta = facts.meta.clone();
    meta.insert("id_verified".into(), serde_json::Value::Bool(true));
    store
        .update_asset_reused("dir:/work/npm-v3", Some("renamed"), &meta)
        .await
        .unwrap();
    let after = store
        .asset_reuse_facts("dir:/work/npm-v3")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.name.as_deref(), Some("renamed"));
    assert_eq!(after.meta["id_verified"], true);
    assert_eq!(after.latest_scan_id, Some(2), "no scan row is written");
    assert!(matches!(
        store.update_asset_reused("dir:/nope", None, &meta).await,
        Err(secmonk_store::StoreError::NotFound(_))
    ));
    assert!(!store.asset_exists("dir:/nope").await.unwrap());
}

#[tokio::test]
async fn schema_is_v3_with_wal_and_private_files() {
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    let pool = SqlitePool::connect(&format!("sqlite://{}", store.state_path().display()))
        .await
        .unwrap();
    let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(mode, "wal");
    let uv: i64 = sqlx::query_scalar("PRAGMA user_version")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(uv, 3);
    let schema: String = sqlx::query_scalar("SELECT value FROM store_meta WHERE key='schema'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(schema, "3");
    assert!(!StateStore::is_initialized(&store).await.unwrap());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for p in [store.state_path(), store.mirror_path()] {
            assert_eq!(
                std::fs::metadata(p).unwrap().permissions().mode() & 0o777,
                0o600,
                "{}",
                p.display()
            );
        }
    }
    store.close().await;
    // reopening runs no migration twice
    let again = open(d.path()).await;
    again.close().await;
}

#[tokio::test]
async fn unknown_migration_is_refused() {
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    let pool = SqlitePool::connect(&format!("sqlite://{}", store.state_path().display()))
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO _sqlx_migrations(version, description, installed_on, success, checksum, execution_time)
         VALUES (99, 'from a newer app', CURRENT_TIMESTAMP, 1, x'00', 0)",
    )
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
    store.close().await;
    let err = SqliteStore::open(
        &d.path().join("db/state.sqlite3"),
        &d.path().join("db/mirror.sqlite3"),
        &StoreOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, StoreError::Migrate(_)), "{err}");
}

fn batch_of(source: &str, seq: u64, ops: Value) -> RowsBatch {
    serde_json::from_value(json!({"kind": "rows", "seq": seq, "source": source, "ops": ops}))
        .unwrap()
}

/// An `osv` batch with a fresh seq (every call: the next one).
fn batch(ops: Value) -> RowsBatch {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(100);
    batch_of(
        "osv",
        SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        ops,
    )
}

#[tokio::test]
async fn mirror_rows_apply_in_one_transaction() {
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    // the contract example batch applies
    let ex: Value = serde_json::from_str(include_str!(
        "../../../contracts/examples/wire/17-event-rows.json"
    ))
    .unwrap();
    let b: RowsBatch = serde_json::from_value(ex["data"].clone()).unwrap();
    store.apply_rows(&b).await.unwrap();
    // the same delete naming another source in a kev batch is refused (one source never touches another's rows)
    let mut foreign = b.clone();
    foreign.seq = 2;
    let mut ops = serde_json::to_value(&foreign.ops).unwrap();
    for op in ops.as_array_mut().unwrap() {
        if op["table"] == "affected" {
            op["key"]["source"] = json!("osv");
        }
    }
    foreign.ops = serde_json::from_value(ops).unwrap();
    assert!(matches!(
        store.apply_rows(&foreign).await,
        Err(StoreError::Invalid(_))
    ));
    assert!(MirrorStore::is_initialized(&store).await.unwrap());

    let aff = json!({"source": "osv", "vuln_id": "GHSA-x", "ecosystem": "PyPI", "package": "p",
                     "events": [{"introduced": "0"}, {"fixed": "1.0"}], "versions": null});
    let s = store
        .apply_rows(&batch(json!([
            {"op": "upsert", "table": "affected", "row": aff},
            {"op": "upsert", "table": "affected", "row": aff},
            {"op": "upsert", "table": "vulnerability", "row": {"source": "osv", "id": "GHSA-x", "summary": "a",
                "cvss_score": 9.8, "cwes": ["CWE-79"], "extra": {"b": 1, "a": 2}}},
            {"op": "upsert", "table": "vulnerability", "row": {"source": "osv", "id": "GHSA-x", "summary": "b"}},
            {"op": "upsert", "table": "source_sync", "row": {"source": "osv", "records": 3, "status": "ok"}},
            // per-ecosystem cursor rows of the same source (`osv:<Eco>`)
            {"op": "upsert", "table": "source_sync", "row": {"source": "osv:PyPI", "cursor": "2026-01-01T00:00:00Z", "status": "ok"}},
        ])))
        .await
        .unwrap();
    assert_eq!(s.upserts, 6);
    assert!(store.sync_state("osv:PyPI").await.unwrap().is_some());
    for bad in ["kev:PyPI", "osvx", "osv:"] {
        assert!(
            matches!(
                store
                    .apply_rows(&batch(
                        json!([{"op": "upsert", "table": "source_sync", "row": {"source": bad}}])
                    ))
                    .await,
                Err(StoreError::Invalid(_))
            ),
            "{bad} is not a cursor row of osv"
        );
    }
    let pool = SqlitePool::connect(&format!("sqlite://{}", store.mirror_path().display()))
        .await
        .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM affected WHERE vuln_id='GHSA-x'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 2);
    let r =
        sqlx::query("SELECT summary, cvss_score, cwes, extra FROM vulnerability WHERE id='GHSA-x'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(r.get::<String, _>(0), "b"); // upsert updated only the given column
    assert_eq!(r.get::<f64, _>(1), 9.8);
    assert_eq!(r.get::<String, _>(2), r#"["CWE-79"]"#);
    assert_eq!(r.get::<String, _>(3), r#"{"b":1,"a":2}"#);
    assert_eq!(
        store.sync_state("osv").await.unwrap().unwrap().records,
        Some(3)
    );

    // affected delete removes exactly one of the two identical rows
    let s = store
        .apply_rows(&batch(
            json!([{"op": "delete", "table": "affected", "key": aff}]),
        ))
        .await
        .unwrap();
    assert_eq!(s.deleted, 1);
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM affected WHERE vuln_id='GHSA-x'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 1);

    // a bad op refuses the whole batch: nothing written
    let k1 = json!({"op": "upsert", "table": "kev", "row": {"cve_id": "CVE-1", "source": "kev"}});
    for (n, bad) in [
        json!([k1, {"op": "upsert", "table": "kev", "row": {"cve_id": "CVE-2", "source": "kev", "evil": "x"}}]),
        json!([k1, {"op": "upsert", "table": "kev", "row": {"vendor": "no key", "source": "kev"}}]),
        json!([k1, {"op": "delete", "table": "kev", "key": {"cve_id": "CVE-1", "vendor": "x"}}]),
        json!([{"op": "upsert", "table": "kev", "row": {"cve_id": "CVE-1", "source": "kev", "vendor": {"nested": 1}}}]),
        // rows of another source, or without their source
        json!([k1, {"op": "upsert", "table": "vulnerability", "row": {"source": "osv", "id": "X"}}]),
        json!([k1, {"op": "upsert", "table": "kev", "row": {"cve_id": "CVE-3"}}]),
        json!([k1, {"op": "delete", "table": "raw_record", "key": {"source": "osv", "record_id": "r"}}]),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            matches!(store.apply_rows(&batch_of("kev", 500 + n as u64, bad)).await, Err(StoreError::Invalid(_))),
            "bad batch {n} must be refused"
        );
    }
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kev WHERE cve_id='CVE-1'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 0);
    // unknown tables do not even deserialize
    assert!(
        serde_json::from_value::<RowsBatch>(json!({"kind": "rows", "seq": 1, "source": "x",
        "ops": [{"op": "upsert", "table": "finding", "row": {}}]}))
        .is_err()
    );
    store.checkpoint().await.unwrap();
}

fn finding(component_id: i64) -> Finding {
    Finding {
        component_id,
        vuln_id: "CVE-2021-44228".into(),
        advisory_ids: vec!["CVE-2021-44228".into(), "GHSA-jfh8-c2jp-5v3q".into()],
        matched_by: Some("osv-package".into()),
        confidence: Some(1.0),
        fixed_version: Some("2.15.0".into()),
        severity: Some("CRITICAL".into()),
        cvss_score: Some(10.0),
        epss: Some(0.97),
        kev: true,
        priority: Some("P1".into()),
        status: FindingStatus::Open,
        first_seen: Some("2026-11-11T00:00:00+00:00".into()),
        last_seen: Some("2026-11-11T00:00:00+00:00".into()),
        fixed_at: None,
        triage: None,
        triage_source: None,
    }
}

#[tokio::test]
async fn findings_replace_with_stale_check() {
    let golden: Value = serde_json::from_str(include_str!("golden/save_inventory.json")).unwrap();
    let inv: Inventory = serde_json::from_value(golden["inventories"][0].clone()).unwrap();
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    let scan = store.save_inventory(&inv, None).await.unwrap();
    let based = BasedOn {
        latest_scan_id: Some(scan),
        mirror_synced_at: None,
    };
    assert_eq!(
        store
            .replace_findings(&inv.asset.id, &[finding(1), finding(2)], &based)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        store
            .replace_findings(&inv.asset.id, &[finding(1)], &based)
            .await
            .unwrap(),
        1
    );
    store.save_inventory(&inv, None).await.unwrap();
    assert!(matches!(
        store.replace_findings(&inv.asset.id, &[], &based).await,
        Err(StoreError::Stale(_))
    ));
    let pool = SqlitePool::connect(&format!("sqlite://{}", store.state_path().display()))
        .await
        .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM finding")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
}

#[tokio::test]
async fn run_history() {
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    let new = |owner: JobOwner| NewJob {
        kind: JobKind::Scan,
        origin: JobOrigin::Ui,
        title: Some("scan".into()),
        params: Some(json!({"save": true})),
        started_at: None,
        owner,
    };
    let id = store.job_insert(&new(jobs::this_owner())).await.unwrap();
    let dead = store
        .job_insert(&new(JobOwner {
            pid: 1,
            host: "gone.invalid".into(),
        }))
        .await
        .unwrap();
    assert_eq!(store.job_mark_interrupted().await.unwrap(), 1);
    let log: Vec<String> = (0..350).map(|i| format!("line {i}")).collect();
    store
        .job_finish(
            id,
            &JobFinish {
                status: JobStatus::Ok,
                result: Some(json!({"saved": true})),
                error: None,
                log,
                summary: Some(json!({"targets": 1})),
            },
        )
        .await
        .unwrap();
    let rows = store.job_rows(None, 50).await.unwrap();
    assert_eq!(
        rows.iter().map(|r| r.id).collect::<Vec<_>>(),
        vec![dead, id]
    );
    assert_eq!(rows[0].status, Some(JobStatus::Error));
    assert_eq!(rows[0].error.as_deref(), Some("interrupted"));
    assert_eq!(rows[1].log_lines, 300);
    assert!(rows[1].log.is_none());
    let full = store.job_row(id).await.unwrap().unwrap();
    assert_eq!(full.log.as_ref().unwrap()[0], "line 50");
    assert_eq!(full.owner, Some(jobs::this_owner()));
    assert_eq!(
        store.job_rows(Some(JobKind::Sync), 50).await.unwrap().len(),
        0
    );
}

#[tokio::test]
async fn job_pruning_keeps_200() {
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    for _ in 0..205 {
        store
            .job_insert(&NewJob {
                kind: JobKind::Sync,
                origin: JobOrigin::Cli,
                title: None,
                params: None,
                started_at: None,
                owner: jobs::this_owner(),
            })
            .await
            .unwrap();
    }
    let rows = store.job_rows(None, 1000).await.unwrap();
    assert_eq!(rows.len(), 200);
    assert_eq!(rows.last().unwrap().id, 6);
}

#[tokio::test]
async fn replayed_batches_are_skipped() {
    // review M5: a host stop between apply and `source.ack` replays the batch with the same seq
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    let aff = json!({"source": "osv", "vuln_id": "GHSA-r", "ecosystem": "npm", "package": "p",
                     "events": [{"introduced": "0"}]});
    let b = batch_of(
        "osv",
        7,
        json!([{"op": "upsert", "table": "affected", "row": aff}]),
    );
    assert!(!store.apply_rows(&b).await.unwrap().skipped);
    let again = store.apply_rows(&b).await.unwrap();
    assert!(again.skipped && again.upserts == 0);
    let older = batch_of(
        "osv",
        3,
        json!([{"op": "upsert", "table": "affected", "row": aff}]),
    );
    assert!(store.apply_rows(&older).await.unwrap().skipped);
    assert_eq!(store.applied_seq("osv").await.unwrap(), Some(7));
    assert_eq!(store.applied_seq("kev").await.unwrap(), None, "per source");
    let pool = SqlitePool::connect(&format!("sqlite://{}", store.mirror_path().display()))
        .await
        .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM affected WHERE vuln_id='GHSA-r'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(n, 1, "no duplicate affected row");
    // a refused batch does not advance the seq
    let bad = batch_of(
        "osv",
        8,
        json!([{"op": "upsert", "table": "kev", "row": {"cve_id": "C", "source": "kev"}}]),
    );
    assert!(store.apply_rows(&bad).await.is_err());
    assert_eq!(store.applied_seq("osv").await.unwrap(), Some(7));
    // the export repair path starts over
    store.reset_applied_seq("osv").await.unwrap();
    assert!(!store.apply_rows(&older).await.unwrap().skipped);
}

#[tokio::test]
async fn shared_tables_keep_their_owner() {
    // epss: EUVD never overwrites or deletes a FIRST score; the epss source may replace a EUVD one
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    let row = |src: &str, score: f64| {
        json!({"op": "upsert", "table": "epss",
        "row": {"cve_id": "CVE-9", "score": score, "source": src}})
    };
    store
        .apply_rows(&batch_of("epss", 1, json!([row("epss", 0.5)])))
        .await
        .unwrap();
    store
        .apply_rows(&batch_of("euvd", 2, json!([row("euvd", 0.9)])))
        .await
        .unwrap();
    let del = json!([{"op": "delete", "table": "epss", "key": {"cve_id": "CVE-9"}}]);
    assert_eq!(
        store
            .apply_rows(&batch_of("euvd", 3, del.clone()))
            .await
            .unwrap()
            .deleted,
        0
    );
    let pool = SqlitePool::connect(&format!("sqlite://{}", store.mirror_path().display()))
        .await
        .unwrap();
    let get = || async {
        sqlx::query_as::<_, (f64, String)>("SELECT score, source FROM epss WHERE cve_id='CVE-9'")
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    assert_eq!(get().await, (0.5, "epss".into()));
    store
        .apply_rows(&batch_of(
            "euvd",
            4,
            json!([{"op": "delete", "table": "epss", "key": {"cve_id": "CVE-9"}}]),
        ))
        .await
        .unwrap();
    store.apply_rows(&batch_of("epss", 5, del)).await.unwrap();
    store
        .apply_rows(&batch_of("euvd", 6, json!([row("euvd", 0.9)])))
        .await
        .unwrap();
    assert_eq!(get().await, (0.9, "euvd".into()));
    store
        .apply_rows(&batch_of("epss", 7, json!([row("epss", 0.1)])))
        .await
        .unwrap();
    assert_eq!(get().await, (0.1, "epss".into()));
}

#[tokio::test]
async fn batch_size_follows_the_schema() {
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    let op = json!({"op": "upsert", "table": "kev", "row": {"cve_id": "CVE-1", "source": "kev"}});
    let ok = batch_of("kev", 1, Value::Array(vec![op.clone(); 5000]));
    store.apply_rows(&ok).await.unwrap();
    let big = batch_of("kev", 2, Value::Array(vec![op; 5001]));
    assert!(matches!(
        store.apply_rows(&big).await,
        Err(StoreError::Invalid(_))
    ));
}

// ------------------------------------------------------------------------------------------------ W4.4: generations

const GEN_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const GEN_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn gbatch(source: &str, seq: u64, generation: &str, acked: u64, ops: Value) -> RowsBatch {
    serde_json::from_value(
        json!({"kind": "rows", "seq": seq, "source": source, "ops": ops,
                                  "generation": generation, "acked_through": acked}),
    )
    .unwrap()
}

/// An `affected` row of `osv` (no natural key: duplicates are what the tests look for).
fn aff(vuln: &str, pkg: &str) -> Value {
    json!({"source": "osv", "vuln_id": vuln, "ecosystem": "npm", "package": pkg,
           "events": [{"introduced": "0"}], "versions": null, "extra": null})
}

fn up_aff(row: &Value) -> Value {
    json!({"op": "upsert", "table": "affected", "row": row})
}

fn del_aff(row: &Value) -> Value {
    json!({"op": "delete", "table": "affected", "key": row})
}

async fn mirror_pool(store: &SqliteStore) -> SqlitePool {
    SqlitePool::connect(&format!("sqlite://{}", store.mirror_path().display()))
        .await
        .unwrap()
}

/// Every `affected` row of the mirror (duplicates kept), sorted: compared with the test's model of staging.
async fn affected_rows(pool: &SqlitePool) -> Vec<String> {
    let cols: Vec<String> = ["source", "vuln_id", "ecosystem", "package", "events"]
        .iter()
        .map(|c| (*c).to_owned())
        .collect();
    let mut out: Vec<String> = rows(pool, "affected", &cols, "rowid_")
        .await
        .into_iter()
        .map(|m| Value::Object(m).to_string())
        .collect();
    out.sort();
    out
}

/// The same rows as `affected_rows` reads them, from the staging model.
fn expected(staging: &[Value]) -> Vec<String> {
    let mut out: Vec<String> = staging
        .iter()
        .map(|r| {
            json!({"source": r["source"], "vuln_id": r["vuln_id"], "ecosystem": r["ecosystem"],
                   "package": r["package"], "events": r["events"].to_string()})
            .to_string()
        })
        .collect();
    out.sort();
    out
}

#[tokio::test]
async fn generations_decide_apply_skip_or_repair() {
    // review M1: seqs compare only within one staging generation
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    let pool = mirror_pool(&store).await;
    let a1 = aff("GHSA-1", "p");
    let b3 = gbatch("osv", 3, GEN_A, 0, json!([up_aff(&a1)]));
    let s = store.apply_rows(&b3).await.unwrap();
    assert!(!s.skipped && !s.needs_repair && s.upserts == 1);
    let st = store.applied_state("osv").await.unwrap().unwrap();
    assert_eq!((st.seq, st.generation.as_deref()), (3, Some(GEN_A)));
    assert!(store.apply_rows(&b3).await.unwrap().skipped, "replay");
    // (a) staging recreated: seq 1 of another generation is neither skipped nor applied
    let other = gbatch("osv", 1, GEN_B, 0, json!([up_aff(&aff("GHSA-2", "q"))]));
    let s = store.apply_rows(&other).await.unwrap();
    assert!(s.needs_repair && !s.skipped && s.upserts == 0);
    // staging acknowledged more than the mirror applied (mirror restored from an older copy)
    let ahead = gbatch("osv", 9, GEN_A, 7, json!([up_aff(&aff("GHSA-3", "r"))]));
    assert!(store.apply_rows(&ahead).await.unwrap().needs_repair);
    assert_eq!(
        affected_rows(&pool).await,
        expected(std::slice::from_ref(&a1))
    );
    let st = store.applied_state("osv").await.unwrap().unwrap();
    assert_eq!(
        (st.seq, st.generation.as_deref()),
        (3, Some(GEN_A)),
        "unchanged"
    );
    // a batch without a generation keeps the plain seq rule and the recorded generation
    let legacy = batch_of("osv", 4, json!([up_aff(&aff("GHSA-4", "s"))]));
    assert!(!store.apply_rows(&legacy).await.unwrap().needs_repair);
    let st = store.applied_state("osv").await.unwrap().unwrap();
    assert_eq!((st.seq, st.generation.as_deref()), (4, Some(GEN_A)));

    // (b) a reset mirror: no applied state, but staging acknowledged through 8
    let d2 = tempfile::tempdir().unwrap();
    let fresh = open(d2.path()).await;
    let after_reset = gbatch("osv", 9, GEN_A, 8, json!([up_aff(&a1)]));
    assert!(fresh.apply_rows(&after_reset).await.unwrap().needs_repair);
    assert_eq!(fresh.applied_state("osv").await.unwrap(), None);
    // a first sync (nothing acknowledged yet) applies
    let first = gbatch("osv", 9, GEN_A, 0, json!([up_aff(&a1)]));
    assert!(!fresh.apply_rows(&first).await.unwrap().needs_repair);
    // a seq recorded before generations existed: the first generation-aware batch repairs once
    let d3 = tempfile::tempdir().unwrap();
    let old = open(d3.path()).await;
    old.apply_rows(&batch_of("osv", 5, json!([up_aff(&a1)])))
        .await
        .unwrap();
    assert_eq!(
        old.applied_state("osv").await.unwrap().unwrap().generation,
        None
    );
    assert!(
        old.apply_rows(&gbatch("osv", 6, GEN_A, 5, json!([up_aff(&a1)])))
            .await
            .unwrap()
            .needs_repair
    );
}

#[tokio::test]
async fn export_repair_never_loses_or_duplicates_rows() {
    // review M5: the repair path for M1, then the replays and normal syncs that follow it. The test keeps a model of
    // the staging contents and compares the mirror with it row by row (duplicates count).
    let d = tempfile::tempdir().unwrap();
    let store = open(d.path()).await;
    let pool = mirror_pool(&store).await;
    let (a1, a2, a3, a4, a5, a6) = (
        aff("GHSA-1", "p"),
        aff("GHSA-2", "q"),
        aff("GHSA-3", "r"),
        aff("GHSA-4", "s"),
        aff("GHSA-5", "t"),
        aff("GHSA-6", "u"),
    );
    // another source's rows and a qualified cursor: the repair of osv keeps the first, owns the second
    store
        .apply_rows(&batch_of(
            "kev",
            1,
            json!([{"op": "upsert", "table": "kev", "row": {"cve_id": "CVE-K", "source": "kev"}}]),
        ))
        .await
        .unwrap();
    // 1. a normal sync: two batches, one row twice (affected has no natural key)
    let mut staging = vec![a1.clone(), a2.clone(), a1.clone()];
    store
        .apply_rows(&gbatch(
            "osv",
            1,
            GEN_A,
            0,
            json!([up_aff(&a1), up_aff(&a2),
                   {"op": "upsert", "table": "source_sync", "row": {"source": "osv:npm", "cursor": "c1"}}]),
        ))
        .await
        .unwrap();
    store
        .apply_rows(&gbatch("osv", 2, GEN_A, 0, json!([up_aff(&a1)])))
        .await
        .unwrap();
    assert_eq!(affected_rows(&pool).await, expected(&staging));
    // 2. a crash between apply and ack: batch 3 applied, never acknowledged, replayed with the same seq
    let b3 = gbatch("osv", 3, GEN_A, 2, json!([del_aff(&a1), up_aff(&a3)]));
    store.apply_rows(&b3).await.unwrap();
    staging.remove(0);
    staging.push(a3.clone());
    assert!(store.apply_rows(&b3).await.unwrap().skipped);
    assert_eq!(affected_rows(&pool).await, expected(&staging));
    // 3. the staging file is recreated (generation B, seqs from 1): its first sync wrote a2, a4, a4
    staging = vec![a2.clone(), a4.clone(), a4.clone()];
    let replay_b1 = gbatch(
        "osv",
        1,
        GEN_B,
        0,
        json!([up_aff(&a2), up_aff(&a4), up_aff(&a4)]),
    );
    assert!(store.apply_rows(&replay_b1).await.unwrap().needs_repair);
    //    a dropped repair rolls back everything (the delete included)
    let mut rep = store.begin_repair("osv").await.unwrap();
    rep.apply(&gbatch("osv", 1, GEN_B, 0, json!([up_aff(&a2)])))
        .await
        .unwrap();
    drop(rep);
    assert_eq!(affected_rows(&pool).await.len(), 3, "rolled back");
    assert_eq!(store.applied_seq("osv").await.unwrap(), Some(3));
    //    the export, in two batches, over the existing rows: one transaction, no duplicate
    let mut rep = store.begin_repair("osv").await.unwrap();
    let foreign = rep
        .apply(&gbatch("kev", 1, GEN_B, 0, json!([up_aff(&a2)])))
        .await;
    assert!(matches!(foreign, Err(StoreError::Invalid(_))));
    rep.apply(&gbatch(
        "osv",
        1,
        GEN_B,
        0,
        json!([up_aff(&a2), up_aff(&a4)]),
    ))
    .await
    .unwrap();
    rep.apply(&gbatch("osv", 2, GEN_B, 0, json!([up_aff(&a4)])))
        .await
        .unwrap();
    let stats = rep.commit(1, Some(GEN_B)).await.unwrap();
    assert_eq!((stats.upserts, stats.batches), (3, 2));
    assert_eq!(stats.deleted, 4, "3 affected rows + the osv:npm cursor");
    assert_eq!(affected_rows(&pool).await, expected(&staging));
    assert!(store.sync_state("osv:npm").await.unwrap().is_none());
    let kev: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM kev")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(kev, 1, "another source's rows are untouched");
    let st = store.applied_state("osv").await.unwrap().unwrap();
    assert_eq!((st.seq, st.generation.as_deref()), (1, Some(GEN_B)));
    //    a crash between the repair and its ack: the un-acknowledged batch 1 is replayed, and skipped
    assert!(store.apply_rows(&replay_b1).await.unwrap().skipped);
    assert_eq!(affected_rows(&pool).await, expected(&staging));
    // 4. a normal sync after the repair
    store
        .apply_rows(&gbatch(
            "osv",
            2,
            GEN_B,
            1,
            json!([up_aff(&a5), del_aff(&a4)]),
        ))
        .await
        .unwrap();
    let i = staging.iter().position(|r| *r == a4).unwrap();
    staging.remove(i); // one matching row
    staging.push(a5.clone());
    assert_eq!(affected_rows(&pool).await, expected(&staging));
    // 5. the mirror is reset (a new file); staging keeps its rows and acknowledged through 2
    let d2 = tempfile::tempdir().unwrap();
    let reset = open(d2.path()).await;
    let reset_pool = mirror_pool(&reset).await;
    let b3 = gbatch("osv", 3, GEN_B, 2, json!([up_aff(&a6)]));
    assert!(reset.apply_rows(&b3).await.unwrap().needs_repair);
    staging.push(a6.clone());
    let mut rep = reset.begin_repair("osv").await.unwrap();
    let ops: Vec<Value> = staging.iter().map(up_aff).collect();
    rep.apply(&gbatch("osv", 1, GEN_B, 2, Value::Array(ops)))
        .await
        .unwrap();
    rep.commit(3, Some(GEN_B)).await.unwrap();
    assert_eq!(affected_rows(&reset_pool).await, expected(&staging));
    assert!(
        reset.apply_rows(&b3).await.unwrap().skipped,
        "replay after the repair"
    );
    assert_eq!(affected_rows(&reset_pool).await, expected(&staging));
    assert!(MirrorStore::is_initialized(&reset).await.unwrap());
}
