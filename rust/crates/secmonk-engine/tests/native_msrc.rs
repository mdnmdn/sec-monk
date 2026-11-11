//! Differential test of the native msrc importer against `py-sources` (stage 6, rust ADR-0011 / ADR-0012): both
//! through the engine on their own mirrors over the same documents (first sync, re-sync, several months, an older
//! month after a newer one, a revised month with products removed and fixed builds changed, odd shapes, per-document
//! errors and errors that stop the run), then a mirror that switches between the two implementations; and the
//! row-contract check of the native batches. Harness: `common/`. Doc: rust/_docs/tech/source-msrc.md. Fixture:
//! `tests/fixtures/sources/msrc/cvrf-2024-Aug.synthetic.json` (synthetic, read only); the other documents are written at
//! test time (synthetic).

mod common;

use common::*;

const TIMESTAMPS: &[&str] = &["raw_record.fetched_at", "source_sync.last_sync"];
const MSRC_TABLES: &[&str] = &["raw_record", "vulnerability", "affected", "source_sync"];

fn fixture() -> PathBuf {
    rust_root().join("../tests/fixtures/sources/msrc/cvrf-2024-Aug.synthetic.json")
}

fn native(store: &SqliteStore) -> Arc<dyn Source> {
    Arc::new(secmonk_sources::msrc::MsrcSource::new(Diff::view(store)))
}

fn write(dir: &Path, name: &str, doc: &Value) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, serde_json::to_vec_pretty(doc).unwrap()).unwrap();
    p
}

fn aug(fixture: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(fixture).unwrap()).unwrap()
}

/// A document of the fixture's shape: id, release date, vulnerabilities (the fixture's product tree).
fn month(fixture: &Path, id: &str, released: &str, vulns: Value) -> Value {
    let mut d = aug(fixture);
    d["DocumentTracking"]["Identification"]["ID"]["Value"] = json!(id);
    d["DocumentTracking"]["CurrentReleaseDate"] = json!(released);
    d["DocumentTracking"]["InitialReleaseDate"] = json!(released);
    d["Vulnerability"] = vulns;
    d
}

fn rem(kb: Value, fixed: Value, pids: Value) -> Value {
    json!({"Type": 2, "Description": {"Value": kb}, "FixedBuild": fixed, "ProductID": pids,
           "Supercedence": "5030000"})
}

/// July: CVE-2024-38063 with older builds and other KBs (the August fixture is newer), and a CVE of its own.
fn july(fixture: &Path) -> Value {
    month(
        fixture,
        "2024-Jul",
        "2024-07-09T07:00:00Z",
        json!([
            {"CVE": "CVE-2024-38063", "Title": {"Value": "older title"},
             "CVSSScoreSets": [{"BaseScore": 8.1, "Vector": "CVSS:3.1/AV:N/AC:H"}],
             "Remediations": [rem(json!("5040442"), json!("10.0.22631.3880"), json!(["12086"])),
                              rem(json!("5040427"), json!("10.0.19045.4651"), json!(["11923", "11924"]))]},
            {"CVE": "CVE-2099-0701", "Title": {"Value": "Synthetic July CVE"},
             "Notes": [{"Title": "Description", "Value": "synthetic"}],
             "CVSSScoreSets": [{"BaseScore": 5.5}],
             "Remediations": [rem(json!("5040442"), json!("10.0.22631.3880"), json!(["12086", "12087"]))]}
        ]),
    )
}

/// July again with one KB more for the shared CVE (a non-fix remediation) and one build changed.
fn july_kbs(fixture: &Path) -> Value {
    let mut d = july(fixture);
    let r = d["Vulnerability"][0]["Remediations"]
        .as_array_mut()
        .unwrap();
    r.push(json!({"Type": 3, "Description": {"Value": "5099001"}}));
    r[0]["FixedBuild"] = json!("10.0.22631.3881");
    d
}

/// August revised: Windows 10 removed from the fix, a fixed build changed, the Excel CVE gone, a new KB, odd shapes:
/// a nested product branch, numeric ProductID / Supercedence / KB, `Vendor Fix` as text, a duplicate CVE, a
/// vulnerability without CVE, a Type 2.0, a string ProductID, an empty Vector.
fn aug_revised(fixture: &Path) -> Value {
    let mut d = aug(fixture);
    d["DocumentTracking"]["CurrentReleaseDate"] = json!("2024-08-20T07:00:00Z");
    d["ProductTree"]["Branch"] = json!([{"Items": [{"Items": [
        {"ProductID": "13000", "Value": "Windows 11 Version 24H2 for x64-based Systems"},
        {"ProductID": "13001", "Value": "Windows Server 2025 (Server Core installation)"}]}]}]);
    let v = &mut d["Vulnerability"][0];
    let r = v["Remediations"].as_array_mut().unwrap();
    r.remove(1); // Windows 10
    r[0]["FixedBuild"] = json!("10.0.22631.4038");
    r.push(
        json!({"Type": "Vendor Fix", "Description": 5041571, "FixedBuild": "10.0.26100.1457",
                  "ProductID": [13000, "13001"], "Supercedence": 5040435}),
    );
    r.push(
        json!({"Type": 2.0, "Description": "5041999", "FixedBuild": "1", "ProductID": ["12086"]}),
    );
    r.push(json!({"Type": 2, "Description": "Security Update", "FixedBuild": "2", "ProductID": "12086"}));
    v["CVSSScoreSets"] = json!([{"BaseScore": 9.8, "Vector": ""}, {"BaseScore": true}]);
    let dup = json!({"CVE": "CVE-2099-0801", "Remediations": [rem(json!(5041585), json!("10.0.1"), json!(["12086"]))]});
    let dup2 = json!({"CVE": "CVE-2099-0801", "Remediations": [rem(json!(5041586), json!("10.0.2"), json!(["12087"]))]});
    let first = d["Vulnerability"][0].clone();
    d["Vulnerability"] = json!([first, {"Title": "no CVE"}, dup, dup2]);
    d
}

#[tokio::test(flavor = "multi_thread")]
async fn native_msrc_matches_py_sources() {
    let fixture = fixture();
    let Some(mut d) = Diff::new(&[&fixture]).await else {
        return;
    };
    let python = d.python.clone();
    let dir = tempfile::tempdir().unwrap();
    let (py_store, rs_store, switch_store) = (
        d.store("py").await,
        d.store("rs").await,
        d.store("switch").await,
    );
    let (py_src, _) = d.py_sources(&py_store, "modules-py");
    let (rs_py_src, _) = d.py_sources(&rs_store, "modules-rs");
    let (switch_src, switch_staging) = d.py_sources(&switch_store, "modules-switch");
    let py = d.engine(&py_store, vec![py_src]);
    let rs = d.engine(&rs_store, vec![native(&rs_store), rs_py_src]);
    let switch_py = d.engine(&switch_store, vec![switch_src.clone()]);
    let switch_rs = d.engine(&switch_store, vec![native(&switch_store), switch_src]);

    let compare = |what: &str, ignore: &[&str]| {
        assert_mirrors_equal(
            &python,
            py_store.mirror_path(),
            rs_store.mirror_path(),
            what,
            ignore,
            &[],
        );
    };
    let same = |what: &str| compare(what, TIMESTAMPS);
    // py and rs, plus the switch mirror on py-sources (the same history as the py mirror)
    let step = |path: PathBuf, extra: Value, what: &'static str| {
        let (py, rs, sw) = (py.clone(), rs.clone(), switch_py.clone());
        async move {
            let a = sync_job(&py, &["msrc"], &path, extra.clone()).await;
            let b = sync_job(&rs, &["msrc"], &path, extra.clone()).await;
            check_entries(&a, &b, what);
            sync_job(&sw, &["msrc"], &path, extra).await;
            b
        }
    };
    let count = |table: secmonk_model::MirrorTable| {
        let store = rs_store.clone();
        async move { store.count_rows(table, "msrc").await.unwrap() }
    };
    use secmonk_model::MirrorTable as T;
    let vuln = |id: &'static str| {
        let store = rs_store.clone();
        async move {
            store
                .rows_by_id(T::Vulnerability, "msrc", &[id.to_owned()])
                .await
                .unwrap()
                .into_iter()
                .next()
        }
    };

    // 1. the fixture, then again
    let b = step(fixture.clone(), json!({}), "first sync").await;
    assert_eq!(entry_of(&b)["status"], "ok", "{b:#}");
    assert_eq!(entry_of(&b)["records"], 2);
    same("first sync");
    assert_eq!(
        (count(T::Vulnerability).await, count(T::Affected).await),
        (2, 4),
        "the comparison is not vacuous"
    );
    step(fixture.clone(), json!({}), "second sync").await;
    same("second sync");

    // 2. a directory: July (older) and August; the documents keep their own rows; source_sync.records counts all
    let months = dir.path().join("months");
    std::fs::create_dir(&months).unwrap();
    write(&months, "z-july.json", &july(&fixture));
    std::fs::copy(&fixture, months.join("a-aug.json")).unwrap();
    let b = step(months.clone(), json!({}), "two months").await;
    assert_eq!(entry_of(&b)["records"], 4, "{b:#}");
    same("two months");
    assert_eq!(count(T::Affected).await, 7);

    // 3. the older month again with a new KB and a changed build: extra.kbs merged, its own rows replaced
    let jul2 = write(dir.path(), "july-kbs.json", &july_kbs(&fixture));
    step(jul2.clone(), json!({}), "older month").await;
    same("older month");
    let v = vuln("CVE-2024-38063").await.unwrap();
    assert_eq!(v["modified"], "2024-08-14T07:00:00Z", "the newer row stays");
    assert!(v["extra"]["kbs"].to_string().contains("KB5099001"), "{v:?}");

    // 4. August revised (removed and changed products and builds, odd shapes, duplicate CVE in one document)
    let revised = write(dir.path(), "aug-revised.json", &aug_revised(&fixture));
    let a = sync_job(&py, &["msrc"], &revised, json!({})).await;
    let b = sync_job(&rs, &["msrc"], &revised, json!({})).await;
    check_entries(&a, &b, "revised");
    assert_eq!(entry_of(&b)["status"], "ok", "{b:#}");
    same("revised");

    // the switch mirror: the native importer for the same revision
    let job = sync_job(&switch_rs, &["msrc"], &revised, json!({})).await;
    assert_eq!(entry_of(&job)["status"], "ok", "{job:#}");
    assert!(
        job["log"]
            .to_string()
            .contains("msrc: native importer: applied state of generation "),
        "{job:#}"
    );
    let switch_same = |what: &str| {
        assert_source_rows_equal(
            &python,
            py_store.mirror_path(),
            switch_store.mirror_path(),
            "msrc",
            what,
            TIMESTAMPS,
            MSRC_TABLES,
        );
    };
    switch_same("switch from py-sources to the native importer");

    // a failed Python run after the native one: nothing applied, native state kept
    // (a missing path is refused by the engine before any source runs: an unreadable document instead)
    let latin1 = dir.path().join("latin1.json");
    std::fs::write(&latin1, b"{\"x\": \"caf\xe9\"}").unwrap();
    let job = sync_job(&switch_py, &["msrc"], &latin1, json!({})).await;
    let e = entry_of(&job);
    assert_eq!(e["status"], "error", "{job:#}");
    assert!(
        e["message"].as_str().unwrap().ends_with(
            "; not applied: mirror keeps the native importer data until a successful py-sources sync"
        ),
        "{job:#}"
    );
    switch_same("a failed Python run after Rust");
    let st = switch_store.applied_state("msrc").await.unwrap().unwrap();
    assert_eq!(
        st.generation.as_deref(),
        Some(secmonk_traits::NATIVE_GENERATION)
    );
    // back to py-sources: an ok run repairs from the staging export
    let job = sync_job(&switch_py, &["msrc"], &revised, json!({})).await;
    assert_eq!(entry_of(&job)["status"], "ok", "{job:#}");
    assert_mirror_equals_staging(
        &python,
        switch_store.mirror_path(),
        &switch_staging,
        "switch back to py-sources",
    );
    switch_same("switch back to py-sources vs py-sources only");

    // 5. the same document twice in one directory (a revision and the original): each replaces the other's rows
    let twice = dir.path().join("twice");
    std::fs::create_dir(&twice).unwrap();
    std::fs::copy(&fixture, twice.join("1.json")).unwrap();
    std::fs::copy(&revised, twice.join("2.json")).unwrap();
    step(
        twice,
        json!({"limit": 1}),
        "a document twice; limit ignored",
    )
    .await;
    same("a document twice");

    // 6. per-document errors: partial; the vulnerabilities before the failing one stay
    let bad = dir.path().join("bad");
    std::fs::create_dir(&bad).unwrap();
    let good = json!({"CVE": "CVE-2099-0901", "Remediations": [rem(json!("5090001"), json!("9.1"), json!(["12000"]))]});
    write(
        &bad,
        "1.json",
        &month(
            &fixture,
            "2024-Sep",
            "2024-09-10T07:00:00Z",
            json!([good, "x", good]),
        ),
    );
    write(&bad, "2.json", &json!([1]));
    write(
        &bad,
        "3.json",
        &month(&fixture, "2024-Oct", "2024-10-08T07:00:00Z", json!(5)),
    );
    write(
        &bad,
        "4.json",
        &month(
            &fixture,
            "2024-Nov",
            "2024-11-12T07:00:00Z",
            json!([{"CVE": "CVE-2099-1101", "CVSSScoreSets": [{"BaseScore": 3, "Vector": 31}]},
                   {"CVE": "CVE-2099-1102", "Remediations": [{"Type": 2, "FixedBuild": ["1"], "ProductID": ["12000"]}]}]),
        ),
    );
    write(
        &bad,
        "5.json",
        &month(
            &fixture,
            "2024-Dec",
            "2024-12-10T07:00:00Z",
            json!([{"CVE": "CVE-2099-1201",
            "Remediations": [{"Type": 2, "FixedBuild": "1", "ProductID": ["12000"]}, {"Type": 2, "FixedBuild": "2", "ProductID": 3}]}]),
        ),
    );
    let b = step(bad.clone(), json!({}), "per-document errors").await;
    assert_eq!(entry_of(&b)["status"], "partial", "{b:#}");
    same("per-document errors");
    assert!(
        vuln("CVE-2099-0901").await.is_some(),
        "written before the failing vulnerability"
    );
    assert!(vuln("CVE-2099-1101").await.is_none(), "the vector error");
    assert!(
        vuln("CVE-2099-1201").await.is_none(),
        "a ProductID that is not iterable"
    );

    // 7. errors that stop the run: a directory named *.json (error), an undated document then invalid UTF-8
    // (partial), a single unreadable file (error), an empty directory
    let stop = dir.path().join("stop");
    std::fs::create_dir_all(stop.join("sub/x.json")).unwrap();
    write(&stop, "z.json", &july(&fixture));
    let b = step(stop.clone(), json!({}), "a directory named .json").await;
    assert_eq!(entry_of(&b)["status"], "error", "{b:#}");
    same("a directory named .json");
    std::fs::remove_dir(stop.join("sub/x.json")).unwrap();
    let mut undated = july(&fixture);
    undated["DocumentTracking"] = json!({"Identification": {"ID": {"Value": "undated"}}});
    write(&stop, "a.json", &undated);
    std::fs::write(
        stop.join("b.json"),
        b"\xef\xbb\xbf{\"Vulnerability\": [\"caf\xe9\"]}",
    )
    .unwrap();
    let b = step(stop.clone(), json!({}), "undated then invalid UTF-8").await;
    assert_eq!(entry_of(&b)["status"], "partial", "{b:#}");
    same("undated then invalid UTF-8");
    let b = step(latin1.clone(), json!({}), "an unreadable file").await;
    assert_eq!(entry_of(&b)["status"], "error", "{b:#}");
    same("an unreadable file");
    let empty = dir.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    let b = step(empty, json!({}), "empty directory").await;
    assert_eq!(entry_of(&b)["status"], "ok", "{b:#}");
    same("empty directory");
    assert_source_rows_equal(
        &python,
        py_store.mirror_path(),
        rs_store.mirror_path(),
        "msrc",
        "end",
        TIMESTAMPS,
        MSRC_TABLES,
    );

    // invalid JSON: same status, other wording (from here on the status rows differ in their message)
    std::fs::write(stop.join("b.json"), "{").unwrap();
    let a = sync_job(&py, &["msrc"], &stop, json!({})).await;
    let b = sync_job(&rs, &["msrc"], &stop, json!({})).await;
    assert_eq!(entry_of(&b)["status"], "partial", "{b:#}");
    assert_eq!(entry_of(&a)["status"], entry_of(&b)["status"], "{a:#}");
    compare(
        "invalid JSON",
        &[
            "raw_record.fetched_at",
            "source_sync.last_sync",
            "source_sync.message",
        ],
    );

    // 8. a documented difference (source-msrc.md): a number as FixedBuild is stored by Python and fails the
    // document natively; the mirrors differ from here on
    let num = write(
        dir.path(),
        "fixed-number.json",
        &month(
            &fixture,
            "2025-Jan",
            "2025-01-14T08:00:00Z",
            json!([{"CVE": "CVE-2099-2501",
            "Remediations": [{"Type": 2, "FixedBuild": 26100, "ProductID": ["12000"]}]}]),
        ),
    );
    let a = sync_job(&py, &["msrc"], &num, json!({})).await;
    let b = sync_job(&rs, &["msrc"], &num, json!({})).await;
    assert_eq!(entry_of(&a)["status"], "ok", "{a:#}");
    assert_eq!(entry_of(&b)["status"], "partial", "{b:#}");
    d.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn native_msrc_batches_follow_the_row_contract() {
    // every native msrc batch and end validates against rust/contracts (source/rows, source/sync-end); applied to a
    // real store, none skipped; affected deletes keyed by the full row and an extra-only vulnerability upsert among
    // them
    let fixture = fixture();
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(
        &dir.path().join("state.sqlite3"),
        &dir.path().join("mirror.sqlite3"),
        &StoreOptions::default(),
    )
    .await
    .unwrap();
    let src = secmonk_sources::msrc::MsrcSource::new(Diff::view(&store)).with_limits(
        secmonk_sources::batch::Limits {
            ops: 4,
            bytes: 1 << 20,
        },
    );
    let path = |p: &Path| json!({"path": p.display().to_string()});
    let july = write(dir.path(), "july.json", &july(&fixture));
    let july_kbs = write(dir.path(), "july-kbs.json", &july_kbs(&fixture));
    let revised = write(dir.path(), "aug-revised.json", &aug_revised(&fixture));
    let missing = dir.path().join("missing.json");
    let deletes = check_row_contract(
        &src,
        &store,
        "msrc",
        &[
            path(&fixture),
            path(&july),
            path(&july_kbs),
            path(&revised),
            path(&fixture),
            path(&missing),
        ],
    )
    .await;
    assert!(deletes >= 3, "affected deletes: {deletes}");
    store.close().await;
}
