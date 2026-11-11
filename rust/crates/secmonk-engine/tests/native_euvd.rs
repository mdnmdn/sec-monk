//! Differential test of the native euvd importer against `py-sources` (stage 6, rust ADR-0011 / ADR-0012): both
//! through the engine on their own mirrors, with FIRST epss rows before and after the EUVD scores (the native epss
//! importer on the Rust mirror, `py-sources` on the Python one), then a mirror that switches between the two
//! implementations; and the row-contract check of the native batches. Harness: `common/`. Doc:
//! rust/_docs/tech/source-euvd.md. Fixture: `tests/fixtures/sources/euvd/exploited-sample.json` (synthetic, read only);
//! the variants are written at test time (synthetic).

mod common;

use common::*;

const TIMESTAMPS: &[&str] = &["raw_record.fetched_at", "source_sync.last_sync"];
const EUVD_TABLES: &[&str] = &[
    "raw_record",
    "vulnerability",
    "alias",
    "affected",
    "epss",
    "source_sync",
];

fn fixtures() -> (PathBuf, PathBuf) {
    let root = rust_root();
    (
        root.join("../tests/fixtures/sources/euvd/exploited-sample.json"),
        root.join("../tests/fixtures/sources/epss/epss_scores-sample.csv"),
    )
}

fn native(store: &SqliteStore) -> Arc<dyn Source> {
    Arc::new(secmonk_sources::euvd::EuvdSource::new(Diff::view(store)))
}

fn native_epss(store: &SqliteStore) -> Arc<dyn Source> {
    Arc::new(secmonk_sources::epss::EpssSource::new(Diff::view(store)))
}

fn write(dir: &Path, name: &str, doc: &Value) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, serde_json::to_vec_pretty(doc).unwrap()).unwrap();
    p
}

/// The fixture changed: the Log4j record gets products (vendor names to normalize, a version, a non-dict entry) and a
/// second CVE, an EUVD score as a string; the record without alias is left out (it stays stored); new records: one
/// with lower-case and comma-separated aliases and a bool score, the same id again later (the later one counts), one
/// without an id, one with `products` as a string. Synthetic.
fn euvd_update(fixture: &Path, dir: &Path) -> PathBuf {
    let doc: Value = serde_json::from_slice(&std::fs::read(fixture).unwrap()).unwrap();
    let mut log4j = doc["items"][0].clone();
    log4j["aliases"] = json!("CVE-2021-44228\nCVE-2021-45046");
    log4j["epss"] = json!("0.9");
    log4j["dateUpdated"] = json!("2026-11-10T08:00:00.000Z");
    log4j["products"] = json!([
        {"vendor": "Apache_Software  Foundation", "product": "Log4j", "version": "2.14.1"},
        {"vendor": "apache", "product": "log4j-core", "version": ""},
        "not a product",
        {"vendor": "N/A", "product": "Ünïcode Product"}
    ]);
    let new = |aliases: &str, epss: Value, extra: Value| {
        let mut r = json!({
            "id": "EUVD-2026-00003", "description": "Synthetic record of the euvd differential test.",
            "datePublished": "2026-11-01T00:00:00.000Z", "dateUpdated": "2026-11-09T00:00:00.000Z",
            "baseScore": true, "baseScoreVersion": "4.0", "baseScoreVector": null, "aliases": aliases,
            "assigner": {"name": "nested"}, "epss": epss, "exploited": 0
        });
        for (k, v) in extra.as_object().unwrap() {
            r[k] = v.clone();
        }
        r
    };
    let items = json!([
        log4j,
        new("cve-2026-0003, GHSA-xxxx-yyyy\tcve-2026-0004", json!(0.25), json!({"products": "abc"})),
        {"description": "no id: skipped"},
        {"id": "", "description": "empty id: skipped"},
        new("CVE-2026-0003", json!(0.5), json!({"products": [{"product": "Widget", "version": "3"}]})),
    ]);
    write(
        dir,
        "euvd-update.json",
        &json!({"total": 5, "content": items}),
    )
}

/// The update with the children of the Log4j record gone (no products, no alias) and a NaN-free zero score.
fn euvd_shrink(fixture: &Path, dir: &Path) -> PathBuf {
    let doc: Value = serde_json::from_slice(&std::fs::read(fixture).unwrap()).unwrap();
    let mut log4j = doc["items"][0].clone();
    log4j["aliases"] = json!("");
    log4j["products"] = json!([]);
    log4j["baseScore"] = json!(0);
    write(dir, "euvd-shrink.json", &json!([log4j]))
}

/// `(vuln_id, extra)` of every euvd `affected` row as stored (raw text, so key order and number forms count).
fn affected_extra_text(python: &Path, mirror: &Path) -> Vec<(String, String)> {
    let dir = tempfile::tempdir().unwrap();
    let out = std::process::Command::new(python)
        .arg("-I")
        .arg("-c")
        .arg(
            "import json, sqlite3, sys\n\
             c = sqlite3.connect(sys.argv[1])\n\
             q = \"SELECT vuln_id, extra FROM affected WHERE source='euvd' ORDER BY vuln_id, extra\"\n\
             print(json.dumps(c.execute(q).fetchall()))\n",
        )
        .arg(mirror)
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn native_euvd_matches_py_sources() {
    let (fixture, epss_fixture) = fixtures();
    let Some(mut d) = Diff::new(&[&fixture, &epss_fixture]).await else {
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
    // the Rust mirror: euvd and epss both native (the others, unused here, from py-sources)
    let rs = d.engine(
        &rs_store,
        vec![native(&rs_store), native_epss(&rs_store), rs_py_src],
    );
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
    let step = |source: &'static str, path: PathBuf, extra: Value, what: &'static str| {
        let (py, rs) = (py.clone(), rs.clone());
        async move {
            let a = sync_job(&py, &[source], &path, extra.clone()).await;
            let b = sync_job(&rs, &[source], &path, extra).await;
            check_entries(&a, &b, what);
            b
        }
    };
    let count = |table: secmonk_model::MirrorTable, source: &'static str| {
        let store = rs_store.clone();
        async move { store.count_rows(table, source).await.unwrap() }
    };
    use secmonk_model::MirrorTable as T;

    // 1. EUVD before FIRST: scores for a CVE of the FIRST file and for one it lacks; the switch mirror on py-sources
    let v1 = euvd_variant(&fixture, dir.path(), "euvd-1.json", 0.5, 0.25);
    let b = step("euvd", v1.clone(), json!({}), "first sync").await;
    assert_eq!(entry_of(&b)["status"], "ok", "{b:#}");
    assert_eq!(entry_of(&b)["records"], 3);
    same("first sync");
    assert_eq!(
        (
            count(T::Vulnerability, "euvd").await,
            count(T::Alias, "euvd").await,
            count(T::Epss, "euvd").await
        ),
        (3, 2, 2),
        "the comparison is not vacuous"
    );
    let job = sync_job(&switch_py, &["euvd"], &v1, json!({})).await;
    assert_eq!(entry_of(&job)["status"], "ok", "{job:#}");

    // 2. the same file again
    step("euvd", v1.clone(), json!({}), "second sync").await;
    same("second sync");

    // 3. FIRST after EUVD: the FIRST row replaces the EUVD row of its CVE, the other EUVD row stays
    let b = step("epss", epss_fixture.clone(), json!({}), "epss after euvd").await;
    assert_eq!(entry_of(&b)["status"], "ok", "{b:#}");
    same("epss after euvd");
    assert_eq!(count(T::Epss, "euvd").await, 1);

    // 4. EUVD after FIRST: its own row changes, the FIRST row does not
    let v2 = euvd_variant(&fixture, dir.path(), "euvd-2.json", 0.1, 0.3);
    step("euvd", v2.clone(), json!({}), "euvd after epss").await;
    same("euvd after epss");
    let job = sync_job(&switch_py, &["euvd"], &v2, json!({})).await;
    assert_eq!(entry_of(&job)["status"], "ok", "{job:#}");

    // 5. an update: products, aliases, duplicate ids, skipped records, odd field types
    let updated = euvd_update(&fixture, dir.path());
    let b = step("euvd", updated.clone(), json!({}), "update").await;
    assert_eq!(entry_of(&b)["records"], 2, "{b:#}");
    same("update");
    assert!(count(T::Affected, "euvd").await >= 4);

    // the switch mirror: the native importer for the same update
    let job = sync_job(&switch_rs, &["euvd"], &updated, json!({})).await;
    assert_eq!(entry_of(&job)["status"], "ok", "{job:#}");
    assert!(
        job["log"]
            .to_string()
            .contains("euvd: native importer: applied state of generation "),
        "{job:#}"
    );
    // (the switch mirror has no FIRST rows: the euvd rows are compared; the EUVD scores of CVEs that have a FIRST row
    // differ by design, so `epss` is left out here and compared on the main pair)
    let switch_tables = &[
        "raw_record",
        "vulnerability",
        "alias",
        "affected",
        "source_sync",
    ];
    let switch_same = |what: &str| {
        assert_source_rows_equal(
            &python,
            py_store.mirror_path(),
            switch_store.mirror_path(),
            "euvd",
            what,
            TIMESTAMPS,
            switch_tables,
        );
    };
    switch_same("switch from py-sources to the native importer");

    // 5a. a failed and a limited Python run after the native one: nothing applied, native state kept
    let a_dir = dir.path().join("a-directory.json");
    std::fs::create_dir(&a_dir).unwrap();
    for (path, extra, status) in [
        (&a_dir, json!({}), "error"),
        (&updated, json!({"limit": 1}), "partial"),
    ] {
        let job = sync_job(&switch_py, &["euvd"], path, extra).await;
        let e = entry_of(&job);
        if status == "partial" {
            // the Python euvd source reports ok with --limit: an ok run repairs (checked below instead)
            assert_eq!(e["status"], "ok", "{job:#}");
            continue;
        }
        assert_eq!(e["status"], "error", "{status}: {job:#}");
        assert!(
            e["message"].as_str().unwrap().ends_with(
                "; not applied: mirror keeps the native importer data until a successful py-sources sync"
            ),
            "{job:#}"
        );
        switch_same(&format!("a {status} Python run after Rust"));
        let st = switch_store.applied_state("euvd").await.unwrap().unwrap();
        assert_eq!(
            st.generation.as_deref(),
            Some(secmonk_traits::NATIVE_GENERATION)
        );
    }

    // 5b. back to py-sources: the limited ok run above repaired from the staging export; one more full run
    let job = sync_job(&switch_py, &["euvd"], &updated, json!({})).await;
    assert_eq!(entry_of(&job)["status"], "ok", "{job:#}");
    assert_mirror_equals_staging(
        &python,
        switch_store.mirror_path(),
        &switch_staging,
        "switch back to py-sources",
    );
    switch_same("switch back to py-sources vs py-sources only");

    // 6. children removed, a zero score
    step(
        "euvd",
        euvd_shrink(&fixture, dir.path()),
        json!({}),
        "shrink",
    )
    .await;
    same("shrink");

    // 7. a limited run (Python reports ok)
    let b = step("euvd", updated.clone(), json!({"limit": 1}), "limit").await;
    assert_eq!(entry_of(&b)["records"], 1);
    same("limit");

    // 7a. review W9.1 L6: an id whose two records fall in different chunks (at most 500 records each), two identical
    // products (kept when unchanged, both removed when one goes), and the stored text of `affected.extra` (key order)
    let p = json!({"version": "1", "vendor": "Acme", "product": "Same", "zeta": {"b": 1, "a": [2.5, "ü"]}});
    let mut items: Vec<Value> = vec![
        json!({"id": "EUVD-X", "aliases": "CVE-2099-0009", "epss": 0.9, "products": [{"product": "Old"}]}),
    ];
    items.extend(
        (0..600).map(|i| json!({"id": format!("EUVD-F-{i}"), "aliases": format!("CVE-2098-{i}")})),
    );
    items
        .push(json!({"id": "EUVD-X", "aliases": "CVE-2099-0001", "epss": 0.2, "products": [p, p]}));
    let cross = write(dir.path(), "cross.json", &Value::Array(items.clone()));
    let b = step(
        "euvd",
        cross.clone(),
        json!({}),
        "repeated id across chunks",
    )
    .await;
    assert_eq!(entry_of(&b)["records"], 601, "{b:#}");
    same("repeated id across chunks");
    step("euvd", cross, json!({}), "identical products again").await;
    same("identical products again");
    *items.last_mut().unwrap() =
        json!({"id": "EUVD-X", "aliases": "CVE-2099-0001", "epss": 0.2, "products": [p]});
    let one = write(dir.path(), "cross-one.json", &Value::Array(items));
    step("euvd", one, json!({}), "one of two identical products").await;
    same("one of two identical products");
    let (ea, eb) = (
        affected_extra_text(&python, py_store.mirror_path()),
        affected_extra_text(&python, rs_store.mirror_path()),
    );
    assert_eq!(ea, eb, "affected.extra as stored");
    assert!(
        eb.iter().any(|(v, e)| v == "EUVD-X"
            && e == r#"{"version":"1","vendor":"Acme","product":"Same","zeta":{"b":1,"a":[2.5,"ü"]}}"#),
        "feed key order kept: {eb:?}"
    );

    // 8. errors with Python's wording: nothing stored but the status row
    let cases: Vec<(&str, Value)> = vec![
        ("not-a-dict.json", json!([{"id": "EUVD-X"}, 5])),
        (
            "bad-epss.json",
            json!([{"id": "EUVD-X", "aliases": "CVE-1", "epss": "high"}]),
        ),
        (
            "list-epss.json",
            json!([{"id": "EUVD-X", "aliases": "CVE-1", "epss": [1]}]),
        ),
        (
            "bad-aliases.json",
            json!([{"id": "EUVD-X", "aliases": ["CVE-1"]}]),
        ),
        (
            "bad-score.json",
            json!([{"id": "EUVD-X", "baseScore": "9.8"}]),
        ),
        (
            "bad-products.json",
            json!([{"id": "EUVD-X", "products": 3}]),
        ),
        ("shape.json", json!({"total": 0, "items": {"a": 1}})),
    ];
    for (name, doc) in cases {
        let p = write(dir.path(), name, &doc);
        let b = step("euvd", p, json!({}), "a bad record").await;
        assert_eq!(entry_of(&b)["status"], "error", "{name}: {b:#}");
        same(name);
    }
    let latin1 = dir.path().join("latin1.json");
    std::fs::write(&latin1, b"[{\"id\": \"EUVD-caf\xe9\"}]").unwrap();
    for (p, what) in [(&a_dir, "a directory"), (&latin1, "invalid UTF-8")] {
        let b = step("euvd", p.clone(), json!({}), what).await;
        assert_eq!(entry_of(&b)["status"], "error", "{what}");
        same(what);
    }
    // 9. the euvd rows of both mirrors, once more after everything
    assert_source_rows_equal(
        &python,
        py_store.mirror_path(),
        rs_store.mirror_path(),
        "euvd",
        "end",
        TIMESTAMPS,
        EUVD_TABLES,
    );

    // a JSON syntax error: same status, other wording (from here on the status rows differ in their message)
    let not_json = dir.path().join("not.json");
    std::fs::write(&not_json, "[{").unwrap();
    let a = sync_job(&py, &["euvd"], &not_json, json!({})).await;
    let b = sync_job(&rs, &["euvd"], &not_json, json!({})).await;
    assert_eq!(entry_of(&b)["status"], "error", "{b:#}");
    assert_eq!(entry_of(&a)["status"], entry_of(&b)["status"], "{a:#}");
    compare(
        "invalid JSON",
        &[
            "raw_record.fetched_at",
            "source_sync.last_sync",
            "source_sync.message",
        ],
    );

    // 10. a documented difference (source-euvd.md): a number in a text field is stored as text by Python and refuses
    // the run natively; the mirrors differ from here on
    let text_number = write(
        dir.path(),
        "text-number.json",
        &json!([{"id": "EUVD-X", "description": 5}]),
    );
    let a = sync_job(&py, &["euvd"], &text_number, json!({})).await;
    let b = sync_job(&rs, &["euvd"], &text_number, json!({})).await;
    assert_eq!(entry_of(&a)["status"], "ok", "{a:#}");
    assert_eq!(entry_of(&b)["status"], "error", "{b:#}");
    assert_eq!(
        entry_of(&b)["message"],
        "euvd: EUVD-X: description is not a string"
    );
    d.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn native_euvd_batches_follow_the_row_contract() {
    // every native euvd batch and end validates against rust/contracts (source/rows, source/sync-end); applied to a
    // real store, none skipped; affected deletes keyed by the record are among them
    let (fixture, _) = fixtures();
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(
        &dir.path().join("state.sqlite3"),
        &dir.path().join("mirror.sqlite3"),
        &StoreOptions::default(),
    )
    .await
    .unwrap();
    let src = secmonk_sources::euvd::EuvdSource::new(Diff::view(&store)).with_limits(
        secmonk_sources::batch::Limits {
            ops: 4,
            bytes: 1 << 20,
        },
    );
    let path = |p: &Path| json!({"path": p.display().to_string()});
    let updated = euvd_update(&fixture, dir.path());
    let shrink = euvd_shrink(&fixture, dir.path());
    let missing = dir.path().join("missing.json");
    let deletes = check_row_contract(
        &src,
        &store,
        "euvd",
        &[
            path(&fixture),
            path(&updated),
            path(&shrink),
            json!({"path": updated.display().to_string(), "limit": 1}),
            path(&missing),
        ],
    )
    .await;
    assert!(deletes >= 3, "alias and affected deletes: {deletes}");
    store.close().await;
}
