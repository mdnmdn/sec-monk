//! Differential test of the native kev importer against `py-sources` (stage 6, rust ADR-0011): both through the
//! engine on their own mirrors, then a mirror that switches between them. Harness: `common/`. Doc:
//! rust/_docs/tech/source-kev.md.

mod common;

use common::*;

/// `(cve_id, extra)` of every `kev` row as stored (raw text), ordered by CVE.
fn kev_extra_text(python: &Path, mirror: &Path) -> Vec<(String, String)> {
    let dir = tempfile::tempdir().unwrap();
    let out = std::process::Command::new(python)
        .arg("-I")
        .arg("-c")
        .arg(
            "import json, sqlite3, sys\n\
             c = sqlite3.connect(sys.argv[1])\n\
             print(json.dumps(c.execute('SELECT cve_id, extra FROM kev ORDER BY cve_id').fetchall()))\n",
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

/// The kev fixture changed: `drop` entries removed from the end, the first entry's product renamed, one new entry
/// with an unmapped field, another catalog version.
fn kev_update(fixture: &Path, dir: &Path) -> PathBuf {
    let mut doc: Value = serde_json::from_slice(&std::fs::read(fixture).unwrap()).unwrap();
    let v = doc["vulnerabilities"].as_array_mut().unwrap();
    v.truncate(v.len() - 2);
    v[0]["product"] = json!("Log4j2 (renamed)");
    v[1]["knownRansomwareCampaignUse"] = json!("Unknown");
    v.push(json!({
        "cveID": "CVE-2026-99999", "vendorProject": "Example", "product": "Widget",
        "vulnerabilityName": "Example Widget Synthetic Vulnerability", "dateAdded": "2026-11-10",
        "shortDescription": "Synthetic entry of the differential test (no real CVE).", "requiredAction": "None.",
        "dueDate": "2026-12-01", "knownRansomwareCampaignUse": "Known", "notes": "", "cwes": [],
        "newField": {"nested": [1, 2.5, "ü"]}
    }));
    doc["count"] = json!(v.len());
    doc["catalogVersion"] = json!("2026.11.10");
    let p = dir.join("kev-update.json");
    std::fs::write(&p, serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
    p
}

#[tokio::test(flavor = "multi_thread")]
async fn native_kev_matches_py_sources() {
    // Stage 6 differential test (component-lifecycle.md): the native kev source and py-sources' kev, each through
    // the engine on its own mirror, leave identical mirrors (run timestamps aside) after every step; a mirror that
    // switches from py-sources to the native importer and back to py-sources ends where ADR-0010/0011 say.
    let fixture =
        rust_root().join("../tests/fixtures/sources/kev/known_exploited_vulnerabilities.json");
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
    let (switch_src, switch_staging) = d.py_sources(&switch_store, "modules-switch");
    let native = |store: &SqliteStore| -> Arc<dyn Source> {
        Arc::new(secmonk_sources::kev::KevSource::new(Diff::view(store)))
    };
    let py = d.engine(&py_store, vec![py_src]);
    let rs = d.engine(&rs_store, vec![native(&rs_store)]);
    let switch_py = d.engine(&switch_store, vec![switch_src]);
    let switch_rs = d.engine(&switch_store, vec![native(&switch_store)]);

    async fn sync(engine: &SecmonkEngine, path: &Path, extra: Value) -> Value {
        sync_job(engine, &["kev"], path, extra).await
    }
    let entry = entry_of;
    const TIMESTAMPS: &[&str] = &["raw_record.fetched_at", "source_sync.last_sync"];
    let same = |what: &str| {
        assert_mirrors_equal(
            &python,
            py_store.mirror_path(),
            rs_store.mirror_path(),
            what,
            TIMESTAMPS,
            &[],
        );
    };
    // both versions on the same input: same entry (status, records, message) and the same mirror
    async fn both(
        py: &SecmonkEngine,
        rs: &SecmonkEngine,
        path: &Path,
        extra: Value,
    ) -> (Value, Value) {
        let a = sync(py, path, extra.clone()).await;
        let b = sync(rs, path, extra).await;
        (a, b)
    }
    let updated = kev_update(&fixture, dir.path());
    let small = {
        let mut doc: Value = serde_json::from_slice(&std::fs::read(&fixture).unwrap()).unwrap();
        doc["vulnerabilities"].as_array_mut().unwrap().truncate(2);
        let p = dir.path().join("kev-small.json");
        std::fs::write(&p, serde_json::to_vec(&doc).unwrap()).unwrap();
        p
    };

    // 1. first sync; the switch mirror starts on py-sources
    let (a, b) = both(&py, &rs, &fixture, json!({})).await;
    check_entries(&a, &b, "first sync");
    assert_eq!(entry(&b)["status"], "ok");
    let kev_rows = rs_store
        .count_rows(secmonk_model::MirrorTable::Kev, "kev")
        .await
        .unwrap();
    assert_eq!(kev_rows, 9, "the comparison is not vacuous");
    same("first sync");
    // `same` compares JSON normalized; the stored text of `kev.extra` must be equal too (feed key order, compact)
    let (pa, pb) = (
        kev_extra_text(&python, py_store.mirror_path()),
        kev_extra_text(&python, rs_store.mirror_path()),
    );
    assert_eq!(pa, pb, "kev.extra as stored");
    let log4j = pb.iter().find(|(c, _)| c == "CVE-2021-44228").unwrap();
    assert!(
        log4j
            .1
            .starts_with("{\"shortDescription\":\"Apache Log4j2 contains")
            && log4j.1.contains("\"forensicTriage\":\"No\",\"notes\":")
            && log4j
                .1
                .ends_with("\"cwes\":[\"CWE-20\",\"CWE-400\",\"CWE-502\"]}"),
        "unmapped fields in feed order: {}",
        log4j.1
    );
    assert_eq!(sync(&switch_py, &fixture, json!({})).await["status"], "ok");

    // 2. the same feed again (no change)
    let (a, b) = both(&py, &rs, &fixture, json!({})).await;
    check_entries(&a, &b, "second sync");
    same("second sync");

    // 3. an update: removed, changed and added entries; the switch mirror uses the native importer for it
    let (a, b) = both(&py, &rs, &updated, json!({})).await;
    check_entries(&a, &b, "update");
    same("update");
    let job = sync(&switch_rs, &updated, json!({})).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    assert!(
        job["log"]
            .to_string()
            .contains("kev: native importer: applied state of generation "),
        "{job:#}"
    );
    assert_mirrors_equal(
        &python,
        py_store.mirror_path(),
        switch_store.mirror_path(),
        "switch from py-sources to the native importer",
        TIMESTAMPS,
        &[],
    );

    // 3a. a failed and a limited Python run after the native one: staging is stale, nothing is applied (review M1)
    let a_dir = dir.path().join("a-directory.json");
    std::fs::create_dir(&a_dir).unwrap();
    for (path, extra, status) in [
        (&a_dir, json!({}), "error"),
        (&fixture, json!({"limit": 3}), "partial"),
    ] {
        let job = sync(&switch_py, path, extra).await;
        let e = entry(&job);
        assert_eq!(e["status"], "error", "{status}: {job:#}");
        let msg = e["message"].as_str().unwrap();
        assert!(
            msg.starts_with(&format!("{status}: "))
                && msg.ends_with(
                    "; not applied: mirror keeps the native importer data until a successful py-sources sync"
                ),
            "{msg}"
        );
        assert_mirrors_equal(
            &python,
            py_store.mirror_path(),
            switch_store.mirror_path(),
            &format!("a {status} Python run after Rust"),
            TIMESTAMPS,
            &[],
        );
        let st = switch_store.applied_state("kev").await.unwrap().unwrap();
        assert_eq!(
            st.generation.as_deref(),
            Some(secmonk_traits::NATIVE_GENERATION)
        );
    }

    // 3b. switch back to py-sources: another generation, repair from the staging export
    let job = sync(&switch_py, &updated, json!({})).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    assert!(
        job["log"]
            .to_string()
            .contains("repaired from the staging export"),
        "{job:#}"
    );
    assert!(
        job["log"].to_string().contains(
            "kev: repair from py-sources export: the last applied batches came from the native importer"
        ),
        "{job:#}"
    );
    assert_mirror_equals_staging(
        &python,
        switch_store.mirror_path(),
        &switch_staging,
        "switch back to py-sources",
    );
    assert_mirrors_equal(
        &python,
        py_store.mirror_path(),
        switch_store.mirror_path(),
        "switch back to py-sources vs py-sources only",
        TIMESTAMPS,
        &[],
    );

    // 4. a limited run (partial, nothing deleted, the cursor kept)
    let (a, b) = both(&py, &rs, &fixture, json!({"limit": 3})).await;
    check_entries(&a, &b, "limit");
    assert_eq!(entry(&b)["status"], "partial");
    same("limit");

    // 5. a snapshot under half of the stored rows is refused; 6. unreadable or invalid input
    let (a, b) = both(&py, &rs, &small, json!({})).await;
    check_entries(&a, &b, "snapshot guard");
    assert_eq!(entry(&b)["status"], "error");
    same("snapshot guard");
    // (a missing path is refused by the engine before any source runs; a directory reaches the source)
    let (a, b) = both(&py, &rs, &a_dir, json!({})).await;
    assert_eq!(entry(&a)["status"], "error");
    check_entries(&a, &b, "unreadable file"); // "[Errno 21] Is a directory: '<path>'" in both
    same("unreadable file");
    let not_json = dir.path().join("not.json");
    std::fs::write(&not_json, "{").unwrap();
    let (a, b) = both(&py, &rs, &not_json, json!({})).await;
    assert_eq!(
        (entry(&a)["status"].clone(), entry(&b)["status"].clone()),
        (json!("error"), json!("error"))
    );
    // json.loads and serde_json word their errors differently: the status row compares without the message
    assert_mirrors_equal(
        &python,
        py_store.mirror_path(),
        rs_store.mirror_path(),
        "invalid JSON",
        &[
            "raw_record.fetched_at",
            "source_sync.last_sync",
            "source_sync.message",
        ],
        &[],
    );

    // 7. forced replacement
    let (a, b) = both(&py, &rs, &small, json!({"full": true})).await;
    check_entries(&a, &b, "full");
    same("full");

    // 8. repair: the Rust mirror is reset (a new file); the next native sync rebuilds kev and source_sync. Raw
    // records of CVEs that left the feed are not restored (py-sources would restore them from staging; ADR-0011).
    let reset = d.store("rs-reset").await;
    let rs2 = d.engine(&reset, vec![native(&reset)]);
    let (a, b) = both(&py, &rs2, &fixture, json!({})).await;
    check_entries(&a, &b, "after a mirror reset");
    assert_mirrors_equal(
        &python,
        py_store.mirror_path(),
        reset.mirror_path(),
        "after a mirror reset",
        TIMESTAMPS,
        &[
            "kev",
            "source_sync",
            "vulnerability",
            "alias",
            "affected",
            "epss",
            "distro_triage",
        ],
    );

    d.close().await;
}
