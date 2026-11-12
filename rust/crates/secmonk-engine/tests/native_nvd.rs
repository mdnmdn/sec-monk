//! Differential test of the native nvd importer against `py-sources` (stage 6, rust ADR-0011 / ADR-0012): both
//! through the engine on their own mirrors (`--path` pages: the Python source's API URL is fixed, so the API itself is
//! covered by `secmonk-sources/tests/nvd.rs` against a local server), then a mirror that switches between the two
//! implementations; the row-contract check of the native batches (an API delta against a local server among them, for
//! the `nvd:progress` rows); and the volume measurement (ignored, run by hand). Harness: `common/`. Doc:
//! rust/_docs/tech/source-nvd.md. Fixture: `tests/fixtures/sources/nvd/cve-2021-44228.json` (synthetic, read only); the
//! variants are written at test time (synthetic).

mod common;

use common::*;

const SRC: &str = "nvd";
const TIMESTAMPS: &[&str] = &["raw_record.fetched_at", "source_sync.last_sync"];
const NVD_TABLES: &[&str] = &[
    "raw_record",
    "vulnerability",
    "alias",
    "affected",
    "source_sync",
];

fn fixture() -> PathBuf {
    rust_root().join("../tests/fixtures/sources/nvd/cve-2021-44228.json")
}

fn native(store: &SqliteStore) -> Arc<dyn Source> {
    Arc::new(secmonk_sources::nvd::NvdSource::new(Diff::view(store)))
}

fn write(dir: &Path, name: &str, doc: &Value) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, serde_json::to_vec_pretty(doc).unwrap()).unwrap();
    p
}

fn page(cves: &[Value]) -> Value {
    json!({"resultsPerPage": cves.len(), "startIndex": 0, "totalResults": cves.len(), "format": "NVD_CVE",
           "version": "2.0", "timestamp": "2026-11-11T00:00:00.000",
           "vulnerabilities": cves.iter().map(|c| json!({"cve": c})).collect::<Vec<_>>()})
}

fn fixture_cve() -> Value {
    let doc: Value = serde_json::from_slice(&std::fs::read(fixture()).unwrap()).unwrap();
    doc["vulnerabilities"][0]["cve"].clone()
}

/// A synthetic CVE: `matches` as its cpeMatch list, a CVSS 3.1 Primary metric of `score`.
fn cve(id: &str, modified: &str, score: f64, matches: Value) -> Value {
    json!({"id": id, "sourceIdentifier": "cna@example.org", "published": "2026-01-01T00:00:00.000",
           "lastModified": modified, "vulnStatus": "Analyzed", "cveTags": [],
           "descriptions": [{"lang": "es", "value": "sintético"}, {"lang": "en", "value": format!("{id} synthetic")}],
           "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
               "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L", "baseScore": score}}]},
           "weaknesses": [{"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-79"}]}],
           "configurations": [{"nodes": [{"operator": "OR", "negate": false, "cpeMatch": matches}]}],
           "references": [{"url": "https://example.org/advisory", "source": "cna@example.org"}]})
}

fn m(criteria: &str, extra: Value) -> Value {
    let mut v = json!({"vulnerable": true, "criteria": criteria});
    for (k, x) in extra.as_object().unwrap() {
        v[k] = x.clone();
    }
    v
}

/// The first update: the Log4j CVE with another configuration and metrics (a CVSS 4.0 Secondary, a 3.1 Primary, a
/// 2.0 one), CWEs Secondary before Primary; a CVE with every cpeMatch shape; a CVE that the second update rejects.
fn update1(dir: &Path) -> PathBuf {
    let mut log4j = fixture_cve();
    log4j["lastModified"] = json!("2026-11-10T00:00:00.000");
    log4j["metrics"]["cvssMetricV40"] = json!([{"source": "cna@example.org", "type": "Secondary",
        "cvssData": {"version": "4.0", "vectorString": "CVSS:4.0/AV:N", "baseScore": 9.3, "baseSeverity": "CRITICAL"}}]);
    log4j["metrics"]["cvssMetricV2"] = json!([{"source": "nvd@nist.gov", "type": "Primary", "baseSeverity": "HIGH",
        "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:M/Au:N/C:C/I:C/A:C", "baseScore": 9.3}}]);
    log4j["weaknesses"] = json!([
        {"source": "cna", "type": "Secondary", "description": [{"lang": "en", "value": "CWE-20"}, {"lang": "en", "value": "NVD-CWE-noinfo"}]},
        {"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-917"}, {"lang": "en", "value": "CWE-20"}]}]);
    log4j["configurations"][0]["nodes"][0]["cpeMatch"]
        .as_array_mut()
        .unwrap()
        .push(m(
            "cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*",
            json!({"matchCriteriaId": "11111111-0000-0000-0000-000000000001"}),
        ));
    let shapes = cve(
        "CVE-2099-1000",
        "2026-11-09T00:00:00.000",
        6.1,
        json!([
            m("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", json!({"versionEndExcluding": "120.0.6099.109", "matchCriteriaId": "A"})),
            m("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*", json!({"versionEndIncluding": "99", "matchCriteriaId": "A"})),
            m("cpe:2.3:a:Foo_Bar:Some_Product:1.2.3:*:*:*:*:*:*:*", json!({})),
            m("cpe:2.3:a:Foo_Bar:Some_Product:1.2.3:*:*:*:*:*:*:*", json!({})),
            m("cpe:2.3:a:foo:dash:-:*:*:*:*:*:*:*", json!({"matchCriteriaId": "D"})),
            m("cpe:2.3:a:foo:rc:3.0:rc1:*:*:*:*:*:*", json!({"matchCriteriaId": "E"})),
            m("cpe:2.3:a:foo:all:*:*:*:*:*:*:*:*", json!({"matchCriteriaId": 7})),
            m("cpe:2.3:a:foo:same:*:*:*:*:*:*:*:*", json!({"matchCriteriaId": 7.0})),
            m("cpe:2.3:a:foo:esc\\:aped:*:*:*:*:*:*:*:*", json!({"versionStartExcluding": "1", "versionEndIncluding": "2", "matchCriteriaId": "F"})),
            m("cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*", json!({"versionStartIncluding": "5.10", "versionEndExcluding": 6, "matchCriteriaId": "G"})),
            {"vulnerable": false, "criteria": "cpe:2.3:h:foo:board:-:*:*:*:*:*:*:*", "matchCriteriaId": "H"},
            m("not a cpe", json!({"matchCriteriaId": "I"})),
            m("", json!({"matchCriteriaId": "J"})),
        ]),
    );
    let doomed = cve(
        "CVE-2099-2000",
        "2026-11-09T00:00:00.000",
        0.0,
        json!([m(
            "cpe:2.3:a:acme:doomed:*:*:*:*:*:*:*:*",
            json!({"versionEndExcluding": "2", "matchCriteriaId": "K"})
        )]),
    );
    let d = dir.join("update1");
    std::fs::create_dir_all(&d).unwrap();
    write(&d, "a.json", &page(&[log4j, shapes]));
    write(&d, "b.json", &page(&[doomed]));
    d
}

/// The second update: the doomed CVE rejected, the shapes CVE shrunk, a CVE twice (pages a and b: b counts) and twice
/// within one page.
fn update2(dir: &Path) -> PathBuf {
    let mut doomed = cve("CVE-2099-2000", "2026-11-11T00:00:00.000", 0.0, json!([]));
    doomed["vulnStatus"] = json!("Rejected");
    doomed["configurations"] = json!(null);
    let shapes = cve(
        "CVE-2099-1000",
        "2026-11-11T00:00:00.000",
        6.1,
        json!([m(
            "cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*",
            json!({"versionEndExcluding": "121.0", "matchCriteriaId": "A"})
        )]),
    );
    let twice = |v: &str| {
        cve(
            "CVE-2099-3000",
            "2026-11-11T00:00:00.000",
            5.0,
            json!([m(
                &format!("cpe:2.3:a:acme:twice_{v}:*:*:*:*:*:*:*:*"),
                json!({"matchCriteriaId": v})
            )]),
        )
    };
    let d = dir.join("update2");
    std::fs::create_dir_all(&d).unwrap();
    write(
        &d,
        "a.json",
        &page(&[doomed, shapes, twice("one"), twice("two")]),
    );
    write(&d, "b.json", &page(&[twice("three")]));
    d
}

/// `n` CVEs, CVE-2098-00000 again as the last one (another chunk): the repeated id replaces the rows it got earlier
/// in the run.
fn many(dir: &Path, n: usize) -> PathBuf {
    let mut cves: Vec<Value> = (0..n)
        .map(|i| {
            cve(
                &format!("CVE-2098-{i:05}"),
                "2026-11-11T00:00:00.000",
                4.0,
                json!([m(
                    &format!("cpe:2.3:a:v:p{i}:*:*:*:*:*:*:*:*"),
                    json!({"versionEndExcluding": "1", "matchCriteriaId": format!("M{i}")})
                )]),
            )
        })
        .collect();
    cves.push(cve(
        "CVE-2098-00000",
        "2026-11-12T00:00:00.000",
        4.0,
        json!([m(
            "cpe:2.3:a:v:again:*:*:*:*:*:*:*:*",
            json!({"matchCriteriaId": "again"})
        )]),
    ));
    let d = dir.join("many");
    std::fs::create_dir_all(&d).unwrap();
    write(&d, "a.json", &page(&cves));
    d
}

#[tokio::test(flavor = "multi_thread")]
async fn native_nvd_matches_py_sources() {
    let fx = fixture();
    let Some(mut d) = Diff::new(&[&fx]).await else {
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
    let step = |path: PathBuf, extra: Value, what: &'static str| {
        let (py, rs) = (py.clone(), rs.clone());
        async move {
            let a = sync_job(&py, &[SRC], &path, extra.clone()).await;
            let b = sync_job(&rs, &[SRC], &path, extra).await;
            check_entries(&a, &b, what);
            b
        }
    };
    let count = |table: secmonk_model::MirrorTable| {
        let store = rs_store.clone();
        async move { store.count_rows(table, SRC).await.unwrap() }
    };
    let status = |b: &Value| entry_of(b)["status"].as_str().unwrap().to_owned();
    use secmonk_model::MirrorTable as T;

    // 1. the fixture; the switch mirror on py-sources
    let b = step(fx.clone(), json!({}), "first sync").await;
    assert_eq!(status(&b), "ok", "{b:#}");
    assert_eq!(entry_of(&b)["records"], 1);
    same("first sync");
    assert_eq!(
        (count(T::Vulnerability).await, count(T::Affected).await),
        (1, 1),
        "the comparison is not vacuous"
    );
    let job = sync_job(&switch_py, &[SRC], &fx, json!({})).await;
    assert_eq!(status(&job), "ok", "{job:#}");

    // 2. the same file again
    step(fx.clone(), json!({}), "second sync").await;
    same("second sync");

    // 3. a directory of pages: a changed configuration and metrics, every cpeMatch shape, a CVE to reject later
    let u1 = update1(dir.path());
    let b = step(u1.clone(), json!({}), "update 1").await;
    assert_eq!(
        (status(&b), entry_of(&b)["records"].clone()),
        ("ok".into(), json!(3)),
        "{b:#}"
    );
    same("update 1");
    assert!(count(T::Affected).await >= 9);

    // the switch mirror: the native importer for the same update
    let job = sync_job(&switch_rs, &[SRC], &u1, json!({})).await;
    assert_eq!(status(&job), "ok", "{job:#}");
    assert!(
        job["log"]
            .to_string()
            .contains("nvd: native importer: applied state of generation "),
        "{job:#}"
    );
    let switch_same = |what: &str| {
        assert_source_rows_equal(
            &python,
            py_store.mirror_path(),
            switch_store.mirror_path(),
            SRC,
            what,
            TIMESTAMPS,
            NVD_TABLES,
        );
    };
    switch_same("switch from py-sources to the native importer");

    // 4. the second update: a CVE rejected (its rows dropped), a configuration shrunk, a CVE twice
    let u2 = update2(dir.path());
    let b = step(u2.clone(), json!({}), "update 2").await;
    assert_eq!(entry_of(&b)["records"], 5);
    same("update 2");
    let job = sync_job(&switch_rs, &[SRC], &u2, json!({})).await;
    assert_eq!(status(&job), "ok", "{job:#}");
    switch_same("native update 2 on the switch mirror");

    // 4a. a failed py-sources run after native ones: nothing applied, the native state kept
    let a_dir = dir.path().join("a-directory.json");
    std::fs::create_dir(&a_dir).unwrap();
    let broken = dir.path().join("broken.json");
    std::fs::write(&broken, "{").unwrap();
    let job = sync_job(&switch_py, &[SRC], &broken, json!({})).await;
    let e = entry_of(&job);
    assert_eq!(e["status"], "error", "{job:#}");
    assert!(
        e["message"].as_str().unwrap().ends_with(
            "; not applied: mirror keeps the native importer data until a successful py-sources sync"
        ),
        "{job:#}"
    );
    switch_same("a failed Python run after Rust");
    let st = switch_store.applied_state(SRC).await.unwrap().unwrap();
    assert_eq!(
        st.generation.as_deref(),
        Some(secmonk_traits::NATIVE_GENERATION)
    );

    // 4b. back to py-sources: an ok run repairs from the staging export (staging has not seen update 1: it ran
    // natively here, so update 1 then update 2 give it the history of the Python-only mirror)
    let job = sync_job(&switch_py, &[SRC], &u1, json!({})).await;
    assert_eq!(status(&job), "ok", "{job:#}");
    assert!(
        job["log"]
            .to_string()
            .contains("nvd: repair from py-sources export"),
        "{job:#}"
    );
    let job = sync_job(&switch_py, &[SRC], &u2, json!({})).await;
    assert_eq!(status(&job), "ok", "{job:#}");
    assert_mirror_equals_staging(
        &python,
        switch_store.mirror_path(),
        &switch_staging,
        "switch back to py-sources",
    );
    switch_same("switch back to py-sources vs py-sources only");

    // 5. limit (the file branch reports ok), then the whole update again
    let b = step(u1.clone(), json!({"limit": 2}), "limit").await;
    assert_eq!(
        (status(&b), entry_of(&b)["records"].clone()),
        ("ok".into(), json!(2))
    );
    same("limit");
    step(u1.clone(), json!({}), "update 1 again").await;
    same("update 1 again");

    // 6. 601 records in one page (two chunks of rows_by_id), one id again at the end
    let b = step(many(dir.path(), 600), json!({}), "many").await;
    assert_eq!(entry_of(&b)["records"], 601);
    same("many");

    // 7. errors: a later page fails (caught: partial, uncaught: error); the earlier pages stay
    let err_dir = dir.path().join("errors");
    std::fs::create_dir(&err_dir).unwrap();
    write(
        &err_dir,
        "1.json",
        &page(&[cve(
            "CVE-2099-4000",
            "2026-11-12T00:00:00.000",
            3.0,
            json!([]),
        )]),
    );
    let cases: Vec<(&str, Value, &str)> = vec![
        (
            "key-error",
            json!({"vulnerabilities": [{"cve": cve("CVE-2099-4001", "x", 1.0, json!([]))}, {"nocve": 1}]}),
            "partial",
        ),
        (
            "no-id",
            json!({"vulnerabilities": [{"cve": {"lastModified": "x"}}]}),
            "partial",
        ),
        ("not-a-dict", json!([{"vulnerabilities": []}]), "error"),
        ("null-items", json!({"vulnerabilities": null}), "error"),
        (
            "string-item",
            json!({"vulnerabilities": ["CVE-1"]}),
            "error",
        ),
        (
            "metrics-list",
            json!({"vulnerabilities": [{"cve": {"id": "CVE-2099-4002", "metrics": []}}]}),
            "error",
        ),
        (
            "score-text",
            json!({"vulnerabilities": [{"cve": {"id": "CVE-2099-4003", "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": "9"}}]}}}]}),
            "error",
        ),
        (
            "criteria-number",
            json!({"vulnerabilities": [{"cve": cve("CVE-2099-4004", "x", 1.0, json!([{"vulnerable": true, "criteria": 5}]))}]}),
            "error",
        ),
        (
            "unhashable",
            json!({"vulnerabilities": [{"cve": cve("CVE-2099-4005", "x", 1.0, json!([{"vulnerable": true, "matchCriteriaId": [1]}]))}]}),
            "error",
        ),
        (
            "cwe-null",
            json!({"vulnerabilities": [{"cve": {"id": "CVE-2099-4006", "weaknesses": [{"description": [{"value": null}]}]}}]}),
            "error",
        ),
    ];
    for (name, doc, want) in cases {
        let p = write(&err_dir, "2.json", &doc);
        let b = step(err_dir.clone(), json!({}), "a failing page").await;
        assert_eq!(status(&b), want, "{name}: {b:#}");
        same(name);
        std::fs::remove_file(p).unwrap();
    }
    let latin1 = err_dir.join("2.json");
    std::fs::write(&latin1, b"{\"vulnerabilities\": [], \"x\": \"caf\xe9\"}").unwrap();
    let b = step(err_dir.clone(), json!({}), "invalid UTF-8").await;
    assert_eq!(status(&b), "partial", "{b:#}");
    same("invalid UTF-8");
    std::fs::remove_file(&latin1).unwrap();
    std::fs::create_dir(err_dir.join("2.json")).unwrap();
    let b = step(err_dir.clone(), json!({}), "a directory named .json").await;
    assert_eq!(status(&b), "partial", "{b:#}");
    same("a directory named .json");
    let b = step(a_dir.clone(), json!({}), "a directory without pages").await;
    assert_eq!(
        (status(&b), entry_of(&b)["records"].clone()),
        ("ok".into(), json!(0))
    );
    same("a directory without pages");

    // 8. the nvd rows of both mirrors, once more after everything
    assert_source_rows_equal(
        &python,
        py_store.mirror_path(),
        rs_store.mirror_path(),
        SRC,
        "end",
        TIMESTAMPS,
        NVD_TABLES,
    );

    // a JSON syntax error: same status, other wording (from here on the status rows differ in their message)
    let not_json = dir.path().join("not.json");
    std::fs::write(&not_json, "{\"vulnerabilities\": [").unwrap();
    let a = sync_job(&py, &[SRC], &not_json, json!({})).await;
    let b = sync_job(&rs, &[SRC], &not_json, json!({})).await;
    assert_eq!(status(&b), "error", "{b:#}");
    assert_eq!(entry_of(&a)["status"], entry_of(&b)["status"], "{a:#}");
    compare(
        "invalid JSON",
        &[
            "raw_record.fetched_at",
            "source_sync.last_sync",
            "source_sync.message",
        ],
    );

    // 9. a documented difference (source-nvd.md): a number in a text field is stored as text by Python and stops the
    // native run at its page; the mirrors differ from here on
    let text_number = write(
        dir.path(),
        "text-number.json",
        &page(&[json!({"id": "CVE-2099-5000", "published": 5})]),
    );
    let a = sync_job(&py, &[SRC], &text_number, json!({})).await;
    let b = sync_job(&rs, &[SRC], &text_number, json!({})).await;
    assert_eq!(status(&a), "ok", "{a:#}");
    assert_eq!(status(&b), "error", "{b:#}");
    assert_eq!(
        entry_of(&b)["message"],
        "nvd: CVE-2099-5000: published is not a string"
    );
    d.close().await;
}

/// A canned answer: status, headers, body.
type Answer = (u16, Vec<(&'static str, String)>, Vec<u8>);

/// A local HTTP server answering each connection with the next answer of `script`, then with an empty page; the
/// request lines are recorded.
async fn serve_script(script: Vec<Answer>) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let log = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = log.clone();
    let empty = serde_json::to_vec(&page(&[])).unwrap();
    tokio::spawn(async move {
        let mut script = script.into_iter();
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let mut buf = vec![0u8; 16384];
            let mut n = 0;
            while n < buf.len() {
                let k = s.read(&mut buf[n..]).await.unwrap_or(0);
                n += k;
                if k == 0 || buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&buf[..n]).into_owned();
            seen.lock()
                .unwrap()
                .push(head.lines().next().unwrap_or("").to_owned());
            let (status, headers, body) = script.next().unwrap_or((200, Vec::new(), empty.clone()));
            let extra: String = headers
                .iter()
                .map(|(k, v)| format!("{k}: {v}\r\n"))
                .collect();
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes()).await;
            let _ = s.write_all(&body).await;
            let _ = s.shutdown().await;
        }
    });
    (format!("http://{addr}"), log)
}

/// One API step of the API differential test: the script, the run's "now", the sync options, and whether the
/// messages are worded alike (HTTP errors are not: httpx's text there, `HTTP <code> for <url>` here).
struct ApiStep {
    what: &'static str,
    script: Vec<Answer>,
    now: &'static str,
    extra: Value,
    status: &'static str,
    same_message: bool,
}

#[tokio::test(flavor = "multi_thread")]
async fn native_nvd_api_matches_py_sources() {
    // review W10.3 M2: the API path of both versions against the same scripted local server. `py-sources` runs the
    // unchanged nvd source with the test-only hook `SECMONK_TEST_NVD_HOOK` (rust/python sources/sync.py: the API URL,
    // no-op sleeps, a fixed "now"); the native importer gets the same URL and "now" and short delays. The scenarios
    // follow tests/sources/test_review_fixes.py (test_nvd_retries_throttling_with_retry_after,
    // test_nvd_gives_up_after_max_retries, test_nvd_partial_failure_keeps_completed_windows,
    // test_nvd_since_accepts_year_and_never_skips_a_gap, test_nvd_limit_is_honored) and compare every mirror table,
    // the entries and the request lines.
    let fx = fixture();
    let Some(mut d) = Diff::new(&[&fx]).await else {
        return;
    };
    let python = d.python.clone();
    let dir = tempfile::tempdir().unwrap();
    let hook = dir.path().join("nvd-hook.json");
    let (py_store, rs_store) = (d.store("py").await, d.store("rs").await);
    let (py_src, _) =
        d.py_sources_env(&py_store, "modules-py", &[("SECMONK_TEST_NVD_HOOK", &hook)]);
    let py = d.engine(&py_store, vec![py_src]);
    let fast = secmonk_sources::nvd::Timing {
        pause_with_key: Duration::ZERO,
        pause_without_key: Duration::ZERO,
        backoff_base: Duration::from_millis(1),
        backoff_max: Duration::from_millis(5),
        retries: 5,
        request_total: Duration::from_secs(30),
    };
    let c = |id: &str| {
        cve(
            id,
            "2026-01-05T00:00:00.000",
            7.5,
            json!([m(
                &format!("cpe:2.3:a:acme:{}:*:*:*:*:*:*:*:*", id.to_lowercase()),
                json!({"versionEndExcluding": "2", "matchCriteriaId": id})
            )]),
        )
    };
    let ok = |cves: &[Value], total: usize| -> Answer {
        let mut p = page(cves);
        p["totalResults"] = json!(total);
        (200, Vec::new(), serde_json::to_vec(&p).unwrap())
    };
    let status = |code: u16| -> Answer { (code, Vec::new(), b"{}".to_vec()) };
    let mut bad_total = page(&[c("CVE-2097-0009")]);
    bad_total["totalResults"] = json!("many");
    let steps = vec![
        ApiStep {
            what: "full pull over two pages",
            now: "2026-01-10T00:00:00Z",
            extra: json!({}),
            status: "ok",
            same_message: true,
            script: vec![
                ok(&[c("CVE-2097-0001"), c("CVE-2097-0002")], 3),
                ok(&[c("CVE-2097-0003")], 3),
            ],
        },
        ApiStep {
            what: "retries: 429 with Retry-After, 503, 403",
            now: "2026-02-01T00:00:00Z",
            extra: json!({}),
            status: "ok",
            same_message: true,
            script: vec![
                (429, vec![("Retry-After", "7".into())], Vec::new()),
                status(503),
                status(403),
                ok(&[c("CVE-2097-0004")], 1),
            ],
        },
        ApiStep {
            what: "a failing third window keeps the completed ones",
            now: "2026-11-01T00:00:00Z",
            extra: json!({}),
            status: "partial",
            same_message: false,
            script: vec![
                ok(&[c("CVE-2097-0005")], 1),
                ok(&[c("CVE-2097-0006")], 1),
                status(503),
                status(503),
                status(503),
                status(503),
                status(503),
                status(503),
            ],
        },
        ApiStep {
            what: "the next run resumes after the completed windows",
            now: "2026-11-01T00:00:00Z",
            extra: json!({}),
            status: "ok",
            same_message: true,
            script: vec![],
        },
        ApiStep {
            what: "an uncaught error in the second window",
            now: "2027-06-01T00:00:00Z",
            extra: json!({}),
            status: "error",
            same_message: true,
            script: vec![
                ok(&[c("CVE-2097-0007")], 1),
                (200, Vec::new(), serde_json::to_vec(&bad_total).unwrap()),
            ],
        },
        ApiStep {
            what: "--since after the stored cursor",
            now: "2027-06-01T00:00:00Z",
            extra: json!({"since": "2027-05-01T00:00:00Z"}),
            status: "ok",
            same_message: true,
            script: vec![],
        },
        ApiStep {
            what: "--since before the stored cursor",
            now: "2027-06-01T00:00:00Z",
            extra: json!({"since": "2026"}),
            status: "ok",
            same_message: true,
            script: vec![ok(&[c("CVE-2097-0001")], 1)],
        },
        ApiStep {
            what: "a full pull with a limit",
            now: "2027-06-01T00:00:00Z",
            extra: json!({"full": true, "limit": 2}),
            status: "partial",
            same_message: true,
            script: vec![ok(
                &[c("CVE-2097-0010"), c("CVE-2097-0011"), c("CVE-2097-0012")],
                3,
            )],
        },
        ApiStep {
            what: "retries used up",
            now: "2027-06-01T00:00:00Z",
            extra: json!({"full": true}),
            status: "error",
            same_message: false,
            script: (0..6).map(|_| status(503)).collect(),
        },
    ];
    for step in steps {
        let (py_url, py_log) = serve_script(step.script.clone()).await;
        std::fs::write(
            &hook,
            serde_json::to_vec(
                &json!({"api_url": format!("{py_url}/rest/json/cves/2.0"), "now": step.now}),
            )
            .unwrap(),
        )
        .unwrap();
        let a = api_job(&py, &step.extra).await;
        let (rs_url, rs_log) = serve_script(step.script).await;
        let native = secmonk_sources::nvd::NvdSource::new(Diff::view(&rs_store))
            .with_api_url(&format!("{rs_url}/rest/json/cves/2.0"))
            .with_timing(fast)
            .with_now(step.now);
        let rs = d.engine(&rs_store, vec![Arc::new(native)]);
        let b = api_job(&rs, &step.extra).await;
        let what = step.what;
        assert_eq!(entry_of(&b)["status"], step.status, "{what}: {b:#}");
        assert_eq!(
            entry_of(&a)["status"],
            entry_of(&b)["status"],
            "{what}: {a:#}"
        );
        assert_eq!(entry_of(&a)["records"], entry_of(&b)["records"], "{what}");
        if step.same_message {
            assert_eq!(entry_of(&a)["message"], entry_of(&b)["message"], "{what}");
        }
        let lines = py_log.lock().unwrap().clone();
        assert!(
            !lines.is_empty(),
            "{what}: the Python source reached the local server"
        );
        assert_eq!(lines, *rs_log.lock().unwrap(), "{what}: request lines");
        eprintln!(
            "{what}: {} requests, {}",
            lines.len(),
            entry_of(&b)["message"]
        );
        let mut ignore = TIMESTAMPS.to_vec();
        if !step.same_message {
            ignore.push("source_sync.message");
        }
        assert_mirrors_equal(
            &python,
            py_store.mirror_path(),
            rs_store.mirror_path(),
            what,
            &ignore,
            &[],
        );
        if what == "a failing third window keeps the completed ones" {
            let progress = rs_store
                .rows_page(
                    secmonk_model::MirrorTable::SourceSync,
                    "nvd:progress",
                    None,
                    1,
                )
                .await
                .unwrap();
            let main = rs_store
                .rows_page(secmonk_model::MirrorTable::SourceSync, "nvd", None, 1)
                .await
                .unwrap();
            assert_eq!(
                progress.0[0]["cursor"], main.0[0]["cursor"],
                "progress == res.cursor"
            );
        }
    }
    let n = py_store
        .count_rows(secmonk_model::MirrorTable::Vulnerability, SRC)
        .await
        .unwrap();
    assert_eq!(n, 10, "the Python side wrote what the local server sent");
    d.close().await;
}

/// One sync job of nvd without `--path` (the API path), with the plan keys in `extra`.
async fn api_job(engine: &SecmonkEngine, extra: &Value) -> Value {
    let mut b = json!({"kind": "sync", "sources": [SRC]});
    for (k, v) in extra.as_object().unwrap() {
        b[k] = v.clone();
    }
    let started = engine
        .job_start(b.as_object().cloned().unwrap())
        .await
        .unwrap();
    wait_job_secs(engine, started["id"].as_u64().unwrap(), 120).await
}

/// A local HTTP server answering each connection with the next body (status 200), recording nothing.
async fn serve(bodies: Vec<Vec<u8>>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        for body in bodies {
            let (mut s, _) = l.accept().await.unwrap();
            let mut buf = [0u8; 8192];
            let _ = s.read(&mut buf).await;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(head.as_bytes()).await;
            let _ = s.write_all(&body).await;
            let _ = s.shutdown().await;
        }
    });
    format!("http://{addr}")
}

#[tokio::test(flavor = "multi_thread")]
async fn native_nvd_batches_follow_the_row_contract() {
    // every native nvd batch and end validates against rust/contracts (source/rows, source/sync-end); applied to a
    // real store, none skipped; affected deletes keyed by the record and nvd:progress rows among them
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(
        &dir.path().join("state.sqlite3"),
        &dir.path().join("mirror.sqlite3"),
        &StoreOptions::default(),
    )
    .await
    .unwrap();
    let small = secmonk_sources::batch::Limits {
        ops: 4,
        bytes: 1 << 20,
    };
    let src = secmonk_sources::nvd::NvdSource::new(Diff::view(&store)).with_limits(small);
    let path = |p: &Path| json!({"path": p.display().to_string()});
    let (u1, u2) = (update1(dir.path()), update2(dir.path()));
    let missing = dir.path().join("missing.json");
    let deletes = check_row_contract(
        &src,
        &store,
        SRC,
        &[
            path(&fixture()),
            path(&u1),
            path(&u2),
            json!({"path": u1.display().to_string(), "limit": 1}),
            path(&missing),
        ],
    )
    .await;
    assert!(deletes >= 3, "affected deletes: {deletes}");

    // an API delta of two windows from the stored cursor (`nvd:progress` rows), against a local server
    let fast = secmonk_sources::nvd::Timing {
        pause_with_key: Duration::ZERO,
        pause_without_key: Duration::ZERO,
        backoff_base: Duration::from_millis(1),
        backoff_max: Duration::from_millis(10),
        retries: 0,
        request_total: Duration::from_secs(30),
    };
    let cursor = secmonk_model::RowsBatch {
        kind: "rows".into(),
        seq: 1_000,
        source: SRC.into(),
        ops: vec![secmonk_model::RowOp::Upsert {
            table: secmonk_model::MirrorTable::SourceSync,
            row: json!({"source": "nvd", "cursor": "2026-01-01T00:00:00.000Z", "status": "ok"})
                .as_object()
                .unwrap()
                .clone(),
        }],
        generation: Some(secmonk_traits::NATIVE_GENERATION.into()),
        acked_through: None,
    };
    assert!(!store.apply_rows(&cursor).await.unwrap().skipped);
    let one = page(&[cve(
        "CVE-2099-6000",
        "2026-03-01T00:00:00.000",
        5.0,
        json!([m(
            "cpe:2.3:a:x:y:*:*:*:*:*:*:*:*",
            json!({"matchCriteriaId": "Z"})
        )]),
    )]);
    let url = serve(vec![
        serde_json::to_vec(&one).unwrap(),
        serde_json::to_vec(&page(&[])).unwrap(),
    ])
    .await;
    let api = secmonk_sources::nvd::NvdSource::new(Diff::view(&store))
        .with_limits(small)
        .with_timing(fast)
        .with_api_url(&url)
        .with_now("2026-06-15T00:00:00Z");
    check_row_contract(&api, &store, SRC, &[json!({})]).await;
    let page = store
        .rows_page(
            secmonk_model::MirrorTable::SourceSync,
            "nvd:progress",
            None,
            10,
        )
        .await
        .unwrap();
    assert_eq!(page.0.len(), 1);
    assert_eq!(page.0[0]["cursor"], "2026-06-15T00:00:00.000Z");
    store.close().await;
}

// ------------------------------------------------------------------------------------------------ volume

/// A synthetic NVD corpus in the API's page layout: `n` CVEs in pages of 2000, each with 1-6 cpeMatch entries (ranges,
/// exact versions, an update field, a non-vulnerable platform), CVSS 3.1 Primary and 4.0 Secondary metrics, CWEs,
/// descriptions and references (about 3 KiB per CVE). `changed`: every third CVE gets another configuration and
/// lastModified, every 50th is rejected.
fn corpus(dir: &Path, n: usize, changed: bool) -> u64 {
    let mut rows = 0u64;
    for (p, start) in (0..n).step_by(2000).enumerate() {
        let cves: Vec<Value> = (start..(start + 2000).min(n))
            .map(|i| {
                let bump = changed && i % 3 == 0;
                let k = 1 + i % 6;
                let mut ms: Vec<Value> = (0..k)
                    .map(|j| {
                        let fixed = format!("{}.{}.{}", j + 1, i % 17, if bump { 9 } else { 1 });
                        match j % 3 {
                            0 => m(&format!("cpe:2.3:a:vendor{}:product{}_{j}:*:*:*:*:*:*:*:*", i % 997, i % 4999),
                                   json!({"versionStartIncluding": "1.0", "versionEndExcluding": fixed, "matchCriteriaId": format!("{i:08}-{j}")})),
                            1 => m(&format!("cpe:2.3:a:vendor{}:product{}_{j}:{fixed}:*:*:*:*:*:*:*", i % 997, i % 4999),
                                   json!({"matchCriteriaId": format!("{i:08}-{j}")})),
                            _ => m(&format!("cpe:2.3:a:vendor{}:tool{}:2.0:rc{j}:*:*:*:*:*:*", i % 997, i % 101),
                                   json!({"matchCriteriaId": format!("{i:08}-{j}")})),
                        }
                    })
                    .collect();
                ms.push(json!({"vulnerable": false, "criteria": "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", "matchCriteriaId": "W"}));
                let id = format!("CVE-2090-{i:06}");
                let mut c = cve(&id, if bump { "2026-11-12T00:00:00.000" } else { "2026-11-11T00:00:00.000" }, (i % 100) as f64 / 10.0, Value::Array(ms));
                c["metrics"]["cvssMetricV40"] = json!([{"source": "cna@example.org", "type": "Secondary",
                    "cvssData": {"version": "4.0", "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "baseScore": 9.3, "baseSeverity": "CRITICAL"}}]);
                c["descriptions"][1]["value"] = json!(format!("{id}: a synthetic description of a vulnerability in vendor{} product{} that allows a remote attacker to do something unexpected via a crafted request, long enough to look like a real one.", i % 997, i % 4999));
                if changed && i % 50 == 0 {
                    c["vulnStatus"] = json!("Rejected");
                } else {
                    rows += k as u64;
                }
                c
            })
            .collect();
        write(dir, &format!("page-{p:04}.json"), &page(&cves));
    }
    rows
}

struct Volume {
    d: Diff,
    day1: PathBuf,
    day2: PathBuf,
    rows1: u64,
    _dir: tempfile::TempDir,
}

async fn volume() -> Option<Volume> {
    let n: usize = std::env::var("SECMONK_NVD_CVES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let d = Diff::new(&[]).await?;
    let dir = tempfile::tempdir().unwrap();
    let (day1, day2) = (dir.path().join("day1"), dir.path().join("day2"));
    std::fs::create_dir_all(&day1).unwrap();
    std::fs::create_dir_all(&day2).unwrap();
    let t = std::time::Instant::now();
    let rows1 = corpus(&day1, n, false);
    corpus(&day2, n, true);
    let size: u64 = std::fs::read_dir(&day1)
        .unwrap()
        .flatten()
        .map(|e| e.metadata().unwrap().len())
        .sum();
    eprintln!(
        "nvd volume: {n} CVEs, {rows1} affected rows, {} MiB per day, generated in {:.1} s",
        size >> 20,
        t.elapsed().as_secs_f64()
    );
    Some(Volume {
        d,
        day1,
        day2,
        rows1,
        _dir: dir,
    })
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "volume measurement, run by hand (source-nvd.md)"]
async fn nvd_volume_baseline() {
    let Some(mut v) = volume().await else { return };
    let _store = v.d.store("baseline").await;
    v.d.close().await;
}

/// A view that counts the `rows_by_id` reads and the time spent in them (volume measurement).
struct TimedView {
    inner: Arc<dyn secmonk_traits::MirrorView>,
    nanos: std::sync::atomic::AtomicU64,
    calls: std::sync::atomic::AtomicU64,
}

#[async_trait]
impl secmonk_traits::MirrorView for TimedView {
    async fn applied(&self, s: &str) -> StepResult<Option<secmonk_traits::AppliedMark>> {
        self.inner.applied(s).await
    }
    async fn count_rows(&self, t: secmonk_model::MirrorTable, s: &str) -> StepResult<u64> {
        self.inner.count_rows(t, s).await
    }
    async fn row_keys(
        &self,
        t: secmonk_model::MirrorTable,
        s: &str,
    ) -> StepResult<Vec<secmonk_model::JsonMap>> {
        self.inner.row_keys(t, s).await
    }
    async fn rows_by_id(
        &self,
        t: secmonk_model::MirrorTable,
        s: &str,
        ids: &[String],
    ) -> StepResult<Vec<secmonk_model::JsonMap>> {
        let t0 = std::time::Instant::now();
        let r = self.inner.rows_by_id(t, s, ids).await;
        self.nanos.fetch_add(
            t0.elapsed().as_nanos() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        r
    }
    async fn rows_page(
        &self,
        t: secmonk_model::MirrorTable,
        s: &str,
        after: Option<u64>,
        limit: usize,
    ) -> StepResult<secmonk_traits::RowPage> {
        self.inner.rows_page(t, s, after, limit).await
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "volume measurement, run by hand (source-nvd.md)"]
async fn nvd_volume_native_stream() {
    // the importer alone: read, split, check, plan and cut every batch against an empty mirror, nothing applied
    let Some(mut v) = volume().await else { return };
    let store = v.d.store("scratch").await;
    let view = Arc::new(TimedView {
        inner: Diff::view(&store),
        nanos: Default::default(),
        calls: Default::default(),
    });
    let src = secmonk_sources::nvd::NvdSource::new(view.clone());
    let t = std::time::Instant::now();
    let params: secmonk_traits::SyncParams = serde_json::from_value(
        json!({"source": SRC, "options": {"path": v.day1.display().to_string()}}),
    )
    .unwrap();
    let mut stream = src.sync(params, CallCtx::default()).await.unwrap();
    let (mut batches, mut first_at, mut ops) = (0u64, 0.0, 0u64);
    while let Some(m) = futures_util::StreamExt::next(&mut stream).await {
        if let secmonk_traits::StreamMsg::Item(b) = m.unwrap() {
            batches += 1;
            ops += b.ops.len() as u64;
            if batches == 1 {
                first_at = t.elapsed().as_secs_f64();
            }
        }
    }
    use std::sync::atomic::Ordering::Relaxed;
    eprintln!(
        "nvd volume: native stream: first batch after {first_at:.2} s, all {batches} batches ({ops} ops) built in {:.2} s \
         ({} rows_by_id reads, {:.2} s in them)",
        t.elapsed().as_secs_f64(),
        view.calls.load(Relaxed),
        view.nanos.load(Relaxed) as f64 / 1e9
    );
    v.d.close().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "volume measurement, run by hand (source-nvd.md)"]
async fn nvd_volume_sync() {
    let Some(mut v) = volume().await else { return };
    let native_only = std::env::var("SECMONK_NVD_NATIVE_ONLY").is_ok_and(|x| x == "1");
    let py_only = std::env::var("SECMONK_NVD_PY_ONLY").is_ok_and(|x| x == "1");
    let mut timed = Vec::new();
    let steps = [
        ("first sync", v.day1.clone()),
        ("re-sync, changed", v.day2.clone()),
        ("re-sync, unchanged", v.day2.clone()),
    ];
    let rs_store = v.d.store("rs").await;
    if !py_only {
        let rs = v.d.engine(&rs_store, vec![native(&rs_store)]);
        for (what, p) in &steps {
            let t = std::time::Instant::now();
            let job = sync_job_secs(&rs, &[SRC], p, json!({}), 3600).await;
            assert_eq!(entry_of(&job)["status"], "ok", "{job:#}");
            timed.push(format!("native {what}: {:.1} s", t.elapsed().as_secs_f64()));
            if *what == "first sync" {
                let n = rs_store
                    .count_rows(secmonk_model::MirrorTable::Affected, SRC)
                    .await
                    .unwrap();
                assert_eq!(n, v.rows1);
            }
        }
    }
    if !native_only {
        let py_store = v.d.store("py").await;
        let (py_src, _) = v.d.py_sources(&py_store, "modules-py");
        let py = v.d.engine(&py_store, vec![py_src]);
        for (what, p) in &steps {
            let t = std::time::Instant::now();
            let job = sync_job_secs(&py, &[SRC], p, json!({}), 7200).await;
            assert_eq!(entry_of(&job)["status"], "ok", "{job:#}");
            timed.push(format!(
                "py-sources {what}: {:.1} s",
                t.elapsed().as_secs_f64()
            ));
        }
        if !py_only {
            assert_mirrors_equal(
                &v.d.python,
                py_store.mirror_path(),
                rs_store.mirror_path(),
                "volume",
                TIMESTAMPS,
                &[],
            );
        }
    }
    eprintln!("nvd volume: {}", timed.join("; "));
    v.d.close().await;
}
