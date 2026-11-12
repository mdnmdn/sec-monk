//! Differential test of the native cvelist importer against `py-sources` (stage 6, rust ADR-0011 / ADR-0012): both
//! through the engine on their own mirrors. `--path`: the fixture directory (first sync, re-sync, `--full` with a
//! limit), synthetic variants (an update, a rejection, every version and CPE shape, ADP data, duplicates in walk
//! order, per-record errors, files that are not records); the git mode against a local repository built at test time
//! (first clone, unchanged re-sync, a commit with an update, a new record, a deleted file, a rejection and a record
//! error, the fix, `--since`, a limit, `--full`, an unreachable origin); then a mirror that switches between the two
//! implementations; the row-contract check of the native batches; and the volume measurement (ignored, run by hand).
//! Harness: `common/`. Doc: rust/_docs/tech/source-cvelist.md. Fixtures: `tests/fixtures/sources/cvelist` (real
//! records, read only); everything else is written at test time (synthetic).
//!
//! `py-sources` runs the unchanged Python source. Its git URL is fixed (`REPO_URL`, GitHub), so the test points git at
//! the local repository with `GIT_CONFIG_PARAMETERS` (`url.<local>.insteadOf=<REPO_URL>`, read by git itself; the
//! Python source passes that variable through), and gives each `py-sources` its own `SECMONK_CACHE`. Nothing reaches
//! the network. The host never passes either variable to a module; only this test's runtime adds them.

mod common;

use common::*;

const SRC: &str = "cvelist";
const TIMESTAMPS: &[&str] = &["raw_record.fetched_at", "source_sync.last_sync"];
const TABLES: &[&str] = &["raw_record", "vulnerability", "affected", "source_sync"];

fn fixtures() -> PathBuf {
    rust_root().join("../tests/fixtures/sources/cvelist")
}

fn year() -> i64 {
    secmonk_model::time::now_iso()[..4].parse().unwrap()
}

fn have_git() -> bool {
    if std::process::Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        return true;
    }
    assert!(
        std::env::var("SECMONK_REQUIRE_VENV").as_deref() != Ok("1"),
        "SECMONK_REQUIRE_VENV=1 but git does not run (the cvelist differential test needs it)"
    );
    eprintln!("git not found: cvelist differential test skipped");
    false
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .args([
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "user.name=t",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(cwd)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn write(dir: &Path, rel: &str, doc: &Value) -> PathBuf {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, serde_json::to_vec_pretty(doc).unwrap()).unwrap();
    p
}

fn load(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(fixtures().join(name)).unwrap()).unwrap()
}

/// A synthetic record with one CNA `affected` entry.
fn rec(id: &str, updated: &str, desc: &str, versions: Value) -> Value {
    json!({"dataType": "CVE_RECORD", "dataVersion": "5.1",
           "cveMetadata": {"cveId": id, "state": "PUBLISHED", "dateUpdated": updated,
                           "datePublished": "2026-01-01T00:00:00.000Z", "assignerShortName": "acme"},
           "containers": {"cna": {"descriptions": [{"lang": "en", "value": desc}],
                                  "affected": [{"vendor": "Acme_Corp", "product": "Widget", "versions": versions}]}}})
}

/// A record of every version, package and CPE shape the importer converts, with ADP containers.
fn shapes(id: &str, updated: &str) -> Value {
    let versions = json!([
        {"version": "< 2.5.4", "status": "affected"}, {"version": ">= 1.0, <= 1.2", "status": "affected"},
        {"version": "3.0.0 - 3.0.3", "status": "affected"}, {"version": "prior to 4.5", "status": "affected"},
        {"version": "1.0 or later", "status": "affected"}, {"version": "2.3 and earlier", "status": "affected"},
        {"version": "some text", "status": "affected"}, {"version": "n/a", "status": "affected"},
        {"version": "unspecified", "lessThan": "2.0", "status": "affected"},
        {"version": "0", "lessThanOrEqual": "*", "status": "affected"},
        {"version": "1.0", "lessThan": "1.0", "status": "affected", "versionType": "Custom"},
        {"version": "abcdef1234567", "lessThan": "1234567abcdef0", "status": "affected"},
        {"version": "1.0", "versionType": "git", "status": "affected"},
        {"version": "1.0", "status": "unknown"}, {"version": "9.0", "status": "unaffected"},
        {"version": "1.0", "status": "affected", "changes": [{"at": "1.1", "status": "unaffected"}]},
        {"version": "1.0", "status": "affected", "changes": [{"at": "x y", "status": "unaffected"}]},
        {"version": "text", "lessThan": "2.0", "status": "affected", "changes": [{"at": "1.5", "status": "affected"}]},
        {"version": 5, "status": "affected"}, {"version": true, "lessThan": 3, "status": "affected"},
        {"version": "1.0", "lessThan": "2.0", "status": "affected", "changes": [
            {"at": "1.2-rc1", "status": "unaffected"}, {"at": "1.2", "status": "affected"},
            {"at": "1.10", "status": "unaffected"}, {"at": "2.5", "status": "affected"}]},
        {"version": "2.0", "lessThan": "*", "status": "affected", "changes": [{"at": "2.4.58", "status": "unaffected"}]},
        {"version": "1.0", "lessThan": "2.*", "status": "affected"},
        {"version": "1.0", "lessThan": "", "status": "affected"},
        {"version": "", "status": "affected"}, {"version": "*"},
        "a string", null, 3
    ]);
    json!({"dataType": "CVE_RECORD", "dataVersion": "5.2",
    "cveMetadata": {"cveId": id, "state": "PUBLISHED", "dateUpdated": updated, "datePublished": "2026-01-02",
                    "assignerShortName": "shapes"},
    "containers": {
        "cna": {
            "title": "Every shape",
            "descriptions": [{"lang": "fr", "value": "x"}, {"lang": "EN-us", "value": "English"}, 5],
            "references": [{"url": "https://a.example/1"}, {"url": "https://a.example/1"}, {"name": "no url"}],
            "affected": [
                {"vendor": "Acme", "product": "Everything", "defaultStatus": "unknown", "versions": versions,
                 "platforms": ["Linux"], "cpes": ["cpe:2.3:a:acme:everything:*:*:*:*:*:*:*:*"]},
                {"packageName": "Zope.Interface", "collectionURL": "https://pypi.org/project/zope.interface",
                 "versions": [{"version": "1.0", "status": "affected"}]},
                {"packageName": "Form_Data", "collectionURL": "registry.npmjs.org/form-data",
                 "versions": [{"version": "0", "lessThan": "2.5.4", "status": "affected"}]},
                {"packageName": "org.apache:Log4j", "collectionURL": "https://user:pw@repo1.maven.org:443/maven2",
                 "versions": [{"version": "2.0", "lessThan": "2.17", "status": "affected"}]},
                {"packageName": "  ", "vendor": "n/a", "product": "Thing",
                 "versions": [{"version": "1", "status": "affected"}]},
                {"packageName": "mystery", "collectionURL": "https://example.org/x",
                 "versions": [{"version": "1", "status": "affected"}]},
                {"vendor": "N/A", "product": "n/a", "versions": [{"version": "1"}]},
                {"vendor": "Mozilla", "product": "Firefox", "versions": [
                    {"version": "128.0", "lessThanOrEqual": "128.*", "status": "unaffected", "versionType": "rpm"},
                    {"version": "135", "status": "unaffected"}]},
                {"vendor": "acme", "product": "statement", "defaultStatus": "Affected"},
                {"vendor": "acme", "product": "no versions"},
                "not a dict"
            ],
            "cpeApplicability": [{"nodes": [
                {"operator": "OR", "children": [{"cpeMatch": [
                    {"vulnerable": true, "criteria": "cpe:2.3:a:acme:child:*:*:*:*:*:*:*:*",
                     "versionEndIncluding": "3.0", "matchCriteriaId": 7}]}],
                 "cpeMatch": [
                    {"vulnerable": true, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                     "versionStartIncluding": "1.0", "versionStartExcluding": "0.9",
                     "versionEndExcluding": "2.0", "versionEndIncluding": "2.1", "matchCriteriaId": "A"},
                    {"vulnerable": true, "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                     "versionEndExcluding": "9.9", "matchCriteriaId": "A"},
                    {"vulnerable": true, "criteria": "cpe:2.3:a:acme:dup:*:*:*:*:*:*:*:*", "matchCriteriaId": 7.0},
                    {"vulnerable": false, "criteria": "cpe:2.3:o:acme:os:-:*:*:*:*:*:*:*"},
                    {"vulnerable": true},
                    {"vulnerable": true, "criteria": "x:y"},
                    {"vulnerable": true, "criteria": "cpe:2.3:a:acme:exact:4.2:*:*:*:*:*:*:*"},
                    {"vulnerable": true, "criteria": "cpe:2.3:a:acme:dash:-:*:*:*:*:*:*:*"},
                    {"vulnerable": true, "criteria": "cpe:2.3:a:acme:beta:1.0:beta:*:*:*:*:*:*"},
                    {"vulnerable": true, "criteria": "cpe:2.3:a:acme:url:*:*:*:*:*:*:*:*",
                     "versionStartIncluding": "16.0", "versionEndExcluding": "https://aka.ms/x"},
                    {"vulnerable": 0, "criteria": "cpe:2.3:a:acme:zero:*:*:*:*:*:*:*:*",
                     "versionStartExcluding": "1"}
                 ]}
            ]}]
        },
        "adp": [
            {"providerMetadata": {"shortName": "CISA-ADP"}, "title": "CISA ADP Vulnrichment",
             "metrics": [
                {"cvssV3_1": {"baseScore": 7.5, "version": "3.1", "vectorString": "CVSS:3.1/AV:N",
                              "baseSeverity": "HIGH"}},
                {"other": {"type": "ssvc", "content": {"id": id, "role": "CISA Coordinator", "version": "2.0.3",
                    "timestamp": "2026-01-01T00:00:00+00:00",
                    "options": [{"Exploitation": "active"}, {"Automatable": "yes"}, "x",
                                {"Technical Impact": "total"}]}}},
                {"other": {"type": "kev", "content": {"dateAdded": "2026-01-01", "reference": "https://k"}}}],
             "problemTypes": [{"descriptions": [{"cweId": "CWE-79"}, {"cweId": "CWE-79"}, {"type": "text"}]}],
             "references": [{"url": "https://a.example/1"}, {"url": "https://adp.example/2"}]},
            {"providerMetadata": {"shortName": "siemens-SADP"},
             "affected": [{"vendor": "Siemens", "product": "SIMATIC", "versions": [
                {"version": "0", "lessThan": "V3.0 SP1", "status": "affected"}]}]},
            "not a dict"
        ]
    }})
}

/// The variant directory: an update, a rejection, the shapes record, duplicates, record errors, non-records.
fn variants(dir: &Path) -> PathBuf {
    let v = dir.join("variants");
    // Log4Shell updated: one affected entry less, a CNA CVSS 4.0 metric
    let mut log4j = load("CVE-2021-44228.json");
    log4j["cveMetadata"]["dateUpdated"] = json!("2026-10-01T00:00:00.000Z");
    log4j["containers"]["cna"]["affected"]
        .as_array_mut()
        .unwrap()
        .truncate(1);
    log4j["containers"]["cna"]["metrics"] = json!([{"cvssV4_0": {"baseScore": 9.3, "version": "4.0",
        "vectorString": "CVSS:4.0/AV:N", "baseSeverity": "CRITICAL"}}, {"cvssV3_1": {"baseScore": 10, "version": "3.1"}}]);
    write(&v, "2021/44xxx/CVE-2021-44228.json", &log4j);
    // Chrome rejected
    let mut chrome = load("CVE-2025-1914.json");
    chrome["cveMetadata"]["state"] = json!("REJECTED");
    chrome["cveMetadata"]["dateUpdated"] = json!("2026-10-01T00:00:00.000Z");
    chrome["cveMetadata"]["dateRejected"] = json!("2026-10-01T00:00:00.000Z");
    chrome["containers"]["cna"]["rejectedReasons"] = json!([{"lang": "en", "value": "Duplicate."}]);
    write(&v, "2025/1xxx/CVE-2025-1914.json", &chrome);
    write(
        &v,
        "2099/0xxx/CVE-2099-0001.json",
        &shapes("CVE-2099-0001", "2026-01-01T00:00:00.000Z"),
    );
    // the same id in `a`, `a-b`, `a.b`: Python sorts paths by component (`a/` first: March, then nothing newer, one
    // record); sorted as text (`a-b/` < `a.b/` < `a/`) all three would be newer in turn
    write(
        &v,
        "dup/a/CVE-2099-0100.json",
        &rec(
            "CVE-2099-0100",
            "2026-03-01T00:00:00.000Z",
            "mar",
            json!([{"version": "1"}]),
        ),
    );
    write(
        &v,
        "dup/a-b/CVE-2099-0100.json",
        &rec(
            "CVE-2099-0100",
            "2026-01-01T00:00:00.000Z",
            "jan",
            json!([{"version": "2"}]),
        ),
    );
    write(
        &v,
        "dup/a.b/CVE-2099-0100.json",
        &rec(
            "CVE-2099-0100",
            "2026-02-01T00:00:00.000Z",
            "feb",
            json!([]),
        ),
    );
    // per-record errors (Python raises inside the record's SAVEPOINT)
    let err = |n: u32, f: &dyn Fn(&mut Value)| {
        let id = format!("CVE-2099-1{n:03}");
        let mut r = rec(
            &id,
            "2026-01-01T00:00:00.000Z",
            "err",
            json!([{"version": "1.0"}]),
        );
        f(&mut r);
        write(&v, &format!("errors/{id}.json"), &r);
    };
    err(1, &|r| r["containers"]["cna"]["metrics"] = json!(["junk"]));
    err(2, &|r| {
        r["containers"]["cna"]["metrics"] = json!([{"cvssV3_1": {"baseScore": "n/a"}}])
    });
    err(3, &|r| {
        r["containers"]["cna"]["affected"][0]["vendor"] = json!(5)
    });
    err(4, &|r| r["containers"]["cna"]["affected"] = json!(3));
    err(5, &|r| {
        r["containers"]["cna"]["descriptions"] = json!([]);
        r["containers"]["cna"]["title"] = json!(["x"]);
    });
    err(6, &|r| {
        r["containers"]["adp"] = json!([{"providerMetadata": null}])
    });
    err(7, &|r| {
        r["containers"]["cna"]["cpeApplicability"] = json!([{"nodes": ["x"]}])
    });
    err(
        8,
        &|r| {
            r["containers"]["cna"]["cpeApplicability"] =
                json!([{"nodes": [{"cpeMatch": [{"vulnerable": true, "criteria": 5}]}]}])
        },
    );
    err(9, &|r| {
        r["containers"]["cna"]["cpeApplicability"] = json!([{"nodes": [{"cpeMatch": [
        {"vulnerable": true, "criteria": "cpe:2.3:a:b:c:*", "matchCriteriaId": [1]}]}]}])
    });
    err(10, &|r| {
        r["containers"]["cna"]["affected"][0]["versions"][0]["changes"] = json!(7)
    });
    err(11, &|r| r["containers"]["cna"]["descriptions"] = json!([1]));
    err(12, &|r| r["containers"] = json!("x"));
    err(13, &|r| r["cveMetadata"]["datePublished"] = json!({"a": 1}));
    err(14, &|r| {
        r["containers"]["cna"]["metrics"] = json!([{"cvssV3_1": {"baseScore": [1]}}])
    });
    err(15, &|r| {
        r["containers"]["cna"]["affected"][0]["versions"] = json!([{"version": "1.0", "lessThan": "2.0",
        "changes": [{"at": "1.5", "status": "unaffected"}, {"at": format!("1.{}", "9".repeat(4400)), "status": "x"}]}])
    });
    // not records, unreadable, not walked
    write(&v, "other/CVE-list.json", &json!([1, 2]));
    write(&v, "other/CVE-nometa.json", &json!({"x": 1}));
    write(
        &v,
        "other/CVE-meta-list.json",
        &json!({"cveMetadata": ["x"]}),
    );
    write(
        &v,
        "other/CVE-meta-empty.json",
        &json!({"cveMetadata": {}, "containers": {}}),
    );
    write(
        &v,
        "other/CVE-id-empty.json",
        &json!({"cveMetadata": {"cveId": ""}}),
    );
    std::fs::write(v.join("other/CVE-latin1.json"), b"{\"x\": \"caf\xe9\"}").unwrap();
    std::fs::write(
        v.join("other/CVE-bom.json"),
        b"\xef\xbb\xbf{\"cveMetadata\": {}}",
    )
    .unwrap();
    std::fs::create_dir_all(v.join("other/CVE-dir.json")).unwrap();
    write(
        &v,
        "other/not-cve.json",
        &rec("CVE-2099-0999", "2026-01-01", "not walked", json!([])),
    );
    v
}

/// A local upstream repository (a working tree on `main`, serving partial clones).
struct Origin {
    path: PathBuf,
}

impl Origin {
    fn new(path: PathBuf) -> Origin {
        std::fs::create_dir_all(&path).unwrap();
        git(&path, &["init", "-q", "-b", "main"]);
        git(&path, &["config", "uploadpack.allowFilter", "true"]);
        git(&path, &["config", "uploadpack.allowAnySHA1InWant", "true"]);
        Origin { path }
    }

    fn url(&self) -> String {
        format!("file://{}", self.path.display())
    }

    fn file(id: &str) -> String {
        let mut p = id.split('-');
        let (_, y, n) = (p.next(), p.next().unwrap(), p.next().unwrap());
        format!("cves/{y}/{}xxx/{id}.json", n.parse::<u64>().unwrap() / 1000)
    }

    fn put(&self, doc: &Value) {
        let id = doc["cveMetadata"]["cveId"].as_str().unwrap();
        write(&self.path, &Origin::file(id), doc);
    }

    /// A fixture record under another id (its real content), dated `updated`.
    fn put_fixture(&self, name: &str, id: &str, updated: &str) {
        let mut d = load(name);
        d["cveMetadata"]["cveId"] = json!(id);
        d["cveMetadata"]["dateUpdated"] = json!(updated);
        self.put(&d);
    }

    fn remove(&self, id: &str) {
        std::fs::remove_file(self.path.join(Origin::file(id))).unwrap();
    }

    fn commit(&self) -> String {
        git(&self.path, &["add", "-A"]);
        git(&self.path, &["commit", "-qm", "c", "--allow-empty"]);
        git(&self.path, &["rev-parse", "HEAD"])
    }
}

/// One sync job of cvelist without `path` (the git mode), with the other plan keys in `extra`.
async fn git_job(engine: &SecmonkEngine, extra: Value) -> Value {
    let mut b = json!({"kind": "sync", "sources": [SRC]});
    for (k, v) in extra.as_object().unwrap() {
        b[k] = v.clone();
    }
    let started = engine
        .job_start(b.as_object().cloned().unwrap())
        .await
        .unwrap();
    wait_job_secs(engine, started["id"].as_u64().unwrap(), 300).await
}

/// The environment of a `py-sources`: git redirected to the local origin, its own cache.
fn py_env(dir: &Path, origin: &Origin, name: &str) -> Vec<(String, PathBuf)> {
    vec![
        (
            "GIT_CONFIG_PARAMETERS".into(),
            PathBuf::from(format!(
                "'url.{}.insteadof'='{}'",
                origin.url(),
                secmonk_sources::cvelist::REPO_URL
            )),
        ),
        ("SECMONK_CACHE".into(), dir.join(format!("py-cache-{name}"))),
    ]
}

fn env_refs(v: &[(String, PathBuf)]) -> Vec<(&str, &Path)> {
    v.iter().map(|(k, p)| (k.as_str(), p.as_path())).collect()
}

fn native(store: &SqliteStore, origin: &Origin, cache: &Path) -> Arc<dyn Source> {
    Arc::new(
        secmonk_sources::cvelist::CvelistSource::new(Diff::view(store))
            .with_repo_url(&origin.url())
            .with_cache_dir(cache),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn native_cvelist_matches_py_sources() {
    let fx = fixtures();
    if !have_git() {
        return;
    }
    let Some(mut d) = Diff::new(&[&fx]).await else {
        return;
    };
    let python = d.python.clone();
    let dir = tempfile::tempdir().unwrap();
    let origin = Origin::new(dir.path().join("origin"));
    let (py_store, rs_store, switch_store) = (
        d.store("py").await,
        d.store("rs").await,
        d.store("switch").await,
    );
    let (e1, e2, e3) = (
        py_env(dir.path(), &origin, "py"),
        py_env(dir.path(), &origin, "rs"),
        py_env(dir.path(), &origin, "switch"),
    );
    let (py_src, _) = d.py_sources_env(&py_store, "modules-py", &env_refs(&e1));
    let (rs_py_src, _) = d.py_sources_env(&rs_store, "modules-rs", &env_refs(&e2));
    let (switch_src, switch_staging) =
        d.py_sources_env(&switch_store, "modules-switch", &env_refs(&e3));
    let py = d.engine(&py_store, vec![py_src]);
    let rs = d.engine(
        &rs_store,
        vec![
            native(&rs_store, &origin, &dir.path().join("rs-cache")),
            rs_py_src,
        ],
    );
    let switch_py = d.engine(&switch_store, vec![switch_src.clone()]);
    let switch_rs = d.engine(
        &switch_store,
        vec![
            native(&switch_store, &origin, &dir.path().join("switch-cache")),
            switch_src,
        ],
    );

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
    let count = |table: secmonk_model::MirrorTable| {
        let store = rs_store.clone();
        async move { store.count_rows(table, SRC).await.unwrap() }
    };
    use secmonk_model::MirrorTable as T;
    // py and rs, plus the switch mirror on py-sources (the same history as the py mirror)
    let step = |path: PathBuf, extra: Value, what: &'static str| {
        let (py, rs, sw) = (py.clone(), rs.clone(), switch_py.clone());
        async move {
            let a = sync_job_secs(&py, &[SRC], &path, extra.clone(), 120).await;
            let b = sync_job_secs(&rs, &[SRC], &path, extra.clone(), 120).await;
            check_entries(&a, &b, what);
            sync_job_secs(&sw, &[SRC], &path, extra, 120).await;
            b
        }
    };
    let gstep = |extra: Value, what: &'static str| {
        let (py, rs, sw) = (py.clone(), rs.clone(), switch_py.clone());
        async move {
            let a = git_job(&py, extra.clone()).await;
            let b = git_job(&rs, extra.clone()).await;
            check_entries(&a, &b, what);
            git_job(&sw, extra).await;
            b
        }
    };

    // 1. --path: the fixture directory, again, --full with a limit, one file
    let n = 21;
    let b = step(fx.clone(), json!({}), "fixtures").await;
    assert_eq!(entry_of(&b)["status"], "ok", "{b:#}");
    assert_eq!(entry_of(&b)["records"], n);
    same("fixtures");
    assert_eq!(count(T::Vulnerability).await, n);
    assert!(
        count(T::Affected).await > 50,
        "the comparison is not vacuous"
    );
    let b = step(fx.clone(), json!({}), "fixtures again").await;
    assert_eq!(entry_of(&b)["records"], 0);
    same("fixtures again");
    let b = step(fx.clone(), json!({"full": true, "limit": 3}), "full, limit").await;
    assert_eq!(
        (
            entry_of(&b)["status"].as_str(),
            entry_of(&b)["records"].as_u64()
        ),
        (Some("ok"), Some(3))
    );
    same("full, limit");
    step(
        fx.join("CVE-2025-24077.json"),
        json!({"full": true}),
        "one file",
    )
    .await;
    same("one file");

    // 2. the variants: a limit first (errors before it count), then all of them
    let v = variants(dir.path());
    let b = step(v.clone(), json!({"limit": 2}), "variants, limit").await;
    assert_eq!(entry_of(&b)["records"], 2, "{b:#}");
    same("variants, limit");
    let b = step(v.clone(), json!({}), "variants").await;
    assert_eq!(entry_of(&b)["status"], "partial", "{b:#}");
    same("variants");
    let b = step(v.clone(), json!({"full": true}), "variants, full").await;
    assert_eq!(entry_of(&b)["status"], "partial", "{b:#}");
    same("variants, full");
    assert_eq!(
        rs_store
            .rows_by_id(T::Affected, SRC, &["CVE-2025-1914".to_owned()])
            .await
            .unwrap()
            .len(),
        0,
        "rejected: its rows deleted"
    );

    // 3. the git mode: the first clone (records of both years, a fixture of the shapes per year)
    let y = year();
    let ids: Vec<String> = (0..4).map(|i| format!("CVE-{y}-{}", 7000 + i)).collect();
    for (i, f) in [
        "CVE-2021-44228.json",
        "CVE-2025-24077.json",
        "CVE-2026-19868.json",
        "CVE-2025-48709.json",
    ]
    .iter()
    .enumerate()
    {
        origin.put_fixture(f, &ids[i], "2026-01-01T00:00:00.000Z");
    }
    origin.put_fixture(
        "CVE-2025-7783.json",
        &format!("CVE-{}-7100", y - 1),
        "2026-01-01T00:00:00.000Z",
    );
    origin.put(&shapes(
        &format!("CVE-{}-7101", y - 1),
        "2026-01-01T00:00:00.000Z",
    ));
    origin.put(&rec(
        &format!("CVE-{}-7200", y - 5),
        "2026-01-01T00:00:00.000Z",
        "old year",
        json!([{"version": "1"}]),
    ));
    let c1 = origin.commit();
    let b = gstep(json!({}), "git: first clone").await;
    assert_eq!(entry_of(&b)["status"], "ok", "{b:#}");
    assert_eq!(entry_of(&b)["records"], 6);
    assert_eq!(
        entry_of(&b)["message"],
        format!("git {}, years {}..{y}", &c1[..10], y - 1)
    );
    same("git: first clone");
    let b = gstep(json!({}), "git: unchanged").await;
    assert_eq!(entry_of(&b)["records"], 0);
    same("git: unchanged");

    // a commit: an update, a new record, a deleted file, a rejection, a record error (the cursor stays)
    let mut upd = load("CVE-2021-44228.json");
    upd["cveMetadata"]["cveId"] = json!(ids[0]);
    upd["cveMetadata"]["dateUpdated"] = json!("2026-02-01T00:00:00.000Z");
    upd["containers"]["cna"]["affected"][0]["versions"] =
        json!([{"version": "2.0", "lessThan": "2.17.1"}]);
    origin.put(&upd);
    origin.put(&rec(
        &format!("CVE-{y}-7004"),
        "2026-02-01T00:00:00.000Z",
        "new",
        json!([{"version": "< 3"}]),
    ));
    origin.remove(&ids[3]);
    let mut rej = load("CVE-2025-24077.json");
    rej["cveMetadata"] = json!({"cveId": ids[1], "state": "REJECTED", "dateUpdated": "2026-02-01T00:00:00.000Z",
                                "dateRejected": "2026-02-01T00:00:00.000Z"});
    rej["containers"]["cna"]["rejectedReasons"] = json!([{"lang": "en", "value": "Rejected."}]);
    origin.put(&rej);
    let mut bad = rec(
        &format!("CVE-{y}-7005"),
        "2026-02-01T00:00:00.000Z",
        "bad",
        json!([]),
    );
    bad["containers"]["cna"]["metrics"] = json!(["junk"]);
    origin.put(&bad);
    origin.commit();
    let b = gstep(json!({}), "git: update with a record error").await;
    assert_eq!(entry_of(&b)["status"], "partial", "{b:#}");
    assert_eq!(entry_of(&b)["records"], 3);
    same("git: update with a record error");
    // the fix: the diff from the stored cursor (the first commit) covers both commits
    origin.put(&rec(
        &format!("CVE-{y}-7005"),
        "2026-02-02T00:00:00.000Z",
        "fixed",
        json!([]),
    ));
    let c3 = origin.commit();
    let b = gstep(json!({}), "git: fixed").await;
    assert_eq!(entry_of(&b)["status"], "ok", "{b:#}");
    assert_eq!(entry_of(&b)["records"], 1);
    same("git: fixed");
    let cursor = rs_store
        .rows_page(T::SourceSync, "cvelist:git", None, 1)
        .await
        .unwrap()
        .0[0]["cursor"]
        .clone();
    assert_eq!(cursor, json!(c3));

    // --since widens the years; a plain sync keeps them; a limit; --full
    let b = gstep(json!({"since": format!("{}-01-01", y - 5)}), "git: since").await;
    assert_eq!(entry_of(&b)["records"], 1, "{b:#}");
    same("git: since");
    origin.put(&rec(
        &format!("CVE-{}-7200", y - 5),
        "2026-03-01T00:00:00.000Z",
        "old year v2",
        json!([]),
    ));
    origin.put(&rec(
        &format!("CVE-{y}-7006"),
        "2026-03-01T00:00:00.000Z",
        "x",
        json!([]),
    ));
    origin.commit();
    let b = gstep(json!({"limit": 1}), "git: limit").await;
    assert_eq!(entry_of(&b)["status"], "partial", "{b:#}");
    same("git: limit");
    let b = gstep(json!({}), "git: after the limit").await;
    assert_eq!(entry_of(&b)["status"], "ok", "{b:#}");
    same("git: after the limit");
    let b = gstep(json!({"full": true}), "git: full").await;
    assert_eq!(entry_of(&b)["status"], "ok", "{b:#}");
    same("git: full");

    // an unreachable origin: error, nothing written
    let away = dir.path().join("origin-away");
    std::fs::rename(&origin.path, &away).unwrap();
    let b = gstep(json!({}), "git: unreachable origin").await;
    assert_eq!(entry_of(&b)["status"], "error", "{b:#}");
    assert!(
        entry_of(&b)["message"]
            .as_str()
            .unwrap()
            .starts_with("git failed: ")
    );
    same("git: unreachable origin");
    std::fs::rename(&away, &origin.path).unwrap();

    // 4. the switch mirror: the native importer after py-sources (its own fresh clone; nothing newer)
    origin.put(&rec(
        &format!("CVE-{y}-7007"),
        "2026-04-01T00:00:00.000Z",
        "switch",
        json!([{"version": "1.0", "lessThan": "1.5"}]),
    ));
    origin.put_fixture("CVE-2026-19868.json", &ids[2], "2026-04-01T00:00:00.000Z");
    origin.commit();
    let a = git_job(&py, json!({})).await;
    let b = git_job(&rs, json!({})).await;
    check_entries(&a, &b, "git: before the switch");
    same("git: before the switch");
    let job = git_job(&switch_rs, json!({})).await;
    assert_eq!(entry_of(&job)["status"], "ok", "{job:#}");
    assert!(
        job["log"]
            .to_string()
            .contains("cvelist: native importer: applied state of generation "),
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
            TABLES,
        );
    };
    switch_same("switch from py-sources to the native importer");
    // a native update on the switch mirror
    origin.put(&rec(
        &format!("CVE-{y}-7007"),
        "2026-05-01T00:00:00.000Z",
        "switch v2",
        json!([{"version": "1.0", "lessThan": "1.6"}]),
    ));
    origin.commit();
    let a = git_job(&py, json!({})).await;
    let b = git_job(&rs, json!({})).await;
    check_entries(&a, &b, "git: native update");
    same("git: native update");
    let job = git_job(&switch_rs, json!({})).await;
    assert_eq!(entry_of(&job)["records"], 1, "{job:#}");
    switch_same("a native update on the switch mirror");
    // a failed Python run after the native ones: nothing applied, native state kept
    std::fs::rename(&origin.path, &away).unwrap();
    let job = git_job(&switch_py, json!({})).await;
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
    std::fs::rename(&away, &origin.path).unwrap();
    // back to py-sources: an ok run repairs from the staging export
    let job = git_job(&switch_py, json!({})).await;
    assert_eq!(entry_of(&job)["status"], "ok", "{job:#}");
    assert_mirror_equals_staging(
        &python,
        switch_store.mirror_path(),
        &switch_staging,
        "switch back to py-sources",
    );
    switch_same("switch back to py-sources vs py-sources only");

    // 5. the documented differences (source-cvelist.md); the mirrors differ from here on.
    // a number in a text column: stored as text by Python, the record refused natively
    let num_dir = dir.path().join("diff-number");
    let mut num = rec("CVE-2099-2001", "2026-01-01T00:00:00.000Z", "x", json!([]));
    num["cveMetadata"]["datePublished"] = json!(20260101);
    write(&num_dir, "CVE-2099-2001.json", &num);
    let a = sync_job(&py, &[SRC], &num_dir, json!({})).await;
    let b = sync_job(&rs, &[SRC], &num_dir, json!({})).await;
    assert_eq!(
        (
            entry_of(&a)["status"].as_str(),
            entry_of(&a)["records"].as_u64()
        ),
        (Some("ok"), Some(1)),
        "{a:#}"
    );
    assert_eq!(
        (
            entry_of(&b)["status"].as_str(),
            entry_of(&b)["records"].as_u64()
        ),
        (Some("partial"), Some(0)),
        "{b:#}"
    );
    // a NaN literal: json.loads reads it, but py-sources cannot stream the row (its whole run fails: "result is not
    // JSON"); invalid JSON natively (one record error)
    let nan_dir = dir.path().join("diff-nan");
    std::fs::create_dir_all(&nan_dir).unwrap();
    std::fs::write(
        nan_dir.join("CVE-2099-2002.json"),
        br#"{"cveMetadata": {"cveId": "CVE-2099-2002"}, "containers": {"cna": {"metrics": [{"cvssV3_1": {"baseScore": NaN}}]}}}"#,
    )
    .unwrap();
    let a = sync_job(&py, &[SRC], &nan_dir, json!({})).await;
    let b = sync_job(&rs, &[SRC], &nan_dir, json!({})).await;
    assert_eq!(entry_of(&a)["status"], "error", "{a:#}");
    assert!(
        entry_of(&a)["message"]
            .as_str()
            .unwrap()
            .contains("not JSON"),
        "{a:#}"
    );
    assert_eq!(
        (
            entry_of(&b)["status"].as_str(),
            entry_of(&b)["records"].as_u64()
        ),
        (Some("partial"), Some(0)),
        "{b:#}"
    );
    d.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn native_cvelist_batches_follow_the_row_contract() {
    // every native cvelist batch and end validates against rust/contracts (source/rows, source/sync-end); applied to a
    // real store, none skipped; record-keyed affected deletes (an update, a rejection) and the internal git rows among
    // them
    if !have_git() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(
        &dir.path().join("state.sqlite3"),
        &dir.path().join("mirror.sqlite3"),
        &StoreOptions::default(),
    )
    .await
    .unwrap();
    let origin = Origin::new(dir.path().join("origin"));
    let y = year();
    origin.put_fixture(
        "CVE-2021-44228.json",
        &format!("CVE-{y}-0001"),
        "2026-01-01T00:00:00.000Z",
    );
    origin.commit();
    let src = secmonk_sources::cvelist::CvelistSource::new(Diff::view(&store))
        .with_repo_url(&origin.url())
        .with_cache_dir(&dir.path().join("cache"))
        .with_limits(secmonk_sources::batch::Limits {
            ops: 4,
            bytes: 1 << 20,
        });
    let path = |p: &Path| json!({"path": p.display().to_string()});
    let v = variants(dir.path());
    let fx = fixtures();
    let first = check_row_contract(
        &src,
        &store,
        SRC,
        &[
            path(&fx),
            path(&v),
            json!({}),
            path(&dir.path().join("missing")),
        ],
    )
    .await;
    // an update and a rejection through the git mode
    let mut upd = load("CVE-2021-44228.json");
    upd["cveMetadata"]["cveId"] = json!(format!("CVE-{y}-0001"));
    upd["cveMetadata"]["state"] = json!("REJECTED");
    upd["cveMetadata"]["dateUpdated"] = json!("2026-02-01T00:00:00.000Z");
    origin.put(&upd);
    origin.commit();
    let second = check_row_contract(
        &src,
        &store,
        SRC,
        &[json!({}), json!({"full": true, "limit": 1})],
    )
    .await;
    assert!(
        first >= 1,
        "affected deletes (the rejected Chrome record): {first}"
    );
    assert!(second >= 1, "affected deletes of the rejection: {second}");
    let rows = store
        .rows_page(
            secmonk_model::MirrorTable::SourceSync,
            "cvelist:years",
            None,
            1,
        )
        .await
        .unwrap()
        .0;
    assert_eq!(rows[0]["cursor"], json!((y - 1).to_string()));
    store.close().await;
}

// ------------------------------------------------------------------------------------------------ volume

/// A synthetic record of realistic size (about 4 KiB): two to four CNA `affected` entries of different shapes, a CVSS
/// 3.1 metric, CWE, references, an ADP container with SSVC; every third one with a `cpeApplicability` node.
fn volume_record(i: u64, updated: &str) -> Value {
    let id = format!("CVE-2099-{:06}", 100_000 + i);
    let mut affected = vec![
        json!({"vendor": format!("Vendor {}", i % 997), "product": format!("Product {}", i % 4999),
               "defaultStatus": "unaffected",
               "versions": [{"version": "0", "lessThan": format!("{}.{}.{}", i % 7, i % 13, i % 31),
                             "status": "affected", "versionType": "semver"},
                            {"version": format!("{}.0", i % 9 + 1), "lessThanOrEqual": format!("{}.4", i % 9 + 1),
                             "status": "affected", "versionType": "custom",
                             "changes": [{"at": format!("{}.2", i % 9 + 1), "status": "unaffected"}]}]}),
        json!({"packageName": format!("pkg-{}", i % 3001), "collectionURL": "https://www.npmjs.com",
               "versions": [{"version": format!("< {}.{}", i % 5 + 1, i % 11), "status": "affected"}]}),
    ];
    if i.is_multiple_of(2) {
        affected.push(
            json!({"vendor": "Acme", "product": format!("Suite {}", i % 50),
            "versions": [{"version": format!("{}.{}", i % 4, i % 10), "status": "affected"},
                         {"version": "n/a", "status": "affected"}]}),
        );
    }
    let mut cna = json!({
        "providerMetadata": {"orgId": "00000000-0000-0000-0000-000000000000", "shortName": "synthetic"},
        "title": format!("Synthetic vulnerability {i} in Product {}", i % 4999),
        "descriptions": [{"lang": "en", "value": format!("A synthetic description of record {i}, long enough to resemble \
            a real CVE description: improper neutralization of input during web page generation allows a remote \
            attacker to inject arbitrary web script or HTML via a crafted parameter. {}", "x".repeat((i % 400) as usize))}],
        "affected": affected,
        "metrics": [{"cvssV3_1": {"version": "3.1", "baseScore": (i % 100) as f64 / 10.0,
            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "baseSeverity": "MEDIUM"}}],
        "problemTypes": [{"descriptions": [{"type": "CWE", "lang": "en", "cweId": format!("CWE-{}", i % 900),
                                            "description": "CWE description"}]}],
        "references": (0..(i % 5 + 1)).map(|k| json!({"url": format!("https://example.invalid/{i}/{k}"),
                                                         "tags": ["vendor-advisory"]})).collect::<Vec<_>>()
    });
    if i.is_multiple_of(3) {
        cna["cpeApplicability"] = json!([{"nodes": [{"operator": "OR", "negate": false, "cpeMatch": [
            {"vulnerable": true, "criteria": format!("cpe:2.3:a:vendor{}:product{}:*:*:*:*:*:*:*:*", i % 997, i % 4999),
             "versionStartIncluding": "1.0", "versionEndExcluding": format!("{}.0", i % 9 + 2)}]}]}]);
    }
    json!({"dataType": "CVE_RECORD", "dataVersion": "5.1",
        "cveMetadata": {"cveId": id, "assignerOrgId": "00000000-0000-0000-0000-000000000000",
                        "assignerShortName": "synthetic", "state": "PUBLISHED", "dateReserved": "2026-01-01T00:00:00.000Z",
                        "datePublished": "2026-01-02T00:00:00.000Z", "dateUpdated": updated},
        "containers": {"cna": cna, "adp": [{"providerMetadata": {"shortName": "CISA-ADP"},
            "title": "CISA ADP Vulnrichment",
            "metrics": [{"other": {"type": "ssvc", "content": {"id": format!("CVE-2099-{:06}", 100_000 + i),
                "role": "CISA Coordinator", "version": "2.0.3", "timestamp": "2026-01-03T00:00:00+00:00",
                "options": [{"Exploitation": "none"}, {"Automatable": "no"}, {"Technical Impact": "partial"}]}}}]}]}})
}

/// Writes `n` records under `dir` in the repository layout; every third one newer on the second day.
fn volume_corpus(dir: &Path, n: u64, day: u32) -> u64 {
    let mut bytes = 0u64;
    for i in 0..n {
        let updated = if day == 2 && i.is_multiple_of(3) {
            "2026-02-01T00:00:00.000Z"
        } else {
            "2026-01-01T00:00:00.000Z"
        };
        let mut r = volume_record(i, updated);
        if day == 2 && i.is_multiple_of(3) {
            r["containers"]["cna"]["affected"][0]["versions"][0]["lessThan"] = json!("99.0");
        }
        let id = r["cveMetadata"]["cveId"].as_str().unwrap().to_owned();
        let p = dir.join(format!("cves/2099/{}xxx/{id}.json", (100_000 + i) / 1000));
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let body = serde_json::to_vec(&r).unwrap();
        bytes += body.len() as u64;
        std::fs::write(&p, body).unwrap();
    }
    bytes
}

/// `--path` imports of a synthetic corpus through the engine, native and `py-sources` on their own mirrors: first
/// sync, re-sync of an unchanged corpus (every record skipped by its `dateUpdated`), re-sync with every third record
/// newer, `--full`. `SECMONK_CVELIST_RECORDS` (default 100 000); `SECMONK_CVELIST_NATIVE_ONLY=1` /
/// `SECMONK_CVELIST_PY_ONLY=1` for one half. Prints the times; run with `--nocapture` under `/usr/bin/time -l`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "volume measurement, run by hand (source-cvelist.md)"]
async fn cvelist_volume_sync() {
    let fx = fixtures();
    let Some(mut d) = Diff::new(&[&fx]).await else {
        return;
    };
    let n: u64 = std::env::var("SECMONK_CVELIST_RECORDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let native_only = std::env::var("SECMONK_CVELIST_NATIVE_ONLY").as_deref() == Ok("1");
    let py_only = std::env::var("SECMONK_CVELIST_PY_ONLY").as_deref() == Ok("1");
    let dir = tempfile::tempdir().unwrap();
    let (day1, day2) = (dir.path().join("day1"), dir.path().join("day2"));
    let t = std::time::Instant::now();
    let bytes = volume_corpus(&day1, n, 1);
    volume_corpus(&day2, n, 2);
    eprintln!(
        "cvelist volume: {n} records, {} MiB per day, generated in {:.1} s",
        bytes / (1 << 20),
        t.elapsed().as_secs_f64()
    );
    let mut engines: Vec<(&str, Arc<SecmonkEngine>, SqliteStore)> = Vec::new();
    if !py_only {
        let s = d.store("rs").await;
        let e = d.engine(
            &s,
            vec![Arc::new(secmonk_sources::cvelist::CvelistSource::new(
                Diff::view(&s),
            ))],
        );
        engines.push(("native", e, s));
    }
    if !native_only {
        let s = d.store("py").await;
        let (src, _) = d.py_sources(&s, "modules-py");
        let e = d.engine(&s, vec![src]);
        engines.push(("py-sources", e, s));
    }
    for (name, e, s) in &engines {
        for (what, path, extra) in [
            ("first sync", &day1, json!({})),
            ("unchanged re-sync", &day1, json!({})),
            ("re-sync, a third newer", &day2, json!({})),
            ("full re-sync", &day2, json!({"full": true})),
        ] {
            let t = std::time::Instant::now();
            let job = sync_job_secs(e, &[SRC], path, extra, 7200).await;
            eprintln!(
                "cvelist volume: {name}: {what}: {:.1} s, {} records, status {}, affected rows {}",
                t.elapsed().as_secs_f64(),
                entry_of(&job)["records"],
                entry_of(&job)["status"],
                s.count_rows(secmonk_model::MirrorTable::Affected, SRC)
                    .await
                    .unwrap()
            );
        }
    }
    if engines.len() == 2 {
        assert_mirrors_equal(
            &d.python.clone(),
            engines[1].2.mirror_path(),
            engines[0].2.mirror_path(),
            "volume",
            TIMESTAMPS,
            &[],
        );
        eprintln!("cvelist volume: the two mirrors are equal");
    }
    d.close().await;
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

/// The native stream alone (no engine, nothing applied) over a store that holds the corpus: the time of one
/// unchanged `--path` pass and of its `rows_by_id` reads. `SECMONK_CVELIST_RECORDS` as above.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "volume measurement, run by hand (source-cvelist.md)"]
async fn cvelist_volume_native_stream() {
    use futures_util::StreamExt;
    let n: u64 = std::env::var("SECMONK_CVELIST_RECORDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let dir = tempfile::tempdir().unwrap();
    let day1 = dir.path().join("day1");
    volume_corpus(&day1, n, 1);
    let store = SqliteStore::open(
        &dir.path().join("state.sqlite3"),
        &dir.path().join("mirror.sqlite3"),
        &StoreOptions::default(),
    )
    .await
    .unwrap();
    let path = json!({"path": day1.display().to_string()});
    for pass in ["empty mirror", "after the import"] {
        let view = Arc::new(TimedView {
            inner: Diff::view(&store),
            nanos: 0.into(),
            calls: 0.into(),
        });
        let src = secmonk_sources::cvelist::CvelistSource::new(view.clone());
        let params: secmonk_traits::SyncParams =
            serde_json::from_value(json!({"source": SRC, "options": path})).unwrap();
        let t = std::time::Instant::now();
        let mut s = src.sync(params, CallCtx::default()).await.unwrap();
        let mut batches = Vec::new();
        while let Some(m) = s.next().await {
            if let secmonk_traits::StreamMsg::Item(b) = m.unwrap() {
                batches.push(b);
            }
        }
        let secs = t.elapsed().as_secs_f64();
        eprintln!(
            "cvelist volume: native stream, {pass}: {secs:.1} s, {} batches; {} rows_by_id reads in {:.1} s",
            batches.len(),
            view.calls.load(std::sync::atomic::Ordering::Relaxed),
            view.nanos.load(std::sync::atomic::Ordering::Relaxed) as f64 / 1e9
        );
        if pass == "empty mirror" {
            let t = std::time::Instant::now();
            for b in &batches {
                assert!(!store.apply_rows(b).await.unwrap().skipped);
            }
            eprintln!(
                "cvelist volume: apply_rows of those batches: {:.1} s",
                t.elapsed().as_secs_f64()
            );
        }
    }
    store.close().await;
}
