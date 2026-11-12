//! Differential test of the native osv importer against `py-sources` (stage 6, rust ADR-0011 / ADR-0012): both
//! through the engine on their own mirrors, for `--path` imports (the fixtures, the sample zip, updates with changed,
//! withdrawn, repeated and odd records, limit, errors, archives built at test time) and for the bucket (first sync per
//! ecosystem from `all.zip`, delta from `modified_id.csv`, failures, limit, `--full`, the fallback to the zip) against
//! one local HTTP server that both read (`py-sources` through the test-only hook
//! `secmonk_modules/sources/test_hooks_osv.py`, started as its own entry point); raw storage on and off; then a mirror
//! that switches between the two implementations; the row-contract check of the native batches; and the volume
//! measurement (ignored, run by hand). Harness: `common/`. Doc: rust/_docs/tech/source-osv.md. Fixtures:
//! `tests/fixtures/sources/osv/` and `tests/fixtures/lang/{dart,swift}/osv-*.json` (real records, read only); every
//! other record and archive is written at test time (synthetic).

mod common;

use std::collections::HashMap;
use std::sync::Mutex;

use common::*;
use secmonk_model::MirrorTable as T;

const SRC: &str = "osv";
const TIMESTAMPS: &[&str] = &["raw_record.fetched_at", "source_sync.last_sync"];
const OSV_TABLES: &[&str] = &["raw_record", "vulnerability", "alias", "affected"];

fn fixtures() -> PathBuf {
    rust_root().join("../tests/fixtures")
}

fn osv_dir() -> PathBuf {
    fixtures().join("sources/osv")
}

fn native(store: &SqliteStore) -> secmonk_sources::osv::OsvSource {
    secmonk_sources::osv::OsvSource::new(Diff::view(store)).with_store_raw(false)
}

fn write(dir: &Path, name: &str, doc: &Value) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, serde_json::to_vec_pretty(doc).unwrap()).unwrap();
    p
}

// ------------------------------------------------------------------------------------------------ py-sources with the hook

/// [`EnvRuntime`] that also starts `py-sources` through the test-only entry point
/// `secmonk_modules.sources.test_hooks_osv` (it wraps the unchanged osv source and runs the normal module).
struct HookRuntime {
    inner: Arc<dyn PythonRuntime>,
    env: Vec<(String, OsString)>,
}

#[async_trait]
impl PythonRuntime for HookRuntime {
    async fn ensure(&self) -> RuntimeResult<RuntimeInfo> {
        self.inner.ensure().await
    }

    async fn ensure_env(&self, project: &Path, env: &str) -> RuntimeResult<EnvInfo> {
        self.inner.ensure_env(project, env).await
    }

    fn command(&self, env: &str, entry: &[String]) -> RuntimeResult<LaunchSpec> {
        self.command_for(env, entry, &["read-target", "network"])
    }

    fn command_for(&self, env: &str, entry: &[String], caps: &[&str]) -> RuntimeResult<LaunchSpec> {
        let entry: Vec<String> = entry
            .iter()
            .map(|a| {
                if a == "secmonk_modules" {
                    "secmonk_modules.sources.test_hooks_osv".to_owned()
                } else {
                    a.clone()
                }
            })
            .collect();
        let mut spec = self.inner.command_for(env, &entry, caps)?;
        for (k, v) in &self.env {
            spec.env.insert(k.clone(), v.clone());
        }
        Ok(spec)
    }
}

/// A `py-sources` over `store` started through the hook, with `env`.
fn py_hooked(
    d: &mut Diff,
    store: &SqliteStore,
    modules: &str,
    env: &[(&str, &Path)],
) -> (Arc<dyn Source>, PathBuf) {
    let root = d.config.data_dir.join(modules);
    std::fs::create_dir_all(&root).unwrap();
    let runtime: Arc<dyn PythonRuntime> = Arc::new(HookRuntime {
        inner: d.runtime.clone(),
        env: env
            .iter()
            .map(|(k, v)| ((*k).to_owned(), v.as_os_str().to_os_string()))
            .collect(),
    });
    let h = ModuleHandle::python(
        d.registry.get("py-sources").unwrap(),
        runtime,
        Diff::settings(store, root.clone()),
    );
    d.handles.push(h.clone());
    (
        Arc::new(PySource::new(h)),
        root.join("py-sources/staging.sqlite3"),
    )
}

/// One sync job of osv without `--path` (the bucket), with the plan keys in `extra`.
async fn bucket_job(engine: &SecmonkEngine, extra: &Value) -> Value {
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

fn status(b: &Value) -> String {
    entry_of(b)["status"]
        .as_str()
        .unwrap_or_default()
        .to_owned()
}

// ------------------------------------------------------------------------------------------------ zips and the server

fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for b in data {
        c ^= u32::from(*b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                (c >> 1) ^ 0xEDB8_8320
            } else {
                c >> 1
            };
        }
    }
    !c
}

fn deflate(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// One member of a hand-written zip: name, method (0 stored, 8 deflate, else as given), flags, content; `size` and
/// `local_name` override what the headers say.
#[derive(Clone)]
struct Member {
    name: String,
    method: u16,
    flags: u16,
    content: Vec<u8>,
    size: Option<u32>,
    csize_extra: u32,
    local_name: Option<String>,
}

fn m(name: &str, content: &[u8]) -> Member {
    Member {
        name: name.into(),
        method: 8,
        flags: 0,
        content: content.to_vec(),
        size: None,
        csize_extra: 0,
        local_name: None,
    }
}

/// A zip written byte by byte (no zip writer in this crate's dependencies).
fn zip_bytes(members: &[Member]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut cd = Vec::new();
    for e in members {
        let data = if e.method == 8 {
            deflate(&e.content)
        } else {
            e.content.clone()
        };
        let crc = crc32(&e.content);
        let size = e.size.unwrap_or(u32::try_from(e.content.len()).unwrap());
        let csize = u32::try_from(data.len()).unwrap() + e.csize_extra;
        let at = u32::try_from(out.len()).unwrap();
        let local = e.local_name.as_ref().unwrap_or(&e.name);
        let head = |sig: &[u8], name: &str, central: bool| {
            let mut h = sig.to_vec();
            if central {
                h.extend(20u16.to_le_bytes());
            }
            h.extend(20u16.to_le_bytes());
            h.extend(e.flags.to_le_bytes());
            h.extend(e.method.to_le_bytes());
            h.extend([0u8; 4]);
            h.extend(crc.to_le_bytes());
            h.extend(csize.to_le_bytes());
            h.extend(size.to_le_bytes());
            h.extend(u16::try_from(name.len()).unwrap().to_le_bytes());
            h.extend(0u16.to_le_bytes());
            if central {
                h.extend([0u8; 10]); // comment length, disk, internal and external attributes
                h.extend(at.to_le_bytes());
            }
            h.extend(name.as_bytes());
            h
        };
        out.extend(head(b"PK\x03\x04", local, false));
        out.extend(&data);
        cd.extend(head(b"PK\x01\x02", &e.name, true));
    }
    let cd_at = u32::try_from(out.len()).unwrap();
    let cd_len = u32::try_from(cd.len()).unwrap();
    out.extend(cd);
    out.extend(b"PK\x05\x06");
    out.extend([0u8; 4]);
    let n = u16::try_from(members.len()).unwrap();
    out.extend(n.to_le_bytes());
    out.extend(n.to_le_bytes());
    out.extend(cd_len.to_le_bytes());
    out.extend(cd_at.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

fn zip_of(recs: &[Value]) -> Vec<u8> {
    let ms: Vec<Member> = recs
        .iter()
        .map(|r| {
            m(
                &format!("{}.json", r["id"].as_str().unwrap()),
                &serde_json::to_vec(r).unwrap(),
            )
        })
        .collect();
    zip_bytes(&ms)
}

type Files = Arc<Mutex<HashMap<String, (u16, Vec<u8>)>>>;

/// A local HTTP server answering by path from `files` (404 otherwise), recording the request lines.
async fn serve_files(files: Files) -> (String, Arc<Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let log = Arc::new(Mutex::new(Vec::new()));
    let seen = log.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else {
                return;
            };
            let (files, seen) = (files.clone(), seen.clone());
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                let mut n = 0;
                while n < buf.len() {
                    let k = s.read(&mut buf[n..]).await.unwrap_or(0);
                    n += k;
                    if k == 0 || buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let line = String::from_utf8_lossy(&buf[..n])
                    .lines()
                    .next()
                    .unwrap_or("")
                    .to_owned();
                let path = line.split(' ').nth(1).unwrap_or("").to_owned();
                seen.lock().unwrap().push(line);
                let (code, body) = files
                    .lock()
                    .unwrap()
                    .get(&path)
                    .cloned()
                    .unwrap_or((404, b"not found".to_vec()));
                let head = format!(
                    "HTTP/1.1 {code} X\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(head.as_bytes()).await;
                let _ = s.write_all(&body).await;
                let _ = s.shutdown().await;
            });
        }
    });
    (format!("http://{addr}"), log)
}

// ------------------------------------------------------------------------------------------------ records

/// A synthetic record of `eco`: `pkg` with an ECOSYSTEM range fixed at `fixed`, a CVE alias, a CVSS 3.1 vector.
fn rec(id: &str, modified: &str, eco: &str, pkg: &str, fixed: &str) -> Value {
    json!({"schema_version": "1.6.0", "id": id, "modified": modified, "published": "2026-01-01T00:00:00Z",
           "aliases": [format!("CVE-2099-{}", id.len())], "summary": format!("{id}: synthetic"),
           "details": "A synthetic record of the osv differential test.",
           "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"}],
           "affected": [{"package": {"name": pkg, "ecosystem": eco, "purl": format!("pkg:generic/{pkg}")},
                         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
                         "versions": ["0.1", "0.2"]}],
           "references": [{"type": "WEB", "url": format!("https://example.org/{id}")}]})
}

/// Purls of every shape `_strip_purl` meets (expected values in `secmonk-sources/src/osv.rs` unit tests).
const PURLS: &[&str] = &[
    "pkg:pypi/Foo_Bar",
    "pkg:pypi/foo@1.0?x=1#sub",
    "pkg:deb/ubuntu/python-tornado?arch=source&distro=esm-apps%2Fbionic",
    "pkg:npm/%40scope/name",
    "pkg:npm/@scope/Name@1.0",
    "pkg:pub/Foo-Bar.baz",
    "PKG:pypi/x",
    "pkg:pypi",
    "pkg:1abc/x",
    "pkg:pypi/x?bad",
    "pkg:pypi/x?1a=b",
    "pkg:pypi/%20",
    "pkg:generic/a%2Fb/c",
    "pkg:generic//a//b//",
    "pkg:generic/a:b/c",
    "pkg:generic/http://host/path/n",
    "pkg:generic///host/x",
    "pkg:generic/x@y@z",
    "pkg:generic/n%C3",
    "pkg:generic/é%41",
    "pkg:generic/n a",
    "pkg:mlflow/MyModel?repository_url=https://databricks.example",
    "pkg:m/AbC",
    "pkg:cpan/a/B",
    "pkg:c/ns/x",
    "pkg:hackage/a_b",
    "pkg:generic///[::1]/y",
    "pkg:generic///[x/y",
    "pkg:generic/\tx\ny",
    "pkg:oci/Foo@sha256:ABC",
    "pkg:npm/@/x",
    "pkg:generic/x%zz",
    "pkg:generic/%2F",
    "noscheme",
];

/// The first update: changes, a withdrawal, repeats, purls, odd values Python stores as text, records Python skips.
fn update1() -> (Vec<Value>, Value) {
    let mut log4j: Value = serde_json::from_slice(
        &std::fs::read(osv_dir().join("maven-GHSA-jfh8-c2jp-5v3q.json")).unwrap(),
    )
    .unwrap();
    log4j["affected"].as_array_mut().unwrap().truncate(3);
    log4j["affected"][0]["ranges"][0]["events"] = json!([{"introduced": "2.0"}, {"fixed": "2.99"}]);
    log4j["modified"] = json!("2026-11-01T00:00:00.123456Z");
    let mut go: Value =
        serde_json::from_slice(&std::fs::read(osv_dir().join("go-GO-2024-2428.json")).unwrap())
            .unwrap();
    go["withdrawn"] = json!("2026-11-02T00:00:00Z");
    let purls: Vec<Value> = PURLS
        .iter()
        .map(|p| json!({"package": {"name": "n", "ecosystem": "PyPI", "purl": p}, "versions": ["1"]}))
        .collect();
    let mut first = vec![
        log4j,
        go,
        json!({"id": "PURLS-1", "modified": "2026-10-01T00:00:00Z", "affected": purls}),
        rec("DUP-1", "2026-10-01T00:00:00Z", "PyPI", "dup", "1"),
        // odd values Python stores as text: a numeric id, falsy and numeric text fields, falsy ecosystems
        json!({"id": 7, "modified": 5, "summary": 0, "details": "", "published": true, "withdrawn": false,
        "aliases": "CVE-9", "upstream": {"CVE-8": 1},
        "database_specific": {"cwe_ids": {"CWE-1": 1}, "severity": "NEGLIGIBLE", "source": ""},
        "severity": [{"type": "CVSS_V3", "score": ""}, {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "references": [{"url": 12}, {"url": null}, "x"],
        "affected": [
            {"package": {"name": " Foo_Bar ", "ecosystem": ""}, "versions": ["1"]},
            {"package": {"name": "zero", "ecosystem": 0}, "ranges": [{"type": "SEMVER", "events": [{"limit": "*"}], "_custom": 1}]},
            {"package": {"name": "no", "ecosystem": false}, "versions": ["2", 3]},
            {"package": {"name": "deb", "ecosystem": "Debian:13", "purl": ""},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}], "database_specific": {"k": [1, 2.5]}},
                        {"type": "GIT", "repo": "https://example.org/r", "events": []}, {"type": "OTHER"}],
             "ecosystem_specific": {"urgency": " Unimportant ", "binaries": [{"binary_name": "b1"}, {"binary_name": 2}, {}]}},
            {"package": {"name": "Rpm", "ecosystem": "Red Hat:rhel_eus:9.6::baseos"},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0:1-1"}]}]},
            {"package": {"name": "Pkg", "ecosystem": "Ubuntu:Pro:FIPS-updates:22.04:LTS"}, "versions": ["1.0"]},
            {"package": {"name": "garbage-v3"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}
        ]}),
        json!({"id": "ODD-7", "modified": "2026-10-01", "severity": [{"type": "CVSS_V3", "score": "garbage"}, {"type": "Ubuntu", "score": "Medium"}]}),
        json!({"id": "ODD-8", "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N"}], "database_specific": {"severity": "HIGH"}}),
        // records Python skips (an exception in its savepoint): SKIP-1 keeps the rows of the first sync
        json!({"id": "SKIP-1", "severity": "not a list"}),
        json!({"id": "SKIP-2", "references": 3}),
        json!({"id": "SKIP-3", "details": 5}),
        json!({"id": "SKIP-4", "affected": [{"package": {"name": 5}}]}),
        json!({"id": "SKIP-5", "modified": [1]}),
        json!({"id": "SKIP-6", "affected": [{"package": {"name": "x", "purl": 5}}]}),
        json!({"id": "SKIP-7", "affected": [{"package": {"name": "x", "ecosystem": []}, "versions": ["1"]}]}),
        json!({"id": ""}),
        json!([1, 2]),
    ];
    first.push(rec("DUP-2", "2026-10-01T00:00:00Z", "npm", "two", "1"));
    // DUP-1 again in another file, with other rows: the last record of an id is the one written
    let mut dup = rec("DUP-1", "2026-10-02T00:00:00Z", "PyPI", "dup", "2");
    dup["aliases"] = json!(["CVE-2099-1", "CVE-2099-2"]);
    (first, dup)
}

fn write_update1(dir: &Path) -> PathBuf {
    let d = dir.join("update1");
    std::fs::create_dir_all(&d).unwrap();
    let (first, dup) = update1();
    write(&d, "a.json", &Value::Array(first));
    write(&d, "b.json", &dup);
    std::fs::write(d.join("c.json"), b"{").unwrap();
    std::fs::write(
        d.join("d.json"),
        b"{\"id\": \"LATIN-1\", \"x\": \"caf\xe9\"}",
    )
    .unwrap();
    std::fs::create_dir_all(d.join("e.json")).unwrap();
    d
}

/// The first sync of the path steps: the fixture directory plus SKIP-1 as a good record.
fn write_base(dir: &Path) -> PathBuf {
    let d = dir.join("base");
    std::fs::create_dir_all(&d).unwrap();
    for e in std::fs::read_dir(osv_dir()).unwrap().flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if n.ends_with(".json") {
            std::fs::copy(e.path(), d.join(&n)).unwrap();
        }
    }
    write(
        &d,
        "skip-1.json",
        &rec("SKIP-1", "2026-09-01T00:00:00Z", "PyPI", "skip", "1"),
    );
    d
}

// ------------------------------------------------------------------------------------------------ the --path steps

#[tokio::test(flavor = "multi_thread")]
async fn native_osv_matches_py_sources_on_path_imports() {
    let fx = osv_dir();
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
    let rs = d.engine(&rs_store, vec![Arc::new(native(&rs_store)), rs_py_src]);
    let switch_py = d.engine(&switch_store, vec![switch_src.clone()]);
    let switch_rs = d.engine(
        &switch_store,
        vec![Arc::new(native(&switch_store)), switch_src],
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
    let step = |path: PathBuf, extra: Value, what: &'static str| {
        let (py, rs) = (py.clone(), rs.clone());
        async move {
            let a = sync_job(&py, &[SRC], &path, extra.clone()).await;
            let b = sync_job(&rs, &[SRC], &path, extra).await;
            check_entries(&a, &b, what);
            b
        }
    };
    let count = |table: T| {
        let store = rs_store.clone();
        async move { store.count_rows(table, SRC).await.unwrap() }
    };

    // 1. the fixture directory (and SKIP-1); the switch mirror on py-sources
    let base = write_base(dir.path());
    let b = step(base.clone(), json!({}), "first sync").await;
    assert_eq!(status(&b), "ok", "{b:#}");
    assert!(entry_of(&b)["records"].as_u64().unwrap() > 10, "{b:#}");
    same("first sync");
    assert!(
        count(T::Affected).await > 30 && count(T::Alias).await > 10,
        "the comparison is not vacuous"
    );
    let job = sync_job(&switch_py, &[SRC], &base, json!({})).await;
    assert_eq!(status(&job), "ok", "{job:#}");

    // 2. the same again; the sample zip; the Pub and SwiftURL records
    step(base.clone(), json!({}), "second sync").await;
    same("second sync");
    let b = step(fx.join("sample-all.zip"), json!({}), "sample zip").await;
    assert_eq!(entry_of(&b)["records"], 6);
    same("sample zip");
    for f in [
        "lang/dart/osv-pub-GHSA-4rgh-jx4f-qfcq.json",
        "lang/swift/osv-swifturl-GHSA-ccw9-q5h2-8c2w.json",
    ] {
        let b = step(fixtures().join(f), json!({}), "pub and swift").await;
        assert_eq!(entry_of(&b)["records"], 1);
        same(f);
    }

    // 3. the first update: changed rows, a withdrawal, a repeated id, purls, odd values, skipped records, bad files
    let u1 = write_update1(dir.path());
    let b = step(u1.clone(), json!({}), "update 1").await;
    assert_eq!(
        (status(&b), entry_of(&b)["records"].clone()),
        ("ok".into(), json!(9)),
        "{b:#}"
    );
    same("update 1");
    let skip1 = rs_store
        .rows_page(T::Affected, SRC, None, 5000)
        .await
        .unwrap();
    assert!(
        skip1.0.iter().any(|r| r["vuln_id"] == "SKIP-1"),
        "a skipped record keeps its rows"
    );

    // the switch mirror: the native importer for the same update
    let job = sync_job(&switch_rs, &[SRC], &u1, json!({})).await;
    assert_eq!(status(&job), "ok", "{job:#}");
    assert!(
        job["log"]
            .to_string()
            .contains("osv: native importer: applied state of generation "),
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
            OSV_TABLES,
        );
    };
    let only = [
        &base,
        &fx.join("sample-all.zip"),
        &fixtures().join("lang/dart/osv-pub-GHSA-4rgh-jx4f-qfcq.json"),
        &fixtures().join("lang/swift/osv-swifturl-GHSA-ccw9-q5h2-8c2w.json"),
    ];
    for p in &only[1..] {
        sync_job(&switch_rs, &[SRC], p, json!({})).await;
    }
    sync_job(&switch_rs, &[SRC], &u1, json!({})).await;
    switch_same("switch from py-sources to the native importer");

    // a failed py-sources run after native ones: nothing applied
    let not_zip = dir.path().join("not.zip");
    std::fs::write(&not_zip, b"PK not really").unwrap();
    let job = sync_job(&switch_py, &[SRC], &not_zip, json!({})).await;
    let e = entry_of(&job);
    assert_eq!(e["status"], "error", "{job:#}");
    assert!(
        e["message"].as_str().unwrap().ends_with("; not applied: mirror keeps the native importer data until a successful py-sources sync"),
        "{job:#}"
    );
    switch_same("a failed Python run after Rust");
    // back to py-sources: an ok run repairs from the staging export (staging has seen only the first sync, so it
    // gets the same history as the Python-only mirror)
    for (i, p) in only[1..].iter().enumerate() {
        let job = sync_job(&switch_py, &[SRC], p, json!({})).await;
        assert_eq!(status(&job), "ok", "{job:#}");
        if i == 0 {
            assert!(
                job["log"]
                    .to_string()
                    .contains("osv: repair from py-sources export"),
                "{job:#}"
            );
        }
    }
    let job = sync_job(&switch_py, &[SRC], &u1, json!({})).await;
    assert_eq!(status(&job), "ok", "{job:#}");
    assert_mirror_equals_staging(
        &python,
        switch_store.mirror_path(),
        &switch_staging,
        "switch back to py-sources",
    );
    switch_same("switch back to py-sources vs py-sources only");

    // 4. limit (status ok from a path), then the update again
    let b = step(u1.clone(), json!({"limit": 2}), "limit").await;
    assert_eq!(
        (status(&b), entry_of(&b)["records"].clone()),
        ("ok".into(), json!(2))
    );
    same("limit");
    step(u1.clone(), json!({}), "update 1 again").await;
    same("update 1 again");

    // 5. 130 records (groups of rows_by_id), an id again 100 records later
    let many = dir.path().join("many.json");
    let mut recs: Vec<Value> = (0..130)
        .map(|i| {
            rec(
                &format!("MANY-{i:03}"),
                "2026-10-05T00:00:00Z",
                "PyPI",
                "p",
                "1",
            )
        })
        .collect();
    recs.push(rec("MANY-005", "2026-10-06T00:00:00Z", "PyPI", "p", "2"));
    std::fs::write(&many, serde_json::to_vec(&recs).unwrap()).unwrap();
    let b = step(many, json!({}), "many").await;
    assert_eq!(entry_of(&b)["records"], 131);
    same("many");

    // an integer beyond 64 bits: exact in Python's staging, a float once parsed here; equal in both mirrors (the
    // store parses the text py-sources sends the same way); not on the switch mirror, whose staging keeps it exact
    let big = dir.path().join("bigint.json");
    std::fs::write(
        &big,
        b"{\"id\": \"BIGINT-1\", \"references\": [{\"url\": 123456789012345678901234567890}]}",
    )
    .unwrap();
    step(big, json!({}), "a big integer").await;
    same("a big integer");

    // 6. archives: errors and members both versions refuse alike
    let r =
        |id: &str| serde_json::to_vec(&rec(id, "2026-10-07T00:00:00Z", "PyPI", "z", "1")).unwrap();
    let zips: Vec<(&str, Vec<Member>, &str)> = vec![
        (
            "encrypted after a good member",
            vec![
                m("Z-1.json", &r("Z-1")),
                Member {
                    flags: 1,
                    ..m("Z-2.json", &r("Z-2"))
                },
            ],
            "error",
        ),
        (
            "an unknown method",
            vec![Member {
                method: 99,
                ..m("Z-3.json", &r("Z-3"))
            }],
            "error",
        ),
        (
            "a lying size",
            vec![
                Member {
                    size: Some(10),
                    ..m("Z-4.json", &r("Z-4"))
                },
                m("Z-5.json", &r("Z-5")),
            ],
            "ok",
        ),
        (
            "overlapping data",
            vec![
                Member {
                    csize_extra: 40,
                    ..m("Z-6.json", &r("Z-6"))
                },
                m("Z-7.json", &r("Z-7")),
            ],
            "ok",
        ),
        (
            "another name in the local header",
            vec![Member {
                local_name: Some("Z-X.json".into()),
                ..m("Z-8.json", &r("Z-8"))
            }],
            "ok",
        ),
        (
            "stored, a directory and a text member",
            vec![
                Member {
                    method: 0,
                    ..m("Z-9.json", &r("Z-9"))
                },
                m("dir/", b""),
                m("notes.txt", b"x"),
            ],
            "ok",
        ),
        (
            "a member that is not JSON",
            vec![
                m("Z-10.json", b"{"),
                m("Z-11.json", b"[1, {\"id\": \"no\"}]"),
            ],
            "ok",
        ),
    ];
    for (what, members, want) in zips {
        let p = dir.path().join("crafted.zip");
        std::fs::write(&p, zip_bytes(&members)).unwrap();
        let b = step(p, json!({}), what).await;
        assert_eq!(status(&b), want, "{what}: {b:#}");
        same(what);
    }
    // (a missing path is refused by the engine before any source runs)
    for (p, want, what) in [
        (not_zip, "error", "not a zip"),
        (dir.path().join("empty-dir"), "ok", "an empty directory"),
    ] {
        if what == "an empty directory" {
            std::fs::create_dir_all(&p).unwrap();
        }
        let b = step(p, json!({}), what).await;
        assert_eq!(status(&b), want, "{what}: {b:#}");
        same(what);
    }

    // 7. documented differences (source-osv.md): from here on the mirrors differ
    // a float in a text column: stored as text by Python, the record skipped natively
    let float = write(
        dir.path(),
        "float.json",
        &json!({"id": "FLOAT-1", "published": 1.5}),
    );
    let a = sync_job(&py, &[SRC], &float, json!({})).await;
    let b = sync_job(&rs, &[SRC], &float, json!({})).await;
    assert_eq!(
        (
            entry_of(&a)["records"].clone(),
            entry_of(&b)["records"].clone()
        ),
        (json!(1), json!(0))
    );
    // range events that are not a list of objects: stored by Python, outside the row contract, the record skipped
    let events = write(
        dir.path(),
        "events.json",
        &json!({"id": "EVENTS-1", "affected": [{"package": {"name": "x"}, "ranges": [{"type": "GIT", "events": {"a": 1}}]}]}),
    );
    let a = sync_job(&py, &[SRC], &events, json!({})).await;
    let b = sync_job(&rs, &[SRC], &events, json!({})).await;
    assert_eq!(
        (
            entry_of(&a)["records"].clone(),
            entry_of(&b)["records"].clone()
        ),
        (json!(1), json!(0))
    );
    // a member with a path trick and a compression bomb: read by Python, skipped natively
    let mut bomb = b"{\"id\": \"BOMB-1\"".to_vec();
    bomb.extend(std::iter::repeat_n(b' ', 4 * 1024 * 1024));
    bomb.push(b'}');
    let p = dir.path().join("tricks.zip");
    std::fs::write(
        &p,
        zip_bytes(&[m("../TRICK-1.json", &r("TRICK-1")), m("BOMB-1.json", &bomb)]),
    )
    .unwrap();
    let a = sync_job(&py, &[SRC], &p, json!({})).await;
    let b = sync_job(&rs, &[SRC], &p, json!({})).await;
    assert_eq!(
        (
            entry_of(&a)["records"].clone(),
            entry_of(&b)["records"].clone()
        ),
        (json!(2), json!(0)),
        "{a:#} {b:#}"
    );
    d.close().await;
}

// ------------------------------------------------------------------------------------------------ the bucket

#[tokio::test(flavor = "multi_thread")]
async fn native_osv_matches_py_sources_on_the_bucket() {
    let fx = osv_dir();
    let Some(mut d) = Diff::new(&[&fx]).await else {
        return;
    };
    let python = d.python.clone();
    let dir = tempfile::tempdir().unwrap();
    let files: Files = Arc::default();
    let (url, log) = serve_files(files.clone()).await;
    let hook = dir.path().join("osv-hook.json");
    std::fs::write(&hook, serde_json::to_vec(&json!({"bucket": url})).unwrap()).unwrap();
    let (py_store, rs_store) = (d.store("py").await, d.store("rs").await);
    let (py_src, _) = py_hooked(
        &mut d,
        &py_store,
        "modules-py",
        &[("SECMONK_TEST_OSV_HOOK", &hook)],
    );
    let py = d.engine(&py_store, vec![py_src]);
    let rs = d.engine(
        &rs_store,
        vec![Arc::new(native(&rs_store).with_bucket(&url))],
    );
    let put = |path: &str, code: u16, body: Vec<u8>| {
        files.lock().unwrap().insert(path.to_owned(), (code, body));
    };
    let fixture = |name: &str| -> Value {
        serde_json::from_slice(&std::fs::read(fx.join(name)).unwrap()).unwrap()
    };
    let lang = |name: &str| -> Value {
        serde_json::from_slice(&std::fs::read(fixtures().join(name)).unwrap()).unwrap()
    };
    put(
        "/PyPI/all.zip",
        200,
        zip_of(&[
            fixture("pypi-GHSA-fhq3-2gf3-8f3j.json"),
            fixture("pypi-PYSEC-2021-375.json"),
            fixture("pypi-OSV-2022-1074.json"),
        ]),
    );
    put(
        "/Red%20Hat/all.zip",
        200,
        zip_of(&[fixture("redhat-RHSA-2026_39976.json")]),
    );
    put(
        "/Pub/all.zip",
        200,
        zip_of(&[lang("lang/dart/osv-pub-GHSA-4rgh-jx4f-qfcq.json")]),
    );
    put(
        "/SwiftURL/all.zip",
        200,
        zip_of(&[lang("lang/swift/osv-swifturl-GHSA-ccw9-q5h2-8c2w.json")]),
    );
    let ecos = json!(["PyPI", "Red Hat", "Pub", "SwiftURL"]);

    struct Step {
        what: &'static str,
        extra: Value,
        status: &'static str,
        same_message: bool,
    }
    let run = |s: Step| {
        let (py, rs, log, python) = (py.clone(), rs.clone(), log.clone(), python.clone());
        let (py_m, rs_m) = (
            py_store.mirror_path().to_path_buf(),
            rs_store.mirror_path().to_path_buf(),
        );
        async move {
            log.lock().unwrap().clear();
            let a = bucket_job(&py, &s.extra).await;
            let py_lines = std::mem::take(&mut *log.lock().unwrap());
            let b = bucket_job(&rs, &s.extra).await;
            let rs_lines = std::mem::take(&mut *log.lock().unwrap());
            let what = s.what;
            assert_eq!(status(&b), s.status, "{what}: {b:#}");
            assert_eq!(status(&a), status(&b), "{what}: {a:#}");
            assert_eq!(entry_of(&a)["records"], entry_of(&b)["records"], "{what}");
            if s.same_message {
                assert_eq!(entry_of(&a)["message"], entry_of(&b)["message"], "{what}");
            }
            assert!(
                !py_lines.is_empty() || s.status == "error",
                "{what}: the Python source reached the local server"
            );
            assert_eq!(py_lines, rs_lines, "{what}: request lines");
            let mut ignore = TIMESTAMPS.to_vec();
            if !s.same_message {
                ignore.push("source_sync.message");
            }
            assert_mirrors_equal(&python, &py_m, &rs_m, what, &ignore, &[]);
            eprintln!(
                "{what}: {} requests, {}",
                py_lines.len(),
                entry_of(&b)["message"]
            );
            b
        }
    };

    // 1. first sync of four ecosystems (all.zip each)
    let b = run(Step {
        what: "first sync per ecosystem",
        extra: json!({"ecosystems": ecos}),
        status: "ok",
        same_message: true,
    })
    .await;
    assert_eq!(entry_of(&b)["records"], 6);
    assert!(rs_store.count_rows(T::Affected, SRC).await.unwrap() > 5);

    // 2. a delta: a changed record, a new one, an id gone (404), an old line; the others unchanged
    let mut changed = fixture("pypi-PYSEC-2021-375.json");
    changed["modified"] = json!("2026-11-10T00:00:00.123456789Z");
    changed["affected"][0]["ranges"] =
        json!([{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "9.9"}]}]);
    let new = rec(
        "PYSEC-2099-1",
        "2026-11-10T01:00:00Z",
        "PyPI",
        "newpkg",
        "1.0",
    );
    put(
        "/PyPI/modified_id.csv",
        200,
        b"2026-11-10T02:00:00Z,PYSEC-GONE\n2026-11-10T01:00:00Z,PYSEC-2099-1\n2026-11-10T00:00:00.123456789Z,PYSEC-2021-375\n\nbad line\n2020-01-01T00:00:00Z,OSV-2022-1074\n"
            .to_vec(),
    );
    put(
        "/PyPI/PYSEC-2021-375.json",
        200,
        serde_json::to_vec(&changed).unwrap(),
    );
    put(
        "/PyPI/PYSEC-2099-1.json",
        200,
        serde_json::to_vec(&new).unwrap(),
    );
    for e in ["Red%20Hat", "Pub", "SwiftURL"] {
        put(
            &format!("/{e}/modified_id.csv"),
            200,
            b"2020-01-01T00:00:00Z,OLD\n".to_vec(),
        );
    }
    let b = run(Step {
        what: "delta",
        extra: json!({"ecosystems": ecos}),
        status: "ok",
        same_message: true,
    })
    .await;
    assert_eq!(entry_of(&b)["records"], 2);

    // 3. a failing id: partial, the cursor stops before it
    put("/PyPI/modified_id.csv", 200, b"2026-11-11T03:00:00Z,PYSEC-2099-3\n2026-11-11T02:00:00Z,PYSEC-2099-2\n2026-11-11T01:00:00Z,PYSEC-2099-1\n".to_vec());
    put(
        "/PyPI/PYSEC-2099-1.json",
        200,
        serde_json::to_vec(&rec(
            "PYSEC-2099-1",
            "2026-11-11T01:00:00Z",
            "PyPI",
            "newpkg",
            "1.1",
        ))
        .unwrap(),
    );
    put("/PyPI/PYSEC-2099-2.json", 500, b"oops".to_vec());
    put("/PyPI/PYSEC-2099-3.json", 200, b"[1, 2]".to_vec());
    run(Step {
        what: "a failing id",
        extra: json!({"ecosystems": ["PyPI"]}),
        status: "partial",
        same_message: true,
    })
    .await;
    // the next delta retries from the cursor
    put(
        "/PyPI/PYSEC-2099-2.json",
        200,
        serde_json::to_vec(&rec(
            "PYSEC-2099-2",
            "2026-11-11T02:00:00Z",
            "PyPI",
            "two",
            "1",
        ))
        .unwrap(),
    );
    put(
        "/PyPI/PYSEC-2099-3.json",
        200,
        serde_json::to_vec(&rec(
            "PYSEC-2099-3",
            "2026-11-11T03:00:00Z",
            "PyPI",
            "three",
            "1",
        ))
        .unwrap(),
    );
    run(Step {
        what: "the retry",
        extra: json!({"ecosystems": ["PyPI"]}),
        status: "ok",
        same_message: true,
    })
    .await;

    // 4. --full with a limit: partial, no cursor; the next run takes the zip again; the same ecosystem twice
    run(Step {
        what: "full with a limit",
        extra: json!({"ecosystems": ["PyPI", "Pub"], "full": true, "limit": 1}),
        status: "partial",
        same_message: true,
    })
    .await;
    run(Step {
        what: "after a limited run",
        extra: json!({"ecosystems": ["PyPI"]}),
        status: "ok",
        same_message: true,
    })
    .await;
    run(Step {
        what: "an ecosystem twice",
        extra: json!({"ecosystems": ["Pub", "Pub"], "full": true}),
        status: "ok",
        same_message: true,
    })
    .await;

    // 5. withdrawn records and changed ranges in a new zip, through --full
    let mut w = fixture("pypi-GHSA-fhq3-2gf3-8f3j.json");
    w["withdrawn"] = json!("2026-11-12T00:00:00Z");
    w["modified"] = json!("2026-11-12T00:00:00Z");
    let mut g = fixture("pypi-OSV-2022-1074.json");
    g["affected"][0]["versions"] = json!(["only"]);
    g["modified"] = json!("2026-11-12T00:00:00Z");
    put(
        "/PyPI/all.zip",
        200,
        zip_of(&[w, g, fixture("pypi-PYSEC-2021-375.json")]),
    );
    run(Step {
        what: "withdrawn and changed in a full import",
        extra: json!({"ecosystems": ["PyPI"], "full": true}),
        status: "ok",
        same_message: true,
    })
    .await;

    // 6. more than 5000 changes since the cursor: the zip instead
    let lines: String = (0..5001)
        .map(|i| format!("2026-11-13T00:00:00Z,PYSEC-MANY-{i}\n"))
        .collect();
    put("/PyPI/modified_id.csv", 200, lines.into_bytes());
    run(Step {
        what: "fallback to the zip",
        extra: json!({"ecosystems": ["PyPI"]}),
        status: "ok",
        same_message: true,
    })
    .await;

    // 7. failures: one ecosystem without a zip (partial), only failures (error; HTTP wording differs), a bad zip,
    // a release-qualified name
    run(Step {
        what: "one ecosystem fails",
        extra: json!({"ecosystems": ["PyPI", "Nope"], "full": true}),
        status: "partial",
        same_message: false,
    })
    .await;
    run(Step {
        what: "every ecosystem fails",
        extra: json!({"ecosystems": ["Nope"]}),
        status: "error",
        same_message: false,
    })
    .await;
    put("/Bad/all.zip", 200, b"not a zip".to_vec());
    run(Step {
        what: "a bad zip",
        extra: json!({"ecosystems": ["Bad"]}),
        status: "error",
        same_message: true,
    })
    .await;
    run(Step {
        what: "release-qualified",
        extra: json!({"ecosystems": ["Debian:12"]}),
        status: "error",
        same_message: true,
    })
    .await;
    d.close().await;
}

// ------------------------------------------------------------------------------------------------ raw storage

#[tokio::test(flavor = "multi_thread")]
async fn native_osv_matches_py_sources_with_raw_storage() {
    let fx = osv_dir();
    let Some(mut d) = Diff::new(&[&fx]).await else {
        return;
    };
    let python = d.python.clone();
    let dir = tempfile::tempdir().unwrap();
    let (py_store, rs_store) = (d.store("py").await, d.store("rs").await);
    // SECMONK_OSV_STORE_RAW=1 for the module process (`py_sources_env` takes the value as a path)
    let (py_src, _) = d.py_sources_env(
        &py_store,
        "modules-py",
        &[("SECMONK_OSV_STORE_RAW", Path::new("1"))],
    );
    let py = d.engine(&py_store, vec![py_src]);
    let rs = d.engine(
        &rs_store,
        vec![Arc::new(native(&rs_store).with_store_raw(true))],
    );
    let base = write_base(dir.path());
    let u1 = write_update1(dir.path());
    for (p, what) in [
        (&base, "raw: first sync"),
        (&u1, "raw: update 1"),
        (&fx.join("sample-all.zip"), "raw: zip"),
    ] {
        let a = sync_job(&py, &[SRC], p, json!({})).await;
        let b = sync_job(&rs, &[SRC], p, json!({})).await;
        check_entries(&a, &b, what);
        assert_mirrors_equal(
            &python,
            py_store.mirror_path(),
            rs_store.mirror_path(),
            what,
            TIMESTAMPS,
            &[],
        );
    }
    let n = rs_store.count_rows(T::RawRecord, SRC).await.unwrap();
    assert!(n >= 20, "raw records stored: {n}");
    d.close().await;
}

// ------------------------------------------------------------------------------------------------ row contract

#[tokio::test(flavor = "multi_thread")]
async fn native_osv_batches_follow_the_row_contract() {
    // every native osv batch and end validates against rust/contracts (source/rows, source/sync-end); applied to a
    // real store, none skipped; alias and record-keyed affected deletes and `osv:<Eco>` rows among them
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(
        &dir.path().join("state.sqlite3"),
        &dir.path().join("mirror.sqlite3"),
        &StoreOptions::default(),
    )
    .await
    .unwrap();
    let small = secmonk_sources::batch::Limits {
        ops: 7,
        bytes: 1 << 20,
    };
    let files: Files = Arc::default();
    let (url, _) = serve_files(files.clone()).await;
    let src = native(&store)
        .with_limits(small)
        .with_bucket(&url)
        .with_store_raw(true);
    let path = |p: &Path| json!({"path": p.display().to_string()});
    let base = write_base(dir.path());
    let u1 = write_update1(dir.path());
    let deletes = check_row_contract(
        &src,
        &store,
        SRC,
        &[
            path(&base),
            path(&u1),
            json!({"path": u1.display().to_string(), "limit": 1}),
            path(&dir.path().join("missing.zip")),
        ],
    )
    .await;
    assert!(deletes >= 3, "deletes: {deletes}");
    files.lock().unwrap().insert(
        "/PyPI/all.zip".into(),
        (
            200,
            zip_of(&[rec("PC-1", "2026-01-01T00:00:00Z", "PyPI", "a", "1")]),
        ),
    );
    files.lock().unwrap().insert(
        "/PyPI/modified_id.csv".into(),
        (200, b"2026-02-01T00:00:00Z,PC-1\n".to_vec()),
    );
    files.lock().unwrap().insert(
        "/PyPI/PC-1.json".into(),
        (
            200,
            serde_json::to_vec(&rec("PC-1", "2026-02-01T00:00:00Z", "PyPI", "a", "2")).unwrap(),
        ),
    );
    check_row_contract(
        &src,
        &store,
        SRC,
        &[
            json!({"ecosystems": ["PyPI"]}),
            json!({"ecosystems": ["PyPI"]}),
            json!({"ecosystems": ["PyPI"], "full": true, "limit": 1}),
        ],
    )
    .await;
    let row = store
        .rows_page(T::SourceSync, "osv:PyPI", None, 1)
        .await
        .unwrap();
    assert_eq!(row.0[0]["status"], "partial");
    assert_eq!(row.0[0]["cursor"], Value::Null);
    store.close().await;
}

// ------------------------------------------------------------------------------------------------ volume

/// A synthetic OSV corpus: `n` records over five ecosystems (one zip each), about 2 KiB per record: 1-4 affected
/// entries with an ECOSYSTEM or SEMVER range, 5-20 versions, aliases, a CVSS 3.1 vector, references, CWE ids, a purl.
/// `changed`: every third record gets another fixed version and `modified`.
/// The zips of one day: (path on the server, bytes).
type Zips = Vec<(String, Vec<u8>)>;

fn corpus(n: usize, changed: bool) -> (Zips, u64) {
    let ecos = ["PyPI", "npm", "Maven", "Debian", "Alpine"];
    let mut per: Vec<Vec<Member>> = vec![Vec::new(); ecos.len()];
    let mut rows = 0u64;
    for i in 0..n {
        let e = i % ecos.len();
        let eco = ecos[e];
        let bump = changed && i % 3 == 0;
        let k = 1 + i % 4;
        let affected: Vec<Value> = (0..k)
            .map(|j| {
                let name = format!("pkg{}-{j}", i % 4999);
                let eco_full = if eco == "Debian" { "Debian:12".to_owned() } else if eco == "Alpine" { "Alpine:v3.20".to_owned() } else { eco.to_owned() };
                let versions: Vec<String> = (0..(5 + i % 16)).map(|v| format!("1.{v}.{}", i % 7)).collect();
                json!({"package": {"name": name, "ecosystem": eco_full, "purl": format!("pkg:generic/{name}")},
                       "ranges": [{"type": if j % 2 == 0 { "ECOSYSTEM" } else { "SEMVER" },
                                   "events": [{"introduced": "0"}, {"fixed": format!("2.{}.{}", i % 13, if bump { 9 } else { 1 })}]}],
                       "versions": versions, "database_specific": {"source": format!("https://example.org/{i}")}})
            })
            .collect();
        rows += k as u64;
        let id = format!("{}-2090-{i:07}", eco.to_uppercase());
        let r = json!({"schema_version": "1.6.0", "id": id, "modified": if bump { "2026-11-12T00:00:00Z" } else { "2026-11-11T00:00:00Z" },
            "published": "2026-01-01T00:00:00Z", "aliases": [format!("CVE-2090-{i:07}")],
            "summary": format!("{id}: a synthetic vulnerability in pkg{}", i % 4999),
            "details": "A synthetic description of a vulnerability that lets a remote attacker do something unexpected via a crafted request; long enough to look like a real advisory text of a package ecosystem.",
            "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N"}],
            "database_specific": {"cwe_ids": ["CWE-79", "CWE-20"], "severity": "HIGH", "github_reviewed": true},
            "affected": affected,
            "references": [{"type": "ADVISORY", "url": format!("https://example.org/advisory/{i}")}, {"type": "WEB", "url": "https://example.org/x"}]});
        per[e].push(m(&format!("{id}.json"), &serde_json::to_vec(&r).unwrap()));
    }
    let zips = ecos
        .iter()
        .zip(per)
        .map(|(e, ms)| (format!("/{e}/all.zip"), zip_bytes(&ms)))
        .collect();
    (zips, rows)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "volume measurement, run by hand (source-osv.md)"]
async fn osv_volume_sync() {
    let n: usize = std::env::var("SECMONK_OSV_RECORDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let native_only = std::env::var("SECMONK_OSV_NATIVE_ONLY").is_ok_and(|x| x == "1");
    let py_only = std::env::var("SECMONK_OSV_PY_ONLY").is_ok_and(|x| x == "1");
    let Some(mut d) = Diff::new(&[]).await else {
        return;
    };
    let t = std::time::Instant::now();
    let (day1, rows1) = corpus(n, false);
    let (day2, _) = corpus(n, true);
    let size: usize = day1.iter().map(|(_, z)| z.len()).sum();
    eprintln!(
        "osv volume: {n} records, {rows1} affected rows, {} MiB of zips per day, generated in {:.1} s",
        size >> 20,
        t.elapsed().as_secs_f64()
    );
    let files: Files = Arc::default();
    let (url, _) = serve_files(files.clone()).await;
    let dir = tempfile::tempdir().unwrap();
    let hook = dir.path().join("osv-hook.json");
    std::fs::write(&hook, serde_json::to_vec(&json!({"bucket": url})).unwrap()).unwrap();
    let load = |day: &Zips| {
        let mut f = files.lock().unwrap();
        for (p, z) in day {
            f.insert(p.clone(), (200, z.clone()));
        }
    };
    let ecos = json!({"ecosystems": ["PyPI", "npm", "Maven", "Debian", "Alpine"], "full": true});
    let steps: [(&str, &Zips); 3] = [
        ("first sync", &day1),
        ("re-sync, changed", &day2),
        ("re-sync, unchanged", &day2),
    ];
    let mut timed = Vec::new();
    let rs_store = d.store("rs").await;
    if !py_only {
        let rs = d.engine(
            &rs_store,
            vec![Arc::new(native(&rs_store).with_bucket(&url))],
        );
        for (what, day) in &steps {
            load(day);
            let t = std::time::Instant::now();
            let job = bucket_job(&rs, &ecos).await;
            assert_eq!(status(&job), "ok", "{job:#}");
            timed.push(format!("native {what}: {:.1} s", t.elapsed().as_secs_f64()));
            if *what == "first sync" {
                assert_eq!(rs_store.count_rows(T::Affected, SRC).await.unwrap(), rows1);
            }
        }
    }
    if !native_only {
        let py_store = d.store("py").await;
        let (py_src, _) = py_hooked(
            &mut d,
            &py_store,
            "modules-py",
            &[("SECMONK_TEST_OSV_HOOK", &hook)],
        );
        let py = d.engine(&py_store, vec![py_src]);
        for (what, day) in &steps {
            load(day);
            let t = std::time::Instant::now();
            let job = bucket_job(&py, &ecos).await;
            assert_eq!(status(&job), "ok", "{job:#}");
            timed.push(format!(
                "py-sources {what}: {:.1} s",
                t.elapsed().as_secs_f64()
            ));
        }
        if !py_only {
            assert_mirrors_equal(
                &d.python,
                py_store.mirror_path(),
                rs_store.mirror_path(),
                "volume",
                TIMESTAMPS,
                &[],
            );
        }
    }
    eprintln!("osv volume: {}", timed.join("; "));
    d.close().await;
}
