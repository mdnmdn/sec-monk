//! The native CVE List source over an in-memory mirror (`common::MemView`): the fixture's rows, a second run (records
//! not newer are skipped), `--full` with a limit, updates and a record twice in one run, per-record errors, groups
//! larger than one `rows_by_id` read, the ids mode against a local server (never the network), and the git mode
//! against a local repository built at test time (clone, unchanged re-sync, diff of a new commit, record errors that
//! hold the cursor back, a foreign origin, a stored cursor that is not a commit, a symlink out of the clone, a missing
//! git program). Fixtures: `tests/fixtures/sources/cvelist` of the repository (real records, read only); everything
//! else is written at test time (synthetic). The comparison with the Python source is
//! `secmonk-engine/tests/native_cvelist.rs`.

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use common::{MemView, of, ops, serve_logged};
use secmonk_model::{JsonMap, MirrorTable, RowOp};
use secmonk_sources::batch::Limits;
use secmonk_sources::cvelist::{Caps, CvelistSource, GIT_KEY, YEARS_KEY};
use secmonk_traits::{RowsBatch, SyncEnd};
use serde_json::{Value, json};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/fixtures/sources/cvelist")
}

async fn run(src: &CvelistSource, options: Value) -> (Vec<RowsBatch>, SyncEnd, Vec<String>) {
    common::run(src, "cvelist", options).await
}

/// Run and apply to the in-memory mirror.
async fn sync(
    view: &Arc<MemView>,
    src: &CvelistSource,
    options: Value,
) -> (Vec<RowOp>, SyncEnd, Vec<String>) {
    let (b, end, lines) = run(src, options).await;
    view.apply(&b);
    (ops(&b), end, lines)
}

fn path_opts(p: &Path) -> Value {
    json!({"path": p.display().to_string()})
}

/// A synthetic record: one CNA `affected` entry (`acme` / `widget`, the given versions).
fn rec(id: &str, updated: &str, desc: &str, versions: Value) -> Value {
    json!({"dataType": "CVE_RECORD", "dataVersion": "5.1",
           "cveMetadata": {"cveId": id, "state": "PUBLISHED", "dateUpdated": updated,
                           "datePublished": "2026-01-01T00:00:00.000Z", "assignerShortName": "acme"},
           "containers": {"cna": {"descriptions": [{"lang": "en", "value": desc}],
                                  "affected": [{"vendor": "acme", "product": "widget", "versions": versions}]}}})
}

fn write(dir: &Path, rel: &str, doc: &Value) -> PathBuf {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(&p, serde_json::to_vec_pretty(doc).unwrap()).unwrap();
    p
}

fn rows_of(view: &MemView, table: MirrorTable, id: &str) -> Vec<JsonMap> {
    let col = if table == MirrorTable::Vulnerability {
        "id"
    } else {
        "vuln_id"
    };
    view.rows(table)
        .into_iter()
        .filter(|r| r.get(col).and_then(Value::as_str) == Some(id))
        .collect()
}

fn sync_row(view: &MemView, key: &str) -> Option<JsonMap> {
    view.rows(MirrorTable::SourceSync)
        .into_iter()
        .find(|r| r["source"] == key)
}

fn count_files(dir: &Path) -> usize {
    let mut n = 0;
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            n += count_files(&p);
        } else if e.file_name().to_string_lossy().starts_with("CVE-")
            && p.extension().is_some_and(|x| x == "json")
        {
            n += 1;
        }
    }
    n
}

#[tokio::test]
async fn the_fixture_directory_becomes_vulnerability_raw_and_affected_rows() {
    let view = MemView::new();
    let src = CvelistSource::new(view.clone());
    let n = count_files(&fixtures()) as u64;
    assert!(n >= 20, "{n}");
    let (all, end, _) = sync(&view, &src, path_opts(&fixtures())).await;
    assert_eq!(end.entry.status, "ok", "{end:?}");
    assert_eq!(end.entry.records, n);
    assert_eq!(
        end.entry.message.as_deref(),
        Some(format!("imported {n} from {}", fixtures().display()).as_str())
    );
    assert_eq!(view.rows(MirrorTable::Vulnerability).len() as u64, n);
    assert_eq!(view.rows(MirrorTable::RawRecord).len() as u64, n);
    assert_eq!(sync_row(&view, "cvelist").unwrap()["records"], json!(n));
    // Log4Shell: lessThan "log4j-core*" with changes[]; CISA-ADP SSVC and CVSS
    let v = &rows_of(&view, MirrorTable::Vulnerability, "CVE-2021-44228")[0];
    assert_eq!(v["cvss_score"], json!(10.0));
    assert_eq!(v["extra"]["cvss_source"], "adp:CISA-ADP");
    assert!(v["extra"]["ssvc"]["Exploitation"].is_string(), "{v:?}");
    let ev: Vec<Value> = rows_of(&view, MirrorTable::Affected, "CVE-2021-44228")
        .into_iter()
        .map(|r| r["events"].clone())
        .collect();
    assert!(
        ev.contains(
            &json!([{"introduced": "2.0-beta9"}, {"fixed": "2.3.1"}, {"introduced": "2.4"},
                                {"fixed": "2.12.2"}, {"introduced": "2.13.0"}, {"fixed": "2.15.0"}])
        ),
        "{ev:?}"
    );
    // rejected: no affected rows, withdrawn set
    let r = &rows_of(&view, MirrorTable::Vulnerability, "CVE-2025-24468")[0];
    assert_eq!(r["state"], "REJECTED");
    assert!(r["withdrawn"].is_string());
    assert!(rows_of(&view, MirrorTable::Affected, "CVE-2025-24468").is_empty());
    // npm package from collectionURL; Firefox unaffected-only; cpeApplicability rows
    let npm = rows_of(&view, MirrorTable::Affected, "CVE-2025-7783");
    assert!(
        npm.iter()
            .all(|r| r["ecosystem"] == "npm" && r["package"] == "form-data"),
        "{npm:?}"
    );
    let ff = rows_of(&view, MirrorTable::Affected, "CVE-2025-1013");
    assert!(ff.iter().all(|r| r["status"] == "unaffected"), "{ff:?}");
    let office = rows_of(&view, MirrorTable::Affected, "CVE-2025-24077");
    assert!(office.iter().any(|r| r["range_type"] == "CPE"));
    assert!(
        office
            .iter()
            .any(|r| r["range_type"] == "CVE-UNPARSED" && r["extra"]["dropped_bounds"].is_object())
    );
    assert!(
        of(&all, MirrorTable::Affected, false).is_empty(),
        "nothing stored before"
    );

    // again: nothing newer, only the source_sync row
    let (again, end, _) = sync(&view, &src, path_opts(&fixtures())).await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 0));
    assert_eq!(again.len(), 1, "{again:?}");
    assert_eq!(
        sync_row(&view, "cvelist").unwrap()["records"],
        json!(n),
        "the total stays"
    );

    // --full with a limit: two records rewritten, equal affected rows not rewritten; the limit is not partial here
    let (full, end, _) = sync(
        &view,
        &src,
        json!({"path": fixtures().display().to_string(), "full": true, "limit": 2}),
    )
    .await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("ok", 2),
        "{end:?}"
    );
    assert_eq!(of(&full, MirrorTable::Vulnerability, true).len(), 2);
    assert!(of(&full, MirrorTable::Affected, false).is_empty());

    // one file
    let (_, end, _) = sync(
        &view,
        &src,
        json!({"path": fixtures().join("CVE-2025-1914.json").display().to_string(), "full": true}),
    )
    .await;
    assert_eq!(end.entry.records, 1);
}

#[tokio::test]
async fn updates_repeats_and_record_errors() {
    let view = MemView::new();
    let src = CvelistSource::new(view.clone()).with_limits(Limits {
        ops: 3,
        bytes: 1 << 20,
    });
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    let v1 =
        json!([{"version": "1.0", "lessThan": "2.0", "status": "affected"}, {"version": "3.0"}]);
    write(
        d,
        "a/CVE-2026-0001.json",
        &rec(
            "CVE-2026-0001",
            "2026-01-01T00:00:00.000Z",
            "one",
            v1.clone(),
        ),
    );
    write(
        d,
        "a/CVE-2026-0002.json",
        &rec(
            "CVE-2026-0002",
            "2026-01-01T00:00:00.000Z",
            "two",
            v1.clone(),
        ),
    );
    let (_, end, _) = sync(&view, &src, path_opts(d)).await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 2));
    assert_eq!(view.rows(MirrorTable::Affected).len(), 4);

    // an update of 0001 (newer), the same id again later in the walk (newer still), one not newer, errors
    let v2 = json!([{"version": "1.5", "lessThan": "2.0", "status": "affected"}]);
    write(
        d,
        "a/CVE-2026-0001.json",
        &rec(
            "CVE-2026-0001",
            "2026-02-01T00:00:00.000Z",
            "one v2",
            v2.clone(),
        ),
    );
    write(
        d,
        "b/CVE-2026-0001-again.json",
        &rec(
            "CVE-2026-0001",
            "2026-03-01T00:00:00.000Z",
            "one v3",
            json!([]),
        ),
    );
    write(
        d,
        "b/CVE-2026-0001-older.json",
        &rec(
            "CVE-2026-0001",
            "2026-02-15T00:00:00.000Z",
            "older",
            v1.clone(),
        ),
    );
    let mut bad = rec(
        "CVE-2026-0002",
        "2026-05-01T00:00:00.000Z",
        "bad",
        v1.clone(),
    );
    bad["containers"]["cna"]["metrics"] =
        json!([{"cvssV3_1": {"baseScore": "n/a", "version": "3.1"}}]);
    write(d, "c/CVE-2026-0002.json", &bad);
    write(
        d,
        "c/CVE-2026-0003.json",
        &rec(
            "CVE-2026-0003",
            "2026-01-01T00:00:00.000Z",
            "three",
            json!("x"),
        ),
    );
    write(d, "c/CVE-not-a-record.json", &json!([1, 2]));
    write(d, "c/CVE-no-meta.json", &json!({"x": 1}));
    std::fs::write(d.join("c/CVE-latin1.json"), b"{\"x\": \"caf\xe9\"}").unwrap();
    std::fs::create_dir_all(d.join("c/CVE-dir.json")).unwrap();
    write(
        d,
        "c/other.json",
        &rec(
            "CVE-2026-0009",
            "2026-01-01T00:00:00.000Z",
            "not walked",
            json!([]),
        ),
    );
    let (all, end, lines) = sync(&view, &src, path_opts(d)).await;
    assert_eq!(end.entry.status, "partial", "{end:?} {lines:?}");
    assert_eq!(
        end.entry.records, 3,
        "0001 twice, 0003 (strings iterate as characters, none a dict)"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("skipping") && l.contains("ValueError")),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.contains("CVE-latin1.json") && l.contains("UnicodeDecodeError")),
        "{lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("CVE-dir.json")),
        "{lines:?}"
    );
    let v = &rows_of(&view, MirrorTable::Vulnerability, "CVE-2026-0001")[0];
    assert_eq!(v["summary"], "one v3");
    assert!(rows_of(&view, MirrorTable::Affected, "CVE-2026-0001").is_empty());
    // the failed record left the stored one as it was
    assert_eq!(
        rows_of(&view, MirrorTable::Vulnerability, "CVE-2026-0002")[0]["summary"],
        "two"
    );
    assert_eq!(
        rows_of(&view, MirrorTable::Affected, "CVE-2026-0002").len(),
        2
    );
    assert!(rows_of(&view, MirrorTable::Vulnerability, "CVE-2026-0009").is_empty());
    // record-keyed deletes of the stored rows, then of the rows emitted earlier in the run
    let dels = of(&all, MirrorTable::Affected, false);
    assert_eq!(dels.len(), 3, "{dels:?}");
    assert!(
        dels.iter()
            .all(|k| k.len() == 2 && k["vuln_id"] == "CVE-2026-0001")
    );
    assert_eq!(
        sync_row(&view, "cvelist").unwrap()["records"],
        json!(3),
        "0001, 0002, 0003"
    );
}

#[tokio::test]
async fn groups_beyond_one_read_and_progress_lines() {
    let view = MemView::new();
    let src = CvelistSource::new(view.clone());
    let dir = tempfile::tempdir().unwrap();
    for i in 0..1203 {
        let id = format!("CVE-2026-{:05}", 10000 + i);
        write(
            dir.path(),
            &format!("{}/{id}.json", i % 7),
            &rec(
                &id,
                "2026-01-01T00:00:00.000Z",
                "x",
                json!([{"version": "1.0"}]),
            ),
        );
    }
    let (_, end, lines) = sync(&view, &src, path_opts(dir.path())).await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 1203));
    assert!(
        lines.contains(&"cvelist: 500 records".to_owned()),
        "{lines:?}"
    );
    assert!(
        lines.contains(&"cvelist: 1000 records".to_owned()),
        "{lines:?}"
    );
    let (_, end, _) = sync(
        &view,
        &src,
        json!({"path": dir.path().display().to_string(), "full": true}),
    )
    .await;
    assert_eq!(end.entry.records, 1203);
    assert_eq!(
        view.rows(MirrorTable::Affected).len(),
        1203,
        "equal rows are not rewritten"
    );
}

#[tokio::test]
async fn path_errors_and_options() {
    let view = MemView::new();
    let src = CvelistSource::new(view.clone());
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing");
    let (b, end, _) = run(&src, path_opts(&missing)).await;
    assert_eq!(end.entry.status, "error");
    assert_eq!(
        end.entry.message,
        Some(format!("path not found: {}", missing.display()))
    );
    assert_eq!(ops(&b).len(), 1);
    #[cfg(unix)]
    {
        let fifo = dir.path().join("fifo");
        assert!(
            Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .unwrap()
                .success()
        );
        let (_, end, _) = run(&src, path_opts(&fifo)).await;
        assert_eq!(end.entry.status, "error");
        assert!(
            end.entry
                .message
                .unwrap()
                .contains("not a regular file or a directory")
        );
    }
    let big = write(
        dir.path(),
        "CVE-2026-0001.json",
        &rec("CVE-2026-0001", "2026", "x", json!([])),
    );
    let small = CvelistSource::new(view.clone()).with_caps(Caps {
        file_bytes: 10,
        ..Caps::default()
    });
    let (_, end, lines) = run(&small, path_opts(&big)).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("partial", 0)
    );
    assert!(
        lines.iter().any(|l| l.contains("larger than 10 bytes")),
        "{lines:?}"
    );
    let few = CvelistSource::new(view.clone()).with_caps(Caps {
        files: 0,
        ..Caps::default()
    });
    let (_, end, _) = run(&few, path_opts(dir.path())).await;
    assert_eq!(end.entry.status, "error");
    assert!(end.entry.message.unwrap().contains("more than 0 files"));
    let e = secmonk_traits::Source::sync(
        &src,
        common::params("cvelist", json!({"limit": 0})),
        Default::default(),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(e.code, secmonk_traits::ErrorCode::InvalidParams);
    let (_, end, _) = run(&src, json!({"ids": ["@referenced"]})).await;
    assert_eq!(end.entry.status, "error");
    assert!(end.entry.message.unwrap().contains("python implementation"));
}

#[tokio::test]
async fn the_ids_mode_fetches_raw_records() {
    let view = MemView::new();
    let good = rec(
        "CVE-2026-1001",
        "2026-01-01T00:00:00.000Z",
        "fetched",
        json!([{"version": "1.0"}]),
    );
    let mut bad = rec(
        "CVE-2026-1002",
        "2026-01-01T00:00:00.000Z",
        "bad",
        json!([]),
    );
    bad["containers"]["cna"]["metrics"] = json!(["junk"]);
    let (url, log) = serve_logged(vec![
        (200, serde_json::to_vec(&bad).unwrap()),
        (404, b"no".to_vec()),
        (500, b"oops".to_vec()),
        (200, b"{".to_vec()),
        (200, serde_json::to_vec(&good).unwrap()),
    ])
    .await;
    let src = CvelistSource::new(view.clone()).with_raw_base(&format!("{url}/main/"));
    let (_, end, lines) = sync(
        &view,
        &src,
        json!({"ids": [" cve-2026-1002 ", "CVE-2026-1003", "CVE-2026-1004",
        "CVE-2026-1005", "GHSA-x", "CVE-2026-1001"]}),
    )
    .await;
    assert_eq!(end.entry.status, "partial", "{end:?} {lines:?}");
    assert_eq!(end.entry.records, 1);
    assert_eq!(end.entry.message.as_deref(), Some("fetched 1 ids"));
    assert_eq!(
        log.lock().unwrap().clone(),
        vec![
            "GET /main/cves/2026/1xxx/CVE-2026-1002.json HTTP/1.1",
            "GET /main/cves/2026/1xxx/CVE-2026-1003.json HTTP/1.1",
            "GET /main/cves/2026/1xxx/CVE-2026-1004.json HTTP/1.1",
            "GET /main/cves/2026/1xxx/CVE-2026-1005.json HTTP/1.1",
            "GET /main/cves/2026/1xxx/CVE-2026-1001.json HTTP/1.1",
        ]
    );
    assert!(
        lines.contains(&"cvelist: CVE-2026-1003 not found".to_owned()),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("cvelist: GHSA-X: ValueError")),
        "{lines:?}"
    );
    assert_eq!(
        rows_of(&view, MirrorTable::Vulnerability, "CVE-2026-1001")[0]["summary"],
        "fetched"
    );
    // the limit stops before the next request
    let (url, log) = serve_logged(vec![(200, serde_json::to_vec(&good).unwrap())]).await;
    let src = CvelistSource::new(view.clone()).with_raw_base(&format!("{url}/"));
    let (_, end, _) = run(
        &src,
        json!({"ids": ["CVE-2026-1001", "CVE-2026-1002"], "limit": 1}),
    )
    .await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 1));
    assert_eq!(log.lock().unwrap().len(), 1);
}

// ------------------------------------------------------------------------------------------------ git mode

/// Whether `git` runs; missing: skipped, or a failure with `SECMONK_REQUIRE_VENV=1` / `SECMONK_REQUIRE_GIT=1`.
fn have_git() -> bool {
    if Command::new("git")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success())
    {
        return true;
    }
    let strict = ["SECMONK_REQUIRE_VENV", "SECMONK_REQUIRE_GIT"]
        .iter()
        .any(|k| std::env::var(k).as_deref() == Ok("1"));
    assert!(
        !strict,
        "git is required (SECMONK_REQUIRE_VENV=1 or SECMONK_REQUIRE_GIT=1) but does not run"
    );
    eprintln!("git not found: cvelist git-mode test skipped");
    false
}

/// A local upstream repository (a working tree on `main`, serving partial clones).
struct Origin {
    path: PathBuf,
}

fn git(cwd: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
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

    fn put(&self, year: i64, n: u32, desc: &str, updated: &str) -> String {
        let id = format!("CVE-{year}-{n:04}");
        write(
            &self.path,
            &format!("cves/{year}/{}xxx/{id}.json", n / 1000),
            &rec(
                &id,
                updated,
                desc,
                json!([{"version": "1.0", "lessThan": "2.0"}]),
            ),
        );
        id
    }

    fn commit(&self) -> String {
        git(&self.path, &["add", "-A"]);
        git(&self.path, &["commit", "-qm", "c", "--allow-empty"]);
        git(&self.path, &["rev-parse", "HEAD"])
    }
}

fn year() -> i64 {
    secmonk_model::time::now_iso()[..4].parse().unwrap()
}

fn summaries(view: &MemView) -> std::collections::BTreeMap<String, String> {
    view.rows(MirrorTable::Vulnerability)
        .into_iter()
        .map(|r| {
            (
                r["id"].as_str().unwrap().to_owned(),
                r["summary"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_git_mode_clones_diffs_and_keeps_its_cursor() {
    if !have_git() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let origin = Origin::new(dir.path().join("origin"));
    let y = year();
    let a = origin.put(y, 1001, "a v1", "2026-01-01T00:00:00.000Z");
    let b = origin.put(y - 1, 2002, "b v1", "2026-01-01T00:00:00.000Z");
    let old = origin.put(y - 5, 5000, "old v1", "2024-01-01T00:00:00.000Z");
    let c1 = origin.commit();
    let view = MemView::new();
    let cache = dir.path().join("cache");
    let src = CvelistSource::new(view.clone())
        .with_repo_url(&origin.url())
        .with_cache_dir(&cache);

    // 1. a fresh clone walks the previous and current year
    let (_, end, lines) = sync(&view, &src, json!({})).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("ok", 2),
        "{end:?} {lines:?}"
    );
    assert!(
        lines.contains(&"cvelist: cloning (partial, sparse)".to_owned()),
        "{lines:?}"
    );
    assert_eq!(
        end.entry.message,
        Some(format!("git {}, years {}..{y}", &c1[..10], y - 1))
    );
    assert_eq!(sync_row(&view, GIT_KEY).unwrap()["cursor"], json!(c1));
    assert_eq!(
        sync_row(&view, YEARS_KEY).unwrap()["cursor"],
        json!((y - 1).to_string())
    );
    assert_eq!(sync_row(&view, "cvelist").unwrap()["cursor"], json!(c1));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    // 2. unchanged
    let (o, end, _) = sync(&view, &src, json!({})).await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 0));
    assert_eq!(o.len(), 3, "the two internal rows and source_sync: {o:?}");

    // 3. a new commit: only the changed file is read; a record error holds the cursor back
    origin.put(y, 1001, "a v2", "2026-02-01T00:00:00.000Z");
    let bad = format!("CVE-{y}-1003");
    let mut r = rec(&bad, "2026-02-01T00:00:00.000Z", "bad", json!([]));
    r["containers"]["cna"]["metrics"] = json!(["junk"]);
    write(&origin.path, &format!("cves/{y}/1xxx/{bad}.json"), &r);
    let c2 = origin.commit();
    let (_, end, _) = sync(&view, &src, json!({})).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("partial", 1),
        "{end:?}"
    );
    assert!(
        end.entry
            .message
            .as_deref()
            .unwrap()
            .ends_with(", 1 record errors")
    );
    assert_eq!(
        sync_row(&view, GIT_KEY).unwrap()["cursor"],
        json!(c1),
        "not advanced"
    );
    assert_eq!(summaries(&view)[&a], "a v2");
    // fixed: the diff from the stored cursor covers both commits
    write(
        &origin.path,
        &format!("cves/{y}/1xxx/{bad}.json"),
        &rec(&bad, "2026-02-02T00:00:00.000Z", "fixed", json!([])),
    );
    std::fs::remove_file(origin.path.join(format!("cves/{}/2xxx/{b}.json", y - 1))).unwrap();
    let c3 = origin.commit();
    let (_, end, _) = sync(&view, &src, json!({})).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("ok", 1),
        "{end:?}"
    );
    assert_eq!(sync_row(&view, GIT_KEY).unwrap()["cursor"], json!(c3));
    assert!(
        summaries(&view).contains_key(&b),
        "a file removed upstream keeps its rows"
    );
    let _ = c2;

    // 4. --since widens the years (the new year walked in full) and the plain sync keeps them
    let (_, end, _) = sync(&view, &src, json!({"since": format!("{}-06-01", y - 5)})).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("ok", 1),
        "{end:?}"
    );
    assert_eq!(
        sync_row(&view, YEARS_KEY).unwrap()["cursor"],
        json!((y - 5).to_string())
    );
    origin.put(y - 5, 5000, "old v2", "2026-11-01T00:00:00.000Z");
    origin.commit();
    let (_, end, _) = sync(&view, &src, json!({})).await;
    assert_eq!(end.entry.records, 1);
    assert_eq!(summaries(&view)[&old], "old v2");

    // 5. --full with a limit: partial, cursor not advanced
    origin.put(y, 1004, "d", "2026-03-01T00:00:00.000Z");
    let c5 = origin.commit();
    let (_, end, _) = sync(&view, &src, json!({"full": true, "limit": 1})).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("partial", 1),
        "{end:?}"
    );
    assert!(
        end.entry
            .message
            .as_deref()
            .unwrap()
            .contains(", limit reached")
    );
    assert_ne!(sync_row(&view, GIT_KEY).unwrap()["cursor"], json!(c5));
    let (_, end, _) = sync(&view, &src, json!({"full": true})).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("ok", 4),
        "{end:?}"
    );
    assert_eq!(sync_row(&view, GIT_KEY).unwrap()["cursor"], json!(c5));

    // 6. a stored cursor that is not a commit is not passed to git; an unknown commit falls back to the walk
    view.apply(&[RowsBatch {
        kind: "rows".into(),
        seq: 0,
        source: "cvelist".into(),
        ops: vec![RowOp::Upsert {
            table: MirrorTable::SourceSync,
            row: json!({"source": GIT_KEY, "cursor": "--output=/tmp/cvelist-should-not-exist", "status": "ok"})
                .as_object().unwrap().clone(),
        }],
        generation: None,
        acked_through: None,
    }]);
    origin.put(y, 1001, "a v3", "2026-04-01T00:00:00.000Z");
    origin.commit();
    let (_, end, _) = sync(&view, &src, json!({})).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("ok", 1),
        "{end:?}"
    );
    assert!(!Path::new("/tmp/cvelist-should-not-exist").exists());
    let mut row = sync_row(&view, GIT_KEY).unwrap();
    row.insert("cursor".into(), json!("f".repeat(40)));
    view.apply(&[RowsBatch {
        kind: "rows".into(),
        seq: 0,
        source: "cvelist".into(),
        ops: vec![RowOp::Upsert {
            table: MirrorTable::SourceSync,
            row,
        }],
        generation: None,
        acked_through: None,
    }]);
    origin.put(y, 1001, "a v4", "2026-05-01T00:00:00.000Z");
    origin.commit();
    let (_, end, lines) = sync(&view, &src, json!({})).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("ok", 1),
        "{end:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("diff unavailable")),
        "{lines:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_git_mode_refuses_foreign_caches_symlinks_and_a_missing_git() {
    if !have_git() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let origin = Origin::new(dir.path().join("origin"));
    let y = year();
    let a = origin.put(y, 1001, "v1", "2026-01-01T00:00:00.000Z");
    origin.commit();
    let view = MemView::new();
    let cache = dir.path().join("cache");

    // a cache with another origin and a hostile fsmonitor: never run, re-cloned
    let marker = dir.path().join("PWNED");
    let evil = dir.path().join("evil.sh");
    std::fs::write(&evil, format!("#!/bin/sh\ntouch {}\n", marker.display())).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&evil, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::create_dir_all(cache.join(".git")).unwrap();
    std::fs::write(
        cache.join(".git/config"),
        format!("[core]\n\trepositoryformatversion = 0\n\tfsmonitor = {}\n[remote \"origin\"]\n\turl = https://evil.example/x.git\n", evil.display()),
    )
    .unwrap();
    std::fs::write(cache.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
    let src = CvelistSource::new(view.clone())
        .with_repo_url(&origin.url())
        .with_cache_dir(&cache);
    let (_, end, lines) = sync(&view, &src, json!({})).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("ok", 1),
        "{end:?} {lines:?}"
    );
    assert!(
        lines.iter().any(|l| l.contains("foreign/unknown origin")),
        "{lines:?}"
    );
    assert!(!marker.exists());
    assert_eq!(
        git(&cache, &["config", "--local", "--get", "remote.origin.url"]),
        origin.url()
    );

    // a file of the clone that is a symlink out of it: refused (a record error), never read
    #[cfg(unix)]
    {
        let outside = write(
            dir.path(),
            "outside.json",
            &rec(&format!("CVE-{y}-1999"), "2026", "outside", json!([])),
        );
        let link = origin.path.join(format!("cves/{y}/1xxx/CVE-{y}-1999.json"));
        std::os::unix::fs::symlink(&outside, &link).unwrap();
        origin.commit();
        let (_, end, lines) = sync(&view, &src, json!({})).await;
        assert_eq!(
            (end.entry.status.as_str(), end.entry.records),
            ("partial", 0),
            "{end:?} {lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("outside the boundary")),
            "{lines:?}"
        );
        assert!(!summaries(&view).contains_key(&format!("CVE-{y}-1999")));
    }

    // the cache directory is a symlink: refused
    #[cfg(unix)]
    {
        let real = dir.path().join("real-cache");
        std::fs::create_dir_all(&real).unwrap();
        let linked = dir.path().join("linked-cache");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        let src = CvelistSource::new(view.clone())
            .with_repo_url(&origin.url())
            .with_cache_dir(&linked);
        let (_, end, _) = run(&src, json!({})).await;
        assert_eq!(end.entry.status, "error");
        assert!(
            end.entry
                .message
                .unwrap()
                .contains("is a symlink; refusing to use it")
        );
    }

    // no git program; an origin that does not exist
    let src = CvelistSource::new(view.clone())
        .with_repo_url(&origin.url())
        .with_cache_dir(&dir.path().join("c2"))
        .with_git("/nonexistent/git");
    let (b, end, _) = run(&src, json!({})).await;
    assert_eq!(end.entry.status, "error");
    assert!(
        end.entry
            .message
            .as_deref()
            .unwrap()
            .starts_with("git failed: [Errno 2]"),
        "{end:?}"
    );
    assert_eq!(ops(&b).len(), 1);
    let src = CvelistSource::new(view.clone())
        .with_repo_url(&format!("file://{}", dir.path().join("nowhere").display()))
        .with_cache_dir(&dir.path().join("c3"));
    let (_, end, _) = run(&src, json!({})).await;
    assert_eq!(end.entry.status, "error");
    assert!(
        end.entry
            .message
            .as_deref()
            .unwrap()
            .starts_with("git failed: "),
        "{end:?}"
    );
    assert!(summaries(&view).contains_key(&a));
}
