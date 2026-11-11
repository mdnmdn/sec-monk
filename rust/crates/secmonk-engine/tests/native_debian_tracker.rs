//! Differential test of the native debian-tracker importer against `py-sources` (stage 6, rust ADR-0011 / ADR-0012):
//! both through the engine on their own mirrors (JSON and repository checkout, updates, the guard, limit, errors, and
//! tables of exactly one and two full `rows_page` pages on the real store), then a mirror that switches between the
//! two implementations; the row-contract check of the native batches; and the volume measurements of
//! rust/_docs/tech/source-debian-tracker.md (ignored). Harness: `common/`. Fixtures:
//! `tests/fixtures/sources/debian-tracker/` (synthetic, read only); the variants are written at test time (synthetic).

mod common;

use common::*;

const SRC: &str = "debian-tracker";
const TIMESTAMPS: &[&str] = &["raw_record.fetched_at", "source_sync.last_sync"];

fn fixtures() -> PathBuf {
    rust_root().join("../tests/fixtures/sources/debian-tracker")
}

fn native(store: &SqliteStore) -> Arc<dyn Source> {
    Arc::new(secmonk_sources::debian_tracker::DebianTrackerSource::new(
        Diff::view(store),
    ))
}

fn write(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, data).unwrap();
    p
}

fn sample_doc() -> Value {
    serde_json::from_slice(&std::fs::read(fixtures().join("tracker-sample.json")).unwrap()).unwrap()
}

/// The sample changed: `tor` and the bullseye release of `openssh` removed, statuses, urgencies and no-dsa fields
/// changed (a `*` urgency, a `nodsa_reason`, a fixed version `0`), TEMP and unknown releases, a package in upper case
/// colliding with an existing one (the later key in sorted order counts), a new package. Synthetic.
fn update_doc() -> Value {
    let mut doc = sample_doc();
    let m = doc.as_object_mut().unwrap();
    m.remove("tor");
    if let Some(r) = m["openssh"]["CVE-2024-6387"]["releases"].as_object_mut() {
        r.remove("bullseye");
    }
    let curl = &mut m["curl"]["CVE-2023-38545"]["releases"]["bookworm"];
    curl["status"] = json!("open");
    curl["urgency"] = json!("medium*");
    curl["nodsa"] = json!(" Minor issue ");
    curl["nodsa_reason"] = json!("postponed");
    curl.as_object_mut().unwrap().remove("fixed_version");
    m.insert(
        "Zz-New".into(),
        json!({
            "CVE-2026-0001": {"releases": {"trixie": {"status": "resolved", "fixed_version": "0", "urgency": "low"},
                                           "etch": {"status": "open"}, "sid": {"status": "open"},
                                           "bookworm": {"status": "open", "nodsa": ""}}},
            "TEMP-0000000-ABCDEF": {"releases": {"trixie": {"status": "open"}}},
            "CVE-2026-0002": {"releases": {}}
        }),
    );
    m.insert(
        "zz-new".into(),
        json!({"CVE-2026-0001": {"releases": {"trixie": {"status": "open", "urgency": "high"}}}}),
    );
    doc
}

/// `n` packages with one CVE each in bookworm and trixie (`2n` rows); `variant` changes the status of every third row.
fn big_doc(n: usize, variant: bool) -> Vec<u8> {
    let mut m = serde_json::Map::new();
    for i in 0..n {
        let st = if variant && i % 3 == 0 {
            "resolved"
        } else {
            "open"
        };
        m.insert(
            format!("pkg{i:06}"),
            json!({format!("CVE-2026-{:05}", i % 50_000 + 10_000): {"releases": {
                "bookworm": {"status": st, "urgency": "low", "fixed_version": if st == "resolved" { json!("1.0-1") } else { Value::Null }},
                "trixie": {"status": "open"}}}}),
        );
    }
    serde_json::to_vec(&Value::Object(m)).unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn native_debian_tracker_matches_py_sources() {
    let fx = fixtures();
    let sample = fx.join("tracker-sample.json");
    let repo = fx.join("repo");
    let Some(mut d) = Diff::new(&[&sample, &repo]).await else {
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
    let count = || {
        let store = rs_store.clone();
        async move {
            store
                .count_rows(secmonk_model::MirrorTable::DistroTriage, SRC)
                .await
                .unwrap()
        }
    };
    let status = |b: &Value| entry_of(b)["status"].as_str().unwrap().to_owned();

    // 1. the JSON fixture; the switch mirror on py-sources
    let b = step(sample.clone(), json!({}), "first sync").await;
    assert_eq!(status(&b), "ok", "{b:#}");
    assert_eq!(entry_of(&b)["records"], 33);
    same("first sync");
    assert_eq!(count().await, 33, "the comparison is not vacuous");
    let job = sync_job(&switch_py, &[SRC], &sample, json!({})).await;
    assert_eq!(status(&job), "ok", "{job:#}");

    // 2. the same file again
    step(sample.clone(), json!({}), "second sync").await;
    same("second sync");

    // 3. an update: removed, changed and added rows, odd fields
    let updated = write(
        dir.path(),
        "update.json",
        &serde_json::to_vec_pretty(&update_doc()).unwrap(),
    );
    let b = step(updated.clone(), json!({}), "update").await;
    assert_eq!(status(&b), "ok", "{b:#}");
    same("update");

    // the switch mirror: the native importer for the same update
    let job = sync_job(&switch_rs, &[SRC], &updated, json!({})).await;
    assert_eq!(status(&job), "ok", "{job:#}");
    assert!(
        job["log"]
            .to_string()
            .contains("debian-tracker: native importer: applied state of generation "),
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

    // 3a. a failed and a limited Python run after the native one: nothing applied, native state kept
    // an empty directory: a checkout without lists, no rows, the guard refuses (the engine refuses a missing path)
    let missing = dir.path().join("empty-checkout");
    std::fs::create_dir(&missing).unwrap();
    for (path, extra) in [(&missing, json!({})), (&updated, json!({"limit": 2}))] {
        let job = sync_job(&switch_py, &[SRC], path, extra).await;
        let e = entry_of(&job);
        assert_eq!(e["status"], "error", "{job:#}");
        assert!(
            e["message"].as_str().unwrap().ends_with(
                "; not applied: mirror keeps the native importer data until a successful py-sources sync"
            ),
            "{job:#}"
        );
        assert_mirrors_equal(
            &python,
            py_store.mirror_path(),
            switch_store.mirror_path(),
            "a failed Python run after Rust",
            TIMESTAMPS,
            &[],
        );
        let st = switch_store.applied_state(SRC).await.unwrap().unwrap();
        assert_eq!(
            st.generation.as_deref(),
            Some(secmonk_traits::NATIVE_GENERATION)
        );
    }

    // 3b. back to py-sources: repair from the staging export
    let job = sync_job(&switch_py, &[SRC], &updated, json!({})).await;
    assert_eq!(status(&job), "ok", "{job:#}");
    assert!(
        job["log"]
            .to_string()
            .contains("repaired from the staging export"),
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

    // 4. the repository checkout (advisories, sid propagation; the JSON-only rows are deleted), then the JSON again
    let b = step(repo.clone(), json!({}), "repo checkout").await;
    assert_eq!(status(&b), "ok", "{b:#}");
    assert_eq!(entry_of(&b)["records"], 31);
    same("repo checkout");
    step(sample.clone(), json!({}), "JSON after the checkout").await;
    same("JSON after the checkout");

    // 5. gzip, a UTF-8 BOM, and a gzip with trailing data after the member (ignored by both)
    let text = std::fs::read(&sample).unwrap();
    let gz = write(
        dir.path(),
        "tracker.json.gz",
        &gzip(&serde_json::to_vec(&update_doc()).unwrap()),
    );
    step(gz, json!({}), "gzip").await;
    same("gzip");
    let mut bom = b"\xef\xbb\xbf".to_vec();
    bom.extend_from_slice(&text);
    let bom = write(dir.path(), "bom.json", &bom);
    step(bom, json!({}), "BOM").await;
    same("BOM");
    let mut trailing = gzip(&text);
    trailing.extend_from_slice(b"trailing bytes");
    let trailing = write(dir.path(), "trailing.gz", &trailing);
    step(trailing, json!({}), "gzip trailing data").await;
    same("gzip trailing data");

    // 6. limits: JSON (first packages by name) and checkout (first package names)
    for (p, n) in [(&updated, 3), (&repo, 2)] {
        let b = step(p.clone(), json!({"limit": n}), "limit").await;
        assert_eq!(status(&b), "partial", "{b:#}");
        same("limit");
    }

    // 7. the guard, then --full
    let tiny = write(
        dir.path(),
        "tiny.json",
        br#"{"p": {"CVE-2026-0001": {"releases": {"trixie": {"status": "open"}}}}}"#,
    );
    let b = step(tiny.clone(), json!({}), "guard").await;
    assert_eq!(status(&b), "error");
    same("guard");
    let empty = write(dir.path(), "empty.json", b"{}");
    let b = step(empty, json!({}), "empty").await;
    assert_eq!(status(&b), "error");
    same("empty");
    let b = step(tiny, json!({"full": true}), "full").await;
    assert_eq!(status(&b), "ok");
    same("full");
    assert_eq!(count().await, 1);

    // 8. errors with Python's wording: nothing stored but the status row
    let cases: Vec<(&str, &[u8])> = vec![
        ("list.json", b"[1, 2]"),
        (
            "releases.json",
            br#"{"p": {"CVE-2026-0001": {"releases": ["trixie"]}}}"#,
        ),
        (
            "status.json",
            br#"{"p": {"CVE-2026-0001": {"releases": {"trixie": {"status": 5}}}}}"#,
        ),
        (
            "urgency.json",
            br#"{"p": {"CVE-2026-0001": {"releases": {"trixie": {"urgency": [1]}}}}}"#,
        ),
        (
            "reason.json",
            br#"{"p": {"CVE-2026-0001": {"releases": {"trixie": {"nodsa_reason": true}}}}}"#,
        ),
    ];
    for (name, doc) in cases {
        let p = write(dir.path(), name, doc);
        let b = step(p, json!({}), "a bad document").await;
        assert_eq!(status(&b), "error", "{name}: {b:#}");
        same(name);
    }
    let b = step(missing.clone(), json!({}), "empty checkout").await;
    assert_eq!(status(&b), "error");
    same("empty checkout");
    let truncated = write(dir.path(), "truncated.gz", &gzip(&text)[..200]);
    let b = step(truncated, json!({}), "truncated gzip").await;
    assert_eq!(
        entry_of(&b)["message"],
        "DecompressError: truncated gz data (no end-of-stream marker)"
    );
    same("truncated gzip");

    // 9. tables of exactly one and two full pages of `rows_page` (5 000 rows each), read on the real store: 10 000
    // rows, then 5 000 (half deleted, the guard's limit), then 10 000 with a third changed, then 15 000
    let pages = [
        (5_000, false),
        (2_500, false),
        (5_000, true),
        (7_500, true),
        (5_000, false),
    ];
    for (i, (n, variant)) in pages.into_iter().enumerate() {
        let p = write(dir.path(), &format!("pages-{i}.json"), &big_doc(n, variant));
        let b = step(p, json!({}), "full pages").await;
        assert_eq!(status(&b), "ok", "{b:#}");
        assert_eq!(entry_of(&b)["records"], 2 * n as u64);
        same("full pages");
    }
    assert_eq!(count().await, 10_000);

    // 10. a JSON syntax error: same status, other wording (from here on the status rows differ in their message)
    let not_json = write(dir.path(), "not.json", b"{\"p\": ");
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
    d.close().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn native_debian_tracker_batches_follow_the_row_contract() {
    // every native batch and end validates against rust/contracts (source/rows, source/sync-end); applied to a real
    // store, none skipped; distro_triage deletes are among them
    let fx = fixtures();
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(
        &dir.path().join("state.sqlite3"),
        &dir.path().join("mirror.sqlite3"),
        &StoreOptions::default(),
    )
    .await
    .unwrap();
    let src = secmonk_sources::debian_tracker::DebianTrackerSource::new(Diff::view(&store))
        .with_limits(secmonk_sources::batch::Limits {
            ops: 4,
            bytes: 1 << 20,
        });
    let path = |p: &Path| json!({"path": p.display().to_string()});
    let updated = write(
        dir.path(),
        "update.json",
        &serde_json::to_vec(&update_doc()).unwrap(),
    );
    let deletes = check_row_contract(
        &src,
        &store,
        SRC,
        &[
            path(&fx.join("tracker-sample.json")),
            path(&updated),
            path(&fx.join("repo")),
            json!({"path": updated.display().to_string(), "limit": 2}),
            path(&dir.path().join("missing.json")),
        ],
    )
    .await;
    assert!(deletes >= 3, "distro_triage deletes: {deletes}");
    store.close().await;
}

// Volume measurements (rust/_docs/tech/source-debian-tracker.md), run by hand, each in its own process under
// `/usr/bin/time -l`: `debian_tracker_volume_baseline` (the file and a store), `debian_tracker_volume_native_stream`
// (parse, guard, compare and every batch built against an empty mirror, nothing applied), `debian_tracker_volume_sync`
// (native importer through the engine: first sync, a re-sync with a tenth of the packages gone and a third of the rows
// changed, an unchanged re-sync; then the same through py-sources unless `SECMONK_DT_NATIVE_ONLY=1`). Packages:
// `SECMONK_DT_PACKAGES` (100 000; 3 CVEs x 2 releases each, 600 000 rows).

struct Volume {
    d: Diff,
    rows: u64,
    day1: PathBuf,
    day2: PathBuf,
    _dir: tempfile::TempDir,
}

/// A tracker JSON in the real layout: `n` packages, 3 CVE entries each (descriptions, scope, sid, repositories),
/// releases bookworm and trixie kept (`2` rows per entry). `day2`: every tenth package gone, a third of the rows
/// changed.
fn synthetic_tracker(n: usize, day2: bool) -> Vec<u8> {
    use std::fmt::Write;
    let mut out = String::with_capacity(n * 1200);
    out.push('{');
    let mut first = true;
    for i in 0..n {
        if day2 && i % 10 == 0 {
            continue;
        }
        if !first {
            out.push(',');
        }
        first = false;
        write!(out, "\"pkg-{i:06}\":{{").unwrap();
        for j in 0..3 {
            let cve = format!(
                "CVE-20{:02}-{:05}",
                10 + (i + j) % 16,
                (i * 3 + j) % 90_000 + 10_000
            );
            let changed = day2 && (i + j) % 3 == 0;
            let (st, fixed) = if changed {
                ("resolved", "\"fixed_version\":\"1.2-3+deb12u1\",")
            } else {
                ("open", "")
            };
            if j > 0 {
                out.push(',');
            }
            write!(
                out,
                "\"{cve}\":{{\"description\":\"Synthetic issue {i}-{j} in a package of the volume test\",\"scope\":\"remote\",\
                 \"releases\":{{\"bookworm\":{{{fixed}\"repositories\":{{\"bookworm\":\"1.2-3\"}},\"status\":\"{st}\",\"urgency\":\"low\"}},\
                 \"sid\":{{\"fixed_version\":\"1.2-4\",\"repositories\":{{\"sid\":\"1.2-4\"}},\"status\":\"resolved\",\"urgency\":\"low\"}},\
                 \"trixie\":{{\"repositories\":{{\"trixie\":\"1.2-3\"}},\"status\":\"open\",\"urgency\":\"not yet assigned\",\"nodsa\":\"Minor issue\"}}}}}}"
            )
            .unwrap();
        }
        out.push('}');
    }
    out.push('}');
    out.into_bytes()
}

async fn volume() -> Option<Volume> {
    let n: usize = std::env::var("SECMONK_DT_PACKAGES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100_000);
    let d = Diff::new(&[]).await?;
    let dir = tempfile::tempdir().unwrap();
    let day1 = write(dir.path(), "day1.json", &synthetic_tracker(n, false));
    let day2 = write(dir.path(), "day2.json", &synthetic_tracker(n, true));
    eprintln!(
        "debian-tracker volume: {n} packages, {} rows, JSON {} MiB",
        n * 6,
        std::fs::metadata(&day1).unwrap().len() / (1024 * 1024)
    );
    Some(Volume {
        d,
        rows: (n * 6) as u64,
        day1,
        day2,
        _dir: dir,
    })
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "volume measurement, run by hand (source-debian-tracker.md)"]
async fn debian_tracker_volume_baseline() {
    let Some(mut v) = volume().await else { return };
    let _store = v.d.store("baseline").await;
    v.d.close().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "volume measurement, run by hand (source-debian-tracker.md)"]
async fn debian_tracker_volume_native_stream() {
    let Some(mut v) = volume().await else { return };
    let store = v.d.store("scratch").await;
    let src = secmonk_sources::debian_tracker::DebianTrackerSource::new(Diff::view(&store));
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
    assert_eq!(ops, v.rows + 1);
    eprintln!(
        "debian-tracker volume: native stream: first batch after {first_at:.2} s (parse, guard, compare), all {batches} \
         batches built in {:.2} s",
        t.elapsed().as_secs_f64()
    );
    v.d.close().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "volume measurement, run by hand (source-debian-tracker.md)"]
async fn debian_tracker_volume_sync() {
    let Some(mut v) = volume().await else { return };
    let native_only = std::env::var("SECMONK_DT_NATIVE_ONLY").is_ok_and(|x| x == "1");
    let rs_store = v.d.store("rs").await;
    let rs = v.d.engine(&rs_store, vec![native(&rs_store)]);
    let mut timed = Vec::new();
    for (what, p) in [
        ("first sync", &v.day1),
        ("re-sync, changed", &v.day2),
        ("re-sync, unchanged", &v.day2),
    ] {
        let t = std::time::Instant::now();
        let job = sync_job_secs(&rs, &[SRC], p, json!({}), 1800).await;
        assert_eq!(entry_of(&job)["status"], "ok", "{job:#}");
        timed.push(format!("native {what}: {:.1} s", t.elapsed().as_secs_f64()));
    }
    if !native_only {
        let py_store = v.d.store("py").await;
        let (py_src, _) = v.d.py_sources(&py_store, "modules-py");
        let py = v.d.engine(&py_store, vec![py_src]);
        for (what, p) in [
            ("first sync", &v.day1),
            ("re-sync, changed", &v.day2),
            ("re-sync, unchanged", &v.day2),
        ] {
            let t = std::time::Instant::now();
            let job = sync_job_secs(&py, &[SRC], p, json!({}), 3600).await;
            assert_eq!(entry_of(&job)["status"], "ok", "{job:#}");
            timed.push(format!(
                "py-sources {what}: {:.1} s",
                t.elapsed().as_secs_f64()
            ));
        }
        assert_mirrors_equal(
            &v.d.python,
            py_store.mirror_path(),
            rs_store.mirror_path(),
            "volume",
            TIMESTAMPS,
            &[],
        );
    }
    eprintln!("debian-tracker volume: {}", timed.join("; "));
    v.d.close().await;
}
