//! Differential test of the native epss importer against `py-sources` (stage 6, rust ADR-0011), with EUVD scores
//! synced through `py-sources` on both mirrors, and the volume measurements of rust/_docs/tech/source-epss.md
//! (ignored). Harness: `common/`.

mod common;

use common::*;

/// The EPSS fixture changed: two rows removed, two scores changed, two rows added, a later `score_date`; gzipped.
fn epss_update(fixture: &Path, dir: &Path) -> PathBuf {
    let text = std::fs::read_to_string(fixture).unwrap();
    let mut out = String::new();
    for line in text.lines() {
        let line = line.replace("score_date:2026-11-06", "score_date:2026-11-07");
        if line.starts_with("CVE-2019-0708") || line.starts_with("CVE-2020-1472") {
            continue; // removed: the stored rows stay (the Python source never deletes)
        }
        let line = match line.split(',').next() {
            Some("CVE-2021-44228") => "CVE-2021-44228,0.97500,0.99990".to_owned(),
            Some("CVE-2023-0001") => "CVE-2023-0001,0.00051,0.05000".to_owned(),
            _ => line,
        };
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str("CVE-2026-99998,0.00010,0.01000\nCVE-2026-99999,0.00020,0.02000\n");
    let p = dir.join("epss-update.csv.gz");
    std::fs::write(&p, gzip(out.as_bytes())).unwrap();
    p
}

/// Lines the parser must treat as the Python source does: comment and header variants, whitespace (also
/// non-breaking), CRLF, lower-case ids, extra columns, short and non-numeric lines, `_` in numbers, exponents, Unicode
/// decimal digits, a NaN
/// (NULL), an empty id, duplicates (the later one is stored), a `score_date` change in the middle. Synthetic.
const EPSS_ODD: &str = "CVE-1999-0001,0.1,0.2\n\
    \x20 #model_version:v1,score_date:2026-01-02T00:00:00+0000\n\
    CVE,EPSS,PERCENTILE\n\
    \n\
    \x20 cve-1999-0002 , 0.3 , 0.4 ,extra\r\n\
    CVE-1999-0003,not-a-number,0.5\n\
    CVE-1999-0004,0.5\n\
    CVE-1999-0005,1_0e-1,+.5\n\
    CVE-1999-0006,2.5E-05,1\n\
    CVE-1999-0007,nan,0.5\n\
    CVE-1999-0008,1__0,0.5\n\
    \u{a0}CVE-1999-0009\u{a0},0.25\u{a0},0.75\n\
    CVE-1999-0010,\u{ff10}.\u{ff15},\u{660}.\u{667}\u{665}\n\
    ,0.6,0.6\n\
    #no date here\n\
    #score_date:2026-01-03\n\
    CVE-1999-0002,0.6,0.7";

#[tokio::test(flavor = "multi_thread")]
async fn native_epss_matches_py_sources() {
    // Stage 6 differential test (component-lifecycle.md) for epss: py-sources' epss and the native one, each through
    // the engine on its own mirror, leave identical mirrors (run timestamps aside) after every step. EUVD-provided
    // scores (source 'euvd') are synced through py-sources on both mirrors, so the ownership rule of the sourceless
    // epss key is compared too. A third mirror switches py-sources -> native -> py-sources.
    let root = rust_root();
    let fixture = root.join("../tests/fixtures/sources/epss/epss_scores-sample.csv");
    let euvd_fixture = root.join("../tests/fixtures/sources/euvd/exploited-sample.json");
    let Some(mut d) = Diff::new(&[&fixture, &euvd_fixture]).await else {
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
    let (rs_py_src, _) = d.py_sources(&rs_store, "modules-rs"); // euvd on the Rust mirror
    let (switch_src, switch_staging) = d.py_sources(&switch_store, "modules-switch");
    let native = |store: &SqliteStore| -> Arc<dyn Source> {
        Arc::new(secmonk_sources::epss::EpssSource::new(Diff::view(store)))
    };
    let py = d.engine(&py_store, vec![py_src]);
    let rs = d.engine(&rs_store, vec![native(&rs_store), rs_py_src]);
    let switch_py = d.engine(&switch_store, vec![switch_src.clone()]);
    let switch_rs = d.engine(&switch_store, vec![native(&switch_store), switch_src]);

    const TIMESTAMPS: &[&str] = &["raw_record.fetched_at", "source_sync.last_sync"];
    let compare = |other: &SqliteStore, what: &str, ignore: &[&str]| {
        assert_mirrors_equal(
            &python,
            py_store.mirror_path(),
            other.mirror_path(),
            what,
            ignore,
            &[],
        );
    };
    let same = |what: &str| compare(&rs_store, what, TIMESTAMPS);
    // both versions on the same input: same entry and the same mirror; returns the Rust job
    let step = |path: PathBuf, extra: Value, what: &'static str| {
        let (py, rs) = (py.clone(), rs.clone());
        async move {
            let a = sync_job(&py, &["epss"], &path, extra.clone()).await;
            let b = sync_job(&rs, &["epss"], &path, extra).await;
            check_entries(&a, &b, what);
            b
        }
    };
    let euvd = |path: PathBuf| {
        let engines = [py.clone(), rs.clone(), switch_py.clone()];
        async move {
            for e in engines {
                let job = sync_job(&e, &["euvd"], &path, json!({})).await;
                assert_eq!(entry_of(&job)["status"], "ok", "{job:#}");
            }
        }
    };
    let epss_rows = |store: &SqliteStore, source: &'static str| {
        let store = store.clone();
        async move {
            store
                .count_rows(secmonk_model::MirrorTable::Epss, source)
                .await
                .unwrap()
        }
    };

    // 0. EUVD scores first: one for a CVE of the FIRST file, one for a CVE it lacks
    euvd(euvd_variant(
        &euvd_fixture,
        dir.path(),
        "euvd-1.json",
        0.5,
        0.25,
    ))
    .await;
    same("euvd before epss");
    assert_eq!(epss_rows(&rs_store, "euvd").await, 2);

    // 1. first sync: FIRST replaces the EUVD row of its CVE, the other EUVD row stays
    let b = step(fixture.clone(), json!({}), "first sync").await;
    assert_eq!(entry_of(&b)["status"], "ok", "{b:#}");
    assert_eq!(entry_of(&b)["records"], 10);
    same("first sync");
    assert_eq!(
        (
            epss_rows(&rs_store, "epss").await,
            epss_rows(&rs_store, "euvd").await
        ),
        (10, 1),
        "the comparison is not vacuous"
    );
    assert_eq!(
        sync_job(&switch_py, &["epss"], &fixture, json!({})).await["status"],
        "ok"
    );

    // 2. the same file again (no change)
    step(fixture.clone(), json!({}), "second sync").await;
    same("second sync");

    // 3. an update (gzip): removed rows stay, changed rows change, new rows are added
    let updated = epss_update(&fixture, dir.path());
    let b = step(updated.clone(), json!({}), "update").await;
    assert_eq!(entry_of(&b)["records"], 10);
    same("update");
    assert_eq!(epss_rows(&rs_store, "epss").await, 12);
    // the switch mirror: native importer for the same update
    let job = sync_job(&switch_rs, &["epss"], &updated, json!({})).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    assert!(
        job["log"]
            .to_string()
            .contains("epss: native importer: applied state of generation "),
        "{job:#}"
    );
    // (the switch mirror has no EUVD rows: compare the epss rows of source 'epss' and the epss sync state)
    let only_epss = |what: &str| {
        let out = std::process::Command::new(&python)
            .arg("-I")
            .arg("-c")
            .arg(
                "import sqlite3, sys\n\
                 q = \"SELECT cve_id, score, percentile, date, source FROM epss WHERE source='epss' ORDER BY cve_id\"\n\
                 s = \"SELECT source, cursor, records, status, message FROM source_sync WHERE source='epss'\"\n\
                 a, b = sqlite3.connect(sys.argv[1]), sqlite3.connect(sys.argv[2])\n\
                 sys.exit(0 if a.execute(q).fetchall() == b.execute(q).fetchall() and a.execute(s).fetchall() == b.execute(s).fetchall() else 1)\n",
            )
            .arg(py_store.mirror_path())
            .arg(switch_store.mirror_path())
            .current_dir(dir.path())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{what}: epss rows differ: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    only_epss("switch from py-sources to the native importer");

    // 3a. a failed and a limited Python run after the native one: nothing applied, native state kept
    let a_dir = dir.path().join("a-directory.csv");
    std::fs::create_dir(&a_dir).unwrap();
    for (path, extra, status) in [
        (&a_dir, json!({}), "error"),
        (&fixture, json!({"limit": 3}), "partial"),
    ] {
        let job = sync_job(&switch_py, &["epss"], path, extra).await;
        let e = entry_of(&job);
        assert_eq!(e["status"], "error", "{status}: {job:#}");
        assert!(
            e["message"].as_str().unwrap().ends_with(
                "; not applied: mirror keeps the native importer data until a successful py-sources sync"
            ),
            "{job:#}"
        );
        only_epss(&format!("a {status} Python run after Rust"));
        let st = switch_store.applied_state("epss").await.unwrap().unwrap();
        assert_eq!(
            st.generation.as_deref(),
            Some(secmonk_traits::NATIVE_GENERATION)
        );
    }

    // 3b. switch back to py-sources: repair from the staging export
    let job = sync_job(&switch_py, &["epss"], &updated, json!({})).await;
    assert_eq!(job["status"], "ok", "{job:#}");
    assert!(
        job["log"].to_string().contains(
            "epss: repair from py-sources export: the last applied batches came from the native importer"
        ),
        "{job:#}"
    );
    assert_mirror_equals_staging(
        &python,
        switch_store.mirror_path(),
        &switch_staging,
        "switch back to py-sources",
    );
    only_epss("switch back to py-sources vs py-sources only");

    // 4. EUVD again with other scores: its own row changes, the FIRST row of the shared CVE does not
    euvd(euvd_variant(
        &euvd_fixture,
        dir.path(),
        "euvd-2.json",
        0.1,
        0.3,
    ))
    .await;
    same("euvd after epss");

    // 5. parser edge cases (forced: fewer rows than stored)
    let odd = dir.path().join("odd.csv");
    std::fs::write(&odd, EPSS_ODD).unwrap();
    let b = step(odd.clone(), json!({"full": true}), "odd lines").await;
    assert_eq!(entry_of(&b)["status"], "ok", "{b:#}");
    same("odd lines");

    // 6. a limited run (partial, cursor kept)
    let b = step(fixture.clone(), json!({"limit": 3}), "limit").await;
    assert_eq!(entry_of(&b)["status"], "partial");
    same("limit");

    // 7. guard: a file under half of the stored rows; an empty file (also with --full)
    let small = dir.path().join("small.csv");
    let head: String = std::fs::read_to_string(&fixture)
        .unwrap()
        .lines()
        .take(5)
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(&small, head).unwrap();
    let b = step(small.clone(), json!({}), "snapshot guard").await;
    assert_eq!(entry_of(&b)["status"], "error");
    same("snapshot guard");
    let empty = dir.path().join("empty.csv");
    std::fs::write(&empty, "#score_date:2026-11-08\ncve,epss,percentile\n").unwrap();
    for full in [false, true] {
        let b = step(empty.clone(), json!({"full": full}), "empty file").await;
        assert_eq!(entry_of(&b)["status"], "error");
        same("empty file");
    }

    // 8. unreadable or broken input: same status and message
    let cut = gzip(std::fs::read(&fixture).unwrap().as_slice());
    let truncated = dir.path().join("truncated.csv.gz");
    std::fs::write(&truncated, &cut[..cut.len() / 2]).unwrap();
    let long = dir.path().join("long.csv");
    std::fs::write(&long, "x".repeat(70_000)).unwrap();
    for (path, what) in [
        (&a_dir, "a directory"),
        (&truncated, "truncated gzip"),
        (&long, "a line over 64 KiB"),
    ] {
        let b = step(path.clone(), json!({}), what).await;
        assert_eq!(entry_of(&b)["status"], "error", "{what}");
        same(what);
    }
    // invalid UTF-8: same status, Python's message names the reason (`invalid start byte`)
    let bad = dir.path().join("bad-utf8.csv");
    std::fs::write(&bad, b"CVE-1,0.1,0.2\nCVE-\xff,0.1,0.2\n").unwrap();
    let a = sync_job(&py, &["epss"], &bad, json!({})).await;
    let b = sync_job(&rs, &["epss"], &bad, json!({})).await;
    assert_eq!(
        (
            entry_of(&a)["status"].clone(),
            entry_of(&b)["status"].clone()
        ),
        (json!("error"), json!("error"))
    );
    let (ma, mb) = (
        entry_of(&a)["message"].as_str().unwrap().to_owned(),
        entry_of(&b)["message"].as_str().unwrap().to_owned(),
    );
    assert!(ma.starts_with(&mb), "py: {ma}\nrs: {mb}");
    compare(
        &rs_store,
        "invalid UTF-8",
        &[
            "raw_record.fetched_at",
            "source_sync.last_sync",
            "source_sync.message",
        ],
    );

    // 9. forced replacement with a small file
    step(small.clone(), json!({"full": true}), "full").await;
    same("full");

    d.close().await;
}

/// A synthetic EPSS file of `n` rows in the real file's layout (comment line, header, `cve,epss,percentile`), gzipped.
fn synthetic_epss(n: usize, date: &str, salt: u64) -> Vec<u8> {
    let mut text =
        format!("#model_version:v2025.03.14,score_date:{date}T12:55:00Z\ncve,epss,percentile\n");
    for i in 0..n {
        let year = 1999 + (i / 40_000);
        let h = (i as u64).wrapping_mul(2_654_435_761).wrapping_add(salt) % 100_000;
        text.push_str(&format!(
            "CVE-{year}-{:05},0.{h:05},0.{:05}\n",
            i % 100_000,
            99_999 - h
        ));
    }
    gzip(text.as_bytes())
}

// Volume measurements (source-epss.md "Volume"). Ignored: run by hand, each in its own process so that the peak
// resident set (`/usr/bin/time -l <test binary> --ignored --exact <name>`) belongs to one measurement:
// `epss_volume_baseline` (the file and a store, nothing else), `epss_volume_native_stream` (parse, guard and every
// batch built, nothing applied), `epss_volume_row_keys` (the read of all keys, which epss itself does not need),
// `epss_volume_sync` (native importer, then py-sources, through the engine: first sync and re-sync with a new
// score_date, so every row changes; py-sources runs in a child process). Rows: `SECMONK_EPSS_ROWS` (400 000);
// `SECMONK_EPSS_FILL_ONLY=1` stops `epss_volume_row_keys` before the read (the peak of the fill alone);
// `SECMONK_EPSS_NATIVE_ONLY=1` runs only the native half of `epss_volume_sync` (its peak without py-sources).

struct Volume {
    d: Diff,
    n: usize,
    day1: PathBuf,
    day2: PathBuf,
    _dir: tempfile::TempDir,
}

async fn volume() -> Option<Volume> {
    let n: usize = std::env::var("SECMONK_EPSS_ROWS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(400_000);
    let d = Diff::new(&[]).await?;
    let dir = tempfile::tempdir().unwrap();
    let day1 = dir.path().join("day1.csv.gz");
    let day2 = dir.path().join("day2.csv.gz");
    std::fs::write(&day1, synthetic_epss(n, "2026-11-10", 1)).unwrap();
    std::fs::write(&day2, synthetic_epss(n, "2026-11-11", 7)).unwrap();
    eprintln!(
        "epss volume: {n} rows, gzip {} KiB",
        std::fs::metadata(&day1).unwrap().len() / 1024
    );
    Some(Volume {
        d,
        n,
        day1,
        day2,
        _dir: dir,
    })
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "volume measurement, run by hand (source-epss.md)"]
async fn epss_volume_baseline() {
    let Some(mut v) = volume().await else { return };
    let _store = v.d.store("baseline").await;
    v.d.close().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "volume measurement, run by hand (source-epss.md)"]
async fn epss_volume_native_stream() {
    let Some(mut v) = volume().await else { return };
    let store = v.d.store("scratch").await;
    let src = secmonk_sources::epss::EpssSource::new(Diff::view(&store));
    let t = std::time::Instant::now();
    let params: secmonk_traits::SyncParams = serde_json::from_value(
        json!({"source": "epss", "options": {"path": v.day1.display().to_string()}}),
    )
    .unwrap();
    let mut stream = src.sync(params, CallCtx::default()).await.unwrap();
    let (mut batches, mut first_at, mut ops) = (0u64, 0.0, 0usize);
    while let Some(m) = futures_util::StreamExt::next(&mut stream).await {
        if let secmonk_traits::StreamMsg::Item(b) = m.unwrap() {
            batches += 1;
            ops += b.ops.len();
            if batches == 1 {
                first_at = t.elapsed().as_secs_f64();
            }
        }
    }
    assert_eq!(ops, v.n + 1);
    eprintln!(
        "epss volume: native stream: first batch after {first_at:.2} s (download aside: parse + guard), all {batches} \
         batches built in {:.2} s",
        t.elapsed().as_secs_f64()
    );
    v.d.close().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "volume measurement, run by hand (source-epss.md)"]
async fn epss_volume_row_keys() {
    let Some(mut v) = volume().await else { return };
    let store = v.d.store("keys").await;
    // fill the mirror with n epss rows, one batch at a time (low memory)
    let mut seq = 0;
    for chunk in (0..v.n).collect::<Vec<_>>().chunks(5000) {
        seq += 1;
        let ops: Vec<Value> = chunk
            .iter()
            .map(|i| json!({"op": "upsert", "table": "epss", "row": {"cve_id": format!("CVE-{}-{:05}", 1999 + i / 40_000, i % 100_000),
                     "score": 0.5, "percentile": 0.5, "date": "2026-11-10", "source": "epss"}}))
            .collect();
        let batch: secmonk_model::RowsBatch = serde_json::from_value(
            json!({"kind": "rows", "seq": seq, "source": "epss", "ops": ops}),
        )
        .unwrap();
        store.apply_rows(&batch).await.unwrap();
    }
    if std::env::var("SECMONK_EPSS_FILL_ONLY").as_deref() == Ok("1") {
        // the peak of the fill alone, to subtract from the run with the read
        v.d.close().await;
        return;
    }
    let view = Diff::view(&store);
    let t = std::time::Instant::now();
    let c = view
        .count_rows(secmonk_model::MirrorTable::Epss, "epss")
        .await
        .unwrap();
    let count_s = t.elapsed().as_secs_f64();
    let t = std::time::Instant::now();
    let keys = view
        .row_keys(secmonk_model::MirrorTable::Epss, "epss")
        .await
        .unwrap();
    eprintln!(
        "epss volume: count_rows {c} in {count_s:.3} s; row_keys {} keys in {:.2} s",
        keys.len(),
        t.elapsed().as_secs_f64()
    );
    drop(keys);
    v.d.close().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "volume measurement, run by hand (source-epss.md)"]
async fn epss_volume_sync() {
    let Some(mut v) = volume().await else { return };
    let rs_store = v.d.store("rs").await;
    let rs = v.d.engine(
        &rs_store,
        vec![Arc::new(secmonk_sources::epss::EpssSource::new(Diff::view(
            &rs_store,
        ))) as Arc<dyn Source>],
    );
    let py_store = v.d.store("py").await;
    let (py_src, _) = v.d.py_sources(&py_store, "modules-py");
    let py = v.d.engine(&py_store, vec![py_src]);
    let mut report = Vec::new();
    let native_only = std::env::var("SECMONK_EPSS_NATIVE_ONLY").as_deref() == Ok("1");
    for (name, engine) in [("native", &rs), ("py-sources", &py)] {
        if native_only && name != "native" {
            continue;
        }
        for (what, path) in [("first sync", &v.day1), ("re-sync", &v.day2)] {
            let t = std::time::Instant::now();
            let job = sync_job_secs(engine, &["epss"], path, json!({}), 900).await;
            assert_eq!(entry_of(&job)["status"], "ok", "{job:#}");
            report.push(format!("{name} {what}: {:.1} s", t.elapsed().as_secs_f64()));
        }
    }
    if native_only {
        eprintln!("epss volume: {}", report.join("; "));
        v.d.close().await;
        return;
    }
    assert_mirrors_equal(
        &v.d.python,
        py_store.mirror_path(),
        rs_store.mirror_path(),
        "volume",
        &["source_sync.last_sync"],
        &["epss", "source_sync"],
    );
    eprintln!("epss volume: {}", report.join("; "));
    v.d.close().await;
}
