//! The native OSV source over an in-memory mirror (`common::MemView`): the rows of the fixtures (files, a directory,
//! the sample zip), a second run, changed and repeated records, limit, raw storage, the zip safety checks (a
//! compression bomb, entry count, path tricks, duplicate names, overlapping data, a lying declared size, encryption,
//! unsupported methods) on archives built at test time, and the bucket (first sync per ecosystem, delta, fallback,
//! failures, limit) against a local HTTP server (never the network). Fixtures: `tests/fixtures/sources/osv` and
//! `tests/fixtures/lang/{dart,swift}/osv-*.json` of the repository (read only, real records). The comparison with
//! the Python source is `secmonk-engine/tests/native_osv.rs` (differential test).

mod common;

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use common::{MemView, of, ops};
use secmonk_model::{JsonMap, MirrorTable, RowOp};
use secmonk_sources::osv::{Caps, OsvSource};
use secmonk_traits::{RowsBatch, SyncEnd};
use serde_json::{Value, json};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/fixtures")
}

fn osv_dir() -> PathBuf {
    fixtures().join("sources/osv")
}

fn src(view: &Arc<MemView>) -> OsvSource {
    OsvSource::new(view.clone()).with_store_raw(false)
}

async fn run(src: &OsvSource, options: Value) -> (Vec<RowsBatch>, SyncEnd, Vec<String>) {
    common::run(src, "osv", options).await
}

/// Run and apply to the in-memory mirror.
async fn sync(
    view: &Arc<MemView>,
    src: &OsvSource,
    options: Value,
) -> (Vec<RowOp>, SyncEnd, Vec<String>) {
    let (b, end, lines) = run(src, options).await;
    view.apply(&b);
    (ops(&b), end, lines)
}

fn path_opts(p: &Path) -> Value {
    json!({"path": p.display().to_string()})
}

fn write(dir: &Path, name: &str, doc: &Value) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, serde_json::to_vec_pretty(doc).unwrap()).unwrap();
    p
}

fn osv_rows(view: &MemView, t: MirrorTable) -> Vec<JsonMap> {
    view.rows(t)
        .into_iter()
        .filter(|r| r.get("source").and_then(Value::as_str) == Some("osv"))
        .collect()
}

fn sync_row(view: &MemView, key: &str) -> JsonMap {
    view.rows(MirrorTable::SourceSync)
        .into_iter()
        .find(|r| r["source"] == key)
        .unwrap_or_else(|| panic!("no source_sync row {key}"))
}

/// A synthetic record: `pkg` with an ECOSYSTEM range fixed at `fixed`.
fn rec(id: &str, modified: &str, pkg: &str, fixed: &str) -> Value {
    json!({"id": id, "modified": modified, "published": "2026-01-01T00:00:00Z", "aliases": [format!("CVE-{id}")],
           "summary": format!("{id} synthetic"), "details": "synthetic record of the osv importer tests",
           "affected": [{"package": {"name": pkg, "ecosystem": "PyPI", "purl": format!("pkg:pypi/{pkg}")},
                         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]})
}

// ------------------------------------------------------------------------------------------------ zips

/// One entry of a zip built by hand ([`raw_zip`]): what the local header and the central directory say.
#[derive(Clone)]
struct Raw {
    name: Vec<u8>,
    /// The name in the local header (another one: a mismatch).
    local_name: Option<Vec<u8>>,
    method: u16,
    flags: u16,
    data: Vec<u8>,
    crc: u32,
    /// Declared uncompressed size.
    size: u32,
    /// Declared compressed size (default: `data.len()`).
    csize: Option<u32>,
    /// Point the central directory at the local header of entry N instead of its own.
    header_of: Option<usize>,
}

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
    let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// A stored or deflated member as [`raw_zip`] writes it.
fn member(name: &str, content: &[u8], deflated: bool) -> Raw {
    Raw {
        name: name.as_bytes().to_vec(),
        local_name: None,
        method: if deflated { 8 } else { 0 },
        flags: 0,
        data: if deflated {
            deflate(content)
        } else {
            content.to_vec()
        },
        crc: crc32(content),
        size: u32::try_from(content.len()).unwrap(),
        csize: None,
        header_of: None,
    }
}

/// A zip archive written byte by byte (local headers, data, central directory, end record), so that its central
/// directory can say what a well-behaved writer never would.
fn raw_zip(entries: &[Raw]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offsets = Vec::new();
    for e in entries {
        offsets.push(u32::try_from(out.len()).unwrap());
        let name = e.local_name.as_ref().unwrap_or(&e.name);
        out.extend(b"PK\x03\x04");
        out.extend(20u16.to_le_bytes());
        out.extend(e.flags.to_le_bytes());
        out.extend(e.method.to_le_bytes());
        out.extend([0u8; 4]); // time, date
        out.extend(e.crc.to_le_bytes());
        out.extend(
            e.csize
                .unwrap_or(u32::try_from(e.data.len()).unwrap())
                .to_le_bytes(),
        );
        out.extend(e.size.to_le_bytes());
        out.extend(u16::try_from(name.len()).unwrap().to_le_bytes());
        out.extend(0u16.to_le_bytes());
        out.extend(name);
        out.extend(&e.data);
    }
    let cd = u32::try_from(out.len()).unwrap();
    for (i, e) in entries.iter().enumerate() {
        out.extend(b"PK\x01\x02");
        out.extend(20u16.to_le_bytes()); // made by
        out.extend(20u16.to_le_bytes()); // needed
        out.extend(e.flags.to_le_bytes());
        out.extend(e.method.to_le_bytes());
        out.extend([0u8; 4]);
        out.extend(e.crc.to_le_bytes());
        out.extend(
            e.csize
                .unwrap_or(u32::try_from(e.data.len()).unwrap())
                .to_le_bytes(),
        );
        out.extend(e.size.to_le_bytes());
        out.extend(u16::try_from(e.name.len()).unwrap().to_le_bytes());
        out.extend([0u8; 12]); // extra, comment, disk, internal attributes, external attributes (4)
        out.extend(offsets[e.header_of.unwrap_or(i)].to_le_bytes());
        out.extend(&e.name);
    }
    let cd_len = u32::try_from(out.len()).unwrap() - cd;
    out.extend(b"PK\x05\x06");
    out.extend([0u8; 4]);
    let n = u16::try_from(entries.len()).unwrap();
    out.extend(n.to_le_bytes());
    out.extend(n.to_le_bytes());
    out.extend(cd_len.to_le_bytes());
    out.extend(cd.to_le_bytes());
    out.extend(0u16.to_le_bytes());
    out
}

fn json_member(name: &str, doc: &Value) -> Raw {
    member(name, &serde_json::to_vec(doc).unwrap(), true)
}

// ------------------------------------------------------------------------------------------------ files

#[tokio::test]
async fn fixture_records_become_vulnerability_alias_and_affected_rows() {
    let view = MemView::new();
    let s = src(&view);
    let (ops1, end, _) = sync(&view, &s, path_opts(&osv_dir())).await;
    assert_eq!(end.entry.status, "ok", "{end:?}");
    // every *.json of the directory is one record (the legacy DSA included)
    let n = std::fs::read_dir(osv_dir())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
        .count() as u64;
    assert_eq!(end.entry.records, n);
    let path = feed_path(&osv_dir());
    assert_eq!(
        end.entry.message.as_deref(),
        Some(format!("from {path}").as_str())
    );
    let vulns = osv_rows(&view, MirrorTable::Vulnerability);
    assert_eq!(vulns.len() as u64, n);
    assert!(
        of(&ops1, MirrorTable::RawRecord, true).is_empty(),
        "raw storage is off by default"
    );
    assert!(of(&ops1, MirrorTable::Affected, false).is_empty());
    // the main row: total, cursor = the largest `modified`
    let main = sync_row(&view, "osv");
    assert_eq!(main["records"], json!(n));
    assert_eq!(main["status"], "ok");
    assert!(
        main["cursor"]
            .as_str()
            .is_some_and(|c| c.starts_with("2026-")),
        "{main:?}"
    );
    // a few rows checked by hand: log4j (Maven names, versions as VERSIONS rows), Go (custom ranges), Ubuntu
    let affected = osv_rows(&view, MirrorTable::Affected);
    let log4j: Vec<&JsonMap> = affected
        .iter()
        .filter(|r| r["vuln_id"] == "GHSA-jfh8-c2jp-5v3q")
        .collect();
    assert!(
        log4j
            .iter()
            .any(|r| r["package"] == "org.apache.logging.log4j:log4j-core"),
        "{log4j:#?}"
    );
    let go: Vec<&JsonMap> = affected
        .iter()
        .filter(|r| r["vuln_id"] == "GO-2024-2428")
        .collect();
    assert!(
        go.iter()
            .all(|r| r["extra"]["custom_range"] == true || r["range_type"] == "GIT"),
        "{go:#?}"
    );
    let ubuntu: Vec<&JsonMap> = affected
        .iter()
        .filter(|r| r["vuln_id"] == "UBUNTU-CVE-2024-58384")
        .collect();
    assert!(
        ubuntu
            .iter()
            .any(|r| r["extra"]["ecosystem_variant"].is_string()),
        "{ubuntu:#?}"
    );
    let aliases = osv_rows(&view, MirrorTable::Alias);
    assert!(aliases.iter().any(|r| r["kind"] == "upstream"));
    assert!(aliases.iter().any(|r| r["kind"] == "alias"));

    // the same directory again: the vulnerability rows rewritten, no alias or affected operation
    let (ops2, end, _) = sync(&view, &s, path_opts(&osv_dir())).await;
    assert_eq!(end.entry.records, n);
    assert_eq!(of(&ops2, MirrorTable::Vulnerability, true).len() as u64, n);
    assert!(
        of(&ops2, MirrorTable::Alias, true).is_empty()
            && of(&ops2, MirrorTable::Alias, false).is_empty()
    );
    assert!(
        of(&ops2, MirrorTable::Affected, true).is_empty()
            && of(&ops2, MirrorTable::Affected, false).is_empty()
    );
    assert_eq!(osv_rows(&view, MirrorTable::Affected).len(), affected.len());
}

fn feed_path(p: &Path) -> String {
    secmonk_sources::feed::py_path(p)
}

#[tokio::test]
async fn the_sample_zip_and_the_pub_and_swift_records() {
    let view = MemView::new();
    let s = src(&view);
    let (_, end, _) = sync(&view, &s, path_opts(&osv_dir().join("sample-all.zip"))).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("ok", 6),
        "{end:?}"
    );
    let ids: Vec<String> = osv_rows(&view, MirrorTable::Vulnerability)
        .iter()
        .map(|r| r["id"].as_str().unwrap().to_owned())
        .collect();
    assert!(ids.contains(&"RHSA-2026:39976".to_owned()), "{ids:?}");
    for (f, purl) in [
        ("lang/dart/osv-pub-GHSA-4rgh-jx4f-qfcq.json", "pkg:pub/http"),
        (
            "lang/swift/osv-swifturl-GHSA-ccw9-q5h2-8c2w.json",
            "pkg:swift/",
        ),
    ] {
        let (_, end, _) = sync(&view, &s, path_opts(&fixtures().join(f))).await;
        assert_eq!(end.entry.records, 1, "{f}");
        let rows = osv_rows(&view, MirrorTable::Affected);
        assert!(
            rows.iter()
                .any(|r| r["purl"].as_str().is_some_and(|p| p.starts_with(purl))),
            "{f}: {rows:#?}"
        );
    }
}

#[tokio::test]
async fn changed_withdrawn_and_repeated_records() {
    let view = MemView::new();
    let s = src(&view);
    let d = tempfile::tempdir().unwrap();
    write(
        d.path(),
        "a.json",
        &json!([
            rec("PYSEC-1", "2026-01-01T00:00:00Z", "foo", "1.0"),
            rec("PYSEC-2", "2026-01-01T00:00:00Z", "bar", "2.0")
        ]),
    );
    sync(&view, &s, path_opts(d.path())).await;
    assert_eq!(osv_rows(&view, MirrorTable::Affected).len(), 2);
    // PYSEC-1: another fix; PYSEC-2 withdrawn (its affected rows go, the aliases stay); PYSEC-3 twice in one run
    let mut w = rec("PYSEC-2", "2026-02-01T00:00:00Z", "bar", "2.0");
    w["withdrawn"] = json!("2026-02-01T00:00:00Z");
    let mut three = rec("PYSEC-3", "2026-02-01T00:00:00Z", "baz", "1.0");
    three["aliases"] = json!(["CVE-X", "CVE-Y"]);
    let mut three_b = rec("PYSEC-3", "2026-02-02T00:00:00Z", "baz", "3.0");
    three_b["aliases"] = json!(["CVE-Y"]);
    write(
        d.path(),
        "a.json",
        &json!([
            rec("PYSEC-1", "2026-02-01T00:00:00Z", "foo", "1.1"),
            w,
            three
        ]),
    );
    write(d.path(), "b.json", &three_b);
    let (ops, end, _) = sync(&view, &s, path_opts(d.path())).await;
    assert_eq!(end.entry.records, 4);
    let deletes = of(&ops, MirrorTable::Affected, false);
    assert_eq!(
        deletes.len(),
        3,
        "PYSEC-1, PYSEC-2, the first PYSEC-3: {deletes:?}"
    );
    let aff = osv_rows(&view, MirrorTable::Affected);
    let fixed = |id: &str| -> Vec<Value> {
        aff.iter()
            .filter(|r| r["vuln_id"] == id)
            .map(|r| r["events"][1]["fixed"].clone())
            .collect()
    };
    assert_eq!(fixed("PYSEC-1"), vec![json!("1.1")]);
    assert!(fixed("PYSEC-2").is_empty());
    assert_eq!(
        fixed("PYSEC-3"),
        vec![json!("3.0")],
        "the last record of an id is the one written"
    );
    let aliases: Vec<String> = osv_rows(&view, MirrorTable::Alias)
        .iter()
        .filter(|r| r["vuln_id"] == "PYSEC-3")
        .map(|r| r["alias"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(aliases, vec!["CVE-Y"]);
    assert_eq!(sync_row(&view, "osv")["cursor"], "2026-02-02T00:00:00Z");
    assert_eq!(
        sync_row(&view, "osv")["records"],
        json!(3),
        "the total counts distinct records"
    );
}

#[tokio::test]
async fn limit_raw_storage_skipped_records_and_bad_files() {
    let view = MemView::new();
    let d = tempfile::tempdir().unwrap();
    write(
        d.path(),
        "1.json",
        &json!([
            rec("A-1", "2026-01-01T00:00:00Z", "a", "1"),
            rec("A-2", "2026-01-02T00:00:00Z", "b", "1")
        ]),
    );
    write(
        d.path(),
        "2.json",
        &json!({"id": "A-3", "severity": "not a list"}),
    );
    std::fs::write(d.path().join("3.json"), b"{").unwrap();
    std::fs::write(d.path().join("4.json"), b"\xef\xbb\xbf{\"id\": \"BOM\"}").unwrap();
    std::fs::create_dir(d.path().join("5.json")).unwrap();
    write(
        d.path(),
        "6.json",
        &json!([1, {"id": ""}, rec("A-4", "2026-01-03T00:00:00Z", "c", "1")]),
    );
    std::fs::write(d.path().join("7.txt"), b"{}").unwrap();
    let raw = OsvSource::new(view.clone()).with_store_raw(true);
    let (ops, end, lines) = sync(
        &view,
        &raw,
        json!({"path": d.path().display().to_string(), "limit": 1}),
    )
    .await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("ok", 1),
        "{end:?}"
    );
    assert_eq!(of(&ops, MirrorTable::RawRecord, true).len(), 1);
    assert_eq!(
        of(&ops, MirrorTable::RawRecord, true)[0]["data"]["id"],
        "A-1"
    );
    let (_, end, lines2) = sync(&view, &raw, path_opts(d.path())).await;
    // A-3 skipped (Python raises), 3.json bad JSON, 4.json a BOM (read_text keeps it), 5.json a directory, the
    // list's non-records ignored
    assert_eq!(end.entry.records, 3, "{lines:?} {lines2:?}");
    let all = lines2.join("\n");
    for want in [
        "skipping A-3",
        "3.json: invalid JSON",
        "4.json: invalid JSON",
        "5.json: [Errno 21]",
    ] {
        assert!(all.contains(want), "{want}: {all}");
    }
    // a missing .json path: Python logs it and reports ok with 0 records
    let (_, end, _) = sync(&view, &raw, path_opts(&d.path().join("missing.json"))).await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 0));
    // a missing .zip: FileNotFoundError, error
    let (_, end, _) = sync(&view, &raw, path_opts(&d.path().join("missing.zip"))).await;
    assert_eq!(end.entry.status, "error");
    assert!(
        end.entry
            .message
            .as_deref()
            .unwrap()
            .starts_with("FileNotFoundError: [Errno 2] "),
        "{end:?}"
    );
    // not a zip
    let fake = d.path().join("fake.zip");
    std::fs::write(&fake, b"not a zip").unwrap();
    let (_, end, _) = sync(&view, &raw, path_opts(&fake)).await;
    assert_eq!(
        end.entry.message.as_deref(),
        Some("BadZipFile: File is not a zip file")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_fifo_path_is_refused_without_blocking() {
    let d = tempfile::tempdir().unwrap();
    let fifo = d.path().join("feed.json");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let view = MemView::new();
    let s = src(&view);
    let (_, end, lines) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        sync(&view, &s, path_opts(&fifo)),
    )
    .await
    .expect("no hang");
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 0));
    assert!(lines.join("\n").contains("not a regular file"), "{lines:?}");
}

// ------------------------------------------------------------------------------------------------ zip safety

async fn zip_run(entries: &[Raw], caps: Caps) -> (SyncEnd, Vec<String>, Arc<MemView>) {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("crafted.zip");
    std::fs::write(&p, raw_zip(entries)).unwrap();
    let view = MemView::new();
    let s = src(&view).with_caps(caps);
    let (_, end, lines) = sync(&view, &s, path_opts(&p)).await;
    (end, lines, view)
}

#[tokio::test]
async fn a_compression_bomb_member_is_skipped() {
    // 8 MiB of spaces around a record compress about 1000 to 1
    let mut bomb = b"{\"id\": \"BOMB-1\"".to_vec();
    bomb.extend(std::iter::repeat_n(b' ', 8 * 1024 * 1024));
    bomb.push(b'}');
    let good = json_member(
        "GOOD-1.json",
        &rec("GOOD-1", "2026-01-01T00:00:00Z", "a", "1"),
    );
    let (end, lines, view) =
        zip_run(&[member("BOMB-1.json", &bomb, true), good], Caps::default()).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("ok", 1),
        "{end:?}"
    );
    assert!(
        lines.join("\n").contains("compression ratio above 200"),
        "{lines:?}"
    );
    assert_eq!(
        osv_rows(&view, MirrorTable::Vulnerability)[0]["id"],
        "GOOD-1"
    );
}

#[tokio::test]
async fn path_tricks_in_member_names_are_skipped() {
    let r = |id: &str| rec(id, "2026-01-01T00:00:00Z", "a", "1");
    let entries = [
        json_member("../X-1.json", &r("X-1")),
        json_member("/abs/X-2.json", &r("X-2")),
        json_member("a/../../X-3.json", &r("X-3")),
        json_member("C:X-4.json", &r("X-4")),
        json_member("a\\X-5.json", &r("X-5")),
        json_member("ok/GOOD-2.json", &r("GOOD-2")),
        json_member("dir/", &json!({})),
    ];
    let (end, lines, _) = zip_run(&entries, Caps::default()).await;
    assert_eq!(end.entry.records, 1, "{lines:?}");
    assert_eq!(
        lines.iter().filter(|l| l.contains("unsafe name")).count(),
        5,
        "{lines:?}"
    );
}

#[tokio::test]
async fn archive_caps_and_refusals() {
    let r = |id: &str| {
        json_member(
            &format!("{id}.json"),
            &rec(id, "2026-01-01T00:00:00Z", "a", "1"),
        )
    };
    // entry count
    let entries: Vec<Raw> = (0..5).map(|i| r(&format!("N-{i}"))).collect();
    let (end, _, view) = zip_run(
        &entries,
        Caps {
            zip_entries: 4,
            ..Caps::default()
        },
    )
    .await;
    assert_eq!(end.entry.status, "error");
    assert!(
        end.entry
            .message
            .as_deref()
            .unwrap()
            .ends_with("more than 4 zip entries; refusing"),
        "{end:?}"
    );
    assert!(
        osv_rows(&view, MirrorTable::Vulnerability).is_empty(),
        "refused before the first record"
    );
    // declared uncompressed total
    let (end, _, _) = zip_run(
        &entries,
        Caps {
            zip_total: 100,
            ..Caps::default()
        },
    )
    .await;
    assert!(
        end.entry
            .message
            .as_deref()
            .unwrap()
            .contains("bytes uncompressed; refusing"),
        "{end:?}"
    );
    // duplicate names
    let (end, _, _) = zip_run(&[r("D-1"), r("D-1")], Caps::default()).await;
    assert!(
        end.entry
            .message
            .as_deref()
            .unwrap()
            .ends_with("duplicate member names; refusing"),
        "{end:?}"
    );
    // the member cap (Python's 50 MB, smaller here) and a lying declared size
    let (end, lines, _) = zip_run(
        &entries[..2],
        Caps {
            member_bytes: 10,
            ..Caps::default()
        },
    )
    .await;
    assert_eq!(end.entry.records, 0);
    assert!(
        lines.join("\n").contains("oversized zip member"),
        "{lines:?}"
    );
    let mut liar = r("L-1");
    liar.size = 20; // the data inflates to more: cut at the declared size, then the CRC fails
    let (end, lines, _) = zip_run(&[liar, r("L-2")], Caps::default()).await;
    assert_eq!(end.entry.records, 1, "{lines:?}");
    assert!(
        lines.join("\n").contains("bad member L-1.json"),
        "{lines:?}"
    );
}

#[tokio::test]
async fn overlapping_and_inconsistent_members() {
    let r = |id: &str| {
        json_member(
            &format!("{id}.json"),
            &rec(id, "2026-01-01T00:00:00Z", "a", "1"),
        )
    };
    // O-1's data claims to run over O-2's local header (the overlap of a zip bomb)
    let (a, b) = (r("O-1"), r("O-2"));
    let mut a2 = a.clone();
    a2.csize = Some(u32::try_from(a.data.len() + 40).unwrap());
    let (end, lines, view) = zip_run(&[a2, b], Caps::default()).await;
    assert_eq!(end.entry.records, 1, "{lines:?}");
    assert!(lines.join("\n").contains("Overlapped entries"), "{lines:?}");
    assert_eq!(osv_rows(&view, MirrorTable::Vulnerability)[0]["id"], "O-2");
    // a name that differs in the local header
    let mut c = r("M-1");
    c.local_name = Some(b"M-X.json".to_vec());
    let (end, lines, _) = zip_run(&[c, r("M-2")], Caps::default()).await;
    assert_eq!(end.entry.records, 1);
    assert!(lines.join("\n").contains("and header"), "{lines:?}");
    // two directory entries for one local header: Python warns and reads the one whose name matches
    let mut twin = r("T-1");
    twin.name = b"T-2.json".to_vec();
    twin.header_of = Some(0);
    let (end, lines, _) = zip_run(&[r("T-1"), twin], Caps::default()).await;
    assert_eq!(end.entry.records, 1, "{lines:?}");
}

#[tokio::test]
async fn encryption_and_compression_methods() {
    let r = |id: &str| {
        json_member(
            &format!("{id}.json"),
            &rec(id, "2026-01-01T00:00:00Z", "a", "1"),
        )
    };
    let mut enc = r("E-1");
    enc.flags = 1;
    let (end, _, view) = zip_run(&[r("E-0"), enc, r("E-2")], Caps::default()).await;
    assert_eq!(end.entry.status, "error");
    let msg = end.entry.message.as_deref().unwrap();
    assert!(
        msg.starts_with(
            "RuntimeError: File <ZipInfo filename='E-1.json' compress_type=deflate file_size="
        ) && msg.ends_with("> is encrypted, password required for extraction"),
        "{msg}"
    );
    assert_eq!(
        osv_rows(&view, MirrorTable::Vulnerability).len(),
        1,
        "the records before it stay"
    );
    let mut bz = r("B-1");
    bz.method = 12;
    let (end, lines, _) = zip_run(&[bz, r("B-2")], Caps::default()).await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("ok", 1));
    assert!(lines.join("\n").contains("bzip2 or lzma"), "{lines:?}");
    let mut odd = r("U-1");
    odd.method = 99;
    let (end, _, _) = zip_run(&[odd], Caps::default()).await;
    assert_eq!(
        end.entry.message.as_deref(),
        Some("NotImplementedError: That compression method is not supported")
    );
}

// ------------------------------------------------------------------------------------------------ the bucket

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
                let (status, body) = files
                    .lock()
                    .unwrap()
                    .get(&path)
                    .cloned()
                    .unwrap_or((404, b"not found".to_vec()));
                let head = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
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

fn zip_of(recs: &[Value]) -> Vec<u8> {
    let entries: Vec<Raw> = recs
        .iter()
        .map(|r| json_member(&format!("{}.json", r["id"].as_str().unwrap()), r))
        .collect();
    raw_zip(&entries)
}

fn csv(lines: &[(&str, &str)]) -> Vec<u8> {
    lines
        .iter()
        .map(|(t, id)| format!("{t},{id}\n"))
        .collect::<String>()
        .into_bytes()
}

#[tokio::test]
async fn the_bucket_full_then_delta_per_ecosystem() {
    let files: Files = Arc::default();
    let (url, log) = serve_files(files.clone()).await;
    let put = |path: &str, status: u16, body: Vec<u8>| {
        files
            .lock()
            .unwrap()
            .insert(path.to_owned(), (status, body));
    };
    let a1 = rec("PYSEC-1", "2026-01-01T00:00:00Z", "a", "1");
    let a2 = rec("PYSEC-2", "2026-01-02T00:00:00.123456789Z", "b", "1");
    let r1 = {
        let mut r = rec("RHSA-2026:1", "2026-01-05T00:00:00Z", "openssl", "1:3.0-1");
        r["affected"][0]["package"]["ecosystem"] = json!("Red Hat:enterprise_linux:9::appstream");
        r
    };
    put("/PyPI/all.zip", 200, zip_of(&[a1.clone(), a2.clone()]));
    put("/Red%20Hat/all.zip", 200, zip_of(std::slice::from_ref(&r1)));
    let view = MemView::new();
    let s = src(&view).with_bucket(&url);
    let opts = json!({"ecosystems": ["PyPI", "Red Hat"]});

    // 1. first sync: both all.zip
    let (_, end, _) = sync(&view, &s, opts.clone()).await;
    assert_eq!(
        (
            end.entry.status.as_str(),
            end.entry.records,
            end.entry.message.as_deref()
        ),
        ("ok", 3, Some("2 ecosystems")),
        "{end:?}"
    );
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            "GET /PyPI/all.zip HTTP/1.1",
            "GET /Red%20Hat/all.zip HTTP/1.1"
        ]
    );
    let st = sync_row(&view, "osv:PyPI");
    assert_eq!(
        (
            st["status"].clone(),
            st["cursor"].clone(),
            st["message"].clone()
        ),
        (
            json!("ok"),
            json!("2026-01-02T00:00:00.123456789Z"),
            json!("full")
        )
    );
    assert_eq!(sync_row(&view, "osv")["records"], json!(3));
    assert_eq!(
        osv_rows(&view, MirrorTable::Affected)
            .iter()
            .filter(|r| r["ecosystem"] == "Red Hat:9")
            .count(),
        1
    );

    // 2. delta: PYSEC-2 changed, PYSEC-3 new, an id gone (404), an old line; Red Hat unchanged
    log.lock().unwrap().clear();
    let a2b = rec("PYSEC-2", "2026-02-01T00:00:00Z", "b", "2");
    let a3 = rec("PYSEC-3", "2026-02-02T00:00:00Z", "c", "1");
    put(
        "/PyPI/modified_id.csv",
        200,
        csv(&[
            ("2026-02-03T00:00:00Z", "PYSEC-GONE"),
            ("2026-02-02T00:00:00Z", "PYSEC-3"),
            ("2026-02-01T00:00:00Z", "PYSEC-2"),
            ("2026-01-01T00:00:00Z", "PYSEC-1"),
        ]),
    );
    put("/PyPI/PYSEC-2.json", 200, serde_json::to_vec(&a2b).unwrap());
    put("/PyPI/PYSEC-3.json", 200, serde_json::to_vec(&a3).unwrap());
    put(
        "/Red%20Hat/modified_id.csv",
        200,
        csv(&[("2026-01-05T00:00:00Z", "RHSA-2026:1")]),
    );
    let (ops, end, _) = sync(&view, &s, opts.clone()).await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("ok", 2),
        "{end:?}"
    );
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            "GET /PyPI/modified_id.csv HTTP/1.1",
            "GET /PyPI/PYSEC-2.json HTTP/1.1",
            "GET /PyPI/PYSEC-3.json HTTP/1.1",
            "GET /PyPI/PYSEC-GONE.json HTTP/1.1",
            "GET /Red%20Hat/modified_id.csv HTTP/1.1",
        ]
    );
    assert_eq!(of(&ops, MirrorTable::Affected, false).len(), 1);
    let st = sync_row(&view, "osv:PyPI");
    assert_eq!(
        (
            st["cursor"].clone(),
            st["message"].clone(),
            st["records"].clone()
        ),
        (json!("2026-02-03T00:00:00Z"), json!("delta"), json!(2))
    );
    assert_eq!(
        sync_row(&view, "osv:Red Hat")["cursor"],
        "2026-01-05T00:00:00Z"
    );
    assert_eq!(sync_row(&view, "osv")["records"], json!(4));

    // 3. a failing id: partial; the cursor stops before it, the later success is imported
    log.lock().unwrap().clear();
    put(
        "/PyPI/modified_id.csv",
        200,
        csv(&[
            ("2026-03-03T00:00:00Z", "PYSEC-5"),
            ("2026-03-02T00:00:00Z", "PYSEC-4"),
            ("2026-03-01T00:00:00Z", "PYSEC-1"),
        ]),
    );
    put(
        "/PyPI/PYSEC-1.json",
        200,
        serde_json::to_vec(&rec("PYSEC-1", "2026-03-01T00:00:00Z", "a", "9")).unwrap(),
    );
    put("/PyPI/PYSEC-4.json", 500, b"oops".to_vec());
    put(
        "/PyPI/PYSEC-5.json",
        200,
        serde_json::to_vec(&rec("PYSEC-5", "2026-03-03T00:00:00Z", "e", "1")).unwrap(),
    );
    let (_, end, _) = sync(&view, &s, json!({"ecosystems": ["PyPI"]})).await;
    assert_eq!(
        (
            end.entry.status.as_str(),
            end.entry.records,
            end.entry.message.as_deref()
        ),
        ("partial", 2, Some("1 ecosystems"))
    );
    let st = sync_row(&view, "osv:PyPI");
    assert_eq!(
        (
            st["status"].clone(),
            st["cursor"].clone(),
            st["message"].clone()
        ),
        (
            json!("ok"),
            json!("2026-03-01T00:00:00Z"),
            json!("delta, 1 failed")
        )
    );

    // 4. --full with a limit: a partial row without cursor; the next run is a full one again
    log.lock().unwrap().clear();
    let (_, end, _) = sync(
        &view,
        &s,
        json!({"ecosystems": ["PyPI"], "full": true, "limit": 1}),
    )
    .await;
    assert_eq!(
        (end.entry.status.as_str(), end.entry.records),
        ("partial", 1)
    );
    let st = sync_row(&view, "osv:PyPI");
    assert_eq!(
        (st["status"].clone(), st["cursor"].clone()),
        (json!("partial"), Value::Null)
    );
    let (_, end, _) = sync(&view, &s, json!({"ecosystems": ["PyPI"]})).await;
    assert_eq!(end.entry.status, "ok");
    assert_eq!(
        log.lock()
            .unwrap()
            .iter()
            .filter(|l| l.contains("all.zip"))
            .count(),
        2
    );

    // 5. one ecosystem fails (no zip): partial with its message; all fail: error, the totals kept
    let (_, end, _) = sync(
        &view,
        &s,
        json!({"ecosystems": ["PyPI", "Nope"], "full": true}),
    )
    .await;
    assert_eq!(end.entry.status, "partial");
    assert!(
        end.entry
            .message
            .as_deref()
            .unwrap()
            .starts_with("Nope: HTTP 404 for http://"),
        "{end:?}"
    );
    let before = sync_row(&view, "osv")["records"].clone();
    let (_, end, _) = sync(&view, &s, json!({"ecosystems": ["Nope"]})).await;
    assert_eq!((end.entry.status.as_str(), end.entry.records), ("error", 0));
    assert_eq!(sync_row(&view, "osv")["records"], before);
    // release-qualified names
    let (_, end, _) = sync(&view, &s, json!({"ecosystems": ["Debian:12"]})).await;
    assert_eq!(end.entry.status, "error");
    assert!(
        end.entry
            .message
            .as_deref()
            .unwrap()
            .starts_with("OSV ecosystem 'Debian:12' is release-qualified")
    );
}

#[tokio::test]
async fn more_than_5000_changes_fall_back_to_the_zip_and_downloads_are_capped() {
    let files: Files = Arc::default();
    let (url, log) = serve_files(files.clone()).await;
    let put = |path: &str, body: Vec<u8>| {
        files.lock().unwrap().insert(path.to_owned(), (200, body));
    };
    let a = rec("GO-1", "2026-01-01T00:00:00Z", "x", "1");
    put("/Go/all.zip", zip_of(&[a]));
    let view = MemView::new();
    let s = src(&view).with_bucket(&url);
    sync(&view, &s, json!({"ecosystems": ["Go"]})).await;
    let lines: Vec<String> = (0..5001)
        .map(|i| format!("2026-02-01T00:00:00Z,GO-{i}\n"))
        .collect();
    put("/Go/modified_id.csv", lines.concat().into_bytes());
    log.lock().unwrap().clear();
    let (_, end, progress) = sync(&view, &s, json!({"ecosystems": ["Go"]})).await;
    assert_eq!(end.entry.status, "ok");
    assert_eq!(
        *log.lock().unwrap(),
        vec![
            "GET /Go/modified_id.csv HTTP/1.1",
            "GET /Go/all.zip HTTP/1.1"
        ]
    );
    assert!(
        progress
            .join("\n")
            .contains("5001 changes since cursor, falling back to full zip"),
        "{progress:?}"
    );
    // the download cap, with Python's wording
    let small = src(&view).with_bucket(&url).with_caps(Caps {
        download_bytes: 10,
        ..Caps::default()
    });
    let (_, end, _) = sync(&view, &small, json!({"ecosystems": ["Go"], "full": true})).await;
    assert_eq!(end.entry.status, "error");
    assert!(
        end.entry
            .message
            .as_deref()
            .unwrap()
            .starts_with("Go: Go/all.zip is ")
            && end
                .entry
                .message
                .as_deref()
                .unwrap()
                .ends_with("bytes, above the 10 byte limit"),
        "{end:?}"
    );
}

#[tokio::test]
async fn many_records_in_groups_and_ids_repeated_across_groups() {
    // 130 records in groups of 25 (rows_by_id per group), one id again 100 records later
    let view = MemView::new();
    let s = src(&view);
    let d = tempfile::tempdir().unwrap();
    let mut recs: Vec<Value> = (0..130)
        .map(|i| rec(&format!("M-{i:03}"), "2026-01-01T00:00:00Z", "p", "1"))
        .collect();
    recs.push(rec("M-005", "2026-01-02T00:00:00Z", "p", "2"));
    write(d.path(), "many.json", &Value::Array(recs));
    let (_, end, _) = sync(&view, &s, path_opts(d.path())).await;
    assert_eq!(end.entry.records, 131);
    let aff = osv_rows(&view, MirrorTable::Affected);
    assert_eq!(aff.len(), 130);
    let m5: Vec<&JsonMap> = aff.iter().filter(|r| r["vuln_id"] == "M-005").collect();
    assert_eq!(m5.len(), 1);
    assert_eq!(m5[0]["events"][1]["fixed"], "2");
    assert_eq!(sync_row(&view, "osv")["records"], json!(130));
}
