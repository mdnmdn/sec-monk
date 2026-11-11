from __future__ import annotations

import json
from pathlib import Path

from secmonk.collectors.lang import parse_file, parsers_for, wants
from secmonk.collectors.lang.base import EV_LOCKFILE, REGISTRY, dedupe
from secmonk.engine import purl as purls
from secmonk.engine.inventory import save_inventory
from secmonk.engine.match import match_asset
from secmonk.models import Asset, Inventory
from secmonk.sources.osv import DEFAULT_ECOSYSTEMS, import_record

FX = Path(__file__).parents[2] / "fixtures" / "lang" / "dart"


def run(rel: str):
    comps, warns = parse_file(rel, (FX / rel).read_bytes())
    assert warns == []
    return {c.name: c for c in comps}


def test_flutter_app_lock():
    got = run("flutter-app/pubspec.lock")
    # sdk (flutter, flutter_test), path (local_core) and self-hosted (internal_ui) are skipped
    assert set(got) == {"async", "collection", "flutter_lints", "http", "http_parser", "meta", "path",
                        "shared_preferences_android", "widgets_kit"}
    http = got["http"]
    assert (http.version, http.ecosystem, http.purl) == ("0.13.1", "Pub", "pkg:pub/http@0.13.1")
    assert http.meta["evidence"] == EV_LOCKFILE and http.meta["direct"] is True and "dev" not in http.meta
    assert http.meta["dart_sdk"] == ">=3.3.0 <4.0.0"
    lints = got["flutter_lints"].meta
    assert lints["direct"] is True and lints["dev"] is True
    assert got["async"].meta["direct"] is False and "dev" not in got["async"].meta
    assert got["meta"].meta["overridden"] is True and got["meta"].meta["direct"] is True
    assert got["shared_preferences_android"].version == "2.3.3"                 # pub.dev mirror kept


def test_git_source_meta_redacted():
    w = run("flutter-app/pubspec.lock")["widgets_kit"]
    assert w.version == "1.2.0" and w.purl == "pkg:pub/widgets_kit@1.2.0"
    assert w.meta["source"] == "git" and w.meta["resolved_ref"].startswith("4e5f6a7b")
    assert w.meta["git_url"] == "https://github.com/example-org/widgets.git"
    assert w.meta["git_path"] == "packages/widgets_kit"
    assert "t0ken" not in json.dumps(w.meta)


def test_legacy_lock_pub_dartlang_org():
    got = run("legacy/pubspec.lock")
    assert {(n, c.version) for n, c in got.items()} == {("archive", "3.3.7"), ("crypto", "3.0.2"),
                                                        ("test", "1.21.4")}
    assert got["test"].meta["dev"] is True


def test_malformed_and_edge_entries():
    comps, warns = parse_file("pubspec.lock", b"packages: [unclosed")
    assert comps == [] and len(warns) == 1
    assert parse_file("pubspec.lock", b"") == ([], [])
    assert parse_file("pubspec.lock", b"packages: 3\n") == ([], [])
    deep = b"packages:\n  a:\n    description: " + b"[" * 500 + b"\n"
    comps, warns = parse_file("pubspec.lock", deep)
    assert comps == [] and "too deep" in warns[0]
    odd = (b"packages:\n  old:\n    dependency: transitive\n    description: old\n    source: hosted\n"
           b"    version: \"1.0.0\"\n  nover:\n    source: hosted\n  weird:\n    source: unknown\n"
           b"    version: \"1.0.0\"\n")
    comps, _ = parse_file("pubspec.lock", odd)
    assert [(c.name, c.version) for c in comps] == [("old", "1.0.0")]


def test_registry_paths_and_dedupe():
    assert {p.name for p in REGISTRY if p.ecosystem == "Pub"} == {"pubspec-lock"}
    assert wants("apps/mobile/pubspec.lock")
    assert not wants("home/u/.pub-cache/hosted/pub.dev/http-0.13.1/pubspec.lock")
    assert not parsers_for("apps/mobile/pubspec.yaml")              # manifest: unpinned, not parsed
    a = run("flutter-app/pubspec.lock")["path"]
    b = parse_file("other/pubspec.lock", b'packages:\n  path:\n    dependency: "direct main"\n'
                                         b'    source: hosted\n    version: "1.9.0"\n')[0][0]
    merged = dedupe([a, b])
    assert len(merged) == 1 and merged[0].meta["paths"] == ["flutter-app/pubspec.lock", "other/pubspec.lock"]


def test_purl_mapping_and_sync_default():
    assert purls.PURL_TO_OSV["pub"] == "Pub"
    assert purls.osv_package_name(purls.parse("pkg:pub/http@1.0.0")) == "http"
    assert "Pub" in DEFAULT_ECOSYSTEMS


def _findings(conn, asset_id, comps):
    save_inventory(conn, Inventory(Asset(asset_id, "repository", asset_id), "test", comps))
    match_asset(conn, asset_id)
    return [tuple(r) for r in conn.execute(
        """SELECT c.name, c.version, f.fixed_version FROM finding f JOIN component c ON c.id=f.component_id
           WHERE f.asset_id=?""", (asset_id,))]


def test_pub_matches_osv(conn):
    import_record(conn, json.loads((FX / "osv-pub-GHSA-4rgh-jx4f-qfcq.json").read_text()))   # http < 0.13.3
    conn.commit()
    comps, _ = parse_file("pubspec.lock", (FX / "flutter-app/pubspec.lock").read_bytes())
    assert _findings(conn, "d1", comps) == [("http", "0.13.1", "0.13.3")]
    ok = b'packages:\n  http:\n    dependency: "direct main"\n    source: hosted\n    version: "0.13.3"\n'
    assert _findings(conn, "d2", parse_file("pubspec.lock", ok)[0]) == []
