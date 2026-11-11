from __future__ import annotations

import json
from pathlib import Path

import pytest

from secmonk.collectors.lang import parse_file, parsers_for, wants
from secmonk.collectors.lang.base import EV_LOCKFILE, REGISTRY
from secmonk.collectors.lang.swift import repo_id
from secmonk.engine import purl as purls
from secmonk.engine.inventory import save_inventory
from secmonk.engine.match import match_asset
from secmonk.models import Asset, Inventory
from secmonk.sources.osv import DEFAULT_ECOSYSTEMS, import_record

FX = Path(__file__).parents[2] / "fixtures" / "lang" / "swift"


def run(rel: str):
    comps, warns = parse_file(f"app/{rel}", (FX / rel).read_bytes())
    return {c.name: c for c in comps}, warns


def test_v1_object_pins():
    got, warns = run("v1/Package.resolved")
    nio = got["github.com/apple/swift-nio-http2"]
    assert (nio.version, nio.ecosystem, nio.purl) == (
        "1.19.1", "SwiftURL", "pkg:swift/github.com/apple/swift-nio-http2@1.19.1")
    assert nio.meta["evidence"] == EV_LOCKFILE and nio.meta["lock_version"] == 1
    assert nio.meta["identity"] == "swift-nio-http2"
    assert got["github.com/apple/swift-log"].purl == "pkg:swift/github.com/apple/swift-log@1.4.2"   # scp URL
    inhouse = got["git.example.com/mobile/InHouseKit"]
    assert inhouse.version is None and inhouse.meta["branch"] == "main" and inhouse.meta["revision"]
    assert inhouse.purl == "pkg:swift/git.example.com/mobile/InHouseKit"
    assert len(got) == 4
    assert len(warns) == 1 and "without a version" in warns[0] and "InHouseKit" in warns[0]


def test_v2_kinds_and_case():
    got, warns = run("v2/Package.resolved")
    assert warns == []
    assert set(got) == {"github.com/swift-server/async-http-client", "github.com/apple/swift-crypto",
                        "github.com/vapor/vapor", "github.com/marmelroy/Zip"}     # fileSystem pin skipped
    assert got["github.com/marmelroy/Zip"].purl == "pkg:swift/github.com/marmelroy/Zip@2.1.2"
    assert got["github.com/vapor/vapor"].meta["lock_version"] == 2


def test_v3_registry_branch_and_secrets():
    got, warns = run("v3/Package.resolved")
    assert set(got) == {"github.com/grpc/grpc-swift", "github.com/apple/swift-argument-parser",
                        "github.com/swiftlang/swift-syntax", "git.example.com/platform/tooling"}
    syntax = got["github.com/swiftlang/swift-syntax"]
    assert syntax.version is None and syntax.meta["branch"] == "main"
    tooling = got["git.example.com/platform/tooling"]
    assert tooling.version == "0.4.0" and "s3cr3t" not in json.dumps(tooling.meta)
    assert tooling.meta["location"] == "https://git.example.com/platform/tooling.git"
    assert any("registry" in w for w in warns) and any("swift-syntax" in w for w in warns)


@pytest.mark.parametrize("loc, want", [
    ("https://github.com/apple/swift-nio.git", "github.com/apple/swift-nio"),
    ("https://GitHub.com/apple/swift-nio/", "github.com/apple/swift-nio"),
    ("git@github.com:apple/swift-nio.git", "github.com/apple/swift-nio"),
    ("ssh://git@gitlab.example.com:2222/group/sub/pkg.git", "gitlab.example.com/group/sub/pkg"),
    ("https://user:pw@github.com/a/b", "github.com/a/b"),
    ("/Users/someone/LocalKit", None),
    ("file:///tmp/x/y", None),
    ("https://github.com/onlyowner", None),
    ("https://github.com/a/../b", None),
    ("", None),
    (None, None),
])
def test_repo_id(loc, want):
    assert repo_id(loc) == want


def test_malformed_and_odd_entries():
    comps, warns = parse_file("Package.resolved", b"{nope")
    assert comps == [] and len(warns) == 1
    assert parse_file("Package.resolved", b"[]") == ([], [])
    doc = {"pins": [None, {"location": 3}, {"location": "https://github.com/a/b", "state": "x"},
                    {"location": "https://github.com/a/c", "state": {"version": "v1.2.0"}}], "version": 2}
    comps, _ = parse_file("Package.resolved", json.dumps(doc).encode())
    assert [(c.name, c.version) for c in comps] == [("github.com/a/b", None), ("github.com/a/c", "1.2.0")]
    assert comps[1].meta["raw_version"] == "v1.2.0"


def test_registry_and_vendored_checkouts():
    assert {p.name for p in REGISTRY if p.ecosystem == "SwiftURL"} == {"swift-package-resolved"}
    assert wants("App.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/Package.resolved")
    assert not wants("proj/.build/checkouts/swift-nio/Package.resolved")
    assert not parsers_for("DerivedData/App/SourcePackages/checkouts/vapor/Package.resolved")
    assert not wants("proj/Package.swift")               # manifest: unpinned, not parsed


def test_purl_mapping_and_sync_default():
    p = purls.parse("pkg:swift/github.com/apple/swift-nio@2.0.0")
    assert purls.PURL_TO_OSV["swift"] == "SwiftURL"
    assert purls.osv_package_name(p) == "github.com/apple/swift-nio"
    assert "SwiftURL" in DEFAULT_ECOSYSTEMS


def _findings(conn, asset_id, comps):
    save_inventory(conn, Inventory(Asset(asset_id, "repository", asset_id), "test", comps))
    match_asset(conn, asset_id)
    return conn.execute("""SELECT c.name, c.version, f.vuln_id, f.fixed_version FROM finding f
                           JOIN component c ON c.id=f.component_id WHERE f.asset_id=?""", (asset_id,)).fetchall()


def test_swifturl_matches_osv(conn):
    import_record(conn, json.loads((FX / "osv-swifturl-GHSA-ccw9-q5h2-8c2w.json").read_text()))
    conn.commit()
    comps, _ = parse_file("Package.resolved", (FX / "v1/Package.resolved").read_bytes())
    rows = [tuple(r) for r in _findings(conn, "r1", comps)]
    assert [(n, v, f) for n, v, _, f in rows] == [("github.com/apple/swift-nio-http2", "1.19.1", "1.19.2")]
    fixed = {"pins": [{"location": "https://github.com/apple/swift-nio-http2.git", "kind": "remoteSourceControl",
                       "state": {"version": "1.19.2"}}], "version": 2}
    assert _findings(conn, "r2", parse_file("Package.resolved", json.dumps(fixed).encode())[0]) == []
