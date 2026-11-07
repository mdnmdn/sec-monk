"""Rootfs engine against the real alpine / debian / rocky fixture trees."""

from __future__ import annotations

import os
from pathlib import Path

from secmonk.collectors import rootfs as rf
from secmonk.collectors.base import REGISTRY
from secmonk.models import CAT_LIBRARY, CAT_OS, CAT_OS_PACKAGE, Asset

FX = Path(__file__).parent.parent / "fixtures" / "collectors" / "docker"


def collect(name: str):
    inv = REGISTRY["rootfs"]().collect(str(FX / name / "rootfs"))
    return inv, {c.name: c for c in inv.components}


def test_alpine():
    inv, comps = collect("alpine-3.20")
    assert inv.asset.id.startswith("rootfs:") and inv.asset.type == "server"
    assert inv.asset.os_name == "Alpine Linux" and inv.asset.os_version == "3.20.10"
    os_c = next(c for c in inv.components if c.category == CAT_OS)
    assert os_c.vendor == "alpine" and os_c.version == "3.20.10"
    musl = comps["musl"]
    assert musl.category == CAT_OS_PACKAGE and musl.ecosystem == "Alpine:v3.20"
    assert musl.version.startswith("1.2.5-r") and musl.meta["source_package"] == "musl"
    assert musl.purl.startswith("pkg:apk/alpine/musl@") and "distro=alpine-3.20.10" in musl.purl
    assert comps["musl-utils"].meta["source_package"] == "musl"
    assert "upstream=musl" in comps["musl-utils"].purl
    assert inv.warnings == []


def test_debian_source_version():
    _, comps = collect("debian-12")
    bash = comps["bash"]
    assert bash.ecosystem == "Debian:12"
    assert bash.version == "5.2.15-2+b13" and bash.meta["source_package"] == "bash"
    assert bash.meta["source_version"] == "5.2.15-2"
    assert "distro=debian-12" in bash.purl and "arch=amd64" in bash.purl
    # `Source: shadow` (name only) -> source version defaults to the binary version
    assert comps["login"].meta["source_package"] == "shadow"
    assert comps["login"].meta["source_version"] == comps["login"].version == "1:4.13+dfsg1-1+deb12u2"
    assert "upstream=shadow" in comps["login"].purl
    assert comps["libc6"].meta["source_package"] == "glibc"


def test_rocky_rpm():
    inv, comps = collect("rocky-9")
    ssl = comps["openssl-libs"]
    assert ssl.ecosystem == "Rocky Linux:9"
    assert ssl.version.startswith("1:3.0.7-") and ssl.meta["epoch"] == 1
    assert ssl.meta["source_package"] == "openssl"
    assert ssl.purl.startswith("pkg:rpm/rocky/openssl-libs@3.0.7-") and "epoch=1" in ssl.purl
    # no epoch in the header -> "0:" prefix keeps rpm comparisons consistent with OSV
    assert comps["rocky-release"].version.startswith("0:9.3-")
    assert "epoch" not in comps["rocky-release"].purl
    assert "gpg-pubkey" not in comps
    assert inv.asset.os_name == "Rocky Linux"


def test_parsers():
    assert rf.parse_os_release('A=1\nB="x y"\n# c\nC=\'z\'\n') == {"A": "1", "B": "x y", "C": "z"}
    pk = rf.parse_dpkg_status(
        "Package: a\nStatus: install ok installed\nVersion: 1\nSource: src (2)\nArchitecture: all\n"
        "Description: x\n y\n\nPackage: b\nStatus: deinstall ok config-files\nVersion: 1\n")
    assert [p["name"] for p in pk] == ["a"] and pk[0]["source_version"] == "2"
    ap = rf.parse_apk_installed("P:foo\nV:1-r0\nA:x86_64\no:bar\nL:MIT\nF:usr\nR:x\n\nP:baz\nV:2\n")
    assert ap[0]["origin"] == "bar" and ap[1]["origin"] == "baz"
    assert rf.parse_python_metadata("Metadata-Version: 2.1\nName: Foo_Bar\nVersion: 1.0\n\nName: no")["name"] == "Foo_Bar"
    assert rf.parse_package_json('{"name":"@a/b","version":"1"}')["name"] == "@a/b"
    assert rf.parse_package_json("not json") == {}
    assert rf.rpm_source_name("openssl-3.0.7-24.el9.src.rpm", "x") == "openssl"


def test_dirview_symlinks_do_not_escape(tmp_path: Path):
    outside = tmp_path / "secret"
    outside.write_text("HOST")
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "usr/lib").mkdir(parents=True)
    (root / "usr/lib/os-release").write_text("ID=alpine\nVERSION_ID=3.20.1\n")
    os.symlink("/usr/lib/os-release", root / "etc/os-release")           # absolute -> re-rooted
    os.symlink("../../secret", root / "etc/escape")                       # '..' beyond root -> clamped
    os.symlink("/../secret", root / "etc/escape2")
    v = rf.DirView(root)
    assert v.read_text("etc/os-release").startswith("ID=alpine")
    assert v.read("etc/escape") is None and v.read("etc/escape2") is None
    os.symlink("loop", root / "etc/loop")
    assert v.read("etc/loop") is None


def test_lang_packages_and_limits(tmp_path: Path):
    r = tmp_path
    (r / "usr/lib/python3/dist-packages/Foo_Bar-1.2.dist-info").mkdir(parents=True)
    (r / "usr/lib/python3/dist-packages/Foo_Bar-1.2.dist-info/METADATA").write_text(
        "Metadata-Version: 2.1\nName: Foo_Bar\nVersion: 1.2\n")
    nm = r / "app/node_modules"
    (nm / "@scope/pkg").mkdir(parents=True)
    (nm / "@scope/pkg/package.json").write_text('{"name":"@scope/pkg","version":"2.0.0"}')
    (nm / "left-pad/node_modules/inner").mkdir(parents=True)
    (nm / "left-pad/package.json").write_text('{"name":"left-pad","version":"1.3.0"}')
    (nm / "left-pad/node_modules/inner/package.json").write_text('{"name":"inner","version":"0.1.0"}')
    (nm / "left-pad/test").mkdir()
    (nm / "left-pad/test/package.json").write_text('{"name":"nope","version":"9"}')
    inv = REGISTRY["rootfs"]().collect(str(r))
    c = {x.name: x for x in inv.components}
    # display name keeps the original spelling; the purl is PEP 503-normalized
    assert c["Foo_Bar"].purl == "pkg:pypi/foo-bar@1.2" and c["Foo_Bar"].ecosystem == "PyPI"
    assert c["Foo_Bar"].category == CAT_LIBRARY
    assert c["@scope/pkg"].purl == "pkg:npm/%40scope/pkg@2.0.0" and c["@scope/pkg"].ecosystem == "npm"
    assert "left-pad" in c and "inner" in c and "nope" not in c
    assert c["left-pad"].source_path == "/app/node_modules/left-pad/package.json"
    assert any("not identified" in w for w in inv.warnings)


def test_rpm_legacy_bdb_warns(tmp_path: Path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc/os-release").write_text('ID="centos"\nVERSION_ID="7"\nNAME="CentOS Linux"\n')
    (tmp_path / "var/lib/rpm").mkdir(parents=True)
    (tmp_path / "var/lib/rpm/Packages").write_bytes(b"\x00\x00\x00\x00" * 8)
    asset = Asset("x", "server", "x")
    warns: list[str] = []
    rf.collect_from_view(rf.DirView(tmp_path), asset, warns)
    assert any("BerkeleyDB" in w for w in warns)


def test_id_like_fallback():
    assert rf.distro_ecosystem({"ID": "linuxmint", "ID_LIKE": "ubuntu debian", "VERSION_ID": "22.04"}) == "Ubuntu:22.04"
    assert rf.distro_ecosystem({"ID": "weird"}) is None


def test_rpmdb_wal_is_replayed(tmp_path: Path):
    import shutil
    import sqlite3

    db = tmp_path / "rpmdb.sqlite"
    shutil.copy(FX / "rocky-9/rootfs/var/lib/rpm/rpmdb.sqlite", db)
    n = len(rf.parse_rpmdb_sqlite(db))
    assert n >= 7
    # source db must be left untouched and openable read-only
    assert sqlite3.connect(f"file:{db}?mode=ro", uri=True).execute("select count(*) from Packages").fetchone()[0] >= n
