"""collect -> save -> match on a synthetic Alpine rootfs against a real OSV Alpine advisory."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("secmonk.sources.osv")

from secmonk.collectors import rootfs  # noqa: F401
from secmonk.collectors.base import REGISTRY
from secmonk.engine.inventory import save_inventory
from secmonk.engine.match import match_asset
from secmonk.sources.base import SyncOptions
from secmonk.sources.osv import OsvSource

OSV = Path(__file__).parent / "fixtures" / "sources" / "osv" / "alpine-ALPINE-CVE-2024-3094.json"


def _rootfs(tmp: Path, xz_version: str) -> Path:
    (tmp / "etc").mkdir(parents=True)
    (tmp / "lib/apk/db").mkdir(parents=True)
    (tmp / "etc/os-release").write_text('NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.20.3\n')
    (tmp / "lib/apk/db/installed").write_text(
        f"P:xz-libs\nV:{xz_version}\nA:x86_64\no:xz\n\nP:musl\nV:1.2.5-r0\nA:x86_64\no:musl\n\n")
    return tmp


def _findings(conn, asset_id):
    return conn.execute("SELECT f.*, c.name FROM finding f JOIN component c ON c.id=f.component_id "
                        "WHERE f.asset_id=?", (asset_id,)).fetchall()


def test_alpine_xz_backdoor_found(conn, tmp_path):
    OsvSource().sync(conn, SyncOptions(path=OSV))
    inv = REGISTRY["rootfs"]().collect(str(_rootfs(tmp_path / "vuln", "5.6.0-r0")))
    save_inventory(conn, inv)
    match_asset(conn, inv.asset.id)
    rows = _findings(conn, inv.asset.id)
    assert rows, "expected the xz backdoor advisory to match"
    f = rows[0]
    assert f["matched_by"] == "osv-package" and f["name"] == "xz-libs"      # matched via origin `xz`
    assert f["vuln_id"] == "CVE-2024-3094" and f["fixed_version"] == "5.6.1-r2"


def test_fixed_version_not_flagged(conn, tmp_path):
    OsvSource().sync(conn, SyncOptions(path=OSV))
    inv = REGISTRY["rootfs"]().collect(str(_rootfs(tmp_path / "fixed", "5.6.1-r2")))
    save_inventory(conn, inv)
    match_asset(conn, inv.asset.id)
    assert _findings(conn, inv.asset.id) == []
