"""KEV source tests: local fixture import, full replace, mirror fallback. No network."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from secmonk.sources import kev
from secmonk.sources.base import SyncOptions


def test_import_fixture(conn, fixtures: Path):
    res = kev.KevSource().sync(conn, SyncOptions(path=fixtures / "kev" / "known_exploited_vulnerabilities.json"))
    assert res.status == "ok"
    assert res.cursor == "2026.11.06"
    assert conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0] == 9

    row = conn.execute("SELECT * FROM kev WHERE cve_id='CVE-2021-44228'").fetchone()
    assert row["vendor"] == "Apache"
    assert row["product"] == "Log4j2"
    assert row["ransomware"] == "1"  # 'Known' -> 1 (TEXT column, reads back as text)
    assert row["due_date"] == "2021-12-24"
    extra = json.loads(row["extra"])
    assert "requiredAction" in extra and "notes" in extra and "cwes" in extra
    assert "cveID" not in extra

    unknown = conn.execute("SELECT ransomware FROM kev WHERE cve_id='CVE-2019-8394'").fetchone()
    assert unknown["ransomware"] == "0"


def test_full_replace_drops_stale_rows(conn, fixtures: Path):
    conn.execute("INSERT INTO kev(cve_id, vendor) VALUES ('CVE-1999-0001', 'stale')")
    conn.commit()
    kev.KevSource().sync(conn, SyncOptions(path=fixtures / "kev" / "known_exploited_vulnerabilities.json"))
    assert conn.execute("SELECT COUNT(*) FROM kev WHERE cve_id='CVE-1999-0001'").fetchone()[0] == 0


def test_mirror_used_when_official_fails(conn, monkeypatch, fixtures: Path):
    doc = json.loads((fixtures / "kev" / "known_exploited_vulnerabilities.json").read_text())
    calls: list[str] = []

    def fake_download(url: str):
        calls.append(url)
        if url == kev.OFFICIAL_URL:
            raise httpx.ConnectError("blocked")
        return doc

    monkeypatch.setattr(kev, "_download", fake_download)
    res = kev.KevSource().sync(conn, SyncOptions())
    assert calls == [kev.OFFICIAL_URL, kev.MIRROR_URL]
    assert res.status == "ok"
    assert "mirror" in res.message and "official failed" in res.message
    assert conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0] == 9


def test_network_error_returns_error_result(conn, monkeypatch):
    def boom(url: str):
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(kev, "_download", boom)
    res = kev.KevSource().sync(conn, SyncOptions())
    assert res.status == "error"
    assert "no route" in res.message
