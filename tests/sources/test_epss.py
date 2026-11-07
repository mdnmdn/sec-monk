"""EPSS source tests: CSV with comment lines, gzip streaming, API batch parsing. No network."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

from secmonk.sources import epss
from secmonk.sources.base import SyncOptions


def test_import_csv_skips_comments_and_header(conn, fixtures: Path):
    res = epss.EpssSource().sync(conn, SyncOptions(path=fixtures / "epss" / "epss_scores-sample.csv"))
    assert res.status == "ok"
    assert res.records == 10
    assert res.cursor == "2026-11-06"
    row = conn.execute("SELECT * FROM epss WHERE cve_id='CVE-2021-44228'").fetchone()
    assert row["score"] == 0.97431
    assert row["percentile"] == 0.99986
    assert row["date"] == "2026-11-06"
    assert row["source"] == "epss"
    assert conn.execute("SELECT COUNT(*) FROM epss WHERE cve_id='cve,epss,percentile'").fetchone()[0] == 0


def test_import_gzip_path(conn, tmp_path: Path, fixtures: Path):
    gz = tmp_path / "epss_scores-current.csv.gz"
    gz.write_bytes(gzip.compress((fixtures / "epss" / "epss_scores-sample.csv").read_bytes()))
    res = epss.EpssSource().sync(conn, SyncOptions(path=gz))
    assert res.status == "ok" and res.records == 10


def test_line_splitting_across_chunks(monkeypatch):
    payload = gzip.compress(b"#model_version:v1,score_date:2026-01-02\ncve,epss,percentile\nCVE-1,0.5,0.6\n")
    chunks = [payload[i:i + 3] for i in range(0, len(payload), 3)]  # tiny chunks split every line
    lines = list(epss._iter_lines(iter(chunks), gz=True))
    rows = list(epss._parse_rows(lines))
    assert rows == [("CVE-1", 0.5, 0.6, "2026-01-02")]


def test_api_ids_parse_string_values(conn, monkeypatch, fixtures: Path):
    doc = json.loads((fixtures / "epss" / "api-sample.json").read_text())
    seen: list[list[str]] = []

    def fake_api(client, batch):
        seen.append(batch)
        return doc

    monkeypatch.setattr(epss, "_api_get", fake_api)
    res = epss.EpssSource().sync(conn, SyncOptions(ids=["cve-2021-44228", "CVE-2023-0001"]))
    assert res.status == "ok" and res.records == 2
    assert seen == [["CVE-2021-44228", "CVE-2023-0001"]]
    row = conn.execute("SELECT score, percentile FROM epss WHERE cve_id='CVE-2023-0001'").fetchone()
    assert row["score"] == 0.00043 and row["percentile"] == 0.04819
