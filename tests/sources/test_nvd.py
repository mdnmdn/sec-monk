"""NVD source tests: local API-shaped import, CPE ranges, CVSS selection, delta windows. No network."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from secmonk.sources import nvd
from secmonk.sources.base import SyncOptions


def test_import_fixture(conn, fixtures: Path):
    res = nvd.NvdSource().sync(conn, SyncOptions(path=fixtures / "nvd" / "cve-2021-44228.json"))
    assert res.status == "ok" and res.records == 1

    vuln = conn.execute("SELECT * FROM vulnerability WHERE source='nvd' AND id='CVE-2021-44228'").fetchone()
    assert vuln["cvss_score"] == 10.0
    assert vuln["cvss_version"] == "3.1"
    assert vuln["severity"] == "CRITICAL"
    assert vuln["state"] == "Analyzed"
    assert json.loads(vuln["cwes"]) == ["CWE-917"]
    assert vuln["summary"].startswith("Apache Log4j2 2.0-beta9")

    aff = conn.execute("SELECT * FROM affected WHERE source='nvd' AND vuln_id='CVE-2021-44228'").fetchall()
    assert len(aff) == 1
    assert aff[0]["vendor"] == "apache" and aff[0]["product"] == "log4j"
    assert aff[0]["range_type"] == "CPE"
    assert json.loads(aff[0]["events"]) == [{"introduced": "2.0"}, {"fixed": "2.15.0"}]


def test_reimport_replaces_affected_rows(conn, fixtures: Path):
    path = fixtures / "nvd" / "cve-2021-44228.json"
    nvd.NvdSource().sync(conn, SyncOptions(path=path))
    nvd.NvdSource().sync(conn, SyncOptions(path=path))
    n = conn.execute("SELECT COUNT(*) FROM affected WHERE source='nvd'").fetchone()[0]
    assert n == 1


def test_cpe_version_rules(conn):
    base = "cpe:2.3:a:Vendor_Co:prod\\:name:{v}:*:*:*:*:*:*:*"

    def row_for(match: dict):
        nvd._add_cpe(conn, "CVE-X", match)
        return conn.execute("SELECT * FROM affected WHERE vuln_id='CVE-X' ORDER BY rowid_ DESC").fetchone()

    exact = row_for({"vulnerable": True, "criteria": base.format(v="1.2.3")})
    assert json.loads(exact["versions"]) == ["1.2.3"] and exact["events"] is None
    assert exact["vendor"] == "vendor co" and exact["product"] == "prod:name"  # '_' normalized

    all_versions = row_for({"vulnerable": True, "criteria": base.format(v="*")})
    assert json.loads(all_versions["events"]) == [{"introduced": "0"}]

    bounded = row_for({"vulnerable": True, "criteria": base.format(v="*"),
                       "versionStartExcluding": "1.0", "versionEndIncluding": "1.5"})
    assert json.loads(bounded["events"]) == [{"introduced_exclusive": "1.0"}, {"last_affected": "1.5"}]


def test_best_cvss_prefers_newest_and_primary():
    metrics = {
        "cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 5.0, "version": "3.1", "baseSeverity": "MEDIUM"}},
            {"type": "Primary", "cvssData": {"baseScore": 7.5, "version": "3.1", "baseSeverity": "HIGH"}},
        ],
        "cvssMetricV2": [{"type": "Primary", "baseSeverity": "LOW", "cvssData": {"baseScore": 2.0}}],
    }
    assert nvd._best_cvss(metrics) == (7.5, None, "3.1", "HIGH")
    v2 = nvd._best_cvss({"cvssMetricV2": [{"type": "Primary", "baseSeverity": "LOW",
                                           "cvssData": {"baseScore": 2.0, "version": "2.0"}}]})
    assert v2 == (2.0, None, "2.0", "LOW")


def test_cwes_skip_nvd_placeholders():
    weak = [
        {"type": "Secondary", "description": [{"lang": "en", "value": "CWE-79"}]},
        {"type": "Primary", "description": [{"lang": "en", "value": "NVD-CWE-Other"},
                                            {"lang": "en", "value": "CWE-20"}]},
    ]
    assert nvd._cwes(weak) == ["CWE-20", "CWE-79"]


def test_delta_windows_respect_cap():
    start = datetime(2026, 1, 1, tzinfo=UTC)
    end = datetime(2026, 7, 1, tzinfo=UTC)  # 181 days later
    windows = list(nvd._windows(start, end))
    assert len(windows) == 2
    assert all((hi - lo).days <= 119 for lo, hi in windows)
    assert windows[0][0] == start and windows[-1][1] == end
