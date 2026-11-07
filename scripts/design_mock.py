"""Generate _design/mock/data.js: the payloads the web UI renders, produced by the real code on the test fixtures.

    uv run python scripts/design_mock.py            # rewrite _design/mock/data.js

Everything happens in a temporary directory; the payloads are built by the objects behind `secmonk ui`
(`ProcessMonitor`, `DataApi`, `JobRunner`) and by `secmonk.reports`, so the design renders real shapes.

Process monitor: `ProcessMonitor` on tests/fixtures/collectors/process/snapshot.json with the fixture tree, then one
simulated watch tick (a new binary, a replaced binary, a changed launch item).

Mirror: the source fixtures imported by the real sources (KEV, EPSS, cvelist, NVD, EUVD, OSV: Log4Shell and the
Alpine xz backdoor), plus hand-added records: GO-2022-1059 (golang.org/x/text < 0.3.8), CVE-2024-6197 / CVE-2024-7264
(curl) and the npm advisories GHSA-35jh-r3h4-6jhm (lodash), GHSA-xvch-5gv4-984h (minimist), GHSA-c2qf-rxjj-qqgw
(semver) are real records with their real ranges; MOCK-2026-0001 is fictional (fictional product "ExampleUpdater").
The EPSS fixture is a synthetic sample (illustrative scores).

Assets, scanned with the real collectors from copies of the fixtures under /srv (paths rewritten from the temporary
directory): payments-api (tests/fixtures/lang/java: log4j-core 2.14.1), web-frontend (lang/javascript/npm-v3, rescanned
by a scan job after a lodash upgrade, so one finding is `fixed`), alpine-rootfs (docker/alpine-3.20 + xz-libs
5.6.0-r0), macbook (collectors/macos/root) and process:fixture-mac (saved by the process monitor).
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from secmonk import ops, reports
from secmonk.collectors.process import snapshot as snapfile
from secmonk.collectors.process.model import LaunchItem
from secmonk.db import connect
from secmonk.engine.match import canonical_ids, match_asset
from secmonk.engine.scoring import DEFERRED_TRIAGE, MINOR_TRIAGE
from secmonk.sources.base import SyncOptions, add_affected, add_alias, upsert_vulnerability
from secmonk.web.api import ProcessMonitor
from secmonk.web.data import DataApi
from secmonk.web.jobs import JobRunner

FIX = REPO / "tests/fixtures"
SRC = FIX / "sources"
OUT = REPO / "_design/mock/data.js"
MOCK_DB = "~/.local/share/secmonk/secmonk.db"


def build_root(tmp: Path) -> Path:
    """The shared fixture tree (tests/fixtures/collectors/process/fixture_root.py, also used by the tests)."""
    spec = importlib.util.spec_from_file_location("process_fixture_root", FIX / "collectors/process/fixture_root.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_root(tmp / "root")


def build_mirror(db: Path, files: Path) -> None:
    """Fixture records through the real sources, then hand-added real advisories (see the module docstring)."""
    reg = ops.sources_registry()
    c = connect(db)
    for name, rel in (("epss", "epss/epss_scores-sample.csv"), ("osv", "osv/maven-GHSA-jfh8-c2jp-5v3q.json"),
                      ("osv", "osv/alpine-ALPINE-CVE-2024-3094.json"), ("cvelist", "cvelist/CVE-2021-44228.json"),
                      ("nvd", "nvd/cve-2021-44228.json"), ("euvd", "euvd/exploited-sample.json")):
        f = files / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(SRC / rel, f)
        res, _ = ops.sync_source(c, name, reg[name], SyncOptions(path=f))
        assert res.status == "ok", (name, res)
    upsert_vulnerability(c, "osv", "GO-2022-1059", summary="golang.org/x/text: denial of service via crafted Accept-Language",
                         severity="HIGH", cvss_score=7.5)
    add_affected(c, "osv", "GO-2022-1059", ecosystem="Go", package="golang.org/x/text", range_type="SEMVER",
                 events=[{"introduced": "0"}, {"fixed": "0.3.8"}])
    for cve, intro, fixed, sev, score in (("CVE-2024-6197", "8.6.0", "8.9.0", "MEDIUM", 7.5),
                                          ("CVE-2024-7264", "7.32.0", "8.9.1", "MEDIUM", 6.5)):
        upsert_vulnerability(c, "cvelist", cve, summary=f"curl {cve}", severity=sev, cvss_score=score)
        add_affected(c, "cvelist", cve, vendor="haxx", product="curl", range_type="CVE",
                     events=[{"introduced": intro}, {"fixed": fixed}])
    npm = (("GHSA-35jh-r3h4-6jhm", "CVE-2021-23337", "lodash", "Command Injection in lodash", "HIGH", 7.2,
            [[{"introduced": "0"}, {"fixed": "4.17.21"}]]),
           ("GHSA-xvch-5gv4-984h", "CVE-2021-44906", "minimist", "Prototype Pollution in minimist", "CRITICAL", 9.8,
            [[{"introduced": "0"}, {"fixed": "0.2.4"}], [{"introduced": "1.0.0"}, {"fixed": "1.2.6"}]]),
           ("GHSA-c2qf-rxjj-qqgw", "CVE-2022-25883", "semver", "semver vulnerable to Regular Expression Denial of Service",
            "HIGH", 7.5, [[{"introduced": "0"}, {"fixed": "5.7.2"}], [{"introduced": "6.0.0"}, {"fixed": "6.3.1"}],
                          [{"introduced": "7.0.0"}, {"fixed": "7.5.2"}]]))
    for ghsa, cve, pkg, summary, sev, score, ranges in npm:
        upsert_vulnerability(c, "osv", ghsa, summary=summary, severity=sev, cvss_score=score)
        add_alias(c, "osv", ghsa, cve)
        for events in ranges:
            add_affected(c, "osv", ghsa, ecosystem="npm", package=pkg, purl=f"pkg:npm/{pkg}", range_type="SEMVER",
                         events=events)
    upsert_vulnerability(c, "cvelist", "MOCK-2026-0001", summary="Fictional advisory for the design mock",
                         severity="CRITICAL", cvss_score=9.8)
    add_affected(c, "cvelist", "MOCK-2026-0001", vendor="example", product="exampleupdater", range_type="CVE",
                 events=[{"introduced": "0"}, {"fixed": "2.5.0"}])
    c.commit()
    c.close()


def scan(db: Path, collector: str, target: Path) -> str:
    inv = ops.collect(collector, str(target), {})
    c = connect(db)
    try:
        ops.save_and_match(c, inv)
    finally:
        c.close()
    return inv.asset.id


def run_job(runner: JobRunner, body: dict) -> dict:
    job = runner.start(body)
    for _ in range(600):
        j = runner.get(job["id"])
        if j["status"] != "running":
            assert j["status"] == "ok", j
            return j
        time.sleep(0.05)
    raise SystemExit(f"job did not finish: {job}")


def monitor_payloads(tmp: Path, root: Path, db: Path) -> tuple[dict, list]:
    src = FIX / "collectors/process/snapshot.json"
    mon = ProcessMonitor(db_path=db, target=str(src), opts={"root": str(root)})
    snapshot = mon.payload()
    mon.save()                                                # asset process:fixture-mac

    # watch events: a second monitor starts from a baseline in which pid 404 runs zsh (not the Go binary), then
    # one tick sees hello start, syncd replaced on disk, the updater plist re-pointed and a new LaunchAgent
    base = snapfile.load(src)
    next(p for p in base.processes if p.pid == 404).exe = "/bin/zsh"
    snapfile.dump(base, tmp / "base.json")
    later = snapfile.load(src)
    later.launch_items[0].program = "/Users/alice/Downloads/updater-helper"
    later.launch_items.append(LaunchItem("launchd-agent", "com.example.newagent", "/Users/alice/.local/bin/agent",
                                         source="/Users/alice/Library/LaunchAgents/com.example.newagent.plist",
                                         scope="user:alice", run_at_load=True))
    snapfile.dump(later, tmp / "later.json")
    w = ProcessMonitor(db_path=db, target=str(tmp / "base.json"), opts={"root": str(root)})
    w.watch()                                                 # baseline
    (root / "Users/alice/Library/Application Support/Sync/syncd").write_text("#!/bin/sh\n# replaced\nexec sleep 1\n")
    w.target = str(tmp / "later.json")
    return snapshot, w.watch()["events"]


def main() -> None:
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        db = tmp / "mirror.db"
        root = build_root(tmp)
        srv = tmp / "srv"
        runner = JobRunner(db)
        kev = tmp / "files/kev/known_exploited_vulnerabilities.json"
        kev.parent.mkdir(parents=True)
        shutil.copy(SRC / "kev/known_exploited_vulnerabilities.json", kev)
        run_job(runner, {"kind": "sync", "sources": ["kev"], "path": str(kev)})      # job 1, creates the mirror
        build_mirror(db, tmp / "files")
        snapshot, events = monitor_payloads(tmp, root, db)

        shutil.copytree(FIX / "lang/java", srv / "payments-api")
        shutil.copytree(FIX / "lang/javascript/npm-v3", srv / "web-frontend")
        shutil.copytree(FIX / "collectors/docker/alpine-3.20/rootfs", srv / "alpine-rootfs")
        with (srv / "alpine-rootfs/lib/apk/db/installed").open("a") as fh:
            fh.write("P:xz-libs\nV:5.6.0-r0\nA:x86_64\no:xz\n\n")
        shutil.copytree(FIX / "collectors/macos/root", srv / "macbook")
        for collector, target in (("fs", "payments-api"), ("fs", "web-frontend"), ("rootfs", "alpine-rootfs"),
                                  ("macos", "macbook")):
            scan(db, collector, srv / target)
        lock = srv / "web-frontend/package-lock.json"
        text = lock.read_text()
        assert text.count('"version": "4.17.20"') == 1
        lock.write_text(text.replace('"version": "4.17.20"', '"version": "4.17.21"'))
        run_job(runner, {"kind": "scan", "collector": "fs", "target": str(srv / "web-frontend")})   # job 2: lodash fixed

        c = connect(db)
        try:
            assets = reports.asset_rows(c)
            details = {}
            for a in assets:
                stats = match_asset(c, a["id"], min_confidence=0.5)
                details[a["id"]] = {**reports.asset_detail(c, a["id"]), "match_stats": stats}
            # every id the pages can ask for (records, findings, matched advisories) -> canonical id, as the server resolves it
            vulns, vuln_ids = {}, {}
            asked = {r[0] for r in c.execute("SELECT id FROM vulnerability UNION SELECT vuln_id FROM finding")}
            asked |= {a for f in reports.findings(c, include_closed=True, limit=5000) for a in f["advisory_ids"]}
            for vid in sorted(asked):
                canon = canonical_ids(c, vid)[0]
                if canon not in vulns:
                    d = reports.vuln_detail(c, canon, raw=True)
                    if d is None:
                        continue
                    vulns[canon] = d
                vuln_ids[vid] = canon
            index = []
            for eco, pkg in c.execute("SELECT DISTINCT ecosystem, package FROM affected WHERE package IS NOT NULL"):
                index += reports.vuln_search(c, ecosystem=eco, package=pkg, limit=1000)
            for (prod,) in c.execute("SELECT DISTINCT product FROM affected WHERE product IS NOT NULL"):
                index += reports.vuln_search(c, product=prod, limit=1000)
            data_api = DataApi(db)
            overview = reports.overview(c, MOCK_DB)
            sources = data_api.sources()
            sources["db"]["path"] = sources["status"]["db"] = MOCK_DB
            data = {
                "meta": {"version": "0.1.0", "mode": "snapshot", "platform": "darwin", "bind": "http://127.0.0.1:8765",
                         "db": {"path": MOCK_DB, "exists": True},
                         "features": ["processes", "overview", "assets", "findings", "vulns", "sources", "scan", "jobs"],
                         "actions": True},
                "snapshot": snapshot, "events": events,
                "overview": overview, "assets": assets, "asset_details": details,
                "unmatched": reports.unmatched_rows(c),
                "findings": reports.findings(c, include_closed=True, limit=5000),
                "triage": {"minor": sorted(MINOR_TRIAGE), "deferred": sorted(DEFERRED_TRIAGE)},
                "vulns": vulns, "vuln_ids": vuln_ids, "vuln_index": index, "sources": sources,
                "collectors": data_api.collectors(),
                "jobs": [runner.get(j["id"]) for j in runner.list()],
            }
        finally:
            c.close()
        text = json.dumps(data, indent=1, default=str).replace(str(tmp), "")
    for leak in (str(tmp), str(REPO)):
        if leak in text:
            raise SystemExit(f"local path leaked into the mock: {leak}")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("/* Generated by scripts/design_mock.py from the test fixtures: do not edit by hand. */\n"
                   f"window.SECMONK_MOCK = {text};\n")
    print(f"wrote {OUT.relative_to(REPO)} ({len(text) // 1024} KiB): {len(snapshot['processes'])} processes, "
          f"{len(events)} events, {len(assets)} assets, {len(data['findings'])} findings, {len(vulns)} vulnerabilities, "
          f"{len(data['jobs'])} jobs")


if __name__ == "__main__":
    main()
