"""Generate _design/mock/data.js: the payloads the web UI renders, produced by the real code on the test fixtures.

    uv run python scripts/design_mock.py            # rewrite _design/mock/data.js

Runs `secmonk.web.api.ProcessMonitor` (the object behind `secmonk ui`) on tests/fixtures/collectors/process/
snapshot.json with the fixture tree, against a throw-away mirror holding a few advisories, then simulates one watch
tick (a new binary, a replaced binary, a changed launch item). Nothing outside a temporary directory is touched.

Advisories: GO-2022-1059 (golang.org/x/text < 0.3.8) and CVE-2024-6197 / CVE-2024-7264 (curl) are real records with
their real ranges; MOCK-2026-0001 is fictional (fictional product "ExampleUpdater"). No KEV entry is invented: P1/P2
and KEV styling is shown in the storybook instead.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from secmonk.collectors.process import snapshot as snapfile
from secmonk.collectors.process.model import LaunchItem
from secmonk.db import connect
from secmonk.sources.base import add_affected, upsert_vulnerability
from secmonk.web.api import ProcessMonitor

FIX = REPO / "tests/fixtures"
OUT = REPO / "_design/mock/data.js"


def build_root(tmp: Path) -> Path:
    """The shared fixture tree (tests/fixtures/collectors/process/fixture_root.py, also used by the tests)."""
    spec = importlib.util.spec_from_file_location("process_fixture_root", FIX / "collectors/process/fixture_root.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.build_root(tmp / "root")


def build_mirror(db: Path) -> None:
    c = connect(db)
    upsert_vulnerability(c, "osv", "GO-2022-1059", summary="golang.org/x/text: denial of service via crafted Accept-Language",
                         severity="HIGH", cvss_score=7.5)
    add_affected(c, "osv", "GO-2022-1059", ecosystem="Go", package="golang.org/x/text", range_type="SEMVER",
                 events=[{"introduced": "0"}, {"fixed": "0.3.8"}])
    for cve, intro, fixed, sev, score in (("CVE-2024-6197", "8.6.0", "8.9.0", "MEDIUM", 7.5),
                                          ("CVE-2024-7264", "7.32.0", "8.9.1", "MEDIUM", 6.5)):
        upsert_vulnerability(c, "cvelist", cve, summary=f"curl {cve}", severity=sev, cvss_score=score)
        add_affected(c, "cvelist", cve, vendor="haxx", product="curl", range_type="CVE",
                     events=[{"introduced": intro}, {"fixed": fixed}])
    upsert_vulnerability(c, "cvelist", "MOCK-2026-0001", summary="Fictional advisory for the design mock",
                         severity="CRITICAL", cvss_score=9.8)
    add_affected(c, "cvelist", "MOCK-2026-0001", vendor="example", product="exampleupdater", range_type="CVE",
                 events=[{"introduced": "0"}, {"fixed": "2.5.0"}])
    c.commit()
    c.close()


def main() -> None:
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        root = build_root(tmp)
        build_mirror(tmp / "mirror.db")
        src = FIX / "collectors/process/snapshot.json"
        snapshot = ProcessMonitor(db_path=tmp / "mirror.db", target=str(src), opts={"root": str(root)}).payload()

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
        mon = ProcessMonitor(db_path=tmp / "mirror.db", target=str(tmp / "base.json"), opts={"root": str(root)})
        mon.watch()                                               # baseline
        (root / "Users/alice/Library/Application Support/Sync/syncd").write_text("#!/bin/sh\n# replaced\nexec sleep 1\n")
        mon.target = str(tmp / "later.json")
        events = mon.watch()["events"]
    meta = {"version": "0.1.0", "mode": "snapshot", "platform": "darwin", "bind": "http://127.0.0.1:8765",
            "db": {"path": "~/.local/share/secmonk/secmonk.db", "exists": True}, "features": ["processes"]}
    data = {"meta": meta, "snapshot": snapshot, "events": events}
    text = json.dumps(data, indent=1, default=str)
    if str(tmp) in text:
        raise SystemExit("temporary path leaked into the mock")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("/* Generated by scripts/design_mock.py from the test fixtures: do not edit by hand. */\n"
                   f"window.SECMONK_MOCK = {text};\n")
    print(f"wrote {OUT.relative_to(REPO)}: {len(snapshot['processes'])} processes, {len(snapshot['software'])} software, "
          f"{len(events)} events")


if __name__ == "__main__":
    main()
