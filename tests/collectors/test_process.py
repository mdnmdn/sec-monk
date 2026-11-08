"""Process monitor: parsers, launch classification, identity, provenance, flags, inventory, CLI.

Fixtures (synthetic, see tests/fixtures/collectors/process/README.md): `snapshot.json` + a tree built at test
time from the macOS fixture root, the process overlay and the Go fixture binary.
"""

from __future__ import annotations

import errno
import json
import os
import plistlib
import shutil
import sqlite3
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secmonk import procmon
from secmonk.cli import app
from secmonk.collectors.base import REDACTED, REGISTRY
from secmonk.collectors.process import macos as pm
from secmonk.collectors.process import snapshot as snapfile
from secmonk.collectors.process.backend import Inspector, backend_for
from secmonk.collectors.process.collector import ProcessCollector, build_views
from secmonk.collectors.process.launch import LaunchClassifier
from secmonk.collectors.process.model import LaunchItem, ProcessRecord, Snapshot
from secmonk.db import connect
from secmonk.engine.classify import classify
from secmonk.models import CAT_EXECUTABLE, CAT_OS, CAT_PACKAGE, CAT_RUNTIME, CAT_SYSTEM_APP
from secmonk.sources.base import add_affected, upsert_vulnerability

FIX = Path(__file__).parents[1] / "fixtures"
PFIX = FIX / "collectors" / "process"
SNAP = PFIX / "snapshot.json"


@pytest.fixture
def root(process_root) -> Path:
    return process_root


@pytest.fixture
def analysed(root):
    return ProcessCollector().analyse(str(SNAP), root=str(root))


def _view(views, pid):
    return next(v for v in views if v.proc.pid == pid)


# ----------------------------------------------------------------------------- parsers

def test_parse_ps():
    procs = pm.parse_ps((PFIX / "ps.txt").read_text())
    assert [p.pid for p in procs] == [1, 95, 300, 301, 402]
    helper = procs[3]
    assert helper.ppid == 300 and helper.uid == 501 and helper.user == "alice"
    assert helper.exe.endswith("Slack Helper.app/Contents/MacOS/Slack Helper")     # spaces kept
    assert helper.started == "2026-11-07T09:01:13"
    login_shell = procs[4]
    assert login_shell.exe is None and login_shell.name == "-zsh"                 # comm not a path


def test_parse_ps_args_redacts():
    args = pm.parse_ps_args((PFIX / "ps-args.txt").read_text())
    assert args[301][-1] == "--type=utility"
    curl = args[403]
    assert "https://example.com/x" in curl and not any("pw@" in a or "token=abc" in a for a in curl)
    assert curl[curl.index("--password") + 1] == REDACTED
    spaced = pm.parse_ps_args("  7 tool --password a b --verbose x\n")[7]
    assert spaced == ["tool", "--password", REDACTED, REDACTED, "--verbose", "x"]


def test_parse_launchctl_list():
    assert pm.parse_launchctl_list((PFIX / "launchctl-list.txt").read_text()) == {
        320: "com.sync.agent", 300: "application.com.tinyspeck.slackmacgap.1234.5678"}


def test_parse_codesign_variants():
    dev = pm.parse_codesign((PFIX / "codesign-developer-id.txt").read_text())
    assert dev["signed"] and dev["developer_id"] and dev["team_id"] == "EQHXZ8M8AV"
    assert dev["hardened_runtime"] and dev["identifier"] == "com.google.Chrome"
    assert dev["authority"][0].startswith("Developer ID Application: Google LLC")
    adhoc = pm.parse_codesign((PFIX / "codesign-adhoc.txt").read_text())
    assert adhoc["adhoc"] and "team_id" not in adhoc
    assert pm.parse_codesign((PFIX / "codesign-unsigned.txt").read_text(), 1) == {"signed": False}
    # display failures that are not about the signature are "unknown", never "invalid"
    assert pm.parse_codesign("/x: No such file or directory", 1) == {"unknown": "/x: No such file or directory"}
    mas = pm.parse_codesign("Identifier=com.apple.iWork.Pages\nAuthority=Apple Mac OS Application Signing\n"
                            "Authority=Apple Worldwide Developer Relations Certification Authority\n"
                            "Authority=Apple Root CA\n")
    assert mas.get("mac_app_store") and not mas.get("apple")
    system = pm.parse_codesign("Identifier=com.apple.ls\nAuthority=Software Signing\nAuthority=Apple Code Signing "
                               "Certification Authority\nAuthority=Apple Root CA\n")
    assert system["apple"]


def test_parse_codesign_verify():
    assert pm.parse_codesign_verify("", 0) == {"verified": True}
    bad = pm.parse_codesign_verify("/A.app: a sealed resource is missing or invalid\nfile modified: x", 1)
    assert bad["verified"] is False and "modified" in bad["error"]
    assert pm.parse_codesign_verify("/A.app: Operation not permitted", 1) is None


def test_parse_pkgutil_file_info():
    [p] = pm.parse_pkgutil_file_info((PFIX / "pkgutil-file-info.txt").read_text())
    assert p == {"pkgid": "com.amazon.aws.cli2", "version": "2.17.20", "install_time": "2024-10-01T08:30:00+00:00"}


def test_parse_quarantine_and_where_froms():
    q = pm.parse_quarantine(b"0083;66fbb308;Safari;9F0C1E52-6D3B-4E0B-9C59-1B2A3C4D5E6F\x00")
    assert q["agent"] == "Safari" and q["event_id"].startswith("9F0C1E52")
    assert q["time"] == "2024-10-01T08:30:00+00:00" and q["user_approved"] is False
    assert pm.parse_quarantine("00c1;zz;;")["user_approved"] is True and "time" not in pm.parse_quarantine("00c1;zz;;")
    assert pm.parse_quarantine(None) is None
    wf = plistlib.dumps(["https://u:p@dl.example.com/a.dmg?sig=1", "https://example.com/"], fmt=plistlib.FMT_BINARY)
    assert pm.parse_where_froms(wf) == ["https://dl.example.com/a.dmg", "https://example.com/"]
    assert pm.parse_where_froms(b"not a plist") == []


def test_quarantine_event_db(tmp_path):
    db = tmp_path / "QuarantineEventsV2"
    with sqlite3.connect(db) as c:
        c.execute("""CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT, LSQuarantineTimeStamp REAL,
                     LSQuarantineAgentBundleIdentifier TEXT, LSQuarantineAgentName TEXT,
                     LSQuarantineDataURLString TEXT, LSQuarantineOriginURLString TEXT, LSQuarantineSenderName TEXT)""")
        c.execute("INSERT INTO LSQuarantineEvent VALUES (?,?,?,?,?,?,?)",
                  ("9F0C1E52-6D3B-4E0B-9C59-1B2A3C4D5E6F", 749464200.0, "com.apple.Safari", "Safari",
                   "https://dl.example.com/app.dmg?token=x", "https://example.com/download", None))
    ev = pm.quarantine_event(db, "9f0c1e52-6d3b-4e0b-9c59-1b2a3c4d5e6f")
    assert ev == {"time": "2024-10-01T08:30:00+00:00", "agent_bundle_id": "com.apple.Safari", "agent": "Safari",
                  "data_url": "https://dl.example.com/app.dmg", "origin_url": "https://example.com/download"}
    assert pm.quarantine_event(db, "nope") is None
    assert pm.quarantine_event(tmp_path / "missing", "x") is None


def test_embedded_info_plist():
    data = (PFIX / "root/Library/PrivilegedHelperTools/com.example.updater").read_bytes()
    assert pm.embedded_info_plist(data)["CFBundleIdentifier"] == "com.example.updater"
    assert pm.embedded_info_plist(b"\0" * 100) is None


def test_index_launch_items(root):
    items, warnings = pm.index_launch_items(root, pm.home_dirs(root))
    by = {i.label: i for i in items}
    assert by["com.example.updater"].mechanism == "launchd-daemon" and by["com.example.updater"].keep_alive
    assert by["com.example.updater"].meta["MachServices"] == ["com.example.updater.xpc"]
    assert by["com.example.stale"].program == "/usr/local/libexec/gone"
    assert by["com.apple.syslogd"].mechanism == "launchd-system-daemon"
    assert by["com.openssh.sshd"].disabled is True
    agent = by["com.sync.agent"]
    assert agent.scope == "user:alice" and agent.args == [f"--api-key={REDACTED}"]
    assert agent.source == "/Users/alice/Library/LaunchAgents/com.sync.agent.plist"
    assert any("broken.plist" in w for w in warnings)
    no_sys, _ = pm.index_launch_items(root, [], include_system=False)
    assert {i.mechanism for i in no_sys} == {"launchd-daemon"}


# ----------------------------------------------------------------------------- snapshot file

def test_snapshot_roundtrip_and_validation(tmp_path):
    snap = snapfile.load(SNAP)
    assert snap.platform == "darwin" and snap.os["version"] == "14.5" and len(snap.processes) == 21
    curl = next(p for p in snap.processes if p.pid == 403)
    assert curl.args == ["curl", "https://example.com/x"]                      # re-redacted on load
    out = tmp_path / "s.json"
    snapfile.dump(snap, out)
    assert snapfile.load(out).processes == snap.processes
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema": "other"}))
    with pytest.raises(ValueError, match="schema"):
        snapfile.load(bad)
    junk = {"schema": snapfile.SCHEMA, "processes": [{"pid": "x"}, 5, {"pid": 7, "args": "rm -rf", "exe": 3}],
            "launch_items": [{"label": "a"}], "executables": {"/x": 1}}
    s = snapfile.from_dict(junk)
    assert [(p.pid, p.exe, p.args) for p in s.processes] == [(7, None, [])]
    assert s.launch_items == [] and s.executables == {}


# ----------------------------------------------------------------------------- launch classification

def test_launch_classification(analysed):
    _, _, views = analysed
    expect = {
        0: ("kernel", None), 1: ("kernel", None),
        95: ("service", "pid-label"),          # system daemon plist via launchctl label
        120: ("service", "exe-match"),         # daemon plist Program == exe
        300: ("gui-app", "pid-label"),         # LaunchServices application.<bundle>.<n>.<n>
        301: ("child", "parent"),
        310: ("gui-app", "parent"),            # child of launchd inside an .app
        320: ("agent", "pid-label"),
        402: ("interactive", "ancestry"), 403: ("interactive", "ancestry"),
        503: ("remote-session", "ancestry"),
        601: ("scheduled", "parent"), 602: ("scheduled", "ancestry"),
    }
    for pid, (kind, evidence) in expect.items():
        li = _view(views, pid).launch
        assert (li.kind, li.evidence if evidence else None) == (kind, evidence), pid
    assert _view(views, 403).launch.via.endswith("Terminal.app/Contents/MacOS/Terminal")
    assert _view(views, 320).launch.source == "/Users/alice/Library/LaunchAgents/com.sync.agent.plist"
    assert _view(views, 301).launch.parent_exe.endswith("MacOS/Slack")


def test_launch_ancestry_cycle_and_scope_pick():
    snap = Snapshot("darwin", "h", "", [ProcessRecord(10, 11, "/a"), ProcessRecord(11, 10, "/b")],
                    launch_items=[LaunchItem("launchd-agent", "x.bob", "/c", scope="user:bob"),
                                  LaunchItem("launchd-agent", "x.ann", "/c", scope="user:ann")])
    lc = LaunchClassifier(snap)
    assert lc.classify(snap.processes[0]).kind == "child"                    # no infinite loop
    assert lc.classify(ProcessRecord(12, 99, "/c", user="ann")).label == "x.ann"


# ----------------------------------------------------------------------------- identity + provenance

def test_identity_resolution(analysed):
    _, _, views = analysed
    slack, helper = _view(views, 300), _view(views, 301)
    assert slack.resolution.method == "app-bundle" and slack.identity.name == "Slack"
    assert [c.name for c in slack.resolution.components] == ["Slack", "Electron"]
    assert helper.identity.version == slack.identity.version and helper.resolution.notes["helper"] == "Slack Helper.app"
    curl = _view(views, 403)
    assert curl.resolution.method == "brew-keg" and (curl.identity.name, curl.identity.version) == ("curl", "8.7.1")
    assert curl.resolution.notes["resolved_from"] == "/opt/homebrew/bin/curl"   # symlink followed in the tree
    hello = _view(views, 404)
    assert hello.resolution.method == "go-binary"
    assert {c.name for c in hello.resolution.components} >= {"stdlib", "golang.org/x/text"}
    upd = _view(views, 120)
    assert upd.resolution.method == "info-plist" and upd.identity.meta["bundle_id"] == "com.example.updater"
    assert upd.identity.version == "2.4.1"
    assert _view(views, 95).identity.category == CAT_OS
    assert _view(views, 400).identity.category == CAT_SYSTEM_APP
    assert _view(views, 320).identity.category == CAT_EXECUTABLE
    assert _view(views, 405).script == "/Users/alice/tool.py"


def test_provenance_facts(analysed):
    _, _, views = analysed
    chrome = _view(views, 310)
    assert chrome.facts["quarantine"]["event"]["data_url"].endswith("googlechrome.dmg")   # from the snapshot
    syncd = _view(views, 320).facts
    assert syncd["exists"] and len(syncd["sha256"]) == 64 and "signature" not in syncd   # no codesign off-Mac
    assert _view(views, 503).facts == {"exists": False}


def test_xattr_provenance(root, monkeypatch, tmp_path):
    """Quarantine xattr on the bundle + LaunchServices event in the user's QuarantineEventsV2."""
    db = root / "Users/alice/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2"
    db.parent.mkdir(parents=True)
    with sqlite3.connect(db) as c:
        c.execute("""CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT, LSQuarantineTimeStamp REAL,
                     LSQuarantineAgentBundleIdentifier TEXT, LSQuarantineAgentName TEXT,
                     LSQuarantineDataURLString TEXT, LSQuarantineOriginURLString TEXT, LSQuarantineSenderName TEXT)""")
        c.execute("INSERT INTO LSQuarantineEvent VALUES ('E1', 749464200, 'com.google.Chrome', 'Chrome',"
                  " 'https://downloads.slack-edge.com/Slack.dmg', 'https://slack.com/download', NULL)")

    def fake(path, name):
        if str(path).endswith("Slack.app") and name == "com.apple.quarantine":
            return b"0083;66fbb308;Chrome;E1"
        return None

    monkeypatch.setattr(pm, "_getxattr", fake)
    snap = snapfile.load(SNAP)
    snap.executables = {}
    insp = pm.MacOSInspector(snap, root, {}, [])
    f = insp.facts("/Applications/Slack.app/Contents/MacOS/Slack")
    assert f["quarantine"]["on"] == "/Applications/Slack.app"
    assert f["quarantine"]["event"]["data_url"] == "https://downloads.slack-edge.com/Slack.dmg"


def test_offline_snapshot_reads_nothing(monkeypatch):
    """Without -o root a foreign snapshot is analysed from paths alone: no file on this machine is read."""
    monkeypatch.setattr(pm, "read_within", lambda *a, **k: pytest.fail("read a file"))
    _, insp, views = ProcessCollector().analyse(str(SNAP))
    curl = _view(views, 403)
    assert curl.resolution.method == "none"            # /opt/homebrew/bin/curl: no fs to follow the symlink
    slack = _view(views, 300)
    assert slack.resolution.method == "path-only" and slack.identity.name == "Slack" and slack.identity.version is None
    assert _view(views, 95).identity.category == CAT_OS
    assert _view(views, 310).facts["signature"]["developer_id"]                   # facts from the snapshot
    keg = insp.resolve("/opt/homebrew/Cellar/jq/1.7.1_1/bin/jq")
    assert keg.method == "brew-keg" and keg.primary.version == "1.7.1" and keg.primary.category == CAT_PACKAGE
    assert insp.resolve("/usr/local/bin/tool-from-agent").method == "snapshot"


def test_generic_backend_for_other_platforms():
    snap = Snapshot("windows", "pc", "", [ProcessRecord(4, 0, None, name="System"),
                                          ProcessRecord(800, 4, "C:\\Program Files\\App\\app.exe")],
                    executables={"C:\\Program Files\\App\\app.exe": {"identity": {
                        "name": "App", "version": "1.0", "company": "ACME"}}})
    b = backend_for("windows")
    assert b.take_snapshot is None
    insp = b.inspector(snap, None, {}, [])
    assert type(insp) is Inspector
    views = build_views(snap, insp)
    assert views[1].identity.name == "App" and views[1].identity.meta["company"] == "ACME"
    assert insp.unidentified("C:\\x\\y.exe").name == "y.exe"


# ----------------------------------------------------------------------------- flags + inventory

def test_risk_flags(analysed):
    _, _, views = analysed
    assert set(_view(views, 320).flags) == {"user-writable-path", "persistent-from-user-path", "unidentified"}
    assert set(_view(views, 503).flags) == {"exe-missing", "user-writable-path", "root-from-user-path", "unidentified"}
    assert _view(views, 310).flags == ["downloaded"]
    assert _view(views, 300).flags == []


def test_inventory(analysed):
    snap, insp, views = analysed
    inv = ProcessCollector().inventory(snap, insp, views, {})
    assert inv.asset.id == "process:fixture-mac" and inv.asset.platform == "darwin"
    assert inv.asset.meta["process_count"] == 21 and inv.asset.meta["launch_kinds"]["interactive"] == 4
    assert len(inv.asset.meta["processes"]) == 21
    names = [c.name for c in inv.components]
    assert names.count("Slack") == 1 and names.count("macOS") == 1
    slack = next(c for c in inv.components if c.name == "Slack")
    pmeta = slack.meta["process"]
    assert pmeta["count"] == 2 and set(pmeta["launch"]) == {"gui-app", "child"} and pmeta["users"] == ["alice"]
    assert len(pmeta["executables"]) == 2
    electron = next(c for c in inv.components if c.name == "Electron")
    assert electron.category == CAT_RUNTIME and electron.meta["process"]["via_executable"].endswith("MacOS/Slack")
    chrome = next(c for c in inv.components if c.name == "Google Chrome")
    prov = chrome.meta["process"]["provenance"]["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]
    assert prov["quarantine"]["agent"] == "Safari" and prov["where_froms"]
    curl = next(c for c in inv.components if c.name == "curl")
    assert curl.meta["process"]["provenance"]["/opt/homebrew/bin/curl"]["identity_installed_at"]
    missing = inv.asset.meta["launch_items_missing_program"]
    assert [m["label"] for m in missing] == ["com.openssh.sshd"]
    for c in inv.components:
        classify(c)
    os_c = next(c for c in inv.components if c.category == CAT_OS)
    assert os_c.version == "14.5" and set(os_c.meta["process"]["launch"]) >= {"service", "scheduled"}


def test_registered():
    assert REGISTRY["process"] is ProcessCollector


def test_take_snapshot_glue(root, monkeypatch):
    """The live path on a non-Mac: commands replaced by the fixture outputs."""
    outputs = {"comm=": (PFIX / "ps.txt").read_text(), "args=": (PFIX / "ps-args.txt").read_text(),
               "list": (PFIX / "launchctl-list.txt").read_text()}

    def fake_run(cmd, timeout=30):
        key = next(k for k in outputs if k in cmd[-1])
        return subprocess.CompletedProcess(cmd, 0, outputs[key], "")

    monkeypatch.setattr(pm, "_run", fake_run)
    snap = pm.take_snapshot(root, {"hostname": "mac1"})
    assert snap.host == "mac1" and snap.os["version"] == "14.5"
    assert {p.pid: p.label for p in snap.processes}[300].startswith("application.com.tinyspeck")
    assert next(p for p in snap.processes if p.pid == 301).args[-1] == "--type=utility"
    assert {i.label for i in snap.launch_items} >= {"com.example.updater", "com.sync.agent"}


# ----------------------------------------------------------------------------- monitor + CLI

def test_watcher_reports_new_executables_and_launch_items(root):
    snap, insp, _ = ProcessCollector().analyse(str(SNAP), root=str(root))
    w = procmon.Watcher(insp)
    assert w.tick(snap)[1] == []                                             # first tick = baseline
    snap2 = snapfile.load(SNAP)
    snap2.processes += [ProcessRecord(900, 402, "/usr/local/bin/hello", user="alice"),
                        ProcessRecord(901, 1, "/Users/alice/Downloads/evil", uid=501, user="alice"),
                        ProcessRecord(902, 1, "/Users/alice/Downloads/evil", uid=501, user="alice")]
    snap2.launch_items = snap2.launch_items[1:] + [LaunchItem("launchd-agent", "com.evil", "/Users/alice/Downloads/evil",
                                                              source="/Users/alice/Library/LaunchAgents/com.evil.plist")]
    _, events = w.tick(snap2)
    kinds = [(e.kind, e.data["view"].proc.exe if "view" in e.data else e.data["item"].label) for e in events]
    assert kinds == [("new-executable", "/Users/alice/Downloads/evil"), ("new-launch-item", "com.evil"),
                     ("removed-launch-item", "com.example.updater")]
    assert w.tick(snap2)[1] == []


def test_tree_rows_order_and_suspicious(analysed):
    _, _, views = analysed
    rows = procmon.tree_rows(views)
    assert [r["pid"] for r in rows][:4] == [0, 1, 95, 120]
    zsh = next(r for r in rows if r["pid"] == 402)
    assert zsh["depth"] == 4 and next(r for r in rows if r["pid"] == 403)["depth"] == 5
    assert {r["pid"] for r in rows if procmon.interesting(r)} == {310, 320, 503}


@pytest.fixture
def mirror(tmp_path) -> Path:
    db = tmp_path / "m.db"
    c = connect(db)
    upsert_vulnerability(c, "osv", "GO-2022-1059", summary="x/text DoS", severity="HIGH", cvss_score=7.5)
    add_affected(c, "osv", "GO-2022-1059", ecosystem="Go", package="golang.org/x/text", range_type="SEMVER",
                 events=[{"introduced": "0"}, {"fixed": "0.3.8"}])
    c.commit()
    c.close()
    return db


def test_cli_procs_json_with_findings(root, mirror):
    r = CliRunner().invoke(app, ["procs", str(SNAP), "-o", f"root={root}", "--db", str(mirror), "-f", "json"])
    assert r.exit_code == 0, r.output
    doc = json.loads(r.stdout)
    hello = next(p for p in doc["processes"] if p["pid"] == 404)
    assert hello["findings"].startswith("P") and hello["findings_detail"][0]["vuln_id"] == "GO-2022-1059"
    assert hello["findings_detail"][0]["component"] == "golang.org/x/text"
    assert doc["launch_items_missing_program"][0]["label"] == "com.openssh.sshd"
    # the default overlay match persists nothing
    with sqlite3.connect(mirror) as c:
        assert c.execute("SELECT COUNT(*) FROM asset").fetchone()[0] == 0


def test_cli_procs_under_sudo_with_foreign_default_db(root, monkeypatch):
    """`sudo secmonk procs` on macOS keeps HOME: the default DB folder belongs to the invoking user (2026-11-08)."""
    from secmonk import paths
    from secmonk.db import connect as db_connect

    db_connect(None).close()                                  # the user's default database exists
    monkeypatch.setattr(paths.os, "getuid", lambda: 0)        # ... and we are now someone else (root)
    monkeypatch.setattr("secmonk.cli.os.geteuid", lambda: 0, raising=False)
    monkeypatch.setenv("SUDO_USER", "alice")
    r = CliRunner().invoke(app, ["procs", str(SNAP), "-o", f"root={root}", "-f", "json"])
    assert r.exit_code == 0, r.output                         # processes still listed, without findings
    err = " ".join(r.stderr.split())                          # rich wraps long lines
    assert "showing processes without findings" in err and "sudo -H" in err
    assert json.loads(r.stdout)["processes"]
    r = CliRunner().invoke(app, ["procs", str(SNAP), "-o", f"root={root}", "--save"])
    assert r.exit_code == 1 and "not owned by the current user" in " ".join(r.stderr.split())
    assert isinstance(r.exception, SystemExit)                # a clean exit, not a PermissionError traceback


def test_cli_procs_save_suspicious_and_table(root, mirror):
    r = CliRunner().invoke(app, ["procs", str(SNAP), "-o", f"root={root}", "--db", str(mirror), "--save",
                                 "--suspicious", "--flat", "-f", "json"])
    assert r.exit_code == 0, r.output
    assert {p["pid"] for p in json.loads(r.stdout)["processes"]} == {310, 320, 404, 503}
    with sqlite3.connect(mirror) as c:
        assert c.execute("SELECT id FROM asset").fetchall() == [("process:fixture-mac",)]
        assert c.execute("SELECT COUNT(*) FROM finding").fetchone()[0] == 1
    t = CliRunner().invoke(app, ["procs", str(SNAP), "-o", f"root={root}", "--no-match"])
    assert t.exit_code == 0 and "persistent-from-user-path" in t.stdout and "remote-session" in t.stdout


def test_cli_scan_process(root, mirror):
    r = CliRunner().invoke(app, ["scan", "process", str(SNAP), "-o", f"root={root}", "--db", str(mirror),
                                 "-f", "json"])
    assert r.exit_code == 0, r.output
    assert [f["vuln_id"] for f in json.loads(r.stdout)["findings"]] == ["GO-2022-1059"]


def test_cli_procs_errors(monkeypatch):
    runner = CliRunner()
    assert runner.invoke(app, ["procs", str(SNAP), "--watch", "5"]).exit_code == 2
    monkeypatch.setattr("secmonk.collectors.process.collector.current_platform", lambda: "plan9")
    r = runner.invoke(app, ["procs", "--no-match"])
    assert r.exit_code == 1 and "not implemented on plan9" in " ".join(r.output.split())


def test_cli_procs_watch(root, mirror, monkeypatch):
    """--watch loop with the live snapshot replaced: baseline, then one tick with a new executable + launch item."""
    base = snapfile.load(SNAP)
    later = snapfile.load(SNAP)
    later.processes.append(ProcessRecord(900, 1, "/usr/local/bin/hello", uid=501, user="alice"))
    later.processes[[p.pid for p in later.processes].index(404)].exe = "/bin/zsh"     # hello only appears later
    base.processes[[p.pid for p in base.processes].index(404)].exe = "/bin/zsh"
    later.launch_items.append(LaunchItem("launchd-agent", "com.new", "/usr/local/bin/hello", scope="user:alice"))
    snaps = iter([base, later])
    monkeypatch.setattr(ProcessCollector, "snapshot", staticmethod(lambda target=None, **o: next(snaps)))
    monkeypatch.setattr("secmonk.cli.time.sleep", lambda s: None)
    r = CliRunner().invoke(app, ["procs", "-o", f"root={root}", "--db", str(mirror), "--watch", "1",
                                 "--max-ticks", "1", "-f", "json"])
    assert r.exit_code == 0, r.output
    events = [json.loads(line) for line in r.stdout.splitlines() if line.startswith("{")]
    assert [e["event"] for e in events] == ["new-executable", "new-launch-item"]
    assert events[0]["exe"] == "/usr/local/bin/hello" and events[0]["findings"].startswith("P")
    assert events[1]["label"] == "com.new"


# ----------------------------------------------------------------------------- review regressions

def test_generic_program_plist_does_not_claim_every_shell():
    """A plist whose program is /bin/bash must not label every bash on the machine as that service."""
    snap = Snapshot("darwin", "h", "", [
        ProcessRecord(1, 0, "/sbin/launchd", uid=0),
        ProcessRecord(400, 1, "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", uid=501),
        ProcessRecord(401, 400, "/bin/bash", uid=501),
        ProcessRecord(402, 401, "/usr/bin/vim", uid=501),
        ProcessRecord(500, 1, "/bin/bash", uid=0, label="com.mdm.helper"),
    ], launch_items=[LaunchItem("launchd-daemon", "com.mdm.helper", "/bin/bash", scope="system")])
    lc = LaunchClassifier(snap)
    shell = lc.classify(snap.processes[2])
    assert shell.kind == "child" and shell.label is None                      # not "service (com.mdm.helper)"
    assert lc.classify(snap.processes[3]).kind == "interactive"
    assert lc.classify(snap.processes[4]).label == "com.mdm.helper"          # the pid label still attributes it


REAL_SNAP = PFIX / "real" / "snapshot-user.json"


def test_real_user_snapshot_launch_classification(tmp_path):
    """Trimmed live snapshot (macOS 26.5, arm64, non-root): see tests/fixtures/collectors/process/real/README.md."""
    from secmonk.collectors.process.collector import missing_launch_programs

    snap = snapfile.load(REAL_SNAP)
    assert snap.os == {"name": "macOS", "version": "26.5", "build": "25F71"}
    lc = LaunchClassifier(snap)
    got = {p.pid: lc.classify(p) for p in snap.processes}
    by_exe = {p.pid: p.exe for p in snap.processes}
    assert got[1].kind == "kernel"
    assert (got[456].kind, got[456].label) == ("service", "com.apple.logd")
    assert (got[1896].kind, got[1896].label) == ("service", "at.obdev.littlesnitch.daemon")
    assert got[531].mechanism == "launchd-system-daemon"                     # cfprefsd as root: the daemon
    assert got[712].mechanism == "launchd-system-agent"                      # cfprefsd as _locationd: the agent
    for pid in (770, 2529, 16134, 41203, 44169):                             # incl. the .<UUID> label form
        assert got[pid].kind == "gui-app", by_exe[pid]
    assert got[905].kind == got[1751].kind == "xpc-service"                  # .appex widget, .xpc service
    uv = got[45376]
    assert (uv.kind, uv.mechanism, uv.via) == ("interactive", "terminal", "/Applications/Warp.app/Contents/MacOS/stable")
    os_owned = {i.label for i in snap.launch_items if i.meta.get("os_owned")}
    assert "com.apple.cvmsCompAgent_arm64" in os_owned and "com.docker.socket" not in os_owned
    insp = pm.MacOSInspector(snap, tmp_path, {}, [])                         # empty root: every program missing
    assert {m["label"] for m in missing_launch_programs(snap, insp)} == {"at.obdev.littlesnitch.daemon",
                                                                         "com.docker.socket"}


def test_real_root_snapshot_launch_classification():
    """Trimmed live root snapshot (same Mac, same day): system labels plus each user's domain (`launchctl asuser`)."""
    snap = snapfile.load(PFIX / "real" / "snapshot-root.json")
    assert not snap.warnings
    lc = LaunchClassifier(snap)
    got = {p.pid: lc.classify(p) for p in snap.processes}
    assert (got[529].kind, got[529].label) == ("service", "com.apple.WindowServer")      # only labelled as root
    assert (got[895].kind, got[895].label) == ("service", "com.apple.adid")
    assert (got[539].kind, got[539].mechanism) == ("service", "launchd-system-daemon")   # lsd as root
    assert (got[743].kind, got[743].mechanism) == ("agent", "launchd-system-agent")      # lsd as the user
    assert got[26682].kind == "service" and got[26683].kind == "agent"                   # XProtect daemon / agent
    assert got[3225].evidence == "pid-label" and got[3225].kind == "agent"               # user-domain label
    for pid in (770, 2529, 16134, 41203, 44169):
        assert got[pid].kind == "gui-app"
    assert got[45376].kind == "interactive"


def _app_tree(base: Path) -> Path:
    """Apps shipping launch definitions the way SMAppService / SMLoginItemSetEnabled apps do (layout as on macOS 26.5)."""
    def plist(path: Path, data: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(plistlib.dumps(data))

    app = base / "Applications/Example App.app/Contents"
    plist(app / "Info.plist", {"CFBundleIdentifier": "com.example.app", "CFBundleShortVersionString": "1.0"})
    plist(app / "Library/LaunchAgents/com.example.app.agent.plist",
          {"Label": "com.example.app.agent", "BundleProgram": "Contents/Library/LaunchAgents/agent", "RunAtLoad": True})
    plist(app / "Library/LaunchDaemons/com.example.app.helper.plist",       # relative ProgramArguments[0]
          {"Label": "com.example.app.helper", "ProgramArguments": ["Contents/MacOS/helper", "--daemon"]})
    plist(app / "Library/LaunchAgents/com.example.app.evil.plist",
          {"Label": "com.example.app.evil", "BundleProgram": "../../../../../usr/bin/evil"})
    plist(app / "Library/LoginItems/Example Helper.app/Contents/Info.plist",
          {"CFBundleIdentifier": "ABCDE12345.com.example.helper", "CFBundleExecutable": "Example Helper"})
    nested = base / "Applications/Vendor/Other.app/Contents"                 # one folder level down
    plist(nested / "Info.plist", {"CFBundleIdentifier": "com.vendor.other"})
    plist(nested / "Library/LoginItems/OtherLauncher.app/Contents/Info.plist",
          {"CFBundleIdentifier": "com.vendor.other.launcher", "CFBundleExecutable": "OtherLauncher"})
    home_app = base / "Users/alice/Applications/Mine.app/Contents"
    plist(home_app / "Library/LaunchAgents/com.mine.agent.plist", {"Label": "com.mine.agent", "Program": "/opt/mine"})
    (base / "Applications/Link.app").symlink_to("Example App.app")           # walked once, via the target
    return base


def test_app_bundle_launch_items(tmp_path):
    root = _app_tree(tmp_path)
    warnings: list[str] = []
    items = pm.index_app_launch_items(root, [root / "Users/alice"], warnings)
    by = {i.label: i for i in items}
    assert not warnings and len(items) == len(by) == 6
    agent = by["com.example.app.agent"]
    assert (agent.mechanism, agent.scope, agent.program) == (
        "launchd-app-agent", "system", "/Applications/Example App.app/Contents/Library/LaunchAgents/agent")
    assert agent.meta["host_app"] == "/Applications/Example App.app"
    assert by["com.example.app.helper"].mechanism == "launchd-app-daemon"
    assert by["com.example.app.helper"].program == "/Applications/Example App.app/Contents/MacOS/helper"
    assert by["com.example.app.evil"].program is None                        # `..` out of the bundle
    li = by["ABCDE12345.com.example.helper"]
    li_bundle = "/Applications/Example App.app/Contents/Library/LoginItems/Example Helper.app"
    assert (li.mechanism, li.program, li.source) == ("login-item", f"{li_bundle}/Contents/MacOS/Example Helper", li_bundle)
    assert by["com.vendor.other.launcher"].meta["host_app"] == "/Applications/Vendor/Other.app"
    assert by["com.mine.agent"].scope == "user:alice"
    # the login-item helper runs under a `<TeamID>.<id>` label that is no plist: attributed by its executable
    snap = Snapshot("darwin", "h", "", [ProcessRecord(1, 0, "/sbin/launchd", uid=0),
                                        ProcessRecord(40, 1, li.program, uid=501, user="alice", label="XYZ.other")],
                    launch_items=items)
    info = LaunchClassifier(snap).classify(snap.processes[1])
    assert (info.kind, info.evidence, info.label) == ("login-item", "exe-match", "ABCDE12345.com.example.helper")


def test_parse_btm_is_tolerant():
    recs = pm.parse_btm((PFIX / "sfltool-dumpbtm.txt").read_text())
    assert len(recs) == 8 and {r["uid"] for r in recs} == {-2, 501}
    by = {r["id"]: r for r in recs}
    up = by["com.example.updater"]
    assert (up["type"], up["enabled"], up["allowed"]) == ("legacy daemon", True, False)
    assert up["path"] == "/Library/LaunchDaemons/com.example.updater.plist"
    helper = by["ABCDE12345.com.example.helper"]                              # relative to its parent app record
    assert helper["path"] == "/Applications/Example App.app/Contents/Library/LoginItems/Example Helper.app"
    assert helper["program"] is None and (helper["enabled"], helper["allowed"]) == (True, True)
    assert by["com.example.app.agent"]["program"] == "/Applications/Example App.app/Contents/Library/LaunchAgents/agent"
    assert "some future field" not in by["com.example.app.agent"]
    new = by["com.example.new"]
    assert new["type"] == "curious new type" and new["path"] is None          # `..` out of the parent app
    assert by["Unknown Developer"]["type"] == "developer"
    assert pm.parse_btm("garbage\n  Type: agent\n") == []                      # fields outside a record: ignored
    assert pm.parse_btm(" #1:\n   Type: agent (0x8)\n")[0]["uid"] is None    # no UID header


def test_apply_btm(tmp_path):
    root = _app_tree(tmp_path)
    (root / "Library/LaunchDaemons").mkdir(parents=True)
    (root / "Library/LaunchDaemons/com.example.updater.plist").write_bytes(plistlib.dumps(
        {"Label": "com.example.updater", "Program": "/Library/Example/Updater.app/Contents/MacOS/Updater"}))
    items, _ = pm.index_launch_items(root, [root / "Users/alice"], include_system=False)
    n_before = len(items)
    recs = pm.parse_btm((PFIX / "sfltool-dumpbtm.txt").read_text())
    matched, added = pm.apply_btm(items, recs, lambda t: pm._btm_addable(root / t.lstrip("/")))
    by = {i.label: i for i in items}
    assert by["com.example.updater"].disabled is True                        # disallowed in Login Items
    assert by["com.example.updater"].meta["btm"] == {"type": "legacy daemon", "enabled": True, "allowed": False}
    assert by["ABCDE12345.com.example.helper"].meta["btm"]["allowed"] is True
    assert by["ABCDE12345.com.example.helper"].disabled is None              # running is allowed: unchanged
    assert by["com.example.app.agent"].disabled is True
    assert "com.example.gone" not in by and added == 0 and len(items) == n_before   # stale record not added
    assert matched == 3                                                      # quicklook / app / developer ignored
    # without an existence check (e.g. a dump analysed on its own) BTM-only records are added
    items2: list[LaunchItem] = []
    _, added2 = pm.apply_btm(items2, recs)
    assert added2 == 4 and all(i.meta["from_btm"] for i in items2)
    assert {i.scope for i in items2} == {"system", "uid:501"}


def test_btm_option_failures(tmp_path, monkeypatch):
    w: list[str] = []
    monkeypatch.setattr(pm.os, "geteuid", lambda: 501)
    assert pm.btm_records(True, w) is None and "needs root" in w[-1]
    assert pm.btm_records(str(tmp_path / "nope.txt"), w) is None and "cannot read BTM dump" in w[-1]
    (tmp_path / "x.txt").write_text("not a dump\n")
    assert pm.btm_records(str(tmp_path / "x.txt"), w) == [] and "no records" in w[-1]
    monkeypatch.setattr(pm.os, "geteuid", lambda: 0)
    monkeypatch.setattr(pm, "_run", lambda cmd, timeout=30: subprocess.CompletedProcess(
        cmd, 0, (PFIX / "sfltool-dumpbtm.txt").read_text(), ""))
    assert len(pm.btm_records(True, w)) == 8


def test_gui_label_with_uuid_suffix():
    # real labels from macOS 26.5 launchctl list (the UUID form for apps relaunched by the system)
    snap = Snapshot("darwin", "h", "", [
        ProcessRecord(1, 0, "/sbin/launchd", uid=0),
        ProcessRecord(10, 1, "/Applications/Claude.app/Contents/MacOS/Claude", uid=501,
                      label="application.com.anthropic.claudefordesktop.345365221.345365228"),
        ProcessRecord(11, 1, "/Applications/Ollama.app/Contents/MacOS/Ollama", uid=501,
                      label="application.com.electron.ollama.345754396.345754402.BBF5BE8F-F0F8-40E3-B2CF-4EA205C511CC"),
        ProcessRecord(12, 1, "/usr/local/bin/tool", uid=501, label="application.com.example.1.2.not-a-uuid"),
        # widget extension started by launchd without a label (live macOS 26.5: 49 such processes)
        ProcessRecord(13, 1, "/System/Applications/Weather.app/Contents/PlugIns/WeatherWidget.appex/Contents/MacOS/"
                             "WeatherWidget", uid=501),
    ])
    lc = LaunchClassifier(snap)
    assert [lc.classify(p).kind for p in snap.processes[1:]] == ["gui-app", "gui-app", "agent", "xpc-service"]


def test_label_shared_by_daemon_and_agent_and_instance_labels():
    # macOS 26.5: com.apple.lsd is both /System/Library/LaunchDaemons and LaunchAgents; instance jobs carry .<UUID>
    items = [LaunchItem("launchd-system-daemon", "com.apple.lsd", "/usr/libexec/lsd", scope="system"),
             LaunchItem("launchd-system-agent", "com.apple.lsd", "/usr/libexec/lsd", scope="system"),
             LaunchItem("launchd-system-agent", "com.apple.loginwindow", "/x/loginwindow", scope="system")]
    snap = Snapshot("darwin", "h", "", [
        ProcessRecord(1, 0, "/sbin/launchd", uid=0),
        ProcessRecord(10, 1, "/usr/libexec/lsd", uid=0, user="root", label="com.apple.lsd"),
        ProcessRecord(11, 1, "/usr/libexec/lsd", uid=501, user="alice", label="com.apple.lsd"),
        ProcessRecord(12, 1, "/x/loginwindow", uid=501, user="alice",
                      label="com.apple.loginwindow.15693B03-4006-43BB-9907-29AEEBE114CB"),
    ], launch_items=items)
    lc = LaunchClassifier(snap)
    got = [lc.classify(p) for p in snap.processes[1:]]
    assert [(i.kind, i.mechanism) for i in got[:2]] == [("service", "launchd-system-daemon"),
                                                        ("agent", "launchd-system-agent")]
    assert (got[2].label, got[2].evidence) == ("com.apple.loginwindow", "pid-label")


def test_root_snapshot_reads_user_domain_labels(monkeypatch):
    calls = []

    def fake_run(cmd, timeout=30):
        calls.append(cmd)
        out = "PID\tStatus\tLabel\n300\t0\tapplication.com.example.App.1.2\n" if "asuser" in cmd else ""
        return subprocess.CompletedProcess(cmd, 0, out, "")

    monkeypatch.setattr(pm, "_run", fake_run)
    procs = [ProcessRecord(1, 0, "/sbin/launchd", uid=0, label=None),
             ProcessRecord(95, 1, "/usr/sbin/syslogd", uid=0, label="com.apple.syslogd"),
             ProcessRecord(300, 1, "/Applications/App.app/Contents/MacOS/App", uid=501, label=None),
             ProcessRecord(310, 1, "/usr/libexec/locationd", uid=205, label=None)]   # service account: skipped
    warnings: list[str] = []
    pm._add_user_domain_labels(procs, warnings)
    assert calls == [["launchctl", "asuser", "501", "launchctl", "list"]]
    assert procs[2].label == "application.com.example.App.1.2" and procs[1].label == "com.apple.syslogd"
    assert not warnings


def test_shell_spawned_by_daemon_is_a_child_not_interactive():
    snap = Snapshot("darwin", "h", "", [
        ProcessRecord(1, 0, "/sbin/launchd", uid=0),
        ProcessRecord(120, 1, "/Library/PrivilegedHelperTools/updater", uid=0),
        ProcessRecord(121, 120, "/bin/sh", uid=0),
        ProcessRecord(122, 121, "/usr/bin/curl", uid=0),
        ProcessRecord(130, 1, "/usr/bin/login", uid=0),
        ProcessRecord(131, 130, "/bin/zsh", uid=501),
        ProcessRecord(132, 131, "/usr/bin/vim", uid=501),
    ])
    lc = LaunchClassifier(snap)
    curl = lc.classify(snap.processes[3])
    assert curl.kind == "child" and curl.via == "/Library/PrivilegedHelperTools/updater"
    vim = lc.classify(snap.processes[6])
    assert (vim.kind, vim.mechanism) == ("interactive", "login")             # console login, no terminal app


def test_untrusted_snapshot_facts_are_typed_and_stripped(tmp_path):
    d = json.loads(SNAP.read_text())
    d["executables"]["/usr/sbin/syslogd"] = {
        "signature": "yes", "size": True, "junk": {"x": 1},
        "where_froms": ["https://u:p@h/f.dmg?X-Amz-Signature=SECRET", 3],
        "quarantine": {"agent": "Safari", "event": {"data_url": "https://a:b@x/y?token=t", "origin_url": 5}}}
    f = tmp_path / "s.json"
    f.write_text(json.dumps(d))
    facts = snapfile.load(f).executables["/usr/sbin/syslogd"]
    assert facts == {"where_froms": ["https://h/f.dmg"],
                     "quarantine": {"agent": "Safari", "event": {"data_url": "https://x/y"}}}
    r = CliRunner().invoke(app, ["procs", str(f), "--no-match", "-f", "json"])
    assert r.exit_code == 0, r.output and "SECRET" not in r.stdout


def test_copied_tree_links_never_reach_the_host(root):
    """An absolute symlink in a copied tree points at the analyst's machine: no facts from there."""
    (root / "usr/local/bin/hostlink").symlink_to("/etc/hostname")
    snap = snapfile.load(SNAP)
    snap.executables = {}
    insp = pm.MacOSInspector(snap, root, {}, [])
    assert insp.facts("/usr/local/bin/hostlink") == {"outside_root": True}
    assert insp.facts("/does/not/exist") == {"exists": False}


def test_non_utf8_process_output_does_not_abort(root, monkeypatch):
    real_run = subprocess.run

    def fake(cmd, **kw):
        out = b"  300     1   501 alice  Thu Nov  7 09:01:12 2026     /Applications/Caf\xe9.app/Contents/MacOS/C\n"
        return real_run(["printf", "%s", out.decode("latin-1")], **{**kw, "env": {"LC_ALL": "C"}}) \
            if cmd[0] == "ps" else subprocess.CompletedProcess(cmd, 1, "", "")

    monkeypatch.setattr(pm.subprocess, "run", fake)
    snap = pm.take_snapshot(root, {"args": False})
    assert snap.processes and snap.processes[0].pid == 300


def test_snapshot_timeout_is_a_collector_error(root, monkeypatch):
    def boom(cmd, timeout=30):
        raise subprocess.TimeoutExpired(cmd, timeout)

    monkeypatch.setattr(pm, "_run", boom)
    with pytest.raises(RuntimeError, match="ps failed"):
        pm.take_snapshot(root, {})


def test_watcher_reports_replaced_binary_and_edited_plist(root):
    snap, insp, _ = ProcessCollector().analyse(str(SNAP), root=str(root))
    w = procmon.Watcher(insp)
    w.tick(snap)
    syncd = root / "Users/alice/Library/Application Support/Sync/syncd"
    syncd.write_text("#!/bin/sh\n# updated payload, different size\nexec sleep 9999\n")
    snap2 = snapfile.load(SNAP)
    snap2.launch_items[0].program = "/Users/alice/Downloads/evil"
    _, events = w.tick(snap2)
    kinds = [(e.kind, e.data["view"].proc.exe if "view" in e.data else e.data["item"].label) for e in events]
    assert ("changed-executable", "/Users/alice/Library/Application Support/Sync/syncd") in kinds
    assert ("changed-launch-item", "com.example.updater") in kinds
    assert w.tick(snap2)[1] == []


def test_cli_watch_save_keeps_the_asset(root, mirror, monkeypatch):
    """--watch --save stores each tick as a partial increment: the baseline components stay current."""
    base = snapfile.load(SNAP)
    later = snapfile.load(SNAP)
    later.processes.append(ProcessRecord(900, 1, "/Users/alice/Library/Application Support/Sync/syncd", uid=501))
    snaps = iter([base, later])
    monkeypatch.setattr(ProcessCollector, "snapshot", staticmethod(lambda target=None, **o: next(snaps)))

    def sleep(_s):          # between baseline and tick: the agent binary is replaced on disk
        (root / "Users/alice/Library/Application Support/Sync/syncd").write_text("replaced payload\n")

    monkeypatch.setattr("secmonk.cli.time.sleep", sleep)
    r = CliRunner().invoke(app, ["-q", "procs", "-o", f"root={root}", "--db", str(mirror), "--save", "--watch", "1",
                                 "--max-ticks", "1"])
    assert r.exit_code == 0, r.output
    assert "CHANGED exe" in r.stdout
    c = connect(mirror)
    from secmonk.engine.inventory import current_components
    names = {row["name"] for row in current_components(c, "process:fixture-mac")}
    assert {"Slack", "curl", "golang.org/x/text"} <= names
    assert c.execute("SELECT COUNT(*) FROM finding WHERE status='open'").fetchone()[0] == 1
    c.close()


# ----------------------------------------------------------------------------- restricted host (EPERM)
# Observed on macOS 26.5 under a host restriction (2026-11-08): exec of `ps` -> PermissionError,
# `launchctl list` -> exit 1, listing /Users, /Library/LaunchDaemons, ~/Library/LaunchAgents -> EPERM.

def _eperm(path) -> PermissionError:
    return PermissionError(errno.EPERM, "Operation not permitted", str(path))


def test_ps_not_executable_is_a_clear_collector_error(root, monkeypatch):
    def denied(cmd, timeout=30):
        raise _eperm(cmd[0])

    monkeypatch.setattr(pm, "_run", denied)
    with pytest.raises(RuntimeError, match=r"ps failed: PermissionError.*denied on this host.*snapshot"):
        pm.take_snapshot(root, {})


def test_cli_procs_ps_denied_exits_1_without_traceback(monkeypatch):
    monkeypatch.setattr("secmonk.collectors.process.collector.current_platform", lambda: "darwin")
    monkeypatch.setattr(pm, "_run", lambda cmd, timeout=30: (_ for _ in ()).throw(_eperm(cmd[0])))
    res = CliRunner().invoke(app, ["procs", "--no-match", "-f", "json"])
    assert res.exit_code == 1
    assert "ps failed: PermissionError" in res.output and "Traceback" not in res.output


def test_snapshot_degrades_when_launchctl_and_dirs_are_denied(root, monkeypatch):
    outputs = {"comm=": (PFIX / "ps.txt").read_text(), "args=": (PFIX / "ps-args.txt").read_text()}

    def fake_run(cmd, timeout=30):
        if cmd[0] == "launchctl":
            raise _eperm("launchctl")
        return subprocess.CompletedProcess(cmd, 0, outputs[next(k for k in outputs if k in cmd[-1])], "")

    denied = {str(root / "Users"), str(root / "Library/LaunchDaemons")}
    real_iterdir = Path.iterdir

    def iterdir(self):
        if str(self) in denied:
            raise _eperm(self)
        return real_iterdir(self)

    monkeypatch.setattr(pm, "_run", fake_run)
    monkeypatch.setattr(Path, "iterdir", iterdir)
    snap = pm.take_snapshot(root, {"hostname": "mac1"})
    assert len(snap.processes) == 5 and not any(p.label for p in snap.processes)
    w = "\n".join(snap.warnings)
    assert "launchctl list failed (PermissionError" in w
    assert "cannot list /Users: permission denied" in w and "Full Disk Access" in w
    assert "cannot list /Library/LaunchDaemons: permission denied" in w
    labels = {i.label for i in snap.launch_items}
    assert "com.apple.syslogd" in labels and "com.example.updater" not in labels   # readable dirs still indexed


def test_home_dirs_fall_back_to_own_home_on_live_root(monkeypatch):
    real_iterdir = Path.iterdir

    def iterdir(self):
        if str(self) == "/Users":
            raise _eperm(self)
        return real_iterdir(self)

    monkeypatch.setattr(Path, "iterdir", iterdir)
    warnings: list[str] = []
    homes = pm.home_dirs(Path("/"), None, warnings)
    assert warnings and warnings[0].startswith("cannot list /Users:")
    assert homes == ([Path.home()] if Path.home().is_dir() else [])


def test_inspector_denied_command_warns_once_and_keeps_going(root, monkeypatch):
    monkeypatch.setattr(pm, "_run", lambda cmd, timeout=30: (_ for _ in ()).throw(_eperm(cmd[0])))
    snap = snapfile.load(SNAP)
    snap.executables = {}
    warnings: list[str] = []
    insp = pm.MacOSInspector(snap, root, {}, warnings)
    insp.live = True                                   # as on a Mac: codesign / pkgutil would run
    exes = ["/Applications/Slack.app/Contents/MacOS/Slack", "/Library/PrivilegedHelperTools/com.example.updater",
            "/opt/homebrew/Cellar/curl/8.7.1/bin/curl"]
    facts = [insp.facts(e) for e in exes]
    assert all(f.get("exists") and "signature" not in f for f in facts)
    assert [w for w in warnings if w.startswith("cannot run codesign: PermissionError")] != []
    assert len([w for w in warnings if w.startswith("cannot run codesign")]) == 1


def test_denied_executable_is_not_reported_missing(root, monkeypatch):
    exe = "/Applications/Slack.app/Contents/MacOS/Slack"
    real_lstat = Path.lstat

    def lstat(self):
        if str(self).endswith(exe):
            raise _eperm(self)
        return real_lstat(self)

    monkeypatch.setattr(Path, "lstat", lstat)
    snap = snapfile.load(SNAP)
    snap.executables = {}
    warnings: list[str] = []
    insp = pm.MacOSInspector(snap, root, {}, warnings)
    assert insp.facts(exe) == {}                       # unknown, not {"exists": False} -> no exe-missing flag
    assert len(warnings) == 1 and "permission denied" in warnings[0]


def test_denied_bundle_is_identified_by_path_only(root, monkeypatch):
    real_open = os.open

    def fake_open(path, *a, **k):
        if ".app/Contents/Info.plist" in str(path):
            raise _eperm(path)
        return real_open(path, *a, **k)

    monkeypatch.setattr(os, "open", fake_open)
    snap = snapfile.load(SNAP)
    warnings: list[str] = []
    insp = pm.MacOSInspector(snap, root, {}, warnings)
    for exe in ("/Applications/Slack.app/Contents/MacOS/Slack", "/Applications/Firefox.app/Contents/MacOS/firefox"):
        res = insp.resolve(exe)
        assert res.method == "path-only" and res.primary.version is None
    assert insp.resolve("/Applications/Slack.app/Contents/MacOS/Slack").primary.name == "Slack"
    assert len([w for w in warnings if "app bundles" in w]) == 1


def test_non_app_bundle_wrappers_are_identified(root):
    # live macOS 26.5: Little Snitch's daemon `.bundle`, an OBS `.systemextension` (synthetic plists, real layout)
    def bundle(rel: str, bid: str, ver: str) -> str:
        c = root / rel / "Contents"
        (c / "MacOS").mkdir(parents=True)
        (c / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": bid, "CFBundleShortVersionString": ver}))
        exe = c / "MacOS" / bid
        exe.write_bytes(b"\xcf\xfa\xed\xfe")
        return "/" + str(exe.relative_to(root))

    ls = bundle("Library/Application Support/Little Snitch/at.obdev.littlesnitch.daemon.bundle",
                "at.obdev.littlesnitch.daemon", "5.8")
    ext = bundle("Library/SystemExtensions/0000/com.example.camera.systemextension", "com.example.camera", "30.1.2")
    bare = root / "Library/Thing.bundle/Contents/MacOS"
    bare.mkdir(parents=True)
    (bare / "thing").write_bytes(b"\xcf\xfa\xed\xfe")
    insp = pm.MacOSInspector(snapfile.load(SNAP), root, {}, [])
    for exe, ver in ((ls, "5.8"), (ext, "30.1.2")):
        res = insp.resolve(exe)
        assert (res.method, res.primary.version) == ("app-bundle", ver)
    assert insp.resolve("/Library/Thing.bundle/Contents/MacOS/thing").method != "app-bundle"   # no Info.plist


def test_os_owned_launch_item_with_missing_program_is_not_reported(tmp_path):
    # macOS 26.5: e.g. com.apple.cvmsCompAgent_arm64 -> OpenGLES.framework/CVMCompiler, absent on this hardware
    from secmonk.collectors.process.collector import missing_launch_programs

    for rel, label in (("System/Library/LaunchAgents", "com.apple.dormant"), ("Library/LaunchDaemons", "com.example.gone")):
        (tmp_path / rel).mkdir(parents=True)
        (tmp_path / rel / f"{label}.plist").write_bytes(plistlib.dumps({"Label": label, "Program": f"/opt/{label}"}))
    items, _ = pm.index_launch_items(tmp_path, [])
    assert {i.label: i.meta.get("os_owned", False) for i in items} == {"com.apple.dormant": True, "com.example.gone": False}
    snap = Snapshot(platform="darwin/arm64", host="h", taken_at="t", processes=[], launch_items=items)
    insp = pm.MacOSInspector(snap, tmp_path, {}, [])
    assert [m["label"] for m in missing_launch_programs(snap, insp)] == ["com.example.gone"]


def test_bundle_without_info_plist(root):
    # macOS 26.5: /System/Library/CoreServices/liquiddetectiond.app has the binary at the top, no Info.plist
    sysapp = root / "System/Library/CoreServices/liquiddetectiond.app"
    sysapp.mkdir(parents=True)
    (sysapp / "liquiddetectiond").write_bytes(b"\xcf\xfa\xed\xfe")
    other = root / "Applications/Empty.app/Contents/MacOS"
    other.mkdir(parents=True)
    (other / "Empty").write_bytes(b"\xcf\xfa\xed\xfe")
    warnings: list[str] = []
    insp = pm.MacOSInspector(snapfile.load(SNAP), root, {}, warnings)
    assert insp.resolve("/System/Library/CoreServices/liquiddetectiond.app/liquiddetectiond").method == "os"
    res = insp.resolve("/Applications/Empty.app/Contents/MacOS/Empty")
    assert (res.method, res.primary.name) == ("path-only", "Empty")
    assert not [w for w in warnings if "Info.plist" in w]


def test_real_unquoted_launchd_plist_is_indexed(tmp_path):
    """Apple ships com.apple.familycircled.plist with an unquoted XML prolog (macOS 26.5, real fixture)."""
    d = tmp_path / "System/Library/LaunchAgents"
    d.mkdir(parents=True)
    shutil.copy(FIX / "collectors/macos/real/launchd/com.apple.familycircled.plist", d)
    items, warnings = pm.index_launch_items(tmp_path, [])
    assert warnings == []
    assert [(i.label, i.mechanism) for i in items] == [("com.apple.familycircled", "launchd-system-agent")]
    assert items[0].program.endswith("/FamilyCircle.framework/Versions/A/Resources/familycircled")
