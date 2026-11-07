"""Process monitor: parsers, launch classification, identity, provenance, flags, inventory, CLI.

Fixtures (synthetic, see tests/fixtures/collectors/process/README.md): `snapshot.json` + a tree built at test
time from the macOS fixture root, the process overlay and the Go fixture binary.
"""

from __future__ import annotations

import json
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
def root(tmp_path) -> Path:
    r = tmp_path / "root"
    shutil.copytree(FIX / "collectors/macos/root", r, symlinks=True)
    shutil.copytree(PFIX / "root", r, symlinks=True, dirs_exist_ok=True)
    (r / "usr/local/bin").mkdir(parents=True)
    shutil.copy(FIX / "lang/go/hello-darwin-arm64", r / "usr/local/bin/hello")
    return r


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
    broken = pm.parse_codesign("Identifier=x\nAuthority=Developer ID Application: X\nsomething: invalid signature", 1)
    assert broken["error"]


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
    assert r.exit_code == 1 and "not implemented on plan9" in r.output


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
