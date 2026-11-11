"""Process monitor, Linux backend: /proc parsers, launch items, identity, the remote ssh snapshot.

Fixtures (synthetic, see tests/fixtures/collectors/process/linux/README.md): a Debian tree with a `/proc` built at
test time, fake GNU/Debian tools for running the real remote script on it, and a captured script output.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from secmonk.collectors import ssh
from secmonk.collectors.base import REDACTED
from secmonk.collectors.process import linux, remote
from secmonk.collectors.process import snapshot as snapfile
from secmonk.collectors.process.backend import BACKENDS, backend_for
from secmonk.collectors.process.collector import ProcessCollector, build_views
from secmonk.collectors.process.launch import LINUX, LaunchClassifier, hints_for, systemd_unit
from secmonk.collectors.process.model import LaunchItem, ProcessRecord, Snapshot
from secmonk.collectors.rootfs import DirView, collect_from_view, parse_apk_installed, parse_dpkg_status
from secmonk.models import CAT_EXECUTABLE, CAT_OS, CAT_OS_PACKAGE, Asset

FIX = Path(__file__).parents[1] / "fixtures"
LFIX = FIX / "collectors/process/linux"
CAPTURE = LFIX / "remote-output.txt"


def _fixture_module():
    spec = importlib.util.spec_from_file_location("process_fixture_linux", LFIX / "fixture_linux.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fx = _fixture_module()


@pytest.fixture
def lroot(tmp_path) -> Path:
    return fx.build_root(tmp_path / "root")


@pytest.fixture
def fakebin(tmp_path) -> Path:
    return fx.fake_bin(tmp_path / "bin")


class FixtureTransport(ssh.Transport):
    """Runs the remote script with the local `sh` against the fixture tree (its `R=''` line pointed at it) with the
    fake tools first on PATH; records commands and stdin."""

    name = "fixture"

    def __init__(self, root: Path, fakebin: Path, rewrite=None):
        self.root, self.fakebin, self.rewrite = root, fakebin, rewrite
        self.commands: list[str] = []
        self.stdins: list[bytes] = []

    def stream(self, cmd, timeout=60, stdin=None):
        self.commands.append(cmd)
        self.stdins.append(stdin or b"")
        text = (stdin or b"").decode().replace("\nR=''\n", f"\nR='{self.root}'\n", 1)
        if self.rewrite:
            text = self.rewrite(text)
        env = {**os.environ, "PATH": f"{self.fakebin}{os.pathsep}{os.environ.get('PATH', '')}"}
        proc = subprocess.Popen(["sh", "-s"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=env)
        return ssh._ProcStream(proc, timeout, text.encode())


class CannedTransport(ssh.Transport):
    """Returns fixed stdout."""

    name = "canned"

    def __init__(self, out: bytes, rc: int = 0, err: bytes = b""):
        self.out, self.rc, self.err = out, rc, err
        self.commands: list[str] = []

    def stream(self, cmd, timeout=60, stdin=None):
        self.commands.append(cmd)
        proc = subprocess.Popen(["sh", "-c", f"cat; echo {self.err.decode()!r} >&2; exit {self.rc}"],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return ssh._ProcStream(proc, timeout, self.out)


def _views(snap, root=None, **opts):
    w: list[str] = []
    insp = backend_for("linux").inspector(snap, root, opts, w)
    return {v.proc.pid: v for v in build_views(snap, insp)}, insp, w


# ============================================================================ parsers

def test_parse_stat_comm_with_spaces_and_parens():
    st = linux.parse_stat(b"403 (tool (x) y) S 402 403 403 0 -1 4194304 0 0 0 0 0 0 0 0 20 0 1 0 80100 1000 0\n")
    assert st == {"pid": 403, "comm": "tool (x) y", "state": "S", "ppid": 402, "flags": 4194304, "starttime": 80100}
    assert linux.parse_stat(b"garbage") is None
    assert linux.parse_stat(b"12 (x) S 1") is None                       # truncated


def test_parse_status_cmdline_exe():
    assert linux.parse_status("Name:\tnginx\nPPid:\t211\nUid:\t33\t33\t33\t33\n") == \
        {"name": "nginx", "ppid": 211, "uid": 33}
    argv = linux.parse_cmdline(b"/bin/tool\0--password\0a b\0--url=https://u:p@h/x?k=1\0")
    assert argv[:3] == ["/bin/tool", "--password", REDACTED]           # exact argv boundaries, no over-redaction
    assert "u:p@" not in argv[3]
    assert linux.parse_cmdline(b"") == []
    assert linux.parse_exe_link("/usr/bin/x (deleted)") == ("/usr/bin/x", True)
    assert linux.parse_exe_link("/usr/bin/x") == ("/usr/bin/x", False)
    assert linux.parse_exe_link("anon_inode:[x]") == (None, False)
    assert linux.parse_exe_link(None) == (None, False)


@pytest.mark.parametrize("text,unit,user_unit,container", [
    ("0::/system.slice/ssh.service\n", "ssh.service", False, None),
    ("0::/user.slice/user-1000.slice/user@1000.service/app.slice/syncthing.service\n", "syncthing.service", True,
     None),
    ("0::/user.slice/user-1000.slice/user@1000.service/init.scope\n", "user@1000.service", False, None),
    ("0::/user.slice/user-1000.slice/session-3.scope\n", "session-3.scope", False, None),
    # cgroup v1 (hybrid): the name=systemd hierarchy wins
    ("12:pids:/system.slice/cron.service\n1:name=systemd:/system.slice/cron.service\n0::/\n", "cron.service", False,
     None),
    ("0::/system.slice/docker-" + "a" * 64 + ".scope\n", "docker-" + "a" * 64 + ".scope", False,
     {"runtime": "docker", "id": "a" * 64}),
    ("11:memory:/docker/" + "b" * 64 + "\n1:name=systemd:/docker/" + "b" * 64 + "\n", None, None,
     {"runtime": "docker", "id": "b" * 64}),
    ("0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod0123abcd_0000_1111_2222_333344445555.slice/"
     "cri-containerd-" + "c" * 64 + ".scope\n", "cri-containerd-" + "c" * 64 + ".scope", False,
     {"runtime": "containerd", "id": "c" * 64, "pod": "0123abcd-0000-1111-2222-333344445555"}),
    ("0::/machine.slice/libpod-conmon-" + "d" * 64 + ".scope\n", "libpod-conmon-" + "d" * 64 + ".scope", False, None),
    ("0::/machine.slice/libpod-" + "d" * 64 + ".scope/container\n", "libpod-" + "d" * 64 + ".scope", False,
     {"runtime": "podman", "id": "d" * 64}),
])
def test_parse_cgroup(text, unit, user_unit, container):
    cg = linux.parse_cgroup(text)
    assert cg.get("unit") == unit
    if unit:
        assert cg["user_unit"] is user_unit
    assert cg.get("container") == container


def test_btime_and_start_time():
    assert linux.parse_proc_btime("cpu 1 2\nbtime 1794290400\nprocesses 3\n") == 1794290400
    assert linux.parse_proc_btime("cpu 1\n") is None
    assert linux.started_at(1500, 1794290400, 100) == "2026-11-10T06:00:15+00:00"
    assert linux.started_at(1500, None, 100) is None


def test_parse_unit_file():
    u = linux.parse_unit_file("[Unit]\nDescription=x\n[Service]\nExecStart=/bin/old\nExecStart=\n"
                              "ExecStart=-/usr/bin/a \\\n  --flag 'b c'\nUser=svc\n[Install]\nWantedBy=multi-user.target\n")
    assert u["exec"] == ["/usr/bin/a", "--flag", "b c"] and u["user"] == "svc" and u["description"] == "x"
    assert linux.parse_unit_file("[Service]\nExecStart=@/usr/bin/real argv0 --x\n")["exec"] == ["/usr/bin/real", "--x"]
    assert linux.parse_unit_file("[Timer]\nUnit=other.service\n") == {"unit": "other.service"}
    assert "exec" not in linux.parse_unit_file("[Service]\nExecStart=\n")


def test_parse_desktop_and_crontab():
    d = linux.parse_desktop_entry("[Desktop Entry]\nName=Up\nExec=/opt/up --quiet %U\nHidden=true\n"
                                  "[Desktop Action x]\nExec=/other\n")
    assert d == {"name": "Up", "exec": ["/opt/up", "--quiet"], "disabled": True}
    sys_rows = linux.parse_crontab("SHELL=/bin/sh\n# c\n*/5 * * * * root /usr/bin/x --y\n@daily root /bin/z\n"
                                   "bad line\n", system=True)
    assert [(r["schedule"], r["user"], r["command"]) for r in sys_rows] == [
        ("*/5 * * * *", "root", "/usr/bin/x --y"), ("@daily", "root", "/bin/z")]
    assert linux.parse_crontab("@reboot /home/a/t --d\n", system=False)[0]["user"] is None
    assert linux.cron_program("test -x /usr/sbin/a && /usr/sbin/a run") == ("/usr/sbin/a", ["run"])
    assert linux.cron_program("cd / && run-parts --report /etc/cron.hourly") == \
        ("run-parts", ["--report", "/etc/cron.hourly"])
    assert linux.cron_program("/usr/bin/php x%stdin%data") == ("/usr/bin/php", ["x"])


def test_package_query_parsers():
    out = ("diversion by dash from: /bin/sh\nlibc6:amd64, libc6:i386: /lib/x86_64-linux-gnu/libc.so.6\n"
           "bash: /bin/bash\n")
    assert linux.parse_dpkg_search(out) == ["libc6", "bash"]
    assert linux.parse_dpkg_search(out, "/usr/bin/bash") == ["bash"]                 # merged-/usr variant
    rows = linux.parse_rpm_query("file /x is not owned by any package\n"
                                 "openssl\t1\t3.0.7\t27.el9\tx86_64\topenssl-3.0.7-27.el9.src.rpm\t1700000000\tRocky\n"
                                 "bash\t(none)\t5.1.8\t9.el9\tx86_64\tbash-5.1.8-9.el9.src.rpm\tx\t(none)\n")
    assert rows[0]["epoch"] == 1 and rows[0]["source_name"] == "openssl" and rows[0]["install_time"].startswith("2023")
    assert rows[1]["epoch"] is None and rows[1]["vendor"] is None and rows[1]["install_time"] is None
    files = linux.parse_apk_files("P:busybox\nV:1\nF:bin\nR:busybox\n\nP:x\nR:top\n")
    assert files == {"/bin/busybox": "busybox", "/top": "x"}
    assert linux._variants("/usr/bin/bash") == ["/usr/bin/bash", "/bin/bash"]
    assert linux._variants("/sbin/agetty") == ["/sbin/agetty", "/usr/sbin/agetty"]
    assert linux._variants("/usr/local/bin/x") == ["/usr/local/bin/x"]


@pytest.mark.parametrize("image,kind", [("debian-12", "deb"), ("alpine-3.20", "apk"), ("rocky-9", "rpm")])
def test_package_component_equals_rootfs(image, kind):
    """Owners resolved on a remote host must produce the components the rootfs/ssh inventory does."""
    rootfs = FIX / "collectors/docker" / image / "rootfs"
    w: list[str] = []
    comps = {c.name: c for c in collect_from_view(DirView(rootfs), Asset(id="x", type="server", name="x"), w)
             if c.category == CAT_OS_PACKAGE}
    osc = next(c for c in collect_from_view(DirView(rootfs), Asset(id="x", type="server", name="x"), [])
               if c.category == CAT_OS)
    view = DirView(rootfs)
    from secmonk.collectors.rootfs import detect_os
    osr = detect_os(view)
    eco = osc.meta["osv_ecosystem"]
    if kind == "deb":
        rows = parse_dpkg_status((rootfs / "var/lib/dpkg/status").read_text())
    elif kind == "apk":
        rows = parse_apk_installed((rootfs / "lib/apk/db/installed").read_text())
    else:
        from secmonk.collectors.rootfs import parse_rpmdb_sqlite
        rows = parse_rpmdb_sqlite(rootfs / "var/lib/rpm/rpmdb.sqlite")
    assert rows
    for p in rows[:25]:
        c = linux.package_component(kind, p, osr, eco)
        ref = comps[p["name"]]
        assert (c.purl, c.version, c.ecosystem, c.meta["source_package"], c.meta["source_version"]) == \
            (ref.purl, ref.version, ref.ecosystem, ref.meta["source_package"], ref.meta["source_version"])


# ============================================================================ local snapshot

def test_backend_registered():
    assert "linux" in BACKENDS
    b = backend_for("linux")
    assert b.take_snapshot is linux.take_snapshot
    assert hints_for("linux") is LINUX


def test_local_snapshot_processes(lroot):
    snap = linux.take_snapshot(lroot, {})
    by = {p.pid: p for p in snap.processes}
    assert snap.platform == "linux" and snap.host == "fixture-linux"
    assert snap.os["name"] == "Debian GNU/Linux" and snap.os["version"] == "12"
    assert 2 not in by and 3 not in by                       # kernel threads omitted by default
    assert len(snap.processes) == len(fx.PROCS) - 2
    assert by[403].name == "tool (x) y" and by[403].user == "alice" and by[212].user == "www-data"
    assert by[403].args == ["/home/alice/bin/tool", "--password", REDACTED, "a b"]
    assert by[210].started == "2026-11-10T06:00:15+00:00"
    assert by[404].exe == "/usr/bin/olddaemon" and snap.executables["/usr/bin/olddaemon"] == {"exists": False}
    # units label the main process only
    assert by[211].label == "nginx.service" and by[212].label is None
    assert by[500].label == "user@1000.service" and by[501].label == "syncthing.service"
    assert by[502].label.startswith("app-gnome-firefox") and by[503].label is None
    assert by[400].label is None                              # session scope: no label
    assert by[601].container == {"runtime": "docker", "id": fx.CONTAINER_ID} and by[601].label is None
    assert by[1].cgroup == "/init.scope"
    assert snap.source == {"kind": "local", "boot_id": "0f0e0d0c-0b0a-4908-8706-050403020100"}
    kept = linux.take_snapshot(lroot, {"kernel_threads": True, "args": False})
    assert {2, 3} <= {p.pid for p in kept.processes} and all(not p.args for p in kept.processes)
    views, _, _ = _views(kept, lroot)
    assert views[3].launch.kind == "kernel" and views[3].launch.mechanism == "kernel-thread"
    assert views[2].launch.kind == "kernel"


def test_local_launch_items(lroot):
    snap = linux.take_snapshot(lroot, {})
    items = {(it.mechanism, it.label): it for it in snap.launch_items}
    nginx = items[("systemd-system", "nginx.service")]
    assert nginx.source == "/etc/systemd/system/nginx.service"            # /etc hides the vendor unit
    assert nginx.args == ["-g", "daemon on;"] and nginx.meta["type"] == "forking"
    assert items[("systemd-system", "masked.service")].disabled is True
    stale = items[("systemd-system", "stale-agent.service")]
    assert stale.program == "/opt/gone/bin/agent" and stale.args == ["--api-key=" + REDACTED]
    lr = items[("systemd-timer", "logrotate.service")]
    assert lr.meta["timer"] == "logrotate.timer"
    st = items[("systemd-user", "syncthing.service")]
    assert st.scope == "user:alice" and st.meta["UserName"] == "alice"
    nm = items[("xdg-autostart", "nm-applet")]
    assert nm.program == "/usr/bin/nm-applet" and nm.meta["command"] == "nm-applet"   # bare Exec resolved
    assert items[("xdg-autostart", "disabled")].disabled is True
    assert items[("xdg-autostart", "updater")].scope == "user:alice"
    backup = items[("cron", "/etc/cron.d/backup:2")]
    assert backup.program == "/usr/local/bin/backup" and backup.args == ["--token=" + REDACTED]
    assert items[("cron", "/var/spool/cron/crontabs/alice:1")].scope == "user:alice"
    assert not any(it.label.startswith("logrotate.timer") for it in snap.launch_items)


EXPECTED_LAUNCH = {
    1: ("kernel", "init"),
    210: ("service", "systemd-system"),
    212: ("service", "systemd-system"),          # nginx worker: same unit, exe-match
    302: ("scheduled", "cron"),
    303: ("scheduled", "cron"),                  # program of /etc/cron.d/backup, below cron
    400: ("child", "spawn"),                     # sshd session process: in session-3.scope, not ssh.service
    402: ("child", "spawn"),
    403: ("remote-session", "sshd"),             # same program as a @reboot crontab line, but started from a shell
    404: ("service", "systemd-system"),
    501: ("agent", "systemd-user"),
    502: ("gui-app", "desktop"),
    503: ("child", "spawn"),
    504: ("login-item", "xdg-autostart"),
    601: ("child", "container"),                 # nginx in a container: not the host's nginx.service
    700: ("service", "systemd-system"),          # getty@tty1 -> getty@.service
    701: ("scheduled", "systemd-timer"),
}


def test_local_launch_classification(lroot):
    views, _, _ = _views(linux.take_snapshot(lroot, {}), lroot)
    got = {pid: (views[pid].launch.kind, views[pid].launch.mechanism) for pid in EXPECTED_LAUNCH}
    assert got == EXPECTED_LAUNCH
    assert views[700].launch.label == "getty@.service" and views[700].launch.evidence == "pid-label"
    assert views[601].launch.label == fx.CONTAINER_ID[:12] and views[601].launch.via.endswith("runc-v2")
    assert views[403].launch.via == "/usr/sbin/sshd"


def test_local_identity_and_facts(lroot):
    views, insp, w = _views(linux.take_snapshot(lroot, {}), lroot)
    ident = {pid: (v.resolution.method, v.identity.name, v.identity.version) for pid, v in views.items()
             if v.resolution}
    assert ident[210] == ("os-package", "openssh-server", "1:9.2p1-2+deb12u3")
    assert ident[402] == ("os-package", "bash", "5.2.15-2+b7")              # /usr/bin/bash listed as /bin/bash
    assert ident[1] == ("os-package", "systemd", "252.30-1~deb12u2")
    assert ident[303][0] == "go-binary"
    assert ident[502] == ("snap", "firefox", "132.0-1")
    assert ident[601] == ("container", "nginx", None)                         # host package not attributed
    assert ident[403][0] == "none"
    ssh_c = views[210].identity
    assert ssh_c.ecosystem == "Debian:12" and ssh_c.meta["source_package"] == "openssh"
    assert ssh_c.purl.startswith("pkg:deb/debian/openssh-server@")
    assert views[210].resolution.notes["pkg_install_time"].startswith("2026-09-")
    assert views[210].facts["exists"] is True and "sha256" in views[210].facts
    assert set(views[403].flags) >= {"world-writable", "user-writable-path", "unidentified"}
    assert "exe-missing" in views[404].flags
    assert views[601].facts == {} and views[601].identity.category == CAT_EXECUTABLE
    osc = insp.os_component()
    assert osc.name == "Debian GNU/Linux" and osc.version == "12" and osc.meta["osv_ecosystem"] == "Debian:12"
    assert not w


def test_local_inventory(lroot):
    snap = linux.take_snapshot(lroot, {})
    col = ProcessCollector()
    w: list[str] = []
    insp = backend_for("linux").inspector(snap, lroot, {}, w)
    views = build_views(snap, insp)
    inv = col.inventory(snap, insp, views, {})
    assert inv.asset.id == "process:fixture-linux" and inv.asset.platform == "linux"
    assert inv.asset.meta["source"]["kind"] == "local"
    missing = {m["label"] for m in inv.asset.meta["launch_items_missing_program"]}
    assert {"stale-agent.service", "updater"} <= missing and "masked.service" not in missing
    comps = {c.name: c for c in inv.components}
    assert comps["openssh-server"].category == CAT_OS_PACKAGE
    assert comps["Debian GNU/Linux"].category == CAT_OS
    nginx_rows = [p for p in inv.asset.meta["processes"] if p["pid"] == 601]
    assert nginx_rows[0]["container"]["runtime"] == "docker"


def test_local_denied_and_unreadable(lroot, monkeypatch):
    real = os.readlink

    def readlink(p, *a, **k):
        if str(p).endswith("/proc/501/exe"):
            raise PermissionError(13, "denied")
        return real(p, *a, **k)

    monkeypatch.setattr(linux.os, "readlink", readlink)
    snap = linux.take_snapshot(lroot, {})
    assert next(p for p in snap.processes if p.pid == 501).exe is None
    assert any("executable of 1 process(es) unreadable" in w for w in snap.warnings)


def test_live_snapshot_dispatch_on_linux(monkeypatch, lroot):
    """`collect()` with no target on Linux uses this backend (root pointed at the fixture tree)."""
    import secmonk.collectors.process.collector as coll

    monkeypatch.setattr(coll, "current_platform", lambda: "linux")
    inv = ProcessCollector().collect(None, root=str(lroot))
    assert inv.asset.id == "process:fixture-linux"
    assert any(c.name == "nginx-core" for c in inv.components)


def test_linux_hints_do_not_change_darwin():
    assert hints_for("darwin").cgroup_unit is None and not hints_for("darwin").container_shims
    assert systemd_unit("/a.slice/b.service/c.scope") == "c.scope"
    assert systemd_unit("/") is None


def test_classifier_container_and_cron_rules():
    snap = Snapshot("linux", "h", "", [
        ProcessRecord(1, 0, "/sbin/init"),
        ProcessRecord(10, 1, "/usr/sbin/cron", uid=0),
        ProcessRecord(11, 10, "/usr/bin/job", uid=0),
        ProcessRecord(20, 1, "/usr/bin/tmux", uid=1000),
        ProcessRecord(21, 20, "/usr/bin/bash", uid=1000),
        ProcessRecord(22, 21, "/usr/bin/job", uid=1000),
    ], launch_items=[LaunchItem("cron", "/etc/crontab:1", "/usr/bin/job")])
    c = LaunchClassifier(snap)
    by = {p.pid: p for p in snap.processes}
    assert c.classify(by[11]).evidence == "exe-match"
    assert c.classify(by[22]).kind == "interactive"


# ============================================================================ snapshot file

def test_snapshot_roundtrip_keeps_linux_fields(lroot, tmp_path):
    snap = remote.take_remote_snapshot("ssh://alice@fixture-linux", transport=FixtureTransport(lroot, fx.fake_bin(
        tmp_path / "b")))
    out = tmp_path / "snap.json"
    snapfile.dump(snap, out)
    back = snapfile.load(out)
    by = {p.pid: p for p in back.processes}
    assert by[601].container["id"] == fx.CONTAINER_ID and by[211].cgroup == "/system.slice/nginx.service"
    assert back.source["kind"] == "ssh" and back.source["sudo"] is False
    ident = back.executables["/usr/sbin/sshd"]["identity"]
    assert ident["source_package"] == "openssh" and ident["ecosystem"] == "Debian:12"
    assert ident["install_time"].startswith("2026-09-")


def test_snapshot_validation_of_new_fields():
    d = {"schema": snapfile.SCHEMA, "platform": "linux", "processes": [
        {"pid": 5, "cgroup": 7, "container": {"runtime": 3, "id": "x"}},
        {"pid": 6, "container": {"runtime": "docker", "id": "y", "evil": {"a": 1}}, "cgroup": "x" * 9000}],
        "source": {"kind": "ssh", "sudo": "yes", "boot_id": "b"},
        "executables": {"/x": {"identity": {"name": "n", "ecosystem": 5, "source_package": "s"}}}}
    s = snapfile.from_dict(d)
    assert s.processes[0].cgroup is None and s.processes[0].container is None
    assert s.processes[1].container == {"runtime": "docker", "id": "y"} and len(s.processes[1].cgroup) == 4096
    assert s.source == {"kind": "ssh", "boot_id": "b"}
    assert s.executables["/x"]["identity"] == {"name": "n", "source_package": "s"}
    old = json.loads((FIX / "collectors/process/snapshot.json").read_text())
    assert snapfile.from_dict(old).source == {}                                  # older files still load


# ============================================================================ remote over ssh

def test_script_is_constant_and_read_only(lroot, fakebin):
    script = remote.SCRIPT
    assert subprocess.run(["sh", "-n"], input=script.encode(), check=False).returncode == 0
    dash = shutil.which("dash")
    if dash:
        assert subprocess.run([dash, "-n"], input=script.encode(), check=False).returncode == 0
    # every redirection goes to /dev/null or merges streams: nothing is written on the target
    targets = re.findall(r"(?<![0-9&])>+\s*([^\s;)|]+)|[0-9]>+\s*([^\s;)|]+)", script)
    assert {t for pair in targets for t in pair if t} <= {"/dev/null", "&1", "&2"}
    for cmd in ("rm ", "mv ", "tee ", "chmod", "chown", "mkdir", "touch", "eval", "curl", "wget"):
        assert cmd not in script
    t = FixtureTransport(lroot, fakebin)
    remote.take_remote_snapshot("ssh://alice@host", transport=t, sudo=True, hostname="h", args=False)
    assert t.commands == ["sudo -n sh -s"] and t.stdins == [script.encode()]   # same text whatever the options


def test_parse_captured_output():
    cap = remote.parse_output(CAPTURE.read_bytes())
    assert cap.begun and cap.complete
    assert cap.hostname == "fixture-linux" and cap.btime == fx.BTIME and cap.clk_tck == 100 and cap.uid == 1000
    assert len(cap.procs) == len(fx.PROCS)
    assert "/etc/systemd/system/masked.service" in cap.masked
    assert linux.dpkg_search_index(cap.dpkg_search)["/bin/bash"] == ["bash"]       # one batched dpkg-query -S
    assert cap.files["/home/alice/bin/tool"][3] == 0o777
    assert cap.snap_versions == {"/snap/firefox/5000": "132.0-1"}
    assert "openssh-server" in cap.dpkg_lists and "libc6" in cap.dpkg_lists
    snap = linux.snapshot_from_capture(cap, {}, cap.hostname)
    assert remote.remote_executables(cap, snap) == 10       # every dpkg file but libc
    assert snap.executables["/usr/bin/olddaemon"]["exists"] is False
    assert snap.executables["/home/alice/bin/tool"]["world_writable"] is True


def test_parse_output_is_tolerant():
    data = (b"motd banner\nP 1 zz\n@@SECMONK-PROCS/1@@ BEGIN\nP 7 " + b"7 (x) S 1 7 7 0 -1 0 0 0 0 0 0 0 0 0 0 0 1 0 5 0".hex().encode()
            + b"\ne 7 !\nP x 00\nF 2f61 1 2 3 9\nZ junk\nH btime nope\nU 2e2e 00\n")
    cap = remote.parse_output(data)
    assert cap.begun and not cap.complete and cap.btime is None
    assert [p.pid for p in cap.procs] == [7] and cap.procs[0].exe_denied
    assert cap.files == {} and cap.units == []
    snap = linux.snapshot_from_capture(cap, {}, "h")
    assert any("unreadable" in w for w in snap.warnings)


def test_remote_collect_end_to_end(lroot, fakebin):
    t = FixtureTransport(lroot, fakebin)
    col = ProcessCollector()
    snap, insp, views = col.analyse("ssh://alice@fixture-linux:2222", transport=t)
    assert insp.fs is False and insp.root is None                    # nothing on this machine is read
    inv = col.inventory(snap, insp, views, {})
    assert inv.asset.id == "process:ssh:fixture-linux:2222" and inv.collector == "process"
    assert inv.asset.meta["source"] == {"kind": "ssh", "target": "alice@fixture-linux:2222", "transport": "fixture",
                                        "sudo": False, "boot_id": "0f0e0d0c-0b0a-4908-8706-050403020100",
                                        "remote_hostname": "fixture-linux"}
    pkgs = {c.name: c for c in inv.components if c.category == CAT_OS_PACKAGE}
    assert {"openssh-server", "nginx-core", "bash", "dash", "systemd", "cron", "util-linux", "logrotate",
            "syncthing", "network-manager-gnome"} <= set(pkgs)
    sshd = pkgs["openssh-server"]
    assert sshd.ecosystem == "Debian:12" and sshd.meta["source_package"] == "openssh"
    assert sshd.purl.startswith("pkg:deb/debian/openssh-server@1:9.2p1-2%2Bdeb12u3")
    assert sshd.meta["process"]["provenance"]["/usr/sbin/sshd"]["pkg_install_time"].startswith("2026-09-")
    assert any(c.category == CAT_OS and c.version == "12" for c in inv.components)
    got = {pid: (views_by.launch.kind, views_by.launch.mechanism)
           for pid, views_by in {v.proc.pid: v for v in views}.items() if pid in EXPECTED_LAUNCH}
    assert got == EXPECTED_LAUNCH
    v = {v.proc.pid: v for v in views}
    assert v[502].identity.name == "firefox" and v[502].identity.version == "132.0-1"
    assert "exe-missing" in v[404].flags and "world-writable" in v[403].flags
    assert v[601].resolution.method == "container"
    assert any("not root" in w for w in inv.warnings)


def test_remote_snapshot_out_and_hostname(lroot, fakebin, tmp_path):
    out = tmp_path / "remote.json"
    inv = ProcessCollector().collect("ssh://fixture-linux", transport=FixtureTransport(lroot, fakebin),
                                     snapshot_out=str(out), hostname="web-1")
    assert inv.asset.id == "process:web-1"
    again = ProcessCollector().collect(str(out))
    assert {c.key for c in again.components} == {c.key for c in inv.components}


def test_remote_failures(lroot, fakebin):
    with pytest.raises(ValueError, match="root"):
        ProcessCollector().collect("ssh://h", transport=CannedTransport(b""), root=str(lroot))
    with pytest.raises(ssh.SSHError, match="produced nothing.*sudo -n"):
        remote.take_remote_snapshot("ssh://h", transport=CannedTransport(b"", rc=1, err=b"sudo: a password is "
                                                                                              b"required"), sudo=True)
    darwin = b"@@SECMONK-PROCS/1@@ BEGIN\nH ostype " + b"Darwin\n".hex().encode() + b"\n"
    with pytest.raises(ssh.SSHError, match="Linux only"):
        remote.take_remote_snapshot("ssh://h", transport=CannedTransport(darwin))
    with pytest.raises(ssh.SSHError, match="no processes"):
        remote.take_remote_snapshot("ssh://h", transport=CannedTransport(b"@@SECMONK-PROCS/1@@ BEGIN\n"))
    with pytest.raises(ValueError):
        remote.take_remote_snapshot("ssh://user:pw@h", transport=CannedTransport(b""))


def test_remote_partial_output(monkeypatch):
    data = CAPTURE.read_bytes()
    cut = data[:data.index(b"\nF ")]                                  # stream ended before the executables
    snap = remote.take_remote_snapshot("ssh://h", transport=CannedTransport(cut + b"\n"))
    assert any("ended early" in w for w in snap.warnings) and snap.processes
    monkeypatch.setattr(remote, "MAX_OUTPUT", 4096)
    snap = remote.take_remote_snapshot("ssh://h", transport=CannedTransport(data))
    assert any("exceeded" in w for w in snap.warnings)


def test_remote_package_owners_rpm_and_apk():
    """Owners on rpm and apk hosts come out as the rootfs components would."""
    osr_rocky = 'NAME="Rocky Linux"\nVERSION_ID="9.3"\nID="rocky"\nID_LIKE="rhel centos fedora"\n'
    rpm_line = "openssl\t1\t3.0.7\t27.el9\tx86_64\topenssl-3.0.7-27.el9.src.rpm\t1700000000\tRocky\n"
    cap = linux.Capture(begun=True, complete=True, os_release=osr_rocky,
                        procs=[linux.RawProc(9, b"9 (openssl) S 1 9 9 0 -1 0 0 0 0 0 0 0 0 0 0 0 1 0 5 0 0",
                                             exe="/usr/bin/openssl")],
                        rpm_owner={"/usr/bin/openssl": rpm_line})
    snap = linux.snapshot_from_capture(cap, {}, "h")
    remote.remote_executables(cap, snap)
    ident = snap.executables["/usr/bin/openssl"]["identity"]
    assert ident["purl"].startswith("pkg:rpm/rocky/openssl@3.0.7-27.el9") and ident["version"] == "1:3.0.7-27.el9"
    apk = (FIX / "collectors/docker/alpine-3.20/rootfs/lib/apk/db/installed").read_text()
    osr_alpine = (FIX / "collectors/docker/alpine-3.20/rootfs/etc/os-release").read_text()
    cap = linux.Capture(begun=True, complete=True, os_release=osr_alpine, apk_db=apk,
                        procs=[linux.RawProc(9, b"9 (sh) S 1 9 9 0 -1 0 0 0 0 0 0 0 0 0 0 0 1 0 5 0 0",
                                             exe="/bin/busybox")])
    snap = linux.snapshot_from_capture(cap, {}, "h")
    remote.remote_executables(cap, snap)
    ident = snap.executables["/bin/busybox"]["identity"]
    assert ident["name"] == "busybox" and ident["purl"].startswith("pkg:apk/alpine/busybox@")
    views, _, _ = _views(snap)
    assert views[9].identity.ecosystem and views[9].identity.ecosystem.startswith("Alpine")


def test_ssh_target_detection():
    from secmonk.collectors.process.collector import is_remote_target

    assert is_remote_target("ssh://h") and not is_remote_target("snap.json") and not is_remote_target(None)


# ============================================================================ review fixes (2026-11-11)

def test_env_prefixes_never_become_program_or_meta():
    cap = linux.Capture(
        crontabs=[("/etc/cron.d/db", ("0 3 * * * root PGPASSWORD=s3cret pg_dump db > /backup/db.sql\n"
                                      "5 3 * * * root env -i TOKEN=t0k /usr/bin/sync --x\n"))],
        units=[("/etc/systemd/system/a.service", "[Service]\nExecStart=/usr/bin/env API_KEY=k3y /usr/bin/a run\n")],
        autostart=[("/etc/xdg/autostart/b.desktop", "[Desktop Entry]\nExec=env SECRET=xyz b-applet\n")])
    items = {it.label: it for it in linux.launch_items(cap)}
    dump = json.dumps([vars(it) for it in items.values()], default=str)
    for secret in ("s3cret", "t0k", "k3y", "xyz"):
        assert secret not in dump
    assert items["/etc/cron.d/db:1"].program is None and items["/etc/cron.d/db:1"].meta["command"] == "pg_dump"
    assert items["/etc/cron.d/db:2"].program == "/usr/bin/sync"
    assert items["a.service"].program == "/usr/bin/a" and items["a.service"].args == ["run"]
    assert items["b"].meta["command"] == "b-applet"
    assert linux.strip_env(["FOO=1", "BAR=2", "/bin/x", "Y=3"]) == ["/bin/x", "Y=3"]
    assert linux.strip_env(["env", "-i", "--", "A=1", "x"]) == ["x"]


def test_remote_asset_id_is_the_ssh_target(lroot, fakebin):
    t = FixtureTransport(lroot, fakebin, rewrite=lambda s: s.replace(
        '{ cat "$R/proc/sys/kernel/hostname"', '{ echo victim-host; cat "$R/proc/sys/kernel/hostname"'))
    inv = ProcessCollector().collect("ssh://alice@10.0.0.5", transport=t)
    assert inv.asset.id == "process:ssh:10.0.0.5"                      # not process:victim-host
    assert inv.asset.meta["source"]["remote_hostname"].startswith("victim-host")
    inv = ProcessCollector().collect("ssh://[fe80::1]:2222", transport=FixtureTransport(lroot, fakebin))
    assert inv.asset.id == "process:ssh:[fe80::1]:2222"


@pytest.mark.parametrize("path,container", [
    ("/system.slice/lxc.service", None),
    ("/lxc.monitor.c1", None),
    ("/system.slice/lxc-net.service", None),
    ("/lxc.payload.c1/init.scope", {"runtime": "lxc", "id": "c1"}),
    ("/lxc/c2", {"runtime": "lxc", "id": "c2"}),
    ("/machine.slice/machine-deb12.scope/payload", {"runtime": "nspawn", "id": "deb12"}),
    ("/user.slice/user-1000.slice/user@1000.service/app.slice/app-flatpak-org.mozilla.firefox-4242.scope",
     {"runtime": "flatpak", "id": "org.mozilla.firefox"}),
])
def test_cgroup_container_patterns(path, container):
    assert linux.parse_cgroup(f"0::{path}\n").get("container") == container


def test_other_root_filesystem_is_not_resolved_against_host(lroot, fakebin):
    views, _, _ = _views(linux.take_snapshot(lroot, {}), lroot)
    assert views[702].proc.container["runtime"] == "chroot" and views[702].resolution.method == "container"
    assert views[210].proc.container is None
    snap = remote.take_remote_snapshot("ssh://h", transport=FixtureTransport(lroot, fakebin))
    by = {p.pid: p for p in snap.processes}
    assert by[702].container["runtime"] == "chroot" and by[210].container is None


def test_hostile_numbers_do_not_crash():
    huge = "9" * 5000
    assert linux.parse_stat(f"1 (x) S {huge} 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 1 0 5 0".encode()) is None
    assert "ppid" not in linux.parse_status(f"PPid:\t{huge}\nUid:\t{huge}\t0\n")
    assert linux.parse_proc_btime(f"btime {huge}\n") is None
    assert linux.parse_passwd(f"x:{huge}\n") == {}
    rows = linux.parse_rpm_query(f"a\t{huge}\t1\t1\tx86_64\t(none)\t99999999999999999999\t(none)\n")
    assert rows[0]["epoch"] is None and rows[0]["install_time"] is None
    assert linux.iso_time(1e20) is None
    out = (b"@@SECMONK-PROCS/1@@ BEGIN\nH btime " + huge.encode() + b"\nF 2f61 " + huge.encode()
           + b" 1 0 755\nP " + huge.encode() + b" 00\nL " + f"{huge} x.list\n".encode().hex().encode() + b"\n")
    cap = remote.parse_output(out)
    assert cap.btime is None and cap.files == {} and cap.procs == [] and cap.dpkg_lists == {}


def test_truncated_last_line_is_dropped():
    data = CAPTURE.read_bytes()
    cut = data[:data.index(b"\nF ") + 30]                             # in the middle of an F record
    cap = remote.parse_output(cut)
    assert cap.files == {} and any("middle of a record" in w for w in cap.warnings)
    snap = remote.take_remote_snapshot("ssh://h", transport=CannedTransport(cut))
    assert any("middle of a record" in w for w in snap.warnings) and any("ended early" in w for w in snap.warnings)


def test_replaced_binary_keeps_identity_with_note(lroot):
    snap = linux.take_snapshot(lroot, {})
    snap.executables["/usr/sbin/cron"] = {"exists": False}
    views, insp, _ = _views(snap, lroot)
    assert views[300].identity.name == "cron" and "exe-missing" in views[300].flags
    assert views[300].resolution.notes["version_is_installed_not_running"] is True
    inv = ProcessCollector().inventory(snap, insp, list(views.values()), {})
    cron = next(c for c in inv.components if c.name == "cron")
    assert cron.meta["process"]["version_is_installed_not_running"] is True
    assert "version_is_installed_not_running" not in views[210].resolution.notes


def test_setproctitle_single_argument_is_redacted(lroot):
    by = {p.pid: p for p in linux.take_snapshot(lroot, {}).processes}
    assert by[703].args == [f"worker --api-key={REDACTED} --queue jobs"]
    assert linux.parse_cmdline(b"postgres: app db 10.0.0.1 idle\0") == ["postgres: app db 10.0.0.1 idle"]


def test_remote_counts_are_capped(monkeypatch):
    monkeypatch.setattr(remote, "MAX_PROCS", 3)
    monkeypatch.setattr(remote, "MAX_CONFIG_FILES", 2)
    cap = remote.parse_output(CAPTURE.read_bytes())
    assert len(cap.procs) == 3 and len(cap.units) == 2
    assert any("too many processes" in w for w in cap.warnings)
    assert any("too many unit files" in w for w in cap.warnings)


def test_zombies_and_root_are_not_counted_as_denied():
    def rec(pid, state):
        return (f"P {pid} " + f"{pid} (x) {state} 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 1 0 5 0".encode().hex()
                + f"\ne {pid} !\n")
    body = "@@SECMONK-PROCS/1@@ BEGIN\nH uid 1000\n" + rec(10, "Z") + rec(11, "S") + "@@SECMONK-PROCS/1@@ END\n"
    snap = linux.snapshot_from_capture(remote.parse_output(body.encode()), {}, "h")
    assert any("executable of 1 process(es)" in w for w in snap.warnings)
    as_root = remote.parse_output(body.replace("H uid 1000", "H uid 0").encode())
    assert not any("unreadable" in w for w in linux.snapshot_from_capture(as_root, {}, "h").warnings)
    # the script marks `!` only when the exe link exists (a zombie's has none)
    assert 'elif [ -L "$d/exe" ]; then' in remote.SCRIPT


def test_exe_path_with_newline(lroot, fakebin):
    d = lroot / "proc/905"
    shutil.copytree(lroot / "proc/210", d, symlinks=True)
    (d / "stat").write_text((d / "stat").read_text().replace("210 (sshd)", "905 (odd)", 1))
    (d / "exe").unlink()
    os.symlink("/usr/bin/a\nb", d / "exe")
    snap = remote.take_remote_snapshot("ssh://h", transport=FixtureTransport(lroot, fakebin))
    odd = next(p for p in snap.processes if p.pid == 905)
    assert odd.exe == "/usr/bin/a\nb"
    assert "/usr/bin/a\nb" not in snap.executables and not any(k in ("/usr/bin/a", "b") for k in snap.executables)


def test_home_symlinks_are_not_followed(lroot, fakebin):
    local = {it.label for it in linux.take_snapshot(lroot, {}).launch_items}
    rem = {it.label for it in remote.take_remote_snapshot("ssh://h", transport=FixtureTransport(
        lroot, fakebin)).launch_items}
    for labels in (local, rem):
        assert "updater" in labels and "evil" not in labels
    assert "/secret/from/shadow" not in json.dumps([vars(i) for i in linux.take_snapshot(lroot, {}).launch_items])


def test_package_index_built_once_and_refreshed(lroot):
    snap = linux.take_snapshot(lroot, {})
    _, insp, _ = _views(snap, lroot)
    stamp, owners = insp._stamp, insp._owners
    insp._refresh()
    assert insp._owners is owners                                       # unchanged databases: no rebuild
    info = lroot / "var/lib/dpkg/info"
    (info / "newpkg.list").write_text("/usr/bin/newtool\n")
    os.utime(info, (stamp[0][1] / 1e9 + 10, stamp[0][1] / 1e9 + 10))
    insp._refresh()
    assert insp._owners is not owners and insp._owners["/usr/bin/newtool"][1] == "newpkg"
