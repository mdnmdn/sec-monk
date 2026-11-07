"""SSH collector tests: no sshd/ssh binary needed.

* unit: target parsing, find-script builder, OS detection, safe tar extraction
* LocalTransport: runs the generated script with /bin/sh against a fixture "remote root"
* paramiko: real paramiko client against an in-process paramiko SSH server (127.0.0.1)
The macOS bsdtar/BSD find variant of the script is NOT exercised (GNU find/tar only here).
"""

from __future__ import annotations

import io
import os
import shlex
import shutil
import socket
import subprocess
import tarfile
import threading
from pathlib import Path

import paramiko
import pytest

from secmonk.collectors import harvest, ssh
from secmonk.collectors.base import REGISTRY
from secmonk.collectors.harvest import HarvestSpec
from secmonk.collectors.macos import MacOSCollector
from secmonk.collectors.rootfs import DirView, collect_from_view
from secmonk.collectors.ssh import SSHCollector, SSHError, Stream, Transport, parse_target
from secmonk.models import Asset

FIX = Path(__file__).parents[1] / "fixtures" / "collectors"
DEBIAN = FIX / "docker/debian-12/rootfs"
ALPINE = FIX / "docker/alpine-3.20/rootfs"
MACOS = FIX / "macos/root"


# --------------------------------------------------------------------------- helpers

class LocalTransport(Transport):
    """Test double: runs the command locally (`sudo -n` is stripped and recorded)."""

    name = "local"

    def __init__(self) -> None:
        self.commands: list[str] = []

    def stream(self, cmd: str, timeout: float = 60, stdin: bytes | None = None) -> Stream:
        self.commands.append(cmd)
        cmd = cmd.removeprefix("sudo -n ")
        proc = subprocess.Popen(cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)
        return ssh._ProcStream(proc, timeout, stdin)


def keys(inv) -> set[str]:
    return {c.key for c in inv.components}


def harvested_files(root: Path, tmp_path: Path, **spec_kw) -> set[str]:
    """Run the harvest script locally against `root` and list what arrives (files + symlinks + dirs)."""
    spec = HarvestSpec(**{"os": "linux", "root": str(root), **spec_kw})
    t = LocalTransport()
    s = t.stream("sh -s", 60, harvest.build_script(spec).encode())
    assert ssh._skip_to_marker(s, (harvest.STREAM_MARKER + "\n").encode())
    dest = tmp_path / "out"
    dest.mkdir(parents=True, exist_ok=True)
    harvest.safe_extract(ssh._Reader(s), str(dest))
    s.finish()
    return {str(p.relative_to(dest)) for p in dest.rglob("*") if not p.is_dir()}


# --------------------------------------------------------------------------- target parsing

@pytest.mark.parametrize("raw,user,host,port", [
    ("admin@10.0.0.5", "admin", "10.0.0.5", None),
    ("admin@srv.example.com:2222", "admin", "srv.example.com", 2222),
    ("srv", None, "srv", None),
    ("ssh://root@host:22/", "root", "host", 22),
    ("ssh://host", None, "host", None),
    ("bob@[fe80::1]:2200", "bob", "fe80::1", 2200),
    ("bob@[::1]", "bob", "::1", None),
    ("bob@::1", "bob", "::1", None),
    ("dom\\user@host", "dom\\user", "host", None),
])
def test_parse_target(raw, user, host, port):
    t = parse_target(raw)
    assert (t.user, t.host, t.port) == (user, host, port)


@pytest.mark.parametrize("raw", ["", "@host", "user@", "host:0", "host:99999", "host:abc", "-oProxyCommand=x",
                                 "user@-host", "bob@[::1", "a b@host", "host;rm"])
def test_parse_target_rejects(raw):
    with pytest.raises(ValueError):
        parse_target(raw)


def test_registered_and_collect_needs_target():
    assert REGISTRY["ssh"] is SSHCollector
    with pytest.raises(ValueError):
        SSHCollector().collect(None)


# --------------------------------------------------------------------------- script builder

EVIL_ROOT = "/srv/ro ot/'; touch /tmp/pwned; echo \"$(id)\" `id`"


def test_script_quotes_user_input():
    script = harvest.build_script(HarvestSpec("linux", root=EVIL_ROOT, exclude=("/a b/'x';rm -rf /", "../../etc")))
    assert script.splitlines()[0] == f"cd {harvest.quote(EVIL_ROOT)} || exit 3"
    toks = shlex.split(script)                      # what sh will see: user data stays single tokens
    assert EVIL_ROOT in toks and any(t.startswith("./a b/'x';rm -rf") for t in toks) and "./etc" in toks
    assert not any(t.startswith("./..") for t in toks)
    assert subprocess.run(["sh", "-n"], check=False, input=script.encode(), capture_output=True).returncode == 0


def test_script_is_syntactically_valid_and_never_mutates():
    for os_name in ("linux", "macos"):
        for binaries in (False, True):
            s = harvest.build_script(HarvestSpec(os_name, binaries=binaries))
            assert subprocess.run(["sh", "-n"], check=False, input=s.encode(), capture_output=True).returncode == 0
            toks = set(shlex.split(s))
            assert not toks & {"rm", "mv", "chmod", "chown", "curl", "wget", "sudo", ">", ">>", "dd", "tee"}
    assert "tar --null --no-recursion -T - -czf -" in s
    assert "-print0" in s


def test_linux_script_content():
    s = harvest.build_script(HarvestSpec("linux"))
    for p in harvest.LINUX_FIXED_FILES + harvest.LINUX_FIXED_DIRS:
        assert p in s
    assert {"etc/os-release", "var/lib/dpkg/status", "lib/apk/db/installed",
            "var/lib/rpm/rpmdb.sqlite", "usr/lib/sysimage/rpm/rpmdb.sqlite-wal"} <= set(harvest.LINUX_FIXED_FILES)
    for pruned in ("./proc", "./sys", "./dev", "./run", "./tmp", "./var/lib/docker", "./snap", "./nix/store"):
        assert f"-path {pruned} " in s
    assert " -xdev " in s
    assert "-name package-lock.json" in s and "'*.dist-info/METADATA'" in s and "'requirements*.txt'" in s
    assert "*.jar" not in s and "-perm -100" not in s                       # binaries are opt-in
    assert "SystemVersion.plist" not in s


def test_binaries_and_xdev_options():
    s = harvest.build_script(HarvestSpec("linux", binaries=True, max_binary_bytes=10 * harvest.MB, xdev=False))
    assert "'*.jar'" in s and "-perm -100" in s and f"-size -{10 * harvest.MB + 1}c" in s
    assert " -xdev " not in s
    assert " -xdev " not in harvest.build_script(HarvestSpec("macos"))      # firmlinked Data volume
    assert "-prune" in harvest.build_script(HarvestSpec("macos"))
    nolang = harvest.build_script(HarvestSpec("linux", lang=False))
    assert "find ." not in nolang and "os-release" in nolang


def test_macos_script_content():
    s = harvest.build_script(HarvestSpec("macos"))
    assert "System/Library/CoreServices/SystemVersion.plist" in s
    assert "Users/*/Applications" in s and "'Users/*/Applications'" not in s       # glob stays live
    assert "Electron Framework.framework" in s and "Sparkle.framework" in s
    for pfx in harvest.BREW_PREFIXES:
        assert f"{pfx}/Cellar" in s and f"{pfx}/Caskroom" in s and f"{pfx}/opt" in s
    assert "INSTALL_RECEIPT.json" in s and "sbom.spdx.json" in s and "var/db/receipts" in s
    assert "./Volumes" in s


@pytest.mark.parametrize("path,expected", [
    ("usr/lib/python3/dist-packages/requests-2.31.0.dist-info/METADATA", True),
    ("app/package-lock.json", True), ("app/yarn.lock", True), ("srv/go.mod", True), ("a/Cargo.lock", True),
    ("a/requirements-dev.txt", True), ("a/App.csproj", True), ("a/App.deps.json", True), ("a/pom.xml", True),
    ("app/node_modules/left-pad/package.json", True), ("app/node_modules/@scope/x/package.json", True),
    ("app/vendor/composer/installed.json", True), ("opt/conda/conda-meta/numpy-1.26.json", True),
    ("srv/README.md", False), ("a/b/package.json", False), ("etc/passwd", False), ("a/METADATA", False),
])
def test_lang_match(path, expected):
    assert harvest.lang_match(path) is expected


def test_lang_registry_is_covered_by_harvest():
    """Drift guard: whatever the lang parser registry wants by path must be harvested (non-binary)."""
    from secmonk.collectors import lang

    samples = [
        "a/package-lock.json", "a/yarn.lock", "a/pnpm-lock.yaml", "a/bun.lock", "a/poetry.lock", "a/Pipfile.lock",
        "a/uv.lock", "a/pdm.lock", "a/requirements.txt", "a/composer.lock", "a/go.mod", "a/go.sum", "a/Cargo.lock",
        "a/x.deps.json", "a/packages.lock.json", "a/obj/project.assets.json", "a/packages.config", "a/x.csproj",
        "a/x.fsproj", "a/x.vbproj", "a/Directory.Packages.props", "a/pom.xml", "a/gradle.lockfile",
        "a/gradle/verification-metadata.xml", "a/vendor/composer/installed.json", "a/x-1.0.dist-info/METADATA",
        "a/x.egg-info/PKG-INFO", "a/venv/pyvenv.cfg", "a/node_modules/x/package.json",
        "a/node_modules/@s/x/package.json", "opt/conda/conda-meta/x-1-0.json", "a/npm-shrinkwrap.json",
    ]
    missing = [p for p in samples if lang.wants(p) and not harvest.lang_match(p)]
    assert not missing


# --------------------------------------------------------------------------- OS detection

LINUX_OUT = """Welcome to the box!
@@secmonk:kernel@@
Linux
@@secmonk:arch@@
x86_64
@@secmonk:os-release@@
PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"
NAME="Debian GNU/Linux"
ID=debian
VERSION_ID="12"
@@secmonk:sw_vers@@
@@secmonk:hostname@@
web01
@@secmonk:end@@
"""

MAC_OUT = """@@secmonk:kernel@@
Darwin
@@secmonk:arch@@
arm64
@@secmonk:os-release@@
@@secmonk:sw_vers@@
ProductName:\t\tmacOS
ProductVersion:\t\t14.5
BuildVersion:\t\t23F79
@@secmonk:hostname@@
mbp.local
@@secmonk:end@@
"""


def test_parse_detect_linux_and_macos():
    li = harvest.parse_detect(LINUX_OUT)
    assert (li.family, li.arch, li.hostname) == ("linux", "x86_64", "web01")
    assert li.os_release["ID"] == "debian" and "Debian" in li.description
    mi = harvest.parse_detect(MAC_OUT)
    assert (mi.family, mi.arch, mi.hostname) == ("macos", "arm64", "mbp.local")
    assert mi.sw_vers["ProductVersion"] == "14.5" and mi.description == "macOS 14.5"
    assert harvest.parse_detect(LINUX_OUT.replace("Linux", "FreeBSD", 1)).family is None
    with pytest.raises(ValueError):
        harvest.parse_detect("bash: uname: command not found\n")


def test_detect_script_runs_locally():
    out = subprocess.run(["sh"], check=False, input=harvest.detect_script().encode(), capture_output=True).stdout.decode()
    assert harvest.parse_detect(out).family == "linux"
    out = subprocess.run(["sh"], check=False, input=harvest.detect_script(str(DEBIAN)).encode(), capture_output=True).stdout.decode()
    assert harvest.parse_detect(out).os_release["ID"] == "debian"


# --------------------------------------------------------------------------- safe extraction

def make_tar(entries) -> io.BytesIO:
    """entries: (name, kind, payload) with kind in file|dir|sym|hard|chr|fifo."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, kind, payload in entries:
            ti = tarfile.TarInfo(name)
            if kind == "file":
                data = payload if isinstance(payload, bytes) else payload.encode()
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
                continue
            ti.type = {"dir": tarfile.DIRTYPE, "sym": tarfile.SYMTYPE, "hard": tarfile.LNKTYPE,
                       "chr": tarfile.CHRTYPE, "fifo": tarfile.FIFOTYPE}[kind]
            if kind in ("sym", "hard"):
                ti.linkname = payload
            tf.addfile(ti)
    buf.seek(0)
    return buf


def test_extract_rejects_malicious_entries(tmp_path):
    dest = tmp_path / "dest"
    dest.mkdir()
    entries = [
        ("/etc/evil", "file", "abs"),
        ("../escape", "file", "dotdot"),
        ("a/../../escape2", "file", "dotdot2"),
        ("dev/null", "chr", None),
        ("pipe", "fifo", None),
        ("esc-link", "sym", "../../outside"),
        ("deep/esc", "sym", "../../x"),
        ("hl-missing", "hard", "does/not/exist"),
        ("hl-abs", "hard", "/etc/passwd"),
        ("ok/file.txt", "file", "fine"),
    ]
    stats = harvest.safe_extract(make_tar(entries), str(dest))
    assert sorted(p.name for p in tmp_path.iterdir()) == ["dest"]                 # nothing outside
    assert [p.relative_to(dest).as_posix() for p in dest.rglob("*") if p.is_file()] == ["ok/file.txt"]
    assert not any(p.is_symlink() for p in dest.rglob("*"))
    assert len(stats.rejected) == 9
    assert stats.files == 1 and stats.bytes == 4
    assert not os.path.exists("/etc/evil")


def test_extract_symlink_handling(tmp_path):
    dest = tmp_path / "dest"
    dest.mkdir()
    entries = [
        ("usr/lib/os-release", "file", "ID=x\n"),
        ("etc/os-release", "sym", "../usr/lib/os-release"),
        ("etc/abs-link", "sym", "/usr/lib/os-release"),          # re-rooted -> relative inside dest
        ("loop", "sym", "."),                                    # in-root symlink to dir ...
        ("loop/payload", "file", "x"),                           # ... must not be traversed
        ("sub/link", "sym", "../usr"),
        ("sub/link/file", "file", "via-link"),                   # through a symlink dir: rejected
        ("a", "file", "plain"),
        ("a/b", "file", "file where dir needed"),
    ]
    stats = harvest.safe_extract(make_tar(entries), str(dest))
    assert os.readlink(dest / "etc/os-release") == "../usr/lib/os-release"
    assert os.readlink(dest / "etc/abs-link") == "../usr/lib/os-release"
    assert (dest / "etc/abs-link").read_text() == "ID=x\n"
    assert not (dest / "payload").exists() and not (dest / "usr/file").exists()
    assert (dest / "a").read_text() == "plain"
    assert len(stats.rejected) == 3


def test_extract_hardlinks_become_copies(tmp_path):
    dest = tmp_path / "dest"
    dest.mkdir()
    harvest.safe_extract(make_tar([("a", "file", "data"), ("b", "hard", "./a")]), str(dest))
    assert (dest / "b").read_text() == "data"
    assert (dest / "a").stat().st_ino != (dest / "b").stat().st_ino
    assert (dest / "a").stat().st_mode & 0o777 == 0o600


def test_extract_limits(tmp_path):
    dest = tmp_path / "d1"
    dest.mkdir()
    st = harvest.ExtractStats()
    with pytest.raises(harvest.HarvestLimitExceeded):
        harvest.safe_extract(make_tar([("a", "file", "x" * 10), ("b", "file", "y" * 10)]), str(dest),
                             max_bytes=15, stats=st)
    assert st.limit and st.files == 1
    dest2 = tmp_path / "d2"
    dest2.mkdir()
    with pytest.raises(harvest.HarvestLimitExceeded):
        harvest.safe_extract(make_tar([(f"f{i}", "file", "x") for i in range(5)]), str(dest2), max_files=3)


# --------------------------------------------------------------------------- LocalTransport end to end

def collect(root: Path, **opts):
    t = LocalTransport()
    inv = SSHCollector().collect("admin@10.0.0.5:2222", transport=t, root=str(root), **opts)
    return inv, t


@pytest.mark.parametrize("root", [DEBIAN, ALPINE], ids=["debian", "alpine"])
def test_linux_fixture_matches_rootfs_collector(root):
    inv, t = collect(root)
    direct_asset = Asset(id="x", type="server", name="x")
    direct = collect_from_view(DirView(root), direct_asset, [])
    assert keys(inv) == {c.key for c in direct}
    assert len(keys(inv)) > 5
    a = inv.asset
    assert (a.id, a.type, a.name, a.os_name, a.os_version) == (
        "ssh:10.0.0.5", "server", "10.0.0.5", direct_asset.os_name, direct_asset.os_version)
    assert a.meta["transport"] == "local" and a.meta["user"] == "admin" and a.meta["port"] == 2222
    assert a.meta["remote_os"] and a.meta["harvested_files"] >= 2 and a.meta["harvested_bytes"] > 0
    assert inv.collector == "ssh"
    assert t.commands == ["sh -s", "sh -s"]                                    # detect + harvest only


def test_macos_fixture_matches_macos_collector():
    inv, _ = collect(MACOS, os="macos")
    direct = MacOSCollector().collect(str(MACOS), home=[])
    assert keys(inv) == {c.key for c in direct.components}
    assert any(c.name == "Slack" for c in inv.components)
    assert any(c.name == "Electron" for c in inv.components)
    assert any(c.meta.get("brew_name") == "curl" for c in inv.components)
    a = inv.asset
    assert (a.id, a.type, a.name, a.os_name, a.os_version) == ("ssh:10.0.0.5", "desktop", "10.0.0.5", "macOS", "14.5")
    assert a.platform.startswith("darwin/")
    slack = next(c for c in inv.components if c.name == "Slack")
    assert slack.meta["mas"] is True                                           # _MASReceipt marker harvested


def test_sudo_uses_non_interactive_sudo():
    _, t = collect(DEBIAN, sudo=True)
    assert t.commands == ["sh -s", "sudo -n sh -s"]


def test_unsupported_os_and_failures(tmp_path):
    class Fake(LocalTransport):
        def stream(self, cmd, timeout=60, stdin=None):
            self.commands.append(cmd)
            proc = subprocess.Popen(["sh", "-c", "echo 'sudo: a password is required' >&2; exit 1"],
                                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return ssh._ProcStream(proc, timeout, stdin)

    with pytest.raises(SSHError, match="no recognisable output"):
        SSHCollector().collect("h", transport=Fake())
    with pytest.raises(SSHError, match="unsupported remote OS"):
        SSHCollector().collect("h", transport=LocalTransport(), root=str(DEBIAN), os="freebsd")

    class HarvestFails(LocalTransport):
        def stream(self, cmd, timeout=60, stdin=None):
            if b"STREAM" in (stdin or b""):
                return Fake.stream(self, cmd, timeout, stdin)
            return super().stream(cmd, timeout, stdin)

    with pytest.raises(SSHError, match="password is required"):
        SSHCollector().collect("h", transport=HarvestFails(), root=str(DEBIAN), sudo=True)


def test_limits_truncate_with_warning():
    inv, _ = collect(DEBIAN, max_files=1)
    assert any("truncated" in w for w in inv.warnings)
    assert inv.asset.meta["truncated"] is True


def test_temp_dir_is_cleaned(tmp_path, monkeypatch):
    monkeypatch.setattr("tempfile.tempdir", str(tmp_path))
    collect(DEBIAN)
    assert list(tmp_path.iterdir()) == []


@pytest.fixture
def messy_root(tmp_path):
    root = tmp_path / "remote"
    shutil.copytree(DEBIAN, root, symlinks=True)

    def w(rel, text="x"):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    w("usr/lib/python3/dist-packages/requests-2.31.0.dist-info/METADATA",
      "Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\n")
    w("srv/app/node_modules/left-pad/package.json", '{"name":"left-pad","version":"1.3.0"}')
    w("srv/app/package-lock.json", "{}")
    w("srv/app/package.json", '{"name":"app","version":"1.0.0"}')
    w("srv/lonely/package.json", "{}")                                        # no lockfile: not harvested
    w("srv/lonely2/go.mod", "module x\n")
    w("srv/weird dir 'q\"$(id)\nnl/Cargo.lock", "")                         # odd names survive -print0
    w("tmp/x/Cargo.lock")
    w("var/cache/pip/node_modules/evil/package.json", '{"name":"evil","version":"1"}')
    w("var/lib/docker/overlay2/a/Cargo.lock")
    w("srv/app/.git/Cargo.lock")
    w("srv/data/foo.jar", "PK")
    w("usr/local/bin/tool", "\x7fELF")
    os.chmod(root / "usr/local/bin/tool", 0o755)
    w("srv/readme.txt")
    return root


def test_harvest_selection(messy_root, tmp_path):
    got = harvested_files(messy_root, tmp_path)
    expect = {
        "etc/os-release", "usr/lib/os-release", "etc/debian_version", "var/lib/dpkg/status",
        "usr/lib/python3/dist-packages/requests-2.31.0.dist-info/METADATA",
        "srv/app/node_modules/left-pad/package.json", "srv/app/package-lock.json", "srv/app/package.json",
        "srv/lonely2/go.mod", "srv/weird dir 'q\"$(id)\nnl/Cargo.lock",
    }
    assert got == expect


def test_harvest_binaries_opt_in(messy_root, tmp_path):
    got = harvested_files(messy_root, tmp_path / "b", binaries=True)
    assert {"srv/data/foo.jar", "usr/local/bin/tool"} <= got
    assert "srv/readme.txt" not in got
    capped = harvested_files(messy_root, tmp_path / "c", binaries=True, max_binary_bytes=1)
    assert "srv/data/foo.jar" not in capped and "usr/local/bin/tool" not in capped


def test_harvest_exclude_and_lang_off(messy_root, tmp_path):
    got = harvested_files(messy_root, tmp_path / "e", exclude=("/srv/app",))
    assert "srv/app/package-lock.json" not in got and "srv/lonely2/go.mod" in got
    only_os = harvested_files(messy_root, tmp_path / "f", lang=False)
    assert only_os == {"etc/os-release", "usr/lib/os-release", "etc/debian_version", "var/lib/dpkg/status"}


def test_inventory_with_language_packages(messy_root):
    inv, _ = collect(messy_root)
    direct = collect_from_view(DirView(messy_root), Asset(id="x", type="server", name="x"), [])
    names = {c.name for c in inv.components}
    assert {"requests", "left-pad"} <= names
    assert "evil" not in names                                                # pruned var/cache
    assert "evil" in {c.name for c in direct}
    assert keys(inv) == {c.key for c in direct if c.name != "evil"}


# --------------------------------------------------------------------------- transport selection

def test_make_transport_auto(monkeypatch):
    t = parse_target("u@h")
    monkeypatch.delenv(ssh.PASSWORD_ENV, raising=False)
    monkeypatch.setattr(shutil, "which", lambda n: "/usr/bin/ssh")
    assert ssh.make_transport(t, {}).name == "openssh"
    monkeypatch.setenv(ssh.PASSWORD_ENV, "pw")
    assert ssh.make_transport(t, {}).name == "paramiko"
    monkeypatch.delenv(ssh.PASSWORD_ENV)
    monkeypatch.setattr(shutil, "which", lambda n: None)
    assert ssh.make_transport(t, {}).name == "paramiko"
    assert ssh.make_transport(t, {"transport": "openssh"}).name == "openssh"
    with pytest.raises(ValueError):
        ssh.make_transport(t, {"transport": "carrier-pigeon"})


def test_openssh_argv():
    tr = ssh.OpenSSHTransport(parse_target("bob@h:2200"), ssh_bin="ssh", identity="/k", connect_timeout=7,
                              ssh_options=["ProxyJump=bastion"])
    argv = tr.argv("sh -s")
    assert argv[-3:] == ["--", "h", "sh -s"]
    assert "BatchMode=yes" in argv and "ConnectTimeout=7" in argv and "ProxyJump=bastion" in argv
    assert argv[argv.index("-p") + 1] == "2200" and argv[argv.index("-l") + 1] == "bob"
    assert argv[argv.index("-i") + 1] == "/k" and "StrictHostKeyChecking=no" not in argv
    assert "StrictHostKeyChecking=no" in ssh.OpenSSHTransport(parse_target("h"), insecure_host_key=True).argv("x")


def test_openssh_transport_with_fake_ssh_binary(tmp_path):
    """The real OpenSSHTransport/_ProcStream code path with a stub `ssh` that just runs the command locally."""
    stub = tmp_path / "ssh"
    stub.write_text('#!/bin/sh\nwhile [ "$1" != "--" ]; do shift; done\nshift 2\nexec sh -c "$1"\n')
    stub.chmod(0o755)
    tr = ssh.OpenSSHTransport(parse_target("u@h"), ssh_bin=str(stub))
    inv = SSHCollector().collect("u@h", transport=tr, root=str(DEBIAN))
    assert any(c.name == "bash" or c.category == "os-package" for c in inv.components)
    rc, out, _ = tr.run("echo hi; exit 3")
    assert (rc, out) == (3, b"hi\n")
    with pytest.raises(TimeoutError):
        tr.run("sleep 5", timeout=0.3)


# --------------------------------------------------------------------------- paramiko end to end

class _Server(paramiko.ServerInterface):
    def __init__(self, client_pub: paramiko.PKey, commands: list[str], root_fn):
        self.client_pub, self.commands, self.cmd_event = client_pub, commands, threading.Event()
        self.cmd: str | None = None
        self.root_fn = root_fn

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "publickey"

    def check_auth_publickey(self, username, key):
        ok = username == "admin" and key == self.client_pub
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_channel_exec_request(self, channel, command):
        self.cmd = command.decode()
        self.commands.append(self.cmd)
        self.cmd_event.set()
        return True


class PrivateSSHServer:
    """In-process sshd: one thread accepts, one thread per connection executes exec requests locally."""

    def __init__(self, host_key: paramiko.PKey, client_pub: paramiko.PKey):
        self.host_key, self.client_pub = host_key, client_pub
        self.commands: list[str] = []
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        t = paramiko.Transport(conn)
        t.add_server_key(self.host_key)
        srv = _Server(self.client_pub, self.commands, None)
        try:
            t.start_server(server=srv)
            while t.is_active():
                chan = t.accept(5)
                if chan is None:
                    continue
                if not srv.cmd_event.wait(10):
                    continue
                srv.cmd_event.clear()
                data = bytearray()
                while True:
                    chunk = chan.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                p = subprocess.run(srv.cmd, check=False, shell=True, input=bytes(data), capture_output=True)
                chan.sendall(p.stdout)
                if p.stderr:
                    chan.sendall_stderr(p.stderr)
                chan.send_exit_status(p.returncode)
                chan.close()
        except Exception:  # noqa: BLE001, S110
            pass
        finally:
            t.close()

    def close(self):
        self._stop = True
        self.sock.close()


@pytest.fixture(scope="module")
def sshd(tmp_path_factory):
    d = tmp_path_factory.mktemp("sshd")
    host_key = paramiko.RSAKey.generate(2048)
    client_key = paramiko.RSAKey.generate(2048)
    client_key.write_private_key_file(str(d / "id_rsa"))
    server = PrivateSSHServer(host_key, client_key)
    (d / "known_hosts").write_text(
        f"[127.0.0.1]:{server.port} {host_key.get_name()} {host_key.get_base64()}\n")
    (d / "empty_known_hosts").write_text("")
    wrong = paramiko.RSAKey.generate(2048)
    (d / "wrong_known_hosts").write_text(f"[127.0.0.1]:{server.port} {wrong.get_name()} {wrong.get_base64()}\n")
    server.dir = d
    yield server
    server.close()


def _popts(sshd, **extra):
    return {"transport": "paramiko", "identity": str(sshd.dir / "id_rsa"), "known_hosts": str(sshd.dir / "known_hosts"),
            "allow_agent": False, "look_for_keys": False, "ssh_config": str(sshd.dir / "nonexistent"),
            "connect_timeout": 10, "root": str(DEBIAN), **extra}


def test_paramiko_end_to_end(sshd, monkeypatch):
    monkeypatch.delenv(ssh.PASSWORD_ENV, raising=False)
    before = len(sshd.commands)
    inv = SSHCollector().collect(f"ssh://admin@127.0.0.1:{sshd.port}", **_popts(sshd))
    direct = collect_from_view(DirView(DEBIAN), Asset(id="x", type="server", name="x"), [])
    assert keys(inv) == {c.key for c in direct}
    assert inv.asset.id == "ssh:127.0.0.1" and inv.asset.meta["transport"] == "paramiko"
    assert inv.asset.meta["port"] == sshd.port and inv.asset.meta["harvested_files"] >= 2
    assert sshd.commands[before:] == ["sh -s", "sh -s"]                       # nothing but the fixed commands


def test_paramiko_macos_end_to_end(sshd):
    inv = SSHCollector().collect(f"admin@127.0.0.1:{sshd.port}", **_popts(sshd, root=str(MACOS), os="macos"))
    direct = MacOSCollector().collect(str(MACOS), home=[])
    assert keys(inv) == {c.key for c in direct.components}
    assert inv.asset.type == "desktop"


def test_paramiko_rejects_unknown_and_wrong_host_keys(sshd):
    target = f"admin@127.0.0.1:{sshd.port}"
    with pytest.raises(SSHError, match="known_hosts"):
        SSHCollector().collect(target, **_popts(sshd, known_hosts=str(sshd.dir / "empty_known_hosts")))
    with pytest.raises(SSHError, match="HOST KEY MISMATCH"):
        SSHCollector().collect(target, **_popts(sshd, known_hosts=str(sshd.dir / "wrong_known_hosts")))


def test_paramiko_insecure_host_key_opt_in(sshd):
    inv = SSHCollector().collect(f"admin@127.0.0.1:{sshd.port}",
                                 **_popts(sshd, known_hosts=str(sshd.dir / "empty_known_hosts"),
                                          insecure_host_key=True))
    assert inv.components


def test_paramiko_auth_failure(sshd):
    with pytest.raises(SSHError, match="mallory"):
        SSHCollector().collect(f"mallory@127.0.0.1:{sshd.port}", **_popts(sshd))


def test_paramiko_password_only_from_env(monkeypatch):
    monkeypatch.setenv(ssh.PASSWORD_ENV, "s3cret")
    tr = ssh.make_transport(parse_target("u@h"), {"transport": "paramiko"})
    assert tr.password == "s3cret"
